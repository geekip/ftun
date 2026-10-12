#include "event/event.h"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "event contract failed: %s\n", #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  pthread_mutex_t mutex;
  ftun_event_loop_t *loop;
  int calls;
  int wakeups;
  int recursive_again;
  uint32_t events;
} event_state_t;

typedef struct {
  ftun_event_loop_t *loop;
  event_state_t *state;
  size_t count;
  ftun_status_t status;
} producer_state_t;

static void wakeup(void *user)
{
  event_state_t *state = (event_state_t *)user;
  (void)pthread_mutex_lock(&state->mutex);
  state->wakeups++;
  (void)pthread_mutex_unlock(&state->mutex);
}

static void deferred(void *user)
{
  event_state_t *state = (event_state_t *)user;
  size_t callbacks = 99u;
  state->calls++;
  if (ftun_event_loop_poll(state->loop, 0u, 1u, &callbacks) == FTUN_E_AGAIN &&
      callbacks == 0u) state->recursive_again++;
}

static void source_ready(ftun_event_source_t *source, uint32_t events, void *user)
{
  event_state_t *state = (event_state_t *)user;
  (void)source;
  state->calls++;
  state->events |= events;
}

static void *produce(void *user)
{
  producer_state_t *producer = (producer_state_t *)user;
  size_t index;
  producer->status = FTUN_OK;
  for (index = 0u; index < producer->count; index++) {
    ftun_status_t status = ftun_event_defer(producer->loop, deferred, producer->state);
    if (status != FTUN_OK) {
      producer->status = status;
      break;
    }
  }
  return NULL;
}

/* TASK-EVENT-001 / TEST-EVENT-001：I/O、timer、wakeup 与 stop/drain。 */
int main(void)
{
  ftun_event_loop_t *loop = (ftun_event_loop_t *)(uintptr_t)1;
  ftun_event_source_t *io = (ftun_event_source_t *)(uintptr_t)1;
  ftun_event_source_t *timer = (ftun_event_source_t *)(uintptr_t)1;
  ftun_event_source_t **sources = NULL;
  ftun_event_loop_usage_t usage;
  event_state_t state;
  producer_state_t producers[4];
  pthread_t threads[4];
  size_t callbacks = 99u;
  size_t index;

  state.mutex = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
  state.loop = NULL;
  state.calls = 0;
  state.wakeups = 0;
  state.recursive_again = 0;
  state.events = 0u;

  CHECK(ftun_event_loop_create(NULL, &loop) == FTUN_OK);
  state.loop = loop;
  CHECK(ftun_event_loop_get_usage(loop, &usage) == FTUN_OK);
  CHECK(usage.deferred_capacity == 256u && usage.source_capacity == 1024u &&
        usage.deferred_count == 0u && usage.source_count == 0u && usage.accepting);
  CHECK(ftun_event_loop_set_wakeup(loop, wakeup, &state) == FTUN_OK);
  CHECK(ftun_event_defer(loop, NULL, &state) == FTUN_E_INVALID);

  for (index = 0u; index < 4u; index++) {
    producers[index].loop = loop;
    producers[index].state = &state;
    producers[index].count = usage.deferred_capacity / 4u;
    producers[index].status = FTUN_E_STATE_CORRUPT;
    CHECK(pthread_create(&threads[index], NULL, produce, &producers[index]) == 0);
  }
  for (index = 0u; index < 4u; index++) {
    CHECK(pthread_join(threads[index], NULL) == 0);
    CHECK(producers[index].status == FTUN_OK);
  }
  CHECK(ftun_event_defer(loop, deferred, &state) == FTUN_E_LIMIT);
  CHECK(state.calls == 0);
  (void)pthread_mutex_lock(&state.mutex);
  CHECK(state.wakeups == 1);
  (void)pthread_mutex_unlock(&state.mutex);
  CHECK(ftun_event_loop_poll(loop, 0u, 10u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 10u && state.calls == 10 && state.recursive_again == 10);
  (void)pthread_mutex_lock(&state.mutex);
  CHECK(state.wakeups == 2);
  (void)pthread_mutex_unlock(&state.mutex);
  CHECK(ftun_event_loop_poll(loop, 0u, SIZE_MAX, &callbacks) == FTUN_OK);
  CHECK(callbacks == usage.deferred_capacity - 10u);
  CHECK(state.calls == (int)usage.deferred_capacity &&
        state.recursive_again == (int)usage.deferred_capacity);

  state.calls = 0;
  state.events = 0u;
  CHECK(ftun_event_io_start(loop, 7u, FTUN_EVENT_READ | FTUN_EVENT_ERROR,
                            source_ready, &state, &io) == FTUN_OK);
  timer = (ftun_event_source_t *)(uintptr_t)1;
  CHECK(ftun_event_io_start(loop, 7u, FTUN_EVENT_TIMER, source_ready,
                            &state, &timer) == FTUN_E_INVALID && timer == NULL);
  CHECK(ftun_event_io_ready(io, FTUN_EVENT_WRITE) == FTUN_OK);
  CHECK(ftun_event_loop_poll(loop, 50u, 1u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 0u && state.calls == 0);
  CHECK(ftun_event_io_ready(io, FTUN_EVENT_READ | FTUN_EVENT_ERROR) == FTUN_OK);
  CHECK(ftun_event_loop_poll(loop, 50u, 1u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 1u && state.calls == 1 &&
        state.events == (FTUN_EVENT_READ | FTUN_EVENT_ERROR));
  state.calls = 0;
  state.events = 0u;
  CHECK(ftun_event_io_ready(io, FTUN_EVENT_READ) == FTUN_OK);
  CHECK(ftun_event_io_update(io, FTUN_EVENT_WRITE | FTUN_EVENT_ERROR) ==
        FTUN_OK);
  CHECK(ftun_event_loop_poll(loop, 50u, 1u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 0u && state.calls == 0);
  CHECK(ftun_event_io_ready(io, FTUN_EVENT_WRITE) == FTUN_OK);
  CHECK(ftun_event_loop_poll(loop, 50u, 1u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 1u && state.calls == 1 && state.events == FTUN_EVENT_WRITE);

  state.calls = 0;
  state.events = 0u;
  CHECK(ftun_event_timer_start(loop, 100u, source_ready, &state, &timer) == FTUN_OK);
  CHECK(ftun_event_io_ready(timer, FTUN_EVENT_READ) == FTUN_E_INVALID);
  CHECK(ftun_event_loop_poll(loop, 99u, 2u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 0u && state.calls == 0);
  CHECK(ftun_event_loop_poll(loop, 100u, 2u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 1u && state.calls == 1 && state.events == FTUN_EVENT_TIMER);
  CHECK(ftun_event_loop_poll(loop, 101u, 2u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 0u && state.calls == 1);
  CHECK(ftun_event_source_cancel(&timer) == FTUN_OK && timer == NULL);
  CHECK(ftun_event_source_cancel(&timer) == FTUN_OK);

  CHECK(ftun_event_loop_get_usage(loop, &usage) == FTUN_OK);
  sources = (ftun_event_source_t **)calloc(usage.source_capacity,
                                           sizeof(*sources));
  CHECK(sources != NULL);
  for (index = usage.source_count; index < usage.source_capacity; index++) {
    CHECK(ftun_event_timer_start(loop, UINT64_MAX, source_ready, &state,
                                 &sources[index]) == FTUN_OK);
  }
  timer = (ftun_event_source_t *)(uintptr_t)1;
  CHECK(ftun_event_timer_start(loop, 1u, source_ready, &state, &timer) == FTUN_E_LIMIT);
  CHECK(timer == NULL);
  CHECK(ftun_event_loop_get_usage(loop, &usage) == FTUN_OK);
  CHECK(usage.source_count == usage.source_capacity);

  CHECK(ftun_event_defer(loop, deferred, &state) == FTUN_OK);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_defer(loop, deferred, &state) == FTUN_E_CANCELLED);
  CHECK(ftun_event_io_ready(io, FTUN_EVENT_READ) == FTUN_E_STALE);
  CHECK(ftun_event_loop_set_wakeup(loop, wakeup, &state) == FTUN_E_CANCELLED);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_E_AGAIN && loop != NULL);
  state.calls = 0;
  CHECK(ftun_event_loop_poll(loop, UINT64_MAX, 8u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 1u && state.calls == 1);
  CHECK(ftun_event_source_cancel(&io) == FTUN_OK && io == NULL);
  for (index = 0u; index < usage.source_capacity; index++) {
    CHECK(ftun_event_source_cancel(&sources[index]) == FTUN_OK);
  }
  free(sources);
  CHECK(ftun_event_loop_get_usage(loop, &usage) == FTUN_OK);
  CHECK(usage.deferred_count == 0u && usage.source_count == 0u &&
        !usage.accepting && usage.stopped);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK && loop == NULL);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);

  loop = (ftun_event_loop_t *)(uintptr_t)1;
  CHECK(ftun_event_loop_create(NULL, NULL) == FTUN_E_INVALID);
  CHECK(ftun_event_loop_get_usage(NULL, &usage) == FTUN_E_INVALID);
  CHECK(usage.deferred_capacity == 0u && usage.source_count == 0u);
  CHECK(ftun_event_loop_poll(NULL, 0u, 1u, &callbacks) == FTUN_E_INVALID);
  CHECK(callbacks == 0u);
  CHECK(ftun_event_source_cancel(NULL) == FTUN_E_INVALID);
  CHECK(ftun_event_loop_destroy(NULL) == FTUN_E_INVALID);
  CHECK(loop == (ftun_event_loop_t *)(uintptr_t)1);
  CHECK(pthread_mutex_destroy(&state.mutex) == 0);
  return 0;
}
