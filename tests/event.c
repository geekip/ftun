#include "event/event.h"
#include <pthread.h>
#include <sched.h>
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
  size_t busy_requeues;
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

static void busy_deferred(void *user)
{
  event_state_t *state = (event_state_t *)user;
  state->calls++;
  if (state->busy_requeues != 0u) {
    state->busy_requeues--;
    if (ftun_event_defer(state->loop, busy_deferred, state) != FTUN_OK) {
      state->calls = -1000;
    }
  }
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

typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  ftun_event_loop_t *loop;
  size_t ready;
  size_t done;
  int start;
} concurrent_shared_t;

typedef struct {
  concurrent_shared_t *shared;
  size_t accepted;
  size_t callbacks;
  ftun_status_t status;
} concurrent_producer_t;

static void concurrent_callback(void *user)
{
  concurrent_producer_t *producer = user;
  producer->callbacks++;
}

static void *produce_while_polling(void *user)
{
  concurrent_producer_t *producer = user;
  concurrent_shared_t *shared = producer->shared;
  size_t index;
  (void)pthread_mutex_lock(&shared->mutex);
  shared->ready++;
  (void)pthread_cond_broadcast(&shared->condition);
  while (!shared->start)
    (void)pthread_cond_wait(&shared->condition, &shared->mutex);
  (void)pthread_mutex_unlock(&shared->mutex);
  for (index = 0u; index < 5000u; index++) {
    do {
      producer->status = ftun_event_defer(shared->loop, concurrent_callback, producer);
      if (producer->status == FTUN_E_LIMIT) (void)sched_yield();
    } while (producer->status == FTUN_E_LIMIT);
    if (producer->status != FTUN_OK) break;
    producer->accepted++;
    if (index % 64u == 0u) (void)ftun_event_loop_wakeup(shared->loop);
  }
  (void)pthread_mutex_lock(&shared->mutex);
  shared->done++;
  (void)pthread_mutex_unlock(&shared->mutex);
  return NULL;
}

static int concurrent_poll(int stop_early)
{
  concurrent_shared_t shared = {0};
  concurrent_producer_t producers[4] = {{0}};
  pthread_t threads[4];
  ftun_event_loop_usage_t usage;
  size_t index, callbacks, done = 0u, total = 0u;
  int stopped = 0;
  CHECK(pthread_mutex_init(&shared.mutex, NULL) == 0);
  CHECK(pthread_cond_init(&shared.condition, NULL) == 0);
  CHECK(ftun_event_loop_create(NULL, &shared.loop) == FTUN_OK);
  for (index = 0u; index < 4u; index++) {
    producers[index].shared = &shared;
    CHECK(pthread_create(&threads[index], NULL, produce_while_polling, &producers[index]) == 0);
  }
  (void)pthread_mutex_lock(&shared.mutex);
  while (shared.ready != 4u)
    (void)pthread_cond_wait(&shared.condition, &shared.mutex);
  shared.start = 1;
  (void)pthread_cond_broadcast(&shared.condition);
  (void)pthread_mutex_unlock(&shared.mutex);
  do {
    CHECK(ftun_event_loop_poll(shared.loop, 0u, 1u, &callbacks) == FTUN_OK);
    CHECK(callbacks <= 1u);
    total += callbacks;
    if (stop_early && !stopped && total >= 100u) {
      CHECK(ftun_event_loop_stop(shared.loop) == FTUN_OK);
      stopped = 1;
    }
    (void)pthread_mutex_lock(&shared.mutex);
    done = shared.done;
    (void)pthread_mutex_unlock(&shared.mutex);
    CHECK(ftun_event_loop_get_usage(shared.loop, &usage) == FTUN_OK);
    CHECK(usage.deferred_count <= usage.deferred_capacity && usage.callbacks == total &&
          usage.max_callbacks_per_poll <= 1u && usage.quota_exhaustions <= usage.polls);
    if (callbacks == 0u) (void)sched_yield();
  } while (done != 4u || usage.deferred_count != 0u);
  for (index = 0u; index < 4u; index++) {
    CHECK(pthread_join(threads[index], NULL) == 0);
    CHECK(producers[index].callbacks == producers[index].accepted);
    CHECK(producers[index].status == (stop_early ? FTUN_E_CANCELLED : FTUN_OK));
    if (!stop_early) CHECK(producers[index].accepted == 5000u);
  }
  if (!stop_early) CHECK(total == 20000u);
  CHECK(ftun_event_loop_stop(shared.loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&shared.loop) == FTUN_OK);
  CHECK(pthread_cond_destroy(&shared.condition) == 0);
  CHECK(pthread_mutex_destroy(&shared.mutex) == 0);
  return 0;
}

typedef struct {
  uint64_t deadline;
  size_t calls;
} indexed_timer_t;

static void indexed_timer_ready(ftun_event_source_t *source, uint32_t events, void *user)
{
  indexed_timer_t *state = user;
  (void)source;
  if (events == FTUN_EVENT_TIMER) state->calls++;
}

static int timer_index_contract(void)
{
  ftun_event_loop_t *loop = NULL;
  ftun_event_source_t *sources[513] = {0};
  indexed_timer_t states[513] = {{0}};
  ftun_event_loop_usage_t usage;
  uint64_t now, next;
  uint32_t seed = 93u;
  size_t index, round, callbacks, remaining = 0u;
  bool present;
  CHECK(ftun_event_loop_create_with_capacity(NULL, 513u, &loop) == FTUN_OK);
  for (index = 0u; index < 513u; index++) {
    seed = seed * 1664525u + 1013904223u;
    states[index].deadline = 100u + seed % 1024u;
    CHECK(ftun_event_timer_start(loop, states[index].deadline,
      indexed_timer_ready, &states[index], &sources[index]) == FTUN_OK);
    remaining++;
  }
  /* 从任意位置撤销，包括堆根、内部节点与末节点。 */
  for (index = 0u; index < 513u; index += 3u) {
    CHECK(ftun_event_source_cancel(&sources[index]) == FTUN_OK);
    remaining--;
  }
  for (round = 0u; round < remaining; round++) {
    uint64_t expected = UINT64_MAX;
    size_t calls = 0u;
    for (index = 0u; index < 513u; index++) {
      if (sources[index] != NULL && states[index].calls == 0u && states[index].deadline < expected) expected = states[index].deadline;
      calls += states[index].calls;
    }
    CHECK(calls == round);
    CHECK(ftun_event_loop_next_deadline(loop, &next, &present) == FTUN_OK && present && next == expected);
    now = next;
    CHECK(ftun_event_loop_poll(loop, now - 1u, 1u, &callbacks) == FTUN_OK && callbacks == 0u);
    CHECK(ftun_event_loop_poll(loop, now, 1u, &callbacks) == FTUN_OK && callbacks == 1u);
    CHECK(ftun_event_loop_get_usage(loop, &usage) == FTUN_OK && usage.last_timer_work == 1u && usage.ready_count == 0u);
    for (index = 0u; index < 513u; index++) {
      CHECK(states[index].calls <= 1u);
      if (states[index].calls != 0u) CHECK(states[index].deadline <= now);
    }
  }
  CHECK(ftun_event_loop_next_deadline(loop, &next, &present) == FTUN_OK && !present);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  for (index = 0u; index < 513u; index++) CHECK(ftun_event_source_cancel(&sources[index]) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_event_loop_create_with_capacity(NULL, SIZE_MAX, &loop) == FTUN_E_LIMIT && loop == NULL);
  return 0;
}

/* I/O、timer、wakeup 与 stop/drain。 */
static int owner_tasks(void)
{
  ftun_event_loop_t *loop = NULL;
  ftun_event_source_t *tasks[300] = {0};
  ftun_event_source_t *overflow = NULL;
  ftun_event_loop_usage_t usage;
  event_state_t state = {0};
  size_t index, callbacks;
  CHECK(ftun_event_loop_create_with_capacity(NULL, 300u, &loop) == FTUN_OK);
  state.loop = loop;
  CHECK(ftun_event_loop_get_usage(loop, &usage) == FTUN_OK);
  for (index = 0u; index < usage.deferred_capacity; index++) {
    CHECK(ftun_event_defer(loop, deferred, &state) == FTUN_OK);
  }
  CHECK(ftun_event_defer(loop, deferred, &state) == FTUN_E_LIMIT);
  /* defer 满载不妨碍已占 source 额度的任务；重复 ready 只排队一次。 */
  for (index = 0u; index < 300u; index++) {
    CHECK(ftun_event_task_start(loop, source_ready, &state, &tasks[index]) == FTUN_OK);
    CHECK(ftun_event_task_ready(tasks[index]) == FTUN_OK);
    CHECK(ftun_event_task_ready(tasks[index]) == FTUN_OK);
  }
  CHECK(ftun_event_task_start(loop, source_ready, &state, &overflow) == FTUN_E_LIMIT && overflow == NULL);
  CHECK(ftun_event_loop_poll(loop, 0u, 4u, &callbacks) == FTUN_OK && callbacks == 4u);
  CHECK((state.events & FTUN_EVENT_TASK) != 0u && state.recursive_again != 0);
  CHECK(ftun_event_loop_poll(loop, 0u, 1024u, &callbacks) == FTUN_OK);
  CHECK((size_t)state.calls == usage.deferred_capacity + 300u);
  CHECK(ftun_event_task_ready(tasks[0]) == FTUN_OK);
  CHECK(ftun_event_loop_poll(loop, 0u, 1u, &callbacks) == FTUN_OK && callbacks == 1u);
  CHECK(ftun_event_task_ready(tasks[0]) == FTUN_OK);
  CHECK(ftun_event_source_cancel(&tasks[0]) == FTUN_OK);
  CHECK(ftun_event_loop_poll(loop, 0u, 1u, &callbacks) == FTUN_OK && callbacks == 0u);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_task_ready(tasks[1]) == FTUN_E_STALE);
  for (index = 1u; index < 300u; index++) CHECK(ftun_event_source_cancel(&tasks[index]) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  return 0;
}

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
  state.busy_requeues = 0u;
  state.events = 0u;

  CHECK(timer_index_contract() == 0);
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
  CHECK(ftun_event_loop_get_usage(loop, &usage) == FTUN_OK &&
        usage.wakeups == 2u && usage.deferred_count ==
          usage.deferred_capacity - 10u && usage.polls == 1u &&
        usage.callbacks == 10u && usage.quota_exhaustions == 1u &&
        usage.max_callbacks_per_poll == 10u);
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
  CHECK(ftun_event_loop_get_usage(loop, &usage) == FTUN_OK &&
        usage.ready_count == 1u);
  CHECK(ftun_event_loop_poll(loop, 50u, 1u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 1u && state.calls == 1 &&
        state.events == (FTUN_EVENT_READ | FTUN_EVENT_ERROR));
  CHECK(ftun_event_loop_get_usage(loop, &usage) == FTUN_OK &&
        usage.ready_count == 0u);
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
  CHECK(ftun_event_loop_poll(loop, 110u, 2u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 1u && state.calls == 1 && state.events == FTUN_EVENT_TIMER);
  CHECK(ftun_event_loop_get_usage(loop, &usage) == FTUN_OK &&
        usage.max_timer_lateness_ms == 10u);
  CHECK(ftun_event_loop_poll(loop, 101u, 2u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 0u && state.calls == 1);
  CHECK(ftun_event_source_cancel(&timer) == FTUN_OK && timer == NULL);
  CHECK(ftun_event_source_cancel(&timer) == FTUN_OK);

  /* A permanently busy deferred lane must not starve an already-ready I/O
   * source.  The dispatcher alternates lanes within the same quota. */
  state.calls = 0;
  state.events = 0u;
  state.busy_requeues = 8u;
  CHECK(ftun_event_defer(loop, busy_deferred, &state) == FTUN_OK);
  CHECK(ftun_event_io_ready(io, FTUN_EVENT_WRITE) == FTUN_OK);
  CHECK(ftun_event_loop_poll(loop, 200u, 2u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 2u && state.calls == 2 &&
        state.events == FTUN_EVENT_WRITE);
  while (state.busy_requeues != 0u) {
    CHECK(ftun_event_loop_poll(loop, 200u, 2u, &callbacks) == FTUN_OK &&
          callbacks != 0u);
  }
  CHECK(ftun_event_loop_poll(loop, 200u, 2u, &callbacks) == FTUN_OK &&
        callbacks == 0u);

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
        usage.wakeups >= 3u && !usage.accepting && usage.stopped);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK && loop == NULL);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);

  sources = (ftun_event_source_t **)calloc(3u, sizeof(*sources));
  CHECK(sources != NULL);
  CHECK(ftun_event_loop_create_with_capacity(NULL, 3u, &loop) == FTUN_OK);
  CHECK(ftun_event_loop_get_usage(loop, &usage) == FTUN_OK &&
        usage.source_capacity == 3u);
  for (index = 0u; index < 3u; index++) {
    CHECK(ftun_event_timer_start(loop, UINT64_MAX, source_ready, &state,
                                 &sources[index]) == FTUN_OK);
  }
  CHECK(ftun_event_timer_start(loop, UINT64_MAX, source_ready, &state,
                               &timer) == FTUN_E_LIMIT && timer == NULL);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  for (index = 0u; index < 3u; index++) {
    CHECK(ftun_event_source_cancel(&sources[index]) == FTUN_OK);
  }
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  free(sources);

  loop = (ftun_event_loop_t *)(uintptr_t)1;
  CHECK(ftun_event_loop_create(NULL, NULL) == FTUN_E_INVALID);
  CHECK(ftun_event_loop_create_with_capacity(NULL, 0u, &loop) ==
        FTUN_E_INVALID && loop == NULL);
  CHECK(ftun_event_loop_get_usage(NULL, &usage) == FTUN_E_INVALID);
  CHECK(usage.deferred_capacity == 0u && usage.source_count == 0u);
  CHECK(ftun_event_loop_poll(NULL, 0u, 1u, &callbacks) == FTUN_E_INVALID);
  CHECK(callbacks == 0u);
  CHECK(ftun_event_source_cancel(NULL) == FTUN_E_INVALID);
  loop = (ftun_event_loop_t *)(uintptr_t)1;
  CHECK(ftun_event_loop_destroy(NULL) == FTUN_E_INVALID);
  CHECK(loop == (ftun_event_loop_t *)(uintptr_t)1);
  CHECK(pthread_mutex_destroy(&state.mutex) == 0);
  CHECK(owner_tasks() == 0);
  CHECK(concurrent_poll(0) == 0);
  CHECK(concurrent_poll(1) == 0);
  return 0;
}
