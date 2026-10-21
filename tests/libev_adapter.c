#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "event/event.h"
#include "event/libev_adapter.h"
#include "util/time.h"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "libev adapter failed: %s\n", #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  ftun_event_loop_t *loop;
  int read_fd;
  int io_calls;
  int timer_calls;
  int deferred_calls;
  ftun_status_t producer_status;
} adapter_state_t;

static void ready(ftun_event_source_t *source, uint32_t events, void *user)
{
  adapter_state_t *state = (adapter_state_t *)user;
  char byte;
  (void)source;
  if ((events & FTUN_EVENT_TIMER) != 0u) state->timer_calls++;
  if ((events & FTUN_EVENT_READ) != 0u) {
    if (read(state->read_fd, &byte, 1u) == 1 && byte == 'x') state->io_calls++;
  }
}

static void deferred(void *user)
{
  adapter_state_t *state = (adapter_state_t *)user;
  state->deferred_calls++;
}

static void *produce(void *user)
{
  adapter_state_t *state = (adapter_state_t *)user;
  struct timespec delay = {0, 5000000L};
  (void)nanosleep(&delay, NULL);
  state->producer_status = ftun_event_defer(state->loop, deferred, state);
  return NULL;
}

/* TASK-EVENT-002 / TEST-EVENT-002：epoll I/O、timer 与跨线程 ev_async。 */
int main(void)
{
  ftun_event_loop_t *loop = NULL;
  ftun_event_source_t *io = NULL;
  ftun_event_source_t *timer = NULL;
  ftun_event_source_t *guard_timer = NULL;
  ftun_libev_info_t info;
  ftun_event_loop_usage_t usage;
  adapter_state_t state;
  pthread_t producer;
  uint64_t now_ms = 0u;
  size_t callbacks = 99u;
  int descriptors[2] = {-1, -1};

  memset(&state, 0, sizeof(state));
  CHECK(pipe(descriptors) == 0);
  state.read_fd = descriptors[0];
  state.producer_status = FTUN_E_STATE_CORRUPT;
  CHECK(ftun_event_loop_create(NULL, &loop) == FTUN_OK);
  state.loop = loop;
  CHECK(ftun_libev_attach(loop) == FTUN_OK);
  CHECK(ftun_libev_attach(loop) == FTUN_E_AGAIN);
  CHECK(ftun_libev_get_info(loop, &info) == FTUN_OK);
  CHECK(info.version_major == 4u && info.version_minor == 33u &&
        strcmp(info.backend, "epoll") == 0 && info.async_thread_safe);
  CHECK(ftun_event_loop_get_usage(loop, &usage) == FTUN_OK && usage.backend_attached);

  CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)descriptors[0],
                            FTUN_EVENT_READ | FTUN_EVENT_ERROR,
                            ready, &state, &io) == FTUN_OK);
  CHECK(write(descriptors[1], "x", 1u) == 1);
  CHECK(ftun_event_loop_run_once(loop, true, 8u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 1u && state.io_calls == 1);

  CHECK(ftun_event_io_update(io, FTUN_EVENT_ERROR) == FTUN_OK);
  CHECK(write(descriptors[1], "x", 1u) == 1);
  /* Drain any readiness which was already queued by epoll before READ was
   * disabled; inactive watcher callbacks must not affect the timing check. */
  CHECK(ftun_event_loop_run_once(loop, false, 8u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 0u && state.io_calls == 1);
  CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK);
  {
    uint64_t started_ms = now_ms;
    uint64_t finished_ms = 0u;
    /* With READ disabled, only this explicit absolute deadline may wake the
     * blocking backend.  This rejects the former hidden 10 ms poll timer. */
    CHECK(ftun_event_timer_start(loop, now_ms + 40u, ready, &state,
                                 &guard_timer) == FTUN_OK);
    CHECK(ftun_event_loop_run_once(loop, true, 8u, &callbacks) == FTUN_OK);
    CHECK(ftun_monotonic_now(&finished_ms) == FTUN_OK &&
          finished_ms >= started_ms + 25u);
  }
  CHECK(callbacks == 1u && state.io_calls == 1 && state.timer_calls == 1);
  CHECK(ftun_event_source_cancel(&guard_timer) == FTUN_OK);
  CHECK(ftun_event_io_update(io, FTUN_EVENT_READ | FTUN_EVENT_ERROR) ==
        FTUN_OK);
  CHECK(ftun_event_loop_run_once(loop, true, 8u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 1u && state.io_calls == 2);

  CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK);
  CHECK(ftun_event_timer_start(loop, now_ms + 5u, ready, &state, &timer) == FTUN_OK);
  CHECK(ftun_event_loop_run_once(loop, true, 8u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 1u && state.timer_calls == 2);

  CHECK(pthread_create(&producer, NULL, produce, &state) == 0);
  CHECK(ftun_event_loop_run_once(loop, true, 8u, &callbacks) == FTUN_OK);
  CHECK(pthread_join(producer, NULL) == 0);
  CHECK(state.producer_status == FTUN_OK && callbacks == 1u &&
        state.deferred_calls == 1);

  CHECK(ftun_libev_detach(loop) == FTUN_E_AGAIN);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_source_cancel(&timer) == FTUN_OK);
  CHECK(ftun_event_source_cancel(&io) == FTUN_OK);
  CHECK(ftun_libev_detach(loop) == FTUN_OK);
  CHECK(ftun_libev_get_info(loop, &info) == FTUN_E_UNSUPPORTED);
  CHECK(info.version_major == 0u && info.backend == NULL);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK && loop == NULL);
  CHECK(close(descriptors[0]) == 0);
  CHECK(close(descriptors[1]) == 0);
  CHECK(ftun_libev_attach(NULL) == FTUN_E_INVALID);
  CHECK(ftun_libev_get_info(NULL, &info) == FTUN_E_INVALID);
  CHECK(ftun_libev_detach(NULL) == FTUN_E_INVALID);
  return 0;
}
