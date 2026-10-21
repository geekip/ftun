#include "event.h"
#include "util/time.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define FTUN_EVENT_DEFERRED_CAPACITY 256u
#define FTUN_EVENT_SOURCE_CAPACITY 1024u

typedef enum {
  FTUN_EVENT_SOURCE_IO = 1,
  FTUN_EVENT_SOURCE_TIMER
} ftun_event_source_kind_t;

typedef struct {
  ftun_event_deferred_fn callback;
  void *user;
} ftun_event_deferred_t;

struct ftun_event_source {
  ftun_event_loop_t *loop;
  ftun_event_source_t *previous;
  ftun_event_source_t *next;
  ftun_event_source_t *ready_previous;
  ftun_event_source_t *ready_next;
  ftun_event_callback_fn callback;
  void *user;
  void *backend_data;
  ftun_event_source_kind_t kind;
  ftun_native_socket_t socket;
  uint64_t deadline_ms;
  uint32_t interests;
  uint32_t pending;
  int active;
  int in_ready;
};

struct ftun_event_loop {
  ftun_core_t *core;
  ftun_event_source_t *sources;
  ftun_event_source_t *ready_head;
  ftun_event_source_t *ready_tail;
  ftun_event_deferred_t deferred[FTUN_EVENT_DEFERRED_CAPACITY];
  pthread_mutex_t mutex;
  ftun_event_wakeup_fn wakeup;
  void *wakeup_user;
  const ftun_event_backend_ops_t *backend;
  void *backend_context;
  size_t deferred_head;
  size_t deferred_tail;
  size_t deferred_count;
  size_t source_capacity;
  size_t source_count;
  size_t ready_count;
  size_t wakeups;
  uint64_t polls;
  uint64_t callbacks;
  uint64_t quota_exhaustions;
  uint64_t last_dispatch_ms;
  uint64_t max_dispatch_ms;
  uint64_t max_timer_lateness_ms;
  size_t max_callbacks_per_poll;
  int prefer_deferred;
  int accepting;
  int dispatching;
  int stopped;
};

/* TASK-EVENT-001 / TEST-EVENT-001，目标 0.2.0：后端无关的有界事件前端。 */
ftun_status_t ftun_event_loop_create(ftun_core_t *core, ftun_event_loop_t **out)
{
  return ftun_event_loop_create_with_capacity(
    core, FTUN_EVENT_SOURCE_CAPACITY, out);
}

ftun_status_t ftun_event_loop_create_with_capacity(
  ftun_core_t *core, size_t source_capacity, ftun_event_loop_t **out)
{
  ftun_event_loop_t *loop;
  if (out != NULL) *out = NULL;
  if (out == NULL || source_capacity == 0u) return FTUN_E_INVALID;
  loop = (ftun_event_loop_t *)calloc(1u, sizeof(*loop));
  if (loop == NULL) return FTUN_E_LIMIT;
  if (pthread_mutex_init(&loop->mutex, NULL) != 0) {
    free(loop);
    return FTUN_E_IO;
  }
  loop->core = core;
  loop->source_capacity = source_capacity;
  loop->accepting = 1;
  loop->prefer_deferred = 1;
  *out = loop;
  return FTUN_OK;
}

ftun_status_t ftun_event_loop_set_wakeup(ftun_event_loop_t *loop,
                                         ftun_event_wakeup_fn wakeup, void *user)
{
  if (loop == NULL || (wakeup == NULL && user != NULL)) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&loop->mutex);
  if (loop->stopped) {
    (void)pthread_mutex_unlock(&loop->mutex);
    return FTUN_E_CANCELLED;
  }
  if (loop->backend != NULL) {
    (void)pthread_mutex_unlock(&loop->mutex);
    return FTUN_E_AGAIN;
  }
  loop->wakeup = wakeup;
  loop->wakeup_user = user;
  if (wakeup != NULL && loop->deferred_count != 0u) {
    loop->wakeups++;
    wakeup(user);
  }
  (void)pthread_mutex_unlock(&loop->mutex);
  return FTUN_OK;
}

static int ftun_event_backend_ops_valid(const ftun_event_backend_ops_t *ops)
{
  return ops != NULL && ops->io_start != NULL && ops->io_update != NULL &&
    ops->timer_start != NULL &&
    ops->source_cancel != NULL && ops->wakeup != NULL && ops->run_once != NULL &&
    ops->stop != NULL && ops->destroy != NULL;
}

ftun_status_t ftun_event_loop_attach_backend(ftun_event_loop_t *loop,
                                             const ftun_event_backend_ops_t *ops,
                                             void *context)
{
  if (loop == NULL || !ftun_event_backend_ops_valid(ops) || context == NULL) {
    return FTUN_E_INVALID;
  }
  (void)pthread_mutex_lock(&loop->mutex);
  if (!loop->accepting || loop->stopped) {
    (void)pthread_mutex_unlock(&loop->mutex);
    return FTUN_E_CANCELLED;
  }
  if (loop->backend != NULL || loop->wakeup != NULL || loop->source_count != 0u ||
      loop->deferred_count != 0u) {
    (void)pthread_mutex_unlock(&loop->mutex);
    return FTUN_E_AGAIN;
  }
  loop->backend = ops;
  loop->backend_context = context;
  (void)pthread_mutex_unlock(&loop->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_event_loop_backend_context(ftun_event_loop_t *loop,
                                              const ftun_event_backend_ops_t *ops,
                                              void **out)
{
  if (out != NULL) *out = NULL;
  if (loop == NULL || ops == NULL || out == NULL) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&loop->mutex);
  if (loop->backend != ops || loop->backend_context == NULL) {
    (void)pthread_mutex_unlock(&loop->mutex);
    return FTUN_E_UNSUPPORTED;
  }
  *out = loop->backend_context;
  (void)pthread_mutex_unlock(&loop->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_event_loop_detach_backend(ftun_event_loop_t *loop)
{
  const ftun_event_backend_ops_t *backend;
  void *context;
  if (loop == NULL) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&loop->mutex);
  if (loop->backend == NULL) {
    (void)pthread_mutex_unlock(&loop->mutex);
    return FTUN_OK;
  }
  if (!loop->stopped || loop->dispatching || loop->source_count != 0u ||
      loop->deferred_count != 0u) {
    (void)pthread_mutex_unlock(&loop->mutex);
    return FTUN_E_AGAIN;
  }
  backend = loop->backend;
  context = loop->backend_context;
  loop->backend = NULL;
  loop->backend_context = NULL;
  (void)pthread_mutex_unlock(&loop->mutex);
  backend->destroy(context);
  return FTUN_OK;
}

static ftun_status_t ftun_event_source_add(ftun_event_loop_t *loop,
                                           ftun_event_source_kind_t kind,
                                           ftun_event_callback_fn callback, void *user,
                                           ftun_event_source_t **out)
{
  ftun_event_source_t *source;
  if (out != NULL) *out = NULL;
  if (loop == NULL || callback == NULL || out == NULL) return FTUN_E_INVALID;
  if (!loop->accepting) return FTUN_E_CANCELLED;
  if (loop->source_count >= loop->source_capacity) return FTUN_E_LIMIT;
  source = (ftun_event_source_t *)calloc(1u, sizeof(*source));
  if (source == NULL) return FTUN_E_LIMIT;
  source->loop = loop;
  source->kind = kind;
  source->callback = callback;
  source->user = user;
  source->active = 1;
  source->next = loop->sources;
  if (loop->sources != NULL) loop->sources->previous = source;
  loop->sources = source;
  loop->source_count++;
  *out = source;
  return FTUN_OK;
}

static void ftun_event_source_unlink(ftun_event_source_t *source)
{
  ftun_event_loop_t *loop = source->loop;
  if (source->previous != NULL) source->previous->next = source->next;
  else loop->sources = source->next;
  if (source->next != NULL) source->next->previous = source->previous;
  loop->source_count--;
  source->loop = NULL;
  source->previous = NULL;
  source->next = NULL;
}

static void ftun_event_ready_unlink(ftun_event_source_t *source)
{
  ftun_event_loop_t *loop;
  if (source == NULL || !source->in_ready || source->loop == NULL) return;
  loop = source->loop;
  if (source->ready_previous != NULL) {
    source->ready_previous->ready_next = source->ready_next;
  } else {
    loop->ready_head = source->ready_next;
  }
  if (source->ready_next != NULL) {
    source->ready_next->ready_previous = source->ready_previous;
  } else {
    loop->ready_tail = source->ready_previous;
  }
  source->ready_previous = NULL;
  source->ready_next = NULL;
  source->in_ready = 0;
  if (loop->ready_count != 0u) loop->ready_count--;
}

static void ftun_event_ready_enqueue(ftun_event_source_t *source)
{
  ftun_event_loop_t *loop;
  if (source == NULL || source->loop == NULL || !source->active ||
      source->pending == 0u || source->in_ready) return;
  loop = source->loop;
  source->ready_previous = loop->ready_tail;
  if (loop->ready_tail != NULL) loop->ready_tail->ready_next = source;
  else loop->ready_head = source;
  loop->ready_tail = source;
  source->in_ready = 1;
  loop->ready_count++;
}

ftun_status_t ftun_event_io_start(ftun_event_loop_t *loop, ftun_native_socket_t socket,
                                  uint32_t interests, ftun_event_callback_fn callback,
                                  void *user, ftun_event_source_t **out)
{
  ftun_event_source_t *source;
  ftun_status_t status;
  uint32_t allowed = FTUN_EVENT_READ | FTUN_EVENT_WRITE | FTUN_EVENT_ERROR;
  if (out != NULL) *out = NULL;
  if (out == NULL || interests == 0u || (interests & ~allowed) != 0u) {
    return FTUN_E_INVALID;
  }
  status = ftun_event_source_add(loop, FTUN_EVENT_SOURCE_IO, callback, user, &source);
  if (status != FTUN_OK) return status;
  source->socket = socket;
  source->interests = interests;
  if (loop->backend != NULL) {
    status = loop->backend->io_start(loop->backend_context, source, socket, interests);
    if (status != FTUN_OK) {
      ftun_event_source_unlink(source);
      free(source);
      return status;
    }
  }
  *out = source;
  return FTUN_OK;
}

ftun_status_t ftun_event_timer_start(ftun_event_loop_t *loop, uint64_t deadline_ms,
                                     ftun_event_callback_fn callback, void *user,
                                     ftun_event_source_t **out)
{
  ftun_event_source_t *source;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (out == NULL) return FTUN_E_INVALID;
  status = ftun_event_source_add(loop, FTUN_EVENT_SOURCE_TIMER,
                                 callback, user, &source);
  if (status != FTUN_OK) return status;
  source->deadline_ms = deadline_ms;
  if (loop->backend != NULL) {
    status = loop->backend->timer_start(loop->backend_context, source, deadline_ms);
    if (status != FTUN_OK) {
      ftun_event_source_unlink(source);
      free(source);
      return status;
    }
  }
  *out = source;
  return FTUN_OK;
}

ftun_status_t ftun_event_io_update(ftun_event_source_t *source,
                                   uint32_t interests)
{
  const uint32_t allowed = FTUN_EVENT_READ | FTUN_EVENT_WRITE |
                           FTUN_EVENT_ERROR;
  ftun_event_loop_t *loop;
  ftun_status_t status;
  if (source == NULL || source->loop == NULL ||
      source->kind != FTUN_EVENT_SOURCE_IO || interests == 0u ||
      (interests & ~allowed) != 0u) return FTUN_E_INVALID;
  if (!source->active) return FTUN_E_STALE;
  if (source->interests == interests) return FTUN_OK;
  loop = source->loop;
  if (loop->backend != NULL) {
    status = loop->backend->io_update(loop->backend_context, source,
                                      interests);
    if (status != FTUN_OK) return status;
  }
  source->interests = interests;
  source->pending &= interests;
  if (source->pending == 0u) ftun_event_ready_unlink(source);
  else ftun_event_ready_enqueue(source);
  return FTUN_OK;
}

ftun_status_t ftun_event_source_backend_data(ftun_event_source_t *source,
                                             void **out)
{
  if (out != NULL) *out = NULL;
  if (source == NULL || source->loop == NULL || out == NULL) {
    return FTUN_E_INVALID;
  }
  *out = source->backend_data;
  return FTUN_OK;
}

ftun_status_t ftun_event_source_set_backend_data(ftun_event_source_t *source,
                                                 void *data)
{
  if (source == NULL || source->loop == NULL) return FTUN_E_INVALID;
  source->backend_data = data;
  return FTUN_OK;
}

ftun_status_t ftun_event_io_ready(ftun_event_source_t *source, uint32_t events)
{
  uint32_t allowed = FTUN_EVENT_READ | FTUN_EVENT_WRITE | FTUN_EVENT_ERROR;
  if (source == NULL || source->loop == NULL || source->kind != FTUN_EVENT_SOURCE_IO ||
      events == 0u || (events & ~allowed) != 0u) return FTUN_E_INVALID;
  if (!source->active) return FTUN_E_STALE;
  source->pending |= events & source->interests;
  ftun_event_ready_enqueue(source);
  return FTUN_OK;
}

ftun_status_t ftun_event_timer_ready(ftun_event_source_t *source)
{
  if (source == NULL || source->loop == NULL ||
      source->kind != FTUN_EVENT_SOURCE_TIMER) return FTUN_E_INVALID;
  if (!source->active) return FTUN_E_STALE;
  source->pending = FTUN_EVENT_TIMER;
  ftun_event_ready_enqueue(source);
  return FTUN_OK;
}

ftun_status_t ftun_event_defer(ftun_event_loop_t *loop,
                               ftun_event_deferred_fn callback, void *user)
{
  int needs_wakeup;
  if (loop == NULL || callback == NULL) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&loop->mutex);
  if (!loop->accepting) {
    (void)pthread_mutex_unlock(&loop->mutex);
    return FTUN_E_CANCELLED;
  }
  if (loop->deferred_count >= FTUN_EVENT_DEFERRED_CAPACITY) {
    (void)pthread_mutex_unlock(&loop->mutex);
    return FTUN_E_LIMIT;
  }
  needs_wakeup = loop->deferred_count == 0u;
  loop->deferred[loop->deferred_tail].callback = callback;
  loop->deferred[loop->deferred_tail].user = user;
  loop->deferred_tail = (loop->deferred_tail + 1u) % FTUN_EVENT_DEFERRED_CAPACITY;
  loop->deferred_count++;
  if (needs_wakeup && loop->backend != NULL) {
    loop->wakeups++;
    loop->backend->wakeup(loop->backend_context);
  } else if (needs_wakeup && loop->wakeup != NULL) {
    loop->wakeups++;
    loop->wakeup(loop->wakeup_user);
  }
  (void)pthread_mutex_unlock(&loop->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_event_loop_wakeup(ftun_event_loop_t *loop)
{
  if (loop == NULL) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&loop->mutex);
  if (loop->stopped) {
    (void)pthread_mutex_unlock(&loop->mutex);
    return FTUN_E_CANCELLED;
  }
  if (loop->backend != NULL) {
    loop->wakeups++;
    loop->backend->wakeup(loop->backend_context);
  } else if (loop->wakeup != NULL) {
    loop->wakeups++;
    loop->wakeup(loop->wakeup_user);
  }
  (void)pthread_mutex_unlock(&loop->mutex);
  return FTUN_OK;
}

static int ftun_event_pop_deferred(ftun_event_loop_t *loop,
                                   ftun_event_deferred_t *out)
{
  int found = 0;
  (void)pthread_mutex_lock(&loop->mutex);
  if (loop->deferred_count != 0u) {
    *out = loop->deferred[loop->deferred_head];
    memset(&loop->deferred[loop->deferred_head], 0,
           sizeof(loop->deferred[loop->deferred_head]));
    loop->deferred_head = (loop->deferred_head + 1u) % FTUN_EVENT_DEFERRED_CAPACITY;
    loop->deferred_count--;
    found = 1;
  }
  (void)pthread_mutex_unlock(&loop->mutex);
  return found;
}

static void ftun_event_queue_expired_timers(ftun_event_loop_t *loop,
                                             uint64_t now_ms)
{
  ftun_event_source_t *source;
  for (source = loop->sources; source != NULL; source = source->next) {
    if (source->active && source->kind == FTUN_EVENT_SOURCE_TIMER &&
        now_ms >= source->deadline_ms) {
      source->pending = FTUN_EVENT_TIMER;
      ftun_event_ready_enqueue(source);
    }
  }
}

static ftun_event_source_t *ftun_event_ready_source(ftun_event_loop_t *loop,
                                                     uint32_t *events)
{
  ftun_event_source_t *source = loop->ready_head;
  if (source == NULL) return NULL;
  *events = source->pending;
  source->pending = 0u;
  ftun_event_ready_unlink(source);
  if (source->kind == FTUN_EVENT_SOURCE_TIMER) source->active = 0;
  return source;
}

ftun_status_t ftun_event_loop_poll(ftun_event_loop_t *loop, uint64_t now_ms,
                                   size_t max_callbacks, size_t *out_callbacks)
{
  uint64_t started_ms = 0u;
  uint64_t finished_ms = 0u;
  size_t callbacks = 0u;
  if (out_callbacks != NULL) *out_callbacks = 0u;
  if (loop == NULL || max_callbacks == 0u || out_callbacks == NULL) {
    return FTUN_E_INVALID;
  }
  if (loop->dispatching) return FTUN_E_AGAIN;
  loop->dispatching = 1;
  (void)ftun_monotonic_now(&started_ms);
  /* A direct poll without a backend still owns timer expiry and therefore
   * performs one bounded scan.  Production backends enqueue timer readiness
   * themselves, so the hot dispatch path only performs O(1) ready pops. */
  if (loop->backend == NULL || !loop->backend->native_timers) {
    ftun_event_queue_expired_timers(loop, now_ms);
  }
  while (callbacks < max_callbacks) {
    ftun_event_deferred_t deferred;
    ftun_event_source_t *source;
    uint32_t events = 0u;
    int have_deferred = 0;
    if (loop->prefer_deferred) {
      have_deferred = ftun_event_pop_deferred(loop, &deferred);
      if (!have_deferred) source = ftun_event_ready_source(loop, &events);
      else source = NULL;
    } else {
      source = ftun_event_ready_source(loop, &events);
      if (source == NULL) have_deferred = ftun_event_pop_deferred(loop,
                                                                  &deferred);
    }
    if (!have_deferred && source == NULL) break;
    loop->prefer_deferred = !loop->prefer_deferred;
    if (have_deferred) {
      deferred.callback(deferred.user);
    } else {
      if (source->kind == FTUN_EVENT_SOURCE_TIMER &&
          now_ms > source->deadline_ms &&
          now_ms - source->deadline_ms > loop->max_timer_lateness_ms) {
        loop->max_timer_lateness_ms = now_ms - source->deadline_ms;
      }
      source->callback(source, events, source->user);
    }
    callbacks++;
  }
  loop->dispatching = 0;
  loop->polls++;
  if (UINT64_MAX - loop->callbacks < callbacks) loop->callbacks = UINT64_MAX;
  else loop->callbacks += callbacks;
  if (callbacks > loop->max_callbacks_per_poll) {
    loop->max_callbacks_per_poll = callbacks;
  }
  if (callbacks == max_callbacks &&
      (loop->ready_count != 0u || loop->deferred_count != 0u)) {
    if (loop->quota_exhaustions != UINT64_MAX) loop->quota_exhaustions++;
  }
  if (ftun_monotonic_now(&finished_ms) == FTUN_OK &&
      finished_ms >= started_ms) {
    loop->last_dispatch_ms = finished_ms - started_ms;
    if (loop->last_dispatch_ms > loop->max_dispatch_ms) {
      loop->max_dispatch_ms = loop->last_dispatch_ms;
    }
  }
  (void)pthread_mutex_lock(&loop->mutex);
  if (loop->deferred_count != 0u && loop->backend != NULL) {
    loop->wakeups++;
    loop->backend->wakeup(loop->backend_context);
  } else if (loop->deferred_count != 0u && loop->wakeup != NULL) {
    loop->wakeups++;
    loop->wakeup(loop->wakeup_user);
  }
  (void)pthread_mutex_unlock(&loop->mutex);
  *out_callbacks = callbacks;
  return FTUN_OK;
}

ftun_status_t ftun_event_loop_run_once(ftun_event_loop_t *loop, bool block,
                                       size_t max_callbacks, size_t *out_callbacks)
{
  ftun_status_t status;
  uint64_t now_ms = 0u;
  if (out_callbacks != NULL) *out_callbacks = 0u;
  if (loop == NULL || max_callbacks == 0u || out_callbacks == NULL) {
    return FTUN_E_INVALID;
  }
  if (loop->backend == NULL) return FTUN_E_UNSUPPORTED;
  if (loop->stopped) return FTUN_E_CANCELLED;
  /* A retained ready/deferred item already is a wakeup source.  Never enter
   * the backend in blocking mode after a quota-limited dispatch left work. */
  (void)pthread_mutex_lock(&loop->mutex);
  if (loop->deferred_count != 0u) block = false;
  (void)pthread_mutex_unlock(&loop->mutex);
  if (loop->ready_count != 0u) block = false;
  status = loop->backend->run_once(loop->backend_context, block);
  if (status != FTUN_OK) return status;
  status = ftun_monotonic_now(&now_ms);
  if (status != FTUN_OK) return status;
  return ftun_event_loop_poll(loop, now_ms, max_callbacks, out_callbacks);
}

ftun_status_t ftun_event_source_cancel(ftun_event_source_t **source)
{
  ftun_event_source_t *owned;
  ftun_event_loop_t *loop;
  ftun_status_t status;
  if (source == NULL) return FTUN_E_INVALID;
  owned = *source;
  if (owned == NULL) return FTUN_OK;
  loop = owned->loop;
  if (loop == NULL || loop->source_count == 0u) return FTUN_E_STATE_CORRUPT;
  if (loop->backend != NULL) {
    status = loop->backend->source_cancel(loop->backend_context, owned);
    if (status != FTUN_OK) return status;
  }
  ftun_event_ready_unlink(owned);
  ftun_event_source_unlink(owned);
  owned->backend_data = NULL;
  owned->callback = NULL;
  owned->user = NULL;
  free(owned);
  *source = NULL;
  return FTUN_OK;
}

ftun_status_t ftun_event_loop_stop(ftun_event_loop_t *loop)
{
  ftun_event_source_t *source;
  int first_stop;
  if (loop == NULL) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&loop->mutex);
  first_stop = !loop->stopped;
  loop->accepting = 0;
  loop->stopped = 1;
  loop->wakeup = NULL;
  loop->wakeup_user = NULL;
  if (first_stop && loop->backend != NULL) {
    loop->backend->stop(loop->backend_context);
  }
  (void)pthread_mutex_unlock(&loop->mutex);
  for (source = loop->sources; source != NULL; source = source->next) {
    source->active = 0;
    source->pending = 0u;
    source->ready_previous = NULL;
    source->ready_next = NULL;
    source->in_ready = 0;
  }
  loop->ready_head = NULL;
  loop->ready_tail = NULL;
  loop->ready_count = 0u;
  return FTUN_OK;
}

ftun_status_t ftun_event_loop_get_usage(ftun_event_loop_t *loop,
                                        ftun_event_loop_usage_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (loop == NULL || out == NULL) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&loop->mutex);
  out->deferred_capacity = FTUN_EVENT_DEFERRED_CAPACITY;
  out->deferred_count = loop->deferred_count;
  out->source_capacity = loop->source_capacity;
  out->source_count = loop->source_count;
  out->ready_count = loop->ready_count;
  out->wakeups = loop->wakeups;
  out->polls = loop->polls;
  out->callbacks = loop->callbacks;
  out->quota_exhaustions = loop->quota_exhaustions;
  out->last_dispatch_ms = loop->last_dispatch_ms;
  out->max_dispatch_ms = loop->max_dispatch_ms;
  out->max_timer_lateness_ms = loop->max_timer_lateness_ms;
  out->max_callbacks_per_poll = loop->max_callbacks_per_poll;
  out->accepting = loop->accepting != 0;
  out->dispatching = loop->dispatching != 0;
  out->stopped = loop->stopped != 0;
  out->backend_attached = loop->backend != NULL;
  (void)pthread_mutex_unlock(&loop->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_event_loop_destroy(ftun_event_loop_t **loop)
{
  ftun_event_loop_t *owned;
  if (loop == NULL) return FTUN_E_INVALID;
  owned = *loop;
  if (owned == NULL) return FTUN_OK;
  (void)pthread_mutex_lock(&owned->mutex);
  if (!owned->stopped || owned->dispatching || owned->deferred_count != 0u ||
      owned->source_count != 0u || owned->backend != NULL) {
    (void)pthread_mutex_unlock(&owned->mutex);
    return FTUN_E_AGAIN;
  }
  (void)pthread_mutex_unlock(&owned->mutex);
  if (owned->sources != NULL) return FTUN_E_STATE_CORRUPT;
  if (owned->ready_head != NULL || owned->ready_tail != NULL ||
      owned->ready_count != 0u) return FTUN_E_STATE_CORRUPT;
  if (pthread_mutex_destroy(&owned->mutex) != 0) return FTUN_E_STATE_CORRUPT;
  owned->core = NULL;
  free(owned);
  *loop = NULL;
  return FTUN_OK;
}
