#include "libev_adapter.h"
#include "event/event.h"
#include "util/time.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#if defined(FTUN_HAVE_LIBEV)
#include <signal.h>
/* libev 允许调用方提供跨线程原子类型；Linux 构建使用编译器原子扩展，
 * 避免默认 volatile sig_atomic_t 在 C 内存模型下形成数据竞态。 */
#define EV_ATOMIC_T _Atomic sig_atomic_t
#include <ev.h>
#undef EV_ATOMIC_T

typedef enum {
  FTUN_LIBEV_IO = 1,
  FTUN_LIBEV_TIMER
} ftun_libev_watcher_kind_t;

typedef struct ftun_libev_watcher ftun_libev_watcher_t;

typedef struct {
  ftun_event_loop_t *front;
  struct ev_loop *loop;
  ev_async async;
  ftun_libev_watcher_t *watchers;
  ftun_status_t pending_error;
  int stopped;
} ftun_libev_adapter_t;

struct ftun_libev_watcher {
  ftun_libev_adapter_t *adapter;
  ftun_libev_watcher_t *previous;
  ftun_libev_watcher_t *next;
  ftun_event_source_t *source;
  ftun_libev_watcher_kind_t kind;
  ev_io io;
  ev_timer timer;
};

static void ftun_libev_record(ftun_libev_adapter_t *adapter, ftun_status_t status)
{
  if (status != FTUN_OK && adapter->pending_error == FTUN_OK) {
    adapter->pending_error = status;
  }
}

static void ftun_libev_io_callback(EV_P_ ev_io *io, int revents)
{
  ftun_libev_watcher_t *watcher = (ftun_libev_watcher_t *)io->data;
  uint32_t events = 0u;
  (void)loop;
  if ((revents & EV_READ) != 0) events |= FTUN_EVENT_READ;
  if ((revents & EV_WRITE) != 0) events |= FTUN_EVENT_WRITE;
  if ((revents & EV_ERROR) != 0) events |= FTUN_EVENT_ERROR;
  if (events != 0u) {
    ftun_libev_record(watcher->adapter,
                      ftun_event_io_ready(watcher->source, events));
  }
}

static void ftun_libev_timer_callback(EV_P_ ev_timer *timer, int revents)
{
  ftun_libev_watcher_t *watcher = (ftun_libev_watcher_t *)timer->data;
  (void)loop;
  (void)revents;
  ftun_libev_record(watcher->adapter, ftun_event_timer_ready(watcher->source));
}

static void ftun_libev_async_callback(EV_P_ ev_async *async, int revents)
{
  (void)loop;
  (void)async;
  (void)revents;
}

static int ftun_libev_events(uint32_t interests)
{
  int events = 0;
  if ((interests & FTUN_EVENT_READ) != 0u) events |= EV_READ;
  if ((interests & FTUN_EVENT_WRITE) != 0u) events |= EV_WRITE;
  return events;
}

static ftun_status_t ftun_libev_io_start(void *context, ftun_event_source_t *source,
                                         ftun_native_socket_t socket,
                                         uint32_t interests)
{
  ftun_libev_adapter_t *adapter = (ftun_libev_adapter_t *)context;
  ftun_libev_watcher_t *watcher;
  int events = ftun_libev_events(interests);
  if (socket > (ftun_native_socket_t)INT_MAX) return FTUN_E_INVALID;
  watcher = (ftun_libev_watcher_t *)calloc(1u, sizeof(*watcher));
  if (watcher == NULL) return FTUN_E_LIMIT;
  watcher->adapter = adapter;
  watcher->source = source;
  watcher->kind = FTUN_LIBEV_IO;
  ev_io_init(&watcher->io, ftun_libev_io_callback, (int)socket,
             events == 0 ? EV_READ : events);
  watcher->io.data = watcher;
  if (events != 0) ev_io_start(adapter->loop, &watcher->io);
  watcher->next = adapter->watchers;
  if (watcher->next != NULL) watcher->next->previous = watcher;
  adapter->watchers = watcher;
  if (ftun_event_source_set_backend_data(source, watcher) != FTUN_OK) {
    ev_io_stop(adapter->loop, &watcher->io);
    adapter->watchers = watcher->next;
    if (adapter->watchers != NULL) adapter->watchers->previous = NULL;
    free(watcher);
    return FTUN_E_STATE_CORRUPT;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_libev_io_update(void *context,
                                          ftun_event_source_t *source,
                                          uint32_t interests)
{
  ftun_libev_adapter_t *adapter = (ftun_libev_adapter_t *)context;
  ftun_libev_watcher_t *watcher = NULL;
  int events = ftun_libev_events(interests);
  if (ftun_event_source_backend_data(source, (void **)&watcher) != FTUN_OK ||
      watcher == NULL ||
      watcher->adapter != adapter || watcher->kind != FTUN_LIBEV_IO) {
    return FTUN_E_INVALID;
  }
  if (ev_is_active(&watcher->io)) ev_io_stop(adapter->loop, &watcher->io);
  if (events != 0) {
    ev_io_set(&watcher->io, watcher->io.fd, events);
    ev_io_start(adapter->loop, &watcher->io);
  }
  return FTUN_OK;
}

static ftun_status_t ftun_libev_timer_start(void *context,
                                            ftun_event_source_t *source,
                                            uint64_t deadline_ms)
{
  ftun_libev_adapter_t *adapter = (ftun_libev_adapter_t *)context;
  ftun_libev_watcher_t *watcher;
  uint64_t now_ms = 0u;
  ev_tstamp after;
  ftun_status_t status = ftun_monotonic_now(&now_ms);
  if (status != FTUN_OK) return status;
  after = deadline_ms > now_ms ? (ev_tstamp)(deadline_ms - now_ms) / 1000.0 : 0.0;
  watcher = (ftun_libev_watcher_t *)calloc(1u, sizeof(*watcher));
  if (watcher == NULL) return FTUN_E_LIMIT;
  watcher->adapter = adapter;
  watcher->source = source;
  watcher->kind = FTUN_LIBEV_TIMER;
  ev_timer_init(&watcher->timer, ftun_libev_timer_callback, after, 0.0);
  watcher->timer.data = watcher;
  ev_timer_start(adapter->loop, &watcher->timer);
  watcher->next = adapter->watchers;
  if (watcher->next != NULL) watcher->next->previous = watcher;
  adapter->watchers = watcher;
  if (ftun_event_source_set_backend_data(source, watcher) != FTUN_OK) {
    ev_timer_stop(adapter->loop, &watcher->timer);
    adapter->watchers = watcher->next;
    if (adapter->watchers != NULL) adapter->watchers->previous = NULL;
    free(watcher);
    return FTUN_E_STATE_CORRUPT;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_libev_source_cancel(void *context,
                                              ftun_event_source_t *source)
{
  ftun_libev_adapter_t *adapter = (ftun_libev_adapter_t *)context;
  ftun_libev_watcher_t *watcher = NULL;
  if (ftun_event_source_backend_data(source, (void **)&watcher) != FTUN_OK ||
      watcher == NULL || watcher->adapter != adapter) {
    return FTUN_E_STATE_CORRUPT;
  }
  if (watcher->kind == FTUN_LIBEV_IO) ev_io_stop(adapter->loop, &watcher->io);
  else ev_timer_stop(adapter->loop, &watcher->timer);
  if (watcher->previous != NULL) watcher->previous->next = watcher->next;
  else adapter->watchers = watcher->next;
  if (watcher->next != NULL) watcher->next->previous = watcher->previous;
  (void)ftun_event_source_set_backend_data(source, NULL);
  watcher->source = NULL;
  watcher->adapter = NULL;
  watcher->previous = NULL;
  watcher->next = NULL;
  free(watcher);
  return FTUN_OK;
}

static void ftun_libev_wakeup(void *context)
{
  ftun_libev_adapter_t *adapter = (ftun_libev_adapter_t *)context;
  ev_async_send(adapter->loop, &adapter->async);
}

static ftun_status_t ftun_libev_run_once(void *context, bool block)
{
  ftun_libev_adapter_t *adapter = (ftun_libev_adapter_t *)context;
  if (adapter->stopped) return FTUN_E_CANCELLED;
  adapter->pending_error = FTUN_OK;
  (void)ev_run(adapter->loop, block ? EVRUN_ONCE : EVRUN_NOWAIT);
  return adapter->pending_error;
}

static void ftun_libev_stop(void *context)
{
  ftun_libev_adapter_t *adapter = (ftun_libev_adapter_t *)context;
  adapter->stopped = 1;
  ev_break(adapter->loop, EVBREAK_ALL);
  ev_async_send(adapter->loop, &adapter->async);
}

static void ftun_libev_destroy(void *context)
{
  ftun_libev_adapter_t *adapter = (ftun_libev_adapter_t *)context;
  while (adapter->watchers != NULL) {
    ftun_libev_watcher_t *watcher = adapter->watchers;
    adapter->watchers = watcher->next;
    if (watcher->kind == FTUN_LIBEV_IO) ev_io_stop(adapter->loop, &watcher->io);
    else ev_timer_stop(adapter->loop, &watcher->timer);
    free(watcher);
  }
  ev_async_stop(adapter->loop, &adapter->async);
  ev_loop_destroy(adapter->loop);
  adapter->front = NULL;
  adapter->loop = NULL;
  free(adapter);
}

static const ftun_event_backend_ops_t ftun_libev_ops = {
  ftun_libev_io_start,
  ftun_libev_io_update,
  ftun_libev_timer_start,
  ftun_libev_source_cancel,
  ftun_libev_wakeup,
  ftun_libev_run_once,
  ftun_libev_stop,
  ftun_libev_destroy,
  true
};

/* TASK-EVENT-002 / TEST-EVENT-002，目标 0.2.0：完整 libev 4.33 epoll 适配。 */
ftun_status_t ftun_libev_attach(ftun_event_loop_t *loop)
{
  ftun_libev_adapter_t *adapter;
  ftun_status_t status;
  if (loop == NULL) return FTUN_E_INVALID;
  adapter = (ftun_libev_adapter_t *)calloc(1u, sizeof(*adapter));
  if (adapter == NULL) return FTUN_E_LIMIT;
  adapter->front = loop;
  adapter->loop = ev_loop_new(EVFLAG_NOENV | EVBACKEND_EPOLL);
  if (adapter->loop == NULL || ev_backend(adapter->loop) != EVBACKEND_EPOLL) {
    if (adapter->loop != NULL) ev_loop_destroy(adapter->loop);
    free(adapter);
    return FTUN_E_UNSUPPORTED;
  }
  ev_async_init(&adapter->async, ftun_libev_async_callback);
  adapter->async.data = adapter;
  ev_async_start(adapter->loop, &adapter->async);
  status = ftun_event_loop_attach_backend(loop, &ftun_libev_ops, adapter);
  if (status != FTUN_OK) {
    ev_async_stop(adapter->loop, &adapter->async);
    ev_loop_destroy(adapter->loop);
    free(adapter);
    return status;
  }
  return FTUN_OK;
}

ftun_status_t ftun_libev_get_info(ftun_event_loop_t *loop, ftun_libev_info_t *out)
{
  void *context = NULL;
  ftun_status_t status;
  int version_major;
  int version_minor;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (loop == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_event_loop_backend_context(loop, &ftun_libev_ops, &context);
  if (status != FTUN_OK) return status;
  version_major = ev_version_major();
  version_minor = ev_version_minor();
  if (version_major < 0 || version_minor < 0) return FTUN_E_STATE_CORRUPT;
  out->version_major = (unsigned int)version_major;
  out->version_minor = (unsigned int)version_minor;
  out->backend = "epoll";
  out->async_thread_safe = true;
  return FTUN_OK;
}

ftun_status_t ftun_libev_detach(ftun_event_loop_t *loop)
{
  void *context = NULL;
  ftun_status_t status;
  if (loop == NULL) return FTUN_E_INVALID;
  status = ftun_event_loop_backend_context(loop, &ftun_libev_ops, &context);
  if (status == FTUN_E_UNSUPPORTED) return FTUN_OK;
  if (status != FTUN_OK) return status;
  (void)context;
  return ftun_event_loop_detach_backend(loop);
}

#else

ftun_status_t ftun_libev_attach(ftun_event_loop_t *loop)
{
  return loop == NULL ? FTUN_E_INVALID : FTUN_E_UNSUPPORTED;
}

ftun_status_t ftun_libev_get_info(ftun_event_loop_t *loop, ftun_libev_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  return loop == NULL || out == NULL ? FTUN_E_INVALID : FTUN_E_UNSUPPORTED;
}

ftun_status_t ftun_libev_detach(ftun_event_loop_t *loop)
{
  return loop == NULL ? FTUN_E_INVALID : FTUN_OK;
}

#endif
