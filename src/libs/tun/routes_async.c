#include "libs/tun/routes_internal.h"
#include "core/event/loop.h"
#include <stdlib.h>

struct ftun_route_async {
  ftun_platform_route_async_t *native;
  ftun_event_loop_t *loop;
  ftun_event_source_t *io, *timer;
  ftun_route_notify_fn io_notify, timer_notify;
  void *io_user, *timer_user;
};
size_t ftun_route_async_allocation_size(void)
{ return sizeof(ftun_route_async_t) + ftun_platform_route_async_allocation_size(); }
static void io_ready(ftun_event_source_t *source, uint32_t events, void *user)
{
  ftun_route_async_t *owned = user;
  uint32_t ready = ((events & FTUN_EVENT_READ) ? FTUN_POLLER_READ : 0u) |
    ((events & FTUN_EVENT_WRITE) ? FTUN_POLLER_WRITE : 0u) |
    ((events & FTUN_EVENT_ERROR) ? FTUN_POLLER_ERROR : 0u);
  (void)source;
  owned->io_notify(owned->io_user, ready);
}
static void timer_ready(ftun_event_source_t *source, uint32_t events, void *user)
{
  ftun_route_async_t *owned = user;
  (void)source;
  if (events & FTUN_EVENT_TIMER) owned->timer_notify(owned->timer_user, FTUN_ROUTE_TIMER);
}
static uint32_t interests(uint32_t events)
{
  return ((events & FTUN_POLLER_READ) ? FTUN_EVENT_READ : 0u) |
    ((events & FTUN_POLLER_WRITE) ? FTUN_EVENT_WRITE : 0u) |
    ((events & FTUN_POLLER_ERROR) ? FTUN_EVENT_ERROR : 0u);
}
static ftun_status_t watch(void *context, ftun_native_socket_t socket,
  uint32_t events, ftun_route_notify_fn notify, void *user)
{
  ftun_route_async_t *owned = context;
  owned->io_notify = notify; owned->io_user = user;
  return ftun_event_io_start(owned->loop, socket, interests(events), io_ready, owned, &owned->io);
}
static ftun_status_t update(void *context, uint32_t events)
{
  ftun_route_async_t *owned = context;
  return ftun_event_io_update(owned->io, interests(events));
}
static ftun_status_t unwatch(void *context)
{ return ftun_event_source_cancel(&((ftun_route_async_t *)context)->io); }
static ftun_status_t timer(void *context, uint64_t deadline,
  ftun_route_notify_fn notify, void *user)
{
  ftun_route_async_t *owned = context;
  owned->timer_notify = notify; owned->timer_user = user;
  return ftun_event_timer_start(owned->loop, deadline, timer_ready, owned, &owned->timer);
}
static ftun_status_t untimer(void *context)
{ return ftun_event_source_cancel(&((ftun_route_async_t *)context)->timer); }
static ftun_route_events_t events(ftun_route_async_t *owned)
{ return (ftun_route_events_t){watch, update, unwatch, timer, untimer, owned}; }
static ftun_status_t publish(ftun_route_async_t *owned,
  ftun_status_t status, ftun_route_async_t **out)
{
  if (status == FTUN_OK) *out = owned;
  else free(owned);
  return status;
}

ftun_status_t ftun_route_async_start(
  const ftun_route_policy_t *policy, ftun_event_loop_t *loop,
  uint64_t now, uint64_t step, uint64_t deadline, ftun_route_async_t **out)
{
  ftun_route_async_t *owned;
  ftun_status_t status;
  ftun_route_events_t binding;
  if (out == NULL || loop == NULL) return FTUN_E_INVALID;
  *out = NULL;
  owned = calloc(1u, sizeof(*owned));
  if (owned == NULL) return FTUN_E_LIMIT;
  owned->loop = loop;
  binding = events(owned);
  status = ftun_platform_route_async_start(policy, &binding, now, step, deadline, &owned->native);
  return publish(owned, status, out);
}

ftun_status_t ftun_route_async_start_plan(
  const ftun_route_plan_t *plan, ftun_event_loop_t *loop,
  uint64_t now, uint64_t step, uint64_t deadline, ftun_route_async_t **out)
{
  ftun_route_async_t *owned;
  ftun_status_t status;
  ftun_route_events_t binding;
  if (out == NULL || loop == NULL) return FTUN_E_INVALID;
  *out = NULL;
  owned = calloc(1u, sizeof(*owned));
  if (owned == NULL) return FTUN_E_LIMIT;
  owned->loop = loop;
  binding = events(owned);
  status = ftun_platform_route_async_start_plan(plan, &binding, now, step, deadline, &owned->native);
  return publish(owned, status, out);
}

ftun_status_t ftun_route_async_start_with_io(
  const ftun_route_policy_t *policy, const ftun_route_async_io_t *io,
  uint64_t now, uint64_t step, uint64_t deadline, uint32_t sequence, ftun_route_async_t **out)
{
  ftun_route_async_t *owned;
  ftun_status_t status;

  if (out == NULL) return FTUN_E_INVALID;
  *out = NULL;
  owned = calloc(1u, sizeof(*owned));
  if (owned == NULL) return FTUN_E_LIMIT;
  owned->loop = NULL;

  status = ftun_platform_route_async_start_with_io(policy, io, now, step, deadline, sequence, &owned->native);
  return publish(owned, status, out);
}

ftun_status_t ftun_route_async_start_plan_with_io(
  const ftun_route_plan_t *plan, const ftun_route_async_io_t *io,
  uint64_t now, uint64_t step, uint64_t deadline, uint32_t sequence, ftun_route_async_t **out)
{
  ftun_route_async_t *owned;
  ftun_status_t status;

  if (out == NULL) return FTUN_E_INVALID;
  *out = NULL;
  owned = calloc(1u, sizeof(*owned));
  if (owned == NULL) return FTUN_E_LIMIT;
  owned->loop = NULL;

  status = ftun_platform_route_async_start_plan_with_io(plan, io, now, step, deadline, sequence, &owned->native);
  return publish(owned, status, out);
}

ftun_status_t ftun_route_async_adopt(ftun_route_transaction_t **source,
  ftun_event_loop_t *loop, uint64_t now, uint64_t step, uint64_t deadline, ftun_route_async_t **out)
{
  ftun_route_async_t *owned;
  ftun_route_transaction_t *previous;
  ftun_status_t status;
  ftun_route_events_t binding;
  if (source == NULL || *source == NULL || out == NULL || loop == NULL) return FTUN_E_INVALID;
  *out = NULL;
  previous = *source;
  owned = calloc(1u, sizeof(*owned));
  if (owned == NULL) return FTUN_E_LIMIT;
  owned->loop = loop;
  binding = events(owned);
  status = ftun_platform_route_async_adopt(&previous->native, &binding, now, step, deadline, &owned->native);
  if (status == FTUN_OK) {
    ftun_reservation_release(&previous->reservation);
    free(previous);
    *source = NULL;
  }
  return publish(owned, status, out);
}

ftun_status_t ftun_route_async_adopt_with_io(ftun_route_transaction_t **source,
  const ftun_route_async_io_t *io, uint64_t now, uint64_t step, uint64_t deadline, uint32_t sequence, ftun_route_async_t **out)
{
  ftun_route_async_t *owned;
  ftun_route_transaction_t *previous;
  ftun_status_t status;

  if (source == NULL || *source == NULL || out == NULL) return FTUN_E_INVALID;
  *out = NULL;
  previous = *source;
  owned = calloc(1u, sizeof(*owned));
  if (owned == NULL) return FTUN_E_LIMIT;
  owned->loop = NULL;

  status = ftun_platform_route_async_adopt_with_io(&previous->native, io, now, step, deadline, sequence, &owned->native);
  if (status == FTUN_OK) {
    ftun_reservation_release(&previous->reservation);
    free(previous);
    *source = NULL;
  }
  return publish(owned, status, out);
}

ftun_status_t ftun_route_async_run(ftun_route_async_t *operation, uint64_t now, size_t quota, size_t *work)
{ return ftun_platform_route_async_run(operation == NULL ? NULL : operation->native, now, quota, work); }

ftun_status_t ftun_route_async_next_deadline(const ftun_route_async_t *operation, uint64_t *deadline, bool *present)
{ return ftun_platform_route_async_next_deadline(operation == NULL ? NULL : operation->native, deadline, present); }

ftun_status_t ftun_route_async_get_info(const ftun_route_async_t *operation, ftun_route_async_info_t *out)
{ return ftun_platform_route_async_get_info(operation == NULL ? NULL : operation->native, out); }

ftun_status_t ftun_route_async_repair(ftun_route_async_t *operation, uint64_t now, uint64_t deadline)
{ return ftun_platform_route_async_repair(operation == NULL ? NULL : operation->native, now, deadline); }

ftun_status_t ftun_route_async_release(ftun_route_async_t *operation, uint64_t now, uint64_t deadline)
{ return ftun_platform_route_async_release(operation == NULL ? NULL : operation->native, now, deadline); }

ftun_status_t ftun_route_async_destroy(ftun_route_async_t **operation)
{
  ftun_route_async_t *owned;
  ftun_status_t status;
  if (operation == NULL) return FTUN_E_INVALID;
  owned = *operation;
  if (owned == NULL) return FTUN_OK;
  status = ftun_platform_route_async_destroy(&owned->native);
  if (status != FTUN_OK) return status;
  free(owned);
  *operation = NULL;
  return FTUN_OK;
}
