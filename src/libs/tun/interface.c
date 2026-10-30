#include "libs/tun/interface_backend.h"
#include "libs/tun/routes.h"
#include "libs/tun/routes_internal.h"
#include "core/limits.h"
#include <stdlib.h>
#include <string.h>

static ftun_status_t restore(void *context, const ftun_interface_spec_t *spec, void **state)
{
  ftun_route_policy_t route = {0};
  ftun_route_transaction_t *transaction = NULL;
  ftun_status_t status;
  if (spec == NULL || state == NULL || *state != NULL) return FTUN_E_INVALID;
  route.tun_interface = spec->name;
  memcpy(route.tun_addresses, spec->addresses, sizeof(route.tun_addresses));
  route.tun_address_count = spec->address_count;
  route.routing_domain = spec->route_table;
  route.precedence = spec->rule_priority;
  route.bypass_tag = spec->protection_mark;
  route.bypass_mask = UINT32_MAX;
  route.manage_local = true;
  route.strict_route = spec->strict_route;
  status = context == NULL ? ftun_route_prepare_with_budget(spec->budget, &route, &transaction)
    : ftun_route_prepare_with_io_and_budget(spec->budget, &route, context, &transaction);
  *state = transaction;
  return status;
}

static ftun_status_t withdraw(void *context, void **state)
{
  ftun_route_transaction_t *transaction;
  ftun_status_t status;
  (void)context;
  if (state == NULL) return FTUN_E_INVALID;
  transaction = *state;
  status = ftun_route_release(&transaction);
  *state = transaction;
  return status;
}

typedef struct {
  ftun_route_async_t *operation;
  ftun_reservation_t reservation;
} ftun_linux_interface_async_t;

static ftun_status_t async_allocate(void *context,
  const ftun_interface_async_options_t *options, bool cleanup,
  ftun_linux_interface_async_t **out)
{
  ftun_linux_interface_async_t *state;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_budget_resources_t resources = {
    sizeof(*state) + ftun_route_async_allocation_size(), context == NULL ? 2u : 0u, 0u};
  ftun_status_t status;
  if (options == NULL || options->budget == NULL || options->loop == NULL ||
      options->step_timeout_ms == 0u || options->deadline_ms <= options->now_ms) return FTUN_E_INVALID;
  status = cleanup
    ? ftun_budget_reserve_cleanup_resources(options->budget, resources, &reservation)
    : ftun_budget_reserve_resources(options->budget, resources, &reservation);
  if (status != FTUN_OK) return status;
  state = calloc(1u, sizeof(*state));
  if (state == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  state->reservation = reservation;
  *out = state;
  return FTUN_OK;
}

static ftun_status_t async_publish(ftun_linux_interface_async_t *owned,
  ftun_status_t status, void **out)
{
  if (status != FTUN_OK) {
    ftun_reservation_release(&owned->reservation);
    free(owned);
  } else *out = owned;
  return status;
}

static ftun_status_t async_start(void *context, const ftun_interface_spec_t *spec,
  const ftun_interface_async_options_t *options, void **out)
{
  ftun_linux_interface_async_t *owned = NULL;
  ftun_route_policy_t route = {0};
  ftun_status_t status;
  if (spec == NULL || out == NULL || *out != NULL) return FTUN_E_INVALID;
  status = async_allocate(context, options, false, &owned);
  if (status != FTUN_OK) return status;
  route.tun_interface = spec->name;
  memcpy(route.tun_addresses, spec->addresses, sizeof(route.tun_addresses));
  route.tun_address_count = spec->address_count;
  route.routing_domain = spec->route_table;
  route.precedence = spec->rule_priority;
  route.bypass_tag = spec->protection_mark;
  route.bypass_mask = UINT32_MAX;
  route.manage_local = true;
  route.strict_route = spec->strict_route;
  status = context == NULL
    ? ftun_route_async_start(&route, options->loop, options->now_ms,
        options->step_timeout_ms, options->deadline_ms, &owned->operation)
    : ftun_route_async_start_with_io(&route, context, options->now_ms,
        options->step_timeout_ms, options->deadline_ms, 1u, &owned->operation);
  return async_publish(owned, status, out);
}

static ftun_status_t async_adopt(void *context, void **source,
  const ftun_interface_async_options_t *options, void **out)
{
  ftun_linux_interface_async_t *owned = NULL;
  ftun_route_transaction_t *transaction;
  ftun_status_t status;
  if (source == NULL || *source == NULL || out == NULL || *out != NULL || source == out) return FTUN_E_INVALID;
  status = async_allocate(context, options, true, &owned);
  if (status != FTUN_OK) return status;
  transaction = *source;
  status = context == NULL
    ? ftun_route_async_adopt(&transaction, options->loop, options->now_ms,
        options->step_timeout_ms, options->deadline_ms, &owned->operation)
    : ftun_route_async_adopt_with_io(&transaction, context, options->now_ms,
        options->step_timeout_ms, options->deadline_ms, 1u, &owned->operation);
  *source = transaction;
  return async_publish(owned, status, out);
}

static ftun_status_t async_withdraw(void *context, void *state,
  uint64_t now_ms, uint64_t deadline_ms)
{
  ftun_linux_interface_async_t *owned = state;
  (void)context;
  return owned == NULL ? FTUN_E_INVALID :
    ftun_route_async_release(owned->operation, now_ms, deadline_ms);
}

static ftun_status_t async_run(void *context, void *state, uint64_t now_ms,
  size_t quota, size_t *out_work)
{
  ftun_linux_interface_async_t *owned = state;
  (void)context;
  if (out_work != NULL) *out_work = 0u;
  return owned == NULL ? FTUN_E_INVALID :
    ftun_route_async_run(owned->operation, now_ms, quota, out_work);
}

static ftun_status_t async_query(void *context, const void *state,
  ftun_interface_async_info_t *out)
{
  const ftun_linux_interface_async_t *owned = state;
  ftun_route_async_info_t info;
  ftun_status_t status;
  (void)context;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (owned == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_route_async_get_info(owned->operation, &info);
  if (status != FTUN_OK) return status;
  switch (info.state) {
  case FTUN_ROUTE_ASYNC_APPLYING: out->state = FTUN_INTERFACE_INSTALLING; break;
  case FTUN_ROUTE_ASYNC_READY: out->state = FTUN_INTERFACE_READY; break;
  case FTUN_ROUTE_ASYNC_COMPENSATING:
  case FTUN_ROUTE_ASYNC_RELEASING: out->state = FTUN_INTERFACE_REMOVING; break;
  case FTUN_ROUTE_ASYNC_FAILED: out->state = FTUN_INTERFACE_FAILED; break;
  case FTUN_ROUTE_ASYNC_CLEANUP_FAILED: out->state = FTUN_INTERFACE_RETAINED; break;
  case FTUN_ROUTE_ASYNC_RELEASED: out->state = FTUN_INTERFACE_RELEASED; break;
  default: return FTUN_E_STATE_CORRUPT;
  }
  out->result = info.result;
  out->cleanup_result = info.cleanup_result;
  out->active_count = info.active_count;
  out->runnable = info.runnable;
  out->repairing = info.repairing;
  out->repair_result = info.repair_result;
  out->repair_runs = info.repair_runs;
  out->repairs = info.repairs;
  out->repair_failures = info.repair_failures;
  return ftun_route_async_next_deadline(owned->operation,
    &out->next_deadline_ms, &out->has_deadline);
}

static ftun_status_t async_repair(void *context, void *state, uint64_t now_ms,
  uint64_t deadline_ms)
{
  ftun_linux_interface_async_t *owned = state;
  (void)context;
  return owned == NULL ? FTUN_E_INVALID :
    ftun_route_async_repair(owned->operation, now_ms, deadline_ms);
}

static ftun_status_t async_destroy(void *context, void **state)
{
  ftun_linux_interface_async_t *owned;
  ftun_status_t status;
  (void)context;
  if (state == NULL) return FTUN_E_INVALID;
  owned = *state;
  if (owned == NULL) return FTUN_OK;
  status = ftun_route_async_destroy(&owned->operation);
  if (status != FTUN_OK) return status;
  ftun_reservation_release(&owned->reservation);
  free(owned);
  *state = NULL;
  return FTUN_OK;
}

const ftun_interface_ops_t ftun_interface_default_ops = {
  restore, withdraw, NULL,
  {async_start, async_adopt, async_withdraw, async_run, async_query, async_destroy, async_repair, NULL}
};
