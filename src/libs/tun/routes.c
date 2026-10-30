#include "libs/tun/routes_internal.h"
#include "core/event/loop.h"
#include <stdlib.h>
#include <string.h>

static ftun_status_t prepare(ftun_budget_t *budget,
  const ftun_route_policy_t *policy, const ftun_route_io_t *io, bool system,
  ftun_route_transaction_t **out)
{
  ftun_route_transaction_t *owned;
  ftun_reservation_t reservation = {0}, control = {0};
  ftun_status_t status;
  size_t bytes = sizeof(*owned) + ftun_platform_route_transaction_allocation_size();
  if (out != NULL) *out = NULL;
  if (out == NULL || !ftun_platform_route_prepare_valid(policy, io, system)) return FTUN_E_INVALID;
  if (budget != NULL) {
    /* 系统事务预留表锁和控制 socket；清理继续使用已保留的额度。 */
    status = ftun_budget_reserve_resources(budget,
      (ftun_budget_resources_t){bytes, system ? 2u : 0u, 0u}, &reservation);
    if (status == FTUN_OK && !system) status = ftun_budget_reserve_resources(budget,
      (ftun_budget_resources_t){0u, 1u, 0u}, &control);
    if (status != FTUN_OK) { ftun_reservation_release(&reservation); return status; }
  }
  owned = calloc(1u, sizeof(*owned));
  if (owned == NULL) {
    ftun_reservation_release(&control);
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  owned->reservation = reservation;
  owned->budget = budget;
  owned->system = system;
  status = system ? ftun_platform_route_prepare(policy, &owned->native) :
    ftun_platform_route_prepare_with_io(policy, io, &owned->native);
  ftun_reservation_release(&control);
  if (owned->native != NULL) *out = owned;
  else { ftun_reservation_release(&owned->reservation); free(owned); }
  return status;
}
ftun_status_t ftun_route_prepare_with_budget(ftun_budget_t *budget,
  const ftun_route_policy_t *policy, ftun_route_transaction_t **out)
{ return prepare(budget, policy, NULL, true, out); }
ftun_status_t ftun_route_prepare_with_io_and_budget(ftun_budget_t *budget,
  const ftun_route_policy_t *policy, const ftun_route_io_t *io, ftun_route_transaction_t **out)
{ return prepare(budget, policy, io, false, out); }
ftun_status_t ftun_route_prepare(const ftun_route_policy_t *policy, ftun_route_transaction_t **out)
{ return prepare(NULL, policy, NULL, true, out); }
ftun_status_t ftun_route_prepare_with_io(const ftun_route_policy_t *policy,
  const ftun_route_io_t *io, ftun_route_transaction_t **out)
{ return prepare(NULL, policy, io, false, out); }
ftun_status_t ftun_route_get_info(const ftun_route_transaction_t *transaction, ftun_route_info_t *out)
{ return ftun_platform_route_get_info(transaction == NULL ? NULL : transaction->native, out); }
ftun_status_t ftun_route_release(ftun_route_transaction_t **transaction)
{
  ftun_route_transaction_t *owned;
  ftun_reservation_t control = {0};
  ftun_status_t status;
  if (transaction == NULL) return FTUN_E_INVALID;
  owned = *transaction;
  if (owned == NULL) return FTUN_OK;
  if (owned->budget != NULL && !owned->system) {
    ftun_route_info_t info;
    status = ftun_platform_route_get_info(owned->native, &info);
    if (status != FTUN_OK) return status;
    if (info.active_count != 0u) {
      status = ftun_budget_reserve_cleanup_resources(owned->budget,
        (ftun_budget_resources_t){0u, 1u, 0u}, &control);
      if (status != FTUN_OK) return status;
    }
  }
  status = ftun_platform_route_release(&owned->native);
  ftun_reservation_release(&control);
  if (status != FTUN_OK) return status;
  ftun_reservation_release(&owned->reservation);
  free(owned);
  *transaction = NULL;
  return FTUN_OK;
}

static ftun_status_t prefixes(const ftun_network_view_t *view, bool overlay,
  ftun_cidr_t out[128], size_t *count)
{
  ftun_network_view_info_t info;
  size_t i;
  if (view == NULL || ftun_network_view_get_info(view, &info) != FTUN_OK) return FTUN_E_INVALID;
  *count = overlay ? info.overlay_route_count : info.protected_prefix_count;
  if (*count > 128u) return FTUN_E_INVALID;
  for (i = 0u; i < *count; i++) {
    ftun_network_prefix_t prefix;
    if (overlay) {
      ftun_network_route_t route;
      if (ftun_network_view_get_route(view, i, &route) != FTUN_OK) return FTUN_E_STATE_CORRUPT;
      prefix = route.prefix;
    } else if (ftun_network_view_get_protected(view, i, &prefix) != FTUN_OK) return FTUN_E_STATE_CORRUPT;
    out[i] = prefix;
  }
  return FTUN_OK;
}
ftun_status_t ftun_route_guard_plan(const ftun_network_view_t *view,
  uint32_t table, uint32_t priority, ftun_route_plan_t *out)
{
  ftun_cidr_t input[128];
  size_t count;
  ftun_status_t status;
  if (out == NULL) return FTUN_E_INVALID;
  memset(out, 0, ftun_platform_route_plan_allocation_size());
  status = prefixes(view, false, input, &count);
  return status == FTUN_OK ? ftun_platform_route_guard_plan(input, count, table, priority, out) : status;
}
ftun_status_t ftun_route_overlay_plan(const ftun_network_view_t *view,
  ftun_string_t interface, uint32_t table, uint32_t metric, ftun_route_plan_t *out)
{
  ftun_cidr_t input[128];
  size_t count;
  ftun_status_t status;
  if (out == NULL) return FTUN_E_INVALID;
  memset(out, 0, ftun_platform_route_plan_allocation_size());
  status = prefixes(view, true, input, &count);
  return status == FTUN_OK ? ftun_platform_route_overlay_plan(input, count, interface, table, metric, out) : status;
}
