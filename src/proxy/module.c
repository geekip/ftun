#include "proxy/module.h"

#include "proxy/runtime.h"

#include <string.h>

static ftun_status_t ftun_proxy_service_plan_prepare(ftun_budget_t *budget,
  const ftun_config_t *config, uint32_t socket_mark, void **out)
{
  (void)budget;
  if (out != NULL) *out = NULL;
  if (config == NULL || out == NULL) return FTUN_E_INVALID;
  (void)socket_mark;
  return FTUN_OK;
}

static ftun_status_t ftun_proxy_service_plan_destroy(void **plan)
{
  if (plan == NULL) return FTUN_E_INVALID;
  if (*plan != NULL) return FTUN_E_STATE_CORRUPT;
  return FTUN_OK;
}

static ftun_status_t ftun_proxy_service_prepare(
  ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations,
  const ftun_core_service_binding_t *binding,
  const ftun_config_t *config,
  uint64_t generation, void **out)
{
  const ftun_proxy_bindings_t *bindings;
  ftun_proxy_runtime_t *runtime = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (binding == NULL || binding->value == NULL ||
      binding->size != sizeof(ftun_proxy_bindings_t) || out == NULL) {
    return FTUN_E_INVALID;
  }
  bindings = (const ftun_proxy_bindings_t *)binding->value;
  if (!ftun_proxy_bindings_valid(bindings)) return FTUN_E_INVALID;
  status = ftun_proxy_runtime_prepare(core, budget, operations, bindings,
                                      config, generation, &runtime);
  *out = runtime;
  return status;
}

static ftun_status_t ftun_proxy_service_activate(void *implementation)
{
  return ftun_proxy_runtime_activate((ftun_proxy_runtime_t *)implementation);
}

static ftun_status_t ftun_proxy_service_reload_prepare(
  void *implementation, const ftun_config_t *config, uint64_t generation)
{
  return ftun_proxy_runtime_reload_prepare(
    (ftun_proxy_runtime_t *)implementation, config, generation);
}

static ftun_status_t ftun_proxy_service_reload_prepare_planned(
  void *implementation, const ftun_config_t *config, uint64_t generation,
  const void *plan)
{
  return ftun_proxy_runtime_reload_prepare_planned(
    (ftun_proxy_runtime_t *)implementation, config, generation, plan);
}

static ftun_status_t ftun_proxy_service_reload_commit(
  void *implementation, uint64_t generation)
{
  return ftun_proxy_runtime_reload_commit(
    (ftun_proxy_runtime_t *)implementation, generation);
}

static ftun_status_t ftun_proxy_service_reload_abort(void *implementation)
{
  return ftun_proxy_runtime_reload_abort(
    (ftun_proxy_runtime_t *)implementation);
}

static ftun_status_t ftun_proxy_service_run_once(
  void *implementation, bool may_block,
  ftun_core_service_run_usage_t *out_usage)
{
  ftun_proxy_runtime_run_usage_t usage;
  ftun_status_t status;
  if (out_usage != NULL) memset(out_usage, 0, sizeof(*out_usage));
  if (out_usage == NULL) return FTUN_E_INVALID;
  memset(&usage, 0, sizeof(usage));
  status = ftun_proxy_runtime_run_once(
    (ftun_proxy_runtime_t *)implementation, may_block, &usage);
  out_usage->work = usage.work;
  out_usage->busy_ms = usage.busy_ms;
  out_usage->deadline_lateness_ms = usage.deadline_lateness_ms;
  out_usage->quota_exhausted = usage.quota_exhausted;
  out_usage->faults[FTUN_FAULT_SCOPE_OBJECT] = usage.object_faults;
  return status;
}

static ftun_status_t ftun_proxy_service_wakeup(void *implementation)
{
  return ftun_proxy_runtime_wakeup((ftun_proxy_runtime_t *)implementation);
}

static ftun_status_t ftun_proxy_service_quiesce(void *implementation)
{
  return ftun_proxy_runtime_quiesce(
    (ftun_proxy_runtime_t *)implementation);
}

static ftun_status_t ftun_proxy_service_drain_until(
  void *implementation, uint64_t deadline_ms)
{
  return ftun_proxy_runtime_drain_until(
    (ftun_proxy_runtime_t *)implementation, deadline_ms);
}

static ftun_status_t ftun_proxy_service_stop_until(
  void *implementation, uint64_t deadline_ms)
{
  return ftun_proxy_runtime_stop_until(
    (ftun_proxy_runtime_t *)implementation, deadline_ms);
}

static ftun_status_t ftun_proxy_service_destroy_until(
  void **implementation, uint64_t deadline_ms)
{
  ftun_proxy_runtime_t *runtime;
  ftun_status_t status;
  if (implementation == NULL) return FTUN_E_INVALID;
  runtime = (ftun_proxy_runtime_t *)*implementation;
  status = ftun_proxy_runtime_destroy_until(&runtime, deadline_ms);
  *implementation = runtime;
  return status;
}

static void ftun_proxy_service_network_changed(void *implementation,
  const ftun_network_change_t *change, uint64_t now_ms)
{
  (void)change;
  ftun_proxy_runtime_network_changed((ftun_proxy_runtime_t *)implementation, now_ms);
}

const ftun_core_service_descriptor_t ftun_proxy_service = {
  "proxy",
  ftun_proxy_service_plan_prepare,
  ftun_proxy_service_plan_destroy,
  ftun_proxy_service_prepare,
  ftun_proxy_service_activate,
  ftun_proxy_service_reload_prepare,
  ftun_proxy_service_reload_prepare_planned,
  ftun_proxy_service_reload_commit,
  ftun_proxy_service_reload_abort,
  ftun_proxy_service_run_once,
  ftun_proxy_service_wakeup,
  ftun_proxy_service_quiesce,
  ftun_proxy_service_drain_until,
  ftun_proxy_service_stop_until,
  ftun_proxy_service_destroy_until,
  NULL /* maintain_once：尚未支持暂停 */,
  ftun_proxy_service_network_changed
};
