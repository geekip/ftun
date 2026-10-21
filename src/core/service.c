#include "core/service.h"

#include <string.h>

bool ftun_core_service_descriptor_valid(
  const ftun_core_service_descriptor_t *descriptor)
{
  return descriptor != NULL && descriptor->name != NULL &&
    descriptor->name[0] != '\0' && descriptor->plan_prepare != NULL &&
    descriptor->plan_destroy != NULL && descriptor->prepare != NULL &&
    descriptor->activate != NULL && descriptor->reload_prepare != NULL &&
    descriptor->reload_prepare_planned != NULL &&
    descriptor->reload_commit != NULL && descriptor->reload_abort != NULL &&
    descriptor->run_once != NULL && descriptor->wakeup != NULL &&
    descriptor->quiesce != NULL && descriptor->drain_until != NULL &&
    descriptor->stop_until != NULL && descriptor->destroy_until != NULL;
}

ftun_status_t ftun_core_service_plan_prepare(
  const ftun_core_service_descriptor_t *descriptor,
  const ftun_config_t *config, uint32_t socket_mark,
  ftun_core_service_plan_t *out)
{
  void *implementation = NULL;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (!ftun_core_service_descriptor_valid(descriptor) || config == NULL ||
      out == NULL) return FTUN_E_INVALID;
  status = descriptor->plan_prepare(config, socket_mark, &implementation);
  if (status != FTUN_OK) {
    if (implementation != NULL) {
      (void)descriptor->plan_destroy(&implementation);
    }
    return status;
  }
  out->descriptor = descriptor;
  out->implementation = implementation;
  return FTUN_OK;
}

ftun_status_t ftun_core_service_plan_destroy(ftun_core_service_plan_t *plan)
{
  ftun_status_t status;
  if (plan == NULL) return FTUN_E_INVALID;
  if (plan->descriptor == NULL && plan->implementation == NULL) return FTUN_OK;
  if (!ftun_core_service_descriptor_valid(plan->descriptor)) {
    return FTUN_E_STATE_CORRUPT;
  }
  status = plan->descriptor->plan_destroy(&plan->implementation);
  if (status == FTUN_OK) plan->descriptor = NULL;
  return status;
}

ftun_status_t ftun_core_service_prepare(
  ftun_core_service_t *service,
  const ftun_core_service_descriptor_t *descriptor,
  ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations,
  const ftun_core_service_binding_t *binding,
  const ftun_config_t *config,
  uint64_t generation)
{
  void *implementation = NULL;
  ftun_status_t status;
  if (service == NULL || !ftun_core_service_descriptor_valid(descriptor) ||
      core == NULL || budget == NULL || operations == NULL || config == NULL ||
      service->implementation != NULL) return FTUN_E_INVALID;
  status = descriptor->prepare(core, budget, operations, binding, config,
                               generation, &implementation);
  if (status != FTUN_OK) {
    if (implementation != NULL) {
      (void)descriptor->destroy_until(&implementation, UINT64_MAX);
    }
    return status;
  }
  if (implementation == NULL) return FTUN_E_STATE_CORRUPT;
  service->descriptor = descriptor;
  service->implementation = implementation;
  return FTUN_OK;
}

static ftun_status_t ftun_core_service_check(ftun_core_service_t *service)
{
  if (service == NULL || service->implementation == NULL ||
      service->descriptor == NULL) {
    return FTUN_E_INVALID;
  }
  return FTUN_OK;
}

ftun_status_t ftun_core_service_activate(ftun_core_service_t *service)
{
  ftun_status_t status = ftun_core_service_check(service);
  return status == FTUN_OK
    ? service->descriptor->activate(service->implementation) : status;
}

ftun_status_t ftun_core_service_reload_prepare(
  ftun_core_service_t *service, const ftun_config_t *config,
  uint64_t generation)
{
  ftun_status_t status = ftun_core_service_check(service);
  if (status != FTUN_OK || config == NULL) {
    return status == FTUN_OK ? FTUN_E_INVALID : status;
  }
  return service->descriptor->reload_prepare(service->implementation, config,
                                              generation);
}

ftun_status_t ftun_core_service_reload_prepare_planned(
  ftun_core_service_t *service, const ftun_config_t *config,
  uint64_t generation, const ftun_core_service_plan_t *plan)
{
  ftun_status_t status = ftun_core_service_check(service);
  if (status != FTUN_OK || config == NULL || plan == NULL ||
      plan->descriptor != service->descriptor) {
    return status == FTUN_OK ? FTUN_E_INVALID : status;
  }
  return service->descriptor->reload_prepare_planned(
    service->implementation, config, generation, plan->implementation);
}

ftun_status_t ftun_core_service_reload_commit(ftun_core_service_t *service,
                                              uint64_t generation)
{
  ftun_status_t status = ftun_core_service_check(service);
  return status == FTUN_OK
    ? service->descriptor->reload_commit(service->implementation, generation)
    : status;
}

ftun_status_t ftun_core_service_reload_abort(ftun_core_service_t *service)
{
  ftun_status_t status = ftun_core_service_check(service);
  return status == FTUN_OK
    ? service->descriptor->reload_abort(service->implementation) : status;
}

ftun_status_t ftun_core_service_run_once(
  ftun_core_service_t *service, bool may_block,
  ftun_core_service_run_usage_t *out_usage)
{
  ftun_status_t status = ftun_core_service_check(service);
  if (out_usage != NULL) memset(out_usage, 0, sizeof(*out_usage));
  if (status != FTUN_OK || out_usage == NULL) {
    return status == FTUN_OK ? FTUN_E_INVALID : status;
  }
  return service->descriptor->run_once(service->implementation, may_block,
                                       out_usage);
}

ftun_status_t ftun_core_service_wakeup(ftun_core_service_t *service)
{
  ftun_status_t status = ftun_core_service_check(service);
  return status == FTUN_OK
    ? service->descriptor->wakeup(service->implementation) : status;
}

ftun_status_t ftun_core_service_quiesce(ftun_core_service_t *service)
{
  ftun_status_t status = ftun_core_service_check(service);
  return status == FTUN_OK
    ? service->descriptor->quiesce(service->implementation) : status;
}

ftun_status_t ftun_core_service_drain_until(ftun_core_service_t *service,
                                            uint64_t deadline_ms)
{
  ftun_status_t status = ftun_core_service_check(service);
  return status == FTUN_OK
    ? service->descriptor->drain_until(service->implementation, deadline_ms)
    : status;
}

ftun_status_t ftun_core_service_stop_until(ftun_core_service_t *service,
                                           uint64_t deadline_ms)
{
  ftun_status_t status = ftun_core_service_check(service);
  return status == FTUN_OK
    ? service->descriptor->stop_until(service->implementation, deadline_ms)
    : status;
}

ftun_status_t ftun_core_service_destroy_until(ftun_core_service_t *service,
                                              uint64_t deadline_ms)
{
  ftun_status_t status;
  if (service == NULL) return FTUN_E_INVALID;
  if (service->implementation == NULL) {
    service->descriptor = NULL;
    return FTUN_OK;
  }
  if (!ftun_core_service_descriptor_valid(service->descriptor)) {
    return FTUN_E_STATE_CORRUPT;
  }
  status = service->descriptor->destroy_until(&service->implementation,
                                               deadline_ms);
  if (status == FTUN_OK) service->descriptor = NULL;
  return status;
}

ftun_status_t ftun_core_service_destroy(ftun_core_service_t *service)
{
  return ftun_core_service_destroy_until(service, UINT64_MAX);
}
