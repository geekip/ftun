#include "core/service.h"

#include <string.h>

static void ftun_core_service_record(ftun_status_t *first,
                                      ftun_status_t status)
{
  if (*first == FTUN_OK && status != FTUN_OK) *first = status;
}

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
  ftun_budget_t *budget, const ftun_config_t *config, uint32_t socket_mark,
  ftun_core_service_plan_t *out)
{
  void *implementation = NULL;
  ftun_status_t status;
  if (!ftun_core_service_descriptor_valid(descriptor) || budget == NULL || config == NULL ||
      out == NULL) return FTUN_E_INVALID;
  if (out->descriptor != NULL || out->implementation != NULL) {
    return FTUN_E_AGAIN;
  }
  memset(out, 0, sizeof(*out));
  status = descriptor->plan_prepare(budget, config, socket_mark, &implementation);
  out->descriptor = status == FTUN_OK || implementation != NULL
    ? descriptor : NULL;
  out->implementation = implementation;
  out->first_error = status;
  out->cleanup_only = status != FTUN_OK;
  return status;
}

ftun_status_t ftun_core_service_plan_destroy(ftun_core_service_plan_t *plan)
{
  ftun_status_t status;
  if (plan == NULL) return FTUN_E_INVALID;
  if (plan->descriptor == NULL && plan->implementation == NULL) return FTUN_OK;
  if (!ftun_core_service_descriptor_valid(plan->descriptor)) {
    return FTUN_E_STATE_CORRUPT;
  }
  plan->cleanup_only = true;
  status = plan->descriptor->plan_destroy(&plan->implementation);
  if (status == FTUN_OK && plan->implementation != NULL) {
    status = FTUN_E_STATE_CORRUPT;
  }
  ftun_core_service_record(&plan->cleanup_error, status);
  if (status == FTUN_OK) {
    plan->descriptor = NULL;
    plan->cleanup_only = false;
  }
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
      core == NULL || budget == NULL || operations == NULL || config == NULL) {
    return FTUN_E_INVALID;
  }
  if (service->descriptor != NULL || service->implementation != NULL) {
    return FTUN_E_AGAIN;
  }
  memset(service, 0, sizeof(*service));
  status = descriptor->prepare(core, budget, operations, binding, config,
                               generation, &implementation);
  if (status == FTUN_OK && implementation == NULL) {
    status = FTUN_E_STATE_CORRUPT;
  }
  service->descriptor = implementation != NULL ? descriptor : NULL;
  service->implementation = implementation;
  service->first_error = status;
  service->cleanup_only = status != FTUN_OK;
  service->prepared = status == FTUN_OK;
  return status;
}

static ftun_status_t ftun_core_service_check(ftun_core_service_t *service)
{
  if (service == NULL || service->implementation == NULL ||
      service->descriptor == NULL) {
    return FTUN_E_INVALID;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_core_service_running(ftun_core_service_t *service)
{
  ftun_status_t status = ftun_core_service_check(service);
  return status == FTUN_OK && service->cleanup_only ? FTUN_E_STALE : status;
}

ftun_status_t ftun_core_service_activate(ftun_core_service_t *service)
{
  ftun_status_t status = ftun_core_service_running(service);
  if (status != FTUN_OK) return status;
  status = service->descriptor->activate(service->implementation);
  ftun_core_service_record(&service->first_error, status);
  if (status != FTUN_OK) service->cleanup_only = true;
  return status;
}

ftun_status_t ftun_core_service_reload_prepare(
  ftun_core_service_t *service, const ftun_config_t *config,
  uint64_t generation)
{
  ftun_status_t status = ftun_core_service_running(service);
  if (status != FTUN_OK || config == NULL) {
    return status == FTUN_OK ? FTUN_E_INVALID : status;
  }
  if (service->reload_pending) return FTUN_E_AGAIN;
  service->reload_pending = true;
  status = service->descriptor->reload_prepare(service->implementation, config,
                                                generation);
  service->reload_ready = status == FTUN_OK;
  ftun_core_service_record(&service->first_error, status);
  return status;
}

ftun_status_t ftun_core_service_reload_prepare_planned(
  ftun_core_service_t *service, const ftun_config_t *config,
  uint64_t generation, const ftun_core_service_plan_t *plan)
{
  ftun_status_t status = ftun_core_service_running(service);
  if (status != FTUN_OK || config == NULL || plan == NULL ||
      plan->descriptor != service->descriptor || plan->cleanup_only) {
    return status == FTUN_OK ? FTUN_E_INVALID : status;
  }
  if (service->reload_pending) return FTUN_E_AGAIN;
  service->reload_pending = true;
  status = service->descriptor->reload_prepare_planned(
    service->implementation, config, generation, plan->implementation);
  service->reload_ready = status == FTUN_OK;
  ftun_core_service_record(&service->first_error, status);
  return status;
}

ftun_status_t ftun_core_service_reload_commit(ftun_core_service_t *service,
                                              uint64_t generation)
{
  ftun_status_t status = ftun_core_service_running(service);
  if (status != FTUN_OK) return status;
  if (!service->reload_ready) return FTUN_E_STALE;
  status = service->descriptor->reload_commit(service->implementation,
                                              generation);
  if (status == FTUN_OK) {
    service->reload_pending = false;
    service->reload_ready = false;
  } else {
    ftun_core_service_record(&service->first_error, status);
    service->cleanup_only = true;
  }
  return status;
}

ftun_status_t ftun_core_service_reload_abort(ftun_core_service_t *service)
{
  ftun_status_t status = ftun_core_service_check(service);
  if (status != FTUN_OK) return status;
  if (!service->reload_pending) return FTUN_OK;
  status = service->descriptor->reload_abort(service->implementation);
  ftun_core_service_record(&service->cleanup_error, status);
  if (status == FTUN_OK) {
    service->reload_pending = false;
    service->reload_ready = false;
  }
  return status;
}

ftun_status_t ftun_core_service_run_once(
  ftun_core_service_t *service, bool may_block,
  ftun_core_service_run_usage_t *out_usage)
{
  ftun_status_t status = ftun_core_service_running(service);
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
  if (status == FTUN_OK && !service->prepared) return FTUN_OK;
  return status == FTUN_OK
    ? service->descriptor->wakeup(service->implementation) : status;
}

ftun_status_t ftun_core_service_quiesce(ftun_core_service_t *service)
{
  ftun_status_t status = ftun_core_service_check(service);
  if (status != FTUN_OK || !service->prepared) return status;
  service->cleanup_only = true;
  status = service->descriptor->quiesce(service->implementation);
  ftun_core_service_record(&service->cleanup_error, status);
  return status;
}

ftun_status_t ftun_core_service_drain_until(ftun_core_service_t *service,
                                            uint64_t deadline_ms)
{
  ftun_status_t status = ftun_core_service_check(service);
  if (status != FTUN_OK || !service->prepared) return status;
  service->cleanup_only = true;
  status = service->descriptor->drain_until(service->implementation,
                                            deadline_ms);
  ftun_core_service_record(&service->cleanup_error, status);
  return status;
}

ftun_status_t ftun_core_service_stop_until(ftun_core_service_t *service,
                                           uint64_t deadline_ms)
{
  ftun_status_t status = ftun_core_service_check(service);
  if (status != FTUN_OK || !service->prepared) return status;
  service->cleanup_only = true;
  status = service->descriptor->stop_until(service->implementation, deadline_ms);
  ftun_core_service_record(&service->cleanup_error, status);
  return status;
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
  service->cleanup_only = true;
  if (service->reload_pending) {
    status = ftun_core_service_reload_abort(service);
    if (status != FTUN_OK) return status;
  }
  status = service->descriptor->destroy_until(&service->implementation,
                                               deadline_ms);
  if (status == FTUN_OK && service->implementation != NULL) {
    status = FTUN_E_STATE_CORRUPT;
  }
  ftun_core_service_record(&service->cleanup_error, status);
  if (status == FTUN_OK) {
    service->descriptor = NULL;
    service->cleanup_only = false;
    service->prepared = false;
  }
  return status;
}

ftun_status_t ftun_core_service_destroy(ftun_core_service_t *service)
{
  return ftun_core_service_destroy_until(service, UINT64_MAX);
}
