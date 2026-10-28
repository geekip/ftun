#include "dns/core_service.h"

#include "util/time.h"
#include "core/budget.h"

#include <stdlib.h>
#include <string.h>

#define FTUN_DNS_SERVICE_QUOTA 32u
#define FTUN_DNS_SERVICE_EVENT_QUOTA 64u

typedef struct {
  ftun_core_t *core;
  ftun_budget_t *budget;
  ftun_reservation_t *reservation;
  ftun_operation_queue_t *operations;
  ftun_event_loop_t *loop;
  ftun_dns_service_slot_t *slot;
  ftun_dns_runtime_adapter_t adapter;
  ftun_dns_runtime_network_t network;
  ftun_dns_runtime_t *active;
  ftun_dns_runtime_t *pending;
  ftun_dns_runtime_t *retired;
  ftun_event_source_t *deadline_source;
  uint64_t generation;
  uint64_t pending_generation;
  uint64_t deadline_ms;
  uint32_t socket_mark;
  bool deadline_ready;
  bool reload_prepared;
  bool activated;
  bool stopped;
} ftun_dns_service_instance_t;

bool ftun_dns_service_binding_valid(const ftun_dns_service_binding_t *binding)
{
  return binding != NULL && binding->loop != NULL && binding->slot != NULL &&
    binding->path.open != NULL;
}

ftun_status_t ftun_dns_service_slot_get(
  const ftun_dns_service_slot_t *slot, ftun_dns_runtime_t **out)
{
  if (out != NULL) *out = NULL;
  if (slot == NULL || out == NULL) return FTUN_E_INVALID;
  if (!slot->accepting || slot->active == NULL || slot->generation == 0u) {
    return FTUN_E_AGAIN;
  }
  *out = slot->active;
  return FTUN_OK;
}

static void ftun_dns_service_publish(ftun_dns_service_instance_t *service,
                                     bool accepting)
{
  service->slot->active = service->active;
  service->slot->generation = service->generation;
  service->slot->accepting = accepting && service->active != NULL;
}

static ftun_status_t ftun_dns_service_plan_prepare(ftun_budget_t *budget,
  const ftun_config_t *config, uint32_t socket_mark, void **out)
{
  ftun_dns_runtime_plan_t *plan = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (config == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_dns_runtime_plan_prepare(budget, config, socket_mark, &plan);
  if (status == FTUN_OK) *out = plan;
  return status;
}

static ftun_status_t ftun_dns_service_plan_destroy(void **plan)
{
  ftun_dns_runtime_plan_t *owned;
  ftun_status_t status;
  if (plan == NULL) return FTUN_E_INVALID;
  owned = (ftun_dns_runtime_plan_t *)*plan;
  status = ftun_dns_runtime_plan_destroy(&owned);
  if (status == FTUN_OK) *plan = NULL;
  return status;
}

static ftun_status_t ftun_dns_service_prepare(
  ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations,
  const ftun_core_service_binding_t *binding,
  const ftun_config_t *config, uint64_t generation, void **out)
{
  const ftun_dns_service_binding_t *bindings;
  ftun_dns_service_instance_t *service;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core == NULL || budget == NULL || operations == NULL ||
      binding == NULL || binding->value == NULL ||
      binding->size != sizeof(ftun_dns_service_binding_t) ||
      config == NULL || generation == 0u || out == NULL) {
    return FTUN_E_INVALID;
  }
  bindings = (const ftun_dns_service_binding_t *)binding->value;
  if (!ftun_dns_service_binding_valid(bindings) ||
      bindings->slot->active != NULL || bindings->slot->accepting) {
    return FTUN_E_INVALID;
  }
  status = ftun_budget_reserve(budget, sizeof(*service), &reservation);
  if (status != FTUN_OK) return status;
  service = (ftun_dns_service_instance_t *)calloc(1u, sizeof(*service));
  if (service == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  service->reservation = reservation;
  service->core = core;
  service->budget = budget;
  service->operations = operations;
  service->loop = bindings->loop;
  service->slot = bindings->slot;
  service->adapter = bindings->adapter;
  service->socket_mark = bindings->socket_mark;
  service->generation = generation;
  service->network.generation = generation;
  service->network.socket_mark = bindings->socket_mark;
  service->network.path = bindings->path;
  service->network.context = bindings->path_context;
  status = ftun_dns_runtime_prepare(core, budget, operations, service->loop,
    config, &service->adapter, &service->network,
    &service->active);
  if (status != FTUN_OK && service->active == NULL) {
    free(service);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  /* 失败且仍拥有 runtime 时，仅可由上层 cleanup-only service 销毁。 */
  *out = service;
  return status;
}

static ftun_status_t ftun_dns_service_activate(void *implementation)
{
  ftun_dns_service_instance_t *service =
    (ftun_dns_service_instance_t *)implementation;
  ftun_status_t status;
  if (service == NULL || service->stopped || service->activated) {
    return FTUN_E_INVALID;
  }
  status = ftun_dns_runtime_activate(service->active);
  if (status != FTUN_OK) return status;
  service->activated = true;
  ftun_dns_service_publish(service, true);
  return FTUN_OK;
}

static ftun_status_t ftun_dns_service_reload_prepare_planned(
  void *implementation, const ftun_config_t *config, uint64_t generation,
  const void *plan)
{
  ftun_dns_service_instance_t *service =
    (ftun_dns_service_instance_t *)implementation;
  ftun_status_t status;
  if (service == NULL || config == NULL || generation <= service->generation ||
      service->stopped || service->reload_prepared ||
      service->retired != NULL || service->pending != NULL) {
    return FTUN_E_INVALID;
  }
  service->network.generation = generation;
  status = ftun_dns_runtime_prepare_reload_planned(
    service->active, service->core, service->budget, service->operations,
    service->loop, config, &service->adapter, &service->network,
    (const ftun_dns_runtime_plan_t *)plan,
    &service->pending);
  if (status == FTUN_OK) {
    service->pending_generation = generation;
    service->reload_prepared = true;
  }
  return status;
}

static ftun_status_t ftun_dns_service_reload_prepare(
  void *implementation, const ftun_config_t *config, uint64_t generation)
{
  return ftun_dns_service_reload_prepare_planned(
    implementation, config, generation, NULL);
}

static ftun_status_t ftun_dns_service_reload_commit(
  void *implementation, uint64_t generation)
{
  ftun_dns_service_instance_t *service =
    (ftun_dns_service_instance_t *)implementation;
  ftun_status_t status;
  if (service == NULL || !service->reload_prepared ||
      generation != service->pending_generation) return FTUN_E_STALE;
  status = ftun_dns_runtime_commit_reload(
    &service->active, &service->pending, &service->retired);
  if (status != FTUN_OK) return status;
  service->generation = generation;
  service->pending_generation = 0u;
  service->reload_prepared = false;
  ftun_dns_service_publish(service, true);
  return FTUN_OK;
}

static ftun_status_t ftun_dns_service_reload_abort(void *implementation)
{
  ftun_dns_service_instance_t *service =
    (ftun_dns_service_instance_t *)implementation;
  ftun_status_t status;
  if (service == NULL) return FTUN_E_INVALID;
  status = ftun_dns_runtime_destroy(&service->pending);
  if (status == FTUN_OK) {
    service->pending_generation = 0u;
    service->reload_prepared = false;
  }
  return status;
}

static void ftun_dns_service_deadline_ready(
  ftun_event_source_t *source, uint32_t events, void *user)
{
  ftun_dns_service_instance_t *service =
    (ftun_dns_service_instance_t *)user;
  if (service != NULL && service->deadline_source == source &&
      (events & FTUN_EVENT_TIMER) != 0u) service->deadline_ready = true;
}

static ftun_status_t ftun_dns_service_next_deadline(
  const ftun_dns_service_instance_t *service, uint64_t *out, bool *present)
{
  uint64_t active_deadline = 0u;
  uint64_t retired_deadline = 0u;
  bool active_present = false;
  bool retired_present = false;
  ftun_status_t status;
  if (out != NULL) *out = 0u;
  if (present != NULL) *present = false;
  if (service == NULL || out == NULL || present == NULL) return FTUN_E_INVALID;
  status = ftun_dns_runtime_next_deadline(
    service->active, &active_deadline, &active_present);
  if (status == FTUN_OK) status = ftun_dns_runtime_next_deadline(
    service->retired, &retired_deadline, &retired_present);
  if (status != FTUN_OK) return status;
  if (active_present || retired_present) {
    *out = !retired_present || (active_present &&
      active_deadline <= retired_deadline) ? active_deadline : retired_deadline;
    *present = true;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_dns_service_schedule(
  ftun_dns_service_instance_t *service)
{
  uint64_t deadline = 0u;
  bool present = false;
  ftun_status_t status = ftun_dns_service_next_deadline(
    service, &deadline, &present);
  if (status != FTUN_OK) return status;
  if (service->deadline_source != NULL && !service->deadline_ready &&
      present && service->deadline_ms == deadline) return FTUN_OK;
  status = ftun_event_source_cancel(&service->deadline_source);
  if (status != FTUN_OK) return status;
  service->deadline_ms = 0u;
  service->deadline_ready = false;
  if (!present) return FTUN_OK;
  status = ftun_event_timer_start(service->loop, deadline,
    ftun_dns_service_deadline_ready, service, &service->deadline_source);
  if (status == FTUN_OK) service->deadline_ms = deadline;
  return status;
}

static ftun_status_t ftun_dns_service_run_once(
  void *implementation, bool may_block,
  ftun_core_service_run_usage_t *out_usage)
{
  ftun_dns_service_instance_t *service =
    (ftun_dns_service_instance_t *)implementation;
  uint64_t started_ms = 0u;
  uint64_t before_event_ms = 0u;
  uint64_t after_event_ms = 0u;
  uint64_t finished_ms = 0u;
  ftun_event_loop_usage_t event_usage;
  size_t active_work = 0u;
  size_t retired_work = 0u;
  size_t callbacks = 0u;
  bool immediate;
  bool blocked;
  ftun_status_t status;
  if (out_usage != NULL) memset(out_usage, 0, sizeof(*out_usage));
  if (service == NULL || !service->activated || service->stopped ||
      out_usage == NULL) return FTUN_E_INVALID;
  status = ftun_monotonic_now(&started_ms);
  if (status == FTUN_OK) status = ftun_dns_service_schedule(service);
  if (status == FTUN_OK) status = ftun_dns_runtime_run_once(
    service->active, FTUN_DNS_SERVICE_QUOTA, &active_work);
  if (status == FTUN_OK && service->retired != NULL) {
    status = ftun_dns_runtime_run_once(
      service->retired, FTUN_DNS_SERVICE_QUOTA, &retired_work);
  }
  if (status == FTUN_OK && service->retired != NULL) {
    ftun_status_t reap = ftun_dns_runtime_reap(&service->retired);
    if (reap != FTUN_OK && reap != FTUN_E_AGAIN) status = reap;
  }
  if (status != FTUN_OK) return status;
  immediate = active_work != 0u || retired_work != 0u ||
    service->deadline_ready || ftun_dns_runtime_has_ready(service->active) ||
    ftun_dns_runtime_has_ready(service->retired);
  blocked = may_block && !immediate;
  status = ftun_monotonic_now(&before_event_ms);
  if (status != FTUN_OK) return status;
  status = ftun_event_loop_run_once(service->loop, blocked,
    FTUN_DNS_SERVICE_EVENT_QUOTA, &callbacks);
  if (status != FTUN_OK) return status;
  status = ftun_monotonic_now(&after_event_ms);
  if (status != FTUN_OK) return status;
  service->deadline_ready = false;
  status = ftun_dns_service_schedule(service);
  if (status == FTUN_OK) status = ftun_event_loop_get_usage(service->loop, &event_usage);
  if (status == FTUN_OK) status = ftun_monotonic_now(&finished_ms);
  if (status != FTUN_OK) return status;
  out_usage->work = active_work + retired_work + event_usage.last_work;
  /* 等待型回合仅计派发与两侧 owner 工作，排除 backend 阻塞等待。 */
  if (before_event_ms >= started_ms) out_usage->busy_ms = before_event_ms - started_ms;
  if (finished_ms >= after_event_ms) out_usage->busy_ms += finished_ms - after_event_ms;
  if (blocked) out_usage->busy_ms += event_usage.last_dispatch_ms;
  else if (after_event_ms >= before_event_ms) {
    out_usage->busy_ms += after_event_ms - before_event_ms;
  }
  out_usage->quota_exhausted = active_work == FTUN_DNS_SERVICE_QUOTA ||
    retired_work == FTUN_DNS_SERVICE_QUOTA ||
    callbacks == FTUN_DNS_SERVICE_EVENT_QUOTA || event_usage.backend_quota_exhausted;
  out_usage->faults[FTUN_FAULT_SCOPE_OBJECT] =
    ftun_dns_runtime_take_object_faults(service->active) +
    ftun_dns_runtime_take_object_faults(service->retired);
  return FTUN_OK;
}

static ftun_status_t ftun_dns_service_wakeup(void *implementation)
{
  ftun_dns_service_instance_t *service =
    (ftun_dns_service_instance_t *)implementation;
  return service == NULL ? FTUN_E_INVALID : ftun_event_loop_wakeup(service->loop);
}

static ftun_status_t ftun_dns_service_quiesce(void *implementation)
{
  ftun_dns_service_instance_t *service =
    (ftun_dns_service_instance_t *)implementation;
  ftun_status_t result;
  ftun_status_t status;
  if (service == NULL) return FTUN_E_INVALID;
  ftun_dns_service_publish(service, false);
  result = ftun_event_source_cancel(&service->deadline_source);
  status = ftun_dns_runtime_quiesce(service->active);
  if (result == FTUN_OK) result = status;
  status = ftun_dns_runtime_quiesce(service->retired);
  if (result == FTUN_OK) result = status;
  return result;
}

static ftun_status_t ftun_dns_service_stop_until(
  void *implementation, uint64_t deadline_ms)
{
  ftun_dns_service_instance_t *service =
    (ftun_dns_service_instance_t *)implementation;
  ftun_status_t result;
  ftun_status_t status;
  if (service == NULL || deadline_ms == 0u) return FTUN_E_INVALID;
  result = ftun_dns_service_quiesce(service);
  status = ftun_dns_runtime_stop_until(service->active, deadline_ms);
  if (result == FTUN_OK) result = status;
  status = ftun_dns_runtime_stop_until(service->retired, deadline_ms);
  if (result == FTUN_OK) result = status;
  if (result == FTUN_OK) service->stopped = true;
  return result;
}

static ftun_status_t ftun_dns_service_drain_until(
  void *implementation, uint64_t deadline_ms)
{
  return ftun_dns_service_stop_until(implementation, deadline_ms);
}

static ftun_status_t ftun_dns_service_destroy_until(
  void **implementation, uint64_t deadline_ms)
{
  ftun_dns_service_instance_t *service;
  ftun_status_t status;
  ftun_reservation_t *reservation;
  if (implementation == NULL || deadline_ms == 0u) return FTUN_E_INVALID;
  service = (ftun_dns_service_instance_t *)*implementation;
  if (service == NULL) return FTUN_OK;
  status = ftun_dns_service_stop_until(service, deadline_ms);
  if (status != FTUN_OK) return status;
  if (service->reload_prepared || service->pending != NULL) {
    status = ftun_dns_service_reload_abort(service);
    if (status != FTUN_OK) return status;
  }
  status = ftun_dns_runtime_destroy(&service->retired);
  if (status == FTUN_OK) status = ftun_dns_runtime_destroy(&service->active);
  if (status != FTUN_OK) return status;
  service->slot->active = NULL;
  service->slot->generation = 0u;
  service->slot->accepting = false;
  reservation = service->reservation;
  memset(service, 0, sizeof(*service));
  free(service);
  *implementation = NULL;
  return ftun_reservation_release(&reservation);
}

static void ftun_dns_service_network_changed(void *implementation,
  const ftun_network_change_t *change, uint64_t now_ms)
{
  ftun_dns_service_instance_t *service = (ftun_dns_service_instance_t *)implementation;
  (void)change;
  if (service == NULL) return;
  ftun_dns_runtime_network_changed(service->active, now_ms);
  ftun_dns_runtime_network_changed(service->retired, now_ms);
  /* 提前到期的恢复要在这一轮就被处理，而不是等原来的期限计时器。 */
  service->deadline_ready = true;
}

const ftun_core_service_descriptor_t ftun_dns_core_service = {
  "dns",
  ftun_dns_service_plan_prepare,
  ftun_dns_service_plan_destroy,
  ftun_dns_service_prepare,
  ftun_dns_service_activate,
  ftun_dns_service_reload_prepare,
  ftun_dns_service_reload_prepare_planned,
  ftun_dns_service_reload_commit,
  ftun_dns_service_reload_abort,
  ftun_dns_service_run_once,
  ftun_dns_service_wakeup,
  ftun_dns_service_quiesce,
  ftun_dns_service_drain_until,
  ftun_dns_service_stop_until,
  ftun_dns_service_destroy_until,
  NULL /* maintain_once：尚未支持暂停 */,
  ftun_dns_service_network_changed
};
