#include "core/lifecycle.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(expression) do { \
  if (!(expression)) { \
    fprintf(stderr, "check failed: %s:%d: %s\n", \
            __FILE__, __LINE__, #expression); \
    return 1; \
  } \
} while (0)

struct ftun_config { ftun_config_document_t document; };

typedef struct {
  unsigned int prepared;
  unsigned int activated;
  unsigned int reload_prepared;
  unsigned int reload_committed;
  unsigned int reload_aborted;
  unsigned int ran;
  unsigned int woke;
  unsigned int quiesced;
  unsigned int drained;
  unsigned int stopped;
  unsigned int destroy_attempts;
} fake_service_t;

static fake_service_t fake;
static unsigned int fake_plan;
static ftun_status_t prepare_error;
static ftun_status_t plan_error;
static ftun_status_t activate_error;
static ftun_status_t reload_error;
static unsigned int destroy_failures = 1u;
static unsigned int plan_destroy_failures;
static unsigned int abort_failures;

static ftun_status_t fake_plan_prepare(ftun_budget_t *budget,
  const ftun_config_t *config,
                                       uint32_t socket_mark, void **out)
{
  (void)budget;
  (void)socket_mark;
  if (config == NULL || out == NULL) return FTUN_E_INVALID;
  fake_plan++;
  *out = &fake_plan;
  return plan_error;
}

static ftun_status_t fake_plan_destroy(void **plan)
{
  if (plan == NULL || *plan != &fake_plan) return FTUN_E_INVALID;
  if (plan_destroy_failures != 0u) {
    plan_destroy_failures--;
    return FTUN_E_AGAIN;
  }
  fake_plan--;
  *plan = NULL;
  return FTUN_OK;
}

static ftun_status_t fake_prepare(
  ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations,
  const ftun_core_service_binding_t *binding,
  const ftun_config_t *config,
  uint64_t generation, void **out)
{
  (void)binding;
  if (core == NULL || budget == NULL || operations == NULL || config == NULL ||
      generation == 0u || out == NULL) return FTUN_E_INVALID;
  fake.prepared++;
  *out = &fake;
  return prepare_error;
}

static ftun_status_t fake_activate(void *implementation)
{
  if (implementation != &fake) return FTUN_E_INVALID;
  fake.activated++;
  return activate_error;
}

static ftun_status_t fake_reload_prepare(
  void *implementation, const ftun_config_t *config, uint64_t generation)
{
  if (implementation != &fake || config == NULL || generation == 0u) {
    return FTUN_E_INVALID;
  }
  fake.reload_prepared++;
  return reload_error;
}

static ftun_status_t fake_reload_prepare_planned(
  void *implementation, const ftun_config_t *config, uint64_t generation,
  const void *plan)
{
  if (implementation != &fake || config == NULL || generation == 0u ||
      plan != &fake_plan) return FTUN_E_INVALID;
  fake.reload_prepared++;
  return reload_error;
}

static ftun_status_t fake_reload_commit(void *implementation,
                                        uint64_t generation)
{
  if (implementation != &fake || generation == 0u) return FTUN_E_INVALID;
  fake.reload_committed++;
  return FTUN_OK;
}

static ftun_status_t fake_reload_abort(void *implementation)
{
  if (implementation != &fake) return FTUN_E_INVALID;
  fake.reload_aborted++;
  if (abort_failures != 0u) {
    abort_failures--;
    return FTUN_E_AGAIN;
  }
  return FTUN_OK;
}

static ftun_status_t fake_run_once(
  void *implementation, bool may_block,
  ftun_core_service_run_usage_t *out_usage)
{
  if (implementation != &fake || !may_block || out_usage == NULL) {
    return FTUN_E_INVALID;
  }
  fake.ran++;
  out_usage->work = 3u;
  out_usage->quota_exhausted = true;
  return FTUN_OK;
}

static ftun_status_t fake_wakeup(void *implementation)
{
  if (implementation != &fake) return FTUN_E_INVALID;
  fake.woke++;
  return FTUN_OK;
}

static ftun_status_t fake_stop_until(void *implementation,
                                     uint64_t deadline_ms)
{
  if (implementation != &fake || deadline_ms == 0u) return FTUN_E_INVALID;
  fake.stopped++;
  return FTUN_OK;
}

static ftun_status_t fake_quiesce(void *implementation)
{
  if (implementation != &fake) return FTUN_E_INVALID;
  fake.quiesced++;
  return FTUN_OK;
}

static ftun_status_t fake_drain_until(void *implementation,
                                      uint64_t deadline_ms)
{
  if (implementation != &fake || deadline_ms == 0u) return FTUN_E_INVALID;
  fake.drained++;
  return FTUN_OK;
}

static ftun_status_t fake_destroy_until(void **implementation,
                                        uint64_t deadline_ms)
{
  if (implementation == NULL || *implementation != &fake ||
      deadline_ms == 0u) return FTUN_E_INVALID;
  fake.destroy_attempts++;
  if (destroy_failures != 0u) {
    destroy_failures--;
    return FTUN_E_TIMEOUT;
  }
  *implementation = NULL;
  return FTUN_OK;
}

static const ftun_core_service_descriptor_t descriptor = {
  "fake", fake_plan_prepare, fake_plan_destroy, fake_prepare, fake_activate,
  fake_reload_prepare, fake_reload_prepare_planned, fake_reload_commit,
  fake_reload_abort, fake_run_once, fake_wakeup, fake_quiesce,
  fake_drain_until,
  fake_stop_until, fake_destroy_until,
  NULL,
  NULL /* network_changed */
};

static ftun_status_t empty_plan_prepare(ftun_budget_t *budget,
  const ftun_config_t *config,
                                        uint32_t socket_mark, void **out)
{
  (void)budget;
  (void)config;
  (void)socket_mark;
  *out = NULL;
  return FTUN_OK;
}

static ftun_status_t empty_plan_destroy(void **plan)
{
  return plan != NULL && *plan == NULL ? FTUN_OK : FTUN_E_STATE_CORRUPT;
}

static int failed_lifecycle(void)
{
  ftun_core_service_t service = {0};
  ftun_core_service_plan_t plan = {0};
  ftun_core_service_run_usage_t usage;
  ftun_core_service_descriptor_t empty = descriptor;
  const ftun_config_t *config = (const ftun_config_t *)(uintptr_t)1u;
  ftun_core_t *core = (ftun_core_t *)(uintptr_t)1u;
  ftun_budget_t *budget = (ftun_budget_t *)(uintptr_t)1u;
  ftun_operation_queue_t *operations =
    (ftun_operation_queue_t *)(uintptr_t)1u;
  memset(&fake, 0, sizeof(fake));
  prepare_error = FTUN_E_IO;
  destroy_failures = 1u;
  CHECK(ftun_core_service_prepare(&service, &descriptor, core, budget,
    operations, NULL, config, 1u) == FTUN_E_IO);
  CHECK(service.implementation == &fake && service.descriptor == &descriptor &&
        service.cleanup_only && !service.prepared &&
        service.first_error == FTUN_E_IO && fake.destroy_attempts == 0u);
  CHECK(ftun_core_service_prepare(&service, &descriptor, core, budget,
    operations, NULL, config, 1u) == FTUN_E_AGAIN);
  CHECK(ftun_core_service_activate(&service) == FTUN_E_STALE);
  CHECK(ftun_core_service_run_once(&service, false, &usage) == FTUN_E_STALE);
  CHECK(ftun_core_service_quiesce(&service) == FTUN_OK);
  CHECK(ftun_core_service_stop_until(&service, 1u) == FTUN_OK);
  CHECK(fake.quiesced == 0u && fake.stopped == 0u);
  CHECK(ftun_core_service_destroy_until(&service, 1u) == FTUN_E_TIMEOUT);
  CHECK(service.implementation == &fake &&
        service.first_error == FTUN_E_IO && service.cleanup_error == FTUN_E_TIMEOUT);
  CHECK(ftun_core_service_destroy_until(&service, 1u) == FTUN_OK);
  CHECK(service.implementation == NULL && service.descriptor == NULL);
  CHECK(ftun_core_service_destroy_until(&service, 1u) == FTUN_OK);
  CHECK(fake.destroy_attempts == 2u);

  plan_error = FTUN_E_IO;
  plan_destroy_failures = 1u;
  CHECK(ftun_core_service_plan_prepare(&descriptor, budget, config, 0u, &plan) ==
        FTUN_E_IO);
  CHECK(plan.implementation == &fake_plan && plan.descriptor == &descriptor &&
        plan.cleanup_only && plan.first_error == FTUN_E_IO && fake_plan == 1u);
  CHECK(ftun_core_service_plan_prepare(&descriptor, budget, config, 0u, &plan) ==
        FTUN_E_AGAIN);
  CHECK(ftun_core_service_plan_destroy(&plan) == FTUN_E_AGAIN);
  CHECK(plan.implementation == &fake_plan && plan.cleanup_error == FTUN_E_AGAIN);
  CHECK(ftun_core_service_plan_destroy(&plan) == FTUN_OK && fake_plan == 0u);
  CHECK(ftun_core_service_plan_destroy(&plan) == FTUN_OK);
  empty.plan_prepare = empty_plan_prepare;
  empty.plan_destroy = empty_plan_destroy;
  CHECK(ftun_core_service_plan_prepare(&empty, budget, config, 0u, &plan) == FTUN_OK);
  CHECK(plan.implementation == NULL && plan.descriptor == &empty);
  CHECK(ftun_core_service_plan_prepare(&empty, budget, config, 0u, &plan) == FTUN_E_AGAIN);
  CHECK(ftun_core_service_plan_destroy(&plan) == FTUN_OK);

  prepare_error = FTUN_OK;
  activate_error = FTUN_E_IO;
  CHECK(ftun_core_service_prepare(&service, &descriptor, core, budget,
    operations, NULL, config, 1u) == FTUN_OK);
  CHECK(ftun_core_service_activate(&service) == FTUN_E_IO);
  CHECK(service.cleanup_only && service.prepared);
  CHECK(ftun_core_service_activate(&service) == FTUN_E_STALE);
  CHECK(ftun_core_service_quiesce(&service) == FTUN_OK && fake.quiesced == 1u);
  CHECK(ftun_core_service_destroy_until(&service, 1u) == FTUN_OK);

  activate_error = FTUN_OK;
  reload_error = FTUN_E_IO;
  abort_failures = 1u;
  CHECK(ftun_core_service_prepare(&service, &descriptor, core, budget,
    operations, NULL, config, 1u) == FTUN_OK);
  CHECK(ftun_core_service_activate(&service) == FTUN_OK);
  CHECK(ftun_core_service_reload_prepare(&service, config, 2u) == FTUN_E_IO);
  CHECK(service.reload_pending && !service.reload_ready);
  CHECK(ftun_core_service_reload_commit(&service, 2u) == FTUN_E_STALE);
  CHECK(ftun_core_service_reload_prepare(&service, config, 2u) == FTUN_E_AGAIN);
  CHECK(ftun_core_service_reload_abort(&service) == FTUN_E_AGAIN);
  CHECK(service.reload_pending && service.cleanup_error == FTUN_E_AGAIN);
  CHECK(ftun_core_service_reload_abort(&service) == FTUN_OK);
  CHECK(!service.reload_pending);
  reload_error = FTUN_OK;
  CHECK(ftun_core_service_reload_prepare(&service, config, 2u) == FTUN_OK);
  CHECK(ftun_core_service_reload_commit(&service, 2u) == FTUN_OK);
  CHECK(ftun_core_service_destroy_until(&service, 1u) == FTUN_OK);
  return 0;
}

int main(void)
{
  ftun_core_service_t service;
  ftun_core_service_plan_t plan;
  ftun_core_service_plan_t wrong;
  ftun_core_service_run_usage_t usage;
  ftun_core_service_descriptor_t other = descriptor;
  const ftun_config_t *config = (const ftun_config_t *)(uintptr_t)1u;
  ftun_core_t *core = (ftun_core_t *)(uintptr_t)1u;
  ftun_budget_t *budget = (ftun_budget_t *)(uintptr_t)1u;
  ftun_operation_queue_t *operations =
    (ftun_operation_queue_t *)(uintptr_t)1u;
  memset(&fake, 0, sizeof(fake));
  memset(&service, 0, sizeof(service));
  memset(&plan, 0, sizeof(plan));
  memset(&wrong, 0, sizeof(wrong));
  memset(&usage, 0, sizeof(usage));
  CHECK(ftun_core_service_descriptor_valid(&descriptor));
  CHECK(ftun_core_service_plan_prepare(&descriptor, budget, config, 0u, &plan) ==
        FTUN_OK);
  CHECK(ftun_core_service_prepare(&service, &descriptor, core, budget,
        operations, NULL, config, 1u) == FTUN_OK);
  CHECK(ftun_core_service_activate(&service) == FTUN_OK);
  wrong = plan;
  wrong.descriptor = &other;
  CHECK(ftun_core_service_reload_prepare_planned(
        &service, config, 2u, &wrong) == FTUN_E_INVALID);
  CHECK(ftun_core_service_reload_prepare_planned(
        &service, config, 2u, &plan) == FTUN_OK);
  CHECK(ftun_core_service_reload_commit(&service, 2u) == FTUN_OK);
  CHECK(ftun_core_service_reload_prepare(&service, config, 3u) == FTUN_OK);
  CHECK(ftun_core_service_reload_abort(&service) == FTUN_OK);
  CHECK(ftun_core_service_run_once(&service, true, &usage) == FTUN_OK);
  CHECK(usage.work == 3u && usage.quota_exhausted);
  CHECK(ftun_core_service_wakeup(&service) == FTUN_OK);
  CHECK(ftun_core_service_quiesce(&service) == FTUN_OK);
  CHECK(ftun_core_service_drain_until(&service, 1u) == FTUN_OK);
  CHECK(ftun_core_service_stop_until(&service, 1u) == FTUN_OK);
  CHECK(ftun_core_service_destroy_until(&service, 1u) == FTUN_E_TIMEOUT);
  CHECK(service.implementation == &fake);
  CHECK(ftun_core_service_destroy_until(&service, 1u) == FTUN_OK);
  CHECK(service.implementation == NULL && service.descriptor == NULL);
  CHECK(ftun_core_service_plan_destroy(&plan) == FTUN_OK);
  CHECK(fake.prepared == 1u && fake.activated == 1u &&
        fake.reload_prepared == 2u && fake.reload_committed == 1u &&
        fake.reload_aborted == 1u && fake.ran == 1u && fake.woke == 1u &&
        fake.quiesced == 1u && fake.drained == 1u && fake.stopped == 1u &&
        fake.destroy_attempts == 2u && fake_plan == 0u);
  CHECK(failed_lifecycle() == 0);
  return 0;
}
