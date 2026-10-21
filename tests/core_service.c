#include "core/service.h"

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

static ftun_status_t fake_plan_prepare(const ftun_config_t *config,
                                       uint32_t socket_mark, void **out)
{
  (void)socket_mark;
  if (config == NULL || out == NULL) return FTUN_E_INVALID;
  fake_plan++;
  *out = &fake_plan;
  return FTUN_OK;
}

static ftun_status_t fake_plan_destroy(void **plan)
{
  if (plan == NULL || *plan != &fake_plan) return FTUN_E_INVALID;
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
  return FTUN_OK;
}

static ftun_status_t fake_activate(void *implementation)
{
  if (implementation != &fake) return FTUN_E_INVALID;
  fake.activated++;
  return FTUN_OK;
}

static ftun_status_t fake_reload_prepare(
  void *implementation, const ftun_config_t *config, uint64_t generation)
{
  if (implementation != &fake || config == NULL || generation == 0u) {
    return FTUN_E_INVALID;
  }
  fake.reload_prepared++;
  return FTUN_OK;
}

static ftun_status_t fake_reload_prepare_planned(
  void *implementation, const ftun_config_t *config, uint64_t generation,
  const void *plan)
{
  if (implementation != &fake || config == NULL || generation == 0u ||
      plan != &fake_plan) return FTUN_E_INVALID;
  fake.reload_prepared++;
  return FTUN_OK;
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
  if (fake.destroy_attempts == 1u) return FTUN_E_TIMEOUT;
  *implementation = NULL;
  return FTUN_OK;
}

static const ftun_core_service_descriptor_t descriptor = {
  "fake", fake_plan_prepare, fake_plan_destroy, fake_prepare, fake_activate,
  fake_reload_prepare, fake_reload_prepare_planned, fake_reload_commit,
  fake_reload_abort, fake_run_once, fake_wakeup, fake_quiesce,
  fake_drain_until,
  fake_stop_until, fake_destroy_until
};

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
  CHECK(ftun_core_service_plan_prepare(&descriptor, config, 0u, &plan) ==
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
  return 0;
}
