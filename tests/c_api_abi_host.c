#define _POSIX_C_SOURCE 200809L
#include "core/core.h"
#include "c_api_abi_fixture.h"
#include "c_api_abi_layout.h"

#include <string.h>
#include <time.h>

typedef struct {
  ftun_core_t *core;
  int (*tick)(void *, void *);
  void *user;
  int blocked;
  uint64_t deadline;
} test_service_t;

static test_service_t service;
static void *saved_control;
static int fail_usage;

size_t ftun_test_current_layout(size_t *out, size_t capacity)
{
  return ftun_test_abi_layout(out, capacity);
}

ftun_status_t __real_ftun_operation_queue_get_usage(
  const ftun_operation_queue_t *queue, ftun_operation_queue_usage_t *out);

ftun_status_t __wrap_ftun_operation_queue_get_usage(
  const ftun_operation_queue_t *queue, ftun_operation_queue_usage_t *out)
{
  if (fail_usage) {
    fail_usage = 0;
    return FTUN_E_IO;
  }
  return __real_ftun_operation_queue_get_usage(queue, out);
}

void ftun_test_fail_usage(void)
{
  fail_usage = 1;
}

int ftun_test_control_detach(void *core, int detach)
{
  ftun_status_t status;
  if (detach) {
    status = ftun_core_context_control(core, &saved_control);
    if (status != FTUN_OK) return (int)status;
    return (int)ftun_core_context_set_control(core, NULL);
  }
  status = ftun_core_context_set_control(core, saved_control);
  saved_control = NULL;
  return (int)status;
}

int ftun_test_budget_limits(void *core, size_t limits[3])
{
  ftun_budget_t *budget = NULL;
  ftun_budget_usage_t usage;
  ftun_status_t status = ftun_core_context_budget(core, &budget);
  if (status == FTUN_OK) status = ftun_budget_get_usage(budget, &usage);
  if (status != FTUN_OK) return (int)status;
  limits[0] = usage.limits.memory_bytes;
  limits[1] = usage.limits.descriptors;
  limits[2] = usage.limits.queue_slots;
  return FTUN_OK;
}

void ftun_test_service_begin(int (*tick)(void *, void *), void *user,
                              int blocked)
{
  memset(&service, 0, sizeof(service));
  service.tick = tick;
  service.user = user;
  service.blocked = blocked;
}

void ftun_test_service_release(void)
{
  service.blocked = 0;
}

uint64_t ftun_test_service_deadline(void)
{
  return service.deadline;
}

static ftun_status_t plan_prepare(ftun_budget_t *budget,
  const ftun_config_t *config,
                                   uint32_t mark, void **out)
{
  (void)budget;
  (void)config;
  (void)mark;
  *out = &service;
  return FTUN_OK;
}

static ftun_status_t plan_destroy(void **plan)
{
  *plan = NULL;
  return FTUN_OK;
}

static ftun_status_t prepare(ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations, const ftun_core_service_binding_t *binding,
  const ftun_config_t *config, uint64_t generation, void **out)
{
  (void)budget;
  (void)operations;
  (void)binding;
  (void)config;
  (void)generation;
  service.core = core;
  *out = &service;
  return FTUN_OK;
}

static ftun_status_t success(void *implementation)
{
  return implementation == &service ? FTUN_OK : FTUN_E_INVALID;
}

static ftun_status_t reload_prepare(void *implementation,
  const ftun_config_t *config, uint64_t generation)
{
  (void)config;
  (void)generation;
  return success(implementation);
}

static ftun_status_t reload_planned(void *implementation,
  const ftun_config_t *config, uint64_t generation, const void *plan)
{
  (void)plan;
  return reload_prepare(implementation, config, generation);
}

static ftun_status_t reload_commit(void *implementation, uint64_t generation)
{
  (void)generation;
  return success(implementation);
}

static ftun_status_t run_once(void *implementation, bool may_block,
  ftun_core_service_run_usage_t *usage)
{
  const struct timespec pause = {0, 2 * 1000 * 1000};
  (void)may_block;
  if (implementation != &service) return FTUN_E_INVALID;
  (void)nanosleep(&pause, NULL);
  usage->work = 7u;
  usage->busy_ms = 2u;
  usage->deadline_lateness_ms = 13u;
  usage->quota_exhausted = true;
  return service.tick(service.core, service.user) == 0 ? FTUN_OK : FTUN_E_IO;
}

static ftun_status_t drain_until(void *implementation, uint64_t deadline)
{
  (void)deadline;
  return success(implementation);
}

static ftun_status_t stop_until(void *implementation, uint64_t deadline)
{
  if (implementation != &service) return FTUN_E_INVALID;
  service.deadline = deadline;
  return service.blocked ? FTUN_E_TIMEOUT : FTUN_OK;
}

static ftun_status_t destroy_until(void **implementation, uint64_t deadline)
{
  (void)deadline;
  if (*implementation != &service) return FTUN_E_INVALID;
  if (service.blocked) return FTUN_E_TIMEOUT;
  *implementation = NULL;
  return FTUN_OK;
}

static const ftun_core_service_descriptor_t descriptor = {
  "abi-test", plan_prepare, plan_destroy, prepare, success,
  reload_prepare, reload_planned, reload_commit, success,
  run_once, success, success, drain_until, stop_until, destroy_until
};

int ftun_test_service_create(const void *options, void **out)
{
  ftun_core_t *core = NULL;
  ftun_status_t status = ftun_core_create_with_service(options, &descriptor, &core);
  *out = core;
  return (int)status;
}
