#include "core/module_plan.h"
#include "core/context.h"
#include "core/operation.h"
#include "config/compile.h"
#include "util/event_log.h"

#include <stdint.h>
#include <pthread.h>
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
  char prepare;
  char activate;
  char quiesce;
  char drain;
  char destroy;
  char plan_prepare;
  char plan_destroy;
  char reload_prepare;
  char reload_commit;
  char reload_abort;
  int fail_activate;
  int fail_reload_prepare;
  int timeout_drain;
} fake_module_t;

static fake_module_t module_a = {
  'a', 'A', 'x', 'm', 'u', 'p', 'r', 'c', 'C', 'e', 0, 0, 0
};
static fake_module_t module_b = {
  'b', 'B', 'y', 'n', 'v', 'q', 's', 'd', 'D', 'f', 0, 0, 0
};
static char events[256];
static size_t event_count;
static unsigned int plan_a;
static unsigned int plan_b;
static ftun_budget_t *last_plan_budget;
static bool fail_plan_calloc;
void *__real_calloc(size_t count, size_t size);
void *__wrap_calloc(size_t count, size_t size)
{
  if (fail_plan_calloc) {
    fail_plan_calloc = false;
    return NULL;
  }
  return __real_calloc(count, size);
}
typedef struct {
  int fail_prepare;
  int fail_plan;
  unsigned int destroy_failures;
  unsigned int plan_destroy_failures;
  unsigned int abort_failures;
  unsigned int live;
  unsigned int pending;
  uint64_t destroy_deadline;
  uint64_t drain_deadline;
  ftun_status_t run_error;
  ftun_status_t quiesce_error;
  ftun_status_t drain_error;
  ftun_status_t destroy_error;
} fake_faults_t;
static fake_faults_t faults_a;
static fake_faults_t faults_b;
static const uint32_t binding_a = UINT32_C(0xa1);
static const uint32_t binding_b = UINT32_C(0xb2);
static ftun_core_module_runtime_t *wake_during_poll;
static unsigned int blocking_calls;
static bool pending_quota;

static void *wake_runtime(void *value)
{
  return ftun_core_module_runtime_wakeup(value) == FTUN_OK ? value : NULL;
}

static fake_faults_t *faults(fake_module_t *module)
{
  return module == &module_a ? &faults_a : &faults_b;
}

static void record(char event)
{
  if (event_count + 1u < sizeof(events)) {
    events[event_count++] = event;
    events[event_count] = '\0';
  }
}

static void reset(void)
{
  event_count = 0u;
  events[0] = '\0';
  module_a.fail_activate = 0;
  module_b.fail_activate = 0;
  module_a.fail_reload_prepare = 0;
  module_b.fail_reload_prepare = 0;
  module_a.timeout_drain = 0;
  module_b.timeout_drain = 0;
  plan_a = 0u;
  plan_b = 0u;
  memset(&faults_a, 0, sizeof(faults_a));
  memset(&faults_b, 0, sizeof(faults_b));
}

static ftun_status_t plan_prepare_common(
  fake_module_t *module, unsigned int *plan, const ftun_config_t *config,
  void **out)
{
  if (config == NULL || out == NULL || *plan != 0u) return FTUN_E_INVALID;
  record(module->plan_prepare);
  *plan = 1u;
  *out = plan;
  return faults(module)->fail_plan ? FTUN_E_IO : FTUN_OK;
}

static ftun_status_t plan_prepare_a(ftun_budget_t *budget,
  const ftun_config_t *config,
                                    uint32_t socket_mark, void **out)
{
  last_plan_budget = budget;
  (void)socket_mark;
  return plan_prepare_common(&module_a, &plan_a, config, out);
}

static ftun_status_t plan_prepare_b(ftun_budget_t *budget,
  const ftun_config_t *config,
                                    uint32_t socket_mark, void **out)
{
  last_plan_budget = budget;
  (void)socket_mark;
  return plan_prepare_common(&module_b, &plan_b, config, out);
}

static ftun_status_t plan_destroy_common(fake_module_t *module,
                                         unsigned int *plan, void **value)
{
  if (value == NULL || *value != plan || *plan == 0u) return FTUN_E_INVALID;
  record(module->plan_destroy);
  if (faults(module)->plan_destroy_failures != 0u) {
    faults(module)->plan_destroy_failures--;
    return FTUN_E_AGAIN;
  }
  *plan = 0u;
  *value = NULL;
  return FTUN_OK;
}

static ftun_status_t plan_destroy_a(void **value)
{
  return plan_destroy_common(&module_a, &plan_a, value);
}

static ftun_status_t plan_destroy_b(void **value)
{
  return plan_destroy_common(&module_b, &plan_b, value);
}

static ftun_status_t prepare_common(
  fake_module_t *module, ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations,
  const ftun_core_service_binding_t *binding,
  const ftun_config_t *config,
  uint64_t generation, void **out)
{
  const void *expected = module == &module_a
    ? (const void *)&binding_a : (const void *)&binding_b;
  if (core == NULL || budget == NULL || operations == NULL || config == NULL ||
      generation == 0u || out == NULL || binding == NULL ||
      binding->value != expected || binding->size != sizeof(binding_a)) {
    return FTUN_E_INVALID;
  }
  record(module->prepare);
  faults(module)->live++;
  *out = module;
  return faults(module)->fail_prepare ? FTUN_E_IO : FTUN_OK;
}

static ftun_status_t prepare_a(
  ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations,
  const ftun_core_service_binding_t *binding,
  const ftun_config_t *config,
  uint64_t generation, void **out)
{
  return prepare_common(&module_a, core, budget, operations, binding, config,
                        generation, out);
}

static ftun_status_t prepare_b(
  ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations,
  const ftun_core_service_binding_t *binding,
  const ftun_config_t *config,
  uint64_t generation, void **out)
{
  return prepare_common(&module_b, core, budget, operations, binding, config,
                        generation, out);
}

static ftun_status_t activate(void *implementation)
{
  fake_module_t *module = (fake_module_t *)implementation;
  if (module != &module_a && module != &module_b) return FTUN_E_INVALID;
  record(module->activate);
  return module->fail_activate ? FTUN_E_IO : FTUN_OK;
}

static ftun_status_t reload_prepare(
  void *implementation, const ftun_config_t *config, uint64_t generation)
{
  fake_module_t *module = (fake_module_t *)implementation;
  if ((module != &module_a && module != &module_b) || config == NULL ||
      generation == 0u) return FTUN_E_INVALID;
  record(module->reload_prepare);
  faults(module)->pending++;
  return module->fail_reload_prepare ? FTUN_E_IO : FTUN_OK;
}

static ftun_status_t reload_prepare_planned(
  void *implementation, const ftun_config_t *config, uint64_t generation,
  const void *plan)
{
  fake_module_t *module = (fake_module_t *)implementation;
  if ((module != &module_a && module != &module_b) || config == NULL ||
      generation == 0u ||
      (module == &module_a && plan != &plan_a) ||
      (module == &module_b && plan != &plan_b)) return FTUN_E_INVALID;
  record(module->reload_prepare);
  faults(module)->pending++;
  return module->fail_reload_prepare ? FTUN_E_IO : FTUN_OK;
}

static ftun_status_t reload_commit(void *implementation, uint64_t generation)
{
  fake_module_t *module = (fake_module_t *)implementation;
  if ((module != &module_a && module != &module_b) || generation == 0u) {
    return FTUN_E_INVALID;
  }
  record(module->reload_commit);
  if (faults(module)->pending != 1u) return FTUN_E_STATE_CORRUPT;
  faults(module)->pending--;
  return FTUN_OK;
}

static ftun_status_t reload_abort(void *implementation)
{
  fake_module_t *module = (fake_module_t *)implementation;
  if (module != &module_a && module != &module_b) return FTUN_E_INVALID;
  record(module->reload_abort);
  if (faults(module)->abort_failures != 0u) {
    faults(module)->abort_failures--;
    return FTUN_E_AGAIN;
  }
  if (faults(module)->pending != 1u) return FTUN_E_STATE_CORRUPT;
  faults(module)->pending--;
  return FTUN_OK;
}

static ftun_status_t run_once(
  void *implementation, bool may_block,
  ftun_core_service_run_usage_t *out_usage)
{
  fake_module_t *module = (fake_module_t *)implementation;
  if ((module != &module_a && module != &module_b) || out_usage == NULL) {
    return FTUN_E_INVALID;
  }
  memset(out_usage, 0, sizeof(*out_usage));
  out_usage->quota_exhausted = pending_quota;
  if (may_block) blocking_calls++;
  if (!may_block && module == &module_b && wake_during_poll != NULL) {
    pthread_t producer;
    void *result = NULL;
    ftun_core_module_runtime_t *runtime = wake_during_poll;
    wake_during_poll = NULL;
    /* 唤醒发生于最后一次非阻塞轮询，底层已消费通知且没有业务工作。 */
    if (pthread_create(&producer, NULL, wake_runtime, runtime) != 0) return FTUN_E_IO;
    if (pthread_join(producer, &result) != 0 || result != runtime) return FTUN_E_IO;
  }
  out_usage->work = may_block ? 1u : 0u;
  return faults(module)->run_error;
}

static ftun_status_t wakeup(void *implementation)
{
  return implementation == &module_a || implementation == &module_b
    ? FTUN_OK : FTUN_E_INVALID;
}

static ftun_status_t quiesce(void *implementation)
{
  fake_module_t *module = (fake_module_t *)implementation;
  if (module != &module_a && module != &module_b) return FTUN_E_INVALID;
  record(module->quiesce);
  return faults(module)->quiesce_error;
}

static ftun_status_t drain_until(void *implementation, uint64_t deadline_ms)
{
  fake_module_t *module = (fake_module_t *)implementation;
  if ((module != &module_a && module != &module_b) || deadline_ms == 0u) {
    return FTUN_E_INVALID;
  }
  record(module->drain);
  faults(module)->drain_deadline = deadline_ms;
  if (module->timeout_drain) {
    module->timeout_drain = 0;
    return FTUN_E_TIMEOUT;
  }
  return faults(module)->drain_error;
}

static ftun_status_t stop_until(void *implementation, uint64_t deadline_ms)
{
  ftun_status_t status = quiesce(implementation);
  return status == FTUN_OK ? drain_until(implementation, deadline_ms) : status;
}

static ftun_status_t destroy_until(void **implementation,
                                   uint64_t deadline_ms)
{
  fake_module_t *module;
  if (implementation == NULL || deadline_ms == 0u) return FTUN_E_INVALID;
  module = (fake_module_t *)*implementation;
  if (module != &module_a && module != &module_b) return FTUN_E_INVALID;
  record(module->destroy);
  faults(module)->destroy_deadline = deadline_ms;
  if (faults(module)->destroy_error != FTUN_OK) return faults(module)->destroy_error;
  if (faults(module)->destroy_failures != 0u) {
    faults(module)->destroy_failures--;
    return FTUN_E_TIMEOUT;
  }
  if (faults(module)->live != 1u || faults(module)->pending != 0u) {
    return FTUN_E_STATE_CORRUPT;
  }
  faults(module)->live--;
  *implementation = NULL;
  return FTUN_OK;
}

static const ftun_core_service_descriptor_t service_a = {
  "a", plan_prepare_a, plan_destroy_a, prepare_a, activate,
  reload_prepare, reload_prepare_planned, reload_commit, reload_abort,
  run_once, wakeup, quiesce, drain_until, stop_until, destroy_until,
  NULL,
  NULL /* network_changed */
};

static const ftun_core_service_descriptor_t service_b = {
  "b", plan_prepare_b, plan_destroy_b, prepare_b, activate,
  reload_prepare, reload_prepare_planned, reload_commit, reload_abort,
  run_once, wakeup, quiesce, drain_until, stop_until, destroy_until,
  NULL,
  NULL /* network_changed */
};

static const ftun_core_module_descriptor_t modules[] = {
  {
    .name = "core",
    .capability = FTUN_BUILD_MODULE_CORE
  },
  {
    .name = "a",
    .capability = FTUN_BUILD_MODULE_PROXY,
    .dependencies = FTUN_BUILD_MODULE_CORE,
    .startup_order = 20u,
    .service = &service_a,
    .binding = {&binding_a, sizeof(binding_a)}
  },
  {
    .name = "b",
    .capability = FTUN_BUILD_MODULE_DNS,
    .dependencies = FTUN_BUILD_MODULE_CORE | FTUN_BUILD_MODULE_PROXY,
    .startup_order = 10u,
    .service = &service_b,
    .binding = {&binding_b, sizeof(binding_b)}
  }
};

static const ftun_core_module_catalog_t catalog = {
  modules, sizeof(modules) / sizeof(modules[0]), FTUN_BUILD_MODULE_TUN
};

static void set_config(ftun_config_t *config, ftun_feature_plan_t *plan,
                       uint32_t built, uint32_t required)
{
  memset(config, 0, sizeof(*config));
  memset(plan, 0, sizeof(*plan));
  plan->built_modules = built;
  plan->required_modules = required;
  config->plan = plan;
}

static int failed_cleanup(void)
{
  ftun_core_module_runtime_t *runtime = NULL;
  ftun_core_module_reload_plan_t *reload_plan = NULL;
  ftun_core_module_info_t info;
  ftun_core_module_descriptor_t extended[4];
  ftun_core_module_catalog_t extended_catalog;
  ftun_config_t config;
  ftun_feature_plan_t plan;
  ftun_status_t first_error;
  ftun_status_t cleanup_error;
  const uint32_t required = FTUN_BUILD_MODULE_CORE | FTUN_BUILD_MODULE_PROXY |
    FTUN_BUILD_MODULE_DNS;
  ftun_core_t *core = NULL;
  ftun_budget_t *budget = NULL;
  ftun_operation_queue_t *operations = NULL;

  CHECK(ftun_budget_create(NULL, 65536u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 4u, &operations) == FTUN_OK);
  reset();
  memcpy(extended, modules, sizeof(modules));
  extended[3] = modules[1];
  extended[3].name = "later";
  extended[3].capability = FTUN_BUILD_MODULE_FRS;
  extended[3].dependencies = FTUN_BUILD_MODULE_DNS;
  extended_catalog = (ftun_core_module_catalog_t){extended, 4u, 0u};
  set_config(&config, &plan, required | FTUN_BUILD_MODULE_FRS,
             required | FTUN_BUILD_MODULE_FRS);
  faults_b.fail_prepare = 1;
  faults_a.destroy_failures = 1u;
  faults_b.destroy_failures = 1u;
  CHECK(ftun_core_module_runtime_prepare(&extended_catalog, core, budget,
    operations, &config, 1u, &runtime, NULL) == FTUN_E_IO);
  CHECK(runtime != NULL && strcmp(events, "abv") == 0);
  CHECK(faults_a.live == 1u && faults_b.live == 1u &&
        faults_b.destroy_deadline != UINT64_MAX);
  CHECK(ftun_core_module_runtime_get_info(runtime, &info) == FTUN_OK);
  CHECK(info.cleanup_only && info.first_error == FTUN_E_IO &&
        info.cleanup_error == FTUN_E_TIMEOUT && info.prepared_count == 2u);
  CHECK(ftun_core_module_runtime_prepare(&extended_catalog, core, budget,
    operations, &config, 1u, &runtime, NULL) == FTUN_E_AGAIN);
  CHECK(ftun_core_module_runtime_activate(runtime, 100u) == FTUN_E_STALE);
  CHECK(ftun_core_module_runtime_destroy_until(&runtime, 100u) == FTUN_E_TIMEOUT);
  CHECK(runtime != NULL && strcmp(events, "abvvu") == 0);
  CHECK(faults_a.live == 1u && faults_b.live == 0u);
  CHECK(ftun_core_module_runtime_destroy_until(&runtime, 100u) == FTUN_OK);
  CHECK(runtime == NULL && strcmp(events, "abvvuu") == 0);
  CHECK(faults_a.live == 0u && faults_b.live == 0u);
  CHECK(ftun_core_module_runtime_destroy_until(&runtime, 100u) == FTUN_OK);

  reset();
  set_config(&config, &plan, required, required);
  faults_b.fail_plan = 1;
  faults_b.plan_destroy_failures = 1u;
  faults_a.plan_destroy_failures = 1u;
  CHECK(ftun_core_module_reload_plan_prepare(&catalog, budget, &config, 0u,
    &reload_plan, NULL) == FTUN_E_IO);
  CHECK(reload_plan != NULL && plan_a == 1u && plan_b == 1u &&
        strcmp(events, "pqs") == 0);
  CHECK(ftun_core_module_reload_plan_get_errors(reload_plan,
    &first_error, &cleanup_error) == FTUN_OK);
  CHECK(first_error == FTUN_E_IO && cleanup_error == FTUN_E_AGAIN);
  CHECK(ftun_core_module_reload_plan_prepare(&catalog, budget, &config, 0u,
    &reload_plan, NULL) == FTUN_E_AGAIN);
  CHECK(ftun_core_module_reload_plan_destroy(&reload_plan) == FTUN_E_AGAIN);
  CHECK(reload_plan != NULL && plan_a == 1u && plan_b == 0u);
  CHECK(ftun_core_module_reload_plan_destroy(&reload_plan) == FTUN_OK);
  CHECK(reload_plan == NULL && plan_a == 0u && plan_b == 0u &&
        strcmp(events, "pqssrr") == 0);

  reset();
  module_b.fail_activate = 1;
  module_b.timeout_drain = 1;
  CHECK(ftun_core_module_runtime_prepare(&catalog, core, budget, operations,
    &config, 1u, &runtime, NULL) == FTUN_OK);
  CHECK(ftun_core_module_runtime_activate(runtime, UINT64_MAX) == FTUN_E_IO);
  CHECK(strcmp(events, "abAByxn") == 0 && faults_a.live == 1u &&
        faults_b.live == 1u && faults_b.drain_deadline != UINT64_MAX);
  CHECK(ftun_core_module_runtime_get_info(runtime, &info) == FTUN_OK);
  CHECK(info.cleanup_only && !info.rolled_back && info.first_error == FTUN_E_IO &&
        info.cleanup_error == FTUN_E_TIMEOUT);
  CHECK(ftun_core_module_runtime_activate(runtime, 100u) == FTUN_E_STALE);
  CHECK(ftun_core_module_runtime_destroy_until(&runtime, 100u) == FTUN_OK);
  CHECK(strcmp(events, "abAByxnnmvu") == 0 && faults_a.live == 0u &&
        faults_b.live == 0u);

  reset();
  CHECK(ftun_core_module_runtime_prepare(&catalog, core, budget, operations,
    &config, 1u, &runtime, NULL) == FTUN_OK);
  CHECK(ftun_core_module_runtime_activate(runtime, 100u) == FTUN_OK);
  module_b.fail_reload_prepare = 1;
  faults_b.abort_failures = 1u;
  faults_a.abort_failures = 1u;
  CHECK(ftun_core_module_runtime_reload_prepare(runtime, &config, 2u) ==
        FTUN_E_IO);
  CHECK(strcmp(events, "abABcdf") == 0 && faults_a.pending == 1u &&
        faults_b.pending == 1u);
  CHECK(ftun_core_module_runtime_get_info(runtime, &info) == FTUN_OK);
  CHECK(info.reload_pending_count == 2u && !info.reload_prepared &&
        info.first_error == FTUN_E_IO && info.cleanup_error == FTUN_E_AGAIN);
  CHECK(ftun_core_module_runtime_reload_prepare(runtime, &config, 2u) ==
        FTUN_E_STALE);
  CHECK(ftun_core_module_runtime_reload_commit(runtime, 2u) == FTUN_E_STALE);
  CHECK(ftun_core_module_runtime_reload_abort(runtime) == FTUN_E_AGAIN);
  CHECK(faults_a.pending == 1u && faults_b.pending == 0u);
  CHECK(ftun_core_module_runtime_reload_abort(runtime) == FTUN_OK);
  CHECK(faults_a.pending == 0u && faults_b.pending == 0u &&
        strcmp(events, "abABcdffee") == 0);
  module_b.fail_reload_prepare = 0;
  CHECK(ftun_core_module_runtime_reload_prepare(runtime, &config, 2u) == FTUN_OK);
  CHECK(ftun_core_module_runtime_reload_commit(runtime, 2u) == FTUN_OK);
  CHECK(ftun_core_module_runtime_destroy_until(&runtime, 100u) == FTUN_OK);
  CHECK(faults_a.live == 0u && faults_b.live == 0u);

  reset();
  CHECK(ftun_core_module_runtime_prepare(&catalog, core, budget, operations,
    &config, 1u, &runtime, NULL) == FTUN_OK);
  CHECK(ftun_core_module_runtime_activate(runtime, 100u) == FTUN_OK);
  CHECK(ftun_core_module_reload_plan_prepare(&catalog, budget, &config, 0u,
    &reload_plan, NULL) == FTUN_OK);
  module_b.fail_reload_prepare = 1;
  faults_a.abort_failures = 1u;
  CHECK(ftun_core_module_runtime_reload_prepare_planned(runtime, &config,
    2u, reload_plan) == FTUN_E_IO);
  CHECK(faults_a.pending == 1u && faults_b.pending == 0u);
  CHECK(ftun_core_module_runtime_destroy_until(&runtime, 100u) == FTUN_OK);
  CHECK(faults_a.pending == 0u && faults_b.pending == 0u &&
        faults_a.live == 0u && faults_b.live == 0u);
  CHECK(ftun_core_module_reload_plan_destroy(&reload_plan) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int failure_events(void)
{
  ftun_core_t *core = NULL;
  ftun_budget_t *budget = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_event_log_t *log = NULL;
  ftun_event_log_usage_t events_usage;
  ftun_core_module_runtime_t *runtime = NULL;
  ftun_core_service_run_usage_t usage;
  ftun_config_t config;
  ftun_feature_plan_t plan;
  ftun_diagnostic_t diagnostic;
  uint32_t built = FTUN_BUILD_MODULE_CORE | FTUN_BUILD_MODULE_PROXY | FTUN_BUILD_MODULE_DNS;
  reset();
  CHECK(ftun_budget_create(NULL, 65536u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 4u, &operations) == FTUN_OK);
  CHECK(ftun_event_log_create(budget, &log) == FTUN_OK);
  CHECK(ftun_core_context_set_event_log(core, log) == FTUN_OK);
  CHECK(ftun_core_context_publish_logger(core, NULL, true) == FTUN_OK);
  set_config(&config, &plan, built, built);
  CHECK(ftun_core_module_runtime_prepare(&catalog, core, budget, operations,
    &config, 4u, &runtime, &diagnostic) == FTUN_OK);
  CHECK(ftun_core_module_runtime_activate(runtime, 100u) == FTUN_OK);
  faults_b.run_error = FTUN_E_IO;
  CHECK(ftun_core_module_runtime_run_once(runtime, false, &usage) == FTUN_E_IO);
  CHECK(ftun_event_log_get_usage(log, &events_usage) == FTUN_OK &&
    events_usage.last_error.kind == FTUN_LIFECYCLE_MODULE_FAILED &&
    events_usage.last_error.module == FTUN_BUILD_MODULE_DNS &&
    events_usage.last_error.generation == 4u && events_usage.last_error.reason == FTUN_LIFECYCLE_REASON_RUN);
  faults_b.run_error = FTUN_OK;
  faults_b.quiesce_error = FTUN_E_IO;
  CHECK(ftun_core_module_runtime_quiesce(runtime) == FTUN_E_IO);
  CHECK(ftun_event_log_get_usage(log, &events_usage) == FTUN_OK &&
    events_usage.last_error.reason == FTUN_LIFECYCLE_REASON_QUIESCE);
  faults_b.quiesce_error = FTUN_OK;
  faults_b.drain_error = FTUN_E_IO;
  CHECK(ftun_core_module_runtime_drain_until(runtime, 100u) == FTUN_E_IO);
  CHECK(ftun_event_log_get_usage(log, &events_usage) == FTUN_OK &&
    events_usage.last_error.reason == FTUN_LIFECYCLE_REASON_DRAIN);
  faults_b.drain_error = FTUN_E_TIMEOUT;
  CHECK(ftun_core_module_runtime_drain_until(runtime, 100u) == FTUN_E_TIMEOUT);
  CHECK(ftun_event_log_get_usage(log, &events_usage) == FTUN_OK &&
    events_usage.last_error.status == FTUN_E_IO && events_usage.last_error.reason == FTUN_LIFECYCLE_REASON_DRAIN);
  faults_b.drain_error = FTUN_OK;
  faults_b.destroy_error = FTUN_E_IO;
  CHECK(ftun_core_module_runtime_destroy_until(&runtime, 100u) == FTUN_E_IO && runtime != NULL);
  CHECK(ftun_event_log_get_usage(log, &events_usage) == FTUN_OK &&
    events_usage.last_error.reason == FTUN_LIFECYCLE_REASON_DESTROY);
  faults_b.destroy_error = FTUN_OK;
  CHECK(ftun_core_module_runtime_destroy_until(&runtime, 100u) == FTUN_OK);
  CHECK(ftun_core_context_finish_logging(core, NULL) == FTUN_OK);
  CHECK(ftun_core_context_set_event_log(core, NULL) == FTUN_OK);
  CHECK(ftun_event_log_destroy(&log) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int resource_admission(void)
{
  const uint32_t required = FTUN_BUILD_MODULE_CORE | FTUN_BUILD_MODULE_PROXY |
    FTUN_BUILD_MODULE_DNS;
  ftun_core_t *core = NULL;
  ftun_budget_t *budget = NULL;
  ftun_reservation_t *hold = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_core_module_runtime_t *runtime = NULL;
  ftun_core_module_reload_plan_t *reload_plan = NULL;
  ftun_config_t config;
  ftun_feature_plan_t plan;
  ftun_budget_usage_t baseline, active, usage;
  CHECK(ftun_budget_create(NULL, 65536u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 4u, &operations) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &baseline) == FTUN_OK);
  set_config(&config, &plan, required, required);
  reset();
  CHECK(ftun_budget_reserve(budget, baseline.normal_available, &hold) == FTUN_OK);
  CHECK(ftun_core_module_runtime_prepare(&catalog, core, budget, operations,
    &config, 1u, &runtime, NULL) == FTUN_E_LIMIT);
  CHECK(runtime == NULL && event_count == 0u && faults_a.live == 0u && faults_b.live == 0u);
  CHECK(ftun_reservation_release(&hold) == FTUN_OK);
  CHECK(ftun_core_module_runtime_prepare(&catalog, core, budget, operations,
    &config, 1u, &runtime, NULL) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &active) == FTUN_OK && active.used > baseline.used);
  CHECK(active.used_resources.queue_slots == baseline.used_resources.queue_slots &&
        active.used_resources.descriptors == baseline.used_resources.descriptors);
  faults_b.destroy_failures = 1u;
  CHECK(ftun_core_module_runtime_destroy_until(&runtime, 100u) == FTUN_E_TIMEOUT);
  CHECK(runtime != NULL);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == active.used);
  CHECK(ftun_core_module_runtime_destroy_until(&runtime, 100u) == FTUN_OK && runtime == NULL);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == baseline.used &&
        usage.metadata_bytes == baseline.metadata_bytes);
  reset();
  faults_b.fail_prepare = 1;
  faults_b.destroy_failures = 1u;
  CHECK(ftun_core_module_runtime_prepare(&catalog, core, budget, operations,
    &config, 1u, &runtime, NULL) == FTUN_E_IO && runtime != NULL);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == active.used);
  CHECK(ftun_core_module_runtime_destroy_until(&runtime, 100u) == FTUN_OK && runtime == NULL);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == baseline.used &&
        usage.metadata_bytes == baseline.metadata_bytes);
  reset();
  last_plan_budget = NULL;
  CHECK(ftun_budget_reserve(budget, baseline.normal_available, &hold) == FTUN_OK);
  CHECK(ftun_core_module_reload_plan_prepare(&catalog, budget, &config, 0u,
    &reload_plan, NULL) == FTUN_E_LIMIT);
  CHECK(reload_plan == NULL && event_count == 0u && last_plan_budget == NULL);
  CHECK(ftun_reservation_release(&hold) == FTUN_OK);
  fail_plan_calloc = true;
  CHECK(ftun_core_module_reload_plan_prepare(&catalog, budget, &config, 0u,
    &reload_plan, NULL) == FTUN_E_LIMIT && reload_plan == NULL && !fail_plan_calloc);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == baseline.used);
  CHECK(ftun_core_module_reload_plan_prepare(&catalog, budget, &config, 0u,
    &reload_plan, NULL) == FTUN_OK && last_plan_budget == budget);
  CHECK(ftun_budget_get_usage(budget, &active) == FTUN_OK && active.used > baseline.used);
  faults_b.plan_destroy_failures = 1u;
  CHECK(ftun_core_module_reload_plan_destroy(&reload_plan) == FTUN_E_AGAIN);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == active.used);
  CHECK(ftun_core_module_reload_plan_destroy(&reload_plan) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == baseline.used);
  reset();
  faults_b.fail_plan = 1;
  faults_b.plan_destroy_failures = 1u;
  CHECK(ftun_core_module_reload_plan_prepare(&catalog, budget, &config, 0u,
    &reload_plan, NULL) == FTUN_E_IO && reload_plan != NULL);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == active.used);
  CHECK(ftun_core_module_reload_plan_destroy(&reload_plan) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == baseline.used &&
    usage.metadata_bytes == baseline.metadata_bytes);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(void)
{
  ftun_core_module_runtime_t *runtime = NULL;
  ftun_core_module_reload_plan_t *reload_plan = NULL;
  ftun_core_module_info_t info;
  ftun_core_service_run_usage_t usage;
  ftun_diagnostic_t diagnostic;
  ftun_config_t config;
  ftun_feature_plan_t plan;
  ftun_core_module_descriptor_t invalid_modules[3];
  ftun_core_module_descriptor_t compatible_modules[3];
  ftun_core_module_catalog_t invalid_catalog;
  ftun_core_module_catalog_t compatible_catalog;
  const uint32_t built = FTUN_BUILD_MODULE_CORE | FTUN_BUILD_MODULE_PROXY |
    FTUN_BUILD_MODULE_DNS;
  const uint32_t required = FTUN_BUILD_MODULE_CORE |
    FTUN_BUILD_MODULE_PROXY | FTUN_BUILD_MODULE_DNS;
  ftun_core_t *core = NULL;
  ftun_budget_t *budget = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_status_t status;

  CHECK(failed_cleanup() == 0);
  CHECK(failure_events() == 0);
  CHECK(resource_admission() == 0);
  CHECK(ftun_budget_create(NULL, 65536u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 4u, &operations) == FTUN_OK);

  reset();
  CHECK(ftun_core_module_catalog_valid(&catalog));
  set_config(&config, &plan, built, required);
  status = ftun_core_module_runtime_prepare(&catalog, core, budget, operations,
    &config, 1u, &runtime, &diagnostic);
  if (status != FTUN_OK) {
    fprintf(stderr, "module prepare status=%d message=%.*s\n", (int)status,
      (int)diagnostic.message.length,
      diagnostic.message.data == NULL ? "" : diagnostic.message.data);
  }
  CHECK(status == FTUN_OK);
  CHECK(strcmp(events, "ab") == 0);
  CHECK(ftun_core_module_runtime_get_info(runtime, &info) == FTUN_OK);
  CHECK(info.required_modules == required && info.selected_modules == required);
  CHECK(info.skipped_optional == FTUN_BUILD_MODULE_TUN);
  CHECK(info.module_count == 3u && info.service_count == 2u &&
        info.prepared_count == 3u);
  CHECK(ftun_core_module_runtime_activate(runtime, 100u) == FTUN_OK);
  CHECK(strcmp(events, "abAB") == 0);
  CHECK(ftun_core_module_runtime_run_once(runtime, true, &usage) == FTUN_OK);
  CHECK(usage.work == 1u);

  {
    unsigned int before = blocking_calls;
    CHECK(ftun_core_module_runtime_wakeup(runtime) == FTUN_OK);
    CHECK(ftun_core_module_runtime_run_once(runtime, true, &usage) == FTUN_OK);
    CHECK(usage.work == 0u && blocking_calls == before);
    wake_during_poll = runtime;
    CHECK(ftun_core_module_runtime_run_once(runtime, true, &usage) == FTUN_OK);
    CHECK(usage.work == 0u && blocking_calls == before && wake_during_poll == NULL);
    pending_quota = true;
    CHECK(ftun_core_module_runtime_run_once(runtime, true, &usage) == FTUN_OK);
    CHECK(usage.quota_exhausted && blocking_calls == before);
    pending_quota = false;
    CHECK(ftun_core_module_runtime_run_once(runtime, true, &usage) == FTUN_OK);
    CHECK(usage.work == 1u && blocking_calls == before + 1u);
  }

  memcpy(compatible_modules, modules, sizeof(compatible_modules));
  compatible_catalog = (ftun_core_module_catalog_t){
    compatible_modules, 3u, FTUN_BUILD_MODULE_TUN
  };
  CHECK(ftun_core_module_reload_plan_prepare(
        &compatible_catalog, budget, &config, 0u,
        &reload_plan, &diagnostic) == FTUN_OK);
  CHECK(strcmp(events, "abABpq") == 0);
  CHECK(ftun_core_module_runtime_reload_prepare_planned(
        runtime, &config, 2u, reload_plan) == FTUN_OK);
  CHECK(ftun_core_module_runtime_reload_commit(runtime, 2u) == FTUN_OK);
  CHECK(ftun_core_module_reload_plan_destroy(&reload_plan) == FTUN_OK);
  CHECK(strcmp(events, "abABpqcdCDsr") == 0);

  {
    size_t before = strlen(events);
    module_b.fail_reload_prepare = 1;
    CHECK(ftun_core_module_reload_plan_prepare(&catalog, budget, &config, 0u,
          &reload_plan, &diagnostic) == FTUN_OK);
    CHECK(ftun_core_module_runtime_reload_prepare_planned(
          runtime, &config, 3u, reload_plan) == FTUN_E_IO);
    CHECK(ftun_core_module_reload_plan_destroy(&reload_plan) == FTUN_OK);
    CHECK(strcmp(events + before, "pqcdfesr") == 0);
    module_b.fail_reload_prepare = 0;
  }

  {
    size_t before = strlen(events);
    set_config(&config, &plan, built,
               FTUN_BUILD_MODULE_CORE | FTUN_BUILD_MODULE_PROXY);
    CHECK(ftun_core_module_reload_plan_prepare(&catalog, budget, &config, 0u,
          &reload_plan, &diagnostic) == FTUN_OK);
    CHECK(ftun_core_module_runtime_reload_prepare_planned(
          runtime, &config, 3u, reload_plan) == FTUN_E_RESTART_REQUIRED);
    CHECK(ftun_core_module_reload_plan_destroy(&reload_plan) == FTUN_OK);
    CHECK(strcmp(events + before, "pr") == 0);
    set_config(&config, &plan, built, required);
  }

  CHECK(ftun_core_module_reload_plan_prepare(&catalog, budget, &config, 0u,
        &reload_plan, &diagnostic) == FTUN_OK);
  CHECK(ftun_core_module_runtime_reload_prepare_planned(
        runtime, &config, 3u, reload_plan) == FTUN_OK);
  CHECK(ftun_core_module_runtime_reload_abort(runtime) == FTUN_OK);
  CHECK(ftun_core_module_reload_plan_destroy(&reload_plan) == FTUN_OK);
  CHECK(strstr(events, "pqcdfe" "sr") != NULL);

  module_b.timeout_drain = 1;
  CHECK(ftun_core_module_runtime_stop_until(runtime, 100u) == FTUN_E_TIMEOUT);
  CHECK(ftun_core_module_runtime_stop_until(runtime, 100u) == FTUN_OK);
  {
    size_t length = strlen(events);
    CHECK(length >= 5u && strcmp(events + length - 5u, "yxnnm") == 0);
  }
  CHECK(ftun_core_module_runtime_stop_until(runtime, 100u) == FTUN_OK);
  CHECK(ftun_core_module_runtime_destroy_until(&runtime, 100u) == FTUN_OK);
  CHECK(runtime == NULL);
  {
    size_t length = strlen(events);
    CHECK(length >= 2u && strcmp(events + length - 2u, "vu") == 0);
  }

  /* 无依赖边的 provider/consumer 仍可由 Composition 固定启动顺序。 */
  {
    ftun_core_module_descriptor_t priority_modules[3];
    ftun_core_module_catalog_t priority_catalog;
    memcpy(priority_modules, modules, sizeof(priority_modules));
    priority_modules[2].dependencies = FTUN_BUILD_MODULE_CORE;
    priority_catalog = (ftun_core_module_catalog_t){
      priority_modules, 3u, FTUN_BUILD_MODULE_TUN
    };
    reset();
    set_config(&config, &plan, built, required);
    CHECK(ftun_core_module_runtime_prepare(&priority_catalog, core, budget,
          operations, &config, 1u, &runtime, NULL) == FTUN_OK);
    CHECK(strcmp(events, "ba") == 0);
    CHECK(ftun_core_module_runtime_activate(runtime, 100u) == FTUN_OK);
    CHECK(strcmp(events, "baBA") == 0);
    CHECK(ftun_core_module_runtime_destroy_until(&runtime, 100u) == FTUN_OK);
  }

  reset();
  module_b.fail_activate = 1;
  set_config(&config, &plan, built, required);
  CHECK(ftun_core_module_runtime_prepare(&catalog, core, budget, operations,
        &config, 1u, &runtime, NULL) == FTUN_OK);
  CHECK(ftun_core_module_runtime_activate(runtime, 100u) == FTUN_E_IO);
  CHECK(strcmp(events, "abAByxnmvu") == 0);
  CHECK(ftun_core_module_runtime_get_info(runtime, &info) == FTUN_OK);
  CHECK(info.rolled_back && info.active_count == 0u);
  CHECK(ftun_core_module_runtime_destroy_until(&runtime, 100u) == FTUN_OK);

  reset();
  set_config(&config, &plan, built,
             required | FTUN_BUILD_MODULE_TUN);
  CHECK(ftun_core_module_runtime_prepare(&catalog, core, budget, operations,
        &config, 1u, &runtime, &diagnostic) == FTUN_E_UNSUPPORTED);
  CHECK(runtime == NULL && diagnostic.error.status == FTUN_E_UNSUPPORTED &&
        diagnostic.path.data != NULL && diagnostic.message.data != NULL);

  {
    static const ftun_core_module_descriptor_t core_only_modules[] = {
      {
        .name = "core",
        .capability = FTUN_BUILD_MODULE_CORE
      }
    };
    static const ftun_core_module_catalog_t core_only = {
      core_only_modules, 1u, 0u
    };
    reset();
    set_config(&config, &plan, FTUN_BUILD_MODULE_CORE,
               FTUN_BUILD_MODULE_CORE);
    CHECK(ftun_core_module_runtime_prepare(&core_only, core, budget,
          operations, &config, 1u, &runtime, NULL) == FTUN_OK);
    CHECK(ftun_core_module_runtime_activate(runtime, 100u) ==
          FTUN_E_UNSUPPORTED);
    CHECK(ftun_core_module_runtime_destroy_until(&runtime, 100u) == FTUN_OK);
  }

  memcpy(invalid_modules, modules, sizeof(invalid_modules));
  invalid_modules[0].dependencies = FTUN_BUILD_MODULE_DNS;
  invalid_catalog.modules = invalid_modules;
  invalid_catalog.module_count = 3u;
  invalid_catalog.optional_modules = 0u;
  CHECK(!ftun_core_module_catalog_valid(&invalid_catalog));
  invalid_modules[0] = modules[0];
  invalid_modules[2].capability = FTUN_BUILD_MODULE_PROXY;
  CHECK(!ftun_core_module_catalog_valid(&invalid_catalog));
  invalid_modules[2] = modules[2];
  invalid_modules[1].binding.size = 0u;
  CHECK(!ftun_core_module_catalog_valid(&invalid_catalog));
  invalid_modules[1] = modules[1];
  invalid_modules[1].binding.value = NULL;
  CHECK(!ftun_core_module_catalog_valid(&invalid_catalog));
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}
