#include "core/module_plan.h"
#include "config/compile.h"

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
static const uint32_t binding_a = UINT32_C(0xa1);
static const uint32_t binding_b = UINT32_C(0xb2);

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
}

static ftun_status_t plan_prepare_common(
  fake_module_t *module, unsigned int *plan, const ftun_config_t *config,
  void **out)
{
  if (config == NULL || out == NULL || *plan != 0u) return FTUN_E_INVALID;
  record(module->plan_prepare);
  *plan = 1u;
  *out = plan;
  return FTUN_OK;
}

static ftun_status_t plan_prepare_a(const ftun_config_t *config,
                                    uint32_t socket_mark, void **out)
{
  (void)socket_mark;
  return plan_prepare_common(&module_a, &plan_a, config, out);
}

static ftun_status_t plan_prepare_b(const ftun_config_t *config,
                                    uint32_t socket_mark, void **out)
{
  (void)socket_mark;
  return plan_prepare_common(&module_b, &plan_b, config, out);
}

static ftun_status_t plan_destroy_common(fake_module_t *module,
                                         unsigned int *plan, void **value)
{
  if (value == NULL || *value != plan || *plan == 0u) return FTUN_E_INVALID;
  record(module->plan_destroy);
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
  *out = module;
  return FTUN_OK;
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
  return module->fail_reload_prepare ? FTUN_E_IO : FTUN_OK;
}

static ftun_status_t reload_commit(void *implementation, uint64_t generation)
{
  fake_module_t *module = (fake_module_t *)implementation;
  if ((module != &module_a && module != &module_b) || generation == 0u) {
    return FTUN_E_INVALID;
  }
  record(module->reload_commit);
  return FTUN_OK;
}

static ftun_status_t reload_abort(void *implementation)
{
  fake_module_t *module = (fake_module_t *)implementation;
  if (module != &module_a && module != &module_b) return FTUN_E_INVALID;
  record(module->reload_abort);
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
  out_usage->work = may_block ? 1u : 0u;
  return FTUN_OK;
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
  return FTUN_OK;
}

static ftun_status_t drain_until(void *implementation, uint64_t deadline_ms)
{
  fake_module_t *module = (fake_module_t *)implementation;
  if ((module != &module_a && module != &module_b) || deadline_ms == 0u) {
    return FTUN_E_INVALID;
  }
  record(module->drain);
  if (module->timeout_drain) {
    module->timeout_drain = 0;
    return FTUN_E_TIMEOUT;
  }
  return FTUN_OK;
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
  *implementation = NULL;
  return FTUN_OK;
}

static const ftun_core_service_descriptor_t service_a = {
  "a", plan_prepare_a, plan_destroy_a, prepare_a, activate,
  reload_prepare, reload_prepare_planned, reload_commit, reload_abort,
  run_once, wakeup, quiesce, drain_until, stop_until, destroy_until
};

static const ftun_core_service_descriptor_t service_b = {
  "b", plan_prepare_b, plan_destroy_b, prepare_b, activate,
  reload_prepare, reload_prepare_planned, reload_commit, reload_abort,
  run_once, wakeup, quiesce, drain_until, stop_until, destroy_until
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
  ftun_core_t *core = (ftun_core_t *)(uintptr_t)1u;
  ftun_budget_t *budget = (ftun_budget_t *)(uintptr_t)1u;
  ftun_operation_queue_t *operations =
    (ftun_operation_queue_t *)(uintptr_t)1u;
  ftun_status_t status;

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

  memcpy(compatible_modules, modules, sizeof(compatible_modules));
  compatible_catalog = (ftun_core_module_catalog_t){
    compatible_modules, 3u, FTUN_BUILD_MODULE_TUN
  };
  CHECK(ftun_core_module_reload_plan_prepare(
        &compatible_catalog, &config, 0u,
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
    CHECK(ftun_core_module_reload_plan_prepare(&catalog, &config, 0u,
          &reload_plan, &diagnostic) == FTUN_OK);
    CHECK(ftun_core_module_runtime_reload_prepare_planned(
          runtime, &config, 3u, reload_plan) == FTUN_E_IO);
    CHECK(ftun_core_module_reload_plan_destroy(&reload_plan) == FTUN_OK);
    CHECK(strcmp(events + before, "pqcdesr") == 0);
    module_b.fail_reload_prepare = 0;
  }

  {
    size_t before = strlen(events);
    set_config(&config, &plan, built,
               FTUN_BUILD_MODULE_CORE | FTUN_BUILD_MODULE_PROXY);
    CHECK(ftun_core_module_reload_plan_prepare(&catalog, &config, 0u,
          &reload_plan, &diagnostic) == FTUN_OK);
    CHECK(ftun_core_module_runtime_reload_prepare_planned(
          runtime, &config, 3u, reload_plan) == FTUN_E_RESTART_REQUIRED);
    CHECK(ftun_core_module_reload_plan_destroy(&reload_plan) == FTUN_OK);
    CHECK(strcmp(events + before, "pr") == 0);
    set_config(&config, &plan, built, required);
  }

  CHECK(ftun_core_module_reload_plan_prepare(&catalog, &config, 0u,
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
  CHECK(strcmp(events, "abABxnmvu") == 0);
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
  return 0;
}
