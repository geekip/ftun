#include "core/core.h"
#include "core/module_plan.h"
#include "config/compile.h"
#include "event/event.h"
#include "event/libev_adapter.h"
#include "dns/core_service.h"
#if defined(FTUN_HAVE_MODULE_PROXY)
#include "proxy/bindings.h"
#include "proxy/dns/dispatch_adapter.h"
#include "proxy/dns/runtime_adapter.h"
#include "proxy/runtime.h"
#include "proxy/service.h"
#endif
#if defined(FTUN_HAVE_MODULE_TUN)
#include "tun/owner.h"
#endif

#include <stdlib.h>
#include <string.h>

#define FTUN_DEFAULT_TUN_MARK UINT32_C(0x4654)

typedef struct {
  ftun_core_module_descriptor_t modules[FTUN_CORE_MODULE_LIMIT];
  ftun_core_module_catalog_t catalog;
  ftun_core_module_runtime_t *modules_runtime;
  ftun_core_t *core;
  ftun_event_loop_t *loop;
#if defined(FTUN_HAVE_MODULE_PROXY)
  ftun_proxy_bindings_t proxy;
  ftun_fakeip_service_t *fakeip;
#endif
#if defined(FTUN_HAVE_MODULE_DNS)
  ftun_dns_service_slot_t dns;
#endif
#if defined(FTUN_HAVE_MODULE_DNS)
#if defined(FTUN_HAVE_MODULE_PROXY)
  ftun_proxy_dns_runtime_adapter_t proxy_dns;
#endif
  ftun_dns_service_binding_t dns_binding;
#endif
#if defined(FTUN_HAVE_MODULE_TUN)
  ftun_tun_owner_binding_t tun;
  ftun_l3_provider_t l3;
#endif
} ftun_default_runtime_t;

#if defined(FTUN_HAVE_MODULE_PROXY)
static ftun_status_t ftun_default_resolve_start(
  void *context, ftun_core_t *core,
  const ftun_resolver_provider_request_t *request, ftun_operation_t **out)
{
  (void)context;
  return ftun_system_resolve(core, &request->system, out);
}

static ftun_status_t ftun_default_path_start(
  void *context, ftun_core_t *core, const ftun_dial_request_t *request,
  ftun_operation_t **out)
{
  (void)context;
  return ftun_dial_start(core, request, out);
}
#endif

static const ftun_core_module_descriptor_t ftun_default_modules[] = {
  {.name = "core", .capability = FTUN_BUILD_MODULE_CORE},
#if defined(FTUN_HAVE_MODULE_TUN)
  {.name = "tun", .capability = FTUN_BUILD_MODULE_TUN,
   .dependencies = FTUN_BUILD_MODULE_CORE, .startup_order = 10u,
   .service = &ftun_tun_owner_service},
#endif
#if defined(FTUN_HAVE_MODULE_PROXY)
  {.name = "proxy", .capability = FTUN_BUILD_MODULE_PROXY,
   .dependencies = FTUN_BUILD_MODULE_CORE, .startup_order = 20u,
   .service = &ftun_proxy_service},
#endif
#if defined(FTUN_HAVE_MODULE_DNS)
  {.name = "dns", .capability = FTUN_BUILD_MODULE_DNS,
   .dependencies = FTUN_BUILD_MODULE_CORE, .startup_order = 30u,
   .service = &ftun_dns_core_service},
#endif
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  {.name = "fakeip", .capability = FTUN_BUILD_MODULE_FAKEIP,
   .dependencies = FTUN_BUILD_MODULE_CORE | FTUN_BUILD_MODULE_PROXY |
                   FTUN_BUILD_MODULE_DNS,
   .startup_order = 40u},
#endif
#if defined(FTUN_HAVE_MODULE_FRS)
  {.name = "frs", .capability = FTUN_BUILD_MODULE_FRS,
   .dependencies = FTUN_BUILD_MODULE_CORE | FTUN_BUILD_MODULE_PROXY,
   .startup_order = 40u},
#endif
};

static const ftun_core_module_catalog_t ftun_default_catalog = {
  ftun_default_modules,
  sizeof(ftun_default_modules) / sizeof(ftun_default_modules[0]),
  0u
};

static ftun_status_t ftun_default_plan_prepare(
  const ftun_config_t *config, uint32_t socket_mark, void **out)
{
  ftun_core_module_reload_plan_t *plan = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (out == NULL) return FTUN_E_INVALID;
  status = ftun_core_module_reload_plan_prepare(&ftun_default_catalog, config,
                                                 socket_mark, &plan, NULL);
  if (status == FTUN_OK) *out = plan;
  return status;
}

static ftun_status_t ftun_default_plan_destroy(void **plan)
{
  ftun_core_module_reload_plan_t *owned;
  ftun_status_t status;
  if (plan == NULL) return FTUN_E_INVALID;
  owned = (ftun_core_module_reload_plan_t *)*plan;
  status = ftun_core_module_reload_plan_destroy(&owned);
  if (status == FTUN_OK) *plan = NULL;
  return status;
}

static void ftun_default_bind_modules(ftun_default_runtime_t *runtime,
                                      const ftun_config_t *config)
{
#if defined(FTUN_HAVE_MODULE_PROXY) || defined(FTUN_HAVE_MODULE_DNS) || \
    defined(FTUN_HAVE_MODULE_TUN)
  size_t index;
#else
  (void)runtime;
#endif
#if !defined(FTUN_HAVE_MODULE_PROXY) && !defined(FTUN_HAVE_MODULE_DNS)
  (void)config;
#endif
#if defined(FTUN_HAVE_MODULE_PROXY)
  runtime->proxy.loop = runtime->loop;
  runtime->proxy.resolver.start = ftun_default_resolve_start;
  runtime->proxy.path.start = ftun_default_path_start;
  runtime->proxy.fakeip_slot = &runtime->fakeip;
#endif
#if defined(FTUN_HAVE_MODULE_DNS)
  runtime->dns_binding.loop = runtime->loop;
  runtime->dns_binding.slot = &runtime->dns;
#if defined(FTUN_HAVE_MODULE_PROXY)
  runtime->proxy_dns.core = runtime->core;
  runtime->proxy_dns.slot = &runtime->dns;
  runtime->proxy_dns.fakeip_slot = &runtime->fakeip;
  runtime->proxy.dns = &runtime->proxy_dns;
  runtime->dns_binding.adapter.select_member =
    ftun_proxy_dns_select_member;
  runtime->dns_binding.adapter.dispatch = ftun_proxy_dns_dispatch;
  runtime->dns_binding.adapter.user = &runtime->proxy_dns;
#endif
  runtime->dns_binding.socket_mark =
    (config->plan->required_modules & FTUN_BUILD_MODULE_TUN) != 0u
      ? FTUN_DEFAULT_TUN_MARK : 0u;
#endif
#if defined(FTUN_HAVE_MODULE_TUN)
  runtime->tun.provider = &runtime->l3;
  runtime->tun.loop = runtime->loop;
  runtime->tun.protection_mark = FTUN_DEFAULT_TUN_MARK;
#if defined(FTUN_HAVE_MODULE_PROXY)
  runtime->proxy.l3 =
    (config->plan->required_modules & FTUN_BUILD_MODULE_TUN) != 0u
      ? &runtime->l3 : NULL;
  runtime->proxy.l3_deferred = runtime->proxy.l3 != NULL;
#endif
#endif
#if defined(FTUN_HAVE_MODULE_PROXY) || defined(FTUN_HAVE_MODULE_DNS) || \
    defined(FTUN_HAVE_MODULE_TUN)
  for (index = 0u; index < runtime->catalog.module_count; index++) {
    ftun_core_module_descriptor_t *module = &runtime->modules[index];
#if defined(FTUN_HAVE_MODULE_PROXY)
    if (module->capability == FTUN_BUILD_MODULE_PROXY) {
      module->binding.value = &runtime->proxy;
      module->binding.size = sizeof(runtime->proxy);
    }
#endif
#if defined(FTUN_HAVE_MODULE_DNS)
    if (module->capability == FTUN_BUILD_MODULE_DNS) {
      module->binding.value = &runtime->dns_binding;
      module->binding.size = sizeof(runtime->dns_binding);
    }
#endif
#if defined(FTUN_HAVE_MODULE_TUN)
    if (module->capability == FTUN_BUILD_MODULE_TUN) {
      module->binding.value = &runtime->tun;
      module->binding.size = sizeof(runtime->tun);
    }
#endif
  }
#endif
}

static ftun_status_t ftun_default_loop_destroy(ftun_default_runtime_t *runtime)
{
  ftun_status_t status;
  if (runtime == NULL || runtime->loop == NULL) return FTUN_OK;
  status = ftun_event_loop_stop(runtime->loop);
  if (status != FTUN_OK) return status;
  status = ftun_libev_detach(runtime->loop);
  if (status != FTUN_OK) return status;
  return ftun_event_loop_destroy(&runtime->loop);
}

static ftun_status_t ftun_default_prepare(
  ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations,
  const ftun_core_service_binding_t *binding,
  const ftun_config_t *config,
  uint64_t generation, void **out)
{
  ftun_default_runtime_t *runtime;
  size_t source_capacity = 0u;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core == NULL || budget == NULL || operations == NULL || config == NULL ||
      config->plan == NULL || generation == 0u || out == NULL) {
    return FTUN_E_INVALID;
  }
  (void)binding;
#if defined(FTUN_HAVE_MODULE_PROXY)
  status = ftun_proxy_runtime_event_source_capacity(config, &source_capacity);
#else
  /* DNS-only 组合只需要 listener/upstream watcher；保持固定有界额度。 */
  source_capacity = 512u;
  status = FTUN_OK;
#endif
  if (status != FTUN_OK) return status;
  runtime = (ftun_default_runtime_t *)calloc(1u, sizeof(*runtime));
  if (runtime == NULL) return FTUN_E_LIMIT;
  runtime->core = core;
  memcpy(runtime->modules, ftun_default_modules,
         sizeof(ftun_default_modules));
  runtime->catalog.modules = runtime->modules;
  runtime->catalog.module_count = ftun_default_catalog.module_count;
  runtime->catalog.optional_modules = ftun_default_catalog.optional_modules;
  status = ftun_event_loop_create_with_capacity(
    core, source_capacity, &runtime->loop);
  if (status == FTUN_OK) status = ftun_libev_attach(runtime->loop);
  if (status == FTUN_OK) ftun_default_bind_modules(runtime, config);
  if (status == FTUN_OK) {
    status = ftun_core_module_runtime_prepare(&runtime->catalog, core,
      budget, operations, config, generation, &runtime->modules_runtime, NULL);
  }
  if (status != FTUN_OK) {
    (void)ftun_core_module_runtime_destroy_until(
      &runtime->modules_runtime, UINT64_MAX);
    (void)ftun_default_loop_destroy(runtime);
    free(runtime);
    return status;
  }
  *out = runtime;
  return FTUN_OK;
}

static ftun_status_t ftun_default_activate(void *implementation)
{
  ftun_default_runtime_t *runtime = (ftun_default_runtime_t *)implementation;
  return runtime == NULL ? FTUN_E_INVALID :
    ftun_core_module_runtime_activate(runtime->modules_runtime, UINT64_MAX);
}

static ftun_status_t ftun_default_reload_prepare(
  void *implementation, const ftun_config_t *config, uint64_t generation)
{
  ftun_default_runtime_t *runtime = (ftun_default_runtime_t *)implementation;
  return runtime == NULL ? FTUN_E_INVALID :
    ftun_core_module_runtime_reload_prepare(
      runtime->modules_runtime, config, generation);
}

static ftun_status_t ftun_default_reload_prepare_planned(
  void *implementation, const ftun_config_t *config, uint64_t generation,
  const void *plan)
{
  ftun_default_runtime_t *runtime = (ftun_default_runtime_t *)implementation;
  return runtime == NULL ? FTUN_E_INVALID :
    ftun_core_module_runtime_reload_prepare_planned(
      runtime->modules_runtime, config, generation,
      (const ftun_core_module_reload_plan_t *)plan);
}

static ftun_status_t ftun_default_reload_commit(void *implementation,
                                                 uint64_t generation)
{
  ftun_default_runtime_t *runtime = (ftun_default_runtime_t *)implementation;
  return runtime == NULL ? FTUN_E_INVALID :
    ftun_core_module_runtime_reload_commit(
      runtime->modules_runtime, generation);
}

static ftun_status_t ftun_default_reload_abort(void *implementation)
{
  ftun_default_runtime_t *runtime = (ftun_default_runtime_t *)implementation;
  return runtime == NULL ? FTUN_E_INVALID :
    ftun_core_module_runtime_reload_abort(runtime->modules_runtime);
}

static ftun_status_t ftun_default_run_once(
  void *implementation, bool may_block,
  ftun_core_service_run_usage_t *out_usage)
{
  ftun_default_runtime_t *runtime = (ftun_default_runtime_t *)implementation;
  return runtime == NULL ? FTUN_E_INVALID :
    ftun_core_module_runtime_run_once(
      runtime->modules_runtime, may_block, out_usage);
}

static ftun_status_t ftun_default_wakeup(void *implementation)
{
  ftun_default_runtime_t *runtime = (ftun_default_runtime_t *)implementation;
  return runtime == NULL ? FTUN_E_INVALID :
    ftun_core_module_runtime_wakeup(runtime->modules_runtime);
}

static ftun_status_t ftun_default_quiesce(void *implementation)
{
  ftun_default_runtime_t *runtime = (ftun_default_runtime_t *)implementation;
  return runtime == NULL ? FTUN_E_INVALID :
    ftun_core_module_runtime_quiesce(runtime->modules_runtime);
}

static ftun_status_t ftun_default_drain_until(void *implementation,
                                               uint64_t deadline_ms)
{
  ftun_default_runtime_t *runtime = (ftun_default_runtime_t *)implementation;
  ftun_status_t status;
  if (runtime == NULL) return FTUN_E_INVALID;
  status = ftun_core_module_runtime_drain_until(
    runtime->modules_runtime, deadline_ms);
  if (status == FTUN_OK) status = ftun_event_loop_stop(runtime->loop);
  return status;
}

static ftun_status_t ftun_default_stop_until(void *implementation,
                                              uint64_t deadline_ms)
{
  return ftun_default_drain_until(implementation, deadline_ms);
}

static ftun_status_t ftun_default_destroy_until(void **implementation,
                                                 uint64_t deadline_ms)
{
  ftun_default_runtime_t *runtime;
  ftun_status_t status;
  if (implementation == NULL || deadline_ms == 0u) return FTUN_E_INVALID;
  runtime = (ftun_default_runtime_t *)*implementation;
  if (runtime == NULL) return FTUN_OK;
  status = ftun_core_module_runtime_destroy_until(
    &runtime->modules_runtime, deadline_ms);
  if (status != FTUN_OK) return status;
  status = ftun_default_loop_destroy(runtime);
  if (status != FTUN_OK) return status;
  free(runtime);
  *implementation = NULL;
  return FTUN_OK;
}

static const ftun_core_service_descriptor_t ftun_default_service = {
  "default-module-plan",
  ftun_default_plan_prepare,
  ftun_default_plan_destroy,
  ftun_default_prepare,
  ftun_default_activate,
  ftun_default_reload_prepare,
  ftun_default_reload_prepare_planned,
  ftun_default_reload_commit,
  ftun_default_reload_abort,
  ftun_default_run_once,
  ftun_default_wakeup,
  ftun_default_quiesce,
  ftun_default_drain_until,
  ftun_default_stop_until,
  ftun_default_destroy_until
};

ftun_status_t ftun_core_create(const ftun_core_options_t *options,
                               ftun_core_t **out)
{
  return ftun_core_create_with_service(options,
                                       &ftun_default_service, out);
}
