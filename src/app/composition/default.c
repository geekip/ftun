#include "core/core.h"
#include "app/runtime_support.h"
#include "core/module_plan.h"
#include "core/operation.h"
#include "config/compile.h"
#include "event/event.h"
#include "event/libev_adapter.h"
#include "dns/core_service.h"
#include "util/time.h"
#include "transport/socket_path.h"
#if defined(FTUN_HAVE_MODULE_PROXY)
#include "proxy/bindings.h"
#include "proxy/dns/dispatch_adapter.h"
#include "proxy/dns/runtime_adapter.h"
#include "proxy/runtime.h"
#include "proxy/service.h"
#endif
#if defined(FTUN_HAVE_MODULE_TUN)
#include "tun/owner.h"
#include "platform/linux/interface.h"
#endif

#include <stdlib.h>
#include <string.h>

#define FTUN_DEFAULT_TUN_MARK UINT32_C(0x4654)
#define FTUN_DEFAULT_CLEANUP_QUOTA 32u

#if defined(FTUN_HAVE_MODULE_PROXY)
extern const ftun_app_runtime_support_t ftun_proxy_runtime_support;
#endif

const ftun_app_runtime_support_t *ftun_app_runtime_support(void)
{
#if defined(FTUN_HAVE_MODULE_PROXY)
  return &ftun_proxy_runtime_support;
#else
  return NULL;
#endif
}

ftun_status_t ftun_app_event_source_capacity(const ftun_config_t *config, size_t *out)
{
  if (out != NULL) *out = 0u;
  if (config == NULL || out == NULL) return FTUN_E_INVALID;
#if defined(FTUN_HAVE_MODULE_PROXY)
  return ftun_proxy_runtime_event_source_capacity(config, out);
#else
  *out = 512u;
  return FTUN_OK;
#endif
}

ftun_status_t ftun_app_datagram_capacity(const ftun_config_t *config, size_t *out)
{
  if (out != NULL) *out = 0u;
  if (config == NULL || out == NULL) return FTUN_E_INVALID;
#if defined(FTUN_HAVE_MODULE_PROXY)
  return ftun_proxy_runtime_datagram_capacity(config, out);
#else
  return FTUN_OK;
#endif
}

typedef struct {
  ftun_core_module_descriptor_t modules[FTUN_CORE_MODULE_LIMIT];
  ftun_core_module_catalog_t catalog;
  ftun_core_module_runtime_t *modules_runtime;
  ftun_core_t *core;
  ftun_reservation_t *reservation;
  ftun_event_loop_t *loop;
  ftun_operation_queue_t *operations;
  ftun_status_t first_error;
  ftun_status_t cleanup_error;
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
  if (request->requested_domain == FTUN_DIAL_DOMAIN_OVERLAY) return FTUN_E_UNSUPPORTED;
  if (request->source == FTUN_RESOLVER_SYSTEM) {
    return ftun_system_resolve(core, &request->system, out);
  }
#if defined(FTUN_HAVE_MODULE_DNS)
  {
    ftun_default_runtime_t *runtime = context;
    ftun_bootstrap_request_t query = {0};
    query.loop = request->loop;
    query.operations = request->operations;
    query.worker = request->system.worker;
    query.budget = request->system.budget;
    query.domain = request->system.domain;
    query.protection = request->system.protection;
    query.deadline_ms = request->system.deadline_ms;
    query.check_system_path = request->system.check_path;
    query.system_path_user = request->system.path_user;
    query.completion = request->system.completion;
    query.user = request->system.user;
    query.servers = request->servers;
    query.server_count = request->server_count;
    query.network_view = request->network_view;
    query.network_generation = request->network_generation;
    query.query_id = request->query_id;
    if (request->source == FTUN_RESOLVER_BOOTSTRAP) {
      return ftun_bootstrap_resolve(core, &query, out);
    }
    if (runtime == NULL || !runtime->dns.accepting) return FTUN_E_AGAIN;
    if (runtime->dns.generation != request->generation) return FTUN_E_STALE;
    return ftun_proxy_dns_resolve_named(&runtime->proxy_dns,
      &query, request->resolver_name, out);
  }
#else
  (void)context;
  return FTUN_E_UNSUPPORTED;
#endif
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

static ftun_status_t ftun_default_plan_prepare(ftun_budget_t *budget,
  const ftun_config_t *config, uint32_t socket_mark, void **out)
{
  ftun_core_module_reload_plan_t *plan = NULL;
  ftun_status_t status;
  if (out == NULL) return FTUN_E_INVALID;
  if (*out != NULL) return FTUN_E_AGAIN;
  status = ftun_core_module_reload_plan_prepare(&ftun_default_catalog, budget, config,
                                                 socket_mark, &plan, NULL);
  *out = plan;
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
  runtime->proxy.resolver_context = runtime;
  runtime->proxy.path.start = ftun_default_path_start;
  runtime->proxy.path.open = ftun_socket_path_open;
  runtime->proxy.control_path.open = ftun_socket_path_open;
  runtime->proxy.fakeip_slot = &runtime->fakeip;
#endif
#if defined(FTUN_HAVE_MODULE_DNS)
  runtime->dns_binding.loop = runtime->loop;
  runtime->dns_binding.slot = &runtime->dns;
  runtime->dns_binding.path.open = ftun_socket_path_open;
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
  runtime->tun.network = &ftun_linux_interface_ops;
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
  ftun_reservation_t *reservation = NULL;
  size_t source_capacity = 0u;
  ftun_status_t status;
  if (core == NULL || budget == NULL || operations == NULL || config == NULL ||
      config->plan == NULL || generation == 0u || out == NULL) {
    return FTUN_E_INVALID;
  }
  if (*out != NULL) return FTUN_E_AGAIN;
  (void)binding;
  status = ftun_app_event_source_capacity(config, &source_capacity);
  if (status != FTUN_OK) return status;
  status = ftun_budget_reserve(budget, sizeof(*runtime), &reservation);
  if (status != FTUN_OK) return status;
  runtime = (ftun_default_runtime_t *)calloc(1u, sizeof(*runtime));
  if (runtime == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  runtime->reservation = reservation;
  runtime->core = core;
  runtime->operations = operations;
  memcpy(runtime->modules, ftun_default_modules,
         sizeof(ftun_default_modules));
  runtime->catalog.modules = runtime->modules;
  runtime->catalog.module_count = ftun_default_catalog.module_count;
  runtime->catalog.optional_modules = ftun_default_catalog.optional_modules;
  status = ftun_event_loop_create_with_budget(
    core, budget, source_capacity, &runtime->loop);
  if (status == FTUN_OK) status = ftun_libev_attach(runtime->loop);
  if (status == FTUN_OK) ftun_default_bind_modules(runtime, config);
  if (status == FTUN_OK) {
    status = ftun_core_module_runtime_prepare(&runtime->catalog, core,
      budget, operations, config, generation, &runtime->modules_runtime, NULL);
  }
  if (status != FTUN_OK) {
    runtime->first_error = status;
    if (runtime->modules_runtime != NULL) {
      ftun_core_module_info_t info;
      if (ftun_core_module_runtime_get_info(runtime->modules_runtime,
                                             &info) == FTUN_OK) {
        runtime->cleanup_error = info.cleanup_error;
      }
    } else {
      runtime->cleanup_error = ftun_default_loop_destroy(runtime);
      if (runtime->cleanup_error == FTUN_OK) {
        free(runtime);
        (void)ftun_reservation_release(&reservation);
        runtime = NULL;
      }
    }
    *out = runtime;
    return status;
  }
  *out = runtime;
  return FTUN_OK;
}

static ftun_status_t ftun_default_activate(void *implementation)
{
  ftun_default_runtime_t *runtime = (ftun_default_runtime_t *)implementation;
  uint64_t now_ms = 0u;
  ftun_status_t status;
  if (runtime == NULL) return FTUN_E_INVALID;
  status = ftun_monotonic_now(&now_ms);
  if (status == FTUN_OK) {
    status = ftun_core_module_runtime_activate(runtime->modules_runtime,
      now_ms == 0u ? 1u : now_ms);
  }
  if (status != FTUN_OK && runtime->first_error == FTUN_OK) {
    ftun_core_module_info_t info;
    runtime->first_error = status;
    if (ftun_core_module_runtime_get_info(runtime->modules_runtime,
                                           &info) == FTUN_OK) {
      runtime->cleanup_error = info.cleanup_error;
    }
  }
  return status;
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
  if (runtime == NULL) return FTUN_E_INVALID;
  return runtime->modules_runtime == NULL ? FTUN_OK
    : ftun_core_module_runtime_wakeup(runtime->modules_runtime);
}

static ftun_status_t ftun_default_quiesce(void *implementation)
{
  ftun_default_runtime_t *runtime = (ftun_default_runtime_t *)implementation;
  if (runtime == NULL) return FTUN_E_INVALID;
  return runtime->modules_runtime == NULL ? FTUN_OK
    : ftun_core_module_runtime_quiesce(runtime->modules_runtime);
}

static ftun_status_t ftun_default_drain_until(void *implementation,
                                               uint64_t deadline_ms)
{
  ftun_default_runtime_t *runtime = (ftun_default_runtime_t *)implementation;
  ftun_status_t status;
  ftun_event_loop_usage_t events;
  ftun_operation_queue_usage_t operations;
  uint64_t now = 0u;
  size_t callbacks = 0u;
  if (runtime == NULL) return FTUN_E_INVALID;
  status = runtime->modules_runtime == NULL ? FTUN_OK :
    ftun_core_module_runtime_drain_until(runtime->modules_runtime, deadline_ms);
  if ((status == FTUN_OK || status == FTUN_E_AGAIN ||
       status == FTUN_E_TIMEOUT) && runtime->loop != NULL) {
    ftun_status_t polled = ftun_monotonic_now(&now);
    /* 生产者先 quiesce；只派发已接纳通知，不再等待物理 I/O。即使调用方
     * 不允许等待，仍按固定配额推进清理；总期限由 App 的清理驱动持有。 */
    if (polled == FTUN_OK) polled = ftun_event_loop_poll(
      runtime->loop, now, FTUN_DEFAULT_CLEANUP_QUOTA, &callbacks);
    if (polled != FTUN_OK) status = polled;
    if (status == FTUN_OK) {
      status = ftun_event_loop_get_usage(runtime->loop, &events);
      if (status == FTUN_OK) status = ftun_operation_queue_get_usage(
        runtime->operations, &operations);
      if (status == FTUN_OK) {
        /* Operation 取消/完成还可能排入 owner task，不能提前清空 ready
         * 队列或关闭 defer 接纳；App 在相邻清理轮次继续派发 Operation。 */
        status = events.ready_count != 0u || events.deferred_count != 0u ||
          operations.inflight != 0u ? FTUN_E_AGAIN :
          ftun_event_loop_stop(runtime->loop);
      }
    }
  }
  if (status != FTUN_OK && status != FTUN_E_AGAIN &&
      status != FTUN_E_TIMEOUT && runtime->cleanup_error == FTUN_OK) {
    runtime->cleanup_error = status;
  }
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
  ftun_reservation_t *reservation;
  if (implementation == NULL || deadline_ms == 0u) return FTUN_E_INVALID;
  runtime = (ftun_default_runtime_t *)*implementation;
  if (runtime == NULL) return FTUN_OK;
  status = ftun_core_module_runtime_destroy_until(
    &runtime->modules_runtime, deadline_ms);
  if (status == FTUN_OK) status = ftun_default_loop_destroy(runtime);
  if (status != FTUN_OK) {
    if (runtime->cleanup_error == FTUN_OK) runtime->cleanup_error = status;
    return status;
  }
  reservation = runtime->reservation;
  free(runtime);
  *implementation = NULL;
  return ftun_reservation_release(&reservation);
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
