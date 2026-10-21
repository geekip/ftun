#include "config/compile.h"
#include "core/budget.h"
#include "core/context.h"
#include "core/module_plan.h"
#include "core/operation.h"
#include "event/event.h"
#include "tun/owner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expression) do { \
  if (!(expression)) { \
    fprintf(stderr, "TUN owner contract failed: %s:%d: %s\n", \
            __FILE__, __LINE__, #expression); \
    return 1; \
  } \
} while (0)

typedef struct {
  size_t opens;
  size_t closes;
  size_t apply_attempts;
  size_t applies;
  size_t removes;
  size_t fail_apply_at;
} host_state_t;

typedef struct {
  ftun_l3_provider_t *provider;
  ftun_tun_lease_t lease;
  size_t prepares;
  size_t destroys;
  bool fail_prepare;
  bool fail_activate;
} consumer_state_t;

typedef struct {
  consumer_state_t *state;
  ftun_tun_lease_t lease;
  uint64_t generation;
  uint64_t pending_generation;
  bool needs_tun;
} consumer_runtime_t;

static ftun_status_t fake_open(void *user, ftun_core_t *core,
                               const ftun_tun_spec_t *spec,
                               ftun_packet_port_t **out)
{
  host_state_t *state = (host_state_t *)user;
  (void)core;
  if (out != NULL) *out = NULL;
  if (state == NULL || spec == NULL || out == NULL ||
      spec->name.length != 9u ||
      memcmp(spec->name.data, "ftun-own0", 9u) != 0 ||
      spec->mtu != 1420u) return FTUN_E_INVALID;
  state->opens++;
  *out = (ftun_packet_port_t *)state;
  return FTUN_OK;
}

static ftun_status_t fake_get_info(void *user,
                                   const ftun_packet_port_t *port,
                                   ftun_packet_port_info_t *out)
{
  host_state_t *state = (host_state_t *)user;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (state == NULL || port != (const ftun_packet_port_t *)state ||
      out == NULL) return FTUN_E_INVALID;
  memcpy(out->name, "ftun-own0", 10u);
  out->mtu = 1420u;
  out->native_socket = 77u;
  return FTUN_OK;
}

static ftun_status_t fake_read(void *user, ftun_packet_port_t *port,
                               void *buffer, size_t capacity,
                               size_t *out_length)
{
  (void)buffer;
  (void)capacity;
  if (out_length != NULL) *out_length = 0u;
  return user != NULL && port == (ftun_packet_port_t *)user &&
    out_length != NULL ? FTUN_E_AGAIN : FTUN_E_INVALID;
}

static ftun_status_t fake_write(void *user, ftun_packet_port_t *port,
                                const void *packet, size_t length)
{
  return user != NULL && port == (ftun_packet_port_t *)user &&
    packet != NULL && length != 0u ? FTUN_OK : FTUN_E_INVALID;
}

static ftun_status_t fake_close(void *user, ftun_packet_port_t **port)
{
  host_state_t *state = (host_state_t *)user;
  if (state == NULL || port == NULL) return FTUN_E_INVALID;
  if (*port == NULL) return FTUN_OK;
  if (*port != (ftun_packet_port_t *)state) return FTUN_E_INVALID;
  state->closes++;
  *port = NULL;
  return FTUN_OK;
}

static ftun_status_t route_apply(
  void *context, const ftun_linux_route_resource_t *resource)
{
  host_state_t *state = (host_state_t *)context;
  if (state == NULL || resource == NULL) return FTUN_E_INVALID;
  state->apply_attempts++;
  if (state->fail_apply_at != 0u &&
      state->apply_attempts == state->fail_apply_at) return FTUN_E_IO;
  state->applies++;
  return FTUN_OK;
}

static ftun_status_t route_remove(
  void *context, const ftun_linux_route_resource_t *resource)
{
  host_state_t *state = (host_state_t *)context;
  if (state == NULL || resource == NULL) return FTUN_E_INVALID;
  state->removes++;
  return FTUN_OK;
}

static ftun_status_t consume_packet(void *user, ftun_tun_lease_t lease,
                                    ftun_bytes_t packet)
{
  consumer_runtime_t *runtime = (consumer_runtime_t *)user;
  (void)packet;
  return runtime != NULL && lease.service == runtime->lease.service &&
    lease.generation == runtime->lease.generation
      ? FTUN_OK : FTUN_E_STALE;
}

static ftun_status_t proxy_plan_prepare(
  const ftun_config_t *config, uint32_t socket_mark, void **out)
{
  (void)config;
  (void)socket_mark;
  if (out == NULL) return FTUN_E_INVALID;
  *out = NULL;
  return FTUN_OK;
}

static ftun_status_t proxy_plan_destroy(void **plan)
{
  if (plan == NULL) return FTUN_E_INVALID;
  *plan = NULL;
  return FTUN_OK;
}

static ftun_status_t proxy_prepare(
  ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations,
  const ftun_core_service_binding_t *binding,
  const ftun_config_t *config, uint64_t generation, void **out)
{
  consumer_state_t *state;
  consumer_runtime_t *runtime;
  bool needs_tun;
  (void)core;
  (void)budget;
  (void)operations;
  if (out != NULL) *out = NULL;
  if (binding == NULL || binding->value == NULL ||
      binding->size != sizeof(consumer_state_t) || config == NULL ||
      config->plan == NULL || generation == 0u || out == NULL) {
    return FTUN_E_INVALID;
  }
  state = (consumer_state_t *)binding->value;
  state->prepares++;
  needs_tun = (config->plan->required_modules & FTUN_BUILD_MODULE_TUN) != 0u;
  if (state->fail_prepare) return FTUN_E_IO;
  runtime = (consumer_runtime_t *)calloc(1u, sizeof(*runtime));
  if (runtime == NULL) return FTUN_E_LIMIT;
  runtime->state = state;
  runtime->generation = generation;
  runtime->needs_tun = needs_tun;
  *out = runtime;
  return FTUN_OK;
}

static ftun_status_t proxy_activate(void *implementation)
{
  consumer_runtime_t *runtime = (consumer_runtime_t *)implementation;
  ftun_tun_consumer_spec_t consumer;
  ftun_status_t status = FTUN_OK;
  if (runtime == NULL) return FTUN_E_INVALID;
  if (runtime->needs_tun) {
    if (runtime->state->provider == NULL ||
        runtime->state->provider->service == NULL ||
        runtime->state->provider->generation != runtime->generation) {
      return FTUN_E_STATE_CORRUPT;
    }
    memset(&consumer, 0, sizeof(consumer));
    consumer.consumer.packet = consume_packet;
    consumer.consumer.user = runtime;
    consumer.route.kind = FTUN_TUN_ROUTE_DEFAULT;
    consumer.route.priority = UINT16_MAX;
    status = ftun_l3_provider_acquire(runtime->state->provider,
      runtime->generation, &consumer, &runtime->lease);
    if (status == FTUN_OK) runtime->state->lease = runtime->lease;
  }
  if (status == FTUN_OK && runtime->state->fail_activate) status = FTUN_E_IO;
  return status;
}

static ftun_status_t proxy_reload_prepare(
  void *implementation, const ftun_config_t *config, uint64_t generation)
{
  consumer_runtime_t *runtime = (consumer_runtime_t *)implementation;
  ftun_l3_provider_info_t info;
  ftun_status_t status;
  if (runtime == NULL || config == NULL ||
      generation <= runtime->generation) return FTUN_E_INVALID;
  if (runtime->needs_tun) {
    status = ftun_l3_provider_get_info(runtime->state->provider, &info);
    if (status != FTUN_OK) return status;
    if (!info.reload_prepared || info.pending_generation != generation) {
      return FTUN_E_STATE_CORRUPT;
    }
  }
  runtime->pending_generation = generation;
  return FTUN_OK;
}

static ftun_status_t proxy_reload_prepare_planned(
  void *implementation, const ftun_config_t *config, uint64_t generation,
  const void *plan)
{
  (void)plan;
  return proxy_reload_prepare(implementation, config, generation);
}

static ftun_status_t proxy_reload_commit(
  void *implementation, uint64_t generation)
{
  consumer_runtime_t *runtime = (consumer_runtime_t *)implementation;
  ftun_l3_provider_info_t info;
  ftun_status_t status;
  if (runtime == NULL || generation == 0u ||
      generation != runtime->pending_generation) return FTUN_E_INVALID;
  if (runtime->needs_tun) {
    status = ftun_l3_provider_get_info(runtime->state->provider, &info);
    if (status != FTUN_OK) return status;
    if (info.reload_prepared || info.generation != generation) {
      return FTUN_E_STATE_CORRUPT;
    }
  }
  runtime->generation = generation;
  runtime->pending_generation = 0u;
  return FTUN_OK;
}

static ftun_status_t proxy_reload_abort(void *implementation)
{
  consumer_runtime_t *runtime = (consumer_runtime_t *)implementation;
  if (runtime == NULL) return FTUN_E_INVALID;
  runtime->pending_generation = 0u;
  return FTUN_OK;
}

static ftun_status_t proxy_run_once(
  void *implementation, bool may_block,
  ftun_core_service_run_usage_t *out_usage)
{
  (void)may_block;
  if (out_usage != NULL) memset(out_usage, 0, sizeof(*out_usage));
  return implementation == NULL || out_usage == NULL
    ? FTUN_E_INVALID : FTUN_OK;
}

static ftun_status_t proxy_wakeup(void *implementation)
{
  return implementation == NULL ? FTUN_E_INVALID : FTUN_OK;
}

static ftun_status_t proxy_quiesce(void *implementation)
{
  return implementation == NULL ? FTUN_E_INVALID : FTUN_OK;
}

static ftun_status_t proxy_drain_until(
  void *implementation, uint64_t deadline_ms)
{
  consumer_runtime_t *runtime = (consumer_runtime_t *)implementation;
  if (runtime == NULL || deadline_ms == 0u) return FTUN_E_INVALID;
  return ftun_tun_service_release(&runtime->lease);
}

static ftun_status_t proxy_stop_until(
  void *implementation, uint64_t deadline_ms)
{
  return proxy_drain_until(implementation, deadline_ms);
}

static ftun_status_t proxy_destroy_until(
  void **implementation, uint64_t deadline_ms)
{
  consumer_runtime_t *runtime;
  ftun_status_t status;
  if (implementation == NULL || deadline_ms == 0u) return FTUN_E_INVALID;
  runtime = (consumer_runtime_t *)*implementation;
  if (runtime == NULL) return FTUN_OK;
  status = ftun_tun_service_release(&runtime->lease);
  if (status != FTUN_OK) return status;
  runtime->state->destroys++;
  memset(&runtime->state->lease, 0, sizeof(runtime->state->lease));
  free(runtime);
  *implementation = NULL;
  return FTUN_OK;
}

static const ftun_core_service_descriptor_t proxy_service = {
  "test-proxy",
  proxy_plan_prepare,
  proxy_plan_destroy,
  proxy_prepare,
  proxy_activate,
  proxy_reload_prepare,
  proxy_reload_prepare_planned,
  proxy_reload_commit,
  proxy_reload_abort,
  proxy_run_once,
  proxy_wakeup,
  proxy_quiesce,
  proxy_drain_until,
  proxy_stop_until,
  proxy_destroy_until
};

static void set_config(ftun_config_t *config, ftun_feature_plan_t *plan,
                       ftun_config_inbound_t *inbound, bool with_tun)
{
  memset(config, 0, sizeof(*config));
  memset(plan, 0, sizeof(*plan));
  plan->built_modules = FTUN_BUILD_MODULE_CORE |
    FTUN_BUILD_MODULE_PROXY | FTUN_BUILD_MODULE_TUN;
  plan->required_modules = FTUN_BUILD_MODULE_CORE | FTUN_BUILD_MODULE_PROXY;
  config->plan = plan;
  if (!with_tun) return;
  memset(inbound, 0, sizeof(*inbound));
  inbound->kind = FTUN_CONFIG_INBOUND_TUN;
  inbound->name = "transparent";
  inbound->interface_name = "ftun-own0";
  inbound->mtu = 1420u;
  inbound->ipv4_address = "172.19.0.1/30";
  inbound->tcp = true;
  inbound->auto_route = true;
  inbound->strict_route = true;
  config->inbounds = inbound;
  config->inbound_count = 1u;
  config->tun.present = true;
  config->tun.interface_name = inbound->interface_name;
  config->tun.mtu = inbound->mtu;
  config->tun.ipv4_address = inbound->ipv4_address;
  config->tun.auto_route = inbound->auto_route;
  config->tun.strict_route = inbound->strict_route;
  plan->required_modules |= FTUN_BUILD_MODULE_TUN;
}

int main(void)
{
  host_state_t host;
  consumer_state_t consumer;
  ftun_tun_device_ops_t device_ops;
  ftun_linux_route_io_t route_io;
  ftun_tun_owner_binding_t owner_binding;
  ftun_l3_provider_t provider;
  ftun_core_module_descriptor_t modules[3];
  ftun_core_module_catalog_t catalog;
  ftun_core_module_runtime_t *runtime = NULL;
  ftun_core_t *core = NULL;
  ftun_budget_t *budget = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_config_t config;
  ftun_feature_plan_t plan;
  ftun_config_inbound_t inbound;
  ftun_l3_provider_info_t provider_info;
  ftun_tun_consumer_spec_t stale_consumer;
  ftun_tun_lease_t stale_lease;
  size_t applies_before;
  size_t attempts_before;

  memset(&host, 0, sizeof(host));
  memset(&consumer, 0, sizeof(consumer));
  memset(&device_ops, 0, sizeof(device_ops));
  memset(&route_io, 0, sizeof(route_io));
  memset(&owner_binding, 0, sizeof(owner_binding));
  memset(&provider, 0, sizeof(provider));
  memset(modules, 0, sizeof(modules));
  device_ops.open = fake_open;
  device_ops.get_info = fake_get_info;
  device_ops.read = fake_read;
  device_ops.write = fake_write;
  device_ops.close = fake_close;
  device_ops.user = &host;
  route_io.apply = route_apply;
  route_io.remove = route_remove;
  route_io.context = &host;

  CHECK(ftun_budget_create(NULL, 8u * 1024u * 1024u, 4096u, &budget) ==
        FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 8u, &operations) == FTUN_OK);
  CHECK(ftun_event_loop_create_with_capacity(core, 16u, &loop) == FTUN_OK);
  owner_binding.provider = &provider;
  owner_binding.loop = loop;
  owner_binding.device_ops = &device_ops;
  owner_binding.route_io = &route_io;
  owner_binding.protection_mark = UINT32_C(0x4654);
  consumer.provider = &provider;

  modules[0] = (ftun_core_module_descriptor_t){
    .name = "core", .capability = FTUN_BUILD_MODULE_CORE
  };
  modules[1] = (ftun_core_module_descriptor_t){
    .name = "tun", .capability = FTUN_BUILD_MODULE_TUN,
    .dependencies = FTUN_BUILD_MODULE_CORE, .startup_order = 10u,
    .service = &ftun_tun_owner_service,
    .binding = {&owner_binding, sizeof(owner_binding)}
  };
  modules[2] = (ftun_core_module_descriptor_t){
    .name = "proxy", .capability = FTUN_BUILD_MODULE_PROXY,
    .dependencies = FTUN_BUILD_MODULE_CORE, .startup_order = 20u,
    .service = &proxy_service,
    .binding = {&consumer, sizeof(consumer)}
  };
  catalog = (ftun_core_module_catalog_t){modules, 3u, 0u};
  CHECK(ftun_core_module_catalog_valid(&catalog));

  /* socket-only 组合不选择 TUN service，因此不得打开设备或应用路由。 */
  set_config(&config, &plan, &inbound, false);
  CHECK(ftun_core_module_runtime_prepare(&catalog, core, budget, operations,
        &config, 1u, &runtime, NULL) == FTUN_OK);
  CHECK(host.opens == 0u && host.applies == 0u && provider.service == NULL);
  CHECK(ftun_core_module_runtime_activate(runtime, 100u) == FTUN_OK);
  CHECK(ftun_core_module_runtime_destroy_until(&runtime, 100u) == FTUN_OK);

  /* 路由事务中途失败必须逆序补偿，并关闭尚未发布的物理设备。 */
  set_config(&config, &plan, &inbound, true);
  attempts_before = host.apply_attempts;
  host.fail_apply_at = attempts_before + 3u;
  CHECK(ftun_core_module_runtime_prepare(&catalog, core, budget, operations,
        &config, 1u, &runtime, NULL) == FTUN_OK);
  CHECK(host.opens == 0u && provider.service == NULL);
  CHECK(ftun_core_module_runtime_activate(runtime, 100u) == FTUN_E_IO);
  CHECK(host.opens == 1u && host.closes == 1u &&
        host.apply_attempts == attempts_before + 3u &&
        host.applies == 2u && host.removes == host.applies &&
        provider.service == NULL);
  CHECK(ftun_core_module_runtime_destroy_until(&runtime, 100u) == FTUN_OK);
  host.fail_apply_at = 0u;

  /* prepare 失败发生在设备发布前，不得产生物理设备或主机路由副作用。 */
  consumer.fail_prepare = true;
  CHECK(ftun_core_module_runtime_prepare(&catalog, core, budget, operations,
        &config, 1u, &runtime, NULL) == FTUN_E_IO && runtime == NULL);
  CHECK(host.opens == 1u && host.closes == 1u &&
        host.removes == host.applies && provider.service == NULL);

  consumer.fail_prepare = false;
  /* consumer activate 失败必须释放 lease 并回滚已发布的设备与路由。 */
  consumer.fail_activate = true;
  CHECK(ftun_core_module_runtime_prepare(&catalog, core, budget, operations,
        &config, 1u, &runtime, NULL) == FTUN_OK);
  CHECK(host.opens == 1u && provider.service == NULL);
  CHECK(ftun_core_module_runtime_activate(runtime, 100u) == FTUN_E_IO);
  CHECK(host.opens == 2u && host.closes == 2u &&
        host.removes == host.applies && provider.service == NULL &&
        consumer.lease.service == NULL);
  CHECK(ftun_core_module_runtime_destroy_until(&runtime, 100u) == FTUN_OK);

  consumer.fail_activate = false;
  applies_before = host.applies;
  CHECK(ftun_core_module_runtime_prepare(&catalog, core, budget, operations,
        &config, 1u, &runtime, NULL) == FTUN_OK);
  CHECK(host.opens == 2u && host.applies == applies_before &&
        provider.service == NULL && consumer.lease.service == NULL);
  CHECK(ftun_core_module_runtime_activate(runtime, 100u) == FTUN_OK);
  CHECK(host.opens == 3u && host.applies > applies_before &&
        provider.service != NULL && consumer.lease.service == provider.service);
  CHECK(ftun_l3_provider_get_info(&provider, &provider_info) == FTUN_OK &&
        provider_info.generation == 1u && provider_info.active_leases == 1u &&
        provider_info.device.mtu == 1420u);

  /* 物理重建只替换 owner 的设备，既有 consumer lease 保持。 */
  CHECK(ftun_tun_service_rebuild(provider.service) == FTUN_OK);
  CHECK(host.opens == 4u && host.closes == 3u &&
        consumer.lease.service == provider.service);

  CHECK(ftun_core_module_runtime_reload_prepare(
        runtime, &config, 2u) == FTUN_OK);
  CHECK(ftun_l3_provider_get_info(&provider, &provider_info) == FTUN_OK &&
        provider_info.reload_prepared &&
        provider_info.pending_generation == 2u);
  CHECK(ftun_core_module_runtime_reload_commit(runtime, 2u) == FTUN_OK);
  CHECK(ftun_l3_provider_get_info(&provider, &provider_info) == FTUN_OK &&
        provider_info.generation == 2u && !provider_info.reload_prepared);
  memset(&stale_consumer, 0, sizeof(stale_consumer));
  memset(&stale_lease, 0, sizeof(stale_lease));
  stale_consumer.consumer.packet = consume_packet;
  stale_consumer.consumer.user = NULL;
  stale_consumer.route.kind = FTUN_TUN_ROUTE_IPV4_PREFIX;
  stale_consumer.route.network[0] = 10u;
  stale_consumer.route.prefix_length = 8u;
  CHECK(ftun_l3_provider_acquire(&provider, 1u, &stale_consumer,
        &stale_lease) == FTUN_E_STALE && stale_lease.service == NULL);

  inbound.mtu = 1400u;
  config.tun.mtu = 1400u;
  CHECK(ftun_core_module_runtime_reload_prepare(
        runtime, &config, 3u) == FTUN_E_RESTART_REQUIRED);
  inbound.mtu = 1420u;
  config.tun.mtu = 1420u;
  CHECK(ftun_core_module_runtime_quiesce(runtime) == FTUN_OK);
  CHECK(provider.service == NULL && consumer.lease.service != NULL);
  CHECK(ftun_core_module_runtime_destroy_until(&runtime, 100u) == FTUN_OK);
  CHECK(provider.service == NULL && host.opens == host.closes &&
        host.applies == host.removes && consumer.lease.service == NULL);

  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}
