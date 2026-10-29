#define _POSIX_C_SOURCE 200809L
#include "platform/linux/route.h"
#include <fcntl.h>
#include "app/config/model.h"
#include "libs/tun/service.h"
#include "app/config/compile.h"
#include "core/limits.h"
#include "core/context.h"
#include "core/ddra.h"
#include "core/operation.h"
#include "core/event/loop.h"
#include "core/event/backend.h"
#include "libs/tun/owner.h"
#include "libs/tun/interface_backend.h"
#include "libs/tun/routes.h"
#include "platform/clock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(expression) do { \
  if (!(expression)) { \
    fprintf(stderr, "TUN owner contract failed: %s:%d: %s\n", \
            __FILE__, __LINE__, #expression); \
    return 1; \
  } \
} while (0)

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
  size_t opens;
  size_t closes;
  size_t apply_attempts;
  size_t applies;
  size_t removes;
  size_t fail_apply_at;
  bool fail_remove;
  bool fail_rollback;
  bool fail_open_once;
  bool fail_close_once;
  bool check_close_order;
  bool close_order_error;
  bool real_descriptor;
  int descriptor;
  ftun_route_resource_t resources[32];
  size_t resource_count;
  bool provide_packet;
  bool stall_writes;
  bool withhold_replies;
  bool withhold_add_reply;
  bool has_reply;
  ftun_route_reply_t reply;
  size_t async_requests;
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
  bool stall;
  size_t received;
  size_t network_updates;
  size_t rebuilds;
  size_t failures;
  bool callback_error;
  void *owner;
  ftun_event_loop_t *loop;
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
  if (state->fail_open_once) {
    state->fail_open_once = false;
    return FTUN_E_IO;
  }
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
  out->native_socket = state->real_descriptor ? (ftun_native_socket_t)(unsigned int)state->descriptor : 77u;
  return FTUN_OK;
}

static ftun_status_t fake_read(void *user, ftun_packet_port_t *port,
                               void *buffer, size_t capacity,
                               size_t *out_length)
{
  host_state_t *host = user;
  if (out_length != NULL) *out_length = 0u;
  if (host != NULL && port == (ftun_packet_port_t *)host &&
      host->provide_packet && buffer != NULL && capacity >= 4u && out_length != NULL) {
    memcpy(buffer, (uint8_t[]){0x45u, 0x99u, 0u, 0u}, 4u);
    *out_length = 4u;
    host->provide_packet = false;
    return FTUN_OK;
  }
  return user != NULL && port == (ftun_packet_port_t *)user &&
    out_length != NULL ? FTUN_E_AGAIN : FTUN_E_INVALID;
}

static ftun_status_t fake_write(void *user, ftun_packet_port_t *port,
                                const void *packet, size_t length)
{
  if (user == NULL || port != (ftun_packet_port_t *)user ||
      packet == NULL || length == 0u) return FTUN_E_INVALID;
  return ((host_state_t *)user)->stall_writes ? FTUN_E_AGAIN : FTUN_OK;
}

static ftun_status_t fake_close(void *user, ftun_packet_port_t **port)
{
  host_state_t *state = (host_state_t *)user;
  if (state == NULL || port == NULL) return FTUN_E_INVALID;
  if (*port == NULL) return FTUN_OK;
  if (*port != (ftun_packet_port_t *)state) return FTUN_E_INVALID;
  if (state->check_close_order && state->resource_count != 0u) state->close_order_error = true;
  state->closes++;
  *port = NULL;
  if (state->fail_close_once) {
    state->fail_close_once = false;
    return FTUN_E_IO;
  }
  return FTUN_OK;
}

static bool resource_equal(const ftun_route_resource_t *left,
                             const ftun_route_resource_t *right)
{
  return left->kind == right->kind && left->family == right->family &&
    strcmp(left->interface_name, right->interface_name) == 0 &&
    memcmp(left->address, right->address, sizeof(left->address)) == 0 &&
    left->prefix_length == right->prefix_length && left->table == right->table &&
    left->priority == right->priority && left->mark == right->mark &&
    left->mark_mask == right->mark_mask && left->metric == right->metric &&
    left->protocol == right->protocol;
}

static ftun_status_t route_apply(
  void *context, const ftun_route_resource_t *resource)
{
  host_state_t *state = (host_state_t *)context;
  size_t index;
  if (state == NULL || resource == NULL) return FTUN_E_INVALID;
  state->apply_attempts++;
  if (state->fail_apply_at != 0u &&
      state->apply_attempts == state->fail_apply_at) {
    if (state->fail_rollback) state->fail_remove = true;
    return FTUN_E_IO;
  }
  for (index = 0u; index < state->resource_count; index++) {
    if (resource_equal(resource, &state->resources[index])) return FTUN_E_REJECTED;
  }
  if (state->resource_count >= 32u) return FTUN_E_LIMIT;
  state->resources[state->resource_count++] = *resource;
  state->applies++;
  return FTUN_OK;
}

static ftun_status_t route_remove(
  void *context, const ftun_route_resource_t *resource)
{
  host_state_t *state = (host_state_t *)context;
  size_t index;
  if (state == NULL || resource == NULL) return FTUN_E_INVALID;
  if (state->fail_remove) return FTUN_E_IO;
  for (index = 0u; index < state->resource_count; index++) {
    if (resource_equal(resource, &state->resources[index])) break;
  }
  if (index == state->resource_count) return FTUN_E_STATE_CORRUPT;
  state->resources[index] = state->resources[--state->resource_count];
  state->removes++;
  return FTUN_OK;
}

static ftun_status_t consume_packet(void *user, ftun_tun_lease_t lease,
                                    ftun_bytes_t packet)
{
  consumer_runtime_t *runtime = (consumer_runtime_t *)user;
  (void)packet;
  if (runtime == NULL || lease.service != runtime->lease.service ||
      lease.generation != runtime->lease.generation) return FTUN_E_STALE;
  if (runtime->stall) return FTUN_E_AGAIN;
  runtime->received++;
  return FTUN_OK;
}

static void network_event(void *user, ftun_tun_lease_t lease,
  ftun_tun_service_event_t event, ftun_status_t status)
{
  consumer_runtime_t *runtime = user;
  ftun_tun_service_usage_t usage;
  if (runtime->owner != NULL) {
    ftun_event_loop_usage_t before, after;
    if (ftun_event_loop_get_usage(runtime->loop, &before) != FTUN_OK ||
        ftun_tun_owner_service.quiesce(runtime->owner) != FTUN_E_AGAIN ||
        ftun_event_loop_get_usage(runtime->loop, &after) != FTUN_OK ||
        before.source_count != after.source_count) runtime->callback_error = true;
  }
  if (lease.service != runtime->lease.service ||
      lease.generation != runtime->lease.generation ||
      ftun_tun_service_get_usage(lease.service, &usage) != FTUN_OK ||
      ftun_tun_service_refresh_network(lease.service, usage.network_generation) != FTUN_E_AGAIN) {
    runtime->callback_error = true;
    return;
  }
  if (event == FTUN_TUN_SERVICE_NETWORK_UPDATED) {
    runtime->network_updates++;
    if (status != FTUN_OK || !usage.accepting) runtime->callback_error = true;
  } else if (event == FTUN_TUN_SERVICE_REBUILT) {
    runtime->rebuilds++;
    if (status != FTUN_OK || !usage.accepting) runtime->callback_error = true;
  } else if (event == FTUN_TUN_SERVICE_FAILED) {
    runtime->failures++;
    if (status == FTUN_OK || usage.accepting) runtime->callback_error = true;
  }
}

static ftun_status_t proxy_plan_prepare(ftun_budget_t *budget,
  const ftun_config_t *config, uint32_t socket_mark, void **out)
{
  (void)budget;
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
  needs_tun = (config->plan->modules.required_modules & FTUN_BUILD_MODULE_TUN) != 0u;
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
  proxy_destroy_until,
  NULL,
  NULL /* network_changed */
};

static void set_config(ftun_config_t *config, ftun_feature_plan_t *plan,
                       ftun_config_inbound_t *inbound, bool with_tun)
{
  memset(config, 0, sizeof(*config));
  ftun_config_bind_sections(config);
  memset(plan, 0, sizeof(*plan));
  plan->modules.known_modules = FTUN_BUILD_MODULE_ALL;
  plan->modules.built_modules = FTUN_BUILD_MODULE_CORE |
    FTUN_BUILD_MODULE_PROXY | FTUN_BUILD_MODULE_TUN;
  plan->modules.required_modules = FTUN_BUILD_MODULE_CORE | FTUN_BUILD_MODULE_PROXY;
  ftun_config_bind_plan(config, plan);
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
  config->tun.route_table = 18004u;
  config->tun.rule_priority = 11000u;
  plan->modules.required_modules |= FTUN_BUILD_MODULE_TUN;
}

static bool network_matches(const host_state_t *host, const uint8_t address[4],
                              uint8_t prefix, bool strict_route)
{
  size_t addresses = 0u;
  size_t blocks = 0u;
  size_t index;
  for (index = 0u; index < host->resource_count; index++) {
    const ftun_route_resource_t *resource = &host->resources[index];
    if (resource->kind == FTUN_LINUX_ROUTE_ADDRESS) {
      if (memcmp(resource->address, address, 4u) != 0 ||
          resource->prefix_length != prefix) return false;
      addresses++;
    }
    if (resource->kind == FTUN_LINUX_ROUTE_BLOCK_IPV6) blocks++;
  }
  return addresses == 1u && blocks == (strict_route ? 1u : 0u);
}

static int test_network_update(ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations, ftun_tun_owner_binding_t *binding,
  host_state_t *host)
{
  ftun_config_t config;
  ftun_feature_plan_t plan;
  ftun_config_inbound_t inbound;
  ftun_core_service_binding_t service_binding = {binding, sizeof(*binding)};
  ftun_interface_spec_t candidate = {0};
  ftun_tun_network_update_result_t result;
  ftun_l3_provider_info_t info;
  ftun_tun_service_usage_t usage;
  ftun_tun_consumer_t consumer = {0};
  consumer_runtime_t client = {0};
  void *owner = NULL;
  size_t opens = host->opens;
  size_t attempts;
  size_t work;
  set_config(&config, &plan, &inbound, true);
  CHECK(ftun_tun_owner_service.prepare(core, budget, operations, &service_binding,
        &config, 1u, &owner) == FTUN_OK);
  CHECK(ftun_tun_owner_service.activate(owner) == FTUN_OK);
  CHECK(ftun_l3_provider_get_info(binding->provider, &info) == FTUN_OK &&
        info.device_generation == 1u && info.network_generation == 1u);
  consumer.packet = consume_packet;
  consumer.event = network_event;
  consumer.user = &client;
  CHECK(ftun_tun_service_acquire(binding->provider->service, &consumer, &client.lease) == FTUN_OK);
  client.stall = true;
  host->provide_packet = host->stall_writes = true;
  CHECK(ftun_tun_service_notify(client.lease.service, FTUN_EVENT_READ) == FTUN_OK);
  CHECK(ftun_tun_service_run(client.lease.service, &work) == FTUN_OK && work == 1u);
  CHECK(ftun_tun_service_write(client.lease, (ftun_bytes_t){(const uint8_t *)"old", 3u}) == FTUN_OK);
  CHECK(ftun_tun_service_get_usage(client.lease.service, &usage) == FTUN_OK &&
        usage.queued_inputs == 1u && usage.queued_packets == 1u);
  candidate.name = (ftun_string_t){"ftun-own0", 9u};
  memcpy(candidate.ipv4_address, (uint8_t[]){172u, 30u, 5u, 1u}, 4u);
  candidate.prefix_length = 24u;
  candidate.protection_mark = binding->protection_mark;
  CHECK(ftun_tun_owner_update_network(owner, 1u, &candidate, &result) == FTUN_OK &&
        result.committed && result.ready && result.network_generation == 2u);
  CHECK(network_matches(host, candidate.ipv4_address, 24u, false));
  CHECK(ftun_tun_service_get_usage(client.lease.service, &usage) == FTUN_OK &&
        usage.queued_inputs == 0u && usage.queued_packets == 0u && usage.packets_dropped == 2u);
  client.stall = host->stall_writes = false;
  CHECK(ftun_tun_service_run(client.lease.service, &work) == FTUN_OK &&
        work == 0u && client.received == 0u && client.network_updates == 1u);
  host->provide_packet = true;
  CHECK(ftun_tun_service_notify(client.lease.service, FTUN_EVENT_READ) == FTUN_OK);
  CHECK(ftun_tun_service_run(client.lease.service, &work) == FTUN_OK &&
        work == 1u && client.received == 1u);
  CHECK(ftun_l3_provider_get_info(binding->provider, &info) == FTUN_OK &&
        info.generation == 1u && info.device_generation == 1u && info.active_leases == 1u &&
        info.network_generation == 2u && host->opens == opens + 1u);
  attempts = host->apply_attempts;
  CHECK(ftun_tun_owner_update_network(owner, 2u, &candidate, &result) == FTUN_OK &&
        result.network_generation == 2u && host->apply_attempts == attempts);
  CHECK(ftun_tun_owner_update_network(owner, 1u, &candidate, &result) == FTUN_E_STALE &&
        result.update_status == FTUN_E_STALE && host->apply_attempts == attempts);
  candidate.prefix_length = 0u;
  CHECK(ftun_tun_owner_update_network(owner, 2u, &candidate, &result) == FTUN_E_INVALID &&
        result.update_status == FTUN_E_INVALID && host->apply_attempts == attempts);
  candidate.prefix_length = 28u;
  candidate.protection_mark++;
  CHECK(ftun_tun_owner_update_network(owner, 2u, &candidate, &result) == FTUN_E_INVALID);
  candidate.protection_mark--;
  memcpy(candidate.ipv4_address, (uint8_t[]){172u, 31u, 7u, 1u}, 4u);
  candidate.strict_route = true;
  host->fail_apply_at = host->apply_attempts + 3u;
  CHECK(ftun_tun_owner_update_network(owner, 2u, &candidate, &result) == FTUN_E_IO &&
        result.update_status == FTUN_E_IO && result.rollback_status == FTUN_OK &&
        !result.committed && result.ready && result.network_generation == 3u);
  CHECK(network_matches(host, (uint8_t[]){172u, 30u, 5u, 1u}, 24u, false));
  host->fail_apply_at = host->apply_attempts + 3u;
  host->fail_rollback = true;
  CHECK(ftun_tun_owner_update_network(owner, 3u, &candidate, &result) == FTUN_E_STATE_CORRUPT &&
        result.update_status == FTUN_E_STATE_CORRUPT && result.rollback_status == FTUN_E_IO &&
        !result.committed && !result.ready && result.network_generation == 3u);
  CHECK(host->opens == opens + 1u && host->opens == host->closes + 1u);
  CHECK(ftun_tun_service_write(client.lease,
        (ftun_bytes_t){(const uint8_t *)"x", 1u}) == FTUN_E_CANCELLED);
  host->fail_apply_at = 0u;
  host->fail_rollback = host->fail_remove = false;
  CHECK(ftun_tun_service_rebuild(binding->provider->service) == FTUN_OK);
  CHECK(network_matches(host, (uint8_t[]){172u, 30u, 5u, 1u}, 24u, false));
  CHECK(ftun_l3_provider_get_info(binding->provider, &info) == FTUN_OK && info.accepting &&
        info.device_generation == 2u && info.network_generation == 4u);
  /* 内部网络计划不改变公开 reload 的配置基线。 */
  CHECK(ftun_tun_owner_service.reload_prepare(owner, &config, 2u) == FTUN_OK);
  CHECK(ftun_tun_owner_update_network(owner, 4u, &candidate, &result) == FTUN_E_AGAIN);
  CHECK(ftun_tun_owner_service.reload_commit(owner, 2u) == FTUN_OK);
  config.tun.ipv4_address = "172.30.5.1/24";
  CHECK(ftun_tun_owner_service.reload_prepare(owner, &config, 3u) == FTUN_E_RESTART_REQUIRED);
  CHECK(ftun_tun_owner_service.quiesce(owner) == FTUN_OK);
  CHECK(!client.callback_error && client.network_updates == 2u && client.failures == 3u);
  CHECK(ftun_tun_owner_update_network(owner, 4u, &candidate, &result) == FTUN_E_CANCELLED);
  CHECK(ftun_tun_service_release(&client.lease) == FTUN_OK);
  CHECK(ftun_tun_owner_service.destroy_until(&owner, 100u) == FTUN_OK && owner == NULL);
  CHECK(host->resource_count == 0u && host->applies == host->removes &&
        host->opens == host->closes && binding->provider->service == NULL);
  return 0;
}

static ftun_status_t async_submit(void *context, const ftun_route_request_t *request)
{
  host_state_t *host = context;
  size_t index;
  host->async_requests++;
  host->reply = (ftun_route_reply_t){request->sequence, FTUN_OK, false};
  if (request->kind == FTUN_LINUX_ROUTE_REQUEST_QUERY) {
    for (index = 0u; index < host->resource_count; index++) {
      if (resource_equal(&host->resources[index], &request->resource)) host->reply.present = true;
    }
  } else if (request->kind == FTUN_LINUX_ROUTE_REQUEST_REMOVE) {
    host->reply.status = route_remove(host, &request->resource);
    if (host->reply.status == FTUN_E_STATE_CORRUPT) host->reply.status = FTUN_E_STALE;
  } else if (request->kind == FTUN_LINUX_ROUTE_REQUEST_ADD) {
    host->reply.status = route_apply(host, &request->resource);
    if (host->withhold_add_reply) host->withhold_replies = true;
  } else return FTUN_E_UNSUPPORTED;
  host->has_reply = true;
  return FTUN_OK;
}

static ftun_status_t async_receive(void *context, ftun_route_reply_t *reply)
{
  host_state_t *host = context;
  if (host->withhold_replies || !host->has_reply) return FTUN_E_AGAIN;
  *reply = host->reply;
  host->has_reply = false;
  return FTUN_OK;
}

/* 网络变化触发对账：外部删除一项自有资源后，owner 只补回缺失项；
 * 现状完好时不发任何变更。 */
static int test_network_changed_repair(ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations, ftun_tun_owner_binding_t *binding,
  host_state_t *host)
{
  ftun_interface_ops_t network = ftun_interface_default_ops;
  const ftun_interface_ops_t *previous = binding->network;
  ftun_route_async_io_t io = {async_submit, async_receive, host};
  ftun_core_service_binding_t service_binding = {binding, sizeof(*binding)};
  ftun_config_t config;
  ftun_feature_plan_t plan;
  ftun_config_inbound_t inbound;
  ftun_core_service_run_usage_t run;
  ftun_network_change_t change = {FTUN_NETWORK_CHANGE_ALL, {0}, 0u, 1u, false};
  ftun_budget_usage_t baseline, final;
  void *owner = NULL;
  uint64_t now_ms;
  size_t round, installed, applies, removes, requests;
  ftun_status_t status;
  CHECK(ftun_budget_get_usage(budget, &baseline) == FTUN_OK);
  network.context = previous->context;
  network.async.context = &io;
  binding->network = &network;
  set_config(&config, &plan, &inbound, true);
  CHECK(ftun_tun_owner_service.network_changed != NULL);
  CHECK(ftun_tun_owner_service.prepare(core, budget, operations, &service_binding,
    &config, 1u, &owner) == FTUN_OK);
  CHECK(ftun_tun_owner_service.activate(owner) == FTUN_OK);
  installed = host->resource_count;
  CHECK(installed >= 3u);
  CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK);
  /* 现状完好：只有核验查询，没有任何添加或删除。 */
  applies = host->applies;
  removes = host->removes;
  requests = host->async_requests;
  ftun_tun_owner_service.network_changed(owner, &change, now_ms);
  for (round = 0u; round < 64u; round++) {
    CHECK(ftun_tun_owner_service.run_once(owner, false, &run) == FTUN_OK);
  }
  CHECK(host->async_requests > requests && host->applies == applies &&
        host->removes == removes && host->resource_count == installed);
  /* 外部删除一项（保护规则之后的路由）：补回且只补这一项。 */
  host->resources[1] = host->resources[--host->resource_count];
  CHECK(host->resource_count == installed - 1u);
  ftun_tun_owner_service.network_changed(owner, &change, now_ms);
  for (round = 0u; round < 64u; round++) {
    CHECK(ftun_tun_owner_service.run_once(owner, false, &run) == FTUN_OK);
  }
  CHECK(host->resource_count == installed && host->applies == applies + 1u &&
        host->removes == removes);
  /* 对账出错（添加被拒）：不撤销现有资源，退避后重试。 */
  host->resources[1] = host->resources[--host->resource_count];
  host->fail_apply_at = host->apply_attempts + 1u;
  ftun_tun_owner_service.network_changed(owner, &change, now_ms);
  for (round = 0u; round < 64u; round++) {
    CHECK(ftun_tun_owner_service.run_once(owner, false, &run) == FTUN_OK);
  }
  CHECK(host->resource_count == installed - 1u && host->removes == removes);
  /* 停止仍然撤销全部剩余资源。 */
  CHECK(ftun_tun_owner_service.quiesce(owner) == FTUN_OK);
  CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK);
  for (round = 0u; round < 128u && owner != NULL; round++) {
    status = ftun_tun_owner_service.destroy_until(&owner, now_ms + 5000u);
    CHECK(status == FTUN_OK || status == FTUN_E_AGAIN || status == FTUN_E_TIMEOUT);
  }
  CHECK(owner == NULL && host->resource_count == 0u);
  CHECK(ftun_budget_get_usage(budget, &final) == FTUN_OK && final.used_resources.memory_bytes == baseline.used_resources.memory_bytes);
  host->fail_apply_at = 0u;
  host->async_requests = 0u;
  binding->network = previous;
  return 0;
}

static int test_async_stop(ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations, ftun_tun_owner_binding_t *binding,
  host_state_t *host)
{
  ftun_interface_ops_t network = ftun_interface_default_ops;
  const ftun_interface_ops_t *previous = binding->network;
  ftun_route_async_io_t io = {async_submit, async_receive, host};
  ftun_core_service_binding_t service_binding = {binding, sizeof(*binding)};
  ftun_config_t config;
  ftun_feature_plan_t plan;
  ftun_config_inbound_t inbound;
  ftun_budget_usage_t baseline, held, final;
  ftun_status_t status;
  uint64_t now_ms, deadline;
  size_t closes = host->closes, attempts;
  const struct timespec pause = {0, 250000000};
  void *owner = NULL;
  CHECK(ftun_budget_get_usage(budget, &baseline) == FTUN_OK);
  network.context = previous->context;
  network.async.context = &io;
  binding->network = &network;
  set_config(&config, &plan, &inbound, true);
  CHECK(ftun_tun_owner_service.prepare(core, budget, operations, &service_binding,
    &config, 1u, &owner) == FTUN_OK);
  CHECK(ftun_tun_owner_service.activate(owner) == FTUN_OK);
  CHECK(host->resource_count != 0u);
  host->withhold_replies = true;
  CHECK(ftun_tun_owner_service.quiesce(owner) == FTUN_OK && binding->provider->service == NULL);
  CHECK(host->async_requests == 0u && host->closes == closes);
  CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK);
  deadline = now_ms + 200u;
  CHECK(ftun_tun_owner_service.stop_until(owner, deadline) == FTUN_E_AGAIN);
  CHECK(host->async_requests == 1u && host->closes == closes);
  CHECK(ftun_budget_get_usage(budget, &held) == FTUN_OK && held.used_resources.memory_bytes > baseline.used_resources.memory_bytes);
  (void)nanosleep(&pause, NULL);
  CHECK(ftun_tun_owner_service.stop_until(owner, deadline) == FTUN_E_TIMEOUT);
  CHECK(ftun_tun_owner_service.destroy_until(&owner, deadline) == FTUN_E_TIMEOUT && owner != NULL);
  CHECK(host->async_requests == 2u && host->closes == closes);
  host->withhold_replies = false;
  CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK);
  /* 对齐 Core destroy 的不等待清理入口；过期期限也必须有有限进展。 */
  deadline = now_ms;
  for (attempts = 0u; attempts < 64u; attempts++) {
    status = ftun_tun_owner_service.destroy_until(&owner, deadline);
    if (status == FTUN_OK) break;
    CHECK(status == FTUN_E_AGAIN || status == FTUN_E_TIMEOUT);
  }
  CHECK(owner == NULL && host->closes == closes + 1u && host->resource_count == 0u);
  CHECK(ftun_budget_get_usage(budget, &final) == FTUN_OK && final.used_resources.memory_bytes == baseline.used_resources.memory_bytes &&
    final.used_resources.descriptors == baseline.used_resources.descriptors &&
    final.used_resources.queue_slots == baseline.used_resources.queue_slots);
  binding->network = previous;
  return 0;
}

static int drive_update(void *owner, ftun_tun_network_update_result_t *result)
{
  size_t round;
  ftun_core_service_run_usage_t usage;
  for (round = 0u; round < 128u; round++) {
    CHECK(ftun_tun_owner_query_network_update(owner, result) == FTUN_OK);
    if (!result->pending) return 0;
    CHECK(ftun_tun_owner_service.run_once(owner, false, &usage) == FTUN_OK);
    CHECK(usage.work <= 192u);
  }
  CHECK(!result->pending);
  return 1;
}

static int test_async_update(ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations, ftun_tun_owner_binding_t *binding,
  host_state_t *host)
{
  ftun_interface_ops_t network = ftun_interface_default_ops;
  const ftun_interface_ops_t *previous = binding->network;
  ftun_route_async_io_t io = {async_submit, async_receive, host};
  ftun_core_service_binding_t service_binding = {binding, sizeof(*binding)};
  ftun_config_t config;
  ftun_feature_plan_t plan;
  ftun_config_inbound_t inbound;
  ftun_tun_network_update_result_t result;
  ftun_core_service_run_usage_t run;
  ftun_budget_usage_t baseline, final;
  ftun_tun_consumer_t consumer = {0};
  ftun_interface_spec_t candidate = {{"ftun-own0", 9u}, {172u, 30u, 5u, 1u}, 24u, 0u, 18004u, 11000u, false, NULL};
  size_t scenario;
  network.context = previous->context;
  network.async.context = &io;
  binding->network = &network;
  candidate.protection_mark = binding->protection_mark;
  for (scenario = 0u; scenario < 5u; scenario++) {
    void *owner = NULL;
    consumer_runtime_t client = {0};
    uint64_t now_ms, deadline;
    size_t requests, attempts, round, closes = host->closes;
    ftun_status_t status;
    CHECK(ftun_budget_get_usage(budget, &baseline) == FTUN_OK);
    host->fail_apply_at = 0u;
    host->fail_remove = host->fail_rollback = host->withhold_replies = false;
    host->withhold_add_reply = host->has_reply = false;
    set_config(&config, &plan, &inbound, true);
    CHECK(ftun_tun_owner_service.prepare(core, budget, operations, &service_binding,
      &config, 1u, &owner) == FTUN_OK);
    CHECK(ftun_tun_owner_service.activate(owner) == FTUN_OK);
    consumer.packet = consume_packet;
    consumer.event = network_event;
    consumer.user = &client;
    CHECK(ftun_tun_service_acquire(binding->provider->service, &consumer, &client.lease) == FTUN_OK);
    attempts = host->apply_attempts;
    requests = host->async_requests;
    if (scenario == 1u || scenario == 2u) host->fail_apply_at = attempts + 3u;
    if (scenario == 2u) host->fail_rollback = true;
    if (scenario == 3u) host->withhold_replies = true;
    if (scenario == 4u) host->withhold_add_reply = true;
    CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK);
    deadline = now_ms + (scenario == 3u ? 20u : 5000u);
    CHECK(ftun_tun_owner_start_network_update(owner, 1u, &candidate, deadline) == FTUN_OK);
    CHECK(host->apply_attempts == attempts && host->async_requests == requests);
    CHECK(ftun_tun_owner_query_network_update(owner, &result) == FTUN_OK && result.pending &&
      !result.ready && !result.committed && result.network_generation == 1u);
    CHECK(ftun_tun_owner_start_network_update(owner, 1u, &candidate, deadline) == FTUN_E_AGAIN);
    CHECK(ftun_tun_owner_service.reload_prepare(owner, &config, 2u) == FTUN_E_AGAIN);
    CHECK(ftun_tun_service_rebuild(client.lease.service) == FTUN_E_AGAIN);
    CHECK(ftun_tun_service_write(client.lease,
      (ftun_bytes_t){(const uint8_t *)"x", 1u}) == FTUN_E_CANCELLED);
    if (scenario == 3u) {
      const struct timespec pause = {0, 30000000};
      CHECK(ftun_tun_owner_service.run_once(owner, false, &run) == FTUN_OK);
      (void)nanosleep(&pause, NULL);
      CHECK(ftun_tun_owner_service.run_once(owner, false, &run) == FTUN_OK);
      CHECK(ftun_tun_owner_query_network_update(owner, &result) == FTUN_OK &&
        !result.pending && !result.ready && result.update_status == FTUN_E_TIMEOUT &&
        result.rollback_status == FTUN_E_TIMEOUT && host->resource_count != 0u);
    } else if (scenario == 4u) {
      for (round = 0u; round < 16u && !host->withhold_replies; round++) {
        CHECK(ftun_tun_owner_service.run_once(owner, false, &run) == FTUN_OK);
      }
      CHECK(host->withhold_replies && host->resource_count == 1u);
      CHECK(ftun_tun_owner_service.quiesce(owner) == FTUN_OK);
      CHECK(ftun_tun_owner_query_network_update(owner, &result) == FTUN_OK &&
        !result.pending && !result.ready && result.update_status == FTUN_E_CANCELLED);
    } else {
      candidate.ipv4_address[3] = 99u;
      CHECK(drive_update(owner, &result) == 0);
      candidate.ipv4_address[3] = 1u;
      if (scenario == 0u) {
        CHECK(result.committed && result.ready && result.update_status == FTUN_OK &&
          result.network_generation == 2u);
        CHECK(network_matches(host, candidate.ipv4_address, 24u, false));
        CHECK(ftun_tun_owner_start_network_update(owner, 1u, &candidate, deadline) == FTUN_E_STALE);
        CHECK(ftun_tun_owner_query_network_update(owner, &result) == FTUN_OK && result.committed);
      } else if (scenario == 1u) {
        CHECK(!result.committed && result.ready && result.update_status == FTUN_E_IO &&
          result.rollback_status == FTUN_OK && result.network_generation == 2u);
        CHECK(network_matches(host, (uint8_t[]){172u, 19u, 0u, 1u}, 30u, true));
      } else {
        CHECK(!result.committed && !result.ready && result.rollback_status != FTUN_OK &&
          host->resource_count != 0u && result.network_generation == 1u);
        host->fail_remove = host->fail_rollback = false;
        host->fail_apply_at = 0u;
        CHECK(ftun_tun_owner_start_network_update(owner, 1u, &candidate, deadline) == FTUN_OK);
        CHECK(drive_update(owner, &result) == 0 && result.ready && result.committed);
        CHECK(network_matches(host, candidate.ipv4_address, 24u, false));
      }
      CHECK(ftun_tun_owner_service.reload_prepare(owner, &config, 2u) == FTUN_OK);
      CHECK(ftun_tun_owner_service.reload_abort(owner) == FTUN_OK);
    }
    CHECK(!client.callback_error && host->closes == closes);
    host->withhold_replies = host->withhold_add_reply = false;
    CHECK(ftun_tun_owner_service.quiesce(owner) == FTUN_OK);
    CHECK(ftun_tun_service_release(&client.lease) == FTUN_OK);
    CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK);
    for (round = 0u; round < 128u && owner != NULL; round++) {
      status = ftun_tun_owner_service.destroy_until(&owner, now_ms + 5000u);
      CHECK(status == FTUN_OK || status == FTUN_E_AGAIN || status == FTUN_E_TIMEOUT);
    }
    CHECK(owner == NULL && host->resource_count == 0u && host->closes == closes + 1u);
    CHECK(ftun_budget_get_usage(budget, &final) == FTUN_OK && final.used_resources.memory_bytes == baseline.used_resources.memory_bytes &&
      final.used_resources.descriptors == baseline.used_resources.descriptors &&
      final.used_resources.queue_slots == baseline.used_resources.queue_slots);
  }
  binding->network = previous;
  return 0;
}

static void pressure_timer(ftun_event_source_t *source, uint32_t events, void *user)
{ (void)source; (void)events; (void)user; }

static int test_async_rebuild(ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations, ftun_tun_owner_binding_t *binding,
  host_state_t *host)
{
  ftun_interface_ops_t network = ftun_interface_default_ops;
  const ftun_interface_ops_t *previous = binding->network;
  ftun_route_async_io_t io = {async_submit, async_receive, host};
  ftun_core_service_binding_t service_binding = {binding, sizeof(*binding)};
  ftun_config_t config;
  ftun_feature_plan_t plan;
  ftun_config_inbound_t inbound;
  ftun_tun_network_update_result_t result;
  ftun_core_service_run_usage_t run;
  ftun_budget_usage_t baseline, final;
  ftun_tun_consumer_t consumer = {0};
  ftun_interface_spec_t candidate = {{"ftun-own0", 9u}, {172u, 30u, 5u, 1u}, 24u, 0u, 18004u, 11000u, false, NULL};
  size_t scenario;
  network.context = previous->context;
  network.async.context = &io;
  binding->network = &network;
  candidate.protection_mark = binding->protection_mark;
  host->check_close_order = true;
  for (scenario = 0u; scenario < 8u; scenario++) {
    void *owner = NULL;
    consumer_runtime_t client = {0};
    ftun_event_source_t *pressure[16] = {0};
    uint64_t now_ms, deadline;
    size_t round, opens = host->opens, closes = host->closes;
    ftun_status_t status;
    CHECK(ftun_budget_get_usage(budget, &baseline) == FTUN_OK);
    host->fail_apply_at = 0u;
    host->fail_remove = host->fail_rollback = host->withhold_replies = false;
    host->withhold_add_reply = host->has_reply = false;
    host->fail_open_once = host->fail_close_once = false;
    set_config(&config, &plan, &inbound, true);
    CHECK(ftun_tun_owner_service.prepare(core, budget, operations, &service_binding,
      &config, 1u, &owner) == FTUN_OK);
    CHECK(ftun_tun_owner_service.activate(owner) == FTUN_OK);
    client.owner = owner;
    client.loop = binding->loop;
    consumer.packet = consume_packet;
    consumer.event = network_event;
    consumer.user = &client;
    CHECK(ftun_tun_service_acquire(binding->provider->service, &consumer, &client.lease) == FTUN_OK);
    CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK);
    deadline = now_ms + 5000u;
    if (scenario == 0u) {
      CHECK(ftun_tun_owner_start_network_update(owner, 1u, &candidate, deadline) == FTUN_OK);
      CHECK(drive_update(owner, &result) == 0 && result.ready && result.committed);
      CHECK(ftun_tun_owner_start_rebuild(owner, 2u, 2u, deadline) == FTUN_E_STALE);
    }
    if (scenario == 1u) host->fail_remove = true;
    if (scenario == 2u) host->fail_open_once = true;
    if (scenario == 3u) host->fail_apply_at = host->apply_attempts + 3u;
    if (scenario == 4u) host->fail_close_once = true;
    if (scenario == 5u) host->withhold_replies = true;
    if (scenario == 6u) host->withhold_add_reply = true;
    if (scenario == 5u) {
      CHECK(ftun_tun_owner_start_rebuild(owner, 1u, 1u, now_ms + 20u) == FTUN_OK);
    } else {
      CHECK(ftun_tun_service_rebuild(client.lease.service) == FTUN_E_AGAIN);
    }
    CHECK(ftun_tun_owner_query_network_update(owner, &result) == FTUN_OK &&
      result.pending && result.rebuild && !result.ready && result.device_generation == 1u);
    CHECK(host->opens == opens + 1u && host->closes == closes);
    CHECK(ftun_tun_owner_service.reload_prepare(owner, &config, 2u) == FTUN_E_AGAIN);
    CHECK(ftun_tun_service_rebuild(client.lease.service) == FTUN_E_AGAIN);
    CHECK(ftun_tun_service_write(client.lease,
      (ftun_bytes_t){(const uint8_t *)"x", 1u}) == FTUN_E_CANCELLED);
    if (scenario == 7u) {
      for (round = 0u; round < 15u; round++) {
        CHECK(ftun_event_timer_start(binding->loop, now_ms + 60000u,
          pressure_timer, NULL, &pressure[round]) == FTUN_OK);
      }
    }
    if (scenario == 5u) {
      const struct timespec pause = {0, 30000000};
      CHECK(ftun_tun_owner_service.run_once(owner, false, &run) == FTUN_OK);
      (void)nanosleep(&pause, NULL);
      CHECK(ftun_tun_owner_service.run_once(owner, false, &run) == FTUN_OK);
      CHECK(ftun_tun_owner_query_network_update(owner, &result) == FTUN_OK &&
        !result.pending && !result.ready && result.update_status == FTUN_E_TIMEOUT);
      CHECK(host->closes == closes && client.rebuilds == 0u);
    } else if (scenario == 6u) {
      for (round = 0u; round < 16u && !host->withhold_replies; round++) {
        CHECK(ftun_tun_owner_service.run_once(owner, false, &run) == FTUN_OK);
      }
      CHECK(host->withhold_replies && host->resource_count == 1u && host->closes == closes + 1u);
      CHECK(client.rebuilds == 0u);
      CHECK(ftun_tun_owner_service.quiesce(owner) == FTUN_OK);
      CHECK(ftun_tun_owner_query_network_update(owner, &result) == FTUN_OK &&
        !result.pending && result.rebuild && !result.ready && result.update_status == FTUN_E_CANCELLED);
    } else {
      CHECK(drive_update(owner, &result) == 0);
      if (scenario != 0u) {
        CHECK(!result.ready && !result.committed && client.rebuilds == 0u);
        CHECK(result.update_status == (scenario == 7u ? FTUN_E_LIMIT : FTUN_E_IO));
        if (scenario == 1u) CHECK(host->closes == closes && host->resource_count != 0u);
        else CHECK(host->closes == closes + 1u && host->resource_count == 0u);
        host->fail_remove = false;
        host->fail_apply_at = 0u;
        for (round = 0u; round < 16u; round++) CHECK(ftun_event_source_cancel(&pressure[round]) == FTUN_OK);
        CHECK(ftun_tun_owner_start_rebuild(owner, result.device_generation,
          result.network_generation, deadline) == FTUN_OK);
        CHECK(drive_update(owner, &result) == 0);
      }
      CHECK(result.rebuild && result.ready && result.committed && result.update_status == FTUN_OK);
      CHECK(client.rebuilds == 1u && result.network_generation == (scenario == 0u ? 3u : 2u));
      CHECK(result.device_generation == ((scenario == 3u || scenario == 7u) ? 3u : 2u));
      CHECK(network_matches(host, scenario == 0u ? candidate.ipv4_address :
        (uint8_t[]){172u, 19u, 0u, 1u}, scenario == 0u ? 24u : 30u, scenario != 0u));
      if (scenario == 0u) {
        CHECK(ftun_tun_service_refresh_network(client.lease.service, result.network_generation) == FTUN_E_AGAIN);
        CHECK(drive_update(owner, &result) == 0 && !result.rebuild && result.ready && result.committed);
        CHECK(result.device_generation == 2u && result.network_generation == 4u &&
          host->opens == opens + 2u && host->closes == closes + 1u);
      }
      CHECK(ftun_tun_owner_service.reload_prepare(owner, &config, 2u) == FTUN_OK);
      CHECK(ftun_tun_owner_service.reload_abort(owner) == FTUN_OK);
    }
    CHECK(!client.callback_error && !host->close_order_error);
    host->withhold_replies = host->withhold_add_reply = false;
    CHECK(ftun_tun_owner_service.quiesce(owner) == FTUN_OK);
    CHECK(ftun_tun_service_release(&client.lease) == FTUN_OK);
    CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK);
    for (round = 0u; round < 128u && owner != NULL; round++) {
      status = ftun_tun_owner_service.destroy_until(&owner, now_ms + 5000u);
      CHECK(status == FTUN_OK || status == FTUN_E_AGAIN || status == FTUN_E_TIMEOUT);
    }
    CHECK(owner == NULL && host->resource_count == 0u && !host->close_order_error &&
      host->opens - opens == host->closes - closes);
    CHECK(ftun_budget_get_usage(budget, &final) == FTUN_OK && final.used_resources.memory_bytes == baseline.used_resources.memory_bytes &&
      final.used_resources.descriptors == baseline.used_resources.descriptors &&
      final.used_resources.queue_slots == baseline.used_resources.queue_slots);
  }
  host->check_close_order = false;
  binding->network = previous;
  return 0;
}

static int test_owner_deadline_wakeup(ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations, ftun_tun_owner_binding_t *binding,
  host_state_t *host)
{
  ftun_interface_ops_t network = ftun_interface_default_ops;
  const ftun_interface_ops_t *previous = binding->network;
  ftun_route_async_io_t io = {async_submit, async_receive, host};
  ftun_core_service_binding_t service_binding = {binding, sizeof(*binding)};
  ftun_config_t config;
  ftun_feature_plan_t plan;
  ftun_config_inbound_t inbound;
  ftun_tun_network_update_result_t result;
  ftun_core_service_run_usage_t run;
  ftun_event_loop_usage_t usage;
  ftun_budget_usage_t baseline, final;
  void *owner = NULL;
  uint64_t now_ms, deadline;
  size_t round;
  int pair[2];
  CHECK(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
  host->real_descriptor = true;
  host->descriptor = pair[0];
  host->withhold_replies = host->withhold_add_reply = host->has_reply = false;
  network.context = previous->context;
  network.async.context = &io;
  binding->network = &network;
  CHECK(ftun_event_backend_attach(binding->loop) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &baseline) == FTUN_OK);
  set_config(&config, &plan, &inbound, true);
  CHECK(ftun_tun_owner_service.prepare(core, budget, operations, &service_binding,
    &config, 1u, &owner) == FTUN_OK);
  CHECK(ftun_tun_owner_service.activate(owner) == FTUN_OK);
  host->withhold_replies = true;
  CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK);
  deadline = now_ms + 40u;
  CHECK(ftun_tun_owner_start_rebuild(owner, 1u, 1u, deadline) == FTUN_OK);
  CHECK(ftun_tun_owner_service.run_once(owner, false, &run) == FTUN_OK);
  /* 注入的网络后端不注册 Event source；总期限仍必须有唤醒来源。 */
  CHECK(ftun_event_loop_get_usage(binding->loop, &usage) == FTUN_OK && usage.source_count != 0u);
  for (round = 0u; round < 16u; round++) {
    CHECK(ftun_tun_owner_query_network_update(owner, &result) == FTUN_OK);
    if (!result.pending) break;
    CHECK(ftun_tun_owner_service.run_once(owner, true, &run) == FTUN_OK);
  }
  CHECK(!result.pending && result.update_status == FTUN_E_TIMEOUT && !result.ready);
  CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK && now_ms >= deadline);
  CHECK(ftun_event_loop_get_usage(binding->loop, &usage) == FTUN_OK && usage.source_count == 0u);
  host->withhold_replies = false;
  for (round = 0u; round < 64u && owner != NULL; round++) {
    ftun_status_t status = ftun_tun_owner_service.destroy_until(&owner, now_ms + 5000u);
    CHECK(status == FTUN_OK || status == FTUN_E_AGAIN);
  }
  CHECK(owner == NULL && host->resource_count == 0u);
  CHECK(ftun_budget_get_usage(budget, &final) == FTUN_OK && final.used_resources.memory_bytes == baseline.used_resources.memory_bytes &&
    final.used_resources.descriptors == baseline.used_resources.descriptors &&
    final.used_resources.queue_slots == baseline.used_resources.queue_slots);
  CHECK(ftun_event_loop_stop(binding->loop) == FTUN_OK);
  CHECK(ftun_event_backend_detach(binding->loop) == FTUN_OK);
  CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
  host->real_descriptor = false;
  binding->network = previous;
  return 0;
}

static int test_plan_budget(void)
{
  ftun_budget_t *budget = NULL;
  ftun_reservation_t hold = (ftun_reservation_t){0};
  ftun_core_service_plan_t first = {0}, second = {0};
  ftun_config_t config;
  ftun_feature_plan_t features;
  ftun_config_inbound_t inbound;
  ftun_budget_usage_t usage;
  size_t charge;
  set_config(&config, &features, &inbound, true);
  CHECK(ftun_budget_create(NULL, 65536u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_budget_reserve(budget, 65536u, &hold) == FTUN_OK);
  CHECK(ftun_core_service_plan_prepare(&ftun_tun_owner_service, budget, &config,
    0u, &first) == FTUN_E_LIMIT && first.implementation == NULL);
  ftun_reservation_release(&hold);
  fail_plan_calloc = true;
  CHECK(ftun_core_service_plan_prepare(&ftun_tun_owner_service, budget, &config,
    0u, &first) == FTUN_E_LIMIT && first.implementation == NULL && !fail_plan_calloc);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u);
  config.tun.mtu = 0u;
  CHECK(ftun_core_service_plan_prepare(&ftun_tun_owner_service, budget, &config,
    0u, &first) == FTUN_E_INVALID && first.implementation == NULL);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u);
  config.tun.mtu = 1400u;
  CHECK(ftun_core_service_plan_prepare(&ftun_tun_owner_service, budget, &config,
    0u, &first) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes > 0u &&
    usage.used_resources.descriptors == 0u && usage.used_resources.queue_slots == 0u);
  charge = usage.used_resources.memory_bytes;
  CHECK(ftun_core_service_plan_prepare(&ftun_tun_owner_service, budget, &config,
    0u, &second) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 2u * charge);
  CHECK(ftun_core_service_plan_destroy(&first) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == charge);
  CHECK(ftun_core_service_plan_destroy(&second) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(void)
{
  host_state_t host;
  consumer_state_t consumer;
  ftun_tun_device_ops_t device_ops;
  ftun_route_io_t route_io;
  ftun_interface_ops_t network = ftun_interface_default_ops;
  ftun_tun_owner_binding_t owner_binding;
  ftun_l3_provider_t provider;
  ftun_core_module_descriptor_t modules[3];
  ftun_core_module_catalog_t catalog;
  ftun_core_module_runtime_t *runtime = NULL;
  ftun_core_module_reload_plan_t *reload_plan = NULL;
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

  CHECK(test_plan_budget() == 0);

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
  network.context = &route_io;
  /* 既有同步恢复故障夹具；异步停止由单独场景提供非阻塞 IO。 */
  memset(&network.async, 0, sizeof(network.async));
  owner_binding.network = &network;
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
  applies_before = host.applies;
  CHECK(ftun_tun_service_rebuild(provider.service) == FTUN_OK);
  CHECK(host.opens == 4u && host.closes == 3u &&
        consumer.lease.service == provider.service);
  CHECK(host.applies > applies_before && host.removes == applies_before);

  /* 撤销失败时禁止收发，保留旧设备与事务；重试不得重复打开设备。 */
  host.fail_remove = true;
  CHECK(ftun_tun_service_rebuild(provider.service) == FTUN_E_IO);
  CHECK(host.opens == 4u && host.closes == 3u);
  CHECK(ftun_l3_provider_get_info(&provider, &provider_info) == FTUN_OK &&
        !provider_info.accepting && provider_info.device_generation == 2u);
  CHECK(ftun_tun_service_write(consumer.lease,
        (ftun_bytes_t){(const uint8_t *)"x", 1u}) == FTUN_E_CANCELLED);
  host.fail_remove = false;
  host.fail_apply_at = host.apply_attempts + 3u;
  host.fail_rollback = true;
  CHECK(ftun_tun_service_rebuild(provider.service) != FTUN_OK);
  CHECK(host.opens == 5u && host.closes == 4u && host.fail_remove);
  CHECK(ftun_l3_provider_get_info(&provider, &provider_info) == FTUN_OK &&
        !provider_info.accepting && provider_info.device_generation == 2u);
  /* 部分恢复且补偿失败，候选设备保留到剩余路由可撤销。 */
  CHECK(ftun_tun_service_rebuild(provider.service) == FTUN_E_IO);
  CHECK(host.opens == 5u && host.closes == 4u);
  host.fail_remove = host.fail_rollback = false;
  host.fail_apply_at = 0u;
  CHECK(ftun_tun_service_rebuild(provider.service) == FTUN_OK);
  CHECK(host.opens == 6u && host.closes == 5u);
  CHECK(ftun_l3_provider_get_info(&provider, &provider_info) == FTUN_OK &&
        provider_info.accepting && provider_info.device_generation == 3u);

  CHECK(ftun_core_module_reload_plan_prepare(&catalog, budget, &config,
        owner_binding.protection_mark, &reload_plan, NULL) == FTUN_OK);
  CHECK(ftun_core_module_runtime_reload_prepare_planned(
        runtime, &config, 2u, reload_plan) == FTUN_OK);
  CHECK(ftun_l3_provider_get_info(&provider, &provider_info) == FTUN_OK &&
        provider_info.reload_prepared &&
        provider_info.pending_generation == 2u);
  CHECK(ftun_core_module_runtime_reload_commit(runtime, 2u) == FTUN_OK);
  CHECK(ftun_core_module_reload_plan_destroy(&reload_plan) == FTUN_OK);
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

  /* 首次激活也遵循相同恢复契约；补偿失败时保留未发布的 service/事务。 */
  host.fail_apply_at = host.apply_attempts + 3u;
  host.fail_rollback = true;
  CHECK(ftun_core_module_runtime_prepare(&catalog, core, budget, operations,
        &config, 1u, &runtime, NULL) == FTUN_OK);
  CHECK(ftun_core_module_runtime_activate(runtime, 100u) != FTUN_OK);
  CHECK(runtime != NULL && provider.service == NULL && host.opens == host.closes + 1u);
  CHECK(ftun_core_module_runtime_destroy_until(&runtime, 100u) != FTUN_OK && runtime != NULL);
  host.fail_remove = host.fail_rollback = false;
  host.fail_apply_at = 0u;
  CHECK(ftun_core_module_runtime_destroy_until(&runtime, 100u) == FTUN_OK);
  CHECK(host.opens == host.closes && host.applies == host.removes);

  CHECK(test_network_update(core, budget, operations, &owner_binding, &host) == 0);
  CHECK(test_network_changed_repair(core, budget, operations, &owner_binding, &host) == 0);
  CHECK(test_async_stop(core, budget, operations, &owner_binding, &host) == 0);
  CHECK(test_async_update(core, budget, operations, &owner_binding, &host) == 0);
  CHECK(test_async_rebuild(core, budget, operations, &owner_binding, &host) == 0);
  CHECK(test_owner_deadline_wakeup(core, budget, operations, &owner_binding, &host) == 0);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}
