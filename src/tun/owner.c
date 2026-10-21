#include "tun/owner.h"

#include "event/event.h"
#include "util/buffer.h"
#include "util/time.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define FTUN_TUN_OWNER_CONSUMERS 4u
#define FTUN_TUN_OWNER_INPUT_CAPACITY 64u
#define FTUN_TUN_OWNER_CONSUMER_QUOTA 16u
#define FTUN_TUN_OWNER_OUTPUT_CAPACITY 256u
#define FTUN_TUN_OWNER_IO_QUOTA 64u
#define FTUN_TUN_OWNER_EVENT_QUOTA 64u
#define FTUN_TUN_OWNER_POOL_BYTES (2u * 1024u * 1024u)
#define FTUN_TUN_OWNER_POOL_BUFFERS 64u

typedef struct {
  char name[FTUN_PACKET_PORT_NAME_BYTES];
  uint8_t address[4];
  uint8_t prefix_length;
  uint32_t mtu;
  uint32_t protection_mark;
  bool auto_route;
  bool strict_route;
} ftun_tun_owner_plan_t;

typedef struct {
  ftun_core_t *core;
  ftun_budget_t *budget;
  ftun_reservation_t *reservation;
  ftun_event_loop_t *loop;
  ftun_buffer_pool_t *buffers;
  ftun_tun_service_t *service;
  ftun_route_transaction_t *routes;
  ftun_l3_provider_t *published;
  ftun_tun_device_ops_t device_ops;
  ftun_linux_route_io_t route_io;
  ftun_tun_owner_plan_t plan;
  uint64_t generation;
  uint64_t pending_generation;
  bool has_device_ops;
  bool has_route_io;
  bool active;
  bool quiesced;
  bool reload_prepared;
} ftun_tun_owner_t;

static ftun_status_t ftun_tun_owner_parse_cidr(
  const char *text, uint8_t address[4], uint8_t *prefix)
{
  const char *slash;
  char ip[INET_ADDRSTRLEN];
  char *tail = NULL;
  unsigned long value;
  size_t length;
  if (text == NULL || address == NULL || prefix == NULL ||
      (slash = strchr(text, '/')) == NULL) return FTUN_E_INVALID;
  length = (size_t)(slash - text);
  if (length == 0u || length >= sizeof(ip)) return FTUN_E_INVALID;
  memcpy(ip, text, length);
  ip[length] = '\0';
  errno = 0;
  value = strtoul(slash + 1u, &tail, 10);
  if (errno != 0 || tail == slash + 1u || *tail != '\0' || value > 32u ||
      inet_pton(AF_INET, ip, address) != 1) return FTUN_E_INVALID;
  *prefix = (uint8_t)value;
  return FTUN_OK;
}

static ftun_status_t ftun_tun_owner_plan_build(
  const ftun_config_t *config, uint32_t protection_mark,
  ftun_tun_owner_plan_t *out)
{
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (config == NULL || out == NULL) return FTUN_E_INVALID;
  if (!config->tun.present || config->tun.interface_name == NULL ||
      config->tun.ipv4_address == NULL || config->tun.mtu == 0u ||
      strlen(config->tun.interface_name) == 0u ||
      strlen(config->tun.interface_name) >= sizeof(out->name)) {
    return FTUN_E_INVALID;
  }
  memcpy(out->name, config->tun.interface_name,
         strlen(config->tun.interface_name) + 1u);
  out->mtu = config->tun.mtu;
  out->auto_route = config->tun.auto_route;
  out->strict_route = config->tun.strict_route;
  out->protection_mark = config->tun.auto_route ? protection_mark : 0u;
  status = ftun_tun_owner_parse_cidr(
    config->tun.ipv4_address, out->address, &out->prefix_length);
  return status;
}

static int ftun_tun_owner_plan_equal(
  const ftun_tun_owner_plan_t *left, const ftun_tun_owner_plan_t *right)
{
  return left != NULL && right != NULL &&
    strcmp(left->name, right->name) == 0 &&
    memcmp(left->address, right->address, sizeof(left->address)) == 0 &&
    left->prefix_length == right->prefix_length && left->mtu == right->mtu &&
    left->protection_mark == right->protection_mark &&
    left->auto_route == right->auto_route &&
    left->strict_route == right->strict_route;
}

static ftun_status_t ftun_tun_owner_plan_prepare(
  const ftun_config_t *config, uint32_t socket_mark, void **out)
{
  ftun_tun_owner_plan_t *plan;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (out == NULL) return FTUN_E_INVALID;
  plan = (ftun_tun_owner_plan_t *)calloc(1u, sizeof(*plan));
  if (plan == NULL) return FTUN_E_LIMIT;
  status = ftun_tun_owner_plan_build(config, socket_mark, plan);
  if (status != FTUN_OK) {
    free(plan);
    return status;
  }
  *out = plan;
  return FTUN_OK;
}

static ftun_status_t ftun_tun_owner_plan_destroy(void **plan)
{
  if (plan == NULL) return FTUN_E_INVALID;
  free(*plan);
  *plan = NULL;
  return FTUN_OK;
}

static ftun_status_t ftun_tun_owner_prepare(
  ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations,
  const ftun_core_service_binding_t *binding,
  const ftun_config_t *config, uint64_t generation, void **out)
{
  const ftun_tun_owner_binding_t *host;
  ftun_tun_owner_t *owner = NULL;
  ftun_budget_resources_t resources = {
    sizeof(*owner), 1u,
    FTUN_TUN_OWNER_CONSUMERS *
      (FTUN_TUN_OWNER_INPUT_CAPACITY + FTUN_TUN_OWNER_OUTPUT_CAPACITY)
  };
  ftun_status_t status;
  (void)operations;
  if (out != NULL) *out = NULL;
  if (core == NULL || budget == NULL || binding == NULL ||
      binding->value == NULL ||
      binding->size != sizeof(ftun_tun_owner_binding_t) || config == NULL ||
      generation == 0u || out == NULL) return FTUN_E_INVALID;
  host = (const ftun_tun_owner_binding_t *)binding->value;
  if (host->provider == NULL || host->loop == NULL ||
      host->provider->service != NULL || host->provider->budget != NULL ||
      host->provider->generation != 0u ||
      host->provider->pending_generation != 0u ||
      host->provider->reload_prepared) return FTUN_E_INVALID;
  owner = (ftun_tun_owner_t *)calloc(1u, sizeof(*owner));
  if (owner == NULL) return FTUN_E_LIMIT;
  status = ftun_budget_reserve_resources(budget, resources,
                                          &owner->reservation);
  if (status != FTUN_OK) goto fail;
  owner->core = core;
  owner->budget = budget;
  owner->loop = host->loop;
  owner->published = host->provider;
  owner->generation = generation;
  if (host->device_ops != NULL) {
    owner->device_ops = *host->device_ops;
    owner->has_device_ops = true;
  }
  if (host->route_io != NULL) {
    owner->route_io = *host->route_io;
    owner->has_route_io = true;
  }
  status = ftun_tun_owner_plan_build(
    config, host->protection_mark, &owner->plan);
  if (status != FTUN_OK) goto fail;
  status = ftun_buffer_pool_create(
    budget, FTUN_TUN_OWNER_POOL_BYTES, FTUN_TUN_OWNER_POOL_BUFFERS,
    &owner->buffers);
  if (status != FTUN_OK) goto fail;
  *out = owner;
  return FTUN_OK;

fail:
  if (owner != NULL) {
    if (owner->published != NULL) memset(owner->published, 0,
                                         sizeof(*owner->published));
    (void)ftun_linux_route_release(&owner->routes);
    (void)ftun_tun_service_quiesce(owner->service);
    (void)ftun_tun_service_destroy(&owner->service);
    (void)ftun_buffer_pool_destroy(&owner->buffers);
    (void)ftun_reservation_release(&owner->reservation);
    free(owner);
  }
  return status;
}

static ftun_status_t ftun_tun_owner_activate(void *implementation)
{
  ftun_tun_owner_t *owner = (ftun_tun_owner_t *)implementation;
  ftun_tun_service_spec_t service_spec;
  ftun_route_policy_t route;
  ftun_status_t status;
  ftun_status_t cleanup;
  if (owner == NULL || owner->quiesced || owner->active ||
      owner->service != NULL || owner->routes != NULL ||
      owner->published == NULL || owner->published->service != NULL) {
    return FTUN_E_INVALID;
  }
  memset(&service_spec, 0, sizeof(service_spec));
  service_spec.core = owner->core;
  service_spec.budget = owner->budget;
  service_spec.loop = owner->loop;
  service_spec.buffers = owner->buffers;
  service_spec.device.name.data = owner->plan.name;
  service_spec.device.name.length = strlen(owner->plan.name);
  service_spec.device.mtu = owner->plan.mtu;
  service_spec.consumer_capacity = FTUN_TUN_OWNER_CONSUMERS;
  service_spec.input_capacity = FTUN_TUN_OWNER_INPUT_CAPACITY;
  service_spec.consumer_quota = FTUN_TUN_OWNER_CONSUMER_QUOTA;
  service_spec.output_capacity = FTUN_TUN_OWNER_OUTPUT_CAPACITY;
  service_spec.read_quota = FTUN_TUN_OWNER_IO_QUOTA;
  service_spec.write_quota = FTUN_TUN_OWNER_IO_QUOTA;
  status = owner->has_device_ops
    ? ftun_tun_service_create_with_ops(
        &service_spec, &owner->device_ops, &owner->service)
    : ftun_tun_service_create(&service_spec, &owner->service);
  if (status != FTUN_OK) return status;
  if (owner->plan.auto_route) {
    memset(&route, 0, sizeof(route));
    route.tun_interface.data = owner->plan.name;
    route.tun_interface.length = strlen(owner->plan.name);
    memcpy(route.tun_ipv4, owner->plan.address, sizeof(route.tun_ipv4));
    route.tun_prefix_length = owner->plan.prefix_length;
    route.route_table = 51820u;
    route.rule_priority = 11000u;
    route.protection_mark = owner->plan.protection_mark;
    route.protection_mark_mask = UINT32_MAX;
    route.manage_local = true;
    route.strict_route = owner->plan.strict_route;
    status = owner->has_route_io
      ? ftun_linux_route_prepare_with_io(
          &route, &owner->route_io, &owner->routes)
      : ftun_linux_route_prepare(&route, &owner->routes);
  }
  if (status == FTUN_OK) {
    status = ftun_l3_provider_bind(
      owner->service, owner->generation, owner->published);
  }
  if (status != FTUN_OK) {
    cleanup = ftun_linux_route_release(&owner->routes);
    if (owner->service != NULL) {
      ftun_status_t current = ftun_tun_service_quiesce(owner->service);
      if (cleanup == FTUN_OK && current != FTUN_OK) cleanup = current;
      current = ftun_tun_service_destroy(&owner->service);
      if (cleanup == FTUN_OK && current != FTUN_OK) cleanup = current;
    }
    return cleanup == FTUN_OK ? status : FTUN_E_STATE_CORRUPT;
  }
  owner->active = true;
  return FTUN_OK;
}

static ftun_status_t ftun_tun_owner_reload_prepare_value(
  ftun_tun_owner_t *owner, const ftun_tun_owner_plan_t *plan,
  uint64_t generation)
{
  ftun_status_t status;
  if (owner == NULL || plan == NULL || generation <= owner->generation ||
      !owner->active || owner->service == NULL || owner->quiesced ||
      owner->reload_prepared) return FTUN_E_INVALID;
  if (!ftun_tun_owner_plan_equal(&owner->plan, plan)) {
    return FTUN_E_RESTART_REQUIRED;
  }
  status = ftun_l3_provider_reload_prepare(owner->published, generation);
  if (status == FTUN_OK) {
    owner->pending_generation = generation;
    owner->reload_prepared = true;
  }
  return status;
}

static ftun_status_t ftun_tun_owner_reload_prepare(
  void *implementation, const ftun_config_t *config, uint64_t generation)
{
  ftun_tun_owner_t *owner = (ftun_tun_owner_t *)implementation;
  ftun_tun_owner_plan_t plan;
  ftun_status_t status;
  if (owner == NULL) return FTUN_E_INVALID;
  status = ftun_tun_owner_plan_build(
    config, owner->plan.protection_mark, &plan);
  return status == FTUN_OK
    ? ftun_tun_owner_reload_prepare_value(owner, &plan, generation) : status;
}

static ftun_status_t ftun_tun_owner_reload_prepare_planned(
  void *implementation, const ftun_config_t *config, uint64_t generation,
  const void *plan)
{
  (void)config;
  return ftun_tun_owner_reload_prepare_value(
    (ftun_tun_owner_t *)implementation,
    (const ftun_tun_owner_plan_t *)plan, generation);
}

static ftun_status_t ftun_tun_owner_reload_commit(
  void *implementation, uint64_t generation)
{
  ftun_tun_owner_t *owner = (ftun_tun_owner_t *)implementation;
  ftun_status_t status;
  if (owner == NULL || !owner->reload_prepared ||
      generation != owner->pending_generation) return FTUN_E_INVALID;
  status = ftun_l3_provider_reload_commit(owner->published, generation);
  if (status == FTUN_OK) {
    owner->generation = generation;
    owner->pending_generation = 0u;
    owner->reload_prepared = false;
  }
  return status;
}

static ftun_status_t ftun_tun_owner_reload_abort(void *implementation)
{
  ftun_tun_owner_t *owner = (ftun_tun_owner_t *)implementation;
  ftun_status_t status;
  if (owner == NULL) return FTUN_E_INVALID;
  if (!owner->reload_prepared) return FTUN_OK;
  status = ftun_l3_provider_reload_abort(owner->published);
  if (status == FTUN_OK) {
    owner->pending_generation = 0u;
    owner->reload_prepared = false;
  }
  return status;
}

static ftun_status_t ftun_tun_owner_run_once(
  void *implementation, bool may_block,
  ftun_core_service_run_usage_t *out_usage)
{
  ftun_tun_owner_t *owner = (ftun_tun_owner_t *)implementation;
  ftun_tun_service_usage_t service_usage;
  ftun_event_loop_usage_t event_usage;
  size_t callbacks = 0u;
  size_t work = 0u;
  bool block;
  ftun_status_t status;
  if (out_usage != NULL) memset(out_usage, 0, sizeof(*out_usage));
  if (owner == NULL || out_usage == NULL || !owner->active ||
      owner->quiesced) return FTUN_E_INVALID;
  status = ftun_tun_service_get_usage(owner->service, &service_usage);
  if (status != FTUN_OK) return status;
  block = may_block && !service_usage.ready;
  status = ftun_event_loop_run_once(
    owner->loop, block, FTUN_TUN_OWNER_EVENT_QUOTA, &callbacks);
  if (status == FTUN_OK) status = ftun_tun_service_run(owner->service, &work);
  if (status != FTUN_OK) return status;
  status = ftun_event_loop_get_usage(owner->loop, &event_usage);
  if (status != FTUN_OK) return status;
  out_usage->work = callbacks > SIZE_MAX - work ? SIZE_MAX : callbacks + work;
  out_usage->busy_ms = event_usage.last_dispatch_ms;
  out_usage->deadline_lateness_ms = event_usage.max_timer_lateness_ms;
  out_usage->quota_exhausted = callbacks == FTUN_TUN_OWNER_EVENT_QUOTA ||
    work >= FTUN_TUN_OWNER_IO_QUOTA;
  return FTUN_OK;
}

static ftun_status_t ftun_tun_owner_wakeup(void *implementation)
{
  ftun_tun_owner_t *owner = (ftun_tun_owner_t *)implementation;
  if (owner == NULL || owner->loop == NULL || owner->quiesced) {
    return FTUN_E_INVALID;
  }
  return ftun_event_loop_wakeup(owner->loop);
}

static ftun_status_t ftun_tun_owner_quiesce(void *implementation)
{
  ftun_tun_owner_t *owner = (ftun_tun_owner_t *)implementation;
  ftun_status_t status;
  if (owner == NULL) return FTUN_E_INVALID;
  if (owner->quiesced) return FTUN_OK;
  if (owner->reload_prepared) {
    status = ftun_tun_owner_reload_abort(owner);
    if (status != FTUN_OK) return status;
  }
  if (owner->service == NULL) {
    memset(owner->published, 0, sizeof(*owner->published));
    status = FTUN_OK;
  } else if (owner->published->service == owner->service) {
    status = ftun_l3_provider_quiesce(owner->published);
  } else {
    memset(owner->published, 0, sizeof(*owner->published));
    status = ftun_tun_service_quiesce(owner->service);
  }
  if (status == FTUN_OK) {
    owner->active = false;
    owner->quiesced = true;
  }
  return status;
}

static ftun_status_t ftun_tun_owner_drain_until(
  void *implementation, uint64_t deadline_ms)
{
  ftun_tun_owner_t *owner = (ftun_tun_owner_t *)implementation;
  ftun_status_t status;
  if (owner == NULL || deadline_ms == 0u) return FTUN_E_INVALID;
  status = ftun_tun_owner_quiesce(owner);
  if (status != FTUN_OK) return status;
  return ftun_linux_route_release(&owner->routes);
}

static ftun_status_t ftun_tun_owner_stop_until(
  void *implementation, uint64_t deadline_ms)
{
  return ftun_tun_owner_drain_until(implementation, deadline_ms);
}

static ftun_status_t ftun_tun_owner_destroy_until(
  void **implementation, uint64_t deadline_ms)
{
  ftun_tun_owner_t *owner;
  ftun_reservation_t *reservation;
  ftun_status_t status;
  if (implementation == NULL || deadline_ms == 0u) return FTUN_E_INVALID;
  owner = (ftun_tun_owner_t *)*implementation;
  if (owner == NULL) return FTUN_OK;
  status = ftun_tun_owner_drain_until(owner, deadline_ms);
  if (status != FTUN_OK) return status;
  status = ftun_tun_service_destroy(&owner->service);
  if (status != FTUN_OK) return status;
  status = ftun_buffer_pool_trim(owner->buffers, 0u);
  if (status == FTUN_OK) status = ftun_buffer_pool_destroy(&owner->buffers);
  if (status != FTUN_OK) return status;
  reservation = owner->reservation;
  owner->reservation = NULL;
  owner->published = NULL;
  owner->loop = NULL;
  free(owner);
  *implementation = NULL;
  return ftun_reservation_release(&reservation);
}

const ftun_core_service_descriptor_t ftun_tun_owner_service = {
  "tun-owner",
  ftun_tun_owner_plan_prepare,
  ftun_tun_owner_plan_destroy,
  ftun_tun_owner_prepare,
  ftun_tun_owner_activate,
  ftun_tun_owner_reload_prepare,
  ftun_tun_owner_reload_prepare_planned,
  ftun_tun_owner_reload_commit,
  ftun_tun_owner_reload_abort,
  ftun_tun_owner_run_once,
  ftun_tun_owner_wakeup,
  ftun_tun_owner_quiesce,
  ftun_tun_owner_drain_until,
  ftun_tun_owner_stop_until,
  ftun_tun_owner_destroy_until
};
