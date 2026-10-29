#include "libs/transport/config.h"
#include "libs/tun/config/model.h"
#include "libs/tun/owner.h"

#include "core/event/loop.h"
#include "util/ip.h"
#include "libs/buffer/buffer.h"
#include "platform/clock.h"

#include "platform/atomic.h"
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
  uint32_t route_table;
  uint32_t rule_priority;
  bool auto_route;
  bool strict_route;
} ftun_tun_owner_plan_t;

typedef struct {
  ftun_tun_owner_plan_t value;
  ftun_reservation_t reservation;
} ftun_tun_owner_prepared_plan_t;

typedef enum {
  FTUN_TUN_UPDATE_IDLE = 0,
  FTUN_TUN_UPDATE_WITHDRAW,
  FTUN_TUN_UPDATE_REOPEN,
  FTUN_TUN_UPDATE_INSTALL,
  FTUN_TUN_UPDATE_DISCARD,
  FTUN_TUN_UPDATE_RESTORE
} ftun_tun_update_phase_t;

typedef struct {
  ftun_core_t *core;
  ftun_budget_t *budget;
  ftun_reservation_t reservation;
  ftun_event_loop_t *loop;
  ftun_buffer_pool_t *buffers;
  ftun_tun_service_t *service;
  void *routes;
  void *async_routes;
  ftun_l3_provider_t *published;
  ftun_tun_device_ops_t device_ops;
  ftun_interface_ops_t network;
  ftun_tun_owner_plan_t plan;
  ftun_tun_owner_plan_t network_plan;
  ftun_tun_owner_plan_t candidate_network;
  ftun_tun_network_update_result_t network_result;
  ftun_tun_update_phase_t network_phase;
  uint64_t network_deadline_ms;
  ftun_event_source_t *network_timer;
  bool network_timer_ready;
  bool has_network_result;
  uint64_t generation;
  uint64_t pending_generation;
  bool has_device_ops;
  bool active;
  bool quiesced;
  bool reload_prepared;
  bool network_updating;
  bool rebuilding_device;
  bool async_cleanup;
  bool async_release_started;
  /* 网络对账与设备重建的重试。network_changed 只置位 repair_requested 并唤醒
   * 循环，其余状态只由 owner-loop 访问。*/
  ftun_atomic_bool_t repair_requested;
  bool repairing;
  uint32_t repair_streak;
  uint32_t device_streak;
  uint64_t repair_due_ms;
  uint64_t device_due_ms;
  ftun_event_source_t *retry_timer;
} ftun_tun_owner_t;

#define FTUN_TUN_OWNER_REPAIR_DEADLINE_MS 5000u
#define FTUN_TUN_OWNER_RETRY_MIN_MS 1000u
#define FTUN_TUN_OWNER_RETRY_MAX_MS 30000u

static bool ftun_tun_owner_async_supported(const ftun_tun_owner_t *owner);
static ftun_status_t ftun_tun_owner_change(void *context, bool rebuild,
  uint64_t device_generation, uint64_t network_generation);

static ftun_status_t ftun_tun_owner_parse_cidr(
  const char *text, uint8_t address[4], uint8_t *prefix)
{
  ftun_cidr_t cidr;
  if (text == NULL || address == NULL || prefix == NULL ||
      !ftun_cidr_parse(text, strlen(text), false, &cidr) ||
      cidr.address.family != FTUN_IP_V4) return FTUN_E_INVALID;
  memcpy(address, cidr.address.bytes, 4u);
  *prefix = cidr.prefix;
  return FTUN_OK;
}

static ftun_status_t ftun_tun_owner_plan_build(
  const ftun_config_t *config, uint32_t protection_mark,
  ftun_tun_owner_plan_t *out)
{
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (config == NULL || out == NULL) return FTUN_E_INVALID;
  if (!ftun_config_tun(config)->present || ftun_config_tun(config)->interface_name == NULL ||
      ftun_config_tun(config)->ipv4_address == NULL || ftun_config_tun(config)->mtu == 0u ||
      strlen(ftun_config_tun(config)->interface_name) == 0u ||
      strlen(ftun_config_tun(config)->interface_name) >= sizeof(out->name)) {
    return FTUN_E_INVALID;
  }
  memcpy(out->name, ftun_config_tun(config)->interface_name,
         strlen(ftun_config_tun(config)->interface_name) + 1u);
  out->mtu = ftun_config_tun(config)->mtu;
  out->auto_route = ftun_config_tun(config)->auto_route;
  out->strict_route = ftun_config_tun(config)->strict_route;
  out->protection_mark = ftun_config_tun(config)->auto_route ? protection_mark : 0u;
  out->route_table = ftun_config_tun(config)->route_table;
  out->rule_priority = ftun_config_tun(config)->rule_priority;
  status = ftun_tun_owner_parse_cidr(
    ftun_config_tun(config)->ipv4_address, out->address, &out->prefix_length);
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
    left->route_table == right->route_table &&
    left->rule_priority == right->rule_priority &&
    left->auto_route == right->auto_route &&
    left->strict_route == right->strict_route;
}

static ftun_status_t ftun_tun_owner_plan_prepare(ftun_budget_t *budget,
  const ftun_config_t *config, uint32_t socket_mark, void **out)
{
  ftun_tun_owner_prepared_plan_t *plan;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (budget == NULL || config == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_budget_reserve(budget, sizeof(*plan), &reservation);
  if (status != FTUN_OK) return status;
  plan = (ftun_tun_owner_prepared_plan_t *)calloc(1u, sizeof(*plan));
  if (plan == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  plan->reservation = reservation;
  status = ftun_tun_owner_plan_build(config, socket_mark, &plan->value);
  if (status != FTUN_OK) {
    free(plan);
    ftun_reservation_release(&reservation);
    return status;
  }
  *out = plan;
  return FTUN_OK;
}

static ftun_status_t ftun_tun_owner_plan_destroy(void **plan)
{
  ftun_tun_owner_prepared_plan_t *owned;
  if (plan == NULL) return FTUN_E_INVALID;
  owned = *plan;
  if (owned == NULL) return FTUN_OK;
  ftun_reservation_release(&owned->reservation);
  free(owned);
  *plan = NULL;
  return FTUN_OK;
}

static ftun_status_t ftun_tun_owner_network_withdraw(void *context)
{
  ftun_tun_owner_t *owner = context;
  if (owner->async_cleanup || owner->async_routes != NULL || (owner->network_updating && owner->network_phase != FTUN_TUN_UPDATE_IDLE)) {
    return owner->routes == NULL && owner->async_routes == NULL ? FTUN_OK : FTUN_E_AGAIN;
  }
  if (owner->routes == NULL) return FTUN_OK;
  return owner->network.withdraw(owner->network.context, &owner->routes);
}

static ftun_status_t ftun_tun_owner_network_restore(void *context)
{
  ftun_tun_owner_t *owner = context;
  ftun_interface_spec_t spec = {0};
  if (!owner->network_plan.auto_route) return FTUN_OK;
  if (owner->routes != NULL || owner->async_routes != NULL || (owner->network_updating && owner->network_phase != FTUN_TUN_UPDATE_IDLE)) {
    return FTUN_E_AGAIN;
  }
  spec.budget = owner->budget;
  spec.name = (ftun_string_t){owner->network_plan.name, strlen(owner->network_plan.name)};
  memcpy(spec.ipv4_address, owner->network_plan.address, sizeof(spec.ipv4_address));
  spec.prefix_length = owner->network_plan.prefix_length;
  spec.protection_mark = owner->network_plan.protection_mark;
  spec.route_table = owner->network_plan.route_table;
  spec.rule_priority = owner->network_plan.rule_priority;
  spec.strict_route = owner->network_plan.strict_route;
  return owner->network.restore(owner->network.context, &spec, &owner->routes);
}

static ftun_status_t ftun_tun_owner_prepare(
  ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations,
  const ftun_core_service_binding_t *binding,
  const ftun_config_t *config, uint64_t generation, void **out)
{
  const ftun_tun_owner_binding_t *host;
  ftun_tun_owner_t *owner = NULL;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
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
  /* 系统端口自行计量；外部设备回调仍由宿主预留一个物理FD。 */
  resources.descriptors = host->device_ops == NULL ? 0u : 1u;
  status = ftun_budget_reserve_resources(budget, resources, &reservation);
  if (status != FTUN_OK) return status;
  owner = (ftun_tun_owner_t *)calloc(1u, sizeof(*owner));
  if (owner == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  owner->reservation = reservation;
  owner->core = core;
  owner->budget = budget;
  owner->loop = host->loop;
  owner->published = host->provider;
  owner->generation = generation;
  if (host->device_ops != NULL) {
    owner->device_ops = *host->device_ops;
    owner->has_device_ops = true;
  }
  if (host->network != NULL) {
    owner->network = *host->network;
  }
  status = ftun_tun_owner_plan_build(
    config, host->protection_mark, &owner->plan);
  if (status != FTUN_OK) goto fail;
  owner->network_plan = owner->plan;
  if (owner->plan.auto_route && (owner->network.restore == NULL ||
      owner->network.withdraw == NULL)) { status = FTUN_E_INVALID; goto fail; }
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
    (void)ftun_tun_owner_network_withdraw(owner);
    (void)ftun_tun_service_quiesce(owner->service);
    (void)ftun_tun_service_destroy(&owner->service);
    (void)ftun_buffer_pool_destroy(&owner->buffers);
    ftun_reservation_release(&owner->reservation);
    free(owner);
  }
  return status;
}

static ftun_status_t ftun_tun_owner_activate(void *implementation)
{
  ftun_tun_owner_t *owner = (ftun_tun_owner_t *)implementation;
  ftun_tun_service_spec_t service_spec;
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
  service_spec.network = (ftun_tun_network_lifecycle_t){
    ftun_tun_owner_network_restore, ftun_tun_owner_network_withdraw, owner,
    owner->plan.auto_route && ftun_tun_owner_async_supported(owner) ? ftun_tun_owner_change : NULL};
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
  if (status == FTUN_OK) {
    status = ftun_l3_provider_bind(
      owner->service, owner->generation, owner->published);
  }
  if (status != FTUN_OK) {
    cleanup = ftun_tun_owner_network_withdraw(owner);
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

static ftun_status_t ftun_tun_owner_update_rejected(
  ftun_tun_network_update_result_t *out, ftun_status_t status)
{
  if (out != NULL) out->update_status = status;
  return status;
}

static bool ftun_tun_owner_async_supported(const ftun_tun_owner_t *owner)
{
  const ftun_interface_async_ops_t *ops = &owner->network.async;
  return ops->start != NULL && ops->adopt != NULL && ops->withdraw != NULL &&
    ops->run != NULL && ops->query != NULL && ops->destroy != NULL;
}

static void ftun_tun_owner_update_result(ftun_tun_owner_t *owner)
{
  ftun_tun_service_usage_t usage;
  if (ftun_tun_service_get_usage(owner->service, &usage) == FTUN_OK) {
    owner->network_result.ready = usage.accepting;
    owner->network_result.network_generation = usage.network_generation;
    owner->network_result.device_generation = usage.device_generation;
  }
  owner->network_result.pending = owner->network_updating;
}

static uint64_t ftun_tun_owner_backoff(uint32_t streak)
{
  uint64_t delay = FTUN_TUN_OWNER_RETRY_MIN_MS;
  while (streak > 1u && delay < FTUN_TUN_OWNER_RETRY_MAX_MS) {
    delay *= 2u;
    streak--;
  }
  return delay > FTUN_TUN_OWNER_RETRY_MAX_MS ? FTUN_TUN_OWNER_RETRY_MAX_MS : delay;
}

static void ftun_tun_owner_retry_timer(ftun_event_source_t *source,
  uint32_t events, void *user)
{
  (void)source;
  (void)events;
  (void)user;
}

/* 以最早的重试时刻重新登记唤醒；到期判断仍由 run_once 按单调时钟比较。 */
static void ftun_tun_owner_arm_retry(ftun_tun_owner_t *owner)
{
  uint64_t due = owner->repair_due_ms;
  if (owner->device_due_ms != 0u && (due == 0u || owner->device_due_ms < due)) {
    due = owner->device_due_ms;
  }
  (void)ftun_event_source_cancel(&owner->retry_timer);
  if (due == 0u || owner->loop == NULL) return;
  (void)ftun_event_timer_start(owner->loop, due, ftun_tun_owner_retry_timer,
    owner, &owner->retry_timer);
}

static void ftun_tun_owner_schedule_device(ftun_tun_owner_t *owner, uint64_t now_ms)
{
  if (owner->device_streak != UINT32_MAX) owner->device_streak++;
  owner->device_due_ms = now_ms + ftun_tun_owner_backoff(owner->device_streak);
  ftun_tun_owner_arm_retry(owner);
}

static void ftun_tun_owner_schedule_repair(ftun_tun_owner_t *owner, uint64_t now_ms)
{
  if (owner->repair_streak != UINT32_MAX) owner->repair_streak++;
  owner->repair_due_ms = now_ms + ftun_tun_owner_backoff(owner->repair_streak);
  ftun_tun_owner_arm_retry(owner);
}

static void ftun_tun_owner_update_done(ftun_tun_owner_t *owner,
  ftun_status_t status)
{
  ftun_status_t cancelled = ftun_event_source_cancel(&owner->network_timer);
  if (cancelled != FTUN_OK) owner->network_result.rollback_status = cancelled;
  owner->network_timer_ready = false;
  if (status != FTUN_OK) {
    (void)ftun_tun_service_network_finish(owner->service, status);
  }
  if (owner->rebuilding_device) {
    uint64_t now_ms = 0u;
    ftun_tun_service_usage_t usage;
    if (status == FTUN_OK) {
      owner->device_streak = 0u;
      owner->device_due_ms = 0u;
    } else if (ftun_tun_service_get_usage(owner->service, &usage) == FTUN_OK &&
               usage.device_lost && ftun_monotonic_now(&now_ms) == FTUN_OK) {
      /* 只有设备确实丢失才退避重试；重建由调用方显式发起并失败时不自动重试。 */
      ftun_tun_owner_schedule_device(owner, now_ms);
    }
  }
  owner->network_updating = false;
  owner->rebuilding_device = false;
  owner->async_release_started = false;
  owner->network_phase = FTUN_TUN_UPDATE_IDLE;
  ftun_tun_owner_update_result(owner);
}

ftun_status_t ftun_tun_owner_query_network_update(
  void *implementation, ftun_tun_network_update_result_t *out)
{
  ftun_tun_owner_t *owner = implementation;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (owner == NULL || out == NULL) return FTUN_E_INVALID;
  if (!owner->has_network_result) return FTUN_E_AGAIN;
  ftun_tun_owner_update_result(owner);
  *out = owner->network_result;
  return FTUN_OK;
}

static void ftun_tun_owner_deadline(ftun_event_source_t *source, uint32_t events, void *user)
{
  ftun_tun_owner_t *owner = user;
  if (owner->network_timer == source && (events & FTUN_EVENT_TIMER) != 0u) {
    owner->network_timer_ready = true;
  }
}

static ftun_status_t ftun_tun_owner_begin_change(ftun_tun_owner_t *owner,
  const ftun_tun_owner_plan_t *candidate, uint64_t expected_device_generation,
  uint64_t expected_network_generation, uint64_t deadline_ms, bool rebuild)
{
  ftun_status_t status;
  if (owner->network_timer != NULL || owner->repairing) return FTUN_E_AGAIN;
  status = ftun_event_timer_start(owner->loop, deadline_ms,
    ftun_tun_owner_deadline, owner, &owner->network_timer);
  if (status != FTUN_OK) return status;
  owner->network_timer_ready = false;
  owner->network_updating = true;
  owner->rebuilding_device = rebuild;
  status = rebuild
    ? ftun_tun_service_rebuild_pause(owner->service, expected_device_generation, expected_network_generation)
    : ftun_tun_service_network_pause(owner->service, expected_network_generation);
  if (status != FTUN_OK) {
    owner->network_updating = false;
    owner->rebuilding_device = false;
    (void)ftun_event_source_cancel(&owner->network_timer);
    return status;
  }
  owner->candidate_network = *candidate;
  owner->network_deadline_ms = deadline_ms;
  owner->network_phase = FTUN_TUN_UPDATE_WITHDRAW;
  owner->network_result = (ftun_tun_network_update_result_t){0};
  owner->network_result.update_status = FTUN_E_AGAIN;
  owner->network_result.rebuild = rebuild;
  owner->has_network_result = true;
  owner->async_release_started = false;
  ftun_tun_owner_update_result(owner);
  /* 可变状态只由 owner-loop 访问；这里唤醒共享循环以推进首轮接管。 */
  (void)ftun_event_loop_wakeup(owner->loop);
  return FTUN_OK;
}

ftun_status_t ftun_tun_owner_start_network_update(
  void *implementation, uint64_t expected_network_generation,
  const ftun_interface_spec_t *network, uint64_t deadline_ms)
{
  ftun_tun_owner_t *owner = implementation;
  ftun_tun_owner_plan_t candidate;
  ftun_tun_service_usage_t usage;
  uint64_t now_ms;
  ftun_status_t status;
  if (owner == NULL || network == NULL || deadline_ms == 0u) return FTUN_E_INVALID;
  if (owner->network_updating || owner->reload_prepared) return FTUN_E_AGAIN;
  if (!owner->active || owner->quiesced || owner->service == NULL) return FTUN_E_CANCELLED;
  if (!owner->plan.auto_route || !ftun_tun_owner_async_supported(owner)) return FTUN_E_UNSUPPORTED;
  if (network->name.data == NULL || network->name.length != strlen(owner->plan.name) ||
      memcmp(network->name.data, owner->plan.name, network->name.length) != 0 ||
      network->protection_mark != owner->plan.protection_mark ||
      network->prefix_length == 0u || network->prefix_length > 32u) return FTUN_E_INVALID;
  status = ftun_monotonic_now(&now_ms);
  if (status != FTUN_OK) return status;
  if (deadline_ms <= now_ms) return FTUN_E_TIMEOUT;
  status = ftun_tun_service_get_usage(owner->service, &usage);
  if (status != FTUN_OK) return status;
  if (usage.network_generation != expected_network_generation) return FTUN_E_STALE;
  /* 失败后显式重试可重新撤销残留并安装；不允许把未恢复的同计划当成功。 */
  candidate = owner->network_plan;
  memcpy(candidate.address, network->ipv4_address, sizeof(candidate.address));
  candidate.prefix_length = network->prefix_length;
  candidate.strict_route = network->strict_route;
  if (usage.accepting && ftun_tun_owner_plan_equal(&candidate, &owner->network_plan)) {
    owner->network_result = (ftun_tun_network_update_result_t){0};
    owner->network_result.committed = true;
    owner->has_network_result = true;
    ftun_tun_owner_update_result(owner);
    return FTUN_OK;
  }
  return ftun_tun_owner_begin_change(owner, &candidate, usage.device_generation,
    expected_network_generation, deadline_ms, false);
}

static ftun_status_t ftun_tun_owner_start_current_change(
  ftun_tun_owner_t *owner, uint64_t device_generation,
  uint64_t network_generation, uint64_t deadline_ms, bool rebuild)
{
  ftun_tun_service_usage_t usage;
  ftun_status_t status;
  uint64_t now_ms;
  if (owner == NULL || deadline_ms == 0u) return FTUN_E_INVALID;
  if (owner->network_updating || owner->reload_prepared) return FTUN_E_AGAIN;
  if (!owner->active || owner->quiesced || owner->service == NULL) return FTUN_E_CANCELLED;
  if (!owner->plan.auto_route || !ftun_tun_owner_async_supported(owner)) return FTUN_E_UNSUPPORTED;
  status = ftun_monotonic_now(&now_ms);
  if (status != FTUN_OK) return status;
  if (deadline_ms <= now_ms) return FTUN_E_TIMEOUT;
  status = ftun_tun_service_get_usage(owner->service, &usage);
  if (status != FTUN_OK) return status;
  if (usage.device_generation != device_generation ||
      usage.network_generation != network_generation) return FTUN_E_STALE;
  return ftun_tun_owner_begin_change(owner, &owner->network_plan,
    device_generation, network_generation, deadline_ms, rebuild);
}

ftun_status_t ftun_tun_owner_start_rebuild(
  void *implementation, uint64_t expected_device_generation,
  uint64_t expected_network_generation, uint64_t deadline_ms)
{
  return ftun_tun_owner_start_current_change(implementation,
    expected_device_generation, expected_network_generation, deadline_ms, true);
}

static ftun_status_t ftun_tun_owner_change(void *context, bool rebuild,
  uint64_t device_generation, uint64_t network_generation)
{
  uint64_t now_ms;
  ftun_status_t status = ftun_monotonic_now(&now_ms);
  if (status != FTUN_OK) return status;
  status = ftun_tun_owner_start_current_change(context, device_generation,
    network_generation, now_ms > UINT64_MAX - 5000u ? UINT64_MAX : now_ms + 5000u, rebuild);
  return status == FTUN_OK ? FTUN_E_AGAIN : status;
}

static void ftun_tun_owner_update_failed(ftun_tun_owner_t *owner,
  ftun_status_t status, ftun_status_t cleanup)
{
  if (owner->rebuilding_device) {
    if (owner->network_result.update_status == FTUN_E_AGAIN) owner->network_result.update_status = status;
    owner->network_result.rollback_status = cleanup;
    if (cleanup != FTUN_OK || owner->async_routes == NULL) {
      ftun_tun_owner_update_done(owner, status);
    } else {
      owner->network_phase = FTUN_TUN_UPDATE_DISCARD;
      owner->async_release_started = false;
    }
    return;
  }
  if (owner->network_phase == FTUN_TUN_UPDATE_RESTORE) {
    owner->network_result.rollback_status = status;
    ftun_tun_owner_update_done(owner, status);
    return;
  }
  if (owner->network_result.update_status == FTUN_E_AGAIN) {
    owner->network_result.update_status = status;
  }
  if (cleanup != FTUN_OK) {
    owner->network_result.rollback_status = cleanup;
    ftun_tun_owner_update_done(owner, cleanup);
    return;
  }
  owner->network_phase = owner->async_routes == NULL && owner->routes == NULL
    ? FTUN_TUN_UPDATE_RESTORE : FTUN_TUN_UPDATE_DISCARD;
  owner->async_release_started = false;
}

static void ftun_tun_owner_withdrawn(ftun_tun_owner_t *owner)
{
  if (owner->network_phase == FTUN_TUN_UPDATE_WITHDRAW) {
    owner->network_phase = owner->rebuilding_device
      ? FTUN_TUN_UPDATE_REOPEN : FTUN_TUN_UPDATE_INSTALL;
  } else if (owner->rebuilding_device) {
    ftun_tun_owner_update_done(owner, owner->network_result.update_status);
  } else {
    owner->network_phase = FTUN_TUN_UPDATE_RESTORE;
  }
}

/* 一轮只驱动一个路由事务，阶段转换不在本轮递归执行下一份计划。 */
static ftun_status_t ftun_tun_owner_update_run(
  ftun_tun_owner_t *owner, uint64_t now_ms, size_t *out_work)
{
  ftun_interface_async_ops_t *ops = &owner->network.async;
  ftun_interface_async_options_t options = {owner->budget, owner->loop,
    now_ms, 250u, owner->network_deadline_ms};
  ftun_interface_async_info_t info;
  ftun_status_t status;
  bool removing;
  *out_work = 0u;
  if (!owner->network_updating) return FTUN_OK;
  removing = owner->network_phase == FTUN_TUN_UPDATE_WITHDRAW ||
    owner->network_phase == FTUN_TUN_UPDATE_DISCARD;
  if (now_ms >= owner->network_deadline_ms) {
    /* 不为回滚续期。已有请求仍保留所有权，由显式重试或停止接管。 */
    if (owner->async_routes != NULL) {
      status = ops->run(ops->context, owner->async_routes, now_ms,
        FTUN_TUN_OWNER_IO_QUOTA, out_work);
      if (status != FTUN_OK) return status;
    }
    if (owner->network_result.update_status == FTUN_E_AGAIN) {
      owner->network_result.update_status = FTUN_E_TIMEOUT;
    }
    owner->network_result.rollback_status = FTUN_E_TIMEOUT;
    ftun_tun_owner_update_done(owner, FTUN_E_TIMEOUT);
    return FTUN_OK;
  }
  if (owner->network_phase == FTUN_TUN_UPDATE_REOPEN) {
    status = ftun_tun_service_reopen_paused(owner->service);
    *out_work = 1u;
    if (status == FTUN_OK) owner->network_phase = FTUN_TUN_UPDATE_INSTALL;
    else ftun_tun_owner_update_failed(owner, status, status);
    ftun_tun_owner_update_result(owner);
    return FTUN_OK;
  }
  if (removing && owner->routes != NULL) {
    status = ftun_buffer_pool_trim(owner->buffers, 0u);
    if (status == FTUN_OK) status = ops->adopt(ops->context, &owner->routes,
      &options, &owner->async_routes);
    if (status != FTUN_OK) {
      ftun_tun_owner_update_failed(owner, status, status);
      return FTUN_OK;
    }
  }
  if (!removing && owner->async_routes == NULL) {
    const ftun_tun_owner_plan_t *plan = owner->network_phase == FTUN_TUN_UPDATE_RESTORE
      ? &owner->network_plan : &owner->candidate_network;
    ftun_interface_spec_t spec = {0};
    spec.name = (ftun_string_t){plan->name, strlen(plan->name)};
    memcpy(spec.ipv4_address, plan->address, sizeof(spec.ipv4_address));
    spec.prefix_length = plan->prefix_length;
    spec.protection_mark = plan->protection_mark;
    spec.route_table = plan->route_table;
    spec.rule_priority = plan->rule_priority;
    spec.strict_route = plan->strict_route;
    status = ops->start(ops->context, &spec, &options, &owner->async_routes);
    if (status != FTUN_OK) {
      ftun_tun_owner_update_failed(owner, status, FTUN_OK);
      return FTUN_OK;
    }
  }
  if (removing && owner->async_routes == NULL) {
    ftun_tun_owner_withdrawn(owner);
    *out_work = 1u;
    return FTUN_OK;
  }
  if (removing && !owner->async_release_started) {
    status = ops->withdraw(ops->context, owner->async_routes, now_ms, owner->network_deadline_ms);
    if (status != FTUN_OK && status != FTUN_E_AGAIN) {
      ftun_tun_owner_update_failed(owner, status, status);
      return FTUN_OK;
    }
    owner->async_release_started = true;
  }
  status = ops->run(ops->context, owner->async_routes, now_ms, FTUN_TUN_OWNER_IO_QUOTA, out_work);
  if (status == FTUN_OK) status = ops->query(ops->context, owner->async_routes, &info);
  if (status != FTUN_OK) {
    ftun_tun_owner_update_failed(owner, status, status);
    return FTUN_OK;
  }
  if (info.state == FTUN_INTERFACE_RETAINED) {
    ftun_status_t cleanup = info.cleanup_result == FTUN_OK ? FTUN_E_STATE_CORRUPT : info.cleanup_result;
    ftun_tun_owner_update_failed(owner, info.result == FTUN_OK ? cleanup : info.result, cleanup);
  } else if (info.state == FTUN_INTERFACE_RELEASED ||
      (info.state == FTUN_INTERFACE_FAILED && info.active_count == 0u)) {
    status = ops->destroy(ops->context, &owner->async_routes);
    owner->async_release_started = false;
    if (status != FTUN_OK) {
      ftun_tun_owner_update_failed(owner, status, status);
    } else if (removing) {
      ftun_tun_owner_withdrawn(owner);
    } else {
      ftun_tun_owner_update_failed(owner,
        info.result == FTUN_OK ? FTUN_E_STATE_CORRUPT : info.result, FTUN_OK);
    }
  } else if (!removing && info.state == FTUN_INTERFACE_READY) {
    bool restoring = owner->network_phase == FTUN_TUN_UPDATE_RESTORE;
    uint64_t publish_ms;
    status = ftun_monotonic_now(&publish_ms);
    if (status != FTUN_OK || publish_ms >= owner->network_deadline_ms) {
      if (status == FTUN_OK) status = FTUN_E_TIMEOUT;
      ftun_tun_owner_update_failed(owner, status, status);
      return FTUN_OK;
    }
    status = ftun_tun_service_network_finish(owner->service, FTUN_OK);
    if (status == FTUN_OK) {
      if (!restoring) {
        owner->network_plan = owner->candidate_network;
        owner->network_result.update_status = FTUN_OK;
        owner->network_result.committed = true;
      }
      ftun_tun_owner_update_done(owner, FTUN_OK);
    } else {
      ftun_tun_service_usage_t usage;
      (void)ftun_tun_service_get_usage(owner->service, &usage);
      (void)ftun_tun_service_network_pause(owner->service, usage.network_generation);
      ftun_tun_owner_update_failed(owner, status, restoring ? status : FTUN_OK);
    }
  }
  ftun_tun_owner_update_result(owner);
  return FTUN_OK;
}

/* 网络变化后核对自有地址、规则和路由，只补回缺失项；失败退避重试，不撤销现状。 */
static ftun_status_t ftun_tun_owner_repair_run(
  ftun_tun_owner_t *owner, uint64_t now_ms, size_t *out_work)
{
  ftun_interface_async_ops_t *ops = &owner->network.async;
  ftun_interface_async_info_t info;
  ftun_status_t status;
  size_t work = 0u;
  *out_work = 0u;
  if (!owner->active || owner->quiesced || owner->network_updating ||
      ops->repair == NULL || !owner->network_plan.auto_route) return FTUN_OK;
  if (!owner->repairing) {
    bool due = owner->repair_due_ms != 0u && now_ms >= owner->repair_due_ms;
    ftun_interface_async_options_t options = {owner->budget, owner->loop,
      now_ms, 250u, now_ms + FTUN_TUN_OWNER_REPAIR_DEADLINE_MS};
    if (!ftun_atomic_exchange(&owner->repair_requested, false) && !due) return FTUN_OK;
    if (due) owner->repair_due_ms = 0u;
    if (owner->routes != NULL) {
      status = ftun_buffer_pool_trim(owner->buffers, 0u);
      if (status == FTUN_OK) status = ops->adopt(ops->context, &owner->routes,
        &options, &owner->async_routes);
      if (status != FTUN_OK) {
        ftun_tun_owner_schedule_repair(owner, now_ms);
        return FTUN_OK;
      }
    }
    if (owner->async_routes == NULL) return FTUN_OK;
    status = ops->query(ops->context, owner->async_routes, &info);
    if (status != FTUN_OK || info.state != FTUN_INTERFACE_READY) return FTUN_OK;
    status = ops->repair(ops->context, owner->async_routes, now_ms,
      options.deadline_ms);
    if (status != FTUN_OK) {
      ftun_tun_owner_schedule_repair(owner, now_ms);
      return FTUN_OK;
    }
    owner->repairing = true;
    *out_work = 1u;
  }
  status = ops->run(ops->context, owner->async_routes, now_ms,
    FTUN_TUN_OWNER_IO_QUOTA, &work);
  *out_work += work;
  if (status != FTUN_OK) return status;
  status = ops->query(ops->context, owner->async_routes, &info);
  if (status != FTUN_OK) return status;
  if (info.repairing && info.state == FTUN_INTERFACE_INSTALLING) return FTUN_OK;
  owner->repairing = false;
  if (info.state != FTUN_INTERFACE_READY) return FTUN_OK;
  if (info.repair_result == FTUN_OK) {
    owner->repair_streak = 0u;
  } else {
    ftun_tun_owner_schedule_repair(owner, now_ms);
  }
  return FTUN_OK;
}

/* 设备丢失（被外部删除）后的重建重试：已在重建则等待其结果，否则按退避重新发起。 */
static void ftun_tun_owner_device_run(ftun_tun_owner_t *owner, uint64_t now_ms)
{
  ftun_tun_service_usage_t usage;
  if (!owner->active || owner->quiesced || owner->network_updating) return;
  if (ftun_tun_service_get_usage(owner->service, &usage) != FTUN_OK) return;
  if (!usage.device_lost) {
    owner->device_streak = 0u;
    owner->device_due_ms = 0u;
    return;
  }
  if (owner->device_due_ms > now_ms) return;
  owner->device_due_ms = 0u;
  (void)ftun_tun_service_rebuild(owner->service);
  if (owner->network_updating) return;
  if (ftun_tun_service_get_usage(owner->service, &usage) == FTUN_OK &&
      !usage.device_lost) {
    owner->device_streak = 0u;
    return;
  }
  ftun_tun_owner_schedule_device(owner, now_ms);
}

static void ftun_tun_owner_network_changed(void *implementation,
  const ftun_network_change_t *change, uint64_t now_ms)
{
  ftun_tun_owner_t *owner = (ftun_tun_owner_t *)implementation;
  (void)change;
  (void)now_ms;
  if (owner == NULL) return;
  ftun_atomic_store(&owner->repair_requested, true);
  if (owner->loop != NULL) (void)ftun_event_loop_wakeup(owner->loop);
}

static bool ftun_tun_owner_repair_runnable(ftun_tun_owner_t *owner)
{
  ftun_interface_async_info_t info;
  if (ftun_atomic_load(&owner->repair_requested)) return true;
  if (!owner->repairing) return false;
  if (owner->async_routes == NULL ||
      owner->network.async.query(owner->network.async.context, owner->async_routes, &info) != FTUN_OK) {
    return true;
  }
  return info.runnable || !info.repairing;
}

static bool ftun_tun_owner_update_runnable(ftun_tun_owner_t *owner)
{
  ftun_interface_async_info_t info;
  if (!owner->network_updating) return false;
  if (owner->network_timer_ready) return true;
  if (owner->async_routes == NULL ||
      ((owner->network_phase == FTUN_TUN_UPDATE_WITHDRAW ||
        owner->network_phase == FTUN_TUN_UPDATE_DISCARD) && !owner->async_release_started)) return true;
  if (owner->network.async.query(owner->network.async.context, owner->async_routes, &info) != FTUN_OK) return true;
  return info.runnable || info.state == FTUN_INTERFACE_READY ||
    info.state == FTUN_INTERFACE_FAILED || info.state == FTUN_INTERFACE_RETAINED ||
    info.state == FTUN_INTERFACE_RELEASED;
}

ftun_status_t ftun_tun_owner_update_network(
  void *implementation, uint64_t expected_network_generation,
  const ftun_interface_spec_t *network, ftun_tun_network_update_result_t *out)
{
  ftun_tun_owner_t *owner = implementation;
  ftun_tun_owner_plan_t previous;
  ftun_tun_owner_plan_t candidate;
  ftun_tun_service_usage_t usage;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (owner != NULL && network != NULL && out != NULL && ftun_tun_owner_async_supported(owner)) {
    uint64_t now_ms;
    status = ftun_monotonic_now(&now_ms);
    if (status == FTUN_OK) status = ftun_tun_owner_start_network_update(owner,
      expected_network_generation, network, now_ms > UINT64_MAX - 5000u ? UINT64_MAX : now_ms + 5000u);
    if (status != FTUN_OK) return ftun_tun_owner_update_rejected(out, status);
    (void)ftun_tun_owner_query_network_update(owner, out);
    return out->pending ? FTUN_E_AGAIN : out->update_status;
  }
  if (owner == NULL || network == NULL || out == NULL) {
    return ftun_tun_owner_update_rejected(out, FTUN_E_INVALID);
  }
  if (owner->network_updating || owner->reload_prepared) {
    return ftun_tun_owner_update_rejected(out, FTUN_E_AGAIN);
  }
  if (!owner->active || owner->quiesced || owner->service == NULL) {
    return ftun_tun_owner_update_rejected(out, FTUN_E_CANCELLED);
  }
  if (!owner->plan.auto_route) return ftun_tun_owner_update_rejected(out, FTUN_E_UNSUPPORTED);
  if (network->name.data == NULL || network->name.length != strlen(owner->plan.name) ||
      memcmp(network->name.data, owner->plan.name, network->name.length) != 0 ||
      network->protection_mark != owner->plan.protection_mark ||
      network->prefix_length == 0u || network->prefix_length > 32u) {
    return ftun_tun_owner_update_rejected(out, FTUN_E_INVALID);
  }
  status = ftun_tun_service_get_usage(owner->service, &usage);
  if (status != FTUN_OK) return ftun_tun_owner_update_rejected(out, status);
  out->network_generation = usage.network_generation;
  out->ready = usage.accepting;
  if (usage.network_generation != expected_network_generation) {
    return ftun_tun_owner_update_rejected(out, FTUN_E_STALE);
  }
  if (!usage.accepting) return ftun_tun_owner_update_rejected(out, FTUN_E_CANCELLED);
  previous = candidate = owner->network_plan;
  memcpy(candidate.address, network->ipv4_address, sizeof(candidate.address));
  candidate.prefix_length = network->prefix_length;
  candidate.strict_route = network->strict_route;
  if (ftun_tun_owner_plan_equal(&candidate, &previous)) {
    out->committed = true;
    return FTUN_OK;
  }
  owner->network_updating = true;
  owner->network_plan = candidate;
  status = ftun_tun_service_refresh_network(owner->service, expected_network_generation);
  out->update_status = status;
  out->committed = status == FTUN_OK;
  if (status != FTUN_OK) {
    owner->network_plan = previous;
    (void)ftun_tun_service_get_usage(owner->service, &usage);
    if (!usage.accepting) {
      out->rollback_status = ftun_tun_service_refresh_network(
        owner->service, usage.network_generation);
    }
  }
  (void)ftun_tun_service_get_usage(owner->service, &usage);
  out->ready = usage.accepting;
  out->network_generation = usage.network_generation;
  owner->network_updating = false;
  return out->rollback_status == FTUN_OK ? status : FTUN_E_STATE_CORRUPT;
}

static ftun_status_t ftun_tun_owner_reload_prepare_value(
  ftun_tun_owner_t *owner, const ftun_tun_owner_plan_t *plan,
  uint64_t generation)
{
  ftun_status_t status;
  if (owner != NULL && owner->network_updating) return FTUN_E_AGAIN;
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
    plan == NULL ? NULL : &((const ftun_tun_owner_prepared_plan_t *)plan)->value,
    generation);
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
  size_t network_work = 0u;
  uint64_t now_ms;
  uint64_t started_ms, before_event_ms, after_event_ms, finished_ms;
  bool block;
  ftun_status_t status;
  if (out_usage != NULL) memset(out_usage, 0, sizeof(*out_usage));
  if (owner == NULL || out_usage == NULL || !owner->active ||
      owner->quiesced) return FTUN_E_INVALID;
  status = ftun_monotonic_now(&started_ms);
  if (status != FTUN_OK) return status;
  status = ftun_tun_service_get_usage(owner->service, &service_usage);
  if (status != FTUN_OK) return status;
  block = may_block && !service_usage.ready && !ftun_tun_owner_update_runnable(owner) &&
    !ftun_tun_owner_repair_runnable(owner);
  status = ftun_monotonic_now(&before_event_ms);
  if (status != FTUN_OK) return status;
  status = ftun_event_loop_run_once(
    owner->loop, block, FTUN_TUN_OWNER_EVENT_QUOTA, &callbacks);
  if (status == FTUN_E_UNSUPPORTED) {
    status = ftun_monotonic_now(&now_ms);
    if (status == FTUN_OK) status = ftun_event_loop_poll(owner->loop, now_ms,
      FTUN_TUN_OWNER_EVENT_QUOTA, &callbacks);
  }
  if (status != FTUN_OK) return status;
  status = ftun_monotonic_now(&now_ms);
  if (status != FTUN_OK) return status;
  after_event_ms = now_ms;
  if (status == FTUN_OK) status = ftun_tun_owner_update_run(owner, now_ms, &network_work);
  if (status == FTUN_OK) {
    size_t repair_work = 0u;
    status = ftun_tun_owner_repair_run(owner, now_ms, &repair_work);
    network_work += repair_work;
  }
  if (status == FTUN_OK) status = ftun_tun_service_run(owner->service, &work);
  if (status != FTUN_OK) return status;
  ftun_tun_owner_device_run(owner, now_ms);
  status = ftun_event_loop_get_usage(owner->loop, &event_usage);
  if (status != FTUN_OK) return status;
  out_usage->work = event_usage.last_work > SIZE_MAX - work ? SIZE_MAX : event_usage.last_work + work;
  out_usage->work = network_work > SIZE_MAX - out_usage->work
    ? SIZE_MAX : out_usage->work + network_work;
  status = ftun_monotonic_now(&finished_ms);
  if (status != FTUN_OK) return status;
  out_usage->busy_ms = event_usage.last_dispatch_ms;
  if (before_event_ms >= started_ms) out_usage->busy_ms += before_event_ms - started_ms;
  if (finished_ms >= after_event_ms) out_usage->busy_ms += finished_ms - after_event_ms;
  out_usage->deadline_lateness_ms = event_usage.max_timer_lateness_ms;
  out_usage->quota_exhausted = event_usage.backend_quota_exhausted ||
    callbacks == FTUN_TUN_OWNER_EVENT_QUOTA ||
    work >= FTUN_TUN_OWNER_IO_QUOTA || network_work >= FTUN_TUN_OWNER_IO_QUOTA ||
    ftun_tun_owner_update_runnable(owner);
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
  if (owner->network_updating) {
    if (owner->network_phase == FTUN_TUN_UPDATE_IDLE) return FTUN_E_AGAIN;
    status = ftun_tun_service_network_finish(owner->service, FTUN_E_CANCELLED);
    if (status != FTUN_E_CANCELLED) return status;
    owner->network_result.update_status = FTUN_E_CANCELLED;
    owner->network_updating = false;
    owner->rebuilding_device = false;
    owner->network_phase = FTUN_TUN_UPDATE_IDLE;
    ftun_tun_owner_update_result(owner);
  }
  status = ftun_event_source_cancel(&owner->network_timer);
  if (status != FTUN_OK) return status;
  owner->network_timer_ready = false;
  status = ftun_event_source_cancel(&owner->retry_timer);
  if (status != FTUN_OK) return status;
  owner->repairing = false;
  owner->repair_due_ms = 0u;
  owner->device_due_ms = 0u;
  if (owner->reload_prepared) {
    status = ftun_tun_owner_reload_abort(owner);
    if (status != FTUN_OK) return status;
  }
  if (owner->network.async.adopt != NULL && owner->network.async.withdraw != NULL &&
      owner->network.async.run != NULL && owner->network.async.query != NULL &&
      owner->network.async.destroy != NULL) owner->async_cleanup = true;
  if (owner->service == NULL) {
    memset(owner->published, 0, sizeof(*owner->published));
    status = FTUN_OK;
  } else if (owner->async_cleanup) {
    status = ftun_tun_service_quiesce_io(owner->service);
    if (status == FTUN_OK) memset(owner->published, 0, sizeof(*owner->published));
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
  if (owner->async_cleanup) {
    ftun_interface_async_ops_t *ops = &owner->network.async;
    ftun_interface_async_options_t options;
    ftun_interface_async_info_t info;
    uint64_t now_ms = 0u;
    uint64_t attempt_deadline;
    bool expired;
    size_t work = 0u;
    if (owner->routes == NULL && owner->async_routes == NULL) return FTUN_OK;
    status = ftun_monotonic_now(&now_ms);
    if (status != FTUN_OK) return status;
    expired = now_ms >= deadline_ms;
    /* 到期不等待；独立的非阻塞清理重试仍可接管或重试残留事务。
     * 已在途事务不续期，新尝试最多给 ACK/reconcile 250 ms，但本调用
     * 仍只推进一轮，未完成立即 TIMEOUT，避免 destroy 永远无法进展。 */
    attempt_deadline = expired
      ? (now_ms > UINT64_MAX - 250u ? UINT64_MAX : now_ms + 250u) : deadline_ms;
    if (owner->routes != NULL) {
      status = ftun_buffer_pool_trim(owner->buffers, 0u);
      if (status != FTUN_OK) return status;
      options = (ftun_interface_async_options_t){owner->budget, owner->loop,
        now_ms, 250u, attempt_deadline};
      status = ops->adopt(ops->context, &owner->routes, &options, &owner->async_routes);
      if (status != FTUN_OK) return status;
    }
    status = ops->query(ops->context, owner->async_routes, &info);
    if (status != FTUN_OK) return status;
    if (!owner->async_release_started && info.state != FTUN_INTERFACE_RELEASED) {
      status = ops->withdraw(ops->context, owner->async_routes, now_ms, attempt_deadline);
      if (status != FTUN_OK && status != FTUN_E_AGAIN) return status;
      owner->async_release_started = true;
    }
    /* 这里只派发一轮，不在停止调用内等待 ACK 或睡眠。宿主负责按原
     * 绝对期限再次 drain；到期保留事务、设备和预算供后续重试。 */
    status = ftun_event_loop_run_once(owner->loop, false,
      FTUN_TUN_OWNER_EVENT_QUOTA, &work);
    if (status == FTUN_E_UNSUPPORTED) {
      status = ftun_event_loop_poll(owner->loop, now_ms, FTUN_TUN_OWNER_EVENT_QUOTA, &work);
    }
    if (status != FTUN_OK) return status;
    status = ops->run(ops->context, owner->async_routes, now_ms,
      FTUN_TUN_OWNER_IO_QUOTA, &work);
    if (status != FTUN_OK) return status;
    status = ops->query(ops->context, owner->async_routes, &info);
    if (status != FTUN_OK) return status;
    if (info.state == FTUN_INTERFACE_RELEASED ||
        (info.state == FTUN_INTERFACE_FAILED && info.active_count == 0u)) {
      status = ops->destroy(ops->context, &owner->async_routes);
      if (status == FTUN_OK) owner->async_release_started = false;
      return status;
    }
    if (info.state == FTUN_INTERFACE_RETAINED) {
      owner->async_release_started = false;
      return info.cleanup_result == FTUN_OK ? FTUN_E_STATE_CORRUPT : info.cleanup_result;
    }
    return expired ? FTUN_E_TIMEOUT : FTUN_E_AGAIN;
  }
  return ftun_tun_owner_network_withdraw(owner);
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
  ftun_reservation_t reservation;
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
  owner->reservation = (ftun_reservation_t){0};
  owner->published = NULL;
  owner->loop = NULL;
  free(owner);
  *implementation = NULL;
  ftun_reservation_release(&reservation);
  return FTUN_OK;
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
  ftun_tun_owner_destroy_until,
  NULL, /* maintain_once：尚未支持暂停 */
  ftun_tun_owner_network_changed
};
