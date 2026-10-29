#define _GNU_SOURCE 1
#include "platform/route.h"
#include "platform/linux/route_transaction.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FTUN_LINUX_ROUTE_MAGIC UINT32_C(0x46545254)

static int ftun_route_name_valid(ftun_string_t name, bool optional)
{
  size_t index;
  if (name.length == 0u) return optional;
  if (name.data == NULL || name.length >= FTUN_LINUX_ROUTE_NAME_BYTES) return 0;
  if ((name.length == 1u && name.data[0] == '.') ||
      (name.length == 2u && name.data[0] == '.' && name.data[1] == '.')) return 0;
  for (index = 0u; index < name.length; index++) {
    unsigned char value = (unsigned char)name.data[index];
    if (value <= (unsigned char)' ' || value == (unsigned char)'/' ||
        value == (unsigned char)':') return 0;
  }
  return 1;
}

static int ftun_route_name_equals(ftun_string_t left, const char *right)
{
  size_t length = strlen(right);
  return left.length == length && left.data != NULL &&
         memcmp(left.data, right, length) == 0;
}

static int ftun_route_names_equal(ftun_string_t left, ftun_string_t right)
{
  return left.length != 0u && left.length == right.length &&
         left.data != NULL && right.data != NULL &&
         memcmp(left.data, right.data, left.length) == 0;
}

static int ftun_route_c_name_valid(const char *name, bool optional)
{
  ftun_string_t value;
  if (name == NULL) return 0;
  value.data = name;
  value.length = strnlen(name, FTUN_LINUX_ROUTE_NAME_BYTES);
  if (value.length == FTUN_LINUX_ROUTE_NAME_BYTES) return 0;
  return ftun_route_name_valid(value, optional);
}

static int ftun_route_network_normalized(const uint8_t address[4],
                                         uint8_t prefix_length)
{
  uint32_t value;
  uint32_t mask;
  if (prefix_length > 32u) return 0;
  value = ((uint32_t)address[0] << 24u) |
          ((uint32_t)address[1] << 16u) |
          ((uint32_t)address[2] << 8u) | (uint32_t)address[3];
  mask = prefix_length == 0u ? 0u :
    UINT32_MAX << (32u - (uint32_t)prefix_length);
  return (value & ~mask) == 0u;
}

static int ftun_route_resource_valid(
  const ftun_route_resource_t *resource)
{
  if (resource == NULL || resource->protocol != FTUN_LINUX_ROUTE_PROTOCOL) {
    return 0;
  }
  switch (resource->kind) {
    case FTUN_LINUX_ROUTE_ADDRESS:
      return resource->family == FTUN_ROUTE_FAMILY_IPV4 &&
        ftun_route_c_name_valid(resource->interface_name, false) &&
        resource->prefix_length != 0u && resource->prefix_length <= 32u;
    case FTUN_LINUX_ROUTE_MARK_RULE:
      return resource->family == FTUN_ROUTE_FAMILY_IPV4 && resource->table != 0u &&
        resource->priority != 0u && resource->mark != 0u &&
        resource->mark_mask != 0u &&
        (resource->mark & ~resource->mark_mask) == 0u;
    case FTUN_LINUX_ROUTE_DEFAULT:
      return resource->family == FTUN_ROUTE_FAMILY_IPV4 && resource->table != 0u &&
        ftun_route_c_name_valid(resource->interface_name, false) &&
        resource->prefix_length == 0u;
    case FTUN_LINUX_ROUTE_CAPTURE_RULE:
      return resource->family == FTUN_ROUTE_FAMILY_IPV4 && resource->table != 0u &&
        resource->priority != 0u &&
        ftun_route_c_name_valid(resource->interface_name, false);
    case FTUN_LINUX_ROUTE_BLOCK_IPV6:
      return resource->family == FTUN_ROUTE_FAMILY_IPV6 && resource->priority != 0u &&
        ftun_route_c_name_valid(resource->interface_name, false);
    case FTUN_LINUX_ROUTE_PROTECT_RULE:
      return resource->family == FTUN_ROUTE_FAMILY_IPV4 && resource->table != 0u &&
        resource->priority != 0u &&
        ftun_route_network_normalized(resource->address,
                                      resource->prefix_length);
    case FTUN_LINUX_ROUTE_OVERLAY:
      return resource->family == FTUN_ROUTE_FAMILY_IPV4 && resource->table != 0u &&
        resource->metric != 0u &&
        ftun_route_c_name_valid(resource->interface_name, false) &&
        ftun_route_network_normalized(resource->address,
                                      resource->prefix_length);
    case FTUN_LINUX_ROUTE_UNREACHABLE:
      return resource->family == FTUN_ROUTE_FAMILY_IPV4 && resource->table != 0u &&
        resource->metric != 0u && resource->interface_name[0] == '\0' &&
        ftun_route_network_normalized(resource->address,
                                      resource->prefix_length);
    default:
      return 0;
  }
}

static int ftun_route_resource_equal(
  const ftun_route_resource_t *left,
  const ftun_route_resource_t *right)
{
  return left->kind == right->kind && left->family == right->family &&
    strcmp(left->interface_name, right->interface_name) == 0 &&
    memcmp(left->address, right->address, sizeof(left->address)) == 0 &&
    left->prefix_length == right->prefix_length &&
    left->table == right->table && left->priority == right->priority &&
    left->mark == right->mark && left->mark_mask == right->mark_mask &&
    left->metric == right->metric && left->protocol == right->protocol;
}

int ftun_route_plan_valid(const ftun_route_plan_t *plan)
{
  size_t index;
  size_t previous;
  if (plan == NULL || plan->resource_count == 0u ||
      plan->resource_count > FTUN_LINUX_ROUTE_PLAN_MAX_RESOURCES) return 0;
  for (index = 0u; index < plan->resource_count; index++) {
    if (!ftun_route_resource_valid(&plan->resources[index])) return 0;
    for (previous = 0u; previous < index; previous++) {
      if (ftun_route_resource_equal(&plan->resources[index],
                                    &plan->resources[previous])) return 0;
    }
  }
  return 1;
}

ftun_status_t ftun_platform_route_guard_plan(
  const ftun_cidr_t *prefixes, size_t prefix_count, uint32_t table, uint32_t first_priority,
  ftun_route_plan_t *out)
{
  size_t index;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (prefixes == NULL || out == NULL || table == FTUN_ROUTE_TABLE_UNSPEC ||
      table == FTUN_ROUTE_TABLE_DEFAULT || table == FTUN_ROUTE_TABLE_MAIN ||
      table == FTUN_ROUTE_TABLE_LOCAL || first_priority == 0u ||
      prefix_count == 0u ||
      prefix_count >
        FTUN_LINUX_ROUTE_PLAN_MAX_RESOURCES / 2u ||
      prefix_count - 1u > UINT32_MAX - first_priority) {
    return FTUN_E_INVALID;
  }
  for (index = 0u; index < prefix_count; index++) {
    const ftun_cidr_t *prefix = &prefixes[index];
    if (prefix->address.family != FTUN_IP_V4) {
      memset(out, 0, sizeof(*out));
      return FTUN_E_UNSUPPORTED;
    }
    ftun_route_resource_t *resource;
    resource = &out->resources[out->resource_count++];
    resource->kind = FTUN_LINUX_ROUTE_UNREACHABLE;
    resource->family = FTUN_ROUTE_FAMILY_IPV4;
    memcpy(resource->address, prefix->address.bytes, 4u);
    resource->prefix_length = prefix->prefix;
    resource->table = table;
    resource->metric = UINT32_C(32767);
    resource->protocol = FTUN_LINUX_ROUTE_PROTOCOL;
    resource = &out->resources[out->resource_count++];
    resource->kind = FTUN_LINUX_ROUTE_PROTECT_RULE;
    resource->family = FTUN_ROUTE_FAMILY_IPV4;
    memcpy(resource->address, prefix->address.bytes, 4u);
    resource->prefix_length = prefix->prefix;
    resource->table = table;
    resource->priority = first_priority + (uint32_t)index;
    resource->protocol = FTUN_LINUX_ROUTE_PROTOCOL;
  }
  return ftun_route_plan_valid(out) ? FTUN_OK : FTUN_E_INVALID;
}

ftun_status_t ftun_platform_route_overlay_plan(
  const ftun_cidr_t *prefixes, size_t prefix_count, ftun_string_t tun_interface,
  uint32_t table, uint32_t metric, ftun_route_plan_t *out)
{
  size_t index;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (prefixes == NULL || out == NULL ||
      !ftun_route_name_valid(tun_interface, false) ||
      table == FTUN_ROUTE_TABLE_UNSPEC || table == FTUN_ROUTE_TABLE_DEFAULT ||
      table == FTUN_ROUTE_TABLE_MAIN || table == FTUN_ROUTE_TABLE_LOCAL ||
      metric == 0u ||
      prefix_count == 0u ||
      prefix_count > FTUN_LINUX_ROUTE_PLAN_MAX_RESOURCES) {
    return FTUN_E_INVALID;
  }
  for (index = 0u; index < prefix_count; index++) {
    const ftun_cidr_t *prefix = &prefixes[index];
    if (prefix->address.family != FTUN_IP_V4) {
      memset(out, 0, sizeof(*out));
      return FTUN_E_UNSUPPORTED;
    }
    ftun_route_resource_t *resource =
      &out->resources[out->resource_count++];
    resource->kind = FTUN_LINUX_ROUTE_OVERLAY;
    resource->family = FTUN_ROUTE_FAMILY_IPV4;
    memcpy(resource->interface_name, tun_interface.data,
           tun_interface.length);
    memcpy(resource->address, prefix->address.bytes, 4u);
    resource->prefix_length = prefix->prefix;
    resource->table = table;
    resource->metric = metric;
    resource->protocol = FTUN_LINUX_ROUTE_PROTOCOL;
  }
  return ftun_route_plan_valid(out) ? FTUN_OK : FTUN_E_INVALID;
}

int ftun_route_policy_valid(const ftun_route_policy_t *policy)
{
  uint32_t offset;
  if (policy == NULL) return 0;
  offset = policy->capture_offset == 0u ? 1u :
           policy->capture_offset;
  if (!ftun_route_name_valid(policy->tun_interface, false) ||
      !ftun_route_name_valid(policy->lan_interface, true) ||
      ftun_route_name_equals(policy->tun_interface, "lo") ||
      ftun_route_name_equals(policy->lan_interface, "lo") ||
      ftun_route_names_equal(policy->tun_interface, policy->lan_interface) ||
      (!policy->manage_local && policy->lan_interface.length == 0u) ||
      policy->tun_prefix_length == 0u || policy->tun_prefix_length > 32u ||
      policy->routing_domain == FTUN_ROUTE_TABLE_UNSPEC ||
      policy->routing_domain == FTUN_ROUTE_TABLE_DEFAULT ||
      policy->routing_domain == FTUN_ROUTE_TABLE_MAIN ||
      policy->routing_domain == FTUN_ROUTE_TABLE_LOCAL ||
      policy->precedence == 0u ||
      offset == 0u || offset > UINT32_MAX - policy->precedence ||
      policy->precedence + offset > UINT32_MAX - 1u ||
      policy->bypass_tag == 0u || policy->bypass_mask == 0u ||
      (policy->bypass_tag & ~policy->bypass_mask) != 0u) return 0;
  return 1;
}

static void ftun_route_copy_name(char out[FTUN_LINUX_ROUTE_NAME_BYTES],
                                 ftun_string_t name)
{
  memset(out, 0, FTUN_LINUX_ROUTE_NAME_BYTES);
  if (name.length != 0u) memcpy(out, name.data, name.length);
}

static ftun_route_resource_t *ftun_route_append(
  ftun_platform_route_transaction_t *transaction, ftun_route_resource_kind_t kind,
  int family)
{
  ftun_route_resource_t *resource;
  if (transaction->resource_count >= FTUN_LINUX_ROUTE_MAX_RESOURCES) return NULL;
  resource = &transaction->resources[transaction->resource_count++];
  memset(resource, 0, sizeof(*resource));
  resource->kind = kind;
  resource->family = family;
  resource->protocol = FTUN_LINUX_ROUTE_PROTOCOL;
  return resource;
}

int ftun_route_build(const ftun_route_policy_t *policy,
                     ftun_platform_route_transaction_t *transaction)
{
  ftun_route_resource_t *resource;
  uint32_t offset = policy->capture_offset == 0u ? 1u :
                    policy->capture_offset;
  uint32_t local_priority = policy->precedence + offset;
  uint32_t lan_priority = local_priority + 1u;
  resource = ftun_route_append(transaction, FTUN_LINUX_ROUTE_ADDRESS, FTUN_ROUTE_FAMILY_IPV4);
  if (resource == NULL) return 0;
  ftun_route_copy_name(resource->interface_name, policy->tun_interface);
  memcpy(resource->address, policy->tun_ipv4, 4u);
  resource->prefix_length = policy->tun_prefix_length;

  resource = ftun_route_append(transaction, FTUN_LINUX_ROUTE_MARK_RULE, FTUN_ROUTE_FAMILY_IPV4);
  if (resource == NULL) return 0;
  resource->table = FTUN_ROUTE_TABLE_MAIN;
  resource->priority = policy->precedence;
  resource->mark = policy->bypass_tag;
  resource->mark_mask = policy->bypass_mask;

  resource = ftun_route_append(transaction, FTUN_LINUX_ROUTE_DEFAULT, FTUN_ROUTE_FAMILY_IPV4);
  if (resource == NULL) return 0;
  ftun_route_copy_name(resource->interface_name, policy->tun_interface);
  resource->table = policy->routing_domain;

  if (policy->manage_local) {
    resource = ftun_route_append(transaction, FTUN_LINUX_ROUTE_CAPTURE_RULE,
                                 FTUN_ROUTE_FAMILY_IPV4);
    if (resource == NULL) return 0;
    memcpy(resource->interface_name, "lo", 3u);
    resource->table = policy->routing_domain;
    resource->priority = local_priority;
  }
  if (policy->lan_interface.length != 0u) {
    resource = ftun_route_append(transaction, FTUN_LINUX_ROUTE_CAPTURE_RULE,
                                 FTUN_ROUTE_FAMILY_IPV4);
    if (resource == NULL) return 0;
    ftun_route_copy_name(resource->interface_name, policy->lan_interface);
    resource->table = policy->routing_domain;
    resource->priority = lan_priority;
  }
  if (policy->strict_route && policy->manage_local) {
    resource = ftun_route_append(transaction, FTUN_LINUX_ROUTE_BLOCK_IPV6,
                                 FTUN_ROUTE_FAMILY_IPV6);
    if (resource == NULL) return 0;
    memcpy(resource->interface_name, "lo", 3u);
    resource->priority = local_priority;
  }
  if (policy->strict_route && policy->lan_interface.length != 0u) {
    resource = ftun_route_append(transaction, FTUN_LINUX_ROUTE_BLOCK_IPV6,
                                 FTUN_ROUTE_FAMILY_IPV6);
    if (resource == NULL) return 0;
    ftun_route_copy_name(resource->interface_name, policy->lan_interface);
    resource->priority = lan_priority;
  }
  transaction->strict_route = policy->strict_route;
  return 1;
}

static ftun_status_t ftun_route_remove_active(
  ftun_platform_route_transaction_t *transaction)
{
  ftun_status_t first = FTUN_OK;
  size_t index = transaction->resource_count;
  transaction->retiring = true;
  while (index != 0u) {
    ftun_status_t status;
    index--;
    if (!transaction->active[index]) continue;
    status = transaction->io.remove(transaction->io.context,
                                    &transaction->resources[index]);
    if (status == FTUN_OK || status == FTUN_E_STALE) {
      transaction->active[index] = false;
      transaction->active_count--;
    } else if (first == FTUN_OK) {
      first = status;
    }
  }
  return first;
}

/* 有所有权的路由事务。 */
/* sweep 仅用于真实系统接口：先取得表互斥锁，再清理上次崩溃遗留的同表同优先级
 * 协议号 186 对象（可能与本次计划选择子不同），之后才安装。 */
static ftun_status_t ftun_route_prepare(
  const ftun_route_policy_t *policy, const ftun_route_io_t *io,
  bool sweep, ftun_platform_route_transaction_t **out)
{
  ftun_platform_route_transaction_t *transaction = NULL;
  ftun_status_t status;
  ftun_handle_t lock_descriptor = -1;
  size_t index;
  if (out != NULL) *out = NULL;
  if (out == NULL || !ftun_route_policy_valid(policy) || io == NULL ||
      io->apply == NULL || io->remove == NULL) return FTUN_E_INVALID;

  if (sweep) {
    status = ftun_route_lock_table(policy->routing_domain, &lock_descriptor);
    if (status != FTUN_OK) goto fail;
  }
  transaction = (ftun_platform_route_transaction_t *)calloc(1u, sizeof(*transaction));
  if (transaction == NULL) { status = FTUN_E_LIMIT; goto fail; }
  transaction->lock_descriptor = lock_descriptor;
  transaction->magic = FTUN_LINUX_ROUTE_MAGIC;
  transaction->io = *io;
  if (!ftun_route_build(policy, transaction)) {
    status = FTUN_E_LIMIT;
    goto fail;
  }
  for (index = 0u; sweep && index < transaction->resource_count; index++) {
    ftun_route_resource_t stray = transaction->resources[index];
    size_t removed;
    if (stray.kind == FTUN_LINUX_ROUTE_ADDRESS) continue;
    stray.stray = true;
    for (removed = 0u; removed < FTUN_LINUX_ROUTE_SWEEP_LIMIT; removed++) {
      status = transaction->io.remove(transaction->io.context, &stray);
      if (status != FTUN_OK) break;
    }
    if (status == FTUN_OK) status = FTUN_E_LIMIT;
    if (status != FTUN_E_STALE) goto fail;
  }
  for (index = 0u; index < transaction->resource_count; index++) {
    status = transaction->io.apply(transaction->io.context,
                                   &transaction->resources[index]);
    /* 已存在：实例锁保证没有存活实例使用同一表号，非地址对象只能是上次崩溃遗留，
     * 原地接管并由本事务撤销；地址对象可能属于外部，仍按冲突失败。 */
    if (status == FTUN_E_STALE &&
        transaction->resources[index].kind != FTUN_LINUX_ROUTE_ADDRESS) {
      status = FTUN_OK;
    }
    if (status != FTUN_OK) {
      ftun_status_t rollback = ftun_route_remove_active(transaction);
      if (rollback != FTUN_OK) {
        *out = transaction;
        return FTUN_E_STATE_CORRUPT;
      }
      goto fail;
    }
    transaction->active[index] = true;
    transaction->active_count++;
  }
  *out = transaction;
  return FTUN_OK;
fail:
  if (lock_descriptor >= 0) (void)ftun_platform_route_close(lock_descriptor);
  free(transaction);
  return status;
}



ftun_status_t ftun_platform_route_prepare_with_io(const ftun_route_policy_t *policy,
  const ftun_route_io_t *io, ftun_platform_route_transaction_t **out)
{
  return ftun_route_prepare(policy, io, false, out);
}



ftun_status_t ftun_platform_route_prepare(const ftun_route_policy_t *policy,
  ftun_platform_route_transaction_t **out)
{
  return ftun_route_prepare(policy, ftun_platform_route_io(), true, out);
}

ftun_status_t ftun_platform_route_get_info(
  const ftun_platform_route_transaction_t *transaction, ftun_route_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (transaction == NULL || transaction->magic != FTUN_LINUX_ROUTE_MAGIC ||
      out == NULL) return FTUN_E_INVALID;
  out->resource_count = transaction->resource_count;
  out->active_count = transaction->active_count;
  out->strict_route = transaction->strict_route;
  return FTUN_OK;
}

ftun_status_t ftun_platform_route_release(
  ftun_platform_route_transaction_t **transaction)
{
  ftun_platform_route_transaction_t *owned;
  ftun_status_t status;
  if (transaction == NULL) return FTUN_E_INVALID;
  owned = *transaction;
  if (owned == NULL) return FTUN_OK;
  if (owned->magic != FTUN_LINUX_ROUTE_MAGIC || owned->io.remove == NULL) {
    return FTUN_E_INVALID;
  }
  status = ftun_route_remove_active(owned);
  if (status != FTUN_OK) return status;
  owned->magic = 0u;
  memset(&owned->io, 0, sizeof(owned->io));
  /* 关闭描述符即释放表互斥锁。 */
  if (owned->lock_descriptor >= 0) (void)ftun_platform_route_close(owned->lock_descriptor);
  free(owned);
  *transaction = NULL;
  return FTUN_OK;
}

size_t ftun_platform_route_transaction_allocation_size(void)
{
  return sizeof(ftun_platform_route_transaction_t);
}
size_t ftun_platform_route_plan_allocation_size(void)
{
  return sizeof(ftun_route_plan_t);
}

bool ftun_platform_route_prepare_valid(const ftun_route_policy_t *policy,
  const ftun_route_io_t *io, bool system)
{
  if (system) io = ftun_platform_route_io();
  return ftun_route_policy_valid(policy) && io != NULL &&
    io->apply != NULL && io->remove != NULL;
}

ftun_route_settings_t ftun_platform_route_defaults(void)
{
  return (ftun_route_settings_t){18004u, 11000u};
}

const char *ftun_platform_route_config_error(ftun_route_settings_t settings)
{
  if (settings.routing_domain < 256u || settings.routing_domain > UINT32_C(0xfffffff0) ||
      settings.precedence == 0u || settings.precedence > 32000u) {
    return "TUN route-table must be 256..4294967280 and rule-priority 1..32000";
  }
  return NULL;
}
