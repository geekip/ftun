#define _GNU_SOURCE 1
#include "route.h"
#include <errno.h>
#include <linux/fib_rules.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define FTUN_LINUX_ROUTE_MAGIC UINT32_C(0x46545254)
#define FTUN_NETLINK_MESSAGE_BYTES 512u

#if IFNAMSIZ != FTUN_LINUX_ROUTE_NAME_BYTES
#error "FTUN Linux route name size must match IFNAMSIZ"
#endif

struct ftun_route_transaction {
  uint32_t magic;
  ftun_linux_route_resource_t resources[FTUN_LINUX_ROUTE_MAX_RESOURCES];
  bool active[FTUN_LINUX_ROUTE_MAX_RESOURCES];
  size_t resource_count;
  size_t active_count;
  bool strict_route;
  ftun_linux_route_io_t io;
};

typedef struct {
  struct nlmsghdr header;
  uint8_t body[FTUN_NETLINK_MESSAGE_BYTES - sizeof(struct nlmsghdr)];
} ftun_netlink_message_t;

static ftun_status_t ftun_linux_route_errno(int error_code, bool removing)
{
  if (removing && (error_code == ENOENT || error_code == ESRCH)) {
    return FTUN_E_STALE;
  }
  if (error_code == EEXIST || error_code == EACCES || error_code == EPERM) {
    return FTUN_E_REJECTED;
  }
  if (error_code == ENOMEM || error_code == ENOBUFS || error_code == EMFILE ||
      error_code == ENFILE) return FTUN_E_LIMIT;
  if (error_code == EAFNOSUPPORT || error_code == EOPNOTSUPP ||
      error_code == ENOSYS || error_code == ENODEV) return FTUN_E_UNSUPPORTED;
  if (error_code == EINVAL) return FTUN_E_UNSUPPORTED;
  return FTUN_E_IO;
}

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

static int ftun_route_policy_valid(const ftun_route_policy_t *policy)
{
  if (policy == NULL || !ftun_route_name_valid(policy->tun_interface, false) ||
      !ftun_route_name_valid(policy->lan_interface, true) ||
      ftun_route_name_equals(policy->tun_interface, "lo") ||
      ftun_route_name_equals(policy->lan_interface, "lo") ||
      ftun_route_names_equal(policy->tun_interface, policy->lan_interface) ||
      (!policy->manage_local && policy->lan_interface.length == 0u) ||
      policy->tun_prefix_length == 0u || policy->tun_prefix_length > 32u ||
      policy->route_table == RT_TABLE_UNSPEC ||
      policy->route_table == RT_TABLE_DEFAULT ||
      policy->route_table == RT_TABLE_MAIN ||
      policy->route_table == RT_TABLE_LOCAL ||
      policy->rule_priority == 0u ||
      policy->rule_priority > UINT32_MAX - 2u ||
      policy->protection_mark == 0u || policy->protection_mark_mask == 0u ||
      (policy->protection_mark & ~policy->protection_mark_mask) != 0u) return 0;
  return 1;
}

static void ftun_route_copy_name(char out[FTUN_LINUX_ROUTE_NAME_BYTES],
                                 ftun_string_t name)
{
  memset(out, 0, FTUN_LINUX_ROUTE_NAME_BYTES);
  if (name.length != 0u) memcpy(out, name.data, name.length);
}

static ftun_linux_route_resource_t *ftun_route_append(
  ftun_route_transaction_t *transaction, ftun_linux_route_resource_kind_t kind,
  int family)
{
  ftun_linux_route_resource_t *resource;
  if (transaction->resource_count >= FTUN_LINUX_ROUTE_MAX_RESOURCES) return NULL;
  resource = &transaction->resources[transaction->resource_count++];
  memset(resource, 0, sizeof(*resource));
  resource->kind = kind;
  resource->family = family;
  resource->protocol = FTUN_LINUX_ROUTE_PROTOCOL;
  return resource;
}

static int ftun_route_build(const ftun_route_policy_t *policy,
                            ftun_route_transaction_t *transaction)
{
  ftun_linux_route_resource_t *resource;
  uint32_t local_priority = policy->rule_priority + 1u;
  uint32_t lan_priority = policy->rule_priority + 2u;
  resource = ftun_route_append(transaction, FTUN_LINUX_ROUTE_ADDRESS, AF_INET);
  if (resource == NULL) return 0;
  ftun_route_copy_name(resource->interface_name, policy->tun_interface);
  memcpy(resource->address, policy->tun_ipv4, 4u);
  resource->prefix_length = policy->tun_prefix_length;

  resource = ftun_route_append(transaction, FTUN_LINUX_ROUTE_MARK_RULE, AF_INET);
  if (resource == NULL) return 0;
  resource->table = RT_TABLE_MAIN;
  resource->priority = policy->rule_priority;
  resource->mark = policy->protection_mark;
  resource->mark_mask = policy->protection_mark_mask;

  resource = ftun_route_append(transaction, FTUN_LINUX_ROUTE_DEFAULT, AF_INET);
  if (resource == NULL) return 0;
  ftun_route_copy_name(resource->interface_name, policy->tun_interface);
  resource->table = policy->route_table;

  if (policy->manage_local) {
    resource = ftun_route_append(transaction, FTUN_LINUX_ROUTE_CAPTURE_RULE,
                                 AF_INET);
    if (resource == NULL) return 0;
    memcpy(resource->interface_name, "lo", 3u);
    resource->table = policy->route_table;
    resource->priority = local_priority;
  }
  if (policy->lan_interface.length != 0u) {
    resource = ftun_route_append(transaction, FTUN_LINUX_ROUTE_CAPTURE_RULE,
                                 AF_INET);
    if (resource == NULL) return 0;
    ftun_route_copy_name(resource->interface_name, policy->lan_interface);
    resource->table = policy->route_table;
    resource->priority = lan_priority;
  }
  if (policy->strict_route && policy->manage_local) {
    resource = ftun_route_append(transaction, FTUN_LINUX_ROUTE_BLOCK_IPV6,
                                 AF_INET6);
    if (resource == NULL) return 0;
    memcpy(resource->interface_name, "lo", 3u);
    resource->priority = local_priority;
  }
  if (policy->strict_route && policy->lan_interface.length != 0u) {
    resource = ftun_route_append(transaction, FTUN_LINUX_ROUTE_BLOCK_IPV6,
                                 AF_INET6);
    if (resource == NULL) return 0;
    ftun_route_copy_name(resource->interface_name, policy->lan_interface);
    resource->priority = lan_priority;
  }
  transaction->strict_route = policy->strict_route;
  return 1;
}

static int ftun_netlink_add_attribute(struct nlmsghdr *header, size_t capacity,
                                      uint16_t type, const void *data,
                                      size_t length)
{
  size_t offset = NLMSG_ALIGN(header->nlmsg_len);
  size_t attribute_length = RTA_LENGTH(length);
  size_t total = offset + RTA_ALIGN(attribute_length);
  struct rtattr *attribute;
  if (total > capacity || attribute_length > UINT16_MAX) return 0;
  attribute = (struct rtattr *)((uint8_t *)header + offset);
  attribute->rta_type = type;
  attribute->rta_len = (uint16_t)attribute_length;
  if (length != 0u) memcpy(RTA_DATA(attribute), data, length);
  header->nlmsg_len = (uint32_t)total;
  return 1;
}

static ftun_status_t ftun_netlink_address(ftun_netlink_message_t *message,
                                          const ftun_linux_route_resource_t *resource,
                                          bool add)
{
  struct ifaddrmsg *address;
  unsigned int interface_index = if_nametoindex(resource->interface_name);
  if (interface_index == 0u) return FTUN_E_UNSUPPORTED;
  message->header.nlmsg_type = add ? RTM_NEWADDR : RTM_DELADDR;
  message->header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  if (add) message->header.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
  message->header.nlmsg_len = NLMSG_LENGTH(sizeof(*address));
  address = (struct ifaddrmsg *)NLMSG_DATA(&message->header);
  memset(address, 0, sizeof(*address));
  address->ifa_family = AF_INET;
  address->ifa_prefixlen = resource->prefix_length;
  address->ifa_scope = RT_SCOPE_UNIVERSE;
  address->ifa_index = interface_index;
  if (!ftun_netlink_add_attribute(&message->header, sizeof(*message), IFA_LOCAL,
                                  resource->address, 4u) ||
      !ftun_netlink_add_attribute(&message->header, sizeof(*message), IFA_ADDRESS,
                                  resource->address, 4u)) return FTUN_E_LIMIT;
  return FTUN_OK;
}

static ftun_status_t ftun_netlink_rule(ftun_netlink_message_t *message,
                                       const ftun_linux_route_resource_t *resource,
                                       bool add)
{
  struct fib_rule_hdr *rule;
  uint8_t table_byte;
  message->header.nlmsg_type = add ? RTM_NEWRULE : RTM_DELRULE;
  message->header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  if (add) message->header.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
  message->header.nlmsg_len = NLMSG_LENGTH(sizeof(*rule));
  rule = (struct fib_rule_hdr *)NLMSG_DATA(&message->header);
  memset(rule, 0, sizeof(*rule));
  rule->family = (uint8_t)resource->family;
  rule->action = resource->kind == FTUN_LINUX_ROUTE_BLOCK_IPV6 ?
                 FR_ACT_UNREACHABLE : FR_ACT_TO_TBL;
  table_byte = resource->table <= UINT8_MAX ? (uint8_t)resource->table :
               (uint8_t)RT_TABLE_UNSPEC;
  rule->table = resource->kind == FTUN_LINUX_ROUTE_BLOCK_IPV6 ?
                (uint8_t)RT_TABLE_UNSPEC : table_byte;
  if (!ftun_netlink_add_attribute(&message->header, sizeof(*message),
                                  FRA_PRIORITY, &resource->priority,
                                  sizeof(resource->priority)) ||
      !ftun_netlink_add_attribute(&message->header, sizeof(*message),
                                  FRA_PROTOCOL, &resource->protocol,
                                  sizeof(resource->protocol))) return FTUN_E_LIMIT;
  if (resource->kind != FTUN_LINUX_ROUTE_BLOCK_IPV6 &&
      !ftun_netlink_add_attribute(&message->header, sizeof(*message), FRA_TABLE,
                                  &resource->table,
                                  sizeof(resource->table))) return FTUN_E_LIMIT;
  if (resource->kind == FTUN_LINUX_ROUTE_MARK_RULE &&
      (!ftun_netlink_add_attribute(&message->header, sizeof(*message), FRA_FWMARK,
                                   &resource->mark, sizeof(resource->mark)) ||
       !ftun_netlink_add_attribute(&message->header, sizeof(*message), FRA_FWMASK,
                                   &resource->mark_mask,
                                   sizeof(resource->mark_mask)))) return FTUN_E_LIMIT;
  if ((resource->kind == FTUN_LINUX_ROUTE_CAPTURE_RULE ||
       resource->kind == FTUN_LINUX_ROUTE_BLOCK_IPV6) &&
      !ftun_netlink_add_attribute(&message->header, sizeof(*message), FRA_IIFNAME,
                                  resource->interface_name,
                                  strlen(resource->interface_name) + 1u)) {
    return FTUN_E_LIMIT;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_netlink_default_route(
  ftun_netlink_message_t *message,
  const ftun_linux_route_resource_t *resource, bool add)
{
  struct rtmsg *route;
  unsigned int interface_index = if_nametoindex(resource->interface_name);
  uint8_t table_byte;
  if (interface_index == 0u) return FTUN_E_UNSUPPORTED;
  message->header.nlmsg_type = add ? RTM_NEWROUTE : RTM_DELROUTE;
  message->header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  if (add) message->header.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
  message->header.nlmsg_len = NLMSG_LENGTH(sizeof(*route));
  route = (struct rtmsg *)NLMSG_DATA(&message->header);
  memset(route, 0, sizeof(*route));
  route->rtm_family = AF_INET;
  table_byte = resource->table <= UINT8_MAX ? (uint8_t)resource->table :
               (uint8_t)RT_TABLE_UNSPEC;
  route->rtm_table = table_byte;
  route->rtm_protocol = resource->protocol;
  route->rtm_scope = RT_SCOPE_LINK;
  route->rtm_type = RTN_UNICAST;
  if (!ftun_netlink_add_attribute(&message->header, sizeof(*message), RTA_TABLE,
                                  &resource->table, sizeof(resource->table)) ||
      !ftun_netlink_add_attribute(&message->header, sizeof(*message), RTA_OIF,
                                  &interface_index,
                                  sizeof(interface_index))) return FTUN_E_LIMIT;
  return FTUN_OK;
}

static ftun_status_t ftun_netlink_build(ftun_netlink_message_t *message,
                                        const ftun_linux_route_resource_t *resource,
                                        bool add)
{
  memset(message, 0, sizeof(*message));
  message->header.nlmsg_seq = 1u;
  if (resource->kind == FTUN_LINUX_ROUTE_ADDRESS) {
    return ftun_netlink_address(message, resource, add);
  }
  if (resource->kind == FTUN_LINUX_ROUTE_DEFAULT) {
    return ftun_netlink_default_route(message, resource, add);
  }
  return ftun_netlink_rule(message, resource, add);
}

static ftun_status_t ftun_netlink_exchange(ftun_netlink_message_t *message,
                                           bool removing)
{
  struct sockaddr_nl address;
  struct timeval timeout;
  uint8_t response[FTUN_NETLINK_MESSAGE_BYTES];
  struct nlmsghdr *header;
  ssize_t result;
  int descriptor;
  int error_code;
  descriptor = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (descriptor < 0) return ftun_linux_route_errno(errno, removing);
  memset(&address, 0, sizeof(address));
  address.nl_family = AF_NETLINK;
  if (bind(descriptor, (struct sockaddr *)&address, sizeof(address)) < 0) {
    error_code = errno;
    (void)close(descriptor);
    return ftun_linux_route_errno(error_code, removing);
  }
  timeout.tv_sec = 2;
  timeout.tv_usec = 0;
  if (setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                 sizeof(timeout)) < 0) {
    error_code = errno;
    (void)close(descriptor);
    return ftun_linux_route_errno(error_code, removing);
  }
  do {
    result = sendto(descriptor, &message->header, message->header.nlmsg_len, 0,
                    (struct sockaddr *)&address, sizeof(address));
  } while (result < 0 && errno == EINTR);
  if (result < 0 || (size_t)result != message->header.nlmsg_len) {
    error_code = result < 0 ? errno : EIO;
    (void)close(descriptor);
    return ftun_linux_route_errno(error_code, removing);
  }
  do {
    result = recv(descriptor, response, sizeof(response), 0);
  } while (result < 0 && errno == EINTR);
  if (result < 0) {
    error_code = errno;
    (void)close(descriptor);
    return ftun_linux_route_errno(error_code, removing);
  }
  (void)close(descriptor);
  for (header = (struct nlmsghdr *)response;
       NLMSG_OK(header, (unsigned int)result);
       header = NLMSG_NEXT(header, result)) {
    if (header->nlmsg_seq == 1u && header->nlmsg_type == NLMSG_ERROR) {
      const struct nlmsgerr *error = (const struct nlmsgerr *)NLMSG_DATA(header);
      if (header->nlmsg_len < NLMSG_LENGTH(sizeof(*error))) return FTUN_E_IO;
      return error->error == 0 ? FTUN_OK :
             ftun_linux_route_errno(-error->error, removing);
    }
  }
  return FTUN_E_IO;
}

static ftun_status_t ftun_system_route_change(
  const ftun_linux_route_resource_t *resource, bool add)
{
  ftun_netlink_message_t message;
  ftun_status_t status = ftun_netlink_build(&message, resource, add);
  if (status != FTUN_OK) return status;
  return ftun_netlink_exchange(&message, !add);
}

static ftun_status_t ftun_system_route_apply(
  void *context, const ftun_linux_route_resource_t *resource)
{
  (void)context;
  return ftun_system_route_change(resource, true);
}

static ftun_status_t ftun_system_route_remove(
  void *context, const ftun_linux_route_resource_t *resource)
{
  (void)context;
  return ftun_system_route_change(resource, false);
}

static const ftun_linux_route_io_t ftun_system_route_io = {
  ftun_system_route_apply,
  ftun_system_route_remove,
  NULL
};

static ftun_status_t ftun_route_remove_active(
  ftun_route_transaction_t *transaction)
{
  ftun_status_t first = FTUN_OK;
  size_t index = transaction->resource_count;
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

/* TASK-PLATFORM-002 / TEST-PLATFORM-002，目标 0.2.0：有所有权的路由事务。 */
ftun_status_t ftun_linux_route_prepare_with_io(const ftun_route_policy_t *policy,
                                               const ftun_linux_route_io_t *io,
                                               ftun_route_transaction_t **out)
{
  ftun_route_transaction_t *transaction;
  ftun_status_t status;
  size_t index;
  if (out != NULL) *out = NULL;
  if (out == NULL || !ftun_route_policy_valid(policy) || io == NULL ||
      io->apply == NULL || io->remove == NULL) return FTUN_E_INVALID;
  transaction = (ftun_route_transaction_t *)calloc(1u, sizeof(*transaction));
  if (transaction == NULL) return FTUN_E_LIMIT;
  transaction->magic = FTUN_LINUX_ROUTE_MAGIC;
  transaction->io = *io;
  if (!ftun_route_build(policy, transaction)) {
    free(transaction);
    return FTUN_E_LIMIT;
  }
  for (index = 0u; index < transaction->resource_count; index++) {
    status = transaction->io.apply(transaction->io.context,
                                   &transaction->resources[index]);
    if (status != FTUN_OK) {
      ftun_status_t rollback = ftun_route_remove_active(transaction);
      if (rollback != FTUN_OK) {
        *out = transaction;
        return FTUN_E_STATE_CORRUPT;
      }
      transaction->magic = 0u;
      free(transaction);
      return status;
    }
    transaction->active[index] = true;
    transaction->active_count++;
  }
  *out = transaction;
  return FTUN_OK;
}

ftun_status_t ftun_linux_route_prepare(const ftun_route_policy_t *policy,
                                       ftun_route_transaction_t **out)
{
  return ftun_linux_route_prepare_with_io(policy, &ftun_system_route_io, out);
}

ftun_status_t ftun_linux_route_get_info(
  const ftun_route_transaction_t *transaction, ftun_linux_route_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (transaction == NULL || transaction->magic != FTUN_LINUX_ROUTE_MAGIC ||
      out == NULL) return FTUN_E_INVALID;
  out->resource_count = transaction->resource_count;
  out->active_count = transaction->active_count;
  out->strict_route = transaction->strict_route;
  return FTUN_OK;
}

ftun_status_t ftun_linux_route_release(
  ftun_route_transaction_t **transaction)
{
  ftun_route_transaction_t *owned;
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
  free(owned);
  *transaction = NULL;
  return FTUN_OK;
}
