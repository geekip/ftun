#define _GNU_SOURCE 1
#include "platform/linux/route_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <stdio.h>
#include <net/if.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#if IFNAMSIZ != FTUN_LINUX_ROUTE_NAME_BYTES
#error "FTUN Linux route name size must match IFNAMSIZ"
#endif

ftun_status_t ftun_linux_route_errno(int error_code, bool removing)
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

ftun_status_t ftun_linux_route_lock_table(uint32_t table, int *out)
{
  char path[64];
  int descriptor;
  *out = -1;
  if (table == 0u) return FTUN_OK;
  (void)snprintf(path, sizeof(path), "/run/ftun-net-%u.lock", (unsigned)table);
  descriptor = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (descriptor < 0) return ftun_linux_route_errno(errno, false);
  if (flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
    int error_code = errno;
    (void)close(descriptor);
    return error_code == EWOULDBLOCK ? FTUN_E_REJECTED :
      ftun_linux_route_errno(error_code, false);
  }
  *out = descriptor;
  return FTUN_OK;
}

static int ftun_netlink_add_attribute(struct ftun_nlmsghdr *header,
                                      size_t capacity,
                                      uint16_t type, const void *data,
                                      size_t length)
{
  size_t offset = FTUN_NLMSG_ALIGN(header->nlmsg_len);
  size_t attribute_length = FTUN_RTA_LENGTH(length);
  size_t total = offset + FTUN_RTA_ALIGN(attribute_length);
  struct ftun_rtattr *attribute;
  if (total > capacity || attribute_length > UINT16_MAX) return 0;
  attribute = (struct ftun_rtattr *)((uint8_t *)header + offset);
  attribute->rta_type = type;
  attribute->rta_len = (uint16_t)attribute_length;
  if (length != 0u) memcpy(FTUN_RTA_DATA(attribute), data, length);
  header->nlmsg_len = (uint32_t)total;
  return 1;
}

static ftun_status_t ftun_netlink_address(ftun_netlink_message_t *message,
                                          const ftun_linux_route_resource_t *resource,
                                          bool add)
{
  struct ftun_ifaddrmsg *address;
  unsigned int interface_index = if_nametoindex(resource->interface_name);
  /* 接口已不存在（例如设备被外部删除）：地址随接口消失，删除视为已完成。 */
  if (interface_index == 0u) return add ? FTUN_E_UNSUPPORTED : FTUN_E_STALE;
  message->header.nlmsg_type = add ? FTUN_RTM_NEWADDR : FTUN_RTM_DELADDR;
  message->header.nlmsg_flags = FTUN_NLM_F_REQUEST | FTUN_NLM_F_ACK;
  if (add) message->header.nlmsg_flags |= FTUN_NLM_F_CREATE | FTUN_NLM_F_EXCL;
  message->header.nlmsg_len = FTUN_NLMSG_LENGTH(sizeof(*address));
  address = (struct ftun_ifaddrmsg *)FTUN_NLMSG_DATA(&message->header);
  memset(address, 0, sizeof(*address));
  address->ifa_family = AF_INET;
  address->ifa_prefixlen = resource->prefix_length;
  address->ifa_scope = FTUN_RT_SCOPE_UNIVERSE;
  address->ifa_index = interface_index;
  if (!ftun_netlink_add_attribute(&message->header, sizeof(*message),
                                  FTUN_IFA_LOCAL,
                                  resource->address, 4u) ||
      !ftun_netlink_add_attribute(&message->header, sizeof(*message),
                                  FTUN_IFA_ADDRESS,
                                  resource->address, 4u)) return FTUN_E_LIMIT;
  return FTUN_OK;
}

/* stray 只用于删除：仅以家族、优先级与协议号选择对象，其余选择子全部放宽，
 * 内核删除第一条匹配项，用于清理上次崩溃遗留的过期对象。 */
static ftun_status_t ftun_netlink_rule(ftun_netlink_message_t *message,
                                       const ftun_linux_route_resource_t *resource,
                                       bool add, bool stray)
{
  struct ftun_fib_rule_hdr *rule;
  uint8_t table_byte;
  message->header.nlmsg_type = add ? FTUN_RTM_NEWRULE : FTUN_RTM_DELRULE;
  message->header.nlmsg_flags = FTUN_NLM_F_REQUEST | FTUN_NLM_F_ACK;
  if (add) message->header.nlmsg_flags |= FTUN_NLM_F_CREATE | FTUN_NLM_F_EXCL;
  message->header.nlmsg_len = FTUN_NLMSG_LENGTH(sizeof(*rule));
  rule = (struct ftun_fib_rule_hdr *)FTUN_NLMSG_DATA(&message->header);
  memset(rule, 0, sizeof(*rule));
  rule->family = (uint8_t)resource->family;
  if (resource->kind == FTUN_LINUX_ROUTE_PROTECT_RULE && !stray) {
    rule->dst_len = resource->prefix_length;
  }
  rule->action = resource->kind == FTUN_LINUX_ROUTE_BLOCK_IPV6 ?
                 FTUN_FR_ACT_UNREACHABLE : FTUN_FR_ACT_TO_TBL;
  table_byte = resource->table <= UINT8_MAX ? (uint8_t)resource->table :
               (uint8_t)FTUN_RT_TABLE_UNSPEC;
  rule->table = resource->kind == FTUN_LINUX_ROUTE_BLOCK_IPV6 ?
                (uint8_t)FTUN_RT_TABLE_UNSPEC : table_byte;
  if (stray) {
    rule->action = 0u;
    rule->table = (uint8_t)FTUN_RT_TABLE_UNSPEC;
  }
  if (!ftun_netlink_add_attribute(&message->header, sizeof(*message),
                                  FTUN_FRA_PRIORITY, &resource->priority,
                                  sizeof(resource->priority)) ||
      !ftun_netlink_add_attribute(&message->header, sizeof(*message),
                                  FTUN_FRA_PROTOCOL, &resource->protocol,
                                  sizeof(resource->protocol))) return FTUN_E_LIMIT;
  if (stray) return FTUN_OK;
  if (resource->kind != FTUN_LINUX_ROUTE_BLOCK_IPV6 &&
      !ftun_netlink_add_attribute(&message->header, sizeof(*message),
                                  FTUN_FRA_TABLE,
                                  &resource->table,
                                  sizeof(resource->table))) return FTUN_E_LIMIT;
  if (resource->kind == FTUN_LINUX_ROUTE_MARK_RULE &&
      (!ftun_netlink_add_attribute(&message->header, sizeof(*message),
                                   FTUN_FRA_FWMARK,
                                   &resource->mark, sizeof(resource->mark)) ||
       !ftun_netlink_add_attribute(&message->header, sizeof(*message),
                                   FTUN_FRA_FWMASK,
                                   &resource->mark_mask,
                                   sizeof(resource->mark_mask)))) return FTUN_E_LIMIT;
  if (resource->kind == FTUN_LINUX_ROUTE_PROTECT_RULE &&
      !ftun_netlink_add_attribute(&message->header, sizeof(*message),
                                  FTUN_FRA_DST, resource->address, 4u)) {
    return FTUN_E_LIMIT;
  }
  if ((resource->kind == FTUN_LINUX_ROUTE_CAPTURE_RULE ||
       resource->kind == FTUN_LINUX_ROUTE_BLOCK_IPV6) &&
      !ftun_netlink_add_attribute(&message->header, sizeof(*message),
                                  FTUN_FRA_IIFNAME,
                                  resource->interface_name,
                                  strlen(resource->interface_name) + 1u)) {
    return FTUN_E_LIMIT;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_netlink_route(
  ftun_netlink_message_t *message,
  const ftun_linux_route_resource_t *resource, bool add, bool stray)
{
  struct ftun_rtmsg *route;
  unsigned int interface_index = 0u;
  uint8_t table_byte;
  bool unreachable = resource->kind == FTUN_LINUX_ROUTE_UNREACHABLE;
  if (!unreachable && !stray) {
    interface_index = if_nametoindex(resource->interface_name);
    /* 同上：路由随接口消失，删除视为已完成。 */
    if (interface_index == 0u) return add ? FTUN_E_UNSUPPORTED : FTUN_E_STALE;
  }
  message->header.nlmsg_type = add ? FTUN_RTM_NEWROUTE : FTUN_RTM_DELROUTE;
  message->header.nlmsg_flags = FTUN_NLM_F_REQUEST | FTUN_NLM_F_ACK;
  if (add) message->header.nlmsg_flags |= FTUN_NLM_F_CREATE | FTUN_NLM_F_EXCL;
  message->header.nlmsg_len = FTUN_NLMSG_LENGTH(sizeof(*route));
  route = (struct ftun_rtmsg *)FTUN_NLMSG_DATA(&message->header);
  memset(route, 0, sizeof(*route));
  route->rtm_family = AF_INET;
  route->rtm_dst_len = resource->prefix_length;
  table_byte = resource->table <= UINT8_MAX ? (uint8_t)resource->table :
               (uint8_t)FTUN_RT_TABLE_UNSPEC;
  route->rtm_table = table_byte;
  route->rtm_protocol = resource->protocol;
  route->rtm_scope = unreachable ? FTUN_RT_SCOPE_UNIVERSE :
                                   FTUN_RT_SCOPE_LINK;
  route->rtm_type = unreachable ? FTUN_RTN_UNREACHABLE : FTUN_RTN_UNICAST;
  if (stray) {
    route->rtm_scope = FTUN_RT_SCOPE_NOWHERE;
    route->rtm_type = 0u;
  }
  if (!ftun_netlink_add_attribute(&message->header, sizeof(*message),
                                  FTUN_RTA_TABLE,
                                  &resource->table, sizeof(resource->table))) {
    return FTUN_E_LIMIT;
  }
  if (resource->prefix_length != 0u &&
      !ftun_netlink_add_attribute(&message->header, sizeof(*message),
                                  FTUN_RTA_DST, resource->address, 4u)) {
    return FTUN_E_LIMIT;
  }
  if (stray) return FTUN_OK;
  if (!unreachable &&
      !ftun_netlink_add_attribute(&message->header, sizeof(*message),
                                  FTUN_RTA_OIF, &interface_index,
                                  sizeof(interface_index))) return FTUN_E_LIMIT;
  if (resource->metric != 0u &&
      !ftun_netlink_add_attribute(&message->header, sizeof(*message),
                                  FTUN_RTA_PRIORITY, &resource->metric,
                                  sizeof(resource->metric))) return FTUN_E_LIMIT;
  return FTUN_OK;
}

ftun_status_t ftun_netlink_build(ftun_netlink_message_t *message,
                                 const ftun_linux_route_resource_t *resource,
                                 bool add)
{
  bool stray = resource->stray && !add;
  memset(message, 0, sizeof(*message));
  message->header.nlmsg_seq = 1u;
  if (resource->kind == FTUN_LINUX_ROUTE_ADDRESS) {
    return stray ? FTUN_E_INVALID : ftun_netlink_address(message, resource, add);
  }
  if (resource->kind == FTUN_LINUX_ROUTE_DEFAULT ||
      resource->kind == FTUN_LINUX_ROUTE_OVERLAY ||
      resource->kind == FTUN_LINUX_ROUTE_UNREACHABLE) {
    return ftun_netlink_route(message, resource, add, stray);
  }
  return ftun_netlink_rule(message, resource, add, stray);
}

static ftun_status_t ftun_netlink_exchange(ftun_netlink_message_t *message,
                                           bool removing)
{
  struct ftun_sockaddr_nl address;
  struct timeval timeout;
  uint8_t response[FTUN_NETLINK_MESSAGE_BYTES];
  struct ftun_nlmsghdr *header;
  ssize_t result;
  int descriptor;
  int error_code;
  descriptor = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC,
                      FTUN_NETLINK_ROUTE);
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
  for (header = (struct ftun_nlmsghdr *)response;
       FTUN_NLMSG_OK(header, result);
       header = FTUN_NLMSG_NEXT(header, result)) {
    if (header->nlmsg_seq == 1u && header->nlmsg_type == FTUN_NLMSG_ERROR) {
      const struct ftun_nlmsgerr *error =
        (const struct ftun_nlmsgerr *)FTUN_NLMSG_DATA(header);
      if (header->nlmsg_len < FTUN_NLMSG_LENGTH(sizeof(*error))) {
        return FTUN_E_IO;
      }
      /* 添加时对象已存在（EXCL 冲突）：以 STALE 告知调用方“已存在”，是否接管由
       * 事务按资源类型决定。 */
      if (!removing && error->error == -EEXIST) return FTUN_E_STALE;
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

const ftun_linux_route_io_t *ftun_platform_route_io(void)
{
  return &ftun_system_route_io;
}
ftun_status_t ftun_platform_route_close(int descriptor)
{
  return close(descriptor) == 0 ? FTUN_OK : FTUN_E_IO;
}
ftun_status_t ftun_platform_route_open(int *out)
{
  struct ftun_sockaddr_nl address = {0};
  int descriptor = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, FTUN_NETLINK_ROUTE);
  if (descriptor < 0) return ftun_linux_route_errno(errno, false);
  address.nl_family = AF_NETLINK;
  if (bind(descriptor, (struct sockaddr *)&address, sizeof(address)) < 0) {
    int error_code = errno;
    (void)close(descriptor);
    return ftun_linux_route_errno(error_code, false);
  }
  *out = descriptor;
  return FTUN_OK;
}
