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
static int ftun_netlink_attribute_next(const struct ftun_rtattr **attribute,
                                       size_t *remaining)
{
  size_t length;
  if (attribute == NULL || *attribute == NULL || remaining == NULL ||
      *remaining < sizeof(**attribute) ||
      (*attribute)->rta_len < sizeof(**attribute) ||
      (*attribute)->rta_len > *remaining) return 0;
  length = FTUN_RTA_ALIGN((*attribute)->rta_len);
  if (length > *remaining) return 0;
  *remaining -= length;
  *attribute = (const struct ftun_rtattr *)
    ((const uint8_t *)(*attribute) + length);
  return 1;
}

static int ftun_netlink_attribute_u32(const struct ftun_rtattr *attribute,
                                      uint32_t *out)
{
  if (attribute == NULL || out == NULL ||
      attribute->rta_len < FTUN_RTA_LENGTH(sizeof(*out))) return 0;
  memcpy(out, FTUN_RTA_DATA(attribute), sizeof(*out));
  return 1;
}

static int ftun_netlink_address_matches(
  const struct ftun_nlmsghdr *header,
  const ftun_route_resource_t *resource)
{
  const struct ftun_ifaddrmsg *address;
  const struct ftun_rtattr *attribute;
  size_t remaining;
  unsigned int interface_index = if_nametoindex(resource->interface_name);
  bool local = false;
  bool peer = false;
  if (interface_index == 0u ||
      header->nlmsg_len < FTUN_NLMSG_LENGTH(sizeof(*address))) return 0;
  address = (const struct ftun_ifaddrmsg *)FTUN_NLMSG_DATA(header);
  if (address->ifa_family != AF_INET ||
      address->ifa_prefixlen != resource->prefix_length ||
      address->ifa_index != interface_index) return 0;
  remaining = header->nlmsg_len - FTUN_NLMSG_LENGTH(sizeof(*address));
  attribute = (const struct ftun_rtattr *)
    ((const uint8_t *)address + FTUN_NLMSG_ALIGN(sizeof(*address)));
  while (remaining >= sizeof(*attribute)) {
    size_t value_length;
    if (attribute->rta_len < sizeof(*attribute) ||
        attribute->rta_len > remaining) return 0;
    value_length = attribute->rta_len - FTUN_RTA_LENGTH(0u);
    if (value_length >= 4u && attribute->rta_type == FTUN_IFA_LOCAL &&
        memcmp(FTUN_RTA_DATA(attribute), resource->address, 4u) == 0) {
      local = true;
    }
    if (value_length >= 4u && attribute->rta_type == FTUN_IFA_ADDRESS &&
        memcmp(FTUN_RTA_DATA(attribute), resource->address, 4u) == 0) {
      peer = true;
    }
    if (!ftun_netlink_attribute_next(&attribute, &remaining)) break;
  }
  return local || peer;
}

static int ftun_netlink_route_matches(
  const struct ftun_nlmsghdr *header,
  const ftun_route_resource_t *resource)
{
  const struct ftun_rtmsg *route;
  const struct ftun_rtattr *attribute;
  size_t remaining;
  uint32_t table;
  uint32_t output = 0u;
  uint32_t metric = 0u;
  unsigned int interface_index = 0u;
  bool destination = resource->prefix_length == 0u;
  bool unreachable = resource->kind == FTUN_LINUX_ROUTE_UNREACHABLE;
  if (!unreachable) {
    interface_index = if_nametoindex(resource->interface_name);
    if (interface_index == 0u) return 0;
  }
  if (header->nlmsg_len < FTUN_NLMSG_LENGTH(sizeof(*route))) return 0;
  route = (const struct ftun_rtmsg *)FTUN_NLMSG_DATA(header);
  if (route->rtm_family != AF_INET ||
      route->rtm_dst_len != resource->prefix_length ||
      route->rtm_protocol != resource->protocol ||
      route->rtm_scope != (unreachable ? FTUN_RT_SCOPE_UNIVERSE :
                                        FTUN_RT_SCOPE_LINK) ||
      route->rtm_type != (unreachable ? FTUN_RTN_UNREACHABLE :
                                      FTUN_RTN_UNICAST)) return 0;
  table = route->rtm_table;
  remaining = header->nlmsg_len - FTUN_NLMSG_LENGTH(sizeof(*route));
  attribute = (const struct ftun_rtattr *)
    ((const uint8_t *)route + FTUN_NLMSG_ALIGN(sizeof(*route)));
  while (remaining >= sizeof(*attribute)) {
    uint32_t value;
    if (attribute->rta_type == FTUN_RTA_TABLE &&
        ftun_netlink_attribute_u32(attribute, &value)) table = value;
    if (attribute->rta_type == FTUN_RTA_OIF &&
        ftun_netlink_attribute_u32(attribute, &value)) output = value;
    if (attribute->rta_type == FTUN_RTA_PRIORITY &&
        ftun_netlink_attribute_u32(attribute, &value)) metric = value;
    if (attribute->rta_type == FTUN_RTA_DST &&
        attribute->rta_len >= FTUN_RTA_LENGTH(4u) &&
        memcmp(FTUN_RTA_DATA(attribute), resource->address, 4u) == 0) {
      destination = true;
    }
    if (!ftun_netlink_attribute_next(&attribute, &remaining)) break;
  }
  return table == resource->table && destination &&
    (unreachable || output == interface_index) && metric == resource->metric;
}

static int ftun_netlink_rule_matches(
  const struct ftun_nlmsghdr *header,
  const ftun_route_resource_t *resource)
{
  const struct ftun_fib_rule_hdr *rule;
  const struct ftun_rtattr *attribute;
  size_t remaining;
  uint32_t table;
  uint32_t priority = 0u;
  uint32_t mark = 0u;
  uint32_t mask = 0u;
  uint8_t protocol = 0u;
  const char *interface_name = NULL;
  size_t interface_length = 0u;
  bool destination = resource->prefix_length == 0u;
  uint8_t expected_action = resource->kind == FTUN_LINUX_ROUTE_BLOCK_IPV6 ?
    FTUN_FR_ACT_UNREACHABLE : FTUN_FR_ACT_TO_TBL;
  if (header->nlmsg_len < FTUN_NLMSG_LENGTH(sizeof(*rule))) return 0;
  rule = (const struct ftun_fib_rule_hdr *)FTUN_NLMSG_DATA(header);
  if (rule->family != resource->family || rule->action != expected_action ||
      rule->dst_len != resource->prefix_length) {
    return 0;
  }
  table = rule->table;
  remaining = header->nlmsg_len - FTUN_NLMSG_LENGTH(sizeof(*rule));
  attribute = (const struct ftun_rtattr *)
    ((const uint8_t *)rule + FTUN_NLMSG_ALIGN(sizeof(*rule)));
  while (remaining >= sizeof(*attribute)) {
    uint32_t value;
    size_t value_length;
    if (attribute->rta_len < FTUN_RTA_LENGTH(0u) ||
        attribute->rta_len > remaining) return 0;
    value_length = attribute->rta_len - FTUN_RTA_LENGTH(0u);
    if (attribute->rta_type == FTUN_FRA_TABLE &&
        ftun_netlink_attribute_u32(attribute, &value)) table = value;
    if (attribute->rta_type == FTUN_FRA_PRIORITY &&
        ftun_netlink_attribute_u32(attribute, &value)) priority = value;
    if (attribute->rta_type == FTUN_FRA_FWMARK &&
        ftun_netlink_attribute_u32(attribute, &value)) mark = value;
    if (attribute->rta_type == FTUN_FRA_FWMASK &&
        ftun_netlink_attribute_u32(attribute, &value)) mask = value;
    if (attribute->rta_type == FTUN_FRA_DST && value_length >= 4u &&
        memcmp(FTUN_RTA_DATA(attribute), resource->address, 4u) == 0) {
      destination = true;
    }
    if (attribute->rta_type == FTUN_FRA_PROTOCOL && value_length >= 1u) {
      memcpy(&protocol, FTUN_RTA_DATA(attribute), 1u);
    }
    if (attribute->rta_type == FTUN_FRA_IIFNAME && value_length != 0u) {
      interface_name = (const char *)FTUN_RTA_DATA(attribute);
      interface_length = value_length;
    }
    if (!ftun_netlink_attribute_next(&attribute, &remaining)) break;
  }
  if (priority != resource->priority || protocol != resource->protocol) return 0;
  if (resource->kind == FTUN_LINUX_ROUTE_MARK_RULE) {
    return table == resource->table && mark == resource->mark &&
      mask == resource->mark_mask;
  }
  if (resource->kind == FTUN_LINUX_ROUTE_PROTECT_RULE) {
    return table == resource->table && destination;
  }
  if (resource->kind != FTUN_LINUX_ROUTE_BLOCK_IPV6 &&
      table != resource->table) return 0;
  return interface_name != NULL && interface_length != 0u &&
    strnlen(interface_name, interface_length) + 1u == interface_length &&
    strcmp(interface_name, resource->interface_name) == 0;
}

static int ftun_netlink_resource_matches(
  const struct ftun_nlmsghdr *header,
  const ftun_route_resource_t *resource)
{
  if (resource->kind == FTUN_LINUX_ROUTE_ADDRESS) {
    return header->nlmsg_type == FTUN_RTM_NEWADDR &&
      ftun_netlink_address_matches(header, resource);
  }
  if (resource->kind == FTUN_LINUX_ROUTE_DEFAULT ||
      resource->kind == FTUN_LINUX_ROUTE_OVERLAY ||
      resource->kind == FTUN_LINUX_ROUTE_UNREACHABLE) {
    return header->nlmsg_type == FTUN_RTM_NEWROUTE &&
      ftun_netlink_route_matches(header, resource);
  }
  return header->nlmsg_type == FTUN_RTM_NEWRULE &&
    ftun_netlink_rule_matches(header, resource);
}

static ftun_status_t ftun_netlink_query_build(
  ftun_netlink_message_t *message,
  const ftun_route_resource_t *resource)
{
  memset(message, 0, sizeof(*message));
  message->header.nlmsg_flags = FTUN_NLM_F_REQUEST | FTUN_NLM_F_DUMP;
  if (resource->kind == FTUN_LINUX_ROUTE_ADDRESS) {
    struct ftun_ifaddrmsg *address;
    message->header.nlmsg_type = FTUN_RTM_GETADDR;
    message->header.nlmsg_len = FTUN_NLMSG_LENGTH(sizeof(*address));
    address = (struct ftun_ifaddrmsg *)FTUN_NLMSG_DATA(&message->header);
    memset(address, 0, sizeof(*address));
    address->ifa_family = (uint8_t)resource->family;
  } else if (resource->kind == FTUN_LINUX_ROUTE_DEFAULT ||
             resource->kind == FTUN_LINUX_ROUTE_OVERLAY ||
             resource->kind == FTUN_LINUX_ROUTE_UNREACHABLE) {
    struct ftun_rtmsg *route;
    message->header.nlmsg_type = FTUN_RTM_GETROUTE;
    message->header.nlmsg_len = FTUN_NLMSG_LENGTH(sizeof(*route));
    route = (struct ftun_rtmsg *)FTUN_NLMSG_DATA(&message->header);
    memset(route, 0, sizeof(*route));
    route->rtm_family = (uint8_t)resource->family;
  } else {
    struct ftun_fib_rule_hdr *rule;
    message->header.nlmsg_type = FTUN_RTM_GETRULE;
    message->header.nlmsg_len = FTUN_NLMSG_LENGTH(sizeof(*rule));
    rule = (struct ftun_fib_rule_hdr *)FTUN_NLMSG_DATA(&message->header);
    memset(rule, 0, sizeof(*rule));
    rule->family = (uint8_t)resource->family;
  }
  return FTUN_OK;
}

ftun_status_t ftun_platform_route_submit(
  ftun_route_kernel_t *operation, const ftun_route_request_t *request)
{
  ftun_netlink_message_t message;
  struct ftun_sockaddr_nl address;
  ftun_status_t status;
  ssize_t result;
  int error_code;
  if (operation == NULL || request == NULL) return FTUN_E_INVALID;
  if (request->kind == FTUN_LINUX_ROUTE_REQUEST_QUERY) {
    status = ftun_netlink_query_build(&message, &request->resource);
  } else {
    status = ftun_netlink_build(&message, &request->resource,
      request->kind == FTUN_LINUX_ROUTE_REQUEST_ADD);
  }
  if (status != FTUN_OK) return status;
  message.header.nlmsg_seq = request->sequence;
  memset(&address, 0, sizeof(address));
  address.nl_family = AF_NETLINK;
  do {
    result = sendto(operation->descriptor, &message.header,
      message.header.nlmsg_len, MSG_DONTWAIT,
      (struct sockaddr *)&address, sizeof(address));
  } while (result < 0 && errno == EINTR);
  if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
    operation->write_interest = true;
    return FTUN_E_AGAIN;
  }
  if (result < 0 || (size_t)result != message.header.nlmsg_len) {
    error_code = result < 0 ? errno : EIO;
    return ftun_route_errno(error_code,
      request->kind == FTUN_LINUX_ROUTE_REQUEST_REMOVE);
  }
  operation->write_interest = false;
  operation->io_ready = false;
  if (request->kind == FTUN_LINUX_ROUTE_REQUEST_QUERY) {
    operation->query_resource = request->resource;
    operation->query_present = false;
  }
  return FTUN_OK;
}

ftun_status_t ftun_platform_route_receive(
  ftun_route_kernel_t *operation, ftun_route_reply_t *reply)
{
  struct ftun_sockaddr_nl source;
  socklen_t source_length = (socklen_t)sizeof(source);
  union { struct ftun_nlmsghdr alignment; uint8_t bytes[8192]; } storage;
  uint8_t *response = storage.bytes;
  struct ftun_nlmsghdr *header;
  ssize_t result;
  size_t remaining;
  if (operation == NULL || reply == NULL) return FTUN_E_INVALID;
  memset(reply, 0, sizeof(*reply));
  memset(&source, 0, sizeof(source));
  operation->io_ready = false;
  do {
    result = recvfrom(operation->descriptor, response, sizeof(storage.bytes),
      MSG_DONTWAIT | MSG_TRUNC, (struct sockaddr *)&source, &source_length);
  } while (result < 0 && errno == EINTR);
  if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
    if (operation->io_error) {
      operation->io_error = false;
      return FTUN_E_IO;
    }
    return FTUN_E_AGAIN;
  }
  if (result < 0) return ftun_route_errno(errno, false);
  if ((size_t)result > sizeof(storage.bytes)) return FTUN_E_LIMIT;
  if (source_length < sizeof(source) || source.nl_pid != 0u) return FTUN_E_IO;
  operation->io_error = false;
  remaining = (size_t)result;
  header = (struct ftun_nlmsghdr *)response;
  while (remaining >= sizeof(*header)) {
    size_t aligned_length;
    if (header->nlmsg_len < sizeof(*header) ||
        header->nlmsg_len > remaining) return FTUN_E_IO;
    aligned_length = FTUN_NLMSG_ALIGN(header->nlmsg_len);
    if (aligned_length > remaining) return FTUN_E_IO;
    if (header->nlmsg_seq != operation->pending_sequence) goto next_header;
    if (header->nlmsg_type == FTUN_NLMSG_OVERRUN) return FTUN_E_LIMIT;
    if (header->nlmsg_type == FTUN_NLMSG_ERROR) {
      const struct ftun_nlmsgerr *error =
        (const struct ftun_nlmsgerr *)FTUN_NLMSG_DATA(header);
      if (header->nlmsg_len < FTUN_NLMSG_LENGTH(sizeof(*error))) {
        return FTUN_E_IO;
      }
      reply->sequence = header->nlmsg_seq;
      reply->status = error->error == 0 ? FTUN_OK :
        ftun_route_errno(-error->error,
          operation->pending_kind == FTUN_LINUX_ROUTE_REQUEST_REMOVE);
      return FTUN_OK;
    }
    if (operation->pending_kind == FTUN_LINUX_ROUTE_REQUEST_QUERY) {
      if (ftun_netlink_resource_matches(header, &operation->query_resource)) {
        operation->query_present = true;
      }
      if (header->nlmsg_type == FTUN_NLMSG_DONE) {
        reply->sequence = header->nlmsg_seq;
        reply->status = (header->nlmsg_flags & FTUN_NLM_F_DUMP_INTR) != 0u ?
          FTUN_E_STATE_CORRUPT : FTUN_OK;
        reply->present = operation->query_present;
        return FTUN_OK;
      }
    }
next_header:
    remaining -= aligned_length;
    header = (struct ftun_nlmsghdr *)
      ((uint8_t *)header + aligned_length);
  }
  if (remaining != 0u) return FTUN_E_IO;
  operation->runnable = true;
  return FTUN_E_AGAIN;
}

