#define _GNU_SOURCE 1
#include "platform/iface.h"
#include "platform/linux/uapi.h"
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void ftun_netmon_note_interface(ftun_network_change_t *change, uint32_t index)
{
  size_t position;
  if (index == 0u) return;
  for (position = 0u; position < change->interface_count; position++) {
    if (change->interfaces[position] == index) return;
  }
  if (change->interface_count < FTUN_NETWORK_CHANGE_INTERFACES) {
    change->interfaces[change->interface_count++] = index;
  }
}

/* 路由消息里的出接口（RTA_OIF）。 */
static uint32_t ftun_netmon_route_interface(const struct ftun_nlmsghdr *header)
{
  const struct ftun_rtmsg *route;
  const struct ftun_rtattr *attribute;
  size_t remaining;
  if (header->nlmsg_len < FTUN_NLMSG_LENGTH(sizeof(*route))) return 0u;
  route = (const struct ftun_rtmsg *)FTUN_NLMSG_DATA(header);
  remaining = header->nlmsg_len - FTUN_NLMSG_LENGTH(sizeof(*route));
  attribute = (const struct ftun_rtattr *)
    ((const uint8_t *)route + FTUN_NLMSG_ALIGN(sizeof(*route)));
  while (remaining >= sizeof(*attribute) && attribute->rta_len >= sizeof(*attribute) &&
         attribute->rta_len <= remaining) {
    if (attribute->rta_type == FTUN_RTA_OIF &&
        attribute->rta_len >= FTUN_RTA_LENGTH(4u)) {
      uint32_t value;
      memcpy(&value, FTUN_RTA_DATA(attribute), sizeof(value));
      return value;
    }
    remaining -= FTUN_RTA_ALIGN(attribute->rta_len) < remaining
      ? FTUN_RTA_ALIGN(attribute->rta_len) : remaining;
    attribute = (const struct ftun_rtattr *)
      ((const uint8_t *)attribute + FTUN_RTA_ALIGN(attribute->rta_len));
  }
  return 0u;
}

size_t ftun_netmon_parse(const uint8_t *data, size_t length,
                         ftun_network_change_t *change)
{
  const struct ftun_nlmsghdr *header = (const struct ftun_nlmsghdr *)data;
  size_t remaining = length;
  size_t messages = 0u;
  if (data == NULL || change == NULL) return 0u;
  for (; FTUN_NLMSG_OK(header, remaining); header = FTUN_NLMSG_NEXT(header, remaining)) {
    switch (header->nlmsg_type) {
      case FTUN_RTM_NEWLINK:
      case FTUN_RTM_DELLINK:
        change->mask |= FTUN_NETWORK_CHANGE_LINK;
        if (header->nlmsg_len >= FTUN_NLMSG_LENGTH(sizeof(struct ftun_ifinfomsg))) {
          const struct ftun_ifinfomsg *info =
            (const struct ftun_ifinfomsg *)FTUN_NLMSG_DATA(header);
          ftun_netmon_note_interface(change, (uint32_t)info->ifi_index);
        }
        break;
      case FTUN_RTM_NEWADDR:
      case FTUN_RTM_DELADDR:
        change->mask |= FTUN_NETWORK_CHANGE_ADDRESS;
        if (header->nlmsg_len >= FTUN_NLMSG_LENGTH(sizeof(struct ftun_ifaddrmsg))) {
          const struct ftun_ifaddrmsg *info =
            (const struct ftun_ifaddrmsg *)FTUN_NLMSG_DATA(header);
          ftun_netmon_note_interface(change, info->ifa_index);
        }
        break;
      case FTUN_RTM_NEWROUTE:
      case FTUN_RTM_DELROUTE:
        change->mask |= FTUN_NETWORK_CHANGE_ROUTE;
        ftun_netmon_note_interface(change, ftun_netmon_route_interface(header));
        break;
      case FTUN_RTM_NEWRULE:
      case FTUN_RTM_DELRULE:
        change->mask |= FTUN_NETWORK_CHANGE_RULE;
        break;
      default:
        continue;
    }
    change->events++;
    messages++;
  }
  return messages;
}

ftun_status_t ftun_iface_subscribe(ftun_handle_t *descriptor)
{
  struct ftun_sockaddr_nl address = {0};
  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, FTUN_NETLINK_ROUTE);
  if (fd < 0) return FTUN_E_UNSUPPORTED;
  address.nl_family = AF_NETLINK;
  address.nl_groups = FTUN_RTMGRP_LINK | FTUN_RTMGRP_IPV4_IFADDR |
    FTUN_RTMGRP_IPV4_ROUTE | FTUN_RTMGRP_IPV4_RULE;
  if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    (void)close(fd);
    return FTUN_E_UNSUPPORTED;
  }
  *descriptor = fd;
  return FTUN_OK;
}
ftun_status_t ftun_iface_receive(ftun_handle_t descriptor, void *data, size_t capacity, size_t *received)
{
  ssize_t length = recv((int)descriptor, data, capacity, MSG_DONTWAIT);
  *received = 0u;
  if (length < 0) {
    if (errno == EINTR) return FTUN_OK;
    if (errno == ENOBUFS) return FTUN_E_LIMIT;
    return errno == EAGAIN || errno == EWOULDBLOCK ? FTUN_E_AGAIN : FTUN_E_IO;
  }
  if (length == 0) return FTUN_E_EOF;
  *received = (size_t)length;
  return FTUN_OK;
}
