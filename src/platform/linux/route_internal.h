#ifndef FTUN_PLATFORM_LINUX_ROUTE_INTERNAL_H
#define FTUN_PLATFORM_LINUX_ROUTE_INTERNAL_H
#include "platform/linux/route.h"
#include "platform/linux/uapi.h"

#define FTUN_NETLINK_MESSAGE_BYTES 512u

typedef struct {
  struct ftun_nlmsghdr header;
  uint8_t body[FTUN_NETLINK_MESSAGE_BYTES - sizeof(struct ftun_nlmsghdr)];
} ftun_netlink_message_t;

ftun_status_t ftun_netlink_build(
  ftun_netlink_message_t *message,
  const ftun_route_resource_t *resource, bool add);
ftun_status_t ftun_route_errno(int error_code, bool removing);
#endif
