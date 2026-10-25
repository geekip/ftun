#ifndef FTUN_PLATFORM_LINUX_ROUTE_INTERNAL_H
#define FTUN_PLATFORM_LINUX_ROUTE_INTERNAL_H

#include "platform/linux/route.h"
#include "platform/linux/uapi.h"

#define FTUN_NETLINK_MESSAGE_BYTES 512u

typedef struct {
  struct ftun_nlmsghdr header;
  uint8_t body[FTUN_NETLINK_MESSAGE_BYTES - sizeof(struct ftun_nlmsghdr)];
} ftun_netlink_message_t;

struct ftun_route_transaction {
  ftun_budget_t *budget;
  ftun_reservation_t *reservation;
  uint32_t magic;
  ftun_linux_route_resource_t resources[FTUN_LINUX_ROUTE_MAX_RESOURCES];
  bool active[FTUN_LINUX_ROUTE_MAX_RESOURCES];
  size_t resource_count;
  size_t active_count;
  bool strict_route;
  bool retiring;
  ftun_linux_route_io_t io;
};

ftun_status_t ftun_linux_route_errno(int error_code, bool removing);
int ftun_route_policy_valid(const ftun_route_policy_t *policy);
int ftun_route_build(const ftun_route_policy_t *policy,
                     ftun_route_transaction_t *transaction);
int ftun_linux_route_plan_valid(const ftun_linux_route_plan_t *plan);
ftun_status_t ftun_netlink_build(
  ftun_netlink_message_t *message,
  const ftun_linux_route_resource_t *resource, bool add);
size_t ftun_linux_route_async_allocation_size(void);

#endif
