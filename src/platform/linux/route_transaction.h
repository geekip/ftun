#ifndef FTUN_PLATFORM_LINUX_ROUTE_TRANSACTION_H
#define FTUN_PLATFORM_LINUX_ROUTE_TRANSACTION_H

#include "platform/linux/route.h"
struct ftun_platform_route_transaction {
  uint32_t magic;
  ftun_route_resource_t resources[FTUN_LINUX_ROUTE_MAX_RESOURCES];
  bool active[FTUN_LINUX_ROUTE_MAX_RESOURCES];
  size_t resource_count;
  size_t active_count;
  bool strict_route;
  bool retiring;
  ftun_route_io_t io;
  /* 同一路由表号的实例互斥锁（-1 表示未持有）；转交给异步事务或随事务关闭。 */
  ftun_handle_t lock_descriptor;
};

/* 以表号为键的 flock：第二个实例在改动网络前即被拒绝；table 为 0 时不加锁。 */
ftun_status_t ftun_route_lock_table(uint32_t table, ftun_handle_t *out);
int ftun_route_policy_valid(const ftun_route_policy_t *policy);
int ftun_route_build(const ftun_route_policy_t *policy,
                     ftun_platform_route_transaction_t *transaction);
int ftun_route_plan_valid(const ftun_route_plan_t *plan);
size_t ftun_platform_route_async_allocation_size(void);

#endif
