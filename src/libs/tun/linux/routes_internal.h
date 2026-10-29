#ifndef FTUN_LIBS_TUN_LINUX_ROUTES_INTERNAL_H
#define FTUN_LIBS_TUN_LINUX_ROUTES_INTERNAL_H

#include "core/limits.h"
#include "libs/tun/linux/routes.h"
struct ftun_route_transaction {
  ftun_budget_t *budget;
  ftun_reservation_t reservation;
  uint32_t magic;
  ftun_linux_route_resource_t resources[FTUN_LINUX_ROUTE_MAX_RESOURCES];
  bool active[FTUN_LINUX_ROUTE_MAX_RESOURCES];
  size_t resource_count;
  size_t active_count;
  bool strict_route;
  bool retiring;
  ftun_linux_route_io_t io;
  /* 同一路由表号的实例互斥锁（-1 表示未持有）；转交给异步事务或随事务关闭。 */
  int lock_descriptor;
};

/* 以表号为键的 flock：第二个实例在改动网络前即被拒绝；table 为 0 时不加锁。 */
ftun_status_t ftun_linux_route_lock_table(uint32_t table, int *out);
int ftun_route_policy_valid(const ftun_route_policy_t *policy);
int ftun_route_build(const ftun_route_policy_t *policy,
                     ftun_route_transaction_t *transaction);
int ftun_linux_route_plan_valid(const ftun_linux_route_plan_t *plan);
size_t ftun_linux_route_async_allocation_size(void);

#endif
