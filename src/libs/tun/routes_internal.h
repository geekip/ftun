#ifndef FTUN_LIBS_TUN_ROUTES_INTERNAL_H
#define FTUN_LIBS_TUN_ROUTES_INTERNAL_H
#include "libs/tun/routes.h"
#include "core/limits.h"
struct ftun_route_transaction {
  ftun_platform_route_transaction_t *native;
  ftun_reservation_t reservation;
  ftun_budget_t *budget;
  bool system;
};
#endif
