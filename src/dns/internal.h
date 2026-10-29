#ifndef FTUN_DNS_INTERNAL_H
#define FTUN_DNS_INTERNAL_H

#include "core/limits.h"
#include "dns/dispatcher.h"

struct ftun_dns_dispatcher {
  ftun_budget_t *budget;
  const ftun_config_t *config_scope;
  ftun_operation_queue_t *operations;
  ftun_dns_server_t **servers;
  ftun_dns_server_select_fn select_server;
  ftun_dns_named_server_select_fn select_named_server;
  void *select_user;
  ftun_reservation_t reservation;
  size_t server_count;
  size_t inflight_local;
};

ftun_status_t ftun_dns_query_request_validate(ftun_budget_t *budget, const ftun_dns_query_t *query);

#endif
