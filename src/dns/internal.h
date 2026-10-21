#ifndef FTUN_DNS_INTERNAL_H
#define FTUN_DNS_INTERNAL_H

#include "dns/dispatcher.h"

struct ftun_dns_dispatcher {
  ftun_budget_t *budget;
  ftun_operation_queue_t *operations;
  ftun_dns_server_t **servers;
  ftun_dns_server_select_fn select_server;
  ftun_dns_named_server_select_fn select_named_server;
  void *select_user;
  ftun_reservation_t *reservation;
  size_t server_count;
  size_t inflight_local;
};

int ftun_dns_query_request_valid(const ftun_dns_query_t *query);
ftun_status_t ftun_dns_name_domain(ftun_dns_name_t name, char output[254],
                                   size_t *out_length);
ftun_status_t ftun_dns_local_answer(ftun_dns_dispatcher_t *dispatcher,
                                    const ftun_dns_query_t *query,
                                    uint16_t rcode, int with_address,
                                    uint32_t address,
                                    ftun_operation_t **out);

#endif
