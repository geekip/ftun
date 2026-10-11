#ifndef FTUN_CORE_ENGINE_DNS_H
#define FTUN_CORE_ENGINE_DNS_H

#include "config/model.h"
#include "core/budget.h"
#include "core/operation.h"
#include "core/worker.h"
#include "internal/contracts.h"

#include <stdbool.h>

typedef struct ftun_engine_dns ftun_engine_dns_t;

typedef struct {
  ftun_endpoint_t upstream;
  ftun_endpoint_t proxy;
  ftun_string_t proxy_username;
  ftun_string_t proxy_password;
  uint32_t socket_mark;
  bool tcp;
  bool use_proxy;
} ftun_engine_dns_blocking_query_t;

/* Shared protected DNS transport used by control-endpoint resolution.  The
 * caller owns all input views for the duration of this synchronous call. */
ftun_status_t ftun_engine_dns_query_blocking(
  const ftun_engine_dns_blocking_query_t *query, ftun_bytes_t wire,
  uint8_t *response, size_t response_capacity, size_t *out_response_size);

ftun_status_t ftun_engine_dns_prepare(
  ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations, ftun_worker_t *worker,
  const ftun_config_t *config, ftun_fakeip_service_t *fakeip,
  ftun_engine_dns_t **out);
ftun_status_t ftun_engine_dns_prepare_reload(
  const ftun_engine_dns_t *active, ftun_core_t *core,
  ftun_budget_t *budget, ftun_operation_queue_t *operations,
  ftun_worker_t *worker, const ftun_config_t *config,
  ftun_fakeip_service_t *fakeip, ftun_engine_dns_t **out);
ftun_status_t ftun_engine_dns_commit_reload(ftun_engine_dns_t **active,
                                             ftun_engine_dns_t **prepared);
ftun_status_t ftun_engine_dns_activate(ftun_engine_dns_t *dns);
ftun_status_t ftun_engine_dns_run_once(ftun_engine_dns_t *dns);
bool ftun_engine_dns_has_hijack(const ftun_engine_dns_t *dns);
/* Takes ownership of descriptor on success and attaches it to the same
 * policy DNS protocol used by TUN UDP/53 hijack. */
ftun_status_t ftun_engine_dns_hijack_tcp(ftun_engine_dns_t *dns,
                                         int descriptor);
ftun_status_t ftun_engine_dns_hijack_udp(
  ftun_engine_dns_t *dns, ftun_datagram_t *inbound,
  const ftun_endpoint_t *client, const ftun_packet_t *packet);
ftun_status_t ftun_engine_dns_stop(ftun_engine_dns_t *dns);
ftun_status_t ftun_engine_dns_destroy(ftun_engine_dns_t **dns);

#endif
