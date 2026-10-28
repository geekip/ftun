#ifndef FTUN_PROXY_DNS_DISPATCH_ADAPTER_H
#define FTUN_PROXY_DNS_DISPATCH_ADAPTER_H

#include "dns/dispatcher.h"

/* 
 * dispatch adapter 是 Proxy route/FakeIP 与独立 DNS dispatcher 的显式桥。 */
ftun_status_t ftun_proxy_dns_dispatch(
  void *user, ftun_core_t *core, ftun_dns_dispatcher_t *dispatcher,
  const ftun_dns_query_t *query, ftun_operation_t **out);
ftun_status_t ftun_proxy_dns_resolve_named_dispatcher(
  ftun_core_t *core, ftun_dns_dispatcher_t *dispatcher,
  ftun_string_t server, const ftun_bootstrap_request_t *request,
  ftun_operation_t **out);

#endif
