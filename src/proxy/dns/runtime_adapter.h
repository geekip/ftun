#ifndef FTUN_PROXY_DNS_RUNTIME_ADAPTER_H
#define FTUN_PROXY_DNS_RUNTIME_ADAPTER_H

#include "libs/resolver/basic.h"
typedef struct ftun_dns_service_slot ftun_dns_service_slot_t;


/* Composition 拥有适配器和槽；Proxy/DNS 只借用。DNS service 通过中立
 * callback 使用策略选择，Proxy runtime 通过窄函数借用当前 DNS generation。 */
typedef struct ftun_proxy_dns_runtime_adapter ftun_proxy_dns_runtime_adapter_t;
typedef struct {
  bool (*has_hijack)(const ftun_proxy_dns_runtime_adapter_t *adapter);
  ftun_status_t (*tcp)(const ftun_proxy_dns_runtime_adapter_t *adapter, int descriptor);
  ftun_status_t (*udp)(const ftun_proxy_dns_runtime_adapter_t *adapter,
    ftun_datagram_t *inbound, const ftun_endpoint_t *client, const ftun_packet_t *packet);
} ftun_proxy_dns_hooks_t;
struct ftun_proxy_dns_runtime_adapter {
  ftun_core_t *core;
  ftun_dns_service_slot_t *slot;
  ftun_fakeip_service_t *const *fakeip_slot;
  const ftun_proxy_dns_hooks_t *hooks;
};

bool ftun_proxy_dns_runtime_adapter_valid(
  const ftun_proxy_dns_runtime_adapter_t *adapter);
ftun_status_t ftun_proxy_dns_select_member(
  void *user, const ftun_config_t *expected_config,
  uint32_t group_id, uint32_t *out_member);
bool ftun_proxy_dns_has_hijack(
  const ftun_proxy_dns_runtime_adapter_t *adapter);
ftun_status_t ftun_proxy_dns_hijack_tcp(
  const ftun_proxy_dns_runtime_adapter_t *adapter, int descriptor);
ftun_status_t ftun_proxy_dns_hijack_udp(
  const ftun_proxy_dns_runtime_adapter_t *adapter, ftun_datagram_t *inbound,
  const ftun_endpoint_t *client, const ftun_packet_t *packet);
ftun_status_t ftun_proxy_dns_resolve_named(
  const ftun_proxy_dns_runtime_adapter_t *adapter,
  const ftun_bootstrap_request_t *request, ftun_string_t server,
  ftun_operation_t **out);

#endif
