#include "proxy/dns/runtime_adapter.h"
bool ftun_proxy_dns_runtime_adapter_valid(const ftun_proxy_dns_runtime_adapter_t *adapter)
{
  return adapter && adapter->core && adapter->slot && adapter->hooks;
}
bool ftun_proxy_dns_has_hijack(const ftun_proxy_dns_runtime_adapter_t *adapter)
{
  return ftun_proxy_dns_runtime_adapter_valid(adapter) && adapter->hooks->has_hijack(adapter);
}
ftun_status_t ftun_proxy_dns_hijack_tcp(const ftun_proxy_dns_runtime_adapter_t *adapter, ftun_handle_t descriptor)
{
  return ftun_proxy_dns_runtime_adapter_valid(adapter)
    ? adapter->hooks->tcp(adapter, descriptor) : FTUN_E_INVALID;
}
ftun_status_t ftun_proxy_dns_hijack_udp(const ftun_proxy_dns_runtime_adapter_t *adapter,
  ftun_datagram_t *inbound, const ftun_endpoint_t *client, const ftun_packet_t *packet)
{
  return ftun_proxy_dns_runtime_adapter_valid(adapter)
    ? adapter->hooks->udp(adapter, inbound, client, packet) : FTUN_E_INVALID;
}
