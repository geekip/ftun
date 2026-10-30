#include "app/composition/bridges.h"
#include "dns/module.h"
#include "proxy/dns/runtime_adapter.h"

#include "app/composition/dns_dispatch.h"
#include "proxy/runtime_state.h"

#if defined(FTUN_HAVE_MODULE_DNS)

static ftun_status_t ftun_proxy_dns_runtime_get(
  const ftun_proxy_dns_runtime_adapter_t *adapter, ftun_dns_runtime_t **out)
{
  if (out != NULL) *out = NULL;
  if (!ftun_proxy_dns_runtime_adapter_valid(adapter) || out == NULL) {
    return FTUN_E_INVALID;
  }
  return ftun_dns_service_slot_get(adapter->slot, out);
}

bool bridge_has_hijack(
  const ftun_proxy_dns_runtime_adapter_t *adapter)
{
  ftun_dns_runtime_t *dns = NULL;
  return ftun_proxy_dns_runtime_get(adapter, &dns) == FTUN_OK &&
    ftun_dns_runtime_has_hijack(dns);
}

ftun_status_t bridge_tcp(
  const ftun_proxy_dns_runtime_adapter_t *adapter, ftun_handle_t descriptor)
{
  ftun_dns_runtime_t *dns = NULL;
  ftun_status_t status = ftun_proxy_dns_runtime_get(adapter, &dns);
  return status == FTUN_OK
    ? ftun_dns_runtime_hijack_tcp(dns, descriptor) : status;
}

ftun_status_t bridge_udp(
  const ftun_proxy_dns_runtime_adapter_t *adapter, ftun_datagram_t *inbound,
  const ftun_endpoint_t *client, const ftun_packet_t *packet)
{
  ftun_dns_runtime_t *dns = NULL;
  ftun_status_t status = ftun_proxy_dns_runtime_get(adapter, &dns);
  return status == FTUN_OK
    ? ftun_dns_runtime_hijack_udp(dns, inbound, client, packet) : status;
}

ftun_status_t ftun_proxy_dns_resolve_named(
  const ftun_proxy_dns_runtime_adapter_t *adapter,
  const ftun_bootstrap_request_t *request, ftun_string_t server,
  ftun_operation_t **out)
{
  ftun_dns_runtime_t *dns = NULL;
  ftun_dns_dispatcher_t *dispatcher = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (request == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_proxy_dns_runtime_get(adapter, &dns);
  if (status == FTUN_OK) status = ftun_dns_runtime_dispatcher(dns, &dispatcher);
  if (status != FTUN_OK) return status;
  return ftun_proxy_dns_resolve_named_dispatcher(
    adapter->core, dispatcher, server, request, out);
}

#else

bool bridge_has_hijack(
  const ftun_proxy_dns_runtime_adapter_t *adapter)
{
  (void)adapter;
  return false;
}

ftun_status_t bridge_tcp(
  const ftun_proxy_dns_runtime_adapter_t *adapter, ftun_handle_t descriptor)
{
  (void)adapter;
  (void)descriptor;
  return FTUN_E_UNSUPPORTED;
}

ftun_status_t bridge_udp(
  const ftun_proxy_dns_runtime_adapter_t *adapter, ftun_datagram_t *inbound,
  const ftun_endpoint_t *client, const ftun_packet_t *packet)
{
  (void)adapter;
  (void)inbound;
  (void)client;
  (void)packet;
  return FTUN_E_UNSUPPORTED;
}

ftun_status_t ftun_proxy_dns_resolve_named(
  const ftun_proxy_dns_runtime_adapter_t *adapter,
  const ftun_bootstrap_request_t *request, ftun_string_t server,
  ftun_operation_t **out)
{
  (void)adapter;
  (void)request;
  (void)server;
  if (out != NULL) *out = NULL;
  return FTUN_E_UNSUPPORTED;
}

#endif

void ftun_app_dns_bridge_init(ftun_proxy_dns_runtime_adapter_t *adapter)
{
  static const ftun_proxy_dns_hooks_t hooks = {bridge_has_hijack, bridge_tcp, bridge_udp};
  adapter->hooks = &hooks;
}
