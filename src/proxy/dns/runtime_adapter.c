#include "proxy/dns/runtime_adapter.h"

#include "proxy/dns/dispatch_adapter.h"
#include "proxy/runtime_state.h"

bool ftun_proxy_dns_runtime_adapter_valid(
  const ftun_proxy_dns_runtime_adapter_t *adapter)
{
  return adapter != NULL && adapter->core != NULL && adapter->slot != NULL;
}

ftun_status_t ftun_proxy_dns_select_member(
  void *user, const ftun_config_t *expected_config,
  uint32_t group_id, uint32_t *out_member)
{
  const ftun_proxy_dns_runtime_adapter_t *adapter =
    (const ftun_proxy_dns_runtime_adapter_t *)user;
  ftun_runtime_t *runtime = NULL;
  const ftun_config_t *config = NULL;
  bool is_group = false;
  bool degraded = false;
  ftun_string_t dns_server;
  ftun_status_t status;
  if (out_member != NULL) *out_member = 0u;
  if (!ftun_proxy_dns_runtime_adapter_valid(adapter) ||
      expected_config == NULL || out_member == NULL) {
    return FTUN_E_INVALID;
  }
  status = ftun_runtime_active_acquire(adapter->core, &runtime);
  if (status == FTUN_OK) status = ftun_runtime_config(runtime, &config);
  if (status == FTUN_OK && config != expected_config) status = FTUN_E_STALE;
  if (status == FTUN_OK) {
    status = ftun_runtime_group_selected(runtime, group_id, out_member,
                                          &is_group, &degraded, &dns_server);
  }
  (void)degraded;
  (void)dns_server;
  if (status == FTUN_OK && !is_group) status = FTUN_E_STATE_CORRUPT;
  if (runtime != NULL && ftun_runtime_release(&runtime) != FTUN_OK &&
      status == FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
  }
  if (status != FTUN_OK) *out_member = 0u;
  return status;
}

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

bool ftun_proxy_dns_has_hijack(
  const ftun_proxy_dns_runtime_adapter_t *adapter)
{
  ftun_dns_runtime_t *dns = NULL;
  return ftun_proxy_dns_runtime_get(adapter, &dns) == FTUN_OK &&
    ftun_dns_runtime_has_hijack(dns);
}

ftun_status_t ftun_proxy_dns_hijack_tcp(
  const ftun_proxy_dns_runtime_adapter_t *adapter, int descriptor)
{
  ftun_dns_runtime_t *dns = NULL;
  ftun_status_t status = ftun_proxy_dns_runtime_get(adapter, &dns);
  return status == FTUN_OK
    ? ftun_dns_runtime_hijack_tcp(dns, descriptor) : status;
}

ftun_status_t ftun_proxy_dns_hijack_udp(
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

bool ftun_proxy_dns_has_hijack(
  const ftun_proxy_dns_runtime_adapter_t *adapter)
{
  (void)adapter;
  return false;
}

ftun_status_t ftun_proxy_dns_hijack_tcp(
  const ftun_proxy_dns_runtime_adapter_t *adapter, int descriptor)
{
  (void)adapter;
  (void)descriptor;
  return FTUN_E_UNSUPPORTED;
}

ftun_status_t ftun_proxy_dns_hijack_udp(
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
