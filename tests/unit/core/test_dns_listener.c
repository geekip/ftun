#include "app/composition/bridges.h"
#include "core/limits.h"
#include "core/operation.h"
#include "proxy/runtime_state.h"
#include "dns/listener.h"
#include "app/composition/dns_dispatch.h"
#include "proxy/fakeip/pool.h"
#include "proxy/dns/runtime_adapter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "dns listener contract failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  ftun_dns_transport_completion_fn completion;
  void *user;
  ftun_endpoint_t source;
  ftun_dns_transport_t protocol;
  int pending;
} transport_t;

typedef struct {
  unsigned int calls;
  ftun_dns_transport_t transport;
  uint64_t peer;
  ftun_status_t status;
  uint8_t response[1026];
  size_t length;
} reply_t;

static ftun_status_t transport_select(void *user, uint32_t root,
  ftun_dns_transport_binding_t *out)
{
  memset(out, 0, sizeof(*out));
  out->scope = user;
  out->root_id = root;
  out->leaf_id = root;
  return FTUN_OK;
}

static ftun_status_t transport_submit(
  void *user, const ftun_dns_transport_binding_t *binding,
  uint64_t policy_fingerprint,
  uint64_t server_fingerprint, const ftun_endpoint_t *upstream,
  ftun_dns_transport_t protocol, ftun_bytes_t query, uint64_t deadline,
  ftun_dns_transport_completion_fn completion, void *completion_user,
  void **out_request)
{
  transport_t *transport = (transport_t *)user;
  (void)binding;
  (void)policy_fingerprint;
  (void)server_fingerprint;
  (void)query;
  (void)deadline;
  if (transport->pending) return FTUN_E_LIMIT;
  transport->completion = completion;
  transport->user = completion_user;
  transport->source = *upstream;
  transport->protocol = protocol;
  transport->pending = 1;
  *out_request = transport;
  return FTUN_OK;
}

static ftun_status_t transport_cancel(void *user, void **request)
{
  transport_t *transport = (transport_t *)user;
  if (request == NULL || *request != transport || !transport->pending) {
    return FTUN_E_INVALID;
  }
  transport->pending = 0;
  *request = NULL;
  return FTUN_OK;
}

static void transport_deliver(transport_t *transport, ftun_bytes_t response)
{
  ftun_dns_transport_completion_fn completion = transport->completion;
  void *user = transport->user;
  transport->pending = 0;
  transport->completion = NULL;
  completion(user, FTUN_OK, transport->protocol, &transport->source, response);
}

static void reply(ftun_dns_transport_t transport, uint64_t peer,
                  ftun_error_t error, ftun_bytes_t response, void *user)
{
  reply_t *result = (reply_t *)user;
  result->calls++;
  result->transport = transport;
  result->peer = peer;
  result->status = error.status;
  result->length = response.length;
  if (response.data != NULL && response.length <= sizeof(result->response)) {
    memcpy(result->response, response.data, response.length);
  }
}

static void query(uint8_t wire[27], uint16_t type)
{
  static const uint8_t name[] = {1u,'a',7u,'e','x','a','m','p','l','e',0u};
  memset(wire, 0, 27u);
  wire[0] = 0x22u; wire[1] = 0x33u;
  wire[2] = 0x01u; wire[5] = 1u;
  memcpy(wire + 12u, name, sizeof(name));
  wire[23] = (uint8_t)(type >> 8u); wire[24] = (uint8_t)type;
  wire[25] = 0u; wire[26] = 1u;
}

static void large_response(uint8_t wire[539])
{
  query(wire, 16u);
  wire[2] = 0x81u; wire[3] = 0x80u; wire[7] = 1u;
  wire[27] = 0xc0u; wire[28] = 0x0cu;
  wire[29] = 0u; wire[30] = 16u;
  wire[31] = 0u; wire[32] = 1u;
  wire[36] = 60u;
  wire[37] = 0x01u; wire[38] = 0xf4u;
  memset(wire + 39u, 0x5au, 500u);
}

static ftun_status_t select_server(uint32_t outbound, size_t *out, void *user)
{
  (void)outbound;
  (void)user;
  *out = 0u;
  return FTUN_OK;
}

static int dispatch(ftun_operation_queue_t *operations)
{
  size_t count = 0u;
  return ftun_operation_dispatch(operations, 8u, &count) == FTUN_OK &&
         count == 1u;
}

int main(void)
{
  ftun_budget_t *budget = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_core_t *core = NULL;
  ftun_fakeip_service_t *fakeip = NULL;
  ftun_dns_server_t *server = NULL;
  ftun_dns_server_t *servers[1];
  ftun_dns_dispatcher_t *dispatcher = NULL;
  ftun_dns_listener_t *listener = NULL;
  ftun_dns_connection_t *connection = NULL;
  ftun_dns_connection_t *duplicate = NULL;
  ftun_operation_t *operation = NULL;
  ftun_fakeip_service_options_t fake_options;
  ftun_dns_server_options_t server_options;
  ftun_dns_dispatcher_options_t dispatcher_options;
  ftun_dns_listener_spec_t spec;
  ftun_proxy_dns_runtime_adapter_t dns_adapter;
  ftun_dns_listener_info_t info;
  transport_t transport;
  reply_t result;
  uint8_t request[27];
  uint8_t response[539];
  uint8_t framed[58];
  size_t consumed;
  size_t frames;
  memset(&fake_options, 0, sizeof(fake_options));
  memset(&server_options, 0, sizeof(server_options));
  memset(&dispatcher_options, 0, sizeof(dispatcher_options));
  memset(&spec, 0, sizeof(spec));
  memset(&dns_adapter, 0, sizeof(dns_adapter));
  memset(&transport, 0, sizeof(transport));
  memset(&result, 0, sizeof(result));
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 8u, &operations) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 1u, &core) == FTUN_OK);
  fake_options.budget = budget;
  fake_options.first_address = UINT32_C(0xc6120001);
  fake_options.end_address_exclusive = UINT32_C(0xc6120010);
  fake_options.max_entries = 8u;
  CHECK(ftun_fakeip_service_create(&fake_options, &fakeip) == FTUN_OK);
  server_options.budget = budget;
  server_options.operations = operations;
  server_options.upstream.kind = FTUN_ADDRESS_IPV4;
  server_options.upstream.address[0] = 192u;
  server_options.upstream.address[1] = 0u;
  server_options.upstream.address[2] = 2u;
  server_options.upstream.address[3] = 53u;
  server_options.upstream.port = 53u;
  server_options.outbound_id = 7u;
  server_options.fingerprint = 8u;
  server_options.transport = FTUN_DNS_TRANSPORT_UDP;
  server_options.tcp_fallback = true;
  server_options.fakeip = true;
  server_options.max_response_bytes = 1024u;
  server_options.query_transport.select = transport_select;
  server_options.query_transport.submit = transport_submit;
  server_options.query_transport.cancel = transport_cancel;
  server_options.query_transport.context = &transport;
  CHECK(ftun_dns_server_create(&server_options, &server) == FTUN_OK);
  servers[0] = server;
  dispatcher_options.budget = budget;
  dispatcher_options.operations = operations;
  dispatcher_options.servers = servers;
  dispatcher_options.server_count = 1u;
  dispatcher_options.select_server = select_server;
  CHECK(ftun_dns_dispatcher_create(&dispatcher_options, &dispatcher) == FTUN_OK);
  dns_adapter.core = core;
  ftun_app_dns_bridge_init(&dns_adapter);
  dns_adapter.fakeip_slot = &fakeip;
  spec.budget = budget;
  spec.dispatcher = dispatcher;
  spec.dispatch = ftun_proxy_dns_dispatch;
  spec.dispatch_user = &dns_adapter;
  spec.entry = FTUN_DNS_ENTRY_FIXED;
  spec.fixed_server = 0u;
  spec.query_timeout_ms = 5000u;
  spec.udp_payload_limit = 512u;
  spec.max_tcp_connections = 1u;
  spec.max_tcp_inflight = 1u;
  spec.max_tcp_frame_bytes = 1024u;
  spec.reply = reply;
  spec.reply_user = &result;
  CHECK(ftun_dns_listen(core, &spec, &listener) == FTUN_OK);

  query(request, 16u);
  CHECK(ftun_dns_listener_receive_udp(listener, 100u,
    (ftun_bytes_t){request, sizeof(request)}, &operation) == FTUN_OK &&
    transport.pending);
  large_response(response);
  transport_deliver(&transport, (ftun_bytes_t){response, sizeof(response)});
  CHECK(dispatch(operations) && result.calls == 1u &&
        result.transport == FTUN_DNS_TRANSPORT_UDP && result.peer == 100u &&
        result.length == 27u && (result.response[2] & 0x02u) != 0u &&
        result.response[7] == 0u);

  CHECK(ftun_dns_listener_tcp_open(listener, 200u, &connection) == FTUN_OK);
  CHECK(ftun_dns_listener_tcp_open(listener, 201u, &duplicate) == FTUN_E_LIMIT);
  query(request, 1u);
  framed[0] = 0u; framed[1] = 27u;
  memcpy(framed + 2u, request, 27u);
  memcpy(framed + 29u, framed, 29u);
  CHECK(ftun_dns_connection_feed(connection,
    (ftun_bytes_t){framed, 1u}, &consumed, &frames) == FTUN_OK &&
    consumed == 1u && frames == 0u);
  CHECK(ftun_dns_connection_feed(connection,
    (ftun_bytes_t){framed + 1u, 57u}, &consumed, &frames) == FTUN_E_LIMIT &&
    consumed == 28u && frames == 1u);
  CHECK(ftun_dns_connection_close(&connection) == FTUN_E_AGAIN);
  CHECK(dispatch(operations) && result.calls == 2u &&
        result.transport == FTUN_DNS_TRANSPORT_TCP && result.peer == 200u &&
        result.length == 45u && result.response[0] == 0u &&
        result.response[1] == 43u);
  CHECK(ftun_dns_connection_feed(connection,
    (ftun_bytes_t){framed + 29u, 29u}, &consumed, &frames) == FTUN_OK &&
    consumed == 29u && frames == 1u);
  CHECK(dispatch(operations) && result.calls == 3u);
  CHECK(ftun_dns_listener_get_info(listener, &info) == FTUN_OK &&
        info.tcp_connections == 1u && info.inflight == 0u && info.accepting);
  query(request, 16u);
  CHECK(ftun_dns_listener_receive_udp(listener, 101u,
    (ftun_bytes_t){request, sizeof(request)}, &operation) == FTUN_OK && transport.pending);
  transport.pending = 0;
  transport.completion(transport.user, FTUN_E_RESOLVE, transport.protocol,
    &transport.source, (ftun_bytes_t){NULL, 0u});
  CHECK(dispatch(operations) && result.calls == 4u && result.status == FTUN_OK &&
        result.length == 27u && result.response[0] == 0x22u && result.response[1] == 0x33u &&
        result.response[2] == 0x81u && result.response[3] == 0x82u);
  CHECK(ftun_dns_connection_close(&connection) == FTUN_OK);
  CHECK(ftun_dns_listener_stop(listener) == FTUN_OK);
  CHECK(ftun_dns_listener_tcp_open(listener, 300u, &connection) ==
        FTUN_E_CANCELLED);
  CHECK(ftun_dns_listener_receive_udp(listener, 300u,
    (ftun_bytes_t){request, sizeof(request)}, &operation) == FTUN_E_CANCELLED);
  CHECK(ftun_dns_listener_destroy(&listener) == FTUN_OK);

  CHECK(ftun_dns_dispatcher_destroy(&dispatcher) == FTUN_OK);
  CHECK(ftun_dns_server_destroy(&server) == FTUN_OK);
  CHECK(ftun_fakeip_service_destroy(&fakeip) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}
