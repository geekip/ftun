#include "proxy/outbound/socks5.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "outbound socks5 contract failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

#define SOCKET_BASE 100u
#define MAX_SOCKETS 8u
#define SCRIPT_BYTES 2048u

typedef struct {
  ftun_event_source_t *io_source;
  ftun_event_source_t *timer_source;
  int cancel_failures;
  int cancel_calls;
} backend_state_t;

typedef struct {
  ftun_status_t open_status[MAX_SOCKETS];
  ftun_status_t protect_status[MAX_SOCKETS];
  ftun_status_t connect_status[MAX_SOCKETS];
  ftun_status_t socket_error_status[MAX_SOCKETS];
  ftun_endpoint_t endpoints[MAX_SOCKETS];
  ftun_dial_transport_t transports[MAX_SOCKETS];
  uint32_t marks[MAX_SOCKETS];
  char devices[MAX_SOCKETS][FTUN_SOCKET_INTERFACE_BYTES];
  size_t open_calls;
  size_t protect_calls;
  size_t connect_calls;
  size_t close_calls;
  int closed[MAX_SOCKETS];
} socket_state_t;

typedef struct {
  uint8_t server[SCRIPT_BYTES];
  size_t server_length;
  size_t server_offset;
  uint8_t client[SCRIPT_BYTES];
  size_t client_length;
  size_t max_send;
  size_t max_receive;
  ftun_status_t send_status;
  ftun_status_t receive_status;
  size_t send_calls;
  size_t receive_calls;
} protocol_state_t;

typedef struct {
  int calls;
  ftun_error_t error;
  ftun_socks5_connection_t *connection;
  ftun_operation_t *operation;
} completion_state_t;

typedef struct {
  ftun_budget_t *budget;
  ftun_operation_queue_t *operations;
  ftun_event_loop_t *loop;
  backend_state_t backend;
  socket_state_t socket;
  protocol_state_t protocol;
  completion_state_t completion;
  ftun_dial_io_t dial_io;
  ftun_socks5_io_t protocol_io;
  ftun_endpoint_t proxy_resolved[2];
  ftun_endpoint_t target_candidates[2];
  ftun_socks5_proxy_t proxy;
  ftun_target_t target;
  ftun_socks5_connect_request_t request;
  char device[8];
} fixture_t;

static ftun_status_t backend_io_start(void *user, ftun_event_source_t *source,
                                      ftun_native_socket_t socket,
                                      uint32_t interests)
{
  backend_state_t *state = (backend_state_t *)user;
  (void)socket;
  (void)interests;
  state->io_source = source;
  return FTUN_OK;
}

static ftun_status_t backend_timer_start(void *user,
                                         ftun_event_source_t *source,
                                         uint64_t deadline_ms)
{
  backend_state_t *state = (backend_state_t *)user;
  (void)deadline_ms;
  state->timer_source = source;
  return FTUN_OK;
}

static ftun_status_t backend_io_update(void *user,
                                        ftun_event_source_t *source,
                                        uint32_t interests)
{
  (void)user;
  (void)source;
  (void)interests;
  return FTUN_OK;
}

static ftun_status_t backend_source_cancel(void *user,
                                           ftun_event_source_t *source)
{
  backend_state_t *state = (backend_state_t *)user;
  state->cancel_calls++;
  if (state->cancel_failures > 0) {
    state->cancel_failures--;
    return FTUN_E_IO;
  }
  if (state->io_source == source) state->io_source = NULL;
  if (state->timer_source == source) state->timer_source = NULL;
  return FTUN_OK;
}

static void backend_wakeup(void *user)
{
  (void)user;
}

static ftun_status_t backend_run_once(void *user, bool block)
{
  (void)user;
  (void)block;
  return FTUN_OK;
}

static void backend_stop(void *user)
{
  (void)user;
}

static void backend_destroy(void *user)
{
  (void)user;
}

static const ftun_event_backend_ops_t backend_ops = {
  backend_io_start,
  backend_io_update,
  backend_timer_start,
  backend_source_cancel,
  backend_wakeup,
  backend_run_once,
  backend_stop,
  backend_destroy,
  false
};

static size_t socket_index(ftun_native_socket_t socket)
{
  if (socket < SOCKET_BASE || socket >= SOCKET_BASE + MAX_SOCKETS) {
    return MAX_SOCKETS;
  }
  return (size_t)(socket - SOCKET_BASE);
}

static ftun_status_t socket_open(void *user, ftun_dial_transport_t transport,
                                 ftun_native_socket_t *out)
{
  socket_state_t *state = (socket_state_t *)user;
  size_t index = state->open_calls;
  if (out != NULL) *out = FTUN_INVALID_SOCKET;
  if (out == NULL || index >= MAX_SOCKETS) return FTUN_E_LIMIT;
  state->open_calls++;
  state->transports[index] = transport;
  if (state->open_status[index] != FTUN_OK) return state->open_status[index];
  *out = SOCKET_BASE + (ftun_native_socket_t)index;
  return FTUN_OK;
}

static ftun_status_t socket_protect(void *user, ftun_native_socket_t socket,
                                    const ftun_socket_policy_t *policy)
{
  socket_state_t *state = (socket_state_t *)user;
  size_t index = socket_index(socket);
  if (index >= MAX_SOCKETS || policy == NULL ||
      policy->interface_name.length >= FTUN_SOCKET_INTERFACE_BYTES) {
    return FTUN_E_STATE_CORRUPT;
  }
  state->protect_calls++;
  state->marks[index] = policy->mark;
  if (policy->interface_name.length != 0u) {
    memcpy(state->devices[index], policy->interface_name.data,
           policy->interface_name.length);
  }
  return state->protect_status[index];
}

static ftun_status_t socket_connect(void *user, ftun_native_socket_t socket,
                                    const ftun_endpoint_t *endpoint)
{
  socket_state_t *state = (socket_state_t *)user;
  size_t index = socket_index(socket);
  if (index >= MAX_SOCKETS || endpoint == NULL) {
    return FTUN_E_STATE_CORRUPT;
  }
  state->connect_calls++;
  state->endpoints[index] = *endpoint;
  return state->connect_status[index];
}

static ftun_status_t socket_get_error(void *user,
                                      ftun_native_socket_t socket)
{
  socket_state_t *state = (socket_state_t *)user;
  size_t index = socket_index(socket);
  if (index >= MAX_SOCKETS) return FTUN_E_STATE_CORRUPT;
  return state->socket_error_status[index];
}

static ftun_status_t socket_close(void *user, ftun_native_socket_t socket)
{
  socket_state_t *state = (socket_state_t *)user;
  size_t index = socket_index(socket);
  if (index >= MAX_SOCKETS || state->closed[index]) {
    return FTUN_E_STATE_CORRUPT;
  }
  state->closed[index] = 1;
  state->close_calls++;
  return FTUN_OK;
}

static ftun_status_t protocol_send(void *user, ftun_native_socket_t socket,
                                   const void *data, size_t length,
                                   size_t *out_sent)
{
  protocol_state_t *state = (protocol_state_t *)user;
  size_t amount = length;
  if (out_sent != NULL) *out_sent = 0u;
  if (out_sent == NULL || data == NULL || length == 0u ||
      socket_index(socket) >= MAX_SOCKETS) return FTUN_E_INVALID;
  state->send_calls++;
  if (state->send_status != FTUN_OK) return state->send_status;
  if (state->max_send != 0u && amount > state->max_send) {
    amount = state->max_send;
  }
  if (amount > sizeof(state->client) - state->client_length) {
    return FTUN_E_LIMIT;
  }
  memcpy(state->client + state->client_length, data, amount);
  state->client_length += amount;
  *out_sent = amount;
  return FTUN_OK;
}

static ftun_status_t protocol_receive(void *user, ftun_native_socket_t socket,
                                      void *data, size_t capacity,
                                      size_t *out_received)
{
  protocol_state_t *state = (protocol_state_t *)user;
  size_t amount;
  if (out_received != NULL) *out_received = 0u;
  if (out_received == NULL || data == NULL || capacity == 0u ||
      socket_index(socket) >= MAX_SOCKETS) return FTUN_E_INVALID;
  state->receive_calls++;
  if (state->receive_status != FTUN_OK) return state->receive_status;
  if (state->server_offset == state->server_length) return FTUN_E_AGAIN;
  amount = state->server_length - state->server_offset;
  if (amount > capacity) amount = capacity;
  if (state->max_receive != 0u && amount > state->max_receive) {
    amount = state->max_receive;
  }
  memcpy(data, state->server + state->server_offset, amount);
  state->server_offset += amount;
  *out_received = amount;
  return FTUN_OK;
}

static void connect_completed(ftun_operation_t *operation,
                              ftun_error_t error,
                              ftun_socks5_connection_t *connection,
                              void *user)
{
  completion_state_t *state = (completion_state_t *)user;
  state->calls++;
  state->operation = operation;
  state->error = error;
  state->connection = connection;
}

static void endpoint_set(ftun_endpoint_t *endpoint, uint8_t first,
                         uint8_t last, uint16_t port)
{
  memset(endpoint, 0, sizeof(*endpoint));
  endpoint->kind = FTUN_ADDRESS_IPV4;
  endpoint->address[0] = first;
  endpoint->address[1] = 0u;
  endpoint->address[2] = 0u;
  endpoint->address[3] = last;
  endpoint->port = port;
}

static int fixture_start(fixture_t *fixture, size_t budget_limit,
                         size_t operation_capacity)
{
  size_t index;
  memset(fixture, 0, sizeof(*fixture));
  for (index = 0u; index < MAX_SOCKETS; index++) {
    fixture->socket.socket_error_status[index] = FTUN_OK;
  }
  fixture->dial_io.open_socket = socket_open;
  fixture->dial_io.protect_socket = socket_protect;
  fixture->dial_io.connect_socket = socket_connect;
  fixture->dial_io.get_socket_error = socket_get_error;
  fixture->dial_io.close_socket = socket_close;
  fixture->dial_io.context = &fixture->socket;
  fixture->protocol_io.send_socket = protocol_send;
  fixture->protocol_io.receive_socket = protocol_receive;
  fixture->protocol_io.context = &fixture->protocol;
  if (ftun_budget_create(NULL, budget_limit, 0u, &fixture->budget) != FTUN_OK) {
    return 1;
  }
  if (ftun_operation_queue_create(fixture->budget, operation_capacity,
                                  &fixture->operations) != FTUN_OK) return 1;
  if (ftun_event_loop_create(NULL, &fixture->loop) != FTUN_OK) return 1;
  if (ftun_event_loop_attach_backend(fixture->loop, &backend_ops,
                                     &fixture->backend) != FTUN_OK) return 1;
  endpoint_set(&fixture->proxy.server, 198u, 1u, 1080u);
  fixture->proxy.udp_enabled = true;
  endpoint_set(&fixture->target_candidates[0], 203u, 50u, 443u);
  endpoint_set(&fixture->target_candidates[1], 203u, 60u, 443u);
  fixture->target.generation = 9u;
  fixture->target.original.kind = FTUN_ADDRESS_DOMAIN;
  fixture->target.original.domain.data = "target.example";
  fixture->target.original.domain.length = 14u;
  fixture->target.original.port = 443u;
  fixture->target.identity = fixture->target.original.domain;
  fixture->target.identity_source = FTUN_DOMAIN_EXPLICIT;
  fixture->target.candidates = fixture->target_candidates;
  fixture->target.candidate_count = 2u;
  fixture->target.allowed = fixture->target_candidates;
  fixture->target.allowed_count = 2u;
  memcpy(fixture->device, "eth0", 5u);
  fixture->request.loop = fixture->loop;
  fixture->request.operations = fixture->operations;
  fixture->request.budget = fixture->budget;
  fixture->request.proxy = &fixture->proxy;
  fixture->request.target = &fixture->target;
  fixture->request.protection.mark = 77u;
  fixture->request.protection.interface_name.data = fixture->device;
  fixture->request.protection.interface_name.length = 4u;
  fixture->request.deadline_ms = 1000u;
  fixture->request.transport = FTUN_DIAL_TCP;
  fixture->request.completion = connect_completed;
  fixture->request.user = &fixture->completion;
  return 0;
}

static int fixture_stop(fixture_t *fixture)
{
  ftun_budget_usage_t usage;
  if (fixture->completion.connection != NULL &&
      ftun_socks5_connection_close(&fixture->completion.connection) != FTUN_OK) {
    return 1;
  }
  if (ftun_event_loop_stop(fixture->loop) != FTUN_OK) return 1;
  if (ftun_event_loop_detach_backend(fixture->loop) != FTUN_OK) return 1;
  if (ftun_event_loop_destroy(&fixture->loop) != FTUN_OK) return 1;
  if (ftun_operation_queue_destroy(&fixture->operations) != FTUN_OK) return 1;
  if (ftun_budget_get_usage(fixture->budget, &usage) != FTUN_OK ||
      usage.used != 0u) return 1;
  return ftun_budget_destroy(&fixture->budget) == FTUN_OK ? 0 : 1;
}

static int append_server(fixture_t *fixture, const uint8_t *data,
                         size_t length)
{
  if (length > sizeof(fixture->protocol.server) -
               fixture->protocol.server_length) return 1;
  memcpy(fixture->protocol.server + fixture->protocol.server_length,
         data, length);
  fixture->protocol.server_length += length;
  return 0;
}

static int add_server_script(fixture_t *fixture, uint8_t method,
                             int include_auth, uint8_t auth_status,
                             uint8_t reply_code,
                             const ftun_endpoint_t *reply_endpoint)
{
  uint8_t selection[2] = {FTUN_SOCKS5_VERSION, method};
  uint8_t auth[2] = {FTUN_SOCKS5_AUTH_VERSION, auth_status};
  uint8_t reply[300];
  size_t written = 0u;
  if (append_server(fixture, selection, sizeof(selection)) != 0) return 1;
  if (include_auth && append_server(fixture, auth, sizeof(auth)) != 0) return 1;
  if (ftun_socks5_encode_reply(reply_code, reply_endpoint, reply,
                               sizeof(reply), &written) != FTUN_OK) return 1;
  return append_server(fixture, reply, written);
}

static int drive(fixture_t *fixture)
{
  size_t iteration;
  for (iteration = 0u; iteration < 1024u; iteration++) {
    size_t dispatched = 0u;
    size_t callbacks = 0u;
    if (ftun_operation_dispatch(fixture->operations, SIZE_MAX,
                                &dispatched) != FTUN_OK) return 1;
    if (fixture->completion.calls != 0) return 0;
    if (fixture->backend.io_source != NULL) {
      if (ftun_event_io_ready(fixture->backend.io_source,
                              FTUN_EVENT_READ | FTUN_EVENT_WRITE |
                              FTUN_EVENT_ERROR) != FTUN_OK) return 1;
      if (ftun_event_loop_poll(fixture->loop, 1u, 8u,
                               &callbacks) != FTUN_OK) return 1;
    }
  }
  return 1;
}

static int test_tcp_candidates_partial_and_copy(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = NULL;
  ftun_socks5_connection_info_t info;
  ftun_socks5_method_offer_t offer;
  ftun_socks5_request_t request;
  ftun_endpoint_t bound;
  ftun_bytes_t bytes;
  size_t consumed = 0u;
  size_t request_consumed = 0u;
  CHECK(fixture_start(&fixture, 65536u, 6u) == 0);
  fixture.proxy.server.kind = FTUN_ADDRESS_DOMAIN;
  fixture.proxy.server.domain.data = "proxy.example";
  fixture.proxy.server.domain.length = 13u;
  endpoint_set(&fixture.proxy_resolved[0], 198u, 10u, 1080u);
  endpoint_set(&fixture.proxy_resolved[1], 198u, 20u, 1080u);
  fixture.proxy.resolved = fixture.proxy_resolved;
  fixture.proxy.resolved_count = 2u;
  fixture.socket.connect_status[0] = FTUN_E_REJECTED;
  fixture.protocol.max_send = 1u;
  fixture.protocol.max_receive = 1u;
  endpoint_set(&bound, 127u, 1u, 4000u);
  CHECK(add_server_script(&fixture, FTUN_SOCKS5_METHOD_NO_AUTH, 0, 0u,
                          FTUN_SOCKS5_REPLY_SUCCEEDED, &bound) == 0);
  CHECK(ftun_socks5_connect_with_io(NULL, &fixture.request,
                                    &fixture.dial_io, &fixture.protocol_io,
                                    &operation) == FTUN_OK);
  CHECK(operation != NULL && fixture.completion.calls == 0);
  fixture.target_candidates[0].address[3] = 99u;
  memcpy(fixture.device, "bad0", 5u);
  CHECK(drive(&fixture) == 0);
  CHECK(fixture.completion.calls == 1 &&
        fixture.completion.error.status == FTUN_OK &&
        fixture.completion.connection != NULL);
  CHECK(fixture.socket.open_calls == 2u && fixture.socket.close_calls == 1u &&
        fixture.socket.endpoints[0].address[3] == 10u &&
        fixture.socket.endpoints[1].address[3] == 20u);
  CHECK(fixture.socket.marks[0] == 77u && fixture.socket.marks[1] == 77u &&
        strcmp(fixture.socket.devices[0], "eth0") == 0 &&
        strcmp(fixture.socket.devices[1], "eth0") == 0);
  bytes.data = fixture.protocol.client;
  bytes.length = fixture.protocol.client_length;
  CHECK(ftun_socks5_decode_method_offer(bytes, &offer, &consumed) == FTUN_OK);
  CHECK(offer.methods.length == 1u &&
        offer.methods.data[0] == FTUN_SOCKS5_METHOD_NO_AUTH);
  bytes.data += consumed;
  bytes.length -= consumed;
  CHECK(ftun_socks5_decode_request(bytes, &request,
                                   &request_consumed) == FTUN_OK);
  CHECK(request_consumed == bytes.length &&
        request.command == FTUN_SOCKS5_COMMAND_CONNECT &&
        request.endpoint.kind == FTUN_ADDRESS_IPV4 &&
        request.endpoint.address[3] == 50u && request.endpoint.port == 443u);
  CHECK(ftun_socks5_connection_get_info(fixture.completion.connection,
                                         &info) == FTUN_OK);
  CHECK(info.transport == FTUN_DIAL_TCP &&
        info.control_socket == SOCKET_BASE + 1u &&
        info.data_socket == info.control_socket &&
        info.target.address[3] == 50u);
  CHECK(fixture_stop(&fixture) == 0);
  CHECK(fixture.socket.close_calls == 2u);
  return 0;
}

static int test_authenticated_domain(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = NULL;
  ftun_socks5_method_offer_t offer;
  ftun_socks5_credentials_t credentials;
  ftun_socks5_request_t request;
  ftun_endpoint_t bound;
  ftun_bytes_t bytes;
  size_t consumed = 0u;
  CHECK(fixture_start(&fixture, 65536u, 6u) == 0);
  fixture.proxy.username.data = (const uint8_t *)"alice";
  fixture.proxy.username.length = 5u;
  fixture.proxy.password.data = (const uint8_t *)"secret";
  fixture.proxy.password.length = 6u;
  fixture.target.candidates = NULL;
  fixture.target.candidate_count = 0u;
  fixture.target.allowed = NULL;
  fixture.target.allowed_count = 0u;
  fixture.target.identity.data = "remote.example";
  fixture.target.identity.length = 14u;
  fixture.target.original.domain = fixture.target.identity;
  endpoint_set(&bound, 127u, 1u, 4001u);
  CHECK(add_server_script(&fixture, FTUN_SOCKS5_METHOD_USERNAME_PASSWORD,
                          1, 0u, FTUN_SOCKS5_REPLY_SUCCEEDED, &bound) == 0);
  CHECK(ftun_socks5_connect_with_io(NULL, &fixture.request,
                                    &fixture.dial_io, &fixture.protocol_io,
                                    &operation) == FTUN_OK);
  CHECK(drive(&fixture) == 0 && fixture.completion.error.status == FTUN_OK);
  bytes.data = fixture.protocol.client;
  bytes.length = fixture.protocol.client_length;
  CHECK(ftun_socks5_decode_method_offer(bytes, &offer, &consumed) == FTUN_OK &&
        offer.methods.data[0] == FTUN_SOCKS5_METHOD_USERNAME_PASSWORD);
  bytes.data += consumed;
  bytes.length -= consumed;
  CHECK(ftun_socks5_decode_credentials(bytes, &credentials,
                                       &consumed) == FTUN_OK);
  CHECK(credentials.username.length == 5u &&
        memcmp(credentials.username.data, "alice", 5u) == 0 &&
        credentials.password.length == 6u &&
        memcmp(credentials.password.data, "secret", 6u) == 0);
  bytes.data += consumed;
  bytes.length -= consumed;
  CHECK(ftun_socks5_decode_request(bytes, &request, &consumed) == FTUN_OK);
  CHECK(consumed == bytes.length &&
        request.command == FTUN_SOCKS5_COMMAND_CONNECT &&
        request.endpoint.kind == FTUN_ADDRESS_DOMAIN &&
        request.endpoint.domain.length == 14u &&
        memcmp(request.endpoint.domain.data, "remote.example", 14u) == 0);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_udp_associate_and_source(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = NULL;
  ftun_socks5_connection_info_t info;
  ftun_socks5_udp_datagram_t datagram;
  ftun_endpoint_t relay;
  ftun_endpoint_t wrong_source;
  ftun_bytes_t payload;
  ftun_bytes_t encoded;
  uint8_t packet[300];
  size_t written = 0u;
  size_t consumed = 0u;
  CHECK(fixture_start(&fixture, 65536u, 8u) == 0);
  fixture.request.transport = FTUN_DIAL_UDP;
  endpoint_set(&relay, 0u, 0u, 5300u);
  CHECK(add_server_script(&fixture, FTUN_SOCKS5_METHOD_NO_AUTH, 0, 0u,
                          FTUN_SOCKS5_REPLY_SUCCEEDED, &relay) == 0);
  CHECK(ftun_socks5_connect_with_io(NULL, &fixture.request,
                                    &fixture.dial_io, &fixture.protocol_io,
                                    &operation) == FTUN_OK);
  memcpy(fixture.device, "bad0", 5u);
  CHECK(drive(&fixture) == 0 && fixture.completion.error.status == FTUN_OK);
  CHECK(ftun_socks5_connection_get_info(fixture.completion.connection,
                                         &info) == FTUN_OK);
  CHECK(info.transport == FTUN_DIAL_UDP &&
        info.control_socket == SOCKET_BASE &&
        info.data_socket == SOCKET_BASE + 1u &&
        info.relay.kind == FTUN_ADDRESS_IPV4 &&
        info.relay.address[0] == 198u && info.relay.address[3] == 1u &&
        info.relay.port == 5300u);
  CHECK(fixture.socket.open_calls == 2u &&
        fixture.socket.transports[0] == FTUN_DIAL_TCP &&
        fixture.socket.transports[1] == FTUN_DIAL_UDP &&
        fixture.socket.endpoints[1].port == 5300u &&
        fixture.socket.endpoints[1].address[3] == 1u &&
        fixture.socket.marks[1] == 77u &&
        strcmp(fixture.socket.devices[1], "eth0") == 0);
  payload.data = (const uint8_t *)"abc";
  payload.length = 3u;
  CHECK(ftun_socks5_connection_encode_udp(fixture.completion.connection,
                                           payload, packet, sizeof(packet),
                                           &written) == FTUN_OK);
  encoded.data = packet;
  encoded.length = written;
  CHECK(ftun_socks5_connection_decode_udp(fixture.completion.connection,
                                           &info.relay, encoded, &datagram,
                                           &consumed) == FTUN_OK);
  CHECK(consumed == written && datagram.endpoint.address[3] == 50u &&
        datagram.payload.length == 3u &&
        memcmp(datagram.payload.data, "abc", 3u) == 0);
  wrong_source = info.relay;
  wrong_source.address[3] = 99u;
  CHECK(ftun_socks5_connection_decode_udp(fixture.completion.connection,
                                           &wrong_source, encoded, &datagram,
                                           &consumed) == FTUN_E_REJECTED &&
        consumed == 0u);
  packet[2] = 1u;
  CHECK(ftun_socks5_connection_decode_udp(fixture.completion.connection,
                                           &info.relay, encoded, &datagram,
                                           &consumed) == FTUN_E_UNSUPPORTED);
  CHECK(fixture_stop(&fixture) == 0);
  CHECK(fixture.socket.close_calls == 2u);
  return 0;
}

static int test_overlay_udp_domain_sticky(void)
{
  ftun_network_prefix_t prefix = {{198u, 0u, 0u, 0u}, 8u};
  ftun_network_route_t route = {
    {{198u, 0u, 0u, 0u}, 8u},
    FTUN_DIAL_PURPOSE_BIT(FTUN_DIAL_PURPOSE_PROXY)
  };
  ftun_network_view_spec_t spec;
  ftun_network_view_t *view = NULL;
  ftun_socks5_connection_info_t info;
  ftun_operation_t *operation = NULL;
  ftun_endpoint_t relay;
  fixture_t fixture;

  memset(&spec, 0, sizeof(spec));
  spec.generation = 23u;
  spec.protected_prefixes = &prefix;
  spec.protected_prefix_count = 1u;
  spec.overlay_routes = &route;
  spec.overlay_route_count = 1u;
  CHECK(ftun_network_view_create(&spec, &view) == FTUN_OK);

  CHECK(fixture_start(&fixture, 65536u, 8u) == 0);
  fixture.request.transport = FTUN_DIAL_UDP;
  fixture.request.network_view = view;
  fixture.request.network_generation = 23u;
  endpoint_set(&relay, 192u, 2u, 5300u);
  CHECK(add_server_script(&fixture, FTUN_SOCKS5_METHOD_NO_AUTH, 0, 0u,
                          FTUN_SOCKS5_REPLY_SUCCEEDED, &relay) == 0);
  CHECK(ftun_socks5_connect_with_io(NULL, &fixture.request,
                                    &fixture.dial_io, &fixture.protocol_io,
                                    &operation) == FTUN_OK);
  CHECK(drive(&fixture) == 0 &&
        fixture.completion.error.status == FTUN_E_REJECTED &&
        fixture.completion.connection == NULL &&
        fixture.socket.open_calls == 1u &&
        fixture.socket.protect_calls == 0u &&
        fixture.socket.close_calls == 1u);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(fixture_start(&fixture, 65536u, 8u) == 0);
  fixture.request.transport = FTUN_DIAL_UDP;
  fixture.request.network_view = view;
  fixture.request.network_generation = 23u;
  endpoint_set(&relay, 0u, 0u, 5300u);
  CHECK(add_server_script(&fixture, FTUN_SOCKS5_METHOD_NO_AUTH, 0, 0u,
                          FTUN_SOCKS5_REPLY_SUCCEEDED, &relay) == 0);
  CHECK(ftun_socks5_connect_with_io(NULL, &fixture.request,
                                    &fixture.dial_io, &fixture.protocol_io,
                                    &operation) == FTUN_OK);
  CHECK(drive(&fixture) == 0 && fixture.completion.error.status == FTUN_OK &&
        fixture.completion.connection != NULL &&
        fixture.socket.open_calls == 2u &&
        fixture.socket.protect_calls == 0u);
  CHECK(ftun_socks5_connection_get_info(fixture.completion.connection,
        &info) == FTUN_OK && info.proxy_domain == FTUN_DIAL_DOMAIN_OVERLAY &&
        info.network_generation == 23u && info.relay.address[0] == 198u);
  CHECK(fixture_stop(&fixture) == 0);
  CHECK(ftun_network_view_release(&view) == FTUN_OK);
  return 0;
}

static int test_protocol_failures_timeout_and_cancel(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = NULL;
  ftun_endpoint_t bound;
  size_t dispatched = 0u;
  size_t callbacks = 0u;
  CHECK(fixture_start(&fixture, 65536u, 6u) == 0);
  endpoint_set(&bound, 127u, 1u, 4000u);
  CHECK(add_server_script(&fixture, FTUN_SOCKS5_METHOD_NO_AUTH, 0, 0u,
                          FTUN_SOCKS5_REPLY_CONNECTION_REFUSED,
                          &bound) == 0);
  CHECK(ftun_socks5_connect_with_io(NULL, &fixture.request,
                                    &fixture.dial_io, &fixture.protocol_io,
                                    &operation) == FTUN_OK);
  CHECK(drive(&fixture) == 0);
  CHECK(fixture.completion.error.status == FTUN_E_REJECTED &&
        fixture.completion.connection == NULL && fixture.socket.close_calls == 1u);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(fixture_start(&fixture, 65536u, 6u) == 0);
  fixture.proxy.username.data = (const uint8_t *)"user";
  fixture.proxy.username.length = 4u;
  fixture.proxy.password.data = (const uint8_t *)"pass";
  fixture.proxy.password.length = 4u;
  CHECK(add_server_script(&fixture, FTUN_SOCKS5_METHOD_USERNAME_PASSWORD,
                          1, 1u, FTUN_SOCKS5_REPLY_SUCCEEDED, &bound) == 0);
  CHECK(ftun_socks5_connect_with_io(NULL, &fixture.request,
                                    &fixture.dial_io, &fixture.protocol_io,
                                    &operation) == FTUN_OK);
  CHECK(drive(&fixture) == 0);
  CHECK(fixture.completion.error.status == FTUN_E_REJECTED &&
        fixture.completion.connection == NULL && fixture.socket.close_calls == 1u);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(fixture_start(&fixture, 65536u, 6u) == 0);
  CHECK(ftun_socks5_connect_with_io(NULL, &fixture.request,
                                    &fixture.dial_io, &fixture.protocol_io,
                                    &operation) == FTUN_OK);
  CHECK(ftun_operation_dispatch(fixture.operations, SIZE_MAX,
                                &dispatched) == FTUN_OK && dispatched == 1u);
  CHECK(ftun_event_loop_poll(fixture.loop, 1000u, 8u,
                             &callbacks) == FTUN_OK && callbacks == 1u);
  CHECK(ftun_operation_dispatch(fixture.operations, SIZE_MAX,
                                &dispatched) == FTUN_OK && dispatched == 1u);
  CHECK(fixture.completion.error.status == FTUN_E_TIMEOUT &&
        fixture.socket.close_calls == 1u);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(fixture_start(&fixture, 65536u, 6u) == 0);
  CHECK(ftun_socks5_connect_with_io(NULL, &fixture.request,
                                    &fixture.dial_io, &fixture.protocol_io,
                                    &operation) == FTUN_OK);
  CHECK(ftun_operation_dispatch(fixture.operations, SIZE_MAX,
                                &dispatched) == FTUN_OK && dispatched == 1u);
  fixture.backend.cancel_failures = 1;
  CHECK(ftun_operation_cancel(operation) == FTUN_E_IO);
  CHECK(fixture.socket.close_calls == 0u && fixture.backend.io_source != NULL);
  CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  CHECK(fixture.socket.close_calls == 1u && fixture.backend.io_source == NULL &&
        fixture.backend.timer_source == NULL);
  CHECK(ftun_operation_dispatch(fixture.operations, SIZE_MAX,
                                &dispatched) == FTUN_OK && dispatched == 1u);
  CHECK(fixture.completion.calls == 1 &&
        fixture.completion.error.status == FTUN_E_CANCELLED &&
        fixture.completion.connection == NULL);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(fixture_start(&fixture, 65536u, 6u) == 0);
  fixture.socket.connect_status[0] = FTUN_E_AGAIN;
  CHECK(ftun_socks5_connect_with_io(NULL, &fixture.request,
                                    &fixture.dial_io, &fixture.protocol_io,
                                    &operation) == FTUN_OK);
  CHECK(ftun_operation_cancel(operation) == FTUN_E_AGAIN);
  CHECK(fixture.socket.close_calls == 1u && fixture.backend.io_source == NULL &&
        fixture.backend.timer_source == NULL);
  CHECK(ftun_operation_dispatch(fixture.operations, SIZE_MAX,
                                &dispatched) == FTUN_OK && dispatched == 2u);
  CHECK(fixture.completion.calls == 1 &&
        fixture.completion.error.status == FTUN_E_CANCELLED &&
        fixture.completion.connection == NULL);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_synchronous_boundaries(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = (ftun_operation_t *)(uintptr_t)1;
  CHECK(fixture_start(&fixture, 65536u, 6u) == 0);
  fixture.proxy.server.kind = FTUN_ADDRESS_DOMAIN;
  fixture.proxy.server.domain.data = "proxy.example";
  fixture.proxy.server.domain.length = 13u;
  CHECK(ftun_socks5_connect_with_io(NULL, &fixture.request,
                                    &fixture.dial_io, &fixture.protocol_io,
                                    &operation) == FTUN_E_RESOLVE);
  CHECK(operation == NULL && fixture.socket.open_calls == 0u &&
        fixture.completion.calls == 0);
  fixture.proxy.server.kind = FTUN_ADDRESS_IPV4;
  fixture.proxy.server.domain.data = NULL;
  fixture.proxy.server.domain.length = 0u;
  fixture.target.allowed = NULL;
  fixture.target.allowed_count = 0u;
  CHECK(ftun_socks5_connect_with_io(NULL, &fixture.request,
                                    &fixture.dial_io, &fixture.protocol_io,
                                    &operation) == FTUN_E_REJECTED);
  fixture.target.allowed = fixture.target_candidates;
  fixture.target.allowed_count = 2u;
  fixture.request.transport = FTUN_DIAL_UDP;
  fixture.proxy.udp_enabled = false;
  CHECK(ftun_socks5_connect_with_io(NULL, &fixture.request,
                                    &fixture.dial_io, &fixture.protocol_io,
                                    &operation) == FTUN_E_UNSUPPORTED);
  fixture.request.transport = FTUN_DIAL_TCP;
  fixture.proxy.username.data = (const uint8_t *)"user";
  fixture.proxy.username.length = 4u;
  CHECK(ftun_socks5_connect_with_io(NULL, &fixture.request,
                                    &fixture.dial_io, &fixture.protocol_io,
                                    &operation) == FTUN_E_INVALID);
  CHECK(ftun_socks5_connect_with_io(NULL, &fixture.request, NULL,
                                    &fixture.protocol_io,
                                    &operation) == FTUN_E_INVALID);
  CHECK(ftun_socks5_connect_with_io(NULL, &fixture.request,
                                    &fixture.dial_io, NULL,
                                    &operation) == FTUN_E_INVALID);
  CHECK(fixture.socket.open_calls == 0u && fixture.completion.calls == 0);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(fixture_start(&fixture, 65536u, 1u) == 0);
  operation = (ftun_operation_t *)(uintptr_t)1;
  CHECK(ftun_socks5_connect_with_io(NULL, &fixture.request,
                                    &fixture.dial_io, &fixture.protocol_io,
                                    &operation) == FTUN_E_LIMIT);
  CHECK(operation == NULL && fixture.socket.open_calls == 0u &&
        fixture.completion.calls == 0);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

int main(void)
{
  if (test_tcp_candidates_partial_and_copy() != 0) return 1;
  if (test_authenticated_domain() != 0) return 1;
  if (test_udp_associate_and_source() != 0) return 1;
  if (test_overlay_udp_domain_sticky() != 0) return 1;
  if (test_protocol_failures_timeout_and_cancel() != 0) return 1;
  if (test_synchronous_boundaries() != 0) return 1;
  return 0;
}
