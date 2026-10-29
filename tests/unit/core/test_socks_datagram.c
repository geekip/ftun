#include <unistd.h>
#include <fcntl.h>
#include "core/context.h"
#include "proxy/outbound/socks5.h"
#include "platform/clock.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "SOCKS Datagram failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

ftun_status_t __wrap_ftun_socket_path_open(void *, ftun_core_t *,
  const ftun_path_open_request_t *, const ftun_path_spec_t *, ftun_operation_t **);

typedef struct {
  ftun_path_open_request_t request;
  ftun_path_t *path;
  uint64_t generation;
} opened_t;

typedef struct {
  ftun_budget_t *budget;
  ftun_core_t *core;
  ftun_event_loop_t *loop;
  ftun_operation_queue_t *operations;
  ftun_path_provider_t *provider;
  ftun_path_scope_t *scope;
  ftun_socks5_connection_t *connection;
  ftun_operation_t *operation;
  ftun_channel_t *datagram;
  opened_t opened[2];
  unsigned int starts, completed, sent, receives, accepted, errors;
  ftun_status_t status, send_status, notify_error, close_status;
  ftun_endpoint_t target;
  ftun_packet_t received;
  bool pause_receive;
  bool close_in_callback;
} fixture_t;

static void opened(ftun_operation_t *operation, ftun_error_t error, ftun_path_t *path, void *user)
{
  opened_t *state = user;
  state->path = path;
  state->request.completion(operation, error, path, state->request.user);
}

static ftun_status_t factory(void *user, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *spec, ftun_operation_t **out)
{
  fixture_t *fixture = user;
  ftun_path_open_request_t copy = *request;
  opened_t *state;
  if (fixture->starts >= 2u) return FTUN_E_LIMIT;
  state = &fixture->opened[fixture->starts++];
  state->request = *request;
  state->generation = spec->configuration_generation;
  copy.completion = opened;
  copy.user = state;
  return __wrap_ftun_socket_path_open(NULL, core, &copy, spec, out);
}

static void completed(ftun_operation_t *operation, ftun_error_t error,
  ftun_socks5_connection_t *connection, void *user)
{
  fixture_t *fixture = user;
  (void)operation;
  fixture->completed++;
  fixture->status = error.status;
  fixture->connection = connection;
}

static void written(ftun_operation_t *operation, ftun_error_t error, void *user)
{
  (void)operation;
  (void)error;
  (void)user;
}

static void notified(ftun_path_t *path, uint32_t events, ftun_error_t error, void *user)
{
  fixture_t *fixture = user;
  (void)path;
  if ((events & FTUN_PATH_ERROR) != 0u) {
    fixture->errors++;
    fixture->notify_error = error.status;
  }
  if (fixture->close_in_callback && fixture->connection != NULL) {
    fixture->close_status = ftun_socks5_connection_close(&fixture->connection);
  }
}

static void sent(ftun_datagram_t *channel, ftun_error_t error,
  const ftun_endpoint_t *target, const ftun_packet_t *packet, void *user)
{
  fixture_t *fixture = user;
  (void)channel;
  (void)target;
  (void)packet;
  fixture->sent++;
  fixture->send_status = error.status;
  if (fixture->close_in_callback) fixture->close_status = ftun_socks5_connection_close(&fixture->connection);
}

static ftun_status_t received(ftun_datagram_t *channel, const ftun_endpoint_t *source,
  const ftun_packet_t *packet, void *user)
{
  fixture_t *fixture = user;
  (void)channel;
  fixture->receives++;
  if (source->kind != fixture->target.kind || source->port != fixture->target.port) return FTUN_E_STATE_CORRUPT;
  if (fixture->pause_receive) return FTUN_E_AGAIN;
  if (fixture->close_in_callback) fixture->close_status = ftun_socks5_connection_close(&fixture->connection);
  fixture->accepted++;
  ftun_packet_release(&fixture->received);
  return ftun_packet_clone(packet, &fixture->received);
}

static int tick(fixture_t *fixture)
{
  uint64_t now;
  size_t count;
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  CHECK(ftun_event_loop_poll(fixture->loop, now, 16u, &count) == FTUN_OK);
  CHECK(ftun_operation_dispatch(fixture->operations, 1u, &count) == FTUN_OK);
  return 0;
}

static int setup(fixture_t *fixture, unsigned int mode)
{
  ftun_path_provider_spec_t spec = {0};
  ftun_socks5_proxy_t proxy = {0};
  ftun_target_t target = {0};
  ftun_socks5_connect_request_t request = {0};
  uint64_t now;
  unsigned int round;
  CHECK(ftun_budget_create(NULL, 4194304u, 0u, &fixture->budget) == FTUN_OK);
  CHECK(ftun_core_context_create(fixture->budget, &fixture->core) == FTUN_OK);
  CHECK(ftun_event_loop_create(fixture->core, &fixture->loop) == FTUN_OK);
  CHECK(ftun_operation_queue_create(fixture->budget, 32u, &fixture->operations) == FTUN_OK);
  spec.budget = fixture->budget;
  spec.generation = 7u;
  spec.max_paths = mode == 2u ? 1u : 2u;
  spec.max_pending = spec.max_paths;
  spec.ops.open = factory;
  spec.context = fixture;
  CHECK(ftun_path_provider_create(&spec, &fixture->provider) == FTUN_OK);
  CHECK(ftun_path_provider_scope(fixture->provider, 7u, &fixture->scope) == FTUN_OK);
  proxy.server.kind = FTUN_ADDRESS_IPV4;
  proxy.server.address[0] = 127u;
  proxy.server.address[3] = 1u;
  proxy.server.port = 1080u;
  proxy.udp_enabled = true;
  proxy.username = (ftun_bytes_t){(const uint8_t *)"user", 4u};
  proxy.password = (ftun_bytes_t){(const uint8_t *)"pass", 4u};
  target.original.kind = FTUN_ADDRESS_DOMAIN;
  target.original.domain = (ftun_string_t){"udp.test", 8u};
  target.original.port = 9000u;
  target.identity = target.original.domain;
  target.generation = 7u;
  fixture->target = target.original;
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  request.loop = fixture->loop;
  request.operations = fixture->operations;
  request.budget = fixture->budget;
  request.scope = fixture->scope;
  request.proxy = &proxy;
  request.target = &target;
  request.transport = FTUN_DIAL_UDP;
  request.deadline_ms = now + 10000u;
  request.completion = completed;
  request.user = fixture;
  request.notify = notified;
  request.notify_user = fixture;
  request.stream.max_pending_writes = 1u;
  request.stream.max_pending_bytes = 8192u;
  request.stream.completion = written;
  request.datagram.max_pending_packets = 2u;
  request.datagram.max_pending_bytes = 131072u;
  request.datagram.result = sent;
  request.datagram.receive = received;
  request.datagram.user = fixture;
  {
    ftun_budget_t *foreign = NULL;
    CHECK(ftun_budget_create(NULL, 4194304u, 0u, &foreign) == FTUN_OK);
    request.datagram.budget = foreign;
    CHECK(ftun_socks5_connect(fixture->core, &request, &fixture->operation) == FTUN_E_INVALID);
    CHECK(fixture->operation == NULL && fixture->completed == 0u && fixture->starts == 0u);
    CHECK(ftun_budget_destroy(&foreign) == FTUN_OK);
    request.datagram.budget = NULL;
  }
  CHECK(ftun_socks5_connect(fixture->core, &request, &fixture->operation) == FTUN_OK);
  ftun_path_scope_release(&fixture->scope);
  CHECK(ftun_path_provider_reload_prepare(fixture->provider, 8u) == FTUN_OK);
  CHECK(ftun_path_provider_reload_commit(fixture->provider, 8u) == FTUN_OK);
  for (round = 0u; round < 1000u && fixture->completed == 0u; round++) {
    size_t count;
    CHECK(ftun_monotonic_now(&now) == FTUN_OK);
    CHECK(ftun_event_loop_poll(fixture->loop, now, 16u, &count) == FTUN_OK);
    if (mode == 1u && fixture->starts == 2u) {
      CHECK(ftun_operation_cancel(fixture->operation) == FTUN_E_AGAIN);
      mode = 10u;
    }
    if (mode == 6u && fixture->starts == 2u) {
      ftun_operation_queue_usage_t usage;
      CHECK(ftun_operation_queue_get_usage(fixture->operations, &usage) == FTUN_OK);
      if (usage.inflight == 1u && usage.ready == 1u) {
        ftun_stream_t *control;
        CHECK(ftun_path_stream(fixture->opened[0].path, &control) == FTUN_OK);
        CHECK(ftun_stream_shutdown_write(control) == FTUN_OK);
        mode = 11u;
      }
    }
    CHECK(ftun_operation_dispatch(fixture->operations, 1u, &count) == FTUN_OK);
  }
  CHECK(fixture->completed == 1u);
  return 0;
}

static int packet_make(fixture_t *fixture, size_t length, ftun_packet_t *packet)
{
  ftun_buffer_t *buffer = NULL;
  ftun_buffer_slice_t slice = {0};
  uint8_t *bytes;
  size_t capacity, index;
  CHECK(ftun_buffer_acquire(fixture->budget, length == 0u ? 1u : length, &buffer) == FTUN_OK);
  CHECK(ftun_buffer_data(buffer, &bytes, &capacity) == FTUN_OK);
  for (index = 0u; index < length; index++) bytes[index] = (uint8_t)index;
  CHECK(ftun_buffer_slice(buffer, 0u, length, &slice) == FTUN_OK);
  CHECK(ftun_packet_init(packet, &slice, 77u) == FTUN_OK);
  ftun_buffer_slice_release(&slice);
  ftun_buffer_release(&buffer);
  return 0;
}

static int rejected_packets(fixture_t *fixture)
{
  ftun_datagram_t *wire = NULL;
  ftun_socks5_connection_info_t info;
  ftun_endpoint_t source;
  ftun_buffer_t *buffer = NULL;
  ftun_buffer_slice_t slice = {0};
  ftun_packet_t packet = {0};
  uint8_t *bytes;
  size_t capacity, length;
  unsigned int accepted = fixture->accepted;
  CHECK(ftun_path_datagram(fixture->opened[1].path, &wire) == FTUN_OK);
  CHECK(ftun_socks5_connection_get_info(fixture->connection, &info) == FTUN_OK);
  CHECK(ftun_buffer_acquire(fixture->budget, 64u, &buffer) == FTUN_OK);
  CHECK(ftun_buffer_data(buffer, &bytes, &capacity) == FTUN_OK);
  CHECK(ftun_socks5_connection_encode_udp(fixture->connection,
    (ftun_bytes_t){(const uint8_t *)"checked", 7u}, bytes, capacity, &length) == FTUN_OK);
  CHECK(ftun_buffer_slice(buffer, 0u, length, &slice) == FTUN_OK);
  CHECK(ftun_packet_init(&packet, &slice, 77u) == FTUN_OK);
  source = info.relay;
  source.port++;
  CHECK(ftun_datagram_deliver(wire, &source, &packet) == FTUN_OK && fixture->accepted == accepted);
  source = info.relay;
  bytes[2] = 1u;
  CHECK(ftun_datagram_deliver(wire, &source, &packet) == FTUN_OK && fixture->accepted == accepted);
  bytes[2] = 0u;
  bytes[length - 8u] ^= 1u;
  CHECK(ftun_datagram_deliver(wire, &source, &packet) == FTUN_OK && fixture->accepted == accepted);
  bytes[length - 8u] ^= 1u;
  CHECK(ftun_datagram_deliver(wire, &source, &packet) == FTUN_OK && fixture->accepted == accepted + 1u);
  ftun_packet_release(&fixture->received);
  ftun_packet_release(&packet);
  ftun_buffer_slice_release(&slice);
  ftun_buffer_release(&buffer);
  return 0;
}

static int scenario(unsigned int mode)
{
  fixture_t fixture = {0};
  ftun_path_provider_info_t info;
  ftun_budget_usage_t usage;
  unsigned int round;
  CHECK(setup(&fixture, mode) == 0);
  if (mode == 1u || mode == 2u) {
    CHECK(fixture.status == (mode == 1u ? FTUN_E_CANCELLED : FTUN_E_LIMIT));
    CHECK(fixture.connection == NULL);
  } else {
    ftun_packet_t packet = {0};
    ftun_bytes_t payload;
    CHECK(fixture.status == FTUN_OK && fixture.connection != NULL && fixture.starts == 2u);
    CHECK(fixture.opened[0].generation == 7u && fixture.opened[1].generation == 7u);
    CHECK(fixture.opened[1].request.dial.transport == FTUN_DIAL_UDP);
    CHECK(fixture.opened[1].request.dial.requested_domain == FTUN_DIAL_DOMAIN_UNDERLAY);
    CHECK(fixture.opened[1].request.dial.endpoint.address[0] == 127u &&
      fixture.opened[1].request.dial.endpoint.address[3] == 1u);
    CHECK(ftun_socks5_connection_channel(fixture.connection, &fixture.datagram) == FTUN_OK);
    if (mode == 5u || mode == 6u) {
      ftun_stream_t *control;
      CHECK(ftun_path_stream(fixture.opened[0].path, &control) == FTUN_OK);
      fixture.close_in_callback = true;
      if (mode == 5u) {
        CHECK(ftun_stream_shutdown_write(control) == FTUN_OK);
        CHECK(fixture.close_status == FTUN_E_AGAIN);
      }
      CHECK(fixture.errors == 1u && fixture.notify_error == FTUN_E_EOF);
      CHECK(packet_make(&fixture, 1u, &packet) == 0);
      CHECK(ftun_channel_send(fixture.datagram, &fixture.target, &packet) == FTUN_E_EOF && fixture.sent == 0u);
    } else {
      size_t lengths[] = {0u, 1u, 65000u};
      unsigned int index;
      fixture.pause_receive = mode == 4u;
      fixture.close_in_callback = true;
      for (index = 0u; index < 3u; index++) {
        ftun_endpoint_t wrong = fixture.target;
        unsigned int sent_before = fixture.sent;
        CHECK(packet_make(&fixture, lengths[index], &packet) == 0);
        wrong.port++;
        CHECK(ftun_channel_send(fixture.datagram, &wrong, &packet) == FTUN_E_REJECTED);
        CHECK(ftun_channel_send(fixture.datagram, &fixture.target, &packet) == FTUN_OK);
        CHECK(ftun_channel_send(fixture.datagram, &fixture.target, &packet) == FTUN_E_AGAIN);
        ftun_packet_release(&packet);
        if (mode == 3u) {
          CHECK(ftun_socks5_connection_close(&fixture.connection) == FTUN_E_AGAIN && fixture.connection != NULL);
          CHECK(fixture.sent == 1u && fixture.send_status == FTUN_E_CANCELLED && fixture.accepted == 0u);
          CHECK(tick(&fixture) == 0);
          break;
        }
        for (round = 0u; round < 20u && fixture.sent == sent_before; round++) CHECK(tick(&fixture) == 0);
        CHECK(fixture.sent == sent_before + 1u && fixture.send_status == FTUN_OK);
        if (fixture.pause_receive) {
          CHECK(fixture.accepted == 0u && fixture.receives == 1u);
          fixture.pause_receive = false;
          CHECK(ftun_socks5_connection_resume(fixture.connection) == FTUN_OK);
          CHECK(tick(&fixture) == 0);
        }
        CHECK(fixture.accepted == index + 1u && fixture.close_status == FTUN_E_AGAIN);
        CHECK(ftun_packet_view(&fixture.received, &payload) == FTUN_OK && payload.length == lengths[index]);
        for (size_t byte = 0u; byte < payload.length; byte++) CHECK(payload.data[byte] == (uint8_t)byte);
        CHECK(fixture.received.source_id == 77u);
        ftun_packet_release(&fixture.received);
      }
    }
    fixture.close_in_callback = false;
    if (mode == 0u) {
      CHECK(rejected_packets(&fixture) == 0);
      CHECK(packet_make(&fixture, 65536u, &packet) == 0);
      CHECK(ftun_channel_send(fixture.datagram, &fixture.target, &packet) == FTUN_E_LIMIT);
    }
    ftun_packet_release(&packet);
    CHECK(ftun_socks5_connection_close(&fixture.connection) == FTUN_OK);
  }
  for (round = 0u; round < 4u; round++) CHECK(tick(&fixture) == 0);
  CHECK(fixture.completed == 1u);
  CHECK(ftun_path_provider_get_info(fixture.provider, &info) == FTUN_OK &&
    info.paths == 0u && info.scopes == 0u && info.pending == 0u);
  CHECK(ftun_path_provider_stop_until(fixture.provider, UINT64_MAX) == FTUN_OK);
  CHECK(ftun_path_provider_destroy(&fixture.provider) == FTUN_OK);
  CHECK(ftun_event_loop_stop(fixture.loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&fixture.loop) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&fixture.operations) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&fixture.core) == FTUN_OK);
  CHECK(ftun_budget_get_usage(fixture.budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u);
  CHECK(ftun_budget_destroy(&fixture.budget) == FTUN_OK);
  return 0;
}

int main(void)
{
  unsigned int mode;
  for (mode = 0u; mode < 7u; mode++) {
    if (scenario(mode) != 0) { fprintf(stderr, "scenario %u failed\n", mode); return 1; }
  }
  puts("SOCKS Datagram passed: owned channels, packet boundaries, backpressure, cancellation and close retry");
  return 0;
}
