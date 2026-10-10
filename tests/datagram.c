#include "transport/datagram.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "datagram contract failed at line %d: %s\n", __LINE__, #x); \
    return 1; \
  } \
} while (0)

#define BACKEND_SENDS 8u

typedef struct {
  ftun_datagram_send_t *sends[BACKEND_SENDS];
  size_t send_count;
  ftun_status_t start_status;
  ftun_status_t cancel_status;
  int start_calls;
  int cancel_calls;
  int destroy_calls;
  int complete_in_start;
  int in_start;
  int early_complete_ok;
  ftun_endpoint_t target;
  char target_domain[FTUN_DATAGRAM_DOMAIN_BYTES];
  size_t payload_length;
  uint8_t first_byte;
  uint32_t source_id;
} backend_state_t;

typedef struct {
  backend_state_t *backend;
  int result_calls;
  int receive_calls;
  int callback_saw_pending_zero;
  int callback_saw_in_callback;
  int callback_ran_after_start;
  ftun_error_t error;
  ftun_endpoint_t endpoint;
  char domain[FTUN_DATAGRAM_DOMAIN_BYTES];
  uint8_t payload[16];
  size_t payload_length;
  uint32_t source_id;
  ftun_status_t receive_status;
} callback_state_t;

typedef struct {
  ftun_budget_t *budget;
  ftun_buffer_pool_t *pool;
  ftun_datagram_t *channel;
  backend_state_t backend;
  callback_state_t callback;
} fixture_t;

static void backend_remove(backend_state_t *state, ftun_datagram_send_t *send)
{
  size_t index;
  for (index = 0u; index < state->send_count; index++) {
    if (state->sends[index] == send) {
      state->send_count--;
      state->sends[index] = state->sends[state->send_count];
      state->sends[state->send_count] = NULL;
      return;
    }
  }
}

static ftun_status_t backend_send_start(void *user,
                                        ftun_datagram_send_t *send,
                                        const ftun_endpoint_t *target,
                                        const ftun_packet_t *packet)
{
  backend_state_t *state = (backend_state_t *)user;
  const ftun_endpoint_t *view_target = NULL;
  const ftun_packet_t *view_packet = NULL;
  ftun_bytes_t bytes;
  ftun_error_t success = {FTUN_OK, 3u, 0};
  state->start_calls++;
  state->in_start = 1;
  if (ftun_datagram_send_view(send, &view_target, &view_packet) != FTUN_OK ||
      view_target != target || view_packet != packet ||
      ftun_packet_view(packet, &bytes) != FTUN_OK) return FTUN_E_STATE_CORRUPT;
  state->target = *target;
  memset(state->target_domain, 0, sizeof(state->target_domain));
  if (target->kind == FTUN_ADDRESS_DOMAIN) {
    memcpy(state->target_domain, target->domain.data, target->domain.length);
    state->target.domain.data = state->target_domain;
  }
  state->payload_length = bytes.length;
  state->first_byte = bytes.length == 0u ? 0u : bytes.data[0];
  state->source_id = packet->source_id;
  if (state->start_status != FTUN_OK) {
    state->in_start = 0;
    return state->start_status;
  }
  if (state->send_count >= BACKEND_SENDS) return FTUN_E_LIMIT;
  state->sends[state->send_count++] = send;
  if (state->complete_in_start) {
    backend_remove(state, send);
    if (ftun_datagram_send_complete(send, success) == FTUN_OK) {
      state->early_complete_ok++;
    }
  }
  state->in_start = 0;
  return FTUN_OK;
}

static ftun_status_t backend_send_cancel(void *user,
                                         ftun_datagram_send_t *send)
{
  backend_state_t *state = (backend_state_t *)user;
  size_t before = state->send_count;
  state->cancel_calls++;
  if (state->cancel_status != FTUN_OK) return state->cancel_status;
  backend_remove(state, send);
  return state->send_count + 1u == before ? FTUN_OK : FTUN_E_STATE_CORRUPT;
}

static void backend_destroy(void *user)
{
  backend_state_t *state = (backend_state_t *)user;
  state->destroy_calls++;
}

static void copy_callback_value(callback_state_t *state,
                                const ftun_endpoint_t *endpoint,
                                const ftun_packet_t *packet)
{
  ftun_bytes_t bytes;
  state->endpoint = *endpoint;
  memset(state->domain, 0, sizeof(state->domain));
  if (endpoint->kind == FTUN_ADDRESS_DOMAIN) {
    memcpy(state->domain, endpoint->domain.data, endpoint->domain.length);
    state->endpoint.domain.data = state->domain;
  }
  if (ftun_packet_view(packet, &bytes) != FTUN_OK ||
      bytes.length > sizeof(state->payload)) {
    state->payload_length = SIZE_MAX;
    return;
  }
  state->payload_length = bytes.length;
  if (bytes.length != 0u) memcpy(state->payload, bytes.data, bytes.length);
  state->source_id = packet->source_id;
}

static void send_result(ftun_datagram_t *channel, ftun_error_t error,
                        const ftun_endpoint_t *target,
                        const ftun_packet_t *packet, void *user)
{
  callback_state_t *state = (callback_state_t *)user;
  ftun_datagram_usage_t usage;
  state->result_calls++;
  state->error = error;
  copy_callback_value(state, target, packet);
  if (ftun_datagram_get_usage(channel, &usage) == FTUN_OK) {
    state->callback_saw_pending_zero += usage.pending_packets == 0u;
    state->callback_saw_in_callback += usage.in_callback;
  }
  state->callback_ran_after_start += !state->backend->in_start;
}

static ftun_status_t receive_packet(ftun_datagram_t *channel,
                                    const ftun_endpoint_t *source,
                                    const ftun_packet_t *packet, void *user)
{
  callback_state_t *state = (callback_state_t *)user;
  ftun_datagram_usage_t usage;
  state->receive_calls++;
  copy_callback_value(state, source, packet);
  if (ftun_datagram_get_usage(channel, &usage) == FTUN_OK) {
    state->callback_saw_in_callback += usage.in_callback;
  }
  return state->receive_status;
}

static int fixture_start(fixture_t *fixture, size_t max_packets,
                         size_t max_bytes, int with_receiver)
{
  ftun_datagram_options_t options;
  ftun_datagram_backend_t backend;
  memset(fixture, 0, sizeof(*fixture));
  memset(&options, 0, sizeof(options));
  memset(&backend, 0, sizeof(backend));
  if (ftun_budget_create(NULL, 16384u, 0u, &fixture->budget) != FTUN_OK) return 1;
  if (ftun_buffer_pool_create(fixture->budget, 0u, 0u,
                              &fixture->pool) != FTUN_OK) return 1;
  fixture->callback.backend = &fixture->backend;
  options.budget = fixture->budget;
  options.max_pending_packets = max_packets;
  options.max_pending_bytes = max_bytes;
  options.result = send_result;
  options.receive = with_receiver ? receive_packet : NULL;
  options.user = &fixture->callback;
  backend.send_start = backend_send_start;
  backend.send_cancel = backend_send_cancel;
  backend.destroy = backend_destroy;
  backend.context = &fixture->backend;
  return ftun_datagram_create(&options, &backend, &fixture->channel) == FTUN_OK
    ? 0 : 1;
}

static int fixture_stop(fixture_t *fixture)
{
  ftun_budget_usage_t usage;
  if (ftun_datagram_stop(fixture->channel) != FTUN_OK) return 1;
  if (ftun_datagram_destroy(&fixture->channel) != FTUN_OK) return 1;
  if (fixture->backend.destroy_calls != 1) return 1;
  if (ftun_buffer_pool_destroy(&fixture->pool) != FTUN_OK) return 1;
  if (ftun_budget_get_usage(fixture->budget, &usage) != FTUN_OK ||
      usage.used != 0u) return 1;
  if (ftun_budget_destroy(&fixture->budget) != FTUN_OK) return 1;
  return 0;
}

static int make_packet(fixture_t *fixture, uint8_t seed, size_t length,
                       uint32_t source_id, ftun_packet_t *out)
{
  ftun_buffer_t *buffer = NULL;
  ftun_buffer_slice_t slice = {0};
  uint8_t *data = NULL;
  size_t capacity = 0u;
  size_t index;
  size_t requested = length == 0u ? 1u : length;
  if (ftun_buffer_pool_acquire(fixture->pool, requested, &buffer) != FTUN_OK) {
    return 1;
  }
  if (ftun_buffer_data(buffer, &data, &capacity) != FTUN_OK ||
      capacity < requested) return 1;
  for (index = 0u; index < length; index++) data[index] = seed + (uint8_t)index;
  if (ftun_buffer_slice(buffer, 0u, length, &slice) != FTUN_OK) return 1;
  if (ftun_packet_init(out, &slice, source_id) != FTUN_OK) return 1;
  if (ftun_buffer_slice_release(&slice) != FTUN_OK) return 1;
  if (ftun_buffer_release(&buffer) != FTUN_OK) return 1;
  return 0;
}

static ftun_endpoint_t ipv4_endpoint(uint16_t port, uint8_t last)
{
  ftun_endpoint_t endpoint;
  memset(&endpoint, 0, sizeof(endpoint));
  endpoint.kind = FTUN_ADDRESS_IPV4;
  endpoint.address[0] = 127u;
  endpoint.address[3] = last;
  endpoint.port = port;
  return endpoint;
}

static int complete_first(fixture_t *fixture, ftun_error_t error)
{
  ftun_datagram_send_t *send;
  if (fixture->backend.send_count == 0u) return 1;
  send = fixture->backend.sends[0];
  backend_remove(&fixture->backend, send);
  return ftun_datagram_send_complete(send, error) == FTUN_OK ? 0 : 1;
}

static int complete_index(fixture_t *fixture, size_t index, ftun_error_t error)
{
  ftun_datagram_send_t *send;
  if (index >= fixture->backend.send_count) return 1;
  send = fixture->backend.sends[index];
  backend_remove(&fixture->backend, send);
  return ftun_datagram_send_complete(send, error) == FTUN_OK ? 0 : 1;
}

static int test_async_send_and_error(void)
{
  fixture_t fixture;
  ftun_packet_t packet = {{0}, 0u};
  ftun_endpoint_t target = ipv4_endpoint(53u, 1u);
  const ftun_endpoint_t *view_target = NULL;
  const ftun_packet_t *view_packet = NULL;
  ftun_datagram_usage_t usage;
  ftun_bytes_t bytes;
  ftun_error_t success = {FTUN_OK, 4u, 0};
  ftun_error_t failure = {FTUN_E_IO, 5u, 9};
  CHECK(fixture_start(&fixture, 2u, 8u, 1) == 0);
  CHECK(make_packet(&fixture, 10u, 3u, 7u, &packet) == 0);
  CHECK(ftun_datagram_send(fixture.channel, &target, &packet) == FTUN_OK);
  CHECK(fixture.callback.result_calls == 0 && fixture.backend.send_count == 1u);
  CHECK(ftun_packet_release(&packet) == FTUN_OK);
  target.port = 99u;
  CHECK(ftun_datagram_send_view(fixture.backend.sends[0], &view_target,
                                &view_packet) == FTUN_OK);
  CHECK(view_target->port == 53u && view_packet->source_id == 7u);
  CHECK(ftun_packet_view(view_packet, &bytes) == FTUN_OK &&
        bytes.length == 3u && bytes.data[0] == 10u && bytes.data[2] == 12u);
  CHECK(ftun_datagram_get_usage(fixture.channel, &usage) == FTUN_OK &&
        usage.pending_packets == 1u && usage.pending_bytes == 3u);
  CHECK(complete_first(&fixture, success) == 0);
  CHECK(fixture.callback.result_calls == 1 &&
        fixture.callback.error.status == FTUN_OK &&
        fixture.callback.endpoint.port == 53u &&
        fixture.callback.payload_length == 3u &&
        fixture.callback.payload[2] == 12u && fixture.callback.source_id == 7u);
  CHECK(fixture.callback.callback_saw_pending_zero == 1 &&
        fixture.callback.callback_saw_in_callback == 1 &&
        fixture.callback.callback_ran_after_start == 1);

  CHECK(make_packet(&fixture, 20u, 2u, 8u, &packet) == 0);
  target.port = 54u;
  CHECK(ftun_datagram_send(fixture.channel, &target, &packet) == FTUN_OK);
  CHECK(ftun_packet_release(&packet) == FTUN_OK);
  CHECK(complete_first(&fixture, failure) == 0);
  CHECK(fixture.callback.result_calls == 2 &&
        fixture.callback.error.status == FTUN_E_IO &&
        fixture.callback.error.native_code == 9);
  CHECK(ftun_datagram_get_usage(fixture.channel, &usage) == FTUN_OK &&
        usage.completed_packets == 1u && usage.failed_packets == 1u &&
        usage.pending_packets == 0u);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_zero_domain_and_immediate(void)
{
  fixture_t fixture;
  ftun_packet_t packet = {{0}, 0u};
  ftun_endpoint_t target;
  char domain[] = "dns.example";
  ftun_datagram_usage_t usage;
  memset(&target, 0, sizeof(target));
  target.kind = FTUN_ADDRESS_DOMAIN;
  target.domain.data = domain;
  target.domain.length = strlen(domain);
  target.port = 5353u;
  CHECK(fixture_start(&fixture, 1u, 0u, 1) == 0);
  fixture.backend.complete_in_start = 1;
  CHECK(make_packet(&fixture, 0u, 0u, 11u, &packet) == 0);
  CHECK(ftun_datagram_send(fixture.channel, &target, &packet) == FTUN_OK);
  CHECK(fixture.backend.early_complete_ok == 1 &&
        fixture.backend.send_count == 0u && fixture.callback.result_calls == 1);
  CHECK(fixture.callback.callback_ran_after_start == 1 &&
        fixture.callback.endpoint.kind == FTUN_ADDRESS_DOMAIN &&
        strcmp(fixture.callback.domain, "dns.example") == 0 &&
        fixture.callback.payload_length == 0u && fixture.callback.source_id == 11u);
  CHECK(ftun_packet_release(&packet) == FTUN_OK);
  CHECK(ftun_datagram_get_usage(fixture.channel, &usage) == FTUN_OK &&
        usage.pending_packets == 0u && usage.pending_bytes == 0u &&
        usage.completed_packets == 1u);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_zero_boundaries_and_slots(void)
{
  fixture_t fixture;
  ftun_packet_t first = {{0}, 0u};
  ftun_packet_t second = {{0}, 0u};
  ftun_packet_t third = {{0}, 0u};
  ftun_endpoint_t target;
  ftun_datagram_usage_t usage;
  ftun_error_t success = {FTUN_OK, 0u, 0};
  char domain[] = "queue.example";
  memset(&target, 0, sizeof(target));
  target.kind = FTUN_ADDRESS_DOMAIN;
  target.domain.data = domain;
  target.domain.length = strlen(domain);
  target.port = 53u;
  CHECK(fixture_start(&fixture, 2u, 0u, 1) == 0);
  CHECK(make_packet(&fixture, 0u, 0u, 1u, &first) == 0);
  CHECK(make_packet(&fixture, 0u, 0u, 2u, &second) == 0);
  CHECK(make_packet(&fixture, 0u, 0u, 3u, &third) == 0);
  CHECK(ftun_datagram_send(fixture.channel, &target, &first) == FTUN_OK);
  CHECK(ftun_datagram_send(fixture.channel, &target, &second) == FTUN_OK);
  domain[0] = 'X';
  CHECK(ftun_datagram_send(fixture.channel, &target, &third) == FTUN_E_LIMIT);
  CHECK(fixture.backend.send_count == 2u && fixture.backend.start_calls == 2);
  CHECK(ftun_packet_release(&first) == FTUN_OK);
  CHECK(ftun_packet_release(&second) == FTUN_OK);
  CHECK(ftun_packet_release(&third) == FTUN_OK);
  CHECK(ftun_datagram_get_usage(fixture.channel, &usage) == FTUN_OK &&
        usage.pending_packets == 2u && usage.pending_bytes == 0u);
  CHECK(complete_index(&fixture, 1u, success) == 0);
  CHECK(fixture.callback.source_id == 2u &&
        strcmp(fixture.callback.domain, "queue.example") == 0 &&
        fixture.callback.payload_length == 0u);
  CHECK(complete_index(&fixture, 0u, success) == 0);
  CHECK(fixture.callback.source_id == 1u && fixture.callback.result_calls == 2);
  CHECK(ftun_datagram_get_usage(fixture.channel, &usage) == FTUN_OK &&
        usage.pending_packets == 0u && usage.completed_packets == 2u);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_rejection_limits_and_stop(void)
{
  fixture_t fixture;
  ftun_packet_t first = {{0}, 0u};
  ftun_packet_t second = {{0}, 0u};
  ftun_endpoint_t target = ipv4_endpoint(1000u, 1u);
  ftun_budget_usage_t before;
  ftun_budget_usage_t after;
  ftun_reservation_t *blocker = NULL;
  ftun_datagram_usage_t usage;
  CHECK(fixture_start(&fixture, 2u, 4u, 1) == 0);
  CHECK(make_packet(&fixture, 30u, 2u, 1u, &first) == 0);
  CHECK(ftun_budget_get_usage(fixture.budget, &before) == FTUN_OK);
  fixture.backend.start_status = FTUN_E_AGAIN;
  CHECK(ftun_datagram_send(fixture.channel, &target, &first) == FTUN_E_AGAIN);
  CHECK(fixture.callback.result_calls == 0 && fixture.backend.send_count == 0u);
  CHECK(ftun_budget_get_usage(fixture.budget, &after) == FTUN_OK &&
        after.used == before.used);
  CHECK(after.normal_available > 0u);
  CHECK(ftun_budget_reserve(fixture.budget, after.normal_available,
                            &blocker) == FTUN_OK);
  CHECK(ftun_datagram_send(fixture.channel, &target, &first) == FTUN_E_LIMIT);
  CHECK(fixture.backend.start_calls == 1);
  CHECK(ftun_reservation_release(&blocker) == FTUN_OK);

  fixture.backend.start_status = FTUN_OK;
  CHECK(ftun_datagram_send(fixture.channel, &target, &first) == FTUN_OK);
  CHECK(make_packet(&fixture, 40u, 3u, 2u, &second) == 0);
  CHECK(ftun_datagram_send(fixture.channel, &target, &second) == FTUN_E_LIMIT);
  CHECK(fixture.backend.start_calls == 2);
  CHECK(ftun_packet_release(&first) == FTUN_OK);
  CHECK(ftun_packet_release(&second) == FTUN_OK);
  fixture.backend.cancel_status = FTUN_E_IO;
  CHECK(ftun_datagram_stop(fixture.channel) == FTUN_E_IO);
  CHECK(fixture.backend.cancel_calls == 1 && fixture.callback.result_calls == 0);
  CHECK(ftun_datagram_get_usage(fixture.channel, &usage) == FTUN_OK &&
        !usage.accepting && usage.pending_packets == 1u);
  CHECK(make_packet(&fixture, 50u, 0u, 3u, &first) == 0);
  CHECK(ftun_datagram_send(fixture.channel, &target, &first) == FTUN_E_CANCELLED);
  CHECK(ftun_packet_release(&first) == FTUN_OK);
  fixture.backend.cancel_status = FTUN_OK;
  CHECK(ftun_datagram_stop(fixture.channel) == FTUN_OK);
  CHECK(fixture.callback.result_calls == 1 &&
        fixture.callback.error.status == FTUN_E_CANCELLED);
  CHECK(ftun_datagram_destroy(&fixture.channel) == FTUN_OK &&
        fixture.channel == NULL && fixture.backend.destroy_calls == 1);
  CHECK(ftun_buffer_pool_destroy(&fixture.pool) == FTUN_OK);
  CHECK(ftun_budget_destroy(&fixture.budget) == FTUN_OK);
  return 0;
}

static int test_receive_and_boundaries(void)
{
  fixture_t fixture;
  ftun_packet_t packet = {{0}, 0u};
  ftun_packet_t clone = {{0}, 0u};
  ftun_endpoint_t source = ipv4_endpoint(2000u, 9u);
  ftun_endpoint_t invalid;
  ftun_datagram_usage_t usage;
  ftun_bytes_t bytes;
  CHECK(fixture_start(&fixture, 1u, 8u, 1) == 0);
  CHECK(make_packet(&fixture, 60u, 0u, 99u, &packet) == 0);
  CHECK(ftun_packet_clone(&packet, &clone) == FTUN_OK);
  fixture.callback.receive_status = FTUN_E_REJECTED;
  CHECK(ftun_datagram_deliver(fixture.channel, &source, &packet) == FTUN_E_REJECTED);
  CHECK(fixture.callback.receive_calls == 1 &&
        fixture.callback.endpoint.port == 2000u &&
        fixture.callback.endpoint.address[3] == 9u &&
        fixture.callback.payload_length == 0u && fixture.callback.source_id == 99u);
  CHECK(ftun_packet_view(&clone, &bytes) == FTUN_OK && bytes.length == 0u);
  CHECK(ftun_packet_release(&clone) == FTUN_OK);

  memset(&invalid, 0, sizeof(invalid));
  invalid.kind = FTUN_ADDRESS_IPV6_RESERVED;
  invalid.port = 1u;
  CHECK(ftun_datagram_send(fixture.channel, &invalid, &packet) == FTUN_E_UNSUPPORTED);
  invalid.kind = FTUN_ADDRESS_DOMAIN;
  invalid.domain.data = "";
  invalid.domain.length = 0u;
  CHECK(ftun_datagram_send(fixture.channel, &invalid, &packet) == FTUN_E_INVALID);
  CHECK(ftun_packet_release(&packet) == FTUN_OK);
  CHECK(ftun_datagram_destroy(&fixture.channel) == FTUN_E_AGAIN);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(fixture_start(&fixture, 1u, 8u, 0) == 0);
  CHECK(make_packet(&fixture, 1u, 1u, 1u, &packet) == 0);
  CHECK(ftun_datagram_deliver(fixture.channel, &source, &packet) ==
        FTUN_E_UNSUPPORTED);
  CHECK(ftun_packet_release(&packet) == FTUN_OK);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(ftun_packet_init(NULL, NULL, 0u) == FTUN_E_INVALID);
  CHECK(ftun_packet_clone(NULL, NULL) == FTUN_E_INVALID);
  CHECK(ftun_packet_view(NULL, &bytes) == FTUN_E_INVALID && bytes.data == NULL);
  CHECK(ftun_packet_release(NULL) == FTUN_E_INVALID);
  CHECK(ftun_datagram_create(NULL, NULL, &fixture.channel) == FTUN_E_INVALID &&
        fixture.channel == NULL);
  CHECK(ftun_datagram_send(NULL, NULL, NULL) == FTUN_E_INVALID);
  CHECK(ftun_datagram_send_view(NULL, NULL, NULL) == FTUN_E_INVALID);
  CHECK(ftun_datagram_send_complete(NULL, (ftun_error_t){FTUN_OK, 0u, 0}) ==
        FTUN_E_INVALID);
  CHECK(ftun_datagram_deliver(NULL, NULL, NULL) == FTUN_E_INVALID);
  CHECK(ftun_datagram_stop(NULL) == FTUN_E_INVALID);
  CHECK(ftun_datagram_get_usage(NULL, &usage) == FTUN_E_INVALID &&
        usage.pending_packets == 0u);
  CHECK(ftun_datagram_destroy(NULL) == FTUN_E_INVALID);
  CHECK(ftun_datagram_destroy(&fixture.channel) == FTUN_OK);
  return 0;
}

/* TASK-TRANSPORT-003 / TEST-TRANSPORT-003：整包、零长 payload 与来源。 */
int main(void)
{
  CHECK(test_async_send_and_error() == 0);
  CHECK(test_zero_domain_and_immediate() == 0);
  CHECK(test_zero_boundaries_and_slots() == 0);
  CHECK(test_rejection_limits_and_stop() == 0);
  CHECK(test_receive_and_boundaries() == 0);
  return 0;
}
