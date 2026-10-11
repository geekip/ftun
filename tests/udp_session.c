#include "config/compile.h"
#include "config/model.h"
#include "config/parser.h"
#include "core/budget.h"
#include "core/runtime.h"
#include "route/rule.h"
#include "transport/datagram.h"
#include "tun/udp_session.h"
#include "util/buffer.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
  if (!(condition)) { \
    fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, \
            #condition); \
    return 1; \
  } \
} while (0)

#define FLOW_SLOTS 16u
#define PAYLOAD_BYTES 128u

typedef struct fixture fixture_t;

typedef struct {
  fixture_t *fixture;
  ftun_datagram_t *channel;
  ftun_datagram_send_t *pending;
  ftun_endpoint_t target;
  uint8_t payload[PAYLOAD_BYTES];
  size_t payload_length;
  size_t sends;
  int destroyed;
} outbound_slot_t;

struct fixture {
  ftun_budget_t *budget;
  ftun_core_t *core;
  ftun_udp_flow_table_t *table;
  ftun_datagram_t *inbound;
  outbound_slot_t slots[FLOW_SLOTS];
  size_t slot_count;
  size_t open_calls;
  size_t inbound_lookups;
  size_t inbound_sends;
  ftun_endpoint_t inbound_target;
  ftun_endpoint_t inbound_wire_source;
  uint8_t inbound_payload[PAYLOAD_BYTES];
  size_t inbound_payload_length;
  size_t remote_index;
  ftun_status_t send_start_status;
  uint64_t opened_generation;
  uint32_t opened_outbound_id;
  int async_send;
  int cancel_failures;
  int corrupt_remote;
  int corrupt_outbound_id;
};

static ftun_config_t *make_config(const char *name, unsigned int port)
{
  char json[256];
  ftun_bytes_t input;
  ftun_config_t *config = NULL;
  ftun_feature_plan_t *plan = NULL;
  int length = snprintf(json, sizeof(json),
    "{\"dns\":{\"enable\":false},\"inbounds\":[{\"name\":\"%s\","
    "\"type\":\"mixed\",\"listen\":\"127.0.0.1:%u\"}],"
    "\"rules\":[\"MATCH,DIRECT\"]}", name, port);
  if (length <= 0 || (size_t)length >= sizeof(json)) return NULL;
  input.data = (const uint8_t *)json;
  input.length = (size_t)length;
  if (ftun_config_parse(input, &config) != FTUN_OK) return NULL;
  if (ftun_config_compile(config, &plan) != FTUN_OK) {
    (void)ftun_config_destroy(&config);
    return NULL;
  }
  config->plan = plan;
  return config;
}

static int install_runtime(fixture_t *fixture, const char *name,
                           unsigned int port)
{
  ftun_config_t *config = make_config(name, port);
  ftun_runtime_t *candidate = NULL;
  if (config == NULL) return 1;
  if (ftun_runtime_prepare(fixture->core, config, &candidate) != FTUN_OK ||
      ftun_runtime_commit(fixture->core, &candidate) != FTUN_OK ||
      ftun_config_destroy(&config) != FTUN_OK) return 1;
  return 0;
}

static ftun_endpoint_t ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                            uint16_t port)
{
  ftun_endpoint_t endpoint;
  memset(&endpoint, 0, sizeof(endpoint));
  endpoint.kind = FTUN_ADDRESS_IPV4;
  endpoint.address[0] = a;
  endpoint.address[1] = b;
  endpoint.address[2] = c;
  endpoint.address[3] = d;
  endpoint.port = port;
  return endpoint;
}

static int endpoint_equal(const ftun_endpoint_t *left,
                          const ftun_endpoint_t *right)
{
  return left->kind == right->kind && left->port == right->port &&
         memcmp(left->address, right->address, 4u) == 0;
}

static void fill_real_metadata(ftun_metadata_t *metadata)
{
  memset(metadata, 0, sizeof(*metadata));
  metadata->generation = 1u;
  metadata->known_fields = FTUN_META_SOURCE | FTUN_META_PORT |
                           FTUN_META_NETWORK;
  metadata->inbound_id = 11u;
  metadata->network = 2u;
  metadata->source = ipv4(10u, 0u, 0u, 2u, 50000u);
  metadata->original_target = ipv4(8u, 8u, 8u, 8u, 53u);
}

static void fill_fake_metadata(ftun_metadata_t *metadata,
                               ftun_endpoint_t resolved[2], char *domain)
{
  fill_real_metadata(metadata);
  metadata->known_fields |= FTUN_META_DOMAIN;
  metadata->original_target = ipv4(198u, 18u, 0u, 1u, 53u);
  metadata->domain.data = domain;
  metadata->domain.length = strlen(domain);
  metadata->domain_source = FTUN_DOMAIN_FAKEIP;
  metadata->original_is_fake = true;
  resolved[0] = ipv4(8u, 8u, 8u, 8u, 53u);
  resolved[1] = ipv4(1u, 1u, 1u, 1u, 53u);
  metadata->resolved = resolved;
  metadata->resolved_count = 2u;
}

static ftun_status_t outbound_send_start(
  void *user, ftun_datagram_send_t *send, const ftun_endpoint_t *target,
  const ftun_packet_t *packet)
{
  outbound_slot_t *slot = (outbound_slot_t *)user;
  fixture_t *fixture = slot->fixture;
  ftun_bytes_t payload;
  ftun_error_t result;
  if (ftun_packet_view(packet, &payload) != FTUN_OK ||
      payload.length > sizeof(slot->payload)) return FTUN_E_LIMIT;
  slot->target = *target;
  memcpy(slot->payload, payload.data, payload.length);
  slot->payload_length = payload.length;
  slot->sends++;
  if (fixture->send_start_status != FTUN_OK) {
    return fixture->send_start_status;
  }
  if (fixture->async_send) {
    slot->pending = send;
    return FTUN_OK;
  }
  memset(&result, 0, sizeof(result));
  result.status = FTUN_OK;
  return ftun_datagram_send_complete(send, result);
}

static ftun_status_t outbound_send_cancel(void *user,
                                           ftun_datagram_send_t *send)
{
  outbound_slot_t *slot = (outbound_slot_t *)user;
  if (slot->fixture->cancel_failures != 0) {
    slot->fixture->cancel_failures--;
    return FTUN_E_AGAIN;
  }
  if (slot->pending == send) slot->pending = NULL;
  return FTUN_OK;
}

static void outbound_destroy(void *user)
{
  outbound_slot_t *slot = (outbound_slot_t *)user;
  slot->channel = NULL;
  slot->destroyed++;
}

static ftun_status_t open_outbound(
  void *user, ftun_core_t *core, const ftun_runtime_t *runtime,
  const ftun_metadata_t *metadata, ftun_datagram_result_fn result,
  ftun_datagram_receive_fn receive, void *callback_user,
  uint32_t *outbound_id, ftun_endpoint_t *remote, ftun_datagram_t **out)
{
  fixture_t *fixture = (fixture_t *)user;
  outbound_slot_t *slot;
  ftun_datagram_options_t options;
  ftun_datagram_backend_t backend;
  ftun_runtime_info_t info;
  if (out != NULL) *out = NULL;
  fixture->open_calls++;
  if (core != fixture->core || runtime == NULL || metadata == NULL ||
      result == NULL || receive == NULL || outbound_id == NULL ||
      remote == NULL || out == NULL || fixture->slot_count >= FLOW_SLOTS) {
    return FTUN_E_INVALID;
  }
  if (ftun_runtime_get_info(runtime, &info) != FTUN_OK) return FTUN_E_INVALID;
  fixture->opened_generation = info.generation;
  slot = &fixture->slots[fixture->slot_count++];
  memset(slot, 0, sizeof(*slot));
  slot->fixture = fixture;
  memset(&options, 0, sizeof(options));
  options.budget = fixture->budget;
  options.max_pending_packets = 8u;
  options.max_pending_bytes = 4096u;
  options.result = result;
  options.receive = receive;
  options.user = callback_user;
  memset(&backend, 0, sizeof(backend));
  backend.send_start = outbound_send_start;
  backend.send_cancel = outbound_send_cancel;
  backend.destroy = outbound_destroy;
  backend.context = slot;
  if (ftun_datagram_create(&options, &backend, &slot->channel) != FTUN_OK) {
    return FTUN_E_LIMIT;
  }
  if (metadata->original_is_fake) {
    size_t index = fixture->remote_index < metadata->resolved_count
      ? fixture->remote_index : 0u;
    *remote = metadata->resolved[index];
  } else {
    *remote = metadata->original_target;
  }
  if (fixture->corrupt_remote) remote->port++;
  *outbound_id = fixture->corrupt_outbound_id ? 0u : 77u;
  fixture->opened_outbound_id = *outbound_id;
  *out = slot->channel;
  return FTUN_OK;
}

static ftun_status_t inbound_send_start(
  void *user, ftun_datagram_send_t *send, const ftun_endpoint_t *target,
  const ftun_packet_t *packet)
{
  fixture_t *fixture = (fixture_t *)user;
  ftun_bytes_t payload;
  ftun_error_t result;
  if (ftun_packet_view(packet, &payload) != FTUN_OK ||
      payload.length > sizeof(fixture->inbound_payload)) return FTUN_E_LIMIT;
  fixture->inbound_target = *target;
  memcpy(fixture->inbound_payload, payload.data, payload.length);
  fixture->inbound_payload_length = payload.length;
  fixture->inbound_sends++;
  memset(&result, 0, sizeof(result));
  result.status = FTUN_OK;
  return ftun_datagram_send_complete(send, result);
}

static ftun_status_t inbound_send_cancel(void *user,
                                          ftun_datagram_send_t *send)
{
  (void)user;
  (void)send;
  return FTUN_OK;
}

static void inbound_destroy(void *user)
{
  (void)user;
}

static ftun_status_t lookup_inbound(void *user,
                                    const ftun_metadata_t *metadata,
                                    ftun_datagram_t **out)
{
  fixture_t *fixture = (fixture_t *)user;
  (void)metadata;
  if (out != NULL) *out = fixture->inbound;
  fixture->inbound_lookups++;
  return FTUN_OK;
}

static int create_inbound(fixture_t *fixture)
{
  ftun_datagram_options_t options;
  ftun_datagram_backend_t backend;
  memset(&options, 0, sizeof(options));
  options.budget = fixture->budget;
  options.max_pending_packets = 8u;
  options.max_pending_bytes = 4096u;
  memset(&backend, 0, sizeof(backend));
  backend.send_start = inbound_send_start;
  backend.send_cancel = inbound_send_cancel;
  backend.destroy = inbound_destroy;
  backend.context = fixture;
  return ftun_datagram_create(&options, &backend, &fixture->inbound) == FTUN_OK
    ? 0 : 1;
}

static int fixture_start(fixture_t *fixture, size_t capacity,
                         uint64_t idle_timeout_ms)
{
  ftun_udp_flow_table_spec_t spec;
  memset(fixture, 0, sizeof(*fixture));
  if (ftun_budget_create(NULL, 4u * 1024u * 1024u, 4096u,
                         &fixture->budget) != FTUN_OK) return 1;
  if (ftun_runtime_manager_create(fixture->budget, 4u,
                                  &fixture->core) != FTUN_OK) return 1;
  if (install_runtime(fixture, "one", 10001u) != 0) return 1;
  if (create_inbound(fixture) != 0) return 1;
  memset(&spec, 0, sizeof(spec));
  spec.core = fixture->core;
  spec.budget = fixture->budget;
  spec.capacity = capacity;
  spec.idle_timeout_ms = idle_timeout_ms;
  spec.now_ms = 1000u;
  spec.backend.open = open_outbound;
  spec.backend.inbound = lookup_inbound;
  spec.backend.user = fixture;
  return ftun_udp_flow_table_create(&spec, &fixture->table) == FTUN_OK ? 0 : 1;
}

static int fixture_stop(fixture_t *fixture)
{
  ftun_budget_usage_t usage;
  if (ftun_udp_flow_table_destroy(&fixture->table) != FTUN_OK) return 1;
  if (ftun_datagram_stop(fixture->inbound) != FTUN_OK) return 1;
  if (ftun_datagram_destroy(&fixture->inbound) != FTUN_OK) return 1;
  if (ftun_runtime_manager_destroy(&fixture->core) != FTUN_OK) return 1;
  if (ftun_budget_get_usage(fixture->budget, &usage) != FTUN_OK ||
      usage.used != 0u) return 1;
  return ftun_budget_destroy(&fixture->budget) == FTUN_OK ? 0 : 1;
}

static int make_packet(ftun_budget_t *budget, const uint8_t *payload,
                       size_t length, ftun_packet_t *packet)
{
  ftun_buffer_t *buffer = NULL;
  ftun_buffer_slice_t slice = {0};
  uint8_t *storage = NULL;
  size_t capacity = 0u;
  if (ftun_buffer_acquire(budget, length == 0u ? 1u : length,
                          &buffer) != FTUN_OK ||
      ftun_buffer_data(buffer, &storage, &capacity) != FTUN_OK) return 1;
  if (length != 0u) memcpy(storage, payload, length);
  if (ftun_buffer_slice(buffer, 0u, length, &slice) != FTUN_OK ||
      ftun_packet_init(packet, &slice, 11u) != FTUN_OK) return 1;
  (void)ftun_buffer_slice_release(&slice);
  return ftun_buffer_release(&buffer) == FTUN_OK ? 0 : 1;
}

static int complete_pending(outbound_slot_t *slot, ftun_status_t status)
{
  ftun_error_t result;
  if (slot->pending == NULL) return 1;
  memset(&result, 0, sizeof(result));
  result.status = status;
  if (ftun_datagram_send_complete(slot->pending, result) != FTUN_OK) return 1;
  slot->pending = NULL;
  return 0;
}

static int test_key_runtime_and_idle(void)
{
  static const uint8_t bytes[] = {'o', 'n', 'e'};
  fixture_t fixture;
  ftun_metadata_t metadata;
  ftun_packet_t packet = {{0}, 0u};
  ftun_udp_flow_usage_t usage;
  ftun_runtime_manager_info_t manager;
  CHECK(fixture_start(&fixture, 4u, 100u) == 0);
  fill_real_metadata(&metadata);
  CHECK(make_packet(fixture.budget, bytes, sizeof(bytes), &packet) == 0);
  CHECK(ftun_udp_flow_input(fixture.core, &metadata, &packet) == FTUN_OK);
  CHECK(ftun_udp_flow_input(fixture.core, &metadata, &packet) == FTUN_OK);
  CHECK(fixture.inbound_lookups == 2u && fixture.open_calls == 1u &&
        fixture.slots[0].sends == 2u &&
        endpoint_equal(&fixture.slots[0].target,
                       &metadata.original_target));
  CHECK(ftun_udp_flow_get_usage(fixture.table, &usage) == FTUN_OK &&
        usage.active == 1u && usage.created == 1u && usage.capacity == 4u);
  CHECK(install_runtime(&fixture, "two", 10002u) == 0);
  CHECK(ftun_runtime_manager_get_info(fixture.core, &manager) == FTUN_OK &&
        manager.generation == 2u && manager.retained_count == 1u);
  CHECK(ftun_udp_flow_input(fixture.core, &metadata, &packet) == FTUN_OK &&
        fixture.open_calls == 1u && fixture.slots[0].sends == 3u);
  metadata.generation = 2u;
  CHECK(ftun_udp_flow_input(fixture.core, &metadata, &packet) == FTUN_OK &&
        fixture.open_calls == 2u && fixture.opened_generation == 2u &&
        fixture.opened_outbound_id == 77u);
  metadata.source.port++;
  CHECK(ftun_udp_flow_input(fixture.core, &metadata, &packet) == FTUN_OK &&
        fixture.open_calls == 3u);
  metadata.original_target.address[3] = 9u;
  CHECK(ftun_udp_flow_input(fixture.core, &metadata, &packet) == FTUN_OK &&
        fixture.open_calls == 4u);
  metadata.source.port++;
  CHECK(ftun_udp_flow_input(fixture.core, &metadata, &packet) == FTUN_E_LIMIT &&
        fixture.open_calls == 4u);
  CHECK(ftun_udp_flow_tick(fixture.table, 1099u) == FTUN_OK);
  CHECK(ftun_udp_flow_get_usage(fixture.table, &usage) == FTUN_OK &&
        usage.active == 4u);
  CHECK(ftun_udp_flow_tick(fixture.table, 1100u) == FTUN_OK);
  CHECK(ftun_udp_flow_get_usage(fixture.table, &usage) == FTUN_OK &&
        usage.active == 0u && usage.expired == 4u);
  CHECK(ftun_runtime_manager_get_info(fixture.core, &manager) == FTUN_OK &&
        manager.retained_count == 0u);
  CHECK(ftun_packet_release(&packet) == FTUN_OK);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_fake_reply_and_fixed_remote(void)
{
  static const uint8_t query[] = {'q'};
  static const uint8_t answer[] = {'a', 'n', 's'};
  fixture_t fixture;
  ftun_metadata_t metadata;
  ftun_endpoint_t resolved[2];
  ftun_endpoint_t changed[1];
  ftun_packet_t packet = {{0}, 0u};
  ftun_packet_t response = {{0}, 0u};
  ftun_udp_flow_usage_t usage;
  char domain[] = "fake.example";
  CHECK(fixture_start(&fixture, 4u, 1000u) == 0);
  fill_fake_metadata(&metadata, resolved, domain);
  fixture.inbound_wire_source = metadata.original_target;
  CHECK(make_packet(fixture.budget, query, sizeof(query), &packet) == 0);
  CHECK(ftun_udp_flow_input_on(fixture.table, fixture.inbound,
        &metadata, &packet) == FTUN_OK);
  CHECK(fixture.open_calls == 1u && fixture.slots[0].sends == 1u &&
        endpoint_equal(&fixture.slots[0].target, &resolved[0]));
  CHECK(make_packet(fixture.budget, answer, sizeof(answer), &response) == 0);
  CHECK(ftun_datagram_deliver(fixture.slots[0].channel, &resolved[1],
        &response) == FTUN_E_REJECTED && fixture.inbound_sends == 0u);
  CHECK(ftun_udp_flow_get_usage(fixture.table, &usage) == FTUN_OK &&
        usage.rejected_sources == 1u);
  CHECK(ftun_datagram_deliver(fixture.slots[0].channel, &resolved[0],
        &response) == FTUN_OK && fixture.inbound_sends == 1u &&
        endpoint_equal(&fixture.inbound_target, &metadata.source) &&
        endpoint_equal(&fixture.inbound_wire_source,
                       &metadata.original_target) &&
        fixture.inbound_payload_length == sizeof(answer) &&
        memcmp(fixture.inbound_payload, answer, sizeof(answer)) == 0);
  changed[0] = resolved[1];
  metadata.resolved = changed;
  metadata.resolved_count = 1u;
  CHECK(ftun_udp_flow_input_on(fixture.table, fixture.inbound,
        &metadata, &packet) == FTUN_OK && fixture.open_calls == 1u &&
        fixture.slots[0].sends == 2u &&
        endpoint_equal(&fixture.slots[0].target, &resolved[0]));
  CHECK(ftun_packet_release(&response) == FTUN_OK);
  CHECK(ftun_packet_release(&packet) == FTUN_OK);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_failure_no_replay_and_cancel(void)
{
  static const uint8_t bytes[] = {'x'};
  fixture_t fixture;
  ftun_metadata_t metadata;
  ftun_endpoint_t resolved[2];
  ftun_packet_t packet = {{0}, 0u};
  ftun_udp_flow_usage_t usage;
  char domain[] = "no-replay.example";
  CHECK(fixture_start(&fixture, 2u, 1000u) == 0);
  fill_fake_metadata(&metadata, resolved, domain);
  CHECK(make_packet(fixture.budget, bytes, sizeof(bytes), &packet) == 0);
  fixture.send_start_status = FTUN_E_IO;
  CHECK(ftun_udp_flow_input(fixture.core, &metadata, &packet) == FTUN_E_IO &&
        fixture.open_calls == 1u && fixture.slot_count == 1u &&
        fixture.slots[0].sends == 1u && fixture.slots[0].destroyed == 1);
  CHECK(ftun_udp_flow_get_usage(fixture.table, &usage) == FTUN_OK &&
        usage.active == 0u && usage.failed == 1u);
  fixture.send_start_status = FTUN_OK;
  fixture.async_send = 1;
  CHECK(ftun_udp_flow_input(fixture.core, &metadata, &packet) == FTUN_OK &&
        fixture.slots[1].pending != NULL);
  CHECK(complete_pending(&fixture.slots[1], FTUN_E_IO) == 0);
  CHECK(ftun_udp_flow_tick(fixture.table, 1000u) == FTUN_OK);
  CHECK(ftun_udp_flow_get_usage(fixture.table, &usage) == FTUN_OK &&
        usage.active == 0u && usage.failed == 2u);
  CHECK(ftun_udp_flow_input(fixture.core, &metadata, &packet) == FTUN_OK &&
        fixture.slots[2].pending != NULL);
  fixture.cancel_failures = 1;
  CHECK(ftun_udp_flow_table_destroy(&fixture.table) == FTUN_E_AGAIN &&
        fixture.table != NULL);
  CHECK(ftun_udp_flow_table_destroy(&fixture.table) == FTUN_OK &&
        fixture.table == NULL && fixture.slots[2].destroyed == 1);
  CHECK(ftun_packet_release(&packet) == FTUN_OK);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_boundaries(void)
{
  static const uint8_t bytes[] = {'b'};
  fixture_t fixture;
  ftun_metadata_t metadata;
  ftun_endpoint_t resolved[2];
  ftun_packet_t packet = {{0}, 0u};
  ftun_udp_flow_table_t *other = (ftun_udp_flow_table_t *)(uintptr_t)1u;
  ftun_udp_flow_table_spec_t spec;
  char domain[] = "boundary.example";
  CHECK(fixture_start(&fixture, 2u, 100u) == 0);
  fill_fake_metadata(&metadata, resolved, domain);
  CHECK(make_packet(fixture.budget, bytes, sizeof(bytes), &packet) == 0);
  metadata.network = 1u;
  CHECK(ftun_udp_flow_input(fixture.core, &metadata, &packet) == FTUN_E_INVALID);
  metadata.network = 2u;
  metadata.resolved_count = 0u;
  CHECK(ftun_udp_flow_input(fixture.core, &metadata, &packet) == FTUN_E_INVALID);
  metadata.resolved_count = 2u;
  resolved[1] = resolved[0];
  CHECK(ftun_udp_flow_input(fixture.core, &metadata, &packet) == FTUN_E_INVALID);
  resolved[1] = ipv4(1u, 1u, 1u, 1u, 53u);
  metadata.generation = 9u;
  CHECK(ftun_udp_flow_input(fixture.core, &metadata, &packet) == FTUN_E_STALE &&
        fixture.open_calls == 0u);
  metadata.generation = 1u;
  fixture.corrupt_remote = 1;
  CHECK(ftun_udp_flow_input(fixture.core, &metadata, &packet) ==
        FTUN_E_STATE_CORRUPT && fixture.slots[0].destroyed == 1);
  fixture.corrupt_remote = 0;
  fixture.corrupt_outbound_id = 1;
  CHECK(ftun_udp_flow_input(fixture.core, &metadata, &packet) == FTUN_OK &&
        fixture.opened_outbound_id == FTUN_OUTBOUND_ID_DIRECT &&
        fixture.slots[1].destroyed == 0);
  CHECK(ftun_udp_flow_tick(fixture.table, 999u) == FTUN_E_INVALID);
  memset(&spec, 0, sizeof(spec));
  spec.core = fixture.core;
  spec.budget = fixture.budget;
  spec.capacity = 1u;
  spec.idle_timeout_ms = 1u;
  spec.backend.open = open_outbound;
  CHECK(ftun_udp_flow_table_create(&spec, &other) == FTUN_E_INVALID &&
        other == NULL);
  CHECK(ftun_udp_flow_input(NULL, &metadata, &packet) == FTUN_E_INVALID);
  CHECK(ftun_udp_flow_input_on(NULL, fixture.inbound,
        &metadata, &packet) == FTUN_E_INVALID);
  CHECK(ftun_udp_flow_get_usage(NULL, &(ftun_udp_flow_usage_t){0}) ==
        FTUN_E_INVALID);
  CHECK(ftun_udp_flow_table_destroy(NULL) == FTUN_E_INVALID);
  CHECK(ftun_packet_release(&packet) == FTUN_OK);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

int main(void)
{
  CHECK(test_key_runtime_and_idle() == 0);
  CHECK(test_fake_reply_and_fixed_remote() == 0);
  CHECK(test_failure_no_replay_and_cancel() == 0);
  CHECK(test_boundaries() == 0);
  return 0;
}
