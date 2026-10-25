#include "core/budget.h"
#include "core/operation.h"
#include "proxy/tun/ingress.h"
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

#define OUTPUT_CAPACITY 64u
#define PACKET_CAPACITY 1600u

typedef struct {
  ftun_budget_t *budget;
  ftun_operation_queue_t *operations;
  ftun_core_t *core;
  ftun_packet_port_t *port;
  ftun_tun_ingress_context_t *ingress;
  ftun_stream_t *stream;
  ftun_datagram_t *datagram;
  ftun_metadata_t tcp_metadata;
  ftun_metadata_t udp_metadata;
  ftun_endpoint_t datagram_source;
  uint8_t datagram_payload[64];
  size_t datagram_length;
  uint8_t outputs[OUTPUT_CAPACITY][PACKET_CAPACITY];
  size_t output_lengths[OUTPUT_CAPACITY];
  size_t output_count;
  size_t stream_accepts;
  size_t stream_events;
  size_t datagrams;
  size_t write_completions;
  ftun_status_t write_status;
  ftun_status_t stream_accept_status;
  int callback_failed;
} fixture_t;

static void put_u16(uint8_t *target, uint16_t value)
{
  target[0] = (uint8_t)(value >> 8);
  target[1] = (uint8_t)value;
}

static void put_u32(uint8_t *target, uint32_t value)
{
  target[0] = (uint8_t)(value >> 24);
  target[1] = (uint8_t)(value >> 16);
  target[2] = (uint8_t)(value >> 8);
  target[3] = (uint8_t)value;
}

static uint16_t get_u16(const uint8_t *source)
{
  return (uint16_t)(((uint16_t)source[0] << 8) | source[1]);
}

static uint32_t get_u32(const uint8_t *source)
{
  return ((uint32_t)source[0] << 24) | ((uint32_t)source[1] << 16) |
         ((uint32_t)source[2] << 8) | source[3];
}

static uint32_t checksum_add(uint32_t sum, const uint8_t *data, size_t length)
{
  while (length >= 2u) {
    sum += ((uint32_t)data[0] << 8) | data[1];
    data += 2;
    length -= 2u;
  }
  if (length != 0u) sum += (uint32_t)data[0] << 8;
  return sum;
}

static uint16_t checksum_finish(uint32_t sum)
{
  while ((sum >> 16) != 0u) sum = (sum & 0xffffu) + (sum >> 16);
  return (uint16_t)~sum;
}

static size_t make_tcp_packet(uint8_t *packet, size_t capacity,
                              const uint8_t source[4], const uint8_t target[4],
                              uint16_t source_port, uint16_t target_port,
                              uint32_t sequence, uint32_t acknowledgement,
                              uint8_t flags, const uint8_t *payload,
                              size_t payload_length)
{
  uint8_t pseudo[4];
  uint8_t *tcp;
  uint32_t sum;
  size_t total = 40u + payload_length;
  if (capacity < total || total > 65535u) return 0u;
  memset(packet, 0, total);
  packet[0] = 0x45u;
  put_u16(packet + 2u, (uint16_t)total);
  put_u16(packet + 4u, 7u);
  put_u16(packet + 6u, 0x4000u);
  packet[8] = 64u;
  packet[9] = 6u;
  memcpy(packet + 12u, source, 4u);
  memcpy(packet + 16u, target, 4u);
  put_u16(packet + 10u, checksum_finish(checksum_add(0u, packet, 20u)));
  tcp = packet + 20u;
  put_u16(tcp, source_port);
  put_u16(tcp + 2u, target_port);
  put_u32(tcp + 4u, sequence);
  put_u32(tcp + 8u, acknowledgement);
  tcp[12] = 0x50u;
  tcp[13] = flags;
  put_u16(tcp + 14u, 16384u);
  if (payload_length != 0u) memcpy(tcp + 20u, payload, payload_length);
  sum = checksum_add(0u, source, 4u);
  sum = checksum_add(sum, target, 4u);
  pseudo[0] = 0u;
  pseudo[1] = 6u;
  put_u16(pseudo + 2u, (uint16_t)(20u + payload_length));
  sum = checksum_add(sum, pseudo, sizeof(pseudo));
  sum = checksum_add(sum, tcp, 20u + payload_length);
  put_u16(tcp + 16u, checksum_finish(sum));
  return total;
}

static size_t make_udp_packet(uint8_t *packet, size_t capacity,
                              const uint8_t source[4], const uint8_t target[4],
                              uint16_t source_port, uint16_t target_port,
                              const uint8_t *payload, size_t payload_length)
{
  size_t total = 28u + payload_length;
  if (capacity < total || total > 65535u) return 0u;
  memset(packet, 0, total);
  packet[0] = 0x45u;
  put_u16(packet + 2u, (uint16_t)total);
  put_u16(packet + 4u, 11u);
  put_u16(packet + 6u, 0x4000u);
  packet[8] = 64u;
  packet[9] = 17u;
  memcpy(packet + 12u, source, 4u);
  memcpy(packet + 16u, target, 4u);
  put_u16(packet + 10u, checksum_finish(checksum_add(0u, packet, 20u)));
  put_u16(packet + 20u, source_port);
  put_u16(packet + 22u, target_port);
  put_u16(packet + 24u, (uint16_t)(8u + payload_length));
  if (payload_length != 0u) memcpy(packet + 28u, payload, payload_length);
  return total;
}

static ftun_status_t capture_output(void *user, ftun_bytes_t packet)
{
  fixture_t *fixture = (fixture_t *)user;
  size_t index = fixture->output_count;
  if (index >= OUTPUT_CAPACITY || packet.length > PACKET_CAPACITY) {
    return FTUN_E_LIMIT;
  }
  memcpy(fixture->outputs[index], packet.data, packet.length);
  fixture->output_lengths[index] = packet.length;
  fixture->output_count++;
  return FTUN_OK;
}

static ftun_status_t accept_stream(void *user,
                                   const ftun_metadata_t *metadata,
                                   ftun_stream_t *stream)
{
  fixture_t *fixture = (fixture_t *)user;
  fixture->stream_accepts++;
  fixture->tcp_metadata = *metadata;
  if (fixture->stream_accept_status != FTUN_OK) {
    return fixture->stream_accept_status;
  }
  fixture->stream = stream;
  return FTUN_OK;
}

static void stream_event(void *user, ftun_stream_t *stream,
                         ftun_tun_stream_event_t event,
                         ftun_status_t status)
{
  fixture_t *fixture = (fixture_t *)user;
  if (stream != fixture->stream || status != FTUN_OK ||
      event < FTUN_TUN_STREAM_READABLE || event > FTUN_TUN_STREAM_CLOSED) {
    fixture->callback_failed = 1;
  }
  fixture->stream_events++;
}

static void write_completion(ftun_operation_t *operation,
                             ftun_error_t result, void *user)
{
  fixture_t *fixture = (fixture_t *)user;
  if (operation == NULL) fixture->callback_failed = 1;
  fixture->write_status = result.status;
  fixture->write_completions++;
}

static ftun_status_t receive_datagram(
  void *user, const ftun_metadata_t *metadata, ftun_datagram_t *channel,
  const ftun_endpoint_t *source, const ftun_packet_t *packet)
{
  fixture_t *fixture = (fixture_t *)user;
  ftun_bytes_t payload;
  if (ftun_packet_view(packet, &payload) != FTUN_OK ||
      payload.length > sizeof(fixture->datagram_payload)) {
    return FTUN_E_LIMIT;
  }
  fixture->udp_metadata = *metadata;
  fixture->datagram_source = *source;
  fixture->datagram = channel;
  memcpy(fixture->datagram_payload, payload.data, payload.length);
  fixture->datagram_length = payload.length;
  fixture->datagrams++;
  return FTUN_OK;
}

static void fill_spec(fixture_t *fixture, ftun_tun_ingress_spec_t *spec,
                      bool tcp, bool udp)
{
  memset(spec, 0, sizeof(*spec));
  spec->budget = fixture->budget;
  spec->operations = fixture->operations;
  spec->generation = 7u;
  spec->now_ms = 1000u;
  spec->inbound_id = 13u;
  spec->mtu = 1500u;
  spec->max_pending_stream_writes = 8u;
  spec->max_pending_stream_bytes = 65536u;
  spec->max_pending_datagrams = 8u;
  spec->max_pending_datagram_bytes = 65536u;
  spec->tcp = tcp;
  spec->udp = udp;
  spec->stream_write_completion = write_completion;
  spec->stream_accept = accept_stream;
  spec->stream_event = stream_event;
  spec->datagram_receive = receive_datagram;
  spec->output = capture_output;
  spec->user = fixture;
}

static int fixture_start(fixture_t *fixture, bool tcp, bool udp)
{
  ftun_tun_ingress_spec_t spec;
  memset(fixture, 0, sizeof(*fixture));
  fixture->core = (ftun_core_t *)(uintptr_t)0x101u;
  fixture->port = (ftun_packet_port_t *)(uintptr_t)0x202u;
  if (ftun_budget_create(NULL, 4u * 1024u * 1024u, 4096u,
                         &fixture->budget) != FTUN_OK) return 1;
  if (ftun_operation_queue_create(fixture->budget, 32u,
                                  &fixture->operations) != FTUN_OK) return 1;
  fill_spec(fixture, &spec, tcp, udp);
  return ftun_tun_ingress_bind(&spec, &fixture->ingress) == FTUN_OK ? 0 : 1;
}

static int fixture_stop(fixture_t *fixture)
{
  ftun_budget_usage_t usage;
  if (ftun_tun_ingress_close(&fixture->ingress) != FTUN_OK) return 1;
  if (ftun_operation_queue_stop(fixture->operations) != FTUN_OK) return 1;
  if (ftun_operation_queue_destroy(&fixture->operations) != FTUN_OK) return 1;
  if (ftun_budget_get_usage(fixture->budget, &usage) != FTUN_OK ||
      usage.used != 0u) return 1;
  return ftun_budget_destroy(&fixture->budget) == FTUN_OK ? 0 : 1;
}

static ftun_status_t input_packet(fixture_t *fixture, const uint8_t *bytes,
                                  size_t length, uint32_t source_id)
{
  ftun_buffer_t *buffer = NULL;
  ftun_buffer_slice_t slice = {0};
  ftun_packet_t packet = {{0}, 0u};
  uint8_t *storage = NULL;
  size_t capacity = 0u;
  ftun_status_t status;
  if (ftun_buffer_acquire(fixture->budget, length, &buffer) != FTUN_OK ||
      ftun_buffer_data(buffer, &storage, &capacity) != FTUN_OK ||
      capacity < length) return FTUN_E_LIMIT;
  memcpy(storage, bytes, length);
  if (ftun_buffer_slice(buffer, 0u, length, &slice) != FTUN_OK ||
      ftun_packet_init(&packet, &slice, source_id) != FTUN_OK) {
    (void)ftun_buffer_slice_release(&slice);
    (void)ftun_buffer_release(&buffer);
    return FTUN_E_LIMIT;
  }
  (void)ftun_buffer_slice_release(&slice);
  (void)ftun_buffer_release(&buffer);
  status = ftun_tun_ingress(fixture->ingress, &packet);
  if (ftun_packet_release(&packet) != FTUN_OK) return FTUN_E_STATE_CORRUPT;
  return status;
}

static int establish_tcp(fixture_t *fixture, uint32_t *server_sequence)
{
  static const uint8_t source[4] = {10u, 0u, 0u, 2u};
  static const uint8_t target[4] = {1u, 1u, 1u, 1u};
  uint8_t packet[64];
  const uint8_t *response;
  size_t response_length;
  size_t header_length;
  size_t length;
  length = make_tcp_packet(packet, sizeof(packet), source, target,
                           12345u, 443u, 1000u, 0u, 0x02u, NULL, 0u);
  CHECK(input_packet(fixture, packet, length, 13u) == FTUN_OK);
  CHECK(fixture->output_count != 0u);
  response = fixture->outputs[fixture->output_count - 1u];
  response_length = fixture->output_lengths[fixture->output_count - 1u];
  header_length = (size_t)(response[0] & 0x0fu) * 4u;
  CHECK(response_length >= header_length + 20u);
  CHECK(get_u16(response + header_length) == 443u);
  CHECK((response[header_length + 13u] & 0x12u) == 0x12u);
  *server_sequence = get_u32(response + header_length + 4u);
  length = make_tcp_packet(packet, sizeof(packet), source, target,
                           12345u, 443u, 1001u, *server_sequence + 1u,
                           0x10u, NULL, 0u);
  CHECK(input_packet(fixture, packet, length, 13u) == FTUN_OK);
  CHECK(fixture->stream_accepts == 1u && fixture->stream != NULL);
  return 0;
}

static int test_tcp_stream(void)
{
  static const uint8_t source[4] = {10u, 0u, 0u, 2u};
  static const uint8_t target[4] = {1u, 1u, 1u, 1u};
  static const uint8_t hello[] = {'h', 'e', 'l', 'l', 'o'};
  static const uint8_t reply[] = {'w', 'o', 'r', 'l', 'd'};
  fixture_t fixture;
  ftun_tun_ingress_usage_t ingress_usage;
  ftun_stream_usage_t stream_usage;
  ftun_buffer_t *buffer = NULL;
  ftun_buffer_slice_t slice = {0};
  ftun_operation_t *operation = NULL;
  uint8_t *storage = NULL;
  size_t capacity = 0u;
  uint8_t packet[128];
  uint8_t read_buffer[16];
  uint32_t server_sequence;
  uint32_t reply_sequence = 0u;
  size_t accepted = 0u;
  size_t dispatched = 0u;
  size_t length;
  size_t index;

  CHECK(fixture_start(&fixture, true, false) == 0);
  CHECK(establish_tcp(&fixture, &server_sequence) == 0);
  CHECK(fixture.tcp_metadata.generation == 7u &&
        fixture.tcp_metadata.inbound_id == 13u &&
        fixture.tcp_metadata.network == 1u &&
        fixture.tcp_metadata.source.port == 12345u &&
        fixture.tcp_metadata.original_target.port == 443u);
  length = make_tcp_packet(packet, sizeof(packet), source, target,
                           12345u, 443u, 1001u, server_sequence + 1u,
                           0x18u, hello, sizeof(hello));
  CHECK(input_packet(&fixture, packet, length, 13u) == FTUN_OK);
  CHECK(fixture.stream_events >= 1u && fixture.callback_failed == 0);
  CHECK(ftun_stream_read(fixture.stream, read_buffer, 2u, &length) == FTUN_OK &&
        length == 2u && memcmp(read_buffer, hello, 2u) == 0);
  CHECK(ftun_stream_read(fixture.stream, read_buffer, sizeof(read_buffer),
                         &length) == FTUN_OK && length == 3u &&
        memcmp(read_buffer, hello + 2u, 3u) == 0);
  CHECK(ftun_stream_read(fixture.stream, read_buffer, sizeof(read_buffer),
                         &length) == FTUN_E_AGAIN && length == 0u);

  CHECK(ftun_buffer_acquire(fixture.budget, sizeof(reply), &buffer) == FTUN_OK);
  CHECK(ftun_buffer_data(buffer, &storage, &capacity) == FTUN_OK &&
        capacity >= sizeof(reply));
  memcpy(storage, reply, sizeof(reply));
  CHECK(ftun_buffer_slice(buffer, 0u, sizeof(reply), &slice) == FTUN_OK);
  CHECK(ftun_buffer_release(&buffer) == FTUN_OK);
  CHECK(ftun_stream_write_ref(fixture.stream, &slice, &accepted,
                              &operation) == FTUN_OK &&
        accepted == sizeof(reply) && operation != NULL);
  CHECK(ftun_buffer_slice_release(&slice) == FTUN_OK);
  CHECK(ftun_stream_get_usage(fixture.stream, &stream_usage) == FTUN_OK &&
        stream_usage.pending_writes == 1u);
  for (index = fixture.output_count; index != 0u; index--) {
    const uint8_t *output = fixture.outputs[index - 1u];
    size_t output_length = fixture.output_lengths[index - 1u];
    size_t ip_length = (size_t)(output[0] & 0x0fu) * 4u;
    size_t tcp_length = (size_t)(output[ip_length + 12u] >> 4) * 4u;
    if (output_length == ip_length + tcp_length + sizeof(reply)) {
      reply_sequence = get_u32(output + ip_length + 4u);
      break;
    }
  }
  CHECK(reply_sequence != 0u);
  length = make_tcp_packet(packet, sizeof(packet), source, target,
                           12345u, 443u, 1006u,
                           reply_sequence + (uint32_t)sizeof(reply),
                           0x10u, NULL, 0u);
  CHECK(input_packet(&fixture, packet, length, 13u) == FTUN_OK);
  CHECK(ftun_operation_dispatch(fixture.operations, 8u, &dispatched) ==
        FTUN_OK && dispatched == 1u && fixture.write_completions == 1u &&
        fixture.write_status == FTUN_OK);
  CHECK(ftun_stream_get_usage(fixture.stream, &stream_usage) == FTUN_OK &&
        stream_usage.pending_writes == 0u);

  length = make_tcp_packet(packet, sizeof(packet), source, target,
                           12345u, 443u, 1006u,
                           reply_sequence + (uint32_t)sizeof(reply),
                           0x11u, NULL, 0u);
  CHECK(input_packet(&fixture, packet, length, 13u) == FTUN_OK);
  CHECK(ftun_stream_read(fixture.stream, read_buffer, sizeof(read_buffer),
                         &length) == FTUN_E_EOF && length == 0u);
  CHECK(ftun_tun_ingress_get_usage(fixture.ingress, &ingress_usage) ==
        FTUN_OK && ingress_usage.tcp_streams == 1u &&
        ingress_usage.udp_channels == 0u);
  CHECK(ftun_tun_ingress_close(&fixture.ingress) == FTUN_E_AGAIN &&
        fixture.ingress != NULL);
  CHECK(ftun_stream_destroy(&fixture.stream) == FTUN_OK &&
        fixture.stream == NULL);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_close_pending_tcp_write(void)
{
  static const uint8_t reply[] = {'p', 'e', 'n', 'd'};
  fixture_t fixture;
  ftun_buffer_t *buffer = NULL;
  ftun_buffer_slice_t slice = {0};
  ftun_operation_t *operation = NULL;
  uint8_t *storage = NULL;
  size_t capacity = 0u;
  size_t accepted = 0u;
  size_t dispatched = 0u;
  uint32_t server_sequence;
  CHECK(fixture_start(&fixture, true, false) == 0);
  CHECK(establish_tcp(&fixture, &server_sequence) == 0);
  CHECK(ftun_buffer_acquire(fixture.budget, sizeof(reply), &buffer) == FTUN_OK);
  CHECK(ftun_buffer_data(buffer, &storage, &capacity) == FTUN_OK &&
        capacity >= sizeof(reply));
  memcpy(storage, reply, sizeof(reply));
  CHECK(ftun_buffer_slice(buffer, 0u, sizeof(reply), &slice) == FTUN_OK);
  CHECK(ftun_buffer_release(&buffer) == FTUN_OK);
  CHECK(ftun_stream_write_ref(fixture.stream, &slice, &accepted,
                              &operation) == FTUN_OK &&
        accepted == sizeof(reply) && operation != NULL);
  CHECK(ftun_buffer_slice_release(&slice) == FTUN_OK);
  CHECK(ftun_tun_ingress_close(&fixture.ingress) == FTUN_E_AGAIN);
  CHECK(ftun_operation_dispatch(fixture.operations, 8u, &dispatched) ==
        FTUN_OK && dispatched == 1u && fixture.write_completions == 1u &&
        fixture.write_status == FTUN_E_CANCELLED);
  CHECK(ftun_stream_destroy(&fixture.stream) == FTUN_OK);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int packet_from_payload(ftun_budget_t *budget, const uint8_t *data,
                               size_t length, ftun_packet_t *packet)
{
  ftun_buffer_t *buffer = NULL;
  ftun_buffer_slice_t slice = {0};
  uint8_t *storage = NULL;
  size_t capacity = 0u;
  if (ftun_buffer_acquire(budget, length == 0u ? 1u : length,
                          &buffer) != FTUN_OK ||
      ftun_buffer_data(buffer, &storage, &capacity) != FTUN_OK) return 1;
  if (length != 0u) memcpy(storage, data, length);
  if (ftun_buffer_slice(buffer, 0u, length, &slice) != FTUN_OK ||
      ftun_packet_init(packet, &slice, 99u) != FTUN_OK) return 1;
  (void)ftun_buffer_slice_release(&slice);
  return ftun_buffer_release(&buffer) == FTUN_OK ? 0 : 1;
}

static int test_udp_datagram(void)
{
  static const uint8_t client[4] = {10u, 0u, 0u, 3u};
  static const uint8_t target[4] = {8u, 8u, 8u, 8u};
  static const uint8_t query[] = {'p', 'i', 'n', 'g'};
  static const uint8_t reply[] = {'p', 'o', 'n', 'g'};
  fixture_t fixture;
  ftun_tun_ingress_usage_t usage;
  ftun_packet_t response = {{0}, 0u};
  ftun_endpoint_t wrong;
  uint8_t packet[128];
  const uint8_t *output;
  size_t header_length;
  size_t length;

  CHECK(fixture_start(&fixture, false, true) == 0);
  length = make_udp_packet(packet, sizeof(packet), client, target,
                           53000u, 53u, query, sizeof(query));
  CHECK(input_packet(&fixture, packet, length, 13u) == FTUN_OK);
  CHECK(fixture.datagrams == 1u && fixture.datagram != NULL &&
        fixture.datagram_length == sizeof(query) &&
        memcmp(fixture.datagram_payload, query, sizeof(query)) == 0);
  CHECK(fixture.udp_metadata.generation == 7u &&
        fixture.udp_metadata.inbound_id == 13u &&
        fixture.udp_metadata.network == 2u &&
        fixture.udp_metadata.source.port == 53000u &&
        fixture.udp_metadata.original_target.port == 53u &&
        fixture.datagram_source.port == 53u);
  CHECK(ftun_tun_ingress_get_usage(fixture.ingress, &usage) == FTUN_OK &&
        usage.tcp_streams == 0u && usage.udp_channels == 1u);
  CHECK(packet_from_payload(fixture.budget, reply, sizeof(reply),
                            &response) == 0);
  wrong = fixture.udp_metadata.source;
  wrong.port++;
  CHECK(ftun_datagram_send(fixture.datagram, &wrong, &response) ==
        FTUN_E_REJECTED);
  CHECK(ftun_datagram_send(fixture.datagram,
        &fixture.udp_metadata.source, &response) == FTUN_OK);
  CHECK(ftun_packet_release(&response) == FTUN_OK);
  CHECK(fixture.output_count == 1u);
  output = fixture.outputs[0];
  header_length = (size_t)(output[0] & 0x0fu) * 4u;
  CHECK(fixture.output_lengths[0] == header_length + 8u + sizeof(reply));
  CHECK(output[9] == 17u && memcmp(output + 12u, target, 4u) == 0 &&
        memcmp(output + 16u, client, 4u) == 0 &&
        get_u16(output + header_length) == 53u &&
        get_u16(output + header_length + 2u) == 53000u &&
        memcmp(output + header_length + 8u, reply, sizeof(reply)) == 0);
  CHECK(input_packet(&fixture, packet, length, 13u) == FTUN_OK &&
        fixture.datagrams == 2u);
  CHECK(ftun_datagram_retain(fixture.datagram) == FTUN_OK);
  CHECK(ftun_tun_ingress_close(&fixture.ingress) == FTUN_E_AGAIN &&
        fixture.ingress != NULL);
  CHECK(ftun_tun_ingress_get_usage(fixture.ingress, &usage) == FTUN_OK &&
        !usage.accepting && usage.udp_channels == 1u);
  CHECK(packet_from_payload(fixture.budget, reply, sizeof(reply), &response) == 0);
  CHECK(ftun_datagram_send(fixture.datagram, &fixture.udp_metadata.source,
        &response) == FTUN_E_CANCELLED && fixture.output_count == 1u);
  CHECK(ftun_packet_release(&response) == FTUN_OK);
  CHECK(ftun_datagram_release(&fixture.datagram) == FTUN_OK);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_bounded_udp_close(void)
{
  fixture_t fixture;
  ftun_datagram_t *held;
  ftun_tun_ingress_usage_t usage;
  ftun_packet_t reply = {0};
  static const uint8_t client[4] = {10u, 0u, 0u, 3u};
  static const uint8_t target[4] = {8u, 8u, 8u, 8u};
  uint8_t packet[128];
  size_t length, work;
  CHECK(fixture_start(&fixture, false, true) == 0);
  length = make_udp_packet(packet, sizeof(packet), client, target, 53000u, 53u, NULL, 0u);
  CHECK(input_packet(&fixture, packet, length, 13u) == FTUN_OK);
  held = fixture.datagram;
  CHECK(ftun_datagram_retain(held) == FTUN_OK);
  length = make_udp_packet(packet, sizeof(packet), client, target, 53001u, 53u, NULL, 0u);
  CHECK(input_packet(&fixture, packet, length, 13u) == FTUN_OK);
  CHECK(ftun_tun_ingress_quiesce(fixture.ingress) == FTUN_OK);
  CHECK(input_packet(&fixture, packet, length, 13u) == FTUN_E_CANCELLED);
  CHECK(packet_from_payload(fixture.budget, (const uint8_t *)"x", 1u, &reply) == 0);
  CHECK(ftun_datagram_send(fixture.datagram, &fixture.udp_metadata.source, &reply) == FTUN_E_CANCELLED);
  CHECK(fixture.output_count == 0u);
  CHECK(ftun_tun_ingress_close_step(&fixture.ingress, 1u, &work) == FTUN_E_AGAIN && work == 1u);
  CHECK(ftun_tun_ingress_get_usage(fixture.ingress, &usage) == FTUN_OK && usage.udp_channels == 1u);
  CHECK(ftun_tun_ingress_close_step(&fixture.ingress, 1u, &work) == FTUN_E_AGAIN && work == 1u);
  CHECK(ftun_datagram_release(&held) == FTUN_OK);
  CHECK(ftun_tun_ingress_close_step(&fixture.ingress, 1u, &work) == FTUN_OK && work == 1u && fixture.ingress == NULL);
  CHECK(ftun_packet_release(&reply) == FTUN_OK);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_boundaries_and_rejection(void)
{
  static const uint8_t source[4] = {10u, 0u, 0u, 2u};
  static const uint8_t target[4] = {1u, 1u, 1u, 1u};
  fixture_t fixture;
  ftun_tun_ingress_spec_t spec;
  ftun_tun_ingress_context_t *other = (ftun_tun_ingress_context_t *)1;
  ftun_budget_t *tiny = NULL;
  uint8_t packet[64];
  size_t length;
  uint32_t server_sequence;
  const uint8_t *response;
  size_t header_length;

  memset(&fixture, 0, sizeof(fixture));
  fixture.core = (ftun_core_t *)(uintptr_t)0x101u;
  fixture.port = (ftun_packet_port_t *)(uintptr_t)0x202u;
  CHECK(ftun_tun_ingress(NULL,
        (ftun_packet_t *)(uintptr_t)0x303u) == FTUN_E_INVALID);
  CHECK(fixture_start(&fixture, true, false) == 0);
  length = make_udp_packet(packet, sizeof(packet), source, target,
                           1000u, 53u, NULL, 0u);
  CHECK(input_packet(&fixture, packet, length, 13u) == FTUN_E_UNSUPPORTED);
  packet[9] = 1u;
  CHECK(input_packet(&fixture, packet, length, 13u) == FTUN_E_UNSUPPORTED);
  packet[9] = 17u;
  CHECK(input_packet(&fixture, packet, length, 99u) == FTUN_E_REJECTED);
  put_u16(packet + 2u, (uint16_t)(length - 1u));
  CHECK(input_packet(&fixture, packet, length, 13u) == FTUN_E_PROTOCOL);
  packet[0] = 0x60u;
  CHECK(input_packet(&fixture, packet, length, 13u) == FTUN_E_PROTOCOL);
  fixture.stream_accept_status = FTUN_E_REJECTED;
  length = make_tcp_packet(packet, sizeof(packet), source, target,
                           12345u, 443u, 1000u, 0u, 0x02u, NULL, 0u);
  CHECK(input_packet(&fixture, packet, length, 13u) == FTUN_OK);
  response = fixture.outputs[fixture.output_count - 1u];
  header_length = (size_t)(response[0] & 0x0fu) * 4u;
  server_sequence = get_u32(response + header_length + 4u);
  length = make_tcp_packet(packet, sizeof(packet), source, target,
                           12345u, 443u, 1001u, server_sequence + 1u,
                           0x10u, NULL, 0u);
  CHECK(input_packet(&fixture, packet, length, 13u) == FTUN_OK);
  CHECK(fixture.stream_accepts == 1u && fixture.stream == NULL);
  CHECK(fixture_stop(&fixture) == 0);

  memset(&fixture, 0, sizeof(fixture));
  fixture.core = (ftun_core_t *)(uintptr_t)0x101u;
  fixture.port = (ftun_packet_port_t *)(uintptr_t)0x202u;
  CHECK(ftun_budget_create(NULL, 128u, 0u, &tiny) == FTUN_OK);
  fixture.budget = tiny;
  fixture.operations = (ftun_operation_queue_t *)(uintptr_t)0x404u;
  fill_spec(&fixture, &spec, true, false);
  CHECK(ftun_tun_ingress_bind(&spec, &other) == FTUN_E_LIMIT && other == NULL);
  CHECK(ftun_budget_destroy(&tiny) == FTUN_OK);
  CHECK(ftun_tun_ingress_bind(NULL, &other) == FTUN_E_INVALID && other == NULL);
  CHECK(ftun_tun_ingress_close(NULL) == FTUN_E_INVALID);
  return 0;
}

int main(void)
{
  CHECK(test_tcp_stream() == 0);
  CHECK(test_close_pending_tcp_write() == 0);
  CHECK(test_udp_datagram() == 0);
  CHECK(test_bounded_udp_close() == 0);
  CHECK(test_boundaries_and_rejection() == 0);
  return 0;
}
