#include "core/limits.h"
#include "proxy/netstack/lwip_adapter.h"
#include "libs/buffer/buffer.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
  if (!(condition)) { \
    fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #condition); \
    return 1; \
  } \
} while (0)

#define OUTPUT_CAPACITY 64u
#define PACKET_CAPACITY 1600u

typedef struct {
  uint8_t packets[OUTPUT_CAPACITY][PACKET_CAPACITY];
  size_t lengths[OUTPUT_CAPACITY];
  size_t output_count;
  ftun_lwip_tcp_t *flow;
  size_t accepts;
  size_t readable_events;
  size_t writable_events;
  size_t fin_events;
  size_t closed_events;
  int callback_failed;
  int reject_accept;
} test_context_t;

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

static ftun_status_t capture_output(void *user, ftun_bytes_t packet)
{
  test_context_t *context = (test_context_t *)user;
  size_t index = context->output_count;
  if (index >= OUTPUT_CAPACITY || packet.length > PACKET_CAPACITY) return FTUN_E_LIMIT;
  memcpy(context->packets[index], packet.data, packet.length);
  context->lengths[index] = packet.length;
  context->output_count++;
  return FTUN_OK;
}

static ftun_status_t accept_tcp(void *user, ftun_lwip_tcp_t *flow,
                                const ftun_endpoint_t *source,
                                const ftun_endpoint_t *target)
{
  static const uint8_t expected_source[4] = {10u, 0u, 0u, 2u};
  static const uint8_t expected_target[4] = {1u, 1u, 1u, 1u};
  test_context_t *context = (test_context_t *)user;
  context->accepts++;
  if (source->kind != FTUN_ADDRESS_IPV4 || target->kind != FTUN_ADDRESS_IPV4 ||
      memcmp(source->address, expected_source, 4u) != 0 ||
      memcmp(target->address, expected_target, 4u) != 0 ||
      source->port != 12345u || target->port != 443u) {
    context->callback_failed = 1;
    return FTUN_E_PROTOCOL;
  }
  if (context->reject_accept) return FTUN_E_REJECTED;
  context->flow = flow;
  return FTUN_OK;
}

static void tcp_event(void *user, ftun_lwip_tcp_t *flow,
                      ftun_lwip_tcp_event_t event, ftun_status_t status)
{
  test_context_t *context = (test_context_t *)user;
  if (flow != context->flow || status != FTUN_OK) context->callback_failed = 1;
  if (event == FTUN_LWIP_TCP_READABLE) context->readable_events++;
  else if (event == FTUN_LWIP_TCP_WRITABLE) context->writable_events++;
  else if (event == FTUN_LWIP_TCP_PEER_FIN) context->fin_events++;
  else if (event == FTUN_LWIP_TCP_CLOSED) context->closed_events++;
}

static ftun_status_t input_bytes(ftun_lwip_t *stack, ftun_budget_t *budget,
                                 const uint8_t *bytes, size_t length)
{
  ftun_buffer_t *buffer = NULL;
  ftun_buffer_slice_t slice = {0};
  ftun_packet_t packet = {{0}, 0u};
  uint8_t *storage = NULL;
  size_t capacity = 0u;
  ftun_status_t status;
  if (ftun_buffer_acquire(budget, length, &buffer) != FTUN_OK ||
      ftun_buffer_data(buffer, &storage, &capacity) != FTUN_OK || capacity < length) {
    return FTUN_E_LIMIT;
  }
  memcpy(storage, bytes, length);
  if (ftun_buffer_slice(buffer, 0u, length, &slice) != FTUN_OK ||
      ftun_packet_init(&packet, &slice, 17u) != FTUN_OK) {
    (void)ftun_buffer_slice_release(&slice);
    (void)ftun_buffer_release(&buffer);
    return FTUN_E_LIMIT;
  }
  (void)ftun_buffer_slice_release(&slice);
  (void)ftun_buffer_release(&buffer);
  status = ftun_lwip_input(stack, &packet);
  if (ftun_packet_release(&packet) != FTUN_OK) return FTUN_E_STATE_CORRUPT;
  return status;
}

static int establish(ftun_lwip_t *stack, ftun_budget_t *budget,
                     test_context_t *context, uint32_t *server_sequence)
{
  static const uint8_t source[4] = {10u, 0u, 0u, 2u};
  static const uint8_t target[4] = {1u, 1u, 1u, 1u};
  uint8_t packet[64];
  const uint8_t *response;
  size_t response_length;
  size_t ip_length;
  size_t length;
  length = make_tcp_packet(packet, sizeof(packet), source, target, 12345u, 443u,
                           1000u, 0u, 0x02u, NULL, 0u);
  CHECK(length == 40u);
  CHECK(input_bytes(stack, budget, packet, length) == FTUN_OK);
  CHECK(context->output_count != 0u);
  response = context->packets[context->output_count - 1u];
  response_length = context->lengths[context->output_count - 1u];
  CHECK(response_length >= 40u && (response[0] >> 4) == 4u);
  ip_length = (size_t)(response[0] & 0x0fu) * 4u;
  CHECK(ip_length + 20u <= response_length);
  CHECK(get_u16(response + ip_length) == 443u);
  CHECK(get_u16(response + ip_length + 2u) == 12345u);
  CHECK((response[ip_length + 13u] & 0x12u) == 0x12u);
  CHECK(get_u32(response + ip_length + 8u) == 1001u);
  *server_sequence = get_u32(response + ip_length + 4u);
  length = make_tcp_packet(packet, sizeof(packet), source, target, 12345u, 443u,
                           1001u, *server_sequence + 1u, 0x10u, NULL, 0u);
  CHECK(input_bytes(stack, budget, packet, length) == FTUN_OK);
  CHECK(context->accepts == 1u);
  return 0;
}

static int test_tcp_lifecycle(void)
{
  static const uint8_t source[4] = {10u, 0u, 0u, 2u};
  static const uint8_t target[4] = {1u, 1u, 1u, 1u};
  static const uint8_t hello[] = {'h', 'e', 'l', 'l', 'o'};
  static const uint8_t reply[] = {'w', 'o', 'r', 'l', 'd'};
  ftun_budget_t *budget = NULL;
  ftun_lwip_t *stack = NULL;
  ftun_lwip_t *other = NULL;
  ftun_budget_t *other_budget = NULL;
  ftun_lwip_spec_t other_spec;
  ftun_lwip_spec_t spec;
  ftun_lwip_usage_t usage;
  ftun_budget_usage_t budget_usage;
  test_context_t context;
  ftun_lwip_segment_t segments[4];
  ftun_buffer_t *send_buffer = NULL;
  ftun_buffer_slice_t send_slice = {0};
  uint8_t *send_storage = NULL;
  size_t send_capacity = 0u;
  uint8_t packet[128];
  uint32_t server_sequence;
  uint32_t reply_sequence = 0u;
  uint64_t deadline_ms = 0u;
  size_t count;
  size_t available;
  size_t accepted;
  size_t length;
  size_t index;
  bool peer_finished;
  bool readable;
  bool writable;

  memset(&context, 0, sizeof(context));
  memset(&spec, 0, sizeof(spec));
  CHECK(ftun_budget_create(NULL, 4u * 1024u * 1024u, 4096u, &budget) == FTUN_OK);
  spec.budget = budget;
  spec.mtu = 1500u;
  spec.now_ms = 1000u;
  spec.output = capture_output;
  spec.accept = accept_tcp;
  spec.tcp_event = tcp_event;
  spec.user = &context;
  CHECK(ftun_lwip_create(&spec, &stack) == FTUN_OK);
  CHECK(ftun_lwip_next_deadline(stack, &deadline_ms) == FTUN_OK &&
        deadline_ms == 1250u);
  CHECK(ftun_lwip_create(&spec, &other) == FTUN_E_INVALID && other == NULL);
  CHECK(ftun_budget_create(NULL, 4u * 1024u * 1024u, 4096u,
                           &other_budget) == FTUN_OK);
  other_spec = spec;
  other_spec.budget = other_budget;
  CHECK(ftun_lwip_create(&other_spec, &other) == FTUN_E_INVALID && other == NULL);
  CHECK(ftun_budget_get_usage(other_budget, &budget_usage) == FTUN_OK &&
        budget_usage.used == 0u);
  CHECK(ftun_lwip_tick(stack, 999u) == FTUN_E_INVALID);
  CHECK(ftun_lwip_tick(stack, 2000u) == FTUN_OK);
  CHECK(ftun_lwip_next_deadline(stack, &deadline_ms) == FTUN_OK &&
        deadline_ms == 2250u);
  CHECK(ftun_lwip_get_usage(stack, &usage) == FTUN_OK);
  CHECK(usage.tcp_timer_ticks == 4u && usage.reassembly_timer_ticks == 1u);
  CHECK(establish(stack, budget, &context, &server_sequence) == 0);
  CHECK(context.flow != NULL && context.callback_failed == 0);
  CHECK(ftun_lwip_tcp_ready(context.flow, &readable, &writable) == FTUN_OK &&
        !readable && writable);

  length = make_tcp_packet(packet, sizeof(packet), source, target, 12345u, 443u,
                           1001u, server_sequence + 1u, 0x18u,
                           hello, sizeof(hello));
  CHECK(input_bytes(stack, budget, packet, length) == FTUN_OK);
  CHECK(context.readable_events == 1u);
  CHECK(ftun_lwip_tcp_ready(context.flow, &readable, &writable) == FTUN_OK &&
        readable);
  CHECK(ftun_lwip_tcp_peek(context.flow, segments, 4u, &count, &available,
                           &peer_finished) == FTUN_OK);
  CHECK(count >= 1u && available == sizeof(hello) && !peer_finished);
  CHECK(segments[0].length >= sizeof(hello));
  CHECK(memcmp(segments[0].data, hello, sizeof(hello)) == 0);
  CHECK(ftun_lwip_tcp_consume(context.flow, 2u) == FTUN_OK);
  CHECK(ftun_lwip_get_usage(stack, &usage) == FTUN_OK && usage.received_bytes == 3u);
  CHECK(ftun_lwip_tcp_consume(context.flow, 3u) == FTUN_OK);
  CHECK(ftun_lwip_get_usage(stack, &usage) == FTUN_OK && usage.received_bytes == 0u);
  CHECK(ftun_lwip_tcp_ready(context.flow, &readable, &writable) == FTUN_OK &&
        !readable);

  CHECK(ftun_buffer_acquire(budget, sizeof(reply), &send_buffer) == FTUN_OK);
  CHECK(ftun_buffer_data(send_buffer, &send_storage, &send_capacity) == FTUN_OK);
  CHECK(send_capacity >= sizeof(reply));
  memcpy(send_storage, reply, sizeof(reply));
  CHECK(ftun_buffer_slice(send_buffer, 0u, sizeof(reply), &send_slice) == FTUN_OK);
  CHECK(ftun_buffer_release(&send_buffer) == FTUN_OK);
  CHECK(ftun_lwip_tcp_write_ref(context.flow, &send_slice, &accepted) == FTUN_OK);
  CHECK(accepted == sizeof(reply));
  CHECK(ftun_buffer_slice_release(&send_slice) == FTUN_OK);
  CHECK(ftun_lwip_get_usage(stack, &usage) == FTUN_OK &&
        usage.retained_send_bytes == sizeof(reply));
  for (index = context.output_count; index != 0u; index--) {
    const uint8_t *output = context.packets[index - 1u];
    size_t output_length = context.lengths[index - 1u];
    size_t ip_length = (size_t)(output[0] & 0x0fu) * 4u;
    size_t tcp_length = (size_t)(output[ip_length + 12u] >> 4) * 4u;
    if (output_length == ip_length + tcp_length + sizeof(reply)) {
      reply_sequence = get_u32(output + ip_length + 4u);
      break;
    }
  }
  CHECK(reply_sequence != 0u);
  length = make_tcp_packet(packet, sizeof(packet), source, target, 12345u, 443u,
                           1006u, reply_sequence + (uint32_t)sizeof(reply), 0x10u,
                           NULL, 0u);
  CHECK(input_bytes(stack, budget, packet, length) == FTUN_OK);
  CHECK(context.writable_events >= 1u);
  CHECK(ftun_lwip_get_usage(stack, &usage) == FTUN_OK && usage.retained_send_bytes == 0u);

  length = make_tcp_packet(packet, sizeof(packet), source, target, 12345u, 443u,
                           1006u, reply_sequence + (uint32_t)sizeof(reply), 0x11u,
                           NULL, 0u);
  CHECK(input_bytes(stack, budget, packet, length) == FTUN_OK);
  CHECK(context.fin_events == 1u);
  CHECK(ftun_lwip_tcp_ready(context.flow, &readable, &writable) == FTUN_OK &&
        readable);
  CHECK(ftun_lwip_tcp_peek(context.flow, NULL, 0u, &count, &available,
                           &peer_finished) == FTUN_OK);
  CHECK(available == 0u && peer_finished);
  CHECK(ftun_buffer_acquire(budget, sizeof(reply), &send_buffer) == FTUN_OK);
  CHECK(ftun_buffer_data(send_buffer, &send_storage, &send_capacity) == FTUN_OK);
  memcpy(send_storage, reply, sizeof(reply));
  CHECK(ftun_buffer_slice(send_buffer, 0u, sizeof(reply), &send_slice) == FTUN_OK);
  CHECK(ftun_buffer_release(&send_buffer) == FTUN_OK);
  CHECK(ftun_lwip_tcp_write_ref(context.flow, &send_slice, &accepted) == FTUN_OK);
  CHECK(ftun_buffer_slice_release(&send_slice) == FTUN_OK);
  CHECK(ftun_lwip_get_usage(stack, &usage) == FTUN_OK &&
        usage.retained_send_bytes == sizeof(reply));
  CHECK(ftun_lwip_tcp_shutdown_write(context.flow) == FTUN_OK);
  CHECK(ftun_lwip_tcp_close(&context.flow) == FTUN_OK && context.flow == NULL);
  CHECK(ftun_lwip_get_usage(stack, &usage) == FTUN_OK && usage.tcp_flows == 0u &&
        usage.retained_send_bytes == 0u);
  CHECK(ftun_lwip_destroy(&stack) == FTUN_OK && stack == NULL);
  CHECK(ftun_lwip_create(&other_spec, &other) == FTUN_OK);
  CHECK(ftun_lwip_next_deadline(other, &deadline_ms) == FTUN_OK &&
        deadline_ms == 1250u);
  CHECK(ftun_lwip_destroy(&other) == FTUN_OK && other == NULL);
  CHECK(ftun_budget_get_usage(other_budget, &budget_usage) == FTUN_OK &&
        budget_usage.used == 0u);
  CHECK(ftun_budget_destroy(&other_budget) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK && budget_usage.used == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int test_failure_and_cancel(void)
{
  static const uint8_t invalid_ipv6[40] = {0x60u};
  ftun_budget_t *budget = NULL;
  ftun_budget_t *small_budget = NULL;
  ftun_lwip_t *stack = NULL;
  ftun_lwip_spec_t spec;
  ftun_lwip_usage_t usage;
  ftun_budget_usage_t budget_usage;
  test_context_t context;
  uint32_t server_sequence;

  memset(&context, 0, sizeof(context));
  memset(&spec, 0, sizeof(spec));
  CHECK(ftun_budget_create(NULL, 64u, 0u, &small_budget) == FTUN_OK);
  spec.budget = small_budget;
  spec.mtu = 1500u;
  spec.output = capture_output;
  spec.accept = accept_tcp;
  spec.user = &context;
  CHECK(ftun_lwip_create(&spec, &stack) == FTUN_E_LIMIT && stack == NULL);
  CHECK(ftun_budget_get_usage(small_budget, &budget_usage) == FTUN_OK &&
        budget_usage.used == 0u);
  CHECK(ftun_budget_destroy(&small_budget) == FTUN_OK);

  CHECK(ftun_budget_create(NULL, 4u * 1024u * 1024u, 4096u, &budget) == FTUN_OK);
  spec.budget = budget;
  spec.tcp_event = tcp_event;
  context.reject_accept = 1;
  CHECK(ftun_lwip_create(&spec, &stack) == FTUN_OK);
  CHECK(input_bytes(stack, budget, invalid_ipv6, sizeof(invalid_ipv6)) == FTUN_E_PROTOCOL);
  CHECK(establish(stack, budget, &context, &server_sequence) == 0);
  CHECK(context.accepts == 1u && context.flow == NULL && context.callback_failed == 0);
  CHECK(ftun_lwip_get_usage(stack, &usage) == FTUN_OK && usage.tcp_flows == 0u);
  CHECK(ftun_lwip_destroy(&stack) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK && budget_usage.used == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

/* 存活探测：对端静默后，lwIP 在 idle 之后发出探测；连续 count 次无应答则关闭连接。
 * 未开启时同样的静默不产生任何输出。 */
static int keepalive_case(bool enabled)
{
  ftun_budget_t *budget = NULL;
  ftun_lwip_t *stack = NULL;
  ftun_lwip_spec_t spec;
  test_context_t context;
  uint32_t server_sequence;
  uint64_t now_ms;
  size_t established_outputs;
  size_t probes = 0u;
  size_t index;
  memset(&context, 0, sizeof(context));
  memset(&spec, 0, sizeof(spec));
  CHECK(ftun_budget_create(NULL, 4u * 1024u * 1024u, 4096u, &budget) == FTUN_OK);
  spec.budget = budget;
  spec.mtu = 1500u;
  spec.now_ms = 1000u;
  spec.output = capture_output;
  spec.accept = accept_tcp;
  spec.tcp_event = tcp_event;
  spec.user = &context;
  spec.liveness.keepalive_enabled = enabled;
  spec.liveness.idle_s = 1u;
  spec.liveness.interval_s = 1u;
  spec.liveness.count = 2u;
  CHECK(ftun_lwip_create(&spec, &stack) == FTUN_OK);
  CHECK(establish(stack, budget, &context, &server_sequence) == 0);
  established_outputs = context.output_count;
  /* 对端从此静默；每 250ms 推进一次定时器，共 10 秒。 */
  for (now_ms = 1250u; now_ms <= 11000u; now_ms += 250u) {
    CHECK(ftun_lwip_tick(stack, now_ms) == FTUN_OK);
  }
  for (index = established_outputs; index < context.output_count; index++) {
    const uint8_t *packet = context.packets[index];
    size_t ip_length = (size_t)(packet[0] & 0x0fu) * 4u;
    /* 探测是只带 ACK、序号为 snd_nxt-1 的段，负载为 0 或 1 字节。 */
    if ((packet[ip_length + 13u] & 0x17u) == 0x10u &&
        context.lengths[index] <= ip_length + 20u + 1u) probes++;
  }
  if (enabled) {
    CHECK(probes >= 2u);
    CHECK(context.closed_events == 1u);
  } else {
    CHECK(context.output_count == established_outputs && probes == 0u);
    CHECK(context.closed_events == 0u);
  }
  context.callback_failed = 0;
  (void)context.callback_failed;
  CHECK(ftun_lwip_destroy(&stack) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(void)
{
  CHECK(test_tcp_lifecycle() == 0);
  CHECK(test_failure_and_cancel() == 0);
  CHECK(keepalive_case(true) == 0);
  CHECK(keepalive_case(false) == 0);
  return 0;
}
