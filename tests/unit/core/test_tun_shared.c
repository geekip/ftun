#include <unistd.h>
#include <fcntl.h>
#include "core/limits.h"
#include "core/operation.h"
#include "proxy/netstack/ingress.h"
#include "libs/tun/service.h"
#include "libs/buffer/buffer.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
  if (!(condition)) { \
    fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, \
            #condition); \
    return 1; \
  } \
} while (0)

#define TEST_MTU 1500u
#define TEST_PACKETS 16u
#define TEST_WRITES 16u

typedef struct {
  uint8_t reads[TEST_PACKETS][TEST_MTU];
  size_t read_lengths[TEST_PACKETS];
  size_t read_count;
  size_t read_index;
  uint8_t writes[TEST_WRITES][TEST_MTU];
  size_t write_lengths[TEST_WRITES];
  size_t write_count;
  size_t open_count;
  size_t close_count;
  ftun_status_t write_status;
} fake_device_t;

typedef struct {
  ftun_tun_lease_t expected;
  uint8_t destinations[TEST_PACKETS][4];
  uint8_t markers[TEST_PACKETS];
  size_t attempts;
  size_t packets;
  size_t rebuilt;
  size_t quiesced;
  size_t path_updates;
  bool stall;
} raw_consumer_t;

typedef struct {
  ftun_budget_t *budget;
  ftun_buffer_pool_t *buffers;
  ftun_operation_queue_t *operations;
  ftun_tun_ingress_context_t *ingress;
  ftun_tun_lease_t lease;
  size_t datagrams;
  uint8_t payload[32];
  size_t payload_length;
  size_t quiesced;
} proxy_consumer_t;

static void put_u16(uint8_t *target, uint16_t value)
{
  target[0] = (uint8_t)(value >> 8u);
  target[1] = (uint8_t)value;
}

static uint32_t checksum_add(uint32_t sum, const uint8_t *data, size_t length)
{
  while (length >= 2u) {
    sum += ((uint32_t)data[0] << 8u) | data[1];
    data += 2;
    length -= 2u;
  }
  if (length != 0u) sum += (uint32_t)data[0] << 8u;
  return sum;
}

static uint16_t checksum_finish(uint32_t sum)
{
  while ((sum >> 16u) != 0u) sum = (sum & 0xffffu) + (sum >> 16u);
  return (uint16_t)~sum;
}

static size_t make_udp_packet(uint8_t *packet, const uint8_t source[4],
                              const uint8_t target[4], uint8_t marker)
{
  size_t total = 29u;
  memset(packet, 0, total);
  packet[0] = 0x45u;
  put_u16(packet + 2u, (uint16_t)total);
  put_u16(packet + 4u, (uint16_t)(100u + marker));
  put_u16(packet + 6u, 0x4000u);
  packet[8] = 64u;
  packet[9] = 17u;
  memcpy(packet + 12u, source, 4u);
  memcpy(packet + 16u, target, 4u);
  put_u16(packet + 10u, checksum_finish(checksum_add(0u, packet, 20u)));
  put_u16(packet + 20u, (uint16_t)(20000u + marker));
  put_u16(packet + 22u, 30000u);
  put_u16(packet + 24u, 9u);
  packet[28] = marker;
  return total;
}

static ftun_status_t fake_open(void *user, ftun_core_t *core,
                               const ftun_tun_spec_t *spec,
                               ftun_packet_port_t **out)
{
  fake_device_t *device = (fake_device_t *)user;
  (void)core;
  if (out != NULL) *out = NULL;
  if (device == NULL || spec == NULL || out == NULL ||
      spec->name.length != 9u ||
      memcmp(spec->name.data, "ftun-shr0", 9u) != 0 ||
      spec->mtu != TEST_MTU) return FTUN_E_INVALID;
  device->open_count++;
  *out = (ftun_packet_port_t *)device;
  return FTUN_OK;
}

static ftun_status_t fake_get_info(void *user,
                                   const ftun_packet_port_t *port,
                                   ftun_packet_port_info_t *out)
{
  fake_device_t *device = (fake_device_t *)user;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (device == NULL || port != (const ftun_packet_port_t *)device ||
      out == NULL) return FTUN_E_INVALID;
  memcpy(out->name, "ftun-shr0", 10u);
  out->mtu = TEST_MTU;
  out->native_socket = 81u;
  return FTUN_OK;
}

static ftun_status_t fake_read(void *user, ftun_packet_port_t *port,
                               void *buffer, size_t capacity,
                               size_t *out_length)
{
  fake_device_t *device = (fake_device_t *)user;
  size_t index;
  if (out_length != NULL) *out_length = 0u;
  if (device == NULL || port != (ftun_packet_port_t *)device ||
      buffer == NULL || out_length == NULL) return FTUN_E_INVALID;
  if (device->read_index == device->read_count) return FTUN_E_AGAIN;
  index = device->read_index++;
  if (device->read_lengths[index] > capacity) return FTUN_E_LIMIT;
  memcpy(buffer, device->reads[index], device->read_lengths[index]);
  *out_length = device->read_lengths[index];
  return FTUN_OK;
}

static ftun_status_t fake_write(void *user, ftun_packet_port_t *port,
                                const void *packet, size_t length)
{
  fake_device_t *device = (fake_device_t *)user;
  if (device == NULL || port != (ftun_packet_port_t *)device ||
      packet == NULL || length == 0u || length > TEST_MTU) {
    return FTUN_E_INVALID;
  }
  if (device->write_status != FTUN_OK) return device->write_status;
  if (device->write_count >= TEST_WRITES) return FTUN_E_LIMIT;
  memcpy(device->writes[device->write_count], packet, length);
  device->write_lengths[device->write_count] = length;
  device->write_count++;
  return FTUN_OK;
}

static ftun_status_t fake_close(void *user, ftun_packet_port_t **port)
{
  fake_device_t *device = (fake_device_t *)user;
  if (device == NULL || port == NULL) return FTUN_E_INVALID;
  if (*port == NULL) return FTUN_OK;
  if (*port != (ftun_packet_port_t *)device) return FTUN_E_INVALID;
  device->close_count++;
  *port = NULL;
  return FTUN_OK;
}

static ftun_status_t raw_packet(void *user, ftun_tun_lease_t lease,
                                ftun_bytes_t packet)
{
  raw_consumer_t *raw = (raw_consumer_t *)user;
  size_t index;
  if (raw == NULL || lease.service != raw->expected.service ||
      lease.generation != raw->expected.generation || packet.length < 29u) {
    return FTUN_E_STATE_CORRUPT;
  }
  raw->attempts++;
  if (raw->stall) return FTUN_E_AGAIN;
  if (raw->packets >= TEST_PACKETS) return FTUN_E_LIMIT;
  index = raw->packets++;
  memcpy(raw->destinations[index], packet.data + 16u, 4u);
  raw->markers[index] = packet.data[28];
  return FTUN_OK;
}

static void raw_event(void *user, ftun_tun_lease_t lease,
                      ftun_tun_service_event_t event, ftun_status_t status)
{
  raw_consumer_t *raw = (raw_consumer_t *)user;
  if (raw == NULL || lease.service != raw->expected.service ||
      lease.generation != raw->expected.generation || status != FTUN_OK) return;
  if (event == FTUN_TUN_SERVICE_REBUILT) raw->rebuilt++;
  if (event == FTUN_TUN_SERVICE_QUIESCED) raw->quiesced++;
  if (event == FTUN_TUN_SERVICE_PATH_UPDATED) raw->path_updates++;
}

static ftun_status_t proxy_receive_datagram(
  void *user, const ftun_metadata_t *metadata, ftun_datagram_t *channel,
  const ftun_endpoint_t *source, const ftun_packet_t *packet)
{
  proxy_consumer_t *proxy = (proxy_consumer_t *)user;
  ftun_bytes_t payload;
  (void)metadata;
  (void)channel;
  (void)source;
  if (proxy == NULL || ftun_packet_view(packet, &payload) != FTUN_OK ||
      payload.length > sizeof(proxy->payload)) return FTUN_E_STATE_CORRUPT;
  memcpy(proxy->payload, payload.data, payload.length);
  proxy->payload_length = payload.length;
  proxy->datagrams++;
  return FTUN_OK;
}

static ftun_status_t proxy_output(void *user, ftun_bytes_t packet)
{
  proxy_consumer_t *proxy = (proxy_consumer_t *)user;
  return ftun_tun_service_write(proxy->lease, packet);
}

static ftun_status_t proxy_packet(void *user, ftun_tun_lease_t lease,
                                  ftun_bytes_t packet)
{
  proxy_consumer_t *proxy = (proxy_consumer_t *)user;
  ftun_status_t status;
  if (proxy == NULL || lease.service != proxy->lease.service ||
      lease.generation != proxy->lease.generation) return FTUN_E_STALE;
  status = ftun_tun_ingress_bytes(proxy->ingress, proxy->buffers, packet);
  return status == FTUN_E_PROTOCOL ? FTUN_OK : status;
}

static void proxy_event(void *user, ftun_tun_lease_t lease,
                        ftun_tun_service_event_t event, ftun_status_t status)
{
  proxy_consumer_t *proxy = (proxy_consumer_t *)user;
  if (proxy == NULL || lease.service != proxy->lease.service ||
      lease.generation != proxy->lease.generation || status != FTUN_OK) return;
  if (event == FTUN_TUN_SERVICE_QUIESCED) proxy->quiesced++;
}

static void fill_route(ftun_tun_consumer_spec_t *spec,
                       raw_consumer_t *raw, const uint8_t network[4],
                       uint8_t prefix, uint16_t priority)
{
  memset(spec, 0, sizeof(*spec));
  spec->consumer.packet = raw_packet;
  spec->consumer.event = raw_event;
  spec->consumer.user = raw;
  spec->route.kind = FTUN_TUN_ROUTE_IPV4_PREFIX;
  memcpy(spec->route.network, network, 4u);
  spec->route.prefix_length = prefix;
  spec->route.priority = priority;
}

static int test_shared_dispatch(void)
{
  static const uint8_t source[4] = {198u, 51u, 100u, 7u};
  static const uint8_t proxy_target[4] = {192u, 0u, 2u, 10u};
  static const uint8_t broad_a[4] = {10u, 2u, 0u, 1u};
  static const uint8_t broad_b[4] = {10u, 3u, 0u, 1u};
  static const uint8_t broad_c[4] = {10u, 4u, 0u, 1u};
  static const uint8_t specific_target[4] = {10u, 1u, 2u, 3u};
  static const uint8_t broad_network[4] = {10u, 0u, 0u, 0u};
  static const uint8_t specific_network[4] = {10u, 1u, 0u, 0u};
  static const uint8_t proxy_out_a[] = {0x45u, 0xa1u};
  static const uint8_t proxy_out_b[] = {0x45u, 0xa2u};
  static const uint8_t raw_out_a[] = {0x45u, 0xb1u};
  static const uint8_t raw_out_b[] = {0x45u, 0xb2u};
  ftun_budget_t *budget = NULL;
  ftun_buffer_pool_t *buffers = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_tun_service_t *service = NULL;
  ftun_l3_provider_t l3_provider;
  ftun_tun_service_spec_t service_spec;
  ftun_tun_device_ops_t ops;
  ftun_tun_ingress_spec_t ingress_spec;
  ftun_tun_consumer_spec_t consumer_spec;
  ftun_tun_consumer_t proxy_callbacks;
  ftun_tun_lease_t broad_lease;
  ftun_tun_lease_t slow_lease;
  ftun_tun_lease_t fast_lease;
  ftun_tun_lease_t stale;
  ftun_tun_lease_t replacement;
  ftun_tun_lease_t conflict;
  ftun_tun_service_usage_t usage;
  ftun_tun_consumer_usage_t consumer_usage;
  ftun_buffer_pool_usage_t pool_usage;
  ftun_budget_usage_t budget_usage;
  fake_device_t device;
  proxy_consumer_t proxy;
  raw_consumer_t broad;
  raw_consumer_t slow;
  raw_consumer_t fast;
  raw_consumer_t replacement_raw;
  size_t work = 0u;

  memset(&device, 0, sizeof(device));
  memset(&proxy, 0, sizeof(proxy));
  memset(&broad, 0, sizeof(broad));
  memset(&slow, 0, sizeof(slow));
  memset(&fast, 0, sizeof(fast));
  memset(&replacement_raw, 0, sizeof(replacement_raw));
  memset(&service_spec, 0, sizeof(service_spec));
  memset(&ops, 0, sizeof(ops));
  memset(&ingress_spec, 0, sizeof(ingress_spec));
  memset(&proxy_callbacks, 0, sizeof(proxy_callbacks));
  memset(&l3_provider, 0, sizeof(l3_provider));
  memset(&broad_lease, 0, sizeof(broad_lease));
  memset(&slow_lease, 0, sizeof(slow_lease));
  memset(&fast_lease, 0, sizeof(fast_lease));
  memset(&replacement, 0, sizeof(replacement));
  memset(&conflict, 0, sizeof(conflict));

  CHECK(ftun_budget_create(NULL, 8u * 1024u * 1024u, 4096u, &budget) ==
        FTUN_OK);
  CHECK(ftun_buffer_pool_create(budget, 65536u, 64u, &buffers) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 32u, &operations) == FTUN_OK);
  CHECK(ftun_event_loop_create(NULL, &loop) == FTUN_OK);
  proxy.budget = budget;
  proxy.buffers = buffers;
  proxy.operations = operations;
  ingress_spec.budget = budget;
  ingress_spec.operations = operations;
  ingress_spec.generation = 1u;
  ingress_spec.now_ms = 1000u;
  ingress_spec.inbound_id = 41u;
  ingress_spec.mtu = TEST_MTU;
  ingress_spec.max_pending_stream_writes = 4u;
  ingress_spec.max_pending_stream_bytes = 4096u;
  ingress_spec.max_pending_datagrams = 4u;
  ingress_spec.max_pending_datagram_bytes = 4096u;
  ingress_spec.udp = true;
  ingress_spec.datagram_receive = proxy_receive_datagram;
  ingress_spec.output = proxy_output;
  ingress_spec.user = &proxy;
  CHECK(ftun_tun_ingress_bind(&ingress_spec, &proxy.ingress) == FTUN_OK);

  service_spec.budget = budget;
  service_spec.loop = loop;
  service_spec.buffers = buffers;
  service_spec.device.name.data = "ftun-shr0";
  service_spec.device.name.length = 9u;
  service_spec.device.mtu = TEST_MTU;
  service_spec.consumer_capacity = 4u;
  service_spec.input_capacity = 2u;
  service_spec.consumer_quota = 1u;
  service_spec.output_capacity = 2u;
  service_spec.read_quota = 8u;
  service_spec.write_quota = 2u;
  ops.open = fake_open;
  ops.get_info = fake_get_info;
  ops.read = fake_read;
  ops.write = fake_write;
  ops.close = fake_close;
  ops.user = &device;
  CHECK(ftun_tun_service_create_with_ops(
          &service_spec, &ops, &service) == FTUN_OK);
  CHECK(ftun_l3_provider_bind(service, 17u, &l3_provider) == FTUN_OK);

  proxy_callbacks.packet = proxy_packet;
  proxy_callbacks.event = proxy_event;
  proxy_callbacks.user = &proxy;
  CHECK(ftun_tun_service_acquire(service, &proxy_callbacks, &proxy.lease) ==
        FTUN_OK);
  /* /16 必须先于 priority=1 的 /8；同一 /16 再选较小 priority。 */
  fill_route(&consumer_spec, &broad, broad_network, 8u, 1u);
  CHECK(ftun_l3_provider_acquire(
          &l3_provider, 16u, &consumer_spec, &conflict) == FTUN_E_STALE &&
        conflict.service == NULL);
  CHECK(ftun_l3_provider_acquire(
          &l3_provider, 17u, &consumer_spec, &broad_lease) == FTUN_OK);
  broad.expected = broad_lease;
  broad.stall = true;
  fill_route(&consumer_spec, &slow, specific_network, 16u, 20u);
  CHECK(ftun_tun_service_acquire_routed(
          service, &consumer_spec, &slow_lease) == FTUN_OK);
  slow.expected = slow_lease;
  fill_route(&consumer_spec, &fast, specific_network, 16u, 5u);
  CHECK(ftun_tun_service_acquire_routed(
          service, &consumer_spec, &fast_lease) == FTUN_OK);
  fast.expected = fast_lease;
  CHECK(ftun_tun_service_acquire_routed(
          service, &consumer_spec, &conflict) == FTUN_E_REJECTED &&
        conflict.service == NULL);

  device.read_count = 5u;
  device.read_lengths[0] = make_udp_packet(
    device.reads[0], source, broad_a, 1u);
  device.read_lengths[1] = make_udp_packet(
    device.reads[1], source, proxy_target, 2u);
  device.read_lengths[2] = make_udp_packet(
    device.reads[2], source, broad_b, 3u);
  device.read_lengths[3] = make_udp_packet(
    device.reads[3], source, broad_c, 4u);
  device.read_lengths[4] = make_udp_packet(
    device.reads[4], source, specific_target, 5u);
  CHECK(ftun_tun_service_notify(service, FTUN_EVENT_READ) == FTUN_OK);
  CHECK(ftun_tun_service_run(service, &work) == FTUN_OK && work == 5u);
  CHECK(device.read_index == 5u && proxy.datagrams == 1u &&
        proxy.payload_length == 1u && proxy.payload[0] == 2u);
  CHECK(broad.attempts == 1u && broad.packets == 0u &&
        slow.packets == 0u && fast.packets == 1u &&
        fast.markers[0] == 5u);
  CHECK(ftun_tun_service_get_consumer_usage(
          broad_lease, &consumer_usage) == FTUN_OK &&
        consumer_usage.blocked && consumer_usage.queued_inputs == 2u &&
        consumer_usage.packets_dropped == 1u);
  CHECK(ftun_tun_service_get_usage(service, &usage) == FTUN_OK &&
        usage.active_leases == 4u && usage.blocked_consumers == 1u &&
        usage.queued_inputs == 2u && usage.packets_read == 5u &&
        usage.packets_dropped == 1u && !usage.ready);

  broad.stall = false;
  CHECK(ftun_tun_service_resume(broad_lease) == FTUN_OK);
  CHECK(ftun_tun_service_run(service, &work) == FTUN_OK && work == 1u &&
        broad.packets == 1u && broad.markers[0] == 1u);
  CHECK(ftun_tun_service_run(service, &work) == FTUN_OK && work == 1u &&
        broad.packets == 2u && broad.markers[1] == 3u);
  CHECK(ftun_tun_service_get_consumer_usage(
          broad_lease, &consumer_usage) == FTUN_OK &&
        !consumer_usage.blocked && consumer_usage.queued_inputs == 0u);

  device.write_status = FTUN_E_AGAIN;
  CHECK(ftun_tun_service_write(proxy.lease,
          (ftun_bytes_t){proxy_out_a, sizeof(proxy_out_a)}) == FTUN_OK);
  CHECK(ftun_tun_service_write(proxy.lease,
          (ftun_bytes_t){proxy_out_b, sizeof(proxy_out_b)}) == FTUN_OK);
  CHECK(ftun_tun_service_write(broad_lease,
          (ftun_bytes_t){raw_out_a, sizeof(raw_out_a)}) == FTUN_OK);
  CHECK(ftun_tun_service_write(broad_lease,
          (ftun_bytes_t){raw_out_b, sizeof(raw_out_b)}) == FTUN_OK);
  CHECK(ftun_tun_service_write(broad_lease,
          (ftun_bytes_t){raw_out_b, sizeof(raw_out_b)}) == FTUN_E_LIMIT);
  device.write_status = FTUN_OK;
  CHECK(ftun_tun_service_notify(service, FTUN_EVENT_WRITE) == FTUN_OK);
  CHECK(ftun_tun_service_run(service, &work) == FTUN_OK && work == 2u &&
        device.write_count == 2u && device.writes[0][1] == 0xa1u &&
        device.writes[1][1] == 0xb1u);
  CHECK(ftun_tun_service_notify(service, FTUN_EVENT_WRITE) == FTUN_OK);
  CHECK(ftun_tun_service_run(service, &work) == FTUN_OK && work == 2u &&
        device.write_count == 4u && device.writes[2][1] == 0xa2u &&
        device.writes[3][1] == 0xb2u);

  device.write_status = FTUN_E_AGAIN;
  CHECK(ftun_tun_service_write(proxy.lease,
          (ftun_bytes_t){proxy_out_a, sizeof(proxy_out_a)}) == FTUN_OK);
  CHECK(ftun_tun_service_write(broad_lease,
          (ftun_bytes_t){raw_out_a, sizeof(raw_out_a)}) == FTUN_OK);
  stale = broad_lease;
  CHECK(ftun_tun_service_release(&broad_lease) == FTUN_OK);
  CHECK(ftun_tun_service_get_usage(service, &usage) == FTUN_OK &&
        usage.active_leases == 3u && usage.queued_packets == 1u);
  CHECK(ftun_tun_service_resume(stale) == FTUN_E_STALE);
  CHECK(ftun_tun_service_write(stale,
          (ftun_bytes_t){raw_out_a, sizeof(raw_out_a)}) == FTUN_E_STALE);
  fill_route(&consumer_spec, &replacement_raw, broad_network, 8u, 1u);
  CHECK(ftun_tun_service_acquire_routed(
          service, &consumer_spec, &replacement) == FTUN_OK &&
        replacement.generation != stale.generation);
  replacement_raw.expected = replacement;
  CHECK(ftun_tun_service_resume(stale) == FTUN_E_STALE);
  device.write_status = FTUN_OK;
  CHECK(ftun_tun_service_notify(service, FTUN_EVENT_WRITE) == FTUN_OK);
  CHECK(ftun_tun_service_run(service, &work) == FTUN_OK && work == 1u &&
        device.write_count == 5u && device.writes[4][1] == 0xa1u);

  /* 修改一个消费者的映射与路径，旧队列只属于旧路径；其他消费者继续运行。 */
  fast.stall = true;
  device.read_lengths[5] = make_udp_packet(
    device.reads[5], source, specific_target, 6u);
  device.read_count = 6u;
  CHECK(ftun_tun_service_notify(service, FTUN_EVENT_READ) == FTUN_OK);
  CHECK(ftun_tun_service_run(service, &work) == FTUN_OK && work == 1u);
  device.write_status = FTUN_E_AGAIN;
  CHECK(ftun_tun_service_write(fast_lease,
          (ftun_bytes_t){raw_out_a, sizeof(raw_out_a)}) == FTUN_OK);
  CHECK(ftun_tun_service_write(proxy.lease,
          (ftun_bytes_t){proxy_out_a, sizeof(proxy_out_a)}) == FTUN_OK);
  fill_route(&consumer_spec, &fast, specific_network, 16u, 20u);
  CHECK(ftun_tun_service_update_consumer(fast_lease, 1u,
          &consumer_spec.route, &consumer_spec.path) == FTUN_E_REJECTED);
  consumer_spec.route.network[1] = 2u;
  consumer_spec.route.network[3] = 1u;
  CHECK(ftun_tun_service_update_consumer(fast_lease, 1u,
          &consumer_spec.route, &consumer_spec.path) == FTUN_E_INVALID);
  consumer_spec.route.network[3] = 0u;
  consumer_spec.path.carrier_mtu = 1200u;
  consumer_spec.path.headroom = 1200u;
  CHECK(ftun_tun_service_update_consumer(fast_lease, 1u,
          &consumer_spec.route, &consumer_spec.path) == FTUN_E_INVALID);
  consumer_spec.path.headroom = 100u;
  CHECK(ftun_tun_service_update_consumer(fast_lease, 2u,
          &consumer_spec.route, &consumer_spec.path) == FTUN_E_STALE);
  CHECK(ftun_tun_service_get_consumer_usage(fast_lease, &consumer_usage) == FTUN_OK &&
        consumer_usage.path_generation == 1u && consumer_usage.blocked &&
        consumer_usage.queued_inputs == 1u && consumer_usage.queued_outputs == 1u &&
        fast.path_updates == 0u);
  CHECK(ftun_tun_service_update_consumer(fast_lease, 1u,
          &consumer_spec.route, &consumer_spec.path) == FTUN_OK);
  CHECK(ftun_tun_service_get_consumer_usage(fast_lease, &consumer_usage) == FTUN_OK &&
        consumer_usage.path_generation == 2u && !consumer_usage.blocked &&
        consumer_usage.inner_mtu == 1100u && consumer_usage.queued_inputs == 0u &&
        consumer_usage.queued_outputs == 0u && fast.path_updates == 1u);
  CHECK(ftun_tun_service_update_consumer(fast_lease, 1u,
          &consumer_spec.route, &consumer_spec.path) == FTUN_E_STALE);
  CHECK(ftun_tun_service_update_consumer(fast_lease, 2u,
          &consumer_spec.route, &consumer_spec.path) == FTUN_OK && fast.path_updates == 1u);
  CHECK(ftun_tun_service_get_usage(service, &usage) == FTUN_OK &&
        usage.active_leases == 4u && usage.device_generation == 1u &&
        usage.queued_packets == 1u && usage.queued_inputs == 0u);
  fast.stall = false;
  device.write_status = FTUN_OK;
  device.read_lengths[6] = make_udp_packet(
    device.reads[6], source, specific_target, 7u);
  device.read_lengths[7] = make_udp_packet(
    device.reads[7], source, (uint8_t[]){10u, 2u, 1u, 1u}, 8u);
  device.read_lengths[8] = make_udp_packet(
    device.reads[8], source, proxy_target, 9u);
  device.read_count = 9u;
  CHECK(ftun_tun_service_notify(service, FTUN_EVENT_READ | FTUN_EVENT_WRITE) == FTUN_OK);
  CHECK(ftun_tun_service_run(service, &work) == FTUN_OK && work == 4u);
  CHECK(slow.packets == 1u && slow.markers[0] == 7u && fast.packets == 2u &&
        fast.markers[1] == 8u && proxy.datagrams == 2u && proxy.payload[0] == 9u &&
        device.write_count == 6u && device.writes[5][1] == 0xa1u &&
        device.open_count == 1u && device.close_count == 0u);

  CHECK(ftun_l3_provider_quiesce(&l3_provider) == FTUN_OK &&
        l3_provider.service == NULL && l3_provider.budget == NULL &&
        l3_provider.generation == 0u &&
        proxy.quiesced == 1u && slow.quiesced == 1u &&
        fast.quiesced == 1u && replacement_raw.quiesced == 1u);
  CHECK(ftun_tun_ingress_close(&proxy.ingress) == FTUN_OK);
  CHECK(ftun_tun_service_release(&proxy.lease) == FTUN_OK);
  CHECK(ftun_tun_service_release(&slow_lease) == FTUN_OK);
  CHECK(ftun_tun_service_release(&fast_lease) == FTUN_OK);
  CHECK(ftun_tun_service_release(&replacement) == FTUN_OK);
  CHECK(ftun_tun_service_destroy(&service) == FTUN_OK && service == NULL &&
        device.open_count == 1u && device.close_count == 1u);
  CHECK(ftun_buffer_pool_get_usage(buffers, &pool_usage) == FTUN_OK &&
        pool_usage.active_buffers == 0u);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_buffer_pool_destroy(&buffers) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK &&
        budget_usage.used_resources.memory_bytes == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(void)
{
  CHECK(test_shared_dispatch() == 0);
  return 0;
}
