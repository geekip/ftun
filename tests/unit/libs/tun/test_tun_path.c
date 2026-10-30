#include "libs/tun/service.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
  if (!(condition)) { \
    fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #condition); \
    return 1; \
  } \
} while (0)

#define TEST_MTU 1500u
#define TEST_PACKETS 96u

typedef struct {
  uint8_t reads[TEST_PACKETS][TEST_MTU];
  size_t read_lengths[TEST_PACKETS];
  size_t read_count;
  size_t read_index;
  uint8_t writes[TEST_PACKETS][TEST_MTU];
  size_t write_lengths[TEST_PACKETS];
  size_t write_count;
  ftun_status_t write_status;
  bool fail_update;
  uint32_t interests;
} fake_device_t;

typedef struct {
  ftun_tun_lease_t expected;
  size_t received;
  size_t last_length;
  size_t path_updates;
  size_t rebuilds;
  size_t errors;
  size_t malformed;
  size_t oversized;
  size_t fragments;
  size_t sources;
  size_t feedback_sent;
  ftun_tun_packet_error_t last_error;
  bool stall;
  ftun_buffer_pool_t *release_pool;
  size_t release_checks;
  size_t release_errors;
  bool release_event;
  bool release_error;
} consumer_state_t;

static uint16_t checksum(const uint8_t *data, size_t length)
{
  uint32_t sum = 0u;
  while (length >= 2u) {
    sum += ((uint32_t)data[0] << 8u) | data[1];
    data += 2u;
    length -= 2u;
  }
  if (length != 0u) sum += (uint32_t)data[0] << 8u;
  while ((sum >> 16u) != 0u) sum = (sum & UINT16_MAX) + (sum >> 16u);
  return (uint16_t)~sum;
}

static size_t make_ipv4(uint8_t *packet, size_t length,
                        const uint8_t source[4],
                        const uint8_t destination[4], uint16_t fragment)
{
  uint16_t value;
  if (packet == NULL || length < 20u || length > TEST_MTU) return 0u;
  memset(packet, 0, length);
  packet[0] = 0x45u;
  packet[2] = (uint8_t)(length >> 8u);
  packet[3] = (uint8_t)length;
  packet[6] = (uint8_t)(fragment >> 8u);
  packet[7] = (uint8_t)fragment;
  packet[8] = 64u;
  packet[9] = 17u;
  memcpy(packet + 12u, source, 4u);
  memcpy(packet + 16u, destination, 4u);
  value = checksum(packet, 20u);
  packet[10] = (uint8_t)(value >> 8u);
  packet[11] = (uint8_t)value;
  return length;
}

static void update_ipv4_checksum(uint8_t *packet)
{
  uint16_t value;
  packet[10] = 0u;
  packet[11] = 0u;
  value = checksum(packet, 20u);
  packet[10] = (uint8_t)(value >> 8u);
  packet[11] = (uint8_t)value;
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
      memcmp(spec->name.data, "ftun-pth0", 9u) != 0 ||
      spec->mtu != TEST_MTU) return FTUN_E_INVALID;
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
  memcpy(out->name, "ftun-pth0", 10u);
  out->mtu = TEST_MTU;
  out->native_socket = 71u;
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
  if (device->write_count >= TEST_PACKETS) return FTUN_E_LIMIT;
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
  *port = NULL;
  return FTUN_OK;
}

static ftun_status_t event_update(void *context, ftun_event_source_t *source,
                                   uint32_t interests)
{
  fake_device_t *device = (fake_device_t *)context;
  (void)source;
  if (device->fail_update) return FTUN_E_IO;
  device->interests = interests;
  return FTUN_OK;
}

static ftun_status_t event_start(void *context, ftun_event_source_t *source,
                                  ftun_native_socket_t socket, uint32_t interests)
{
  (void)socket;
  return event_update(context, source, interests);
}

static ftun_status_t event_timer(void *context, ftun_event_source_t *source,
                                  uint64_t deadline)
{
  (void)context;
  (void)source;
  (void)deadline;
  return FTUN_E_UNSUPPORTED;
}

static ftun_status_t event_cancel(void *context, ftun_event_source_t *source)
{
  (void)context;
  (void)source;
  return FTUN_OK;
}

static void event_idle(void *context) { (void)context; }

static ftun_status_t event_run(void *context, bool block)
{
  (void)context;
  (void)block;
  return FTUN_OK;
}

static const ftun_event_backend_ops_t event_ops = {
  .io_start = event_start,
  .io_update = event_update,
  .timer_start = event_timer,
  .source_cancel = event_cancel,
  .wakeup = event_idle,
  .run_once = event_run,
  .stop = event_idle,
  .destroy = event_idle
};

static ftun_status_t consume_packet(void *user, ftun_tun_lease_t lease,
                                    ftun_bytes_t packet);

static void release_in_callback(consumer_state_t *state,
                                 ftun_tun_lease_t lease, ftun_bytes_t packet)
{
  ftun_tun_service_t *borrowed = lease.service;
  ftun_tun_path_t path = {0};
  ftun_tun_consumer_t callbacks = {0};
  ftun_tun_lease_t rejected = {0};
  size_t work = SIZE_MAX;
  callbacks.packet = consume_packet;
  callbacks.user = state;
  if (ftun_tun_service_run(borrowed, &work) != FTUN_E_AGAIN || work != 0u ||
      ftun_tun_service_rebuild(borrowed) != FTUN_E_AGAIN ||
      ftun_tun_service_quiesce(borrowed) != FTUN_E_AGAIN ||
      ftun_tun_service_update_path(lease, &path) != FTUN_E_AGAIN) {
    state->release_errors++;
    return;
  }
  if (ftun_tun_service_release(&state->expected) != FTUN_OK ||
      ftun_tun_service_acquire(borrowed, &callbacks, &rejected) != FTUN_E_AGAIN ||
      rejected.service != NULL ||
      ftun_tun_service_destroy(&borrowed) != FTUN_E_AGAIN ||
      borrowed != lease.service) {
    state->release_errors++;
    return;
  }
  if (packet.data != NULL) {
    ftun_buffer_t *other = NULL;
    uint8_t *data = NULL;
    size_t capacity = 0u;
    uint8_t first = packet.data[0];
    if (ftun_buffer_pool_acquire(state->release_pool, packet.length,
                                 &other) != FTUN_OK ||
        ftun_buffer_data(other, &data, &capacity) != FTUN_OK ||
        capacity < packet.length) {
      state->release_errors++;
    } else {
      memset(data, 0xee, packet.length);
      if (packet.data[0] != first) state->release_errors++;
    }
    ftun_buffer_release(&other);
  }
  state->release_checks++;
}

static ftun_status_t consume_packet(void *user, ftun_tun_lease_t lease,
                                    ftun_bytes_t packet)
{
  consumer_state_t *state = (consumer_state_t *)user;
  if (state == NULL || lease.service != state->expected.service ||
      lease.generation != state->expected.generation || packet.data == NULL ||
      packet.length < 20u) return FTUN_E_STATE_CORRUPT;
  if (state->stall) return FTUN_E_AGAIN;
  if (state->release_pool != NULL) release_in_callback(state, lease, packet);
  state->received++;
  state->last_length = packet.length;
  return FTUN_OK;
}

static void consume_event(void *user, ftun_tun_lease_t lease,
                          ftun_tun_service_event_t event,
                          ftun_status_t status)
{
  consumer_state_t *state = (consumer_state_t *)user;
  if (state == NULL || lease.service != state->expected.service ||
      lease.generation != state->expected.generation || status != FTUN_OK) {
    return;
  }
  if (event == FTUN_TUN_SERVICE_PATH_UPDATED) state->path_updates++;
  else if (event == FTUN_TUN_SERVICE_REBUILT) state->rebuilds++;
  if (state->release_event) {
    release_in_callback(state, lease, (ftun_bytes_t){NULL, 0u});
  }
}

static void consume_error(void *user, ftun_tun_lease_t lease,
                          const ftun_tun_packet_error_t *error)
{
  consumer_state_t *state = (consumer_state_t *)user;
  if (state == NULL || error == NULL ||
      lease.service != state->expected.service ||
      lease.generation != state->expected.generation) return;
  state->errors++;
  state->last_error = *error;
  if (error->reason == FTUN_TUN_PACKET_MALFORMED) state->malformed++;
  else if (error->reason == FTUN_TUN_PACKET_TOO_BIG) state->oversized++;
  else if (error->reason == FTUN_TUN_PACKET_FRAGMENT_UNSUPPORTED) {
    state->fragments++;
  } else if (error->reason == FTUN_TUN_PACKET_SOURCE_REJECTED) {
    state->sources++;
  }
  if (error->feedback_sent) state->feedback_sent++;
  if (state->release_error) {
    release_in_callback(state, lease, (ftun_bytes_t){NULL, 0u});
  }
}

static int append_read(fake_device_t *device, size_t length,
                       const uint8_t source[4],
                       const uint8_t destination[4], uint16_t fragment)
{
  size_t index = device->read_count;
  if (index >= TEST_PACKETS ||
      make_ipv4(device->reads[index], length, source, destination,
                fragment) != length) return 0;
  device->read_lengths[index] = length;
  device->read_count++;
  return 1;
}

static int run_reads(ftun_tun_service_t *service, size_t expected)
{
  size_t work = 0u;
  if (ftun_tun_service_notify(service, FTUN_EVENT_READ) != FTUN_OK) return 0;
  return ftun_tun_service_run(service, &work) == FTUN_OK && work == expected;
}

static int test_path_contract(void)
{
  static const uint8_t local[4] = {10u, 77u, 0u, 2u};
  static const uint8_t remote[4] = {198u, 18u, 1u, 2u};
  static const uint8_t wrong[4] = {203u, 0u, 113u, 9u};
  ftun_budget_t *budget = NULL;
  ftun_buffer_pool_t *buffers = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_tun_service_t *service = NULL;
  ftun_tun_service_spec_t service_spec;
  ftun_tun_device_ops_t ops;
  ftun_tun_consumer_spec_t spec;
  ftun_tun_consumer_spec_t invalid_spec;
  ftun_tun_lease_t lease;
  ftun_tun_lease_t invalid_lease;
  ftun_tun_path_t path;
  ftun_tun_consumer_usage_t usage;
  ftun_tun_service_usage_t service_usage;
  ftun_budget_usage_t budget_usage;
  fake_device_t device;
  consumer_state_t state;
  uint8_t packet[TEST_MTU];
  size_t first_feedback;
  size_t index;

  memset(&device, 0, sizeof(device));
  memset(&state, 0, sizeof(state));
  memset(&service_spec, 0, sizeof(service_spec));
  memset(&ops, 0, sizeof(ops));
  memset(&spec, 0, sizeof(spec));
  memset(&lease, 0, sizeof(lease));
  memset(&invalid_lease, 0, sizeof(invalid_lease));
  CHECK(ftun_budget_create(NULL, 4u * 1024u * 1024u, 4096u, &budget) ==
        FTUN_OK);
  CHECK(ftun_buffer_pool_create(budget, 2048u, 64u, &buffers) == FTUN_OK);
  CHECK(ftun_event_loop_create(NULL, &loop) == FTUN_OK);
  CHECK(ftun_event_loop_attach_backend(loop, &event_ops, &device) == FTUN_OK);
  service_spec.budget = budget;
  service_spec.loop = loop;
  service_spec.buffers = buffers;
  service_spec.device.name.data = "ftun-pth0";
  service_spec.device.name.length = 9u;
  service_spec.device.mtu = TEST_MTU;
  service_spec.consumer_capacity = 2u;
  service_spec.input_capacity = 4u;
  service_spec.consumer_quota = 4u;
  service_spec.output_capacity = 8u;
  service_spec.read_quota = 16u;
  service_spec.write_quota = 8u;
  ops.open = fake_open;
  ops.get_info = fake_get_info;
  ops.read = fake_read;
  ops.write = fake_write;
  ops.close = fake_close;
  ops.user = &device;
  CHECK(ftun_tun_service_create_with_ops(
          &service_spec, &ops, &service) == FTUN_OK);

  spec.consumer.packet = consume_packet;
  spec.consumer.event = consume_event;
  spec.consumer.packet_error = consume_error;
  spec.consumer.user = &state;
  spec.route.kind = FTUN_TUN_ROUTE_PREFIX;
  spec.route.prefix.address.family = FTUN_IP_V4;
  memcpy(spec.route.prefix.address.bytes, (uint8_t[]){198u, 18u, 0u, 0u}, 4u);
  spec.route.prefix.prefix = 16u;
  spec.route.priority = 1u;
  spec.path.carrier_mtu = 1280u;
  spec.path.headroom = 80u;
  spec.path.flags = FTUN_TUN_PATH_ALLOW_IPV4_FRAGMENTS |
    FTUN_TUN_PATH_VALIDATE_OUTPUT_SOURCE;
  CHECK(ftun_tun_service_acquire_routed(service, &spec, &lease) == FTUN_OK);
  state.expected = lease;
  CHECK(ftun_tun_service_get_consumer_usage(lease, &usage) == FTUN_OK &&
        usage.path_generation == 1u && usage.inner_mtu == 1200u &&
        usage.path.headroom == 80u);

  invalid_spec = spec;
  invalid_spec.route.kind = FTUN_TUN_ROUTE_DEFAULT;
  memset(invalid_spec.route.prefix.address.bytes, 0, sizeof(invalid_spec.route.prefix.address.bytes));
  invalid_spec.route.prefix.prefix = 0u;
  invalid_spec.route.priority = 2u;
  CHECK(ftun_tun_service_acquire_routed(
          service, &invalid_spec, &invalid_lease) == FTUN_E_INVALID &&
        invalid_lease.service == NULL);
  path = spec.path;
  path.carrier_mtu = 100u;
  path.headroom = 40u;
  CHECK(ftun_tun_service_update_path(lease, &path) == FTUN_E_INVALID);
  path = spec.path;
  path.flags = UINT16_C(0x8000);
  CHECK(ftun_tun_service_update_path(lease, &path) == FTUN_E_INVALID);

  CHECK(append_read(&device, 100u, local, remote, 0u));
  CHECK(append_read(&device, 1300u, local, remote, UINT16_C(0x4000)));
  CHECK(append_read(&device, 100u, local, remote, UINT16_C(0x2000)));
  CHECK(append_read(&device, 100u, local, remote, 0u));
  device.reads[3][10] ^= 1u;
  CHECK(run_reads(service, 4u));
  CHECK(state.received == 2u && state.oversized == 1u &&
        state.malformed == 1u && state.feedback_sent == 1u &&
        device.write_count == 1u);
  first_feedback = 0u;
  CHECK(device.write_lengths[first_feedback] == 56u &&
        device.writes[first_feedback][0] == 0x45u &&
        device.writes[first_feedback][9] == 1u &&
        device.writes[first_feedback][20] == 3u &&
        device.writes[first_feedback][21] == 4u &&
        device.writes[first_feedback][26] == 0x04u &&
        device.writes[first_feedback][27] == 0xb0u &&
        memcmp(device.writes[first_feedback] + 12u, remote, 4u) == 0 &&
        memcmp(device.writes[first_feedback] + 16u, local, 4u) == 0 &&
        checksum(device.writes[first_feedback], 20u) == 0u &&
        checksum(device.writes[first_feedback] + 20u,
                 device.write_lengths[first_feedback] - 20u) == 0u);

  CHECK(make_ipv4(packet, 100u, remote, local, 0u) == 100u);
  CHECK(ftun_tun_service_write(
          lease, (ftun_bytes_t){packet, 100u}) == FTUN_OK);
  CHECK(make_ipv4(packet, 100u, wrong, local, 0u) == 100u);
  CHECK(ftun_tun_service_write(
          lease, (ftun_bytes_t){packet, 100u}) == FTUN_E_REJECTED);
  CHECK(state.sources == 1u &&
        state.last_error.direction == FTUN_TUN_PACKET_TO_DEVICE);
  packet[10] ^= 1u;
  CHECK(ftun_tun_service_write(
          lease, (ftun_bytes_t){packet, 100u}) == FTUN_E_PROTOCOL &&
        state.malformed == 2u);
  CHECK(make_ipv4(packet, 100u, remote, local, UINT16_C(0x2001)) == 100u);
  CHECK(ftun_tun_service_write(
          lease, (ftun_bytes_t){packet, 100u}) == FTUN_OK);
  CHECK(make_ipv4(packet, 1300u, remote, local, 0u) == 1300u);
  CHECK(ftun_tun_service_write(
          lease, (ftun_bytes_t){packet, 1300u}) == FTUN_E_LIMIT);

  for (index = 0u; index < 5u; index++) {
    CHECK(append_read(&device, 1300u, local, remote, UINT16_C(0x4000)));
  }
  CHECK(run_reads(service, 5u));
  CHECK(state.oversized == 7u && state.feedback_sent == 4u);
  CHECK(ftun_tun_service_get_consumer_usage(lease, &usage) == FTUN_OK &&
        usage.oversized_packets == 7u && usage.feedback_sent == 4u &&
        usage.feedback_suppressed == 2u && usage.sources_rejected == 1u &&
        usage.malformed_packets == 2u);

  /* 固定成功包计数补充一个 feedback token，避免时间源和无界定时器。 */
  for (index = 0u; index < 64u; index++) {
    CHECK(append_read(&device, 100u, local, remote, 0u));
  }
  for (index = 0u; index < 4u; index++) CHECK(run_reads(service, 16u));
  CHECK(append_read(&device, 1300u, local, remote, UINT16_C(0x4000)));
  CHECK(run_reads(service, 1u));
  CHECK(state.received == 66u && state.oversized == 8u &&
        state.feedback_sent == 5u);
  CHECK(append_read(&device, 1300u, (uint8_t[]){0u, 0u, 0u, 0u}, remote,
                    UINT16_C(0x4000)));
  CHECK(run_reads(service, 1u));
  CHECK(!state.last_error.feedback_sent && state.feedback_sent == 5u &&
        memcmp(state.last_error.source.bytes,
               (uint8_t[]){0u, 0u, 0u, 0u}, 4u) == 0);
  CHECK(append_read(&device, 1300u, local, remote, UINT16_C(0x4000)));
  device.reads[device.read_count - 1u][9] = 1u;
  device.reads[device.read_count - 1u][20] = 3u;
  update_ipv4_checksum(device.reads[device.read_count - 1u]);
  CHECK(run_reads(service, 1u));
  CHECK(!state.last_error.feedback_sent && state.feedback_sent == 5u);

  device.write_status = FTUN_E_AGAIN;
  CHECK(make_ipv4(packet, 100u, remote, local, 0u) == 100u);
  CHECK(ftun_tun_service_write(
          lease, (ftun_bytes_t){packet, 100u}) == FTUN_OK);
  state.stall = true;
  CHECK(append_read(&device, 100u, local, remote, 0u));
  CHECK(run_reads(service, 1u));
  CHECK(ftun_tun_service_get_consumer_usage(lease, &usage) == FTUN_OK &&
        usage.queued_inputs == 1u && usage.queued_outputs == 1u &&
        usage.blocked);
  path.carrier_mtu = 1500u;
  path.headroom = 100u;
  path.flags = FTUN_TUN_PATH_VALIDATE_OUTPUT_SOURCE;
  device.fail_update = true;
  CHECK(ftun_tun_service_update_path(lease, &path) == FTUN_E_IO);
  CHECK(ftun_tun_service_get_consumer_usage(lease, &usage) == FTUN_OK &&
        usage.queued_inputs == 1u && usage.queued_outputs == 1u && usage.blocked &&
        usage.path_generation == 1u && usage.inner_mtu == 1200u &&
        state.path_updates == 0u &&
        (device.interests & FTUN_EVENT_WRITE) != 0u);
  device.fail_update = false;
  CHECK(ftun_tun_service_update_path(lease, &path) == FTUN_OK);
  CHECK(state.path_updates == 1u);
  CHECK(ftun_tun_service_get_consumer_usage(lease, &usage) == FTUN_OK &&
        usage.path_generation == 2u && usage.inner_mtu == 1400u &&
        usage.queued_inputs == 0u && usage.queued_outputs == 0u &&
        !usage.blocked);

  device.write_status = FTUN_OK;
  state.stall = false;
  CHECK(append_read(&device, 100u, local, remote, UINT16_C(0x2001)));
  CHECK(append_read(&device, 1300u, local, remote, UINT16_C(0x4000)));
  CHECK(run_reads(service, 2u));
  CHECK(state.fragments == 1u && state.received == 67u &&
        state.last_length == 1300u);

  path.carrier_mtu = 160u;
  path.headroom = 80u;
  path.flags = FTUN_TUN_PATH_VALIDATE_OUTPUT_SOURCE;
  CHECK(ftun_tun_service_update_path(lease, &path) == FTUN_OK);
  CHECK(append_read(&device, 100u, local, remote, UINT16_C(0x4000)));
  CHECK(append_read(&device, 68u, local, remote, 0u));
  CHECK(run_reads(service, 2u));
  CHECK(state.path_updates == 2u && state.received == 68u &&
        state.last_length == 68u && state.last_error.inner_mtu == 80u &&
        state.last_error.headroom == 80u);

  CHECK(ftun_tun_service_get_consumer_usage(lease, &usage) == FTUN_OK &&
        usage.inner_mtu == 80u && usage.fragments_rejected == 1u &&
        usage.queued_inputs == 0u && usage.queued_outputs == 0u);
  CHECK(ftun_tun_service_rebuild(service) == FTUN_OK && state.rebuilds == 1u);
  CHECK(ftun_tun_service_get_consumer_usage(lease, &usage) == FTUN_OK &&
        usage.path_generation == 3u && usage.inner_mtu == 80u);
  CHECK(append_read(&device, 68u, local, remote, 0u));
  CHECK(run_reads(service, 1u));
  CHECK(state.received == 69u);
  CHECK(ftun_tun_service_get_usage(service, &service_usage) == FTUN_OK &&
        service_usage.device.mtu == TEST_MTU &&
        service_usage.device_generation == 2u &&
        service_usage.packet_errors == state.errors &&
        service_usage.feedback_sent == state.feedback_sent &&
        service_usage.feedback_suppressed == 4u);
  CHECK(ftun_tun_service_release(&lease) == FTUN_OK);
  CHECK(ftun_tun_service_destroy(&service) == FTUN_OK && service == NULL);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_loop_detach_backend(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_buffer_pool_destroy(&buffers) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK &&
        budget_usage.used_resources.memory_bytes == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int test_callback_packet_borrow(void)
{
  static const uint8_t source[4] = {10u, 77u, 0u, 2u};
  static const uint8_t target[4] = {198u, 18u, 1u, 2u};
  ftun_budget_t *budget = NULL;
  ftun_buffer_pool_t *buffers = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_tun_service_t *service = NULL;
  ftun_tun_service_spec_t spec;
  ftun_tun_device_ops_t ops;
  ftun_tun_consumer_t consumer;
  ftun_tun_service_usage_t usage;
  ftun_budget_usage_t budget_usage;
  fake_device_t device;
  consumer_state_t state;
  size_t work = 0u;
  size_t mode;

  memset(&device, 0, sizeof(device));
  memset(&state, 0, sizeof(state));
  memset(&spec, 0, sizeof(spec));
  memset(&ops, 0, sizeof(ops));
  memset(&consumer, 0, sizeof(consumer));
  CHECK(ftun_budget_create(NULL, 4u * 1024u * 1024u, 4096u, &budget) == FTUN_OK);
  CHECK(ftun_buffer_pool_create(budget, 2048u, 64u, &buffers) == FTUN_OK);
  CHECK(ftun_event_loop_create(NULL, &loop) == FTUN_OK);
  spec.budget = budget;
  spec.loop = loop;
  spec.buffers = buffers;
  spec.device.name = (ftun_string_t){"ftun-pth0", 9u};
  spec.device.mtu = TEST_MTU;
  spec.input_capacity = 2u;
  spec.output_capacity = 2u;
  spec.read_quota = 2u;
  spec.write_quota = 2u;
  ops.open = fake_open;
  ops.get_info = fake_get_info;
  ops.read = fake_read;
  ops.write = fake_write;
  ops.close = fake_close;
  ops.user = &device;
  CHECK(ftun_tun_service_create_with_ops(&spec, &ops, &service) == FTUN_OK);
  consumer.packet = consume_packet;
  consumer.event = consume_event;
  consumer.packet_error = consume_error;
  consumer.user = &state;
  CHECK(ftun_tun_service_acquire(service, &consumer, &state.expected) == FTUN_OK);
  state.stall = true;
  CHECK(append_read(&device, 100u, source, target, 0u));
  CHECK(run_reads(service, 1u));
  CHECK(ftun_tun_service_get_usage(service, &usage) == FTUN_OK &&
        usage.queued_inputs == 1u);
  state.stall = false;
  state.release_pool = buffers;
  CHECK(ftun_tun_service_resume(state.expected) == FTUN_OK);
  CHECK(ftun_tun_service_run(service, &work) == FTUN_OK && work == 1u);
  CHECK(state.release_checks == 1u && state.release_errors == 0u);
  CHECK(ftun_tun_service_get_usage(service, &usage) == FTUN_OK &&
        usage.queued_inputs == 0u && usage.queued_input_bytes == 0u &&
        usage.active_leases == 0u);
  for (mode = 0u; mode < 5u; mode++) {
    ftun_tun_path_t path = {TEST_MTU, 0u, 0u};
    memset(&state, 0, sizeof(state));
    CHECK(ftun_tun_service_acquire(service, &consumer, &state.expected) == FTUN_OK);
    if (mode == 0u) {
      state.release_pool = buffers;
      CHECK(append_read(&device, 100u, source, target, 0u));
      CHECK(run_reads(service, 1u));
    } else if (mode == 1u) {
      state.release_event = true;
      CHECK(ftun_tun_service_update_path(state.expected, &path) == FTUN_OK);
    } else if (mode == 2u) {
      state.release_event = true;
      CHECK(ftun_tun_service_rebuild(service) == FTUN_OK);
    } else if (mode == 3u) {
      uint8_t malformed = 0u;
      state.release_error = true;
      CHECK(ftun_tun_service_update_path(state.expected, &path) == FTUN_OK);
      CHECK(ftun_tun_service_write(state.expected,
              (ftun_bytes_t){&malformed, 1u}) == FTUN_E_PROTOCOL);
    } else {
      state.release_event = true;
      CHECK(ftun_tun_service_quiesce(service) == FTUN_OK);
    }
    CHECK(state.release_checks == 1u && state.release_errors == 0u);
    CHECK(ftun_tun_service_get_usage(service, &usage) == FTUN_OK &&
          usage.active_leases == 0u && usage.queued_inputs == 0u);
  }
  CHECK(ftun_tun_service_destroy(&service) == FTUN_OK);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_buffer_pool_destroy(&buffers) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK &&
        budget_usage.used_resources.memory_bytes == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int test_ipv6_path(void)
{
  ftun_budget_t *budget = NULL;
  ftun_buffer_pool_t *buffers = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_tun_service_t *service = NULL;
  ftun_tun_service_spec_t service_spec = {0};
  ftun_tun_device_ops_t ops = {fake_open, fake_get_info, fake_read, fake_write, fake_close, NULL};
  ftun_tun_consumer_spec_t spec = {0};
  ftun_tun_lease_t lease = {0};
  ftun_budget_usage_t usage;
  fake_device_t device = {0};
  consumer_state_t state = {0};
  uint8_t packet[TEST_MTU] = {0};
  uint8_t pseudo[1280u + 40u] = {0};
  const uint8_t local[16] = {0xfd, 0, 0, 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
  const uint8_t remote[16] = {0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7};
  CHECK(ftun_budget_create(NULL, 4u * 1024u * 1024u, 4096u, &budget) == FTUN_OK);
  CHECK(ftun_buffer_pool_create(budget, 2048u, 64u, &buffers) == FTUN_OK);
  CHECK(ftun_event_loop_create(NULL, &loop) == FTUN_OK);
  service_spec.budget = budget; service_spec.buffers = buffers; service_spec.loop = loop;
  service_spec.device.name = (ftun_string_t){"ftun-pth0", 9u};
  service_spec.device.mtu = TEST_MTU;
  service_spec.consumer_capacity = 1u; service_spec.input_capacity = 4u;
  service_spec.output_capacity = 4u; service_spec.read_quota = 4u; service_spec.write_quota = 4u;
  ops.user = &device;
  CHECK(ftun_tun_service_create_with_ops(&service_spec, &ops, &service) == FTUN_OK);
  spec.consumer = (ftun_tun_consumer_t){consume_packet, consume_event, consume_error, &state};
  spec.route.kind = FTUN_TUN_ROUTE_PREFIX;
  CHECK(ftun_cidr_parse("2001:db8::/120", sizeof("2001:db8::/120") - 1u, true, &spec.route.prefix));
  spec.path.carrier_mtu = 1279u;
  spec.path.flags = FTUN_TUN_PATH_VALIDATE_OUTPUT_SOURCE;
  CHECK(ftun_tun_service_acquire_routed(service, &spec, &lease) == FTUN_E_INVALID);
  spec.path.carrier_mtu = 1280u;
  CHECK(ftun_tun_service_acquire_routed(service, &spec, &lease) == FTUN_OK);
  state.expected = lease;
  packet[0] = 0x60u; packet[6] = 17u; packet[7] = 64u;
  memcpy(packet + 8u, local, 16u); memcpy(packet + 24u, remote, 16u);
  packet[4] = 4u; packet[5] = 236u; /* 1300 - 40 */
  memcpy(device.reads[0], packet, 1300u);
  device.read_lengths[0] = 1300u; device.read_count = 1u;
  CHECK(run_reads(service, 1u));
  CHECK(state.oversized == 1u && state.feedback_sent == 1u && device.write_count == 1u);
  CHECK(state.last_error.source.family == FTUN_IP_V6 && state.last_error.inner_mtu == 1280u);
  CHECK(device.write_lengths[0] == 1280u && device.writes[0][6] == 58u &&
    device.writes[0][40] == 2u && device.writes[0][46] == 5u && device.writes[0][47] == 0u);
  CHECK(memcmp(device.writes[0] + 8u, remote, 16u) == 0 &&
    memcmp(device.writes[0] + 24u, local, 16u) == 0 &&
    memcmp(device.writes[0] + 48u, packet, 1232u) == 0);
  memcpy(pseudo, device.writes[0] + 8u, 32u);
  pseudo[34] = 4u; pseudo[35] = 216u; pseudo[39] = 58u; /* 1240 字节 ICMPv6。 */
  memcpy(pseudo + 40u, device.writes[0] + 40u, 1240u);
  CHECK(checksum(pseudo, 1280u) == 0u);
  /* 长前缀来源校验使用全部 16 字节；错误地址不能写回设备。 */
  packet[4] = 0u; packet[5] = 60u;
  memcpy(packet + 8u, remote, 16u); memcpy(packet + 24u, local, 16u);
  CHECK(ftun_tun_service_write(lease, (ftun_bytes_t){packet, 100u}) == FTUN_OK);
  packet[22] ^= 1u;
  CHECK(ftun_tun_service_write(lease, (ftun_bytes_t){packet, 100u}) == FTUN_E_REJECTED);
  packet[22] ^= 1u;
  packet[5] = 59u;
  CHECK(ftun_tun_service_write(lease, (ftun_bytes_t){packet, 100u}) == FTUN_E_PROTOCOL);
  CHECK(ftun_tun_service_release(&lease) == FTUN_OK);
  CHECK(ftun_tun_service_destroy(&service) == FTUN_OK);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_buffer_pool_destroy(&buffers) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(void)
{
  CHECK(test_callback_packet_borrow() == 0);
  CHECK(test_path_contract() == 0);
  CHECK(test_ipv6_path() == 0);
  return 0;
}
