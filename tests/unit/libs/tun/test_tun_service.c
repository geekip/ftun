#include "libs/tun/service.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
  if (!(condition)) { \
    fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #condition); \
    return 1; \
  } \
} while (0)

#define TEST_MTU 128u
#define TEST_PACKETS 4u

typedef struct {
  uint8_t reads[TEST_PACKETS][TEST_MTU];
  size_t read_lengths[TEST_PACKETS];
  size_t read_count;
  size_t read_index;
  uint8_t writes[TEST_PACKETS][TEST_MTU];
  size_t write_lengths[TEST_PACKETS];
  size_t write_count;
  size_t open_attempts;
  size_t close_count;
  ftun_status_t write_status;
  ftun_status_t read_status;
  bool fail_open;
} fake_device_t;

typedef struct {
  uint8_t packets[TEST_PACKETS][TEST_MTU];
  size_t lengths[TEST_PACKETS];
  size_t packet_count;
  size_t rebuilt;
  size_t quiesced;
  size_t failed;
  bool stall;
  ftun_status_t failure_status;
  ftun_tun_lease_t expected;
} consumer_state_t;

static ftun_status_t fake_open(void *user, ftun_core_t *core,
                               const ftun_tun_spec_t *spec,
                               ftun_packet_port_t **out)
{
  fake_device_t *device = (fake_device_t *)user;
  (void)core;
  if (out != NULL) *out = NULL;
  if (device == NULL || spec == NULL || out == NULL ||
      spec->name.data == NULL || spec->name.length != 8u ||
      memcmp(spec->name.data, "ftun-ts0", 8u) != 0 ||
      spec->mtu != TEST_MTU) return FTUN_E_INVALID;
  device->open_attempts++;
  if (device->fail_open) return FTUN_E_IO;
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
  memcpy(out->name, "ftun-ts0", 9u);
  out->mtu = TEST_MTU;
  out->native_socket = (ftun_native_socket_t)(40u + device->open_attempts);
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
  if (device->read_status != FTUN_OK) return device->read_status;
  if (device->read_index == device->read_count) return FTUN_E_AGAIN;
  index = device->read_index;
  if (device->read_lengths[index] > capacity) return FTUN_E_LIMIT;
  memcpy(buffer, device->reads[index], device->read_lengths[index]);
  *out_length = device->read_lengths[index];
  device->read_index++;
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
  device->close_count++;
  *port = NULL;
  return FTUN_OK;
}

static ftun_status_t consume_packet(void *user, ftun_tun_lease_t lease,
                                    ftun_bytes_t packet)
{
  consumer_state_t *state = (consumer_state_t *)user;
  size_t index;
  if (state == NULL || lease.service != state->expected.service ||
      lease.generation != state->expected.generation ||
      packet.data == NULL || packet.length == 0u ||
      packet.length > TEST_MTU || state->packet_count >= TEST_PACKETS) {
    return FTUN_E_STATE_CORRUPT;
  }
  index = state->packet_count;
  if (state->stall) return FTUN_E_AGAIN;
  memcpy(state->packets[index], packet.data, packet.length);
  state->lengths[index] = packet.length;
  state->packet_count++;
  return FTUN_OK;
}

static void consume_event(void *user, ftun_tun_lease_t lease,
                          ftun_tun_service_event_t event,
                          ftun_status_t status)
{
  consumer_state_t *state = (consumer_state_t *)user;
  if (state == NULL || lease.service != state->expected.service ||
      lease.generation != state->expected.generation) return;
  if (event == FTUN_TUN_SERVICE_REBUILT) state->rebuilt++;
  else if (event == FTUN_TUN_SERVICE_QUIESCED) state->quiesced++;
  else if (event == FTUN_TUN_SERVICE_FAILED) {
    state->failed++;
    state->failure_status = status;
  }
}

static int test_service_lifecycle(void)
{
  static const uint8_t output_a[] = {0x45u, 0x00u, 0x00u, 0x14u};
  static const uint8_t output_b[] = {0x60u, 0x00u, 0x00u, 0x00u, 0x00u};
  static const uint8_t output_c[] = {0x45u, 0x01u, 0x02u};
  static const uint8_t output_d[] = {0x45u, 0x03u};
  ftun_budget_t *budget = NULL;
  ftun_buffer_pool_t *buffers = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_tun_service_t *service = NULL;
  ftun_tun_service_spec_t spec;
  ftun_tun_device_ops_t ops;
  ftun_tun_consumer_t consumer;
  ftun_tun_lease_t lease;
  ftun_tun_lease_t stale;
  ftun_tun_lease_t second;
  ftun_tun_service_usage_t usage;
  ftun_budget_usage_t budget_usage;
  fake_device_t device;
  consumer_state_t state;
  size_t work = 0u;

  memset(&device, 0, sizeof(device));
  memset(&state, 0, sizeof(state));
  memset(&spec, 0, sizeof(spec));
  memset(&ops, 0, sizeof(ops));
  memset(&consumer, 0, sizeof(consumer));
  memset(&lease, 0, sizeof(lease));
  memset(&second, 0, sizeof(second));
  device.write_status = FTUN_OK;
  device.read_count = 3u;
  device.read_lengths[0] = 4u;
  device.read_lengths[1] = 5u;
  device.read_lengths[2] = 3u;
  memcpy(device.reads[0], output_a, sizeof(output_a));
  memcpy(device.reads[1], output_b, sizeof(output_b));
  memcpy(device.reads[2], output_c, sizeof(output_c));

  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 4096u, &budget) == FTUN_OK);
  CHECK(ftun_buffer_pool_create(budget, 4096u, 4u, &buffers) == FTUN_OK);
  CHECK(ftun_event_loop_create(NULL, &loop) == FTUN_OK);
  spec.budget = budget;
  spec.loop = loop;
  spec.buffers = buffers;
  spec.device.name.data = "ftun-ts0";
  spec.device.name.length = 8u;
  spec.device.mtu = TEST_MTU;
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
  CHECK(ftun_tun_service_get_usage(service, &usage) == FTUN_OK &&
        usage.device_generation == 1u && usage.active_leases == 0u &&
        usage.device.mtu == TEST_MTU && usage.accepting && !usage.ready);

  consumer.packet = consume_packet;
  consumer.event = consume_event;
  consumer.user = &state;
  CHECK(ftun_tun_service_acquire(service, &consumer, &lease) == FTUN_OK);
  state.expected = lease;
  CHECK(lease.generation != 0u &&
        ftun_tun_service_acquire(service, &consumer, &second) == FTUN_E_AGAIN &&
        second.service == NULL);
  CHECK(ftun_tun_service_destroy(&service) == FTUN_E_AGAIN && service != NULL);

  CHECK(ftun_tun_service_notify(service, FTUN_EVENT_READ) == FTUN_OK);
  CHECK(ftun_tun_service_run(service, &work) == FTUN_OK && work == 2u);
  CHECK(state.packet_count == 2u &&
        state.lengths[0] == sizeof(output_a) &&
        memcmp(state.packets[0], output_a, sizeof(output_a)) == 0 &&
        state.lengths[1] == sizeof(output_b) &&
        memcmp(state.packets[1], output_b, sizeof(output_b)) == 0);
  CHECK(ftun_tun_service_run(service, &work) == FTUN_OK && work == 1u &&
        state.packet_count == 3u &&
        memcmp(state.packets[2], output_c, sizeof(output_c)) == 0);
  CHECK(ftun_tun_service_run(service, &work) == FTUN_OK && work == 0u &&
        device.read_index == 3u);

  CHECK(ftun_tun_service_write(
          lease, (ftun_bytes_t){output_a, sizeof(output_a)}) == FTUN_OK &&
        device.write_count == 1u);
  device.write_status = FTUN_E_AGAIN;
  CHECK(ftun_tun_service_write(
          lease, (ftun_bytes_t){output_b, sizeof(output_b)}) == FTUN_OK);
  CHECK(ftun_tun_service_write(
          lease, (ftun_bytes_t){output_c, sizeof(output_c)}) == FTUN_OK);
  CHECK(ftun_tun_service_write(
          lease, (ftun_bytes_t){output_d, sizeof(output_d)}) == FTUN_E_LIMIT);
  CHECK(ftun_tun_service_get_usage(service, &usage) == FTUN_OK &&
        usage.queued_packets == 2u &&
        usage.queued_bytes == sizeof(output_b) + sizeof(output_c));
  CHECK(ftun_tun_service_notify(service, FTUN_EVENT_WRITE) == FTUN_OK);
  CHECK(ftun_tun_service_run(service, &work) == FTUN_OK && work == 0u);
  device.write_status = FTUN_OK;
  CHECK(ftun_tun_service_notify(service, FTUN_EVENT_WRITE) == FTUN_OK);
  CHECK(ftun_tun_service_run(service, &work) == FTUN_OK && work == 2u &&
        device.write_count == 3u &&
        device.write_lengths[1] == sizeof(output_b) &&
        memcmp(device.writes[1], output_b, sizeof(output_b)) == 0 &&
        device.write_lengths[2] == sizeof(output_c) &&
        memcmp(device.writes[2], output_c, sizeof(output_c)) == 0);

  /* 平台层把短写映射为 IO；owner 不得把残缺包当作成功。 */
  device.write_status = FTUN_E_IO;
  CHECK(ftun_tun_service_write(
          lease, (ftun_bytes_t){output_d, sizeof(output_d)}) == FTUN_E_IO &&
        device.write_count == 3u);
  device.write_status = FTUN_E_AGAIN;
  CHECK(ftun_tun_service_write(
          lease, (ftun_bytes_t){output_d, sizeof(output_d)}) == FTUN_OK);
  /* 内部状态错误仍是服务故障；设备 IO 错误按设备丢失处理（见 test_device_loss）。 */
  device.write_status = FTUN_E_STATE_CORRUPT;
  CHECK(ftun_tun_service_notify(service, FTUN_EVENT_WRITE) == FTUN_OK);
  CHECK(ftun_tun_service_run(service, &work) == FTUN_E_STATE_CORRUPT && work == 0u &&
        state.failed == 1u && state.failure_status == FTUN_E_STATE_CORRUPT);

  /* 旧设备读取但消费者背压留下的包，不能在重建后继续交付。 */
  state.stall = true;
  memcpy(device.reads[3], output_d, sizeof(output_d));
  device.read_lengths[3] = sizeof(output_d);
  device.read_count = 4u;
  CHECK(ftun_tun_service_notify(service, FTUN_EVENT_READ) == FTUN_OK);
  CHECK(ftun_tun_service_run(service, &work) == FTUN_OK);
  CHECK(ftun_tun_service_get_usage(service, &usage) == FTUN_OK && usage.queued_inputs == 1u);
  device.fail_open = true;
  CHECK(ftun_tun_service_rebuild(service) == FTUN_E_IO &&
        device.close_count == 1u && device.open_attempts == 2u &&
        state.rebuilt == 0u);
  CHECK(ftun_tun_service_get_usage(service, &usage) == FTUN_OK &&
        usage.device_generation == 1u && usage.queued_packets == 0u &&
        usage.packets_dropped == 2u && usage.active_leases == 1u &&
        usage.queued_inputs == 0u && !usage.accepting);
  CHECK(ftun_tun_service_write(
          lease, (ftun_bytes_t){output_a, sizeof(output_a)}) ==
        FTUN_E_CANCELLED);
  device.fail_open = false;
  state.stall = false;
  device.write_status = FTUN_OK;
  CHECK(ftun_tun_service_rebuild(service) == FTUN_OK &&
        device.open_attempts == 3u && state.rebuilt == 1u);
  CHECK(ftun_tun_service_get_usage(service, &usage) == FTUN_OK &&
        usage.device_generation == 2u &&
        usage.lease_generation == lease.generation &&
        usage.active_leases == 1u);
  CHECK(ftun_tun_service_run(service, &work) == FTUN_OK && state.packet_count == 3u);

  stale = lease;
  CHECK(ftun_tun_service_release(&lease) == FTUN_OK && lease.service == NULL);
  CHECK(ftun_tun_service_acquire(service, &consumer, &second) == FTUN_OK &&
        second.generation != stale.generation);
  state.expected = second;
  CHECK(ftun_tun_service_release(&stale) == FTUN_E_STALE &&
        stale.service == service);
  CHECK(ftun_tun_service_write(
          stale, (ftun_bytes_t){output_a, sizeof(output_a)}) == FTUN_E_STALE);
  CHECK(ftun_tun_service_quiesce(service) == FTUN_OK && state.quiesced == 1u);
  CHECK(ftun_tun_service_quiesce(service) == FTUN_OK && state.quiesced == 1u);
  CHECK(ftun_tun_service_notify(service, FTUN_EVENT_READ) == FTUN_E_CANCELLED);
  CHECK(ftun_tun_service_write(
          second, (ftun_bytes_t){output_a, sizeof(output_a)}) ==
        FTUN_E_CANCELLED);
  CHECK(ftun_tun_service_release(&second) == FTUN_OK);
  CHECK(ftun_tun_service_destroy(&service) == FTUN_OK && service == NULL &&
        device.close_count == 2u);
  CHECK(ftun_tun_service_destroy(&service) == FTUN_OK);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_buffer_pool_destroy(&buffers) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK &&
        budget_usage.used == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

/* 设备被外部删除：读写 IO 错误或 ERROR 事件不是宿主故障，服务重建设备；
 * 重建失败时停止收发、保留 device_lost 供 owner 退避重试，run 本身不报错。 */
static int test_device_loss(void)
{
  fake_device_t device;
  consumer_state_t state;
  ftun_budget_t *budget = NULL;
  ftun_buffer_pool_t *buffers = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_tun_service_t *service = NULL;
  ftun_tun_service_spec_t spec;
  ftun_tun_device_ops_t ops;
  ftun_tun_consumer_t consumer;
  ftun_tun_lease_t lease;
  ftun_tun_service_usage_t usage;
  size_t work = 0u;
  memset(&device, 0, sizeof(device));
  memset(&state, 0, sizeof(state));
  memset(&spec, 0, sizeof(spec));
  memset(&ops, 0, sizeof(ops));
  memset(&consumer, 0, sizeof(consumer));
  memset(&lease, 0, sizeof(lease));
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 4096u, &budget) == FTUN_OK);
  CHECK(ftun_buffer_pool_create(budget, 4096u, 4u, &buffers) == FTUN_OK);
  CHECK(ftun_event_loop_create(NULL, &loop) == FTUN_OK);
  spec.budget = budget;
  spec.loop = loop;
  spec.buffers = buffers;
  spec.device.name.data = "ftun-ts0";
  spec.device.name.length = 8u;
  spec.device.mtu = TEST_MTU;
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
  consumer.user = &state;
  CHECK(ftun_tun_service_acquire(service, &consumer, &lease) == FTUN_OK);
  state.expected = lease;

  /* 读取 IO 错误：重建成功，run 不报错，代次递增，丢失标记清除。 */
  device.read_status = FTUN_E_IO;
  CHECK(ftun_tun_service_notify(service, FTUN_EVENT_READ) == FTUN_OK);
  CHECK(ftun_tun_service_run(service, &work) == FTUN_OK);
  CHECK(ftun_tun_service_get_usage(service, &usage) == FTUN_OK &&
        usage.device_generation == 2u && usage.accepting && !usage.device_lost &&
        state.rebuilt == 1u && device.close_count == 1u);
  /* ERROR 事件同样处理。 */
  device.read_status = FTUN_OK;
  CHECK(ftun_tun_service_notify(service, FTUN_EVENT_ERROR) == FTUN_OK);
  CHECK(ftun_tun_service_run(service, &work) == FTUN_OK);
  CHECK(ftun_tun_service_get_usage(service, &usage) == FTUN_OK &&
        usage.device_generation == 3u && !usage.device_lost && state.rebuilt == 2u);
  /* 重建失败：不是服务故障，停止收发并保留丢失标记。 */
  device.fail_open = true;
  CHECK(ftun_tun_service_notify(service, FTUN_EVENT_ERROR) == FTUN_OK);
  CHECK(ftun_tun_service_run(service, &work) == FTUN_OK);
  CHECK(ftun_tun_service_get_usage(service, &usage) == FTUN_OK &&
        usage.device_lost && !usage.accepting && state.rebuilt == 2u &&
        state.failed >= 1u);
  /* 条件恢复后再次重建（owner 退避重试的入口）。 */
  device.fail_open = false;
  CHECK(ftun_tun_service_rebuild(service) == FTUN_OK);
  CHECK(ftun_tun_service_get_usage(service, &usage) == FTUN_OK &&
        !usage.device_lost && usage.accepting && state.rebuilt == 3u);
  CHECK(ftun_tun_service_release(&lease) == FTUN_OK);
  CHECK(ftun_tun_service_quiesce(service) == FTUN_OK);
  CHECK(ftun_tun_service_destroy(&service) == FTUN_OK);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_buffer_pool_destroy(&buffers) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(void)
{
  CHECK(test_device_loss() == 0);
  CHECK(ftun_tun_service_create(NULL, NULL) == FTUN_E_INVALID);
  CHECK(test_service_lifecycle() == 0);
  return 0;
}
