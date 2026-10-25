#define _POSIX_C_SOURCE 200809L
#include "transport/control_channel.h"

#include "core/context.h"
#include "event/libev_adapter.h"
#include "transport/socket_path.h"
#include "util/time.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define FTUN_CONTROL_CHANNEL_BYTES (64u * 1024u)

ftun_status_t ftun_control_execution_limit(const ftun_control_execution_t *input,
  uint64_t timeout_ms, ftun_control_execution_t *out)
{
  uint64_t now;
  ftun_status_t status;
  if (out == NULL || input == NULL || input->budget == NULL ||
      input->generation == 0u || input->deadline_ms == 0u || timeout_ms == 0u) {
    return FTUN_E_INVALID;
  }
  status = ftun_monotonic_now(&now);
  if (status != FTUN_OK) return status;
  if (now >= input->deadline_ms) return FTUN_E_TIMEOUT;
  *out = *input;
  if (timeout_ms < input->deadline_ms - now) out->deadline_ms = now + timeout_ms;
  return FTUN_OK;
}

struct ftun_control_channel {
  ftun_budget_t *budget;
  ftun_reservation_t *reservation;
  ftun_core_t *core;
  ftun_event_loop_t *loop;
  ftun_event_source_t *timer;
  ftun_operation_queue_t *operations;
  ftun_path_provider_t *provider;
  ftun_resolver_provider_t *resolver;
  ftun_operation_t *resolving;
  ftun_endpoint_t resolved;
  char domain[FTUN_SYSTEM_RESOLVER_MAX_DOMAIN_BYTES + 1u];
  size_t domain_length;
  ftun_path_t *path;
  ftun_stream_t *stream;
  ftun_datagram_t *datagram;
  ftun_packet_t received;
  ftun_endpoint_t received_source;
  ftun_dial_transport_t transport;
  ftun_operation_t *opening;
  ftun_operation_t *writing;
  uint64_t generation;
  uint64_t deadline_ms;
  ftun_status_t status;
  bool expired;
  bool stopping;
  bool sending;
  bool has_received;
};

static void ftun_control_channel_timer(ftun_event_source_t *source,
  uint32_t events, void *user)
{
  ftun_control_channel_t *channel = user;
  (void)source;
  (void)events;
  channel->expired = true;
}

static void ftun_control_channel_opened(ftun_operation_t *operation,
  ftun_error_t error, ftun_path_t *path, void *user)
{
  ftun_control_channel_t *channel = user;
  (void)operation;
  channel->opening = NULL;
  channel->status = error.status;
  channel->path = path;
  if (error.status == FTUN_OK) {
    channel->status = channel->transport == FTUN_DIAL_UDP
      ? ftun_path_datagram(path, &channel->datagram)
      : ftun_path_stream(path, &channel->stream);
  }
}

static void ftun_control_channel_written(ftun_operation_t *operation,
  ftun_error_t error, void *user)
{
  ftun_control_channel_t *channel = user;
  (void)operation;
  channel->writing = NULL;
  if (error.status != FTUN_OK) channel->status = error.status;
}

static void ftun_control_channel_sent(ftun_datagram_t *datagram,
  ftun_error_t error, const ftun_endpoint_t *target,
  const ftun_packet_t *packet, void *user)
{
  ftun_control_channel_t *channel = user;
  (void)datagram;
  (void)target;
  (void)packet;
  channel->sending = false;
  if (error.status != FTUN_OK) channel->status = error.status;
}

static ftun_status_t ftun_control_channel_received(ftun_datagram_t *datagram,
  const ftun_endpoint_t *source, const ftun_packet_t *packet, void *user)
{
  ftun_control_channel_t *channel = user;
  ftun_bytes_t bytes;
  ftun_status_t status;
  (void)datagram;
  if (channel->stopping) return FTUN_E_CANCELLED;
  if (channel->has_received) return FTUN_E_AGAIN;
  status = ftun_packet_view(packet, &bytes);
  if (status != FTUN_OK) return status;
  if (source->kind != FTUN_ADDRESS_IPV4 ||
      bytes.length > FTUN_CONTROL_CHANNEL_BYTES) {
    channel->status = source->kind != FTUN_ADDRESS_IPV4
      ? FTUN_E_UNSUPPORTED : FTUN_E_LIMIT;
    return FTUN_OK;
  }
  status = ftun_packet_clone(packet, &channel->received);
  if (status != FTUN_OK) return status;
  channel->received_source = *source;
  channel->has_received = true;
  return FTUN_OK;
}

static void ftun_control_channel_notified(ftun_path_t *path, uint32_t events,
  ftun_error_t error, void *user)
{
  ftun_control_channel_t *channel = user;
  (void)path;
  if ((events & FTUN_PATH_ERROR) != 0u && error.status != FTUN_OK &&
      error.status != FTUN_E_AGAIN) {
    channel->status = error.status;
  }
}

static ftun_status_t ftun_control_channel_poll(ftun_control_channel_t *channel,
  bool block)
{
  size_t callbacks = 0u;
  ftun_status_t status;
  status = ftun_operation_dispatch(channel->operations, 32u, &callbacks);
  if (status != FTUN_OK || callbacks != 0u) return status;
  status = ftun_event_loop_run_once(channel->loop, block, 32u, &callbacks);
  if (status == FTUN_OK) {
    status = ftun_operation_dispatch(channel->operations, 32u, &callbacks);
  }
  return status;
}

static ftun_status_t ftun_control_channel_deadline(ftun_control_channel_t *channel)
{
  uint64_t now;
  ftun_status_t status = ftun_monotonic_now(&now);
  if (status != FTUN_OK) return status;
  return channel->expired || now >= channel->deadline_ms ? FTUN_E_TIMEOUT : FTUN_OK;
}

ftun_status_t ftun_control_channel_wait(ftun_control_channel_t *channel)
{
  uint64_t now;
  ftun_status_t status;
  if (channel == NULL || channel->stopping) return FTUN_E_INVALID;
  status = ftun_monotonic_now(&now);
  if (status != FTUN_OK) return status;
  if (channel->expired || now >= channel->deadline_ms) return FTUN_E_TIMEOUT;
  status = ftun_control_channel_poll(channel, true);
  if (status == FTUN_OK && channel->expired) status = FTUN_E_TIMEOUT;
  return status;
}

ftun_status_t ftun_control_channel_create(ftun_budget_t *budget,
  uint64_t generation, uint64_t deadline_ms, ftun_control_channel_t **out)
{
  ftun_control_execution_t execution = {0};
  execution.budget = budget;
  execution.generation = generation;
  execution.deadline_ms = deadline_ms;
  return ftun_control_channel_create_execution(&execution, out);
}

ftun_status_t ftun_control_channel_create_execution(
  const ftun_control_execution_t *execution, ftun_control_channel_t **out)
{
  ftun_control_channel_t *channel;
  ftun_reservation_t *reservation = NULL;
  ftun_path_provider_spec_t spec = {0};
  ftun_status_t status;
  ftun_budget_t *budget = execution == NULL ? NULL : execution->budget;
  uint64_t generation = execution == NULL ? 0u : execution->generation;
  uint64_t deadline_ms = execution == NULL ? 0u : execution->deadline_ms;
  if (out != NULL) *out = NULL;
  if (budget == NULL || generation == 0u || deadline_ms == 0u || out == NULL) {
    return FTUN_E_INVALID;
  }
  status = ftun_budget_reserve(budget, sizeof(*channel), &reservation);
  if (status != FTUN_OK) return status;
  channel = calloc(1u, sizeof(*channel));
  if (channel == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  channel->budget = budget;
  channel->reservation = reservation;
  channel->generation = generation;
  channel->deadline_ms = deadline_ms;
  status = ftun_core_context_create(budget, &channel->core);
  if (status == FTUN_OK) status = ftun_operation_queue_create(budget, 8u, &channel->operations);
  if (status == FTUN_OK) status = ftun_event_loop_create_with_capacity(channel->core, 16u, &channel->loop);
  if (status == FTUN_OK) status = ftun_libev_attach(channel->loop);
  spec.budget = budget;
  spec.generation = generation;
  spec.ops.open = execution->path.open == NULL ? ftun_socket_path_open : execution->path.open;
  spec.context = execution->path.context;
  spec.max_pending = 1u;
  spec.max_paths = 1u;
  if (status == FTUN_OK) status = ftun_path_provider_create(&spec, &channel->provider);
  if (status == FTUN_OK) status = ftun_event_timer_start(channel->loop,
    deadline_ms, ftun_control_channel_timer, channel, &channel->timer);
  if (status != FTUN_OK) {
    ftun_control_channel_drain(&channel);
    return status;
  }
  *out = channel;
  return FTUN_OK;
}

static void ftun_control_channel_resolved(ftun_operation_t *operation,
  ftun_error_t error, const ftun_system_resolve_result_t *result, void *user)
{
  ftun_control_channel_t *channel = user;
  (void)operation;
  channel->resolving = NULL;
  channel->status = error.status;
  if (error.status != FTUN_OK) return;
  if (result == NULL || result->domain.length != channel->domain_length ||
      memcmp(result->domain.data, channel->domain, channel->domain_length) != 0 ||
      result->address_count == 0u) {
    channel->status = FTUN_E_PROTOCOL;
    return;
  }
  channel->resolved.kind = FTUN_ADDRESS_IPV4;
  memcpy(channel->resolved.address, result->addresses[0].address, 4u);
}

ftun_status_t ftun_control_channel_resolve(ftun_control_channel_t *channel,
  const ftun_resolver_provider_ops_t *ops, void *context,
  const ftun_resolver_provider_request_t *request, ftun_endpoint_t *out)
{
  ftun_resolver_provider_spec_t spec = {0};
  ftun_resolver_provider_request_t delegated;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (channel == NULL || ops == NULL || request == NULL || out == NULL ||
      channel->resolver != NULL || channel->stopping || request->system.domain.data == NULL ||
      request->system.domain.length == 0u || request->system.domain.length > sizeof(channel->domain) - 1u ||
      request->system.completion != NULL) return FTUN_E_INVALID;
  if (request->generation != channel->generation) return FTUN_E_STALE;
  status = ftun_control_channel_deadline(channel);
  if (status != FTUN_OK) return status;
  spec.budget = channel->budget;
  spec.generation = channel->generation;
  spec.max_pending = 1u;
  spec.max_scopes = 1u;
  spec.ops = *ops;
  spec.context = context;
  status = ftun_resolver_provider_create(&spec, &channel->resolver);
  if (status != FTUN_OK) return status;
  memcpy(channel->domain, request->system.domain.data, request->system.domain.length);
  channel->domain_length = request->system.domain.length;
  delegated = *request;
  delegated.loop = channel->loop;
  delegated.operations = channel->operations;
  delegated.system.budget = channel->budget;
  delegated.system.deadline_ms = channel->deadline_ms;
  delegated.system.completion = ftun_control_channel_resolved;
  delegated.system.user = channel;
  status = ftun_resolver_provider_start(channel->resolver, channel->core,
    &delegated, &channel->resolving);
  while (status == FTUN_OK && channel->resolving != NULL) {
    status = ftun_control_channel_wait(channel);
  }
  if (status == FTUN_OK) status = channel->status;
  if (status == FTUN_OK) status = ftun_control_channel_deadline(channel);
  if (status == FTUN_OK) *out = channel->resolved;
  return status;
}

static ftun_status_t ftun_control_channel_open(ftun_control_channel_t *channel,
  const ftun_endpoint_t *endpoint, uint32_t mark, ftun_dial_purpose_t purpose,
  ftun_dial_transport_t transport)
{
  ftun_path_open_request_t request = {0};
  ftun_status_t status;
  if (channel == NULL || endpoint == NULL || channel->stopping ||
      channel->opening != NULL || channel->path != NULL) return FTUN_E_INVALID;
  status = ftun_control_channel_deadline(channel);
  if (status != FTUN_OK) return status;
  request.dial.loop = channel->loop;
  request.dial.operations = channel->operations;
  request.dial.budget = channel->budget;
  request.dial.endpoint = *endpoint;
  request.dial.allowed = endpoint;
  request.dial.allowed_count = 1u;
  channel->transport = transport;
  request.dial.transport = transport;
  request.dial.requested_domain = FTUN_DIAL_DOMAIN_UNDERLAY;
  request.dial.purpose = purpose;
  request.dial.protection.mark = mark;
  request.dial.deadline_ms = channel->deadline_ms;
  request.completion = ftun_control_channel_opened;
  request.user = channel;
  request.notify = ftun_control_channel_notified;
  request.notify_user = channel;
  request.stream.max_pending_writes = 1u;
  request.stream.max_pending_bytes = FTUN_CONTROL_CHANNEL_BYTES;
  request.stream.completion = ftun_control_channel_written;
  request.stream.completion_user = channel;
  request.datagram.max_pending_packets = 1u;
  request.datagram.max_pending_bytes = FTUN_CONTROL_CHANNEL_BYTES;
  request.datagram.result = ftun_control_channel_sent;
  request.datagram.receive = ftun_control_channel_received;
  request.datagram.user = channel;
  status = ftun_path_provider_open_channel(channel->provider, channel->core,
    channel->generation, &request, &channel->opening);
  while (status == FTUN_OK && channel->opening != NULL) {
    status = ftun_control_channel_wait(channel);
  }
  return status == FTUN_OK ? channel->status : status;
}

ftun_status_t ftun_control_channel_connect(ftun_control_channel_t *channel,
  const ftun_endpoint_t *endpoint, uint32_t mark, ftun_dial_purpose_t purpose)
{
  return ftun_control_channel_open(channel, endpoint, mark, purpose, FTUN_DIAL_TCP);
}

ftun_status_t ftun_control_channel_connect_datagram(ftun_control_channel_t *channel,
  const ftun_endpoint_t *endpoint, uint32_t mark, ftun_dial_purpose_t purpose)
{
  return ftun_control_channel_open(channel, endpoint, mark, purpose, FTUN_DIAL_UDP);
}

ftun_status_t ftun_control_channel_read(void *user, uint8_t *buffer,
  size_t capacity, size_t *length)
{
  ftun_control_channel_t *channel = user;
  ftun_status_t status;
  if (length != NULL) *length = 0u;
  if (channel == NULL || channel->stream == NULL || channel->stopping ||
      buffer == NULL || capacity == 0u || length == NULL) return FTUN_E_INVALID;
  status = ftun_control_channel_deadline(channel);
  if (status != FTUN_OK) return status;
  status = ftun_stream_read(channel->stream, buffer, capacity, length);
  /* 先交付已缓存字节，随后才暴露通知中的错误或 EOF。 */
  return status == FTUN_E_AGAIN && channel->status != FTUN_OK
    ? channel->status : status;
}

ftun_status_t ftun_control_channel_write(void *user, const uint8_t *data,
  size_t length, size_t *written)
{
  ftun_control_channel_t *channel = user;
  ftun_buffer_t *buffer = NULL;
  ftun_buffer_slice_t slice = {0};
  uint8_t *storage;
  size_t capacity, accepted = 0u;
  ftun_status_t status;
  if (written != NULL) *written = 0u;
  if (channel == NULL || channel->stream == NULL || channel->stopping ||
      data == NULL || length == 0u || written == NULL) return FTUN_E_INVALID;
  status = ftun_control_channel_deadline(channel);
  if (status != FTUN_OK) return status;
  if (channel->status != FTUN_OK) return channel->status;
  if (length > FTUN_CONTROL_CHANNEL_BYTES) length = FTUN_CONTROL_CHANNEL_BYTES;
  status = ftun_buffer_acquire(channel->budget, length, &buffer);
  if (status == FTUN_OK) status = ftun_buffer_data(buffer, &storage, &capacity);
  if (status == FTUN_OK) {
    memcpy(storage, data, length);
    status = ftun_buffer_slice(buffer, 0u, length, &slice);
  }
  if (status == FTUN_OK) status = ftun_stream_write_ref(channel->stream,
    &slice, &accepted, &channel->writing);
  (void)ftun_buffer_slice_release(&slice);
  (void)ftun_buffer_release(&buffer);
  while (status == FTUN_OK && channel->writing != NULL) {
    status = ftun_control_channel_wait(channel);
  }
  if (status == FTUN_OK) status = channel->status;
  if (status == FTUN_OK) *written = accepted;
  return status;
}

ftun_status_t ftun_control_channel_send(ftun_control_channel_t *channel,
  const ftun_endpoint_t *target, const uint8_t *data, size_t length)
{
  ftun_buffer_t *buffer = NULL;
  ftun_packet_t packet = {0};
  uint8_t *storage;
  uint64_t now;
  size_t capacity;
  ftun_status_t status;
  if (channel == NULL || channel->datagram == NULL || channel->stopping ||
      target == NULL || (data == NULL && length != 0u)) return FTUN_E_INVALID;
  if (length > FTUN_CONTROL_CHANNEL_BYTES) return FTUN_E_LIMIT;
  if (channel->status != FTUN_OK) return channel->status;
  if (channel->sending) return FTUN_E_AGAIN;
  status = ftun_monotonic_now(&now);
  if (status != FTUN_OK) return status;
  if (channel->expired || now >= channel->deadline_ms) return FTUN_E_TIMEOUT;
  status = ftun_buffer_acquire(channel->budget, length == 0u ? 1u : length, &buffer);
  if (status == FTUN_OK) status = ftun_buffer_data(buffer, &storage, &capacity);
  if (status == FTUN_OK) {
    if (length != 0u) memcpy(storage, data, length);
    status = ftun_buffer_slice(buffer, 0u, length, &packet.payload);
  }
  if (status == FTUN_OK) {
    /* result 可以在 send 返回前调用，必须先设置在途标记。 */
    channel->sending = true;
    status = ftun_datagram_send(channel->datagram, target, &packet);
    if (status != FTUN_OK) channel->sending = false;
  }
  (void)ftun_packet_release(&packet);
  (void)ftun_buffer_release(&buffer);
  while (status == FTUN_OK && channel->sending) {
    status = ftun_control_channel_wait(channel);
  }
  return status == FTUN_OK ? channel->status : status;
}

ftun_status_t ftun_control_channel_read_exact(ftun_control_channel_t *channel,
  uint8_t *data, size_t length)
{
  size_t offset = 0u;
  if (channel == NULL || (data == NULL && length != 0u)) return FTUN_E_INVALID;
  while (offset < length) {
    size_t amount = 0u;
    ftun_status_t status = ftun_control_channel_read(channel, data + offset,
      length - offset, &amount);
    if (status == FTUN_E_AGAIN) {
      status = ftun_control_channel_wait(channel);
      if (status == FTUN_OK) continue;
    }
    if (status != FTUN_OK) return status;
    if (amount == 0u) return FTUN_E_EOF;
    offset += amount;
  }
  return FTUN_OK;
}

ftun_status_t ftun_control_channel_write_all(ftun_control_channel_t *channel,
  const uint8_t *data, size_t length)
{
  size_t offset = 0u;
  if (channel == NULL || (data == NULL && length != 0u)) return FTUN_E_INVALID;
  while (offset < length) {
    size_t amount = 0u;
    ftun_status_t status = ftun_control_channel_write(channel, data + offset,
      length - offset, &amount);
    if (status == FTUN_E_AGAIN) {
      status = ftun_control_channel_wait(channel);
      if (status == FTUN_OK) continue;
    }
    if (status != FTUN_OK) return status;
    if (amount == 0u) return FTUN_E_IO;
    offset += amount;
  }
  return FTUN_OK;
}

ftun_status_t ftun_control_channel_receive(ftun_control_channel_t *channel,
  ftun_endpoint_t *source, uint8_t *data, size_t capacity, size_t *length)
{
  ftun_bytes_t bytes;
  ftun_status_t status, resumed;
  if (length != NULL) *length = 0u;
  if (source != NULL) memset(source, 0, sizeof(*source));
  if (channel == NULL || channel->datagram == NULL || channel->stopping ||
      source == NULL || data == NULL || capacity == 0u || length == NULL) {
    return FTUN_E_INVALID;
  }
  status = ftun_control_channel_deadline(channel);
  if (status != FTUN_OK) return status;
  if (!channel->has_received) {
    return channel->status == FTUN_OK ? FTUN_E_AGAIN : channel->status;
  }
  status = ftun_packet_view(&channel->received, &bytes);
  if (status == FTUN_OK && bytes.length > capacity) status = FTUN_E_LIMIT;
  if (status == FTUN_OK) {
    if (bytes.length != 0u) memcpy(data, bytes.data, bytes.length);
    *length = bytes.length;
    *source = channel->received_source;
  }
  (void)ftun_packet_release(&channel->received);
  channel->has_received = false;
  resumed = ftun_path_resume(channel->path);
  if (resumed != FTUN_OK) channel->status = resumed;
  return status;
}

ftun_status_t ftun_control_channel_close(ftun_control_channel_t **pointer)
{
  ftun_control_channel_t *channel;
  ftun_status_t status;
  if (pointer == NULL) return FTUN_E_INVALID;
  channel = *pointer;
  if (channel == NULL) return FTUN_OK;
  channel->stopping = true;
  if (channel->resolver != NULL) {
    status = ftun_resolver_provider_stop_until(channel->resolver, UINT64_MAX);
    if (status != FTUN_OK && status != FTUN_E_AGAIN) return status;
  }
  if (channel->provider != NULL) {
    status = ftun_path_provider_stop_until(channel->provider, UINT64_MAX);
    if (status != FTUN_OK && status != FTUN_E_AGAIN) return status;
  }
  if (channel->operations != NULL) {
    status = ftun_operation_queue_stop(channel->operations);
    /* 取消失败不阻止已终结操作派发；迟到 OK 也必须先交还 Provider，
     * 由其取消标记抑制结果，不能卡在下一次相同 cancel hook 前。 */
    if (status != FTUN_OK && status != FTUN_E_AGAIN) return status;
    if (channel->loop != NULL) {
      status = ftun_control_channel_poll(channel, false);
      if (status != FTUN_OK) return status;
    }
  }
  if (channel->path != NULL) {
    status = ftun_path_revoke(channel->path);
    if (status == FTUN_OK) status = ftun_path_destroy(&channel->path);
    if (status != FTUN_OK) return status;
    channel->stream = NULL;
    channel->datagram = NULL;
  }
  (void)ftun_packet_release(&channel->received);
  channel->has_received = false;
  if (channel->resolver != NULL) {
    status = ftun_resolver_provider_stop_until(channel->resolver, UINT64_MAX);
    if (status == FTUN_OK) status = ftun_resolver_provider_destroy(&channel->resolver);
    if (status != FTUN_OK) return status;
  }
  if (channel->provider != NULL) {
    status = ftun_path_provider_stop_until(channel->provider, UINT64_MAX);
    if (status == FTUN_OK) status = ftun_path_provider_destroy(&channel->provider);
    if (status != FTUN_OK) return status;
  }
  if (channel->timer != NULL) {
    status = ftun_event_source_cancel(&channel->timer);
    if (status != FTUN_OK) return status;
  }
  if (channel->loop != NULL) {
    status = ftun_event_loop_stop(channel->loop);
    if (status == FTUN_OK) status = ftun_libev_detach(channel->loop);
    if (status == FTUN_OK) status = ftun_event_loop_destroy(&channel->loop);
    if (status != FTUN_OK) return status;
  }
  if (channel->operations != NULL) {
    status = ftun_operation_queue_destroy(&channel->operations);
    if (status != FTUN_OK) return status;
  }
  if (channel->core != NULL) {
    status = ftun_core_context_destroy(&channel->core);
    if (status != FTUN_OK) return status;
  }
  (void)ftun_reservation_release(&channel->reservation);
  free(channel);
  *pointer = NULL;
  return FTUN_OK;
}

void ftun_control_channel_drain(ftun_control_channel_t **pointer)
{
  if (pointer == NULL) return;
  while (ftun_control_channel_close(pointer) != FTUN_OK) {
    ftun_control_channel_t *channel = *pointer;
    uint64_t now;
    /* 取消失败时不能释放生产者引用。只在清理重试期间安排下一次唤醒，
     * 数据传输不使用周期 tick；不延长外层 Worker 的停止期限。 */
    if (channel->loop != NULL && channel->operations != NULL &&
        ftun_monotonic_now(&now) == FTUN_OK) {
      (void)ftun_event_source_cancel(&channel->timer);
      if (ftun_event_timer_start(channel->loop, now + 10u,
            ftun_control_channel_timer, channel, &channel->timer) == FTUN_OK) {
        if (ftun_control_channel_poll(channel, true) == FTUN_OK) continue;
      }
    }
    {
      struct timespec pause = {0, 10000000};
      (void)nanosleep(&pause, NULL);
    }
  }
}
