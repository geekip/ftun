#include "libs/transport/socket_path.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* 测试工厂只提供有界内存 Stream，不能打开任何出站 socket。 */
typedef struct {
  ftun_reservation_t reservation;
  ftun_event_loop_t *loop;
  ftun_path_t *path;
  ftun_stream_write_token_t write;
  ftun_datagram_t *datagram;
  ftun_datagram_send_token_t send;
  ftun_packet_t packet;
  ftun_endpoint_t endpoint;
  bool packet_pending;
  ftun_path_completion_fn completion;
  void *completion_user;
  ftun_path_notify_fn notify;
  void *notify_user;
  size_t length;
  size_t request_length;
  unsigned int phase;
  uint8_t request[600];
  bool deferred;
  bool stopped;
  bool eof;
  bool dns;
  bool banner;
  uint8_t bytes[8192];
} memory_path_t;

static void notify(memory_path_t *state, uint32_t events, ftun_status_t status)
{
  ftun_path_t *held = state->path;
  if (state->notify == NULL || ftun_path_retain(held) != FTUN_OK) return;
  state->notify(held, events, (ftun_error_t){status, 0u, 0}, state->notify_user);
  ftun_path_release(&held);
}

static void flush(void *user)
{
  memory_path_t *state = user;
  ftun_path_t *held = state->path;
  ftun_stream_write_token_t write = state->write;
  ftun_datagram_send_token_t send = state->send;
  if (ftun_path_retain(held) != FTUN_OK) return;
  state->deferred = false;
  memset(&state->write, 0, sizeof(state->write));
  memset(&state->send, 0, sizeof(state->send));
  if (write.stream != NULL) (void)ftun_stream_write_complete(write,
    (ftun_error_t){state->stopped ? FTUN_E_CANCELLED : FTUN_OK, 0u, 0});
  if (send.channel != NULL) (void)ftun_datagram_send_complete(send,
    (ftun_error_t){state->stopped ? FTUN_E_CANCELLED : FTUN_OK, 0u, 0});
  if (state->packet_pending) {
    ftun_status_t delivered = state->stopped ? FTUN_E_CANCELLED :
      ftun_datagram_deliver(state->datagram, &state->endpoint, &state->packet);
    if (delivered != FTUN_E_AGAIN && delivered != FTUN_E_LIMIT) {
      ftun_packet_release(&state->packet);
      state->packet_pending = false;
    } else notify(state, FTUN_PATH_ERROR, delivered);
  }
  notify(state, FTUN_PATH_READABLE | FTUN_PATH_WRITABLE, FTUN_OK);
  ftun_path_release(&held);
}

static ftun_status_t resume(void *user)
{
  memory_path_t *state = user;
  ftun_status_t status;
  if (state->stopped) return FTUN_E_CANCELLED;
  if (state->deferred) return FTUN_OK;
  status = ftun_event_defer(state->loop, flush, state);
  if (status == FTUN_OK) state->deferred = true;
  return status;
}

static ftun_status_t read_bytes(void *user, void *buffer, size_t capacity, size_t *length)
{
  memory_path_t *state = user;
  *length = 0u;
  if (state->stopped) return FTUN_E_CANCELLED;
  if (state->length == 0u) return state->eof ? FTUN_E_EOF : FTUN_E_AGAIN;
  *length = capacity < state->length ? capacity : state->length;
  if (state->phase != 0u && state->phase != 4u && *length > 1u) *length = 1u;
  memcpy(buffer, state->bytes, *length);
  state->length -= *length;
  memmove(state->bytes, state->bytes + *length, state->length);
  notify(state, FTUN_PATH_WRITABLE, FTUN_OK);
  return FTUN_OK;
}

/* 同一内存通道还可充当 SOCKS5 服务端，握手故意逐字节分段。 */
static ftun_status_t protocol_bytes(memory_path_t *state, const uint8_t *data, size_t length)
{
  size_t needed;
  uint8_t *request = state->request;
  if (length > sizeof(state->request) - state->request_length) return FTUN_E_LIMIT;
  memcpy(request + state->request_length, data, length);
  state->request_length += length;
  if (state->phase == 1u) {
    if (state->request_length < 2u) return FTUN_OK;
    needed = 2u + request[1];
    if (state->request_length < needed) return FTUN_OK;
    if (request[0] != 5u || request[1] != 1u || (request[2] != 0u && request[2] != 2u)) return FTUN_E_INVALID;
    state->bytes[0] = 5u;
    state->bytes[1] = request[2];
    state->length = 2u;
    state->phase = request[2] == 2u ? 2u : 3u;
  } else if (state->phase == 2u) {
    if (state->request_length < 2u || state->request_length < 3u + request[1]) return FTUN_OK;
    needed = 3u + request[1] + request[2u + request[1]];
    if (state->request_length < needed) return FTUN_OK;
    state->bytes[0] = 1u;
    state->bytes[1] = (uint8_t)(request[0] == 1u && request[1] == 4u && request[6] == 4u &&
      memcmp(request + 2u, "user", 4u) == 0 && memcmp(request + 7u, "pass", 4u) == 0 ? 0u : 1u);
    state->length = 2u;
    state->phase = 3u;
  } else {
    static const uint8_t reply[] = {5u, 0u, 0u, 1u, 127u, 0u, 0u, 1u, 0u, 1u};
    if (state->request_length < 5u) return FTUN_OK;
    needed = request[3] == 1u ? 10u : request[3] == 3u ? 7u + request[4] : 22u;
    if (state->request_length < needed) return FTUN_OK;
    if (request[0] != 5u || (request[1] != 1u && request[1] != 3u) || request[2] != 0u) return FTUN_E_INVALID;
    memcpy(state->bytes, reply, sizeof(reply));
    state->length = sizeof(reply);
    if (request[1] == 3u) memset(state->bytes + 4u, 0, 4u);
    /* 在回复后拼接应用字节，验证客户端严格读取回复边界。 */
    if (request[3] == 3u && request[4] == 11u && memcmp(request + 5u, "banner.test", 11u) == 0) {
      memcpy(state->bytes + state->length, "hello", 5u);
      state->length += 5u;
    }
    state->phase = 4u;
  }
  if (state->request_length != needed) return FTUN_E_STATE_CORRUPT;
  state->request_length = 0u;
  return FTUN_OK;
}

/* DNS 替身完整收帧后才回复；奇数 ID 的 UDP 响应要求生产端 TC fallback。 */
static ftun_status_t dns_bytes(memory_path_t *state, const uint8_t *data, size_t length)
{
  size_t needed;
  if (length > sizeof(state->request) - state->request_length) return FTUN_E_LIMIT;
  memcpy(state->request + state->request_length, data, length);
  state->request_length += length;
  if (state->request_length < 2u) return FTUN_OK;
  needed = 2u + ((size_t)state->request[0] << 8u) + state->request[1];
  if (state->request_length < needed) return FTUN_OK;
  if (needed < 14u || state->request_length != needed) return FTUN_E_PROTOCOL;
  memcpy(state->bytes, state->request, needed);
  state->bytes[4] |= 0x80u;
  state->length = needed;
  state->request_length = 0u;
  return FTUN_OK;
}

static ftun_status_t write_bytes(void *user, ftun_stream_write_token_t token,
  const ftun_buffer_slice_t *slice, size_t *accepted)
{
  memory_path_t *state = user;
  ftun_bytes_t bytes;
  ftun_status_t status;
  size_t length;
  *accepted = 0u;
  if (state->stopped || state->eof) return FTUN_E_CANCELLED;
  if (state->write.stream != NULL || state->deferred || state->length == sizeof(state->bytes))
    return FTUN_E_AGAIN;
  status = ftun_buffer_slice_data(slice, &bytes);
  if (status != FTUN_OK) return status;
  length = bytes.length < 257u ? bytes.length : 257u;
  if (state->dns || (state->phase != 0u && state->phase != 4u)) length = 1u;
  if (length > sizeof(state->bytes) - state->length) length = sizeof(state->bytes) - state->length;
  status = ftun_event_defer(state->loop, flush, state);
  if (status != FTUN_OK) return status;
  if (state->phase != 0u && state->phase != 4u) {
    status = protocol_bytes(state, bytes.data, length);
  } else if (state->dns) {
    status = dns_bytes(state, bytes.data, length);
  } else {
    memcpy(state->bytes + state->length, bytes.data, length);
    state->length += length;
  }
  if (status != FTUN_OK) {
    /* defer 已接纳，维持对象直到 flush；错误由完成结果传递。 */
    state->stopped = true;
  }
  state->deferred = true;
  state->write = token;
  *accepted = length;
  return FTUN_OK;
}

static ftun_status_t cancel_write(void *user, ftun_stream_write_token_t token)
{
  memory_path_t *state = user;
  if (state->write.stream != token.stream || state->write.generation != token.generation)
    return FTUN_E_STALE;
  memset(&state->write, 0, sizeof(state->write));
  return FTUN_OK;
}

static ftun_status_t shutdown_write(void *user)
{
  memory_path_t *state = user;
  state->eof = true;
  notify(state, FTUN_PATH_READABLE, FTUN_OK);
  return FTUN_OK;
}

static ftun_status_t stop(void *user)
{
  memory_path_t *state = user;
  state->stopped = true;
  return state->deferred ? FTUN_E_AGAIN : FTUN_OK;
}

static void destroy(void *user)
{
  memory_path_t *state = user;
  ftun_reservation_t reservation = state->reservation;
  ftun_packet_release(&state->packet);
  free(state);
  ftun_reservation_release(&reservation);
}

static ftun_status_t send_packet(void *user, ftun_datagram_send_token_t send,
  const ftun_endpoint_t *target, const ftun_packet_t *packet)
{
  memory_path_t *state = user;
  ftun_status_t status;
  if (state->stopped) return FTUN_E_CANCELLED;
  if (state->packet_pending || state->deferred || state->send.channel != NULL) return FTUN_E_AGAIN;
  if (target->kind != FTUN_ADDRESS_IPV4) return FTUN_E_UNSUPPORTED;
  if (state->dns) {
    ftun_bytes_t wire;
    ftun_buffer_t *buffer = NULL;
    ftun_buffer_slice_t slice = {0};
    ftun_budget_t *budget = NULL;
    uint8_t *data = NULL;
    size_t capacity;
    size_t offset = target->port == 53u ? 0u : 10u;
    status = ftun_packet_view(packet, &wire);
    if (status == FTUN_OK && wire.length < offset + 12u) status = FTUN_E_PROTOCOL;
    if (status == FTUN_OK) status = ftun_datagram_budget(state->datagram, &budget);
    if (status == FTUN_OK) status = ftun_buffer_acquire(budget, wire.length, &buffer);
    if (status == FTUN_OK) status = ftun_buffer_data(buffer, &data, &capacity);
    if (status == FTUN_OK) {
      memcpy(data, wire.data, wire.length);
      data[offset + 2u] |= (data[offset + 1u] & 1u) != 0u ? 0x82u : 0x80u;
      status = ftun_buffer_slice(buffer, 0u, wire.length, &slice);
    }
    if (status == FTUN_OK) status = ftun_packet_init(&state->packet, &slice, 0u);
    ftun_buffer_slice_release(&slice);
    ftun_buffer_release(&buffer);
  } else status = ftun_packet_clone(packet, &state->packet);
  if (status != FTUN_OK) return status;
  status = resume(state);
  if (status != FTUN_OK) { ftun_packet_release(&state->packet); return status; }
  state->send = send;
  state->endpoint = *target;
  state->packet_pending = true;
  return FTUN_OK;
}

static ftun_status_t cancel_packet(void *user, ftun_datagram_send_token_t send)
{
  memory_path_t *state = user;
  if (state->send.channel != send.channel || state->send.slot != send.slot ||
      state->send.generation != send.generation) return FTUN_E_STALE;
  memset(&state->send, 0, sizeof(state->send));
  ftun_packet_release(&state->packet);
  state->packet_pending = false;
  return FTUN_OK;
}

static void opened(ftun_operation_t *operation, ftun_error_t error, void *user)
{
  memory_path_t *state = user;
  ftun_path_completion_fn completion = state->completion;
  ftun_path_t *path = state->path;
  void *completion_user = state->completion_user;
  if (error.status == FTUN_OK && state->banner) {
    memcpy(state->bytes, "hello", 5u);
    state->length = 5u;
    /* 完成之前已可读，消费者必须保留提示直到真正移交 Relay。 */
    notify(state, FTUN_PATH_READABLE, FTUN_OK);
  }
  completion(operation, error, path, completion_user);
}

ftun_status_t __wrap_ftun_socket_path_open(void *context, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *spec,
  ftun_operation_t **out)
{
  memory_path_t *state;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_stream_t *stream = NULL;
  ftun_stream_options_t options = request->stream;
  ftun_stream_backend_t backend = {0};
  ftun_path_spec_t adopted = *spec;
  ftun_operation_token_t token;
  ftun_budget_usage_t usage;
  ftun_status_t status;
  (void)context;
  (void)core;
  *out = NULL;
  if (request->dial.transport != FTUN_DIAL_TCP && request->dial.transport != FTUN_DIAL_UDP) return FTUN_E_UNSUPPORTED;
  /* 非 socket 工厂不应继承虚构的出站 FD 占位。TCP 对象最多只有物理
   * 入站的一个 FD；UDP 对象使用共享 listener，本身没有独占 FD。 */
  status = ftun_budget_get_usage(request->dial.budget, &usage);
  if (status != FTUN_OK) return status;
  if (request->dial.purpose != FTUN_DIAL_PURPOSE_DNS &&
      usage.used_resources.descriptors >
      (request->dial.transport == FTUN_DIAL_TCP ? 1u : 0u)) {
    fprintf(stderr, "Memory path inherited a synthetic outbound descriptor charge\n");
    return FTUN_E_STATE_CORRUPT;
  }
  status = ftun_budget_reserve(request->dial.budget, sizeof(*state), &reservation);
  if (status != FTUN_OK) return status;
  state = calloc(1u, sizeof(*state));
  if (state == NULL) { ftun_reservation_release(&reservation); return FTUN_E_LIMIT; }
  state->reservation = reservation;
  state->loop = request->dial.loop;
  state->phase = request->dial.purpose == FTUN_DIAL_PURPOSE_PROXY ? 1u : 0u;
  state->dns = request->dial.purpose == FTUN_DIAL_PURPOSE_DNS;
  state->banner = request->dial.purpose == FTUN_DIAL_PURPOSE_BUSINESS &&
    request->dial.transport == FTUN_DIAL_TCP &&
    request->dial.endpoint.kind == FTUN_ADDRESS_IPV4 &&
    memcmp(request->dial.endpoint.address, "\x7f\x00\x00\x02", 4u) == 0;
  if (state->dns) {
    if (request->dial.endpoint.port == 1080u) state->phase = 1u;
    fprintf(stderr, "DNS memory path: generation=%llu transport=%u port=%u\n",
      (unsigned long long)spec->configuration_generation,
      (unsigned int)request->dial.transport, (unsigned int)request->dial.endpoint.port);
  }
  state->completion = request->completion;
  state->completion_user = request->user;
  state->notify = request->notify;
  state->notify_user = request->notify_user;
  adopted.driver.stop = stop;
  adopted.driver.resume = resume;
  adopted.driver.context = state;
  if (request->dial.transport == FTUN_DIAL_TCP) {
    backend.context = state;
    backend.read = read_bytes;
    backend.write_start = write_bytes;
    backend.write_cancel = cancel_write;
    backend.shutdown_write = shutdown_write;
    backend.destroy = destroy;
    if (options.budget == NULL) options.budget = request->dial.budget;
    if (options.operations == NULL) options.operations = request->dial.operations;
    status = ftun_stream_create(&options, &backend, &stream);
    if (status != FTUN_OK) { destroy(state); return status; }
    status = ftun_path_adopt_stream(&adopted, &stream, &state->path);
    if (status != FTUN_OK) {
      (void)ftun_stream_abort(stream);
      (void)ftun_stream_destroy(&stream);
      return status;
    }
  } else {
    ftun_datagram_options_t datagram_options = request->datagram;
    ftun_datagram_backend_t datagram_backend = {0};
    ftun_datagram_t *channel = NULL;
    if (datagram_options.budget == NULL) datagram_options.budget = request->dial.budget;
    datagram_backend.context = state;
    datagram_backend.send_start = send_packet;
    datagram_backend.send_cancel = cancel_packet;
    datagram_backend.destroy = destroy;
    status = ftun_datagram_create(&datagram_options, &datagram_backend, &channel);
    if (status != FTUN_OK) { destroy(state); return status; }
    state->datagram = channel;
    status = ftun_path_adopt_datagram(&adopted, &channel, &state->path);
    if (status != FTUN_OK) {
      (void)ftun_datagram_stop(channel);
      (void)ftun_datagram_destroy(&channel);
      return status;
    }
  }
  status = ftun_operation_accept(request->dial.operations, opened, state, out, &token);
  if (status != FTUN_OK) {
    ftun_path_t *path = state->path;
    (void)ftun_path_revoke(path);
    (void)ftun_path_destroy(&path);
    return status;
  }
  return ftun_operation_complete(token, (ftun_error_t){FTUN_OK, 0u, 0});
}
