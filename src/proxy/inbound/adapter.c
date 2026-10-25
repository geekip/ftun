#include "proxy/inbound/adapter.h"
#include "proxy/inbound/mixed.h"
#include "util/time.h"

#include <stdlib.h>
#include <string.h>

struct ftun_inbound_adapter {
  ftun_buffer_pool_t *pool;
  ftun_budget_t *budget;
  ftun_reservation_t *reservation;
  ftun_stream_t *client;
  ftun_socks5_server_t *socks;
  ftun_mixed_connection_t *mixed;
  ftun_operation_t *operation;
  ftun_buffer_slice_t reply;
  size_t reply_offset;
  uint64_t handshake_deadline;
  uint64_t reply_timeout;
  uint64_t deadline;
  void (*wakeup)(void *);
  void *user;
  ftun_status_t failure;
  ftun_inbound_event_kind_t request_kind;
  bool http;
  bool forward;
  bool finished;
  bool close_after;
  bool stopped;
  bool busy;
};

static void ftun_inbound_adapter_wake(ftun_inbound_adapter_t *adapter)
{
  if (adapter->wakeup != NULL) adapter->wakeup(adapter->user);
}

static ftun_status_t ftun_inbound_adapter_copy(ftun_inbound_adapter_t *adapter,
  ftun_bytes_t first, ftun_bytes_t tail, ftun_buffer_slice_t *out)
{
  ftun_buffer_t *buffer = NULL;
  ftun_status_t status;
  uint8_t *data;
  size_t capacity;
  memset(out, 0, sizeof(*out));
  if (first.length > SIZE_MAX - tail.length) return FTUN_E_LIMIT;
  if (first.length + tail.length == 0u) return FTUN_OK;
  status = adapter->pool == NULL
    ? ftun_buffer_acquire(adapter->budget, first.length + tail.length, &buffer)
    : ftun_buffer_pool_acquire(adapter->pool, first.length + tail.length, &buffer);
  if (status != FTUN_OK) return status;
  status = ftun_buffer_data(buffer, &data, &capacity);
  if (status == FTUN_OK) {
    if (first.length != 0u) memcpy(data, first.data, first.length);
    if (tail.length != 0u) memcpy(data + first.length, tail.data, tail.length);
    status = ftun_buffer_slice(buffer, 0u, first.length + tail.length, out);
  }
  (void)ftun_buffer_release(&buffer);
  return status;
}

static ftun_status_t ftun_inbound_adapter_reply(ftun_inbound_adapter_t *adapter,
  ftun_bytes_t wire, bool close_after)
{
  uint64_t now;
  ftun_status_t status;
  if (adapter->reply.owner != NULL || adapter->operation != NULL) return FTUN_E_AGAIN;
  if (wire.length > 1024u) return FTUN_E_LIMIT;
  status = ftun_monotonic_now(&now);
  if (status != FTUN_OK) return status;
  if (now > UINT64_MAX - adapter->reply_timeout) return FTUN_E_LIMIT;
  status = ftun_inbound_adapter_copy(adapter, wire, (ftun_bytes_t){NULL, 0u}, &adapter->reply);
  if (status != FTUN_OK) return status;
  adapter->reply_offset = 0u;
  adapter->close_after = close_after;
  adapter->deadline = now + adapter->reply_timeout;
  if (adapter->request_kind == FTUN_INBOUND_EVENT_NONE &&
      adapter->handshake_deadline < adapter->deadline) adapter->deadline = adapter->handshake_deadline;
  ftun_inbound_adapter_wake(adapter);
  return FTUN_OK;
}

static void ftun_inbound_adapter_written(ftun_operation_t *operation,
  ftun_error_t error, void *user)
{
  ftun_inbound_adapter_t *adapter = (ftun_inbound_adapter_t *)user;
  (void)operation;
  adapter->busy = true;
  adapter->operation = NULL;
  if (error.status != FTUN_OK) adapter->failure = error.status;
  ftun_inbound_adapter_wake(adapter);
  adapter->busy = false;
}

static ftun_status_t ftun_inbound_adapter_flush(ftun_inbound_adapter_t *adapter)
{
  ftun_buffer_slice_t remaining;
  size_t accepted = 0u;
  ftun_status_t status;
  if (adapter->operation != NULL) return FTUN_E_AGAIN;
  if (adapter->reply.owner == NULL) return FTUN_OK;
  if (adapter->reply_offset == adapter->reply.length) {
    status = ftun_buffer_slice_release(&adapter->reply);
    adapter->reply_offset = 0u;
    adapter->deadline = adapter->request_kind == FTUN_INBOUND_EVENT_NONE
      ? adapter->handshake_deadline : 0u;
    return status;
  }
  /* 仅借用描述符；write_ref 自行 clone 接纳前缀。 */
  remaining = adapter->reply;
  remaining.offset += adapter->reply_offset;
  remaining.length -= adapter->reply_offset;
  status = ftun_stream_write_ref_with_completion(adapter->client, &remaining,
    ftun_inbound_adapter_written, adapter, &accepted, &adapter->operation);
  if (status == FTUN_OK) adapter->reply_offset += accepted;
  return status == FTUN_OK || status == FTUN_E_LIMIT ? FTUN_E_AGAIN : status;
}

static ftun_status_t ftun_inbound_adapter_socks_event(ftun_inbound_adapter_t *adapter,
  const ftun_socks5_server_event_t *event, ftun_inbound_event_t *out)
{
  ftun_status_t status;
  if (event->kind != FTUN_SOCKS5_SERVER_REQUEST) {
    bool close_after = event->kind == FTUN_SOCKS5_SERVER_COMMAND_REPLY ||
      (event->wire.length >= 2u &&
       ((event->kind == FTUN_SOCKS5_SERVER_METHOD_REPLY && event->wire.data[1] == 0xffu) ||
        (event->kind == FTUN_SOCKS5_SERVER_AUTH_REPLY && event->wire.data[1] != 0u)));
    return ftun_inbound_adapter_reply(adapter, event->wire, close_after);
  }
  if (event->command != FTUN_SOCKS5_COMMAND_CONNECT &&
      event->command != FTUN_SOCKS5_COMMAND_UDP_ASSOCIATE) {
    if (adapter->socks != NULL) {
      ftun_socks5_server_event_t reply;
      status = ftun_socks5_server_finish_request(adapter->socks, FTUN_E_UNSUPPORTED, NULL, &reply);
      return status == FTUN_OK ? ftun_inbound_adapter_reply(adapter, reply.wire, true) : status;
    } else {
      ftun_mixed_event_t reply;
      status = ftun_mixed_socks5_finish_request(adapter->mixed, FTUN_E_UNSUPPORTED, NULL, &reply);
      return status == FTUN_OK ? ftun_inbound_adapter_reply(adapter, reply.socks5.wire, true) : status;
    }
  }
  status = ftun_inbound_adapter_copy(adapter, event->preread,
    (ftun_bytes_t){NULL, 0u}, &out->preread);
  if (status != FTUN_OK) return status;
  out->kind = event->command == FTUN_SOCKS5_COMMAND_CONNECT
    ? FTUN_INBOUND_EVENT_CONNECT : FTUN_INBOUND_EVENT_ASSOCIATE;
  out->target = event->target;
  adapter->request_kind = out->kind;
  adapter->deadline = 0u;
  return FTUN_OK;
}

static ftun_status_t ftun_inbound_adapter_feed(ftun_inbound_adapter_t *adapter,
  ftun_bytes_t bytes, ftun_inbound_event_t *out)
{
  size_t consumed = 0u;
  ftun_status_t status;
  if (adapter->socks != NULL) {
    ftun_socks5_server_event_t event;
    status = ftun_socks5_server_feed(adapter->socks, bytes, &consumed, &event);
    if (status == FTUN_OK) status = ftun_inbound_adapter_socks_event(adapter, &event, out);
  } else {
    ftun_mixed_event_t event;
    status = ftun_mixed_connection_feed(adapter->mixed, bytes, &consumed, &event);
    if (status == FTUN_OK && event.kind == FTUN_MIXED_EVENT_SOCKS5) {
      status = ftun_inbound_adapter_socks_event(adapter, &event.socks5, out);
    } else if (status == FTUN_OK && event.kind == FTUN_MIXED_EVENT_HTTP_REPLY) {
      status = ftun_inbound_adapter_reply(adapter, event.wire, true);
    } else if (status == FTUN_OK && event.kind == FTUN_MIXED_EVENT_HTTP_REQUEST) {
      adapter->http = true;
      adapter->forward = event.http.kind == FTUN_HTTP_PROXY_FORWARD;
      status = ftun_inbound_adapter_copy(adapter,
        adapter->forward ? event.wire : (ftun_bytes_t){NULL, 0u}, event.preread, &out->preread);
      if (status == FTUN_OK) {
        out->kind = FTUN_INBOUND_EVENT_CONNECT;
        out->target = event.http.target;
        adapter->request_kind = out->kind;
        adapter->deadline = 0u;
      }
    } else if (status == FTUN_OK) status = FTUN_E_STATE_CORRUPT;
  }
  if ((status == FTUN_OK || status == FTUN_E_AGAIN) && consumed != bytes.length) {
    (void)ftun_buffer_slice_release(&out->preread);
    memset(out, 0, sizeof(*out));
    return FTUN_E_STATE_CORRUPT;
  }
  return status;
}

ftun_status_t ftun_inbound_adapter_create(ftun_stream_t *client,
  const ftun_inbound_spec_t *spec, uint64_t handshake_deadline_ms,
  uint64_t reply_timeout_ms, void (*wakeup)(void *), void *user,
  ftun_inbound_adapter_t **out)
{
  return ftun_inbound_adapter_create_with_pool(client, spec, NULL,
    handshake_deadline_ms, reply_timeout_ms, wakeup, user, out);
}

ftun_status_t ftun_inbound_adapter_create_with_pool(ftun_stream_t *client,
  const ftun_inbound_spec_t *spec, ftun_buffer_pool_t *pool,
  uint64_t handshake_deadline_ms, uint64_t reply_timeout_ms,
  void (*wakeup)(void *), void *user, ftun_inbound_adapter_t **out)
{
  ftun_inbound_adapter_t *adapter;
  ftun_budget_t *budget = NULL;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  bool same_root = false;
  if (out != NULL) *out = NULL;
  if (client == NULL || spec == NULL || spec->budget == NULL || out == NULL ||
      handshake_deadline_ms == 0u || reply_timeout_ms == 0u ||
      (spec->kind != FTUN_INBOUND_SOCKS5 && spec->kind != FTUN_INBOUND_MIXED)) return FTUN_E_INVALID;
  status = ftun_stream_budget(client, &budget);
  if (status == FTUN_OK) status = ftun_budget_same_root(budget, spec->budget, &same_root);
  if (status != FTUN_OK) return status;
  if (!same_root) return FTUN_E_REJECTED;
  if (pool != NULL) {
    status = ftun_buffer_pool_budget(pool, &budget);
    if (status == FTUN_OK) status = ftun_budget_same_root(budget, spec->budget, &same_root);
    if (status != FTUN_OK) return status;
    if (!same_root) return FTUN_E_REJECTED;
  }
  status = ftun_budget_reserve(spec->budget, sizeof(*adapter), &reservation);
  if (status != FTUN_OK) return status;
  adapter = (ftun_inbound_adapter_t *)calloc(1u, sizeof(*adapter));
  if (adapter == NULL) { (void)ftun_reservation_release(&reservation); return FTUN_E_LIMIT; }
  adapter->reservation = reservation;
  adapter->budget = spec->budget;
  adapter->pool = pool;
  adapter->handshake_deadline = handshake_deadline_ms;
  adapter->deadline = handshake_deadline_ms;
  adapter->reply_timeout = reply_timeout_ms;
  adapter->wakeup = wakeup;
  adapter->user = user;
  status = spec->kind == FTUN_INBOUND_SOCKS5
    ? ftun_socks5_server_create(spec, &adapter->socks)
    : ftun_mixed_connection_create(spec, &adapter->mixed);
  if (status == FTUN_OK) status = ftun_stream_retain(client);
  if (status != FTUN_OK) {
    (void)ftun_socks5_server_destroy(&adapter->socks);
    (void)ftun_mixed_connection_destroy(&adapter->mixed);
    free(adapter);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  adapter->client = client;
  *out = adapter;
  return FTUN_OK;
}

ftun_status_t ftun_inbound_adapter_drive(ftun_inbound_adapter_t *adapter,
  bool readable, ftun_inbound_event_t *out)
{
  ftun_status_t status;
  uint64_t now;
  bool fed = false;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (adapter == NULL || out == NULL) return FTUN_E_INVALID;
  if (adapter->stopped) return FTUN_E_CANCELLED;
  if (adapter->busy) return FTUN_E_AGAIN;
  if (adapter->failure != FTUN_OK) return adapter->failure;
  if (adapter->deadline != 0u) {
    status = ftun_monotonic_now(&now);
    if (status != FTUN_OK) return status;
    if (now >= adapter->deadline) return FTUN_E_TIMEOUT;
  }
  adapter->busy = true;
  status = ftun_inbound_adapter_flush(adapter);
  if (status == FTUN_OK) {
    if (adapter->close_after) status = FTUN_E_EOF;
    else if (adapter->request_kind != FTUN_INBOUND_EVENT_NONE) status = FTUN_E_AGAIN;
    else {
      fed = true;
      /* 先消费上一轮已读入的后续帧，不能等待不存在的新 READ。 */
      status = ftun_inbound_adapter_feed(adapter, (ftun_bytes_t){NULL, 0u}, out);
      if (status == FTUN_E_AGAIN && readable) {
        uint8_t input[512];
        size_t length = 0u;
        status = ftun_stream_read(adapter->client, input, sizeof(input), &length);
        if (status == FTUN_OK) status = ftun_inbound_adapter_feed(adapter,
          (ftun_bytes_t){input, length}, out);
      }
    }
  }
  /* 新产生的回复在本次 drive 尝试一次接纳；完成仍由 Operation 派发。 */
  if (fed && (status == FTUN_OK || status == FTUN_E_AGAIN) &&
      adapter->reply.owner != NULL && adapter->operation == NULL) {
    ftun_status_t flushed = ftun_inbound_adapter_flush(adapter);
    if (flushed != FTUN_OK && flushed != FTUN_E_AGAIN) status = flushed;
  }
  adapter->busy = false;
  return status;
}

ftun_status_t ftun_inbound_adapter_finish(ftun_inbound_adapter_t *adapter,
  ftun_status_t downstream, const ftun_endpoint_t *bound)
{
  ftun_status_t status;
  if (adapter == NULL) return FTUN_E_INVALID;
  if (adapter->stopped) return FTUN_E_CANCELLED;
  if (adapter->busy) return FTUN_E_AGAIN;
  if (adapter->request_kind == FTUN_INBOUND_EVENT_NONE || adapter->finished) return FTUN_E_STALE;
  adapter->busy = true;
  if (adapter->socks != NULL) {
    ftun_socks5_server_event_t event;
    status = ftun_socks5_server_finish_request(adapter->socks, downstream, bound, &event);
    if (status == FTUN_OK) status = ftun_inbound_adapter_reply(adapter, event.wire, downstream != FTUN_OK);
  } else if (adapter->http) {
    if (adapter->forward) status = downstream;
    else {
      ftun_mixed_event_t event;
      status = ftun_mixed_http_finish(adapter->mixed, downstream, &event);
      if (status == FTUN_OK) status = ftun_inbound_adapter_reply(adapter, event.wire, downstream != FTUN_OK);
    }
  } else {
    ftun_mixed_event_t event;
    status = ftun_mixed_socks5_finish_request(adapter->mixed, downstream, bound, &event);
    if (status == FTUN_OK) status = ftun_inbound_adapter_reply(adapter, event.socks5.wire, downstream != FTUN_OK);
  }
  if (status == FTUN_OK) adapter->finished = true;
  adapter->busy = false;
  return status;
}

ftun_status_t ftun_inbound_adapter_udp(ftun_inbound_adapter_t *adapter,
  ftun_bytes_t packet, ftun_socks5_udp_datagram_t *out)
{
  if (adapter == NULL || out == NULL) return FTUN_E_INVALID;
  if (adapter->stopped) return FTUN_E_CANCELLED;
  return adapter->socks != NULL ? ftun_socks5_server_udp(adapter->socks, packet, out)
    : ftun_mixed_socks5_udp(adapter->mixed, packet, out);
}

ftun_status_t ftun_inbound_adapter_get_info(const ftun_inbound_adapter_t *adapter,
  ftun_inbound_adapter_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (adapter == NULL || out == NULL) return FTUN_E_INVALID;
  out->deadline_ms = adapter->deadline;
  out->reply_pending = adapter->reply.owner != NULL || adapter->operation != NULL;
  out->close_after_reply = adapter->close_after;
  out->waiting_downstream = adapter->request_kind != FTUN_INBOUND_EVENT_NONE && !adapter->finished;
  out->stopped = adapter->stopped;
  out->write_pending = adapter->operation != NULL;
  return FTUN_OK;
}

ftun_status_t ftun_inbound_adapter_stop(ftun_inbound_adapter_t *adapter)
{
  ftun_status_t status;
  if (adapter == NULL) return FTUN_E_INVALID;
  adapter->stopped = true;
  if (adapter->busy) return FTUN_E_AGAIN;
  status = adapter->operation == NULL ? FTUN_OK : ftun_operation_cancel(adapter->operation);
  return status == FTUN_E_STALE ? FTUN_OK : status;
}

ftun_status_t ftun_inbound_adapter_destroy(ftun_inbound_adapter_t **adapter)
{
  ftun_inbound_adapter_t *owned;
  ftun_status_t status;
  if (adapter == NULL) return FTUN_E_INVALID;
  owned = *adapter;
  if (owned == NULL) return FTUN_OK;
  if (!owned->stopped || owned->busy || owned->operation != NULL) return FTUN_E_AGAIN;
  status = ftun_stream_release(&owned->client);
  if (status != FTUN_OK) return status;
  status = ftun_buffer_slice_release(&owned->reply);
  if (status != FTUN_OK) return status;
  status = ftun_socks5_server_destroy(&owned->socks);
  if (status != FTUN_OK) return status;
  status = ftun_mixed_connection_destroy(&owned->mixed);
  if (status != FTUN_OK) return status;
  status = ftun_reservation_release(&owned->reservation);
  if (status != FTUN_OK) return status;
  free(owned);
  *adapter = NULL;
  return FTUN_OK;
}
