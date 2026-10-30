#define _GNU_SOURCE 1

#include "util/endpoint.h"
#include "dns/service_internal.h"

#if defined(FTUN_HAVE_MODULE_DNS)

ftun_status_t ftun_dns_runtime_listener_sources_start(
  ftun_dns_runtime_t *dns);

void ftun_dns_runtime_request_ready_enqueue(
  ftun_dns_runtime_transport_request_t *request)
{
  ftun_dns_runtime_t *dns;
  if (request == NULL || request->ready_queued) return;
  dns = request->dns;
  request->ready = true;
  request->ready_previous = dns->ready_request_tail;
  if (dns->ready_request_tail != NULL) {
    dns->ready_request_tail->ready_next = request;
  } else {
    dns->ready_request_head = request;
  }
  dns->ready_request_tail = request;
  request->ready_queued = true;
}

void ftun_dns_runtime_request_ready_remove(
  ftun_dns_runtime_transport_request_t *request)
{
  ftun_dns_runtime_t *dns;
  if (request == NULL || !request->ready_queued) {
    if (request != NULL) request->ready = false;
    return;
  }
  dns = request->dns;
  if (request->ready_previous != NULL) {
    request->ready_previous->ready_next = request->ready_next;
  } else {
    dns->ready_request_head = request->ready_next;
  }
  if (request->ready_next != NULL) {
    request->ready_next->ready_previous = request->ready_previous;
  } else {
    dns->ready_request_tail = request->ready_previous;
  }
  request->ready_previous = NULL;
  request->ready_next = NULL;
  request->ready = false;
  request->ready_queued = false;
}

int ftun_dns_runtime_waiter_before(
  const ftun_dns_runtime_transport_waiter_t *left,
  const ftun_dns_runtime_transport_waiter_t *right)
{
  return left->deadline_ms < right->deadline_ms;
}

void ftun_dns_runtime_waiter_heap_swap(ftun_dns_runtime_t *dns,
                                             size_t left, size_t right)
{
  ftun_dns_runtime_transport_waiter_t *waiter = dns->waiter_heap[left];
  dns->waiter_heap[left] = dns->waiter_heap[right];
  dns->waiter_heap[right] = waiter;
  dns->waiter_heap[left]->heap_index = left;
  dns->waiter_heap[right]->heap_index = right;
}

void ftun_dns_runtime_waiter_heap_push(
  ftun_dns_runtime_t *dns, ftun_dns_runtime_transport_waiter_t *waiter)
{
  size_t position = dns->waiter_count++;
  dns->waiter_heap[position] = waiter;
  waiter->heap_index = position;
  while (position != 0u) {
    size_t parent = (position - 1u) / 2u;
    if (!ftun_dns_runtime_waiter_before(waiter,
                                       dns->waiter_heap[parent])) break;
    ftun_dns_runtime_waiter_heap_swap(dns, position, parent);
    position = parent;
  }
}

void ftun_dns_runtime_waiter_heap_remove(
  ftun_dns_runtime_t *dns, ftun_dns_runtime_transport_waiter_t *waiter)
{
  size_t position = waiter->heap_index;
  ftun_dns_runtime_transport_waiter_t *replacement;
  if (position >= dns->waiter_count || dns->waiter_heap[position] != waiter) {
    return;
  }
  dns->waiter_count--;
  replacement = dns->waiter_heap[dns->waiter_count];
  dns->waiter_heap[dns->waiter_count] = NULL;
  waiter->heap_index = SIZE_MAX;
  if (position == dns->waiter_count) return;
  dns->waiter_heap[position] = replacement;
  replacement->heap_index = position;
  if (position != 0u && ftun_dns_runtime_waiter_before(replacement,
      dns->waiter_heap[(position - 1u) / 2u])) {
    while (position != 0u) {
      size_t parent = (position - 1u) / 2u;
      if (!ftun_dns_runtime_waiter_before(replacement,
                                         dns->waiter_heap[parent])) break;
      ftun_dns_runtime_waiter_heap_swap(dns, position, parent);
      position = parent;
    }
  } else {
    for (;;) {
      size_t left = position * 2u + 1u;
      size_t right = left + 1u;
      size_t smallest = position;
      if (left < dns->waiter_count &&
          ftun_dns_runtime_waiter_before(dns->waiter_heap[left],
                                        dns->waiter_heap[smallest])) {
        smallest = left;
      }
      if (right < dns->waiter_count &&
          ftun_dns_runtime_waiter_before(dns->waiter_heap[right],
                                        dns->waiter_heap[smallest])) {
        smallest = right;
      }
      if (smallest == position) break;
      ftun_dns_runtime_waiter_heap_swap(dns, position, smallest);
      position = smallest;
    }
  }
}

uint64_t ftun_dns_runtime_now(void *user)
{
  uint64_t now = 0u;
  (void)user;
  (void)ftun_monotonic_now(&now);
  return now;
}

/* server 校验响应时使用接收完成时刻；新查询和 fallback 仍检查真实期限。 */
uint64_t ftun_dns_runtime_response_now(void *user)
{
  ftun_dns_runtime_t *dns = user;
  return dns->delivering ? dns->delivery_now_ms : ftun_dns_runtime_now(NULL);
}

void ftun_dns_runtime_record(ftun_dns_runtime_t *dns,
                                   ftun_status_t status)
{
  if (dns != NULL && status != FTUN_OK && dns->pending_status == FTUN_OK) {
    dns->pending_status = status;
  }
}

void ftun_dns_runtime_listener_ready(ftun_event_source_t *source,
                                            uint32_t events, void *user)
{
  ftun_dns_runtime_listener_slot_t *slot =
    (ftun_dns_runtime_listener_slot_t *)user;
  if (slot != NULL && slot->source == source) slot->events |= events;
}

void ftun_dns_runtime_listener_tcp_ready(ftun_event_source_t *source,
                                                uint32_t events, void *user)
{
  ftun_dns_runtime_listener_slot_t *slot =
    (ftun_dns_runtime_listener_slot_t *)user;
  if (slot != NULL && slot->tcp_source == source) slot->tcp_events |= events;
}

void ftun_dns_runtime_tcp_set_ready(ftun_dns_runtime_tcp_t *connection,
                                            bool ready)
{
  ftun_dns_runtime_t *dns = connection->dns;
  size_t index;
  if (dns == NULL) return;
  index = (size_t)(connection - dns->tcp);
  if (ready) dns->tcp_ready_mask |= UINT64_C(1) << index;
  else dns->tcp_ready_mask &= ~(UINT64_C(1) << index);
}

size_t ftun_dns_runtime_tcp_next_ready(const ftun_dns_runtime_t *dns)
{
  uint64_t mask = dns->tcp_ready_mask & (UINT64_MAX << dns->tcp_cursor);
  if (mask == 0u) mask = dns->tcp_ready_mask;
  if (mask == 0u) return SIZE_MAX;
#if defined(__GNUC__) || defined(__clang__)
  return (size_t)__builtin_ctzll(mask);
#else
  {
    size_t index = 0u;
    while ((mask & UINT64_C(1)) == 0u) { mask >>= 1u; index++; }
    return index;
  }
#endif
}

void ftun_dns_runtime_tcp_ready(ftun_event_source_t *source,
                                       uint32_t events, void *user)
{
  ftun_dns_runtime_tcp_t *connection = (ftun_dns_runtime_tcp_t *)user;
  if (connection != NULL && connection->source == source &&
      connection->active) {
    connection->events |= events;
    ftun_dns_runtime_tcp_set_ready(connection, true);
  }
}

ftun_status_t ftun_dns_runtime_tcp_source_update(
  ftun_dns_runtime_tcp_t *connection)
{
  uint32_t interests = FTUN_EVENT_ERROR;
  if (connection == NULL || !connection->active) {
    return FTUN_E_INVALID;
  }
  if (connection->transport_failed ||
      (connection->peer_eof && connection->response_head == NULL)) {
    return ftun_event_source_cancel(&connection->source);
  }
  if (!connection->peer_eof) interests |= FTUN_EVENT_READ;
  if (connection->response_head != NULL) interests |= FTUN_EVENT_WRITE;
  if (connection->source == NULL) {
    return ftun_event_io_start(connection->dns->loop,
      (ftun_native_socket_t)connection->descriptor, interests,
      ftun_dns_runtime_tcp_ready, connection, &connection->source);
  }
  return ftun_event_io_update(connection->source, interests);
}

uint64_t ftun_dns_runtime_hash_bytes(uint64_t hash, const void *data,
                                           size_t length)
{
  const uint8_t *bytes = (const uint8_t *)data;
  size_t index;
  for (index = 0u; index < length; index++) {
    hash ^= bytes[index];
    hash *= UINT64_C(1099511628211);
  }
  return hash;
}

uint64_t ftun_dns_runtime_request_hash(
  uint32_t outbound_id, uint64_t policy_fingerprint,
  uint64_t server_fingerprint, const ftun_endpoint_t *upstream,
  ftun_dns_transport_t transport, ftun_egress_id_t egress_id,
  ftun_bytes_t query)
{
  uint64_t hash = UINT64_C(1469598103934665603);
  uint8_t transport_byte = (uint8_t)transport;
  hash = ftun_dns_runtime_hash_bytes(hash, &outbound_id,
                                    sizeof(outbound_id));
  hash = ftun_dns_runtime_hash_bytes(hash, &policy_fingerprint,
                                    sizeof(policy_fingerprint));
  hash = ftun_dns_runtime_hash_bytes(hash, &server_fingerprint,
                                    sizeof(server_fingerprint));
  hash = ftun_dns_runtime_hash_bytes(hash, &transport_byte,
                                    sizeof(transport_byte));
  hash = ftun_dns_runtime_hash_bytes(hash, &egress_id, sizeof(egress_id));
  hash = ftun_dns_runtime_hash_bytes(hash, &upstream->kind,
                                    sizeof(upstream->kind));
  hash = ftun_dns_runtime_hash_bytes(hash, &upstream->port,
                                    sizeof(upstream->port));
  hash = ftun_dns_runtime_hash_bytes(hash, upstream->address, ftun_endpoint_address_bytes(upstream));
  hash = ftun_dns_runtime_hash_bytes(hash, &query.length,
                                    sizeof(query.length));
  return ftun_dns_runtime_hash_bytes(hash, query.data + 2u,
                                    query.length - 2u);
}

void ftun_dns_runtime_request_index_insert(
  ftun_dns_runtime_transport_request_t *request)
{
  ftun_dns_runtime_t *dns = request->dns;
  size_t bucket = (size_t)request->identity_hash &
                  (FTUN_DNS_RUNTIME_REQUEST_BUCKETS - 1u);
  request->hash_next = dns->request_buckets[bucket];
  if (request->hash_next != NULL) request->hash_next->hash_previous = request;
  dns->request_buckets[bucket] = request;
  request->indexed = true;
}

void ftun_dns_runtime_request_index_remove(
  ftun_dns_runtime_transport_request_t *request)
{
  ftun_dns_runtime_t *dns;
  size_t bucket;
  if (!request->indexed) return;
  dns = request->dns;
  bucket = (size_t)request->identity_hash &
           (FTUN_DNS_RUNTIME_REQUEST_BUCKETS - 1u);
  if (request->hash_previous != NULL) {
    request->hash_previous->hash_next = request->hash_next;
  } else {
    dns->request_buckets[bucket] = request->hash_next;
  }
  if (request->hash_next != NULL) {
    request->hash_next->hash_previous = request->hash_previous;
  }
  request->hash_previous = NULL;
  request->hash_next = NULL;
  request->indexed = false;
}

void ftun_dns_runtime_request_unlink(
  ftun_dns_runtime_transport_request_t *request)
{
  ftun_dns_runtime_t *dns = request->dns;
  ftun_dns_runtime_request_ready_remove(request);
  ftun_dns_runtime_request_index_remove(request);
  if (request->previous != NULL) request->previous->next = request->next;
  else dns->request_head = request->next;
  if (request->next != NULL) request->next->previous = request->previous;
  else dns->request_tail = request->previous;
  request->previous = NULL;
  request->next = NULL;
  if (dns->request_count != 0u) dns->request_count--;
}

/* 完成查询不等于通道静默；请求保留在运行时链表，直到迟到回调全部返回。 */
ftun_status_t ftun_dns_runtime_request_path_close(ftun_path_t **path)
{
  ftun_status_t status;
  if (*path == NULL) return FTUN_OK;
  status = ftun_path_revoke(*path);
  if (status == FTUN_OK) status = ftun_path_destroy(path);
  return status;
}

void ftun_dns_runtime_request_release(
  ftun_dns_runtime_transport_request_t *request)
{
  ftun_reservation_t reservation;
  ftun_status_t status = FTUN_OK;
  ftun_status_t control_status;
  ftun_path_provider_info_t paths;
  ftun_dns_runtime_transport_request_t *parent;
  if (request == NULL) return;
  request->closing = true;
  parent = request->fallback_parent;
  if (request->waiter_head != NULL || request->completion_depth != 0u ||
      request->fallback_children != 0u || (parent != NULL &&
       (parent->waiter_head != NULL || parent->completion_depth != 0u))) {
    ftun_dns_runtime_request_ready_enqueue(request);
    return;
  }
  ftun_dns_runtime_request_index_remove(request);
  if (request->opening != NULL) {
    status = ftun_operation_cancel(request->opening);
    if (status == FTUN_OK) status = FTUN_E_AGAIN;
  }
  control_status = ftun_dns_runtime_request_path_close(&request->path);
  if (status == FTUN_OK) status = control_status;
  /* 被 Provider 拒收的工厂结果仍可能借用 notify_user，须先完成其回收。 */
  control_status = ftun_path_provider_collect(request->dns->paths);
  if (status == FTUN_OK) status = control_status;
  control_status = ftun_path_provider_get_info(request->dns->paths, &paths);
  if (status == FTUN_OK) status = control_status;
  if (status == FTUN_OK && paths.retired != 0u) status = FTUN_E_AGAIN;
  if (status != FTUN_OK || request->write_pending) {
    if (status != FTUN_OK && status != FTUN_E_AGAIN) {
      ftun_dns_runtime_record(request->dns, status);
    }
    ftun_dns_runtime_request_ready_enqueue(request);
    return;
  }
  ftun_dns_runtime_request_unlink(request);
  if (request->received_present) ftun_packet_release(&request->received);
  reservation = request->reservation;
  memset(request, 0, sizeof(*request));
  free(request);
  ftun_reservation_release(&reservation);
  if (parent != NULL) {
    parent->fallback_children--;
    ftun_dns_runtime_request_release(parent);
  }
}

void ftun_dns_runtime_waiter_unlink(
  ftun_dns_runtime_transport_waiter_t *waiter)
{
  ftun_dns_runtime_transport_request_t *request = waiter->request;
  ftun_dns_runtime_waiter_heap_remove(request->dns, waiter);
  if (waiter->previous != NULL) waiter->previous->next = waiter->next;
  else request->waiter_head = waiter->next;
  if (waiter->next != NULL) waiter->next->previous = waiter->previous;
  else request->waiter_tail = waiter->previous;
  waiter->previous = NULL;
  waiter->next = NULL;
  waiter->request = NULL;
}

void ftun_dns_runtime_waiter_release(
  ftun_dns_runtime_transport_waiter_t *waiter)
{
  ftun_reservation_t reservation = waiter->reservation;
  memset(waiter, 0, sizeof(*waiter));
  free(waiter);
  ftun_reservation_release(&reservation);
}

void ftun_dns_runtime_waiter_finish(
  ftun_dns_runtime_transport_waiter_t *waiter, ftun_status_t status,
  ftun_bytes_t response)
{
  ftun_dns_runtime_transport_request_t *request = waiter->request;
  ftun_dns_transport_completion_fn completion = waiter->completion;
  void *completion_user = waiter->completion_user;
  ftun_endpoint_t upstream = request->upstream;
  ftun_dns_transport_t transport = request->transport;
  ftun_dns_runtime_t *dns = request->dns;
  uint64_t previous_time = dns->delivery_now_ms;
  bool previous_delivery = dns->delivering;
  ftun_dns_runtime_transport_request_t *previous_request = dns->delivering_request;
  request->completion_depth++;
  ftun_dns_runtime_waiter_unlink(waiter);
  dns->delivery_now_ms = request->closing ? request->completed_ms :
    ftun_dns_runtime_now(NULL);
  dns->delivering = true;
  dns->delivering_request = request;
  completion(completion_user, status, transport, &upstream, response);
  dns->delivering = previous_delivery;
  dns->delivery_now_ms = previous_time;
  dns->delivering_request = previous_request;
  request->completion_depth--;
  ftun_dns_runtime_waiter_release(waiter);
}

void ftun_dns_runtime_request_finish(
  ftun_dns_runtime_transport_request_t *request, ftun_status_t status)
{
  request->closing = true;
  request->completion_status = status;
  request->completed_ms = ftun_dns_runtime_now(NULL);
  /* 同一 UDP 合并批次尚未交付完时，保留其 TCP fallback 的合并窗口。 */
  if (request->fallback_parent == NULL) ftun_dns_runtime_request_index_remove(request);
}

/* 每个调度单元至多交付一个 waiter，响应和请求保留到最后一个回调返回。 */
void ftun_dns_runtime_request_complete_one(
  ftun_dns_runtime_transport_request_t *request)
{
  ftun_dns_runtime_transport_waiter_t *waiter = request->waiter_head;
  if (waiter != NULL) {
    ftun_status_t status = request->completion_status;
    ftun_bytes_t response = {NULL, 0u};
    if (status == FTUN_OK && waiter->deadline_ms <= request->completed_ms) {
      status = FTUN_E_TIMEOUT;
    }
    if (status == FTUN_OK) {
      request->buffer[0] = (uint8_t)(waiter->query_id >> 8u);
      request->buffer[1] = (uint8_t)waiter->query_id;
      response.data = request->buffer;
      response.length = request->response_length;
    }
    ftun_dns_runtime_waiter_finish(waiter, status, response);
  }
  if (request->waiter_head == NULL) ftun_dns_runtime_request_release(request);
  else ftun_dns_runtime_request_ready_enqueue(request);
}

void ftun_dns_runtime_path_notify(ftun_path_t *path, uint32_t events,
  ftun_error_t error, void *user)
{
  ftun_dns_runtime_transport_request_t *request = user;
  (void)path;
  if ((events & FTUN_PATH_ERROR) != 0u && request->io_status == FTUN_OK) {
    request->io_status = error.status == FTUN_OK ? FTUN_E_IO : error.status;
  }
  ftun_dns_runtime_request_ready_enqueue(request);
}

void ftun_dns_runtime_write_done(ftun_operation_t *operation,
  ftun_error_t error, void *user)
{
  ftun_dns_runtime_transport_request_t *request = user;
  (void)operation;
  request->writing = NULL;
  request->write_pending = false;
  if (error.status == FTUN_OK) request->buffer_offset += request->writing_bytes;
  else request->io_status = error.status;
  request->writing_bytes = 0u;
  ftun_dns_runtime_request_ready_enqueue(request);
}

void ftun_dns_runtime_packet_done(ftun_datagram_t *channel,
  ftun_error_t error, const ftun_endpoint_t *target,
  const ftun_packet_t *packet, void *user)
{
  (void)channel; (void)target; (void)packet;
  ftun_dns_runtime_write_done(NULL, error, user);
}

ftun_status_t ftun_dns_runtime_packet_receive(ftun_datagram_t *channel,
  const ftun_endpoint_t *source, const ftun_packet_t *packet, void *user)
{
  ftun_dns_runtime_transport_request_t *request = user;
  ftun_status_t status;
  (void)channel;
  if (request->closing || request->received_present) return FTUN_OK;
  if (!ftun_endpoint_equal(source, &request->peer)) return FTUN_OK;
  status = ftun_packet_clone(packet, &request->received);
  if (status == FTUN_OK) request->received_present = true;
  else request->io_status = status;
  ftun_dns_runtime_request_ready_enqueue(request);
  return FTUN_OK;
}

void ftun_dns_runtime_path_opened(ftun_operation_t *operation,
  ftun_error_t error, ftun_path_t *path, void *user)
{
  ftun_dns_runtime_transport_request_t *request = user;
  (void)operation;
  request->opening = NULL;
  request->path = path;
  if (error.status != FTUN_OK) request->io_status = error.status;
  else if (request->io_status != FTUN_OK) {
    /* 保留在结果交付前到达的驱动错误，拥有权仍由请求负责回收。 */
  } else if (request->transport == FTUN_DNS_TRANSPORT_TCP) {
    request->io_status = ftun_path_channel(path, &request->stream);
  } else {
    request->io_status = ftun_path_channel(path, &request->datagram);
  }
  ftun_dns_runtime_request_ready_enqueue(request);
}

ftun_status_t ftun_dns_runtime_request_open(
  ftun_dns_runtime_transport_request_t *request)
{
  ftun_dns_runtime_t *dns = request->dns;
  ftun_path_open_request_t open = {0};
  const ftun_endpoint_t *target = &request->upstream;
  if (target == NULL || !ftun_endpoint_is_ip(target) || target->port == 0u) {
    return FTUN_E_INVALID;
  }
  request->peer = *target;
  request->state = FTUN_DNS_RUNTIME_REQUEST_CONNECT;
  open.dial.loop = dns->loop;
  open.dial.operations = dns->operations;
  open.dial.budget = dns->budget;
  open.dial.endpoint = *target;
  open.dial.allowed = target;
  open.dial.allowed_count = 1u;
  open.dial.requested_domain = FTUN_DIAL_DOMAIN_UNDERLAY;
  open.dial.protection.mark = dns->socket_mark;
  open.dial.protection.liveness = dns->liveness;
  open.dial.deadline_ms = request->deadline_ms;
  open.dial.transport = request->transport == FTUN_DNS_TRANSPORT_TCP ? FTUN_DIAL_TCP : FTUN_DIAL_UDP;
  open.egress = request->egress_id;
  open.dial.purpose = FTUN_DIAL_PURPOSE_DNS;
  open.stream.budget = dns->budget;
  open.stream.operations = dns->operations;
  open.stream.max_pending_writes = 1u;
  open.stream.max_pending_bytes = FTUN_DNS_RUNTIME_TRANSPORT_BUFFER_BYTES;
  open.stream.completion = ftun_dns_runtime_write_done;
  open.stream.completion_user = request;
  open.datagram.budget = dns->budget;
  open.datagram.max_pending_packets = 1u;
  open.datagram.max_pending_bytes = FTUN_DNS_RUNTIME_TRANSPORT_BUFFER_BYTES;
  open.datagram.result = ftun_dns_runtime_packet_done;
  open.datagram.receive = ftun_dns_runtime_packet_receive;
  open.datagram.user = request;
  open.completion = ftun_dns_runtime_path_opened;
  open.user = request;
  open.notify = ftun_dns_runtime_path_notify;
  open.notify_user = request;
  return ftun_path_provider_open_channel(dns->paths, dns->core,
    dns->generation, &open, &request->opening);
}

ftun_status_t ftun_dns_runtime_request_connected(
  ftun_dns_runtime_transport_request_t *request, bool *connected)
{
  *connected = false;
  if (request->opening != NULL) return FTUN_E_AGAIN;
  if (request->io_status != FTUN_OK) return request->io_status;
  *connected = true;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_request_send(
  ftun_dns_runtime_transport_request_t *request)
{
  ftun_buffer_t *buffer = NULL;
  ftun_buffer_slice_t slice = {0};
  ftun_packet_t packet = {0};
  uint8_t *data;
  size_t capacity;
  size_t accepted = 0u;
  size_t length = request->buffer_length - request->buffer_offset;
  ftun_status_t status;
  if (request->io_status != FTUN_OK) return request->io_status;
  if (request->write_pending) return FTUN_E_AGAIN;
  if (length == 0u) return FTUN_OK;
  status = ftun_buffer_acquire(request->dns->budget, length, &buffer);
  if (status == FTUN_OK) status = ftun_buffer_data(buffer, &data, &capacity);
  if (status == FTUN_OK) {
    memcpy(data, request->buffer + request->buffer_offset, length);
    status = ftun_buffer_slice(buffer, 0u, length, &slice);
  }
  if (status == FTUN_OK) {
    request->write_pending = true;
    if (request->datagram != NULL) {
      status = ftun_packet_init(&packet, &slice, 0u);
      request->writing_bytes = length;
      if (status == FTUN_OK) status = ftun_channel_send(request->datagram,
        &request->peer, &packet);
    } else {
      status = ftun_channel_write_ref(request->stream, &slice, &accepted,
        &request->writing);
      request->writing_bytes = accepted;
    }
    if (status != FTUN_OK) {
      request->write_pending = false;
      request->writing_bytes = 0u;
    }
  }
  ftun_packet_release(&packet);
  ftun_buffer_slice_release(&slice);
  ftun_buffer_release(&buffer);
  if (status != FTUN_OK) return status;
  if (request->write_pending) return FTUN_E_AGAIN;
  return request->io_status;
}

ftun_status_t ftun_dns_runtime_request_receive(
  ftun_dns_runtime_transport_request_t *request, size_t needed)
{
  size_t received = 0u;
  ftun_status_t status;
  if (request->buffer_length >= needed) return FTUN_OK;
  status = ftun_channel_read(request->stream,
    request->buffer + request->buffer_length,
    needed - request->buffer_length, &received);
  if (status != FTUN_OK) return status;
  request->buffer_length += received;
  if (request->buffer_length == needed) return FTUN_OK;
  ftun_dns_runtime_request_ready_enqueue(request);
  return FTUN_E_AGAIN;
}

/* 握手状态机的下一步：有待发送的帧就编码进请求缓冲等待发送，否则等待回复。 */


ftun_status_t ftun_dns_runtime_request_dns_send(
  ftun_dns_runtime_transport_request_t *request)
{
  request->buffer_offset = 0u;
  request->buffer_length = 0u;
  if (request->transport == FTUN_DNS_TRANSPORT_TCP) {
    if (request->query_length > UINT16_MAX) return FTUN_E_LIMIT;
    request->buffer[0] = (uint8_t)(request->query_length >> 8u);
    request->buffer[1] = (uint8_t)request->query_length;
    memcpy(request->buffer + 2u, request->query, request->query_length);
    request->buffer_length = request->query_length + 2u;
  } else {
    memcpy(request->buffer, request->query, request->query_length);
    request->buffer_length = request->query_length;
  }
  request->state = FTUN_DNS_RUNTIME_REQUEST_DNS_SEND;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_resolve_upstream(
  ftun_budget_t *budget, const ftun_config_t *config, const char *text, uint32_t socket_mark,
  ftun_endpoint_t *out);

/* 仅解释已固定的终端；此处绝不再次调用活动 Runtime 的组选择。 */


ftun_status_t ftun_dns_runtime_transport_select(void *user,
  uint32_t root, ftun_dns_transport_binding_t *out)
{
  ftun_dns_runtime_t *dns = user;
  ftun_egress_info_t info;
  ftun_status_t status;
  memset(out, 0, sizeof(*out));
  status = dns->egress->query(dns->egress->context, root, dns->generation, &info);
  if (status != FTUN_OK) return status;
  if (info.state == FTUN_EGRESS_STATE_UNAVAILABLE) return FTUN_E_REJECTED;
  *out = (ftun_dns_transport_binding_t){dns, root, info.id};
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_binding_validate(
  ftun_dns_runtime_t *dns, const ftun_dns_transport_binding_t *binding)
{
  if (binding == NULL || binding->scope != dns) return FTUN_E_STALE;
  return dns->egress->validate(dns->egress->context, binding->root_id,
    binding->leaf_id, dns->generation);
}

ftun_status_t ftun_dns_runtime_request_drive_connected(ftun_dns_runtime_transport_request_t *request)
{
  bool connected = false;
  ftun_status_t status = ftun_dns_runtime_request_connected(request, &connected);
  return status != FTUN_OK || !connected ? status : ftun_dns_runtime_request_dns_send(request);
}

ftun_status_t ftun_dns_runtime_request_drive(
  ftun_dns_runtime_transport_request_t *request)
{
  size_t steps;
  for (steps = 0u; steps < 16u; steps++) {
    ftun_status_t status;
    if (request->io_status != FTUN_OK) return request->io_status;
    if (ftun_dns_runtime_now(NULL) >= request->deadline_ms) {
      return FTUN_E_TIMEOUT;
    }
    switch (request->state) {
      case FTUN_DNS_RUNTIME_REQUEST_CONNECT:
        status = ftun_dns_runtime_request_drive_connected(request);
        break;
      case FTUN_DNS_RUNTIME_REQUEST_DNS_SEND:
        status = ftun_dns_runtime_request_send(request);
        if (status == FTUN_OK) {
          request->buffer_length = 0u;
          request->buffer_offset = 0u;
          request->state = request->transport == FTUN_DNS_TRANSPORT_UDP
            ? FTUN_DNS_RUNTIME_REQUEST_DNS_RECV_UDP
            : FTUN_DNS_RUNTIME_REQUEST_DNS_RECV_PREFIX;
        }
        break;
      case FTUN_DNS_RUNTIME_REQUEST_DNS_RECV_UDP:
      {
        ftun_bytes_t wire;
        if (!request->received_present) return FTUN_E_AGAIN;
        status = ftun_packet_view(&request->received, &wire);
        if (status != FTUN_OK) return status;
        if (wire.length > FTUN_DNS_RUNTIME_TRANSPORT_BUFFER_BYTES) return FTUN_E_LIMIT;
        if (wire.length == 0u) return FTUN_E_EOF;
        /* 事务 ID 必须与发出的查询一致：对不上的数据报丢弃，继续等正确的应答
         * （交付给等待者之前会按各自的 ID 回填，所以这里是唯一的校验点）。 */
        if (wire.length >= 2u &&
            (wire.data[0] != request->query[0] || wire.data[1] != request->query[1])) {
          ftun_packet_release(&request->received);
          request->received_present = false;
          return FTUN_E_AGAIN;
        }
        memcpy(request->buffer, wire.data, wire.length);
        request->response_length = wire.length;
        return FTUN_OK;
      }
      case FTUN_DNS_RUNTIME_REQUEST_DNS_RECV_PREFIX:
        status = ftun_dns_runtime_request_receive(request, 2u);
        if (status == FTUN_OK) {
          request->receive_needed = ((size_t)request->buffer[0] << 8u) |
                                    request->buffer[1];
          if (request->receive_needed == 0u ||
              request->receive_needed > FTUN_DNS_MAX_MESSAGE_BYTES) {
            return FTUN_E_LIMIT;
          }
          request->buffer_length = 0u;
          request->state = FTUN_DNS_RUNTIME_REQUEST_DNS_RECV_BODY;
        }
        break;
      case FTUN_DNS_RUNTIME_REQUEST_DNS_RECV_BODY:
        status = ftun_dns_runtime_request_receive(request,
                                                 request->receive_needed);
        if (status == FTUN_OK) {
          /* TCP 流无法跳过一条应答：事务 ID 对不上按协议错误处理。 */
          if (request->buffer[0] != request->query[0] ||
              request->buffer[1] != request->query[1]) return FTUN_E_PROTOCOL;
          request->response_length = request->receive_needed;
          return FTUN_OK;
        }
        break;
      default:
        return FTUN_E_STATE_CORRUPT;
    }
    if (status == FTUN_E_AGAIN) return status;
    if (status != FTUN_OK) return status;
  }
  ftun_dns_runtime_request_ready_enqueue(request);
  return FTUN_E_AGAIN;
}

int ftun_dns_runtime_request_matches(
  const ftun_dns_runtime_transport_request_t *request,
  uint32_t outbound_id, uint64_t policy_fingerprint,
  uint64_t server_fingerprint, const ftun_endpoint_t *upstream,
  ftun_dns_transport_t transport, ftun_egress_id_t egress_id, ftun_bytes_t query)
{
  return request->outbound_id == outbound_id &&
    request->policy_fingerprint == policy_fingerprint &&
    request->server_fingerprint == server_fingerprint &&
    request->transport == transport && request->egress_id == egress_id &&
    request->upstream.kind == upstream->kind &&
    request->upstream.port == upstream->port &&
    ftun_endpoint_equal(&request->upstream, upstream) &&
    request->query_length == query.length && query.length >= 2u &&
    memcmp(request->query + 2u, query.data + 2u, query.length - 2u) == 0;
}

ftun_status_t ftun_dns_runtime_waiter_create(
  ftun_dns_runtime_t *dns, ftun_dns_runtime_transport_request_t *request,
  ftun_bytes_t query, uint64_t deadline_ms,
  ftun_dns_transport_completion_fn completion, void *completion_user,
  ftun_dns_runtime_transport_waiter_t **out)
{
  ftun_dns_runtime_transport_waiter_t *waiter;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (dns->waiter_count >= FTUN_DNS_RUNTIME_MAX_WAITERS) return FTUN_E_LIMIT;
  status = ftun_budget_reserve(dns->budget, sizeof(*waiter), &reservation);
  if (status != FTUN_OK) return status;
  waiter = (ftun_dns_runtime_transport_waiter_t *)calloc(1u,
                                                        sizeof(*waiter));
  if (waiter == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  waiter->request = request;
  waiter->reservation = reservation;
  waiter->completion = completion;
  waiter->completion_user = completion_user;
  waiter->deadline_ms = deadline_ms;
  waiter->heap_index = SIZE_MAX;
  waiter->query_id = (uint16_t)(((uint16_t)query.data[0] << 8u) |
                                query.data[1]);
  waiter->previous = request->waiter_tail;
  if (request->waiter_tail != NULL) request->waiter_tail->next = waiter;
  else request->waiter_head = waiter;
  request->waiter_tail = waiter;
  if (deadline_ms > request->deadline_ms) request->deadline_ms = deadline_ms;
  ftun_dns_runtime_waiter_heap_push(dns, waiter);
  *out = waiter;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_transport_submit(
  void *user, const ftun_dns_transport_binding_t *binding,
  uint64_t policy_fingerprint,
  uint64_t server_fingerprint, const ftun_endpoint_t *upstream,
  ftun_dns_transport_t transport, ftun_bytes_t query, uint64_t deadline_ms,
  ftun_dns_transport_completion_fn completion, void *completion_user,
  void **out_request)
{
  ftun_dns_runtime_t *dns = (ftun_dns_runtime_t *)user;
  ftun_dns_runtime_transport_request_t *request;
  ftun_dns_runtime_transport_request_t *parent;
  ftun_dns_runtime_transport_waiter_t *waiter = NULL;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  size_t bytes;
  uint64_t identity_hash;
  uint32_t outbound_id;
  ftun_status_t status;
  if (out_request != NULL) *out_request = NULL;
  if (dns == NULL || upstream == NULL || !ftun_endpoint_is_ip(upstream) ||
      query.data == NULL || query.length < 12u || query.length > UINT32_MAX ||
      completion == NULL || out_request == NULL || deadline_ms == 0u) {
    return FTUN_E_INVALID;
  }
  if (ftun_dns_runtime_now(NULL) >= deadline_ms) return FTUN_E_TIMEOUT;
  status = ftun_dns_runtime_binding_validate(dns, binding);
  if (status != FTUN_OK) return status;
  outbound_id = binding->root_id;
  if (query.length > SIZE_MAX - sizeof(*request) - FTUN_DNS_RUNTIME_TRANSPORT_BUFFER_BYTES) return FTUN_E_LIMIT;
  identity_hash = ftun_dns_runtime_request_hash(outbound_id,
    policy_fingerprint, server_fingerprint, upstream, transport, binding->leaf_id, query);
  parent = dns->delivering_request;
  if (transport != FTUN_DNS_TRANSPORT_TCP || parent == NULL ||
      !parent->closing || parent->completion_status != FTUN_OK ||
      parent->response_length < 3u || (parent->buffer[2] & 0x02u) == 0u ||
      !ftun_dns_runtime_request_matches(parent, outbound_id,
        policy_fingerprint, server_fingerprint, upstream,
        FTUN_DNS_TRANSPORT_UDP, binding->leaf_id, query)) {
    parent = NULL;
  }
  for (request = dns->request_buckets[(size_t)identity_hash &
       (FTUN_DNS_RUNTIME_REQUEST_BUCKETS - 1u)]; request != NULL;
       request = request->hash_next) {
    if ((request->closing && (parent == NULL || request->fallback_parent != parent)) ||
        request->identity_hash != identity_hash ||
        !ftun_dns_runtime_request_matches(request, outbound_id,
                                         policy_fingerprint,
                                         server_fingerprint, upstream,
                                         transport, binding->leaf_id, query)) {
      continue;
    }
    status = ftun_dns_runtime_waiter_create(dns, request, query, deadline_ms,
      completion, completion_user, &waiter);
    if (status == FTUN_OK) {
      if (parent != NULL && request->fallback_parent == NULL) {
        request->fallback_parent = parent;
        parent->fallback_children++;
      }
      *out_request = waiter;
    }
    return status;
  }
  if (dns->request_count >= FTUN_DNS_RUNTIME_MAX_PENDING) return FTUN_E_LIMIT;
  bytes = sizeof(*request) + query.length +
          FTUN_DNS_RUNTIME_TRANSPORT_BUFFER_BYTES;
  status = ftun_budget_reserve(dns->budget, bytes, &reservation);
  if (status != FTUN_OK) return status;
  request = (ftun_dns_runtime_transport_request_t *)calloc(1u, bytes);
  if (request == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  request->dns = dns;
  request->reservation = reservation;
  request->upstream = *upstream;
  request->deadline_ms = deadline_ms;
  request->query = (uint8_t *)(request + 1);
  request->buffer = request->query + query.length;
  request->query_length = query.length;
  request->identity_hash = identity_hash;
  request->policy_fingerprint = policy_fingerprint;
  request->server_fingerprint = server_fingerprint;
  request->outbound_id = outbound_id;
  request->transport = transport;
  request->egress_id = binding->leaf_id;
  memcpy(request->query, query.data, query.length);
  request->previous = dns->request_tail;
  if (dns->request_tail != NULL) dns->request_tail->next = request;
  else dns->request_head = request;
  dns->request_tail = request;
  dns->request_count++;
  status = ftun_dns_runtime_request_open(request);
  if (status != FTUN_OK) {
    ftun_dns_runtime_request_release(request);
    return status;
  }
  status = ftun_dns_runtime_waiter_create(dns, request, query, deadline_ms,
    completion, completion_user, &waiter);
  if (status != FTUN_OK) {
    ftun_dns_runtime_request_release(request);
    return status;
  }
  ftun_dns_runtime_request_index_insert(request);
  if (parent != NULL) {
    request->fallback_parent = parent;
    parent->fallback_children++;
  }
  ftun_dns_runtime_request_ready_enqueue(request);
  *out_request = waiter;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_transport_cancel(void *user,
                                                       void **request_ptr)
{
  ftun_dns_runtime_t *dns = (ftun_dns_runtime_t *)user;
  ftun_dns_runtime_transport_waiter_t *waiter;
  ftun_dns_runtime_transport_request_t *request;
  if (dns == NULL || request_ptr == NULL || *request_ptr == NULL) {
    return FTUN_E_INVALID;
  }
  waiter = (ftun_dns_runtime_transport_waiter_t *)*request_ptr;
  request = waiter->request;
  if (request == NULL || request->dns != dns) return FTUN_E_STALE;
  ftun_dns_runtime_waiter_unlink(waiter);
  ftun_dns_runtime_waiter_release(waiter);
  if (request->waiter_head == NULL) {
    ftun_dns_runtime_request_release(request);
  }
  *request_ptr = NULL;
  return FTUN_OK;
}


#else

struct ftun_dns_runtime { int unused; };
struct ftun_dns_runtime_plan { int unused; };

ftun_status_t ftun_dns_runtime_prepare(
  ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations, ftun_event_loop_t *loop,
  const ftun_config_t *config, const ftun_dns_runtime_adapter_t *adapter,
  const ftun_dns_runtime_network_t *network,
  ftun_dns_runtime_t **out)
{
  (void)core; (void)budget; (void)operations; (void)loop;
  (void)adapter; (void)network;
  if (out != NULL) *out = NULL;
  if (config == NULL || out == NULL) return FTUN_E_INVALID;
  return ftun_config_dns(config)->enable ? FTUN_E_UNSUPPORTED : FTUN_OK;
}
ftun_status_t ftun_dns_runtime_prepare_reload(
  const ftun_dns_runtime_t *active, ftun_core_t *core,
  ftun_budget_t *budget, ftun_operation_queue_t *operations,
  ftun_event_loop_t *loop,
  const ftun_config_t *config, const ftun_dns_runtime_adapter_t *adapter,
  const ftun_dns_runtime_network_t *network,
  ftun_dns_runtime_t **out)
{
  (void)active;
  return ftun_dns_runtime_prepare(core, budget, operations, loop, config,
                                 adapter, network, out);
}
ftun_status_t ftun_dns_runtime_plan_prepare(ftun_budget_t *budget, const ftun_config_t *config,
                                           uint32_t socket_mark,
                                           ftun_dns_runtime_plan_t **out)
{
  (void)socket_mark;
  if (out != NULL) *out = NULL;
  if (budget == NULL || config == NULL || out == NULL) return FTUN_E_INVALID;
  return ftun_config_dns(config)->enable ? FTUN_E_UNSUPPORTED : FTUN_OK;
}
ftun_status_t ftun_dns_runtime_plan_destroy(ftun_dns_runtime_plan_t **plan)
{ if (plan == NULL) return FTUN_E_INVALID; *plan = NULL; return FTUN_OK; }
ftun_status_t ftun_dns_runtime_prepare_reload_planned(
  const ftun_dns_runtime_t *active, ftun_core_t *core,
  ftun_budget_t *budget, ftun_operation_queue_t *operations,
  ftun_event_loop_t *loop,
  const ftun_config_t *config, const ftun_dns_runtime_adapter_t *adapter,
  const ftun_dns_runtime_network_t *network,
  const ftun_dns_runtime_plan_t *plan, ftun_dns_runtime_t **out)
{
  (void)plan;
  return ftun_dns_runtime_prepare_reload(active, core, budget, operations,
    loop, config, adapter, network, out);
}
ftun_status_t ftun_dns_runtime_commit_reload(ftun_dns_runtime_t **active,
                                             ftun_dns_runtime_t **prepared,
                                             ftun_dns_runtime_t **retired)
{
  if (active == NULL || prepared == NULL || retired == NULL ||
      *retired != NULL) return FTUN_E_INVALID;
  *retired = *active;
  *active = *prepared;
  *prepared = NULL;
  return FTUN_OK;
}
ftun_status_t ftun_dns_runtime_reap(ftun_dns_runtime_t **retired)
{ if (retired == NULL) return FTUN_E_INVALID; *retired = NULL; return FTUN_OK; }
ftun_status_t ftun_dns_runtime_activate(ftun_dns_runtime_t *dns)
{ (void)dns; return FTUN_OK; }
ftun_status_t ftun_dns_runtime_run_once(ftun_dns_runtime_t *dns, size_t quota,
                                       size_t *out_work)
{
  (void)dns;
  if (out_work != NULL) *out_work = 0u;
  return quota == 0u || out_work == NULL ? FTUN_E_INVALID : FTUN_OK;
}
bool ftun_dns_runtime_has_ready(const ftun_dns_runtime_t *dns)
{ (void)dns; return false; }
size_t ftun_dns_runtime_quarantined(const ftun_dns_runtime_t *dns)
{ (void)dns; return 0u; }
size_t ftun_dns_runtime_listeners_waiting(const ftun_dns_runtime_t *dns)
{ (void)dns; return 0u; }
size_t ftun_dns_runtime_take_object_faults(ftun_dns_runtime_t *dns)
{ (void)dns; return 0u; }
void ftun_dns_runtime_network_changed(ftun_dns_runtime_t *dns, uint64_t now_ms)
{ (void)dns; (void)now_ms; }
ftun_status_t ftun_dns_runtime_next_deadline(
  const ftun_dns_runtime_t *dns, uint64_t *out_deadline_ms, bool *out_present)
{
  (void)dns;
  if (out_deadline_ms != NULL) *out_deadline_ms = 0u;
  if (out_present != NULL) *out_present = false;
  return out_deadline_ms == NULL || out_present == NULL
    ? FTUN_E_INVALID : FTUN_OK;
}
bool ftun_dns_runtime_has_hijack(const ftun_dns_runtime_t *dns)
{ (void)dns; return false; }
ftun_status_t ftun_dns_runtime_dispatcher(ftun_dns_runtime_t *dns,
                                        ftun_dns_dispatcher_t **out)
{
  (void)dns;
  if (out != NULL) *out = NULL;
  return out == NULL ? FTUN_E_INVALID : FTUN_E_UNSUPPORTED;
}
ftun_status_t ftun_dns_runtime_quiesce(ftun_dns_runtime_t *dns)
{ (void)dns; return FTUN_OK; }
ftun_status_t ftun_dns_runtime_hijack_tcp(ftun_dns_runtime_t *dns,
                                         ftun_handle_t descriptor)
{ (void)dns; (void)descriptor; return FTUN_E_UNSUPPORTED; }
ftun_status_t ftun_dns_runtime_hijack_udp(
  ftun_dns_runtime_t *dns, ftun_datagram_t *inbound,
  const ftun_endpoint_t *client, const ftun_packet_t *packet)
{ (void)dns; (void)inbound; (void)client; (void)packet; return FTUN_E_UNSUPPORTED; }
ftun_status_t ftun_dns_runtime_stop(ftun_dns_runtime_t *dns)
{ (void)dns; return FTUN_OK; }
ftun_status_t ftun_dns_runtime_stop_until(ftun_dns_runtime_t *dns,
                                        uint64_t deadline_ms)
{ (void)dns; return deadline_ms == 0u ? FTUN_E_INVALID : FTUN_OK; }
ftun_status_t ftun_dns_runtime_destroy(ftun_dns_runtime_t **dns)
{ if (dns == NULL) return FTUN_E_INVALID; *dns = NULL; return FTUN_OK; }

#endif
