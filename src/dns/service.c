#define _GNU_SOURCE 1

#include "dns/service.h"

#if defined(FTUN_HAVE_MODULE_DNS)

#include "dns/dispatcher.h"
#include "dns/bootstrap.h"
#include "dns/cache.h"
#include "dns/listener.h"
#include "dns/server.h"
#include "dns/wire.h"
#include "config/parser.h"
#include "protocol/socks5.h"
#include "transport/datagram.h"
#include "transport/blocking.h"
#include "util/buffer.h"
#include "util/time.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define FTUN_DNS_RUNTIME_MAX_SERVERS 32u
#define FTUN_DNS_RUNTIME_MAX_LISTENERS 16u
#define FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS 64u
#define FTUN_DNS_RUNTIME_MAX_PENDING 256u
#define FTUN_DNS_RUNTIME_MAX_PENDING_PER_LISTENER 64u
#define FTUN_DNS_RUNTIME_MAX_WAITERS 1024u
#define FTUN_DNS_RUNTIME_REQUEST_BUCKETS 512u
#define FTUN_DNS_RUNTIME_LANE_COUNT 4u
#define FTUN_DNS_RUNTIME_TIMEOUT_MS UINT64_C(5000)
#define FTUN_DNS_RUNTIME_ACCEPT_BACKOFF_MIN_MS UINT64_C(50)
#define FTUN_DNS_RUNTIME_ACCEPT_BACKOFF_MAX_MS UINT64_C(1000)
#define FTUN_DNS_RUNTIME_TRANSPORT_BUFFER_BYTES \
  (FTUN_DNS_MAX_MESSAGE_BYTES + 263u)

enum {
  FTUN_DNS_RUNTIME_DIRECT = 1,
  FTUN_DNS_RUNTIME_SOCKS5 = 2
};

/* DNS 内部出口编号只在本 service 的配置快照中使用；不依赖 Proxy 私有 ID。 */
enum {
  FTUN_DNS_OUTBOUND_DIRECT = 0,
  FTUN_DNS_OUTBOUND_REJECT = 1,
  FTUN_DNS_OUTBOUND_NAMED_BASE = 2
};

struct ftun_dns_runtime_plan {
  ftun_endpoint_t servers[FTUN_DNS_RUNTIME_MAX_SERVERS];
  ftun_endpoint_t *proxies;
  uint8_t *proxy_valid;
  size_t server_count;
  size_t outbound_count;
};

typedef enum {
  FTUN_DNS_RUNTIME_REQUEST_CONNECT = 1,
  FTUN_DNS_RUNTIME_REQUEST_GREETING_SEND,
  FTUN_DNS_RUNTIME_REQUEST_GREETING_RECV,
  FTUN_DNS_RUNTIME_REQUEST_AUTH_SEND,
  FTUN_DNS_RUNTIME_REQUEST_AUTH_RECV,
  FTUN_DNS_RUNTIME_REQUEST_COMMAND_SEND,
  FTUN_DNS_RUNTIME_REQUEST_COMMAND_RECV_HEAD,
  FTUN_DNS_RUNTIME_REQUEST_COMMAND_RECV_BODY,
  FTUN_DNS_RUNTIME_REQUEST_DNS_SEND,
  FTUN_DNS_RUNTIME_REQUEST_DNS_RECV_UDP,
  FTUN_DNS_RUNTIME_REQUEST_DNS_RECV_PREFIX,
  FTUN_DNS_RUNTIME_REQUEST_DNS_RECV_BODY
} ftun_dns_runtime_request_state_t;

typedef struct ftun_dns_runtime_transport_waiter
  ftun_dns_runtime_transport_waiter_t;

typedef struct ftun_dns_runtime_transport_request {
  struct ftun_dns_runtime_transport_request *previous;
  struct ftun_dns_runtime_transport_request *next;
  struct ftun_dns_runtime_transport_request *hash_previous;
  struct ftun_dns_runtime_transport_request *hash_next;
  struct ftun_dns_runtime_transport_request *ready_previous;
  struct ftun_dns_runtime_transport_request *ready_next;
  struct ftun_dns_runtime *dns;
  ftun_event_source_t *source;
  ftun_reservation_t *reservation;
  ftun_dns_runtime_transport_waiter_t *waiter_head;
  ftun_dns_runtime_transport_waiter_t *waiter_tail;
  ftun_endpoint_t upstream;
  ftun_endpoint_t proxy;
  uint64_t deadline_ms;
  uint8_t *query;
  uint8_t *buffer;
  size_t query_length;
  size_t buffer_length;
  size_t buffer_offset;
  size_t receive_needed;
  size_t response_length;
  size_t username_length;
  size_t password_length;
  uint64_t identity_hash;
  uint64_t policy_fingerprint;
  uint64_t server_fingerprint;
  uint32_t outbound_id;
  int descriptor;
  int control_descriptor;
  int source_descriptor;
  uint32_t events;
  uint8_t username[UINT8_MAX];
  uint8_t password[UINT8_MAX];
  ftun_dns_transport_t transport;
  ftun_dns_runtime_request_state_t state;
  uint8_t mode;
  bool connecting;
  bool ready;
  bool indexed;
  bool ready_queued;
} ftun_dns_runtime_transport_request_t;

struct ftun_dns_runtime_transport_waiter {
  ftun_dns_runtime_transport_waiter_t *previous;
  ftun_dns_runtime_transport_waiter_t *next;
  ftun_dns_runtime_transport_request_t *request;
  ftun_reservation_t *reservation;
  ftun_dns_transport_completion_fn completion;
  void *completion_user;
  uint64_t deadline_ms;
  size_t heap_index;
  uint16_t query_id;
};

typedef struct ftun_dns_runtime_listener_slot {
  struct ftun_dns_runtime *dns;
  int descriptor;
  int tcp_descriptor;
  ftun_event_source_t *source;
  ftun_event_source_t *tcp_source;
  ftun_dns_listener_t *protocol;
  size_t fixed_server;
  uint64_t accept_after_ms;
  uint64_t accept_backoff_ms;
  uint32_t events;
  uint32_t tcp_events;
  size_t pending_count;
  bool policy;
} ftun_dns_runtime_listener_slot_t;

typedef struct {
  struct ftun_dns_runtime *dns;
  int descriptor;
  ftun_event_source_t *source;
  ftun_dns_connection_t *protocol;
  uint64_t peer_id;
  struct ftun_dns_runtime_response *response_head;
  struct ftun_dns_runtime_response *response_tail;
  ftun_reservation_t *input_reservation;
  uint8_t *input;
  size_t input_offset;
  size_t input_length;
  uint8_t prefix[2];
  size_t prefix_length;
  size_t response_count;
  uint32_t events;
  bool active;
  bool peer_eof;
  bool ready;
} ftun_dns_runtime_tcp_t;

typedef struct ftun_dns_runtime_response {
  struct ftun_dns_runtime_response *next;
  ftun_reservation_t *reservation;
  size_t offset;
  size_t length;
  uint8_t data[1];
} ftun_dns_runtime_response_t;

typedef enum {
  FTUN_DNS_RUNTIME_PENDING_SOCKET = 1,
  FTUN_DNS_RUNTIME_PENDING_TUN
} ftun_dns_runtime_pending_kind_t;

typedef struct {
  uint64_t id;
  ftun_dns_runtime_pending_kind_t kind;
  int descriptor;
  struct sockaddr_in peer;
  socklen_t peer_length;
  ftun_datagram_t *inbound;
  ftun_endpoint_t client;
  size_t listener_index;
  bool active;
} ftun_dns_runtime_pending_t;

struct ftun_dns_runtime {
  ftun_core_t *core;
  ftun_budget_t *budget;
  ftun_reservation_t *listener_reservation;
  ftun_operation_queue_t *operations;
  ftun_event_loop_t *loop;
  ftun_config_t *config;
  ftun_dns_runtime_adapter_t adapter;
  ftun_endpoint_t *proxy_endpoints;
  uint8_t *proxy_endpoint_valid;
  ftun_dns_server_t *servers[FTUN_DNS_RUNTIME_MAX_SERVERS];
  ftun_dns_runtime_listener_slot_t listeners[FTUN_DNS_RUNTIME_MAX_LISTENERS];
  ftun_dns_runtime_pending_t pending[FTUN_DNS_RUNTIME_MAX_PENDING];
  ftun_dns_runtime_tcp_t tcp[FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS];
  ftun_dns_dispatcher_t *dispatcher;
  ftun_dns_cache_t *cache;
  ftun_dns_listener_t *hijack;
  ftun_dns_runtime_transport_request_t *request_head;
  ftun_dns_runtime_transport_request_t *request_tail;
  ftun_dns_runtime_transport_request_t *ready_request_head;
  ftun_dns_runtime_transport_request_t *ready_request_tail;
  ftun_dns_runtime_transport_request_t *request_buckets[
    FTUN_DNS_RUNTIME_REQUEST_BUCKETS];
  ftun_dns_runtime_transport_waiter_t *waiter_heap[
    FTUN_DNS_RUNTIME_MAX_WAITERS];
  size_t request_count;
  size_t waiter_count;
  size_t pending_count;
  size_t server_count;
  size_t listener_count;
  size_t default_server;
  size_t listener_cursor;
  size_t tcp_cursor;
  size_t pending_cursor;
  size_t lane_cursor;
  uint64_t next_peer_id;
  uint32_t socket_mark;
  ftun_status_t pending_status;
  bool accepting;
  bool active;
  bool sources_prepared;
  bool listener_tcp_turn;
};

static ftun_status_t ftun_dns_runtime_listener_sources_start(
  ftun_dns_runtime_t *dns);

static void ftun_dns_runtime_request_ready_enqueue(
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

static void ftun_dns_runtime_request_ready_remove(
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

static int ftun_dns_runtime_waiter_before(
  const ftun_dns_runtime_transport_waiter_t *left,
  const ftun_dns_runtime_transport_waiter_t *right)
{
  return left->deadline_ms < right->deadline_ms;
}

static void ftun_dns_runtime_waiter_heap_swap(ftun_dns_runtime_t *dns,
                                             size_t left, size_t right)
{
  ftun_dns_runtime_transport_waiter_t *waiter = dns->waiter_heap[left];
  dns->waiter_heap[left] = dns->waiter_heap[right];
  dns->waiter_heap[right] = waiter;
  dns->waiter_heap[left]->heap_index = left;
  dns->waiter_heap[right]->heap_index = right;
}

static void ftun_dns_runtime_waiter_heap_push(
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

static void ftun_dns_runtime_waiter_heap_remove(
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

static uint64_t ftun_dns_runtime_now(void *user)
{
  uint64_t now = 0u;
  (void)user;
  (void)ftun_monotonic_now(&now);
  return now;
}

static void ftun_dns_runtime_record(ftun_dns_runtime_t *dns,
                                   ftun_status_t status)
{
  if (dns != NULL && status != FTUN_OK && dns->pending_status == FTUN_OK) {
    dns->pending_status = status;
  }
}

static void ftun_dns_runtime_listener_ready(ftun_event_source_t *source,
                                            uint32_t events, void *user)
{
  ftun_dns_runtime_listener_slot_t *slot =
    (ftun_dns_runtime_listener_slot_t *)user;
  if (slot != NULL && slot->source == source) slot->events |= events;
}

static void ftun_dns_runtime_listener_tcp_ready(ftun_event_source_t *source,
                                                uint32_t events, void *user)
{
  ftun_dns_runtime_listener_slot_t *slot =
    (ftun_dns_runtime_listener_slot_t *)user;
  if (slot != NULL && slot->tcp_source == source) slot->tcp_events |= events;
}

static void ftun_dns_runtime_request_ready(ftun_event_source_t *source,
                                           uint32_t events, void *user)
{
  ftun_dns_runtime_transport_request_t *request =
    (ftun_dns_runtime_transport_request_t *)user;
  if (request != NULL && request->source == source) {
    request->events |= events;
    ftun_dns_runtime_request_ready_enqueue(request);
  }
}

static void ftun_dns_runtime_tcp_ready(ftun_event_source_t *source,
                                       uint32_t events, void *user)
{
  ftun_dns_runtime_tcp_t *connection = (ftun_dns_runtime_tcp_t *)user;
  if (connection != NULL && connection->source == source &&
      connection->active) {
    connection->events |= events;
    connection->ready = true;
  }
}

static uint32_t ftun_dns_runtime_request_interests(
  const ftun_dns_runtime_transport_request_t *request)
{
  switch (request->state) {
    case FTUN_DNS_RUNTIME_REQUEST_CONNECT:
    case FTUN_DNS_RUNTIME_REQUEST_GREETING_SEND:
    case FTUN_DNS_RUNTIME_REQUEST_AUTH_SEND:
    case FTUN_DNS_RUNTIME_REQUEST_COMMAND_SEND:
    case FTUN_DNS_RUNTIME_REQUEST_DNS_SEND:
      return FTUN_EVENT_WRITE | FTUN_EVENT_ERROR;
    default:
      return FTUN_EVENT_READ | FTUN_EVENT_ERROR;
  }
}

static ftun_status_t ftun_dns_runtime_request_source_update(
  ftun_dns_runtime_transport_request_t *request)
{
  uint32_t interests;
  ftun_status_t status;
  if (request == NULL || request->dns == NULL || request->descriptor < 0) {
    return FTUN_E_INVALID;
  }
  interests = ftun_dns_runtime_request_interests(request);
  if (request->source != NULL &&
      request->source_descriptor != request->descriptor) {
    status = ftun_event_source_cancel(&request->source);
    if (status != FTUN_OK) return status;
    request->source_descriptor = -1;
  }
  if (request->source == NULL) {
    status = ftun_event_io_start(request->dns->loop,
      (ftun_native_socket_t)(unsigned int)request->descriptor, interests,
      ftun_dns_runtime_request_ready, request, &request->source);
    if (status == FTUN_OK) request->source_descriptor = request->descriptor;
    return status;
  }
  return ftun_event_io_update(request->source, interests);
}

static ftun_status_t ftun_dns_runtime_tcp_source_update(
  ftun_dns_runtime_tcp_t *connection)
{
  uint32_t interests = FTUN_EVENT_READ | FTUN_EVENT_ERROR;
  if (connection == NULL || !connection->active || connection->source == NULL) {
    return FTUN_E_INVALID;
  }
  if (connection->response_head != NULL) interests |= FTUN_EVENT_WRITE;
  return ftun_event_io_update(connection->source, interests);
}

static uint64_t ftun_dns_runtime_hash_bytes(uint64_t hash, const void *data,
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

static uint64_t ftun_dns_runtime_request_hash(
  uint32_t outbound_id, uint64_t policy_fingerprint,
  uint64_t server_fingerprint, const ftun_endpoint_t *upstream,
  ftun_dns_transport_t transport, uint8_t mode,
  const ftun_endpoint_t *proxy, const char *username, const char *password,
  ftun_bytes_t query)
{
  uint64_t hash = UINT64_C(1469598103934665603);
  size_t username_length = username == NULL ? 0u : strlen(username);
  size_t password_length = password == NULL ? 0u : strlen(password);
  uint8_t transport_byte = (uint8_t)transport;
  hash = ftun_dns_runtime_hash_bytes(hash, &outbound_id,
                                    sizeof(outbound_id));
  hash = ftun_dns_runtime_hash_bytes(hash, &policy_fingerprint,
                                    sizeof(policy_fingerprint));
  hash = ftun_dns_runtime_hash_bytes(hash, &server_fingerprint,
                                    sizeof(server_fingerprint));
  hash = ftun_dns_runtime_hash_bytes(hash, &transport_byte,
                                    sizeof(transport_byte));
  hash = ftun_dns_runtime_hash_bytes(hash, &mode, sizeof(mode));
  hash = ftun_dns_runtime_hash_bytes(hash, &upstream->kind,
                                    sizeof(upstream->kind));
  hash = ftun_dns_runtime_hash_bytes(hash, &upstream->port,
                                    sizeof(upstream->port));
  hash = ftun_dns_runtime_hash_bytes(hash, upstream->address, 4u);
  hash = ftun_dns_runtime_hash_bytes(hash, &proxy->kind, sizeof(proxy->kind));
  hash = ftun_dns_runtime_hash_bytes(hash, &proxy->port, sizeof(proxy->port));
  hash = ftun_dns_runtime_hash_bytes(hash, proxy->address, 4u);
  hash = ftun_dns_runtime_hash_bytes(hash, &username_length,
                                    sizeof(username_length));
  if (username_length != 0u) {
    hash = ftun_dns_runtime_hash_bytes(hash, username, username_length);
  }
  hash = ftun_dns_runtime_hash_bytes(hash, &password_length,
                                    sizeof(password_length));
  if (password_length != 0u) {
    hash = ftun_dns_runtime_hash_bytes(hash, password, password_length);
  }
  hash = ftun_dns_runtime_hash_bytes(hash, &query.length,
                                    sizeof(query.length));
  return ftun_dns_runtime_hash_bytes(hash, query.data + 2u,
                                    query.length - 2u);
}

static void ftun_dns_runtime_request_index_insert(
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

static void ftun_dns_runtime_request_index_remove(
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

static void ftun_dns_runtime_request_unlink(
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

static void ftun_dns_runtime_request_close(
  ftun_dns_runtime_transport_request_t *request)
{
  if (request->descriptor >= 0 &&
      request->descriptor != request->control_descriptor) {
    (void)close(request->descriptor);
  }
  if (request->control_descriptor >= 0) {
    (void)close(request->control_descriptor);
  }
  request->descriptor = -1;
  request->control_descriptor = -1;
  request->source_descriptor = -1;
}

static void ftun_dns_runtime_request_release(
  ftun_dns_runtime_transport_request_t *request)
{
  ftun_dns_runtime_t *dns;
  ftun_reservation_t *reservation;
  if (request == NULL) return;
  dns = request->dns;
  reservation = request->reservation;
  ftun_dns_runtime_record(dns, ftun_event_source_cancel(&request->source));
  ftun_dns_runtime_request_close(request);
  memset(request, 0, sizeof(*request));
  free(request);
  (void)ftun_reservation_release(&reservation);
}

static void ftun_dns_runtime_waiter_unlink(
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

static void ftun_dns_runtime_waiter_release(
  ftun_dns_runtime_transport_waiter_t *waiter)
{
  ftun_reservation_t *reservation = waiter->reservation;
  memset(waiter, 0, sizeof(*waiter));
  free(waiter);
  (void)ftun_reservation_release(&reservation);
}

static void ftun_dns_runtime_waiter_finish(
  ftun_dns_runtime_transport_waiter_t *waiter, ftun_status_t status,
  ftun_bytes_t response)
{
  ftun_dns_runtime_transport_request_t *request = waiter->request;
  ftun_dns_transport_completion_fn completion = waiter->completion;
  void *completion_user = waiter->completion_user;
  ftun_endpoint_t upstream = request->upstream;
  ftun_dns_transport_t transport = request->transport;
  ftun_dns_runtime_waiter_unlink(waiter);
  completion(completion_user, status, transport, &upstream, response);
  ftun_dns_runtime_waiter_release(waiter);
}

static void ftun_dns_runtime_request_finish(
  ftun_dns_runtime_transport_request_t *request, ftun_status_t status)
{
  ftun_dns_runtime_request_unlink(request);
  while (request->waiter_head != NULL) {
    ftun_dns_runtime_transport_waiter_t *waiter = request->waiter_head;
    ftun_bytes_t response = {NULL, 0u};
    if (status == FTUN_OK) {
      request->buffer[0] = (uint8_t)(waiter->query_id >> 8u);
      request->buffer[1] = (uint8_t)waiter->query_id;
      response.data = request->buffer;
      response.length = request->response_length;
    }
    ftun_dns_runtime_waiter_finish(waiter, status, response);
  }
  ftun_dns_runtime_request_release(request);
}

static ftun_status_t ftun_dns_runtime_request_open(
  ftun_dns_runtime_transport_request_t *request, int type,
  const ftun_endpoint_t *target, bool control)
{
  struct sockaddr_in address;
  int descriptor;
  int flags;
  if (request == NULL || target == NULL ||
      target->kind != FTUN_ADDRESS_IPV4 || target->port == 0u) {
    return FTUN_E_INVALID;
  }
  descriptor = socket(AF_INET, type | SOCK_CLOEXEC, 0);
  if (descriptor < 0) return ftun_blocking_socket_status(errno);
#if defined(SO_MARK)
  if (request->dns->socket_mark != 0u &&
      setsockopt(descriptor, SOL_SOCKET, SO_MARK, &request->dns->socket_mark,
                 (socklen_t)sizeof(request->dns->socket_mark)) != 0) {
    ftun_status_t status = ftun_blocking_socket_status(errno);
    (void)close(descriptor);
    return status;
  }
#endif
  flags = fcntl(descriptor, F_GETFL, 0);
  if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0) {
    (void)close(descriptor);
    return FTUN_E_IO;
  }
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_port = htons(target->port);
  memcpy(&address.sin_addr.s_addr, target->address, 4u);
  request->connecting = false;
  if (connect(descriptor, (const struct sockaddr *)&address,
              (socklen_t)sizeof(address)) != 0) {
    if (errno != EINPROGRESS && errno != EALREADY && errno != EINTR) {
      ftun_status_t status = ftun_blocking_socket_status(errno);
      (void)close(descriptor);
      return status;
    }
    request->connecting = true;
  }
  if (control) request->control_descriptor = descriptor;
  request->descriptor = descriptor;
  request->state = FTUN_DNS_RUNTIME_REQUEST_CONNECT;
  return FTUN_OK;
}

static ftun_status_t ftun_dns_runtime_request_connected(
  ftun_dns_runtime_transport_request_t *request, bool *connected)
{
  struct pollfd item;
  int error_code = 0;
  socklen_t error_length = (socklen_t)sizeof(error_code);
  *connected = !request->connecting;
  if (!request->connecting) return FTUN_OK;
  memset(&item, 0, sizeof(item));
  item.fd = request->descriptor;
  item.events = POLLOUT;
  if (poll(&item, 1u, 0) < 0) {
    return errno == EINTR ? FTUN_E_AGAIN : ftun_blocking_socket_status(errno);
  }
  if ((item.revents & (POLLOUT | POLLERR | POLLHUP | POLLNVAL)) == 0) {
    return FTUN_E_AGAIN;
  }
  if (getsockopt(request->descriptor, SOL_SOCKET, SO_ERROR, &error_code,
                 &error_length) != 0) return ftun_blocking_socket_status(errno);
  if (error_code != 0) return ftun_blocking_socket_status(error_code);
  request->connecting = false;
  *connected = true;
  return FTUN_OK;
}

static ftun_status_t ftun_dns_runtime_request_send(
  ftun_dns_runtime_transport_request_t *request)
{
  while (request->buffer_offset < request->buffer_length) {
    ssize_t sent = send(request->descriptor,
      request->buffer + request->buffer_offset,
      request->buffer_length - request->buffer_offset, MSG_NOSIGNAL);
    if (sent > 0) {
      request->buffer_offset += (size_t)sent;
      if (request->transport == FTUN_DNS_TRANSPORT_UDP &&
          request->buffer_offset != request->buffer_length) {
        return FTUN_E_PROTOCOL;
      }
      continue;
    }
    if (sent < 0 && errno == EINTR) continue;
    if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK ||
                     errno == EINPROGRESS || errno == EALREADY ||
                     errno == ENOTCONN)) return FTUN_E_AGAIN;
    return sent == 0 ? FTUN_E_EOF : ftun_blocking_socket_status(errno);
  }
  return FTUN_OK;
}

static ftun_status_t ftun_dns_runtime_request_receive(
  ftun_dns_runtime_transport_request_t *request, size_t needed)
{
  while (request->buffer_length < needed) {
    ssize_t received = recv(request->descriptor,
      request->buffer + request->buffer_length,
      needed - request->buffer_length, 0);
    if (received > 0) {
      request->buffer_length += (size_t)received;
      continue;
    }
    if (received < 0 && errno == EINTR) continue;
    if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      return FTUN_E_AGAIN;
    }
    return received == 0 ? FTUN_E_EOF : ftun_blocking_socket_status(errno);
  }
  return FTUN_OK;
}

static ftun_status_t ftun_dns_runtime_request_command(
  ftun_dns_runtime_transport_request_t *request)
{
  ftun_endpoint_t target = request->upstream;
  size_t written = 0u;
  if (request->transport == FTUN_DNS_TRANSPORT_UDP) {
    memset(target.address, 0, 4u);
    target.port = 0u;
  }
  request->buffer_offset = 0u;
  request->buffer_length = 0u;
  if (ftun_socks5_encode_request(
      request->transport == FTUN_DNS_TRANSPORT_UDP
        ? FTUN_SOCKS5_COMMAND_UDP_ASSOCIATE : FTUN_SOCKS5_COMMAND_CONNECT,
      &target, request->buffer, FTUN_DNS_RUNTIME_TRANSPORT_BUFFER_BYTES,
      &written) != FTUN_OK) return FTUN_E_PROTOCOL;
  request->buffer_length = written;
  request->state = FTUN_DNS_RUNTIME_REQUEST_COMMAND_SEND;
  return FTUN_OK;
}

static ftun_status_t ftun_dns_runtime_request_dns_send(
  ftun_dns_runtime_transport_request_t *request)
{
  size_t written;
  request->buffer_offset = 0u;
  request->buffer_length = 0u;
  if (request->transport == FTUN_DNS_TRANSPORT_TCP) {
    if (request->query_length > UINT16_MAX) return FTUN_E_LIMIT;
    request->buffer[0] = (uint8_t)(request->query_length >> 8u);
    request->buffer[1] = (uint8_t)request->query_length;
    memcpy(request->buffer + 2u, request->query, request->query_length);
    request->buffer_length = request->query_length + 2u;
  } else if (request->mode == FTUN_DNS_RUNTIME_SOCKS5) {
    written = 0u;
    if (ftun_socks5_encode_udp_datagram(&request->upstream,
        (ftun_bytes_t){request->query, request->query_length},
        request->buffer, FTUN_DNS_RUNTIME_TRANSPORT_BUFFER_BYTES,
        &written) != FTUN_OK) return FTUN_E_PROTOCOL;
    request->buffer_length = written;
  } else {
    memcpy(request->buffer, request->query, request->query_length);
    request->buffer_length = request->query_length;
  }
  request->state = FTUN_DNS_RUNTIME_REQUEST_DNS_SEND;
  return FTUN_OK;
}

static ftun_status_t ftun_dns_runtime_resolve_upstream(
  const ftun_config_t *config, const char *text, uint32_t socket_mark,
  ftun_endpoint_t *out);

static ftun_status_t ftun_dns_runtime_outbound(
  ftun_dns_runtime_t *dns, uint32_t requested, uint8_t *mode,
  ftun_endpoint_t *proxy, const char **username, const char **password)
{
  uint32_t current = requested;
  size_t depth;
  ftun_status_t status = FTUN_OK;
  *mode = 0u;
  memset(proxy, 0, sizeof(*proxy));
  *username = NULL;
  *password = NULL;
  for (depth = 0u; status == FTUN_OK && depth <= dns->config->outbound_count;
       depth++) {
    if (current == FTUN_DNS_OUTBOUND_DIRECT) {
      *mode = FTUN_DNS_RUNTIME_DIRECT;
      break;
    }
    if (current == FTUN_DNS_OUTBOUND_REJECT ||
        current < FTUN_DNS_OUTBOUND_NAMED_BASE ||
        (size_t)(current - FTUN_DNS_OUTBOUND_NAMED_BASE) >=
          dns->config->outbound_count) {
      status = FTUN_E_REJECTED;
      break;
    }
    {
      const ftun_config_outbound_t *item =
        &dns->config->outbounds[current - FTUN_DNS_OUTBOUND_NAMED_BASE];
      if (item->kind == FTUN_CONFIG_OUTBOUND_SOCKS5) {
        size_t index = current - FTUN_DNS_OUTBOUND_NAMED_BASE;
        if (dns->proxy_endpoint_valid == NULL ||
            dns->proxy_endpoint_valid[index] == 0u) {
          status = FTUN_E_RESOLVE;
        } else {
          *proxy = dns->proxy_endpoints[index];
          *mode = FTUN_DNS_RUNTIME_SOCKS5;
          *username = item->username;
          *password = item->password;
        }
        break;
      }
      {
        uint32_t member = 0u;
        if (dns->adapter.select_member == NULL) {
          status = FTUN_E_UNSUPPORTED;
        } else {
          status = dns->adapter.select_member(
            dns->adapter.user, current, &member);
        }
        if (status == FTUN_OK) current = member;
      }
    }
  }
  if (status == FTUN_OK && *mode == 0u) status = FTUN_E_STATE_CORRUPT;
  return status;
}

static ftun_status_t ftun_dns_runtime_request_drive_connected(
  ftun_dns_runtime_transport_request_t *request)
{
  bool connected = false;
  ftun_status_t status = ftun_dns_runtime_request_connected(request,
                                                            &connected);
  if (status != FTUN_OK || !connected) return status;
  if (request->mode == FTUN_DNS_RUNTIME_DIRECT ||
      request->descriptor != request->control_descriptor) {
    return ftun_dns_runtime_request_dns_send(request);
  }
  request->buffer[0] = FTUN_SOCKS5_VERSION;
  request->buffer[1] = 1u;
  request->buffer[2] = request->username_length == 0u
    ? FTUN_SOCKS5_METHOD_NO_AUTH : FTUN_SOCKS5_METHOD_USERNAME_PASSWORD;
  request->buffer_offset = 0u;
  request->buffer_length = 3u;
  request->state = FTUN_DNS_RUNTIME_REQUEST_GREETING_SEND;
  return FTUN_OK;
}

static ftun_status_t ftun_dns_runtime_request_drive(
  ftun_dns_runtime_transport_request_t *request)
{
  size_t steps;
  for (steps = 0u; steps < 16u; steps++) {
    ftun_status_t status;
    if (ftun_dns_runtime_now(NULL) >= request->deadline_ms) {
      return FTUN_E_TIMEOUT;
    }
    switch (request->state) {
      case FTUN_DNS_RUNTIME_REQUEST_CONNECT:
        status = ftun_dns_runtime_request_drive_connected(request);
        break;
      case FTUN_DNS_RUNTIME_REQUEST_GREETING_SEND:
        status = ftun_dns_runtime_request_send(request);
        if (status == FTUN_OK) {
          request->buffer_length = 0u;
          request->receive_needed = 2u;
          request->state = FTUN_DNS_RUNTIME_REQUEST_GREETING_RECV;
        }
        break;
      case FTUN_DNS_RUNTIME_REQUEST_GREETING_RECV:
        status = ftun_dns_runtime_request_receive(request,
                                                 request->receive_needed);
        if (status == FTUN_OK) {
          uint8_t expected = request->username_length == 0u
            ? FTUN_SOCKS5_METHOD_NO_AUTH : FTUN_SOCKS5_METHOD_USERNAME_PASSWORD;
          if (request->buffer[0] != FTUN_SOCKS5_VERSION ||
              request->buffer[1] != expected) return FTUN_E_REJECTED;
          if (request->username_length == 0u) {
            status = ftun_dns_runtime_request_command(request);
          } else {
            size_t written = 0u;
            status = ftun_socks5_encode_credentials(
              (ftun_bytes_t){request->username, request->username_length},
              (ftun_bytes_t){request->password, request->password_length},
              request->buffer, FTUN_DNS_RUNTIME_TRANSPORT_BUFFER_BYTES,
              &written);
            if (status == FTUN_OK) {
              request->buffer_offset = 0u;
              request->buffer_length = written;
              request->state = FTUN_DNS_RUNTIME_REQUEST_AUTH_SEND;
            }
          }
        }
        break;
      case FTUN_DNS_RUNTIME_REQUEST_AUTH_SEND:
        status = ftun_dns_runtime_request_send(request);
        if (status == FTUN_OK) {
          request->buffer_length = 0u;
          request->receive_needed = 2u;
          request->state = FTUN_DNS_RUNTIME_REQUEST_AUTH_RECV;
        }
        break;
      case FTUN_DNS_RUNTIME_REQUEST_AUTH_RECV:
        status = ftun_dns_runtime_request_receive(request,
                                                 request->receive_needed);
        if (status == FTUN_OK) {
          if (request->buffer[0] != FTUN_SOCKS5_AUTH_VERSION ||
              request->buffer[1] != 0u) return FTUN_E_REJECTED;
          status = ftun_dns_runtime_request_command(request);
        }
        break;
      case FTUN_DNS_RUNTIME_REQUEST_COMMAND_SEND:
        status = ftun_dns_runtime_request_send(request);
        if (status == FTUN_OK) {
          request->buffer_length = 0u;
          request->receive_needed = 4u;
          request->state = FTUN_DNS_RUNTIME_REQUEST_COMMAND_RECV_HEAD;
        }
        break;
      case FTUN_DNS_RUNTIME_REQUEST_COMMAND_RECV_HEAD:
        status = ftun_dns_runtime_request_receive(request,
                                                 request->receive_needed);
        if (status == FTUN_OK) {
          if (request->buffer[0] != FTUN_SOCKS5_VERSION ||
              request->buffer[1] != FTUN_SOCKS5_REPLY_SUCCEEDED ||
              request->buffer[2] != 0u) return FTUN_E_REJECTED;
          if (request->buffer[3] == 1u) request->receive_needed = 10u;
          else if (request->buffer[3] == 4u) request->receive_needed = 22u;
          else if (request->buffer[3] == 3u) request->receive_needed = 5u;
          else return FTUN_E_PROTOCOL;
          request->state = FTUN_DNS_RUNTIME_REQUEST_COMMAND_RECV_BODY;
        }
        break;
      case FTUN_DNS_RUNTIME_REQUEST_COMMAND_RECV_BODY:
        status = ftun_dns_runtime_request_receive(request,
                                                 request->receive_needed);
        if (status == FTUN_OK && request->buffer[3] == 3u &&
            request->receive_needed == 5u) {
          request->receive_needed = 7u + request->buffer[4];
          if (request->receive_needed >
              FTUN_DNS_RUNTIME_TRANSPORT_BUFFER_BYTES) return FTUN_E_LIMIT;
          break;
        }
        if (status == FTUN_OK) {
          ftun_socks5_reply_t reply;
          size_t consumed = 0u;
          status = ftun_socks5_decode_reply(
            (ftun_bytes_t){request->buffer, request->receive_needed},
            &reply, &consumed);
          if (status != FTUN_OK || consumed != request->receive_needed ||
              reply.reply != FTUN_SOCKS5_REPLY_SUCCEEDED) {
            return status == FTUN_OK ? FTUN_E_REJECTED : status;
          }
          if (request->transport == FTUN_DNS_TRANSPORT_TCP) {
            status = ftun_dns_runtime_request_dns_send(request);
          } else {
            ftun_endpoint_t relay = reply.endpoint;
            if (relay.kind != FTUN_ADDRESS_IPV4 || relay.port == 0u) {
              return FTUN_E_UNSUPPORTED;
            }
            if (relay.address[0] == 0u && relay.address[1] == 0u &&
                relay.address[2] == 0u && relay.address[3] == 0u) {
              memcpy(relay.address, request->proxy.address, 4u);
            }
            request->descriptor = -1;
            status = ftun_dns_runtime_request_open(request, SOCK_DGRAM,
                                                   &relay, false);
          }
        }
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
        do {
          ssize_t received = recv(request->descriptor, request->buffer,
            FTUN_DNS_RUNTIME_TRANSPORT_BUFFER_BYTES, 0);
          if (received > 0) {
            if (request->mode == FTUN_DNS_RUNTIME_SOCKS5) {
              ftun_socks5_udp_datagram_t datagram;
              size_t consumed = 0u;
              status = ftun_socks5_decode_udp_datagram(
                (ftun_bytes_t){request->buffer, (size_t)received},
                &datagram, &consumed);
              if (status == FTUN_OK &&
                  (consumed != (size_t)received ||
                   datagram.endpoint.kind != FTUN_ADDRESS_IPV4 ||
                   datagram.endpoint.port != request->upstream.port ||
                   memcmp(datagram.endpoint.address,
                          request->upstream.address, 4u) != 0)) {
                status = FTUN_E_REJECTED;
              }
              if (status != FTUN_OK) return status;
              memmove(request->buffer, datagram.payload.data,
                      datagram.payload.length);
              request->response_length = datagram.payload.length;
            } else {
              request->response_length = (size_t)received;
            }
            return FTUN_OK;
          }
          if (received == 0) return FTUN_E_EOF;
          if (errno == EINTR) continue;
          return errno == EAGAIN || errno == EWOULDBLOCK
            ? FTUN_E_AGAIN : ftun_blocking_socket_status(errno);
        } while (true);
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
  return FTUN_E_AGAIN;
}

static int ftun_dns_runtime_request_matches(
  const ftun_dns_runtime_transport_request_t *request,
  uint32_t outbound_id, uint64_t policy_fingerprint,
  uint64_t server_fingerprint, const ftun_endpoint_t *upstream,
  ftun_dns_transport_t transport,
  uint8_t mode, const ftun_endpoint_t *proxy, const char *username,
  const char *password, ftun_bytes_t query)
{
  size_t username_length = username == NULL ? 0u : strlen(username);
  size_t password_length = password == NULL ? 0u : strlen(password);
  return request->outbound_id == outbound_id &&
    request->policy_fingerprint == policy_fingerprint &&
    request->server_fingerprint == server_fingerprint &&
    request->transport == transport && request->mode == mode &&
    request->upstream.kind == upstream->kind &&
    request->upstream.port == upstream->port &&
    memcmp(request->upstream.address, upstream->address, 4u) == 0 &&
    request->proxy.kind == proxy->kind && request->proxy.port == proxy->port &&
    memcmp(request->proxy.address, proxy->address, 4u) == 0 &&
    request->username_length == username_length &&
    request->password_length == password_length &&
    (username_length == 0u ||
     memcmp(request->username, username, username_length) == 0) &&
    (password_length == 0u ||
     memcmp(request->password, password, password_length) == 0) &&
    request->query_length == query.length && query.length >= 2u &&
    memcmp(request->query + 2u, query.data + 2u, query.length - 2u) == 0;
}

static ftun_status_t ftun_dns_runtime_waiter_create(
  ftun_dns_runtime_t *dns, ftun_dns_runtime_transport_request_t *request,
  ftun_bytes_t query, uint64_t deadline_ms,
  ftun_dns_transport_completion_fn completion, void *completion_user,
  ftun_dns_runtime_transport_waiter_t **out)
{
  ftun_dns_runtime_transport_waiter_t *waiter;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (dns->waiter_count >= FTUN_DNS_RUNTIME_MAX_WAITERS) return FTUN_E_LIMIT;
  status = ftun_budget_reserve(dns->budget, sizeof(*waiter), &reservation);
  if (status != FTUN_OK) return status;
  waiter = (ftun_dns_runtime_transport_waiter_t *)calloc(1u,
                                                        sizeof(*waiter));
  if (waiter == NULL) {
    (void)ftun_reservation_release(&reservation);
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

static ftun_status_t ftun_dns_runtime_transport_submit(
  void *user, uint32_t outbound_id, uint64_t policy_fingerprint,
  uint64_t server_fingerprint, const ftun_endpoint_t *upstream,
  ftun_dns_transport_t transport, ftun_bytes_t query, uint64_t deadline_ms,
  ftun_dns_transport_completion_fn completion, void *completion_user,
  void **out_request)
{
  ftun_dns_runtime_t *dns = (ftun_dns_runtime_t *)user;
  ftun_dns_runtime_transport_request_t *request;
  ftun_dns_runtime_transport_waiter_t *waiter = NULL;
  ftun_endpoint_t proxy;
  ftun_reservation_t *reservation = NULL;
  size_t bytes;
  size_t username_length;
  size_t password_length;
  uint64_t identity_hash;
  const char *username;
  const char *password;
  uint8_t mode;
  ftun_status_t status;
  if (out_request != NULL) *out_request = NULL;
  if (dns == NULL || upstream == NULL || upstream->kind != FTUN_ADDRESS_IPV4 ||
      query.data == NULL || query.length < 12u || query.length > UINT32_MAX ||
      completion == NULL || out_request == NULL || deadline_ms == 0u) {
    return FTUN_E_INVALID;
  }
  if (ftun_dns_runtime_now(NULL) >= deadline_ms) return FTUN_E_TIMEOUT;
  status = ftun_dns_runtime_outbound(dns, outbound_id, &mode, &proxy,
                                    &username, &password);
  if (status != FTUN_OK) return status;
  username_length = username == NULL ? 0u : strlen(username);
  password_length = password == NULL ? 0u : strlen(password);
  if (username_length > UINT8_MAX || password_length > UINT8_MAX ||
      (username_length == 0u) != (password_length == 0u) ||
      query.length > SIZE_MAX - sizeof(*request) ||
      sizeof(*request) + query.length > SIZE_MAX -
        FTUN_DNS_RUNTIME_TRANSPORT_BUFFER_BYTES) return FTUN_E_LIMIT;
  identity_hash = ftun_dns_runtime_request_hash(outbound_id,
    policy_fingerprint, server_fingerprint, upstream, transport, mode,
    &proxy, username, password, query);
  for (request = dns->request_buckets[(size_t)identity_hash &
       (FTUN_DNS_RUNTIME_REQUEST_BUCKETS - 1u)]; request != NULL;
       request = request->hash_next) {
    if (request->identity_hash != identity_hash ||
        !ftun_dns_runtime_request_matches(request, outbound_id,
                                         policy_fingerprint,
                                         server_fingerprint, upstream,
                                         transport, mode, &proxy, username,
                                         password, query)) {
      continue;
    }
    status = ftun_dns_runtime_waiter_create(dns, request, query, deadline_ms,
      completion, completion_user, &waiter);
    if (status == FTUN_OK) *out_request = waiter;
    return status;
  }
  if (dns->request_count >= FTUN_DNS_RUNTIME_MAX_PENDING) return FTUN_E_LIMIT;
  bytes = sizeof(*request) + query.length +
          FTUN_DNS_RUNTIME_TRANSPORT_BUFFER_BYTES;
  status = ftun_budget_reserve(dns->budget, bytes, &reservation);
  if (status != FTUN_OK) return status;
  request = (ftun_dns_runtime_transport_request_t *)calloc(1u, bytes);
  if (request == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  request->dns = dns;
  request->reservation = reservation;
  request->upstream = *upstream;
  request->proxy = proxy;
  request->deadline_ms = deadline_ms;
  request->query = (uint8_t *)(request + 1);
  request->buffer = request->query + query.length;
  request->query_length = query.length;
  request->username_length = username_length;
  request->password_length = password_length;
  request->identity_hash = identity_hash;
  request->policy_fingerprint = policy_fingerprint;
  request->server_fingerprint = server_fingerprint;
  request->outbound_id = outbound_id;
  request->descriptor = -1;
  request->control_descriptor = -1;
  request->transport = transport;
  request->mode = mode;
  memcpy(request->query, query.data, query.length);
  if (username_length != 0u) {
    memcpy(request->username, username, username_length);
    memcpy(request->password, password, password_length);
  }
  status = ftun_dns_runtime_request_open(request,
    mode == FTUN_DNS_RUNTIME_SOCKS5 || transport == FTUN_DNS_TRANSPORT_TCP
      ? SOCK_STREAM : SOCK_DGRAM,
    mode == FTUN_DNS_RUNTIME_SOCKS5 ? &request->proxy : &request->upstream,
    mode == FTUN_DNS_RUNTIME_SOCKS5);
  if (status != FTUN_OK) {
    ftun_dns_runtime_request_release(request);
    return status;
  }
  status = ftun_dns_runtime_request_source_update(request);
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
  request->previous = dns->request_tail;
  if (dns->request_tail != NULL) dns->request_tail->next = request;
  else dns->request_head = request;
  dns->request_tail = request;
  dns->request_count++;
  ftun_dns_runtime_request_index_insert(request);
  ftun_dns_runtime_request_ready_enqueue(request);
  *out_request = waiter;
  return FTUN_OK;
}

static ftun_status_t ftun_dns_runtime_transport_cancel(void *user,
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
    ftun_dns_runtime_request_unlink(request);
    ftun_dns_runtime_request_release(request);
  }
  *request_ptr = NULL;
  return FTUN_OK;
}

static ftun_status_t ftun_dns_runtime_parse_endpoint(const char *text,
                                                     ftun_endpoint_t *out)
{
  const char *colon;
  char address[INET_ADDRSTRLEN];
  char *tail = NULL;
  unsigned long port = 53u;
  size_t length;
  memset(out, 0, sizeof(*out));
  if (text == NULL) return FTUN_E_INVALID;
  colon = strrchr(text, ':');
  length = colon == NULL ? strlen(text) : (size_t)(colon - text);
  if (length == 0u || length >= sizeof(address)) return FTUN_E_UNSUPPORTED;
  memcpy(address, text, length);
  address[length] = '\0';
  if (colon != NULL) {
    errno = 0;
    port = strtoul(colon + 1u, &tail, 10);
    if (errno != 0 || tail == colon + 1u || *tail != '\0' ||
        port == 0u || port > UINT16_MAX) return FTUN_E_INVALID;
  }
  if (inet_pton(AF_INET, address, out->address) != 1) {
    return FTUN_E_UNSUPPORTED;
  }
  out->kind = FTUN_ADDRESS_IPV4;
  out->port = (uint16_t)port;
  return FTUN_OK;
}

static ftun_status_t ftun_dns_runtime_bootstrap_endpoint(
  const ftun_config_t *config, ftun_endpoint_t *out)
{
  FILE *file;
  char line[512];
  if (config == NULL || out == NULL) return FTUN_E_INVALID;
  if (config->dns.bootstrap.count != 0u) {
    return ftun_dns_runtime_parse_endpoint(config->dns.bootstrap.items[0], out);
  }
  file = fopen("/etc/resolv.conf", "r");
  if (file == NULL) return FTUN_E_IO;
  while (fgets(line, sizeof(line), file) != NULL) {
    char address[INET_ADDRSTRLEN];
    char extra;
    if (sscanf(line, " nameserver %15s %c", address, &extra) >= 1 &&
        inet_pton(AF_INET, address, out->address) == 1) {
      out->kind = FTUN_ADDRESS_IPV4;
      out->port = 53u;
      (void)fclose(file);
      return FTUN_OK;
    }
  }
  (void)fclose(file);
  return FTUN_E_RESOLVE;
}

static ftun_status_t ftun_dns_runtime_encode_bootstrap_query(
  const char *domain, uint16_t query_id, uint8_t *wire, size_t capacity,
  size_t *out_length)
{
  size_t input = 0u;
  size_t output = FTUN_DNS_HEADER_BYTES;
  size_t length;
  if (out_length != NULL) *out_length = 0u;
  if (domain == NULL || wire == NULL || out_length == NULL ||
      (length = strlen(domain)) == 0u || length > 253u ||
      capacity < FTUN_DNS_HEADER_BYTES + 5u) return FTUN_E_INVALID;
  if (domain[length - 1u] == '.') length--;
  if (length == 0u) return FTUN_E_INVALID;
  memset(wire, 0, capacity);
  wire[0] = (uint8_t)(query_id >> 8u);
  wire[1] = (uint8_t)query_id;
  wire[2] = 0x01u;
  wire[5] = 0x01u;
  while (input < length) {
    size_t end = input;
    size_t label_length;
    while (end < length && domain[end] != '.') end++;
    label_length = end - input;
    if (label_length == 0u || label_length > 63u ||
        output + label_length + 1u > capacity) return FTUN_E_INVALID;
    wire[output++] = (uint8_t)label_length;
    while (input < end) {
      uint8_t byte = (uint8_t)domain[input++];
      if (byte >= (uint8_t)'A' && byte <= (uint8_t)'Z') byte += 32u;
      if (!((byte >= (uint8_t)'a' && byte <= (uint8_t)'z') ||
            (byte >= (uint8_t)'0' && byte <= (uint8_t)'9') ||
            byte == (uint8_t)'-')) return FTUN_E_INVALID;
      wire[output++] = byte;
    }
    input++;
  }
  if (output + 5u > capacity) return FTUN_E_LIMIT;
  wire[output++] = 0u;
  wire[output++] = 0u;
  wire[output++] = 1u;
  wire[output++] = 0u;
  wire[output++] = 1u;
  *out_length = output;
  return FTUN_OK;
}

static ftun_status_t ftun_dns_runtime_resolve_upstream(
  const ftun_config_t *config, const char *text, uint32_t socket_mark,
  ftun_endpoint_t *out)
{
  uint8_t query[FTUN_DNS_HEADER_BYTES + FTUN_DNS_MAX_NAME_BYTES + 4u];
  uint8_t response[FTUN_BOOTSTRAP_MAX_RESPONSE_BYTES];
  ftun_endpoint_t bootstrap;
  ftun_dns_message_t *message = NULL;
  struct sockaddr_in address;
  const char *colon;
  char domain[254];
  char *tail = NULL;
  unsigned long port = 53u;
  size_t domain_length;
  size_t query_length = 0u;
  size_t index;
  ssize_t received;
  uint64_t deadline;
  int descriptor = -1;
  int flags;
  ftun_status_t status;
  if (config == NULL || text == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_dns_runtime_parse_endpoint(text, out);
  if (status == FTUN_OK) return FTUN_OK;
  if (status != FTUN_E_UNSUPPORTED) return status;
  colon = strrchr(text, ':');
  domain_length = colon == NULL ? strlen(text) : (size_t)(colon - text);
  if (domain_length == 0u || domain_length >= sizeof(domain)) {
    return FTUN_E_INVALID;
  }
  memcpy(domain, text, domain_length);
  domain[domain_length] = '\0';
  if (colon != NULL) {
    errno = 0;
    port = strtoul(colon + 1u, &tail, 10);
    if (errno != 0 || tail == colon + 1u || *tail != '\0' ||
        port == 0u || port > UINT16_MAX) return FTUN_E_INVALID;
  }
  status = ftun_dns_runtime_encode_bootstrap_query(domain, UINT16_C(0x4654),
    query, sizeof(query), &query_length);
  if (status != FTUN_OK) return status;
  status = ftun_dns_runtime_bootstrap_endpoint(config, &bootstrap);
  if (status != FTUN_OK) return status;
  descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (descriptor < 0) return ftun_blocking_socket_status(errno);
#if defined(SO_MARK)
  if (socket_mark != 0u) {
    if (setsockopt(descriptor, SOL_SOCKET, SO_MARK, &socket_mark,
                   (socklen_t)sizeof(socket_mark)) != 0) {
      status = ftun_blocking_socket_status(errno);
      goto done;
    }
  }
#endif
  flags = fcntl(descriptor, F_GETFL, 0);
  if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0) {
    status = FTUN_E_IO;
    goto done;
  }
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_port = htons(bootstrap.port);
  memcpy(&address.sin_addr.s_addr, bootstrap.address, 4u);
  if (connect(descriptor, (const struct sockaddr *)&address,
              (socklen_t)sizeof(address)) != 0 && errno != EINPROGRESS) {
    status = ftun_blocking_socket_status(errno);
    goto done;
  }
  if (ftun_monotonic_now(&deadline) != FTUN_OK ||
      deadline > UINT64_MAX - FTUN_DNS_RUNTIME_TIMEOUT_MS) {
    status = FTUN_E_IO;
    goto done;
  }
  deadline += FTUN_DNS_RUNTIME_TIMEOUT_MS;
  if (!ftun_blocking_socket_wait(descriptor, POLLOUT, deadline) ||
      !ftun_blocking_socket_send_all(descriptor, query, query_length, deadline) ||
      !ftun_blocking_socket_wait(descriptor, POLLIN, deadline)) {
    status = FTUN_E_TIMEOUT;
    goto done;
  }
  do {
    received = recv(descriptor, response, sizeof(response), 0);
  } while (received < 0 && errno == EINTR);
  if (received < 0) {
    status = ftun_blocking_socket_status(errno);
    goto done;
  }
  status = ftun_dns_message_parse(
    (ftun_bytes_t){response, (size_t)received}, &message);
  if (status != FTUN_OK) goto done;
  if (message->id != UINT16_C(0x4654) || (message->flags & 0x8000u) == 0u ||
      message->rcode != 0u || message->question.type != 1u ||
      message->question.class_code != 1u ||
      message->question.name.length + FTUN_DNS_HEADER_BYTES + 4u !=
        query_length ||
      memcmp(message->question.name.data, query + FTUN_DNS_HEADER_BYTES,
             message->question.name.length) != 0) {
    status = FTUN_E_PROTOCOL;
    goto done;
  }
  status = FTUN_E_RESOLVE;
  for (index = 0u; index < message->record_count; index++) {
    const ftun_dns_record_t *record = &message->records[index];
    if (record->section != FTUN_DNS_SECTION_ANSWER || record->type != 1u ||
        record->class_code != 1u || record->rdata.length != 4u) continue;
    memset(out, 0, sizeof(*out));
    out->kind = FTUN_ADDRESS_IPV4;
    out->port = (uint16_t)port;
    memcpy(out->address, record->rdata.data, 4u);
    status = FTUN_OK;
    break;
  }

done:
  (void)ftun_dns_message_release(&message);
  if (descriptor >= 0) (void)close(descriptor);
  return status;
}

ftun_status_t ftun_dns_runtime_plan_prepare(const ftun_config_t *config,
                                           uint32_t socket_mark,
                                           ftun_dns_runtime_plan_t **out)
{
  ftun_dns_runtime_plan_t *plan;
  size_t index;
  ftun_status_t status = FTUN_OK;
  if (out != NULL) *out = NULL;
  if (config == NULL || out == NULL) return FTUN_E_INVALID;
  plan = (ftun_dns_runtime_plan_t *)calloc(1u, sizeof(*plan));
  if (plan == NULL) return FTUN_E_LIMIT;
  if (!config->dns.enable) {
    *out = plan;
    return FTUN_OK;
  }
  plan->server_count = config->dns.server_count == 0u && config->dns.enable
    ? 1u : config->dns.server_count;
  plan->outbound_count = config->outbound_count;
  if (plan->server_count > FTUN_DNS_RUNTIME_MAX_SERVERS) status = FTUN_E_LIMIT;
  if (status == FTUN_OK && plan->outbound_count != 0u) {
    plan->proxies = (ftun_endpoint_t *)calloc(plan->outbound_count,
                                               sizeof(*plan->proxies));
    plan->proxy_valid = (uint8_t *)calloc(plan->outbound_count,
                                           sizeof(*plan->proxy_valid));
    if (plan->proxies == NULL || plan->proxy_valid == NULL) {
      status = FTUN_E_LIMIT;
    }
  }
  for (index = 0u; status == FTUN_OK && index < config->dns.server_count;
       index++) {
    if (config->dns.servers[index].addresses.count == 0u) {
      status = FTUN_E_INVALID;
    } else {
      status = ftun_dns_runtime_resolve_upstream(config,
        config->dns.servers[index].addresses.items[0], socket_mark,
        &plan->servers[index]);
    }
  }
  if (status == FTUN_OK && config->dns.enable &&
      config->dns.server_count == 0u) {
    status = ftun_dns_runtime_bootstrap_endpoint(config, &plan->servers[0]);
  }
  for (index = 0u; status == FTUN_OK && index < config->outbound_count;
       index++) {
    const ftun_config_outbound_t *item = &config->outbounds[index];
    if (item->kind != FTUN_CONFIG_OUTBOUND_SOCKS5) continue;
    status = ftun_dns_runtime_resolve_upstream(config, item->server,
      socket_mark, &plan->proxies[index]);
    if (status == FTUN_OK) plan->proxy_valid[index] = 1u;
  }
  if (status != FTUN_OK) {
    (void)ftun_dns_runtime_plan_destroy(&plan);
    return status;
  }
  *out = plan;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_plan_destroy(ftun_dns_runtime_plan_t **plan_ptr)
{
  ftun_dns_runtime_plan_t *plan;
  if (plan_ptr == NULL) return FTUN_E_INVALID;
  plan = *plan_ptr;
  if (plan == NULL) return FTUN_OK;
  free(plan->proxies);
  free(plan->proxy_valid);
  memset(plan, 0, sizeof(*plan));
  free(plan);
  *plan_ptr = NULL;
  return FTUN_OK;
}

static ftun_status_t ftun_dns_runtime_outbound_id(
  const ftun_config_t *config, const char *name, uint32_t *out)
{
  size_t index;
  if (strcmp(name, "DIRECT") == 0) {
    *out = FTUN_DNS_OUTBOUND_DIRECT;
    return FTUN_OK;
  }
  if (strcmp(name, "REJECT") == 0) {
    *out = FTUN_DNS_OUTBOUND_REJECT;
    return FTUN_OK;
  }
  for (index = 0u; index < config->outbound_count; index++) {
    if (strcmp(config->outbounds[index].name, name) == 0) {
      *out = (uint32_t)index + FTUN_DNS_OUTBOUND_NAMED_BASE;
      return FTUN_OK;
    }
  }
  return FTUN_E_INVALID;
}

static ftun_status_t ftun_dns_runtime_named_index(ftun_string_t name,
                                                  size_t *out, void *user)
{
  ftun_dns_runtime_t *dns = (ftun_dns_runtime_t *)user;
  size_t index;
  for (index = 0u; index < dns->config->dns.server_count; index++) {
    const char *candidate = dns->config->dns.servers[index].name;
    if (strlen(candidate) == name.length &&
        memcmp(candidate, name.data, name.length) == 0) {
      *out = index;
      return FTUN_OK;
    }
  }
  return FTUN_E_INVALID;
}

static ftun_status_t ftun_dns_runtime_select(uint32_t outbound_id,
                                             size_t *out, void *user)
{
  ftun_dns_runtime_t *dns = (ftun_dns_runtime_t *)user;
  if (outbound_id >= FTUN_DNS_OUTBOUND_NAMED_BASE) {
    size_t index = outbound_id - FTUN_DNS_OUTBOUND_NAMED_BASE;
    if (index < dns->config->outbound_count) {
      const char *name = dns->config->outbounds[index].dns_server;
      if (name != NULL && name[0] != '\0') {
        return ftun_dns_runtime_named_index(
          (ftun_string_t){name, strlen(name)}, out, user);
      }
    }
  }
  *out = dns->default_server;
  return FTUN_OK;
}

static ftun_dns_runtime_pending_t *ftun_dns_runtime_pending(
  ftun_dns_runtime_t *dns, uint64_t id)
{
  size_t index;
  for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_PENDING; index++) {
    if (dns->pending[index].active && dns->pending[index].id == id) {
      return &dns->pending[index];
    }
  }
  return NULL;
}

static void ftun_dns_runtime_pending_clear(ftun_dns_runtime_t *dns,
                                          ftun_dns_runtime_pending_t *pending)
{
  if (pending == NULL || !pending->active) return;
  if (pending->listener_index < dns->listener_count &&
      dns->listeners[pending->listener_index].pending_count != 0u) {
    dns->listeners[pending->listener_index].pending_count--;
  }
  if (dns->pending_count != 0u) dns->pending_count--;
  memset(pending, 0, sizeof(*pending));
  pending->descriptor = -1;
  pending->listener_index = SIZE_MAX;
}

static ftun_dns_runtime_tcp_t *ftun_dns_runtime_tcp_find(
  ftun_dns_runtime_t *dns, uint64_t peer_id)
{
  size_t index;
  for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS; index++) {
    if (dns->tcp[index].active && dns->tcp[index].peer_id == peer_id) {
      return &dns->tcp[index];
    }
  }
  return NULL;
}

static void ftun_dns_runtime_reply(ftun_dns_transport_t transport,
                                  uint64_t peer_id, ftun_error_t error,
                                  ftun_bytes_t response, void *user)
{
  ftun_dns_runtime_t *dns = (ftun_dns_runtime_t *)user;
  ftun_dns_runtime_pending_t *pending = ftun_dns_runtime_pending(dns, peer_id);
  if (transport == FTUN_DNS_TRANSPORT_TCP) {
    ftun_dns_runtime_tcp_t *connection = ftun_dns_runtime_tcp_find(dns, peer_id);
    ftun_dns_runtime_response_t *queued;
    ftun_reservation_t *reservation = NULL;
    size_t bytes;
    if (connection == NULL) return;
    if (error.status != FTUN_OK || response.data == NULL ||
        response.length < 2u || response.length > FTUN_DNS_MAX_MESSAGE_BYTES + 2u ||
        connection->response_count >= 4u ||
        response.length > SIZE_MAX - offsetof(ftun_dns_runtime_response_t,
                                               data)) {
      connection->peer_eof = true;
      connection->ready = true;
      return;
    }
    bytes = offsetof(ftun_dns_runtime_response_t, data) + response.length;
    if (ftun_budget_reserve(dns->budget, bytes, &reservation) != FTUN_OK) {
      connection->peer_eof = true;
      connection->ready = true;
      return;
    }
    queued = (ftun_dns_runtime_response_t *)malloc(bytes);
    if (queued == NULL) {
      (void)ftun_reservation_release(&reservation);
      connection->peer_eof = true;
      connection->ready = true;
      return;
    }
    memset(queued, 0, offsetof(ftun_dns_runtime_response_t, data));
    queued->reservation = reservation;
    queued->length = response.length;
    memcpy(queued->data, response.data, response.length);
    if (connection->response_tail != NULL) {
      connection->response_tail->next = queued;
    } else {
      connection->response_head = queued;
    }
    connection->response_tail = queued;
    connection->response_count++;
    connection->ready = true;
    return;
  }
  if (pending == NULL) return;
  if (error.status == FTUN_OK && transport == FTUN_DNS_TRANSPORT_UDP) {
    if (pending->kind == FTUN_DNS_RUNTIME_PENDING_SOCKET) {
      (void)sendto(pending->descriptor, response.data, response.length, 0,
        (const struct sockaddr *)&pending->peer, pending->peer_length);
    } else {
      ftun_buffer_t *buffer = NULL;
      ftun_buffer_slice_t slice;
      ftun_packet_t packet;
      uint8_t *storage = NULL;
      size_t capacity = 0u;
      memset(&slice, 0, sizeof(slice));
      memset(&packet, 0, sizeof(packet));
      if (ftun_buffer_acquire(dns->budget, response.length, &buffer) == FTUN_OK &&
          ftun_buffer_data(buffer, &storage, &capacity) == FTUN_OK &&
          capacity >= response.length) {
        memcpy(storage, response.data, response.length);
        if (ftun_buffer_slice(buffer, 0u, response.length, &slice) == FTUN_OK &&
            ftun_packet_init(&packet, &slice, 0u) == FTUN_OK) {
          (void)ftun_datagram_send(pending->inbound, &pending->client, &packet);
          (void)ftun_packet_release(&packet);
        }
      }
      (void)ftun_buffer_slice_release(&slice);
      (void)ftun_buffer_release(&buffer);
    }
  }
  ftun_dns_runtime_pending_clear(dns, pending);
}

static ftun_dns_runtime_pending_t *ftun_dns_runtime_pending_new(
  ftun_dns_runtime_t *dns, size_t listener_index)
{
  size_t scanned;
  if (dns->pending_count >= FTUN_DNS_RUNTIME_MAX_PENDING ||
      (listener_index < dns->listener_count &&
       dns->listeners[listener_index].pending_count >=
         FTUN_DNS_RUNTIME_MAX_PENDING_PER_LISTENER)) return NULL;
  for (scanned = 0u; scanned < FTUN_DNS_RUNTIME_MAX_PENDING; scanned++) {
    size_t index = (dns->pending_cursor + scanned) %
                   FTUN_DNS_RUNTIME_MAX_PENDING;
    ftun_dns_runtime_pending_t *pending = &dns->pending[index];
    if (pending->active) continue;
    memset(pending, 0, sizeof(*pending));
    pending->descriptor = -1;
    pending->listener_index = listener_index;
    pending->active = true;
    dns->pending_cursor = (index + 1u) % FTUN_DNS_RUNTIME_MAX_PENDING;
    dns->pending_count++;
    if (listener_index < dns->listener_count) {
      dns->listeners[listener_index].pending_count++;
    }
    dns->next_peer_id++;
    if (dns->next_peer_id == 0u) dns->next_peer_id++;
    pending->id = dns->next_peer_id;
    return pending;
  }
  return NULL;
}

static ftun_status_t ftun_dns_runtime_protocol_create(
  ftun_dns_runtime_t *dns, bool policy, size_t fixed_server,
  uint32_t inbound_id, ftun_dns_listener_t **out)
{
  ftun_dns_listener_spec_t spec;
  memset(&spec, 0, sizeof(spec));
  spec.budget = dns->budget;
  spec.dispatcher = dns->dispatcher;
  spec.dispatch = dns->adapter.dispatch != NULL
    ? dns->adapter.dispatch : (policy ? NULL : ftun_dns_dispatch_fixed);
  spec.dispatch_user = dns->adapter.user;
  if (spec.dispatch == NULL) return FTUN_E_UNSUPPORTED;
  spec.entry = policy ? FTUN_DNS_ENTRY_POLICY : FTUN_DNS_ENTRY_FIXED;
  spec.fixed_server = fixed_server;
  spec.inbound_id = inbound_id;
  spec.query_timeout_ms = FTUN_DNS_RUNTIME_TIMEOUT_MS;
  spec.udp_payload_limit = 4096u;
  spec.max_tcp_connections = 64u;
  spec.max_tcp_inflight = 4u;
  spec.max_tcp_frame_bytes = FTUN_DNS_MAX_MESSAGE_BYTES;
  spec.reply = ftun_dns_runtime_reply;
  spec.reply_user = dns;
  return ftun_dns_listen(dns->core, &spec, out);
}

static ftun_status_t ftun_dns_runtime_socket_open(const char *text,
                                                  int type, int *out)
{
  ftun_endpoint_t endpoint;
  struct sockaddr_in address;
  int descriptor;
  ftun_status_t status = ftun_dns_runtime_parse_endpoint(text, &endpoint);
  if (status != FTUN_OK) return status;
  int one = 1;
  descriptor = socket(AF_INET, type | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (descriptor < 0) return ftun_blocking_socket_status(errno);
  (void)setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_port = htons(endpoint.port);
  memcpy(&address.sin_addr.s_addr, endpoint.address, 4u);
  if (bind(descriptor, (const struct sockaddr *)&address,
           (socklen_t)sizeof(address)) != 0 ||
      (type == SOCK_STREAM && listen(descriptor, 64) != 0)) {
    status = ftun_blocking_socket_status(errno);
    (void)close(descriptor);
    return status;
  }
  *out = descriptor;
  return FTUN_OK;
}

static ftun_status_t ftun_dns_runtime_prepare_internal(
  ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations, ftun_event_loop_t *loop,
  const ftun_config_t *config, const ftun_dns_runtime_adapter_t *adapter,
  uint32_t socket_mark, bool bind_sockets,
  const ftun_dns_runtime_plan_t *plan, ftun_dns_runtime_t **out)
{
  ftun_dns_runtime_t *dns;
  ftun_reservation_t *listener_reservation = NULL;
  ftun_budget_resources_t listener_resources = {0u, 0u, 0u};
  ftun_dns_dispatcher_options_t dispatcher;
  ftun_dns_cache_options_t cache;
  ftun_dns_server_options_t server;
  ftun_dns_query_transport_t transport;
  size_t index;
  ftun_status_t status = FTUN_OK;
  if (out != NULL) *out = NULL;
  if (core == NULL || budget == NULL || operations == NULL || loop == NULL ||
      config == NULL || out == NULL) return FTUN_E_INVALID;
  if (!config->dns.enable) return FTUN_OK;
  if (plan != NULL && (plan->server_count !=
      (config->dns.server_count == 0u ? 1u : config->dns.server_count) ||
      plan->outbound_count != config->outbound_count)) return FTUN_E_STALE;
  if (config->dns.server_count > FTUN_DNS_RUNTIME_MAX_SERVERS ||
      config->dns.listener_count > FTUN_DNS_RUNTIME_MAX_LISTENERS) {
    return FTUN_E_LIMIT;
  }
  /* UDP/TCP socket 与对应事件源在重载 prepare 期间和旧代并存。每个 DNS
   * 实例独立持有这份额度，因而只有完整的新代额度获批后才会打开 fd。 */
  listener_resources.descriptors = config->dns.listener_count * 2u;
  listener_resources.queue_slots = config->dns.listener_count * 2u;
  if (config->dns.listener_count != 0u) {
    status = ftun_budget_reserve_resources(budget, listener_resources,
                                            &listener_reservation);
  }
  if (status != FTUN_OK) return status;
  dns = (ftun_dns_runtime_t *)calloc(1u, sizeof(*dns));
  if (dns == NULL) {
    (void)ftun_reservation_release(&listener_reservation);
    return FTUN_E_LIMIT;
  }
  dns->core = core;
  dns->budget = budget;
  dns->listener_reservation = listener_reservation;
  dns->operations = operations;
  dns->loop = loop;
  if (adapter != NULL) dns->adapter = *adapter;
  dns->socket_mark = socket_mark;
  status = ftun_config_retain((ftun_config_t *)config);
  if (status != FTUN_OK) {
    free(dns);
    return status;
  }
  dns->config = (ftun_config_t *)config;
  if (config->outbound_count != 0u) {
    dns->proxy_endpoints = (ftun_endpoint_t *)calloc(config->outbound_count,
      sizeof(*dns->proxy_endpoints));
    dns->proxy_endpoint_valid = (uint8_t *)calloc(config->outbound_count,
      sizeof(*dns->proxy_endpoint_valid));
    if (dns->proxy_endpoints == NULL || dns->proxy_endpoint_valid == NULL) {
      status = FTUN_E_LIMIT;
    }
  }
  for (index = 0u; status == FTUN_OK && index < config->outbound_count;
       index++) {
    const ftun_config_outbound_t *item = &config->outbounds[index];
    if (item->kind != FTUN_CONFIG_OUTBOUND_SOCKS5) continue;
    if (plan != NULL) {
      if (plan->proxy_valid[index] == 0u) status = FTUN_E_RESOLVE;
      else {
        dns->proxy_endpoints[index] = plan->proxies[index];
        dns->proxy_endpoint_valid[index] = 1u;
      }
    } else {
      status = ftun_dns_runtime_resolve_upstream(config, item->server,
        socket_mark, &dns->proxy_endpoints[index]);
      if (status == FTUN_OK) dns->proxy_endpoint_valid[index] = 1u;
    }
  }
  for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_LISTENERS; index++) {
    dns->listeners[index].dns = dns;
    dns->listeners[index].descriptor = -1;
    dns->listeners[index].tcp_descriptor = -1;
  }
  for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_PENDING; index++) {
    dns->pending[index].descriptor = -1;
    dns->pending[index].listener_index = SIZE_MAX;
  }
  for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS; index++) {
    dns->tcp[index].dns = dns;
    dns->tcp[index].descriptor = -1;
  }
  memset(&transport, 0, sizeof(transport));
  transport.submit = ftun_dns_runtime_transport_submit;
  transport.cancel = ftun_dns_runtime_transport_cancel;
  transport.context = dns;
  if (config->dns.cache) {
    memset(&cache, 0, sizeof(cache));
    cache.budget = budget;
    cache.max_entries = 1024u;
    cache.now = ftun_dns_runtime_now;
    status = ftun_dns_cache_create(&cache, &dns->cache);
  }
  for (index = 0u; status == FTUN_OK &&
       index < config->dns.server_count; index++) {
    const ftun_config_dns_server_t *item = &config->dns.servers[index];
    uint32_t outbound_id;
    if (item->addresses.count == 0u) {
      status = FTUN_E_INVALID;
      break;
    }
    memset(&server, 0, sizeof(server));
    server.budget = budget;
    server.operations = operations;
    if (plan != NULL) server.upstream = plan->servers[index];
    else status = ftun_dns_runtime_resolve_upstream(config,
      item->addresses.items[0], socket_mark, &server.upstream);
    if (status != FTUN_OK) break;
    status = ftun_dns_runtime_outbound_id(config, item->outbound,
                                         &outbound_id);
    if (status != FTUN_OK) break;
    server.outbound_id = outbound_id;
    server.fingerprint = (uint64_t)index + 1u;
    server.transport = strcmp(item->type, "tcp") == 0
      ? FTUN_DNS_TRANSPORT_TCP : FTUN_DNS_TRANSPORT_UDP;
    server.tcp_fallback = true;
    server.fakeip = item->fake_ip;
    server.max_response_bytes = FTUN_DNS_MAX_MESSAGE_BYTES;
    server.query_transport = transport;
    server.cache = dns->cache;
    server.now = ftun_dns_runtime_now;
    status = ftun_dns_server_create(&server, &dns->servers[index]);
    if (status != FTUN_OK) break;
    dns->server_count++;
  }
  if (status == FTUN_OK && config->dns.server_count == 0u) {
    uint32_t outbound_id = FTUN_DNS_OUTBOUND_DIRECT;
    memset(&server, 0, sizeof(server));
    server.budget = budget;
    server.operations = operations;
    if (plan != NULL) server.upstream = plan->servers[0];
    else status = ftun_dns_runtime_bootstrap_endpoint(config, &server.upstream);
    server.outbound_id = outbound_id;
    server.fingerprint = UINT64_C(0x42535450);
    server.transport = FTUN_DNS_TRANSPORT_UDP;
    server.tcp_fallback = true;
    server.max_response_bytes = FTUN_DNS_MAX_MESSAGE_BYTES;
    server.query_transport = transport;
    server.cache = dns->cache;
    server.now = ftun_dns_runtime_now;
    if (status == FTUN_OK) {
      status = ftun_dns_server_create(&server, &dns->servers[0]);
    }
    if (status == FTUN_OK) dns->server_count = 1u;
  }
  if (status == FTUN_OK && config->dns.default_server[0] != '\0') {
    status = ftun_dns_runtime_named_index(
      (ftun_string_t){config->dns.default_server,
                      strlen(config->dns.default_server)},
      &dns->default_server, dns);
  }
  memset(&dispatcher, 0, sizeof(dispatcher));
  if (status == FTUN_OK) {
    dispatcher.budget = budget;
    dispatcher.operations = operations;
    dispatcher.servers = dns->servers;
    dispatcher.server_count = dns->server_count;
    dispatcher.select_server = ftun_dns_runtime_select;
    dispatcher.select_named_server = ftun_dns_runtime_named_index;
    dispatcher.select_user = dns;
    status = ftun_dns_dispatcher_create(&dispatcher, &dns->dispatcher);
  }
  for (index = 0u; status == FTUN_OK &&
       index < config->dns.listener_count; index++) {
    const ftun_config_dns_listener_t *item = &config->dns.listeners[index];
    ftun_dns_runtime_listener_slot_t *slot = &dns->listeners[index];
    size_t fixed = dns->default_server;
    bool policy = item->server == NULL || item->server[0] == '\0';
    if (!policy) {
      status = ftun_dns_runtime_named_index(
        (ftun_string_t){item->server, strlen(item->server)}, &fixed, dns);
    }
    if (status == FTUN_OK && bind_sockets) {
      status = ftun_dns_runtime_socket_open(item->listen, SOCK_DGRAM,
                                           &slot->descriptor);
    }
    if (status == FTUN_OK && bind_sockets) {
      status = ftun_dns_runtime_socket_open(item->listen, SOCK_STREAM,
                                           &slot->tcp_descriptor);
    }
    if (status == FTUN_OK) {
      status = ftun_dns_runtime_protocol_create(dns, policy, fixed,
        (uint32_t)index + UINT32_C(0x10000), &slot->protocol);
    }
    slot->fixed_server = fixed;
    slot->policy = policy;
    if (status == FTUN_OK) dns->listener_count++;
  }
  if (status == FTUN_OK) {
    for (index = 0u; index < config->inbound_count; index++) {
      if (config->inbounds[index].kind == FTUN_CONFIG_INBOUND_TUN &&
          config->inbounds[index].dns_hijack) {
        status = ftun_dns_runtime_protocol_create(dns, true,
          dns->default_server, (uint32_t)index + 1u, &dns->hijack);
        break;
      }
    }
  }
  if (status != FTUN_OK) {
    (void)ftun_dns_runtime_destroy(&dns);
    return status;
  }
  *out = dns;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_prepare(
  ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations, ftun_event_loop_t *loop,
  const ftun_config_t *config, const ftun_dns_runtime_adapter_t *adapter,
  uint32_t socket_mark,
  ftun_dns_runtime_t **out)
{
  return ftun_dns_runtime_prepare_internal(core, budget, operations, loop,
                                           config, adapter, socket_mark,
                                           true, NULL, out);
}

static ftun_status_t ftun_dns_runtime_idle(const ftun_dns_runtime_t *dns)
{
  ftun_dns_dispatcher_info_t dispatcher;
  size_t index;
  if (dns == NULL) return FTUN_OK;
  if (dns->dispatcher != NULL) {
    if (ftun_dns_dispatcher_get_info(dns->dispatcher, &dispatcher) != FTUN_OK) {
      return FTUN_E_STATE_CORRUPT;
    }
    if (dispatcher.inflight_local != 0u) return FTUN_E_AGAIN;
  }
  for (index = 0u; index < dns->server_count; index++) {
    ftun_dns_server_info_t server;
    if (ftun_dns_server_get_info(dns->servers[index], &server) != FTUN_OK) {
      return FTUN_E_STATE_CORRUPT;
    }
    if (server.inflight != 0u) return FTUN_E_AGAIN;
  }
  for (index = 0u; index < dns->listener_count; index++) {
    ftun_dns_listener_info_t listener;
    if (ftun_dns_listener_get_info(dns->listeners[index].protocol,
                                   &listener) != FTUN_OK) {
      return FTUN_E_STATE_CORRUPT;
    }
    if (listener.inflight != 0u || listener.tcp_connections != 0u) {
      return FTUN_E_AGAIN;
    }
  }
  if (dns->pending_count != 0u) return FTUN_E_AGAIN;
  return FTUN_OK;
}

static int ftun_dns_runtime_listener_reusable(
  const ftun_dns_runtime_t *dns, const char *listen, size_t *out_index)
{
  size_t index;
  if (dns == NULL || listen == NULL) return 0;
  for (index = 0u; index < dns->listener_count; index++) {
    const char *candidate = dns->config->dns.listeners[index].listen;
    if (candidate != NULL && strcmp(candidate, listen) == 0) {
      if (out_index != NULL) *out_index = index;
      return 1;
    }
  }
  return 0;
}

static ftun_status_t ftun_dns_runtime_socket_duplicate(int descriptor,
                                                       int *out)
{
  int duplicate;
  if (descriptor < 0 || out == NULL) return FTUN_E_INVALID;
  duplicate = fcntl(descriptor, F_DUPFD_CLOEXEC, 0);
  if (duplicate < 0) return ftun_blocking_socket_status(errno);
  *out = duplicate;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_prepare_reload_planned(
  const ftun_dns_runtime_t *active, ftun_core_t *core,
  ftun_budget_t *budget, ftun_operation_queue_t *operations,
  ftun_event_loop_t *loop,
  const ftun_config_t *config, const ftun_dns_runtime_adapter_t *adapter,
  uint32_t socket_mark,
  const ftun_dns_runtime_plan_t *plan,
  ftun_dns_runtime_t **out)
{
  ftun_dns_runtime_t *prepared = NULL;
  size_t index;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core == NULL || budget == NULL || operations == NULL || loop == NULL ||
      config == NULL || out == NULL) return FTUN_E_INVALID;
  if (!config->dns.enable) return FTUN_OK;
  if (active == NULL) {
    status = ftun_dns_runtime_prepare_internal(core, budget, operations, loop,
                                              config, adapter, socket_mark,
                                              true, plan,
                                              &prepared);
    if (status == FTUN_OK) {
      status = ftun_dns_runtime_listener_sources_start(prepared);
      if (status == FTUN_OK) prepared->sources_prepared = true;
    }
    if (status != FTUN_OK) {
      (void)ftun_dns_runtime_destroy(&prepared);
      return status;
    }
    *out = prepared;
    return FTUN_OK;
  }
  status = ftun_dns_runtime_prepare_internal(core, budget, operations, loop,
                                             config, adapter, socket_mark,
                                             false, plan, &prepared);
  for (index = 0u; status == FTUN_OK &&
       index < prepared->listener_count; index++) {
    const char *listen = config->dns.listeners[index].listen;
    ftun_dns_runtime_listener_slot_t *slot = &prepared->listeners[index];
    size_t old_index;
    if (ftun_dns_runtime_listener_reusable(active, listen, &old_index)) {
      status = ftun_dns_runtime_socket_duplicate(
        active->listeners[old_index].descriptor, &slot->descriptor);
      if (status == FTUN_OK) {
        status = ftun_dns_runtime_socket_duplicate(
          active->listeners[old_index].tcp_descriptor,
          &slot->tcp_descriptor);
      }
    } else {
      status = ftun_dns_runtime_socket_open(listen, SOCK_DGRAM,
                                           &slot->descriptor);
      if (status == FTUN_OK) {
        status = ftun_dns_runtime_socket_open(listen, SOCK_STREAM,
                                             &slot->tcp_descriptor);
      }
    }
  }
  if (status == FTUN_OK) {
    status = ftun_dns_runtime_listener_sources_start(prepared);
    if (status == FTUN_OK) prepared->sources_prepared = true;
  }
  if (status != FTUN_OK) {
    (void)ftun_dns_runtime_destroy(&prepared);
    return status;
  }
  *out = prepared;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_prepare_reload(
  const ftun_dns_runtime_t *active, ftun_core_t *core,
  ftun_budget_t *budget, ftun_operation_queue_t *operations,
  ftun_event_loop_t *loop,
  const ftun_config_t *config, const ftun_dns_runtime_adapter_t *adapter,
  uint32_t socket_mark,
  ftun_dns_runtime_t **out)
{
  return ftun_dns_runtime_prepare_reload_planned(active, core, budget,
    operations, loop, config, adapter, socket_mark, NULL, out);
}

ftun_status_t ftun_dns_runtime_quiesce(ftun_dns_runtime_t *dns)
{
  size_t index;
  ftun_status_t result = FTUN_OK;
  if (dns == NULL) return FTUN_OK;
  dns->accepting = false;
  dns->active = false;
  for (index = 0u; index < dns->listener_count; index++) {
    ftun_status_t status = ftun_event_source_cancel(
      &dns->listeners[index].source);
    if (status != FTUN_OK && result == FTUN_OK) result = status;
    status = ftun_event_source_cancel(&dns->listeners[index].tcp_source);
    if (status != FTUN_OK && result == FTUN_OK) result = status;
    dns->listeners[index].events = 0u;
    dns->listeners[index].tcp_events = 0u;
    /* UDP fd 还是已接收请求的回复通道；等旧代 inflight 清零再关闭。 */
    if (dns->listeners[index].tcp_descriptor >= 0) {
      (void)close(dns->listeners[index].tcp_descriptor);
      dns->listeners[index].tcp_descriptor = -1;
    }
    (void)ftun_dns_listener_stop(dns->listeners[index].protocol);
  }
  (void)ftun_dns_listener_stop(dns->hijack);
  for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS; index++) {
    if (dns->tcp[index].active) {
      /* 已接收的请求继续完成并发送回复，但不再读取下一帧。 */
      dns->tcp[index].peer_eof = true;
      dns->tcp[index].ready = true;
    }
  }
  dns->sources_prepared = false;
  return result;
}

ftun_status_t ftun_dns_runtime_commit_reload(ftun_dns_runtime_t **active_ptr,
                                             ftun_dns_runtime_t **prepared_ptr,
                                             ftun_dns_runtime_t **retired_ptr)
{
  ftun_dns_runtime_t *active;
  ftun_dns_runtime_t *prepared;
  ftun_status_t status;
  if (active_ptr == NULL || prepared_ptr == NULL || retired_ptr == NULL ||
      *retired_ptr != NULL) return FTUN_E_INVALID;
  active = *active_ptr;
  prepared = *prepared_ptr;
  if (prepared != NULL && !prepared->sources_prepared) {
    return FTUN_E_STATE_CORRUPT;
  }
  if (active != NULL) {
    status = ftun_dns_runtime_quiesce(active);
    if (status != FTUN_OK) return status;
  }
  if (prepared != NULL) {
    status = ftun_dns_runtime_activate(prepared);
    if (status != FTUN_OK) return status;
  }
  *retired_ptr = active;
  *active_ptr = prepared;
  *prepared_ptr = NULL;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_reap(ftun_dns_runtime_t **retired)
{
  ftun_status_t status;
  if (retired == NULL) return FTUN_E_INVALID;
  if (*retired == NULL) return FTUN_OK;
  status = ftun_dns_runtime_idle(*retired);
  if (status != FTUN_OK) return status;
  return ftun_dns_runtime_destroy(retired);
}

static ftun_status_t ftun_dns_runtime_listener_sources_start(
  ftun_dns_runtime_t *dns)
{
  size_t index;
  ftun_status_t status = FTUN_OK;
  for (index = 0u; status == FTUN_OK && index < dns->listener_count; index++) {
    ftun_dns_runtime_listener_slot_t *slot = &dns->listeners[index];
    if (slot->descriptor >= 0) {
      status = ftun_event_io_start(dns->loop,
        (ftun_native_socket_t)(unsigned int)slot->descriptor,
        FTUN_EVENT_READ | FTUN_EVENT_ERROR, ftun_dns_runtime_listener_ready,
        slot, &slot->source);
    }
    if (status == FTUN_OK && slot->tcp_descriptor >= 0) {
      status = ftun_event_io_start(dns->loop,
        (ftun_native_socket_t)(unsigned int)slot->tcp_descriptor,
        FTUN_EVENT_READ | FTUN_EVENT_ERROR,
        ftun_dns_runtime_listener_tcp_ready, slot, &slot->tcp_source);
    }
  }
  if (status != FTUN_OK) {
    for (index = 0u; index < dns->listener_count; index++) {
      (void)ftun_event_source_cancel(&dns->listeners[index].source);
      (void)ftun_event_source_cancel(&dns->listeners[index].tcp_source);
    }
  }
  return status;
}

ftun_status_t ftun_dns_runtime_activate(ftun_dns_runtime_t *dns)
{
  ftun_status_t status;
  if (dns == NULL) return FTUN_OK;
  status = dns->sources_prepared
    ? FTUN_OK : ftun_dns_runtime_listener_sources_start(dns);
  if (status == FTUN_OK) {
    dns->accepting = true;
    dns->active = true;
    dns->sources_prepared = true;
  } else {
    size_t index;
    for (index = 0u; index < dns->listener_count; index++) {
      (void)ftun_event_source_cancel(&dns->listeners[index].source);
      (void)ftun_event_source_cancel(&dns->listeners[index].tcp_source);
    }
  }
  return status;
}

static void ftun_dns_runtime_tcp_close(ftun_dns_runtime_tcp_t *connection)
{
  ftun_dns_runtime_record(connection->dns,
                         ftun_event_source_cancel(&connection->source));
  while (connection->response_head != NULL) {
    ftun_dns_runtime_response_t *response = connection->response_head;
    ftun_reservation_t *reservation = response->reservation;
    connection->response_head = response->next;
    free(response);
    (void)ftun_reservation_release(&reservation);
  }
  connection->response_tail = NULL;
  connection->response_count = 0u;
  free(connection->input);
  connection->input = NULL;
  (void)ftun_reservation_release(&connection->input_reservation);
  if (connection->descriptor >= 0) (void)close(connection->descriptor);
  connection->descriptor = -1;
  if (connection->protocol != NULL) {
    (void)ftun_dns_connection_close(&connection->protocol);
  }
  connection->active = false;
  connection->ready = false;
  connection->events = 0u;
}

static ftun_status_t ftun_dns_runtime_tcp_accept(
  ftun_dns_runtime_t *dns, ftun_dns_runtime_listener_slot_t *listener,
  size_t quota, size_t *out_accepted)
{
  uint64_t now_ms;
  size_t accepted = 0u;
  ftun_status_t status = ftun_monotonic_now(&now_ms);
  if (out_accepted != NULL) *out_accepted = 0u;
  if (dns == NULL || listener == NULL || quota == 0u ||
      out_accepted == NULL) return FTUN_E_INVALID;
  if (status != FTUN_OK) return status;
  if (now_ms < listener->accept_after_ms) return FTUN_OK;
  while (accepted < quota) {
    ftun_dns_runtime_tcp_t *connection = NULL;
    int descriptor;
    size_t index;
    descriptor = accept4(listener->tcp_descriptor, NULL, NULL,
                         SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (descriptor < 0 && errno == EINTR) continue;
    if (descriptor < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      return FTUN_OK;
    }
    if (descriptor < 0) {
      if (errno == ECONNABORTED || errno == EPROTO || errno == ENETDOWN ||
          errno == EHOSTDOWN || errno == ENONET || errno == EHOSTUNREACH ||
          errno == ENETUNREACH || errno == EOPNOTSUPP) {
        return FTUN_OK;
      }
      if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS ||
          errno == ENOMEM) {
        uint64_t delay = listener->accept_backoff_ms == 0u
          ? FTUN_DNS_RUNTIME_ACCEPT_BACKOFF_MIN_MS
          : listener->accept_backoff_ms;
        if (delay > FTUN_DNS_RUNTIME_ACCEPT_BACKOFF_MAX_MS) {
          delay = FTUN_DNS_RUNTIME_ACCEPT_BACKOFF_MAX_MS;
        }
        listener->accept_after_ms = now_ms > UINT64_MAX - delay
          ? UINT64_MAX : now_ms + delay;
        listener->accept_backoff_ms =
          delay >= FTUN_DNS_RUNTIME_ACCEPT_BACKOFF_MAX_MS / 2u
          ? FTUN_DNS_RUNTIME_ACCEPT_BACKOFF_MAX_MS : delay * 2u;
        status = listener->tcp_source == NULL ? FTUN_OK
          : ftun_event_io_update(listener->tcp_source, FTUN_EVENT_ERROR);
        return status;
      }
      return ftun_blocking_socket_status(errno);
    }
    listener->accept_after_ms = 0u;
    listener->accept_backoff_ms = 0u;
    accepted++;
    *out_accepted = accepted;
    for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS; index++) {
      if (!dns->tcp[index].active) {
        connection = &dns->tcp[index];
        break;
      }
    }
    if (connection == NULL) {
      (void)close(descriptor);
      return FTUN_OK;
    }
    memset(connection, 0, sizeof(*connection));
    connection->dns = dns;
    connection->descriptor = descriptor;
    connection->active = true;
    dns->next_peer_id++;
    if (dns->next_peer_id == 0u) dns->next_peer_id++;
    connection->peer_id = dns->next_peer_id;
    if (ftun_dns_listener_tcp_open(listener->protocol, connection->peer_id,
                                   &connection->protocol) != FTUN_OK) {
      ftun_dns_runtime_tcp_close(connection);
    } else {
      status = ftun_event_io_start(dns->loop,
        (ftun_native_socket_t)(unsigned int)descriptor,
        FTUN_EVENT_READ | FTUN_EVENT_ERROR, ftun_dns_runtime_tcp_ready,
        connection, &connection->source);
      if (status != FTUN_OK) {
        ftun_dns_runtime_tcp_close(connection);
        return status;
      }
      connection->ready = true;
    }
  }
  *out_accepted = accepted;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_hijack_tcp(ftun_dns_runtime_t *dns,
                                         int descriptor)
{
  ftun_dns_runtime_tcp_t *connection = NULL;
  size_t index;
  ftun_status_t status;
  if (dns == NULL || descriptor < 0 || !dns->accepting ||
      dns->hijack == NULL) return FTUN_E_INVALID;
  for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS; index++) {
    if (!dns->tcp[index].active) {
      connection = &dns->tcp[index];
      break;
    }
  }
  if (connection == NULL) return FTUN_E_LIMIT;
  memset(connection, 0, sizeof(*connection));
  connection->dns = dns;
  connection->descriptor = descriptor;
  connection->active = true;
  dns->next_peer_id++;
  if (dns->next_peer_id == 0u) dns->next_peer_id++;
  connection->peer_id = dns->next_peer_id;
  status = ftun_dns_listener_tcp_open(dns->hijack, connection->peer_id,
                                      &connection->protocol);
  if (status != FTUN_OK) {
    connection->descriptor = -1;
    connection->active = false;
  } else {
    status = ftun_event_io_start(dns->loop,
      (ftun_native_socket_t)(unsigned int)descriptor,
      FTUN_EVENT_READ | FTUN_EVENT_ERROR, ftun_dns_runtime_tcp_ready,
      connection, &connection->source);
    if (status != FTUN_OK) {
      ftun_dns_runtime_tcp_close(connection);
    } else {
      connection->ready = true;
    }
  }
  return status;
}

static ftun_status_t ftun_dns_runtime_tcp_drive(
  ftun_dns_runtime_t *dns, ftun_dns_runtime_tcp_t *connection)
{
  if (connection->response_head != NULL) {
    ftun_dns_runtime_response_t *response = connection->response_head;
    ssize_t sent;
    do {
      sent = send(connection->descriptor,
        response->data + response->offset,
        response->length - response->offset,
        MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    if (sent > 0) {
      response->offset += (size_t)sent;
      if (response->offset == response->length) {
        ftun_reservation_t *reservation = response->reservation;
        connection->response_head = response->next;
        if (connection->response_head == NULL) {
          connection->response_tail = NULL;
        }
        if (connection->response_count != 0u) connection->response_count--;
        free(response);
        (void)ftun_reservation_release(&reservation);
      }
    } else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
      connection->peer_eof = true;
    }
  }
  if (!connection->peer_eof) {
    ssize_t received;
    if (connection->input == NULL && connection->prefix_length < 2u) {
      do {
        received = recv(connection->descriptor,
          connection->prefix + connection->prefix_length,
          2u - connection->prefix_length, 0);
      } while (received < 0 && errno == EINTR);
      if (received > 0) connection->prefix_length += (size_t)received;
      else if (received == 0) connection->peer_eof = true;
      else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        connection->peer_eof = true;
      }
      if (connection->prefix_length == 2u) {
        size_t payload = ((size_t)connection->prefix[0] << 8u) |
                         connection->prefix[1];
        if (payload == 0u || payload > FTUN_DNS_MAX_MESSAGE_BYTES ||
            ftun_budget_reserve(dns->budget, payload + 2u,
              &connection->input_reservation) != FTUN_OK) {
          connection->peer_eof = true;
        } else {
          connection->input = (uint8_t *)malloc(payload + 2u);
          if (connection->input == NULL) {
            (void)ftun_reservation_release(&connection->input_reservation);
            connection->peer_eof = true;
          } else {
            memcpy(connection->input, connection->prefix, 2u);
            connection->input_offset = 2u;
            connection->input_length = payload + 2u;
          }
        }
      }
    }
    if (!connection->peer_eof && connection->input != NULL &&
        connection->input_offset < connection->input_length) {
      do {
        received = recv(connection->descriptor,
          connection->input + connection->input_offset,
          connection->input_length - connection->input_offset, 0);
      } while (received < 0 && errno == EINTR);
      if (received > 0) connection->input_offset += (size_t)received;
      else if (received == 0) connection->peer_eof = true;
      else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        connection->peer_eof = true;
      }
    }
    if (!connection->peer_eof && connection->input != NULL &&
        connection->input_offset == connection->input_length) {
      size_t consumed = 0u;
      size_t frames = 0u;
      ftun_status_t status = ftun_dns_connection_feed(connection->protocol,
        (ftun_bytes_t){connection->input, connection->input_length},
        &consumed, &frames);
      if (status == FTUN_OK && consumed == connection->input_length &&
          frames == 1u) {
        free(connection->input);
        connection->input = NULL;
        (void)ftun_reservation_release(&connection->input_reservation);
        connection->input_offset = 0u;
        connection->input_length = 0u;
        connection->prefix_length = 0u;
      } else if (status != FTUN_E_LIMIT) {
        connection->peer_eof = true;
      }
    }
  }
  if (connection->peer_eof && connection->response_head == NULL) {
    ftun_status_t status = ftun_dns_connection_close(&connection->protocol);
    if (status == FTUN_OK) ftun_dns_runtime_tcp_close(connection);
    else if (status != FTUN_E_AGAIN) return status;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_dns_runtime_step_request(ftun_dns_runtime_t *dns,
                                                  bool *out_work)
{
  ftun_dns_runtime_transport_request_t *request = dns->ready_request_head;
  ftun_status_t status;
  *out_work = false;
  if (request == NULL) return FTUN_OK;
  ftun_dns_runtime_request_ready_remove(request);
  request->events = 0u;
  status = ftun_dns_runtime_request_drive(request);
  *out_work = true;
  if (status != FTUN_E_AGAIN) {
    ftun_dns_runtime_request_finish(request, status);
    return FTUN_OK;
  }
  return ftun_dns_runtime_request_source_update(request);
}

static ftun_status_t ftun_dns_runtime_step_deadline(ftun_dns_runtime_t *dns,
                                                   uint64_t now_ms,
                                                   bool *out_work)
{
  ftun_dns_runtime_transport_waiter_t *waiter;
  ftun_dns_runtime_transport_request_t *request;
  *out_work = false;
  if (dns->waiter_count == 0u ||
      dns->waiter_heap[0]->deadline_ms > now_ms) return FTUN_OK;
  waiter = dns->waiter_heap[0];
  request = waiter->request;
  ftun_dns_runtime_waiter_finish(waiter, FTUN_E_TIMEOUT,
                                (ftun_bytes_t){NULL, 0u});
  if (request->waiter_head == NULL) {
    ftun_dns_runtime_request_unlink(request);
    ftun_dns_runtime_request_release(request);
  }
  *out_work = true;
  return FTUN_OK;
}

static ftun_status_t ftun_dns_runtime_listener_udp_one(
  ftun_dns_runtime_t *dns, ftun_dns_runtime_listener_slot_t *slot,
  size_t listener_index, bool *out_work)
{
  uint8_t wire[FTUN_DNS_MAX_MESSAGE_BYTES];
  struct sockaddr_in peer;
  socklen_t peer_length = (socklen_t)sizeof(peer);
  ftun_dns_runtime_pending_t *pending;
  ftun_operation_t *operation = NULL;
  ssize_t length;
  ftun_status_t status;
  *out_work = false;
  do {
    length = recvfrom(slot->descriptor, wire, sizeof(wire), 0,
      (struct sockaddr *)&peer, &peer_length);
  } while (length < 0 && errno == EINTR);
  if (length < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
    slot->events &= ~FTUN_EVENT_READ;
    return FTUN_OK;
  }
  if (length < 0) return ftun_blocking_socket_status(errno);
  *out_work = true;
  pending = ftun_dns_runtime_pending_new(dns, listener_index);
  if (pending == NULL) return FTUN_OK;
  pending->kind = FTUN_DNS_RUNTIME_PENDING_SOCKET;
  pending->descriptor = slot->descriptor;
  pending->peer = peer;
  pending->peer_length = peer_length;
  status = ftun_dns_listener_receive_udp(slot->protocol, pending->id,
    (ftun_bytes_t){wire, (size_t)length}, &operation);
  if (status != FTUN_OK) {
    ftun_dns_runtime_pending_clear(dns, pending);
  }
  return FTUN_OK;
}

static ftun_status_t ftun_dns_runtime_step_listener(ftun_dns_runtime_t *dns,
                                                   uint64_t now_ms,
                                                   bool *out_work)
{
  size_t scanned;
  *out_work = false;
  if (!dns->accepting || dns->listener_count == 0u) return FTUN_OK;
  for (scanned = 0u; scanned < dns->listener_count; scanned++) {
    size_t index = (dns->listener_cursor + scanned) % dns->listener_count;
    ftun_dns_runtime_listener_slot_t *slot = &dns->listeners[index];
    size_t attempt;
    if (slot->accept_after_ms != 0u && now_ms >= slot->accept_after_ms) {
      ftun_status_t status;
      slot->accept_after_ms = 0u;
      status = ftun_event_io_update(slot->tcp_source,
                                    FTUN_EVENT_READ | FTUN_EVENT_ERROR);
      if (status != FTUN_OK) return status;
      slot->tcp_events |= FTUN_EVENT_READ;
    }
    if ((slot->events & FTUN_EVENT_ERROR) != 0u ||
        (slot->tcp_events & FTUN_EVENT_ERROR) != 0u) return FTUN_E_IO;
    for (attempt = 0u; attempt < 2u; attempt++) {
      bool choose_tcp = attempt == 0u ? dns->listener_tcp_turn :
                                       !dns->listener_tcp_turn;
      if (choose_tcp && (slot->tcp_events & FTUN_EVENT_READ) != 0u) {
        size_t accepted = 0u;
        ftun_status_t status = ftun_dns_runtime_tcp_accept(dns, slot, 1u,
                                                          &accepted);
        if (status != FTUN_OK) return status;
        if (accepted == 0u) slot->tcp_events &= ~FTUN_EVENT_READ;
        else {
          dns->listener_cursor = (index + 1u) % dns->listener_count;
          dns->listener_tcp_turn = false;
          *out_work = true;
          return FTUN_OK;
        }
      } else if (!choose_tcp && (slot->events & FTUN_EVENT_READ) != 0u) {
        ftun_status_t status = ftun_dns_runtime_listener_udp_one(
          dns, slot, index, out_work);
        if (status != FTUN_OK) return status;
        if (*out_work) {
          dns->listener_cursor = (index + 1u) % dns->listener_count;
          dns->listener_tcp_turn = true;
          return FTUN_OK;
        }
      }
    }
  }
  return FTUN_OK;
}

static ftun_status_t ftun_dns_runtime_step_tcp(ftun_dns_runtime_t *dns,
                                              bool *out_work)
{
  size_t scanned;
  *out_work = false;
  for (scanned = 0u; scanned < FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS;
       scanned++) {
    size_t index = (dns->tcp_cursor + scanned) %
                   FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS;
    ftun_status_t status;
    if (!dns->tcp[index].active || !dns->tcp[index].ready) continue;
    dns->tcp_cursor = (index + 1u) % FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS;
    dns->tcp[index].ready = false;
    dns->tcp[index].events = 0u;
    status = ftun_dns_runtime_tcp_drive(dns, &dns->tcp[index]);
    *out_work = true;
    if (status != FTUN_OK) return status;
    if (dns->tcp[index].active) {
      return ftun_dns_runtime_tcp_source_update(&dns->tcp[index]);
    }
    return FTUN_OK;
  }
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_run_once(ftun_dns_runtime_t *dns, size_t quota,
                                       size_t *out_work)
{
  size_t work = 0u;
  if (out_work != NULL) *out_work = 0u;
  if (quota == 0u || out_work == NULL) return FTUN_E_INVALID;
  if (dns == NULL) return FTUN_OK;
  if (dns->pending_status != FTUN_OK) {
    ftun_status_t status = dns->pending_status;
    dns->pending_status = FTUN_OK;
    return status;
  }
  while (work < quota) {
    uint64_t now_ms = ftun_dns_runtime_now(NULL);
    bool did_work = false;
    size_t attempt;
    ftun_status_t status;
    if (dns->waiter_count != 0u &&
        dns->waiter_heap[0]->deadline_ms <= now_ms) {
      status = ftun_dns_runtime_step_deadline(dns, now_ms, &did_work);
      if (status != FTUN_OK) return status;
      if (did_work) {
        work++;
        dns->lane_cursor = 2u;
        continue;
      }
    }
    for (attempt = 0u; attempt < FTUN_DNS_RUNTIME_LANE_COUNT; attempt++) {
      size_t lane = (dns->lane_cursor + attempt) %
                    FTUN_DNS_RUNTIME_LANE_COUNT;
      if (lane == 0u) {
        status = ftun_dns_runtime_step_request(dns, &did_work);
      } else if (lane == 1u) {
        status = ftun_dns_runtime_step_deadline(dns, now_ms, &did_work);
      } else if (lane == 2u) {
        status = ftun_dns_runtime_step_listener(dns, now_ms, &did_work);
      } else {
        status = ftun_dns_runtime_step_tcp(dns, &did_work);
      }
      if (status != FTUN_OK) return status;
      if (did_work) {
        dns->lane_cursor = (lane + 1u) % FTUN_DNS_RUNTIME_LANE_COUNT;
        work++;
        break;
      }
    }
    if (!did_work) break;
  }
  *out_work = work;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_next_deadline(
  const ftun_dns_runtime_t *dns, uint64_t *out_deadline_ms, bool *out_present)
{
  uint64_t deadline = UINT64_MAX;
  size_t index;
  if (out_deadline_ms != NULL) *out_deadline_ms = 0u;
  if (out_present != NULL) *out_present = false;
  if (out_deadline_ms == NULL || out_present == NULL) return FTUN_E_INVALID;
  if (dns == NULL) return FTUN_OK;
  if (dns->waiter_count != 0u) deadline = dns->waiter_heap[0]->deadline_ms;
  for (index = 0u; index < dns->listener_count; index++) {
    if (dns->listeners[index].accept_after_ms != 0u &&
        dns->listeners[index].accept_after_ms < deadline) {
      deadline = dns->listeners[index].accept_after_ms;
    }
  }
  if (deadline != UINT64_MAX) {
    *out_deadline_ms = deadline;
    *out_present = true;
  }
  return FTUN_OK;
}

bool ftun_dns_runtime_has_ready(const ftun_dns_runtime_t *dns)
{
  uint64_t deadline = 0u;
  bool present = false;
  size_t index;
  if (dns == NULL) return false;
  if (dns->pending_status != FTUN_OK) return true;
  if (dns->ready_request_head != NULL) return true;
  for (index = 0u; index < dns->listener_count; index++) {
    if (dns->listeners[index].events != 0u ||
        dns->listeners[index].tcp_events != 0u) return true;
  }
  for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS; index++) {
    if (dns->tcp[index].active && dns->tcp[index].ready) return true;
  }
  if (ftun_dns_runtime_next_deadline(dns, &deadline, &present) == FTUN_OK &&
      present && ftun_dns_runtime_now(NULL) >= deadline) return true;
  return false;
}

bool ftun_dns_runtime_has_hijack(const ftun_dns_runtime_t *dns)
{
  return dns != NULL && dns->hijack != NULL && dns->accepting;
}

ftun_status_t ftun_dns_runtime_dispatcher(ftun_dns_runtime_t *dns,
                                        ftun_dns_dispatcher_t **out)
{
  if (out != NULL) *out = NULL;
  if (dns == NULL || out == NULL) return FTUN_E_INVALID;
  if (dns->dispatcher == NULL) return FTUN_E_AGAIN;
  *out = dns->dispatcher;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_hijack_udp(
  ftun_dns_runtime_t *dns, ftun_datagram_t *inbound,
  const ftun_endpoint_t *client, const ftun_packet_t *packet)
{
  ftun_dns_runtime_pending_t *pending;
  ftun_operation_t *operation = NULL;
  ftun_bytes_t wire;
  ftun_status_t status;
  if (!ftun_dns_runtime_has_hijack(dns) || inbound == NULL || client == NULL ||
      packet == NULL || ftun_packet_view(packet, &wire) != FTUN_OK) {
    return FTUN_E_INVALID;
  }
  pending = ftun_dns_runtime_pending_new(dns, SIZE_MAX);
  if (pending == NULL) return FTUN_E_LIMIT;
  pending->kind = FTUN_DNS_RUNTIME_PENDING_TUN;
  pending->inbound = inbound;
  pending->client = *client;
  status = ftun_dns_listener_receive_udp(dns->hijack, pending->id, wire,
                                         &operation);
  if (status != FTUN_OK) {
    ftun_dns_runtime_pending_clear(dns, pending);
  }
  return status;
}

ftun_status_t ftun_dns_runtime_stop(ftun_dns_runtime_t *dns)
{
  size_t index;
  if (dns == NULL) return FTUN_OK;
  (void)ftun_dns_runtime_quiesce(dns);
  /* 完整停止不再等待网络：取消全部上游请求，使 listener/server inflight
   * 同步归零；热重载只调用 quiesce 并在 retired 槽中自然排空。 */
  while (dns->request_head != NULL) {
    ftun_dns_runtime_request_finish(dns->request_head, FTUN_E_CANCELLED);
  }
  for (index = 0u; index < dns->listener_count; index++) {
    if (dns->listeners[index].descriptor >= 0) {
      (void)close(dns->listeners[index].descriptor);
      dns->listeners[index].descriptor = -1;
    }
    if (dns->listeners[index].tcp_descriptor >= 0) {
      (void)close(dns->listeners[index].tcp_descriptor);
      dns->listeners[index].tcp_descriptor = -1;
    }
  }
  for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS; index++) {
    if (dns->tcp[index].active) {
      (void)ftun_event_source_cancel(&dns->tcp[index].source);
      dns->tcp[index].peer_eof = true;
      if (dns->tcp[index].descriptor >= 0) {
        (void)close(dns->tcp[index].descriptor);
        dns->tcp[index].descriptor = -1;
      }
    }
  }
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_destroy(ftun_dns_runtime_t **dns_ptr)
{
  ftun_dns_runtime_t *dns;
  ftun_reservation_t *listener_reservation;
  size_t index;
  if (dns_ptr == NULL) return FTUN_E_INVALID;
  dns = *dns_ptr;
  if (dns == NULL) return FTUN_OK;
  (void)ftun_dns_runtime_stop(dns);
  for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS; index++) {
    if (dns->tcp[index].protocol != NULL &&
        ftun_dns_connection_close(&dns->tcp[index].protocol) != FTUN_OK) {
      return FTUN_E_AGAIN;
    }
    ftun_dns_runtime_tcp_close(&dns->tcp[index]);
  }
  for (index = 0u; index < dns->listener_count; index++) {
    if (ftun_dns_listener_destroy(&dns->listeners[index].protocol) != FTUN_OK) {
      return FTUN_E_AGAIN;
    }
  }
  if (ftun_dns_listener_destroy(&dns->hijack) != FTUN_OK) return FTUN_E_AGAIN;
  if (ftun_dns_dispatcher_destroy(&dns->dispatcher) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
  for (index = dns->server_count; index != 0u; index--) {
    if (ftun_dns_server_destroy(&dns->servers[index - 1u]) != FTUN_OK) {
      return FTUN_E_AGAIN;
    }
  }
  if (ftun_dns_cache_destroy(&dns->cache) != FTUN_OK) return FTUN_E_AGAIN;
  if (ftun_config_destroy(&dns->config) != FTUN_OK) return FTUN_E_AGAIN;
  free(dns->proxy_endpoints);
  free(dns->proxy_endpoint_valid);
  listener_reservation = dns->listener_reservation;
  dns->listener_reservation = NULL;
  memset(dns, 0, sizeof(*dns));
  free(dns);
  *dns_ptr = NULL;
  return ftun_reservation_release(&listener_reservation);
}

#else

struct ftun_dns_runtime { int unused; };
struct ftun_dns_runtime_plan { int unused; };

ftun_status_t ftun_dns_runtime_prepare(
  ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations, ftun_event_loop_t *loop,
  const ftun_config_t *config, const ftun_dns_runtime_adapter_t *adapter,
  uint32_t socket_mark,
  ftun_dns_runtime_t **out)
{
  (void)core; (void)budget; (void)operations; (void)loop;
  (void)adapter; (void)socket_mark;
  if (out != NULL) *out = NULL;
  if (config == NULL || out == NULL) return FTUN_E_INVALID;
  return config->dns.enable ? FTUN_E_UNSUPPORTED : FTUN_OK;
}
ftun_status_t ftun_dns_runtime_prepare_reload(
  const ftun_dns_runtime_t *active, ftun_core_t *core,
  ftun_budget_t *budget, ftun_operation_queue_t *operations,
  ftun_event_loop_t *loop,
  const ftun_config_t *config, const ftun_dns_runtime_adapter_t *adapter,
  uint32_t socket_mark,
  ftun_dns_runtime_t **out)
{
  (void)active;
  return ftun_dns_runtime_prepare(core, budget, operations, loop, config,
                                 adapter, socket_mark, out);
}
ftun_status_t ftun_dns_runtime_plan_prepare(const ftun_config_t *config,
                                           uint32_t socket_mark,
                                           ftun_dns_runtime_plan_t **out)
{
  (void)socket_mark;
  if (out != NULL) *out = NULL;
  if (config == NULL || out == NULL) return FTUN_E_INVALID;
  return config->dns.enable ? FTUN_E_UNSUPPORTED : FTUN_OK;
}
ftun_status_t ftun_dns_runtime_plan_destroy(ftun_dns_runtime_plan_t **plan)
{ if (plan == NULL) return FTUN_E_INVALID; *plan = NULL; return FTUN_OK; }
ftun_status_t ftun_dns_runtime_prepare_reload_planned(
  const ftun_dns_runtime_t *active, ftun_core_t *core,
  ftun_budget_t *budget, ftun_operation_queue_t *operations,
  ftun_event_loop_t *loop,
  const ftun_config_t *config, const ftun_dns_runtime_adapter_t *adapter,
  uint32_t socket_mark,
  const ftun_dns_runtime_plan_t *plan, ftun_dns_runtime_t **out)
{
  (void)plan;
  return ftun_dns_runtime_prepare_reload(active, core, budget, operations,
    loop, config, adapter, socket_mark, out);
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
                                         int descriptor)
{ (void)dns; (void)descriptor; return FTUN_E_UNSUPPORTED; }
ftun_status_t ftun_dns_runtime_hijack_udp(
  ftun_dns_runtime_t *dns, ftun_datagram_t *inbound,
  const ftun_endpoint_t *client, const ftun_packet_t *packet)
{ (void)dns; (void)inbound; (void)client; (void)packet; return FTUN_E_UNSUPPORTED; }
ftun_status_t ftun_dns_runtime_stop(ftun_dns_runtime_t *dns)
{ (void)dns; return FTUN_OK; }
ftun_status_t ftun_dns_runtime_destroy(ftun_dns_runtime_t **dns)
{ if (dns == NULL) return FTUN_E_INVALID; *dns = NULL; return FTUN_OK; }

#endif
