#define _GNU_SOURCE 1

#include "config/compile.h"
#include "config/config.h"
#include "config/model.h"
#include "config/parser.h"
#include "core/budget.h"
#include "core/operation.h"
#include "core/runtime.h"
#include "core/session.h"
#include "core/worker.h"
#include "event/event.h"
#include "event/libev_adapter.h"
#include "inbound/tun.h"
#include "outbound/outbound.h"
#include "platform/linux/route.h"
#include "platform/linux/tun.h"
#include "platform/system_resolver.h"
#include "route/target.h"
#include "transport/datagram.h"
#include "transport/relay.h"
#include "transport/stream.h"
#include "tun/udp_session.h"
#include "util/buffer.h"
#include "util/time.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition) do { \
  if (!(condition)) { \
    fprintf(stderr, "linux integration failed at %s:%d: %s\n", \
            __FILE__, __LINE__, #condition); \
    return 1; \
  } \
} while (0)

#define PEER_ADDRESS "192.0.2.2"
#define DNS_ADDRESS "192.0.2.53"
#define MAIN_ADDRESS "192.0.2.1"
#define DIRECT_TCP_PORT 18080u
#define DIRECT_UDP_PORT 18081u
#define SOCKS_PORT 11080u
#define PROTECTION_MARK 77u
#define TUN_MTU 1400u
#define INBOUND_ID 41u
#define UDP_SLOTS 8u

static volatile sig_atomic_t peer_stopping;
static pthread_mutex_t peer_threads_mutex = PTHREAD_MUTEX_INITIALIZER;
static size_t peer_threads;

static uint64_t deadline_after(uint64_t milliseconds)
{
  uint64_t now = 0u;
  if (ftun_monotonic_now(&now) != FTUN_OK) return 0u;
  if (now > UINT64_MAX - milliseconds) return UINT64_MAX;
  return now + milliseconds;
}

static ftun_endpoint_t endpoint4(const char *address, uint16_t port)
{
  ftun_endpoint_t endpoint;
  memset(&endpoint, 0, sizeof(endpoint));
  endpoint.kind = FTUN_ADDRESS_IPV4;
  endpoint.port = port;
  (void)inet_pton(AF_INET, address, endpoint.address);
  return endpoint;
}

static int endpoint_equal(const ftun_endpoint_t *left,
                          const ftun_endpoint_t *right)
{
  return left != NULL && right != NULL &&
         left->kind == FTUN_ADDRESS_IPV4 &&
         right->kind == FTUN_ADDRESS_IPV4 && left->port == right->port &&
         memcmp(left->address, right->address, 4u) == 0;
}

static int set_nonblocking(int descriptor)
{
  int flags = fcntl(descriptor, F_GETFL, 0);
  return flags >= 0 && fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0;
}

static int socket_bound(int type, const char *address, uint16_t port)
{
  struct sockaddr_in socket_address;
  int descriptor = socket(AF_INET, type | SOCK_CLOEXEC, 0);
  int one = 1;
  if (descriptor < 0) return -1;
  (void)setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  memset(&socket_address, 0, sizeof(socket_address));
  socket_address.sin_family = AF_INET;
  socket_address.sin_port = htons(port);
  if (inet_pton(AF_INET, address, &socket_address.sin_addr) != 1 ||
      bind(descriptor, (const struct sockaddr *)&socket_address,
           (socklen_t)sizeof(socket_address)) != 0) {
    (void)close(descriptor);
    return -1;
  }
  return descriptor;
}

static int socket_port(int descriptor, uint16_t *out)
{
  struct sockaddr_in address;
  socklen_t length = (socklen_t)sizeof(address);
  if (out != NULL) *out = 0u;
  if (out == NULL || getsockname(descriptor, (struct sockaddr *)&address,
                                  &length) != 0 ||
      length != (socklen_t)sizeof(address)) return 0;
  *out = ntohs(address.sin_port);
  return *out != 0u;
}

static int read_exact(int descriptor, uint8_t *buffer, size_t length)
{
  size_t offset = 0u;
  while (offset < length) {
    ssize_t result = recv(descriptor, buffer + offset, length - offset, 0);
    if (result > 0) offset += (size_t)result;
    else if (result < 0 && errno == EINTR) continue;
    else return 0;
  }
  return 1;
}

static int write_exact(int descriptor, const uint8_t *buffer, size_t length)
{
  size_t offset = 0u;
  while (offset < length) {
    ssize_t result = send(descriptor, buffer + offset, length - offset,
                          MSG_NOSIGNAL);
    if (result > 0) offset += (size_t)result;
    else if (result < 0 && errno == EINTR) continue;
    else return 0;
  }
  return 1;
}

static void peer_thread_started(void)
{
  (void)pthread_mutex_lock(&peer_threads_mutex);
  peer_threads++;
  (void)pthread_mutex_unlock(&peer_threads_mutex);
}

static void peer_thread_finished(void)
{
  (void)pthread_mutex_lock(&peer_threads_mutex);
  if (peer_threads != 0u) peer_threads--;
  (void)pthread_mutex_unlock(&peer_threads_mutex);
}

static void *peer_echo_thread(void *argument)
{
  int descriptor = *(int *)argument;
  uint8_t buffer[4096];
  free(argument);
  for (;;) {
    ssize_t length = recv(descriptor, buffer, sizeof(buffer), 0);
    if (length > 0) {
      if (!write_exact(descriptor, buffer, (size_t)length)) break;
    } else if (length < 0 && errno == EINTR) {
      continue;
    } else {
      break;
    }
  }
  (void)shutdown(descriptor, SHUT_WR);
  (void)close(descriptor);
  peer_thread_finished();
  return NULL;
}

static int peer_socks_read_endpoint(int descriptor, uint8_t type,
                                    uint16_t *port)
{
  uint8_t buffer[258];
  size_t length;
  if (type == 1u) length = 4u;
  else if (type == 3u) {
    if (!read_exact(descriptor, buffer, 1u)) return 0;
    length = buffer[0];
    if (length == 0u) return 0;
  } else {
    return 0;
  }
  if (!read_exact(descriptor, buffer, length + 2u)) return 0;
  *port = (uint16_t)(((uint16_t)buffer[length] << 8) | buffer[length + 1u]);
  return 1;
}

static void peer_udp_association(int control)
{
  uint8_t reply[10] = {5u, 0u, 0u, 1u};
  uint8_t buffer[2048];
  struct sockaddr_in source;
  uint16_t port = 0u;
  int datagram = socket_bound(SOCK_DGRAM, PEER_ADDRESS, 0u);
  if (datagram < 0 || !socket_port(datagram, &port)) {
    if (datagram >= 0) (void)close(datagram);
    return;
  }
  (void)inet_pton(AF_INET, PEER_ADDRESS, reply + 4u);
  reply[8] = (uint8_t)(port >> 8);
  reply[9] = (uint8_t)port;
  if (!write_exact(control, reply, sizeof(reply))) {
    (void)close(datagram);
    return;
  }
  while (!peer_stopping) {
    struct pollfd descriptors[2];
    int ready;
    memset(descriptors, 0, sizeof(descriptors));
    descriptors[0].fd = control;
    descriptors[0].events = POLLIN;
    descriptors[1].fd = datagram;
    descriptors[1].events = POLLIN;
    ready = poll(descriptors, 2u, 100);
    if (ready < 0 && errno == EINTR) continue;
    if (ready < 0 || (descriptors[0].revents &
        (POLLIN | POLLERR | POLLHUP)) != 0) break;
    if ((descriptors[1].revents & POLLIN) != 0) {
      socklen_t source_length = (socklen_t)sizeof(source);
      ssize_t length = recvfrom(datagram, buffer, sizeof(buffer), 0,
        (struct sockaddr *)&source, &source_length);
      if (length > 0) {
        (void)sendto(datagram, buffer, (size_t)length, 0,
                     (const struct sockaddr *)&source, source_length);
      }
    }
  }
  (void)close(datagram);
}

static void *peer_socks_thread(void *argument)
{
  int descriptor = *(int *)argument;
  uint8_t header[4];
  uint8_t methods[255];
  uint8_t reply[10] = {5u, 0u, 0u, 1u, 0u, 0u, 0u, 0u, 0u, 0u};
  uint16_t target_port = 0u;
  free(argument);
  if (!read_exact(descriptor, header, 2u) || header[0] != 5u ||
      header[1] == 0u || !read_exact(descriptor, methods, header[1]) ||
      !write_exact(descriptor, (const uint8_t *)"\x05\x00", 2u) ||
      !read_exact(descriptor, header, 4u) || header[0] != 5u ||
      header[2] != 0u || !peer_socks_read_endpoint(
        descriptor, header[3], &target_port)) goto done;
  if (target_port == 9u) {
    reply[1] = 5u;
    (void)write_exact(descriptor, reply, sizeof(reply));
    goto done;
  }
  if (header[1] == 1u) {
    if (!write_exact(descriptor, reply, sizeof(reply))) goto done;
    while (!peer_stopping) {
      ssize_t length = recv(descriptor, methods, sizeof(methods), 0);
      if (length > 0) {
        if (!write_exact(descriptor, methods, (size_t)length)) break;
      } else if (length < 0 && errno == EINTR) {
        continue;
      } else {
        break;
      }
    }
  } else if (header[1] == 3u) {
    peer_udp_association(descriptor);
  }
done:
  (void)close(descriptor);
  peer_thread_finished();
  return NULL;
}

static int peer_accept_thread(int listener, void *(*entry)(void *))
{
  pthread_t thread;
  int *argument = (int *)malloc(sizeof(*argument));
  if (argument == NULL) return 0;
  *argument = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
  if (*argument < 0) {
    free(argument);
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
  }
  peer_thread_started();
  if (pthread_create(&thread, NULL, entry, argument) != 0) {
    peer_thread_finished();
    (void)close(*argument);
    free(argument);
    return 0;
  }
  (void)pthread_detach(thread);
  return 1;
}

static void peer_dns_reply(int descriptor)
{
  uint8_t query[512];
  uint8_t response[528];
  struct sockaddr_in source;
  socklen_t source_length = (socklen_t)sizeof(source);
  ssize_t length = recvfrom(descriptor, query, sizeof(query), 0,
                            (struct sockaddr *)&source, &source_length);
  size_t output_length;
  if (length < 17 || (query[2] & 0x80u) != 0u ||
      query[4] != 0u || query[5] != 1u) return;
  output_length = (size_t)length + 16u;
  if (output_length > sizeof(response)) return;
  memcpy(response, query, (size_t)length);
  response[2] = 0x81u;
  response[3] = 0x80u;
  response[6] = 0u;
  response[7] = 1u;
  response[8] = response[9] = response[10] = response[11] = 0u;
  response[length] = 0xc0u;
  response[length + 1] = 0x0cu;
  response[length + 2] = 0u;
  response[length + 3] = 1u;
  response[length + 4] = 0u;
  response[length + 5] = 1u;
  response[length + 6] = response[length + 7] = response[length + 8] = 0u;
  response[length + 9] = 1u;
  response[length + 10] = 0u;
  response[length + 11] = 4u;
  (void)inet_pton(AF_INET, PEER_ADDRESS, response + length + 12u);
  (void)sendto(descriptor, response, output_length, 0,
               (const struct sockaddr *)&source, source_length);
}

static void peer_signal(int signal_number)
{
  (void)signal_number;
  peer_stopping = 1;
}

static int peer_main(const char *ready_path)
{
  struct pollfd descriptors[4];
  struct sigaction action;
  uint8_t buffer[2048];
  int direct_tcp = socket_bound(SOCK_STREAM, PEER_ADDRESS, DIRECT_TCP_PORT);
  int direct_udp = socket_bound(SOCK_DGRAM, PEER_ADDRESS, DIRECT_UDP_PORT);
  int socks = socket_bound(SOCK_STREAM, PEER_ADDRESS, SOCKS_PORT);
  int dns = socket_bound(SOCK_DGRAM, DNS_ADDRESS, 53u);
  int ready;
  if (direct_tcp < 0 || direct_udp < 0 || socks < 0 || dns < 0 ||
      listen(direct_tcp, 8) != 0 || listen(socks, 8) != 0 ||
      !set_nonblocking(direct_tcp) || !set_nonblocking(socks)) return 1;
  memset(&action, 0, sizeof(action));
  action.sa_handler = peer_signal;
  (void)sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGTERM, &action, NULL) == 0);
  ready = open(ready_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  CHECK(ready >= 0 && write(ready, "ready\n", 6u) == 6);
  (void)close(ready);
  memset(descriptors, 0, sizeof(descriptors));
  descriptors[0].fd = direct_tcp;
  descriptors[0].events = POLLIN;
  descriptors[1].fd = direct_udp;
  descriptors[1].events = POLLIN;
  descriptors[2].fd = socks;
  descriptors[2].events = POLLIN;
  descriptors[3].fd = dns;
  descriptors[3].events = POLLIN;
  while (!peer_stopping) {
    int count = poll(descriptors, 4u, 100);
    if (count < 0 && errno == EINTR) continue;
    if (count < 0) break;
    if ((descriptors[0].revents & POLLIN) != 0 &&
        !peer_accept_thread(direct_tcp, peer_echo_thread)) break;
    if ((descriptors[1].revents & POLLIN) != 0) {
      struct sockaddr_in source;
      socklen_t source_length = (socklen_t)sizeof(source);
      ssize_t length = recvfrom(direct_udp, buffer, sizeof(buffer), 0,
        (struct sockaddr *)&source, &source_length);
      if (length >= 0) (void)sendto(direct_udp, buffer, (size_t)length, 0,
        (const struct sockaddr *)&source, source_length);
    }
    if ((descriptors[2].revents & POLLIN) != 0 &&
        !peer_accept_thread(socks, peer_socks_thread)) break;
    if ((descriptors[3].revents & POLLIN) != 0) peer_dns_reply(dns);
  }
  (void)close(dns);
  (void)close(socks);
  (void)close(direct_udp);
  (void)close(direct_tcp);
  for (;;) {
    struct timespec delay = {0, 1000000L};
    size_t active;
    (void)pthread_mutex_lock(&peer_threads_mutex);
    active = peer_threads;
    (void)pthread_mutex_unlock(&peer_threads_mutex);
    if (active == 0u) break;
    (void)nanosleep(&delay, NULL);
  }
  return 0;
}

static int wait_socket(int descriptor, short events, int timeout_ms)
{
  struct pollfd poll_descriptor;
  int result;
  memset(&poll_descriptor, 0, sizeof(poll_descriptor));
  poll_descriptor.fd = descriptor;
  poll_descriptor.events = events;
  do {
    result = poll(&poll_descriptor, 1u, timeout_ms);
  } while (result < 0 && errno == EINTR);
  return result == 1 && (poll_descriptor.revents & events) != 0;
}

static int client_main(const char *transport, const char *tag)
{
  static const char suffix[] = "-through-ftun";
  struct sockaddr_in target;
  struct timeval timeout;
  char message[128];
  char response[128];
  size_t expected;
  size_t received = 0u;
  int descriptor;
  int type;
  uint16_t port;
  if (strcmp(transport, "tcp") == 0) {
    type = SOCK_STREAM;
    port = DIRECT_TCP_PORT;
  } else if (strcmp(transport, "udp") == 0) {
    type = SOCK_DGRAM;
    port = DIRECT_UDP_PORT;
  } else {
    return 1;
  }
  if (snprintf(message, sizeof(message), "%s%s", tag, suffix) <= 0) return 1;
  expected = strlen(message);
  descriptor = socket(AF_INET, type | SOCK_CLOEXEC, 0);
  if (descriptor < 0) return 1;
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;
  if (setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO,
                 &timeout, sizeof(timeout)) != 0 ||
      setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO,
                 &timeout, sizeof(timeout)) != 0) {
    (void)close(descriptor);
    return 1;
  }
  memset(&target, 0, sizeof(target));
  target.sin_family = AF_INET;
  target.sin_port = htons(port);
  if (inet_pton(AF_INET, PEER_ADDRESS, &target.sin_addr) != 1 ||
      connect(descriptor, (const struct sockaddr *)&target,
              (socklen_t)sizeof(target)) != 0 ||
      !write_exact(descriptor, (const uint8_t *)message, expected)) {
    (void)close(descriptor);
    return 1;
  }
  if (type == SOCK_STREAM) (void)shutdown(descriptor, SHUT_WR);
  while (received < expected) {
    ssize_t amount = recv(descriptor, response + received,
                          expected - received, 0);
    if (amount > 0) received += (size_t)amount;
    else if (amount < 0 && errno == EINTR) continue;
    else break;
  }
  (void)close(descriptor);
  return received == expected && memcmp(response, message, expected) == 0
    ? 0 : 1;
}

typedef struct integration integration_t;

typedef struct {
  integration_t *integration;
  int descriptor;
  ftun_stream_write_t *pending;
  bool write_shutdown;
} socket_stream_t;

typedef struct {
  integration_t *integration;
  ftun_datagram_t *channel;
  ftun_endpoint_t remote;
  int descriptor;
  bool active;
} udp_slot_t;

typedef struct {
  ftun_stream_t *inbound;
  ftun_stream_t *outbound;
  ftun_session_t *session;
  ftun_relay_t *relay;
  ftun_operation_t *open_operation;
  socket_stream_t socket;
  uint32_t left_events;
  bool active;
  bool failed;
} tcp_flow_t;

typedef struct {
  int calls;
  ftun_error_t error;
  ftun_socks5_connection_t *connection;
} socks_completion_t;

typedef struct {
  int calls;
  ftun_error_t error;
  ftun_native_socket_t socket;
} dial_capture_t;

typedef struct {
  int calls;
  ftun_error_t error;
  ftun_endpoint_t addresses[FTUN_SYSTEM_RESOLVER_MAX_IPV4_RESULTS];
  size_t address_count;
} resolver_completion_t;

struct integration {
  ftun_budget_t *budget;
  ftun_operation_queue_t *operations;
  ftun_event_loop_t *loop;
  ftun_worker_t *worker;
  ftun_core_t *core;
  ftun_config_t *config;
  ftun_packet_port_t *port;
  ftun_tun_ingress_context_t *ingress;
  ftun_udp_flow_table_t *udp_flows;
  ftun_route_transaction_t *routes;
  ftun_packet_port_info_t port_info;
  tcp_flow_t tcp;
  udp_slot_t udp[UDP_SLOTS];
  uint64_t generation;
  uint64_t now_ms;
  size_t accepted_tcp;
  size_t received_udp;
  size_t rejected_ipv6;
  size_t write_completions;
  bool callback_failed;
};

static ftun_status_t socket_status(int error_code)
{
  if (error_code == EAGAIN || error_code == EWOULDBLOCK ||
      error_code == EINTR) return FTUN_E_AGAIN;
  if (error_code == ENOMEM || error_code == ENOBUFS) return FTUN_E_LIMIT;
  if (error_code == ECONNRESET || error_code == EPIPE ||
      error_code == ECONNREFUSED) return FTUN_E_REJECTED;
  if (error_code == EBADF || error_code == EINVAL ||
      error_code == ENOTSOCK) return FTUN_E_INVALID;
  return FTUN_E_IO;
}

static ftun_status_t socket_stream_read(void *user, void *buffer,
                                        size_t capacity, size_t *out_length)
{
  socket_stream_t *stream = (socket_stream_t *)user;
  ssize_t length;
  if (out_length != NULL) *out_length = 0u;
  if (stream == NULL || stream->descriptor < 0 || buffer == NULL ||
      capacity == 0u || out_length == NULL) return FTUN_E_INVALID;
  do {
    length = recv(stream->descriptor, buffer, capacity, 0);
  } while (length < 0 && errno == EINTR);
  if (length > 0) {
    *out_length = (size_t)length;
    return FTUN_OK;
  }
  if (length == 0) return FTUN_E_EOF;
  return socket_status(errno);
}

static ftun_status_t socket_stream_write_start(
  void *user, ftun_stream_write_t *write, const ftun_buffer_slice_t *slice,
  size_t *accepted)
{
  socket_stream_t *stream = (socket_stream_t *)user;
  ftun_bytes_t bytes;
  ssize_t length;
  if (accepted != NULL) *accepted = 0u;
  if (stream == NULL || stream->descriptor < 0 || stream->pending != NULL ||
      write == NULL || slice == NULL || accepted == NULL ||
      ftun_buffer_slice_data(slice, &bytes) != FTUN_OK ||
      bytes.length == 0u) return FTUN_E_INVALID;
  do {
    length = send(stream->descriptor, bytes.data, bytes.length, MSG_NOSIGNAL);
  } while (length < 0 && errno == EINTR);
  if (length < 0) return socket_status(errno);
  if (length == 0) return FTUN_E_IO;
  stream->pending = write;
  *accepted = (size_t)length;
  return FTUN_OK;
}

static ftun_status_t socket_stream_write_cancel(
  void *user, ftun_stream_write_t *write)
{
  socket_stream_t *stream = (socket_stream_t *)user;
  if (stream == NULL || stream->pending != write) return FTUN_E_STALE;
  stream->pending = NULL;
  return FTUN_OK;
}

static ftun_status_t socket_stream_shutdown(void *user)
{
  socket_stream_t *stream = (socket_stream_t *)user;
  if (stream == NULL || stream->descriptor < 0) return FTUN_E_INVALID;
  if (stream->write_shutdown) return FTUN_OK;
  if (shutdown(stream->descriptor, SHUT_WR) != 0 && errno != ENOTCONN) {
    return socket_status(errno);
  }
  stream->write_shutdown = true;
  return FTUN_OK;
}

static void socket_stream_destroy(void *user)
{
  socket_stream_t *stream = (socket_stream_t *)user;
  if (stream == NULL) return;
  if (stream->descriptor >= 0) (void)close(stream->descriptor);
  stream->descriptor = -1;
  stream->pending = NULL;
}

static void stream_completion(ftun_operation_t *operation,
                              ftun_error_t error, void *user)
{
  integration_t *integration = (integration_t *)user;
  (void)operation;
  integration->write_completions++;
  if (error.status != FTUN_OK && error.status != FTUN_E_CANCELLED) {
    integration->callback_failed = true;
  }
}

static ftun_status_t create_socket_stream(integration_t *integration,
                                          int descriptor,
                                          ftun_stream_t **out)
{
  ftun_stream_options_t options;
  ftun_stream_backend_t backend;
  socket_stream_t *socket_stream = &integration->tcp.socket;
  memset(socket_stream, 0, sizeof(*socket_stream));
  socket_stream->integration = integration;
  socket_stream->descriptor = descriptor;
  memset(&options, 0, sizeof(options));
  options.budget = integration->budget;
  options.operations = integration->operations;
  options.max_pending_writes = 8u;
  options.max_pending_bytes = 65536u;
  options.completion = stream_completion;
  options.completion_user = integration;
  memset(&backend, 0, sizeof(backend));
  backend.read = socket_stream_read;
  backend.write_start = socket_stream_write_start;
  backend.write_cancel = socket_stream_write_cancel;
  backend.shutdown_write = socket_stream_shutdown;
  backend.destroy = socket_stream_destroy;
  backend.context = socket_stream;
  return ftun_stream_create(&options, &backend, out);
}

static void direct_completed(ftun_operation_t *operation,
                             ftun_error_t error,
                             const ftun_dial_result_t *result, void *user)
{
  integration_t *integration = (integration_t *)user;
  tcp_flow_t *flow = &integration->tcp;
  ftun_status_t status;
  flow->open_operation = NULL;
  if (flow->session == NULL || result == NULL ||
      ftun_session_operation_complete(flow->session, operation,
                                      error) != FTUN_OK) {
    integration->callback_failed = true;
    return;
  }
  if (error.status != FTUN_OK || result->socket == FTUN_INVALID_SOCKET) {
    fprintf(stderr, "DIRECT TCP failed: status=%d stage=%u socket=%lu\n",
            (int)error.status, error.stage,
            (unsigned long)result->socket);
    flow->failed = true;
    return;
  }
  status = create_socket_stream(integration, (int)result->socket,
                                &flow->outbound);
  if (status == FTUN_OK) {
    status = ftun_relay_start(integration->core, flow->inbound,
                              flow->outbound, &flow->relay);
  }
  if (status == FTUN_OK) {
    status = ftun_session_transition(flow->session,
                                     FTUN_SESSION_RELAYING, NULL);
  }
  if (status != FTUN_OK) {
    flow->failed = true;
    integration->callback_failed = true;
  }
}

static ftun_status_t start_direct_tcp(integration_t *integration,
                                      const ftun_metadata_t *metadata)
{
  tcp_flow_t *flow = &integration->tcp;
  ftun_target_t target;
  ftun_route_result_t route;
  ftun_outbound_leaf_t leaf;
  ftun_direct_request_t direct;
  ftun_outbound_request_t request;
  ftun_reject_result_t reject;
  ftun_status_t status;
  memset(&target, 0, sizeof(target));
  status = ftun_target_from_metadata(metadata, &target);
  if (status != FTUN_OK) return status;
  memset(&route, 0, sizeof(route));
  route.kind = FTUN_ROUTE_READY;
  route.generation = metadata->generation;
  route.outbound_id = 1u;
  route.allowed = target.candidates;
  route.allowed_count = target.candidate_count;
  status = ftun_target_apply_route(&target, &route);
  if (status != FTUN_OK) return status;
  status = ftun_session_transition(flow->session, FTUN_SESSION_ROUTING, NULL);
  if (status == FTUN_OK) status = ftun_session_pin_route(flow->session, &route);
  if (status != FTUN_OK) return status;
  memset(&leaf, 0, sizeof(leaf));
  leaf.generation = metadata->generation;
  leaf.id = 1u;
  leaf.kind = FTUN_OUTBOUND_LEAF_DIRECT;
  leaf.supports_tcp = true;
  leaf.supports_udp = true;
  memset(&direct, 0, sizeof(direct));
  direct.loop = integration->loop;
  direct.operations = integration->operations;
  direct.budget = integration->budget;
  direct.protection.mark = PROTECTION_MARK;
  direct.deadline_ms = deadline_after(5000u);
  direct.transport = FTUN_DIAL_TCP;
  direct.completion = direct_completed;
  direct.user = integration;
  memset(&request, 0, sizeof(request));
  request.route = &route;
  request.target = &target;
  request.leaf = &leaf;
  request.transport = FTUN_DIAL_TCP;
  request.direct = &direct;
  status = ftun_outbound_open(integration->core, &request, &reject,
                              &flow->open_operation);
  if (status != FTUN_OK) return status;
  status = ftun_session_transition(flow->session, FTUN_SESSION_CONNECTING,
                                   flow->open_operation);
  return status;
}

static ftun_status_t accept_stream(void *user,
                                   const ftun_metadata_t *metadata,
                                   ftun_stream_t *stream)
{
  integration_t *integration = (integration_t *)user;
  tcp_flow_t *flow = &integration->tcp;
  ftun_status_t status;
  if (flow->active || metadata == NULL || stream == NULL ||
      metadata->network != 1u) return FTUN_E_LIMIT;
  memset(flow, 0, sizeof(*flow));
  flow->socket.descriptor = -1;
  flow->active = true;
  flow->inbound = stream;
  integration->accepted_tcp++;
  status = ftun_session_submit(integration->core, metadata, stream,
                               &flow->session);
  if (status == FTUN_OK) status = start_direct_tcp(integration, metadata);
  if (status != FTUN_OK) {
    ftun_error_t error;
    memset(&error, 0, sizeof(error));
    error.status = status;
    if (flow->session != NULL) {
      (void)ftun_session_finish(flow->session, error);
    }
    flow->failed = true;
  }
  return status;
}

static void inbound_stream_event(void *user, ftun_stream_t *stream,
                                 ftun_tun_stream_event_t event,
                                 ftun_status_t status)
{
  integration_t *integration = (integration_t *)user;
  tcp_flow_t *flow = &integration->tcp;
  if (!flow->active || stream != flow->inbound) {
    integration->callback_failed = true;
    return;
  }
  if (event == FTUN_TUN_STREAM_READABLE ||
      event == FTUN_TUN_STREAM_PEER_FIN) {
    flow->left_events |= FTUN_EVENT_READ;
  } else if (event == FTUN_TUN_STREAM_WRITABLE) {
    flow->left_events |= FTUN_EVENT_WRITE;
  } else if (event == FTUN_TUN_STREAM_CLOSED) {
    /* lwIP 以 ERR_CLSD 结束已经完成 FIN 交换的 pcb；Relay 依据双方 EOF
     * 和已排空写入判断自然完成，不把该终止通知单独升级为失败。 */
    (void)status;
  }
}

static ftun_status_t output_packet(void *user, ftun_packet_port_t *port,
                                   ftun_bytes_t packet)
{
  integration_t *integration = (integration_t *)user;
  if (port != integration->port) return FTUN_E_STATE_CORRUPT;
  return ftun_packet_port_write(port, packet.data, packet.length);
}

static ftun_status_t datagram_send_start(
  void *user, ftun_datagram_send_t *datagram_send,
  const ftun_endpoint_t *target,
  const ftun_packet_t *packet)
{
  udp_slot_t *slot = (udp_slot_t *)user;
  ftun_bytes_t payload;
  ftun_error_t result;
  ssize_t length;
  if (slot == NULL || !slot->active || !endpoint_equal(target, &slot->remote) ||
      ftun_packet_view(packet, &payload) != FTUN_OK) return FTUN_E_INVALID;
  do {
    length = send(slot->descriptor, payload.data, payload.length,
                  MSG_NOSIGNAL);
  } while (length < 0 && errno == EINTR);
  if (length < 0) return socket_status(errno);
  if ((size_t)length != payload.length) return FTUN_E_IO;
  memset(&result, 0, sizeof(result));
  result.status = FTUN_OK;
  return ftun_datagram_send_complete(datagram_send, result);
}

static ftun_status_t datagram_send_cancel(void *user,
                                          ftun_datagram_send_t *send)
{
  (void)user;
  (void)send;
  return FTUN_OK;
}

static void datagram_destroy(void *user)
{
  udp_slot_t *slot = (udp_slot_t *)user;
  if (slot == NULL) return;
  if (slot->descriptor >= 0) (void)close(slot->descriptor);
  slot->descriptor = -1;
  slot->channel = NULL;
  slot->active = false;
}

static void capture_dial(ftun_operation_t *operation, ftun_error_t error,
                         const ftun_dial_result_t *result, void *user)
{
  dial_capture_t *capture = (dial_capture_t *)user;
  (void)operation;
  capture->calls++;
  capture->error = error;
  capture->socket = result == NULL ? FTUN_INVALID_SOCKET : result->socket;
}

static ftun_status_t open_udp_flow(
  void *user, ftun_core_t *core, const ftun_runtime_t *runtime,
  const ftun_metadata_t *metadata, ftun_datagram_result_fn result,
  ftun_datagram_receive_fn receive, void *callback_user,
  uint32_t *outbound_id, ftun_endpoint_t *remote, ftun_datagram_t **out)
{
  integration_t *integration = (integration_t *)user;
  ftun_target_t target;
  ftun_route_result_t route;
  ftun_outbound_leaf_t leaf;
  ftun_direct_request_t direct;
  ftun_outbound_request_t request;
  ftun_reject_result_t reject;
  ftun_operation_t *operation = NULL;
  ftun_datagram_options_t options;
  ftun_datagram_backend_t backend;
  ftun_runtime_info_t runtime_info;
  dial_capture_t capture;
  udp_slot_t *slot = NULL;
  ftun_status_t status;
  size_t dispatched = 0u;
  size_t index;
  (void)callback_user;
  if (out != NULL) *out = NULL;
  if (core != integration->core || runtime == NULL || metadata == NULL ||
      result == NULL || receive == NULL || outbound_id == NULL ||
      remote == NULL || out == NULL ||
      ftun_runtime_get_info(runtime, &runtime_info) != FTUN_OK ||
      runtime_info.generation != metadata->generation) return FTUN_E_INVALID;
  for (index = 0u; index < UDP_SLOTS; index++) {
    if (!integration->udp[index].active) {
      slot = &integration->udp[index];
      break;
    }
  }
  if (slot == NULL) return FTUN_E_LIMIT;
  memset(&target, 0, sizeof(target));
  status = ftun_target_from_metadata(metadata, &target);
  if (status != FTUN_OK) return status;
  memset(&route, 0, sizeof(route));
  route.kind = FTUN_ROUTE_READY;
  route.generation = metadata->generation;
  route.outbound_id = 1u;
  route.allowed = target.candidates;
  route.allowed_count = target.candidate_count;
  status = ftun_target_apply_route(&target, &route);
  if (status != FTUN_OK) return status;
  memset(&leaf, 0, sizeof(leaf));
  leaf.generation = metadata->generation;
  leaf.id = 1u;
  leaf.kind = FTUN_OUTBOUND_LEAF_DIRECT;
  leaf.supports_tcp = true;
  leaf.supports_udp = true;
  memset(&capture, 0, sizeof(capture));
  capture.socket = FTUN_INVALID_SOCKET;
  memset(&direct, 0, sizeof(direct));
  direct.loop = integration->loop;
  direct.operations = integration->operations;
  direct.budget = integration->budget;
  direct.protection.mark = PROTECTION_MARK;
  direct.deadline_ms = deadline_after(5000u);
  direct.transport = FTUN_DIAL_UDP;
  direct.completion = capture_dial;
  direct.user = &capture;
  memset(&request, 0, sizeof(request));
  request.route = &route;
  request.target = &target;
  request.leaf = &leaf;
  request.transport = FTUN_DIAL_UDP;
  request.direct = &direct;
  status = ftun_outbound_open(core, &request, &reject, &operation);
  if (status != FTUN_OK) return status;
  status = ftun_operation_dispatch(integration->operations, SIZE_MAX,
                                   &dispatched);
  if (status != FTUN_OK || capture.calls != 1 ||
      capture.error.status != FTUN_OK ||
      capture.socket == FTUN_INVALID_SOCKET) {
    if (capture.socket != FTUN_INVALID_SOCKET) (void)close((int)capture.socket);
    return status != FTUN_OK ? status : FTUN_E_STATE_CORRUPT;
  }
  memset(slot, 0, sizeof(*slot));
  slot->integration = integration;
  slot->descriptor = (int)capture.socket;
  slot->remote = target.allowed[0];
  slot->active = true;
  memset(&options, 0, sizeof(options));
  options.budget = integration->budget;
  options.max_pending_packets = 8u;
  options.max_pending_bytes = 65536u;
  options.result = result;
  options.receive = receive;
  options.user = callback_user;
  memset(&backend, 0, sizeof(backend));
  backend.send_start = datagram_send_start;
  backend.send_cancel = datagram_send_cancel;
  backend.destroy = datagram_destroy;
  backend.context = slot;
  status = ftun_datagram_create(&options, &backend, &slot->channel);
  if (status != FTUN_OK) {
    (void)close(slot->descriptor);
    memset(slot, 0, sizeof(*slot));
    slot->descriptor = -1;
    return status;
  }
  *outbound_id = 1u;
  *remote = slot->remote;
  *out = slot->channel;
  return FTUN_OK;
}

static ftun_status_t receive_tun_datagram(
  void *user, const ftun_metadata_t *metadata, ftun_datagram_t *channel,
  const ftun_endpoint_t *source, const ftun_packet_t *packet)
{
  integration_t *integration = (integration_t *)user;
  if (source == NULL || !endpoint_equal(source, &metadata->original_target)) {
    return FTUN_E_STATE_CORRUPT;
  }
  integration->received_udp++;
  return ftun_udp_flow_input_on(integration->udp_flows, channel,
                                metadata, (ftun_packet_t *)packet);
}

static ftun_status_t packet_from_bytes(integration_t *integration,
                                       const uint8_t *bytes, size_t length)
{
  ftun_buffer_t *buffer = NULL;
  ftun_buffer_slice_t slice;
  ftun_packet_t packet;
  uint8_t *storage = NULL;
  size_t capacity = 0u;
  ftun_status_t status;
  memset(&slice, 0, sizeof(slice));
  memset(&packet, 0, sizeof(packet));
  status = ftun_buffer_acquire(integration->budget, length, &buffer);
  if (status == FTUN_OK) status = ftun_buffer_data(buffer, &storage, &capacity);
  if (status == FTUN_OK && capacity < length) status = FTUN_E_STATE_CORRUPT;
  if (status == FTUN_OK) memcpy(storage, bytes, length);
  if (status == FTUN_OK) {
    status = ftun_buffer_slice(buffer, 0u, length, &slice);
  }
  if (status == FTUN_OK) {
    status = ftun_packet_init(&packet, &slice, INBOUND_ID);
  }
  (void)ftun_buffer_slice_release(&slice);
  (void)ftun_buffer_release(&buffer);
  if (status == FTUN_OK) {
    status = ftun_tun_ingress(integration->core, integration->port, &packet);
  }
  if (ftun_packet_release(&packet) != FTUN_OK && status == FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
  }
  return status;
}

static ftun_status_t process_tun(integration_t *integration)
{
  uint8_t packet[TUN_MTU];
  ftun_status_t status;
  for (;;) {
    size_t length = 0u;
    status = ftun_packet_port_read(integration->port, packet,
                                   sizeof(packet), &length);
    if (status == FTUN_E_AGAIN) return FTUN_OK;
    if (status != FTUN_OK) {
      fprintf(stderr, "TUN read failed: %d\n", (int)status);
      return status;
    }
    status = packet_from_bytes(integration, packet, length);
    if (status == FTUN_E_PROTOCOL && length != 0u &&
        (packet[0] >> 4) == 6u) {
      integration->rejected_ipv6++;
      continue;
    }
    if (status != FTUN_OK) {
      fprintf(stderr, "TUN ingress failed: %d version=%u protocol=%u "
              "length=%zu target=%u.%u.%u.%u\n", (int)status,
              length == 0u ? 0u : packet[0] >> 4,
              length <= 9u ? 0u : packet[9], length,
              length <= 19u ? 0u : packet[16],
              length <= 19u ? 0u : packet[17],
              length <= 19u ? 0u : packet[18],
              length <= 19u ? 0u : packet[19]);
      return status;
    }
  }
}

static ftun_status_t complete_socket_write(integration_t *integration)
{
  ftun_stream_write_t *pending = integration->tcp.socket.pending;
  ftun_error_t result;
  if (pending == NULL) return FTUN_OK;
  integration->tcp.socket.pending = NULL;
  memset(&result, 0, sizeof(result));
  result.status = FTUN_OK;
  return ftun_stream_write_complete(pending, result);
}

static ftun_status_t receive_udp_slot(udp_slot_t *slot)
{
  uint8_t payload[65535];
  ftun_buffer_t *buffer = NULL;
  ftun_buffer_slice_t slice;
  ftun_packet_t packet;
  uint8_t *storage = NULL;
  size_t capacity = 0u;
  ssize_t length;
  ftun_status_t status;
  memset(&slice, 0, sizeof(slice));
  memset(&packet, 0, sizeof(packet));
  do {
    length = recv(slot->descriptor, payload, sizeof(payload), 0);
  } while (length < 0 && errno == EINTR);
  if (length < 0) return socket_status(errno);
  status = ftun_buffer_acquire(slot->integration->budget,
    length == 0 ? 1u : (size_t)length, &buffer);
  if (status == FTUN_OK) status = ftun_buffer_data(buffer, &storage, &capacity);
  if (status == FTUN_OK && capacity < (size_t)length) {
    status = FTUN_E_STATE_CORRUPT;
  }
  if (status == FTUN_OK && length != 0) {
    memcpy(storage, payload, (size_t)length);
  }
  if (status == FTUN_OK) {
    status = ftun_buffer_slice(buffer, 0u, (size_t)length, &slice);
  }
  if (status == FTUN_OK) status = ftun_packet_init(&packet, &slice, 0u);
  (void)ftun_buffer_slice_release(&slice);
  (void)ftun_buffer_release(&buffer);
  if (status == FTUN_OK) {
    status = ftun_datagram_deliver(slot->channel, &slot->remote, &packet);
  }
  if (ftun_packet_release(&packet) != FTUN_OK && status == FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
  }
  return status;
}

static ftun_status_t drive_operations(integration_t *integration)
{
  size_t callbacks = 0u;
  size_t dispatched = 0u;
  ftun_status_t status;
  status = ftun_event_loop_run_once(integration->loop, false, 32u, &callbacks);
  if (status != FTUN_OK) return status;
  return ftun_operation_dispatch(integration->operations, SIZE_MAX,
                                 &dispatched);
}

static ftun_status_t drive_relay(integration_t *integration,
                                 uint32_t right_events)
{
  tcp_flow_t *flow = &integration->tcp;
  ftun_relay_usage_t usage;
  ftun_status_t status;
  size_t work = 0u;
  if (!flow->active || flow->relay == NULL) return FTUN_OK;
  status = ftun_relay_process(flow->relay, flow->left_events,
                              right_events, &work);
  flow->left_events = 0u;
  if (status != FTUN_OK) return status;
  status = complete_socket_write(integration);
  if (status != FTUN_OK) return status;
  status = drive_operations(integration);
  if (status != FTUN_OK) return status;
  status = ftun_relay_process(flow->relay, 0u, 0u, &work);
  if (status != FTUN_OK) return status;
  status = complete_socket_write(integration);
  if (status != FTUN_OK) return status;
  status = drive_operations(integration);
  if (status != FTUN_OK) return status;
  return ftun_relay_get_usage(flow->relay, &usage);
}

static int cleanup_tcp_flow(integration_t *integration)
{
  tcp_flow_t *flow = &integration->tcp;
  ftun_relay_usage_t usage;
  ftun_error_t result;
  ftun_status_t status;
  if (!flow->active) return 0;
  status = flow->relay == NULL ? FTUN_E_INVALID :
    ftun_relay_get_usage(flow->relay, &usage);
  if (status != FTUN_OK || !usage.complete ||
      usage.terminal_status != FTUN_OK) {
    fprintf(stderr, "TCP cleanup usage failed: status=%d complete=%d terminal=%d\n",
            (int)status, usage.complete, (int)usage.terminal_status);
    return 1;
  }
  status = ftun_relay_destroy(&flow->relay);
  if (status != FTUN_OK) {
    fprintf(stderr, "TCP relay destroy failed: %d\n", (int)status);
    return 1;
  }
  status = ftun_session_transition(flow->session,
                                   FTUN_SESSION_DRAINING, NULL);
  if (status != FTUN_OK) {
    fprintf(stderr, "TCP session draining failed: %d\n", (int)status);
    return 1;
  }
  memset(&result, 0, sizeof(result));
  result.status = FTUN_OK;
  status = ftun_session_finish(flow->session, result);
  if (status == FTUN_OK) status = ftun_session_destroy(&flow->session);
  if (status == FTUN_OK) status = ftun_stream_destroy(&flow->inbound);
  if (status == FTUN_OK) status = ftun_stream_stop(flow->outbound);
  if (status == FTUN_OK) status = ftun_stream_destroy(&flow->outbound);
  if (status != FTUN_OK) {
    fprintf(stderr, "TCP object cleanup failed: %d\n", (int)status);
    return 1;
  }
  memset(flow, 0, sizeof(*flow));
  flow->socket.descriptor = -1;
  return 0;
}

static pid_t spawn_client(const char *self, bool lan,
                          const char *transport, const char *tag)
{
  pid_t child = fork();
  if (child != 0) return child;
  if (lan) {
    execlp("ip", "ip", "netns", "exec", "ftun-lan", self,
           "--client", transport, tag, (char *)NULL);
  } else {
    execl(self, self, "--client", transport, tag, (char *)NULL);
  }
  _exit(127);
}

static int run_data_case(integration_t *integration, const char *self,
                         bool lan, const char *transport, const char *tag)
{
  struct pollfd descriptors[2u + UDP_SLOTS];
  uint64_t deadline = deadline_after(10000u);
  pid_t child = spawn_client(self, lan, transport, tag);
  int child_status = 0;
  bool child_done = false;
  size_t udp_before = integration->received_udp;
  size_t tcp_before = integration->accepted_tcp;
  if (child <= 0) return 1;
  while (!child_done || (strcmp(transport, "tcp") == 0 &&
                         integration->tcp.active)) {
    ftun_relay_usage_t relay_usage;
    uint32_t right_events = 0u;
    bool polled_tcp = false;
    bool polled_udp[UDP_SLOTS];
    size_t count = 0u;
    size_t index;
    uint64_t now = 0u;
    int ready;
    pid_t waited;
    memset(descriptors, 0, sizeof(descriptors));
    memset(polled_udp, 0, sizeof(polled_udp));
    descriptors[count].fd = (int)integration->port_info.native_socket;
    descriptors[count].events = POLLIN;
    count++;
    if (integration->tcp.active && integration->tcp.relay != NULL) {
      if (ftun_relay_get_usage(integration->tcp.relay, &relay_usage) != FTUN_OK) {
        return 1;
      }
      descriptors[count].fd = integration->tcp.socket.descriptor;
      if ((relay_usage.right_interests & FTUN_EVENT_READ) != 0u) {
        descriptors[count].events |= POLLIN;
      }
      if ((relay_usage.right_interests & FTUN_EVENT_WRITE) != 0u) {
        descriptors[count].events |= POLLOUT;
      }
      count++;
      polled_tcp = true;
    }
    for (index = 0u; index < UDP_SLOTS; index++) {
      if (!integration->udp[index].active) continue;
      descriptors[count].fd = integration->udp[index].descriptor;
      descriptors[count].events = POLLIN;
      count++;
      polled_udp[index] = true;
    }
    ready = poll(descriptors, count, 10);
    if (ready < 0 && errno == EINTR) continue;
    if (ready < 0) return 1;
    if ((descriptors[0].revents & POLLIN) != 0 &&
        process_tun(integration) != FTUN_OK) return 1;
    count = 1u;
    if (polled_tcp) {
      if ((descriptors[count].revents & POLLIN) != 0) {
        right_events |= FTUN_EVENT_READ;
      }
      if ((descriptors[count].revents & POLLOUT) != 0) {
        right_events |= FTUN_EVENT_WRITE;
      }
      if ((descriptors[count].revents & (POLLERR | POLLNVAL)) != 0) {
        right_events |= FTUN_EVENT_ERROR;
      }
      count++;
    }
    for (index = 0u; index < UDP_SLOTS; index++) {
      if (!polled_udp[index]) continue;
      if ((descriptors[count].revents & POLLIN) != 0 &&
          receive_udp_slot(&integration->udp[index]) != FTUN_OK) return 1;
      count++;
    }
    {
      ftun_status_t operation_status = drive_operations(integration);
      ftun_status_t relay_status = drive_relay(integration, right_events);
      ftun_status_t time_status = ftun_monotonic_now(&now);
      ftun_status_t ingress_status = time_status == FTUN_OK
        ? ftun_tun_ingress_tick(integration->ingress, now) : time_status;
      ftun_status_t flow_status = time_status == FTUN_OK
        ? ftun_udp_flow_tick(integration->udp_flows, now) : time_status;
      if (operation_status != FTUN_OK || relay_status != FTUN_OK ||
          time_status != FTUN_OK || ingress_status != FTUN_OK ||
          flow_status != FTUN_OK || integration->callback_failed ||
          integration->tcp.failed) {
        fprintf(stderr, "data drive failed: op=%d relay=%d time=%d "
                "ingress=%d flow=%d callback=%d tcp=%d accepted=%zu\n",
                (int)operation_status, (int)relay_status, (int)time_status,
                (int)ingress_status, (int)flow_status,
                integration->callback_failed, integration->tcp.failed,
                integration->accepted_tcp);
        return 1;
      }
    }
    if (integration->tcp.active && integration->tcp.relay != NULL &&
        ftun_relay_get_usage(integration->tcp.relay, &relay_usage) == FTUN_OK &&
        relay_usage.complete && child_done) {
      if (cleanup_tcp_flow(integration) != 0) {
        fprintf(stderr, "data case TCP cleanup failed\n");
        return 1;
      }
    }
    if (!child_done) {
      waited = waitpid(child, &child_status, WNOHANG);
      if (waited == child) child_done = true;
      else if (waited < 0) return 1;
    }
    if (ftun_monotonic_now(&now) != FTUN_OK || now >= deadline) {
      fprintf(stderr, "data case timed out: %s %s active=%d child=%d\n",
              transport, tag, integration->tcp.active, child_done);
      return 1;
    }
  }
  if (!child_done && waitpid(child, &child_status, 0) != child) return 1;
  if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
    fprintf(stderr, "data client failed: exited=%d status=%d\n",
            WIFEXITED(child_status),
            WIFEXITED(child_status) ? WEXITSTATUS(child_status) : -1);
    return 1;
  }
  if (strcmp(transport, "tcp") == 0) {
    if (integration->accepted_tcp != tcp_before + 1u) {
      fprintf(stderr, "unexpected TCP accepts: before=%zu after=%zu\n",
              tcp_before, integration->accepted_tcp);
      return 1;
    }
    return 0;
  }
  if (integration->received_udp != udp_before + 1u) {
    fprintf(stderr, "unexpected UDP receives: before=%zu after=%zu\n",
            udp_before, integration->received_udp);
    return 1;
  }
  return 0;
}

static void socks_completed(ftun_operation_t *operation, ftun_error_t error,
                            ftun_socks5_connection_t *connection, void *user)
{
  socks_completion_t *completion = (socks_completion_t *)user;
  (void)operation;
  completion->calls++;
  completion->error = error;
  completion->connection = connection;
}

static int drive_socks_completion(integration_t *integration,
                                  socks_completion_t *completion)
{
  uint64_t deadline = deadline_after(5000u);
  while (completion->calls == 0) {
    size_t callbacks = 0u;
    size_t dispatched = 0u;
    uint64_t now = 0u;
    if (ftun_event_loop_run_once(integration->loop, true, 32u,
                                 &callbacks) != FTUN_OK ||
        ftun_operation_dispatch(integration->operations, SIZE_MAX,
                                &dispatched) != FTUN_OK ||
        ftun_monotonic_now(&now) != FTUN_OK || now >= deadline) return 1;
  }
  return completion->calls == 1 ? 0 : 1;
}

static int nonblocking_exchange(int descriptor, const uint8_t *message,
                                size_t length)
{
  uint8_t response[256];
  size_t sent = 0u;
  size_t received = 0u;
  while (sent < length) {
    ssize_t amount = send(descriptor, message + sent, length - sent,
                          MSG_NOSIGNAL);
    if (amount > 0) sent += (size_t)amount;
    else if (amount < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      if (!wait_socket(descriptor, POLLOUT, 5000)) return 1;
    } else if (amount < 0 && errno == EINTR) {
      continue;
    } else {
      return 1;
    }
  }
  while (received < length) {
    ssize_t amount = recv(descriptor, response + received,
                          length - received, 0);
    if (amount > 0) received += (size_t)amount;
    else if (amount < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      if (!wait_socket(descriptor, POLLIN, 5000)) return 1;
    } else if (amount < 0 && errno == EINTR) {
      continue;
    } else {
      return 1;
    }
  }
  return memcmp(response, message, length) == 0 ? 0 : 1;
}

static int start_socks(integration_t *integration,
                       ftun_dial_transport_t transport, uint16_t target_port,
                       socks_completion_t *completion)
{
  ftun_endpoint_t candidate = endpoint4(PEER_ADDRESS, target_port);
  ftun_target_t target;
  ftun_route_result_t route;
  ftun_outbound_leaf_t leaf;
  ftun_socks5_proxy_t proxy;
  ftun_socks5_connect_request_t socks;
  ftun_outbound_request_t request;
  ftun_reject_result_t reject;
  ftun_operation_t *operation = NULL;
  ftun_status_t status;
  memset(completion, 0, sizeof(*completion));
  memset(&target, 0, sizeof(target));
  target.generation = integration->generation;
  target.original = candidate;
  target.candidates = &candidate;
  target.candidate_count = 1u;
  target.allowed = &candidate;
  target.allowed_count = 1u;
  memset(&route, 0, sizeof(route));
  route.kind = FTUN_ROUTE_READY;
  route.generation = integration->generation;
  route.outbound_id = 2u;
  route.allowed = &candidate;
  route.allowed_count = 1u;
  memset(&leaf, 0, sizeof(leaf));
  leaf.generation = integration->generation;
  leaf.id = 2u;
  leaf.kind = FTUN_OUTBOUND_LEAF_SOCKS5;
  leaf.supports_tcp = true;
  leaf.supports_udp = true;
  memset(&proxy, 0, sizeof(proxy));
  proxy.server = endpoint4(PEER_ADDRESS, SOCKS_PORT);
  proxy.udp_enabled = true;
  memset(&socks, 0, sizeof(socks));
  socks.loop = integration->loop;
  socks.operations = integration->operations;
  socks.budget = integration->budget;
  socks.proxy = &proxy;
  socks.target = &target;
  socks.protection.mark = PROTECTION_MARK;
  socks.deadline_ms = deadline_after(5000u);
  socks.transport = transport;
  socks.completion = socks_completed;
  socks.user = completion;
  memset(&request, 0, sizeof(request));
  request.route = &route;
  request.target = &target;
  request.leaf = &leaf;
  request.transport = transport;
  request.socks5 = &socks;
  status = ftun_outbound_open(integration->core, &request, &reject, &operation);
  if (status != FTUN_OK || operation == NULL) return 1;
  return drive_socks_completion(integration, completion);
}

static int test_socks(integration_t *integration)
{
  static const uint8_t tcp_payload[] = "socks-tcp";
  static const uint8_t udp_payload[] = "socks-udp";
  socks_completion_t completion;
  ftun_socks5_connection_info_t info;
  ftun_socks5_udp_datagram_t decoded;
  ftun_endpoint_t wrong;
  ftun_bytes_t payload;
  uint8_t frame[512];
  uint8_t response[512];
  size_t written = 0u;
  size_t consumed = 0u;
  ssize_t length;
  CHECK(start_socks(integration, FTUN_DIAL_TCP, DIRECT_TCP_PORT,
                    &completion) == 0);
  if (completion.error.status != FTUN_OK) {
    fprintf(stderr, "SOCKS TCP failed: status=%d stage=%u\n",
            (int)completion.error.status, completion.error.stage);
  }
  CHECK(completion.error.status == FTUN_OK && completion.connection != NULL);
  CHECK(ftun_socks5_connection_get_info(completion.connection, &info) ==
        FTUN_OK && info.transport == FTUN_DIAL_TCP &&
        info.data_socket != FTUN_INVALID_SOCKET);
  CHECK(nonblocking_exchange((int)info.data_socket, tcp_payload,
                             sizeof(tcp_payload) - 1u) == 0);
  CHECK(ftun_socks5_connection_close(&completion.connection) == FTUN_OK);

  CHECK(start_socks(integration, FTUN_DIAL_UDP, DIRECT_UDP_PORT,
                    &completion) == 0);
  CHECK(completion.error.status == FTUN_OK && completion.connection != NULL);
  CHECK(ftun_socks5_connection_get_info(completion.connection, &info) ==
        FTUN_OK && info.transport == FTUN_DIAL_UDP &&
        info.control_socket != FTUN_INVALID_SOCKET &&
        info.data_socket != FTUN_INVALID_SOCKET && info.relay.port != 0u);
  payload.data = udp_payload;
  payload.length = sizeof(udp_payload) - 1u;
  CHECK(ftun_socks5_connection_encode_udp(completion.connection, payload,
        frame, sizeof(frame), &written) == FTUN_OK && written > payload.length);
  CHECK(send((int)info.data_socket, frame, written, MSG_NOSIGNAL) ==
        (ssize_t)written);
  CHECK(wait_socket((int)info.data_socket, POLLIN, 5000));
  length = recv((int)info.data_socket, response, sizeof(response), 0);
  CHECK(length == (ssize_t)written);
  memset(&decoded, 0, sizeof(decoded));
  CHECK(ftun_socks5_connection_decode_udp(completion.connection,
        &info.relay, (ftun_bytes_t){response, (size_t)length},
        &decoded, &consumed) == FTUN_OK && consumed == (size_t)length &&
        decoded.payload.length == payload.length &&
        memcmp(decoded.payload.data, payload.data, payload.length) == 0);
  wrong = info.relay;
  wrong.port++;
  CHECK(ftun_socks5_connection_decode_udp(completion.connection,
        &wrong, (ftun_bytes_t){response, (size_t)length},
        &decoded, &consumed) == FTUN_E_REJECTED);
  CHECK(ftun_socks5_connection_close(&completion.connection) == FTUN_OK);

  CHECK(start_socks(integration, FTUN_DIAL_TCP, 9u, &completion) == 0);
  CHECK(completion.error.status == FTUN_E_REJECTED &&
        completion.connection == NULL);
  return 0;
}

typedef struct {
  ftun_endpoint_t dns;
  uint8_t expected_source[4];
  size_t calls;
} path_check_t;

static ftun_status_t check_resolver_path(
  void *user, const ftun_socket_policy_t *protection)
{
  path_check_t *check = (path_check_t *)user;
  struct sockaddr_in target;
  struct sockaddr_in local;
  socklen_t length = (socklen_t)sizeof(local);
  int descriptor;
  check->calls++;
  if (protection == NULL || protection->mark != PROTECTION_MARK) {
    return FTUN_E_REJECTED;
  }
  descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
  if (descriptor < 0) return FTUN_E_IO;
  memset(&target, 0, sizeof(target));
  target.sin_family = AF_INET;
  target.sin_port = htons(check->dns.port);
  memcpy(&target.sin_addr.s_addr, check->dns.address, 4u);
  if (connect(descriptor, (const struct sockaddr *)&target,
              (socklen_t)sizeof(target)) != 0 ||
      getsockname(descriptor, (struct sockaddr *)&local, &length) != 0 ||
      length != (socklen_t)sizeof(local) ||
      memcmp(&local.sin_addr.s_addr, check->expected_source, 4u) != 0) {
    (void)close(descriptor);
    return FTUN_E_REJECTED;
  }
  (void)close(descriptor);
  return FTUN_OK;
}

static void resolver_completed(
  ftun_operation_t *operation, ftun_error_t error,
  const ftun_system_resolve_result_t *result, void *user)
{
  resolver_completion_t *completion = (resolver_completion_t *)user;
  size_t index;
  (void)operation;
  completion->calls++;
  completion->error = error;
  if (result == NULL ||
      result->address_count > FTUN_SYSTEM_RESOLVER_MAX_IPV4_RESULTS) return;
  completion->address_count = result->address_count;
  for (index = 0u; index < result->address_count; index++) {
    completion->addresses[index] = result->addresses[index];
  }
}

static int test_system_resolver(integration_t *integration)
{
  ftun_system_resolve_request_t request;
  ftun_operation_t *operation = NULL;
  resolver_completion_t completion;
  path_check_t path;
  uint64_t deadline = deadline_after(5000u);
  memset(&completion, 0, sizeof(completion));
  memset(&path, 0, sizeof(path));
  path.dns = endpoint4(DNS_ADDRESS, 53u);
  CHECK(inet_pton(AF_INET, MAIN_ADDRESS, path.expected_source) == 1);
  memset(&request, 0, sizeof(request));
  request.worker = integration->worker;
  request.budget = integration->budget;
  request.domain.data = "guard.test";
  request.domain.length = 10u;
  request.protection.mark = PROTECTION_MARK;
  request.deadline_ms = deadline;
  request.check_path = check_resolver_path;
  request.path_user = &path;
  request.completion = resolver_completed;
  request.user = &completion;
  CHECK(ftun_system_resolve(integration->core, &request, &operation) ==
        FTUN_OK && operation != NULL && path.calls == 1u);
  while (completion.calls == 0) {
    size_t dispatched = 0u;
    uint64_t now = 0u;
    ftun_status_t packet_status = process_tun(integration);
    CHECK(packet_status == FTUN_OK);
    CHECK(ftun_worker_poll(integration->worker, 8u, &dispatched) == FTUN_OK);
    CHECK(ftun_monotonic_now(&now) == FTUN_OK && now < deadline);
  }
  CHECK(completion.calls == 1 && completion.error.status == FTUN_OK &&
        completion.address_count == 1u &&
        memcmp(completion.addresses[0].address,
               endpoint4(PEER_ADDRESS, 0u).address, 4u) == 0);

  /* 接纳后取消只终结逻辑请求；潜在 libc/NSS 后台结果仍由 Worker 排空。 */
  memset(&completion, 0, sizeof(completion));
  operation = NULL;
  CHECK(ftun_system_resolve(integration->core, &request, &operation) ==
        FTUN_OK && operation != NULL && path.calls == 2u);
  CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  while (completion.calls == 0) {
    size_t dispatched = 0u;
    uint64_t now = 0u;
    CHECK(process_tun(integration) == FTUN_OK);
    CHECK(ftun_worker_poll(integration->worker, 8u, &dispatched) == FTUN_OK);
    CHECK(ftun_monotonic_now(&now) == FTUN_OK && now < deadline);
  }
  CHECK(completion.calls == 1 &&
        completion.error.status == FTUN_E_CANCELLED &&
        completion.address_count == 0u);
  return 0;
}

static int test_strict_ipv6(void)
{
  struct sockaddr_in6 target;
  uint32_t mark = PROTECTION_MARK;
  int unprotected = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
  int protected_socket = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC,
                                IPPROTO_UDP);
  int result;
  CHECK(unprotected >= 0 && protected_socket >= 0);
  memset(&target, 0, sizeof(target));
  target.sin6_family = AF_INET6;
  target.sin6_port = htons(9u);
  CHECK(inet_pton(AF_INET6, "2001:db8:1::2", &target.sin6_addr) == 1);
  result = connect(unprotected, (const struct sockaddr *)&target,
                   (socklen_t)sizeof(target));
  CHECK(result != 0 && (errno == ENETUNREACH || errno == EACCES));
  CHECK(setsockopt(protected_socket, SOL_SOCKET, SO_MARK,
                   &mark, (socklen_t)sizeof(mark)) == 0);
  result = connect(protected_socket, (const struct sockaddr *)&target,
                   (socklen_t)sizeof(target));
  CHECK(result != 0 && (errno == ENETUNREACH || errno == EACCES));
  CHECK(close(protected_socket) == 0 && close(unprotected) == 0);
  return 0;
}

static ftun_config_t *integration_config(void)
{
  static const char json[] =
    "{\"dns\":{\"enable\":false},"
    "\"inbounds\":[{\"name\":\"integration\",\"type\":\"mixed\","
    "\"listen\":\"127.0.0.1:17890\"}],"
    "\"rules\":[\"MATCH,DIRECT\"]}";
  ftun_bytes_t input;
  ftun_config_t *config = NULL;
  ftun_feature_plan_t *plan = NULL;
  input.data = (const uint8_t *)json;
  input.length = sizeof(json) - 1u;
  if (ftun_config_parse(input, &config) != FTUN_OK) return NULL;
  if (ftun_config_compile(config, &plan) != FTUN_OK) {
    (void)ftun_config_destroy(&config);
    return NULL;
  }
  config->plan = plan;
  return config;
}

static int integration_start(integration_t *integration)
{
  ftun_runtime_t *candidate = NULL;
  ftun_runtime_manager_info_t manager_info;
  ftun_tun_spec_t tun_spec;
  ftun_route_policy_t route_policy;
  ftun_tun_ingress_spec_t ingress_spec;
  ftun_udp_flow_table_spec_t flow_spec;
  size_t index;
  memset(integration, 0, sizeof(*integration));
  integration->tcp.socket.descriptor = -1;
  for (index = 0u; index < UDP_SLOTS; index++) {
    integration->udp[index].descriptor = -1;
  }
  if (ftun_budget_create(NULL, 16u * 1024u * 1024u, 65536u,
                         &integration->budget) != FTUN_OK ||
      ftun_operation_queue_create(integration->budget, 256u,
                                  &integration->operations) != FTUN_OK ||
      ftun_event_loop_create(NULL, &integration->loop) != FTUN_OK ||
      ftun_libev_attach(integration->loop) != FTUN_OK ||
      ftun_worker_create(integration->budget, 4u,
                         &integration->worker) != FTUN_OK ||
      ftun_runtime_manager_create(integration->budget, 4u,
                                  &integration->core) != FTUN_OK) return 1;
  integration->config = integration_config();
  if (integration->config == NULL ||
      ftun_runtime_prepare(integration->core, integration->config,
                           &candidate) != FTUN_OK ||
      ftun_runtime_commit(integration->core, &candidate) != FTUN_OK ||
      ftun_config_destroy(&integration->config) != FTUN_OK ||
      ftun_runtime_manager_get_info(integration->core, &manager_info) !=
        FTUN_OK || !manager_info.has_active) return 1;
  integration->generation = manager_info.generation;
  if (ftun_monotonic_now(&integration->now_ms) != FTUN_OK) return 1;

  memset(&tun_spec, 0, sizeof(tun_spec));
  tun_spec.name.data = "ftun-it0";
  tun_spec.name.length = 8u;
  tun_spec.mtu = TUN_MTU;
  if (ftun_linux_tun_open(&tun_spec, &integration->port) != FTUN_OK ||
      ftun_packet_port_get_info(integration->port,
                                &integration->port_info) != FTUN_OK) return 1;
  memset(&route_policy, 0, sizeof(route_policy));
  route_policy.tun_interface = tun_spec.name;
  CHECK(inet_pton(AF_INET, "10.77.0.1", route_policy.tun_ipv4) == 1);
  route_policy.tun_prefix_length = 30u;
  route_policy.route_table = 100u;
  route_policy.rule_priority = 12340u;
  route_policy.protection_mark = PROTECTION_MARK;
  route_policy.protection_mark_mask = UINT32_MAX;
  route_policy.manage_local = true;
  route_policy.lan_interface.data = "lan0";
  route_policy.lan_interface.length = 4u;
  route_policy.strict_route = true;
  if (ftun_linux_route_prepare(&route_policy, &integration->routes) !=
      FTUN_OK) return 1;

  memset(&flow_spec, 0, sizeof(flow_spec));
  flow_spec.core = integration->core;
  flow_spec.budget = integration->budget;
  flow_spec.capacity = UDP_SLOTS;
  flow_spec.idle_timeout_ms = 100u;
  flow_spec.now_ms = integration->now_ms;
  flow_spec.backend.open = open_udp_flow;
  flow_spec.backend.user = integration;
  if (ftun_udp_flow_table_create(&flow_spec,
                                 &integration->udp_flows) != FTUN_OK) return 1;

  memset(&ingress_spec, 0, sizeof(ingress_spec));
  ingress_spec.core = integration->core;
  ingress_spec.port = integration->port;
  ingress_spec.budget = integration->budget;
  ingress_spec.operations = integration->operations;
  ingress_spec.generation = integration->generation;
  ingress_spec.now_ms = integration->now_ms;
  ingress_spec.inbound_id = INBOUND_ID;
  ingress_spec.mtu = TUN_MTU;
  ingress_spec.max_pending_stream_writes = 16u;
  ingress_spec.max_pending_stream_bytes = 131072u;
  ingress_spec.max_pending_datagrams = 16u;
  ingress_spec.max_pending_datagram_bytes = 131072u;
  ingress_spec.tcp = true;
  ingress_spec.udp = true;
  ingress_spec.stream_write_completion = stream_completion;
  ingress_spec.stream_accept = accept_stream;
  ingress_spec.stream_event = inbound_stream_event;
  ingress_spec.datagram_receive = receive_tun_datagram;
  ingress_spec.output = output_packet;
  ingress_spec.user = integration;
  return ftun_tun_ingress_bind(&ingress_spec, &integration->ingress) ==
    FTUN_OK ? 0 : 1;
}

static int integration_stop(integration_t *integration)
{
  ftun_budget_usage_t budget_usage;
  ftun_operation_queue_usage_t operation_usage;
  size_t dispatched = 0u;
  if (integration->tcp.active || integration->callback_failed) return 1;
  if (ftun_udp_flow_table_destroy(&integration->udp_flows) != FTUN_OK ||
      ftun_tun_ingress_close(&integration->ingress) != FTUN_OK ||
      ftun_linux_route_release(&integration->routes) != FTUN_OK ||
      ftun_packet_port_close(&integration->port) != FTUN_OK ||
      ftun_worker_stop(integration->worker) != FTUN_OK ||
      ftun_worker_join(integration->worker) != FTUN_OK ||
      ftun_worker_poll(integration->worker, SIZE_MAX, &dispatched) != FTUN_OK ||
      ftun_worker_destroy(&integration->worker) != FTUN_OK ||
      ftun_event_loop_stop(integration->loop) != FTUN_OK ||
      ftun_libev_detach(integration->loop) != FTUN_OK ||
      ftun_event_loop_destroy(&integration->loop) != FTUN_OK ||
      ftun_operation_queue_get_usage(integration->operations,
                                     &operation_usage) != FTUN_OK ||
      operation_usage.inflight != 0u ||
      ftun_operation_queue_stop(integration->operations) != FTUN_OK ||
      ftun_operation_queue_destroy(&integration->operations) != FTUN_OK ||
      ftun_runtime_manager_destroy(&integration->core) != FTUN_OK ||
      ftun_budget_get_usage(integration->budget, &budget_usage) != FTUN_OK ||
      budget_usage.used != 0u ||
      ftun_budget_destroy(&integration->budget) != FTUN_OK) return 1;
  return 0;
}

static int integration_main(const char *self)
{
  integration_t integration;
  ftun_udp_flow_usage_t flow_usage;
  uint64_t expire_at;
  CHECK(integration_start(&integration) == 0);
  CHECK(test_strict_ipv6() == 0);
  CHECK(test_system_resolver(&integration) == 0);
  CHECK(test_socks(&integration) == 0);
  CHECK(run_data_case(&integration, self, false, "tcp", "local-tcp") == 0);
  CHECK(run_data_case(&integration, self, false, "udp", "local-udp") == 0);
  CHECK(run_data_case(&integration, self, true, "tcp", "lan-tcp") == 0);
  CHECK(run_data_case(&integration, self, true, "udp", "lan-udp") == 0);
  CHECK(ftun_monotonic_now(&expire_at) == FTUN_OK &&
        expire_at <= UINT64_MAX - 200u);
  expire_at += 200u;
  CHECK(ftun_tun_ingress_tick(integration.ingress, expire_at) == FTUN_OK);
  CHECK(ftun_udp_flow_tick(integration.udp_flows, expire_at) == FTUN_OK);
  CHECK(ftun_udp_flow_get_usage(integration.udp_flows, &flow_usage) ==
        FTUN_OK && flow_usage.active == 0u && flow_usage.expired == 2u &&
        flow_usage.created == 2u);
  CHECK(integration.accepted_tcp == 2u && integration.received_udp == 2u);
  CHECK(integration_stop(&integration) == 0);
  return 0;
}

int main(int argc, char **argv)
{
  if (argc == 3 && strcmp(argv[1], "--peer") == 0) {
    return peer_main(argv[2]);
  }
  if (argc == 4 && strcmp(argv[1], "--client") == 0) {
    return client_main(argv[2], argv[3]);
  }
  if (argc == 2 && strcmp(argv[1], "--run") == 0) {
    return integration_main(argv[0]);
  }
  fprintf(stderr, "usage: %s --peer READY | --client tcp|udp TAG | --run\n",
          argv[0]);
  return 2;
}
