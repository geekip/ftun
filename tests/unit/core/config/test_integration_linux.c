#define _GNU_SOURCE 1

#include "platform/linux/route.h"
#include "app/config/compile.h"
#include "app/config/config.h"
#include "app/config/model.h"
#include "app/config/parser.h"
#include "core/limits.h"
#include "core/context.h"
#include "core/operation.h"
#include "proxy/runtime_state.h"
#include "proxy/session.h"
#include "core/worker.h"
#include "core/event/loop.h"
#include "core/event/backend.h"
#include "proxy/netstack/ingress.h"
#include "proxy/outbound/outbound.h"
#include "libs/tun/routes.h"
#include "libs/tun/interface_backend.h"
#include "libs/tun/port.h"
#include "platform/linux/uapi.h"
#include "libs/resolver/system.h"
#include "proxy/route/target.h"
#include "libs/transport/datagram.h"
#include "libs/transport/relay.h"
#include "libs/transport/stream.h"
#include "libs/tun/service.h"
#include "libs/tun/owner.h"
#include "proxy/udp/session.h"
#include "libs/buffer/buffer.h"
#include "platform/clock.h"

#include <stdatomic.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
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
#define HTTP_PORT 18082u
#define SOCKS_PORT 11080u
#define MESH_SOCKS_PORT 11081u
#define MESH_WIRE_PORT 19090u
#define MESH_ADDRESS "198.18.1.2"
#define MESH_TUN_NAME "ftun-meshp"
#define PROTECTION_MARK 77u
#define TUN_MTU 1400u
#define INBOUND_ID 41u
#define UDP_SLOTS 8u

/* 信号处理函数写、对端线程读；无锁原子可在信号处理函数中使用。 */
static atomic_int peer_stopping;
static pthread_mutex_t peer_threads_mutex = PTHREAD_MUTEX_INITIALIZER;
static size_t peer_threads;
static const char *peer_frs_path;

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

static int peer_read_exact(int descriptor, uint8_t *buffer, size_t length)
{
  size_t offset = 0u;
  while (offset < length && !peer_stopping) {
    struct pollfd item = {descriptor, POLLIN, 0};
    ssize_t result;
    int ready = poll(&item, 1u, 100);
    if (ready == 0) continue;
    if (ready < 0 && errno == EINTR) continue;
    if (ready < 0 || (item.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
      return 0;
    }
    if ((item.revents & POLLIN) == 0) continue;
    result = recv(descriptor, buffer + offset, length - offset, 0);
    if (result > 0) offset += (size_t)result;
    else if (result < 0 && errno == EINTR) continue;
    else return 0;
  }
  return offset == length;
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

static void *peer_http_thread(void *argument)
{
  int descriptor = *(int *)argument;
  uint8_t request[4096];
  size_t request_length = 0u;
  free(argument);
  while (request_length < sizeof(request) - 1u) {
    ssize_t amount = recv(descriptor, request + request_length,
                          sizeof(request) - 1u - request_length, 0);
    if (amount > 0) {
      request_length += (size_t)amount;
      request[request_length] = '\0';
      if (strstr((const char *)request, "\r\n\r\n") != NULL) break;
    } else if (amount < 0 && errno == EINTR) {
      continue;
    } else {
      break;
    }
  }
  if (request_length >= 16u &&
      memcmp(request, "GET /health ", 12u) == 0) {
    static const uint8_t response[] =
      "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n"
      "Connection: close\r\n\r\n";
    (void)write_exact(descriptor, response, sizeof(response) - 1u);
    fputs("http-health\n", stderr);
  } else if (request_length >= 18u &&
             memcmp(request, "GET /redirect ", 14u) == 0) {
    static const uint8_t response[] =
      "HTTP/1.1 302 Found\r\nLocation: /rules.frs\r\n"
      "Content-Length: 0\r\nConnection: close\r\n\r\n";
    (void)write_exact(descriptor, response, sizeof(response) - 1u);
    fputs("http-rules-redirect\n", stderr);
  } else if (request_length >= 18u &&
             memcmp(request, "GET /rules.frs ", 15u) == 0 &&
             peer_frs_path != NULL) {
    if (strstr((const char *)request, "If-None-Match: \"fixture-1\"") !=
        NULL) {
      static const uint8_t response[] =
        "HTTP/1.1 304 Not Modified\r\nETag: \"fixture-1\"\r\n"
        "Connection: close\r\n\r\n";
      (void)write_exact(descriptor, response, sizeof(response) - 1u);
      fputs("http-rules-conditional\n", stderr);
    } else {
      struct stat metadata;
      uint8_t *contents = NULL;
      char header[256];
      int file = open(peer_frs_path, O_RDONLY | O_CLOEXEC);
      if (file >= 0 && fstat(file, &metadata) == 0 &&
          metadata.st_size > 0 &&
          (uintmax_t)metadata.st_size <= (uintmax_t)SIZE_MAX) {
        size_t length = (size_t)metadata.st_size;
        size_t offset = 0u;
        contents = (uint8_t *)malloc(length);
        while (contents != NULL && offset < length) {
          ssize_t amount = read(file, contents + offset, length - offset);
          if (amount > 0) offset += (size_t)amount;
          else if (amount < 0 && errno == EINTR) continue;
          else break;
        }
        if (contents != NULL && offset == length) {
          int header_length = snprintf(header, sizeof(header),
            "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n"
            "ETag: \"fixture-1\"\r\nConnection: close\r\n\r\n", length);
          if (header_length > 0 && (size_t)header_length < sizeof(header)) {
            (void)write_exact(descriptor, (const uint8_t *)header,
                              (size_t)header_length);
            (void)write_exact(descriptor, contents, length);
            fputs("http-rules-full\n", stderr);
          }
        }
      }
      if (file >= 0) (void)close(file);
      free(contents);
    }
  } else {
    static const uint8_t response[] =
      "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n"
      "Connection: close\r\n\r\n";
    (void)write_exact(descriptor, response, sizeof(response) - 1u);
  }
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
    if (!peer_read_exact(descriptor, buffer, 1u)) return 0;
    length = buffer[0];
    if (length == 0u) return 0;
  } else {
    return 0;
  }
  if (!peer_read_exact(descriptor, buffer, length + 2u)) return 0;
  *port = (uint16_t)(((uint16_t)buffer[length] << 8) | buffer[length + 1u]);
  return 1;
}

static void peer_udp_association(int control)
{
  static int control_close_injected;
  static const uint8_t recovery_payload[] =
    "socks-udp-control-recovery";
  static const uint8_t backoff_payload[] =
    "socks-udp-backoff-probe";
  uint8_t reply[10] = {5u, 0u, 0u, 1u};
  uint8_t buffer[2048];
  struct sockaddr_in source;
  uint16_t port = 0u;
  int datagram = socket_bound(SOCK_DGRAM, PEER_ADDRESS, 0u);
  int outbound = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
  if (datagram < 0 || outbound < 0 || !socket_port(datagram, &port)) {
    if (datagram >= 0) (void)close(datagram);
    if (outbound >= 0) (void)close(outbound);
    return;
  }
  (void)inet_pton(AF_INET, PEER_ADDRESS, reply + 4u);
  reply[8] = (uint8_t)(port >> 8);
  reply[9] = (uint8_t)port;
  if (!write_exact(control, reply, sizeof(reply))) {
    (void)close(datagram);
    (void)close(outbound);
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
        ftun_socks5_udp_datagram_t request;
        size_t consumed = 0u;
        if (ftun_socks5_decode_udp_datagram(
              (ftun_bytes_t){buffer, (size_t)length}, &request,
              &consumed) == FTUN_OK && consumed == (size_t)length &&
            request.endpoint.kind == FTUN_ADDRESS_IPV4) {
          if (request.payload.length == sizeof(backoff_payload) - 1u &&
              memcmp(request.payload.data, backoff_payload,
                     sizeof(backoff_payload) - 1u) == 0) {
            fputs("udp-control-backoff-attempt\n", stderr);
            (void)shutdown(control, SHUT_RDWR);
            break;
          }
          struct sockaddr_in target;
          struct sockaddr_in remote;
          struct pollfd item;
          uint8_t response[2048];
          uint8_t framed[2300];
          socklen_t remote_length = (socklen_t)sizeof(remote);
          ssize_t response_length;
          size_t framed_length = 0u;
          memset(&target, 0, sizeof(target));
          target.sin_family = AF_INET;
          target.sin_port = htons(request.endpoint.port);
          memcpy(&target.sin_addr.s_addr, request.endpoint.address, 4u);
          if (sendto(outbound, request.payload.data, request.payload.length, 0,
                (const struct sockaddr *)&target,
                (socklen_t)sizeof(target)) < 0) continue;
          memset(&item, 0, sizeof(item));
          item.fd = outbound;
          item.events = POLLIN;
          if (poll(&item, 1u, 1000) != 1 ||
              (item.revents & POLLIN) == 0) continue;
          response_length = recvfrom(outbound, response, sizeof(response), 0,
            (struct sockaddr *)&remote, &remote_length);
          if (response_length < 0 || remote.sin_family != AF_INET) continue;
          {
            ftun_endpoint_t response_source;
            memset(&response_source, 0, sizeof(response_source));
            response_source.kind = FTUN_ADDRESS_IPV4;
            response_source.port = ntohs(remote.sin_port);
            memcpy(response_source.address, &remote.sin_addr.s_addr, 4u);
            if (ftun_socks5_encode_udp_datagram(&response_source,
                  (ftun_bytes_t){response, (size_t)response_length}, framed,
                  sizeof(framed), &framed_length) != FTUN_OK) continue;
          }
          (void)sendto(datagram, framed, framed_length, 0,
                       (const struct sockaddr *)&source, source_length);
          if (getenv("FTUN_TEST_UDP_CONTROL_CLOSE") != NULL &&
              request.payload.length == sizeof(recovery_payload) - 1u &&
              memcmp(request.payload.data, recovery_payload,
                     sizeof(recovery_payload) - 1u) == 0 &&
              __atomic_exchange_n(&control_close_injected, 1,
                                  __ATOMIC_RELAXED) == 0) {
            fputs("udp-control-closed\n", stderr);
            (void)shutdown(control, SHUT_RDWR);
            break;
          }
        }
      }
    }
  }
  (void)close(outbound);
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
  if (!peer_read_exact(descriptor, header, 2u) || header[0] != 5u ||
      header[1] == 0u || !peer_read_exact(descriptor, methods, header[1]) ||
      !write_exact(descriptor, (const uint8_t *)"\x05\x00", 2u) ||
      !peer_read_exact(descriptor, header, 4u) || header[0] != 5u ||
      header[2] != 0u || !peer_socks_read_endpoint(
        descriptor, header[3], &target_port)) goto done;
  if (header[3] == 3u) fputs("socks-domain-target\n", stderr);
  if (target_port == 9u) {
    reply[1] = 5u;
    (void)write_exact(descriptor, reply, sizeof(reply));
    goto done;
  }
  if (header[1] == 1u) {
    if (!write_exact(descriptor, reply, sizeof(reply))) goto done;
    while (!peer_stopping) {
      struct pollfd item = {descriptor, POLLIN, 0};
      ssize_t length;
      int ready = poll(&item, 1u, 100);
      if (ready == 0) continue;
      if (ready < 0 && errno == EINTR) continue;
      if (ready < 0 || (item.revents & (POLLERR | POLLHUP)) != 0) break;
      length = recv(descriptor, methods, sizeof(methods), 0);
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

static void peer_dns_reply(int descriptor, const char *default_address)
{
  static const uint8_t upstream_name[] = {
    3u, 'd', 'n', 's', 7u, 'r', 'e', 'l', 'e', 'a', 's', 'e',
    4u, 't', 'e', 's', 't', 0u
  };
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
  (void)inet_pton(AF_INET,
    (size_t)length >= 12u + sizeof(upstream_name) &&
    memcmp(query + 12u, upstream_name, sizeof(upstream_name)) == 0
      ? DNS_ADDRESS : default_address,
    response + length + 12u);
  (void)sendto(descriptor, response, output_length, 0,
               (const struct sockaddr *)&source, source_length);
}

static void peer_signal(int signal_number)
{
  (void)signal_number;
  peer_stopping = 1;
}

static int peer_route_drive(ftun_event_loop_t *loop,
                            ftun_route_async_t *routes,
                            ftun_route_async_state_t terminal,
                            uint64_t deadline_ms)
{
  for (;;) {
    ftun_route_async_info_t info;
    size_t work = 0u;
    size_t callbacks = 0u;
    uint64_t now_ms = 0u;
    if (ftun_monotonic_now(&now_ms) != FTUN_OK || now_ms >= deadline_ms ||
        ftun_route_async_get_info(routes, &info) != FTUN_OK) return 0;
    if (info.state == terminal) return 1;
    if (info.state == FTUN_ROUTE_ASYNC_FAILED ||
        info.state == FTUN_ROUTE_ASYNC_CLEANUP_FAILED ||
        ftun_route_async_run(routes, now_ms, 8u, &work) != FTUN_OK ||
        ftun_route_async_get_info(routes, &info) != FTUN_OK) return 0;
    if (info.state == terminal) return 1;
    if (ftun_event_loop_run_once(loop, work == 0u && !info.runnable, 8u,
                                 &callbacks) != FTUN_OK) return 0;
  }
}

static int peer_main(const char *ready_path, const char *frs_path)
{
  struct pollfd descriptors[8];
  struct sigaction action;
  struct sockaddr_in main_wire_address;
  ftun_event_loop_t *route_loop = NULL;
  ftun_packet_port_t *mesh_port = NULL;
  ftun_packet_port_info_t mesh_info;
  ftun_route_plan_t mesh_plan;
  ftun_route_async_t *mesh_routes = NULL;
  ftun_tun_spec_t mesh_tun;
  uint8_t buffer[2048];
  int direct_tcp = socket_bound(SOCK_STREAM, PEER_ADDRESS, DIRECT_TCP_PORT);
  int direct_udp = socket_bound(SOCK_DGRAM, PEER_ADDRESS, DIRECT_UDP_PORT);
  int socks = socket_bound(SOCK_STREAM, PEER_ADDRESS, SOCKS_PORT);
  int mesh_socks = -1;
  int mesh_wire = socket_bound(SOCK_DGRAM, PEER_ADDRESS, MESH_WIRE_PORT);
  int http = socket_bound(SOCK_STREAM, PEER_ADDRESS, HTTP_PORT);
  int dns = socket_bound(SOCK_DGRAM, DNS_ADDRESS, 53u);
  int ready;
  uint64_t now_ms = 0u;
  peer_frs_path = frs_path;
  memset(&mesh_tun, 0, sizeof(mesh_tun));
  mesh_tun.name.data = MESH_TUN_NAME;
  mesh_tun.name.length = strlen(MESH_TUN_NAME);
  mesh_tun.mtu = TUN_MTU;
  memset(&mesh_plan, 0, sizeof(mesh_plan));
  mesh_plan.resource_count = 2u;
  mesh_plan.resources[0].kind = FTUN_LINUX_ROUTE_ADDRESS;
  mesh_plan.resources[0].family = AF_INET;
  memcpy(mesh_plan.resources[0].interface_name, MESH_TUN_NAME,
         sizeof(MESH_TUN_NAME));
  CHECK(inet_pton(AF_INET, MESH_ADDRESS,
                  mesh_plan.resources[0].address) == 1);
  mesh_plan.resources[0].prefix_length = 16u;
  mesh_plan.resources[0].protocol = FTUN_LINUX_ROUTE_PROTOCOL;
  mesh_plan.resources[1].kind = FTUN_LINUX_ROUTE_OVERLAY;
  mesh_plan.resources[1].family = AF_INET;
  memcpy(mesh_plan.resources[1].interface_name, MESH_TUN_NAME,
         sizeof(MESH_TUN_NAME));
  memcpy(mesh_plan.resources[1].address,
         (uint8_t[]){10u, 77u, 0u, 0u}, 4u);
  mesh_plan.resources[1].prefix_length = 30u;
  mesh_plan.resources[1].table = FTUN_RT_TABLE_MAIN;
  mesh_plan.resources[1].metric = 100u;
  mesh_plan.resources[1].protocol = FTUN_LINUX_ROUTE_PROTOCOL;
  if (direct_tcp < 0 || direct_udp < 0 || socks < 0 || mesh_wire < 0 ||
      http < 0 || dns < 0 || ftun_event_loop_create(NULL, &route_loop) !=
        FTUN_OK || ftun_event_backend_attach(route_loop) != FTUN_OK ||
      ftun_tun_port_open(&mesh_tun, &mesh_port) != FTUN_OK ||
      ftun_packet_port_get_info(mesh_port, &mesh_info) != FTUN_OK ||
      ftun_monotonic_now(&now_ms) != FTUN_OK ||
      ftun_route_async_start_plan(&mesh_plan, route_loop, now_ms, 250u,
        now_ms + 5000u, &mesh_routes) != FTUN_OK ||
      !peer_route_drive(route_loop, mesh_routes,
                        FTUN_ROUTE_ASYNC_READY, now_ms + 5000u)) return 1;
  mesh_socks = socket_bound(SOCK_STREAM, MESH_ADDRESS, MESH_SOCKS_PORT);
  if (mesh_socks < 0 ||
      listen(direct_tcp, 128) != 0 || listen(socks, 128) != 0 ||
      listen(mesh_socks, 128) != 0 ||
      listen(http, 128) != 0 || !set_nonblocking(direct_tcp) ||
      !set_nonblocking(socks) || !set_nonblocking(mesh_socks) ||
      !set_nonblocking(mesh_wire) || !set_nonblocking(http)) return 1;
  memset(&main_wire_address, 0, sizeof(main_wire_address));
  main_wire_address.sin_family = AF_INET;
  main_wire_address.sin_port = htons(MESH_WIRE_PORT);
  CHECK(inet_pton(AF_INET, MAIN_ADDRESS, &main_wire_address.sin_addr) == 1);
  memset(&action, 0, sizeof(action));
  action.sa_handler = peer_signal;
  (void)sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGTERM, &action, NULL) == 0);
  ready = open(ready_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  CHECK(ready >= 0 && write(ready, "ready\n", 6u) == 6);
  (void)close(ready);
  while (!peer_stopping) {
    int count;
    memset(descriptors, 0, sizeof(descriptors));
    descriptors[0] = (struct pollfd){direct_tcp, POLLIN, 0};
    descriptors[1] = (struct pollfd){direct_udp, POLLIN, 0};
    descriptors[2] = (struct pollfd){socks, POLLIN, 0};
    descriptors[3] = (struct pollfd){dns, POLLIN, 0};
    descriptors[4] = (struct pollfd){http, POLLIN, 0};
    descriptors[5] = (struct pollfd){mesh_socks, POLLIN, 0};
    descriptors[6] = (struct pollfd){(int)mesh_info.native_socket, POLLIN, 0};
    descriptors[7] = (struct pollfd){mesh_wire, POLLIN, 0};
    count = poll(descriptors, 8u, 100);
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
    if ((descriptors[3].revents & POLLIN) != 0) {
      peer_dns_reply(dns, PEER_ADDRESS);
    }
    if ((descriptors[4].revents & POLLIN) != 0 &&
        !peer_accept_thread(http, peer_http_thread)) break;
    if ((descriptors[5].revents & POLLIN) != 0 &&
        !peer_accept_thread(mesh_socks, peer_socks_thread)) break;
    if ((descriptors[6].revents & POLLIN) != 0) {
      size_t length = 0u;
      ftun_status_t status;
      do {
        status = ftun_packet_port_read(mesh_port, buffer, TUN_MTU, &length);
        if (status == FTUN_OK && sendto(mesh_wire, buffer, length, 0,
              (const struct sockaddr *)&main_wire_address,
              (socklen_t)sizeof(main_wire_address)) != (ssize_t)length) {
          status = FTUN_E_IO;
        }
      } while (status == FTUN_OK);
      if (status != FTUN_E_AGAIN) break;
    }
    if ((descriptors[7].revents & POLLIN) != 0) {
      ssize_t length;
      do {
        length = recv(mesh_wire, buffer, TUN_MTU, 0);
        if (length > 0 && ftun_packet_port_write(
              mesh_port, buffer, (size_t)length) != FTUN_OK) break;
      } while (length > 0);
      if (length < 0 && errno != EAGAIN && errno != EWOULDBLOCK) break;
    }
  }
  (void)close(mesh_socks);
  (void)close(mesh_wire);
  (void)close(http);
  (void)close(dns);
  (void)close(socks);
  (void)close(direct_udp);
  (void)close(direct_tcp);
  if (ftun_monotonic_now(&now_ms) == FTUN_OK && mesh_routes != NULL &&
      ftun_route_async_release(mesh_routes, now_ms,
                                     now_ms + 5000u) == FTUN_OK) {
    (void)peer_route_drive(route_loop, mesh_routes,
                           FTUN_ROUTE_ASYNC_RELEASED, now_ms + 5000u);
  }
  (void)ftun_route_async_destroy(&mesh_routes);
  (void)ftun_packet_port_close(&mesh_port);
  (void)ftun_event_loop_stop(route_loop);
  (void)ftun_event_backend_detach(route_loop);
  (void)ftun_event_loop_destroy(&route_loop);
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

static int client_main(const char *transport, const char *tag,
                       const char *target_address)
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
  if (inet_pton(AF_INET, target_address, &target.sin_addr) != 1 ||
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

static int parse_ipv4_target(const char *text, struct sockaddr_in *out,
                             char *normalized, size_t normalized_capacity)
{
  const char *colon = strrchr(text, ':');
  char address[INET_ADDRSTRLEN];
  char *tail = NULL;
  unsigned long port;
  size_t length;
  if (colon == NULL || colon == text || out == NULL) return 0;
  length = (size_t)(colon - text);
  if (length >= sizeof(address)) return 0;
  memcpy(address, text, length);
  address[length] = '\0';
  errno = 0;
  port = strtoul(colon + 1u, &tail, 10);
  if (errno != 0 || tail == colon + 1u || *tail != '\0' ||
      port == 0u || port > UINT16_MAX) return 0;
  memset(out, 0, sizeof(*out));
  out->sin_family = AF_INET;
  out->sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, address, &out->sin_addr) != 1) return 0;
  if (normalized != NULL && (snprintf(normalized, normalized_capacity,
      "%s:%lu", address, port) <= 0 || strlen(normalized) >=
      normalized_capacity)) return 0;
  return 1;
}

static int proxy_connect(uint16_t port)
{
  struct sockaddr_in address;
  struct timeval timeout;
  int descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (descriptor < 0) return -1;
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;
  (void)setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO,
                   &timeout, sizeof(timeout));
  (void)setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO,
                   &timeout, sizeof(timeout));
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  (void)inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
  if (connect(descriptor, (const struct sockaddr *)&address,
              (socklen_t)sizeof(address)) != 0) {
    (void)close(descriptor);
    return -1;
  }
  return descriptor;
}

static int proxy_echo(int descriptor, const char *tag)
{
  uint8_t response[128];
  size_t length = strlen(tag);
  if (!write_exact(descriptor, (const uint8_t *)tag, length)) return 0;
  (void)shutdown(descriptor, SHUT_WR);
  return read_exact(descriptor, response, length) &&
         memcmp(response, tag, length) == 0;
}

static int socks_client_with_hold_main(const char *port_text,
                                       const char *target_text,
                                       const char *hold_text)
{
  uint8_t offer[3] = {5u, 1u, 0u};
  uint8_t selected[2];
  uint8_t request[10] = {5u, 1u, 0u, 1u};
  uint8_t reply[10];
  struct sockaddr_in target;
  char *tail = NULL;
  unsigned long port = strtoul(port_text, &tail, 10);
  unsigned long hold_ms = 0u;
  int descriptor;
  int step = 0;
  if (tail == port_text || *tail != '\0' || port == 0u ||
      port > UINT16_MAX || !parse_ipv4_target(target_text, &target,
                                               NULL, 0u)) return 1;
  if (hold_text != NULL) {
    errno = 0;
    hold_ms = strtoul(hold_text, &tail, 10);
    if (errno != 0 || tail == hold_text || *tail != '\0' ||
        hold_ms > 120000u) return 1;
  }
  descriptor = proxy_connect((uint16_t)port);
  if (descriptor < 0) return 1;
  memcpy(request + 4u, &target.sin_addr.s_addr, 4u);
  memcpy(request + 8u, &target.sin_port, 2u);
  if (!write_exact(descriptor, offer, sizeof(offer))) step = 1;
  else if (!read_exact(descriptor, selected, sizeof(selected))) step = 2;
  else if (selected[0] != 5u || selected[1] != 0u) step = 3;
  else if (!write_exact(descriptor, request, sizeof(request))) step = 4;
  else if (!read_exact(descriptor, reply, sizeof(reply))) step = 5;
  else if (reply[0] != 5u || reply[1] != 0u) step = 6;
  else {
    if (hold_ms != 0u) {
      struct timespec delay;
      delay.tv_sec = (time_t)(hold_ms / 1000u);
      delay.tv_nsec = (long)(hold_ms % 1000u) * 1000000L;
      while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {}
    }
    if (!proxy_echo(descriptor, "socks-production")) step = 7;
  }
  if (step != 0) {
    fprintf(stderr, "SOCKS production client failed at step %d (errno=%d)\n",
            step, errno);
    (void)close(descriptor);
    return 1;
  }
  (void)close(descriptor);
  return 0;
}

static int socks_client_main(const char *port_text, const char *target_text)
{
  return socks_client_with_hold_main(port_text, target_text, NULL);
}

static int socks_stall_client_main(const char *port_text,
                                   const char *hold_text)
{
  struct timespec delay;
  char *tail = NULL;
  unsigned long port;
  unsigned long hold_ms;
  uint8_t byte = 5u;
  ssize_t received;
  int descriptor;
  errno = 0;
  port = strtoul(port_text, &tail, 10);
  if (errno != 0 || tail == port_text || *tail != '\0' || port == 0u ||
      port > UINT16_MAX) return 1;
  errno = 0;
  hold_ms = strtoul(hold_text, &tail, 10);
  if (errno != 0 || tail == hold_text || *tail != '\0' ||
      hold_ms > 120000u) return 1;
  descriptor = proxy_connect((uint16_t)port);
  if (descriptor < 0 || send(descriptor, &byte, 1u, MSG_NOSIGNAL) != 1) {
    if (descriptor >= 0) (void)close(descriptor);
    return 1;
  }
  delay.tv_sec = (time_t)(hold_ms / 1000u);
  delay.tv_nsec = (long)(hold_ms % 1000u) * 1000000L;
  while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {}
  received = recv(descriptor, &byte, 1u, MSG_DONTWAIT);
  (void)close(descriptor);
  return received == 0 || (received < 0 &&
    (errno == ECONNRESET || errno == ENOTCONN)) ? 0 : 1;
}

static int tcp_hold_clients_main(const char *port_text,
                                 const char *count_text,
                                 const char *hold_text)
{
  struct timespec delay;
  char *tail = NULL;
  unsigned long port;
  unsigned long count;
  unsigned long hold_ms;
  int *descriptors;
  size_t opened = 0u;
  size_t index;
  errno = 0;
  port = strtoul(port_text, &tail, 10);
  if (errno != 0 || tail == port_text || *tail != '\0' || port == 0u ||
      port > UINT16_MAX) return 1;
  errno = 0;
  count = strtoul(count_text, &tail, 10);
  if (errno != 0 || tail == count_text || *tail != '\0' || count == 0u ||
      count > 1024u) return 1;
  errno = 0;
  hold_ms = strtoul(hold_text, &tail, 10);
  if (errno != 0 || tail == hold_text || *tail != '\0' ||
      hold_ms > 120000u) return 1;
  descriptors = (int *)malloc((size_t)count * sizeof(*descriptors));
  if (descriptors == NULL) return 1;
  for (index = 0u; index < (size_t)count; index++) descriptors[index] = -1;
  for (index = 0u; index < (size_t)count; index++) {
    descriptors[index] = proxy_connect((uint16_t)port);
    if (descriptors[index] < 0) break;
    opened++;
  }
  delay.tv_sec = (time_t)(hold_ms / 1000u);
  delay.tv_nsec = (long)(hold_ms % 1000u) * 1000000L;
  while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {}
  for (index = 0u; index < opened; index++) (void)close(descriptors[index]);
  free(descriptors);
  return opened == (size_t)count ? 0 : 1;
}

typedef struct {
  int descriptor;
  size_t length;
  size_t completed;
  uint8_t payload[16384];
  int succeeded;
} socks_load_writer_t;

static void *socks_load_writer(void *argument)
{
  socks_load_writer_t *writer = (socks_load_writer_t *)argument;
  size_t remaining = writer->length;
  writer->succeeded = 0;
  while (remaining != 0u) {
    size_t amount = remaining < sizeof(writer->payload)
      ? remaining : sizeof(writer->payload);
    if (!write_exact(writer->descriptor, writer->payload, amount)) return NULL;
    remaining -= amount;
    writer->completed += amount;
  }
  writer->succeeded = 1;
  return NULL;
}

static int load_echo(int descriptor, size_t requested, const char *path)
{
  uint8_t response[16384];
  socks_load_writer_t writer;
  pthread_t writer_thread;
  uint64_t started;
  uint64_t finished;
  uint64_t elapsed;
  size_t remaining;
  size_t index;
  int reader_succeeded = 1;
  memset(&writer, 0, sizeof(writer));
  writer.descriptor = descriptor;
  writer.length = requested;
  for (index = 0u; index < sizeof(writer.payload); index++) {
    writer.payload[index] = (uint8_t)(index * 31u + 17u);
  }
  if (ftun_monotonic_now(&started) != FTUN_OK ||
      pthread_create(&writer_thread, NULL, socks_load_writer, &writer) != 0) {
    return 1;
  }
  remaining = requested;
  while (remaining != 0u) {
    size_t amount = remaining < sizeof(writer.payload)
      ? remaining : sizeof(writer.payload);
    if (!read_exact(descriptor, response, amount) ||
        memcmp(writer.payload, response, amount) != 0) {
      reader_succeeded = 0;
      break;
    }
    remaining -= amount;
  }
  if (!reader_succeeded) (void)shutdown(descriptor, SHUT_RDWR);
  if (pthread_join(writer_thread, NULL) != 0 || !reader_succeeded ||
      !writer.succeeded) {
    fprintf(stderr, "load echo failed path=%s sent=%zu received=%zu "
            "requested=%zu errno=%d\n", path, writer.completed,
            requested - remaining, requested, errno);
    return 1;
  }
  if (ftun_monotonic_now(&finished) != FTUN_OK || finished < started) return 1;
  elapsed = finished - started;
  if (elapsed == 0u) elapsed = 1u;
  printf("production-data-plane path=%s bytes=%zu elapsed-ms=%llu "
         "throughput-mib-s=%.2f\n",
         path, requested, (unsigned long long)elapsed,
         ((double)requested * 1000.0) /
           ((double)elapsed * 1024.0 * 1024.0));
  return 0;
}

static int load_client_main(const char *target_text, const char *bytes_text,
                            const char *path)
{
  struct sockaddr_in target;
  struct timeval timeout;
  char *tail = NULL;
  unsigned long long requested;
  int descriptor;
  if (!parse_ipv4_target(target_text, &target, NULL, 0u)) return 1;
  errno = 0;
  requested = strtoull(bytes_text, &tail, 10);
  if (errno != 0 || tail == bytes_text || *tail != '\0' || requested == 0u ||
      requested > (unsigned long long)SIZE_MAX) return 1;
  descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (descriptor < 0) return 1;
  timeout.tv_sec = 30;
  timeout.tv_usec = 0;
  if (setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO,
                 &timeout, sizeof(timeout)) != 0 ||
      setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO,
                 &timeout, sizeof(timeout)) != 0 ||
      connect(descriptor, (const struct sockaddr *)&target,
              (socklen_t)sizeof(target)) != 0 ||
      load_echo(descriptor, (size_t)requested, path) != 0) {
    (void)close(descriptor);
    return 1;
  }
  (void)close(descriptor);
  return 0;
}

static int socks_load_client_main(const char *port_text,
                                  const char *target_text,
                                  const char *bytes_text)
{
  uint8_t offer[3] = {5u, 1u, 0u};
  uint8_t selected[2];
  uint8_t request[10] = {5u, 1u, 0u, 1u};
  uint8_t reply[10];
  struct sockaddr_in target;
  char *tail = NULL;
  unsigned long port = strtoul(port_text, &tail, 10);
  unsigned long long requested;
  int descriptor;
  if (tail == port_text || *tail != '\0' || port == 0u ||
      port > UINT16_MAX || !parse_ipv4_target(target_text, &target,
                                               NULL, 0u)) return 1;
  errno = 0;
  requested = strtoull(bytes_text, &tail, 10);
  if (errno != 0 || tail == bytes_text || *tail != '\0' || requested == 0u ||
      requested > (unsigned long long)SIZE_MAX) return 1;
  descriptor = proxy_connect((uint16_t)port);
  if (descriptor < 0) return 1;
  memcpy(request + 4u, &target.sin_addr.s_addr, 4u);
  memcpy(request + 8u, &target.sin_port, 2u);
  if (!write_exact(descriptor, offer, sizeof(offer)) ||
      !read_exact(descriptor, selected, sizeof(selected)) ||
      selected[0] != 5u || selected[1] != 0u ||
      !write_exact(descriptor, request, sizeof(request)) ||
      !read_exact(descriptor, reply, sizeof(reply)) ||
      reply[0] != 5u || reply[1] != 0u) {
    (void)close(descriptor);
    return 1;
  }
  if (load_echo(descriptor, (size_t)requested, "socks5") != 0) {
    (void)close(descriptor);
    return 1;
  }
  (void)close(descriptor);
  return 0;
}

static int socks_domain_client_main(const char *port_text,
                                    const char *target_text)
{
  uint8_t offer[3] = {5u, 1u, 0u};
  uint8_t selected[2];
  uint8_t request[262] = {5u, 1u, 0u, 3u};
  uint8_t reply[10];
  const char *colon = strrchr(target_text, ':');
  char *tail = NULL;
  unsigned long listener_port = strtoul(port_text, &tail, 10);
  unsigned long target_port;
  size_t domain_length;
  int descriptor;
  int step = 0;
  if (tail == port_text || *tail != '\0' || listener_port == 0u ||
      listener_port > UINT16_MAX || colon == NULL || colon == target_text) {
    return 1;
  }
  domain_length = (size_t)(colon - target_text);
  if (domain_length == 0u || domain_length > 253u) return 1;
  errno = 0;
  target_port = strtoul(colon + 1u, &tail, 10);
  if (errno != 0 || tail == colon + 1u || *tail != '\0' ||
      target_port == 0u || target_port > UINT16_MAX) return 1;
  descriptor = proxy_connect((uint16_t)listener_port);
  if (descriptor < 0) return 1;
  request[4] = (uint8_t)domain_length;
  memcpy(request + 5u, target_text, domain_length);
  request[5u + domain_length] = (uint8_t)(target_port >> 8u);
  request[6u + domain_length] = (uint8_t)target_port;
  if (!write_exact(descriptor, offer, sizeof(offer))) step = 1;
  else if (!read_exact(descriptor, selected, sizeof(selected))) step = 2;
  else if (selected[0] != 5u || selected[1] != 0u) step = 3;
  else if (!write_exact(descriptor, request, domain_length + 7u)) step = 4;
  else if (!read_exact(descriptor, reply, sizeof(reply))) step = 5;
  else if (reply[0] != 5u || reply[1] != 0u) step = 6;
  else if (!proxy_echo(descriptor, "socks-domain-production")) step = 7;
  if (step != 0) {
    fprintf(stderr, "SOCKS domain production client failed at step %d "
            "(errno=%d)\n", step, errno);
    (void)close(descriptor);
    return 1;
  }
  (void)close(descriptor);
  return 0;
}

static int socks_udp_client_main(const char *port_text,
                                 const char *target_text,
                                 const char *packets_text,
                                 bool recovery, bool backoff)
{
  static const uint8_t payload_bytes[] = "socks-udp-production";
  static const uint8_t recovery_payload[] =
    "socks-udp-control-recovery";
  static const uint8_t backoff_payload[] =
    "socks-udp-backoff-probe";
  const uint8_t *payload = recovery ? recovery_payload
    : (backoff ? backoff_payload : payload_bytes);
  size_t payload_length = recovery ? sizeof(recovery_payload) - 1u
    : (backoff ? sizeof(backoff_payload) - 1u : sizeof(payload_bytes) - 1u);
  uint8_t offer[3] = {5u, 1u, 0u};
  uint8_t selected[2];
  uint8_t request[10] = {5u, 3u, 0u, 1u, 0u, 0u, 0u, 0u, 0u, 0u};
  uint8_t reply[10];
  uint8_t wire[512];
  uint8_t response[512];
  struct sockaddr_in target;
  struct sockaddr_in relay;
  struct timeval timeout;
  ftun_endpoint_t endpoint;
  ftun_socks5_udp_datagram_t datagram;
  size_t written = 0u;
  size_t consumed = 0u;
  char *tail = NULL;
  unsigned long port = strtoul(port_text, &tail, 10);
  unsigned long packets = recovery ? 2u : (backoff ? 120u : 1u);
  uint64_t started = 0u;
  uint64_t finished = 0u;
  unsigned long packet_index;
  ssize_t length;
  int control;
  int udp;
  if (tail == port_text || *tail != '\0' || port == 0u ||
      port > UINT16_MAX || !parse_ipv4_target(target_text, &target,
                                               NULL, 0u)) return 1;
  if (packets_text != NULL && !recovery && !backoff) {
    errno = 0;
    packets = strtoul(packets_text, &tail, 10);
    if (errno != 0 || tail == packets_text || *tail != '\0' ||
        packets == 0u || packets > 1000000u) return 1;
  }
  control = proxy_connect((uint16_t)port);
  if (control < 0) return 1;
  if (!write_exact(control, offer, sizeof(offer)) ||
      !read_exact(control, selected, sizeof(selected)) ||
      selected[0] != 5u || selected[1] != 0u ||
      !write_exact(control, request, sizeof(request)) ||
      !read_exact(control, reply, sizeof(reply)) ||
      reply[0] != 5u || reply[1] != 0u || reply[3] != 1u) {
    (void)close(control);
    return 1;
  }
  memset(&relay, 0, sizeof(relay));
  relay.sin_family = AF_INET;
  memcpy(&relay.sin_addr.s_addr, reply + 4u, 4u);
  memcpy(&relay.sin_port, reply + 8u, 2u);
  if (relay.sin_addr.s_addr == htonl(INADDR_ANY)) {
    (void)inet_pton(AF_INET, "127.0.0.1", &relay.sin_addr);
  }
  udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
  if (udp < 0) {
    (void)close(control);
    return 1;
  }
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;
  if (recovery) {
    timeout.tv_sec = 0;
    timeout.tv_usec = 250000;
  }
  (void)setsockopt(udp, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  (void)setsockopt(udp, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  if (connect(udp, (const struct sockaddr *)&relay,
              (socklen_t)sizeof(relay)) != 0) goto fail;
  memset(&endpoint, 0, sizeof(endpoint));
  endpoint.kind = FTUN_ADDRESS_IPV4;
  endpoint.port = ntohs(target.sin_port);
  memcpy(endpoint.address, &target.sin_addr.s_addr, 4u);
  if (ftun_socks5_encode_udp_datagram(&endpoint,
      (ftun_bytes_t){payload, payload_length},
      wire, sizeof(wire), &written) != FTUN_OK ||
      ftun_monotonic_now(&started) != FTUN_OK) goto fail;
  for (packet_index = 0u; packet_index < packets; packet_index++) {
    unsigned int attempt;
    unsigned int attempts = recovery ? 20u : 1u;
    bool received_packet = false;
    for (attempt = 0u; attempt < attempts; attempt++) {
      if (send(udp, wire, written, MSG_NOSIGNAL) != (ssize_t)written) {
        goto fail;
      }
      if (backoff) {
        struct timespec pause = {0, 10000000L};
        while (nanosleep(&pause, &pause) != 0 && errno == EINTR) {}
        received_packet = true;
        break;
      }
      do {
        length = recv(udp, response, sizeof(response), 0);
      } while (length < 0 && errno == EINTR);
      if (length < 0 && recovery &&
          (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
      consumed = 0u;
      if (length <= 0 || ftun_socks5_decode_udp_datagram(
          (ftun_bytes_t){response, (size_t)length}, &datagram, &consumed) !=
          FTUN_OK || consumed != (size_t)length ||
          datagram.endpoint.kind != FTUN_ADDRESS_IPV4 ||
          datagram.endpoint.port != endpoint.port ||
          memcmp(datagram.endpoint.address, endpoint.address, 4u) != 0 ||
          datagram.payload.length != payload_length ||
          memcmp(datagram.payload.data, payload, payload_length) != 0) {
        goto fail;
      }
      received_packet = true;
      break;
    }
    if (!received_packet) goto fail;
    if (recovery && packet_index == 0u) {
      struct timespec pause;
      pause.tv_sec = 0;
      pause.tv_nsec = 500000000L;
      while (nanosleep(&pause, &pause) != 0 && errno == EINTR) {}
    }
  }
  if (backoff) {
    struct timespec pause = {0, 250000000L};
    while (nanosleep(&pause, &pause) != 0 && errno == EINTR) {}
  }
  if (ftun_monotonic_now(&finished) != FTUN_OK || finished < started) goto fail;
  if (packets_text != NULL) {
    uint64_t elapsed = finished - started;
    if (elapsed == 0u) elapsed = 1u;
    printf("production-udp packets=%lu elapsed-ms=%llu packets-per-second=%.0f\n",
           packets, (unsigned long long)elapsed,
           (double)packets * 1000.0 / (double)elapsed);
  }
  (void)close(udp);
  (void)close(control);
  return 0;
fail:
  (void)close(udp);
  (void)close(control);
  return 1;
}

static int mixed_connect_client_main(const char *port_text,
                                     const char *target_text)
{
  static const char established[] =
    "HTTP/1.1 200 Connection Established\r\n\r\n";
  struct sockaddr_in target;
  char request[512];
  uint8_t reply[sizeof(established) - 1u];
  char normalized[64];
  char *tail = NULL;
  unsigned long port = strtoul(port_text, &tail, 10);
  int descriptor;
  if (tail == port_text || *tail != '\0' || port == 0u ||
      port > UINT16_MAX || !parse_ipv4_target(target_text, &target,
        normalized, sizeof(normalized)) || snprintf(request, sizeof(request),
        "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
        normalized, normalized) <= 0) return 1;
  descriptor = proxy_connect((uint16_t)port);
  if (descriptor < 0) return 1;
  if (!write_exact(descriptor, (const uint8_t *)request, strlen(request)) ||
      !read_exact(descriptor, reply, sizeof(reply)) ||
      memcmp(reply, established, sizeof(reply)) != 0 ||
      !proxy_echo(descriptor, "mixed-connect-production")) {
    (void)close(descriptor);
    return 1;
  }
  (void)close(descriptor);
  return 0;
}

static int mixed_forward_client_main(const char *port_text,
                                     const char *target_text)
{
  struct sockaddr_in target;
  char request[1024];
  char expected[512];
  uint8_t response[512];
  char normalized[64];
  char *tail = NULL;
  unsigned long port = strtoul(port_text, &tail, 10);
  int descriptor;
  if (tail == port_text || *tail != '\0' || port == 0u ||
      port > UINT16_MAX || !parse_ipv4_target(target_text, &target,
        normalized, sizeof(normalized)) || snprintf(request, sizeof(request),
        "GET http://%s/release?q=1 HTTP/1.1\r\nHost: %s\r\n"
        "Proxy-Authorization: Basic dTpw\r\n"
        "Proxy-Connection: keep-alive\r\n\r\n", normalized, normalized) <= 0 ||
      snprintf(expected, sizeof(expected),
        "GET /release?q=1 HTTP/1.1\r\nHost: %s\r\n\r\n", normalized) <= 0) {
    return 1;
  }
  descriptor = proxy_connect((uint16_t)port);
  if (descriptor < 0) return 1;
  if (!write_exact(descriptor, (const uint8_t *)request, strlen(request)) ||
      !read_exact(descriptor, response, strlen(expected)) ||
      memcmp(response, expected, strlen(expected)) != 0) {
    (void)close(descriptor);
    return 1;
  }
  (void)close(descriptor);
  return 0;
}

static int echo_server_main(const char *target_text, const char *ready_path)
{
  struct sockaddr_in address;
  struct sigaction action;
  FILE *ready;
  int descriptor;
  int udp_descriptor;
  int one = 1;
  if (!parse_ipv4_target(target_text, &address, NULL, 0u)) return 1;
  descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (descriptor < 0) return 1;
  (void)setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  if (bind(descriptor, (const struct sockaddr *)&address,
           (socklen_t)sizeof(address)) != 0 || listen(descriptor, 16) != 0) {
    (void)close(descriptor);
    return 1;
  }
  udp_descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
  if (udp_descriptor < 0 ||
      bind(udp_descriptor, (const struct sockaddr *)&address,
           (socklen_t)sizeof(address)) != 0) {
    if (udp_descriptor >= 0) (void)close(udp_descriptor);
    (void)close(descriptor);
    return 1;
  }
  memset(&action, 0, sizeof(action));
  action.sa_handler = peer_signal;
  (void)sigemptyset(&action.sa_mask);
  if (sigaction(SIGTERM, &action, NULL) != 0) {
    (void)close(udp_descriptor);
    (void)close(descriptor);
    return 1;
  }
  ready = fopen(ready_path, "wb");
  if (ready == NULL) {
    (void)close(udp_descriptor);
    (void)close(descriptor);
    return 1;
  }
  if (fputs("ready\n", ready) < 0) {
    (void)fclose(ready);
    (void)close(udp_descriptor);
    (void)close(descriptor);
    return 1;
  }
  if (fclose(ready) != 0) {
    (void)close(udp_descriptor);
    (void)close(descriptor);
    return 1;
  }
  while (!peer_stopping) {
    struct pollfd items[2];
    int result;
    memset(items, 0, sizeof(items));
    items[0].fd = descriptor;
    items[0].events = POLLIN;
    items[1].fd = udp_descriptor;
    items[1].events = POLLIN;
    result = poll(items, 2u, 100);
    if (result < 0 && errno == EINTR) continue;
    if (result < 0) break;
    if ((items[0].revents & POLLIN) != 0 &&
        !peer_accept_thread(descriptor, peer_echo_thread)) break;
    if ((items[1].revents & POLLIN) != 0) {
      uint8_t packet[65535];
      struct sockaddr_in peer;
      socklen_t peer_length = (socklen_t)sizeof(peer);
      ssize_t length = recvfrom(udp_descriptor, packet, sizeof(packet), 0,
                                (struct sockaddr *)&peer, &peer_length);
      if (length >= 0) {
        (void)sendto(udp_descriptor, packet, (size_t)length, MSG_NOSIGNAL,
                     (const struct sockaddr *)&peer, peer_length);
      }
    }
  }
  (void)close(udp_descriptor);
  (void)close(descriptor);
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

static int dns_server_main(const char *address, const char *port_text,
                           const char *ready_path)
{
  struct pollfd item;
  struct sigaction action;
  char *tail = NULL;
  unsigned long port;
  int descriptor;
  int ready;
  errno = 0;
  port = strtoul(port_text, &tail, 10);
  if (errno != 0 || tail == port_text || *tail != '\0' || port == 0u ||
      port > UINT16_MAX) return 1;
  descriptor = socket_bound(SOCK_DGRAM, address, (uint16_t)port);
  if (descriptor < 0) return 1;
  memset(&action, 0, sizeof(action));
  action.sa_handler = peer_signal;
  (void)sigemptyset(&action.sa_mask);
  if (sigaction(SIGTERM, &action, NULL) != 0) {
    (void)close(descriptor);
    return 1;
  }
  ready = open(ready_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (ready < 0 || write(ready, "ready\n", 6u) != 6) {
    if (ready >= 0) (void)close(ready);
    (void)close(descriptor);
    return 1;
  }
  (void)close(ready);
  memset(&item, 0, sizeof(item));
  item.fd = descriptor;
  item.events = POLLIN;
  while (!peer_stopping) {
    int count = poll(&item, 1u, 100);
    if (count < 0 && errno == EINTR) continue;
    if (count < 0) break;
    if ((item.revents & POLLIN) != 0) peer_dns_reply(descriptor, address);
  }
  (void)close(descriptor);
  return 0;
}

typedef struct {
  uint8_t wire[512];
  size_t length;
  struct sockaddr_in peer;
  socklen_t peer_length;
  uint64_t due_ms;
  bool active;
} dns_delayed_reply_t;

static int dns_test_name(const uint8_t *wire, size_t length,
                         char *out, size_t capacity)
{
  size_t input = 12u;
  size_t output = 0u;
  if (wire == NULL || out == NULL || capacity == 0u || length < 17u) return 0;
  while (input < length && wire[input] != 0u) {
    size_t label = wire[input++];
    if (label > 63u || label == 0u || input + label > length ||
        output + label + (output == 0u ? 0u : 1u) >= capacity) return 0;
    if (output != 0u) out[output++] = '.';
    memcpy(out + output, wire + input, label);
    output += label;
    input += label;
  }
  if (input >= length || wire[input] != 0u) return 0;
  out[output] = '\0';
  return 1;
}

static int dns_test_response(const uint8_t *query, size_t query_length,
                             const char *address, uint8_t *response,
                             size_t capacity, size_t *out_length)
{
  size_t output_length = query_length + 16u;
  if (out_length != NULL) *out_length = 0u;
  if (query == NULL || address == NULL || response == NULL ||
      out_length == NULL || query_length < 12u || output_length > capacity) {
    return 0;
  }
  memcpy(response, query, query_length);
  response[2] = 0x81u;
  response[3] = 0x80u;
  response[6] = 0u;
  response[7] = 1u;
  response[8] = response[9] = response[10] = response[11] = 0u;
  response[query_length] = 0xc0u;
  response[query_length + 1u] = 0x0cu;
  response[query_length + 2u] = 0u;
  response[query_length + 3u] = 1u;
  response[query_length + 4u] = 0u;
  response[query_length + 5u] = 1u;
  response[query_length + 6u] = response[query_length + 7u] = 0u;
  response[query_length + 8u] = 0u;
  response[query_length + 9u] = 1u;
  response[query_length + 10u] = 0u;
  response[query_length + 11u] = 4u;
  if (inet_pton(AF_INET, address, response + query_length + 12u) != 1) return 0;
  *out_length = output_length;
  return 1;
}

static int dns_test_reply(int descriptor, const uint8_t *query,
                          size_t query_length,
                          const struct sockaddr_in *peer,
                          socklen_t peer_length, const char *address)
{
  uint8_t response[528];
  size_t output_length = 0u;
  if (peer == NULL || !dns_test_response(query, query_length, address,
      response, sizeof(response), &output_length)) return 0;
  return sendto(descriptor, response, output_length, 0,
    (const struct sockaddr *)peer, peer_length) == (ssize_t)output_length;
}

static int dns_delayed_store(dns_delayed_reply_t *delayed,
                             const uint8_t *wire, size_t length,
                             const struct sockaddr_in *peer,
                             socklen_t peer_length, uint64_t delay_ms)
{
  if (delayed == NULL || wire == NULL || peer == NULL ||
      length > sizeof(delayed->wire)) return 0;
  memcpy(delayed->wire, wire, length);
  delayed->length = length;
  delayed->peer = *peer;
  delayed->peer_length = peer_length;
  delayed->due_ms = deadline_after(delay_ms);
  delayed->active = delayed->due_ms != 0u;
  return delayed->active;
}

static int dns_concurrency_server_main(const char *address,
                                       const char *port_text,
                                       const char *ready_path,
                                       const char *result_path)
{
  dns_delayed_reply_t slow;
  dns_delayed_reply_t shared;
  dns_delayed_reply_t isolated[2];
  struct sigaction action;
  struct pollfd item;
  char *tail = NULL;
  unsigned long port;
  unsigned int slow_count = 0u;
  unsigned int fast_count = 0u;
  unsigned int shared_count = 0u;
  unsigned int timeout_count = 0u;
  unsigned int isolated_count = 0u;
  int descriptor;
  int ready;
  int result = 0;
  memset(&slow, 0, sizeof(slow));
  memset(&shared, 0, sizeof(shared));
  memset(isolated, 0, sizeof(isolated));
  peer_stopping = 0;
  errno = 0;
  port = strtoul(port_text, &tail, 10);
  if (errno != 0 || tail == port_text || *tail != '\0' || port == 0u ||
      port > UINT16_MAX) return 1;
  descriptor = socket_bound(SOCK_DGRAM, address, (uint16_t)port);
  if (descriptor < 0) return 1;
  memset(&action, 0, sizeof(action));
  action.sa_handler = peer_signal;
  (void)sigemptyset(&action.sa_mask);
  if (sigaction(SIGTERM, &action, NULL) != 0) goto done;
  ready = open(ready_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (ready < 0 || write(ready, "ready\n", 6u) != 6) {
    if (ready >= 0) (void)close(ready);
    goto done;
  }
  (void)close(ready);
  memset(&item, 0, sizeof(item));
  item.fd = descriptor;
  item.events = POLLIN;
  result = 1;
  while (!peer_stopping) {
    uint64_t now_ms = 0u;
    int count = poll(&item, 1u, 10);
    if (count < 0 && errno == EINTR) continue;
    if (count < 0) goto done;
    if ((item.revents & POLLIN) != 0) {
      uint8_t query[512];
      char name[256];
      struct sockaddr_in source;
      socklen_t source_length = (socklen_t)sizeof(source);
      ssize_t length = recvfrom(descriptor, query, sizeof(query), 0,
        (struct sockaddr *)&source, &source_length);
      if (length > 0 && dns_test_name(query, (size_t)length,
                                      name, sizeof(name))) {
        if (strcmp(name, "slow.example") == 0) {
          slow_count++;
          if (!dns_delayed_store(&slow, query, (size_t)length, &source,
                                 source_length, 700u)) goto done;
        } else if (strcmp(name, "fast.example") == 0) {
          fast_count++;
          if (!dns_test_reply(descriptor, query, (size_t)length, &source,
                              source_length, "127.0.0.2")) goto done;
        } else if (strcmp(name, "shared.example") == 0) {
          shared_count++;
          if (!shared.active && !dns_delayed_store(&shared, query,
              (size_t)length, &source, source_length, 200u)) goto done;
        } else if (strcmp(name, "timeout.example") == 0) {
          timeout_count++;
        } else if (strcmp(name, "isolate.example") == 0) {
          if (isolated_count >= 2u || !dns_delayed_store(
              &isolated[isolated_count], query, (size_t)length, &source,
              source_length, 200u)) goto done;
          isolated_count++;
        } else if (strncmp(name, "flood", 5u) == 0) {
          /* 持续无响应输入用于验证容量满时其他监听器仍可前进。 */
        } else if (!dns_test_reply(descriptor, query, (size_t)length, &source,
                                   source_length, "127.0.0.4")) {
          goto done;
        }
      }
    }
    if (ftun_monotonic_now(&now_ms) != FTUN_OK) goto done;
    if (shared.active && now_ms >= shared.due_ms) {
      if (!dns_test_reply(descriptor, shared.wire, shared.length,
                          &shared.peer, shared.peer_length, "127.0.0.3")) {
        goto done;
      }
      shared.active = false;
    }
    if (slow.active && now_ms >= slow.due_ms) {
      if (!dns_test_reply(descriptor, slow.wire, slow.length,
                          &slow.peer, slow.peer_length, "127.0.0.1")) {
        goto done;
      }
      slow.active = false;
    }
    {
      size_t isolated_index;
      for (isolated_index = 0u; isolated_index < 2u; isolated_index++) {
        if (isolated[isolated_index].active &&
            now_ms >= isolated[isolated_index].due_ms) {
          if (!dns_test_reply(descriptor, isolated[isolated_index].wire,
              isolated[isolated_index].length,
              &isolated[isolated_index].peer,
              isolated[isolated_index].peer_length, "127.0.0.5")) goto done;
          isolated[isolated_index].active = false;
        }
      }
    }
  }
  result = 0;

done:
  {
    int output = open(result_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                      0600);
    if (output >= 0) {
      char summary[128];
      int length = snprintf(summary, sizeof(summary),
        "slow=%u fast=%u shared=%u timeout=%u isolate=%u status=%d\n",
        slow_count, fast_count, shared_count, timeout_count, isolated_count,
        result);
      if (length > 0 && (size_t)length < sizeof(summary)) {
        (void)write(output, summary, (size_t)length);
      }
      (void)close(output);
    }
  }
  (void)close(descriptor);
  return result;
}

typedef struct {
  unsigned int slow_count;
  unsigned int fast_count;
  unsigned int shared_count;
} dns_tcp_test_context_t;

typedef struct {
  dns_tcp_test_context_t *context;
  int descriptor;
} dns_tcp_test_client_t;

static void *dns_tcp_test_thread(void *user)
{
  dns_tcp_test_client_t *client = (dns_tcp_test_client_t *)user;
  dns_tcp_test_context_t *context = client->context;
  uint8_t prefix[2];
  uint8_t query[512];
  uint8_t response[528];
  uint8_t response_prefix[2];
  char name[256];
  size_t query_length;
  size_t response_length = 0u;
  unsigned long delay_ms = 0u;
  const char *answer = "127.0.0.4";
  int descriptor = client->descriptor;
  free(client);
  if (!read_exact(descriptor, prefix, sizeof(prefix))) goto done;
  query_length = ((size_t)prefix[0] << 8u) | prefix[1];
  if (query_length == 0u || query_length > sizeof(query) ||
      !read_exact(descriptor, query, query_length) ||
      !dns_test_name(query, query_length, name, sizeof(name))) goto done;
  if (strcmp(name, "slow.example") == 0) {
    (void)__atomic_add_fetch(&context->slow_count, 1u, __ATOMIC_RELAXED);
    delay_ms = 700u;
    answer = "127.0.0.1";
  } else if (strcmp(name, "fast.example") == 0) {
    (void)__atomic_add_fetch(&context->fast_count, 1u, __ATOMIC_RELAXED);
    answer = "127.0.0.2";
  } else if (strcmp(name, "shared.example") == 0) {
    (void)__atomic_add_fetch(&context->shared_count, 1u, __ATOMIC_RELAXED);
    delay_ms = 200u;
    answer = "127.0.0.3";
  }
  if (delay_ms != 0u) {
    struct timespec pause;
    pause.tv_sec = (time_t)(delay_ms / 1000u);
    pause.tv_nsec = (long)(delay_ms % 1000u) * 1000000L;
    while (nanosleep(&pause, &pause) != 0 && errno == EINTR) {}
  }
  if (!dns_test_response(query, query_length, answer, response,
                         sizeof(response), &response_length) ||
      response_length > UINT16_MAX) goto done;
  response_prefix[0] = (uint8_t)(response_length >> 8u);
  response_prefix[1] = (uint8_t)response_length;
  (void)write_exact(descriptor, response_prefix, sizeof(response_prefix));
  (void)write_exact(descriptor, response, response_length);

done:
  (void)close(descriptor);
  peer_thread_finished();
  return NULL;
}

static int dns_tcp_test_accept(int listener, dns_tcp_test_context_t *context)
{
  dns_tcp_test_client_t *client;
  pthread_t thread;
  int descriptor = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
  if (descriptor < 0) {
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
  }
  client = (dns_tcp_test_client_t *)calloc(1u, sizeof(*client));
  if (client == NULL) {
    (void)close(descriptor);
    return 0;
  }
  client->context = context;
  client->descriptor = descriptor;
  peer_thread_started();
  if (pthread_create(&thread, NULL, dns_tcp_test_thread, client) != 0) {
    peer_thread_finished();
    (void)close(descriptor);
    free(client);
    return 0;
  }
  (void)pthread_detach(thread);
  return 1;
}

static int dns_tcp_concurrency_server_main(const char *address,
                                           const char *port_text,
                                           const char *ready_path,
                                           const char *result_path)
{
  dns_tcp_test_context_t context;
  struct sigaction action;
  struct pollfd item;
  char *tail = NULL;
  unsigned long port;
  int descriptor;
  int ready;
  int result = 1;
  memset(&context, 0, sizeof(context));
  peer_stopping = 0;
  errno = 0;
  port = strtoul(port_text, &tail, 10);
  if (errno != 0 || tail == port_text || *tail != '\0' || port == 0u ||
      port > UINT16_MAX) return 1;
  descriptor = socket_bound(SOCK_STREAM, address, (uint16_t)port);
  if (descriptor < 0 || listen(descriptor, 16) != 0 ||
      !set_nonblocking(descriptor)) {
    if (descriptor >= 0) (void)close(descriptor);
    return 1;
  }
  memset(&action, 0, sizeof(action));
  action.sa_handler = peer_signal;
  (void)sigemptyset(&action.sa_mask);
  if (sigaction(SIGTERM, &action, NULL) != 0) goto done;
  ready = open(ready_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (ready < 0 || write(ready, "ready\n", 6u) != 6) {
    if (ready >= 0) (void)close(ready);
    goto done;
  }
  (void)close(ready);
  memset(&item, 0, sizeof(item));
  item.fd = descriptor;
  item.events = POLLIN;
  while (!peer_stopping) {
    int count = poll(&item, 1u, 100);
    if (count < 0 && errno == EINTR) continue;
    if (count < 0) goto done;
    if ((item.revents & POLLIN) != 0 &&
        !dns_tcp_test_accept(descriptor, &context)) goto done;
  }
  result = 0;

done:
  (void)close(descriptor);
  for (;;) {
    struct timespec pause = {0, 1000000L};
    size_t active;
    (void)pthread_mutex_lock(&peer_threads_mutex);
    active = peer_threads;
    (void)pthread_mutex_unlock(&peer_threads_mutex);
    if (active == 0u) break;
    (void)nanosleep(&pause, NULL);
  }
  {
    int output = open(result_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                      0600);
    if (output >= 0) {
      char summary[128];
      int length = snprintf(summary, sizeof(summary),
        "slow=%u fast=%u shared=%u status=%d\n",
        context.slow_count, context.fast_count, context.shared_count, result);
      if (length > 0 && (size_t)length < sizeof(summary)) {
        (void)write(output, summary, (size_t)length);
      }
      (void)close(output);
    }
  }
  return result;
}

static size_t dns_test_query(uint8_t *wire, size_t capacity, uint16_t id,
                             const char *first)
{
  size_t first_length = strlen(first);
  static const char suffix[] = "example";
  size_t suffix_length = sizeof(suffix) - 1u;
  size_t length = 12u + 1u + first_length + 1u + suffix_length + 1u + 4u;
  size_t offset = 0u;
  if (wire == NULL || first_length == 0u || first_length > 63u ||
      length > capacity) return 0u;
  memset(wire, 0, length);
  wire[0] = (uint8_t)(id >> 8u);
  wire[1] = (uint8_t)id;
  wire[2] = 1u;
  wire[5] = 1u;
  offset = 12u;
  wire[offset++] = (uint8_t)first_length;
  memcpy(wire + offset, first, first_length);
  offset += first_length;
  wire[offset++] = (uint8_t)suffix_length;
  memcpy(wire + offset, suffix, suffix_length);
  offset += suffix_length;
  wire[offset++] = 0u;
  wire[offset++] = 0u;
  wire[offset++] = 1u;
  wire[offset++] = 0u;
  wire[offset++] = 1u;
  return offset;
}

static int dns_concurrency_client_main(const char *address_text,
                                       const char *port_text)
{
  struct sockaddr_in target;
  uint8_t query[64];
  uint8_t response[512];
  char *tail = NULL;
  unsigned long port;
  uint64_t started;
  uint64_t fast_at = 0u;
  bool slow_done = false;
  bool fast_done = false;
  bool shared_one = false;
  bool shared_two = false;
  int descriptor;
  errno = 0;
  port = strtoul(port_text, &tail, 10);
  if (errno != 0 || tail == port_text || *tail != '\0' || port == 0u ||
      port > UINT16_MAX) return 1;
  descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
  if (descriptor < 0) return 1;
  memset(&target, 0, sizeof(target));
  target.sin_family = AF_INET;
  target.sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, address_text, &target.sin_addr) != 1 ||
      connect(descriptor, (const struct sockaddr *)&target,
              (socklen_t)sizeof(target)) != 0 ||
      ftun_monotonic_now(&started) != FTUN_OK) goto fail;
  {
    size_t length = dns_test_query(query, sizeof(query), 0x1001u, "slow");
    if (length == 0u || send(descriptor, query, length, 0) != (ssize_t)length) {
      goto fail;
    }
  }
  {
    struct timespec pause = {0, 25000000L};
    while (nanosleep(&pause, &pause) != 0 && errno == EINTR) {}
  }
  {
    size_t length = dns_test_query(query, sizeof(query), 0x1002u, "fast");
    if (length == 0u || send(descriptor, query, length, 0) != (ssize_t)length) {
      goto fail;
    }
  }
  while (!slow_done || !fast_done) {
    struct pollfd item = {descriptor, POLLIN, 0};
    uint64_t now_ms;
    ssize_t length;
    if (poll(&item, 1u, 1500) != 1 || (item.revents & POLLIN) == 0) goto fail;
    length = recv(descriptor, response, sizeof(response), 0);
    if (length < 12 || (response[2] & 0x80u) == 0u ||
        ftun_monotonic_now(&now_ms) != FTUN_OK) goto fail;
    if (response[0] == 0x10u && response[1] == 0x01u) slow_done = true;
    else if (response[0] == 0x10u && response[1] == 0x02u) {
      fast_done = true;
      fast_at = now_ms;
    }
  }
  if (fast_at < started || fast_at - started >= 500u) goto fail;
  {
    size_t length = dns_test_query(query, sizeof(query), 0x2001u, "shared");
    if (length == 0u || send(descriptor, query, length, 0) != (ssize_t)length) {
      goto fail;
    }
    query[0] = 0x20u;
    query[1] = 0x02u;
    if (send(descriptor, query, length, 0) != (ssize_t)length) goto fail;
  }
  while (!shared_one || !shared_two) {
    struct pollfd item = {descriptor, POLLIN, 0};
    ssize_t length;
    if (poll(&item, 1u, 1500) != 1 || (item.revents & POLLIN) == 0) goto fail;
    length = recv(descriptor, response, sizeof(response), 0);
    if (length < 12 || response[0] != 0x20u) goto fail;
    if (response[1] == 0x01u) shared_one = true;
    else if (response[1] == 0x02u) shared_two = true;
    else goto fail;
  }
  (void)close(descriptor);
  return 0;

fail:
  (void)close(descriptor);
  return 1;
}

static int dns_flood_client_main(const char *address_text,
                                 const char *port_text,
                                 const char *duration_text)
{
  struct sockaddr_in target;
  uint8_t query[64];
  uint8_t response[512];
  char *tail = NULL;
  unsigned long port;
  unsigned long duration_ms;
  uint64_t deadline;
  unsigned int sequence = 0u;
  int descriptor;
  errno = 0;
  port = strtoul(port_text, &tail, 10);
  if (errno != 0 || tail == port_text || *tail != '\0' || port == 0u ||
      port > UINT16_MAX) return 1;
  errno = 0;
  duration_ms = strtoul(duration_text, &tail, 10);
  if (errno != 0 || tail == duration_text || *tail != '\0' ||
      duration_ms == 0u || duration_ms > 30000u) return 1;
  descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
                      IPPROTO_UDP);
  if (descriptor < 0) return 1;
  memset(&target, 0, sizeof(target));
  target.sin_family = AF_INET;
  target.sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, address_text, &target.sin_addr) != 1 ||
      connect(descriptor, (const struct sockaddr *)&target,
              (socklen_t)sizeof(target)) != 0) goto fail;
  deadline = deadline_after((uint64_t)duration_ms);
  if (deadline == 0u) goto fail;
  for (;;) {
    uint64_t now_ms = 0u;
    size_t batch;
    for (batch = 0u; batch < 32u; batch++) {
      char label[16];
      size_t length;
      ssize_t sent;
      uint16_t id = (uint16_t)(sequence + 1u);
      if (snprintf(label, sizeof(label), "flood%05u",
                   sequence % 100000u) <= 0) goto fail;
      length = dns_test_query(query, sizeof(query), id, label);
      if (length == 0u) goto fail;
      sent = send(descriptor, query, length, 0);
      if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
          errno != ENOBUFS) goto fail;
      sequence++;
    }
    while (recv(descriptor, response, sizeof(response), 0) > 0) {}
    if (ftun_monotonic_now(&now_ms) != FTUN_OK) goto fail;
    if (now_ms >= deadline) break;
    {
      struct timespec pause = {0, 1000000L};
      while (nanosleep(&pause, &pause) != 0 && errno == EINTR) {}
    }
  }
  (void)close(descriptor);
  return sequence >= 256u ? 0 : 1;

fail:
  (void)close(descriptor);
  return 1;
}

static int dns_isolation_client_main(const char *address_text,
                                     const char *first_port_text,
                                     const char *second_port_text)
{
  const char *ports[2] = {first_port_text, second_port_text};
  struct pollfd items[2];
  uint8_t query[64];
  uint8_t response[512];
  bool completed[2] = {false, false};
  uint64_t started;
  size_t index;
  memset(items, 0, sizeof(items));
  items[0].fd = -1;
  items[1].fd = -1;
  for (index = 0u; index < 2u; index++) {
    struct sockaddr_in target;
    char *tail = NULL;
    unsigned long port;
    errno = 0;
    port = strtoul(ports[index], &tail, 10);
    if (errno != 0 || tail == ports[index] || *tail != '\0' || port == 0u ||
        port > UINT16_MAX) goto fail;
    items[index].fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
    if (items[index].fd < 0) goto fail;
    items[index].events = POLLIN;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, address_text, &target.sin_addr) != 1 ||
        connect(items[index].fd, (const struct sockaddr *)&target,
                (socklen_t)sizeof(target)) != 0) goto fail;
  }
  if (ftun_monotonic_now(&started) != FTUN_OK) goto fail;
  for (index = 0u; index < 2u; index++) {
    size_t length = dns_test_query(query, sizeof(query),
      (uint16_t)(0x4001u + index), "isolate");
    if (length == 0u ||
        send(items[index].fd, query, length, 0) != (ssize_t)length) goto fail;
  }
  while (!completed[0] || !completed[1]) {
    int ready = poll(items, 2u, 1200);
    if (ready <= 0) goto fail;
    for (index = 0u; index < 2u; index++) {
      if ((items[index].revents & POLLIN) != 0) {
        ssize_t length = recv(items[index].fd, response, sizeof(response), 0);
        if (length < 12 || response[0] != 0x40u ||
            response[1] != (uint8_t)(1u + index) ||
            (response[2] & 0x80u) == 0u) goto fail;
        completed[index] = true;
      }
    }
  }
  {
    uint64_t finished;
    if (ftun_monotonic_now(&finished) != FTUN_OK || finished < started ||
        finished - started >= 1000u) goto fail;
  }
  (void)close(items[0].fd);
  (void)close(items[1].fd);
  return 0;

fail:
  if (items[0].fd >= 0) (void)close(items[0].fd);
  if (items[1].fd >= 0) (void)close(items[1].fd);
  return 1;
}

static int dns_client_main(const char *address_text, const char *port_text,
                           const char *expected_text)
{
  static const uint8_t question[] = {
    0x44u, 0x55u, 0x01u, 0x00u, 0x00u, 0x01u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u,
    0x01u, 'a', 0x07u, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00u,
    0x00u, 0x01u, 0x00u, 0x01u
  };
  struct sockaddr_in target;
  struct timeval timeout;
  uint8_t response[512];
  uint8_t expected[4];
  char *tail = NULL;
  unsigned long port;
  ssize_t length;
  int descriptor;
  errno = 0;
  port = strtoul(port_text, &tail, 10);
  if (errno != 0 || tail == port_text || *tail != '\0' ||
      port == 0u || port > UINT16_MAX ||
      inet_pton(AF_INET, expected_text, expected) != 1) return 1;
  descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (descriptor < 0) return 1;
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;
  (void)setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO,
                   &timeout, sizeof(timeout));
  memset(&target, 0, sizeof(target));
  target.sin_family = AF_INET;
  target.sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, address_text, &target.sin_addr) != 1 ||
      sendto(descriptor, question, sizeof(question), 0,
        (const struct sockaddr *)&target, (socklen_t)sizeof(target)) !=
        (ssize_t)sizeof(question)) {
    (void)close(descriptor);
    return 1;
  }
  do {
    length = recv(descriptor, response, sizeof(response), 0);
  } while (length < 0 && errno == EINTR);
  (void)close(descriptor);
  return length >= 43 && response[0] == 0x44u && response[1] == 0x55u &&
    (response[2] & 0x80u) != 0u && response[7] == 1u &&
    memcmp(response + length - 4, expected, 4u) == 0 ? 0 : 1;
}

static int dns_fakeip_sequence_main(const char *address_text,
                                    const char *port_text,
                                    const char *count_text)
{
  const unsigned long window = 32u;
  struct sockaddr_in target;
  struct timeval timeout;
  uint8_t query[64];
  uint8_t response[512];
  uint32_t *addresses = NULL;
  char *tail = NULL;
  unsigned long port;
  unsigned long count;
  unsigned long batch;
  int descriptor = -1;
  errno = 0;
  port = strtoul(port_text, &tail, 10);
  if (errno != 0 || tail == port_text || *tail != '\0' ||
      port == 0u || port > UINT16_MAX) return 1;
  errno = 0;
  count = strtoul(count_text, &tail, 10);
  if (errno != 0 || tail == count_text || *tail != '\0' ||
      count == 0u || count > 60000u) return 1;
  addresses = (uint32_t *)calloc((size_t)count, sizeof(*addresses));
  if (addresses == NULL) return 1;
  descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (descriptor < 0) goto fail;
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;
  (void)setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO,
                   &timeout, sizeof(timeout));
  (void)setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO,
                   &timeout, sizeof(timeout));
  memset(&target, 0, sizeof(target));
  target.sin_family = AF_INET;
  target.sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, address_text, &target.sin_addr) != 1 ||
      connect(descriptor, (const struct sockaddr *)&target,
              (socklen_t)sizeof(target)) != 0) {
    goto fail;
  }
  for (batch = 0u; batch < count; batch += window) {
    unsigned long end = count - batch > window ? batch + window : count;
    unsigned long index;
    for (index = batch; index < end; index++) {
      char label[16];
      int label_length = snprintf(label, sizeof(label), "f%06lu", index);
      size_t query_length;
      uint16_t identifier = (uint16_t)(index + 1u);
      if (label_length <= 0 || (size_t)label_length >= sizeof(label)) {
        goto fail;
      }
      memset(query, 0, sizeof(query));
      query[0] = (uint8_t)(identifier >> 8u);
      query[1] = (uint8_t)identifier;
      query[2] = 1u;
      query[5] = 1u;
      query[12] = (uint8_t)label_length;
      memcpy(query + 13u, label, (size_t)label_length);
      query[13u + (size_t)label_length] = 4u;
      memcpy(query + 14u + (size_t)label_length, "test", 4u);
      query[18u + (size_t)label_length] = 0u;
      query[19u + (size_t)label_length] = 0u;
      query[20u + (size_t)label_length] = 1u;
      query[21u + (size_t)label_length] = 0u;
      query[22u + (size_t)label_length] = 1u;
      query_length = 23u + (size_t)label_length;
      if (send(descriptor, query, query_length, MSG_NOSIGNAL) !=
          (ssize_t)query_length) goto fail;
    }
    for (index = batch; index < end; index++) {
      uint16_t identifier;
      unsigned long response_index;
      uint32_t current_network;
      ssize_t length;
      do {
        length = recv(descriptor, response, sizeof(response), 0);
      } while (length < 0 && errno == EINTR);
      if (length < 16 || (response[2] & 0x80u) == 0u ||
          response[7] != 1u) goto fail;
      identifier = (uint16_t)(((uint16_t)response[0] << 8u) | response[1]);
      if (identifier == 0u) goto fail;
      response_index = (unsigned long)identifier - 1u;
      if (response_index < batch || response_index >= end ||
          addresses[response_index] != 0u) goto fail;
      memcpy(&current_network, response + (size_t)length - 4u,
             sizeof(current_network));
      addresses[response_index] = ntohl(current_network);
    }
  }
  for (batch = 1u; batch < count; batch++) {
    if (addresses[batch] != addresses[0] + (uint32_t)batch) goto fail;
  }
  printf("fakeip-sequence count=%lu final=%u.%u.%u.%u\n", count,
         (unsigned int)(addresses[count - 1u] >> 24u),
         (unsigned int)((addresses[count - 1u] >> 16u) & 0xffu),
         (unsigned int)((addresses[count - 1u] >> 8u) & 0xffu),
         (unsigned int)(addresses[count - 1u] & 0xffu));
  (void)close(descriptor);
  free(addresses);
  return 0;

fail:
  if (descriptor >= 0) (void)close(descriptor);
  free(addresses);
  return 1;
}

static int dns_tcp_client_main(const char *address_text,
                               const char *port_text,
                               const char *expected_text)
{
  static const uint8_t question[] = {
    0x44u, 0x56u, 0x01u, 0x00u, 0x00u, 0x01u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u,
    0x01u, 'a', 0x07u, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00u,
    0x00u, 0x01u, 0x00u, 0x01u
  };
  struct sockaddr_in target;
  struct timeval timeout;
  uint8_t frame[sizeof(question) + 2u];
  uint8_t response[512];
  uint8_t expected[4];
  uint8_t prefix[2];
  char *tail = NULL;
  unsigned long port;
  size_t length;
  int descriptor;
  errno = 0;
  port = strtoul(port_text, &tail, 10);
  if (errno != 0 || tail == port_text || *tail != '\0' ||
      port == 0u || port > UINT16_MAX ||
      inet_pton(AF_INET, expected_text, expected) != 1) return 1;
  descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (descriptor < 0) return 1;
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;
  (void)setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO,
                   &timeout, sizeof(timeout));
  (void)setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO,
                   &timeout, sizeof(timeout));
  memset(&target, 0, sizeof(target));
  target.sin_family = AF_INET;
  target.sin_port = htons((uint16_t)port);
  frame[0] = (uint8_t)(sizeof(question) >> 8u);
  frame[1] = (uint8_t)sizeof(question);
  memcpy(frame + 2u, question, sizeof(question));
  if (inet_pton(AF_INET, address_text, &target.sin_addr) != 1 ||
      connect(descriptor, (const struct sockaddr *)&target,
              (socklen_t)sizeof(target)) != 0 ||
      !write_exact(descriptor, frame, sizeof(frame)) ||
      !read_exact(descriptor, prefix, sizeof(prefix))) {
    (void)close(descriptor);
    return 1;
  }
  length = ((size_t)prefix[0] << 8u) | prefix[1];
  if (length > sizeof(response) || !read_exact(descriptor, response, length)) {
    (void)close(descriptor);
    return 1;
  }
  (void)close(descriptor);
  return length >= 43u && response[0] == 0x44u && response[1] == 0x56u &&
    (response[2] & 0x80u) != 0u && response[7] == 1u &&
    memcmp(response + length - 4u, expected, 4u) == 0 ? 0 : 1;
}

static int dns_tcp_pipeline_main(const char *address_text,
                                 const char *port_text,
                                 const char *expected_text)
{
  static const uint8_t question[] = {
    0x00u, 0x00u, 0x01u, 0x00u, 0x00u, 0x01u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u,
    0x01u, 'a', 0x07u, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00u,
    0x00u, 0x01u, 0x00u, 0x01u
  };
  uint8_t frames[6u * (sizeof(question) + 2u)];
  uint8_t response[512];
  uint8_t prefix[2];
  uint8_t expected[4];
  struct sockaddr_in target;
  struct timeval timeout;
  char *tail = NULL;
  unsigned long port;
  size_t index;
  int descriptor;
  errno = 0;
  port = strtoul(port_text, &tail, 10);
  if (errno != 0 || tail == port_text || *tail != '\0' ||
      port == 0u || port > UINT16_MAX ||
      inet_pton(AF_INET, expected_text, expected) != 1) return 1;
  descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (descriptor < 0) return 1;
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;
  (void)setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO,
                   &timeout, sizeof(timeout));
  (void)setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO,
                   &timeout, sizeof(timeout));
  memset(&target, 0, sizeof(target));
  target.sin_family = AF_INET;
  target.sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, address_text, &target.sin_addr) != 1 ||
      connect(descriptor, (const struct sockaddr *)&target,
              (socklen_t)sizeof(target)) != 0) {
    (void)close(descriptor);
    return 1;
  }
  for (index = 0u; index < 6u; index++) {
    uint8_t *frame = frames + index * (sizeof(question) + 2u);
    frame[0] = (uint8_t)(sizeof(question) >> 8u);
    frame[1] = (uint8_t)sizeof(question);
    memcpy(frame + 2u, question, sizeof(question));
    frame[2] = 0x55u;
    frame[3] = (uint8_t)(0x60u + index);
  }
  if (!write_exact(descriptor, frames, sizeof(frames))) {
    (void)close(descriptor);
    return 1;
  }
  for (index = 0u; index < 6u; index++) {
    size_t length;
    if (!read_exact(descriptor, prefix, sizeof(prefix))) {
      (void)close(descriptor);
      return 1;
    }
    length = ((size_t)prefix[0] << 8u) | prefix[1];
    if (length > sizeof(response) ||
        !read_exact(descriptor, response, length) || length < 43u ||
        response[0] != 0x55u || response[1] != (uint8_t)(0x60u + index) ||
        memcmp(response + length - 4u, expected, 4u) != 0) {
      (void)close(descriptor);
      return 1;
    }
  }
  (void)close(descriptor);
  return 0;
}

typedef struct integration integration_t;

typedef struct {
  integration_t *integration;
  int descriptor;
  ftun_stream_write_token_t pending;
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
  ftun_buffer_pool_t *tun_buffers;
  ftun_tun_service_t *tun_service;
  ftun_tun_lease_t proxy_tun_lease;
  ftun_tun_lease_t mesh_tun_lease;
  ftun_tun_ingress_context_t *ingress;
  ftun_udp_flow_table_t *udp_flows;
  ftun_route_async_t *routes;
  ftun_route_async_t *network_guard;
  ftun_route_async_t *overlay_routes;
  ftun_network_view_t *network_view;
  int mesh_wire;
  size_t mesh_packets_sent;
  size_t mesh_packets_received;
  size_t mesh_packet_errors;
  size_t mesh_feedback_sent;
  size_t mesh_path_updates;
  ftun_tun_packet_error_t mesh_last_error;
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
  void *user, ftun_stream_write_token_t write,
  const ftun_buffer_slice_t *slice,
  size_t *accepted)
{
  socket_stream_t *stream = (socket_stream_t *)user;
  ftun_bytes_t bytes;
  ssize_t length;
  if (accepted != NULL) *accepted = 0u;
  if (stream == NULL || stream->descriptor < 0 ||
      stream->pending.stream != NULL || write.stream == NULL ||
      slice == NULL || accepted == NULL ||
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
  void *user, ftun_stream_write_token_t write)
{
  socket_stream_t *stream = (socket_stream_t *)user;
  if (stream == NULL || stream->pending.stream != write.stream ||
      stream->pending.slot != write.slot ||
      stream->pending.generation != write.generation) return FTUN_E_STALE;
  memset(&stream->pending, 0, sizeof(stream->pending));
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
  memset(&stream->pending, 0, sizeof(stream->pending));
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

static ftun_status_t output_packet(void *user, ftun_bytes_t packet)
{
  integration_t *integration = (integration_t *)user;
  return ftun_tun_service_write(integration->proxy_tun_lease, packet);
}

static ftun_status_t datagram_send_start(
  void *user, ftun_datagram_send_token_t datagram_send,
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
                                          ftun_datagram_send_token_t send)
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
  const ftun_metadata_t *metadata,
  const ftun_route_result_t *prepared_route,
  const ftun_udp_flow_admission_t *admission,
  ftun_datagram_result_fn result,
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
  (void)prepared_route;
  (void)admission;
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
  ftun_buffer_slice_release(&slice);
  ftun_buffer_release(&buffer);
  if (status == FTUN_OK) {
    status = ftun_tun_ingress(integration->ingress, &packet);
  }
  ftun_packet_release(&packet);
  return status;
}

static ftun_status_t integration_proxy_tun_packet(
  void *user, ftun_tun_lease_t lease, ftun_bytes_t packet)
{
  integration_t *integration = (integration_t *)user;
  ftun_status_t status;
  if (integration == NULL || lease.service != integration->proxy_tun_lease.service ||
      lease.generation != integration->proxy_tun_lease.generation) {
    return FTUN_E_STALE;
  }
  status = packet_from_bytes(integration, packet.data, packet.length);
  if (status == FTUN_E_PROTOCOL && packet.length != 0u &&
      (packet.data[0] >> 4u) == 6u) {
    integration->rejected_ipv6++;
    return FTUN_OK;
  }
  return status;
}

static ftun_status_t integration_mesh_tun_packet(
  void *user, ftun_tun_lease_t lease, ftun_bytes_t packet)
{
  integration_t *integration = (integration_t *)user;
  ssize_t sent;
  if (integration == NULL || lease.service != integration->mesh_tun_lease.service ||
      lease.generation != integration->mesh_tun_lease.generation ||
      packet.length < 20u || (packet.data[0] >> 4u) != 4u ||
      packet.data[16] != 198u || packet.data[17] != 18u) {
    return FTUN_E_STATE_CORRUPT;
  }
  sent = send(integration->mesh_wire, packet.data, packet.length,
              MSG_NOSIGNAL);
  if (sent != (ssize_t)packet.length) return FTUN_E_IO;
  integration->mesh_packets_sent++;
  return FTUN_OK;
}

static void integration_tun_event(void *user, ftun_tun_lease_t lease,
                                  ftun_tun_service_event_t event,
                                  ftun_status_t status)
{
  integration_t *integration = (integration_t *)user;
  if (integration != NULL && event == FTUN_TUN_SERVICE_PATH_UPDATED &&
      lease.service == integration->mesh_tun_lease.service &&
      lease.generation == integration->mesh_tun_lease.generation) {
    integration->mesh_path_updates++;
  }
  if (integration != NULL && status != FTUN_OK) {
    integration->callback_failed = true;
  }
}

static void integration_mesh_packet_error(
  void *user, ftun_tun_lease_t lease,
  const ftun_tun_packet_error_t *error)
{
  integration_t *integration = (integration_t *)user;
  if (integration == NULL || error == NULL ||
      lease.service != integration->mesh_tun_lease.service ||
      lease.generation != integration->mesh_tun_lease.generation) {
    if (integration != NULL) integration->callback_failed = true;
    return;
  }
  integration->mesh_packet_errors++;
  integration->mesh_last_error = *error;
  if (error->feedback_sent) integration->mesh_feedback_sent++;
}

static ftun_status_t process_tun(integration_t *integration)
{
  size_t work = 0u;
  ftun_status_t status = ftun_tun_service_notify(
    integration->tun_service, FTUN_EVENT_READ | FTUN_EVENT_WRITE);
  if (status != FTUN_OK) return status;
  return ftun_tun_service_run(integration->tun_service, &work);
}

static ftun_status_t process_mesh_wire(integration_t *integration)
{
  uint8_t packet[TUN_MTU];
  for (;;) {
    ssize_t length = recv(integration->mesh_wire, packet, sizeof(packet), 0);
    if (length > 0) {
      ftun_status_t status = ftun_tun_service_write(
        integration->mesh_tun_lease,
        (ftun_bytes_t){packet, (size_t)length});
      if (status != FTUN_OK) return status;
      integration->mesh_packets_received++;
      continue;
    }
    if (length < 0 && errno == EINTR) continue;
    if (length < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      return process_tun(integration);
    }
    return FTUN_E_IO;
  }
}

static ftun_status_t complete_socket_write(integration_t *integration)
{
  ftun_stream_write_token_t pending = integration->tcp.socket.pending;
  ftun_error_t result;
  if (pending.stream == NULL) return FTUN_OK;
  memset(&integration->tcp.socket.pending, 0,
         sizeof(integration->tcp.socket.pending));
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
  ftun_buffer_slice_release(&slice);
  ftun_buffer_release(&buffer);
  if (status == FTUN_OK) {
    status = ftun_datagram_deliver(slot->channel, &slot->remote, &packet);
  }
  ftun_packet_release(&packet);
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
    struct pollfd descriptors[2];
    size_t callbacks = 0u;
    size_t dispatched = 0u;
    uint64_t now = 0u;
    memset(descriptors, 0, sizeof(descriptors));
    descriptors[0].fd = (int)integration->port_info.native_socket;
    descriptors[0].events = POLLIN;
    descriptors[1].fd = integration->mesh_wire;
    descriptors[1].events = POLLIN;
    if (poll(descriptors, 2u, 1) < 0 && errno != EINTR) return 1;
    if ((descriptors[0].revents & POLLIN) != 0 &&
        process_tun(integration) != FTUN_OK) return 1;
    if ((descriptors[1].revents & POLLIN) != 0 &&
        process_mesh_wire(integration) != FTUN_OK) return 1;
    if (ftun_event_loop_run_once(integration->loop, false, 32u,
                                 &callbacks) != FTUN_OK ||
        ftun_operation_dispatch(integration->operations, SIZE_MAX,
                                &dispatched) != FTUN_OK ||
        ftun_monotonic_now(&now) != FTUN_OK || now >= deadline) return 1;
  }
  return completion->calls == 1 ? 0 : 1;
}

static int overlay_exchange(integration_t *integration, int descriptor,
                            const uint8_t *message, size_t length)
{
  uint8_t response[256];
  uint64_t deadline = deadline_after(5000u);
  size_t sent = 0u;
  size_t received = 0u;
  while (sent < length || received < length) {
    struct pollfd descriptors[3];
    ssize_t amount;
    memset(descriptors, 0, sizeof(descriptors));
    descriptors[0] = (struct pollfd){
      (int)integration->port_info.native_socket, POLLIN, 0};
    descriptors[1] = (struct pollfd){integration->mesh_wire, POLLIN, 0};
    descriptors[2] = (struct pollfd){descriptor,
      (short)(POLLIN | (sent < length ? POLLOUT : 0)), 0};
    if (poll(descriptors, 3u, 10) < 0 && errno != EINTR) return 1;
    if ((descriptors[0].revents & POLLIN) != 0 &&
        process_tun(integration) != FTUN_OK) return 1;
    if ((descriptors[1].revents & POLLIN) != 0 &&
        process_mesh_wire(integration) != FTUN_OK) return 1;
    if (sent < length && (descriptors[2].revents & POLLOUT) != 0) {
      amount = send(descriptor, message + sent, length - sent, MSG_NOSIGNAL);
      if (amount > 0) sent += (size_t)amount;
      else if (amount < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
               errno != EINTR) return 1;
    }
    if (received < length && (descriptors[2].revents & POLLIN) != 0) {
      amount = recv(descriptor, response + received, length - received, 0);
      if (amount > 0) received += (size_t)amount;
      else if (amount == 0) return 1;
      else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        return 1;
      }
    }
    if ((descriptors[2].revents & (POLLERR | POLLNVAL)) != 0 ||
        deadline_after(0u) >= deadline) return 1;
  }
  return memcmp(response, message, length) == 0 ? 0 : 1;
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
                       bool overlay, socks_completion_t *completion)
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
  proxy.server = endpoint4(overlay ? MESH_ADDRESS : PEER_ADDRESS,
                           overlay ? MESH_SOCKS_PORT : SOCKS_PORT);
  proxy.udp_enabled = true;
  memset(&socks, 0, sizeof(socks));
  socks.loop = integration->loop;
  socks.operations = integration->operations;
  socks.budget = integration->budget;
  socks.proxy = &proxy;
  socks.target = &target;
  socks.network_view = overlay ? integration->network_view : NULL;
  socks.network_generation = overlay ? 1u : 0u;
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
                    false, &completion) == 0);
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
                    false, &completion) == 0);
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

  CHECK(start_socks(integration, FTUN_DIAL_TCP, 9u, false, &completion) == 0);
  CHECK(completion.error.status == FTUN_E_REJECTED &&
        completion.connection == NULL);

  {
    size_t sent_before = integration->mesh_packets_sent;
    size_t received_before = integration->mesh_packets_received;
    CHECK(start_socks(integration, FTUN_DIAL_TCP, DIRECT_TCP_PORT,
                      true, &completion) == 0);
    CHECK(completion.error.status == FTUN_OK && completion.connection != NULL);
    CHECK(ftun_socks5_connection_get_info(completion.connection, &info) ==
          FTUN_OK && info.transport == FTUN_DIAL_TCP &&
          info.proxy_domain == FTUN_DIAL_DOMAIN_OVERLAY &&
          info.network_generation == 1u);
    CHECK(overlay_exchange(integration, (int)info.data_socket, tcp_payload,
                           sizeof(tcp_payload) - 1u) == 0);
    CHECK(integration->mesh_packets_sent > sent_before &&
          integration->mesh_packets_received > received_before);
    CHECK(ftun_socks5_connection_close(&completion.connection) == FTUN_OK);
  }
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
  ftun_config_bind_plan(config, plan);
  return config;
}

static int integration_route_drive(integration_t *integration,
                                   ftun_route_async_t *routes,
                                   ftun_route_async_state_t terminal,
                                   uint64_t deadline_ms)
{
  for (;;) {
    ftun_route_async_info_t info;
    size_t route_work = 0u;
    size_t callbacks = 0u;
    bool block;
    if (ftun_monotonic_now(&integration->now_ms) != FTUN_OK ||
        integration->now_ms >= deadline_ms ||
        ftun_route_async_get_info(routes, &info) != FTUN_OK) {
      return 1;
    }
    if (info.state == terminal) return 0;
    if (info.state == FTUN_ROUTE_ASYNC_FAILED ||
        info.state == FTUN_ROUTE_ASYNC_CLEANUP_FAILED) return 1;
    if (ftun_route_async_run(routes, integration->now_ms,
                                   16u, &route_work) != FTUN_OK ||
        ftun_route_async_get_info(routes, &info) != FTUN_OK) {
      return 1;
    }
    if (info.state == terminal) return 0;
    block = route_work == 0u && !info.runnable;
    if (ftun_event_loop_run_once(integration->loop, block, 16u,
                                 &callbacks) != FTUN_OK) return 1;
  }
}

static int integration_start(integration_t *integration)
{
  ftun_runtime_t *candidate = NULL;
  ftun_runtime_manager_info_t manager_info;
  ftun_tun_spec_t tun_spec;
  ftun_route_policy_t route_policy;
  ftun_network_prefix_t protected_prefix;
  ftun_network_route_t overlay_route;
  ftun_network_view_spec_t network_spec;
  ftun_route_plan_t network_plan;
  ftun_tun_service_spec_t tun_service_spec;
  ftun_tun_consumer_t proxy_consumer;
  ftun_tun_consumer_spec_t mesh_consumer;
  ftun_tun_service_usage_t tun_usage;
  ftun_tun_ingress_spec_t ingress_spec;
  ftun_udp_flow_table_spec_t flow_spec;
  size_t index;
  memset(integration, 0, sizeof(*integration));
  integration->mesh_wire = -1;
  integration->tcp.socket.descriptor = -1;
  for (index = 0u; index < UDP_SLOTS; index++) {
    integration->udp[index].descriptor = -1;
  }
  if (ftun_budget_create(NULL, 16u * 1024u * 1024u, 65536u,
                         &integration->budget) != FTUN_OK ||
      ftun_buffer_pool_create(integration->budget, 65536u, 128u,
                              &integration->tun_buffers) != FTUN_OK ||
      ftun_operation_queue_create(integration->budget, 256u,
                                  &integration->operations) != FTUN_OK ||
      ftun_event_loop_create(NULL, &integration->loop) != FTUN_OK ||
      ftun_event_backend_attach(integration->loop) != FTUN_OK ||
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
  memset(&tun_service_spec, 0, sizeof(tun_service_spec));
  tun_service_spec.core = integration->core;
  tun_service_spec.budget = integration->budget;
  tun_service_spec.loop = integration->loop;
  tun_service_spec.buffers = integration->tun_buffers;
  tun_service_spec.device = tun_spec;
  tun_service_spec.consumer_capacity = 2u;
  tun_service_spec.input_capacity = 16u;
  tun_service_spec.consumer_quota = 16u;
  tun_service_spec.output_capacity = 32u;
  tun_service_spec.read_quota = 32u;
  tun_service_spec.write_quota = 32u;
  memset(&proxy_consumer, 0, sizeof(proxy_consumer));
  proxy_consumer.packet = integration_proxy_tun_packet;
  proxy_consumer.event = integration_tun_event;
  proxy_consumer.user = integration;
  memset(&mesh_consumer, 0, sizeof(mesh_consumer));
  mesh_consumer.consumer.packet = integration_mesh_tun_packet;
  mesh_consumer.consumer.event = integration_tun_event;
  mesh_consumer.consumer.packet_error = integration_mesh_packet_error;
  mesh_consumer.consumer.user = integration;
  mesh_consumer.route.kind = FTUN_TUN_ROUTE_IPV4_PREFIX;
  memcpy(mesh_consumer.route.network, (uint8_t[]){198u, 18u, 0u, 0u}, 4u);
  mesh_consumer.route.prefix_length = 16u;
  mesh_consumer.route.priority = 1u;
  mesh_consumer.path.carrier_mtu = 1500u;
  mesh_consumer.path.headroom = 100u;
  mesh_consumer.path.flags = FTUN_TUN_PATH_ALLOW_IPV4_FRAGMENTS |
    FTUN_TUN_PATH_VALIDATE_OUTPUT_SOURCE;
  if (ftun_tun_service_create(&tun_service_spec,
                              &integration->tun_service) != FTUN_OK ||
      ftun_tun_service_acquire(integration->tun_service, &proxy_consumer,
                               &integration->proxy_tun_lease) != FTUN_OK ||
      ftun_tun_service_acquire_routed(integration->tun_service,
        &mesh_consumer, &integration->mesh_tun_lease) != FTUN_OK ||
      ftun_tun_service_get_usage(integration->tun_service, &tun_usage) !=
        FTUN_OK) return 1;
  integration->port_info = tun_usage.device;
  integration->mesh_wire = socket_bound(SOCK_DGRAM, MAIN_ADDRESS,
                                         MESH_WIRE_PORT);
  if (integration->mesh_wire < 0 ||
      setsockopt(integration->mesh_wire, SOL_SOCKET, SO_MARK,
                 &(uint32_t){PROTECTION_MARK},
                 (socklen_t)sizeof(uint32_t)) != 0 ||
      !set_nonblocking(integration->mesh_wire)) return 1;
  {
    struct sockaddr_in peer_wire;
    memset(&peer_wire, 0, sizeof(peer_wire));
    peer_wire.sin_family = AF_INET;
    peer_wire.sin_port = htons(MESH_WIRE_PORT);
    if (inet_pton(AF_INET, PEER_ADDRESS, &peer_wire.sin_addr) != 1 ||
        connect(integration->mesh_wire, (const struct sockaddr *)&peer_wire,
                (socklen_t)sizeof(peer_wire)) != 0) return 1;
  }
  memset(&route_policy, 0, sizeof(route_policy));
  route_policy.tun_interface = tun_spec.name;
  CHECK(inet_pton(AF_INET, "10.77.0.1", route_policy.tun_ipv4) == 1);
  route_policy.tun_prefix_length = 30u;
  route_policy.routing_domain = 100u;
  route_policy.precedence = 12340u;
  route_policy.capture_offset = 100u;
  route_policy.bypass_tag = PROTECTION_MARK;
  route_policy.bypass_mask = UINT32_MAX;
  route_policy.manage_local = true;
  route_policy.lan_interface.data = "lan0";
  route_policy.lan_interface.length = 4u;
  route_policy.strict_route = true;
  {
    ftun_route_transaction_t *startup = NULL;
    ftun_route_async_t *adopted = NULL;
    ftun_route_async_info_t adopted_info;
    /* 静态启动资源交给非阻塞事务；接管不重新安装，逆序撤销后再验证原动态路径。 */
    if (ftun_route_prepare(&route_policy, &startup) != FTUN_OK ||
        ftun_monotonic_now(&integration->now_ms) != FTUN_OK ||
        ftun_route_async_adopt(&startup, integration->loop,
          integration->now_ms, 250u, integration->now_ms + 5000u, &adopted) != FTUN_OK ||
        startup != NULL || ftun_route_async_get_info(adopted, &adopted_info) != FTUN_OK ||
        adopted_info.state != FTUN_ROUTE_ASYNC_READY || adopted_info.active_count != 7u ||
        ftun_route_async_release(adopted, integration->now_ms,
          integration->now_ms + 5000u) != FTUN_OK ||
        integration_route_drive(integration, adopted, FTUN_ROUTE_ASYNC_RELEASED,
          integration->now_ms + 5000u) != 0 ||
        ftun_route_async_destroy(&adopted) != FTUN_OK) return 1;
  }
  if (ftun_route_async_start(&route_policy, integration->loop,
      integration->now_ms, 250u, integration->now_ms + 5000u,
      &integration->routes) != FTUN_OK ||
      integration_route_drive(integration, integration->routes,
                              FTUN_ROUTE_ASYNC_READY,
                              integration->now_ms + 5000u) != 0) return 1;

  memset(&protected_prefix, 0, sizeof(protected_prefix));
  memcpy(protected_prefix.network, (uint8_t[]){198u, 18u, 0u, 0u}, 4u);
  protected_prefix.prefix_length = 16u;
  memset(&overlay_route, 0, sizeof(overlay_route));
  overlay_route.prefix = protected_prefix;
  overlay_route.purpose_mask =
    FTUN_DIAL_PURPOSE_BIT(FTUN_DIAL_PURPOSE_PROXY) |
    FTUN_DIAL_PURPOSE_BIT(FTUN_DIAL_PURPOSE_BUSINESS);
  memset(&network_spec, 0, sizeof(network_spec));
  network_spec.generation = 1u;
  network_spec.protected_prefixes = &protected_prefix;
  network_spec.protected_prefix_count = 1u;
  network_spec.overlay_routes = &overlay_route;
  network_spec.overlay_route_count = 1u;
  if (ftun_network_view_create(&network_spec, &integration->network_view) !=
        FTUN_OK ||
      ftun_route_guard_plan(integration->network_view, 100u, 12341u,
                                  &network_plan) != FTUN_OK ||
      ftun_monotonic_now(&integration->now_ms) != FTUN_OK ||
      ftun_route_async_start_plan(&network_plan, integration->loop,
        integration->now_ms, 250u, integration->now_ms + 5000u,
        &integration->network_guard) != FTUN_OK ||
      integration_route_drive(integration, integration->network_guard,
        FTUN_ROUTE_ASYNC_READY, integration->now_ms + 5000u) != 0 ||
      ftun_route_overlay_plan(integration->network_view, tun_spec.name,
                                    100u, 100u, &network_plan) != FTUN_OK ||
      ftun_monotonic_now(&integration->now_ms) != FTUN_OK ||
      ftun_route_async_start_plan(&network_plan, integration->loop,
        integration->now_ms, 250u, integration->now_ms + 5000u,
        &integration->overlay_routes) != FTUN_OK ||
      integration_route_drive(integration, integration->overlay_routes,
        FTUN_ROUTE_ASYNC_READY, integration->now_ms + 5000u) != 0) {
    return 1;
  }
  for (index = 0u; index < 3u; index++) {
    ftun_route_policy_t probe_policy = route_policy;
    ftun_route_async_t *duplicate_routes = NULL;
    if (index >= 1u) probe_policy.tun_ipv4[2] = 1u;
    if (index >= 2u) probe_policy.bypass_tag = UINT32_C(0x46000002);
    /* 同表号的第二个实例在改动网络之前就被实例锁拒绝，不留下任何对象。 */
    if (ftun_monotonic_now(&integration->now_ms) != FTUN_OK ||
        ftun_route_async_start(&probe_policy, integration->loop,
          integration->now_ms, 250u, integration->now_ms + 5000u,
          &duplicate_routes) != FTUN_E_REJECTED ||
        duplicate_routes != NULL) return 1;
  }

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

static int overlay_tcp_open(integration_t *integration,
                            const struct sockaddr_in *target)
{
  uint64_t deadline = deadline_after(5000u);
  int descriptor = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                          IPPROTO_TCP);
  int result;
  if (descriptor < 0) return -1;
  result = connect(descriptor, (const struct sockaddr *)target,
                   (socklen_t)sizeof(*target));
  if (result == 0) return descriptor;
  if (errno != EINPROGRESS) {
    (void)close(descriptor);
    return -1;
  }
  for (;;) {
    struct pollfd descriptors[3];
    int error_code = 0;
    socklen_t error_length = (socklen_t)sizeof(error_code);
    memset(descriptors, 0, sizeof(descriptors));
    descriptors[0] = (struct pollfd){
      (int)integration->port_info.native_socket, POLLIN, 0};
    descriptors[1] = (struct pollfd){integration->mesh_wire, POLLIN, 0};
    descriptors[2] = (struct pollfd){descriptor, POLLOUT, 0};
    if (poll(descriptors, 3u, 10) < 0 && errno != EINTR) break;
    if ((descriptors[0].revents & POLLIN) != 0 &&
        process_tun(integration) != FTUN_OK) break;
    if ((descriptors[1].revents & POLLIN) != 0 &&
        process_mesh_wire(integration) != FTUN_OK) break;
    if ((descriptors[2].revents & (POLLOUT | POLLERR | POLLHUP)) != 0) {
      if (getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error_code,
                     &error_length) != 0 || error_length != sizeof(error_code) ||
          error_code != 0) break;
      return descriptor;
    }
    if (deadline_after(0u) >= deadline) break;
  }
  (void)close(descriptor);
  return -1;
}

static int test_mesh_path_mtu(integration_t *integration)
{
  ftun_tun_path_t path;
  ftun_tun_consumer_usage_t usage;
  struct sockaddr_in target;
  struct pollfd descriptor;
  uint8_t payload[1272];
  size_t sent_before = integration->mesh_packets_sent;
  size_t errors_before = integration->mesh_packet_errors;
  size_t feedback_before = integration->mesh_feedback_sent;
  int discovery = IP_PMTUDISC_DO;
  int mtu = 0;
  socklen_t mtu_length = (socklen_t)sizeof(mtu);
  int blocked = -1;
  int probe = -1;
  int result;

  memset(payload, 0x5au, sizeof(payload));
  memset(&target, 0, sizeof(target));
  target.sin_family = AF_INET;
  target.sin_port = htons(19091u);
  CHECK(inet_pton(AF_INET, MESH_ADDRESS, &target.sin_addr) == 1);
  memset(&path, 0, sizeof(path));
  path.carrier_mtu = 1300u;
  path.headroom = 100u;
  path.flags = FTUN_TUN_PATH_ALLOW_IPV4_FRAGMENTS |
    FTUN_TUN_PATH_VALIDATE_OUTPUT_SOURCE;
  CHECK(ftun_tun_service_update_path(integration->mesh_tun_lease, &path) ==
        FTUN_OK);
  CHECK(ftun_tun_service_get_consumer_usage(
          integration->mesh_tun_lease, &usage) == FTUN_OK &&
        usage.inner_mtu == 1200u && usage.path_generation == 2u);

  blocked = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
  CHECK(blocked >= 0 &&
        setsockopt(blocked, IPPROTO_IP, IP_MTU_DISCOVER, &discovery,
                   (socklen_t)sizeof(discovery)) == 0 &&
        connect(blocked, (const struct sockaddr *)&target,
                (socklen_t)sizeof(target)) == 0);
  CHECK(send(blocked, payload, sizeof(payload), 0) == (ssize_t)sizeof(payload));
  descriptor = (struct pollfd){
    (int)integration->port_info.native_socket, POLLIN, 0};
  CHECK(poll(&descriptor, 1u, 1000) == 1 &&
        (descriptor.revents & POLLIN) != 0 &&
        process_tun(integration) == FTUN_OK);
  CHECK(integration->mesh_packets_sent == sent_before &&
        integration->mesh_packet_errors == errors_before + 1u &&
        integration->mesh_feedback_sent == feedback_before + 1u &&
        integration->mesh_last_error.reason == FTUN_TUN_PACKET_TOO_BIG &&
        integration->mesh_last_error.direction == FTUN_TUN_PACKET_FROM_DEVICE &&
        integration->mesh_last_error.packet_length == 1300u &&
        integration->mesh_last_error.inner_mtu == 1200u &&
        integration->mesh_last_error.feedback_sent);
  descriptor = (struct pollfd){blocked, POLLERR, 0};
  CHECK(poll(&descriptor, 1u, 1000) == 1 &&
        (descriptor.revents & POLLERR) != 0 &&
        getsockopt(blocked, IPPROTO_IP, IP_MTU, &mtu, &mtu_length) == 0 &&
        mtu_length == sizeof(mtu) && mtu == 1200);
  errno = 0;
  result = (int)send(blocked, payload, sizeof(payload), 0);
  CHECK(result < 0 && errno == EMSGSIZE);
  CHECK(close(blocked) == 0);
  blocked = -1;

  path.carrier_mtu = 1500u;
  CHECK(ftun_tun_service_update_path(integration->mesh_tun_lease, &path) ==
        FTUN_OK);
  CHECK(ftun_tun_service_get_consumer_usage(
          integration->mesh_tun_lease, &usage) == FTUN_OK &&
        usage.inner_mtu == TUN_MTU && usage.path_generation == 3u &&
        usage.queued_inputs == 0u && usage.queued_outputs == 0u);
  discovery = IP_PMTUDISC_PROBE;
  probe = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
  CHECK(probe >= 0 &&
        setsockopt(probe, IPPROTO_IP, IP_MTU_DISCOVER, &discovery,
                   (socklen_t)sizeof(discovery)) == 0 &&
        connect(probe, (const struct sockaddr *)&target,
                (socklen_t)sizeof(target)) == 0 &&
        send(probe, payload, sizeof(payload), 0) == (ssize_t)sizeof(payload));
  descriptor = (struct pollfd){
    (int)integration->port_info.native_socket, POLLIN, 0};
  CHECK(poll(&descriptor, 1u, 1000) == 1 &&
        (descriptor.revents & POLLIN) != 0 &&
        process_tun(integration) == FTUN_OK &&
        integration->mesh_packets_sent == sent_before + 1u);
  CHECK(close(probe) == 0);
  CHECK(integration->mesh_path_updates == 2u &&
        !integration->callback_failed);
  return 0;
}

static int test_network_protection(integration_t *integration)
{
  ftun_network_prefix_t protected_prefix;
  ftun_network_view_spec_t spec;
  ftun_network_view_t *revoked = NULL;
  ftun_route_plan_t guard_plan;
  struct sockaddr_in target;
  struct sockaddr_ll capture_address;
  uint8_t packet[2048];
  uint8_t byte = 0x5au;
  int old_socket = -1;
  int old_tcp = -1;
  int new_socket = -1;
  int capture = -1;
  int result;
  ssize_t length;
  unsigned int interface_index = if_nametoindex("phys0");

  CHECK(interface_index != 0u);
  capture = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
                   htons(ETH_P_IP));
  CHECK(capture >= 0);
  memset(&capture_address, 0, sizeof(capture_address));
  capture_address.sll_family = AF_PACKET;
  capture_address.sll_protocol = htons(ETH_P_IP);
  capture_address.sll_ifindex = (int)interface_index;
  CHECK(bind(capture, (const struct sockaddr *)&capture_address,
             (socklen_t)sizeof(capture_address)) == 0);

  memset(&target, 0, sizeof(target));
  target.sin_family = AF_INET;
  target.sin_port = htons(1080u);
  CHECK(inet_pton(AF_INET, "198.18.1.2", &target.sin_addr) == 1);
  old_socket = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
  CHECK(old_socket >= 0);
  CHECK(connect(old_socket, (const struct sockaddr *)&target,
                (socklen_t)sizeof(target)) == 0);
  target.sin_port = htons(MESH_SOCKS_PORT);
  old_tcp = overlay_tcp_open(integration, &target);
  CHECK(old_tcp >= 0);

  memset(&protected_prefix, 0, sizeof(protected_prefix));
  memcpy(protected_prefix.network, (uint8_t[]){198u, 18u, 0u, 0u}, 4u);
  protected_prefix.prefix_length = 16u;
  memset(&spec, 0, sizeof(spec));
  spec.generation = 2u;
  spec.protected_prefixes = &protected_prefix;
  spec.protected_prefix_count = 1u;
  CHECK(ftun_network_view_create(&spec, &revoked) == FTUN_OK);
  ftun_network_view_release(&integration->network_view);
  integration->network_view = revoked;
  revoked = NULL;

  CHECK(ftun_monotonic_now(&integration->now_ms) == FTUN_OK);
  CHECK(ftun_route_async_release(integration->overlay_routes,
          integration->now_ms, integration->now_ms + 5000u) == FTUN_OK);
  CHECK(integration_route_drive(integration, integration->overlay_routes,
          FTUN_ROUTE_ASYNC_RELEASED,
          integration->now_ms + 5000u) == 0);
  CHECK(ftun_route_async_destroy(&integration->overlay_routes) ==
        FTUN_OK);

  errno = 0;
  result = (int)send(old_socket, &byte, 1u, 0);
  CHECK(result < 0 && (errno == ENETUNREACH || errno == EHOSTUNREACH ||
                       errno == EACCES));
  {
    size_t mesh_before = integration->mesh_packets_sent;
    struct pollfd descriptor;
    (void)send(old_tcp, &byte, 1u, MSG_NOSIGNAL);
    memset(&descriptor, 0, sizeof(descriptor));
    descriptor.fd = (int)integration->port_info.native_socket;
    descriptor.events = POLLIN;
    if (poll(&descriptor, 1u, 50) == 1 &&
        (descriptor.revents & POLLIN) != 0) {
      CHECK(process_tun(integration) == FTUN_OK);
    }
    CHECK(integration->mesh_packets_sent == mesh_before);
  }
  target.sin_port = htons(1080u);
  new_socket = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
  CHECK(new_socket >= 0);
  errno = 0;
  result = connect(new_socket, (const struct sockaddr *)&target,
                   (socklen_t)sizeof(target));
  CHECK(result < 0 && (errno == ENETUNREACH || errno == EHOSTUNREACH ||
                       errno == EACCES));
  do {
    length = recv(capture, packet, sizeof(packet), 0);
    if (length >= 34 && packet[12] == 0x08u && packet[13] == 0x00u) {
      CHECK(!(packet[30] == 198u && packet[31] == 18u));
    }
  } while (length >= 0 || errno == EINTR);
  CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
  CHECK(close(new_socket) == 0 && close(old_tcp) == 0 &&
        close(old_socket) == 0);
  new_socket = old_tcp = old_socket = -1;

  /* 清理退出后按同一撤销视图重建 guard，模拟干净重启。保护必须先恢复，
   * 才允许后续使用该代 NetworkView。 */
  CHECK(ftun_monotonic_now(&integration->now_ms) == FTUN_OK);
  CHECK(ftun_route_async_release(integration->network_guard,
          integration->now_ms, integration->now_ms + 5000u) == FTUN_OK);
  CHECK(integration_route_drive(integration, integration->network_guard,
          FTUN_ROUTE_ASYNC_RELEASED,
          integration->now_ms + 5000u) == 0);
  CHECK(ftun_route_async_destroy(&integration->network_guard) ==
        FTUN_OK);
  CHECK(ftun_route_guard_plan(integration->network_view, 100u, 12341u,
                                    &guard_plan) == FTUN_OK);
  CHECK(ftun_monotonic_now(&integration->now_ms) == FTUN_OK);
  CHECK(ftun_route_async_start_plan(&guard_plan, integration->loop,
          integration->now_ms, 250u, integration->now_ms + 5000u,
          &integration->network_guard) == FTUN_OK);
  CHECK(integration_route_drive(integration, integration->network_guard,
          FTUN_ROUTE_ASYNC_READY,
          integration->now_ms + 5000u) == 0);
  new_socket = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
  CHECK(new_socket >= 0);
  errno = 0;
  result = connect(new_socket, (const struct sockaddr *)&target,
                   (socklen_t)sizeof(target));
  CHECK(result < 0 && (errno == ENETUNREACH || errno == EHOSTUNREACH ||
                       errno == EACCES));
  CHECK(close(new_socket) == 0 && close(capture) == 0);
  return 0;
}

static int integration_stop(integration_t *integration)
{
  ftun_budget_usage_t budget_usage;
  ftun_operation_queue_usage_t operation_usage;
  size_t dispatched = 0u;
  if (integration->tcp.active || integration->callback_failed) return 1;
  if (ftun_udp_flow_table_destroy(&integration->udp_flows) != FTUN_OK ||
      ftun_tun_ingress_close(&integration->ingress) != FTUN_OK ||
      ftun_monotonic_now(&integration->now_ms) != FTUN_OK ||
      ftun_route_async_release(integration->network_guard,
        integration->now_ms, integration->now_ms + 5000u) != FTUN_OK ||
      integration_route_drive(integration, integration->network_guard,
                              FTUN_ROUTE_ASYNC_RELEASED,
                              integration->now_ms + 5000u) != 0 ||
      ftun_route_async_destroy(&integration->network_guard) != FTUN_OK) return 1;
  ftun_network_view_release(&integration->network_view);
  if (ftun_monotonic_now(&integration->now_ms) != FTUN_OK ||
      ftun_route_async_release(integration->routes,
        integration->now_ms, integration->now_ms + 5000u) != FTUN_OK ||
      integration_route_drive(integration, integration->routes,
                              FTUN_ROUTE_ASYNC_RELEASED,
                              integration->now_ms + 5000u) != 0 ||
      ftun_route_async_destroy(&integration->routes) != FTUN_OK ||
      close(integration->mesh_wire) != 0 ||
      ftun_tun_service_quiesce(integration->tun_service) != FTUN_OK ||
      ftun_tun_service_release(&integration->mesh_tun_lease) != FTUN_OK ||
      ftun_tun_service_release(&integration->proxy_tun_lease) != FTUN_OK ||
      ftun_tun_service_destroy(&integration->tun_service) != FTUN_OK ||
      ftun_worker_stop(integration->worker) != FTUN_OK ||
      ftun_worker_join(integration->worker) != FTUN_OK ||
      ftun_worker_poll(integration->worker, SIZE_MAX, &dispatched) != FTUN_OK ||
      ftun_worker_destroy(&integration->worker) != FTUN_OK ||
      ftun_event_loop_stop(integration->loop) != FTUN_OK ||
      ftun_event_backend_detach(integration->loop) != FTUN_OK ||
      ftun_event_loop_destroy(&integration->loop) != FTUN_OK ||
      ftun_operation_queue_get_usage(integration->operations,
                                     &operation_usage) != FTUN_OK ||
      operation_usage.inflight != 0u ||
      ftun_operation_queue_stop(integration->operations) != FTUN_OK ||
      ftun_operation_queue_destroy(&integration->operations) != FTUN_OK ||
      ftun_buffer_pool_destroy(&integration->tun_buffers) != FTUN_OK ||
      ftun_runtime_manager_destroy(&integration->core) != FTUN_OK ||
      ftun_budget_get_usage(integration->budget, &budget_usage) != FTUN_OK ||
      budget_usage.used_resources.memory_bytes != 0u ||
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
  CHECK(test_mesh_path_mtu(&integration) == 0);
  CHECK(test_socks(&integration) == 0);
  CHECK(test_network_protection(&integration) == 0);
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
        FTUN_OK);
  if (flow_usage.active != 0u || flow_usage.expired != 2u ||
      flow_usage.created != 2u) {
    fprintf(stderr, "UDP usage active=%zu expired=%zu created=%zu\n",
            flow_usage.active, flow_usage.expired, flow_usage.created);
    return 1;
  }
  CHECK(integration.accepted_tcp == 2u && integration.received_udp == 2u);
  CHECK(integration_stop(&integration) == 0);
  return 0;
}

static int owner_update_drive(void *owner, ftun_tun_network_update_result_t *result)
{
  ftun_core_service_run_usage_t run;
  uint64_t now_ms, deadline;
  CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK);
  deadline = now_ms + 6000u;
  for (;;) {
    CHECK(ftun_tun_owner_query_network_update(owner, result) == FTUN_OK);
    if (!result->pending) return 0;
    CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK && now_ms < deadline);
    CHECK(ftun_tun_owner_service.run_once(owner, true, &run) == FTUN_OK);
    CHECK(run.work <= 192u);
  }
}

static int owner_address_matches(const uint8_t expected[4])
{
  struct ifaddrs *list = NULL, *entry;
  size_t matches = 0u, addresses = 0u;
  CHECK(getifaddrs(&list) == 0);
  for (entry = list; entry != NULL; entry = entry->ifa_next) {
    if (entry->ifa_addr == NULL || entry->ifa_addr->sa_family != AF_INET ||
        strcmp(entry->ifa_name, "ftun-own-it0") != 0) continue;
    addresses++;
    if (memcmp(&((const struct sockaddr_in *)entry->ifa_addr)->sin_addr, expected, 4u) == 0) matches++;
  }
  freeifaddrs(list);
  CHECK(matches == 1u && addresses == 1u);
  return 0;
}

static int owner_recovery_main(void)
{
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_tun_owner_binding_t binding = {0};
  ftun_core_service_binding_t service_binding = {&binding, sizeof(binding)};
  ftun_l3_provider_t provider = {0};
  ftun_config_t config = {0};
  ftun_config_bind_sections(&config);
  ftun_budget_usage_t baseline, final;
  ftun_tun_network_update_result_t result;
  ftun_interface_spec_t candidate = {{"ftun-own-it0", 12u}, {10u, 79u, 1u, 1u}, 24u, PROTECTION_MARK, 18004u, 11000u, false, NULL};
  void *owner = NULL;
  uint64_t now_ms, deadline;
  unsigned int old_index;
  const struct timespec pause = {0, 1000000};
  CHECK(ftun_budget_create(NULL, 8u * 1024u * 1024u, 65536u, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 8u, &operations) == FTUN_OK);
  CHECK(ftun_event_loop_create_with_capacity(core, 64u, &loop) == FTUN_OK);
  CHECK(ftun_event_backend_attach(loop) == FTUN_OK);
  binding.provider = &provider;
  binding.loop = loop;
  binding.network = &ftun_interface_default_ops;
  binding.protection_mark = PROTECTION_MARK;
  config.tun.present = true;
  config.tun.interface_name = "ftun-own-it0";
  config.tun.ipv4_address = "10.79.0.1/30";
  config.tun.mtu = TUN_MTU;
  config.tun.auto_route = true;
  config.tun.strict_route = true;
  config.tun.route_table = 18004u;
  config.tun.rule_priority = 11000u;
  CHECK(ftun_budget_get_usage(budget, &baseline) == FTUN_OK);
  CHECK(ftun_tun_owner_service.prepare(core, budget, operations, &service_binding,
    &config, 1u, &owner) == FTUN_OK);
  CHECK(ftun_tun_owner_service.activate(owner) == FTUN_OK);
  old_index = if_nametoindex("ftun-own-it0");
  CHECK(old_index != 0u && owner_address_matches((uint8_t[]){10u, 79u, 0u, 1u}) == 0);
  CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK);
  CHECK(ftun_tun_owner_start_network_update(owner, 1u, &candidate, now_ms + 5000u) == FTUN_OK);
  CHECK(owner_update_drive(owner, &result) == 0 && result.committed && result.ready &&
    result.device_generation == 1u && result.network_generation == 2u);
  CHECK(owner_address_matches(candidate.ipv4_address) == 0);
  CHECK(ftun_tun_service_rebuild(provider.service) == FTUN_E_AGAIN);
  CHECK(owner_update_drive(owner, &result) == 0 && result.rebuild && result.committed && result.ready &&
    result.device_generation == 2u && result.network_generation == 3u);
  CHECK(if_nametoindex("ftun-own-it0") != 0u && if_nametoindex("ftun-own-it0") != old_index);
  CHECK(owner_address_matches(candidate.ipv4_address) == 0);
  CHECK(ftun_tun_service_refresh_network(provider.service, 3u) == FTUN_E_AGAIN);
  CHECK(owner_update_drive(owner, &result) == 0 && !result.rebuild && result.ready &&
    result.device_generation == 2u && result.network_generation == 4u);
  CHECK(owner_address_matches(candidate.ipv4_address) == 0);
  CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK);
  CHECK(ftun_tun_owner_start_rebuild(owner, 1u, 4u, now_ms + 5000u) == FTUN_E_STALE);
  CHECK(ftun_tun_owner_start_rebuild(owner, 2u, 4u, now_ms + 5000u) == FTUN_OK);
  CHECK(ftun_tun_owner_service.quiesce(owner) == FTUN_OK);
  CHECK(ftun_tun_owner_query_network_update(owner, &result) == FTUN_OK &&
    !result.pending && !result.ready && result.update_status == FTUN_E_CANCELLED);
  deadline = now_ms + 5000u;
  while (owner != NULL) {
    ftun_status_t status = ftun_tun_owner_service.destroy_until(&owner, deadline);
    CHECK(status == FTUN_OK || status == FTUN_E_AGAIN);
    if (owner != NULL) {
      CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK && now_ms < deadline);
      (void)nanosleep(&pause, NULL);
    }
  }
  CHECK(provider.service == NULL && if_nametoindex("ftun-own-it0") == 0u);
  CHECK(ftun_budget_get_usage(budget, &final) == FTUN_OK && final.used_resources.memory_bytes == baseline.used_resources.memory_bytes &&
    final.used_resources.descriptors == baseline.used_resources.descriptors &&
    final.used_resources.queue_slots == baseline.used_resources.queue_slots);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK && ftun_event_backend_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(operations) == FTUN_OK && ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK && ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(int argc, char **argv)
{
  if (argc == 2 && strcmp(argv[1], "--tun-owner-recovery") == 0) return owner_recovery_main();
  if (argc == 3 && strcmp(argv[1], "--peer") == 0) {
    return peer_main(argv[2], NULL);
  }
  if (argc == 4 && strcmp(argv[1], "--peer") == 0) {
    return peer_main(argv[2], argv[3]);
  }
  if (argc == 4 && strcmp(argv[1], "--client") == 0) {
    return client_main(argv[2], argv[3], PEER_ADDRESS);
  }
  if (argc == 5 && strcmp(argv[1], "--client-to") == 0) {
    return client_main(argv[2], argv[3], argv[4]);
  }
  if (argc == 5 && strcmp(argv[1], "--dns-client") == 0) {
    return dns_client_main(argv[2], argv[3], argv[4]);
  }
  if (argc == 5 && strcmp(argv[1], "--dns-fakeip-sequence") == 0) {
    return dns_fakeip_sequence_main(argv[2], argv[3], argv[4]);
  }
  if (argc == 5 && strcmp(argv[1], "--dns-tcp-client") == 0) {
    return dns_tcp_client_main(argv[2], argv[3], argv[4]);
  }
  if (argc == 5 && strcmp(argv[1], "--dns-tcp-pipeline") == 0) {
    return dns_tcp_pipeline_main(argv[2], argv[3], argv[4]);
  }
  if (argc == 4 && strcmp(argv[1], "--socks-client") == 0) {
    return socks_client_main(argv[2], argv[3]);
  }
  if (argc == 5 && strcmp(argv[1], "--socks-hold-client") == 0) {
    return socks_client_with_hold_main(argv[2], argv[3], argv[4]);
  }
  if (argc == 4 && strcmp(argv[1], "--socks-stall-client") == 0) {
    return socks_stall_client_main(argv[2], argv[3]);
  }
  if (argc == 5 && strcmp(argv[1], "--tcp-hold-clients") == 0) {
    return tcp_hold_clients_main(argv[2], argv[3], argv[4]);
  }
  if (argc == 5 && strcmp(argv[1], "--socks-load-client") == 0) {
    return socks_load_client_main(argv[2], argv[3], argv[4]);
  }
  if (argc == 5 && strcmp(argv[1], "--load-client") == 0) {
    return load_client_main(argv[2], argv[3], argv[4]);
  }
  if (argc == 4 && strcmp(argv[1], "--socks-domain-client") == 0) {
    return socks_domain_client_main(argv[2], argv[3]);
  }
  if (argc == 4 && strcmp(argv[1], "--socks-udp-client") == 0) {
    return socks_udp_client_main(argv[2], argv[3], NULL, false, false);
  }
  if (argc == 5 && strcmp(argv[1], "--socks-udp-load-client") == 0) {
    return socks_udp_client_main(argv[2], argv[3], argv[4], false, false);
  }
  if (argc == 4 && strcmp(argv[1], "--socks-udp-recovery-client") == 0) {
    return socks_udp_client_main(argv[2], argv[3], NULL, true, false);
  }
  if (argc == 4 && strcmp(argv[1], "--socks-udp-backoff-client") == 0) {
    return socks_udp_client_main(argv[2], argv[3], NULL, false, true);
  }
  if (argc == 4 && strcmp(argv[1], "--mixed-connect-client") == 0) {
    return mixed_connect_client_main(argv[2], argv[3]);
  }
  if (argc == 4 && strcmp(argv[1], "--mixed-forward-client") == 0) {
    return mixed_forward_client_main(argv[2], argv[3]);
  }
  if (argc == 4 && strcmp(argv[1], "--echo-server") == 0) {
    return echo_server_main(argv[2], argv[3]);
  }
  if (argc == 5 && strcmp(argv[1], "--dns-server") == 0) {
    return dns_server_main(argv[2], argv[3], argv[4]);
  }
  if (argc == 6 && strcmp(argv[1], "--dns-concurrency-server") == 0) {
    return dns_concurrency_server_main(argv[2], argv[3], argv[4], argv[5]);
  }
  if (argc == 6 && strcmp(argv[1], "--dns-tcp-concurrency-server") == 0) {
    return dns_tcp_concurrency_server_main(argv[2], argv[3], argv[4], argv[5]);
  }
  if (argc == 4 && strcmp(argv[1], "--dns-concurrency-client") == 0) {
    return dns_concurrency_client_main(argv[2], argv[3]);
  }
  if (argc == 5 && strcmp(argv[1], "--dns-flood-client") == 0) {
    return dns_flood_client_main(argv[2], argv[3], argv[4]);
  }
  if (argc == 5 && strcmp(argv[1], "--dns-isolation-client") == 0) {
    return dns_isolation_client_main(argv[2], argv[3], argv[4]);
  }
  if (argc == 2 && strcmp(argv[1], "--run") == 0) {
    return integration_main(argv[0]);
  }
  fprintf(stderr, "usage: %s --peer READY | --client tcp|udp TAG | "
                  "--client-to tcp|udp TAG ADDRESS | "
                  "--dns-client ADDRESS PORT EXPECTED | "
                  "--dns-fakeip-sequence ADDRESS PORT COUNT | "
                  "--dns-tcp-client ADDRESS PORT EXPECTED | "
                  "--dns-concurrency-server ADDRESS PORT READY RESULT | "
                  "--dns-tcp-concurrency-server ADDRESS PORT READY RESULT | "
                  "--dns-concurrency-client ADDRESS PORT | "
                  "--dns-flood-client ADDRESS PORT DURATION_MS | "
                  "--dns-isolation-client ADDRESS PORT PORT | "
                  "--socks-client PORT TARGET | "
                  "--socks-hold-client PORT TARGET HOLD_MS | "
                  "--socks-stall-client PORT HOLD_MS | "
                  "--tcp-hold-clients PORT COUNT HOLD_MS | "
                  "--socks-load-client PORT TARGET BYTES | "
                  "--load-client TARGET BYTES PATH | "
                  "--socks-domain-client PORT DOMAIN:PORT | "
                  "--socks-udp-client PORT TARGET | "
                  "--socks-udp-load-client PORT TARGET PACKETS | "
                  "--socks-udp-recovery-client PORT TARGET | "
                  "--socks-udp-backoff-client PORT TARGET | "
                  "--mixed-connect-client PORT TARGET | "
                  "--mixed-forward-client PORT TARGET | "
                  "--echo-server TARGET READY | "
                  "--dns-server ADDRESS PORT READY | --tun-owner-recovery | --run\n",
          argv[0]);
  return 2;
}
