#define _POSIX_C_SOURCE 200809L
#include <sys/types.h>
#include "core/context.h"
#include "core/event/backend.h"
#include "libs/transport/socket_path.h"
#include "platform/clock.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "socket path failed at %d: %s\n", \
  __LINE__, #x); return 1; } } while (0)

static unsigned int send_again;
static int send_error;
ssize_t __real_send(int socket, const void *data, size_t length, int flags);
ssize_t __wrap_send(int socket, const void *data, size_t length, int flags)
{
  if (send_error != 0) {
    errno = send_error;
    send_error = 0;
    return -1;
  }
  if (send_again != 0u) {
    send_again--;
    errno = EAGAIN;
    return -1;
  }
  return __real_send(socket, data, length, flags);
}

typedef struct {
  ftun_budget_t *budget;
  ftun_core_t *core;
  ftun_event_loop_t *loop;
  ftun_operation_queue_t *operations;
  ftun_path_provider_t *provider;
  ftun_buffer_pool_t *pool;
  ftun_path_t *path;
  ftun_path_open_request_t request;
  ftun_packet_t held;
  unsigned int opens, writes, received, attempts, readable, errors, failures;
  ftun_status_t open_status, write_status, receive_status;
  bool hold_packet;
  bool revoke_on_notify;
  bool libev;
} fixture_t;

static int descriptor_count(void)
{
  DIR *directory = opendir("/proc/self/fd");
  struct dirent *entry;
  int count = 0;
  if (directory == NULL) return -1;
  while ((entry = readdir(directory)) != NULL) {
    if (entry->d_name[0] != '.') count++;
  }
  (void)closedir(directory);
  return count;
}

static void opened(ftun_operation_t *operation, ftun_error_t error,
  ftun_path_t *path, void *user)
{
  fixture_t *fixture = (fixture_t *)user;
  if (operation == NULL || (error.status == FTUN_OK) != (path != NULL)) fixture->failures++;
  fixture->opens++;
  fixture->open_status = error.status;
  fixture->path = path;
}

static void wrote(ftun_operation_t *operation, ftun_error_t error, void *user)
{
  fixture_t *fixture = (fixture_t *)user;
  (void)operation;
  fixture->writes++;
  fixture->write_status = error.status;
}

static void sent(ftun_datagram_t *channel, ftun_error_t error,
  const ftun_endpoint_t *target, const ftun_packet_t *packet, void *user)
{
  (void)channel; (void)target; (void)packet;
  wrote(NULL, error, user);
}

static ftun_status_t received(ftun_datagram_t *channel, const ftun_endpoint_t *source,
  const ftun_packet_t *packet, void *user)
{
  fixture_t *fixture = (fixture_t *)user;
  ftun_bytes_t bytes;
  (void)channel;
  fixture->attempts++;
  if (fixture->receive_status != FTUN_OK) return fixture->receive_status;
  if (source->port != fixture->request.dial.endpoint.port ||
      ftun_packet_view(packet, &bytes) != FTUN_OK ||
      (bytes.length != 0u && (bytes.length != 8u || memcmp(bytes.data, "ab\0defgh", 8u) != 0))) {
    fixture->failures++;
  }
  if (fixture->hold_packet && ftun_packet_clone(packet, &fixture->held) != FTUN_OK) {
    fixture->failures++;
  }
  fixture->received++;
  return FTUN_OK;
}

static void notified(ftun_path_t *path, uint32_t events, ftun_error_t error, void *user)
{
  fixture_t *fixture = (fixture_t *)user;
  ftun_path_info_t info;
  if (ftun_path_get_info(path, &info) != FTUN_OK || info.references < 2u) fixture->failures++;
  if ((events & FTUN_PATH_READABLE) != 0u) fixture->readable++;
  if ((events & FTUN_PATH_ERROR) != 0u) fixture->errors++;
  if (fixture->revoke_on_notify) {
    ftun_path_t *borrowed = path;
    if (ftun_path_revoke(path) != FTUN_OK ||
        ftun_path_destroy(&borrowed) != FTUN_E_AGAIN || borrowed != path) fixture->failures++;
  }
  (void)error;
}

static int setup_with_pool(fixture_t *fixture, bool libev, bool pooled)
{
  ftun_path_provider_spec_t provider = {0};
  memset(fixture, 0, sizeof(*fixture));
  fixture->libev = libev;
  CHECK(ftun_budget_create(NULL, 4194304u, 0u, &fixture->budget) == FTUN_OK);
  CHECK(ftun_core_context_create(fixture->budget, &fixture->core) == FTUN_OK);
  CHECK(ftun_operation_queue_create(fixture->budget, 16u, &fixture->operations) == FTUN_OK);
  CHECK(ftun_event_loop_create(fixture->core, &fixture->loop) == FTUN_OK);
  if (libev) CHECK(ftun_event_backend_attach(fixture->loop) == FTUN_OK);
  provider.budget = fixture->budget;
  provider.generation = 7u;
  provider.ops.open = ftun_socket_path_open;
  if (pooled) {
    CHECK(ftun_buffer_pool_create(fixture->budget, 65536u, 1u, &fixture->pool) == FTUN_OK);
    provider.receive_pool = fixture->pool;
  }
  CHECK(ftun_path_provider_create(&provider, &fixture->provider) == FTUN_OK);
  fixture->request.dial.budget = fixture->budget;
  fixture->request.dial.loop = fixture->loop;
  fixture->request.dial.operations = fixture->operations;
  fixture->request.dial.purpose = FTUN_DIAL_PURPOSE_BUSINESS;
  fixture->request.dial.endpoint.kind = FTUN_ADDRESS_IPV4;
  fixture->request.dial.endpoint.address[0] = 127u;
  fixture->request.dial.endpoint.address[3] = 1u;
  fixture->request.dial.allowed = &fixture->request.dial.endpoint;
  fixture->request.dial.allowed_count = 1u;
  fixture->request.dial.deadline_ms = UINT64_MAX;
  fixture->request.completion = opened;
  fixture->request.user = fixture;
  fixture->request.notify = notified;
  fixture->request.notify_user = fixture;
  fixture->request.stream.max_pending_writes = 1u;
  fixture->request.stream.max_pending_bytes = 262144u;
  fixture->request.stream.completion = wrote;
  fixture->request.stream.completion_user = fixture;
  fixture->request.datagram.max_pending_packets = 1u;
  fixture->request.datagram.max_pending_bytes = 65536u;
  fixture->request.datagram.result = sent;
  fixture->request.datagram.receive = received;
  fixture->request.datagram.user = fixture;
  return 0;
}

static int setup(fixture_t *fixture, bool libev)
{
  return setup_with_pool(fixture, libev, false);
}

static int pump(fixture_t *fixture)
{
  size_t count;
  CHECK(ftun_event_loop_run_once(fixture->loop, false, 16u, &count) == FTUN_OK);
  CHECK(ftun_operation_dispatch(fixture->operations, 16u, &count) == FTUN_OK);
  return 0;
}

static int wait_counter(fixture_t *fixture, const unsigned int *counter, unsigned int target)
{
  uint64_t start, now;
  CHECK(ftun_monotonic_now(&start) == FTUN_OK);
  while (*counter < target) {
    CHECK(pump(fixture) == 0);
    CHECK(ftun_monotonic_now(&now) == FTUN_OK && now - start < 3000u);
  }
  return 0;
}

static int server(fixture_t *fixture, bool tcp, int *out)
{
  struct sockaddr_in address = {0};
  socklen_t size = sizeof(address);
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  *out = socket(AF_INET, (tcp ? SOCK_STREAM : SOCK_DGRAM) | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  CHECK(*out >= 0 && bind(*out, (struct sockaddr *)&address, sizeof(address)) == 0);
  CHECK(getsockname(*out, (struct sockaddr *)&address, &size) == 0);
  fixture->request.dial.endpoint.port = ntohs(address.sin_port);
  fixture->request.dial.transport = tcp ? FTUN_DIAL_TCP : FTUN_DIAL_UDP;
  if (tcp) CHECK(listen(*out, 8) == 0);
  return 0;
}

static int open_path(fixture_t *fixture, ftun_operation_t **operation)
{
  CHECK(ftun_path_provider_open_channel(fixture->provider, fixture->core, 7u,
        &fixture->request, operation) == FTUN_OK && *operation != NULL);
  CHECK(wait_counter(fixture, &fixture->opens, 1u) == 0 && fixture->open_status == FTUN_OK);
  return 0;
}

static int payload(fixture_t *fixture, size_t length, ftun_buffer_slice_t *slice)
{
  ftun_buffer_t *buffer = NULL;
  uint8_t *data;
  size_t capacity, index;
  CHECK(ftun_buffer_acquire(fixture->budget, length == 0u ? 1u : length, &buffer) == FTUN_OK);
  CHECK(ftun_buffer_data(buffer, &data, &capacity) == FTUN_OK && capacity >= length);
  for (index = 0u; index < length; index++) data[index] = (uint8_t)(index * 37u);
  if (length == 8u) memcpy(data, "ab\0defgh", 8u);
  CHECK(ftun_buffer_slice(buffer, 0u, length, slice) == FTUN_OK);
  CHECK(ftun_buffer_release(&buffer) == FTUN_OK);
  return 0;
}

static int cleanup(fixture_t *fixture)
{
  ftun_budget_usage_t usage;
  ftun_event_loop_usage_t events;
  if (fixture->path != NULL) {
    CHECK(ftun_path_revoke(fixture->path) == FTUN_OK);
    CHECK(ftun_path_destroy(&fixture->path) == FTUN_OK);
  }
  CHECK(ftun_path_provider_stop_until(fixture->provider, UINT64_MAX) == FTUN_OK);
  CHECK(ftun_path_provider_destroy(&fixture->provider) == FTUN_OK);
  CHECK(ftun_buffer_pool_destroy(&fixture->pool) == FTUN_OK);
  CHECK(ftun_event_loop_get_usage(fixture->loop, &events) == FTUN_OK && events.source_count == 0u);
  CHECK(ftun_event_loop_stop(fixture->loop) == FTUN_OK);
  if (fixture->libev) CHECK(ftun_event_backend_detach(fixture->loop) == FTUN_OK);
  else CHECK(ftun_event_loop_detach_backend(fixture->loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&fixture->loop) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&fixture->operations) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&fixture->core) == FTUN_OK);
  CHECK(ftun_budget_get_usage(fixture->budget, &usage) == FTUN_OK &&
        usage.used == 0u && usage.used_resources.descriptors == 0u);
  CHECK(ftun_budget_destroy(&fixture->budget) == FTUN_OK && fixture->failures == 0u);
  return 0;
}

static int test_tcp(void)
{
  fixture_t fixture;
  ftun_stream_t *stream;
  ftun_operation_t *operation;
  ftun_buffer_slice_t slice = {0};
  uint8_t data[131072];
  size_t accepted, total = 0u, length, index;
  uint64_t start, now;
  int listener, peer;
  CHECK(setup(&fixture, true) == 0 && server(&fixture, true, &listener) == 0);
  CHECK(open_path(&fixture, &operation) == 0);
  peer = accept(listener, NULL, NULL);
  CHECK(peer >= 0 && close(listener) == 0);
  CHECK(ftun_path_stream(fixture.path, &stream) == FTUN_OK);
  CHECK(payload(&fixture, sizeof(data), &slice) == 0);
  CHECK(ftun_stream_write_ref(stream, &slice, &accepted, &operation) == FTUN_OK && accepted == sizeof(data));
  {
    struct pollfd writable = {peer, POLLIN, 0};
    /* 网络进展不等待额外 owner 回合，完成回调仍不得内联。 */
    CHECK(poll(&writable, 1u, 1000) == 1 && (writable.revents & POLLIN) != 0);
    CHECK(fixture.writes == 0u);
  }
  CHECK(ftun_stream_write_ref(stream, &slice, &accepted, &operation) == FTUN_E_LIMIT && accepted == 0u);
  CHECK(ftun_stream_shutdown_write(stream) == FTUN_E_AGAIN);
  CHECK(ftun_buffer_slice_release(&slice) == FTUN_OK);
  CHECK(ftun_monotonic_now(&start) == FTUN_OK);
  while (total != sizeof(data) || fixture.writes == 0u) {
    ssize_t count;
    CHECK(pump(&fixture) == 0);
    count = recv(peer, data + total, sizeof(data) - total, MSG_DONTWAIT);
    if (count > 0) total += (size_t)count;
    else CHECK(count == 0 || errno == EAGAIN || errno == EWOULDBLOCK);
    CHECK(ftun_monotonic_now(&now) == FTUN_OK && now - start < 3000u);
  }
  CHECK(fixture.write_status == FTUN_OK);
  for (index = 0u; index < sizeof(data); index++) CHECK(data[index] == (uint8_t)(index * 37u));
  CHECK(send(peer, "ab\0defgh", 8u, MSG_NOSIGNAL) == 8);
  CHECK(wait_counter(&fixture, &fixture.readable, 1u) == 0);
  CHECK(ftun_stream_read(stream, data, sizeof(data), &length) == FTUN_OK &&
        length == 8u && memcmp(data, "ab\0defgh", 8u) == 0);
  CHECK(shutdown(peer, SHUT_WR) == 0);
  CHECK(wait_counter(&fixture, &fixture.readable, 2u) == 0);
  CHECK(ftun_stream_read(stream, data, sizeof(data), &length) == FTUN_E_EOF && length == 0u);
  CHECK(payload(&fixture, 8u, &slice) == 0);
  CHECK(ftun_stream_write_ref(stream, &slice, &accepted, &operation) == FTUN_OK);
  CHECK(ftun_buffer_slice_release(&slice) == FTUN_OK);
  CHECK(wait_counter(&fixture, &fixture.writes, 2u) == 0 && fixture.write_status == FTUN_OK);
  CHECK(recv(peer, data, sizeof(data), MSG_DONTWAIT) == 8 && memcmp(data, "ab\0defgh", 8u) == 0);
  CHECK(ftun_stream_shutdown_write(stream) == FTUN_OK);
  CHECK(close(peer) == 0 && cleanup(&fixture) == 0);
  return 0;
}

static int test_stream_error_completion(void)
{
  fixture_t fixture;
  ftun_stream_t *stream;
  ftun_operation_t *operation;
  ftun_buffer_slice_t slice = {0};
  const int errors[] = {ENOBUFS, EPIPE};
  const ftun_status_t statuses[] = {FTUN_E_LIMIT, FTUN_E_IO};
  int listener, peer;
  size_t accepted, index;
  char byte;
  CHECK(setup(&fixture, true) == 0 && server(&fixture, true, &listener) == 0);
  CHECK(open_path(&fixture, &operation) == 0);
  peer = accept(listener, NULL, NULL);
  CHECK(peer >= 0 && close(listener) == 0);
  CHECK(ftun_path_stream(fixture.path, &stream) == FTUN_OK);
  CHECK(payload(&fixture, 8u, &slice) == 0);
  for (index = 0u; index < 2u; index++) {
    send_error = errors[index];
    CHECK(ftun_stream_write_ref(stream, &slice, &accepted, &operation) == FTUN_OK);
    CHECK(accepted == 8u && fixture.writes == index && send_error == 0);
    CHECK(wait_counter(&fixture, &fixture.writes, (unsigned int)index + 1u) == 0);
    CHECK(fixture.write_status == statuses[index]);
  }
  CHECK(recv(peer, &byte, 1u, MSG_DONTWAIT) == -1 &&
        (errno == EAGAIN || errno == EWOULDBLOCK));
  CHECK(ftun_buffer_slice_release(&slice) == FTUN_OK);
  CHECK(close(peer) == 0 && cleanup(&fixture) == 0);
  return 0;
}

static int test_udp(bool pooled)
{
  fixture_t fixture;
  ftun_datagram_t *datagram;
  ftun_operation_t *operation;
  ftun_buffer_slice_t slice = {0};
  ftun_packet_t packet = {0};
  ftun_endpoint_t wrong;
  struct sockaddr_in client;
  socklen_t size = sizeof(client);
  uint8_t bytes[16];
  ftun_budget_usage_t usage;
  ftun_reservation_t pressure = (ftun_reservation_t){0};
  ftun_bytes_t held;
  int listener;
  unsigned int index, received_before;
  CHECK(setup_with_pool(&fixture, true, pooled) == 0 && server(&fixture, false, &listener) == 0);
  CHECK(open_path(&fixture, &operation) == 0);
  CHECK(ftun_path_datagram(fixture.path, &datagram) == FTUN_OK);
  CHECK(payload(&fixture, 8u, &slice) == 0 && ftun_packet_init(&packet, &slice, 0u) == FTUN_OK);
  CHECK(ftun_buffer_slice_release(&slice) == FTUN_OK);
  wrong = fixture.request.dial.endpoint; wrong.port++;
  CHECK(ftun_datagram_send(datagram, &wrong, &packet) == FTUN_E_REJECTED);
  send_again = 1u;
  CHECK(ftun_datagram_send(datagram, &fixture.request.dial.endpoint, &packet) == FTUN_OK);
  CHECK(ftun_datagram_send(datagram, &fixture.request.dial.endpoint, &packet) == FTUN_E_LIMIT);
  CHECK(wait_counter(&fixture, &fixture.writes, 1u) == 0 && fixture.write_status == FTUN_OK);
  CHECK(recvfrom(listener, bytes, sizeof(bytes), MSG_DONTWAIT,
        (struct sockaddr *)&client, &size) == 8 && memcmp(bytes, "ab\0defgh", 8u) == 0);
  CHECK(ftun_packet_release(&packet) == FTUN_OK);
  fixture.receive_status = FTUN_E_AGAIN;
  CHECK(sendto(listener, bytes, 8u, 0, (struct sockaddr *)&client, size) == 8);
  CHECK(wait_counter(&fixture, &fixture.attempts, 1u) == 0 && fixture.received == 0u);
  for (index = 0u; index < 8u; index++) CHECK(pump(&fixture) == 0);
  CHECK(fixture.attempts == 1u);
  fixture.receive_status = FTUN_OK;
  fixture.hold_packet = true;
  CHECK(ftun_path_resume(fixture.path) == FTUN_OK);
  CHECK(wait_counter(&fixture, &fixture.received, 1u) == 0 && fixture.attempts == 2u);
  fixture.hold_packet = false;
  CHECK(ftun_packet_view(&fixture.held, &held) == FTUN_OK && held.length == 8u);
  CHECK(payload(&fixture, 0u, &slice) == 0 && ftun_packet_init(&packet, &slice, 0u) == FTUN_OK);
  CHECK(ftun_buffer_slice_release(&slice) == FTUN_OK);
  CHECK(ftun_datagram_send(datagram, &fixture.request.dial.endpoint, &packet) == FTUN_OK);
  CHECK(wait_counter(&fixture, &fixture.writes, 2u) == 0 && fixture.write_status == FTUN_OK);
  CHECK(recvfrom(listener, bytes, sizeof(bytes), MSG_DONTWAIT, NULL, NULL) == 0);
  CHECK(ftun_packet_release(&packet) == FTUN_OK);
  CHECK(sendto(listener, NULL, 0u, 0, (struct sockaddr *)&client, size) == 0);
  CHECK(wait_counter(&fixture, &fixture.received, 2u) == 0);
  if (pooled) {
    ftun_buffer_pool_usage_t before, after;
    CHECK(ftun_buffer_pool_get_usage(fixture.pool, &before) == FTUN_OK);
    for (index = 0u; index < 32u; index++) {
      CHECK(sendto(listener, "ab\0defgh", 8u, 0, (struct sockaddr *)&client, size) == 8);
      CHECK(wait_counter(&fixture, &fixture.received, 3u + index) == 0);
    }
    CHECK(ftun_buffer_pool_get_usage(fixture.pool, &after) == FTUN_OK);
    CHECK(after.cache_misses == before.cache_misses &&
          after.cache_hits >= before.cache_hits + 32u && after.active_buffers == 1u);
    CHECK(ftun_packet_view(&fixture.held, &held) == FTUN_OK &&
          held.length == 8u && memcmp(held.data, "ab\0defgh", 8u) == 0);
    /* 闲置缓存可复用已有额度；先回收它再构造真实内存不足。 */
    CHECK(ftun_buffer_pool_trim(fixture.pool, 0u) == FTUN_OK);
  }
  received_before = fixture.received;
  CHECK(ftun_budget_get_usage(fixture.budget, &usage) == FTUN_OK);
  CHECK(ftun_budget_reserve(fixture.budget, usage.normal_available - 1024u, &pressure) == FTUN_OK);
  CHECK(sendto(listener, "ab\0defgh", 8u, 0, (struct sockaddr *)&client, size) == 8);
  CHECK(wait_counter(&fixture, &fixture.errors, 2u) == 0 && fixture.received == received_before);
  CHECK(ftun_reservation_release(&pressure) == FTUN_OK);
  CHECK(ftun_path_resume(fixture.path) == FTUN_OK);
  CHECK(wait_counter(&fixture, &fixture.received, received_before + 1u) == 0);
  CHECK(payload(&fixture, 0u, &slice) == 0 && ftun_packet_init(&packet, &slice, 0u) == FTUN_OK);
  CHECK(ftun_buffer_slice_release(&slice) == FTUN_OK);
  fixture.revoke_on_notify = true;
  send_again = 1u;
  CHECK(ftun_datagram_send(datagram, &fixture.request.dial.endpoint, &packet) == FTUN_OK);
  CHECK(wait_counter(&fixture, &fixture.writes, 3u) == 0 && fixture.write_status == FTUN_OK);
  CHECK(ftun_packet_release(&packet) == FTUN_OK);
  CHECK(ftun_path_revoke(fixture.path) == FTUN_OK && ftun_path_destroy(&fixture.path) == FTUN_OK);
  CHECK(ftun_packet_view(&fixture.held, &held) == FTUN_OK && memcmp(held.data, "ab\0defgh", 8u) == 0);
  CHECK(ftun_packet_release(&fixture.held) == FTUN_OK);
  CHECK(close(listener) == 0 && cleanup(&fixture) == 0);
  return 0;
}

typedef struct {
  ftun_event_source_t *source;
  unsigned int cancel_failures, write_updates, update_failures;
  bool start_fail;
} faults_t;
static ftun_status_t io_start(void *user, ftun_event_source_t *source,
  ftun_native_socket_t socket, uint32_t interests)
{
  faults_t *faults = (faults_t *)user;
  (void)socket; (void)interests;
  if (faults->start_fail) return FTUN_E_IO;
  faults->source = source;
  return FTUN_OK;
}
static ftun_status_t io_update(void *user, ftun_event_source_t *source, uint32_t interests)
{
  faults_t *faults = user;
  (void)source;
  if ((interests & FTUN_EVENT_WRITE) != 0u) faults->write_updates++;
  if (faults->update_failures != 0u) {
    faults->update_failures--;
    return FTUN_E_IO;
  }
  return FTUN_OK;
}
static ftun_status_t timer_start(void *user, ftun_event_source_t *source, uint64_t deadline)
{ (void)user; (void)source; (void)deadline; return FTUN_OK; }
static ftun_status_t source_cancel(void *user, ftun_event_source_t *source)
{
  faults_t *faults = (faults_t *)user;
  (void)source;
  if (faults->cancel_failures != 0u) { faults->cancel_failures--; return FTUN_E_IO; }
  faults->source = NULL;
  return FTUN_OK;
}
static void noop(void *user) { (void)user; }
static ftun_status_t run_once(void *user, bool block)
{ (void)user; (void)block; return FTUN_OK; }
static const ftun_event_backend_ops_t fault_ops = {
  .io_start = io_start, .io_update = io_update, .timer_start = timer_start,
  .source_cancel = source_cancel, .wakeup = noop, .run_once = run_once,
  .stop = noop, .destroy = noop
};

static int test_send_without_write_subscription(void)
{
  fixture_t fixture;
  faults_t faults = {0};
  ftun_operation_t *operation;
  ftun_buffer_slice_t slice = {0};
  ftun_packet_t packet = {0};
  ftun_datagram_t *datagram;
  unsigned int round;
  int listener;
  CHECK(setup(&fixture, false) == 0 && server(&fixture, false, &listener) == 0);
  CHECK(ftun_event_loop_attach_backend(fixture.loop, &fault_ops, &faults) == FTUN_OK);
  CHECK(open_path(&fixture, &operation) == 0);
  CHECK(ftun_path_datagram(fixture.path, &datagram) == FTUN_OK);
  CHECK(payload(&fixture, 8u, &slice) == 0);
  CHECK(ftun_packet_init(&packet, &slice, 0u) == FTUN_OK);
  CHECK(ftun_buffer_slice_release(&slice) == FTUN_OK);
  for (round = 0u; round < 16u; round++) {
    uint8_t bytes[8];
    CHECK(ftun_datagram_send(datagram, &fixture.request.dial.endpoint, &packet) == FTUN_OK);
    CHECK(fixture.writes == round + 1u);
    CHECK(faults.write_updates == 0u);
    CHECK(wait_counter(&fixture, &fixture.writes, round + 1u) == 0);
    CHECK(fixture.write_status == FTUN_OK && faults.write_updates == 0u);
    CHECK(recv(listener, bytes, sizeof(bytes), MSG_DONTWAIT) == 8 &&
          memcmp(bytes, "ab\0defgh", 8u) == 0);
  }
  /* 真正的背压才开启 WRITE；内核提示后只完成一次。 */
  send_again = 2u;
  CHECK(ftun_datagram_send(datagram, &fixture.request.dial.endpoint, &packet) == FTUN_OK);
  CHECK(pump(&fixture) == 0 && fixture.writes == 16u && faults.write_updates == 1u);
  CHECK(ftun_event_io_ready(faults.source, FTUN_EVENT_WRITE) == FTUN_OK);
  CHECK(wait_counter(&fixture, &fixture.writes, 17u) == 0 && fixture.write_status == FTUN_OK);
  {
    uint8_t bytes[8];
    CHECK(recv(listener, bytes, sizeof(bytes), MSG_DONTWAIT) == 8);
  }
  /* 已接纳后的订阅失败由完成回调交付，不能伪装成零接纳。 */
  send_again = 2u;
  faults.update_failures = 1u;
  CHECK(ftun_datagram_send(datagram, &fixture.request.dial.endpoint, &packet) == FTUN_OK);
  CHECK(wait_counter(&fixture, &fixture.writes, 18u) == 0 && fixture.write_status == FTUN_E_IO);
  CHECK(send_again == 0u);
  CHECK(ftun_packet_release(&packet) == FTUN_OK);
  CHECK(close(listener) == 0 && cleanup(&fixture) == 0);
  return 0;
}

static int test_pool_root(void)
{
  fixture_t fixture;
  ftun_budget_t *foreign = NULL;
  ftun_buffer_pool_t *pool = NULL;
  ftun_path_provider_spec_t provider = {0};
  ftun_path_provider_t *rejected = NULL;
  ftun_path_spec_t spec = {0};
  ftun_operation_t *operation = NULL;
  CHECK(setup(&fixture, true) == 0);
  CHECK(ftun_budget_create(NULL, 131072u, 0u, &foreign) == FTUN_OK);
  CHECK(ftun_buffer_pool_create(foreign, 65536u, 1u, &pool) == FTUN_OK);
  provider.budget = fixture.budget;
  provider.generation = 7u;
  provider.ops.open = ftun_socket_path_open;
  provider.receive_pool = pool;
  CHECK(ftun_path_provider_create(&provider, &rejected) == FTUN_E_REJECTED && rejected == NULL);
  spec.receive_pool = pool;
  fixture.request.dial.transport = FTUN_DIAL_UDP;
  CHECK(ftun_socket_path_open(NULL, fixture.core, &fixture.request, &spec,
    &operation) == FTUN_E_REJECTED && operation == NULL);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_OK);
  CHECK(ftun_budget_destroy(&foreign) == FTUN_OK);
  CHECK(cleanup(&fixture) == 0);
  return 0;
}

static int test_faults(void)
{
  fixture_t fixture;
  faults_t faults = {0};
  ftun_operation_t *operation;
  ftun_path_provider_info_t info;
  ftun_event_loop_usage_t events;
  ftun_budget_usage_t before, after;
  ftun_buffer_slice_t slice = {0};
  ftun_packet_t packet = {0};
  ftun_datagram_t *datagram;
  int listener;
  CHECK(setup(&fixture, false) == 0 && server(&fixture, false, &listener) == 0);
  CHECK(ftun_event_loop_attach_backend(fixture.loop, &fault_ops, &faults) == FTUN_OK);
  CHECK(open_path(&fixture, &operation) == 0 && faults.source != NULL);
  CHECK(ftun_budget_get_usage(fixture.budget, &after) == FTUN_OK &&
        after.used_resources.descriptors == 1u);
  CHECK(ftun_path_datagram(fixture.path, &datagram) == FTUN_OK);
  CHECK(payload(&fixture, 8u, &slice) == 0 && ftun_packet_init(&packet, &slice, 0u) == FTUN_OK);
  CHECK(ftun_buffer_slice_release(&slice) == FTUN_OK);
  send_again = 1u;
  CHECK(ftun_datagram_send(datagram, &fixture.request.dial.endpoint, &packet) == FTUN_OK);
  CHECK(ftun_packet_release(&packet) == FTUN_OK);
  faults.cancel_failures = 2u;
  CHECK(ftun_path_revoke(fixture.path) == FTUN_E_IO);
  CHECK(fixture.writes == 1u && fixture.write_status == FTUN_E_CANCELLED);
  CHECK(ftun_path_destroy(&fixture.path) == FTUN_E_IO && fixture.path != NULL);
  CHECK(ftun_event_loop_get_usage(fixture.loop, &events) == FTUN_OK && events.source_count == 1u);
  CHECK(ftun_path_destroy(&fixture.path) == FTUN_OK && faults.source == NULL);
  CHECK(ftun_budget_get_usage(fixture.budget, &before) == FTUN_OK);
  faults.start_fail = true;
  fixture.opens = 0u;
  CHECK(ftun_path_provider_open_channel(fixture.provider, fixture.core, 7u,
        &fixture.request, &operation) == FTUN_OK);
  CHECK(wait_counter(&fixture, &fixture.opens, 1u) == 0 && fixture.open_status == FTUN_E_IO);
  CHECK(ftun_path_provider_get_info(fixture.provider, &info) == FTUN_OK &&
        info.pending == 0u && info.paths == 0u);
  CHECK(ftun_budget_get_usage(fixture.budget, &after) == FTUN_OK && before.used == after.used);
  faults.start_fail = false;
  fixture.opens = 0u;
  CHECK(ftun_path_provider_open_channel(fixture.provider, fixture.core, 7u,
        &fixture.request, &operation) == FTUN_OK);
  CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  CHECK(wait_counter(&fixture, &fixture.opens, 1u) == 0 && fixture.open_status == FTUN_E_CANCELLED);
  CHECK(ftun_budget_get_usage(fixture.budget, &after) == FTUN_OK && before.used == after.used);
  CHECK(close(listener) == 0 && cleanup(&fixture) == 0);
  return 0;
}

int main(void)
{
  int baseline = descriptor_count();
  CHECK(baseline >= 0);
  CHECK(test_tcp() == 0 && descriptor_count() == baseline);
  CHECK(test_stream_error_completion() == 0 && descriptor_count() == baseline);
  CHECK(test_udp(false) == 0 && descriptor_count() == baseline);
  CHECK(test_udp(true) == 0 && descriptor_count() == baseline);
  CHECK(test_pool_root() == 0 && descriptor_count() == baseline);
  CHECK(test_send_without_write_subscription() == 0 && descriptor_count() == baseline);
  CHECK(test_faults() == 0 && descriptor_count() == baseline);
  puts("Socket Path contract passed: TCP, UDP and lifecycle faults");
  return 0;
}
