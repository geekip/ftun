/* 在真实协议、事件源和 Operation 上注入单个系统调用的失败。 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "app/config/parser.h"
#include "app/config/model.h"
#include "dns/service.c"
#include "libs/transport/socket_path.h"
#include "app/config/validate.h"
#include "core/context.h"
#include "core/event/backend.h"

#include <dirent.h>
#include <netinet/tcp.h>

#define CHECK(expression) do { \
  if (!(expression)) { \
    fprintf(stderr, "DNS failure contract failed: %s:%d: %s\n", \
            __FILE__, __LINE__, #expression); \
    return 1; \
  } \
} while (0)

enum { SEND_REAL, SEND_PIPE, SEND_RESET, SEND_ZERO, SEND_SHORT, SEND_AGAIN };
static int watched_fd = -1;
static int send_fault;
static int recv_fault;
static size_t send_calls;
static size_t close_calls;
static ftun_event_source_t *cancel_source;
static unsigned int cancel_failures;
static int start_fail_fd = -1;
static size_t fail_calloc_size;
static unsigned int calloc_failures;
static bool block_socket;
static size_t blocked_sockets;
static bool fail_cache;
static size_t cache_calls;

ssize_t __real_send(int fd, const void *buffer, size_t length, int flags);
ssize_t __real_recv(int fd, void *buffer, size_t length, int flags);
int __real_close(int fd);
int __real_socket(int domain, int type, int protocol);
void *__real_calloc(size_t count, size_t size);
ftun_status_t __real_ftun_event_source_cancel(ftun_event_source_t **source);
ftun_status_t __real_ftun_event_io_start(ftun_event_loop_t *loop,
  ftun_native_socket_t socket_value, uint32_t interests,
  ftun_event_callback_fn callback, void *user, ftun_event_source_t **out);
ftun_status_t __real_ftun_dns_cache_create(
  const ftun_dns_cache_options_t *options, ftun_dns_cache_t **out);

ssize_t __wrap_send(int fd, const void *buffer, size_t length, int flags)
{
  if (fd == watched_fd) {
    int fault = send_fault;
    send_fault = SEND_REAL;
    send_calls++;
    if (fault == SEND_ZERO) return 0;
    if (fault == SEND_PIPE || fault == SEND_RESET || fault == SEND_AGAIN) {
      errno = fault == SEND_PIPE ? EPIPE :
        (fault == SEND_RESET ? ECONNRESET : EAGAIN);
      return -1;
    }
    if (fault == SEND_SHORT && length > 2u) length = 2u;
  }
  return __real_send(fd, buffer, length, flags);
}

ssize_t __wrap_recv(int fd, void *buffer, size_t length, int flags)
{
  if (fd == watched_fd && recv_fault != 0) {
    errno = recv_fault;
    recv_fault = 0;
    return -1;
  }
  return __real_recv(fd, buffer, length, flags);
}

int __wrap_close(int fd)
{
  if (fd == watched_fd) close_calls++;
  return __real_close(fd);
}

int __wrap_socket(int domain, int type, int protocol)
{
  if (block_socket) {
    blocked_sockets++;
    errno = EACCES;
    return -1;
  }
  return __real_socket(domain, type, protocol);
}

void *__wrap_calloc(size_t count, size_t size)
{
  if (calloc_failures != 0u && count == 1u && size == fail_calloc_size) {
    calloc_failures--;
    return NULL;
  }
  return __real_calloc(count, size);
}

ftun_status_t __wrap_ftun_event_source_cancel(ftun_event_source_t **source)
{
  if (source != NULL && *source != NULL && *source == cancel_source &&
      cancel_failures != 0u) {
    cancel_failures--;
    return FTUN_E_AGAIN;
  }
  return __real_ftun_event_source_cancel(source);
}

ftun_status_t __wrap_ftun_event_io_start(ftun_event_loop_t *loop,
  ftun_native_socket_t socket_value, uint32_t interests,
  ftun_event_callback_fn callback, void *user, ftun_event_source_t **out)
{
  if (start_fail_fd >= 0 && socket_value ==
      (ftun_native_socket_t)(unsigned int)start_fail_fd) {
    *out = NULL;
    return FTUN_E_LIMIT;
  }
  return __real_ftun_event_io_start(loop, socket_value, interests, callback,
                                   user, out);
}

ftun_status_t __wrap_ftun_dns_cache_create(
  const ftun_dns_cache_options_t *options, ftun_dns_cache_t **out)
{
  cache_calls++;
  if (fail_cache) {
    *out = NULL;
    return FTUN_E_LIMIT;
  }
  return __real_ftun_dns_cache_create(options, out);
}

typedef struct {
  ftun_dns_query_completion_fn completion;
  void *user;
  ftun_operation_token_t token;
  uint8_t response[27];
  bool completed;
} pending_t;

typedef struct {
  ftun_budget_t *budget;
  ftun_operation_queue_t *operations;
  ftun_core_t *core;
  ftun_event_loop_t *loop;
  ftun_config_t *config;
  ftun_dns_runtime_t *dns;
  ftun_dns_runtime_adapter_t adapter;
  ftun_budget_usage_t baseline;
  pending_t requests[8];
  size_t request_count;
  size_t completions;
  size_t initial_fds;
} fixture_t;

static size_t fd_count(void)
{
  DIR *directory = opendir("/proc/self/fd");
  struct dirent *entry;
  size_t count = 0u;
  if (directory == NULL) return SIZE_MAX;
  while ((entry = readdir(directory)) != NULL) {
    if (entry->d_name[0] != '.') count++;
  }
  (void)closedir(directory);
  return count;
}

static void query_wire(uint8_t wire[29])
{
  static const uint8_t name[] = {1u, 'a', 7u, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0u};
  memset(wire, 0, 29u);
  wire[1] = 27u;
  wire[2] = 0x22u;
  wire[3] = 0x33u;
  wire[4] = 1u;
  wire[7] = 1u;
  memcpy(wire + 14u, name, sizeof(name));
  wire[26] = 1u;
  wire[28] = 1u;
}

static void request_completed(ftun_operation_t *operation,
                              ftun_error_t error, void *user)
{
  pending_t *request = (pending_t *)user;
  ftun_bytes_t response = {request->response, sizeof(request->response)};
  request->completed = true;
  request->completion(operation, error, response, request->user);
}

static ftun_status_t dispatch_query(void *user, ftun_core_t *core,
  ftun_dns_dispatcher_t *dispatcher, const ftun_dns_query_t *query,
  ftun_operation_t **out)
{
  fixture_t *fixture = (fixture_t *)user;
  pending_t *request;
  ftun_status_t status;
  (void)core;
  (void)dispatcher;
  if (fixture->request_count == 8u || query->wire.length != 27u) {
    return FTUN_E_LIMIT;
  }
  request = &fixture->requests[fixture->request_count];
  request->completion = query->completion;
  request->user = query->completion_user;
  memcpy(request->response, query->wire.data, sizeof(request->response));
  request->response[2] = 0x81u;
  request->response[3] = 0x80u;
  status = ftun_operation_accept(fixture->operations, request_completed,
    request, out, &request->token);
  if (status == FTUN_OK) fixture->request_count++;
  return status;
}

static int finish_request(fixture_t *fixture, size_t index)
{
  size_t dispatched = 0u;
  ftun_error_t error;
  memset(&error, 0, sizeof(error));
  CHECK(index < fixture->request_count);
  CHECK(!fixture->requests[index].completed);
  CHECK(ftun_operation_complete(fixture->requests[index].token, error) == FTUN_OK);
  CHECK(ftun_operation_dispatch(fixture->operations, 8u, &dispatched) == FTUN_OK);
  CHECK(dispatched == 1u && fixture->requests[index].completed);
  fixture->completions++;
  return 0;
}

static uint16_t reserve_port(void)
{
  struct sockaddr_in address;
  socklen_t length = (socklen_t)sizeof(address);
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return 0u;
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(fd, (const struct sockaddr *)&address, length) != 0 ||
      getsockname(fd, (struct sockaddr *)&address, &length) != 0) {
    (void)close(fd);
    return 0u;
  }
  (void)close(fd);
  return ntohs(address.sin_port);
}

static const char *config_listen_host = "127.0.0.1";

static ftun_config_t *make_config(bool cache, bool proxy, bool domain,
                                  uint16_t port)
{
  char json[2048];
  char listener[160] = "";
  char outbounds[256] = "";
  ftun_config_t *config = NULL;
  int length;
  if (port != 0u) {
    (void)snprintf(listener, sizeof(listener),
      ",\"listeners\":[{\"listen\":\"%s:%u\",\"server\":\"real\"}]",
      config_listen_host, (unsigned int)port);
  }
  if (proxy) {
    (void)snprintf(outbounds, sizeof(outbounds),
      ",\"outbounds\":[{\"name\":\"proxy\",\"type\":\"socks5\","
      "\"server\":\"%s:1080\"}]", domain ? "proxy.invalid" : "127.0.0.1");
  }
  length = snprintf(json, sizeof(json),
    "{\"dns\":{\"enable\":true,\"cache\":%s,"
    "\"bootstrap\":[\"127.0.0.1:9\"],\"default-server\":\"real\","
    "\"servers\":[{\"name\":\"real\",\"type\":\"udp\","
    "\"address\":[\"127.0.0.1:9\"],\"outbound\":\"%s\"}]%s}%s}",
    cache ? "true" : "false", proxy ? "proxy" : "DIRECT", listener, outbounds);
  if (length <= 0 || (size_t)length >= sizeof(json) ||
      ftun_config_parse((ftun_bytes_t){(const uint8_t *)json, (size_t)length},
                         &config) != FTUN_OK) return NULL;
  if (ftun_config_validate(config, NULL) != FTUN_OK) {
    (void)ftun_config_destroy(&config);
  }
  return config;
}

static int fixture_init(fixture_t *fixture)
{
  memset(fixture, 0, sizeof(*fixture));
  fixture->initial_fds = fd_count();
  CHECK(fixture->initial_fds != SIZE_MAX);
  CHECK(ftun_budget_create(NULL, 16u * 1024u * 1024u, 1024u,
                            &fixture->budget) == FTUN_OK);
  CHECK(ftun_operation_queue_create(fixture->budget, 64u,
                                     &fixture->operations) == FTUN_OK);
  CHECK(ftun_core_context_create(fixture->budget, &fixture->core) == FTUN_OK);
  CHECK(ftun_event_loop_create_with_capacity(fixture->core, 128u,
                                             &fixture->loop) == FTUN_OK);
  CHECK(ftun_event_backend_attach(fixture->loop) == FTUN_OK);
  fixture->adapter.dispatch = dispatch_query;
  fixture->adapter.user = fixture;
  CHECK(ftun_budget_get_usage(fixture->budget, &fixture->baseline) == FTUN_OK);
  return 0;
}

static int fixture_start(fixture_t *fixture)
{
  uint16_t port = reserve_port();
  CHECK(fixture_init(fixture) == 0);
  CHECK(port != 0u);
  fixture->config = make_config(false, false, false, port);
  CHECK(fixture->config != NULL);
  CHECK(ftun_dns_runtime_prepare(fixture->core, fixture->budget,
    fixture->operations, fixture->loop, fixture->config, &fixture->adapter,
    &(ftun_dns_runtime_network_t){.generation = 1u, .socket_mark = 0u,
      .path = {.open = ftun_socket_path_open}}, &fixture->dns) == FTUN_OK);
  CHECK(ftun_dns_runtime_activate(fixture->dns) == FTUN_OK);
  return 0;
}

static int fixture_destroy(fixture_t *fixture)
{
  ftun_budget_usage_t usage;
  ftun_event_loop_usage_t events;
  ftun_operation_queue_usage_t operations;
  CHECK(ftun_dns_runtime_destroy(&fixture->dns) == FTUN_OK);
  CHECK(ftun_config_destroy(&fixture->config) == FTUN_OK);
  CHECK(ftun_budget_get_usage(fixture->budget, &usage) == FTUN_OK);
  CHECK(usage.used == fixture->baseline.used);
  CHECK(usage.metadata_bytes == fixture->baseline.metadata_bytes);
  CHECK(usage.used_resources.descriptors == fixture->baseline.used_resources.descriptors);
  CHECK(usage.used_resources.queue_slots == fixture->baseline.used_resources.queue_slots);
  CHECK(ftun_event_loop_get_usage(fixture->loop, &events) == FTUN_OK);
  CHECK(events.source_count == 0u && events.ready_count == 0u);
  CHECK(ftun_operation_queue_get_usage(fixture->operations, &operations) == FTUN_OK);
  CHECK(operations.inflight == 0u && operations.ready == 0u);
  CHECK(ftun_event_loop_stop(fixture->loop) == FTUN_OK);
  CHECK(ftun_event_backend_detach(fixture->loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&fixture->loop) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&fixture->core) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(fixture->operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&fixture->operations) == FTUN_OK);
  CHECK(ftun_budget_destroy(&fixture->budget) == FTUN_OK);
  CHECK(fd_count() == fixture->initial_fds);
  return 0;
}

static int connection_open(fixture_t *fixture, bool hijack, int *out_client,
                           ftun_dns_runtime_tcp_t **out_connection)
{
  ftun_dns_runtime_t *dns = fixture->dns;
  size_t index;
  if (hijack) {
    int pair[2];
    CHECK(ftun_dns_runtime_protocol_create(dns, false, 0u, 0u,
                                            &dns->hijack) == FTUN_OK);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
                       0, pair) == 0);
    CHECK(ftun_dns_runtime_hijack_tcp(dns, pair[0]) == FTUN_OK);
    *out_client = pair[1];
  } else {
    struct sockaddr_in address;
    socklen_t length = (socklen_t)sizeof(address);
    size_t accepted = 0u;
    int one = 1;
    int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(client >= 0);
    CHECK(setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0);
    CHECK(getsockname(dns->listeners[0].tcp_descriptor,
      (struct sockaddr *)&address, &length) == 0);
    CHECK(connect(client, (const struct sockaddr *)&address, length) == 0);
    CHECK(fcntl(client, F_SETFL, O_NONBLOCK) == 0);
    CHECK(ftun_dns_runtime_tcp_accept(dns, &dns->listeners[0], 1u,
                                       &accepted) == FTUN_OK);
    CHECK(accepted == 1u);
    *out_client = client;
  }
  for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS; index++) {
    if (dns->tcp[index].active && dns->tcp[index].descriptor >= 0 &&
        dns->tcp[index].descriptor != watched_fd) {
      *out_connection = &dns->tcp[index];
      return 0;
    }
  }
  CHECK(false);
  return 1;
}

static int pump(fixture_t *fixture, ftun_dns_runtime_t *dns)
{
  size_t callbacks = 0u;
  size_t work = 0u;
  CHECK(ftun_event_loop_run_once(fixture->loop, false, 32u, &callbacks) == FTUN_OK);
  CHECK(ftun_dns_runtime_run_once(dns, 32u, &work) == FTUN_OK);
  return 0;
}

static int submit_query(fixture_t *fixture, int client)
{
  uint8_t wire[29];
  size_t expected = fixture->request_count + 1u;
  unsigned int round;
  query_wire(wire);
  wire[3] = (uint8_t)expected;
  CHECK(send(client, wire, sizeof(wire), MSG_NOSIGNAL) == (ssize_t)sizeof(wire));
  for (round = 0u; round < 32u && fixture->request_count != expected; round++) {
    CHECK(pump(fixture, fixture->dns) == 0);
  }
  CHECK(fixture->request_count == expected);
  return 0;
}

static bool connection_ready(const ftun_dns_runtime_tcp_t *connection)
{
  size_t index = (size_t)(connection - connection->dns->tcp);
  return (connection->dns->tcp_ready_mask & (UINT64_C(1) << index)) != 0u;
}

static int ready_mask_case(void)
{
  ftun_dns_runtime_t dns = {0};
  size_t indices[] = {0u, 31u, 63u};
  size_t index;
  CHECK(ftun_dns_runtime_tcp_next_ready(&dns) == SIZE_MAX);
  for (index = 0u; index < sizeof(indices) / sizeof(indices[0]); index++) {
    ftun_dns_runtime_tcp_t *connection = &dns.tcp[indices[index]];
    connection->dns = &dns;
    connection->active = true;
    ftun_dns_runtime_tcp_set_ready(connection, true);
    ftun_dns_runtime_tcp_set_ready(connection, true);
  }
  CHECK(ftun_dns_runtime_has_ready(&dns));
  CHECK(ftun_dns_runtime_tcp_next_ready(&dns) == 0u);
  dns.tcp_cursor = 1u;
  CHECK(ftun_dns_runtime_tcp_next_ready(&dns) == 31u);
  dns.tcp_cursor = 32u;
  CHECK(ftun_dns_runtime_tcp_next_ready(&dns) == 63u);
  ftun_dns_runtime_tcp_set_ready(&dns.tcp[63u], false);
  dns.tcp_cursor = 63u;
  CHECK(ftun_dns_runtime_tcp_next_ready(&dns) == 0u);
  ftun_dns_runtime_tcp_set_ready(&dns.tcp[0u], false);
  CHECK(ftun_dns_runtime_tcp_next_ready(&dns) == 31u);
  ftun_dns_runtime_tcp_set_ready(&dns.tcp[31u], false);
  CHECK(ftun_dns_runtime_tcp_next_ready(&dns) == SIZE_MAX && !ftun_dns_runtime_has_ready(&dns));
  return 0;
}

static ftun_status_t drive_step(ftun_dns_runtime_t *dns,
                                ftun_dns_runtime_tcp_t *connection)
{
  bool work = false;
  ftun_dns_runtime_tcp_set_ready(connection, true);
  return ftun_dns_runtime_step_tcp(dns, &work);
}

static int check_quiet(fixture_t *fixture, ftun_dns_runtime_t *dns)
{
  ftun_event_loop_usage_t before;
  ftun_event_loop_usage_t after;
  size_t sends = send_calls;
  unsigned int round;
  CHECK(!ftun_dns_runtime_has_ready(dns));
  CHECK(ftun_event_loop_get_usage(fixture->loop, &before) == FTUN_OK);
  for (round = 0u; round < 16u; round++) CHECK(pump(fixture, dns) == 0);
  CHECK(ftun_event_loop_get_usage(fixture->loop, &after) == FTUN_OK);
  CHECK(after.callbacks == before.callbacks);
  CHECK(send_calls == sends && !ftun_dns_runtime_has_ready(dns));
  return 0;
}

static int reload_start(fixture_t *fixture, ftun_dns_runtime_t **retired)
{
  ftun_dns_runtime_t *prepared = NULL;
  ftun_dns_runtime_plan_t *plan = NULL;
  CHECK(ftun_dns_runtime_plan_prepare(fixture->budget, fixture->config, 0u, &plan) == FTUN_OK);
  CHECK(ftun_dns_runtime_prepare_reload_planned(fixture->dns, fixture->core,
    fixture->budget, fixture->operations, fixture->loop, fixture->config,
    &fixture->adapter,
    &(ftun_dns_runtime_network_t){.generation = 2u, .socket_mark = 0u,
      .path = {.open = ftun_socket_path_open}}, plan, &prepared) == FTUN_OK);
  CHECK(ftun_dns_runtime_commit_reload(&fixture->dns, &prepared, retired) == FTUN_OK);
  CHECK(prepared == NULL && *retired != NULL);
  CHECK(ftun_dns_runtime_plan_destroy(&plan) == FTUN_OK);
  return 0;
}

static int fatal_case(int fault, bool cancel_retry, bool reload, bool pending)
{
  fixture_t fixture;
  ftun_dns_runtime_tcp_t *connection = NULL;
  ftun_dns_runtime_tcp_t *other = NULL;
  ftun_dns_runtime_t *retired = NULL;
  ftun_dns_runtime_t *owner;
  ftun_dns_connection_t *protocol;
  ftun_event_source_t *source;
  uint64_t peer;
  int client;
  int other_client;
  CHECK(fixture_start(&fixture) == 0);
  CHECK(connection_open(&fixture, false, &client, &connection) == 0);
  watched_fd = connection->descriptor;
  close_calls = 0u;
  send_calls = 0u;
  CHECK(submit_query(&fixture, client) == 0);
  if (pending) CHECK(submit_query(&fixture, client) == 0);
  CHECK(finish_request(&fixture, 0u) == 0);
  CHECK(connection->response_count == 1u);
  protocol = connection->protocol;
  source = connection->source;
  peer = connection->peer_id;
  if (cancel_retry) {
    cancel_source = source;
    cancel_failures = 1u;
  }
  send_fault = fault;
  /* 撤销监视失败只隔离这一条连接：不向上报错，连接保持占用，到点重试。 */
  CHECK(drive_step(fixture.dns, connection) == FTUN_OK);
  CHECK(connection->transport_failed && connection->peer_eof);
  CHECK(send_calls == 1u);
  if (cancel_retry) {
    size_t slice_work = 0u;
    CHECK(!connection_ready(connection) && connection->source == source);
    CHECK(connection->quarantine_retry_ms != 0u && fixture.dns->quarantined_tcp == 1u &&
          ftun_dns_runtime_take_object_faults(fixture.dns) == 1u);
    CHECK(connection->descriptor == watched_fd && close_calls == 0u);
    CHECK(connection->response_count == 1u && connection->protocol == protocol);
    CHECK(fcntl(watched_fd, F_GETFD) >= 0);
    /* 未到重试时间不动；到点后重新就绪并完成收尾。 */
    CHECK(ftun_dns_runtime_run_slice(fixture.dns, 4u, &slice_work) == FTUN_OK);
    CHECK(connection->quarantine_retry_ms != 0u && close_calls == 0u);
    connection->quarantine_retry_ms = 1u;
    CHECK(ftun_dns_runtime_run_slice(fixture.dns, 4u, &slice_work) == FTUN_OK);
    CHECK(fixture.dns->quarantined_tcp == 0u && connection->quarantine_retry_ms == 0u);
    CHECK(send_calls == 1u);
    cancel_source = NULL;
  }
  CHECK(connection->active == pending);
  CHECK(connection->protocol == (pending ? protocol : NULL));
  CHECK(connection->descriptor == -1 && connection->source == NULL);
  CHECK(connection->response_head == NULL && connection->response_count == 0u);
  CHECK(connection->input == NULL && (connection->input_reservation).budget == NULL);
  CHECK(close_calls == 1u && fcntl(watched_fd, F_GETFD) < 0 && errno == EBADF);
  CHECK(check_quiet(&fixture, fixture.dns) == 0);
  if (!pending) {
    watched_fd = -1;
    CHECK(close(client) == 0);
    CHECK(fixture_destroy(&fixture) == 0);
    printf("fatal send=%d pending=0 passed\n", fault);
    return 0;
  }
  owner = fixture.dns;
  if (reload) {
    CHECK(reload_start(&fixture, &retired) == 0);
    CHECK(retired == owner && ftun_dns_runtime_reap(&retired) == FTUN_E_AGAIN);
    CHECK(pump(&fixture, owner) == 0);
    CHECK(check_quiet(&fixture, owner) == 0);
  } else {
    /* 在途连接不能被新连接复用，即使传输 FD 已经关闭。 */
    int saved_watch = watched_fd;
    watched_fd = -1;
    CHECK(connection_open(&fixture, false, &other_client, &other) == 0);
    CHECK(other != connection && other->peer_id != peer);
    CHECK(shutdown(other_client, SHUT_WR) == 0);
    CHECK(pump(&fixture, fixture.dns) == 0);
    CHECK(!other->active && connection->active);
    (void)__real_close(other_client);
    watched_fd = saved_watch;
  }
  CHECK(finish_request(&fixture, 1u) == 0);
  CHECK(connection_ready(connection) && connection->response_head == NULL);
  CHECK(connection->active && connection->peer_id == peer);
  CHECK(drive_step(owner, connection) == FTUN_OK);
  CHECK(!connection->active && connection->protocol == NULL);
  CHECK(send_calls == 1u && close_calls == 1u);
  watched_fd = -1;
  CHECK(close(client) == 0);
  if (reload) CHECK(ftun_dns_runtime_reap(&retired) == FTUN_OK && retired == NULL);
  CHECK(fixture_destroy(&fixture) == 0);
  printf("fatal send=%d cancel_retry=%u reload=%u pending=1 passed\n",
         fault, cancel_retry, reload);
  return 0;
}

static int reset_read_case(bool body)
{
  fixture_t fixture;
  ftun_dns_runtime_tcp_t *connection = NULL;
  uint8_t partial[3] = {0u, 27u, 0x22u};
  int client;
  CHECK(fixture_start(&fixture) == 0);
  CHECK(connection_open(&fixture, false, &client, &connection) == 0);
  watched_fd = connection->descriptor;
  send_calls = 0u;
  close_calls = 0u;
  CHECK(submit_query(&fixture, client) == 0);
  if (body) {
    CHECK(send(client, partial, sizeof(partial), MSG_NOSIGNAL) == (ssize_t)sizeof(partial));
    CHECK(drive_step(fixture.dns, connection) == FTUN_OK);
    CHECK(connection->input != NULL && connection->input_offset == 3u);
  }
  recv_fault = ECONNRESET;
  CHECK(drive_step(fixture.dns, connection) == FTUN_OK);
  CHECK(connection->transport_failed && connection->active);
  CHECK(connection->descriptor == -1 && connection->source == NULL);
  CHECK(connection->input == NULL && (connection->input_reservation).budget == NULL);
  CHECK(close_calls == 1u && send_calls == 0u);
  CHECK(check_quiet(&fixture, fixture.dns) == 0);
  CHECK(finish_request(&fixture, 0u) == 0);
  CHECK(drive_step(fixture.dns, connection) == FTUN_OK);
  CHECK(!connection->active && close_calls == 1u && send_calls == 0u);
  watched_fd = -1;
  CHECK(close(client) == 0);
  CHECK(fixture_destroy(&fixture) == 0);
  printf("reset read body=%u passed\n", body);
  return 0;
}

static int half_close_case(bool reload, bool hijack)
{
  fixture_t fixture;
  ftun_dns_runtime_tcp_t *connection = NULL;
  ftun_dns_runtime_t *retired = NULL;
  ftun_dns_runtime_t *owner;
  uint8_t actual[29];
  uint8_t expected[29];
  int client;
  CHECK(fixture_start(&fixture) == 0);
  CHECK(connection_open(&fixture, hijack, &client, &connection) == 0);
  watched_fd = connection->descriptor;
  close_calls = 0u;
  send_calls = 0u;
  CHECK(submit_query(&fixture, client) == 0);
  CHECK(shutdown(client, SHUT_WR) == 0);
  CHECK(pump(&fixture, fixture.dns) == 0);
  CHECK(connection->peer_eof && !connection->transport_failed);
  CHECK(connection->active && connection->source == NULL);
  CHECK(check_quiet(&fixture, fixture.dns) == 0);
  owner = fixture.dns;
  if (reload) {
    CHECK(reload_start(&fixture, &retired) == 0);
    CHECK(ftun_dns_runtime_reap(&retired) == FTUN_E_AGAIN && retired == owner);
    CHECK(pump(&fixture, owner) == 0);
  }
  CHECK(finish_request(&fixture, 0u) == 0);
  CHECK(connection_ready(connection) && connection->response_count == 1u);
  if (reload) CHECK(ftun_dns_runtime_reap(&retired) == FTUN_E_AGAIN);
  send_fault = SEND_SHORT;
  CHECK(drive_step(owner, connection) == FTUN_OK);
  CHECK(connection->active && connection->source != NULL);
  CHECK(connection->response_head->offset == 2u && send_calls == 1u);
  CHECK(recv(client, actual, 2u, 0) == 2);
  if (reload) CHECK(ftun_dns_runtime_reap(&retired) == FTUN_E_AGAIN);
  send_fault = SEND_AGAIN;
  CHECK(drive_step(owner, connection) == FTUN_OK);
  CHECK(connection->active && connection->response_head->offset == 2u);
  CHECK(!connection->transport_failed && close_calls == 0u && send_calls == 2u);
  CHECK(drive_step(owner, connection) == FTUN_OK);
  CHECK(!connection->active && connection->protocol == NULL);
  CHECK(close_calls == 1u && send_calls == 3u);
  CHECK(recv(client, actual + 2u, 27u, 0) == 27);
  CHECK(recv(client, expected, sizeof(expected), 0) == 0);
  query_wire(expected);
  expected[3] = 1u;
  expected[4] = 0x81u;
  expected[5] = 0x80u;
  CHECK(memcmp(actual, expected, sizeof(actual)) == 0);
  watched_fd = -1;
  CHECK(close(client) == 0);
  if (reload) CHECK(ftun_dns_runtime_reap(&retired) == FTUN_OK && retired == NULL);
  CHECK(fixture_destroy(&fixture) == 0);
  printf("half close reload=%u hijack=%u passed\n", reload, hijack);
  return 0;
}

static ftun_status_t hijack_send(void *user, ftun_datagram_send_token_t token,
  const ftun_endpoint_t *endpoint, const ftun_packet_t *packet)
{
  (void)user; (void)token; (void)endpoint; (void)packet;
  abort();
}

static ftun_status_t hijack_cancel(void *user, ftun_datagram_send_token_t token)
{ (void)user; (void)token; abort(); }

static void hijack_destroy(void *user)
{ (*(size_t *)user)++; }

static int hijack_udp_retained(void)
{
  fixture_t fixture;
  ftun_datagram_t *channel = NULL;
  ftun_datagram_options_t options = {0};
  ftun_datagram_backend_t backend = {hijack_send, hijack_cancel, hijack_destroy, NULL};
  ftun_datagram_usage_t usage;
  ftun_buffer_t *buffer = NULL;
  ftun_buffer_slice_t slice = {0};
  ftun_packet_t packet = {0};
  ftun_endpoint_t client = {0};
  size_t destroyed = 0u, capacity = 0u;
  uint8_t wire[29], *data = NULL;
  CHECK(fixture_start(&fixture) == 0);
  CHECK(ftun_dns_runtime_protocol_create(fixture.dns, false, 0u, 0u,
    &fixture.dns->hijack) == FTUN_OK);
  options.budget = fixture.budget;
  options.max_pending_packets = 1u;
  options.max_pending_bytes = 4096u;
  backend.context = &destroyed;
  CHECK(ftun_datagram_create(&options, &backend, &channel) == FTUN_OK);
  query_wire(wire);
  CHECK(ftun_buffer_acquire(fixture.budget, 27u, &buffer) == FTUN_OK);
  CHECK(ftun_buffer_data(buffer, &data, &capacity) == FTUN_OK && capacity >= 27u);
  memcpy(data, wire + 2u, 27u);
  CHECK(ftun_buffer_slice(buffer, 0u, 27u, &slice) == FTUN_OK);
  CHECK(ftun_packet_init(&packet, &slice, 1u) == FTUN_OK);
  client.kind = FTUN_ADDRESS_IPV4;
  client.address[0] = 127u;
  client.address[3] = 1u;
  client.port = 12345u;
  CHECK(ftun_dns_runtime_hijack_udp(fixture.dns, channel, &client, &packet) == FTUN_OK);
  CHECK(fixture.request_count == 1u && fixture.dns->pending_count == 1u);
  CHECK(ftun_datagram_stop(channel) == FTUN_OK);
  CHECK(ftun_datagram_destroy(&channel) == FTUN_E_AGAIN && channel != NULL && destroyed == 0u);
  CHECK(finish_request(&fixture, 0u) == 0);
  CHECK(fixture.dns->pending_count == 0u);
  CHECK(ftun_datagram_get_usage(channel, &usage) == FTUN_OK && usage.reference_count == 1u);
  CHECK(ftun_datagram_destroy(&channel) == FTUN_OK && destroyed == 1u);
  CHECK(ftun_packet_release(&packet) == FTUN_OK);
  CHECK(ftun_buffer_slice_release(&slice) == FTUN_OK);
  CHECK(ftun_buffer_release(&buffer) == FTUN_OK);
  CHECK(fixture_destroy(&fixture) == 0);
  puts("UDP hijack retains stopped inbound until late response passed");
  return 0;
}

static int hijack_admission_failure(void)
{
  fixture_t fixture;
  int pair[2];
  uint8_t byte = 0x5au;
  uint8_t received = 0u;
  ftun_dns_listener_info_t info;
  CHECK(fixture_start(&fixture) == 0);
  CHECK(ftun_dns_runtime_protocol_create(fixture.dns, false, 0u, 0u,
                                          &fixture.dns->hijack) == FTUN_OK);
  CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
                     0, pair) == 0);
  start_fail_fd = pair[0];
  watched_fd = pair[0];
  close_calls = 0u;
  CHECK(ftun_dns_runtime_hijack_tcp(fixture.dns, pair[0]) == FTUN_E_LIMIT);
  start_fail_fd = -1;
  CHECK(close_calls == 0u && fcntl(pair[0], F_GETFD) >= 0);
  CHECK(!fixture.dns->tcp[0].active && fixture.dns->tcp[0].protocol == NULL);
  CHECK(fixture.dns->tcp[0].descriptor == -1 && fixture.dns->tcp[0].source == NULL);
  CHECK(ftun_dns_listener_get_info(fixture.dns->hijack, &info) == FTUN_OK);
  CHECK(info.inflight == 0u && info.tcp_connections == 0u);
  CHECK(send(pair[0], &byte, 1u, MSG_NOSIGNAL) == 1);
  CHECK(recv(pair[1], &received, 1u, 0) == 1 && received == byte);
  watched_fd = -1;
  CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
  CHECK(fixture_destroy(&fixture) == 0);
  puts("hijack admission failure retains caller FD passed");
  return 0;
}

enum { PREPARE_ENDPOINT_ALLOC, PREPARE_VALID_ALLOC, PREPARE_RESOLVE, PREPARE_CACHE };

static int prepare_case(bool cache, bool planned, int fault)
{
  fixture_t fixture;
  ftun_dns_runtime_plan_t *plan = NULL;
  ftun_status_t status;
  ftun_status_t expected = FTUN_E_LIMIT;
#if defined(FTUN_TEST_PROXY)
  bool proxy = true;
#else
  bool proxy = false;
#endif
  CHECK(fixture_init(&fixture) == 0);
  fixture.config = make_config(cache, proxy, !planned && fault == PREPARE_RESOLVE, 0u);
  CHECK(fixture.config != NULL);
  if (planned) {
    CHECK(ftun_dns_runtime_plan_prepare(fixture.budget, fixture.config, 0u, &plan) == FTUN_OK);
    /* 不完整的预解析结果同样不得被 cache 成功掩盖。 */
    if (fault == PREPARE_RESOLVE) plan->proxy_valid[0] = 0u;
  }
  cache_calls = 0u;
  blocked_sockets = 0u;
  if (fault == PREPARE_ENDPOINT_ALLOC || fault == PREPARE_VALID_ALLOC) {
    fail_calloc_size = fault == PREPARE_ENDPOINT_ALLOC ? sizeof(ftun_endpoint_t) : 1u;
    calloc_failures = 1u;
  } else if (fault == PREPARE_RESOLVE) {
    block_socket = !planned;
    expected = planned ? FTUN_E_RESOLVE : FTUN_E_IO;
  } else {
    fail_cache = true;
    if (!cache) expected = FTUN_OK;
  }
  status = planned ? ftun_dns_runtime_prepare_reload_planned(NULL,
    fixture.core, fixture.budget, fixture.operations, fixture.loop,
    fixture.config, &fixture.adapter,
    &(ftun_dns_runtime_network_t){.generation = 2u, .socket_mark = 0u,
      .path = {.open = ftun_socket_path_open}}, plan, &fixture.dns) :
    ftun_dns_runtime_prepare(fixture.core, fixture.budget, fixture.operations,
      fixture.loop, fixture.config, &fixture.adapter,
    &(ftun_dns_runtime_network_t){.generation = 1u, .socket_mark = 0u,
      .path = {.open = ftun_socket_path_open}}, &fixture.dns);
  block_socket = false;
  fail_cache = false;
  CHECK(status == expected);
  CHECK(calloc_failures == 0u);
  CHECK(cache_calls == (fault == PREPARE_CACHE && cache ? 1u : 0u));
  CHECK(blocked_sockets == (!planned && fault == PREPARE_RESOLVE ? 1u : 0u));
  if (expected != FTUN_OK) CHECK(fixture.dns == NULL);
  else CHECK(fixture.dns != NULL && fixture.dns->cache == NULL);
  CHECK(ftun_dns_runtime_plan_destroy(&plan) == FTUN_OK);
  CHECK(fixture_destroy(&fixture) == 0);
  printf("prepare cache=%u planned=%u fault=%d passed\n", cache, planned, fault);
  return 0;
}

#if defined(FTUN_TEST_PROXY)
static int plan_resolution_failure(bool cache)
{
  ftun_config_t *config = make_config(cache, true, true, 0u);
  ftun_dns_runtime_plan_t *plan = NULL;
  ftun_status_t status;
  ftun_budget_t *budget = NULL;
  size_t before = fd_count();
  CHECK(config != NULL);
  CHECK(ftun_budget_create(NULL, 65536u, 0u, &budget) == FTUN_OK);
  block_socket = true;
  blocked_sockets = 0u;
  cache_calls = 0u;
  status = ftun_dns_runtime_plan_prepare(budget, config, 0u, &plan);
  block_socket = false;
  CHECK(status == FTUN_E_IO && plan == NULL);
  CHECK(blocked_sockets == 1u && cache_calls == 0u);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(fd_count() == before);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  printf("plan resolution failure cache=%u passed\n", cache);
  return 0;
}
#else
static int proxy_unavailable(void)
{
  static const char json[] =
    "{\"dns\":{\"enable\":true,\"default-server\":\"real\","
    "\"servers\":[{\"name\":\"real\",\"type\":\"udp\","
    "\"address\":[\"127.0.0.1:9\"],\"outbound\":\"proxy\"}]},"
    "\"outbounds\":[{\"name\":\"proxy\",\"type\":\"socks5\","
    "\"server\":\"127.0.0.1:1080\"}]}";
  ftun_config_t *config = NULL;
  CHECK(ftun_config_parse((ftun_bytes_t){(const uint8_t *)json,
    sizeof(json) - 1u}, &config) == FTUN_OK);
  CHECK(ftun_config_validate(config, NULL) == FTUN_E_UNSUPPORTED);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  puts("unavailable proxy rejected before preparation passed");
  return 0;
}
#endif

static int bootstrap_budget(void)
{
  ftun_budget_options_t options = {0};
  ftun_budget_t *budget = NULL;
  ftun_reservation_t hold = (ftun_reservation_t){0};
  ftun_budget_usage_t usage;
  ftun_config_t config = {0};
  ftun_config_bind_sections(&config);
  ftun_endpoint_t endpoint;
  char *bootstrap[] = {"127.0.0.1:9"};
  options.limit = (ftun_budget_resources_t){65536u, 1u, 1u};
  CHECK(ftun_budget_create_resources(NULL, &options, &budget) == FTUN_OK);
  CHECK(ftun_budget_reserve_resources(budget,
    (ftun_budget_resources_t){0u, 1u, 0u}, &hold) == FTUN_OK);
  CHECK(ftun_dns_runtime_bootstrap_endpoint(budget, &config, &endpoint) == FTUN_E_LIMIT);
  config.dns.bootstrap.items = bootstrap;
  config.dns.bootstrap.count = 1u;
  block_socket = true;
  blocked_sockets = 0u;
  CHECK(ftun_dns_runtime_resolve_upstream(budget, &config, "example.com:53", 0u,
    &endpoint) == FTUN_E_LIMIT && blocked_sockets == 0u);
  CHECK(ftun_reservation_release(&hold) == FTUN_OK);
  CHECK(ftun_dns_runtime_resolve_upstream(budget, &config, "example.com:53", 0u,
    &endpoint) != FTUN_OK && blocked_sockets == 1u);
  block_socket = false;
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK &&
    usage.used == 0u && usage.used_resources.descriptors == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

/* 监听出错只影响这个监听：关闭 socket、等待恢复，到点按原地址重新 bind。 */
static int listener_recovery(void)
{
  fixture_t fixture;
  ftun_dns_runtime_t *dns;
  ftun_dns_runtime_listener_slot_t *slot;
  ftun_recovery_info_t info;
  struct sockaddr_in address;
  socklen_t length = (socklen_t)sizeof(address);
  size_t slice_work = 0u;
  bool work = false;
  CHECK(fixture_start(&fixture) == 0);
  dns = fixture.dns;
  slot = &dns->listeners[0];
  CHECK(slot->descriptor >= 0 && slot->tcp_descriptor >= 0 && !slot->waiting);
  CHECK(getsockname(slot->tcp_descriptor, (struct sockaddr *)&address, &length) == 0);
  slot->events |= FTUN_EVENT_ERROR;
  CHECK(ftun_dns_runtime_step_listener(dns, ftun_dns_runtime_now(NULL), &work) == FTUN_OK);
  CHECK(work && slot->waiting && slot->descriptor == -1 && slot->tcp_descriptor == -1);
  CHECK(slot->source == NULL && slot->tcp_source == NULL);
  CHECK(ftun_dns_runtime_listeners_waiting(dns) == 1u &&
        ftun_dns_runtime_take_object_faults(dns) == 1u);
  /* 服务其余部分不受影响。 */
  CHECK(ftun_dns_runtime_run_slice(dns, 4u, &slice_work) == FTUN_OK);
  CHECK(ftun_recovery_query(dns->recovery, slot->recovery.slot, &info) == FTUN_OK &&
        info.state == FTUN_RECOVERY_WAITING && info.failures == 1u);
  /* 未到时间不重绑；到点后同步重绑成功。 */
  CHECK(ftun_recovery_run(dns->recovery, info.next_ms - 1u, 4u, &slice_work) == FTUN_OK &&
        slice_work == 0u && slot->waiting);
  CHECK(ftun_recovery_run(dns->recovery, info.next_ms, 4u, &slice_work) == FTUN_OK &&
        slice_work == 1u);
  CHECK(!slot->waiting && slot->descriptor >= 0 && slot->tcp_descriptor >= 0);
  CHECK(slot->source != NULL && slot->tcp_source != NULL);
  CHECK(ftun_dns_runtime_listeners_waiting(dns) == 0u);
  CHECK(ftun_recovery_query(dns->recovery, slot->recovery.slot, &info) == FTUN_OK &&
        info.state == FTUN_RECOVERY_AVAILABLE);
  {
    struct sockaddr_in again;
    socklen_t again_length = (socklen_t)sizeof(again);
    CHECK(getsockname(slot->tcp_descriptor, (struct sockaddr *)&again, &again_length) == 0);
    CHECK(again.sin_port == address.sin_port);
  }
  return fixture_destroy(&fixture);
}

/* 启动时监听地址尚未就绪：不失败，进入等待恢复并保持等待。 */
static int listener_startup_waiting(void)
{
  fixture_t fixture;
  ftun_dns_runtime_listener_slot_t *slot;
  ftun_recovery_info_t info;
  size_t slice_work = 0u;
  CHECK(fixture_init(&fixture) == 0);
  /* 192.0.2.0/24 是文档保留网段，本机没有这个地址。 */
  config_listen_host = "192.0.2.77";
  fixture.config = make_config(false, false, false, reserve_port());
  config_listen_host = "127.0.0.1";
  CHECK(fixture.config != NULL);
  CHECK(ftun_dns_runtime_prepare(fixture.core, fixture.budget,
    fixture.operations, fixture.loop, fixture.config, &fixture.adapter,
    &(ftun_dns_runtime_network_t){.generation = 1u, .socket_mark = 0u,
      .path = {.open = ftun_socket_path_open}}, &fixture.dns) == FTUN_OK);
  CHECK(ftun_dns_runtime_activate(fixture.dns) == FTUN_OK);
  slot = &fixture.dns->listeners[0];
  CHECK(slot->waiting && slot->descriptor == -1 && slot->tcp_descriptor == -1);
  CHECK(ftun_dns_runtime_listeners_waiting(fixture.dns) == 1u);
  CHECK(ftun_recovery_query(fixture.dns->recovery, slot->recovery.slot, &info) == FTUN_OK &&
        info.state == FTUN_RECOVERY_WAITING);
  /* 地址一直不出现：到点尝试失败，退避加长，仍在等待。 */
  CHECK(ftun_recovery_run(fixture.dns->recovery, info.next_ms, 4u, &slice_work) == FTUN_OK);
  CHECK(slot->waiting && ftun_recovery_query(fixture.dns->recovery,
    slot->recovery.slot, &info) == FTUN_OK && info.failures == 2u &&
    info.state == FTUN_RECOVERY_WAITING);
  CHECK(ftun_dns_runtime_run_slice(fixture.dns, 4u, &slice_work) == FTUN_OK);
  return fixture_destroy(&fixture);
}

int main(void)
{
  CHECK(bootstrap_budget() == 0);
  CHECK(listener_recovery() == 0);
  CHECK(listener_startup_waiting() == 0);
  CHECK(ready_mask_case() == 0);
  unsigned int cache;
  unsigned int planned;
#if defined(FTUN_TEST_PROXY)
  int fault;
#endif
  CHECK(fatal_case(SEND_PIPE, false, false, true) == 0);
  CHECK(fatal_case(SEND_RESET, false, false, true) == 0);
  CHECK(fatal_case(SEND_ZERO, false, false, true) == 0);
  CHECK(fatal_case(SEND_PIPE, false, false, false) == 0);
  CHECK(fatal_case(SEND_RESET, false, false, false) == 0);
  CHECK(fatal_case(SEND_ZERO, false, false, false) == 0);
  CHECK(fatal_case(SEND_PIPE, true, false, true) == 0);
  CHECK(fatal_case(SEND_PIPE, false, true, true) == 0);
  CHECK(reset_read_case(false) == 0);
  CHECK(reset_read_case(true) == 0);
  CHECK(half_close_case(false, false) == 0);
  CHECK(half_close_case(true, false) == 0);
  CHECK(half_close_case(true, true) == 0);
  CHECK(hijack_admission_failure() == 0);
  CHECK(hijack_udp_retained() == 0);
  for (cache = 0u; cache < 2u; cache++) {
    for (planned = 0u; planned < 2u; planned++) {
#if defined(FTUN_TEST_PROXY)
      for (fault = PREPARE_ENDPOINT_ALLOC; fault <= PREPARE_CACHE; fault++) {
        CHECK(prepare_case(cache != 0u, planned != 0u, fault) == 0);
      }
#else
      CHECK(prepare_case(cache != 0u, planned != 0u, PREPARE_CACHE) == 0);
#endif
    }
#if defined(FTUN_TEST_PROXY)
    CHECK(plan_resolution_failure(cache != 0u) == 0);
#endif
  }
#if defined(FTUN_TEST_PROXY)
  puts("DNS failure contract: 33 scenarios passed");
#else
  CHECK(proxy_unavailable() == 0);
  puts("DNS failure contract: 20 scenarios passed");
#endif
  return 0;
}
