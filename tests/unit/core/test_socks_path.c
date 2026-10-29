#include <unistd.h>
#include <fcntl.h>
#include "core/context.h"
#include "proxy/outbound/socks5.h"
#include "platform/clock.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "SOCKS Path failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

ftun_status_t __wrap_ftun_socket_path_open(void *, ftun_core_t *,
  const ftun_path_open_request_t *, const ftun_path_spec_t *, ftun_operation_t **);

typedef struct {
  ftun_socks5_connection_t *connection;
  ftun_status_t status;
  unsigned int calls;
  unsigned int notifications;
  bool close_in_notify;
  ftun_status_t notify_close;
} result_t;

static void completed(ftun_operation_t *operation, ftun_error_t error,
  ftun_socks5_connection_t *connection, void *user)
{
  result_t *result = user;
  (void)operation;
  result->connection = connection;
  result->status = error.status;
  result->calls++;
}

static void notified(ftun_path_t *path, uint32_t events, ftun_error_t error, void *user)
{
  result_t *result = user;
  (void)path;
  (void)events;
  (void)error;
  result->notifications++;
  if (result->close_in_notify) result->notify_close = ftun_socks5_connection_close(&result->connection);
}

static void written(ftun_operation_t *operation, ftun_error_t error, void *user)
{
  (void)operation;
  (void)error;
  (void)user;
}

static int tick(ftun_event_loop_t *loop, ftun_operation_queue_t *operations)
{
  uint64_t now;
  size_t count;
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  CHECK(ftun_event_loop_poll(loop, now, 16u, &count) == FTUN_OK);
  CHECK(ftun_operation_dispatch(operations, 16u, &count) == FTUN_OK);
  return 0;
}

static int scenario(unsigned int mode)
{
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_path_provider_t *provider = NULL;
  ftun_path_provider_spec_t spec = {0};
  ftun_path_scope_t *scope = NULL;
  ftun_operation_t *operation = NULL;
  ftun_socks5_connect_request_t request = {0};
  ftun_socks5_proxy_t proxy = {0};
  ftun_target_t target = {0};
  ftun_budget_usage_t usage;
  ftun_path_provider_info_t provider_info;
  result_t result = {0};
  uint64_t now;
  size_t count;
  unsigned int round;
  CHECK(ftun_budget_create(NULL, 4194304u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 32u, &operations) == FTUN_OK);
  CHECK(ftun_event_loop_create(core, &loop) == FTUN_OK);
  spec.budget = budget;
  spec.generation = 7u;
  spec.ops.open = __wrap_ftun_socket_path_open;
  spec.max_paths = 2u;
  spec.max_pending = 2u;
  CHECK(ftun_path_provider_create(&spec, &provider) == FTUN_OK);
  CHECK(ftun_path_provider_scope(provider, 7u, &scope) == FTUN_OK);
  proxy.server.kind = FTUN_ADDRESS_IPV4;
  proxy.server.address[0] = 127u;
  proxy.server.address[3] = 1u;
  proxy.server.port = 1080u;
  target.generation = 7u;
  target.original.kind = FTUN_ADDRESS_DOMAIN;
  target.original.domain = (ftun_string_t){"banner.test", 11u};
  target.original.port = 443u;
  target.identity = target.original.domain;
  if (mode == 1u || mode == 2u) {
    proxy.username = (ftun_bytes_t){(const uint8_t *)"user", 4u};
    proxy.password = (ftun_bytes_t){(const uint8_t *)(mode == 1u ? "pass" : "fail"), 4u};
  }
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  request.loop = loop;
  request.operations = operations;
  request.budget = budget;
  request.proxy = &proxy;
  request.target = &target;
  request.scope = scope;
  request.transport = FTUN_DIAL_TCP;
  request.deadline_ms = mode == 5u ? now : now + 10000u;
  request.completion = completed;
  request.user = &result;
  request.notify = notified;
  request.notify_user = &result;
  request.stream.max_pending_writes = 1u;
  request.stream.max_pending_bytes = 8192u;
  request.stream.completion = written;
  CHECK(ftun_socks5_connect(core, &request, &operation) == FTUN_OK);
  /* 发起后释放调用方 scope；握手仍应保持旧代身份和拥有权。 */
  CHECK(ftun_path_scope_release(&scope) == FTUN_OK);
  CHECK(ftun_path_provider_reload_prepare(provider, 8u) == FTUN_OK);
  CHECK(ftun_path_provider_reload_commit(provider, 8u) == FTUN_OK);
  if (mode == 3u) CHECK(ftun_operation_cancel(operation) == FTUN_E_AGAIN);
  if (mode == 4u) {
    CHECK(ftun_operation_dispatch(operations, 16u, &count) == FTUN_OK);
    CHECK(ftun_monotonic_now(&now) == FTUN_OK);
    /* 只执行握手 pump，保留后端异步写和其延迟任务再取消。 */
    CHECK(ftun_event_loop_poll(loop, now, 1u, &count) == FTUN_OK && count == 1u);
    CHECK(ftun_operation_cancel(operation) == FTUN_E_AGAIN);
  }
  if (mode == 6u) {
    ftun_operation_queue_usage_t pending;
    for (round = 0u; round < 500u; round++) {
      CHECK(ftun_monotonic_now(&now) == FTUN_OK);
      CHECK(ftun_event_loop_poll(loop, now, 16u, &count) == FTUN_OK);
      CHECK(ftun_operation_queue_get_usage(operations, &pending) == FTUN_OK);
      if (pending.inflight == 1u && pending.ready == 1u) break;
      CHECK(ftun_operation_dispatch(operations, 1u, &count) == FTUN_OK);
    }
    CHECK(round < 500u && result.calls == 0u);
    CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  }
  for (round = 0u; round < 500u && result.calls == 0u; round++) CHECK(tick(loop, operations) == 0);
  CHECK(result.calls == 1u);
  if (mode == 2u) CHECK(result.status == FTUN_E_REJECTED && result.connection == NULL);
  else if (mode == 3u || mode == 4u || mode == 6u) CHECK(result.status == FTUN_E_CANCELLED && result.connection == NULL);
  else if (mode == 5u) CHECK(result.status == FTUN_E_TIMEOUT && result.connection == NULL);
  else {
    ftun_path_t *path = NULL;
    ftun_path_info_t info;
    ftun_stream_t *stream = NULL;
    ftun_stream_t *held;
    char bytes[8];
    size_t received;
    CHECK(result.status == FTUN_OK && result.connection != NULL);
    CHECK(ftun_socks5_connection_path(result.connection, &path) == FTUN_OK);
    CHECK(ftun_path_get_info(path, &info) == FTUN_OK && info.configuration_generation == 7u);
    CHECK(ftun_path_stream(path, &stream) == FTUN_OK);
    CHECK(ftun_stream_read(stream, bytes, sizeof(bytes), &received) == FTUN_OK && received == 5u);
    CHECK(memcmp(bytes, "hello", 5u) == 0);
    /* ready 之后的通知上下文仍存活；通知栈中 close 必须保留对象。 */
    result.close_in_notify = true;
    CHECK(ftun_stream_shutdown_write(stream) == FTUN_OK);
    CHECK(result.notifications != 0u && result.notify_close == FTUN_E_AGAIN && result.connection != NULL);
    result.close_in_notify = false;
    CHECK(ftun_stream_read(stream, bytes, sizeof(bytes), &received) == FTUN_E_EOF);
    held = stream;
    CHECK(ftun_stream_retain(held) == FTUN_OK);
    CHECK(ftun_socks5_connection_close(&result.connection) == FTUN_E_AGAIN && result.connection != NULL);
    CHECK(ftun_stream_release(&held) == FTUN_OK);
    CHECK(ftun_socks5_connection_close(&result.connection) == FTUN_OK && result.connection == NULL);
  }
  for (round = 0u; round < 4u; round++) CHECK(tick(loop, operations) == 0);
  CHECK(result.calls == 1u);
  CHECK(ftun_path_provider_get_info(provider, &provider_info) == FTUN_OK &&
    provider_info.paths == 0u && provider_info.pending == 0u && provider_info.scopes == 0u);
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  CHECK(ftun_path_provider_stop_until(provider, now + 1000u) == FTUN_OK);
  CHECK(ftun_path_provider_destroy(&provider) == FTUN_OK);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(void)
{
  unsigned int mode;
  for (mode = 0u; mode < 7u; mode++) {
    if (scenario(mode) != 0) { fprintf(stderr, "scenario %u failed\n", mode); return 1; }
  }
  puts("SOCKS Path contract passed: authentication, fragmentation, cancel, timeout, reload and close retry");
  return 0;
}
