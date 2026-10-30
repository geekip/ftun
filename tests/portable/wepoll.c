#include "core/event/backend.h"
#include "core/event/loop.h"
#include "core/limits.h"
#include "platform/clock.h"
#include "platform/poller.h"
#include "platform/socket.h"
#include "platform/thread.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "wepoll contract: %d: %s\n", __LINE__, #x); exit(1); } } while (0)
typedef struct { size_t attempts, fail_at, live; } ledger_t;
typedef union { size_t bytes; long double alignment; } allocation_t;
static void *allocate(void *context, size_t bytes, size_t descriptors)
{
  ledger_t *ledger = context;
  (void)descriptors;
  if (++ledger->attempts == ledger->fail_at) return NULL;
  allocation_t *allocation = malloc(sizeof(*allocation) + bytes);
  CHECK(allocation != NULL);
  allocation->bytes = bytes;
  ledger->live++;
  return allocation + 1u;
}
static void release(void *context, void *allocation)
{
  ledger_t *ledger = context;
  CHECK(ledger->live != 0u);
  ledger->live--;
  free((allocation_t *)allocation - 1u);
}
static ftun_poller_memory_t memory(ledger_t *ledger)
{ return (ftun_poller_memory_t){allocate, release, ledger}; }
static ftun_mutex_t start_mutex = FTUN_MUTEX_INITIALIZER;
static ftun_condition_t start_condition;
static size_t owners_ready;
static bool owners_go;
static void *parallel_owner(void *context)
{
  ledger_t *ledger = context;
  ftun_mutex_lock(&start_mutex);
  owners_ready++;
  ftun_condition_broadcast(&start_condition);
  while (!owners_go) ftun_condition_wait(&start_condition, &start_mutex);
  ftun_mutex_unlock(&start_mutex);
  ftun_poller_t poller = {0};
  ftun_poller_event_t events[FTUN_POLLER_CAPACITY];
  size_t count;
  CHECK(ftun_poller_create(&poller, memory(ledger)) == FTUN_OK);
  ftun_poller_wakeup(&poller);
  CHECK(ftun_poller_wait(&poller, 1000, events, &count) == FTUN_OK && count == 0u);
  ftun_poller_destroy(&poller);
  CHECK(ledger->live == 0u);
  return NULL;
}
static void creation_failures(void)
{
  /* 首次全局初始化可由不同owner并发进入，分配上下文必须保持隔离。 */
  ledger_t ledgers[4] = {0};
  ftun_thread_t owners[4];
  CHECK(ftun_condition_init(&start_condition) == FTUN_OK);
  for (size_t i = 0u; i < 4u; i++) CHECK(ftun_thread_create(&owners[i], parallel_owner, &ledgers[i]) == FTUN_OK);
  ftun_mutex_lock(&start_mutex);
  while (owners_ready != 4u) ftun_condition_wait(&start_condition, &start_mutex);
  owners_go = true;
  ftun_condition_broadcast(&start_condition);
  ftun_mutex_unlock(&start_mutex);
  for (size_t i = 0u; i < 4u; i++) CHECK(ftun_thread_join(&owners[i]) == FTUN_OK);
  ftun_condition_destroy(&start_condition);
  ftun_mutex_destroy(&start_mutex);
  /* Winsock和wepoll的一次性初始化完成后，逐个注入三处构造分配失败。 */
  DWORD handles, after;
  CHECK(GetProcessHandleCount(GetCurrentProcess(), &handles));
  for (size_t fail_at = 1u; fail_at <= 3u; fail_at++) {
    ledger_t ledger = {0u, fail_at, 0u};
    ftun_poller_t poller = {0};
    CHECK(ftun_poller_create(&poller, memory(&ledger)) == FTUN_E_LIMIT);
    CHECK(ledger.live == 0u);
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &after) && after == handles);
  }
}
static void ready(ftun_event_source_t *source, uint32_t events, void *context)
{
  (void)source;
  size_t *calls = context;
  CHECK(events & (FTUN_EVENT_READ | FTUN_EVENT_WRITE));
  (*calls)++;
}
static ftun_budget_t *budget(size_t descriptors)
{
  ftun_budget_t *result;
  ftun_budget_options_t options = {0};
  options.limit = (ftun_budget_resources_t){1024u * 1024u, descriptors, 4096u};
  CHECK(ftun_budget_create_resources(NULL, &options, &result) == FTUN_OK);
  return result;
}
static void budget_lifetime(void)
{
  ftun_budget_t *root = budget(FTUN_POLLER_HANDLES + 2u);
  ftun_event_loop_t *loop;
  ftun_event_source_t *source;
  ftun_budget_usage_t usage, attached;
  ftun_event_backend_info_t info;
  ftun_handle_t pair[2];
  size_t callbacks, calls = 0u;
  CHECK(ftun_event_loop_create_with_budget(NULL, root, 128u, &loop) == FTUN_OK);
  CHECK(ftun_event_backend_attach(loop) == FTUN_OK);
  CHECK(ftun_event_backend_get_info(loop, &info) == FTUN_OK && strcmp(info.backend, "wepoll") == 0);
  CHECK(ftun_budget_get_usage(root, &attached) == FTUN_OK);
  CHECK(attached.used_resources.descriptors == FTUN_POLLER_HANDLES + 2u);
  CHECK(ftun_socket_pair(pair) == FTUN_OK);
  CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)pair[0], FTUN_EVENT_READ, ready, &calls, &source) == FTUN_OK);
  CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK);
  ftun_reservation_t blocker;
  CHECK(ftun_budget_reserve(root, usage.normal_available_resources.memory_bytes, &blocker) == FTUN_OK);
  CHECK(ftun_event_loop_run_once(loop, false, 64u, &callbacks) == FTUN_E_LIMIT);
  CHECK(ftun_event_source_cancel(&source) == FTUN_OK);
  ftun_reservation_release(&blocker);
  CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)pair[0], FTUN_EVENT_READ, ready, &calls, &source) == FTUN_OK);
  CHECK(ftun_event_loop_run_once(loop, false, 64u, &callbacks) == FTUN_OK && calls == 0u);
  CHECK(ftun_event_source_cancel(&source) == FTUN_OK);
  CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK);
  /* 未收割取消完成时，原生sock对象仍然持有真实内存额度。 */
  CHECK(usage.used_resources.memory_bytes > attached.used_resources.memory_bytes);
  uint64_t now, deadline;
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  deadline = now + 5000u;
  while (usage.used_resources.memory_bytes != attached.used_resources.memory_bytes) {
    CHECK(ftun_event_loop_run_once(loop, false, 64u, &callbacks) == FTUN_OK && calls == 0u);
    CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK);
    CHECK(ftun_monotonic_now(&now) == FTUN_OK && now < deadline);
    ftun_thread_pause(1u);
  }
  /* 同一批句柄反复注册、修改和取消；取消后旧通知不能访问已经复用的context。 */
  for (size_t round = 0u; round < 256u; round++) {
    size_t before = calls;
    CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)pair[0], FTUN_EVENT_READ, ready, &calls, &source) == FTUN_OK);
    CHECK(ftun_event_loop_run_once(loop, false, 64u, &callbacks) == FTUN_OK && calls == before);
    CHECK(ftun_event_io_update(source, FTUN_EVENT_WRITE) == FTUN_OK);
    CHECK(ftun_monotonic_now(&now) == FTUN_OK);
    deadline = now + 5000u;
    while (calls == before) {
      CHECK(ftun_event_loop_run_once(loop, false, 64u, &callbacks) == FTUN_OK);
      CHECK(ftun_monotonic_now(&now) == FTUN_OK && now < deadline);
    }
    CHECK(ftun_event_source_cancel(&source) == FTUN_OK);
    before = calls;
    CHECK(ftun_event_loop_run_once(loop, false, 64u, &callbacks) == FTUN_OK && calls == before);
  }
  CHECK(ftun_socket_close((ftun_native_socket_t)pair[0]) == FTUN_OK);
  CHECK(ftun_socket_close((ftun_native_socket_t)pair[1]) == FTUN_OK);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_backend_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u &&
    usage.used_resources.descriptors == 0u && usage.used_resources.queue_slots == 0u);
  CHECK(ftun_budget_destroy(&root) == FTUN_OK);
}
static void descriptor_failure(void)
{
  ftun_budget_t *root = budget(FTUN_POLLER_HANDLES + 1u);
  ftun_event_loop_t *loop;
  ftun_budget_usage_t before, after;
  CHECK(ftun_event_loop_create_with_budget(NULL, root, 1u, &loop) == FTUN_OK);
  CHECK(ftun_budget_get_usage(root, &before) == FTUN_OK);
  /* IOCP可准入，AFD额度不足；attach失败须归还动态存储和构造句柄。 */
  CHECK(ftun_event_backend_attach(loop) == FTUN_E_LIMIT);
  CHECK(ftun_budget_get_usage(root, &after) == FTUN_OK &&
    after.used_resources.memory_bytes == before.used_resources.memory_bytes && after.used_resources.descriptors == 0u);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK && ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_budget_destroy(&root) == FTUN_OK);
}
static void registration_capacity(void)
{
  enum { SOCKETS = 8200 };
  ledger_t ledger = {0};
  ftun_poller_t poller = {0};
  ftun_poller_io_t *io = calloc(SOCKETS, sizeof(*io));
  ftun_handle_t *sockets = malloc(SOCKETS * sizeof(*sockets));
  ftun_endpoint_t address = {.kind = FTUN_ADDRESS_IPV4, .address = {127u, 0u, 0u, 1u}};
  ftun_socket_bind_issue_t issue;
  CHECK(io != NULL && sockets != NULL);
  CHECK(ftun_poller_create(&poller, memory(&ledger)) == FTUN_OK);
  for (size_t i = 0u; i < SOCKETS; i++) {
    CHECK(ftun_socket_listen(&address, FTUN_DIAL_UDP, 0, &sockets[i], &issue) == FTUN_OK);
    io[i].socket = (ftun_native_socket_t)sockets[i];
    CHECK(ftun_poller_update(&poller, &io[i], FTUN_POLLER_READ, &io[i]) == FTUN_OK);
    io[i].events = FTUN_POLLER_READ;
  }
  for (size_t i = 0u; i < SOCKETS; i++) {
    CHECK(ftun_poller_update(&poller, &io[i], 0u, NULL) == FTUN_OK);
    CHECK(ftun_socket_close((ftun_native_socket_t)sockets[i]) == FTUN_OK);
  }
  ftun_poller_destroy(&poller);
  CHECK(ledger.live == 0u);
  free(sockets); free(io);
  puts("wepoll: 8200 registered UDP sockets passed");
}
static void *signal_waitable(void *context)
{
  Sleep(1u);
  CHECK(SetEvent((HANDLE)context));
  return NULL;
}
static void waitable_contract(void)
{
  enum { HANDLES = 96 };
  ledger_t ledger = {0};
  ftun_poller_t poller = {0};
  ftun_poller_event_t events[FTUN_POLLER_CAPACITY];
  ftun_poller_io_t io[HANDLES] = {{0}};
  HANDLE handles[HANDLES];
  bool seen[HANDLES] = {false};
  size_t count, total = 0u;
  CHECK(ftun_poller_create(&poller, memory(&ledger)) == FTUN_OK);
  size_t baseline = ledger.live;
  handles[0] = CreateEventW(NULL, FALSE, FALSE, NULL);
  CHECK(handles[0] != NULL);
  io[0].socket = (ftun_native_socket_t)handles[0]; io[0].kind = FTUN_POLLER_WAITABLE;
  ledger.fail_at = ledger.attempts + 1u;
  CHECK(ftun_poller_update(&poller, &io[0], FTUN_POLLER_READ, &io[0]) == FTUN_E_LIMIT);
  CHECK(io[0].registration == NULL && ledger.live == baseline);
  ledger.fail_at = 0u;
  CHECK(ftun_poller_update(&poller, &io[0], FTUN_POLLER_WRITE, &io[0]) == FTUN_E_UNSUPPORTED);
  for (size_t i = 0u; i < HANDLES; i++) {
    if (i != 0u) handles[i] = CreateEventW(NULL, FALSE, FALSE, NULL);
    CHECK(handles[i] != NULL);
    io[i].socket = (ftun_native_socket_t)handles[i]; io[i].kind = FTUN_POLLER_WAITABLE;
    CHECK(ftun_poller_update(&poller, &io[i], FTUN_POLLER_READ, &io[i]) == FTUN_OK);
    io[i].events = FTUN_POLLER_READ;
    CHECK(SetEvent(handles[i]));
  }
  for (size_t turns = 0u; total < HANDLES && turns < 10u; turns++) {
    CHECK(ftun_poller_wait(&poller, 1000, events, &count) == FTUN_OK);
    CHECK(count <= FTUN_POLLER_CAPACITY);
    for (size_t i = 0u; i < count; i++) {
      size_t index = (ftun_poller_io_t *)events[i].user - io;
      CHECK(index < HANDLES && !seen[index] && events[i].events == FTUN_POLLER_READ);
      seen[index] = true; total++;
    }
  }
  CHECK(total == HANDLES);
  for (size_t i = 1u; i < HANDLES; i++) {
    CHECK(ftun_poller_update(&poller, &io[i], 0u, NULL) == FTUN_OK && io[i].registration == NULL);
    CHECK(CloseHandle(handles[i]));
  }
  /* owner 已阻塞时由原生线程池捕获自动复位信号；注销等待回调退出。 */
  for (size_t i = 0u; i < 256u; i++) {
    ftun_thread_t producer;
    CHECK(ftun_poller_wait(&poller, 0, events, &count) == FTUN_OK && count == 0u);
    CHECK(ftun_thread_create(&producer, signal_waitable, handles[0]) == FTUN_OK);
    if (i % 2u == 0u) {
      uint64_t now, deadline;
      CHECK(ftun_monotonic_now(&now) == FTUN_OK); deadline = now + 5000u;
      do {
        CHECK(ftun_poller_wait(&poller, 1000, events, &count) == FTUN_OK);
        CHECK(ftun_monotonic_now(&now) == FTUN_OK && now < deadline);
      } while (count == 0u);
      CHECK(count == 1u && events[0].user == &io[0] && events[0].events == FTUN_POLLER_READ);
    }
    CHECK(ftun_poller_update(&poller, &io[0], 0u, NULL) == FTUN_OK);
    io[0].events = 0u;
    CHECK(ftun_thread_join(&producer) == FTUN_OK);
    CHECK(ledger.live == baseline);
    CHECK(ftun_poller_wait(&poller, 0, events, &count) == FTUN_OK && count == 0u);
    ResetEvent(handles[0]);
    CHECK(ftun_poller_update(&poller, &io[0], FTUN_POLLER_READ, &io[0]) == FTUN_OK);
    io[0].events = FTUN_POLLER_READ;
  }
  CHECK(ftun_poller_update(&poller, &io[0], FTUN_POLLER_ERROR, &io[0]) == FTUN_OK);
  io[0].events = FTUN_POLLER_ERROR;
  CHECK(SetEvent(handles[0]));
  CHECK(ftun_poller_wait(&poller, 0, events, &count) == FTUN_OK && count == 0u);
  CHECK(ftun_poller_update(&poller, &io[0], FTUN_POLLER_READ, &io[0]) == FTUN_OK);
  io[0].events = FTUN_POLLER_READ;
  CHECK(ftun_poller_wait(&poller, 1000, events, &count) == FTUN_OK && count == 1u);
  /* destroy 同样同步注销，设备事件随后才可关闭。 */
  ftun_poller_destroy(&poller);
  CHECK(CloseHandle(handles[0]) && ledger.live == 0u);
  puts("wepoll: 96 waitable fairness, allocation rejection and 256 in-flight signal/cancel rounds passed");
}

static void waitable_budget_contract(void)
{
  ftun_budget_t *root = budget(FTUN_POLLER_HANDLES + 2u);
  ftun_event_loop_t *loop = NULL;
  ftun_event_source_t *source = NULL;
  HANDLE event = CreateEventW(NULL, FALSE, FALSE, NULL);
  ftun_budget_usage_t before, usage;
  size_t calls = 0u, callbacks;
  CHECK(event != NULL);
  CHECK(ftun_event_loop_create_with_budget(NULL, root, 16u, &loop) == FTUN_OK);
  CHECK(ftun_event_backend_attach(loop) == FTUN_OK);
  CHECK(ftun_budget_get_usage(root, &before) == FTUN_OK);
  CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)event, FTUN_EVENT_WAITABLE | FTUN_EVENT_READ,
    ready, &calls, &source) == FTUN_OK);
  CHECK(ftun_event_loop_run_once(loop, false, 64u, &callbacks) == FTUN_E_LIMIT);
  CHECK(ftun_event_source_cancel(&source) == FTUN_OK);
  CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK &&
    usage.used_resources.memory_bytes == before.used_resources.memory_bytes &&
    usage.used_resources.descriptors == before.used_resources.descriptors);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK && ftun_event_backend_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK && ftun_budget_destroy(&root) == FTUN_OK);
  CHECK(CloseHandle(event));
}

int main(void)
{
  creation_failures(); waitable_contract(); waitable_budget_contract(); descriptor_failure(); budget_lifetime(); registration_capacity();
  puts("wepoll: concurrent owners, allocation/descriptor failures, deferred release and cancellation passed");
  return 0;
}
