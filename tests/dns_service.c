#include "transport/socket_path.h"
#include "config/parser.h"
#include "core/budget.h"
#include "core/context.h"
#include "core/operation.h"
#include "core/service.h"
#include "dns/core_service.h"
#include "event/event.h"
#include "event/libev_adapter.h"
#include "util/time.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>

#define CHECK(expression) do { \
  if (!(expression)) { \
    fprintf(stderr, "DNS service contract failed: %s:%d: %s\n", \
            __FILE__, __LINE__, #expression); \
    return 1; \
  } \
} while (0)

static pthread_mutex_t clock_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool measure_busy;
static uint64_t fake_now;
static pthread_t clock_owner;
static bool blocked_call;

ftun_status_t __real_ftun_monotonic_now(uint64_t *out);
ftun_status_t __wrap_ftun_monotonic_now(uint64_t *out)
{
  bool controlled;
  (void)pthread_mutex_lock(&clock_mutex);
  controlled = measure_busy && pthread_equal(clock_owner, pthread_self());
  if (controlled) *out = fake_now;
  (void)pthread_mutex_unlock(&clock_mutex);
  return controlled ? FTUN_OK : __real_ftun_monotonic_now(out);
}

static void busy_callback(void *user)
{
  (void)user;
  (void)pthread_mutex_lock(&clock_mutex);
  fake_now += 7u;
  (void)pthread_mutex_unlock(&clock_mutex);
}

ftun_status_t __real_ftun_event_loop_run_once(ftun_event_loop_t *loop, bool block,
  size_t maximum, size_t *callbacks);
ftun_status_t __wrap_ftun_event_loop_run_once(ftun_event_loop_t *loop, bool block,
  size_t maximum, size_t *callbacks)
{
  bool controlled;
  (void)pthread_mutex_lock(&clock_mutex);
  controlled = measure_busy && pthread_equal(clock_owner, pthread_self());
  if (controlled) {
    blocked_call = block;
    fake_now += block ? 1000u : 5u;
  }
  (void)pthread_mutex_unlock(&clock_mutex);
  if (controlled) {
    ftun_status_t status = ftun_event_defer(loop, busy_callback, NULL);
    if (status != FTUN_OK) return status;
    /* 只控制 backend 等待与回调耗时，派发/usage 使用真实 Event 实现。 */
    block = false;
  }
  return __real_ftun_event_loop_run_once(loop, block, maximum, callbacks);
}

static int busy_accounting(ftun_core_service_t *service)
{
  ftun_core_service_run_usage_t usage;
  (void)pthread_mutex_lock(&clock_mutex);
  clock_owner = pthread_self();
  fake_now = 10000u;
  measure_busy = true;
  (void)pthread_mutex_unlock(&clock_mutex);
  CHECK(ftun_core_service_run_once(service, true, &usage) == FTUN_OK);
  printf("DNS busy: blocking=%u elapsed=%llu busy=%llu work=%zu\n", blocked_call,
    (unsigned long long)(fake_now - 10000u), (unsigned long long)usage.busy_ms, usage.work);
  CHECK(blocked_call && fake_now == 11007u && usage.busy_ms == 7u && usage.work >= 1u);
  CHECK(ftun_core_service_run_once(service, false, &usage) == FTUN_OK);
  CHECK(!blocked_call && fake_now == 11019u && usage.busy_ms == 12u && usage.work >= 1u);
  (void)pthread_mutex_lock(&clock_mutex);
  measure_busy = false;
  (void)pthread_mutex_unlock(&clock_mutex);
  return 0;
}

static uint16_t reserve_port(void)
{
  struct sockaddr_in address;
  socklen_t length = (socklen_t)sizeof(address);
  int descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (descriptor < 0) return 0u;
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(descriptor, (const struct sockaddr *)&address, length) != 0 ||
      getsockname(descriptor, (struct sockaddr *)&address, &length) != 0) {
    (void)close(descriptor);
    return 0u;
  }
  (void)close(descriptor);
  return ntohs(address.sin_port);
}

static ftun_config_t *make_config(uint16_t port)
{
  char json[1024];
  ftun_bytes_t bytes;
  ftun_config_t *config = NULL;
  int written = snprintf(json, sizeof(json),
    "{\"dns\":{\"enable\":true,\"cache\":true,"
    "\"default-server\":\"real\",\"listeners\":[{"
    "\"listen\":\"127.0.0.1:%u\",\"server\":\"real\"}],"
    "\"servers\":[{"
    "\"name\":\"real\",\"type\":\"udp\","
    "\"address\":[\"192.0.2.53:53\"],"
    "\"outbound\":\"DIRECT\"}]}}", (unsigned int)port);
  if (written <= 0 || (size_t)written >= sizeof(json)) return NULL;
  bytes.data = (const uint8_t *)json;
  bytes.length = (size_t)written;
  if (ftun_config_parse(bytes, &config) != FTUN_OK) return NULL;
  return config;
}

int main(void)
{
  ftun_budget_t *budget = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_core_t *core = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_config_t *initial = NULL;
  ftun_config_t *reload = NULL;
  ftun_core_service_t service;
  ftun_core_service_plan_t plan;
  ftun_core_service_run_usage_t usage;
  ftun_core_service_binding_t erased;
  ftun_dns_service_binding_t binding;
  ftun_dns_service_slot_t slot;
  ftun_dns_runtime_t *first = NULL;
  ftun_dns_runtime_t *second = NULL;
  uint16_t port = reserve_port();

  memset(&service, 0, sizeof(service));
  memset(&plan, 0, sizeof(plan));
  memset(&usage, 0, sizeof(usage));
  memset(&binding, 0, sizeof(binding));
  memset(&slot, 0, sizeof(slot));
  CHECK(port != 0u);
  initial = make_config(port);
  reload = make_config(port);
  CHECK(initial != NULL && reload != NULL);
  CHECK(ftun_budget_create(NULL, 16u * 1024u * 1024u, 1024u, &budget) ==
        FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 512u, &operations) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_event_loop_create_with_capacity(core, 256u, &loop) == FTUN_OK);
  CHECK(ftun_libev_attach(loop) == FTUN_OK);

  binding.loop = loop;
  binding.slot = &slot;
  binding.path.open = ftun_socket_path_open;
  erased.value = &binding;
  erased.size = sizeof(binding);
  CHECK(ftun_dns_service_binding_valid(&binding));
  CHECK(ftun_core_service_plan_prepare(&ftun_dns_core_service, budget, initial, 0u,
                                       &plan) == FTUN_OK);
  CHECK(ftun_core_service_prepare(&service, &ftun_dns_core_service, core,
    budget, operations, &erased, initial, 1u) == FTUN_OK);
  CHECK(slot.active == NULL && !slot.accepting && slot.generation == 0u);
  CHECK(ftun_core_service_activate(&service) == FTUN_OK);
  CHECK(ftun_dns_service_slot_get(&slot, &first) == FTUN_OK &&
        first != NULL && slot.generation == 1u && slot.accepting);
  CHECK(ftun_core_service_run_once(&service, false, &usage) == FTUN_OK);
  CHECK(busy_accounting(&service) == 0);
  CHECK(ftun_core_service_plan_destroy(&plan) == FTUN_OK);

  CHECK(ftun_core_service_plan_prepare(&ftun_dns_core_service, budget, reload, 0u,
                                       &plan) == FTUN_OK);
  CHECK(ftun_core_service_reload_prepare_planned(
    &service, reload, 2u, &plan) == FTUN_OK);
  CHECK(slot.active == first && slot.generation == 1u && slot.accepting);
  CHECK(ftun_core_service_reload_commit(&service, 2u) == FTUN_OK);
  CHECK(ftun_dns_service_slot_get(&slot, &second) == FTUN_OK &&
        second != NULL && second != first && slot.generation == 2u);
  CHECK(ftun_core_service_plan_destroy(&plan) == FTUN_OK);
  CHECK(ftun_core_service_run_once(&service, false, &usage) == FTUN_OK);

  CHECK(ftun_core_service_quiesce(&service) == FTUN_OK);
  CHECK(ftun_dns_service_slot_get(&slot, &second) == FTUN_E_AGAIN &&
        second == NULL && !slot.accepting);
  CHECK(ftun_core_service_drain_until(&service, UINT64_MAX) == FTUN_OK);
  CHECK(ftun_core_service_destroy_until(&service, UINT64_MAX) == FTUN_OK);
  CHECK(slot.active == NULL && slot.generation == 0u && !slot.accepting);

  CHECK(ftun_config_destroy(&initial) == FTUN_OK);
  CHECK(ftun_config_destroy(&reload) == FTUN_OK);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_libev_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}
