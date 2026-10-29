#define _POSIX_C_SOURCE 200809L
#include "ftun/ftun.h"
#include "libs/tun/linux/routes.h"
#include "proxy/netstack/ingress.h"
#include "libs/tun/service.h"
#include "platform/clock.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define REQUIRE(value) do { if (!(value)) { \
  fprintf(stderr, "Async TUN runtime failed at %d: %s\n", __LINE__, #value); \
  abort(); } } while (0)

static ftun_linux_route_resource_t resources[FTUN_LINUX_ROUTE_MAX_RESOURCES];
static size_t resource_count, applies, removes, binds;
static ftun_linux_route_reply_t reply;
static bool has_reply, fail_open;
static ftun_tun_lease_t lease;
static ftun_tun_ingress_spec_t ingress;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
enum { REFRESH, REFRESH_READY, FAIL_REBUILD, FAILED, REBUILD, REBUILT };
typedef struct { int step; bool done, ready; } command_t;

static bool equal(const ftun_linux_route_resource_t *a, const ftun_linux_route_resource_t *b)
{
  return a->kind == b->kind && a->family == b->family &&
    strcmp(a->interface_name, b->interface_name) == 0 &&
    memcmp(a->address, b->address, sizeof(a->address)) == 0 &&
    a->prefix_length == b->prefix_length && a->table == b->table &&
    a->priority == b->priority && a->mark == b->mark &&
    a->mark_mask == b->mark_mask && a->metric == b->metric && a->protocol == b->protocol;
}

static ftun_status_t apply(void *context, const ftun_linux_route_resource_t *resource)
{
  size_t index;
  (void)context;
  for (index = 0u; index < resource_count; index++) {
    if (equal(resource, &resources[index])) return FTUN_E_REJECTED;
  }
  REQUIRE(resource_count < FTUN_LINUX_ROUTE_MAX_RESOURCES);
  resources[resource_count++] = *resource;
  applies++;
  return FTUN_OK;
}

static ftun_status_t remove_route(void *context, const ftun_linux_route_resource_t *resource)
{
  size_t index;
  (void)context;
  for (index = 0u; index < resource_count; index++) {
    if (equal(resource, &resources[index])) {
      resources[index] = resources[--resource_count];
      removes++;
      return FTUN_OK;
    }
  }
  return FTUN_E_STALE;
}

static ftun_status_t submit_route(void *context, const ftun_linux_route_request_t *request)
{
  size_t index;
  (void)context;
  REQUIRE(!has_reply);
  reply = (ftun_linux_route_reply_t){request->sequence, FTUN_OK, false};
  if (request->kind == FTUN_LINUX_ROUTE_REQUEST_QUERY) {
    for (index = 0u; index < resource_count; index++) {
      if (equal(&request->resource, &resources[index])) reply.present = true;
    }
  } else if (request->kind == FTUN_LINUX_ROUTE_REQUEST_ADD) {
    reply.status = apply(NULL, &request->resource);
  } else reply.status = remove_route(NULL, &request->resource);
  has_reply = true;
  return FTUN_OK;
}

static ftun_status_t receive_route(void *context, ftun_linux_route_reply_t *out)
{
  (void)context;
  if (!has_reply) return FTUN_E_AGAIN;
  *out = reply;
  has_reply = false;
  return FTUN_OK;
}

ftun_status_t __wrap_ftun_linux_route_prepare(const ftun_route_policy_t *policy,
  ftun_route_transaction_t **out)
{
  const ftun_linux_route_io_t io = {apply, remove_route, NULL};
  return ftun_linux_route_prepare_with_io(policy, &io, out);
}

ftun_status_t __wrap_ftun_linux_route_prepare_with_budget(ftun_budget_t *budget,
  const ftun_route_policy_t *policy, ftun_route_transaction_t **out)
{
  const ftun_linux_route_io_t io = {apply, remove_route, NULL};
  return ftun_linux_route_prepare_with_io_and_budget(budget, policy, &io, out);
}

ftun_status_t __wrap_ftun_linux_route_async_start(const ftun_route_policy_t *policy,
  ftun_event_loop_t *loop, uint64_t now_ms, uint64_t step_ms, uint64_t deadline_ms,
  ftun_linux_route_async_t **out)
{
  const ftun_linux_route_async_io_t io = {submit_route, receive_route, NULL};
  (void)loop;
  return ftun_linux_route_async_start_with_io(policy, &io, now_ms, step_ms, deadline_ms, 1u, out);
}

ftun_status_t __wrap_ftun_linux_route_async_adopt(ftun_route_transaction_t **source,
  ftun_event_loop_t *loop, uint64_t now_ms, uint64_t step_ms, uint64_t deadline_ms,
  ftun_linux_route_async_t **out)
{
  const ftun_linux_route_async_io_t io = {submit_route, receive_route, NULL};
  (void)loop;
  return ftun_linux_route_async_adopt_with_io(source, &io, now_ms, step_ms, deadline_ms, 1u, out);
}

ftun_status_t __real_ftun_l3_provider_acquire(const ftun_l3_provider_t *,
  uint64_t, const ftun_tun_consumer_spec_t *, ftun_tun_lease_t *);
ftun_status_t __wrap_ftun_l3_provider_acquire(const ftun_l3_provider_t *provider,
  uint64_t generation, const ftun_tun_consumer_spec_t *consumer, ftun_tun_lease_t *out)
{
  ftun_status_t status = __real_ftun_l3_provider_acquire(provider, generation, consumer, out);
  if (status == FTUN_OK) lease = *out;
  return status;
}

ftun_status_t __real_ftun_tun_ingress_bind(const ftun_tun_ingress_spec_t *, ftun_tun_ingress_context_t **);
ftun_status_t __wrap_ftun_tun_ingress_bind(const ftun_tun_ingress_spec_t *spec,
  ftun_tun_ingress_context_t **out)
{
  ftun_status_t status = __real_ftun_tun_ingress_bind(spec, out);
  if (status == FTUN_OK) { ingress = *spec; binds++; }
  return status;
}

bool ftun_test_tun_fail_open(void)
{
  bool fail = fail_open;
  fail_open = false;
  return fail;
}

static void execute(ftun_operation_t *operation, ftun_error_t error, void *context)
{
  command_t *command = context;
  ftun_tun_service_usage_t usage;
  uint8_t packet[20] = {0x45u};
  (void)operation;
  REQUIRE(error.status == FTUN_OK);
  REQUIRE(ftun_tun_service_get_usage(lease.service, &usage) == FTUN_OK);
  command->ready = true;
  if (command->step == REFRESH) {
    REQUIRE(binds == 1u && usage.accepting);
    REQUIRE(ftun_tun_service_refresh_network(lease.service, usage.network_generation) == FTUN_E_AGAIN);
  } else if (command->step == FAIL_REBUILD || command->step == REBUILD) {
    fail_open = command->step == FAIL_REBUILD;
    REQUIRE(ftun_tun_service_rebuild(lease.service) == FTUN_E_AGAIN);
  } else if (command->step == FAILED) {
    command->ready = !usage.accepting && usage.device.mtu == 0u && !fail_open;
    if (command->ready) REQUIRE(resource_count == 0u && binds == 2u);
  } else {
    command->ready = usage.accepting && binds == (command->step == REFRESH_READY ? 2u : 3u);
    if (command->ready) {
      REQUIRE(usage.network_generation == (command->step == REFRESH_READY ? 2u : 3u));
      REQUIRE(usage.device_generation == (command->step == REFRESH_READY ? 1u : 2u));
      REQUIRE(ftun_tun_service_write(lease, (ftun_bytes_t){packet, sizeof(packet)}) == FTUN_OK);
    }
  }
  if (command->step == REFRESH || command->step == FAIL_REBUILD || command->step == REBUILD) {
    REQUIRE(ingress.output(ingress.user, (ftun_bytes_t){packet, sizeof(packet)}) == FTUN_E_CANCELLED);
    REQUIRE(ftun_tun_service_get_usage(lease.service, &usage) == FTUN_OK && !usage.accepting);
  }
  (void)pthread_mutex_lock(&mutex);
  command->done = true;
  (void)pthread_cond_signal(&condition);
  (void)pthread_mutex_unlock(&mutex);
}

static void wait_step(ftun_core_t *core, int step)
{
  uint64_t now_ms, deadline;
  const struct timespec pause = {0, 1000000};
  REQUIRE(ftun_monotonic_now(&now_ms) == FTUN_OK);
  deadline = now_ms + 5000u;
  for (;;) {
    command_t command = {step, false, false};
    ftun_operation_t *operation = NULL;
    struct timespec until;
    REQUIRE(clock_gettime(CLOCK_REALTIME, &until) == 0);
    until.tv_sec += 5;
    REQUIRE(ftun_core_post(core, execute, &command, &operation) == FTUN_OK);
    (void)pthread_mutex_lock(&mutex);
    while (!command.done) REQUIRE(pthread_cond_timedwait(&condition, &mutex, &until) == 0);
    (void)pthread_mutex_unlock(&mutex);
    if (command.ready) return;
    REQUIRE(ftun_monotonic_now(&now_ms) == FTUN_OK && now_ms < deadline);
    (void)nanosleep(&pause, NULL);
  }
}

int ftun_test_tun_admission(ftun_core_t *core)
{
  wait_step(core, REFRESH);
  wait_step(core, REFRESH_READY);
  wait_step(core, FAIL_REBUILD);
  wait_step(core, FAILED);
  wait_step(core, REBUILD);
  wait_step(core, REBUILT);
  return 0;
}

int ftun_test_tun_async_verify(void)
{
  REQUIRE(resource_count == 0u && applies == removes && applies != 0u && !has_reply);
  puts("Async TUN refresh, failed reopen, recovery, Proxy rebinding and cleanup passed");
  return 0;
}
