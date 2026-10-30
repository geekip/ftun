#include "app/config/model.h"
#include "core/context.h"
#include "proxy/egress_internal.h"
#include "platform/clock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "egress resolution line %d: %s\n", __LINE__, #x); return 1; } } while (0)
static uint64_t now = 1000u;
static size_t fail_calloc = SIZE_MAX;
static ftun_status_t resolve_admission;
void *__real_calloc(size_t count, size_t bytes);
void *__wrap_calloc(size_t count, size_t bytes)
{
  if (fail_calloc != SIZE_MAX && fail_calloc-- == 0u) return NULL;
  return __real_calloc(count, bytes);
}
ftun_status_t __wrap_ftun_monotonic_now(uint64_t *out) { *out = now; return FTUN_OK; }

typedef struct {
  ftun_operation_t *operation;
  ftun_operation_token_t token;
  ftun_system_resolve_completion_fn completion;
  void *user;
  ftun_status_t status;
  unsigned int cancelled;
  uint8_t address;
  uint64_t expires;
  char domain[254];
} pending_t;
static pending_t pending[128];
static size_t queries, physical_opens;
static uint8_t physical_address;

static ftun_status_t cancel_pending(void *context)
{
  pending_t *item = context;
  item->cancelled++;
  return FTUN_E_AGAIN;
}
static void delivered(ftun_operation_t *operation, ftun_error_t error, void *context)
{
  pending_t *item = context;
  ftun_endpoint_t endpoint = {0};
  endpoint.kind = FTUN_ADDRESS_IPV4;
  endpoint.address[0] = 127u;
  endpoint.address[3] = item->address;
  ftun_system_resolve_result_t result = {{item->domain, strlen(item->domain)}, &endpoint, 1u, item->expires};
  item->operation = NULL;
  item->completion(operation, error, &result, item->user);
}
ftun_status_t __wrap_ftun_bootstrap_resolve(ftun_core_t *core,
  const ftun_bootstrap_request_t *request, ftun_operation_t **out)
{
  pending_t *item = &pending[queries++];
  ftun_status_t status;
  (void)core;
  if (resolve_admission != FTUN_OK) { *out = NULL; return resolve_admission; }
  item->completion = request->completion;
  item->user = request->user;
  memcpy(item->domain, request->domain.data, request->domain.length);
  status = ftun_operation_accept(request->operations, delivered, item, &item->operation, &item->token);
  if (status == FTUN_OK) status = ftun_operation_set_cancel_hook(item->operation, cancel_pending, item);
  *out = item->operation;
  return status;
}
static ftun_status_t physical(void *context, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *spec,
  ftun_operation_t **out)
{
  (void)context; (void)core; (void)spec;
  physical_opens++;
  physical_address = request->dial.endpoint.address[3];
  *out = NULL;
  return FTUN_E_REJECTED;
}

typedef struct {
  ftun_operation_t *operation;
  size_t calls;
  ftun_status_t status;
} result_t;
static void completed(ftun_operation_t *operation, ftun_error_t error,
  ftun_path_t *path, void *context)
{
  result_t *result = context;
  (void)operation; (void)path;
  result->operation = NULL;
  result->calls++;
  result->status = error.status;
}
typedef struct {
  ftun_budget_t *budget;
  ftun_core_t *core;
  ftun_operation_queue_t *operations;
  ftun_event_loop_t *loop;
  const ftun_egress_provider_t *egress;
  ftun_path_provider_t *provider;
  uint64_t generation;
} fixture_t;
static int plan(fixture_t *f, uint64_t generation)
{
  ftun_config_t config = {0};
  ftun_config_outbound_t node = {0};
  char *bootstrap[] = {"127.0.0.1:53"};
  ftun_path_provider_spec_t provider = {0};
  node.kind = FTUN_CONFIG_OUTBOUND_SOCKS5;
  node.name = "proxy"; node.server = "proxy.test:1080"; node.udp = true;
  config.outbounds = &node; config.outbound_count = 1u;
  config.dns.bootstrap = (ftun_config_string_list_t){bootstrap, 1u};
  ftun_config_bind_sections(&config);
  CHECK(ftun_proxy_egress_prepare(f->budget, &config, 0u, &f->egress) == FTUN_OK);
  ftun_proxy_egress_bind(f->egress, generation, NULL, NULL);
  f->generation = generation;
  ftun_proxy_egress_set_path(f->egress, (ftun_path_provider_ops_t){.open = physical}, NULL);
  provider.budget = f->budget; provider.generation = generation;
  provider.ops.open = ftun_egress_path_open;
  provider.context = (void *)f->egress;
  provider.max_pending = 64u; provider.max_paths = 64u;
  CHECK(ftun_path_provider_create(&provider, &f->provider) == FTUN_OK);
  return 0;
}
static int setup(fixture_t *f)
{
  CHECK(ftun_budget_create(NULL, 8u * 1024u * 1024u, 0u, &f->budget) == FTUN_OK);
  CHECK(ftun_core_context_create(f->budget, &f->core) == FTUN_OK);
  CHECK(ftun_operation_queue_create(f->budget, 256u, &f->operations) == FTUN_OK);
  CHECK(ftun_event_loop_create(f->core, &f->loop) == FTUN_OK);
  return plan(f, 7u);
}
static ftun_status_t open_request(fixture_t *f, result_t *result, uint64_t deadline, uint32_t mark)
{
  ftun_path_open_request_t request = {0};
  request.dial.loop = f->loop; request.dial.operations = f->operations;
  request.dial.budget = f->budget;
  request.dial.endpoint.kind = FTUN_ADDRESS_IPV4;
  request.dial.endpoint.address[0] = 127u; request.dial.endpoint.address[3] = 1u;
  request.dial.endpoint.port = 53u;
  request.dial.allowed = &request.dial.endpoint; request.dial.allowed_count = 1u;
  request.dial.deadline_ms = deadline;
  request.dial.protection.mark = mark;
  request.dial.purpose = FTUN_DIAL_PURPOSE_DNS;
  request.dial.transport = FTUN_DIAL_TCP;
  request.completion = completed; request.user = result; request.egress = 2u;
  return ftun_path_provider_open_channel(f->provider, f->core, f->generation, &request, &result->operation);
}
static int run(fixture_t *f)
{
  for (size_t i = 0u; i < 12u; i++) {
    size_t work;
    CHECK(ftun_operation_dispatch(f->operations, 256u, &work) == FTUN_OK);
    CHECK(ftun_event_loop_poll(f->loop, now, 256u, &work) == FTUN_OK);
  }
  return 0;
}
static int answer(fixture_t *f, size_t index, ftun_status_t status, uint8_t address, uint64_t expires)
{
  pending[index].address = address; pending[index].expires = expires;
  CHECK(ftun_operation_complete(pending[index].token, (ftun_error_t){status, 0u, 0}) == FTUN_OK);
  return run(f);
}
static int finish(fixture_t *f)
{
  ftun_budget_usage_t usage;
  CHECK(ftun_path_provider_stop_until(f->provider, UINT64_MAX) == FTUN_OK);
  CHECK(ftun_path_provider_destroy(&f->provider) == FTUN_OK);
  ftun_egress_release(&f->egress);
  CHECK(ftun_event_loop_stop(f->loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&f->loop) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&f->operations) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&f->core) == FTUN_OK);
  CHECK(ftun_budget_get_usage(f->budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u);
  CHECK(ftun_budget_destroy(&f->budget) == FTUN_OK);
  return 0;
}
static int sharing_and_ttl(void)
{
  fixture_t f = {0}; result_t a = {0}, b = {0}, c = {0};
  size_t base = queries;
  ftun_egress_info_t info;
  CHECK(setup(&f) == 0);
  CHECK(open_request(&f, &a, now + 100u, 0u) == FTUN_OK);
  CHECK(open_request(&f, &b, now + 10000u, 0u) == FTUN_OK && queries == base + 1u);
  now += 100u;
  CHECK(run(&f) == 0 && a.calls == 1u && a.status == FTUN_E_TIMEOUT && b.calls == 0u);
  CHECK(pending[base].cancelled == 0u);
  CHECK(answer(&f, base, FTUN_OK, 7u, now + 1000u) == 0);
  CHECK(b.calls == 1u && b.status == FTUN_E_REJECTED && physical_address == 7u);
  CHECK(open_request(&f, &c, now + 10000u, 0u) == FTUN_E_REJECTED);
  CHECK(run(&f) == 0 && queries == base + 1u && c.calls == 0u);
  now += 1000u;
  CHECK(f.egress->query(f.egress->context, 2u, 7u, &info) == FTUN_OK && info.state == FTUN_EGRESS_STATE_UNAVAILABLE);
  c = (result_t){0};
  CHECK(open_request(&f, &c, now + 10000u, 0u) == FTUN_OK && queries == base + 2u);
  CHECK(answer(&f, base + 1u, FTUN_OK, 8u, now) == 0 && physical_address == 8u);
  c = (result_t){0};
  CHECK(open_request(&f, &c, now + 10000u, 0u) == FTUN_OK && queries == base + 3u);
  CHECK(answer(&f, base + 2u, FTUN_OK, 9u, now + 1000u) == 0);
  CHECK(finish(&f) == 0);
  return 0;
}
static int cancellation_and_backoff(void)
{
  fixture_t f = {0}; result_t a = {0}, b = {0};
  size_t base = queries;
  CHECK(setup(&f) == 0);
  CHECK(open_request(&f, &a, now + 10000u, 0u) == FTUN_OK);
  CHECK(open_request(&f, &b, now + 10000u, 0u) == FTUN_OK);
  CHECK(ftun_operation_cancel(a.operation) == FTUN_E_AGAIN);
  CHECK(run(&f) == 0 && a.calls == 1u && a.status == FTUN_E_CANCELLED && pending[base].cancelled == 0u);
  CHECK(ftun_operation_cancel(b.operation) == FTUN_E_AGAIN);
  CHECK(run(&f) == 0 && b.calls == 1u && pending[base].cancelled == 1u);
  CHECK(answer(&f, base, FTUN_E_CANCELLED, 0u, 0u) == 0);
  a = (result_t){0};
  CHECK(open_request(&f, &a, now + 10000u, 0u) == FTUN_OK && queries == base + 2u);
  CHECK(answer(&f, base + 1u, FTUN_E_RESOLVE, 0u, 0u) == 0);
  CHECK(a.calls == 1u && a.status == FTUN_E_RESOLVE);
  for (size_t i = 0u; i < 20u; i++) {
    a = (result_t){0};
    CHECK(open_request(&f, &a, now + 10000u, 0u) == FTUN_E_RESOLVE && a.calls == 0u);
  }
  CHECK(queries == base + 2u);
  now += 500u;
  CHECK(open_request(&f, &a, now + 10000u, 0u) == FTUN_E_RESOLVE);
  now += 1000u;
  CHECK(open_request(&f, &a, now + 10000u, 0u) == FTUN_OK && queries == base + 3u);
  CHECK(answer(&f, base + 2u, FTUN_E_RESOLVE, 0u, 0u) == 0);
  now += 1300u;
  a = (result_t){0};
  CHECK(open_request(&f, &a, now + 10000u, 0u) == FTUN_E_RESOLVE && queries == base + 3u);
  now += 1500u;
  CHECK(open_request(&f, &a, now + 100u, 0u) == FTUN_OK && queries == base + 4u);
  now += 100u;
  CHECK(run(&f) == 0 && a.status == FTUN_E_TIMEOUT && pending[base + 3u].cancelled == 1u);
  CHECK(answer(&f, base + 3u, FTUN_E_CANCELLED, 0u, 0u) == 0);
  a = (result_t){0};
  CHECK(open_request(&f, &a, now + 10000u, 0u) == FTUN_E_TIMEOUT && queries == base + 4u);
  CHECK(finish(&f) == 0);
  return 0;
}
static int policy_and_generation(void)
{
  fixture_t a = {0}, b = {0}; result_t x = {0}, y = {0};
  size_t base = queries;
  CHECK(setup(&a) == 0 && setup(&b) == 0);
  CHECK(open_request(&a, &x, now + 10000u, 0u) == FTUN_OK);
  CHECK(open_request(&a, &y, now + 10000u, 1u) == FTUN_E_AGAIN);
  CHECK(open_request(&b, &y, now + 10000u, 0u) == FTUN_OK && queries == base + 2u);
  CHECK(answer(&a, base, FTUN_OK, 3u, now + 1000u) == 0);
  CHECK(y.calls == 0u);
  CHECK(answer(&b, base + 1u, FTUN_OK, 4u, now + 1000u) == 0);
  y = (result_t){0};
  CHECK(open_request(&a, &y, now + 10000u, 1u) == FTUN_OK && queries == base + 3u);
  CHECK(answer(&a, base + 2u, FTUN_OK, 5u, now + 1000u) == 0 && physical_address == 5u);
  CHECK(finish(&a) == 0 && finish(&b) == 0);
  return 0;
}
static int reload_and_admission(void)
{
  fixture_t f = {0}; result_t a = {0}, b = {0};
  size_t base = queries;
  CHECK(setup(&f) == 0);
  CHECK(open_request(&f, &a, now + 10000u, 0u) == FTUN_OK);
  fixture_t fresh = f;
  fresh.egress = NULL; fresh.provider = NULL;
  CHECK(plan(&fresh, 8u) == 0);
  CHECK(open_request(&fresh, &b, now + 10000u, 0u) == FTUN_OK && queries == base + 2u);
  CHECK(answer(&f, base, FTUN_OK, 10u, now + 10000u) == 0 && b.calls == 0u);
  ftun_egress_info_t info;
  CHECK(fresh.egress->query(fresh.egress->context, 2u, 8u, &info) == FTUN_OK && info.state == FTUN_EGRESS_STATE_UNAVAILABLE);
  CHECK(answer(&fresh, base + 1u, FTUN_OK, 11u, now + 10000u) == 0 && physical_address == 11u);
  CHECK(ftun_path_provider_stop_until(fresh.provider, UINT64_MAX) == FTUN_OK);
  CHECK(ftun_path_provider_destroy(&fresh.provider) == FTUN_OK);
  ftun_egress_release(&fresh.egress);
  CHECK(finish(&f) == 0);
  for (size_t i = 0u; i < 14u; i++) {
    f = (fixture_t){0}; a = (result_t){0};
    CHECK(setup(&f) == 0);
    fail_calloc = i;
    ftun_status_t status = open_request(&f, &a, now + 10000u, 0u);
    fail_calloc = SIZE_MAX;
    CHECK(status == FTUN_OK || status == FTUN_E_LIMIT);
    if (status == FTUN_OK) CHECK(answer(&f, queries - 1u, FTUN_OK, 12u, now + 10000u) == 0);
    else CHECK(a.calls == 0u && a.operation == NULL);
    CHECK(finish(&f) == 0);
  }
  f = (fixture_t){0}; a = (result_t){0};
  CHECK(setup(&f) == 0);
  resolve_admission = FTUN_E_LIMIT;
  CHECK(open_request(&f, &a, now + 10000u, 0u) == FTUN_E_LIMIT && a.calls == 0u);
  base = queries;
  CHECK(open_request(&f, &a, now + 10000u, 0u) == FTUN_E_LIMIT && queries == base);
  resolve_admission = FTUN_OK;
  CHECK(finish(&f) == 0);
  return 0;
}

int main(void)
{
  CHECK(sharing_and_ttl() == 0);
  CHECK(cancellation_and_backoff() == 0);
  CHECK(policy_and_generation() == 0);
  CHECK(reload_and_admission() == 0);
  printf("PASS shared resolution: queries=%zu physical=%zu, independent deadlines, cancellation, TTL0, expiry, backoff and isolation\n", queries, physical_opens);
  return 0;
}
