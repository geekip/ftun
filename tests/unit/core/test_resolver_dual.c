#include "core/context.h"
#include "core/operation.h"
#include "libs/resolver/resolver.h"
#include "platform/clock.h"
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "dual resolver failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

typedef struct {
  ftun_operation_t *operation;
  ftun_operation_token_t token;
  ftun_system_resolve_completion_fn completion;
  void *user;
  uint16_t type;
  ftun_status_t admission;
  size_t cancels;
  bool invalid;
  char domain[64];
} child_t;
typedef struct {
  ftun_operation_queue_t *queue;
  child_t children[2];
  size_t starts;
  uint64_t deadline;
} backend_t;
typedef struct {
  size_t calls, count;
  ftun_status_t status;
  ftun_endpoint_t addresses[2];
} result_t;

static ftun_status_t cancel_child(void *user)
{
  child_t *child = user;
  child->cancels++;
  return FTUN_E_AGAIN;
}
static void child_done(ftun_operation_t *operation, ftun_error_t error, void *user)
{
  child_t *child = user;
  ftun_endpoint_t endpoint = {0};
  ftun_system_resolve_result_t result = {{child->domain, strlen(child->domain)}, &endpoint, 1u};
  if (child->invalid) result.addresses = NULL;
  endpoint.kind = child->type == 28u ? FTUN_ADDRESS_IPV6 : FTUN_ADDRESS_IPV4;
  endpoint.address[child->type == 28u ? 15u : 3u] = 1u;
  child->operation = NULL;
  child->completion(operation, error, &result, child->user);
}
static ftun_status_t start_child(void *user, ftun_core_t *core,
  const ftun_resolver_provider_request_t *request, ftun_operation_t **out)
{
  backend_t *backend = user;
  size_t index = backend->starts++;
  child_t *child = &backend->children[index];
  (void)core;
  *out = NULL;
  if (index >= 2u || request->system.ipv6 || request->system.deadline_ms != backend->deadline) return FTUN_E_STATE_CORRUPT;
  child->type = request->system.query_type;
  child->completion = request->system.completion;
  child->user = request->system.user;
  memcpy(child->domain, request->system.domain.data, request->system.domain.length);
  child->domain[request->system.domain.length] = '\0';
  if (child->admission != FTUN_OK) return child->admission;
  ftun_status_t status = ftun_operation_accept(backend->queue, child_done, child, out, &child->token);
  if (status != FTUN_OK) return status;
  child->operation = *out;
  return ftun_operation_set_cancel_hook(*out, cancel_child, child);
}
static void done(ftun_operation_t *operation, ftun_error_t error,
  const ftun_system_resolve_result_t *answer, void *user)
{
  result_t *result = user;
  (void)operation;
  result->calls++;
  result->status = error.status;
  if (error.status == FTUN_OK && answer != NULL && answer->address_count <= 2u) {
    result->count = answer->address_count;
    memcpy(result->addresses, answer->addresses, answer->address_count * sizeof(*answer->addresses));
    if (answer->domain.length != 9u || memcmp(answer->domain.data, "dual.test", 9u)) result->status = FTUN_E_STATE_CORRUPT;
  }
}

static int run_case(unsigned int scenario)
{
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_operation_queue_t *queue = NULL;
  ftun_resolver_provider_t *provider = NULL;
  ftun_operation_t *operation = NULL;
  ftun_resolver_provider_spec_t spec = {0};
  ftun_resolver_provider_request_t request = {0};
  ftun_budget_usage_t baseline, usage;
  ftun_reservation_t hold = {0};
  backend_t backend = {0};
  result_t result = {0};
  char domain[] = "dual.test";
  size_t dispatched;
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 128u, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_event_loop_create(core, &loop) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 8u, &queue) == FTUN_OK);
  backend.queue = queue;
  CHECK(ftun_monotonic_now(&backend.deadline) == FTUN_OK);
  backend.deadline += 5000u;
  spec.budget = budget; spec.generation = 1u;
  spec.ops.start = start_child; spec.context = &backend;
  CHECK(ftun_resolver_provider_create(&spec, &provider) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &baseline) == FTUN_OK);
  request.generation = 1u; request.loop = loop; request.operations = queue;
  request.purpose = FTUN_DIAL_PURPOSE_BUSINESS;
  request.requested_domain = FTUN_DIAL_DOMAIN_UNDERLAY;
  request.system.budget = budget;
  request.system.domain = (ftun_string_t){domain, 9u};
  request.system.ipv6 = true;
  request.system.deadline_ms = backend.deadline;
  request.system.completion = done; request.system.user = &result;
  if (scenario == 4u) backend.children[0].admission = FTUN_E_LIMIT;
  if (scenario == 6u) backend.children[0].invalid = true;
  if (scenario == 5u) {
    CHECK(ftun_budget_reserve(budget, baseline.normal_available_resources.memory_bytes, &hold) == FTUN_OK);
    CHECK(ftun_resolver_provider_start(provider, core, &request, &operation) == FTUN_E_LIMIT);
    CHECK(operation == NULL && backend.starts == 0u && result.calls == 0u);
    ftun_reservation_release(&hold);
  } else {
    CHECK(ftun_resolver_provider_start(provider, core, &request, &operation) == FTUN_OK);
    CHECK(backend.starts == 2u && backend.children[0].type == 1u && backend.children[1].type == 28u);
    memset(domain, 'x', 9u);
    if (scenario == 3u) {
      /* A 已排入终结队列但尚未派发；取消仍必须等待 AAAA 的迟到结果。 */
      CHECK(ftun_operation_complete(backend.children[0].token, (ftun_error_t){FTUN_OK, 0u, 0}) == FTUN_OK);
      CHECK(ftun_operation_cancel(operation) == FTUN_E_AGAIN);
      CHECK(result.calls == 0u && backend.children[1].cancels == 1u);
    }
    CHECK(ftun_operation_complete(backend.children[1].token, (ftun_error_t){FTUN_OK, 0u, 0}) == FTUN_OK);
    if (scenario != 3u && scenario != 4u) {
      CHECK(ftun_operation_dispatch(queue, 1u, &dispatched) == FTUN_OK && result.calls == 0u);
      CHECK(ftun_operation_complete(backend.children[0].token,
        (ftun_error_t){scenario == 1u ? FTUN_E_RESOLVE : scenario == 2u ? FTUN_E_IO : FTUN_OK, 0u, 0}) == FTUN_OK);
    }
    CHECK(ftun_operation_dispatch(queue, 8u, &dispatched) == FTUN_OK);
    CHECK(result.calls == 1u);
    CHECK(result.status == (scenario == 2u ? FTUN_E_IO : scenario == 3u ? FTUN_E_CANCELLED : scenario == 4u ? FTUN_E_LIMIT : scenario == 6u ? FTUN_E_STATE_CORRUPT : FTUN_OK));
    if (scenario == 0u) CHECK(result.count == 2u && result.addresses[0].kind == FTUN_ADDRESS_IPV4 && result.addresses[1].kind == FTUN_ADDRESS_IPV6 && result.addresses[1].address[15] == 1u);
    if (scenario == 1u) CHECK(result.count == 1u && result.addresses[0].kind == FTUN_ADDRESS_IPV6);
  }
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == baseline.used_resources.memory_bytes);
  CHECK(ftun_resolver_provider_stop_until(provider, UINT64_MAX) == FTUN_OK);
  CHECK(ftun_resolver_provider_destroy(&provider) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(queue) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&queue) == FTUN_OK);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}
int main(void)
{
  for (unsigned int scenario = 0u; scenario < 7u; scenario++) CHECK(run_case(scenario) == 0);
  puts("dual resolver: A/AAAA ordering, single-family answers, fatal errors, late cancellation and admission cleanup passed");
  return 0;
}
