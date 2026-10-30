#include "core/context.h"
#include "core/operation.h"
#include "libs/resolver/resolver.h"
#include "platform/clock.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "Resolver provider failed: %s:%d: %s\n", __FILE__, __LINE__, #x); \
  return 1; } } while (0)

typedef struct {
  ftun_operation_queue_t *operations;
  ftun_operation_t *operation;
  ftun_operation_token_t token;
  ftun_system_resolve_completion_fn completion;
  void *user;
  ftun_status_t cancel_status;
  ftun_status_t admission_status;
  bool return_bad_operation;
  bool invalid_result;
  size_t starts;
  size_t cancels;
  uint64_t generation;
  ftun_resolver_source_t source;
  ftun_dial_purpose_t purpose;
  char domain[255];
  size_t domain_length;
} backend_t;

typedef struct {
  ftun_resolver_provider_t *provider;
  size_t calls;
  ftun_status_t status;
  bool observed_pending;
} result_t;

static ftun_status_t cancel(void *user)
{
  backend_t *backend = user;
  backend->cancels++;
  return backend->cancel_status;
}

static void completed(ftun_operation_t *operation, ftun_error_t error, void *user)
{
  backend_t *backend = user;
  ftun_endpoint_t address = {0};
  ftun_system_resolve_result_t result = {0};
  address.kind = FTUN_ADDRESS_IPV4;
  address.address[0] = 192u; address.address[1] = 0u;
  address.address[2] = 2u; address.address[3] = 53u;
  result.domain = (ftun_string_t){backend->domain, backend->domain_length};
  result.addresses = &address;
  result.address_count = backend->invalid_result ? 17u : 1u;
  backend->operation = NULL;
  backend->completion(operation, error, &result, backend->user);
}

static ftun_status_t start(void *context, ftun_core_t *core,
  const ftun_resolver_provider_request_t *request, ftun_operation_t **out)
{
  backend_t *backend = context;
  ftun_status_t status;
  (void)core;
  *out = NULL;
  if (backend->admission_status != FTUN_OK && !backend->return_bad_operation) {
    return backend->admission_status;
  }
  backend->completion = request->system.completion;
  backend->user = request->system.user;
  backend->generation = request->generation;
  backend->source = request->source;
  backend->purpose = request->purpose;
  memcpy(backend->domain, request->system.domain.data, request->system.domain.length);
  backend->domain_length = request->system.domain.length;
  status = ftun_operation_accept(backend->operations, completed, backend, out, &backend->token);
  if (status != FTUN_OK) return status;
  backend->operation = *out;
  status = ftun_operation_set_cancel_hook(*out, cancel, backend);
  if (status != FTUN_OK) { (void)ftun_operation_reject(out); return status; }
  backend->starts++;
  return backend->return_bad_operation ? backend->admission_status : FTUN_OK;
}

static void result_completed(ftun_operation_t *operation, ftun_error_t error,
  const ftun_system_resolve_result_t *answer, void *user)
{
  result_t *result = user;
  ftun_resolver_provider_info_t info;
  (void)operation;
  result->calls++;
  result->status = error.status;
  result->observed_pending = ftun_resolver_provider_get_info(result->provider, &info) == FTUN_OK && info.pending == 1u;
  if (error.status == FTUN_OK && (answer == NULL || answer->address_count != 1u)) result->status = FTUN_E_STATE_CORRUPT;
  if (error.status != FTUN_OK && answer != NULL) result->status = FTUN_E_STATE_CORRUPT;
}

int main(void)
{
  ftun_budget_t *budget = NULL, *foreign = NULL;
  ftun_core_t *core = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_resolver_provider_t *provider = NULL;
  ftun_resolver_scope_t *scope = NULL, *other = NULL;
  ftun_operation_t *operation = NULL;
  ftun_resolver_provider_spec_t spec = {0};
  ftun_resolver_provider_request_t request = {0};
  ftun_resolver_provider_info_t info;
  ftun_endpoint_t server = {0};
  ftun_budget_usage_t baseline, usage;
  backend_t backend = {0};
  result_t result = {0};
  uint64_t now;
  size_t dispatched;
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 128u, &budget) == FTUN_OK);
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 128u, &foreign) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_event_loop_create(core, &loop) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 8u, &operations) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &baseline) == FTUN_OK);
  backend.operations = operations;
  spec.budget = budget; spec.generation = 7u;
  spec.ops.start = start; spec.context = &backend;
  spec.max_pending = 1u; spec.max_scopes = 1u;
  CHECK(ftun_resolver_provider_create(&spec, &provider) == FTUN_OK);
  result.provider = provider;
  request.system.budget = budget;
  request.system.domain = (ftun_string_t){"node.example", 12u};
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  request.system.deadline_ms = now + 3000u;
  request.system.completion = result_completed; request.system.user = &result;
  request.generation = 7u; request.purpose = FTUN_DIAL_PURPOSE_BUSINESS;
  request.requested_domain = FTUN_DIAL_DOMAIN_UNDERLAY;
  request.loop = loop; request.operations = operations;
  CHECK(ftun_resolver_provider_scope(provider, 7u, &scope) == FTUN_OK);
  CHECK(ftun_resolver_provider_scope(provider, 7u, &other) == FTUN_E_LIMIT && other == NULL);
  CHECK(ftun_resolver_scope_retain(scope) == FTUN_OK);
  other = scope;
  ftun_resolver_scope_release(&other); CHECK(other == NULL);
  request.system.budget = foreign;
  CHECK(ftun_resolver_scope_start(scope, core, &request, &operation) == FTUN_E_REJECTED && operation == NULL);
  request.system.budget = budget;
  request.source = FTUN_RESOLVER_NAMED;
  CHECK(ftun_resolver_scope_start(scope, core, &request, &operation) == FTUN_E_INVALID && backend.starts == 0u);
  request.resolver_name = (ftun_string_t){"real", 4u};
  CHECK(ftun_resolver_scope_start(scope, core, &request, &operation) == FTUN_OK);
  CHECK(backend.source == FTUN_RESOLVER_NAMED && backend.purpose == FTUN_DIAL_PURPOSE_BUSINESS && backend.generation == 7u);
  CHECK(ftun_resolver_scope_start(scope, core, &request, &operation) == FTUN_E_LIMIT && operation == NULL);
  CHECK(ftun_resolver_provider_reload_prepare(provider, 8u) == FTUN_OK);
  CHECK(ftun_resolver_provider_reload_commit(provider, 8u) == FTUN_OK);
  CHECK(ftun_resolver_provider_start(provider, core, &request, &operation) == FTUN_E_STALE);
  CHECK(ftun_resolver_provider_scope(provider, 7u, &other) == FTUN_E_STALE && other == NULL);
  CHECK(ftun_operation_complete(backend.token, (ftun_error_t){FTUN_OK, 0u, 0}) == FTUN_OK);
  CHECK(ftun_operation_dispatch(operations, 8u, &dispatched) == FTUN_OK && dispatched == 1u);
  CHECK(result.calls == 1u && result.status == FTUN_OK && result.observed_pending);
  CHECK(ftun_resolver_provider_get_info(provider, &info) == FTUN_OK && info.pending == 0u && info.scopes == 1u);
  request.source = FTUN_RESOLVER_BOOTSTRAP;
  request.resolver_name = (ftun_string_t){NULL, 0u};
  server.kind = FTUN_ADDRESS_IPV4; server.address[0] = 127u; server.address[3] = 1u; server.port = 53u;
  request.servers = &server; request.server_count = 1u;
  backend.invalid_result = true;
  CHECK(ftun_resolver_scope_start(scope, core, &request, &operation) == FTUN_OK && backend.generation == 7u);
  CHECK(ftun_operation_complete(backend.token, (ftun_error_t){FTUN_OK, 0u, 0}) == FTUN_OK);
  CHECK(ftun_operation_dispatch(operations, 8u, &dispatched) == FTUN_OK);
  CHECK(result.calls == 2u && result.status == FTUN_E_STATE_CORRUPT);
  backend.invalid_result = false;
  backend.admission_status = FTUN_E_IO;
  CHECK(ftun_resolver_scope_start(scope, core, &request, &operation) == FTUN_E_IO && operation == NULL && result.calls == 2u);
  backend.return_bad_operation = true;
  CHECK(ftun_resolver_scope_start(scope, core, &request, &operation) == FTUN_E_STATE_CORRUPT && operation == NULL);
  CHECK(ftun_resolver_provider_get_info(provider, &info) == FTUN_OK && info.pending == 1u);
  CHECK(ftun_operation_dispatch(operations, 8u, &dispatched) == FTUN_OK && result.calls == 2u);
  backend.return_bad_operation = false; backend.admission_status = FTUN_OK;
  backend.cancel_status = FTUN_E_AGAIN;
  CHECK(ftun_resolver_scope_start(scope, core, &request, &operation) == FTUN_OK);
  CHECK(ftun_resolver_provider_stop_until(provider, now + 3000u) == FTUN_E_AGAIN);
  CHECK(ftun_resolver_provider_stop_until(provider, 1u) == FTUN_E_TIMEOUT);
  CHECK(ftun_resolver_provider_destroy(&provider) == FTUN_E_AGAIN && provider != NULL);
  CHECK(ftun_resolver_scope_start(scope, core, &request, &operation) == FTUN_E_CANCELLED && operation == NULL);
  /* hook 未能取消时，迟到的成功仍归已停止请求，不能写回用户为成功。 */
  CHECK(ftun_operation_complete(backend.token, (ftun_error_t){FTUN_OK, 0u, 0}) == FTUN_OK);
  CHECK(ftun_operation_dispatch(operations, 8u, &dispatched) == FTUN_OK);
  CHECK(result.calls == 3u && result.status == FTUN_E_CANCELLED && result.observed_pending);
  CHECK(ftun_resolver_provider_stop_until(provider, now + 3000u) == FTUN_OK);
  CHECK(ftun_resolver_provider_destroy(&provider) == FTUN_E_AGAIN);
  ftun_resolver_scope_release(&scope);
  CHECK(ftun_resolver_provider_destroy(&provider) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == baseline.used_resources.memory_bytes && usage.metadata_bytes == baseline.metadata_bytes);
  CHECK(ftun_operation_queue_stop(operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&foreign) == FTUN_OK && ftun_budget_destroy(&budget) == FTUN_OK);
  puts("Resolver provider generation, bounds, result and cancellation passed");
  return 0;
}
