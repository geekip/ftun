#include "core/context.h"
#include "core/operation.h"
#include "network/resolver.h"
#if defined(FTUN_EXPECT_PROXY)
#include "proxy/bindings.h"
#endif
#include "transport/path.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(expression) do { \
  if (!(expression)) { \
    fprintf(stderr, "provider binding contract failed: %s:%d: %s\n", \
            __FILE__, __LINE__, #expression); \
    return 1; \
  } \
} while (0)

typedef struct {
  ftun_operation_queue_t *operations;
  size_t starts;
  size_t completions;
  size_t reload_prepares;
  size_t reload_commits;
  size_t reload_aborts;
  size_t quiesces;
  size_t stops;
  bool stop_again;
} provider_state_t;

static void operation_completed(ftun_operation_t *operation,
                                ftun_error_t error, void *user)
{
  provider_state_t *state = (provider_state_t *)user;
  (void)operation;
  if (error.status == FTUN_E_CANCELLED) state->completions++;
}

static ftun_status_t provider_accept(provider_state_t *state,
                                     ftun_operation_t **out)
{
  ftun_operation_token_t completion;
  ftun_status_t status = ftun_operation_accept(
    state->operations, operation_completed, state, out, &completion);
  (void)completion;
  if (status == FTUN_OK) state->starts++;
  return status;
}

static ftun_status_t resolver_start(
  void *context, ftun_core_t *core,
  const ftun_resolver_provider_request_t *request, ftun_operation_t **out)
{
  (void)core;
  (void)request;
  return provider_accept((provider_state_t *)context, out);
}

static ftun_status_t path_start(void *context, ftun_core_t *core,
                                const ftun_dial_request_t *request,
                                ftun_operation_t **out)
{
  (void)core;
  (void)request;
  return provider_accept((provider_state_t *)context, out);
}

static ftun_status_t reload_prepare(void *context, uint64_t generation)
{
  provider_state_t *state = (provider_state_t *)context;
  if (generation == 0u) return FTUN_E_INVALID;
  state->reload_prepares++;
  return FTUN_OK;
}

static void reload_commit(void *context, uint64_t generation)
{
  provider_state_t *state = (provider_state_t *)context;
  if (generation != 0u) state->reload_commits++;
}

static void reload_abort(void *context, uint64_t generation)
{
  provider_state_t *state = (provider_state_t *)context;
  if (generation != 0u) state->reload_aborts++;
}

static ftun_status_t provider_quiesce(void *context)
{
  ((provider_state_t *)context)->quiesces++;
  return FTUN_OK;
}

static ftun_status_t provider_stop(void *context, uint64_t deadline_ms)
{
  provider_state_t *state = (provider_state_t *)context;
  (void)deadline_ms;
  state->stops++;
  if (state->stop_again) {
    state->stop_again = false;
    return FTUN_E_AGAIN;
  }
  return FTUN_OK;
}

static void resolver_completed(
  ftun_operation_t *operation, ftun_error_t error,
  const ftun_system_resolve_result_t *result, void *user)
{
  (void)operation;
  (void)error;
  (void)result;
  (void)user;
}

static void dial_completed(ftun_operation_t *operation, ftun_error_t error,
                           const ftun_dial_result_t *result, void *user)
{
  (void)operation;
  (void)error;
  (void)result;
  (void)user;
}

static int cancel_and_dispatch(ftun_operation_queue_t *operations,
                               ftun_operation_t *operation)
{
  size_t dispatched = 0u;
  return ftun_operation_cancel(operation) == FTUN_OK &&
    ftun_operation_dispatch(operations, 1u, &dispatched) == FTUN_OK &&
    dispatched == 1u;
}

int main(void)
{
  ftun_budget_t *budget = NULL;
  ftun_budget_t *foreign_budget = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_core_t *core = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_resolver_provider_t *resolver = NULL;
  ftun_path_provider_t *path = NULL;
  ftun_operation_t *operation = NULL;
  ftun_resolver_provider_spec_t resolver_spec;
  ftun_path_provider_spec_t path_spec;
  ftun_resolver_provider_request_t resolver_request;
  ftun_resolver_provider_info_t resolver_info;
  ftun_dial_request_t dial_request;
  ftun_path_provider_info_t path_info;
#if defined(FTUN_EXPECT_PROXY)
  ftun_proxy_bindings_t bindings;
  ftun_dns_service_slot_t dns_slot;
  ftun_proxy_dns_runtime_adapter_t dns_adapter;
  ftun_fakeip_service_t *fakeip = NULL;
  ftun_l3_provider_t invalid_l3;
  ftun_bootstrap_request_t dns_request;
  ftun_operation_t *dns_operation = (ftun_operation_t *)(uintptr_t)1;
#endif
  provider_state_t resolver_state;
  provider_state_t path_state;

  memset(&resolver_spec, 0, sizeof(resolver_spec));
  memset(&path_spec, 0, sizeof(path_spec));
  memset(&resolver_request, 0, sizeof(resolver_request));
  memset(&dial_request, 0, sizeof(dial_request));
  memset(&resolver_state, 0, sizeof(resolver_state));
  memset(&path_state, 0, sizeof(path_state));
#if defined(FTUN_EXPECT_PROXY)
  memset(&bindings, 0, sizeof(bindings));
  memset(&dns_slot, 0, sizeof(dns_slot));
  memset(&dns_adapter, 0, sizeof(dns_adapter));
  memset(&dns_request, 0, sizeof(dns_request));
  memset(&invalid_l3, 0, sizeof(invalid_l3));
#endif
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 64u, &budget) == FTUN_OK);
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 64u, &foreign_budget) ==
        FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 8u, &operations) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_event_loop_create(core, &loop) == FTUN_OK);
  resolver_state.operations = operations;
  path_state.operations = operations;

#if defined(FTUN_EXPECT_PROXY)
  bindings.loop = loop;
  bindings.resolver.start = resolver_start;
  bindings.path.start = path_start;
  dns_adapter.core = core;
  dns_adapter.slot = &dns_slot;
  dns_adapter.fakeip_slot = &fakeip;
  bindings.dns = &dns_adapter;
  bindings.fakeip_slot = &fakeip;
  CHECK(ftun_proxy_dns_runtime_adapter_valid(&dns_adapter));
  CHECK(!ftun_proxy_dns_has_hijack(&dns_adapter));
  CHECK(ftun_proxy_dns_hijack_tcp(&dns_adapter, -1) == FTUN_E_AGAIN);
  CHECK(ftun_proxy_dns_hijack_udp(&dns_adapter, NULL, NULL, NULL) ==
        FTUN_E_AGAIN);
  CHECK(ftun_proxy_dns_resolve_named(&dns_adapter, &dns_request,
        (ftun_string_t){"named", 5u}, &dns_operation) == FTUN_E_AGAIN &&
        dns_operation == NULL);
  CHECK(ftun_proxy_bindings_valid(&bindings));
  invalid_l3.generation = 1u;
  bindings.l3 = &invalid_l3;
  CHECK(!ftun_proxy_bindings_valid(&bindings));
  memset(&invalid_l3, 0, sizeof(invalid_l3));
  bindings.l3_deferred = true;
  CHECK(ftun_proxy_bindings_valid(&bindings));
  bindings.l3 = NULL;
  CHECK(!ftun_proxy_bindings_valid(&bindings));
  bindings.l3_deferred = false;
#endif

  resolver_spec.budget = budget;
  resolver_spec.generation = 6u;
  resolver_spec.context = &resolver_state;
  resolver_spec.ops.start = resolver_start;
  resolver_spec.ops.reload_prepare = reload_prepare;
  resolver_spec.ops.reload_commit = reload_commit;
  resolver_spec.ops.reload_abort = reload_abort;
  resolver_spec.ops.quiesce = provider_quiesce;
  resolver_spec.ops.stop_until = provider_stop;
  CHECK(ftun_resolver_provider_create(&resolver_spec, &resolver) == FTUN_OK);
  resolver_request.system.budget = budget;
  resolver_request.system.domain = (ftun_string_t){"node.example", 12u};
  resolver_request.system.deadline_ms = 100u;
  resolver_request.system.completion = resolver_completed;
  resolver_request.generation = 5u;
  resolver_request.purpose = FTUN_DIAL_PURPOSE_MESH_CONTROL;
  resolver_request.requested_domain = FTUN_DIAL_DOMAIN_UNDERLAY;
  resolver_request.system.budget = foreign_budget;
  CHECK(ftun_resolver_provider_start(resolver, core, &resolver_request,
        &operation) == FTUN_E_STALE && operation == NULL);
  resolver_request.system.budget = budget;
  CHECK(ftun_resolver_provider_start(resolver, core, &resolver_request,
        &operation) == FTUN_E_STALE && operation == NULL);
  resolver_request.generation = 6u;
  resolver_request.system.budget = foreign_budget;
  CHECK(ftun_resolver_provider_start(resolver, core, &resolver_request,
        &operation) == FTUN_E_REJECTED && operation == NULL);
  resolver_request.system.budget = budget;
  CHECK(ftun_resolver_provider_start(resolver, core, &resolver_request,
        &operation) == FTUN_OK && operation != NULL);
  CHECK(cancel_and_dispatch(operations, operation));
  CHECK(ftun_resolver_provider_reload_prepare(resolver, 7u) == FTUN_OK);
  CHECK(ftun_resolver_provider_reload_abort(resolver) == FTUN_OK);
  CHECK(ftun_resolver_provider_reload_prepare(resolver, 7u) == FTUN_OK);
  CHECK(ftun_resolver_provider_reload_commit(resolver, 7u) == FTUN_OK);
  CHECK(ftun_resolver_provider_get_info(resolver, &resolver_info) == FTUN_OK &&
        resolver_info.generation == 7u && resolver_info.accepting &&
        !resolver_info.reload_prepared);
  resolver_request.generation = 6u;
  CHECK(ftun_resolver_provider_start(resolver, core, &resolver_request,
        &operation) == FTUN_E_STALE && operation == NULL);
  CHECK(ftun_resolver_provider_quiesce(resolver) == FTUN_OK);
  resolver_request.generation = 7u;
  CHECK(ftun_resolver_provider_start(resolver, core, &resolver_request,
        &operation) == FTUN_E_CANCELLED && operation == NULL);
  CHECK(ftun_resolver_provider_reload_prepare(resolver, 8u) ==
        FTUN_E_CANCELLED);
  CHECK(ftun_resolver_provider_destroy(&resolver) == FTUN_E_AGAIN);
  resolver_state.stop_again = true;
  CHECK(ftun_resolver_provider_stop_until(resolver, 0u) == FTUN_E_INVALID);
  CHECK(ftun_resolver_provider_stop_until(resolver, 200u) == FTUN_E_AGAIN);
  CHECK(ftun_resolver_provider_stop_until(resolver, 200u) == FTUN_OK);
  CHECK(ftun_resolver_provider_destroy(&resolver) == FTUN_OK);
  CHECK(resolver_state.starts == 1u && resolver_state.completions == 1u &&
        resolver_state.reload_prepares == 2u &&
        resolver_state.reload_commits == 1u &&
        resolver_state.reload_aborts == 1u && resolver_state.quiesces == 1u &&
        resolver_state.stops == 2u);

  path_spec.budget = budget;
  path_spec.generation = 9u;
  path_spec.context = &path_state;
  path_spec.ops.start = path_start;
  path_spec.ops.reload_prepare = reload_prepare;
  path_spec.ops.reload_commit = reload_commit;
  path_spec.ops.reload_abort = reload_abort;
  path_spec.ops.quiesce = provider_quiesce;
  path_spec.ops.stop_until = provider_stop;
  CHECK(ftun_path_provider_create(&path_spec, &path) == FTUN_OK);
  dial_request.loop = (ftun_event_loop_t *)(uintptr_t)1;
  dial_request.operations = operations;
  dial_request.budget = budget;
  dial_request.network_generation = 9u;
  dial_request.requested_domain = FTUN_DIAL_DOMAIN_UNDERLAY;
  dial_request.transport = FTUN_DIAL_TCP;
  dial_request.purpose = FTUN_DIAL_PURPOSE_BUSINESS;
  dial_request.completion = dial_completed;
  CHECK(ftun_path_provider_open_datagram(path, core, &dial_request,
        &operation) == FTUN_E_INVALID && operation == NULL);
  CHECK(ftun_path_provider_open_stream(path, core, &dial_request,
        &operation) == FTUN_OK && operation != NULL);
  CHECK(cancel_and_dispatch(operations, operation));
  CHECK(ftun_path_provider_reload_prepare(path, 10u) == FTUN_OK);
  CHECK(ftun_path_provider_reload_commit(path, 10u) == FTUN_OK);
  CHECK(ftun_path_provider_get_info(path, &path_info) == FTUN_OK &&
        path_info.generation == 10u && path_info.accepting);
  dial_request.network_generation = 10u;
  dial_request.transport = FTUN_DIAL_UDP;
  dial_request.budget = foreign_budget;
  CHECK(ftun_path_provider_open_datagram(path, core, &dial_request,
        &operation) == FTUN_E_REJECTED && operation == NULL);
  dial_request.budget = budget;
  CHECK(ftun_path_provider_open_datagram(path, core, &dial_request,
        &operation) == FTUN_OK && operation != NULL);
  CHECK(cancel_and_dispatch(operations, operation));
  CHECK(ftun_path_provider_quiesce(path) == FTUN_OK);
  CHECK(ftun_path_provider_open_datagram(path, core, &dial_request,
        &operation) == FTUN_E_CANCELLED && operation == NULL);
  CHECK(ftun_path_provider_reload_prepare(path, 11u) == FTUN_E_CANCELLED);
  CHECK(ftun_path_provider_stop_until(path, 0u) == FTUN_E_INVALID);
  CHECK(ftun_path_provider_stop_until(path, 200u) == FTUN_OK);
  CHECK(ftun_path_provider_destroy(&path) == FTUN_OK);
  CHECK(path_state.starts == 2u && path_state.completions == 2u &&
        path_state.reload_prepares == 1u && path_state.reload_commits == 1u &&
        path_state.quiesces == 1u && path_state.stops == 1u);

  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(ftun_budget_destroy(&foreign_budget) == FTUN_OK);
  return 0;
}
