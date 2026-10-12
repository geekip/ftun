#include "config/compile.h"
#include "config/model.h"
#include "config/parser.h"
#include "core/budget.h"
#include "core/operation.h"
#include "core/runtime.h"
#include "core/session.h"
#include "dns/resolver.h"
#include "transport/stream.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "dns resolver contract failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  int destroy_calls;
} stream_state_t;

typedef struct {
  ftun_operation_queue_t *operations;
  ftun_operation_t *operation;
  ftun_system_resolve_completion_fn completion;
  void *completion_user;
  ftun_endpoint_t addresses[FTUN_SYSTEM_RESOLVER_MAX_IPV4_RESULTS];
  size_t address_count;
  ftun_error_t result_error;
  ftun_status_t start_status;
  char server[256];
  char domain[FTUN_SYSTEM_RESOLVER_MAX_DOMAIN_BYTES + 1u];
  uint32_t mark;
  uint64_t deadline_ms;
  int system_calls;
  int bootstrap_calls;
  int server_calls;
} backend_state_t;

typedef struct {
  ftun_session_t *session;
  int calls;
  ftun_error_t error;
  ftun_status_t store_status;
  ftun_status_t session_status;
} completion_state_t;

typedef struct {
  int failures;
  int calls;
} cancel_state_t;

typedef struct {
  ftun_budget_t *budget;
  ftun_core_t *core;
  ftun_operation_queue_t *operations;
  ftun_stream_t *stream;
  stream_state_t stream_state;
  backend_state_t backend_state;
  ftun_resolver_backend_t backend;
} fixture_t;

static ftun_endpoint_t ipv4(uint8_t last, uint16_t port)
{
  ftun_endpoint_t endpoint;
  memset(&endpoint, 0, sizeof(endpoint));
  endpoint.kind = FTUN_ADDRESS_IPV4;
  endpoint.address[0] = 192u;
  endpoint.address[1] = 0u;
  endpoint.address[2] = 2u;
  endpoint.address[3] = last;
  endpoint.port = port;
  return endpoint;
}

static ftun_config_t *make_config(void)
{
  static const uint8_t json[] =
    "{\"dns\":{\"enable\":false},\"inbounds\":[{\"name\":\"in\","
    "\"type\":\"mixed\",\"listen\":\"127.0.0.1:10001\"}],"
    "\"rules\":[\"MATCH,DIRECT\"]}";
  ftun_config_t *config = NULL;
  ftun_feature_plan_t *plan = NULL;
  if (ftun_config_parse((ftun_bytes_t){json, sizeof(json) - 1u},
                        &config) != FTUN_OK) return NULL;
  if (ftun_config_compile(config, &plan) != FTUN_OK) {
    (void)ftun_config_destroy(&config);
    return NULL;
  }
  config->plan = plan;
  return config;
}

static ftun_status_t stream_write_start(void *user,
                                         ftun_stream_write_t *write,
                                         const ftun_buffer_slice_t *slice,
                                         size_t *accepted)
{
  (void)user;
  (void)write;
  (void)slice;
  *accepted = 0u;
  return FTUN_E_AGAIN;
}

static ftun_status_t stream_write_cancel(void *user,
                                          ftun_stream_write_t *write)
{
  (void)user;
  (void)write;
  return FTUN_OK;
}

static void stream_destroy(void *user)
{
  ((stream_state_t *)user)->destroy_calls++;
}

static void unused_stream_completion(ftun_operation_t *operation,
                                     ftun_error_t error, void *user)
{
  (void)operation;
  (void)error;
  (void)user;
}

static void resolver_completion(ftun_operation_t *operation,
                                ftun_error_t error,
                                const ftun_system_resolve_result_t *result,
                                void *user)
{
  completion_state_t *state = (completion_state_t *)user;
  state->calls++;
  state->store_status = FTUN_OK;
  if (error.status == FTUN_OK) {
    if (result == NULL) {
      state->store_status = FTUN_E_STATE_CORRUPT;
    } else {
      state->store_status = ftun_session_store_resolved(
        state->session, operation, result->addresses, result->address_count);
    }
    if (state->store_status != FTUN_OK) error.status = state->store_status;
  }
  state->error = error;
  state->session_status = ftun_session_operation_complete(
    state->session, operation, error);
}

static void backend_completed(ftun_operation_t *operation,
                              ftun_error_t error, void *user)
{
  backend_state_t *state = (backend_state_t *)user;
  ftun_system_resolve_result_t result;
  memset(&result, 0, sizeof(result));
  state->operation = NULL;
  result.domain.data = state->domain;
  result.domain.length = strlen(state->domain);
  if (error.status == FTUN_OK) {
    result.addresses = state->addresses;
    result.address_count = state->address_count;
  }
  state->completion(operation, error, &result, state->completion_user);
}

static ftun_status_t flaky_cancel(void *user)
{
  cancel_state_t *state = (cancel_state_t *)user;
  state->calls++;
  if (state->failures != 0) {
    state->failures--;
    return FTUN_E_AGAIN;
  }
  return FTUN_OK;
}

static ftun_status_t backend_start(
  backend_state_t *state, ftun_string_t domain, uint32_t mark,
  uint64_t deadline_ms, ftun_system_resolve_completion_fn completion,
  void *completion_user, ftun_operation_t **out)
{
  if (out != NULL) *out = NULL;
  if (state->start_status != FTUN_OK) return state->start_status;
  if (domain.data == NULL || domain.length >= sizeof(state->domain)) {
    return FTUN_E_INVALID;
  }
  memcpy(state->domain, domain.data, domain.length);
  state->domain[domain.length] = '\0';
  state->mark = mark;
  state->deadline_ms = deadline_ms;
  state->completion = completion;
  state->completion_user = completion_user;
  if (ftun_operation_accept(state->operations, backend_completed, state,
                            &state->operation) != FTUN_OK) return FTUN_E_LIMIT;
  *out = state->operation;
  return FTUN_OK;
}

static ftun_status_t backend_system(
  void *user, ftun_core_t *core,
  const ftun_system_resolve_request_t *request, ftun_operation_t **out)
{
  backend_state_t *state = (backend_state_t *)user;
  (void)core;
  state->system_calls++;
  return backend_start(state, request->domain, request->protection.mark,
                       request->deadline_ms, request->completion,
                       request->user, out);
}

static ftun_status_t backend_bootstrap(
  void *user, ftun_core_t *core, const ftun_bootstrap_request_t *request,
  ftun_operation_t **out)
{
  backend_state_t *state = (backend_state_t *)user;
  (void)core;
  state->bootstrap_calls++;
  return backend_start(state, request->domain, request->protection.mark,
                       request->deadline_ms, request->completion,
                       request->user, out);
}

static ftun_status_t backend_server(
  void *user, ftun_core_t *core, ftun_string_t server,
  const ftun_bootstrap_request_t *request, ftun_operation_t **out)
{
  backend_state_t *state = (backend_state_t *)user;
  (void)core;
  state->server_calls++;
  if (server.data == NULL || server.length >= sizeof(state->server)) {
    return FTUN_E_INVALID;
  }
  memcpy(state->server, server.data, server.length);
  state->server[server.length] = '\0';
  return backend_start(state, request->domain, request->protection.mark,
                       request->deadline_ms, request->completion,
                       request->user, out);
}

static int fixture_start(fixture_t *fixture)
{
  ftun_config_t *config;
  ftun_runtime_t *candidate = NULL;
  ftun_stream_options_t options;
  ftun_stream_backend_t stream_backend;
  memset(fixture, 0, sizeof(*fixture));
  if (ftun_budget_create(NULL, 1024u * 1024u, 0u,
                         &fixture->budget) != FTUN_OK) return 1;
  if (ftun_runtime_manager_create(fixture->budget, 2u,
                                  &fixture->core) != FTUN_OK) return 1;
  config = make_config();
  if (config == NULL ||
      ftun_runtime_prepare(fixture->core, config, &candidate) != FTUN_OK ||
      ftun_runtime_commit(fixture->core, &candidate) != FTUN_OK ||
      ftun_config_destroy(&config) != FTUN_OK) return 1;
  if (ftun_operation_queue_create(fixture->budget, 8u,
                                  &fixture->operations) != FTUN_OK) return 1;
  memset(&options, 0, sizeof(options));
  memset(&stream_backend, 0, sizeof(stream_backend));
  options.budget = fixture->budget;
  options.operations = fixture->operations;
  options.max_pending_writes = 1u;
  options.max_pending_bytes = 1024u;
  options.completion = unused_stream_completion;
  stream_backend.write_start = stream_write_start;
  stream_backend.write_cancel = stream_write_cancel;
  stream_backend.destroy = stream_destroy;
  stream_backend.context = &fixture->stream_state;
  if (ftun_stream_create(&options, &stream_backend,
                         &fixture->stream) != FTUN_OK) return 1;
  fixture->backend_state.operations = fixture->operations;
  fixture->backend.system_resolve = backend_system;
  fixture->backend.bootstrap_resolve = backend_bootstrap;
  fixture->backend.server_resolve = backend_server;
  fixture->backend.context = &fixture->backend_state;
  return 0;
}

static int fixture_stop(fixture_t *fixture)
{
  ftun_budget_usage_t usage;
  if (ftun_stream_stop(fixture->stream) != FTUN_OK) return 1;
  if (ftun_stream_destroy(&fixture->stream) != FTUN_OK) return 1;
  if (fixture->stream_state.destroy_calls != 1) return 1;
  if (ftun_operation_queue_destroy(&fixture->operations) != FTUN_OK) return 1;
  if (ftun_runtime_manager_destroy(&fixture->core) != FTUN_OK) return 1;
  if (ftun_budget_get_usage(fixture->budget, &usage) != FTUN_OK ||
      usage.used != 0u) return 1;
  return ftun_budget_destroy(&fixture->budget) == FTUN_OK ? 0 : 1;
}

static int open_session(fixture_t *fixture, const char *domain,
                        const ftun_endpoint_t *resolved,
                        size_t resolved_count, ftun_session_t **out)
{
  ftun_metadata_t metadata;
  memset(&metadata, 0, sizeof(metadata));
  metadata.known_fields = FTUN_META_PORT | FTUN_META_NETWORK |
                          FTUN_META_DOMAIN;
  metadata.network = 1u;
  metadata.original_target.kind = FTUN_ADDRESS_DOMAIN;
  metadata.original_target.domain.data = domain;
  metadata.original_target.domain.length = strlen(domain);
  metadata.original_target.port = 443u;
  metadata.domain = metadata.original_target.domain;
  metadata.domain_source = FTUN_DOMAIN_EXPLICIT;
  metadata.resolved = resolved;
  metadata.resolved_count = resolved_count;
  if (ftun_session_submit(fixture->core, &metadata, fixture->stream,
                          out) != FTUN_OK) return 1;
  return ftun_session_transition(*out, FTUN_SESSION_ROUTING, NULL) == FTUN_OK
    ? 0 : 1;
}

static int open_real_ip_session(fixture_t *fixture, const char *domain,
                                ftun_session_t **out)
{
  ftun_metadata_t metadata;
  memset(&metadata, 0, sizeof(metadata));
  metadata.known_fields = FTUN_META_PORT | FTUN_META_NETWORK |
                          FTUN_META_DOMAIN;
  metadata.network = 1u;
  metadata.original_target = ipv4(20u, 443u);
  metadata.domain.data = domain;
  metadata.domain.length = strlen(domain);
  metadata.domain_source = FTUN_DOMAIN_SNIFF;
  if (ftun_session_submit(fixture->core, &metadata, fixture->stream,
                          out) != FTUN_OK) return 1;
  return ftun_session_transition(*out, FTUN_SESSION_ROUTING, NULL) == FTUN_OK
    ? 0 : 1;
}

static void fill_request(ftun_resolve_request_t *request,
                         completion_state_t *completion,
                         fixture_t *fixture, ftun_session_t *session,
                         const char *domain)
{
  memset(request, 0, sizeof(*request));
  memset(completion, 0, sizeof(*completion));
  completion->session = session;
  request->session = session;
  request->dns_enabled = true;
  request->query.budget = fixture->budget;
  request->query.operations = fixture->operations;
  request->query.domain.data = domain;
  request->query.domain.length = strlen(domain);
  request->query.protection.mark = 91u;
  request->query.deadline_ms = 123456u;
  request->query.completion = resolver_completion;
  request->query.user = completion;
}

static int finish_backend(fixture_t *fixture, ftun_error_t error)
{
  size_t dispatched = 0u;
  if (ftun_operation_complete(fixture->backend_state.operation,
                              error) != FTUN_OK) return 1;
  if (ftun_operation_dispatch(fixture->operations, 1u,
                              &dispatched) != FTUN_OK) return 1;
  return dispatched == 1u ? 0 : 1;
}

static int close_session(ftun_session_t **session)
{
  if (*session == NULL) return 0;
  if (ftun_session_cancel(*session) != FTUN_OK) return 1;
  return ftun_session_destroy(session) == FTUN_OK ? 0 : 1;
}

static int test_system_store_and_reuse(void)
{
  fixture_t fixture;
  ftun_session_t *session = NULL;
  ftun_resolve_request_t request;
  ftun_operation_t *operation = NULL;
  completion_state_t completion;
  const ftun_metadata_t *metadata = NULL;
  ftun_route_result_t route;
  ftun_endpoint_t allowed;
  ftun_error_t success;
  const char domain[] = "route.example";
  memset(&success, 0, sizeof(success));
  CHECK(fixture_start(&fixture) == 0);
  CHECK(open_session(&fixture, domain, NULL, 0u, &session) == 0);
  fill_request(&request, &completion, &fixture, session, domain);
  request.dns_enabled = false;
  request.default_server.data = "ignored";
  request.default_server.length = 7u;
  request.query.server_count = FTUN_BOOTSTRAP_MAX_SERVERS + 1u;
  fixture.backend_state.addresses[0] = ipv4(1u, 0u);
  fixture.backend_state.addresses[1] = ipv4(2u, 0u);
  fixture.backend_state.address_count = 2u;
  CHECK(ftun_resolve_real_with_backend(fixture.core, &request,
        &fixture.backend, &operation) == FTUN_OK && operation != NULL);
  CHECK(fixture.backend_state.system_calls == 1 &&
        fixture.backend_state.bootstrap_calls == 0 &&
        fixture.backend_state.server_calls == 0 &&
        fixture.backend_state.mark == 91u &&
        fixture.backend_state.deadline_ms == 123456u);
  CHECK(ftun_session_transition(session, FTUN_SESSION_RESOLVING,
                                operation) == FTUN_OK);
  CHECK(finish_backend(&fixture, success) == 0);
  CHECK(completion.calls == 1 && completion.store_status == FTUN_OK &&
        completion.session_status == FTUN_OK &&
        completion.error.status == FTUN_OK);
  CHECK(ftun_session_transition(session, FTUN_SESSION_ROUTING, NULL) == FTUN_OK);
  CHECK(ftun_session_get_metadata(session, &metadata) == FTUN_OK &&
        metadata->resolved_count == 2u &&
        metadata->resolved[0].address[3] == 1u &&
        metadata->resolved[0].port == 443u &&
        metadata->resolved[1].address[3] == 2u &&
        metadata->resolved[1].port == 443u);
  operation = (ftun_operation_t *)(uintptr_t)1;
  CHECK(ftun_resolve_real_with_backend(fixture.core, &request,
        &fixture.backend, &operation) == FTUN_E_STALE && operation == NULL);
  CHECK(fixture.backend_state.system_calls == 1 &&
        fixture.backend_state.bootstrap_calls == 0 &&
        fixture.backend_state.server_calls == 0);
  allowed = metadata->resolved[1];
  memset(&route, 0, sizeof(route));
  route.kind = FTUN_ROUTE_READY;
  route.generation = metadata->generation;
  route.outbound_id = 8u;
  route.allowed = &allowed;
  route.allowed_count = 1u;
  CHECK(ftun_session_pin_route(session, &route) == FTUN_OK);
  CHECK(close_session(&session) == 0);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_enabled_selection_and_no_fallback(void)
{
  fixture_t fixture;
  ftun_session_t *session = NULL;
  ftun_resolve_request_t request;
  ftun_operation_t *operation = NULL;
  completion_state_t completion;
  const char domain[] = "select.example";
  CHECK(fixture_start(&fixture) == 0);
  CHECK(open_session(&fixture, domain, NULL, 0u, &session) == 0);
  fill_request(&request, &completion, &fixture, session, domain);
  fixture.backend_state.start_status = FTUN_E_REJECTED;
  CHECK(ftun_resolve_real_with_backend(fixture.core, &request,
        &fixture.backend, &operation) == FTUN_E_REJECTED && operation == NULL);
  CHECK(fixture.backend_state.bootstrap_calls == 1 &&
        fixture.backend_state.system_calls == 0 &&
        fixture.backend_state.server_calls == 0 && completion.calls == 0);

  request.default_server.data = "route-real";
  request.default_server.length = strlen("route-real");
  fixture.backend_state.start_status = FTUN_E_IO;
  CHECK(ftun_resolve_real_with_backend(fixture.core, &request,
        &fixture.backend, &operation) == FTUN_E_IO && operation == NULL);
  CHECK(fixture.backend_state.server_calls == 1 &&
        strcmp(fixture.backend_state.server, "route-real") == 0 &&
        fixture.backend_state.bootstrap_calls == 1 &&
        fixture.backend_state.system_calls == 0 && completion.calls == 0);
  CHECK(ftun_resolve_real(fixture.core, &request, &operation) ==
        FTUN_E_AGAIN && operation == NULL);
  CHECK(close_session(&session) == 0);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_cancel_and_corrupt_result(void)
{
  fixture_t fixture;
  ftun_session_t *session = NULL;
  ftun_resolve_request_t request;
  ftun_operation_t *operation = NULL;
  completion_state_t completion;
  cancel_state_t cancel_state;
  ftun_session_info_t info;
  size_t dispatched = 0u;
  const char domain[] = "cancel.example";
  CHECK(fixture_start(&fixture) == 0);
  CHECK(open_session(&fixture, domain, NULL, 0u, &session) == 0);
  fill_request(&request, &completion, &fixture, session, domain);
  CHECK(ftun_resolve_real_with_backend(fixture.core, &request,
        &fixture.backend, &operation) == FTUN_OK);
  CHECK(ftun_session_transition(session, FTUN_SESSION_RESOLVING,
                                operation) == FTUN_OK);
  memset(&cancel_state, 0, sizeof(cancel_state));
  cancel_state.failures = 1;
  CHECK(ftun_operation_set_cancel_hook(operation, flaky_cancel,
        &cancel_state) == FTUN_OK);
  CHECK(ftun_session_cancel(session) == FTUN_E_AGAIN);
  CHECK(ftun_session_cancel(session) == FTUN_OK && cancel_state.calls == 2);
  CHECK(ftun_operation_dispatch(fixture.operations, 1u,
        &dispatched) == FTUN_OK && dispatched == 1u);
  CHECK(completion.calls == 1 && completion.error.status == FTUN_E_CANCELLED &&
        completion.session_status == FTUN_OK);
  CHECK(ftun_session_get_info(session, &info) == FTUN_OK &&
        info.state == FTUN_SESSION_CLOSED && !info.has_pending_operation);
  CHECK(ftun_session_destroy(&session) == FTUN_OK);

  CHECK(open_session(&fixture, domain, NULL, 0u, &session) == 0);
  fill_request(&request, &completion, &fixture, session, domain);
  fixture.backend_state.addresses[0] = ipv4(3u, 0u);
  fixture.backend_state.addresses[1] = ipv4(3u, 0u);
  fixture.backend_state.address_count = 2u;
  CHECK(ftun_resolve_real_with_backend(fixture.core, &request,
        &fixture.backend, &operation) == FTUN_OK);
  CHECK(ftun_session_transition(session, FTUN_SESSION_RESOLVING,
                                operation) == FTUN_OK);
  {
    ftun_error_t success;
    memset(&success, 0, sizeof(success));
    CHECK(finish_backend(&fixture, success) == 0);
  }
  CHECK(completion.store_status == FTUN_E_STATE_CORRUPT &&
        completion.error.status == FTUN_E_STATE_CORRUPT &&
        completion.session_status == FTUN_OK);
  CHECK(ftun_session_get_info(session, &info) == FTUN_OK &&
        info.state == FTUN_SESSION_CLOSED);
  CHECK(ftun_session_destroy(&session) == FTUN_OK);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_boundaries(void)
{
  fixture_t fixture;
  ftun_session_t *session = NULL;
  ftun_session_t *resolved_session = NULL;
  ftun_session_t *real_ip_session = NULL;
  ftun_resolve_request_t request;
  ftun_operation_t *operation = (ftun_operation_t *)(uintptr_t)1;
  completion_state_t completion;
  ftun_endpoint_t existing = ipv4(9u, 443u);
  ftun_endpoint_t too_many[FTUN_SESSION_MAX_RESOLVED_IPV4 + 1u];
  ftun_resolver_backend_t invalid_backend;
  size_t index;
  size_t dispatched = 0u;
  const char domain[] = "boundary.example";
  CHECK(fixture_start(&fixture) == 0);
  CHECK(open_session(&fixture, domain, NULL, 0u, &session) == 0);
  fill_request(&request, &completion, &fixture, session, domain);
  CHECK(ftun_resolve_real_with_backend(fixture.core, NULL, &fixture.backend,
        &operation) == FTUN_E_INVALID && operation == NULL);
  CHECK(ftun_resolve_real_with_backend(fixture.core, &request,
        &fixture.backend, NULL) == FTUN_E_INVALID);
  invalid_backend = fixture.backend;
  invalid_backend.server_resolve = NULL;
  CHECK(ftun_resolve_real_with_backend(fixture.core, &request,
        &invalid_backend, &operation) == FTUN_E_INVALID && operation == NULL);
  request.query.domain.data = "other.example";
  request.query.domain.length = strlen("other.example");
  CHECK(ftun_resolve_real_with_backend(fixture.core, &request,
        &fixture.backend, &operation) == FTUN_E_INVALID && operation == NULL);
  request.query.domain.data = domain;
  request.query.domain.length = strlen(domain);
  request.query.protection.mark = 0u;
  CHECK(ftun_resolve_real_with_backend(fixture.core, &request,
        &fixture.backend, &operation) == FTUN_OK && operation != NULL &&
        fixture.backend_state.mark == 0u);
  CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  CHECK(ftun_operation_dispatch(fixture.operations, 1u, &dispatched) ==
        FTUN_OK && dispatched == 1u &&
        completion.error.status == FTUN_E_CANCELLED);
  request.query.protection.mark = 91u;
  request.default_server.data = "bad,name";
  request.default_server.length = strlen("bad,name");
  CHECK(ftun_resolve_real_with_backend(fixture.core, &request,
        &fixture.backend, &operation) == FTUN_E_INVALID && operation == NULL);
  request.default_server.data = NULL;
  request.default_server.length = 0u;
  CHECK(close_session(&session) == 0);

  CHECK(open_session(&fixture, domain, &existing, 1u,
                     &resolved_session) == 0);
  fill_request(&request, &completion, &fixture, resolved_session, domain);
  CHECK(ftun_resolve_real_with_backend(fixture.core, &request,
        &fixture.backend, &operation) == FTUN_E_STALE && operation == NULL);
  CHECK(close_session(&resolved_session) == 0);
  CHECK(open_real_ip_session(&fixture, domain, &real_ip_session) == 0);
  fill_request(&request, &completion, &fixture, real_ip_session, domain);
  CHECK(ftun_resolve_real_with_backend(fixture.core, &request,
        &fixture.backend, &operation) == FTUN_E_STALE && operation == NULL);
  CHECK(close_session(&real_ip_session) == 0);
  CHECK(fixture.backend_state.system_calls == 0 &&
        fixture.backend_state.bootstrap_calls == 1 &&
        fixture.backend_state.server_calls == 0);

  CHECK(open_session(&fixture, domain, NULL, 0u, &session) == 0);
  fill_request(&request, &completion, &fixture, session, domain);
  CHECK(ftun_resolve_real_with_backend(fixture.core, &request,
        &fixture.backend, &operation) == FTUN_OK);
  CHECK(ftun_session_transition(session, FTUN_SESSION_RESOLVING,
                                operation) == FTUN_OK);
  for (index = 0u; index < FTUN_SESSION_MAX_RESOLVED_IPV4 + 1u; index++) {
    too_many[index] = ipv4((uint8_t)(index + 1u), 0u);
  }
  CHECK(ftun_session_store_resolved(
        session, operation, too_many,
        FTUN_SESSION_MAX_RESOLVED_IPV4 + 1u) == FTUN_E_LIMIT);
  CHECK(ftun_session_cancel(session) == FTUN_OK);
  CHECK(ftun_operation_dispatch(fixture.operations, 1u,
        &dispatched) == FTUN_OK && dispatched == 1u);
  CHECK(completion.error.status == FTUN_E_CANCELLED &&
        ftun_session_destroy(&session) == FTUN_OK);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

/* TASK-DNS-005 / TEST-DNS-005：路由前解析器选择与 Session 结果复用。 */
int main(void)
{
  CHECK(test_system_store_and_reuse() == 0);
  CHECK(test_enabled_selection_and_no_fallback() == 0);
  CHECK(test_cancel_and_corrupt_result() == 0);
  CHECK(test_boundaries() == 0);
  return 0;
}
