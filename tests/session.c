#include "config/compile.h"
#include "config/model.h"
#include "config/parser.h"
#include "core/budget.h"
#include "core/operation.h"
#include "core/runtime.h"
#include "core/session.h"
#include "transport/stream.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "session contract failed at line %d: %s\n", __LINE__, #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  int destroy_calls;
} stream_backend_t;

typedef struct {
  ftun_budget_t *budget;
  ftun_core_t *core;
  ftun_operation_queue_t *operations;
  ftun_stream_t *stream;
  stream_backend_t backend;
} fixture_t;

typedef struct {
  ftun_session_t *session;
  ftun_operation_t *operation;
  ftun_error_t result;
  int calls;
  int session_completed;
} child_t;

typedef struct {
  int calls;
  int fail_count;
} cancel_state_t;

static ftun_config_t *make_config(const char *name, unsigned int port)
{
  char json[256];
  ftun_bytes_t input;
  ftun_config_t *config = NULL;
  ftun_feature_plan_t *plan = NULL;
  int length = snprintf(json, sizeof(json),
    "{\"dns\":{\"enable\":false},\"inbounds\":[{\"name\":\"%s\","
    "\"type\":\"mixed\",\"listen\":\"127.0.0.1:%u\"}],"
    "\"rules\":[\"MATCH,DIRECT\"]}", name, port);
  if (length <= 0 || (size_t)length >= sizeof(json)) return NULL;
  input.data = (const uint8_t *)json;
  input.length = (size_t)length;
  if (ftun_config_parse(input, &config) != FTUN_OK) return NULL;
  if (ftun_config_compile(config, &plan) != FTUN_OK) {
    (void)ftun_config_destroy(&config);
    return NULL;
  }
  config->plan = plan;
  return config;
}

static ftun_status_t backend_write_start(void *context,
                                         ftun_stream_write_t *write,
                                         const ftun_buffer_slice_t *slice,
                                         size_t *accepted)
{
  (void)context;
  (void)write;
  (void)slice;
  *accepted = 0u;
  return FTUN_E_AGAIN;
}

static ftun_status_t backend_write_cancel(void *context,
                                          ftun_stream_write_t *write)
{
  (void)context;
  (void)write;
  return FTUN_OK;
}

static void backend_destroy(void *context)
{
  stream_backend_t *backend = (stream_backend_t *)context;
  backend->destroy_calls++;
}

static void unused_stream_completion(ftun_operation_t *operation,
                                     ftun_error_t result, void *user)
{
  (void)operation;
  (void)result;
  (void)user;
}

static int install_runtime(fixture_t *fixture, const char *name,
                           unsigned int port)
{
  ftun_config_t *config = make_config(name, port);
  ftun_runtime_t *candidate = NULL;
  if (config == NULL) return 1;
  if (ftun_runtime_prepare(fixture->core, config, &candidate) != FTUN_OK ||
      ftun_runtime_commit(fixture->core, &candidate) != FTUN_OK ||
      ftun_config_destroy(&config) != FTUN_OK) return 1;
  return 0;
}

static int fixture_start(fixture_t *fixture)
{
  ftun_stream_options_t options;
  ftun_stream_backend_t backend;
  memset(fixture, 0, sizeof(*fixture));
  memset(&options, 0, sizeof(options));
  memset(&backend, 0, sizeof(backend));
  if (ftun_budget_create(NULL, 1024u * 1024u, 0u,
                         &fixture->budget) != FTUN_OK) return 1;
  if (ftun_runtime_manager_create(fixture->budget, 4u,
                                  &fixture->core) != FTUN_OK) return 1;
  if (install_runtime(fixture, "first", 10001u) != 0) return 1;
  if (ftun_operation_queue_create(fixture->budget, 8u,
                                  &fixture->operations) != FTUN_OK) return 1;
  options.budget = fixture->budget;
  options.operations = fixture->operations;
  options.max_pending_writes = 2u;
  options.max_pending_bytes = 1024u;
  options.completion = unused_stream_completion;
  backend.write_start = backend_write_start;
  backend.write_cancel = backend_write_cancel;
  backend.destroy = backend_destroy;
  backend.context = &fixture->backend;
  return ftun_stream_create(&options, &backend, &fixture->stream) == FTUN_OK
    ? 0 : 1;
}

static int fixture_stop(fixture_t *fixture)
{
  ftun_budget_usage_t usage;
  if (ftun_stream_stop(fixture->stream) != FTUN_OK) return 1;
  if (ftun_stream_destroy(&fixture->stream) != FTUN_OK) return 1;
  if (fixture->backend.destroy_calls != 1) return 1;
  if (ftun_operation_queue_destroy(&fixture->operations) != FTUN_OK) return 1;
  if (ftun_runtime_manager_destroy(&fixture->core) != FTUN_OK) return 1;
  if (ftun_budget_get_usage(fixture->budget, &usage) != FTUN_OK ||
      usage.used != 0u) return 1;
  if (ftun_budget_destroy(&fixture->budget) != FTUN_OK) return 1;
  return 0;
}

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

static void fill_metadata(ftun_metadata_t *metadata, char *domain,
                          ftun_endpoint_t *resolved, size_t resolved_count)
{
  memset(metadata, 0, sizeof(*metadata));
  metadata->known_fields = FTUN_META_SOURCE | FTUN_META_PORT |
                           FTUN_META_NETWORK | FTUN_META_DOMAIN;
  metadata->inbound_id = 11u;
  metadata->network = 1u;
  metadata->source = ipv4(10u, 40000u);
  metadata->original_target.kind = FTUN_ADDRESS_DOMAIN;
  metadata->original_target.domain.data = domain;
  metadata->original_target.domain.length = strlen(domain);
  metadata->original_target.port = 443u;
  metadata->domain.data = domain;
  metadata->domain.length = strlen(domain);
  metadata->domain_source = FTUN_DOMAIN_EXPLICIT;
  metadata->resolved = resolved;
  metadata->resolved_count = resolved_count;
}

static void child_complete(ftun_operation_t *operation,
                           ftun_error_t result, void *user)
{
  child_t *child = (child_t *)user;
  child->calls++;
  child->result = result;
  child->session_completed += ftun_session_operation_complete(
    child->session, operation, result) == FTUN_OK;
  child->operation = NULL;
}

static int begin_child(fixture_t *fixture, ftun_session_t *session,
                       ftun_session_state_t state, child_t *child)
{
  memset(child, 0, sizeof(*child));
  child->session = session;
  if (ftun_operation_accept(fixture->operations, child_complete, child,
                            &child->operation) != FTUN_OK) return 1;
  if (ftun_session_transition(session, state, child->operation) != FTUN_OK) {
    (void)ftun_operation_reject(&child->operation);
    return 1;
  }
  return 0;
}

static int finish_child(fixture_t *fixture, child_t *child,
                        ftun_status_t result_status)
{
  ftun_error_t result;
  size_t dispatched = 0u;
  memset(&result, 0, sizeof(result));
  result.status = result_status;
  if (ftun_operation_complete(child->operation, result) != FTUN_OK) return 1;
  if (ftun_operation_dispatch(fixture->operations, 1u,
                              &dispatched) != FTUN_OK) return 1;
  return dispatched == 1u && child->calls == 1 &&
         child->session_completed == 1 && child->result.status == result_status
    ? 0 : 1;
}

static ftun_status_t flaky_cancel(void *user)
{
  cancel_state_t *state = (cancel_state_t *)user;
  state->calls++;
  if (state->fail_count != 0) {
    state->fail_count--;
    return FTUN_E_AGAIN;
  }
  return FTUN_OK;
}

static int test_full_lifecycle_and_reload(void)
{
  fixture_t fixture;
  char domain[32] = "service.example";
  ftun_endpoint_t resolved[2];
  ftun_endpoint_t allowed;
  ftun_metadata_t metadata;
  ftun_session_t *session = NULL;
  const ftun_metadata_t *owned_metadata = NULL;
  const ftun_route_result_t *owned_route = NULL;
  const ftun_runtime_t *owned_runtime = NULL;
  ftun_route_result_t route;
  ftun_session_info_t info;
  ftun_runtime_info_t runtime_info;
  ftun_runtime_manager_info_t manager_info;
  ftun_stream_usage_t stream_usage;
  child_t child;
  ftun_error_t success;
  memset(&success, 0, sizeof(success));
  CHECK(fixture_start(&fixture) == 0);
  resolved[0] = ipv4(21u, 443u);
  resolved[1] = ipv4(22u, 443u);
  allowed = resolved[1];
  fill_metadata(&metadata, domain, resolved, 2u);

  CHECK(ftun_session_submit(fixture.core, &metadata, fixture.stream,
        &session) == FTUN_OK && session != NULL);
  CHECK(ftun_session_get_info(session, &info) == FTUN_OK);
  CHECK(info.state == FTUN_SESSION_ACCEPTED && info.runtime_generation == 1u &&
        info.accounted_bytes > sizeof(info) && !info.route_pinned);
  CHECK(ftun_stream_get_usage(fixture.stream, &stream_usage) == FTUN_OK &&
        stream_usage.reference_count == 2u);
  memset(domain, 'x', strlen(domain));
  resolved[0].address[3] = 99u;
  CHECK(ftun_session_get_metadata(session, &owned_metadata) == FTUN_OK);
  CHECK(owned_metadata->domain.length == strlen("service.example") &&
        memcmp(owned_metadata->domain.data, "service.example",
               strlen("service.example")) == 0);
  CHECK(owned_metadata->resolved[0].address[3] == 21u);

  CHECK(begin_child(&fixture, session, FTUN_SESSION_HANDSHAKING, &child) == 0);
  CHECK(ftun_session_transition(session, FTUN_SESSION_ROUTING, NULL) ==
        FTUN_E_AGAIN);
  CHECK(finish_child(&fixture, &child, FTUN_OK) == 0);
  CHECK(ftun_session_transition(session, FTUN_SESSION_ROUTING, NULL) == FTUN_OK);
  CHECK(begin_child(&fixture, session, FTUN_SESSION_RESOLVING, &child) == 0);
  CHECK(finish_child(&fixture, &child, FTUN_OK) == 0);
  CHECK(ftun_session_transition(session, FTUN_SESSION_ROUTING, NULL) == FTUN_OK);

  memset(&route, 0, sizeof(route));
  route.kind = FTUN_ROUTE_READY;
  route.generation = 1u;
  route.rule_index = 3u;
  route.outbound_id = 7u;
  route.allowed = &allowed;
  route.allowed_count = 1u;
  CHECK(ftun_session_pin_route(session, &route) == FTUN_OK);
  allowed.address[3] = 88u;
  CHECK(ftun_session_get_route(session, &owned_route) == FTUN_OK);
  CHECK(owned_route->generation == 1u && owned_route->outbound_id == 7u &&
        owned_route->allowed_count == 1u &&
        owned_route->allowed[0].address[3] == 22u);

  CHECK(install_runtime(&fixture, "second", 10002u) == 0);
  CHECK(ftun_runtime_manager_get_info(fixture.core, &manager_info) == FTUN_OK &&
        manager_info.generation == 2u && manager_info.retained_count == 1u);
  CHECK(ftun_session_get_runtime(session, &owned_runtime) == FTUN_OK);
  CHECK(ftun_runtime_get_info(owned_runtime, &runtime_info) == FTUN_OK &&
        runtime_info.generation == 1u &&
        runtime_info.state == FTUN_RUNTIME_RETAINED);
  route.generation = 2u;
  CHECK(ftun_session_pin_route(session, &route) == FTUN_E_STALE);

  CHECK(begin_child(&fixture, session, FTUN_SESSION_CONNECTING, &child) == 0);
  CHECK(finish_child(&fixture, &child, FTUN_OK) == 0);
  CHECK(begin_child(&fixture, session, FTUN_SESSION_REPLYING, &child) == 0);
  CHECK(finish_child(&fixture, &child, FTUN_OK) == 0);
  CHECK(ftun_session_transition(session, FTUN_SESSION_RELAYING, NULL) == FTUN_OK);
  CHECK(ftun_session_transition(session, FTUN_SESSION_DRAINING, NULL) == FTUN_OK);
  CHECK(ftun_session_finish(session, success) == FTUN_OK);
  CHECK(ftun_session_get_info(session, &info) == FTUN_OK &&
        info.state == FTUN_SESSION_CLOSED && info.terminal_error.status == FTUN_OK);
  CHECK(ftun_session_destroy(&session) == FTUN_OK && session == NULL);
  CHECK(ftun_runtime_manager_get_info(fixture.core, &manager_info) == FTUN_OK &&
        manager_info.retained_count == 0u);
  CHECK(ftun_stream_get_usage(fixture.stream, &stream_usage) == FTUN_OK &&
        stream_usage.reference_count == 1u && !stream_usage.accepting);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_cancel_waits_for_callback(void)
{
  fixture_t fixture;
  char domain[] = "cancel.example";
  ftun_endpoint_t resolved = ipv4(30u, 443u);
  ftun_metadata_t metadata;
  ftun_session_t *session = NULL;
  ftun_session_info_t info;
  ftun_stream_usage_t usage;
  child_t child;
  cancel_state_t cancel_state;
  size_t dispatched = 99u;
  CHECK(fixture_start(&fixture) == 0);
  fill_metadata(&metadata, domain, &resolved, 1u);
  CHECK(ftun_session_submit(fixture.core, &metadata, fixture.stream,
        &session) == FTUN_OK);
  CHECK(begin_child(&fixture, session, FTUN_SESSION_HANDSHAKING, &child) == 0);
  memset(&cancel_state, 0, sizeof(cancel_state));
  cancel_state.fail_count = 1;
  CHECK(ftun_operation_set_cancel_hook(child.operation, flaky_cancel,
        &cancel_state) == FTUN_OK);
  CHECK(ftun_session_cancel(session) == FTUN_E_AGAIN);
  CHECK(ftun_session_get_info(session, &info) == FTUN_OK &&
        info.state == FTUN_SESSION_CLOSING && info.has_pending_operation &&
        info.terminal_error.status == FTUN_E_CANCELLED);
  CHECK(ftun_stream_get_usage(fixture.stream, &usage) == FTUN_OK &&
        !usage.accepting && usage.reference_count == 2u);
  CHECK(ftun_session_destroy(&session) == FTUN_E_AGAIN && session != NULL);
  CHECK(ftun_operation_dispatch(fixture.operations, 8u,
        &dispatched) == FTUN_OK && dispatched == 0u);
  CHECK(ftun_session_cancel(session) == FTUN_OK && cancel_state.calls == 2);
  CHECK(ftun_session_get_info(session, &info) == FTUN_OK &&
        info.state == FTUN_SESSION_CLOSING && info.has_pending_operation);
  CHECK(ftun_operation_dispatch(fixture.operations, 8u,
        &dispatched) == FTUN_OK && dispatched == 1u);
  CHECK(child.calls == 1 && child.result.status == FTUN_E_CANCELLED);
  CHECK(ftun_session_get_info(session, &info) == FTUN_OK &&
        info.state == FTUN_SESSION_CLOSED && !info.has_pending_operation);
  CHECK(ftun_session_destroy(&session) == FTUN_OK);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_failure_and_boundaries(void)
{
  fixture_t fixture;
  char domain[] = "failure.example";
  ftun_endpoint_t resolved = ipv4(40u, 443u);
  ftun_endpoint_t foreign = ipv4(41u, 443u);
  ftun_metadata_t metadata;
  ftun_session_t *session = NULL;
  ftun_session_t *rejected = (ftun_session_t *)(uintptr_t)1;
  ftun_route_result_t route;
  ftun_session_info_t info;
  ftun_stream_usage_t stream_usage;
  ftun_budget_usage_t budget_usage;
  ftun_reservation_t *exhaustion = NULL;
  child_t child;
  CHECK(fixture_start(&fixture) == 0);
  fill_metadata(&metadata, domain, &resolved, 1u);

  metadata.generation = 99u;
  CHECK(ftun_session_submit(fixture.core, &metadata, fixture.stream,
        &rejected) == FTUN_E_STALE && rejected == NULL);
  metadata.generation = 0u;
  metadata.network = 3u;
  CHECK(ftun_session_submit(fixture.core, &metadata, fixture.stream,
        &rejected) == FTUN_E_INVALID && rejected == NULL);
  metadata.network = 1u;
  CHECK(ftun_budget_get_usage(fixture.budget, &budget_usage) == FTUN_OK &&
        budget_usage.normal_available != 0u);
  CHECK(ftun_budget_reserve(fixture.budget, budget_usage.normal_available,
        &exhaustion) == FTUN_OK);
  CHECK(ftun_session_submit(fixture.core, &metadata, fixture.stream,
        &rejected) == FTUN_E_LIMIT && rejected == NULL);
  CHECK(ftun_stream_get_usage(fixture.stream, &stream_usage) == FTUN_OK &&
        stream_usage.reference_count == 1u);
  CHECK(ftun_reservation_release(&exhaustion) == FTUN_OK);

  CHECK(ftun_session_submit(fixture.core, &metadata, fixture.stream,
        &session) == FTUN_OK);
  CHECK(ftun_session_transition(session, FTUN_SESSION_CONNECTING, NULL) ==
        FTUN_E_STALE);
  CHECK(ftun_session_transition(session, FTUN_SESSION_ROUTING, NULL) == FTUN_OK);
  memset(&route, 0, sizeof(route));
  route.kind = FTUN_ROUTE_READY;
  route.generation = 1u;
  route.outbound_id = 3u;
  route.allowed = &foreign;
  route.allowed_count = 1u;
  CHECK(ftun_session_pin_route(session, &route) == FTUN_E_REJECTED);
  route.allowed = &resolved;
  CHECK(ftun_session_pin_route(session, &route) == FTUN_OK);
  CHECK(begin_child(&fixture, session, FTUN_SESSION_CONNECTING, &child) == 0);
  CHECK(finish_child(&fixture, &child, FTUN_E_IO) == 0);
  CHECK(ftun_session_get_info(session, &info) == FTUN_OK &&
        info.state == FTUN_SESSION_CLOSED &&
        info.terminal_error.status == FTUN_E_IO);
  CHECK(ftun_session_destroy(&session) == FTUN_OK);

  CHECK(ftun_session_submit(NULL, &metadata, fixture.stream,
        &rejected) == FTUN_E_INVALID && rejected == NULL);
  CHECK(ftun_session_submit(fixture.core, NULL, fixture.stream,
        &rejected) == FTUN_E_INVALID && rejected == NULL);
  CHECK(ftun_session_get_info(NULL, &info) == FTUN_E_INVALID && info.state == 0);
  CHECK(ftun_session_destroy(NULL) == FTUN_E_INVALID);
  CHECK(ftun_session_destroy(&session) == FTUN_OK);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

int main(void)
{
  CHECK(test_full_lifecycle_and_reload() == 0);
  CHECK(test_cancel_waits_for_callback() == 0);
  CHECK(test_failure_and_boundaries() == 0);
  return 0;
}
