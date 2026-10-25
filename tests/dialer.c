#define _GNU_SOURCE 1
#include "transport/dialer.h"
#include "event/libev_adapter.h"
#include "util/time.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "dialer contract failed at line %d: %s\n", __LINE__, #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  ftun_event_source_t *io_source;
  ftun_event_source_t *timer_source;
  ftun_status_t io_start_status;
  ftun_status_t timer_start_status;
  int cancel_failures;
  int cancel_calls;
  int stopped;
  int destroyed;
} backend_state_t;

typedef struct {
  ftun_status_t open_status;
  ftun_status_t protect_status;
  ftun_status_t connect_status;
  ftun_status_t socket_error_status;
  ftun_status_t close_status;
  ftun_native_socket_t socket;
  int sequence[8];
  int sequence_count;
  int open_calls;
  int protect_calls;
  int connect_calls;
  int get_error_calls;
  int close_calls;
  uint32_t protected_mark;
  char protected_device[FTUN_SOCKET_INTERFACE_BYTES];
  ftun_endpoint_t connected_endpoint;
} socket_state_t;

typedef struct {
  int calls;
  ftun_error_t error;
  ftun_dial_result_t result;
  ftun_operation_t *operation;
} completion_state_t;

typedef struct {
  ftun_budget_t *budget;
  ftun_operation_queue_t *operations;
  ftun_event_loop_t *loop;
  backend_state_t backend;
  socket_state_t socket;
  completion_state_t completion;
  ftun_dial_io_t io;
  ftun_dial_request_t request;
} fixture_t;

static ftun_status_t backend_io_start(void *user, ftun_event_source_t *source,
                                      ftun_native_socket_t socket,
                                      uint32_t interests)
{
  backend_state_t *state = (backend_state_t *)user;
  (void)socket;
  (void)interests;
  if (state->io_start_status != FTUN_OK) return state->io_start_status;
  state->io_source = source;
  return FTUN_OK;
}

static ftun_status_t backend_timer_start(void *user,
                                         ftun_event_source_t *source,
                                         uint64_t deadline_ms)
{
  backend_state_t *state = (backend_state_t *)user;
  (void)deadline_ms;
  if (state->timer_start_status != FTUN_OK) return state->timer_start_status;
  state->timer_source = source;
  return FTUN_OK;
}

static ftun_status_t backend_io_update(void *user,
                                        ftun_event_source_t *source,
                                        uint32_t interests)
{
  (void)user;
  (void)source;
  (void)interests;
  return FTUN_OK;
}

static ftun_status_t backend_source_cancel(void *user,
                                           ftun_event_source_t *source)
{
  backend_state_t *state = (backend_state_t *)user;
  state->cancel_calls++;
  if (state->cancel_failures > 0) {
    state->cancel_failures--;
    return FTUN_E_IO;
  }
  if (state->io_source == source) state->io_source = NULL;
  if (state->timer_source == source) state->timer_source = NULL;
  return FTUN_OK;
}

static void backend_wakeup(void *user)
{
  (void)user;
}

static ftun_status_t backend_run_once(void *user, bool block)
{
  (void)user;
  (void)block;
  return FTUN_OK;
}

static void backend_stop(void *user)
{
  backend_state_t *state = (backend_state_t *)user;
  state->stopped++;
}

static void backend_destroy(void *user)
{
  backend_state_t *state = (backend_state_t *)user;
  state->destroyed++;
}

static const ftun_event_backend_ops_t backend_ops = {
  backend_io_start,
  backend_io_update,
  backend_timer_start,
  backend_source_cancel,
  backend_wakeup,
  backend_run_once,
  backend_stop,
  backend_destroy,
  false
};

static void socket_step(socket_state_t *state, int step)
{
  if (state->sequence_count < (int)(sizeof(state->sequence) /
                                    sizeof(state->sequence[0]))) {
    state->sequence[state->sequence_count++] = step;
  }
}

static ftun_status_t socket_open(void *user, ftun_dial_transport_t transport,
                                 ftun_native_socket_t *out)
{
  socket_state_t *state = (socket_state_t *)user;
  socket_step(state, 1);
  state->open_calls++;
  if (out != NULL) *out = FTUN_INVALID_SOCKET;
  if (transport != FTUN_DIAL_TCP && transport != FTUN_DIAL_UDP) {
    return FTUN_E_INVALID;
  }
  if (state->open_status != FTUN_OK) return state->open_status;
  *out = state->socket;
  return FTUN_OK;
}

static ftun_status_t socket_protect(void *user, ftun_native_socket_t socket,
                                    const ftun_socket_policy_t *policy)
{
  socket_state_t *state = (socket_state_t *)user;
  socket_step(state, 2);
  state->protect_calls++;
  if (socket != state->socket || policy == NULL) return FTUN_E_STATE_CORRUPT;
  state->protected_mark = policy->mark;
  memset(state->protected_device, 0, sizeof(state->protected_device));
  if (policy->interface_name.length >= sizeof(state->protected_device)) {
    return FTUN_E_INVALID;
  }
  if (policy->interface_name.length != 0u) {
    memcpy(state->protected_device, policy->interface_name.data,
           policy->interface_name.length);
  }
  return state->protect_status;
}

static ftun_status_t socket_connect(void *user, ftun_native_socket_t socket,
                                    const ftun_endpoint_t *endpoint)
{
  socket_state_t *state = (socket_state_t *)user;
  socket_step(state, 3);
  state->connect_calls++;
  if (socket != state->socket || endpoint == NULL) return FTUN_E_STATE_CORRUPT;
  state->connected_endpoint = *endpoint;
  return state->connect_status;
}

static ftun_status_t socket_get_error(void *user, ftun_native_socket_t socket)
{
  socket_state_t *state = (socket_state_t *)user;
  socket_step(state, 4);
  state->get_error_calls++;
  if (socket != state->socket) return FTUN_E_STATE_CORRUPT;
  return state->socket_error_status;
}

static ftun_status_t socket_close(void *user, ftun_native_socket_t socket)
{
  socket_state_t *state = (socket_state_t *)user;
  socket_step(state, 5);
  state->close_calls++;
  if (socket != state->socket) return FTUN_E_STATE_CORRUPT;
  return state->close_status;
}

static void dial_completed(ftun_operation_t *operation, ftun_error_t error,
                           const ftun_dial_result_t *result, void *user)
{
  completion_state_t *state = (completion_state_t *)user;
  state->calls++;
  state->operation = operation;
  state->error = error;
  state->result = *result;
}

static int fixture_start(fixture_t *fixture, size_t budget_limit,
                         size_t operation_capacity)
{
  static const uint8_t address[4] = {127u, 0u, 0u, 1u};
  memset(fixture, 0, sizeof(*fixture));
  fixture->socket.socket = 42u;
  fixture->socket.connect_status = FTUN_E_AGAIN;
  fixture->io.open_socket = socket_open;
  fixture->io.protect_socket = socket_protect;
  fixture->io.connect_socket = socket_connect;
  fixture->io.get_socket_error = socket_get_error;
  fixture->io.close_socket = socket_close;
  fixture->io.context = &fixture->socket;
  if (ftun_budget_create(NULL, budget_limit, 0u, &fixture->budget) != FTUN_OK) {
    return 1;
  }
  if (ftun_operation_queue_create(fixture->budget, operation_capacity,
                                  &fixture->operations) != FTUN_OK) return 1;
  if (ftun_event_loop_create(NULL, &fixture->loop) != FTUN_OK) return 1;
  if (ftun_event_loop_attach_backend(fixture->loop, &backend_ops,
                                     &fixture->backend) != FTUN_OK) return 1;
  fixture->request.loop = fixture->loop;
  fixture->request.operations = fixture->operations;
  fixture->request.budget = fixture->budget;
  fixture->request.endpoint.kind = FTUN_ADDRESS_IPV4;
  memcpy(fixture->request.endpoint.address, address, sizeof(address));
  fixture->request.endpoint.port = 443u;
  fixture->request.protection.mark = 77u;
  fixture->request.protection.interface_name.data = "eth0";
  fixture->request.protection.interface_name.length = 4u;
  fixture->request.deadline_ms = 1000u;
  fixture->request.transport = FTUN_DIAL_TCP;
  fixture->request.purpose = FTUN_DIAL_PURPOSE_PROXY;
  fixture->request.completion = dial_completed;
  fixture->request.user = &fixture->completion;
  return 0;
}

static int fixture_stop(fixture_t *fixture)
{
  ftun_budget_usage_t usage;
  if (ftun_event_loop_stop(fixture->loop) != FTUN_OK) return 1;
  if (ftun_event_loop_detach_backend(fixture->loop) != FTUN_OK) return 1;
  if (ftun_event_loop_destroy(&fixture->loop) != FTUN_OK) return 1;
  if (ftun_operation_queue_destroy(&fixture->operations) != FTUN_OK) return 1;
  if (ftun_budget_get_usage(fixture->budget, &usage) != FTUN_OK ||
      usage.used != 0u) return 1;
  if (ftun_budget_destroy(&fixture->budget) != FTUN_OK) return 1;
  return 0;
}

static int dispatch_all(fixture_t *fixture)
{
  size_t dispatched = 0u;
  if (ftun_operation_dispatch(fixture->operations, SIZE_MAX,
                              &dispatched) != FTUN_OK) return 1;
  return dispatched == 1u ? 0 : 1;
}

static int test_pending_success(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = NULL;
  size_t callbacks = 0u;
  CHECK(fixture_start(&fixture, 16384u, 4u) == 0);
  fixture.socket.socket_error_status = FTUN_OK;
  CHECK(ftun_dial_start_with_io(NULL, &fixture.request, &fixture.io,
                                &operation) == FTUN_OK);
  CHECK(operation != NULL && fixture.completion.calls == 0);
  CHECK(fixture.socket.sequence_count == 3);
  CHECK(fixture.socket.sequence[0] == 1 && fixture.socket.sequence[1] == 2 &&
        fixture.socket.sequence[2] == 3);
  CHECK(fixture.socket.protected_mark == 77u);
  CHECK(strcmp(fixture.socket.protected_device, "eth0") == 0);
  CHECK(fixture.backend.io_source != NULL && fixture.backend.timer_source != NULL);
  fixture.request.endpoint.port = 80u;
  fixture.request.purpose = FTUN_DIAL_PURPOSE_DNS;
  CHECK(ftun_event_io_ready(fixture.backend.io_source,
                            FTUN_EVENT_WRITE) == FTUN_OK);
  CHECK(ftun_event_loop_poll(fixture.loop, 999u, 4u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 1u && fixture.socket.get_error_calls == 1);
  CHECK(fixture.backend.io_source == NULL && fixture.backend.timer_source == NULL);
  CHECK(fixture.completion.calls == 0 && fixture.socket.close_calls == 0);
  CHECK(dispatch_all(&fixture) == 0);
  CHECK(fixture.completion.calls == 1 && fixture.completion.error.status == FTUN_OK);
  CHECK(fixture.completion.error.stage == FTUN_DIAL_STAGE_WAIT);
  CHECK(fixture.completion.result.socket == 42u);
  CHECK(fixture.completion.result.endpoint.kind == FTUN_ADDRESS_IPV4 &&
        fixture.completion.result.endpoint.port == 443u);
  CHECK(fixture.completion.result.transport == FTUN_DIAL_TCP &&
        fixture.completion.result.purpose == FTUN_DIAL_PURPOSE_PROXY);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_cancel_paths(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = NULL;
  CHECK(fixture_start(&fixture, 16384u, 4u) == 0);
  CHECK(ftun_dial_start_with_io(NULL, &fixture.request, &fixture.io,
                                &operation) == FTUN_OK);
  fixture.backend.cancel_failures = 1;
  CHECK(ftun_operation_cancel(operation) == FTUN_E_IO);
  CHECK(fixture.socket.close_calls == 0 && fixture.completion.calls == 0);
  CHECK(fixture.backend.io_source != NULL && fixture.backend.timer_source != NULL);
  CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  CHECK(fixture.socket.close_calls == 1);
  CHECK(dispatch_all(&fixture) == 0);
  CHECK(fixture.completion.calls == 1 &&
        fixture.completion.error.status == FTUN_E_CANCELLED &&
        fixture.completion.result.socket == FTUN_INVALID_SOCKET);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(fixture_start(&fixture, 16384u, 4u) == 0);
  fixture.socket.connect_status = FTUN_OK;
  CHECK(ftun_dial_start_with_io(NULL, &fixture.request, &fixture.io,
                                &operation) == FTUN_OK);
  CHECK(operation != NULL && fixture.socket.close_calls == 0);
  CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  CHECK(fixture.socket.close_calls == 1);
  CHECK(dispatch_all(&fixture) == 0);
  CHECK(fixture.completion.error.status == FTUN_E_CANCELLED &&
        fixture.completion.result.socket == FTUN_INVALID_SOCKET);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(fixture_start(&fixture, 16384u, 4u) == 0);
  CHECK(ftun_dial_start_with_io(NULL, &fixture.request, &fixture.io,
                                &operation) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(fixture.operations) == FTUN_OK);
  CHECK(fixture.socket.close_calls == 1 && fixture.backend.io_source == NULL &&
        fixture.backend.timer_source == NULL);
  CHECK(dispatch_all(&fixture) == 0);
  CHECK(fixture.completion.error.status == FTUN_E_CANCELLED &&
        fixture.completion.result.socket == FTUN_INVALID_SOCKET);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_async_failures(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = NULL;
  size_t callbacks = 0u;
  CHECK(fixture_start(&fixture, 16384u, 4u) == 0);
  fixture.socket.socket_error_status = FTUN_E_REJECTED;
  CHECK(ftun_dial_start_with_io(NULL, &fixture.request, &fixture.io,
                                &operation) == FTUN_OK);
  CHECK(ftun_event_io_ready(fixture.backend.io_source,
                            FTUN_EVENT_ERROR) == FTUN_OK);
  CHECK(ftun_event_loop_poll(fixture.loop, 1u, 4u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 1u && fixture.socket.close_calls == 1);
  CHECK(dispatch_all(&fixture) == 0);
  CHECK(fixture.completion.error.status == FTUN_E_REJECTED &&
        fixture.completion.error.stage == FTUN_DIAL_STAGE_WAIT &&
        fixture.completion.result.socket == FTUN_INVALID_SOCKET);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(fixture_start(&fixture, 16384u, 4u) == 0);
  CHECK(ftun_dial_start_with_io(NULL, &fixture.request, &fixture.io,
                                &operation) == FTUN_OK);
  CHECK(ftun_event_loop_poll(fixture.loop, 1000u, 4u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 1u && fixture.socket.close_calls == 1);
  CHECK(dispatch_all(&fixture) == 0);
  CHECK(fixture.completion.error.status == FTUN_E_TIMEOUT &&
        fixture.completion.error.stage == FTUN_DIAL_STAGE_TIMEOUT &&
        fixture.completion.result.socket == FTUN_INVALID_SOCKET);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_synchronous_rejection(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = (ftun_operation_t *)(uintptr_t)1;
  ftun_budget_usage_t before;
  ftun_budget_usage_t after;
  CHECK(fixture_start(&fixture, 16384u, 4u) == 0);
  CHECK(ftun_budget_get_usage(fixture.budget, &before) == FTUN_OK);
  fixture.socket.protect_status = FTUN_E_REJECTED;
  CHECK(ftun_dial_start_with_io(NULL, &fixture.request, &fixture.io,
                                &operation) == FTUN_E_REJECTED);
  CHECK(operation == NULL && fixture.completion.calls == 0);
  CHECK(fixture.socket.open_calls == 1 && fixture.socket.protect_calls == 1 &&
        fixture.socket.connect_calls == 0 && fixture.socket.close_calls == 1);
  CHECK(ftun_budget_get_usage(fixture.budget, &after) == FTUN_OK);
  CHECK(after.used == before.used);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(fixture_start(&fixture, 16384u, 4u) == 0);
  fixture.backend.timer_start_status = FTUN_E_LIMIT;
  operation = (ftun_operation_t *)(uintptr_t)1;
  CHECK(ftun_dial_start_with_io(NULL, &fixture.request, &fixture.io,
                                &operation) == FTUN_E_LIMIT);
  CHECK(operation == NULL && fixture.completion.calls == 0 &&
        fixture.socket.close_calls == 1 && fixture.backend.io_source == NULL &&
        fixture.backend.timer_source == NULL);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(fixture_start(&fixture, 16384u, 4u) == 0);
  fixture.backend.io_start_status = FTUN_E_IO;
  operation = (ftun_operation_t *)(uintptr_t)1;
  CHECK(ftun_dial_start_with_io(NULL, &fixture.request, &fixture.io,
                                &operation) == FTUN_E_IO);
  CHECK(operation == NULL && fixture.completion.calls == 0 &&
        fixture.socket.close_calls == 1 && fixture.backend.timer_source == NULL);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_all_purposes_protected(void)
{
  int purpose;
  for (purpose = (int)FTUN_DIAL_PURPOSE_BUSINESS;
       purpose <= (int)FTUN_DIAL_PURPOSE_FRS_UPDATE; purpose++) {
    fixture_t fixture;
    ftun_operation_t *operation = NULL;
    CHECK(fixture_start(&fixture, 16384u, 2u) == 0);
    fixture.request.purpose = (ftun_dial_purpose_t)purpose;
    fixture.request.transport = (purpose & 1) != 0 ? FTUN_DIAL_TCP : FTUN_DIAL_UDP;
    fixture.socket.connect_status = FTUN_OK;
    CHECK(ftun_dial_start_with_io(NULL, &fixture.request, &fixture.io,
                                  &operation) == FTUN_OK);
    CHECK(operation != NULL && fixture.socket.protect_calls == 1 &&
          fixture.socket.connect_calls == 1);
    CHECK(dispatch_all(&fixture) == 0);
    CHECK(fixture.completion.error.status == FTUN_OK &&
          fixture.completion.error.stage == FTUN_DIAL_STAGE_CONNECT &&
          fixture.completion.result.purpose == (ftun_dial_purpose_t)purpose &&
          fixture.completion.result.transport == fixture.request.transport &&
          fixture.socket.close_calls == 0);
    CHECK(fixture_stop(&fixture) == 0);
  }
  return 0;
}

static int test_network_view_domains(void)
{
  ftun_network_prefix_t prefix = {{10u, 0u, 0u, 0u}, 8u};
  ftun_network_route_t route = {
    {{10u, 0u, 0u, 0u}, 8u},
    FTUN_DIAL_PURPOSE_BIT(FTUN_DIAL_PURPOSE_PROXY)
  };
  ftun_network_view_spec_t spec;
  ftun_network_view_t *view = NULL;
  ftun_network_view_t *revoked = NULL;
  ftun_endpoint_t allowed[2];
  fixture_t fixture;
  ftun_operation_t *operation = NULL;

  memset(&spec, 0, sizeof(spec));
  spec.generation = 41u;
  spec.protected_prefixes = &prefix;
  spec.protected_prefix_count = 1u;
  spec.overlay_routes = &route;
  spec.overlay_route_count = 1u;
  CHECK(ftun_network_view_create(&spec, &view) == FTUN_OK);
  CHECK(fixture_start(&fixture, 16384u, 4u) == 0);
  fixture.request.endpoint.address[0] = 10u;
  fixture.request.endpoint.address[1] = 2u;
  fixture.request.endpoint.address[2] = 3u;
  fixture.request.endpoint.address[3] = 4u;
  allowed[0] = fixture.request.endpoint;
  allowed[1] = fixture.request.endpoint;
  allowed[1].address[3] = 5u;
  fixture.request.allowed = allowed;
  fixture.request.allowed_count = 2u;
  fixture.request.network_view = view;
  fixture.request.network_generation = 41u;
  fixture.socket.connect_status = FTUN_OK;
  CHECK(ftun_dial_start_with_io(NULL, &fixture.request, &fixture.io,
                                &operation) == FTUN_OK);
  CHECK(operation != NULL && fixture.socket.protect_calls == 0 &&
        fixture.socket.connect_calls == 1);
  CHECK(dispatch_all(&fixture) == 0 && fixture.completion.calls == 1 &&
        fixture.completion.error.status == FTUN_OK &&
        fixture.completion.result.domain == FTUN_DIAL_DOMAIN_OVERLAY &&
        fixture.completion.result.network_generation == 41u);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(fixture_start(&fixture, 16384u, 4u) == 0);
  fixture.request.network_view = view;
  fixture.request.network_generation = 40u;
  CHECK(ftun_dial_start_with_io(NULL, &fixture.request, &fixture.io,
                                &operation) == FTUN_E_STALE &&
        operation == NULL && fixture.socket.open_calls == 0);
  fixture.request.network_generation = 0u;
  fixture.request.requested_domain = FTUN_DIAL_DOMAIN_OVERLAY;
  fixture.request.network_view = NULL;
  CHECK(ftun_dial_start_with_io(NULL, &fixture.request, &fixture.io,
                                &operation) == FTUN_E_UNSUPPORTED &&
        operation == NULL && fixture.socket.open_calls == 0);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(fixture_start(&fixture, 16384u, 4u) == 0);
  fixture.request.allowed = allowed;
  fixture.request.allowed_count = 1u;
  allowed[0] = fixture.request.endpoint;
  allowed[0].address[3] = 99u;
  CHECK(ftun_dial_start_with_io(NULL, &fixture.request, &fixture.io,
                                &operation) == FTUN_E_REJECTED &&
        operation == NULL && fixture.socket.open_calls == 0);
  CHECK(fixture_stop(&fixture) == 0);

  spec.generation = 42u;
  spec.overlay_routes = NULL;
  spec.overlay_route_count = 0u;
  CHECK(ftun_network_view_create(&spec, &revoked) == FTUN_OK);
  CHECK(fixture_start(&fixture, 16384u, 4u) == 0);
  fixture.request.endpoint.address[0] = 10u;
  fixture.request.endpoint.address[1] = 2u;
  fixture.request.endpoint.address[2] = 3u;
  fixture.request.endpoint.address[3] = 4u;
  fixture.request.network_view = revoked;
  fixture.request.network_generation = 42u;
  CHECK(ftun_dial_start_with_io(NULL, &fixture.request, &fixture.io,
                                &operation) == FTUN_E_REJECTED &&
        operation == NULL && fixture.socket.open_calls == 0);
  CHECK(fixture_stop(&fixture) == 0);
  CHECK(ftun_network_view_release(&revoked) == FTUN_OK);
  CHECK(ftun_network_view_release(&view) == FTUN_OK);
  return 0;
}

static void dummy_completed(ftun_operation_t *operation, ftun_error_t error,
                            void *user)
{
  int *calls = (int *)user;
  (void)operation;
  (void)error;
  (*calls)++;
}

static int test_admission_and_boundaries(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = (ftun_operation_t *)(uintptr_t)1;
  ftun_operation_t *blocker = NULL;
  ftun_operation_token_t blocker_completion = {0};
  ftun_reservation_t *reservation = NULL;
  ftun_budget_usage_t usage;
  ftun_error_t cancelled = {FTUN_E_CANCELLED, 0u, 0};
  int dummy_calls = 0;
  CHECK(fixture_start(&fixture, 16384u, 1u) == 0);
  CHECK(ftun_operation_accept(fixture.operations, dummy_completed,
                              &dummy_calls, &blocker,
                              &blocker_completion) == FTUN_OK);
  CHECK(ftun_dial_start_with_io(NULL, &fixture.request, &fixture.io,
                                &operation) == FTUN_E_LIMIT);
  CHECK(operation == NULL && fixture.socket.open_calls == 0 &&
        fixture.completion.calls == 0);
  CHECK(ftun_operation_complete(blocker_completion, cancelled) == FTUN_OK);
  CHECK(dispatch_all(&fixture) == 0 && dummy_calls == 1);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(fixture_start(&fixture, 16384u, 2u) == 0);
  CHECK(ftun_budget_get_usage(fixture.budget, &usage) == FTUN_OK);
  CHECK(usage.normal_available > 0u);
  CHECK(ftun_budget_reserve(fixture.budget, usage.normal_available,
                            &reservation) == FTUN_OK);
  operation = (ftun_operation_t *)(uintptr_t)1;
  CHECK(ftun_dial_start_with_io(NULL, &fixture.request, &fixture.io,
                                &operation) == FTUN_E_LIMIT);
  CHECK(operation == NULL && fixture.socket.open_calls == 0);
  CHECK(ftun_reservation_release(&reservation) == FTUN_OK);

  fixture.request.endpoint.kind = FTUN_ADDRESS_DOMAIN;
  operation = (ftun_operation_t *)(uintptr_t)1;
  CHECK(ftun_dial_start_with_io(NULL, &fixture.request, &fixture.io,
                                &operation) == FTUN_E_INVALID);
  CHECK(operation == NULL && fixture.socket.open_calls == 0);
  fixture.request.endpoint.kind = FTUN_ADDRESS_IPV4;
  fixture.request.protection.mark = 0u;
  CHECK(ftun_dial_start_with_io(NULL, &fixture.request, &fixture.io,
                                &operation) == FTUN_E_INVALID);
  CHECK(ftun_dial_start_with_io(NULL, &fixture.request, NULL,
                                &operation) == FTUN_E_INVALID);
  CHECK(ftun_dial_start_with_io(NULL, &fixture.request, &fixture.io,
                                NULL) == FTUN_E_INVALID);
  CHECK(fixture.completion.calls == 0);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

/* 仅由隔离网络命名空间显式调用，不加入普通 CTest。 */
static int test_real_loopback(void)
{
  ftun_budget_t *budget = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_operation_t *operation = NULL;
  ftun_dial_request_t request;
  completion_state_t completion;
  struct sockaddr_in address;
  socklen_t address_length = (socklen_t)sizeof(address);
  uint64_t now_ms = 0u;
  size_t dispatched = 0u;
  size_t callbacks = 0u;
  int listener;
  int accepted;
  int datagram_server;
  char byte = 'x';
  char received = '\0';

  memset(&request, 0, sizeof(request));
  memset(&completion, 0, sizeof(completion));
  memset(&address, 0, sizeof(address));
  listener = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                    IPPROTO_TCP);
  CHECK(listener >= 0);
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  CHECK(bind(listener, (const struct sockaddr *)&address,
             (socklen_t)sizeof(address)) == 0);
  CHECK(listen(listener, 1) == 0);
  CHECK(getsockname(listener, (struct sockaddr *)&address, &address_length) == 0);
  CHECK(address_length == (socklen_t)sizeof(address));
  CHECK(ftun_budget_create(NULL, 16384u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 2u, &operations) == FTUN_OK);
  CHECK(ftun_event_loop_create(NULL, &loop) == FTUN_OK);
  CHECK(ftun_libev_attach(loop) == FTUN_OK);
  CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK && now_ms <= UINT64_MAX - 2000u);
  request.loop = loop;
  request.operations = operations;
  request.budget = budget;
  request.endpoint.kind = FTUN_ADDRESS_IPV4;
  memcpy(request.endpoint.address, &address.sin_addr.s_addr, 4u);
  request.endpoint.port = ntohs(address.sin_port);
  request.protection.mark = 77u;
  request.deadline_ms = now_ms + 2000u;
  request.transport = FTUN_DIAL_TCP;
  request.purpose = FTUN_DIAL_PURPOSE_PROBE;
  request.completion = dial_completed;
  request.user = &completion;
  CHECK(ftun_dial_start(NULL, &request, &operation) == FTUN_OK);
  CHECK(operation != NULL);
  CHECK(ftun_operation_dispatch(operations, 1u, &dispatched) == FTUN_OK);
  if (dispatched == 0u) {
    CHECK(ftun_event_loop_run_once(loop, true, 4u, &callbacks) == FTUN_OK);
    CHECK(callbacks >= 1u);
    CHECK(ftun_operation_dispatch(operations, 1u, &dispatched) == FTUN_OK);
  }
  CHECK(dispatched == 1u && completion.calls == 1 &&
        completion.error.status == FTUN_OK &&
        completion.result.socket != FTUN_INVALID_SOCKET);
  accepted = accept(listener, NULL, NULL);
  CHECK(accepted >= 0);
  CHECK(close(accepted) == 0);
  CHECK(close((int)completion.result.socket) == 0);
  CHECK(close(listener) == 0);

  datagram_server = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                           IPPROTO_UDP);
  CHECK(datagram_server >= 0);
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address_length = (socklen_t)sizeof(address);
  CHECK(bind(datagram_server, (const struct sockaddr *)&address,
             (socklen_t)sizeof(address)) == 0);
  CHECK(getsockname(datagram_server, (struct sockaddr *)&address,
                    &address_length) == 0);
  memset(&completion, 0, sizeof(completion));
  memcpy(request.endpoint.address, &address.sin_addr.s_addr, 4u);
  request.endpoint.port = ntohs(address.sin_port);
  request.transport = FTUN_DIAL_UDP;
  request.purpose = FTUN_DIAL_PURPOSE_DNS;
  operation = NULL;
  dispatched = 0u;
  CHECK(ftun_dial_start(NULL, &request, &operation) == FTUN_OK);
  CHECK(operation != NULL);
  CHECK(ftun_operation_dispatch(operations, 1u, &dispatched) == FTUN_OK);
  if (dispatched == 0u) {
    callbacks = 0u;
    CHECK(ftun_event_loop_run_once(loop, true, 4u, &callbacks) == FTUN_OK);
    CHECK(callbacks >= 1u);
    CHECK(ftun_operation_dispatch(operations, 1u, &dispatched) == FTUN_OK);
  }
  CHECK(dispatched == 1u && completion.calls == 1 &&
        completion.error.status == FTUN_OK &&
        completion.result.transport == FTUN_DIAL_UDP);
  CHECK(send((int)completion.result.socket, &byte, 1u, 0) == 1);
  CHECK(recv(datagram_server, &received, 1u, 0) == 1 && received == byte);
  CHECK(close((int)completion.result.socket) == 0);
  CHECK(close(datagram_server) == 0);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_libev_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

/* TASK-TRANSPORT-001 / TEST-TRANSPORT-001：准入、保护、异步终结与回滚。 */
int main(int argc, char **argv)
{
  if (argc == 2 && strcmp(argv[1], "--real-loopback") == 0) {
    return test_real_loopback();
  }
  CHECK(argc == 1);
  CHECK(test_pending_success() == 0);
  CHECK(test_cancel_paths() == 0);
  CHECK(test_async_failures() == 0);
  CHECK(test_synchronous_rejection() == 0);
  CHECK(test_all_purposes_protected() == 0);
  CHECK(test_network_view_domains() == 0);
  CHECK(test_admission_and_boundaries() == 0);
  return 0;
}
