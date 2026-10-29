#include <sys/socket.h>
#include "proxy/outbound/direct.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "direct contract failed at line %d: %s\n", __LINE__, #x); \
    return 1; \
  } \
} while (0)

#define SOCKET_BASE 100u
#define MAX_ATTEMPTS 8u

typedef struct {
  ftun_event_source_t *io_source;
  ftun_event_source_t *timer_source;
  int cancel_failures;
  int cancel_calls;
} backend_state_t;

typedef struct {
  ftun_status_t open_status[MAX_ATTEMPTS];
  ftun_status_t protect_status[MAX_ATTEMPTS];
  ftun_status_t connect_status[MAX_ATTEMPTS];
  ftun_status_t socket_error_status[MAX_ATTEMPTS];
  ftun_endpoint_t endpoints[MAX_ATTEMPTS];
  ftun_dial_transport_t transports[MAX_ATTEMPTS];
  uint32_t marks[MAX_ATTEMPTS];
  char devices[MAX_ATTEMPTS][FTUN_SOCKET_INTERFACE_BYTES];
  size_t open_calls;
  size_t protect_calls;
  size_t connect_calls;
  size_t get_error_calls;
  size_t close_calls;
  int closed[MAX_ATTEMPTS];
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
  ftun_endpoint_t candidates[3];
  ftun_target_t target;
  ftun_direct_request_t request;
  char device[8];
} fixture_t;

static ftun_status_t backend_io_start(void *user, ftun_event_source_t *source,
                                      ftun_native_socket_t socket,
                                      uint32_t interests)
{
  backend_state_t *state = (backend_state_t *)user;
  (void)socket;
  (void)interests;
  state->io_source = source;
  return FTUN_OK;
}

static ftun_status_t backend_timer_start(void *user,
                                         ftun_event_source_t *source,
                                         uint64_t deadline_ms)
{
  backend_state_t *state = (backend_state_t *)user;
  (void)deadline_ms;
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
  (void)user;
}

static void backend_destroy(void *user)
{
  (void)user;
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

static size_t socket_index(ftun_native_socket_t socket)
{
  if (socket < SOCKET_BASE || socket >= SOCKET_BASE + MAX_ATTEMPTS) {
    return MAX_ATTEMPTS;
  }
  return (size_t)(socket - SOCKET_BASE);
}

static ftun_status_t socket_open(void *user, ftun_dial_transport_t transport,
                                 ftun_native_socket_t *out)
{
  socket_state_t *state = (socket_state_t *)user;
  size_t index = state->open_calls;
  if (out != NULL) *out = FTUN_INVALID_SOCKET;
  if (out == NULL || index >= MAX_ATTEMPTS) return FTUN_E_LIMIT;
  state->open_calls++;
  state->transports[index] = transport;
  if (state->open_status[index] != FTUN_OK) return state->open_status[index];
  *out = SOCKET_BASE + index;
  return FTUN_OK;
}

static ftun_status_t socket_protect(void *user, ftun_native_socket_t socket,
                                    const ftun_socket_policy_t *policy)
{
  socket_state_t *state = (socket_state_t *)user;
  size_t index = socket_index(socket);
  if (index >= MAX_ATTEMPTS || policy == NULL ||
      policy->interface_name.length >= FTUN_SOCKET_INTERFACE_BYTES) {
    return FTUN_E_STATE_CORRUPT;
  }
  state->protect_calls++;
  state->marks[index] = policy->mark;
  if (policy->interface_name.length != 0u) {
    memcpy(state->devices[index], policy->interface_name.data,
           policy->interface_name.length);
  }
  return state->protect_status[index];
}

static ftun_status_t socket_connect(void *user, ftun_native_socket_t socket,
                                    const ftun_endpoint_t *endpoint)
{
  socket_state_t *state = (socket_state_t *)user;
  size_t index = socket_index(socket);
  if (index >= MAX_ATTEMPTS || endpoint == NULL) {
    return FTUN_E_STATE_CORRUPT;
  }
  state->connect_calls++;
  state->endpoints[index] = *endpoint;
  return state->connect_status[index];
}

static ftun_status_t socket_get_error(void *user,
                                      ftun_native_socket_t socket)
{
  socket_state_t *state = (socket_state_t *)user;
  size_t index = socket_index(socket);
  if (index >= MAX_ATTEMPTS) return FTUN_E_STATE_CORRUPT;
  state->get_error_calls++;
  return state->socket_error_status[index];
}

static ftun_status_t socket_close(void *user, ftun_native_socket_t socket)
{
  socket_state_t *state = (socket_state_t *)user;
  size_t index = socket_index(socket);
  if (index >= MAX_ATTEMPTS || state->closed[index]) {
    return FTUN_E_STATE_CORRUPT;
  }
  state->close_calls++;
  state->closed[index] = 1;
  return FTUN_OK;
}

static void direct_completed(ftun_operation_t *operation, ftun_error_t error,
                             const ftun_dial_result_t *result, void *user)
{
  completion_state_t *state = (completion_state_t *)user;
  state->calls++;
  state->operation = operation;
  state->error = error;
  state->result = *result;
}

static void endpoint_set(ftun_endpoint_t *endpoint, uint8_t last,
                         uint16_t port)
{
  memset(endpoint, 0, sizeof(*endpoint));
  endpoint->kind = FTUN_ADDRESS_IPV4;
  endpoint->address[0] = 192u;
  endpoint->address[1] = 0u;
  endpoint->address[2] = 2u;
  endpoint->address[3] = last;
  endpoint->port = port;
}

static int fixture_start(fixture_t *fixture, size_t budget_limit,
                         size_t operation_capacity)
{
  size_t index;
  memset(fixture, 0, sizeof(*fixture));
  for (index = 0u; index < MAX_ATTEMPTS; index++) {
    fixture->socket.socket_error_status[index] = FTUN_OK;
  }
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
  endpoint_set(&fixture->candidates[0], 10u, 443u);
  endpoint_set(&fixture->candidates[1], 20u, 443u);
  endpoint_set(&fixture->candidates[2], 30u, 443u);
  fixture->target.generation = 7u;
  fixture->target.original.kind = FTUN_ADDRESS_DOMAIN;
  fixture->target.original.domain.data = "origin.example";
  fixture->target.original.domain.length = 14u;
  fixture->target.original.port = 443u;
  fixture->target.identity = fixture->target.original.domain;
  fixture->target.identity_source = FTUN_DOMAIN_EXPLICIT;
  fixture->target.candidates = fixture->candidates;
  fixture->target.candidate_count = 3u;
  fixture->target.allowed = fixture->candidates;
  fixture->target.allowed_count = 2u;
  memcpy(fixture->device, "eth0", 5u);
  fixture->request.loop = fixture->loop;
  fixture->request.operations = fixture->operations;
  fixture->request.budget = fixture->budget;
  fixture->request.target = &fixture->target;
  fixture->request.protection.mark = 77u;
  fixture->request.protection.interface_name.data = fixture->device;
  fixture->request.protection.interface_name.length = 4u;
  fixture->request.deadline_ms = 1000u;
  fixture->request.transport = FTUN_DIAL_TCP;
  fixture->request.completion = direct_completed;
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
      usage.used_resources.memory_bytes != 0u) return 1;
  return ftun_budget_destroy(&fixture->budget) == FTUN_OK ? 0 : 1;
}

static int dispatch_all(fixture_t *fixture, size_t expected)
{
  size_t dispatched = 0u;
  if (ftun_operation_dispatch(fixture->operations, SIZE_MAX,
                              &dispatched) != FTUN_OK) return 1;
  return dispatched == expected ? 0 : 1;
}

static int test_immediate_success(void)
{
  ftun_dial_transport_t transports[2] = {FTUN_DIAL_TCP, FTUN_DIAL_UDP};
  size_t index;
  for (index = 0u; index < 2u; index++) {
    fixture_t fixture;
    ftun_operation_t *operation = NULL;
    CHECK(fixture_start(&fixture, 32768u, 4u) == 0);
    fixture.request.transport = transports[index];
    CHECK(ftun_direct_open_with_io(NULL, &fixture.request, &fixture.io,
                                   &operation) == FTUN_OK);
    CHECK(operation != NULL && fixture.completion.calls == 0);
    CHECK(fixture.socket.open_calls == 1u &&
          fixture.socket.protect_calls == 1u &&
          fixture.socket.connect_calls == 1u);
    CHECK(fixture.socket.transports[0] == transports[index]);
    CHECK(fixture.socket.marks[0] == 77u &&
          strcmp(fixture.socket.devices[0], "eth0") == 0);
    CHECK(dispatch_all(&fixture, 2u) == 0);
    CHECK(fixture.completion.calls == 1 &&
          fixture.completion.error.status == FTUN_OK);
    CHECK(fixture.completion.result.socket == SOCKET_BASE &&
          fixture.completion.result.transport == transports[index] &&
          fixture.completion.result.purpose == FTUN_DIAL_PURPOSE_BUSINESS);
    CHECK(socket_close(&fixture.socket,
                       fixture.completion.result.socket) == FTUN_OK);
    CHECK(fixture_stop(&fixture) == 0);
  }
  return 0;
}

static int test_async_retry_and_copy(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = NULL;
  size_t callbacks = 0u;
  CHECK(fixture_start(&fixture, 32768u, 6u) == 0);
  fixture.socket.connect_status[0] = FTUN_E_AGAIN;
  fixture.socket.socket_error_status[0] = FTUN_E_REJECTED;
  CHECK(ftun_direct_open_with_io(NULL, &fixture.request, &fixture.io,
                                 &operation) == FTUN_OK);
  CHECK(operation != NULL && fixture.backend.io_source != NULL &&
        fixture.backend.timer_source != NULL);
  fixture.candidates[1].address[3] = 99u;
  memcpy(fixture.device, "bad0", 5u);
  CHECK(ftun_event_io_ready(fixture.backend.io_source,
                            FTUN_EVENT_ERROR) == FTUN_OK);
  CHECK(ftun_event_loop_poll(fixture.loop, 1u, 4u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 1u && fixture.socket.get_error_calls == 1u);
  CHECK(dispatch_all(&fixture, 3u) == 0);
  CHECK(fixture.socket.open_calls == 2u &&
        fixture.socket.protect_calls == 2u &&
        fixture.socket.connect_calls == 2u);
  CHECK(fixture.socket.endpoints[0].address[3] == 10u &&
        fixture.socket.endpoints[1].address[3] == 20u);
  CHECK(strcmp(fixture.socket.devices[0], "eth0") == 0 &&
        strcmp(fixture.socket.devices[1], "eth0") == 0);
  CHECK(fixture.socket.close_calls == 1u && fixture.socket.closed[0]);
  CHECK(fixture.completion.calls == 1 &&
        fixture.completion.error.status == FTUN_OK &&
        fixture.completion.result.socket == SOCKET_BASE + 1u &&
        fixture.completion.result.endpoint.address[3] == 20u);
  CHECK(socket_close(&fixture.socket,
                     fixture.completion.result.socket) == FTUN_OK);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_sync_failures_and_udp_boundary(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = (ftun_operation_t *)(uintptr_t)1;
  ftun_budget_usage_t before;
  ftun_budget_usage_t after;
  CHECK(fixture_start(&fixture, 32768u, 4u) == 0);
  fixture.socket.connect_status[0] = FTUN_E_REJECTED;
  fixture.socket.connect_status[1] = FTUN_E_REJECTED;
  CHECK(ftun_budget_get_usage(fixture.budget, &before) == FTUN_OK);
  CHECK(ftun_direct_open_with_io(NULL, &fixture.request, &fixture.io,
                                 &operation) == FTUN_E_REJECTED);
  CHECK(operation == NULL && fixture.completion.calls == 0);
  CHECK(fixture.socket.open_calls == 2u && fixture.socket.close_calls == 2u);
  CHECK(ftun_budget_get_usage(fixture.budget, &after) == FTUN_OK &&
        after.used_resources.memory_bytes == before.used_resources.memory_bytes);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(fixture_start(&fixture, 32768u, 4u) == 0);
  fixture.request.transport = FTUN_DIAL_UDP;
  fixture.socket.connect_status[0] = FTUN_E_REJECTED;
  operation = (ftun_operation_t *)(uintptr_t)1;
  CHECK(ftun_direct_open_with_io(NULL, &fixture.request, &fixture.io,
                                 &operation) == FTUN_E_REJECTED);
  CHECK(operation == NULL && fixture.socket.open_calls == 1u &&
        fixture.socket.connect_calls == 1u && fixture.socket.close_calls == 1u &&
        fixture.socket.transports[0] == FTUN_DIAL_UDP);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_cancel_paths(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = NULL;
  CHECK(fixture_start(&fixture, 32768u, 4u) == 0);
  fixture.socket.connect_status[0] = FTUN_E_AGAIN;
  fixture.backend.cancel_failures = 1;
  CHECK(ftun_direct_open_with_io(NULL, &fixture.request, &fixture.io,
                                 &operation) == FTUN_OK);
  CHECK(ftun_operation_cancel(operation) == FTUN_E_IO);
  CHECK(fixture.socket.close_calls == 0u && fixture.backend.io_source != NULL);
  CHECK(ftun_operation_cancel(operation) == FTUN_E_AGAIN);
  CHECK(fixture.socket.close_calls == 1u && fixture.backend.io_source == NULL &&
        fixture.backend.timer_source == NULL);
  CHECK(dispatch_all(&fixture, 2u) == 0);
  CHECK(fixture.completion.calls == 1 &&
        fixture.completion.error.status == FTUN_E_CANCELLED &&
        fixture.completion.result.socket == FTUN_INVALID_SOCKET);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(fixture_start(&fixture, 32768u, 4u) == 0);
  CHECK(ftun_direct_open_with_io(NULL, &fixture.request, &fixture.io,
                                 &operation) == FTUN_OK);
  CHECK(ftun_operation_cancel(operation) == FTUN_E_AGAIN);
  CHECK(fixture.socket.close_calls == 1u);
  CHECK(dispatch_all(&fixture, 2u) == 0);
  CHECK(fixture.completion.calls == 1 &&
        fixture.completion.error.status == FTUN_E_CANCELLED);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_resolution_and_validation(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = (ftun_operation_t *)(uintptr_t)1;
  ftun_endpoint_t outside;
  CHECK(fixture_start(&fixture, 32768u, 4u) == 0);
  fixture.target.candidates = NULL;
  fixture.target.candidate_count = 0u;
  fixture.target.allowed = NULL;
  fixture.target.allowed_count = 0u;
  CHECK(ftun_direct_open_with_io(NULL, &fixture.request, &fixture.io,
                                 &operation) == FTUN_E_RESOLVE);
  CHECK(operation == NULL && fixture.socket.open_calls == 0u);

  fixture.target.candidates = fixture.candidates;
  fixture.target.candidate_count = 3u;
  fixture.target.allowed = NULL;
  fixture.target.allowed_count = 0u;
  CHECK(ftun_direct_open_with_io(NULL, &fixture.request, &fixture.io,
                                 &operation) == FTUN_E_REJECTED);
  endpoint_set(&outside, 40u, 443u);
  fixture.target.allowed = &outside;
  fixture.target.allowed_count = 1u;
  CHECK(ftun_direct_open_with_io(NULL, &fixture.request, &fixture.io,
                                 &operation) == FTUN_E_REJECTED);
  fixture.target.allowed = fixture.candidates;
  fixture.target.allowed_count = 2u;
  fixture.candidates[1] = fixture.candidates[0];
  CHECK(ftun_direct_open_with_io(NULL, &fixture.request, &fixture.io,
                                 &operation) == FTUN_E_INVALID);
  fixture.candidates[1].address[3] = 20u;
  fixture.request.protection.mark = 0u;
  CHECK(ftun_direct_open_with_io(NULL, &fixture.request, &fixture.io,
                                 &operation) == FTUN_E_INVALID);
  CHECK(ftun_direct_open_with_io(NULL, &fixture.request, NULL,
                                 &operation) == FTUN_E_INVALID);
  CHECK(ftun_direct_open_with_io(NULL, &fixture.request, &fixture.io,
                                 NULL) == FTUN_E_INVALID);
  CHECK(fixture.completion.calls == 0 && fixture.socket.open_calls == 0u);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(fixture_start(&fixture, 32768u, 1u) == 0);
  operation = (ftun_operation_t *)(uintptr_t)1;
  CHECK(ftun_direct_open_with_io(NULL, &fixture.request, &fixture.io,
                                 &operation) == FTUN_E_LIMIT);
  CHECK(operation == NULL && fixture.completion.calls == 0 &&
        fixture.socket.open_calls == 0u);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

int main(void)
{
  if (test_immediate_success() != 0) return 1;
  if (test_async_retry_and_copy() != 0) return 1;
  if (test_sync_failures_and_udp_boundary() != 0) return 1;
  if (test_cancel_paths() != 0) return 1;
  if (test_resolution_and_validation() != 0) return 1;
  return 0;
}
