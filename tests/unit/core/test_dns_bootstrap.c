#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "core/limits.h"
#include "core/operation.h"
#include "core/worker.h"
#include "libs/resolver/basic.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "dns bootstrap contract failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  ftun_event_source_t *io_source;
  ftun_event_source_t *timer_source;
  uint32_t interests;
  int cancel_failures;
  int cancel_calls;
  int stopped;
  int destroyed;
} backend_state_t;

typedef struct {
  ftun_status_t open_status;
  ftun_status_t protect_status;
  ftun_status_t connect_status[FTUN_BOOTSTRAP_MAX_SERVERS];
  ftun_status_t close_status;
  ftun_endpoint_t endpoints[FTUN_BOOTSTRAP_MAX_SERVERS];
  ftun_native_socket_t sockets[FTUN_BOOTSTRAP_MAX_SERVERS];
  uint32_t mark;
  char device[FTUN_SOCKET_INTERFACE_BYTES];
  int open_calls;
  int protect_calls;
  int connect_calls;
  int close_calls;
} socket_state_t;

typedef struct {
  ftun_status_t send_status;
  ftun_status_t receive_status;
  uint8_t sent[FTUN_DNS_HEADER_BYTES + FTUN_DNS_MAX_NAME_BYTES + 4u];
  size_t sent_length;
  uint8_t response[512];
  size_t response_length;
  ftun_endpoint_t source;
  int send_calls;
  int receive_calls;
} data_state_t;

typedef struct {
  int calls;
  ftun_error_t error;
  char domain[FTUN_SYSTEM_RESOLVER_MAX_DOMAIN_BYTES + 1u];
  ftun_endpoint_t addresses[FTUN_SYSTEM_RESOLVER_MAX_RESULTS];
  size_t address_count;
} completion_state_t;

typedef struct {
  int calls;
  ftun_status_t status;
} path_state_t;

typedef struct {
  ftun_budget_t *budget;
  ftun_operation_queue_t *operations;
  ftun_event_loop_t *loop;
  backend_state_t backend;
  socket_state_t sockets;
  data_state_t data;
  completion_state_t completion;
  path_state_t path;
  ftun_dial_io_t dial_io;
  ftun_bootstrap_io_t io;
  ftun_bootstrap_request_t request;
  ftun_endpoint_t servers[2];
} fixture_t;

static const uint8_t response_ok[] = {
  0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02,
  0x00, 0x00, 0x00, 0x00,
  0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
  0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
  0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
  0x00, 0x3c, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04,
  0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
  0x00, 0x3c, 0x00, 0x04, 0x05, 0x06, 0x07, 0x08
};

static const uint8_t response_nxdomain[] = {
  0x12, 0x34, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
  0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01
};

static const uint8_t response_tc[] = {
  0x12, 0x34, 0x83, 0x80, 0x00, 0x01, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
  0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01
};

static void sleep_one_millisecond(void)
{
  struct timespec delay = {0, 1000000L};
  (void)nanosleep(&delay, NULL);
}

static ftun_status_t backend_io_start(void *user, ftun_event_source_t *source,
                                      ftun_native_socket_t socket,
                                      uint32_t interests)
{
  backend_state_t *state = (backend_state_t *)user;
  (void)socket;
  state->io_source = source;
  state->interests = interests;
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
  ((backend_state_t *)user)->stopped++;
}

static void backend_destroy(void *user)
{
  ((backend_state_t *)user)->destroyed++;
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

static ftun_status_t socket_open(void *user, ftun_address_kind_t family, ftun_dial_transport_t transport,
                                 ftun_native_socket_t *out)
{
  if (family != FTUN_ADDRESS_IPV4) return FTUN_E_UNSUPPORTED;
  socket_state_t *state = (socket_state_t *)user;
  if (out != NULL) *out = FTUN_INVALID_SOCKET;
  if (out == NULL || transport != FTUN_DIAL_UDP) return FTUN_E_INVALID;
  if (state->open_status != FTUN_OK) return state->open_status;
  if (state->open_calls >= (int)FTUN_BOOTSTRAP_MAX_SERVERS) {
    return FTUN_E_LIMIT;
  }
  *out = (ftun_native_socket_t)(100 + state->open_calls);
  state->sockets[state->open_calls] = *out;
  state->open_calls++;
  return FTUN_OK;
}

static ftun_status_t socket_protect(void *user, ftun_native_socket_t socket,
                                    const ftun_socket_policy_t *policy)
{
  socket_state_t *state = (socket_state_t *)user;
  (void)socket;
  state->protect_calls++;
  state->mark = policy->mark;
  memset(state->device, 0, sizeof(state->device));
  if (policy->interface_name.length >= sizeof(state->device)) {
    return FTUN_E_INVALID;
  }
  if (policy->interface_name.length != 0u) {
    memcpy(state->device, policy->interface_name.data,
           policy->interface_name.length);
  }
  return state->protect_status;
}

static ftun_status_t socket_connect(void *user, ftun_native_socket_t socket,
                                    const ftun_endpoint_t *endpoint)
{
  socket_state_t *state = (socket_state_t *)user;
  int index = state->connect_calls;
  if (index >= (int)FTUN_BOOTSTRAP_MAX_SERVERS ||
      socket != state->sockets[index]) return FTUN_E_STATE_CORRUPT;
  state->endpoints[index] = *endpoint;
  state->connect_calls++;
  return state->connect_status[index];
}

static ftun_status_t socket_get_error(void *user, ftun_native_socket_t socket)
{
  (void)user;
  (void)socket;
  return FTUN_OK;
}

static ftun_status_t socket_close(void *user, ftun_native_socket_t socket)
{
  socket_state_t *state = (socket_state_t *)user;
  (void)socket;
  state->close_calls++;
  return state->close_status;
}

static ftun_status_t data_send(void *user, ftun_native_socket_t socket,
                               const void *data, size_t length,
                               size_t *out_sent)
{
  data_state_t *state = (data_state_t *)user;
  (void)socket;
  if (out_sent != NULL) *out_sent = 0u;
  state->send_calls++;
  if (state->send_status != FTUN_OK) return state->send_status;
  if (out_sent == NULL || length > sizeof(state->sent)) return FTUN_E_LIMIT;
  memcpy(state->sent, data, length);
  state->sent_length = length;
  *out_sent = length;
  return FTUN_OK;
}

static ftun_status_t data_receive(void *user, ftun_native_socket_t socket,
                                  void *data, size_t capacity,
                                  size_t *out_received,
                                  ftun_endpoint_t *out_source)
{
  data_state_t *state = (data_state_t *)user;
  (void)socket;
  if (out_received != NULL) *out_received = 0u;
  if (out_source != NULL) memset(out_source, 0, sizeof(*out_source));
  state->receive_calls++;
  if (state->receive_status != FTUN_OK) return state->receive_status;
  if (state->response_length > capacity) return FTUN_E_LIMIT;
  memcpy(data, state->response, state->response_length);
  *out_received = state->response_length;
  *out_source = state->source;
  state->receive_status = FTUN_E_AGAIN;
  return FTUN_OK;
}

static ftun_status_t check_path(void *user,
                                const ftun_socket_policy_t *protection)
{
  path_state_t *state = (path_state_t *)user;
  (void)protection;
  state->calls++;
  return state->status;
}

static void completed(ftun_operation_t *operation, ftun_error_t error,
                      const ftun_system_resolve_result_t *result, void *user)
{
  completion_state_t *state = (completion_state_t *)user;
  size_t index;
  (void)operation;
  state->calls++;
  state->error = error;
  if (result == NULL || result->domain.length >
      FTUN_SYSTEM_RESOLVER_MAX_DOMAIN_BYTES ||
      result->address_count > FTUN_SYSTEM_RESOLVER_MAX_RESULTS) {
    state->calls = -100;
    return;
  }
  memcpy(state->domain, result->domain.data, result->domain.length);
  state->domain[result->domain.length] = '\0';
  state->address_count = result->address_count;
  for (index = 0u; index < result->address_count; index++) {
    state->addresses[index] = result->addresses[index];
  }
}

static void endpoint(ftun_endpoint_t *out, uint8_t a, uint8_t b,
                     uint8_t c, uint8_t d, uint16_t port)
{
  memset(out, 0, sizeof(*out));
  out->kind = FTUN_ADDRESS_IPV4;
  out->address[0] = a;
  out->address[1] = b;
  out->address[2] = c;
  out->address[3] = d;
  out->port = port;
}

static int fixture_start(fixture_t *fixture, size_t operation_capacity)
{
  memset(fixture, 0, sizeof(*fixture));
  if (ftun_budget_create(NULL, 131072u, 1024u, &fixture->budget) != FTUN_OK ||
      ftun_operation_queue_create(fixture->budget, operation_capacity,
                                  &fixture->operations) != FTUN_OK ||
      ftun_event_loop_create(NULL, &fixture->loop) != FTUN_OK ||
      ftun_event_loop_attach_backend(fixture->loop, &backend_ops,
                                     &fixture->backend) != FTUN_OK) return 1;
  fixture->dial_io.open_socket = socket_open;
  fixture->dial_io.protect_socket = socket_protect;
  fixture->dial_io.connect_socket = socket_connect;
  fixture->dial_io.get_socket_error = socket_get_error;
  fixture->dial_io.close_socket = socket_close;
  fixture->dial_io.context = &fixture->sockets;
  fixture->io.send_datagram = data_send;
  fixture->io.receive_datagram = data_receive;
  fixture->io.context = &fixture->data;
  endpoint(&fixture->servers[0], 9u, 9u, 9u, 9u, 53u);
  endpoint(&fixture->servers[1], 1u, 1u, 1u, 1u, 53u);
  fixture->request.loop = fixture->loop;
  fixture->request.operations = fixture->operations;
  fixture->request.budget = fixture->budget;
  fixture->request.domain.data = "example.com";
  fixture->request.domain.length = 11u;
  fixture->request.servers = fixture->servers;
  fixture->request.server_count = 1u;
  fixture->request.protection.mark = 77u;
  fixture->request.protection.interface_name.data = "eth0";
  fixture->request.protection.interface_name.length = 4u;
  fixture->request.deadline_ms = 1000u;
  fixture->request.query_id = 0x1234u;
  fixture->request.check_system_path = check_path;
  fixture->request.system_path_user = &fixture->path;
  fixture->request.completion = completed;
  fixture->request.user = &fixture->completion;
  fixture->data.receive_status = FTUN_E_AGAIN;
  return 0;
}

static int fixture_stop(fixture_t *fixture)
{
  ftun_budget_usage_t usage;
  if (fixture->backend.io_source != NULL ||
      fixture->backend.timer_source != NULL) return 1;
  if (ftun_event_loop_stop(fixture->loop) != FTUN_OK ||
      ftun_event_loop_detach_backend(fixture->loop) != FTUN_OK ||
      ftun_event_loop_destroy(&fixture->loop) != FTUN_OK ||
      ftun_operation_queue_destroy(&fixture->operations) != FTUN_OK ||
      ftun_budget_get_usage(fixture->budget, &usage) != FTUN_OK ||
      usage.used_resources.memory_bytes != 0u || ftun_budget_destroy(&fixture->budget) != FTUN_OK) {
    return 1;
  }
  return 0;
}

static int dispatch_operations(fixture_t *fixture, size_t expected)
{
  size_t dispatched = 0u;
  if (ftun_operation_dispatch(fixture->operations, 16u, &dispatched) !=
      FTUN_OK) return 0;
  return dispatched == expected;
}

static int deliver(fixture_t *fixture, const uint8_t *wire, size_t length,
                   const ftun_endpoint_t *source)
{
  size_t callbacks = 0u;
  if (length > sizeof(fixture->data.response) ||
      fixture->backend.io_source == NULL) return 0;
  memcpy(fixture->data.response, wire, length);
  fixture->data.response_length = length;
  fixture->data.source = *source;
  fixture->data.receive_status = FTUN_OK;
  if (ftun_event_io_ready(fixture->backend.io_source,
                          FTUN_EVENT_READ) != FTUN_OK ||
      ftun_event_loop_poll(fixture->loop, 500u, 8u, &callbacks) != FTUN_OK ||
      callbacks != 1u) return 0;
  return 1;
}

static int test_explicit_success_and_copy(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = NULL;
  ftun_dns_message_t *query = NULL;
  char domain[] = "example.com";
  CHECK(fixture_start(&fixture, 8u) == 0);
  fixture.request.domain.data = domain;
  CHECK(ftun_bootstrap_resolve_with_io(NULL, &fixture.request,
                                       &fixture.dial_io, &fixture.io,
                                       &operation) == FTUN_OK);
  CHECK(operation != NULL && fixture.completion.calls == 0 &&
        fixture.path.calls == 0);
  memcpy(domain, "xxxxxxx.xxx", 11u);
  memset(fixture.servers[0].address, 4, 4u);
  fixture.request.protection.interface_name.data = "bad0";
  CHECK(dispatch_operations(&fixture, 1u));
  CHECK(fixture.sockets.open_calls == 1 && fixture.sockets.protect_calls == 1 &&
        fixture.sockets.connect_calls == 1 && fixture.sockets.mark == 77u &&
        strcmp(fixture.sockets.device, "eth0") == 0);
  CHECK(fixture.sockets.endpoints[0].address[0] == 9u &&
        fixture.data.send_calls == 1 &&
        (fixture.backend.interests & FTUN_EVENT_READ) != 0u);
  CHECK(ftun_dns_message_parse(
          (ftun_bytes_t){fixture.data.sent, fixture.data.sent_length},
          &query) == FTUN_OK);
  CHECK(query->id == 0x1234u && query->question.type == 1u &&
        query->question.class_code == 1u);
  ftun_dns_message_release(&query);
  CHECK(deliver(&fixture, response_ok, sizeof(response_ok),
                &fixture.sockets.endpoints[0]));
  CHECK(dispatch_operations(&fixture, 1u));
  CHECK(fixture.completion.calls == 1 &&
        fixture.completion.error.status == FTUN_OK &&
        fixture.completion.error.stage == FTUN_BOOTSTRAP_STAGE_RESPONSE &&
        strcmp(fixture.completion.domain, "example.com") == 0 &&
        fixture.completion.address_count == 2u);
  CHECK(fixture.completion.addresses[0].address[0] == 1u &&
        fixture.completion.addresses[1].address[0] == 5u &&
        fixture.sockets.close_calls == 1);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_source_filter_and_retry(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = NULL;
  ftun_endpoint_t wrong;
  CHECK(fixture_start(&fixture, 8u) == 0);
  fixture.request.server_count = 2u;
  CHECK(ftun_bootstrap_resolve_with_io(NULL, &fixture.request,
                                       &fixture.dial_io, &fixture.io,
                                       &operation) == FTUN_OK);
  CHECK(dispatch_operations(&fixture, 1u));
  endpoint(&wrong, 8u, 8u, 8u, 8u, 53u);
  CHECK(deliver(&fixture, response_ok, sizeof(response_ok), &wrong));
  CHECK(fixture.completion.calls == 0 && fixture.sockets.close_calls == 0 &&
        fixture.backend.io_source != NULL);
  CHECK(deliver(&fixture, response_nxdomain, sizeof(response_nxdomain),
                &fixture.sockets.endpoints[0]));
  CHECK(fixture.completion.calls == 0 && fixture.sockets.close_calls == 1);
  CHECK(dispatch_operations(&fixture, 1u));
  CHECK(fixture.sockets.connect_calls == 2 &&
        fixture.sockets.endpoints[1].address[0] == 1u &&
        fixture.path.calls == 0);
  CHECK(deliver(&fixture, response_ok, sizeof(response_ok),
                &fixture.sockets.endpoints[1]));
  CHECK(dispatch_operations(&fixture, 1u));
  CHECK(fixture.completion.calls == 1 &&
        fixture.completion.error.status == FTUN_OK &&
        fixture.sockets.close_calls == 2);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_tc_timeout_and_cancel(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = NULL;
  size_t callbacks = 0u;
  CHECK(fixture_start(&fixture, 8u) == 0);
  CHECK(ftun_bootstrap_resolve_with_io(NULL, &fixture.request,
                                       &fixture.dial_io, &fixture.io,
                                       &operation) == FTUN_OK);
  CHECK(dispatch_operations(&fixture, 1u));
  CHECK(deliver(&fixture, response_tc, sizeof(response_tc),
                &fixture.sockets.endpoints[0]));
  CHECK(dispatch_operations(&fixture, 1u));
  CHECK(fixture.completion.error.status == FTUN_E_UNSUPPORTED &&
        fixture.completion.error.stage == FTUN_BOOTSTRAP_STAGE_RESPONSE);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(fixture_start(&fixture, 8u) == 0);
  CHECK(ftun_bootstrap_resolve_with_io(NULL, &fixture.request,
                                       &fixture.dial_io, &fixture.io,
                                       &operation) == FTUN_OK);
  CHECK(dispatch_operations(&fixture, 1u));
  CHECK(ftun_event_timer_ready(fixture.backend.timer_source) == FTUN_OK);
  CHECK(ftun_event_loop_poll(fixture.loop, 1000u, 8u, &callbacks) == FTUN_OK &&
        callbacks == 1u);
  CHECK(dispatch_operations(&fixture, 1u));
  CHECK(fixture.completion.error.status == FTUN_E_TIMEOUT &&
        fixture.completion.error.stage == FTUN_BOOTSTRAP_STAGE_TIMEOUT);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(fixture_start(&fixture, 8u) == 0);
  CHECK(ftun_bootstrap_resolve_with_io(NULL, &fixture.request,
                                       &fixture.dial_io, &fixture.io,
                                       &operation) == FTUN_OK);
  CHECK(dispatch_operations(&fixture, 1u));
  fixture.backend.cancel_failures = 1;
  CHECK(ftun_operation_cancel(operation) == FTUN_E_IO);
  CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  CHECK(dispatch_operations(&fixture, 1u));
  CHECK(fixture.completion.calls == 1 &&
        fixture.completion.error.status == FTUN_E_CANCELLED &&
        fixture.sockets.close_calls == 1);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_cancel_failure_then_response(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = NULL;
  CHECK(fixture_start(&fixture, 8u) == 0);
  CHECK(ftun_bootstrap_resolve_with_io(NULL, &fixture.request,
                                       &fixture.dial_io, &fixture.io,
                                       &operation) == FTUN_OK);
  CHECK(dispatch_operations(&fixture, 1u));
  fixture.backend.cancel_failures = 1;
  CHECK(ftun_operation_cancel(operation) == FTUN_E_IO);
  CHECK(fixture.completion.calls == 0 && fixture.sockets.close_calls == 0);
  CHECK(deliver(&fixture, response_ok, sizeof(response_ok),
                &fixture.sockets.endpoints[0]));
  CHECK(dispatch_operations(&fixture, 1u));
  CHECK(fixture.completion.calls == 1 && fixture.completion.error.status == FTUN_OK &&
        fixture.completion.address_count == 2u && fixture.sockets.close_calls == 1);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_send_again_and_deferred_cleanup(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = NULL;
  size_t callbacks = 0u;
  CHECK(fixture_start(&fixture, 8u) == 0);
  fixture.data.send_status = FTUN_E_AGAIN;
  CHECK(ftun_bootstrap_resolve_with_io(NULL, &fixture.request,
                                       &fixture.dial_io, &fixture.io,
                                       &operation) == FTUN_OK);
  CHECK(dispatch_operations(&fixture, 1u));
  CHECK(fixture.data.send_calls == 1 &&
        (fixture.backend.interests & FTUN_EVENT_WRITE) != 0u);
  fixture.data.send_status = FTUN_OK;
  CHECK(ftun_event_io_ready(fixture.backend.io_source,
                            FTUN_EVENT_WRITE) == FTUN_OK);
  CHECK(ftun_event_loop_poll(fixture.loop, 500u, 1u, &callbacks) == FTUN_OK &&
        callbacks == 1u && fixture.data.send_calls == 2 &&
        (fixture.backend.interests & FTUN_EVENT_READ) != 0u);
  CHECK(deliver(&fixture, response_ok, sizeof(response_ok),
                &fixture.sockets.endpoints[0]));
  CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  CHECK(dispatch_operations(&fixture, 1u));
  CHECK(fixture.completion.error.status == FTUN_E_CANCELLED &&
        fixture.completion.address_count == 0u);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(fixture_start(&fixture, 8u) == 0);
  CHECK(ftun_bootstrap_resolve_with_io(NULL, &fixture.request,
                                       &fixture.dial_io, &fixture.io,
                                       &operation) == FTUN_OK);
  CHECK(dispatch_operations(&fixture, 1u));
  memcpy(fixture.data.response, response_ok, sizeof(response_ok));
  fixture.data.response_length = sizeof(response_ok);
  fixture.data.source = fixture.sockets.endpoints[0];
  fixture.data.receive_status = FTUN_OK;
  fixture.backend.cancel_failures = 1;
  CHECK(ftun_event_io_ready(fixture.backend.io_source,
                            FTUN_EVENT_READ) == FTUN_OK);
  callbacks = 0u;
  CHECK(ftun_event_loop_poll(fixture.loop, 500u, 1u, &callbacks) == FTUN_OK &&
        callbacks == 1u && fixture.completion.calls == 0);
  CHECK(ftun_operation_cancel(operation) == FTUN_E_AGAIN);
  callbacks = 0u;
  CHECK(ftun_event_loop_poll(fixture.loop, 500u, 1u, &callbacks) == FTUN_OK &&
        callbacks == 1u);
  CHECK(dispatch_operations(&fixture, 1u));
  CHECK(fixture.completion.error.status == FTUN_OK &&
        fixture.completion.address_count == 2u);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_sync_boundaries(void)
{
  fixture_t fixture;
  completion_state_t limited = {0};
  ftun_budget_t *tiny = NULL;
  ftun_operation_t *operation = (ftun_operation_t *)(uintptr_t)1;
  CHECK(fixture_start(&fixture, 8u) == 0);
  fixture.sockets.protect_status = FTUN_E_REJECTED;
  CHECK(ftun_bootstrap_resolve_with_io(NULL, &fixture.request,
                                       &fixture.dial_io, &fixture.io,
                                       &operation) == FTUN_E_REJECTED);
  CHECK(operation == NULL && fixture.completion.calls == 0 &&
        fixture.path.calls == 0 && fixture.sockets.close_calls == 1);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(fixture_start(&fixture, 1u) == 0);
  CHECK(ftun_bootstrap_resolve_with_io(NULL, &fixture.request,
                                       &fixture.dial_io, &fixture.io,
                                       &operation) == FTUN_E_LIMIT);
  CHECK(operation == NULL && fixture.completion.calls == 0);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(fixture_start(&fixture, 8u) == 0);
  CHECK(ftun_budget_create(NULL, 1u, 0u, &tiny) == FTUN_OK);
  fixture.request.budget = tiny;
  fixture.request.user = &limited;
  CHECK(ftun_bootstrap_resolve_with_io(NULL, &fixture.request,
                                       &fixture.dial_io, &fixture.io,
                                       &operation) == FTUN_E_LIMIT);
  CHECK(operation == NULL && limited.calls == 0);
  CHECK(ftun_budget_destroy(&tiny) == FTUN_OK);
  fixture.request.budget = fixture.budget;
  fixture.servers[1] = fixture.servers[0];
  fixture.request.server_count = 2u;
  CHECK(ftun_bootstrap_resolve_with_io(NULL, &fixture.request,
                                       &fixture.dial_io, &fixture.io,
                                       &operation) == FTUN_E_INVALID);
  fixture.request.server_count = FTUN_BOOTSTRAP_MAX_SERVERS + 1u;
  CHECK(ftun_bootstrap_resolve_with_io(NULL, &fixture.request,
                                       &fixture.dial_io, &fixture.io,
                                       &operation) == FTUN_E_INVALID);
  CHECK(ftun_bootstrap_resolve_with_io(NULL, NULL, &fixture.dial_io,
                                       &fixture.io, &operation) ==
        FTUN_E_INVALID);
  CHECK(ftun_bootstrap_resolve_with_io(NULL, &fixture.request,
                                       &fixture.dial_io, &fixture.io,
                                       NULL) == FTUN_E_INVALID);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int wait_for_system(ftun_worker_t *worker, completion_state_t *state)
{
  size_t attempt;
  for (attempt = 0u; attempt < 5000u; attempt++) {
    size_t dispatched = 0u;
    if (ftun_worker_poll(worker, 8u, &dispatched) != FTUN_OK) return 0;
    if (state->calls == 1) return 1;
    sleep_one_millisecond();
  }
  return 0;
}

static int test_system_branch(void)
{
  ftun_budget_t *budget = NULL;
  ftun_worker_t *worker = NULL;
  ftun_operation_t *operation = NULL;
  ftun_bootstrap_request_t request;
  completion_state_t state = {0};
  path_state_t path = {0};
  ftun_budget_usage_t usage;
  size_t index;
  int found = 0;
  CHECK(ftun_budget_create(NULL, 65536u, 1024u, &budget) == FTUN_OK);
  CHECK(ftun_worker_create(budget, 1u, &worker) == FTUN_OK);
  memset(&request, 0, sizeof(request));
  request.worker = worker;
  request.budget = budget;
  request.domain.data = "localhost";
  request.domain.length = 9u;
  request.protection.mark = 77u;
  request.check_system_path = check_path;
  request.system_path_user = &path;
  request.completion = completed;
  request.user = &state;
  CHECK(ftun_bootstrap_resolve(NULL, &request, &operation) == FTUN_OK);
  CHECK(operation != NULL && path.calls == 1 && state.calls == 0);
  CHECK(wait_for_system(worker, &state));
  CHECK(state.error.status == FTUN_OK && state.address_count != 0u);
  for (index = 0u; index < state.address_count; index++) {
    if (state.addresses[index].address[0] == 127u) found = 1;
  }
  CHECK(found);
  CHECK(ftun_worker_stop(worker) == FTUN_OK);
  CHECK(ftun_worker_join(worker) == FTUN_OK);
  CHECK(ftun_worker_destroy(&worker) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

/* 显式 DIRECT 源与 SystemResolver 分支。 */
int main(void)
{
  CHECK(test_explicit_success_and_copy() == 0);
  CHECK(test_source_filter_and_retry() == 0);
  CHECK(test_tc_timeout_and_cancel() == 0);
  CHECK(test_cancel_failure_then_response() == 0);
  CHECK(test_send_again_and_deferred_cleanup() == 0);
  CHECK(test_sync_boundaries() == 0);
  CHECK(test_system_branch() == 0);
  return 0;
}
