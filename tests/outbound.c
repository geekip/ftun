#include "proxy/outbound/outbound.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "outbound contract failed at line %d: %s\n", __LINE__, #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  ftun_budget_t *budget;
  ftun_operation_queue_t *operations;
  ftun_endpoint_t candidates[2];
  ftun_target_t target;
  ftun_route_result_t route;
  ftun_outbound_leaf_t leaf;
  ftun_metadata_t metadata;
  ftun_direct_request_t direct;
  ftun_socks5_connect_request_t socks5;
  ftun_outbound_request_t request;
  ftun_outbound_backend_t backend;
  ftun_status_t direct_status;
  ftun_status_t socks5_status;
  ftun_status_t reject_status;
  ftun_reject_result_t reject_value;
  const ftun_target_t *captured_target;
  ftun_dial_transport_t captured_transport;
  int direct_calls;
  int socks5_calls;
  int reject_calls;
  int completion_calls;
  ftun_error_t completion_error;
  ftun_operation_token_t mock_completion;
} fixture_t;

static void operation_completed(ftun_operation_t *operation,
                                ftun_error_t error, void *user)
{
  fixture_t *fixture = (fixture_t *)user;
  (void)operation;
  fixture->completion_calls++;
  fixture->completion_error = error;
}

static ftun_status_t mock_direct_open(
  void *user, ftun_core_t *core, const ftun_direct_request_t *request,
  ftun_operation_t **out)
{
  fixture_t *fixture = (fixture_t *)user;
  (void)core;
  fixture->direct_calls++;
  fixture->captured_target = request->target;
  fixture->captured_transport = request->transport;
  if (out != NULL) *out = NULL;
  if (fixture->direct_status != FTUN_OK) return fixture->direct_status;
  return ftun_operation_accept(request->operations, operation_completed,
                               fixture, out, &fixture->mock_completion);
}

static ftun_status_t mock_socks5_open(
  void *user, ftun_core_t *core,
  const ftun_socks5_connect_request_t *request, ftun_operation_t **out)
{
  fixture_t *fixture = (fixture_t *)user;
  (void)core;
  fixture->socks5_calls++;
  fixture->captured_target = request->target;
  fixture->captured_transport = request->transport;
  if (out != NULL) *out = NULL;
  if (fixture->socks5_status != FTUN_OK) return fixture->socks5_status;
  return ftun_operation_accept(request->operations, operation_completed,
                               fixture, out, &fixture->mock_completion);
}

static ftun_status_t mock_reject_classify(
  void *user, const ftun_metadata_t *metadata, bool dns_query,
  ftun_reject_result_t *out)
{
  fixture_t *fixture = (fixture_t *)user;
  (void)metadata;
  (void)dns_query;
  fixture->reject_calls++;
  if (out != NULL) *out = fixture->reject_value;
  return fixture->reject_status;
}

static void endpoint_set(ftun_endpoint_t *endpoint, uint8_t last)
{
  memset(endpoint, 0, sizeof(*endpoint));
  endpoint->kind = FTUN_ADDRESS_IPV4;
  endpoint->address[0] = 192u;
  endpoint->address[1] = 0u;
  endpoint->address[2] = 2u;
  endpoint->address[3] = last;
  endpoint->port = 443u;
}

static int fixture_start(fixture_t *fixture)
{
  memset(fixture, 0, sizeof(*fixture));
  if (ftun_budget_create(NULL, 16384u, 0u, &fixture->budget) != FTUN_OK) {
    return 1;
  }
  if (ftun_operation_queue_create(fixture->budget, 4u,
                                  &fixture->operations) != FTUN_OK) return 1;
  endpoint_set(&fixture->candidates[0], 10u);
  endpoint_set(&fixture->candidates[1], 20u);
  fixture->target.generation = 4u;
  fixture->target.original = fixture->candidates[0];
  fixture->target.candidates = fixture->candidates;
  fixture->target.candidate_count = 2u;
  fixture->target.allowed = fixture->candidates;
  fixture->target.allowed_count = 2u;
  fixture->route.kind = FTUN_ROUTE_READY;
  fixture->route.generation = 4u;
  fixture->route.outbound_id = 7u;
  fixture->route.allowed = fixture->candidates;
  fixture->route.allowed_count = 2u;
  fixture->leaf.generation = 4u;
  fixture->leaf.id = 7u;
  fixture->leaf.kind = FTUN_OUTBOUND_LEAF_DIRECT;
  fixture->leaf.supports_tcp = true;
  fixture->leaf.supports_udp = true;
  fixture->metadata.generation = 4u;
  fixture->metadata.known_fields = FTUN_META_NETWORK;
  fixture->metadata.network = 1u;
  fixture->direct.operations = fixture->operations;
  fixture->socks5.operations = fixture->operations;
  fixture->request.route = &fixture->route;
  fixture->request.target = &fixture->target;
  fixture->request.leaf = &fixture->leaf;
  fixture->request.transport = FTUN_DIAL_TCP;
  fixture->request.direct = &fixture->direct;
  fixture->backend.direct_open = mock_direct_open;
  fixture->backend.socks5_open = mock_socks5_open;
  fixture->backend.reject_classify = mock_reject_classify;
  fixture->backend.context = fixture;
  fixture->reject_value.action = FTUN_REJECT_TCP_REFUSE;
  fixture->reject_value.terminal_status = FTUN_E_REJECTED;
  return 0;
}

static int fixture_stop(fixture_t *fixture)
{
  ftun_budget_usage_t usage;
  if (ftun_operation_queue_destroy(&fixture->operations) != FTUN_OK) return 1;
  if (ftun_budget_get_usage(fixture->budget, &usage) != FTUN_OK ||
      usage.used != 0u) return 1;
  return ftun_budget_destroy(&fixture->budget) == FTUN_OK ? 0 : 1;
}

static int test_direct_passthrough_and_cancel(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = NULL;
  ftun_reject_result_t reject;
  size_t dispatched = 0u;
  CHECK(fixture_start(&fixture) == 0);
  CHECK(ftun_outbound_open_with_backend(NULL, &fixture.request,
                                         &fixture.backend, &reject,
                                         &operation) == FTUN_OK);
  CHECK(operation != NULL && fixture.direct_calls == 1 &&
        fixture.socks5_calls == 0 && fixture.reject_calls == 0);
  CHECK(fixture.captured_target == &fixture.target &&
        fixture.captured_transport == FTUN_DIAL_TCP &&
        reject.action == 0);
  CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  CHECK(ftun_operation_dispatch(fixture.operations, SIZE_MAX,
                                &dispatched) == FTUN_OK && dispatched == 1u);
  CHECK(fixture.completion_calls == 1 &&
        fixture.completion_error.status == FTUN_E_CANCELLED);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_socks_failure_never_falls_back(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = (ftun_operation_t *)(uintptr_t)1;
  ftun_reject_result_t reject;
  CHECK(fixture_start(&fixture) == 0);
  fixture.leaf.kind = FTUN_OUTBOUND_LEAF_SOCKS5;
  fixture.request.direct = NULL;
  fixture.request.socks5 = &fixture.socks5;
  fixture.socks5_status = FTUN_E_REJECTED;
  CHECK(ftun_outbound_open_with_backend(NULL, &fixture.request,
                                         &fixture.backend, &reject,
                                         &operation) == FTUN_E_REJECTED);
  CHECK(operation == NULL && fixture.socks5_calls == 1 &&
        fixture.direct_calls == 0 && fixture.reject_calls == 0);
  fixture.leaf.supports_udp = false;
  fixture.request.transport = FTUN_DIAL_UDP;
  CHECK(ftun_outbound_open_with_backend(NULL, &fixture.request,
                                         &fixture.backend, &reject,
                                         &operation) == FTUN_E_UNSUPPORTED);
  CHECK(fixture.socks5_calls == 1 && fixture.direct_calls == 0);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_reject_mapping(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = (ftun_operation_t *)(uintptr_t)1;
  ftun_reject_result_t reject;
  CHECK(fixture_start(&fixture) == 0);
  fixture.leaf.kind = FTUN_OUTBOUND_LEAF_REJECT;
  fixture.request.direct = NULL;
  fixture.request.metadata = &fixture.metadata;
  CHECK(ftun_outbound_open_with_backend(NULL, &fixture.request,
                                         &fixture.backend, &reject,
                                         &operation) == FTUN_E_REJECTED);
  CHECK(operation == NULL && fixture.reject_calls == 1 &&
        reject.action == FTUN_REJECT_TCP_REFUSE &&
        reject.terminal_status == FTUN_E_REJECTED &&
        fixture.direct_calls == 0 && fixture.socks5_calls == 0);
  fixture.request.transport = FTUN_DIAL_UDP;
  fixture.metadata.network = 2u;
  fixture.reject_value.action = FTUN_REJECT_UDP_DROP;
  CHECK(ftun_outbound_open_with_backend(NULL, &fixture.request,
                                         &fixture.backend, &reject,
                                         &operation) == FTUN_E_REJECTED);
  CHECK(reject.action == FTUN_REJECT_UDP_DROP && fixture.reject_calls == 2);
  fixture.request.transport = FTUN_DIAL_TCP;
  CHECK(ftun_outbound_open_with_backend(NULL, &fixture.request,
                                         &fixture.backend, &reject,
                                         &operation) == FTUN_E_INVALID);
  fixture.metadata.network = 1u;
  fixture.reject_value.action = FTUN_REJECT_DNS_REFUSED;
  CHECK(ftun_outbound_open_with_backend(NULL, &fixture.request,
                                         &fixture.backend, &reject,
                                         &operation) == FTUN_E_STATE_CORRUPT);
  CHECK(reject.action == 0);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_fixed_leaf_boundaries(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = (ftun_operation_t *)(uintptr_t)1;
  ftun_reject_result_t reject;
  ftun_endpoint_t changed[2];
  CHECK(fixture_start(&fixture) == 0);
  fixture.route.kind = FTUN_ROUTE_NEED_RESOLVE;
  CHECK(ftun_outbound_open_with_backend(NULL, &fixture.request,
                                         &fixture.backend, &reject,
                                         &operation) == FTUN_E_INVALID);
  fixture.route.kind = FTUN_ROUTE_READY;
  fixture.leaf.generation = 3u;
  CHECK(ftun_outbound_open_with_backend(NULL, &fixture.request,
                                         &fixture.backend, &reject,
                                         &operation) == FTUN_E_STALE);
  fixture.leaf.generation = 4u;
  fixture.leaf.id = 8u;
  CHECK(ftun_outbound_open_with_backend(NULL, &fixture.request,
                                         &fixture.backend, &reject,
                                         &operation) == FTUN_E_STALE);
  fixture.leaf.id = 7u;
  memcpy(changed, fixture.candidates, sizeof(changed));
  changed[1].address[3] = 99u;
  fixture.route.allowed = changed;
  CHECK(ftun_outbound_open_with_backend(NULL, &fixture.request,
                                         &fixture.backend, &reject,
                                         &operation) == FTUN_E_REJECTED);
  fixture.route.allowed = fixture.candidates;
  fixture.leaf.kind = FTUN_OUTBOUND_LEAF_GROUP;
  CHECK(ftun_outbound_open_with_backend(NULL, &fixture.request,
                                         &fixture.backend, &reject,
                                         &operation) == FTUN_E_UNSUPPORTED);
  fixture.leaf.kind = (ftun_outbound_leaf_kind_t)99;
  CHECK(ftun_outbound_open_with_backend(NULL, &fixture.request,
                                         &fixture.backend, &reject,
                                         &operation) == FTUN_E_INVALID);
  fixture.leaf.kind = FTUN_OUTBOUND_LEAF_DIRECT;
  fixture.request.metadata = &fixture.metadata;
  CHECK(ftun_outbound_open_with_backend(NULL, &fixture.request,
                                         &fixture.backend, &reject,
                                         &operation) == FTUN_E_INVALID);
  fixture.request.metadata = NULL;
  CHECK(ftun_outbound_open_with_backend(NULL, &fixture.request, NULL,
                                         &reject, &operation) == FTUN_E_INVALID);
  CHECK(ftun_outbound_open_with_backend(NULL, &fixture.request,
                                         &fixture.backend, NULL,
                                         &operation) == FTUN_E_INVALID);
  CHECK(ftun_outbound_open_with_backend(NULL, &fixture.request,
                                         &fixture.backend, &reject,
                                         NULL) == FTUN_E_INVALID);
  CHECK(fixture.direct_calls == 0 && fixture.socks5_calls == 0 &&
        fixture.reject_calls == 0);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

int main(void)
{
  if (test_direct_passthrough_and_cancel() != 0) return 1;
  if (test_socks_failure_never_falls_back() != 0) return 1;
  if (test_reject_mapping() != 0) return 1;
  if (test_fixed_leaf_boundaries() != 0) return 1;
  return 0;
}
