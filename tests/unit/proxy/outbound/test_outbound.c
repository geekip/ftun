#include <fcntl.h>
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
  ftun_connector_registry_t registry;
  ftun_status_t direct_status;
  ftun_status_t socks5_status;
  const ftun_target_t *captured_target;
  ftun_dial_transport_t captured_transport;
  int direct_calls;
  int socks5_calls;
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
  void *user, ftun_core_t *core, const void *raw, ftun_operation_t **out)
{
  fixture_t *fixture = (fixture_t *)user;
  const ftun_direct_request_t *request = (const ftun_direct_request_t *)raw;
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
  void *user, ftun_core_t *core, const void *raw, ftun_operation_t **out)
{
  fixture_t *fixture = (fixture_t *)user;
  const ftun_socks5_connect_request_t *request =
    (const ftun_socks5_connect_request_t *)raw;
  (void)core;
  fixture->socks5_calls++;
  fixture->captured_target = request->target;
  fixture->captured_transport = request->transport;
  if (out != NULL) *out = NULL;
  if (fixture->socks5_status != FTUN_OK) return fixture->socks5_status;
  return ftun_operation_accept(request->operations, operation_completed,
                               fixture, out, &fixture->mock_completion);
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
  /* 注入的登记表：两个 Connector 都是计数的假实现，能力位与真实实现一致。 */
  if (ftun_connector_register(&fixture->registry,
        &(ftun_connector_ops_t){"direct", FTUN_CONNECTOR_TCP | FTUN_CONNECTOR_UDP,
                                mock_direct_open, fixture}) != FTUN_OK ||
      ftun_connector_register(&fixture->registry,
        &(ftun_connector_ops_t){"socks5", FTUN_CONNECTOR_TCP | FTUN_CONNECTOR_UDP,
                                mock_socks5_open, fixture}) != FTUN_OK) return 1;
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
  CHECK(ftun_outbound_open_with_registry(NULL, &fixture.request,
                                         &fixture.registry, &reject,
                                         &operation) == FTUN_OK);
  CHECK(operation != NULL && fixture.direct_calls == 1 &&
        fixture.socks5_calls == 0);
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
  CHECK(ftun_outbound_open_with_registry(NULL, &fixture.request,
                                         &fixture.registry, &reject,
                                         &operation) == FTUN_E_REJECTED);
  CHECK(operation == NULL && fixture.socks5_calls == 1 &&
        fixture.direct_calls == 0);
  fixture.leaf.supports_udp = false;
  fixture.request.transport = FTUN_DIAL_UDP;
  CHECK(ftun_outbound_open_with_registry(NULL, &fixture.request,
                                         &fixture.registry, &reject,
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
  /* REJECT 不是 Connector：只做分类，不调用任何登记项。 */
  CHECK(ftun_outbound_open_with_registry(NULL, &fixture.request,
                                         &fixture.registry, &reject,
                                         &operation) == FTUN_E_REJECTED);
  CHECK(operation == NULL && reject.action == FTUN_REJECT_TCP_REFUSE &&
        reject.terminal_status == FTUN_E_REJECTED &&
        fixture.direct_calls == 0 && fixture.socks5_calls == 0);
  fixture.request.transport = FTUN_DIAL_UDP;
  fixture.metadata.network = 2u;
  CHECK(ftun_outbound_open_with_registry(NULL, &fixture.request,
                                         &fixture.registry, &reject,
                                         &operation) == FTUN_E_REJECTED);
  CHECK(reject.action == FTUN_REJECT_UDP_DROP);
  fixture.request.transport = FTUN_DIAL_TCP;
  CHECK(ftun_outbound_open_with_registry(NULL, &fixture.request,
                                         &fixture.registry, &reject,
                                         &operation) == FTUN_E_INVALID);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

/* 登记表：能力位决定能否承载某种传输；没有登记的类型不能分派；
 * 名字重复或缺少 open 的登记被拒绝；登记表满了返回 LIMIT。 */
static int test_registry(void)
{
  fixture_t fixture;
  ftun_operation_t *operation = (ftun_operation_t *)(uintptr_t)1;
  ftun_reject_result_t reject;
  ftun_connector_registry_t registry;
  ftun_connector_ops_t tcp_only = {"socks5", FTUN_CONNECTOR_TCP, mock_socks5_open, NULL};
  size_t index;
  char names[FTUN_CONNECTOR_MAX + 1u][8];
  CHECK(fixture_start(&fixture) == 0);
  /* 只支持 TCP 的 socks5：UDP 请求在到达 Connector 之前就被拒绝。 */
  memset(&registry, 0, sizeof(registry));
  tcp_only.context = &fixture;
  CHECK(ftun_connector_register(&registry, &tcp_only) == FTUN_OK);
  fixture.leaf.kind = FTUN_OUTBOUND_LEAF_SOCKS5;
  fixture.request.direct = NULL;
  fixture.request.socks5 = &fixture.socks5;
  fixture.request.transport = FTUN_DIAL_UDP;
  CHECK(ftun_outbound_open_with_registry(NULL, &fixture.request, &registry,
        &reject, &operation) == FTUN_E_UNSUPPORTED && fixture.socks5_calls == 0);
  fixture.request.transport = FTUN_DIAL_TCP;
  CHECK(ftun_outbound_open_with_registry(NULL, &fixture.request, &registry,
        &reject, &operation) == FTUN_OK && fixture.socks5_calls == 1);
  CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  {
    size_t dispatched = 0u;
    CHECK(ftun_operation_dispatch(fixture.operations, SIZE_MAX, &dispatched) == FTUN_OK);
  }
  /* 没有登记 direct：direct 叶子无法分派。 */
  fixture.leaf.kind = FTUN_OUTBOUND_LEAF_DIRECT;
  fixture.request.socks5 = NULL;
  fixture.request.direct = &fixture.direct;
  CHECK(ftun_outbound_open_with_registry(NULL, &fixture.request, &registry,
        &reject, &operation) == FTUN_E_UNSUPPORTED && fixture.direct_calls == 0);
  /* 登记的合法性。 */
  CHECK(ftun_connector_register(&registry, &tcp_only) == FTUN_E_INVALID); /* 重复 */
  CHECK(ftun_connector_register(&registry,
    &(ftun_connector_ops_t){"x", FTUN_CONNECTOR_TCP, NULL, NULL}) == FTUN_E_INVALID);
  CHECK(ftun_connector_register(&registry,
    &(ftun_connector_ops_t){"x", FTUN_CONNECTOR_KEEPALIVE, mock_socks5_open, NULL}) == FTUN_E_INVALID);
  CHECK(ftun_connector_register(&registry,
    &(ftun_connector_ops_t){"", FTUN_CONNECTOR_TCP, mock_socks5_open, NULL}) == FTUN_E_INVALID);
  CHECK(ftun_connector_lookup(&registry, "nope") == NULL &&
        ftun_connector_lookup(&registry, "socks5") != NULL);
  for (index = 1u; index < FTUN_CONNECTOR_MAX; index++) {
    ftun_connector_ops_t ops = {names[index], FTUN_CONNECTOR_UDP, mock_socks5_open, NULL};
    snprintf(names[index], sizeof(names[index]), "k%zu", index);
    CHECK(ftun_connector_register(&registry, &ops) == FTUN_OK);
  }
  snprintf(names[FTUN_CONNECTOR_MAX], sizeof(names[0]), "full");
  CHECK(ftun_connector_register(&registry,
    &(ftun_connector_ops_t){names[FTUN_CONNECTOR_MAX], FTUN_CONNECTOR_TCP,
                            mock_socks5_open, NULL}) == FTUN_E_LIMIT);
  /* 默认登记表含 direct 与 socks5 两个真实实现，socks5 带域名目标能力。 */
  CHECK(ftun_connector_lookup(ftun_outbound_default_registry(), "direct") != NULL);
  CHECK(ftun_connector_lookup(ftun_outbound_default_registry(), "socks5") != NULL &&
        (ftun_connector_lookup(ftun_outbound_default_registry(), "socks5")->capabilities &
         FTUN_CONNECTOR_DOMAIN_TARGET) != 0u);
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
  CHECK(ftun_outbound_open_with_registry(NULL, &fixture.request,
                                         &fixture.registry, &reject,
                                         &operation) == FTUN_E_INVALID);
  fixture.route.kind = FTUN_ROUTE_READY;
  fixture.leaf.generation = 3u;
  CHECK(ftun_outbound_open_with_registry(NULL, &fixture.request,
                                         &fixture.registry, &reject,
                                         &operation) == FTUN_E_STALE);
  fixture.leaf.generation = 4u;
  fixture.leaf.id = 8u;
  CHECK(ftun_outbound_open_with_registry(NULL, &fixture.request,
                                         &fixture.registry, &reject,
                                         &operation) == FTUN_E_STALE);
  fixture.leaf.id = 7u;
  memcpy(changed, fixture.candidates, sizeof(changed));
  changed[1].address[3] = 99u;
  fixture.route.allowed = changed;
  CHECK(ftun_outbound_open_with_registry(NULL, &fixture.request,
                                         &fixture.registry, &reject,
                                         &operation) == FTUN_E_REJECTED);
  fixture.route.allowed = fixture.candidates;
  fixture.leaf.kind = FTUN_OUTBOUND_LEAF_GROUP;
  CHECK(ftun_outbound_open_with_registry(NULL, &fixture.request,
                                         &fixture.registry, &reject,
                                         &operation) == FTUN_E_UNSUPPORTED);
  fixture.leaf.kind = (ftun_outbound_leaf_kind_t)99;
  CHECK(ftun_outbound_open_with_registry(NULL, &fixture.request,
                                         &fixture.registry, &reject,
                                         &operation) == FTUN_E_INVALID);
  fixture.leaf.kind = FTUN_OUTBOUND_LEAF_DIRECT;
  fixture.request.metadata = &fixture.metadata;
  CHECK(ftun_outbound_open_with_registry(NULL, &fixture.request,
                                         &fixture.registry, &reject,
                                         &operation) == FTUN_E_INVALID);
  fixture.request.metadata = NULL;
  CHECK(ftun_outbound_open_with_registry(NULL, &fixture.request, NULL,
                                         &reject, &operation) == FTUN_E_INVALID);
  CHECK(ftun_outbound_open_with_registry(NULL, &fixture.request,
                                         &fixture.registry, NULL,
                                         &operation) == FTUN_E_INVALID);
  CHECK(ftun_outbound_open_with_registry(NULL, &fixture.request,
                                         &fixture.registry, &reject,
                                         NULL) == FTUN_E_INVALID);
  CHECK(fixture.direct_calls == 0 && fixture.socks5_calls == 0);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

int main(void)
{
  if (test_direct_passthrough_and_cancel() != 0) return 1;
  if (test_socks_failure_never_falls_back() != 0) return 1;
  if (test_reject_mapping() != 0) return 1;
  if (test_registry() != 0) return 1;
  if (test_fixed_leaf_boundaries() != 0) return 1;
  return 0;
}
