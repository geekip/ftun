#include "core/context.h"
#include "libs/transport/egress.h"

#if defined(FTUN_TEST_PROXY)
#include "app/config/model.h"
#include "proxy/egress.h"
#endif
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "egress contract failed at %d: %s\n", __LINE__, #x); \
  return 1; } } while (0)

/* 假出口：代表「任意一种代理协议或 Mesh 节点」。消费方只经编号使用它，
 * 本测试验证编号、最终目标与代次原样到达出口实现，Path 层不解释出口。 */
typedef struct {
  unsigned int opens;
  ftun_egress_id_t last_egress;
  ftun_endpoint_t last_endpoint;
  uint64_t last_generation;
} fake_t;

static ftun_status_t fake_resolve(const void *context, const ftun_config_t *config,
  ftun_string_t name, ftun_egress_info_t *out)
{
  (void)context;
  (void)config;
  memset(out, 0, sizeof(*out));
  if (name.length != 7u || memcmp(name.data, "relay-a", 7u) != 0) return FTUN_E_REJECTED;
  out->id = 42u;
  out->capabilities = FTUN_EGRESS_CAP_STREAM | FTUN_EGRESS_CAP_DOMAIN_TARGET;
  out->state = FTUN_EGRESS_STATE_AVAILABLE;
  out->provider_kind = "fake";
  return FTUN_OK;
}

static ftun_status_t fake_query(const void *context, ftun_egress_id_t egress,
  uint64_t generation, ftun_egress_info_t *out)
{
  (void)context;
  memset(out, 0, sizeof(*out));
  if (egress != 42u) return FTUN_E_REJECTED;
  out->id = egress;
  out->capabilities = FTUN_EGRESS_CAP_STREAM | FTUN_EGRESS_CAP_DOMAIN_TARGET;
  out->state = FTUN_EGRESS_STATE_DEGRADED;
  out->configuration_generation = generation;
  out->provider_kind = "fake";
  return FTUN_OK;
}

static ftun_status_t fake_open(void *context, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *spec,
  ftun_operation_t **out)
{
  fake_t *fake = (fake_t *)context;
  (void)core;
  *out = NULL;
  fake->opens++;
  fake->last_egress = request->egress;
  fake->last_endpoint = spec->endpoint;
  fake->last_generation = spec->configuration_generation;
  /* 真实实现会接纳并稍后交付 Path；这里同步拒绝即可验证分派。 */
  return FTUN_E_REJECTED;
}

static unsigned int completions;

static void user_completed(ftun_operation_t *operation, ftun_error_t error,
  ftun_path_t *path, void *user)
{
  (void)operation;
  (void)error;
  (void)path;
  (void)user;
  completions++;
}

typedef struct {
  ftun_budget_t *budget;
  ftun_core_t *core;
  ftun_operation_queue_t *operations;
  ftun_event_loop_t *loop;
  ftun_path_provider_t *provider;
} fixture_t;

static int setup(fixture_t *fixture, const ftun_egress_provider_t *egress)
{
  ftun_path_provider_spec_t spec = {0};
  memset(fixture, 0, sizeof(*fixture));
  CHECK(ftun_budget_create(NULL, 4194304u, 0u, &fixture->budget) == FTUN_OK);
  CHECK(ftun_core_context_create(fixture->budget, &fixture->core) == FTUN_OK);
  CHECK(ftun_operation_queue_create(fixture->budget, 16u, &fixture->operations) == FTUN_OK);
  CHECK(ftun_event_loop_create(fixture->core, &fixture->loop) == FTUN_OK);
  spec.budget = fixture->budget;
  spec.generation = 7u;
  spec.ops.open = ftun_egress_path_open;
  spec.context = (void *)egress;
  CHECK(ftun_path_provider_create(&spec, &fixture->provider) == FTUN_OK);
  return 0;
}

static int cleanup(fixture_t *fixture)
{
  ftun_budget_usage_t usage;
  CHECK(ftun_path_provider_stop_until(fixture->provider, UINT64_MAX) == FTUN_OK);
  CHECK(ftun_path_provider_destroy(&fixture->provider) == FTUN_OK);
  CHECK(ftun_event_loop_stop(fixture->loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&fixture->loop) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&fixture->operations) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&fixture->core) == FTUN_OK);
  CHECK(ftun_budget_get_usage(fixture->budget, &usage) == FTUN_OK &&
        usage.used_resources.memory_bytes == 0u);
  CHECK(ftun_budget_destroy(&fixture->budget) == FTUN_OK);
  return 0;
}

static void request_init(const fixture_t *fixture, ftun_egress_id_t egress,
  ftun_path_open_request_t *request)
{
  memset(request, 0, sizeof(*request));
  request->dial.loop = fixture->loop;
  request->dial.operations = fixture->operations;
  request->dial.budget = fixture->budget;
  request->dial.endpoint.kind = FTUN_ADDRESS_IPV4;
  request->dial.endpoint.address[0] = 127u;
  request->dial.endpoint.address[3] = 1u;
  request->dial.endpoint.port = 53u;
  request->dial.allowed = &request->dial.endpoint;
  request->dial.allowed_count = 1u;
  request->dial.requested_domain = FTUN_DIAL_DOMAIN_AUTO;
  request->dial.purpose = FTUN_DIAL_PURPOSE_DNS;
  request->dial.transport = FTUN_DIAL_TCP;
  request->completion = user_completed;
  request->egress = egress;
}

static int direct_provider_contract(void)
{
  const ftun_egress_provider_t *direct = ftun_egress_direct_provider();
  ftun_egress_info_t info;
  ftun_path_open_request_t zeroed;
  ftun_operation_t *operation = (ftun_operation_t *)&info;
  CHECK(direct != NULL && direct->resolve != NULL && direct->query != NULL &&
        direct->open != NULL);
  CHECK(direct->resolve(direct->context, NULL, (ftun_string_t){"DIRECT", 6u},
        &info) == FTUN_OK);
  CHECK(info.id == FTUN_EGRESS_DIRECT && strcmp(info.provider_kind, "direct") == 0);
  CHECK(ftun_egress_supports(&info, FTUN_DIAL_TCP) &&
        ftun_egress_supports(&info, FTUN_DIAL_UDP));
  CHECK(direct->resolve(direct->context, NULL, (ftun_string_t){"proxy-a", 7u},
        &info) == FTUN_E_REJECTED);
  CHECK(direct->resolve(direct->context, NULL, (ftun_string_t){"DIRECTX", 7u},
        &info) == FTUN_E_REJECTED);
  CHECK(direct->query(direct->context, FTUN_EGRESS_DIRECT, 9u, &info) == FTUN_OK &&
        info.configuration_generation == 9u &&
        info.state == FTUN_EGRESS_STATE_AVAILABLE);
  CHECK(direct->query(direct->context, 5u, 9u, &info) == FTUN_E_REJECTED);
  /* 零初始化的请求就是直连，既有调用方不受影响。 */
  memset(&zeroed, 0, sizeof(zeroed));
  CHECK(zeroed.egress == FTUN_EGRESS_DIRECT);
  /* 直连提供者不会把未知出口静默当作直连，拒绝前不触碰 core。 */
  zeroed.egress = 5u;
  CHECK(direct->open(direct->context, NULL, &zeroed, NULL, &operation) ==
        FTUN_E_REJECTED && operation == NULL);
  return 0;
}

static int capability_contract(void)
{
  ftun_egress_info_t info = {0};
  info.capabilities = FTUN_EGRESS_CAP_STREAM;
  info.state = FTUN_EGRESS_STATE_AVAILABLE;
  CHECK(ftun_egress_supports(&info, FTUN_DIAL_TCP));
  CHECK(!ftun_egress_supports(&info, FTUN_DIAL_UDP));
  info.state = FTUN_EGRESS_STATE_DEGRADED;
  CHECK(ftun_egress_supports(&info, FTUN_DIAL_TCP));
  info.state = FTUN_EGRESS_STATE_UNAVAILABLE;
  CHECK(!ftun_egress_supports(&info, FTUN_DIAL_TCP));
  return 0;
}

static int provider_routes_to_fake(void)
{
  fake_t fake = {0};
  ftun_egress_provider_t provider = {fake_resolve, fake_query, fake_open, &fake, NULL, NULL, NULL};
  ftun_egress_info_t info;
  fixture_t fixture;
  ftun_path_open_request_t request;
  ftun_operation_t *operation = NULL;
  CHECK(provider.resolve(provider.context, NULL, (ftun_string_t){"relay-a", 7u},
        &info) == FTUN_OK && info.id == 42u);
  CHECK(provider.query(provider.context, 42u, 7u, &info) == FTUN_OK &&
        ftun_egress_supports(&info, FTUN_DIAL_TCP) &&
        !ftun_egress_supports(&info, FTUN_DIAL_UDP));
  CHECK(setup(&fixture, &provider) == 0);
  request_init(&fixture, info.id, &request);
  completions = 0u;
  CHECK(ftun_path_provider_open_channel(fixture.provider, fixture.core, 7u,
        &request, &operation) == FTUN_E_REJECTED && operation == NULL);
  CHECK(fake.opens == 1u && fake.last_egress == 42u);
  CHECK(fake.last_generation == 7u);
  CHECK(fake.last_endpoint.kind == FTUN_ADDRESS_IPV4 &&
        fake.last_endpoint.address[0] == 127u && fake.last_endpoint.port == 53u);
  CHECK(completions == 0u);
  CHECK(cleanup(&fixture) == 0);
  return 0;
}

static int direct_factory_rejects_foreign_ids(void)
{
  fixture_t fixture;
  ftun_path_open_request_t request;
  ftun_operation_t *operation = NULL;
  CHECK(setup(&fixture, ftun_egress_direct_provider()) == 0);
  request_init(&fixture, 42u, &request);
  completions = 0u;
  CHECK(ftun_path_provider_open_channel(fixture.provider, fixture.core, 7u,
        &request, &operation) == FTUN_E_REJECTED && operation == NULL);
  CHECK(completions == 0u);
  CHECK(cleanup(&fixture) == 0);
  return 0;
}

#if defined(FTUN_TEST_PROXY)
static ftun_status_t choose(void *context, uint64_t generation,
  uint32_t root, uint32_t *out)
{
  (void)generation; (void)root;
  *out = *(uint32_t *)context;
  return FTUN_OK;
}

static int proxy_selection_contract(void)
{
  fixture_t fixture;
  ftun_config_t config = {0};
  ftun_config_outbound_t nodes[2] = {{0}};
  char *members[] = {"DIRECT", "REJECT", "leaf"};
  const ftun_egress_provider_t *provider = NULL;
  ftun_egress_info_t info;
  ftun_path_open_request_t request;
  ftun_path_spec_t spec = {0};
  ftun_operation_t *operation = NULL;
  ftun_path_provider_ops_t physical = {0};
  uint32_t selected = 0u;
  fake_t fake = {0};
  CHECK(setup(&fixture, ftun_egress_direct_provider()) == 0);
  nodes[0].kind = FTUN_CONFIG_OUTBOUND_SOCKS5;
  nodes[0].name = "leaf";
  nodes[0].server = "offline.test:1080";
  nodes[0].udp = true;
  nodes[1].kind = FTUN_CONFIG_OUTBOUND_SELECT;
  nodes[1].name = "group";
  nodes[1].members = (ftun_config_string_list_t){members, 3u};
  nodes[1].default_member = "DIRECT";
  config.outbounds = nodes;
  config.outbound_count = 2u;
  ftun_config_bind_sections(&config);
  CHECK(ftun_proxy_egress_prepare(fixture.budget, &config, 0u, &provider) == FTUN_OK);
  ftun_proxy_egress_bind(provider, 7u, choose, &selected);
  physical.open = fake_open;
  ftun_proxy_egress_set_path(provider, physical, &fake);
  CHECK(provider->resolve(provider->context, &config, (ftun_string_t){"group", 5u}, &info) == FTUN_OK && info.id == 3u);
  CHECK(provider->query(provider->context, 3u, 7u, &info) == FTUN_OK && info.id == FTUN_EGRESS_DIRECT);
  request_init(&fixture, 3u, &request);
  spec.configuration_generation = 7u;
  spec.endpoint = request.dial.endpoint;
  CHECK(provider->open(provider->context, fixture.core, &request, &spec, &operation) == FTUN_E_REJECTED);
  CHECK(fake.opens == 1u && fake.last_egress == FTUN_EGRESS_DIRECT && operation == NULL);
  selected = 1u;
  CHECK(provider->open(provider->context, fixture.core, &request, &spec, &operation) == FTUN_E_REJECTED && fake.opens == 1u);
  selected = 2u;
  CHECK(provider->query(provider->context, 3u, 7u, &info) == FTUN_OK && info.id == 2u && info.state == FTUN_EGRESS_STATE_UNAVAILABLE);
  CHECK(provider->validate(provider->context, 3u, 2u, 7u) == FTUN_OK);
  CHECK(provider->query(provider->context, 3u, 8u, &info) == FTUN_E_STALE);
  CHECK(provider->query(provider->context, FTUN_EGRESS_MESH_FIRST, 7u, &info) == FTUN_E_REJECTED);
  CHECK(provider->query(provider->context, FTUN_EGRESS_NONE, 7u, &info) == FTUN_E_REJECTED);
  ftun_egress_release(&provider);
  CHECK(cleanup(&fixture) == 0);
  return 0;
}
#endif

int main(void)
{
  CHECK(direct_provider_contract() == 0);
#if defined(FTUN_TEST_PROXY)
  CHECK(proxy_selection_contract() == 0);
#endif
  CHECK(capability_contract() == 0);
  CHECK(provider_routes_to_fake() == 0);
  CHECK(direct_factory_rejects_foreign_ids() == 0);
  puts("egress contract tests passed");
  return 0;
}
