#include "config/compile.h"
#include "config/model.h"
#include "config/parser.h"
#include "core/budget.h"
#include "core/runtime.h"
#include "route/router.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "route router contract failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

static ftun_endpoint_t ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                            uint16_t port)
{
  ftun_endpoint_t endpoint;
  memset(&endpoint, 0, sizeof(endpoint));
  endpoint.kind = FTUN_ADDRESS_IPV4;
  endpoint.address[0] = a;
  endpoint.address[1] = b;
  endpoint.address[2] = c;
  endpoint.address[3] = d;
  endpoint.port = port;
  return endpoint;
}

static ftun_metadata_t domain_metadata(const char *name, uint64_t generation)
{
  ftun_metadata_t metadata;
  memset(&metadata, 0, sizeof(metadata));
  metadata.generation = generation;
  metadata.known_fields = FTUN_META_DOMAIN | FTUN_META_PORT |
                          FTUN_META_NETWORK;
  metadata.network = 1u;
  metadata.original_target.kind = FTUN_ADDRESS_DOMAIN;
  metadata.original_target.domain = (ftun_string_t){name, strlen(name)};
  metadata.original_target.port = 443u;
  metadata.domain = metadata.original_target.domain;
  metadata.domain_source = FTUN_DOMAIN_EXPLICIT;
  return metadata;
}

static ftun_status_t outbound(ftun_string_t name, uint32_t *out, void *user)
{
  (void)user;
  if (name.length == 5u && memcmp(name.data, "proxy", 5u) == 0) {
    *out = 9u;
    return FTUN_OK;
  }
  return FTUN_E_INVALID;
}

static int test_order_suspend_resume_and_subset(void)
{
  const char *rules[] = {
    "IP-CIDR,10.0.0.0/8,DIRECT",
    "DOMAIN,a.example,proxy",
    "MATCH,REJECT"
  };
  ftun_route_table_t *table = NULL;
  ftun_metadata_t metadata = domain_metadata("a.example", 7u);
  ftun_endpoint_t candidates[2];
  ftun_endpoint_t too_many[FTUN_ROUTE_MAX_CANDIDATES + 1u];
  ftun_route_result_t route;
  size_t index;
  candidates[0] = ipv4(10u, 1u, 2u, 3u, 443u);
  candidates[1] = ipv4(192u, 0u, 2u, 1u, 443u);
  CHECK(ftun_route_table_create(7u, rules, 3u, outbound, NULL, &table) ==
        FTUN_OK);
  CHECK(ftun_route_table_evaluate(table, &metadata, 0u, &route) == FTUN_OK);
  CHECK(route.kind == FTUN_ROUTE_NEED_RESOLVE && route.rule_index == 0u &&
        route.resume_rule == 0u && route.generation == 7u &&
        route.allowed == NULL && route.allowed_count == 0u);
  metadata.resolved = candidates;
  metadata.resolved_count = 2u;
  CHECK(ftun_route_table_evaluate(table, &metadata, route.resume_rule,
                                  &route) == FTUN_OK);
  CHECK(route.kind == FTUN_ROUTE_READY && route.rule_index == 0u &&
        route.outbound_id == FTUN_OUTBOUND_ID_DIRECT &&
        route.allowed == route.allowed_storage && route.allowed_count == 1u &&
        route.allowed[0].address[0] == 10u);

  candidates[0] = ipv4(192u, 0u, 2u, 1u, 443u);
  candidates[1] = ipv4(203u, 0u, 113u, 2u, 443u);
  CHECK(ftun_route_table_evaluate(table, &metadata, 0u, &route) == FTUN_OK);
  CHECK(route.kind == FTUN_ROUTE_READY && route.rule_index == 1u &&
        route.outbound_id == 9u && route.allowed_count == 2u &&
        route.allowed[0].address[0] == 192u &&
        route.allowed[1].address[0] == 203u);

  metadata.domain.data = "other.example";
  metadata.domain.length = strlen(metadata.domain.data);
  metadata.original_target.domain = metadata.domain;
  CHECK(ftun_route_table_evaluate(table, &metadata, 0u, &route) == FTUN_OK);
  CHECK(route.kind == FTUN_ROUTE_DENY && route.rule_index == 2u &&
        route.outbound_id == FTUN_OUTBOUND_ID_REJECT &&
        route.allowed_count == 0u);
  metadata.generation = 8u;
  CHECK(ftun_route_table_evaluate(table, &metadata, 0u, &route) ==
        FTUN_E_STALE && route.kind == FTUN_ROUTE_UNSET);
  for (index = 0u; index < FTUN_ROUTE_MAX_CANDIDATES + 1u; index++) {
    too_many[index] = ipv4(192u, 0u, 2u, (uint8_t)(index + 1u), 443u);
  }
  metadata.generation = 7u;
  metadata.resolved = too_many;
  metadata.resolved_count = FTUN_ROUTE_MAX_CANDIDATES + 1u;
  CHECK(ftun_route_table_evaluate(table, &metadata, 0u, &route) ==
        FTUN_E_LIMIT && route.kind == FTUN_ROUTE_UNSET);
  CHECK(ftun_route_table_destroy(&table) == FTUN_OK);
  return 0;
}

static ftun_config_t *make_config(void)
{
  static const char text[] =
    "{\"dns\":{\"enable\":false},"
    "\"outbounds\":[{\"name\":\"proxy\",\"type\":\"socks5\","
    "\"server\":\"192.0.2.1:1080\"}],"
    "\"rules\":[\"DOMAIN,a.example,proxy\"]}";
  ftun_config_t *config = NULL;
  ftun_feature_plan_t *plan = NULL;
  ftun_bytes_t bytes = {(const uint8_t *)text, sizeof(text) - 1u};
  if (ftun_config_parse(bytes, &config) != FTUN_OK) return NULL;
  if (ftun_config_compile(config, &plan) != FTUN_OK) {
    (void)ftun_config_destroy(&config);
    return NULL;
  }
  config->plan = plan;
  return config;
}

static int test_runtime_owned_table(void)
{
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_config_t *config = make_config();
  ftun_runtime_t *candidate = NULL;
  ftun_runtime_t *runtime = NULL;
  ftun_metadata_t metadata = domain_metadata("a.example", 1u);
  ftun_route_result_t route;
  CHECK(config != NULL);
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 0u, &core) == FTUN_OK);
  CHECK(ftun_runtime_prepare(core, config, &candidate) == FTUN_OK);
  CHECK(ftun_route_evaluate(candidate, &metadata, 0u, &route) ==
        FTUN_E_INVALID);
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_active_acquire(core, &runtime) == FTUN_OK);
  CHECK(ftun_route_evaluate(runtime, &metadata, 0u, &route) == FTUN_OK);
  CHECK(route.kind == FTUN_ROUTE_READY && route.outbound_id ==
        FTUN_OUTBOUND_ID_NAMED_BASE && route.allowed_count == 0u);
  CHECK(ftun_runtime_release(&runtime) == FTUN_OK);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static uint32_t route_random(uint32_t *state)
{
  uint32_t value = *state;
  value ^= value << 13u;
  value ^= value >> 17u;
  value ^= value << 5u;
  *state = value;
  return value;
}

static int test_first_match_differential(void)
{
  const char *rules[] = {
    "IP-CIDR,10.0.0.0/8,DIRECT",
    "IP-CIDR,10.1.0.0/16,REJECT",
    "IP-CIDR,192.168.0.0/16,proxy",
    "MATCH,REJECT"
  };
  ftun_route_table_t *table = NULL;
  ftun_metadata_t metadata;
  ftun_route_result_t route;
  uint32_t random_state = UINT32_C(0x13579bdf);
  size_t iteration;
  CHECK(ftun_route_table_create(11u, rules, 4u, outbound, NULL, &table) ==
        FTUN_OK);
  memset(&metadata, 0, sizeof(metadata));
  metadata.generation = 11u;
  metadata.known_fields = FTUN_META_PORT | FTUN_META_NETWORK;
  metadata.network = 1u;
  metadata.original_target.kind = FTUN_ADDRESS_IPV4;
  metadata.original_target.port = 443u;
  for (iteration = 0u; iteration < 100000u; iteration++) {
    uint32_t value = route_random(&random_state);
    uint32_t expected;
    memcpy(metadata.original_target.address, &value, 4u);
    if (metadata.original_target.address[0] == 10u) {
      expected = FTUN_OUTBOUND_ID_DIRECT;
    } else if (metadata.original_target.address[0] == 192u &&
               metadata.original_target.address[1] == 168u) {
      expected = 9u;
    } else {
      expected = FTUN_OUTBOUND_ID_REJECT;
    }
    CHECK(ftun_route_table_evaluate(table, &metadata, 0u, &route) == FTUN_OK);
    CHECK(route.outbound_id == expected);
    if (expected == FTUN_OUTBOUND_ID_REJECT) {
      CHECK(route.kind == FTUN_ROUTE_DENY && route.allowed_count == 0u);
    } else {
      CHECK(route.kind == FTUN_ROUTE_READY && route.allowed_count == 1u &&
            memcmp(route.allowed[0].address,
                   metadata.original_target.address, 4u) == 0);
    }
  }
  CHECK(ftun_route_table_destroy(&table) == FTUN_OK);
  return 0;
}

int main(void)
{
  CHECK(test_order_suspend_resume_and_subset() == 0);
  CHECK(test_runtime_owned_table() == 0);
  CHECK(test_first_match_differential() == 0);
  return 0;
}
