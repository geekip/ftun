#include "route/rule.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "route rule contract failed at line %d: %s\n", \
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

static ftun_metadata_t metadata_domain(const char *domain)
{
  ftun_metadata_t metadata;
  memset(&metadata, 0, sizeof(metadata));
  metadata.generation = 9u;
  metadata.known_fields = FTUN_META_DOMAIN;
  metadata.domain.data = domain;
  metadata.domain.length = strlen(domain);
  metadata.domain_source = FTUN_DOMAIN_EXPLICIT;
  metadata.original_target.kind = FTUN_ADDRESS_DOMAIN;
  metadata.original_target.domain = metadata.domain;
  metadata.original_target.port = 443u;
  return metadata;
}

static ftun_status_t resolve_outbound(ftun_string_t name, uint32_t *out,
                                      void *user)
{
  unsigned int *calls = (unsigned int *)user;
  (*calls)++;
  if (name.length != 5u || memcmp(name.data, "proxy", 5u) != 0) {
    return FTUN_E_INVALID;
  }
  *out = 7u;
  return FTUN_OK;
}

static bool geoip(ftun_string_t label, const ftun_endpoint_t *address,
                  void *user)
{
  unsigned int *calls = (unsigned int *)user;
  (*calls)++;
  return label.length == 2u && memcmp(label.data, "cn", 2u) == 0 &&
         address->address[0] == 10u;
}

static bool geosite(ftun_string_t label, ftun_string_t domain, void *user)
{
  unsigned int *calls = (unsigned int *)user;
  (*calls)++;
  return label.length == 4u && memcmp(label.data, "test", 4u) == 0 &&
         domain.length == 11u && memcmp(domain.data, "example.com", 11u) == 0;
}

static int test_domain_port_and_network_boundaries(void)
{
  ftun_rule_t *rule = NULL;
  ftun_metadata_t metadata = metadata_domain("API.Example.COM.");
  ftun_match_result_t match;
  unsigned int calls = 0u;
  CHECK(ftun_rule_compile("DOMAIN-SUFFIX,example.com,proxy",
                          resolve_outbound, &calls, &rule) == FTUN_OK);
  CHECK(calls == 1u && rule->outbound_id == 7u);
  CHECK(ftun_rule_match(rule, &metadata, &match) == FTUN_OK && match.matched &&
        !match.needs_resolve);
  CHECK(ftun_rule_destroy(&rule) == FTUN_OK);
  CHECK(ftun_rule_compile("DOMAIN-SUFFIX,example.com,DIRECT", NULL, NULL,
                          &rule) == FTUN_OK);
  metadata.domain.data = "badexample.com";
  metadata.domain.length = strlen(metadata.domain.data);
  CHECK(ftun_rule_match(rule, &metadata, &match) == FTUN_OK && !match.matched);
  CHECK(ftun_rule_destroy(&rule) == FTUN_OK);

  CHECK(ftun_rule_compile("DST-PORT,443,DIRECT", NULL, NULL, &rule) == FTUN_OK);
  metadata.original_target.port = 443u;
  CHECK(ftun_rule_match(rule, &metadata, &match) == FTUN_OK && !match.matched);
  metadata.known_fields |= FTUN_META_PORT;
  CHECK(ftun_rule_match(rule, &metadata, &match) == FTUN_OK && match.matched);
  CHECK(ftun_rule_destroy(&rule) == FTUN_OK);
  CHECK(ftun_rule_compile("NETWORK,udp,DIRECT", NULL, NULL, &rule) == FTUN_OK);
  CHECK(ftun_rule_match(rule, &metadata, &match) == FTUN_OK && !match.matched);
  metadata.known_fields |= FTUN_META_NETWORK;
  metadata.network = 2u;
  CHECK(ftun_rule_match(rule, &metadata, &match) == FTUN_OK && match.matched);
  CHECK(ftun_rule_destroy(&rule) == FTUN_OK);
  return 0;
}

static int test_real_candidates_and_fake_identity(void)
{
  ftun_rule_t *rule = NULL;
  ftun_metadata_t metadata = metadata_domain("fake.example");
  ftun_endpoint_t candidates[2];
  ftun_match_result_t match;
  CHECK(ftun_rule_compile("IP-CIDR,10.0.0.0/8,DIRECT", NULL, NULL,
                          &rule) == FTUN_OK);
  CHECK(ftun_rule_match(rule, &metadata, &match) == FTUN_OK &&
        !match.matched && match.needs_resolve);
  metadata.original_target = ipv4(10u, 1u, 2u, 3u, 443u);
  metadata.original_is_fake = true;
  metadata.domain_source = FTUN_DOMAIN_FAKEIP;
  CHECK(ftun_rule_match(rule, &metadata, &match) == FTUN_OK &&
        !match.matched && match.needs_resolve);
  candidates[0] = ipv4(192u, 0u, 2u, 1u, 443u);
  candidates[1] = ipv4(10u, 2u, 3u, 4u, 443u);
  metadata.resolved = candidates;
  metadata.resolved_count = 2u;
  CHECK(ftun_rule_match(rule, &metadata, &match) == FTUN_OK &&
        match.matched && !match.needs_resolve);
  metadata.original_is_fake = false;
  metadata.resolved = NULL;
  metadata.resolved_count = 0u;
  CHECK(ftun_rule_match(rule, &metadata, &match) == FTUN_OK && match.matched);
  CHECK(ftun_rule_destroy(&rule) == FTUN_OK);
  return 0;
}

static int test_geo_callbacks_are_pure(void)
{
  ftun_rule_t rule;
  ftun_metadata_t metadata = metadata_domain("example.com");
  ftun_match_result_t match;
  unsigned int calls = 0u;
  memset(&rule, 0, sizeof(rule));
  rule.kind = FTUN_RULE_GEOSITE;
  rule.operand = (ftun_string_t){"test", 4u};
  rule.geosite = geosite;
  rule.geo_user = &calls;
  CHECK(ftun_rule_match(&rule, &metadata, &match) == FTUN_OK &&
        match.matched && calls == 1u && !match.needs_resolve);
  rule.kind = FTUN_RULE_GEOIP;
  rule.operand = (ftun_string_t){"cn", 2u};
  rule.geoip = geoip;
  CHECK(ftun_rule_match(&rule, &metadata, &match) == FTUN_OK &&
        !match.matched && match.needs_resolve && calls == 1u);
  metadata.original_target = ipv4(10u, 0u, 0u, 1u, 53u);
  CHECK(ftun_rule_match(&rule, &metadata, &match) == FTUN_OK &&
        match.matched && calls == 2u);
  rule.geoip = NULL;
  CHECK(ftun_rule_match(&rule, &metadata, &match) == FTUN_E_UNSUPPORTED);
  return 0;
}

int main(void)
{
  CHECK(test_domain_port_and_network_boundaries() == 0);
  CHECK(test_real_candidates_and_fake_identity() == 0);
  CHECK(test_geo_callbacks_are_pure() == 0);
  return 0;
}
