#include "proxy/route/target.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "route target contract failed at line %d: %s\n", \
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

static ftun_endpoint_t domain(const char *name, uint16_t port)
{
  ftun_endpoint_t endpoint;
  memset(&endpoint, 0, sizeof(endpoint));
  endpoint.kind = FTUN_ADDRESS_DOMAIN;
  endpoint.domain.data = name;
  endpoint.domain.length = strlen(name);
  endpoint.port = port;
  return endpoint;
}

static ftun_metadata_t base_metadata(ftun_endpoint_t original)
{
  ftun_metadata_t metadata;
  memset(&metadata, 0, sizeof(metadata));
  metadata.generation = 7u;
  metadata.known_fields = FTUN_META_PORT | FTUN_META_NETWORK;
  metadata.network = 1u;
  metadata.original_target = original;
  return metadata;
}

static void set_identity(ftun_metadata_t *metadata, const char *name,
                         ftun_domain_source_t source)
{
  metadata->known_fields |= FTUN_META_DOMAIN;
  metadata->domain.data = name;
  metadata->domain.length = strlen(name);
  metadata->domain_source = source;
}

static int test_real_ip_is_not_replaced_by_sniff(void)
{
  static const char name[] = "sniffed.example";
  ftun_endpoint_t original = ipv4(203u, 0u, 113u, 9u, 443u);
  ftun_endpoint_t resolved = ipv4(192u, 0u, 2u, 99u, 443u);
  ftun_metadata_t metadata = base_metadata(original);
  ftun_target_t target;
  set_identity(&metadata, name, FTUN_DOMAIN_SNIFF);
  metadata.resolved = &resolved;
  metadata.resolved_count = 1u;
  CHECK(ftun_target_from_metadata(&metadata, &target) == FTUN_OK);
  CHECK(target.generation == 7u && target.original.kind == FTUN_ADDRESS_IPV4 &&
        target.original.address[3] == 9u && !target.original_is_fake);
  CHECK(target.identity_source == FTUN_DOMAIN_SNIFF &&
        target.identity.length == sizeof(name) - 1u);
  CHECK(target.candidate_count == 1u && target.candidates == &metadata.original_target &&
        target.candidates[0].address[3] == 9u);
  CHECK(target.allowed == target.candidates && target.allowed_count == 1u);
  CHECK(ftun_target_select_dial(&target, &resolved) == FTUN_E_REJECTED &&
        !target.dial_selected);
  CHECK(ftun_target_select_remote_domain(&target) == FTUN_E_REJECTED);
  CHECK(ftun_target_select_dial(&target, &original) == FTUN_OK &&
        target.dial_selected && target.dial.address[3] == 9u);
  return 0;
}

static int test_remote_domain_without_local_candidates(void)
{
  static const char name[] = "remote.example";
  ftun_endpoint_t original = domain(name, 8443u);
  ftun_metadata_t metadata = base_metadata(original);
  ftun_target_t target;
  ftun_route_result_t route;
  memset(&route, 0, sizeof(route));
  CHECK(ftun_target_from_metadata(&metadata, &target) == FTUN_OK);
  CHECK(target.identity_source == FTUN_DOMAIN_EXPLICIT &&
        target.identity.length == sizeof(name) - 1u &&
        target.candidate_count == 0u && target.allowed_count == 0u);
  route.kind = FTUN_ROUTE_READY;
  route.generation = 7u;
  route.outbound_id = 4u;
  CHECK(ftun_target_apply_route(&target, &route) == FTUN_OK);
  CHECK(ftun_target_select_remote_domain(&target) == FTUN_OK);
  CHECK(target.dial_selected && target.dial.kind == FTUN_ADDRESS_DOMAIN &&
        target.dial.port == 8443u &&
        target.dial.domain.data == target.identity.data);
  return 0;
}

static int test_fakeip_subset_and_retry(void)
{
  static const char name[] = "fake.example";
  ftun_endpoint_t fake = ipv4(198u, 18u, 0u, 8u, 443u);
  ftun_endpoint_t candidates[2];
  ftun_endpoint_t allowed[2];
  ftun_endpoint_t duplicates[2];
  ftun_metadata_t metadata = base_metadata(fake);
  ftun_target_t target;
  ftun_route_result_t route;
  candidates[0] = ipv4(192u, 0u, 2u, 1u, 443u);
  candidates[1] = ipv4(192u, 0u, 2u, 2u, 443u);
  allowed[0] = candidates[1];
  set_identity(&metadata, name, FTUN_DOMAIN_FAKEIP);
  metadata.original_is_fake = true;
  metadata.resolved = candidates;
  metadata.resolved_count = 2u;
  CHECK(ftun_target_from_metadata(&metadata, &target) == FTUN_OK);
  CHECK(target.original_is_fake && target.original.address[0] == 198u &&
        target.identity_source == FTUN_DOMAIN_FAKEIP &&
        target.candidate_count == 2u && target.allowed_count == 2u);

  memset(&route, 0, sizeof(route));
  route.kind = FTUN_ROUTE_READY;
  route.generation = 7u;
  route.outbound_id = 9u;
  route.allowed = allowed;
  route.allowed_count = 1u;
  CHECK(ftun_target_apply_route(&target, &route) == FTUN_OK);
  CHECK(target.allowed == allowed && target.allowed_count == 1u);
  CHECK(ftun_target_select_dial(&target, &candidates[0]) == FTUN_E_REJECTED);
  CHECK(ftun_target_select_dial(&target, &candidates[1]) == FTUN_OK &&
        target.dial.address[3] == 2u);

  route.allowed = NULL;
  route.allowed_count = 0u;
  CHECK(ftun_target_apply_route(&target, &route) == FTUN_OK);
  CHECK(target.allowed == NULL && target.allowed_count == 0u &&
        !target.dial_selected && target.dial.kind == FTUN_ADDRESS_NONE);
  route.allowed = candidates;
  route.allowed_count = 2u;
  CHECK(ftun_target_apply_route(&target, &route) == FTUN_E_REJECTED);
  CHECK(ftun_target_select_remote_domain(&target) == FTUN_E_REJECTED);

  CHECK(ftun_target_from_metadata(&metadata, &target) == FTUN_OK);
  duplicates[0] = candidates[0];
  duplicates[1] = candidates[0];
  route.allowed = duplicates;
  route.allowed_count = 2u;
  CHECK(ftun_target_apply_route(&target, &route) == FTUN_E_INVALID);
  CHECK(target.allowed == candidates && target.allowed_count == 2u);
  return 0;
}

static int test_route_and_metadata_failures(void)
{
  static const char first[] = "one.example";
  static const char second[] = "two.example";
  ftun_endpoint_t original = domain(first, 443u);
  ftun_endpoint_t candidate = ipv4(192u, 0u, 2u, 10u, 443u);
  ftun_metadata_t metadata = base_metadata(original);
  ftun_target_t target;
  ftun_route_result_t route;

  set_identity(&metadata, second, FTUN_DOMAIN_EXPLICIT);
  memset(&target, 0xa5, sizeof(target));
  CHECK(ftun_target_from_metadata(&metadata, &target) == FTUN_E_INVALID);
  CHECK(target.generation == 0u && target.original.kind == FTUN_ADDRESS_NONE &&
        target.candidates == NULL && !target.dial_selected);
  set_identity(&metadata, first, FTUN_DOMAIN_EXPLICIT);
  metadata.resolved = &candidate;
  metadata.resolved_count = 1u;
  candidate.port = 80u;
  CHECK(ftun_target_from_metadata(&metadata, &target) == FTUN_E_INVALID);
  candidate.port = 443u;
  CHECK(ftun_target_from_metadata(&metadata, &target) == FTUN_OK);

  memset(&route, 0, sizeof(route));
  route.kind = FTUN_ROUTE_READY;
  route.generation = 8u;
  CHECK(ftun_target_apply_route(&target, &route) == FTUN_E_STALE);
  route.generation = 7u;
  route.kind = FTUN_ROUTE_NEED_RESOLVE;
  CHECK(ftun_target_apply_route(&target, &route) == FTUN_E_INVALID);

  metadata.generation = 0u;
  CHECK(ftun_target_from_metadata(&metadata, &target) == FTUN_E_INVALID);
  metadata.generation = 7u;
  metadata.original_target.kind = FTUN_ADDRESS_IPV6_RESERVED;
  CHECK(ftun_target_from_metadata(&metadata, &target) == FTUN_E_UNSUPPORTED);
  metadata.original_target = ipv4(198u, 18u, 0u, 2u, 443u);
  metadata.original_is_fake = true;
  metadata.known_fields &= ~FTUN_META_DOMAIN;
  memset(&metadata.domain, 0, sizeof(metadata.domain));
  metadata.domain_source = FTUN_DOMAIN_NONE;
  CHECK(ftun_target_from_metadata(&metadata, &target) == FTUN_E_INVALID);
  CHECK(ftun_target_from_metadata(NULL, &target) == FTUN_E_INVALID);
  CHECK(ftun_target_from_metadata(&metadata, NULL) == FTUN_E_INVALID);
  CHECK(ftun_target_select_dial(NULL, &candidate) == FTUN_E_INVALID);
  CHECK(ftun_target_apply_route(NULL, &route) == FTUN_E_INVALID);
  return 0;
}

int main(void)
{
  CHECK(test_real_ip_is_not_replaced_by_sniff() == 0);
  CHECK(test_remote_domain_without_local_candidates() == 0);
  CHECK(test_fakeip_subset_and_retry() == 0);
  CHECK(test_route_and_metadata_failures() == 0);
  return 0;
}
