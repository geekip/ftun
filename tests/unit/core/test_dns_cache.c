#include "core/limits.h"
#include "dns/cache.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "dns cache contract failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

static ftun_status_t fake_clock_status;

static ftun_status_t fake_now(void *user, uint64_t *out)
{
  if (fake_clock_status != FTUN_OK) return fake_clock_status;
  *out = *(uint64_t *)user;
  return FTUN_OK;
}

static void query_init(ftun_dns_query_t *query, uint16_t id,
                       uint64_t policy, uint32_t outbound)
{
  static const uint8_t name[] = {7u,'e','x','a','m','p','l','e',
                                 3u,'c','o','m',0u};
  memset(query, 0, sizeof(*query));
  query->id = id;
  query->flags = 0x0110u;
  query->transport = FTUN_DNS_TRANSPORT_UDP;
  query->upstream.kind = FTUN_ADDRESS_IPV4;
  query->upstream.address[0] = 192u;
  query->upstream.address[1] = 0u;
  query->upstream.address[2] = 2u;
  query->upstream.address[3] = 53u;
  query->upstream.port = 53u;
  query->question.name.data = name;
  query->question.name.length = sizeof(name);
  query->question.type = 1u;
  query->question.class_code = 1u;
  query->policy_fingerprint = policy;
  query->server_fingerprint = 7u;
  query->outbound_id = outbound;
  query->resolution_mode = 1u;
}

static void response_init(uint8_t wire[45], uint16_t id, uint8_t last,
                          uint32_t ttl, uint16_t rcode)
{
  static const uint8_t question[] = {
    7u,'e','x','a','m','p','l','e',3u,'c','o','m',0u,0u,1u,0u,1u
  };
  memset(wire, 0, 45u);
  wire[0] = (uint8_t)(id >> 8u);
  wire[1] = (uint8_t)id;
  wire[2] = 0x81u;
  wire[3] = (uint8_t)(0x80u | rcode);
  wire[5] = 1u;
  wire[7] = rcode == 0u ? 1u : 0u;
  memcpy(wire + 12u, question, sizeof(question));
  if (rcode == 0u) {
    wire[29] = 0xc0u;
    wire[30] = 0x0cu;
    wire[31] = 0u; wire[32] = 1u;
    wire[33] = 0u; wire[34] = 1u;
    wire[35] = (uint8_t)(ttl >> 24u);
    wire[36] = (uint8_t)(ttl >> 16u);
    wire[37] = (uint8_t)(ttl >> 8u);
    wire[38] = (uint8_t)ttl;
    wire[39] = 0u; wire[40] = 4u;
    wire[41] = 203u; wire[42] = 0u; wire[43] = 113u; wire[44] = last;
  }
}

static void negative_response_init(uint8_t wire[63], uint16_t id,
                                   uint32_t ttl, uint32_t minimum)
{
  static const uint8_t question[] = {
    7u,'e','x','a','m','p','l','e',3u,'c','o','m',0u,0u,1u,0u,1u
  };
  memset(wire, 0, 63u);
  wire[0] = (uint8_t)(id >> 8u);
  wire[1] = (uint8_t)id;
  wire[2] = 0x81u;
  wire[3] = 0x83u;
  wire[5] = 1u;
  wire[9] = 1u;
  memcpy(wire + 12u, question, sizeof(question));
  wire[29] = 0xc0u;
  wire[30] = 0x0cu;
  wire[31] = 0u; wire[32] = 6u;
  wire[33] = 0u; wire[34] = 1u;
  wire[35] = (uint8_t)(ttl >> 24u);
  wire[36] = (uint8_t)(ttl >> 16u);
  wire[37] = (uint8_t)(ttl >> 8u);
  wire[38] = (uint8_t)ttl;
  wire[39] = 0u; wire[40] = 22u;
  wire[59] = (uint8_t)(minimum >> 24u);
  wire[60] = (uint8_t)(minimum >> 16u);
  wire[61] = (uint8_t)(minimum >> 8u);
  wire[62] = (uint8_t)minimum;
}

int main(void)
{
  ftun_budget_t *budget = NULL;
  ftun_dns_cache_t *cache = NULL;
  ftun_dns_answer_t *answer = NULL;
  ftun_dns_cache_options_t options;
  ftun_dns_cache_usage_t usage;
  ftun_dns_query_t query;
  ftun_dns_query_t isolated;
  uint8_t response[45];
  uint8_t negative[63];
  static const uint32_t heap_ttls[] = {30u, 5u, 20u, 10u};
  size_t index;
  uint64_t now = 1000u;
  memset(&options, 0, sizeof(options));
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  options.budget = budget;
  options.max_entries = 4u;
  options.now = fake_now;
  options.now_user = &now;
  CHECK(ftun_dns_cache_create(&options, &cache) == FTUN_OK);
  query_init(&query, 0x1234u, 10u, 2u);
  response_init(response, query.id, 7u, 10u, 0u);
  CHECK(ftun_dns_cache_store(cache, &query,
    (ftun_bytes_t){response, sizeof(response)}) == FTUN_OK);
  fake_clock_status = FTUN_E_IO;
  CHECK(ftun_dns_cache_lookup(cache, &query, &answer) == FTUN_E_IO && answer == NULL);
  CHECK(ftun_dns_cache_store(cache, &query,
    (ftun_bytes_t){response, sizeof(response)}) == FTUN_E_IO);
  fake_clock_status = FTUN_OK;
  now = 3500u;
  query.id = 0x4567u;
  CHECK(ftun_dns_cache_lookup(cache, &query, &answer) == FTUN_OK &&
        answer->kind == FTUN_DNS_CACHE_POSITIVE &&
        answer->wire[0] == 0x45u && answer->wire[1] == 0x67u &&
        answer->wire[38] == 8u);
  ftun_dns_answer_release(&answer);
  isolated = query;
  isolated.policy_fingerprint++;
  CHECK(ftun_dns_cache_lookup(cache, &isolated, &answer) == FTUN_E_EOF);
  isolated = query;
  isolated.outbound_id++;
  CHECK(ftun_dns_cache_lookup(cache, &isolated, &answer) == FTUN_E_EOF);
  isolated = query;
  isolated.dnssec_ok = true;
  CHECK(ftun_dns_cache_lookup(cache, &isolated, &answer) == FTUN_E_EOF);
  query.id = 0x7777u;
  negative_response_init(negative, query.id, 30u, 5u);
  CHECK(ftun_dns_cache_store(cache, &query,
    (ftun_bytes_t){negative, sizeof(negative)}) == FTUN_OK);
  query.id = 0x8888u;
  CHECK(ftun_dns_cache_lookup(cache, &query, &answer) == FTUN_OK &&
        answer->kind == FTUN_DNS_CACHE_NEGATIVE &&
        answer->wire[0] == 0x88u && answer->wire[1] == 0x88u &&
        answer->wire[38] == 30u);
  ftun_dns_answer_release(&answer);
  isolated = query;
  isolated.server_fingerprint++;
  CHECK(ftun_dns_cache_store_failure(cache, &isolated, FTUN_E_TIMEOUT,
                                      500u) == FTUN_OK);
  CHECK(ftun_dns_cache_lookup(cache, &isolated, &answer) == FTUN_E_TIMEOUT &&
        answer == NULL);
  now += 500u;
  CHECK(ftun_dns_cache_lookup(cache, &isolated, &answer) == FTUN_E_EOF);
  CHECK(ftun_dns_cache_get_usage(cache, &usage) == FTUN_OK &&
        usage.positive == 0u && usage.negative == 1u && usage.failures == 0u);
  now = 9000u;
  CHECK(ftun_dns_cache_lookup(cache, &query, &answer) == FTUN_E_EOF);
  CHECK(ftun_dns_cache_destroy(&cache) == FTUN_OK);

  now = 1000u;
  CHECK(ftun_dns_cache_create(&options, &cache) == FTUN_OK);
  for (index = 0u; index < 4u; index++) {
    query_init(&query, (uint16_t)(0x3000u + index), 100u + index, 2u);
    response_init(response, query.id, (uint8_t)(20u + index),
                  heap_ttls[index], 0u);
    CHECK(ftun_dns_cache_store(cache, &query,
      (ftun_bytes_t){response, sizeof(response)}) == FTUN_OK);
  }
  query_init(&query, 0x3005u, 105u, 2u);
  response_init(response, query.id, 25u, 15u, 0u);
  CHECK(ftun_dns_cache_store(cache, &query,
    (ftun_bytes_t){response, sizeof(response)}) == FTUN_OK);
  query_init(&isolated, 0x3001u, 101u, 2u);
  CHECK(ftun_dns_cache_lookup(cache, &isolated, &answer) == FTUN_E_EOF);
  query_init(&isolated, 0x3000u, 100u, 2u);
  CHECK(ftun_dns_cache_lookup(cache, &isolated, &answer) == FTUN_OK);
  ftun_dns_answer_release(&answer);
  CHECK(ftun_dns_cache_get_usage(cache, &usage) == FTUN_OK &&
        usage.entries == 4u && usage.evictions == 1u &&
        usage.expirations == 0u && usage.hits == 1u && usage.misses == 1u);
  now = 12000u;
  query_init(&query, 0x3006u, 106u, 2u);
  response_init(response, query.id, 26u, 40u, 0u);
  CHECK(ftun_dns_cache_store(cache, &query,
    (ftun_bytes_t){response, sizeof(response)}) == FTUN_OK);
  query_init(&isolated, 0x3003u, 103u, 2u);
  CHECK(ftun_dns_cache_lookup(cache, &isolated, &answer) == FTUN_E_EOF);
  CHECK(ftun_dns_cache_get_usage(cache, &usage) == FTUN_OK &&
        usage.entries == 4u && usage.evictions == 1u &&
        usage.expirations == 1u && usage.misses == 2u);
  CHECK(ftun_dns_cache_destroy(&cache) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}
