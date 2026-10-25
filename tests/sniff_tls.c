#include "proxy/sniff/tls_sni.h"
#include "proxy/sniff/sniff.h"
#include "core/budget.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "TLS sniff contract failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

static size_t client_hello(uint8_t *out, const char *name, int fragmented)
{
  uint8_t body[512];
  uint8_t handshake[520];
  size_t name_length = strlen(name);
  size_t cursor = 0u;
  size_t body_length;
  size_t handshake_length;
  size_t first;
  body[cursor++] = 3u;
  body[cursor++] = 3u;
  memset(body + cursor, 0x5au, 32u);
  cursor += 32u;
  body[cursor++] = 0u;
  body[cursor++] = 0u;
  body[cursor++] = 2u;
  body[cursor++] = 0x13u;
  body[cursor++] = 0x01u;
  body[cursor++] = 1u;
  body[cursor++] = 0u;
  body[cursor++] = 0u;
  body[cursor++] = (uint8_t)(9u + name_length);
  body[cursor++] = 0u;
  body[cursor++] = 0u;
  body[cursor++] = 0u;
  body[cursor++] = (uint8_t)(5u + name_length);
  body[cursor++] = 0u;
  body[cursor++] = (uint8_t)(3u + name_length);
  body[cursor++] = 0u;
  body[cursor++] = (uint8_t)(name_length >> 8u);
  body[cursor++] = (uint8_t)name_length;
  memcpy(body + cursor, name, name_length);
  cursor += name_length;
  body_length = cursor;
  handshake[0] = 1u;
  handshake[1] = (uint8_t)(body_length >> 16u);
  handshake[2] = (uint8_t)(body_length >> 8u);
  handshake[3] = (uint8_t)body_length;
  memcpy(handshake + 4u, body, body_length);
  handshake_length = body_length + 4u;
  first = fragmented ? 13u : handshake_length;
  out[0] = 22u;
  out[1] = 3u;
  out[2] = 3u;
  out[3] = (uint8_t)(first >> 8u);
  out[4] = (uint8_t)first;
  memcpy(out + 5u, handshake, first);
  if (!fragmented) return handshake_length + 5u;
  out[5u + first] = 22u;
  out[6u + first] = 3u;
  out[7u + first] = 3u;
  out[8u + first] = (uint8_t)((handshake_length - first) >> 8u);
  out[9u + first] = (uint8_t)(handshake_length - first);
  memcpy(out + 10u + first, handshake + first, handshake_length - first);
  return handshake_length + 10u;
}

int main(void)
{
  uint8_t wire[1024];
  ftun_sniff_result_t result;
  ftun_bytes_t input;
  size_t length = client_hello(wire, "WWW.Example.COM", 1);
  input.data = wire;
  input.length = length;
  {
    ftun_budget_t *budget = NULL;
    ftun_reservation_t *hold = NULL;
    ftun_budget_usage_t usage;
    ftun_metadata_t metadata = {0};
    CHECK(ftun_budget_create(NULL, 131072u, 0u, &budget) == FTUN_OK);
    CHECK(ftun_budget_reserve(budget, 65537u, &hold) == FTUN_OK);
    CHECK(ftun_sniff_domain_with_budget(budget, &metadata, input, &result) == FTUN_E_LIMIT);
    CHECK(!result.found && result.domain.data == NULL);
    CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == 65537u);
    CHECK(ftun_reservation_release(&hold) == FTUN_OK);
    CHECK(ftun_sniff_domain_with_budget(budget, &metadata, input, &result) == FTUN_OK && result.found);
    CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == 0u &&
      usage.high_watermarks.memory_bytes >= 65536u);
    CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  }
  CHECK(ftun_sniff_tls_sni(input, &result) == FTUN_OK);
  CHECK(result.found && !result.need_more);
  CHECK(result.domain.length == strlen("www.example.com"));
  CHECK(memcmp(result.domain.data, "www.example.com", result.domain.length) == 0);
  CHECK(result.domain.data == result.domain_storage);

  input.length = 7u;
  CHECK(ftun_sniff_tls_sni(input, &result) == FTUN_OK);
  CHECK(!result.found && result.need_more);

  length = client_hello(wire, "bad..example", 0);
  input.length = length;
  CHECK(ftun_sniff_tls_sni(input, &result) == FTUN_E_PROTOCOL);
  CHECK(!result.found && !result.need_more && result.domain.data == NULL);

  wire[0] = 23u;
  input.length = 5u;
  CHECK(ftun_sniff_tls_sni(input, &result) == FTUN_OK);
  CHECK(!result.found && !result.need_more);
  CHECK(ftun_sniff_tls_sni((ftun_bytes_t){NULL, 1u}, &result) ==
        FTUN_E_INVALID);
  CHECK(ftun_sniff_tls_sni((ftun_bytes_t){NULL, 0u}, NULL) ==
        FTUN_E_INVALID);
  return 0;
}
