#include "proxy/sniff/sniff.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "sniff contract failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

int main(void)
{
  static const char request[] =
    "GET / HTTP/1.1\r\nHost: Hint.Example\r\n\r\nbody";
  ftun_metadata_t metadata;
  ftun_metadata_t before;
  ftun_sniff_result_t result;
  memset(&metadata, 0, sizeof(metadata));
  metadata.original_target.kind = FTUN_ADDRESS_IPV4;
  metadata.original_target.address[0] = 192u;
  metadata.original_target.address[1] = 0u;
  metadata.original_target.address[2] = 2u;
  metadata.original_target.address[3] = 1u;
  metadata.original_target.port = 80u;
  before = metadata;
  CHECK(ftun_sniff_domain(&metadata,
        (ftun_bytes_t){(const uint8_t *)request, sizeof(request) - 1u},
        &result) == FTUN_OK);
  CHECK(result.found && result.domain.length == strlen("hint.example"));
  CHECK(memcmp(&metadata, &before, sizeof(metadata)) == 0);

  metadata.domain.data = "configured.example";
  metadata.domain.length = strlen(metadata.domain.data);
  CHECK(ftun_sniff_domain(&metadata,
        (ftun_bytes_t){(const uint8_t *)request, sizeof(request) - 1u},
        &result) == FTUN_OK);
  CHECK(!result.found && !result.need_more);

  memset(&metadata, 0, sizeof(metadata));
  metadata.original_target.kind = FTUN_ADDRESS_IPV4;
  CHECK(ftun_sniff_domain(&metadata,
        (ftun_bytes_t){(const uint8_t *)"not a protocol\r\n\r\n", 18u},
        &result) == FTUN_OK);
  CHECK(!result.found && !result.need_more);
  CHECK(ftun_sniff_domain(NULL, (ftun_bytes_t){NULL, 0u}, &result) ==
        FTUN_E_INVALID);
  return 0;
}
