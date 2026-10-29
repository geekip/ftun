#include "fuzz_common.h"

#include "proxy/sniff/sniff.h"

#include <string.h>

/* 嗅探：第一个字节选择原始目标端口（80/443/其他），其余为预读字节。 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  static const uint16_t ports[] = {80u, 443u, 8080u, 25u};
  ftun_metadata_t metadata;
  ftun_sniff_result_t result;
  ftun_status_t status;
  memset(&metadata, 0, sizeof(metadata));
  metadata.original_target.kind = FTUN_ADDRESS_IPV4;
  metadata.original_target.port = size == 0u ? 443u : ports[data[0] & 3u];
  status = ftun_sniff_domain(&metadata,
    (ftun_bytes_t){size == 0u ? data : data + 1u, size == 0u ? 0u : size - 1u}, &result);
  FUZZ_NOT_CORRUPT(status);
  return 0;
}

void ftun_fuzz_seeds(ftun_fuzz_seed_fn add)
{
  static const uint8_t http[] =
    "\x00GET / HTTP/1.1\r\nHost: sniff.example\r\nUser-Agent: x\r\n\r\n";
  static const uint8_t tls[] = {
    0x01, 0x16, 0x03, 0x01, 0x00, 0x3c, 0x01, 0x00, 0x00, 0x38, 0x03, 0x03,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x0d,
    0x00, 0x00, 0x00, 0x09, 0x00, 0x07, 0x00, 0x00, 0x04, 't','l','s','.'
  };
  add(http, sizeof(http) - 1u);
  add(tls, sizeof(tls));
}
