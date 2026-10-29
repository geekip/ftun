#include "fuzz_common.h"

#include "libs/resolver/dnswire.h"

/* DNS 报文解析：成功交付对象，失败不留对象，也不报内部状态损坏。 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  ftun_dns_message_t *message = NULL;
  ftun_status_t status = ftun_dns_message_parse((ftun_bytes_t){data, size}, &message);
  FUZZ_NOT_CORRUPT(status);
  if (status == FTUN_OK) {
    FUZZ_REQUIRE(message != NULL);
    FUZZ_REQUIRE(ftun_dns_message_release(&message) == FTUN_OK && message == NULL);
  } else {
    FUZZ_REQUIRE(message == NULL);
  }
  return 0;
}

/* 一个普通 A 查询和一个带压缩指针的响应。 */
void ftun_fuzz_seeds(ftun_fuzz_seed_fn add)
{
  static const uint8_t query[] = {
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0, 0x00, 0x01, 0x00, 0x01
  };
  static const uint8_t response[] = {
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0, 0x00, 0x01, 0x00, 0x01,
    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
    93, 184, 216, 34
  };
  add(query, sizeof(query));
  add(response, sizeof(response));
}
