#include "fuzz_common.h"
#include "app/control/request.h"
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  ftun_ctl_request_t request;
  ftun_status_t status = ftun_ctl_request_parse(NULL, (ftun_bytes_t){data, size}, &request);
  FUZZ_REQUIRE(status == FTUN_OK || status == FTUN_E_INVALID ||
    status == FTUN_E_LIMIT || status == FTUN_E_AGAIN);
  if (status == FTUN_OK) {
    FUZZ_REQUIRE(request.operation >= FTUN_CTL_STATUS && request.operation <= FTUN_CTL_STOP);
    FUZZ_REQUIRE(request.timeout_ms <= FTUN_CTL_TIMEOUT_MAX);
    FUZZ_REQUIRE(request.timeout_ms != 0u || request.operation == FTUN_CTL_RELOAD ||
      request.operation == FTUN_CTL_STOP);
  } else {
    FUZZ_REQUIRE(request.operation == 0 && request.timeout_ms == 0u && !request.boot_present && request.boot == 0u);
  }
  return 0;
}

void ftun_fuzz_seeds(ftun_fuzz_seed_fn add)
{
  static const char *const seeds[] = {"{\"op\":\"status\"}", "{\"op\":\"reload\",\"timeout_ms\":0}",
    "{\"op\":\"stop\",\"boot\":\"0123456789abcdef\",\"timeout_ms\":1}",
    "{\"op\":\"stop\",\"op\":\"status\"}", "{\"op\":\"status\\u0000\"}", "[]"};
  size_t i;
  for (i = 0u; i < sizeof(seeds) / sizeof(seeds[0]); i++) {
    add((const uint8_t *)seeds[i], strlen(seeds[i]));
  }
}
