#include "ftun/error.h"
/* REQ-OBS-001：真实基础实现，只映射错误名，无全局 errno 读取。 */
const char *ftun_status_name(ftun_status_t status) {
  static const char *const names[] = {"ok", "invalid", "not-implemented", "unsupported",
    "again", "eof", "cancelled", "timeout", "limit", "io", "resolve", "rejected",
    "protocol", "restart-required", "stale", "state-corrupt"};
  unsigned int value = (unsigned int)status;
  return value < sizeof(names)/sizeof(names[0]) ? names[value] : "unknown";
}
