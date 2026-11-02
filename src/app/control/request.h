#ifndef FTUN_APP_CONTROL_REQUEST_H
#define FTUN_APP_CONTROL_REQUEST_H
#include "util/types.h"

#define FTUN_CTL_REQUEST_MAX 4096u
#define FTUN_CTL_TIMEOUT_MAX 3600000u

typedef enum {
  FTUN_CTL_STATUS = 1,
  FTUN_CTL_DNS_STATUS,
  FTUN_CTL_PROXY_STATUS,
  FTUN_CTL_RELOAD,
  FTUN_CTL_STOP
} ftun_ctl_operation_t;

typedef struct {
  ftun_ctl_operation_t operation;
  uint32_t timeout_ms;
  bool boot_present;
  uint64_t boot;
} ftun_ctl_request_t;

/* 单行JSON正文，不含行终止符；输出按值拥有，失败清零。
 * 复用cJSON的严格边界和临时预算；全局解析器忙时返回AGAIN，不等待Worker。
 * timeout_ms=0只用于reload/stop的接纳回执，其余请求等待有界终态。 */
ftun_status_t ftun_ctl_request_parse(ftun_budget_t *budget, ftun_bytes_t input,
  ftun_ctl_request_t *out);
#endif
