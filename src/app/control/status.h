#ifndef FTUN_APP_CONTROL_STATUS_H
#define FTUN_APP_CONTROL_STATUS_H
#include "app/control.h"
#include "app/control/request.h"
#include "core/status.h"
#include "platform/clock.h"
#if defined(FTUN_HAVE_MODULE_DNS)
#include "dns/status.h"
#endif
#if defined(FTUN_HAVE_MODULE_PROXY)
#include "proxy/status.h"
#endif

typedef struct {
  const char *name; /* 编译期常量，无运行时借用。 */
  ftun_service_status_t status;
} ftun_ctl_service_status_t;

typedef struct {
  ftun_app_control_snapshot_t host;
  ftun_budget_usage_t resources;
  uint64_t uptime_ms, reload_sequence, reload_generation, log_sequence;
  ftun_status_t reload_result;
  ftun_calendar_time_t reload_time;
  bool reload_time_valid;
  ftun_ctl_service_status_t services[6];
  size_t service_count;
  char log_level[16], log_output[16];
  char log_file[FTUN_APP_CONTROL_PATH_CAPACITY];
#if defined(FTUN_HAVE_MODULE_DNS)
  ftun_dns_status_t dns;
#endif
#if defined(FTUN_HAVE_MODULE_PROXY)
  ftun_proxy_status_t proxy;
#endif
} ftun_ctl_status_t;

/* 仅同一owner同步查询；调用方先准入整个out，填完后无运行时对象借用。
 * 不分配、不做文件/网络I/O；默认组合只通过模块status_fill读取业务。 */
ftun_status_t ftun_ctl_status_fill(ftun_core_t *core, ftun_ctl_status_t *out);
ftun_status_t ftun_app_default_status_fill(ftun_core_t *core, ftun_ctl_status_t *out);
/* 追加以逗号开头的正文并关闭已有JSON对象；不分配，明细按字节/项数截断。 */
ftun_status_t ftun_ctl_status_json(const ftun_ctl_status_t *snapshot, ftun_ctl_operation_t operation,
  char *out, size_t capacity, size_t *length);
/* 外部字符串转义到调用方缓冲；0表示容量不足，无分配。 */
size_t ftun_ctl_json_quote(const char *text, char *out, size_t capacity);
#endif
