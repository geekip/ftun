#ifndef FTUN_PLATFORM_CLOCK_H
#define FTUN_PLATFORM_CLOCK_H
#include "util/types.h"
/* 返回绝对单调时刻，单位为毫秒。
 * 实现路径：平台时钟转换检查溢出；阶段 timeout 共享总 deadline；不能用墙钟变化延长重试。
 * 调用边界：不访问配置 AST，不跨线程修改 Session。
 * out 不能为空；失败时清零。该同步查询不转移所有权，也不触发回调。
 */
ftun_status_t ftun_monotonic_now(uint64_t *out);
/* UTC 日历值，用于诊断格式化；同步查询，不依赖进程时区。 */
typedef struct {
  int year, month, day, hour, minute, second;
  unsigned int millisecond;
} ftun_calendar_time_t;
ftun_status_t ftun_wallclock_utc(ftun_calendar_time_t *out);
#endif
