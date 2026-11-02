#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "platform/clock.h"
#include <time.h>

/* 单调时间。
 * 实现路径：平台时钟转换检查溢出；阶段 timeout 共享总 deadline；不能用墙钟变化延长重试。
 * 调用边界：不访问配置 AST，不跨线程修改 Session。
 */
ftun_status_t ftun_monotonic_now(uint64_t *out)
{
  if (out == NULL) return FTUN_E_INVALID;
  *out = 0;
#if defined(CLOCK_MONOTONIC)
  struct timespec now;
  uint64_t seconds;
  uint64_t fractional;

  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return FTUN_E_IO;
  if (now.tv_sec < 0 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000L) return FTUN_E_IO;
  seconds = (uint64_t)now.tv_sec;
  fractional = (uint64_t)now.tv_nsec / 1000000u;
  if (seconds > (UINT64_MAX - fractional) / 1000u) return FTUN_E_LIMIT;
  *out = seconds * 1000u + fractional;
  return FTUN_OK;
#else
  return FTUN_E_UNSUPPORTED;
#endif
}

ftun_status_t ftun_wallclock_utc(ftun_calendar_time_t *out)
{
  struct timespec now;
  struct tm parts;
  if (out == NULL) return FTUN_E_INVALID;
  if (clock_gettime(CLOCK_REALTIME, &now) != 0 || gmtime_r(&now.tv_sec, &parts) == NULL) {
    return FTUN_E_IO;
  }
  *out = (ftun_calendar_time_t){parts.tm_year + 1900, parts.tm_mon + 1, parts.tm_mday,
    parts.tm_hour, parts.tm_min, parts.tm_sec, (unsigned int)(now.tv_nsec / 1000000L)};
  return FTUN_OK;
}

ftun_status_t ftun_wallclock_unix_ms(int64_t *out)
{
  struct timespec now;
  if (clock_gettime(CLOCK_REALTIME, &now) != 0) return FTUN_E_IO;
  *out = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
  return FTUN_OK;
}

ftun_status_t ftun_wallclock_local(ftun_local_time_t *out)
{
  struct timespec now;
  struct tm parts;
  char zone[6];
  int offset;
  if (out == NULL) return FTUN_E_INVALID;
  if (clock_gettime(CLOCK_REALTIME, &now) != 0) return FTUN_E_IO;
  if (localtime_r(&now.tv_sec, &parts) == NULL ||
      strftime(zone, sizeof(zone), "%z", &parts) != 5u) {
    if (gmtime_r(&now.tv_sec, &parts) == NULL) return FTUN_E_IO;
    offset = 0;
  } else {
    offset = ((zone[1] - '0') * 10 + zone[2] - '0') * 60 +
      (zone[3] - '0') * 10 + zone[4] - '0';
    if (zone[0] == '-') offset = -offset;
  }
  out->calendar = (ftun_calendar_time_t){parts.tm_year + 1900, parts.tm_mon + 1,
    parts.tm_mday, parts.tm_hour, parts.tm_min, parts.tm_sec,
    (unsigned int)(now.tv_nsec / 1000000L)};
  out->offset_minutes = offset;
  return FTUN_OK;
}
