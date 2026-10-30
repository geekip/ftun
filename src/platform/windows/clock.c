#include "platform/clock.h"
#include <windows.h>
ftun_status_t ftun_monotonic_now(uint64_t *out)
{
  if (out == NULL) return FTUN_E_INVALID;
  *out = GetTickCount64();
  return FTUN_OK;
}
ftun_status_t ftun_wallclock_utc(ftun_calendar_time_t *out)
{
  SYSTEMTIME now;
  if (out == NULL) return FTUN_E_INVALID;
  GetSystemTime(&now);
  *out = (ftun_calendar_time_t){now.wYear, now.wMonth, now.wDay, now.wHour,
    now.wMinute, now.wSecond, now.wMilliseconds};
  return FTUN_OK;
}
