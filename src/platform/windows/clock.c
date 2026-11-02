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

ftun_status_t ftun_wallclock_unix_ms(int64_t *out)
{
  FILETIME now;
  GetSystemTimeAsFileTime(&now);
  *out = (int64_t)((((uint64_t)now.dwHighDateTime << 32u) | now.dwLowDateTime) / 10000u)
    - INT64_C(11644473600000);
  return FTUN_OK;
}

ftun_status_t ftun_wallclock_local(ftun_local_time_t *out)
{
  SYSTEMTIME utc, local;
  FILETIME utc_file, local_file;
  int64_t utc_ticks, local_ticks;
  if (out == NULL) return FTUN_E_INVALID;
  GetSystemTime(&utc);
  if (!SystemTimeToTzSpecificLocalTime(NULL, &utc, &local)) {
    out->offset_minutes = 0;
    out->calendar = (ftun_calendar_time_t){utc.wYear, utc.wMonth, utc.wDay,
      utc.wHour, utc.wMinute, utc.wSecond, utc.wMilliseconds};
    return FTUN_OK;
  }
  if (!SystemTimeToFileTime(&utc, &utc_file) ||
      !SystemTimeToFileTime(&local, &local_file)) return FTUN_E_IO;
  utc_ticks = (int64_t)(((uint64_t)utc_file.dwHighDateTime << 32u) | utc_file.dwLowDateTime);
  local_ticks = (int64_t)(((uint64_t)local_file.dwHighDateTime << 32u) | local_file.dwLowDateTime);
  out->offset_minutes = (int)((local_ticks - utc_ticks) / INT64_C(600000000));
  out->calendar = (ftun_calendar_time_t){local.wYear, local.wMonth, local.wDay,
    local.wHour, local.wMinute, local.wSecond, local.wMilliseconds};
  return FTUN_OK;
}
