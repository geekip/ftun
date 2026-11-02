#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "platform/clock.h"
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "time contract failed: %s\n", #x); return 1; } } while (0)

static uint64_t milliseconds(const struct timespec *value)
{
  return (uint64_t)value->tv_sec * 1000u + (uint64_t)value->tv_nsec / 1000000u;
}

int main(void)
{
  struct timespec before, after;
  uint64_t first = UINT64_MAX;
  uint64_t next = 0;
  size_t i;

  CHECK(ftun_monotonic_now(NULL) == FTUN_E_INVALID);
  CHECK(clock_gettime(CLOCK_MONOTONIC, &before) == 0);
  CHECK(ftun_monotonic_now(&first) == FTUN_OK);
  CHECK(clock_gettime(CLOCK_MONOTONIC, &after) == 0);
  CHECK(first >= milliseconds(&before));
  CHECK(first <= milliseconds(&after));
  for (i = 0; i < 1024; ++i) {
    CHECK(ftun_monotonic_now(&next) == FTUN_OK);
    CHECK(next >= first);
    first = next;
  }
  {
    int64_t wall;
    CHECK(clock_gettime(CLOCK_REALTIME, &before) == 0);
    CHECK(ftun_wallclock_unix_ms(&wall) == FTUN_OK);
    CHECK(clock_gettime(CLOCK_REALTIME, &after) == 0);
    CHECK(wall >= (int64_t)milliseconds(&before) && wall <= (int64_t)milliseconds(&after));
  }
  {
    const char *zones[] = {"UTC0", "CST-8", "EST5EDT", ":/ftun-missing-zoneinfo"};
    CHECK(ftun_wallclock_local(NULL) == FTUN_E_INVALID);
    for (i = 0u; i < sizeof(zones) / sizeof(zones[0]); ++i) {
      ftun_local_time_t local;
      struct tm oracle;
      time_t seconds;
      int64_t wall_for_local;
      char actual[48], expected[48];
      CHECK(setenv("TZ", zones[i], 1) == 0);
      tzset();
      CHECK(ftun_wallclock_local(&local) == FTUN_OK);
      CHECK(ftun_wallclock_unix_ms(&wall_for_local) == FTUN_OK);
      seconds = (time_t)(wall_for_local / 1000);
      CHECK(localtime_r(&seconds, &oracle) != NULL);
      CHECK(strftime(expected, sizeof(expected), "%Y-%m-%d %H:%M %z", &oracle) != 0u);
      (void)snprintf(actual, sizeof(actual), "%04d-%02d-%02d %02d:%02d %c%02d%02d",
        local.calendar.year, local.calendar.month, local.calendar.day, local.calendar.hour,
        local.calendar.minute, local.offset_minutes < 0 ? '-' : '+',
        abs(local.offset_minutes) / 60, abs(local.offset_minutes) % 60);
      CHECK(strcmp(actual, expected) == 0);
      CHECK(local.calendar.millisecond < 1000u);
    }
  }
  return 0;
}
