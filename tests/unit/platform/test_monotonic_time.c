#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "platform/clock.h"
#include <stdint.h>
#include <stdio.h>
#include <time.h>

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
  return 0;
}
