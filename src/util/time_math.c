#include "util/time_math.h"
#include <string.h>

int ftun_duration_parse_ms(const char *value, uint64_t *out)
{
  size_t length;
  size_t digits;
  size_t index;
  uint64_t result = 0u;
  uint64_t multiplier;
  if (value == NULL) return 0;
  length = strlen(value);
  if (length < 2u || value[0] < '1' || value[0] > '9') return 0;
  if (length >= 3u && value[length - 2u] == 'm' && value[length - 1u] == 's') {
    digits = length - 2u;
    multiplier = 1u;
  } else {
    digits = length - 1u;
    if (value[length - 1u] == 's') multiplier = 1000u;
    else if (value[length - 1u] == 'm') multiplier = 60u * 1000u;
    else if (value[length - 1u] == 'h') multiplier = 60u * 60u * 1000u;
    else return 0;
  }
  for (index = 0u; index < digits; index++) {
    uint64_t digit;
    if (value[index] < '0' || value[index] > '9') return 0;
    digit = (uint64_t)(value[index] - '0');
    if (result > (UINT64_MAX - digit) / 10u) return 0;
    result = result * 10u + digit;
  }
  if (result == 0u || result > UINT64_MAX / multiplier) return 0;
  if (out != NULL) *out = result * multiplier;
  return 1;
}

