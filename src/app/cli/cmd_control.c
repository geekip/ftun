#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include "app/cli/internal.h"

#include <limits.h>
#include "platform/process.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int ftun_cli_signal_process(const char *text, int signal_number,
                            const char *operation)
{
  char *end = NULL;
  unsigned long value;
  int native_error;
  errno = 0;
  value = strtoul(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || value <= 1u ||
      value > (unsigned long)INT_MAX) {
    fprintf(stderr, "ftun: %s: invalid PID\n", operation);
    return 2;
  }
  if (ftun_process_signal((uint32_t)value, (uint32_t)signal_number, &native_error) != FTUN_OK) {
    fprintf(stderr, "ftun: %s: %s\n", operation, strerror(native_error));
    return 1;
  }
  return 0;
}
