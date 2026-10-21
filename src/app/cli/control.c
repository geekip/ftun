#define _POSIX_C_SOURCE 200809L

#include "app/cli/internal.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int ftun_cli_signal_process(const char *text, int signal_number,
                            const char *operation)
{
  char *end = NULL;
  unsigned long value;
  errno = 0;
  value = strtoul(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || value <= 1u ||
      value > (unsigned long)INT_MAX) {
    fprintf(stderr, "ftun: %s: invalid PID\n", operation);
    return 2;
  }
  if (kill((pid_t)value, signal_number) != 0) {
    fprintf(stderr, "ftun: %s: %s\n", operation, strerror(errno));
    return 1;
  }
  return 0;
}
