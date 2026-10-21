#include "app/cli/internal.h"

#include <stdio.h>

#ifndef FTUN_SOURCE_REVISION
#define FTUN_SOURCE_REVISION "unknown"
#endif

void ftun_cli_print_version(void)
{
  printf("FTUN %s\nsource: %s\ncapabilities: core", ftun_version(),
         FTUN_SOURCE_REVISION);
#if defined(FTUN_HAVE_MODULE_PROXY)
  fputs(",proxy", stdout);
#endif
#if defined(FTUN_HAVE_MODULE_DNS)
  fputs(",dns", stdout);
#endif
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  fputs(",fakeip", stdout);
#endif
#if defined(FTUN_HAVE_MODULE_TUN)
  fputs(",tun", stdout);
#endif
#if defined(FTUN_HAVE_MODULE_FRS)
  fputs(",frs", stdout);
#endif
  fputc('\n', stdout);
}
