#define _DARWIN_C_SOURCE 1
#include "platform/process.h"
#include <mach-o/dyld.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <unistd.h>

uint64_t ftun_process_boot_token(void)
{
  uint64_t token;
  arc4random_buf(&token, sizeof(token));
  return token == 0u ? 1u : token;
}
ftun_status_t ftun_platform_boot_identity(void *buffer, size_t capacity, size_t *length)
{
  size_t size = capacity;
  *length = 0u;
  if (sysctlbyname("kern.bootsessionuuid", buffer, &size, NULL, 0u) != 0) return FTUN_E_IO;
  *length = strnlen(buffer, size);
  return FTUN_OK;
}
size_t ftun_platform_descriptor_limit(size_t requested)
{
  struct rlimit limit;
  if (getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur != RLIM_INFINITY &&
      limit.rlim_cur < (rlim_t)requested) return (size_t)limit.rlim_cur;
  return requested;
}
ptrdiff_t ftun_process_executable(char *buffer, size_t capacity)
{
  uint32_t size = capacity > UINT32_MAX ? UINT32_MAX : (uint32_t)capacity;
  return _NSGetExecutablePath(buffer, &size) == 0 ? (ptrdiff_t)strlen(buffer) : -1;
}
/* CLI只有一个启用内核兜底期限的看门狗，ITIMER_REAL按经过时长发送SIGALRM。 */
ftun_status_t ftun_process_alarm_start(ftun_process_alarm_t *alarm, uint64_t milliseconds)
{
  struct itimerval value = {{0, 0}, {(time_t)(milliseconds / 1000u),
    (suseconds_t)(milliseconds % 1000u) * 1000}};
  if (setitimer(ITIMER_REAL, &value, NULL) != 0) return FTUN_E_IO;
  alarm->native = 1u;
  return FTUN_OK;
}
void ftun_process_alarm_destroy(ftun_process_alarm_t *alarm)
{
  struct itimerval value = {{0, 0}, {0, 0}};
  if (setitimer(ITIMER_REAL, &value, NULL) != 0) abort();
  alarm->native = 0u;
}
