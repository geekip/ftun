#define _POSIX_C_SOURCE 200809L
#include "platform/file.h"
#include <sys/resource.h>
#include "platform/process.h"
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

uint64_t ftun_process_boot_token(void)
{
  uint64_t fresh = 0u;
  struct timespec now = {0, 0};
  /* 沿用日志标识的非阻塞生成语义；该值不是安全凭据。 */
  if (getrandom(&fresh, sizeof(fresh), GRND_NONBLOCK) != (ssize_t)sizeof(fresh)) {
    (void)clock_gettime(CLOCK_REALTIME, &now);
    fresh = ((uint64_t)now.tv_sec << 32) ^ (uint64_t)now.tv_nsec ^ ((uint64_t)getpid() << 16);
  }
  return fresh == 0u ? 1u : fresh;
}

ftun_status_t ftun_platform_boot_identity(void *buffer, size_t capacity, size_t *length)
{
  int descriptor;
  size_t offset = 0u;
  ftun_status_t status = ftun_file_open("/proc/sys/kernel/random/boot_id",
    FTUN_FILE_READ_NOFOLLOW, &descriptor);
  *length = 0u;
  if (status != FTUN_OK) return status;
  while (offset < capacity) {
    ptrdiff_t count = ftun_file_read(descriptor, (uint8_t *)buffer + offset, capacity - offset);
    if (count < 0) { status = FTUN_E_IO; break; }
    if (count == 0) break;
    offset += (size_t)count;
  }
  if (ftun_file_close(descriptor) != FTUN_OK) status = FTUN_E_IO;
  if (status == FTUN_OK) *length = offset;
  return status;
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
  return (ptrdiff_t)readlink("/proc/self/exe", buffer, capacity);
}
