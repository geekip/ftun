#include "platform/random.h"
#include "platform/file.h"
#include <sys/random.h>
#include <errno.h>
ftun_status_t ftun_random_bytes(void *buffer, size_t length)
{
  size_t offset = 0;
  while (offset < length) {
    ssize_t count = getrandom((uint8_t *)buffer + offset, length - offset, 0);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return FTUN_E_IO;
    offset += (size_t)count;
  }
  return FTUN_OK;
}

ftun_status_t ftun_random_device_bytes(void *buffer, size_t length)
{
  size_t offset = 0u;
  ftun_handle_t descriptor;
  ftun_status_t status = ftun_file_open("/dev/urandom", FTUN_FILE_READ, &descriptor);
  if (status != FTUN_OK) return FTUN_E_IO;
  while (offset < length) {
    ptrdiff_t count = ftun_file_read(descriptor, (uint8_t *)buffer + offset, length - offset);
    if (count <= 0) { status = FTUN_E_IO; break; }
    offset += (size_t)count;
  }
  if (ftun_file_close(descriptor) != FTUN_OK) status = FTUN_E_IO;
  return status;
}
