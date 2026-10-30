#include "platform/random.h"
#include <unistd.h>
#include <sys/random.h>

ftun_status_t ftun_random_bytes(void *buffer, size_t length)
{
  uint8_t *bytes = buffer;
  while (length != 0u) {
    size_t count = length > 256u ? 256u : length;
    if (getentropy(bytes, count) != 0) return FTUN_E_IO;
    bytes += count;
    length -= count;
  }
  return FTUN_OK;
}
ftun_status_t ftun_random_device_bytes(void *buffer, size_t length)
{
  return ftun_random_bytes(buffer, length);
}
