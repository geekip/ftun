#include "platform/random.h"
#include <windows.h>
#include <limits.h>
#include <bcrypt.h>
ftun_status_t ftun_random_bytes(void *buffer, size_t length)
{
  unsigned char *bytes = buffer;
  while (length != 0u) {
    ULONG count = length > ULONG_MAX ? ULONG_MAX : (ULONG)length;
    if (BCryptGenRandom(NULL, bytes, count, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return FTUN_E_IO;
    bytes += count;
    length -= count;
  }
  return FTUN_OK;
}
ftun_status_t ftun_random_device_bytes(void *buffer, size_t length)
{
  return ftun_random_bytes(buffer, length);
}
