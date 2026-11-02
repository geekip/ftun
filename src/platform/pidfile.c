#define _POSIX_C_SOURCE 200809L
#include "platform/pidfile.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/un.h>
#include <unistd.h>
#endif

ftun_status_t ftun_pidfile_read(ftun_handle_t descriptor, uint32_t *pid)
{
  char contents[32];
  uint32_t value = 0u;
  ptrdiff_t length = ftun_file_read(descriptor, contents, sizeof(contents));
  size_t i;
  *pid = 0u;
  if (length < 0) return FTUN_E_IO;
  if (length == 0 || (size_t)length == sizeof(contents)) return FTUN_E_INVALID;
  if (contents[length - 1] == '\n') --length;
  if (length == 0) return FTUN_E_INVALID;
  for (i = 0u; i < (size_t)length; ++i) {
    uint32_t digit;
    if (contents[i] < '0' || contents[i] > '9') return FTUN_E_INVALID;
    digit = (uint32_t)(contents[i] - '0');
    if (value > ((uint32_t)INT_MAX - digit) / 10u) return FTUN_E_INVALID;
    value = value * 10u + digit;
  }
  if (value <= 1u) return FTUN_E_INVALID;
  *pid = value;
  return FTUN_OK;
}

ftun_status_t ftun_pidfile_path(const char *configured, char *out, size_t capacity)
{
  char storage[4096];
  ftun_string_t home;
  const char *suffix;
  int length;
  if (configured == NULL) {
#if !defined(_WIN32)
    if (geteuid() == 0) {
      length = snprintf(out, capacity, "/run/ftun/ftun.pid");
      return length >= 0 && (size_t)length < capacity ? FTUN_OK : FTUN_E_LIMIT;
    }
#endif
    suffix = "/.ftun/ftun.pid";
  } else if (configured[0] == '~' &&
      (configured[1] == '/' || configured[1] == '\0'
#if defined(_WIN32)
       || configured[1] == '\\'
#endif
      )) {
    suffix = configured + 1u;
  } else {
    length = snprintf(out, capacity, "%s", configured);
    if (length < 0 || (size_t)length >= capacity) return FTUN_E_LIMIT;
    ftun_file_path_normalize(out);
    return length == 0 ? FTUN_E_INVALID : FTUN_OK;
  }
  if (ftun_user_home(storage, sizeof(storage), &home) != FTUN_OK) return FTUN_E_IO;
  length = snprintf(out, capacity, "%.*s%s", (int)home.length, home.data, suffix);
  if (length < 0 || (size_t)length >= capacity) return FTUN_E_LIMIT;
  ftun_file_path_normalize(out);
  return FTUN_OK;
}

ftun_status_t ftun_pidfile_socket_path(const char *path, char *out, size_t capacity)
{
  size_t length = strlen(path);
  size_t native_capacity;
#if defined(_WIN32)
  native_capacity = 108u;
#else
  native_capacity = sizeof(((struct sockaddr_un *)0)->sun_path);
#endif
  if (length >= 4u && memcmp(path + length - 4u, ".pid", 4u) == 0) length -= 4u;
  if (length + sizeof(".sock") > capacity ||
      length + sizeof(".sock") > native_capacity) return FTUN_E_LIMIT;
  memcpy(out, path, length);
  memcpy(out + length, ".sock", sizeof(".sock"));
  return FTUN_OK;
}
