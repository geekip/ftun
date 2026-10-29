#define _POSIX_C_SOURCE 200809L
#include <sys/types.h>
#include "platform/file.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "file primitive failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)
static bool fail_write;
static unsigned int write_calls;
ssize_t __real_write(int fd, const void *data, size_t length);
ssize_t __wrap_write(int fd, const void *data, size_t length)
{
  if (fail_write) {
    if (write_calls++ == 0u) return __real_write(fd, data, length > 3u ? 3u : length);
    errno = ENOSPC;
    return -1;
  }
  return __real_write(fd, data, length);
}
static ftun_status_t after_rename(ftun_file_stage_t stage, void *user)
{
  bool *published = user;
  if ((*published) != (stage >= FTUN_FILE_STAGE_RENAMED)) return FTUN_E_STATE_CORRUPT;
  return stage == FTUN_FILE_STAGE_RENAMED ? FTUN_E_IO : FTUN_OK;
}
int main(void)
{
  char directory[] = "/tmp/ftun-platform-file.XXXXXX";
  char path[256], temporary[256], value[8] = {0};
  ftun_file_handle_t file = FTUN_FILE_INVALID;
  ftun_platform_file_lock_t lock, contender;
  ftun_string_t parent;
  uint64_t size;
  size_t written;
  bool created, published;
  struct stat info;
  int descriptor;
  CHECK(mkdtemp(directory) != NULL);
  CHECK(snprintf(path, sizeof(path), "%s/value", directory) > 0);
  CHECK(snprintf(temporary, sizeof(temporary), "%s%s", directory, FTUN_FILE_TEMPORARY_SUFFIX) > 0);
  CHECK(ftun_platform_file_parent(path, &parent) == FTUN_OK);
  CHECK(parent.length == strlen(directory) && memcmp(parent.data, directory, parent.length) == 0);
  CHECK(ftun_platform_file_parent("value", &parent) == FTUN_OK && parent.length == 1u && parent.data[0] == '.');
  CHECK(ftun_platform_file_parent("/value", &parent) == FTUN_OK && parent.length == 1u && parent.data[0] == '/');
  CHECK(ftun_platform_file_parent("value/", &parent) == FTUN_E_INVALID);
  CHECK(ftun_platform_file_open_append(path, false, &file, &size) == FTUN_OK && size == 0u);
  fail_write = true;
  CHECK(ftun_platform_file_write(&file, (ftun_bytes_t){(const uint8_t *)"abcdef", 6u}, &written) == FTUN_E_LIMIT);
  CHECK(written == 3u);
  fail_write = false;
  CHECK(ftun_platform_file_write(&file, (ftun_bytes_t){(const uint8_t *)"def", 3u}, &written) == FTUN_OK && written == 3u);
  CHECK(ftun_platform_file_close(&file) == FTUN_OK && !ftun_platform_file_is_open(&file));
  descriptor = open(path, O_RDONLY);
  CHECK(descriptor >= 0 && read(descriptor, value, 6u) == 6 && memcmp(value, "abcdef", 6u) == 0);
  CHECK(close(descriptor) == 0);
  CHECK(ftun_platform_file_lock_acquire(path, &lock) == FTUN_OK);
  CHECK(ftun_platform_file_lock_acquire(path, &contender) == FTUN_E_AGAIN);
  CHECK(ftun_platform_file_lock_release(&lock) == FTUN_OK);
  CHECK(ftun_platform_file_write_temporary(temporary,
    (ftun_bytes_t){(const uint8_t *)"new", 3u}, 0640u, &created) == FTUN_OK && created);
  CHECK(stat(temporary, &info) == 0 && (info.st_mode & 0777) == 0640);
  CHECK(ftun_platform_file_replace(temporary, path, directory, after_rename, &published, &published) == FTUN_E_IO);
  CHECK(published && access(temporary, F_OK) != 0);
  CHECK(ftun_platform_file_rename_if_exists(temporary, path) == FTUN_OK);
  CHECK(unlink(path) == 0 && rmdir(directory) == 0);
  return 0;
}
