#define _POSIX_C_SOURCE 200809L
#include "platform/pidfile.h"
#include "platform/process.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

ftun_status_t ftun_pidfile_probe(const char *path, uint32_t *pid)
{
  int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  ftun_status_t status;
  struct stat info;
  *pid = 0u;
  if (descriptor < 0) return errno == ENOENT ? FTUN_E_EOF : FTUN_E_IO;
  if (fstat(descriptor, &info) != 0) {
    status = FTUN_E_IO;
  } else if (!S_ISREG(info.st_mode)) {
    status = FTUN_E_INVALID;
  } else if (flock(descriptor, LOCK_EX | LOCK_NB) == 0) {
    status = FTUN_E_EOF;
  } else if (errno == EWOULDBLOCK || errno == EAGAIN) {
    status = ftun_pidfile_read(descriptor, pid);
  } else {
    status = FTUN_E_IO;
  }
  if (close(descriptor) != 0) status = FTUN_E_IO;
  if (status != FTUN_OK) *pid = 0u;
  return status;
}

ftun_status_t ftun_pidfile_rewrite(ftun_pidfile_t *pidfile)
{
  char contents[32];
  size_t written;
  int length = snprintf(contents, sizeof(contents), "%u\n", ftun_process_id());
  if (ftruncate((int)pidfile->file.descriptor, 0) != 0 ||
      lseek((int)pidfile->file.descriptor, 0, SEEK_SET) < 0) return FTUN_E_IO;
  return ftun_platform_file_write(&pidfile->file,
    (ftun_bytes_t){(const uint8_t *)contents, (size_t)length}, &written);
}

ftun_status_t ftun_pidfile_acquire(const char *path, ftun_pidfile_t *out,
  uint32_t *holder)
{
  ftun_status_t status;
  struct stat info;
  *out = (ftun_pidfile_t)FTUN_PIDFILE_INVALID;
  *holder = 0u;
  status = ftun_platform_file_lock_acquire(path, &out->file);
  if (status != FTUN_OK) {
    if (status == FTUN_E_AGAIN) (void)ftun_pidfile_probe(path, holder);
    return status;
  }
  out->path = path;
  if (fstat((int)out->file.descriptor, &info) != 0) {
    (void)ftun_pidfile_discard(out);
    return FTUN_E_IO;
  }
  if (!S_ISREG(info.st_mode)) {
    (void)ftun_pidfile_discard(out);
    return FTUN_E_INVALID;
  }
  if (fchmod((int)out->file.descriptor, 0600) != 0) {
    status = FTUN_E_IO;
  } else {
    status = ftun_pidfile_rewrite(out);
  }
  if (status != FTUN_OK) (void)ftun_pidfile_release(out);
  return status;
}

ftun_status_t ftun_pidfile_discard(ftun_pidfile_t *pidfile)
{
  ftun_status_t status = FTUN_OK;
  if (ftun_platform_file_is_open(&pidfile->file)) {
    /* 不显式 LOCK_UN：fork 后其他进程可能仍持有同一个打开描述。 */
    status = ftun_platform_file_close(&pidfile->file);
  }
  pidfile->path = NULL;
  return status;
}

ftun_status_t ftun_pidfile_release(ftun_pidfile_t *pidfile)
{
  struct stat owned, current;
  ftun_status_t status = FTUN_OK;
  ftun_status_t closed;
  if (!ftun_platform_file_is_open(&pidfile->file)) return FTUN_OK;
  if (fstat((int)pidfile->file.descriptor, &owned) != 0) {
    status = FTUN_E_IO;
  } else if (lstat(pidfile->path, &current) == 0) {
    if (owned.st_dev == current.st_dev && owned.st_ino == current.st_ino &&
        unlink(pidfile->path) != 0) status = FTUN_E_IO;
  } else if (errno != ENOENT) {
    status = FTUN_E_IO;
  }
  closed = ftun_pidfile_discard(pidfile);
  return status == FTUN_OK ? closed : status;
}
