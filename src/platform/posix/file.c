#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809L
#include "platform/file.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <sys/mman.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

static ftun_status_t ftun_file_errno(int value)
{
  if (value == EAGAIN || value == EWOULDBLOCK || value == EBUSY) {
    return FTUN_E_AGAIN;
  }
  if (value == ENOSPC || value == EDQUOT || value == ENOMEM ||
      value == EMFILE || value == ENFILE) return FTUN_E_LIMIT;
  if (value == EINVAL || value == ENAMETOOLONG || value == ELOOP ||
      value == ENOTDIR || value == EISDIR) return FTUN_E_INVALID;
  return FTUN_E_IO;
}


ftun_status_t ftun_platform_file_parent(const char *path, ftun_string_t *out)
{
  const char *slash;
  if (path == NULL || path[0] == '\0' || out == NULL) return FTUN_E_INVALID;
  slash = strrchr(path, '/');
  if (slash != NULL && slash[1] == '\0') return FTUN_E_INVALID;
  if (slash == NULL) *out = (ftun_string_t){".", 1u};
  else *out = (ftun_string_t){path, slash == path ? 1u : (size_t)(slash - path)};
  return FTUN_OK;
}

ftun_status_t ftun_platform_file_lock_acquire(const char *path,
  ftun_platform_file_lock_t *out)
{
  int descriptor = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
  ftun_status_t status;
  if (descriptor < 0) return ftun_file_errno(errno);
  if (flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
    status = ftun_file_errno(errno);
    (void)close(descriptor);
    return status;
  }
  out->descriptor = descriptor;
  return FTUN_OK;
}
ftun_status_t ftun_platform_file_lock_release(ftun_platform_file_lock_t *lock)
{
  int unlock_status = flock(lock->descriptor, LOCK_UN);
  int close_status = close(lock->descriptor);
  lock->descriptor = -1;
  return unlock_status == 0 && close_status == 0 ? FTUN_OK : FTUN_E_IO;
}

ftun_status_t ftun_platform_file_replace(const char *temporary,
  const char *destination, const char *parent, ftun_file_stage_hook_fn hook,
  void *hook_user, bool *published)
{
  struct stat temporary_stat, parent_stat;
  int temporary_fd = -1, parent_fd = -1;
  ftun_status_t status;
  *published = false;
  temporary_fd = open(temporary, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (temporary_fd < 0) return ftun_file_errno(errno);
  parent_fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (parent_fd < 0) { status = ftun_file_errno(errno); goto done; }
  if (fstat(temporary_fd, &temporary_stat) != 0 || fstat(parent_fd, &parent_stat) != 0) {
    status = FTUN_E_IO;
    goto done;
  }
  if (!S_ISREG(temporary_stat.st_mode) || !S_ISDIR(parent_stat.st_mode) ||
      temporary_stat.st_dev != parent_stat.st_dev) {
    status = FTUN_E_INVALID;
    goto done;
  }
  if (fsync(temporary_fd) != 0) { status = ftun_file_errno(errno); goto done; }
  if (hook != NULL) {
    status = hook(FTUN_FILE_STAGE_TEMP_SYNCED, hook_user);
    if (status != FTUN_OK) goto done;
  }
  if (rename(temporary, destination) != 0) { status = ftun_file_errno(errno); goto done; }
  *published = true;
  if (hook != NULL) {
    status = hook(FTUN_FILE_STAGE_RENAMED, hook_user);
    if (status != FTUN_OK) goto done;
  }
  if (fsync(parent_fd) != 0) { status = ftun_file_errno(errno); goto done; }
  status = hook == NULL ? FTUN_OK : hook(FTUN_FILE_STAGE_DIRECTORY_SYNCED, hook_user);
done:
  if (close(temporary_fd) != 0 && status == FTUN_OK) status = FTUN_E_IO;
  if (parent_fd >= 0 && close(parent_fd) != 0 && status == FTUN_OK) status = FTUN_E_IO;
  return status;
}

static ftun_status_t ftun_file_write_all(int descriptor, ftun_bytes_t contents)
{
  ftun_file_handle_t file = {descriptor};
  size_t written;
  return ftun_platform_file_write(&file, contents, &written);
}


ftun_status_t ftun_platform_file_write_temporary(char *temporary,
  ftun_bytes_t contents, unsigned int mode, bool *created)
{
  ftun_status_t status;
  int descriptor;
  *created = false;
  descriptor = mkstemp(temporary);
  if (descriptor < 0) return ftun_file_errno(errno);
  *created = true;
  if (fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0 || fchmod(descriptor, (mode_t)mode) != 0) {
    status = ftun_file_errno(errno);
  } else status = ftun_file_write_all(descriptor, contents);
  if (close(descriptor) != 0 && status == FTUN_OK) status = FTUN_E_IO;
  return status;
}
void ftun_platform_file_remove_temporary(const char *temporary)
{
  /* 仅清理本次唯一临时路径；不覆盖写入或持久化阶段的主要错误。 */
  (void)unlink(temporary);
}

bool ftun_platform_file_is_open(const ftun_file_handle_t *file)
{
  return file->descriptor >= 0;
}
ftun_status_t ftun_platform_file_open_append(const char *path, bool truncate,
  ftun_file_handle_t *out, uint64_t *size)
{
  struct stat info;
  int flags = O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW;
  if (truncate) flags |= O_TRUNC;
  out->descriptor = open(path, flags, 0600);
  if (out->descriptor < 0) return FTUN_E_IO;
  *size = fstat(out->descriptor, &info) == 0 && info.st_size > 0 ? (uint64_t)info.st_size : 0u;
  return FTUN_OK;
}
ftun_status_t ftun_platform_file_close(ftun_file_handle_t *file)
{
  int result = close(file->descriptor);
  file->descriptor = -1;
  return result == 0 ? FTUN_OK : FTUN_E_IO;
}
ftun_status_t ftun_platform_file_write(ftun_file_handle_t *file,
  ftun_bytes_t contents, size_t *written)
{
  *written = 0u;
  while (*written < contents.length) {
    ssize_t count = write(file->descriptor, contents.data + *written, contents.length - *written);
    if (count < 0 && errno == EINTR) continue;
    if (count < 0) return ftun_file_errno(errno);
    if (count == 0) return FTUN_E_IO;
    *written += (size_t)count;
  }
  return FTUN_OK;
}
ftun_status_t ftun_platform_file_rename_if_exists(const char *from, const char *to)
{
  return rename(from, to) == 0 || errno == ENOENT ? FTUN_OK : FTUN_E_IO;
}

ftun_status_t ftun_platform_file_write_ready(int descriptor, ftun_bytes_t contents)
{
  struct pollfd entry = {descriptor, POLLOUT, 0};
  if (poll(&entry, 1u, 0) != 1 || (entry.revents & POLLOUT) == 0) return FTUN_E_AGAIN;
  return write(descriptor, contents.data, contents.length) == (ssize_t)contents.length
    ? FTUN_OK : FTUN_E_IO;
}

ftun_status_t ftun_file_open(const char *path, ftun_file_open_mode_t mode, int *out)
{
  int flags = O_RDONLY | O_CLOEXEC;
  if (mode != FTUN_FILE_READ) flags |= O_NOFOLLOW;
  if (mode == FTUN_FILE_READ_DIRECTORY) flags |= O_DIRECTORY;
  if (mode == FTUN_FILE_APPEND_EXISTING) flags = O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW;
  *out = open(path, flags);
  if (*out >= 0) return FTUN_OK;
  return errno == ENOENT ? FTUN_E_EOF : ftun_file_errno(errno);
}

ftun_status_t ftun_file_close(int descriptor)
{
  return close(descriptor) == 0 ? FTUN_OK : FTUN_E_IO;
}

static ftun_status_t ftun_file_describe(const struct stat *info, ftun_file_info_t *out)
{
  if (info->st_size < 0) return FTUN_E_IO;
  out->size = (uint64_t)info->st_size;
  out->regular = S_ISREG(info->st_mode);
  out->directory = S_ISDIR(info->st_mode);
  return FTUN_OK;
}

ftun_status_t ftun_file_inspect(int descriptor, ftun_file_info_t *out)
{
  struct stat info;
  if (fstat(descriptor, &info) != 0) return FTUN_E_IO;
  return ftun_file_describe(&info, out);
}

ftun_status_t ftun_file_inspect_path(const char *path, ftun_file_info_t *out)
{
  struct stat info;
  if (stat(path, &info) != 0) return errno == ENOENT ? FTUN_E_EOF : FTUN_E_IO;
  return ftun_file_describe(&info, out);
}

ptrdiff_t ftun_file_read(int descriptor, void *buffer, size_t capacity)
{
  ssize_t count;
  do {
    count = read(descriptor, buffer, capacity);
  } while (count < 0 && errno == EINTR);
  return (ptrdiff_t)count;
}

ptrdiff_t ftun_file_write_some(int descriptor, const void *buffer, size_t length,
  ftun_status_t *status)
{
  ssize_t count = write(descriptor, buffer, length);
  *status = count < 0 ? (errno == EINTR ? FTUN_E_AGAIN : ftun_file_errno(errno)) : FTUN_OK;
  return (ptrdiff_t)count;
}

ftun_status_t ftun_file_sync(int descriptor, bool data_only)
{
  int result = data_only ? fdatasync(descriptor) : fsync(descriptor);
  return result == 0 ? FTUN_OK : FTUN_E_IO;
}

ftun_status_t ftun_directory_create(const char *path, unsigned int mode)
{
  if (mkdir(path, (mode_t)mode) == 0) return FTUN_OK;
  return errno == EEXIST ? FTUN_E_INVALID : FTUN_E_IO;
}

ftun_status_t ftun_directory_ensure(const char *path, unsigned int mode)
{
  struct stat info;
  if (mkdir(path, (mode_t)mode) != 0 && errno != EEXIST) return FTUN_E_IO;
  return stat(path, &info) == 0 && S_ISDIR(info.st_mode) ? FTUN_OK : FTUN_E_IO;
}

void ftun_directory_remove(const char *path)
{
  (void)rmdir(path);
}

void *ftun_file_map_read(int descriptor, size_t length)
{
  void *mapped = mmap(NULL, length, PROT_READ, MAP_PRIVATE, descriptor, 0);
  return mapped == MAP_FAILED ? NULL : mapped;
}

ftun_status_t ftun_file_unmap(const void *address, size_t length)
{
  return munmap((void *)address, length) == 0 ? FTUN_OK : FTUN_E_IO;
}

ftun_status_t ftun_file_real_path(const char *path, char *out, size_t capacity)
{
  char resolved[PATH_MAX];
  size_t length;
  if (realpath(path, resolved) == NULL) return FTUN_E_IO;
  length = strlen(resolved);
  if (length >= capacity) return FTUN_E_LIMIT;
  memcpy(out, resolved, length + 1u);
  return FTUN_OK;
}

ftun_status_t ftun_user_home(char *storage, size_t capacity, ftun_string_t *home)
{
  struct passwd record;
  struct passwd *user = NULL;
  int error = getpwuid_r(geteuid(), &record, storage, capacity, &user);
  if (error == ERANGE) return FTUN_E_AGAIN;
  if (error != 0 || user == NULL || user->pw_dir == NULL || user->pw_dir[0] == '\0') return FTUN_E_IO;
  *home = (ftun_string_t){user->pw_dir, strlen(user->pw_dir)};
  return FTUN_OK;
}

ftun_status_t ftun_file_duplicate(int descriptor, int *out)
{
  *out = fcntl(descriptor, F_DUPFD_CLOEXEC, 0);
  return *out >= 0 ? FTUN_OK : FTUN_E_IO;
}

ftun_status_t ftun_file_wait_writable(int descriptor, uint32_t timeout_ms)
{
  struct pollfd item = {descriptor, POLLOUT, 0};
  int result = poll(&item, 1u, (int)timeout_ms);
  if (result < 0) return errno == EINTR ? FTUN_E_AGAIN : FTUN_E_IO;
  if (result == 0) return FTUN_E_AGAIN;
  return (item.revents & POLLOUT) != 0 ? FTUN_OK : FTUN_E_IO;
}

int ftun_file_standard_error(void)
{
  return STDERR_FILENO;
}
