#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "file.h"
#include "core/budget.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct ftun_file_lock {
  int descriptor;
  ftun_reservation_t *reservation;
};

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

static int ftun_file_path_valid(const char *path)
{
  return path != NULL && path[0] != '\0';
}

static ftun_status_t ftun_file_parent(ftun_budget_t *budget,
  const char *path, char **out, ftun_reservation_t **reservation)
{
  const char *slash;
  size_t length;
  char *parent;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (!ftun_file_path_valid(path) || out == NULL) return FTUN_E_INVALID;
  slash = strrchr(path, '/');
  if (slash != NULL && slash[1] == '\0') return FTUN_E_INVALID;
  length = slash == NULL || slash == path ? 1u : (size_t)(slash - path);
  if (budget != NULL) {
    status = ftun_budget_reserve(budget, length + 1u, reservation);
    if (status != FTUN_OK) return status;
  }
  parent = (char *)malloc(length + 1u);
  if (parent == NULL) {
    (void)ftun_reservation_release(reservation);
    return FTUN_E_LIMIT;
  }
  if (slash == NULL) {
    memcpy(parent, ".", 2u);
  } else {
    memcpy(parent, path, length);
    parent[length] = '\0';
  }
  *out = parent;
  return FTUN_OK;
}

ftun_status_t ftun_file_lock_acquire_budget(ftun_budget_t *budget,
  const char *path, ftun_file_lock_t **out)
{
  ftun_file_lock_t *lock;
  ftun_reservation_t *reservation = NULL;
  ftun_budget_resources_t resources = {sizeof(*lock), 1u, 0u};
  ftun_status_t status;
  int descriptor;
  if (out != NULL) *out = NULL;
  if (!ftun_file_path_valid(path) || out == NULL) return FTUN_E_INVALID;
  if (budget != NULL) {
    status = ftun_budget_reserve_resources(budget, resources, &reservation);
    if (status != FTUN_OK) return status;
  }
  descriptor = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (descriptor < 0) {
    status = ftun_file_errno(errno);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  if (flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
    ftun_status_t status = ftun_file_errno(errno);
    (void)close(descriptor);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  lock = (ftun_file_lock_t *)calloc(1u, sizeof(*lock));
  if (lock == NULL) {
    (void)flock(descriptor, LOCK_UN);
    (void)close(descriptor);
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  lock->descriptor = descriptor;
  lock->reservation = reservation;
  *out = lock;
  return FTUN_OK;
}

ftun_status_t ftun_file_lock_acquire(const char *path, ftun_file_lock_t **out)
{
  return ftun_file_lock_acquire_budget(NULL, path, out);
}

ftun_status_t ftun_file_lock_release(ftun_file_lock_t **lock)
{
  ftun_file_lock_t *owned;
  ftun_reservation_t *reservation;
  int unlock_status;
  int close_status;
  if (lock == NULL) return FTUN_E_INVALID;
  owned = *lock;
  if (owned == NULL) return FTUN_OK;
  unlock_status = flock(owned->descriptor, LOCK_UN);
  close_status = close(owned->descriptor);
  reservation = owned->reservation;
  free(owned);
  (void)ftun_reservation_release(&reservation);
  *lock = NULL;
  return unlock_status == 0 && close_status == 0 ? FTUN_OK : FTUN_E_IO;
}

static ftun_status_t ftun_file_replace_internal(
  ftun_budget_t *budget, const char *temporary, const char *destination,
  ftun_file_stage_hook_fn hook, void *hook_user)
{
  char *parent = NULL;
  struct stat temporary_stat;
  struct stat parent_stat;
  int temporary_fd = -1;
  int parent_fd = -1;
  ftun_reservation_t *parent_reservation = NULL;
  ftun_reservation_t *fd_reservation = NULL;
  ftun_budget_resources_t descriptors = {0u, 2u, 0u};
  ftun_status_t status;
  if (!ftun_file_path_valid(temporary) ||
      !ftun_file_path_valid(destination) ||
      strcmp(temporary, destination) == 0) return FTUN_E_INVALID;
  status = ftun_file_parent(budget, destination, &parent, &parent_reservation);
  if (status != FTUN_OK) return status;
  if (budget != NULL) {
    status = ftun_budget_reserve_resources(budget, descriptors, &fd_reservation);
    if (status != FTUN_OK) goto done;
  }
  temporary_fd = open(temporary, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (temporary_fd < 0) {
    status = ftun_file_errno(errno);
    goto done;
  }
  parent_fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (parent_fd < 0) {
    status = ftun_file_errno(errno);
    goto done;
  }
  if (fstat(temporary_fd, &temporary_stat) != 0 ||
      fstat(parent_fd, &parent_stat) != 0) {
    status = FTUN_E_IO;
    goto done;
  }
  if (!S_ISREG(temporary_stat.st_mode) ||
      !S_ISDIR(parent_stat.st_mode)) {
    status = FTUN_E_INVALID;
    goto done;
  }
  if (temporary_stat.st_dev != parent_stat.st_dev) {
    status = FTUN_E_INVALID;
    goto done;
  }
  if (fsync(temporary_fd) != 0) {
    status = ftun_file_errno(errno);
    goto done;
  }
  if (hook != NULL) {
    status = hook(FTUN_FILE_STAGE_TEMP_SYNCED, hook_user);
    if (status != FTUN_OK) goto done;
  }
  if (rename(temporary, destination) != 0) {
    status = ftun_file_errno(errno);
    goto done;
  }
  if (hook != NULL) {
    status = hook(FTUN_FILE_STAGE_RENAMED, hook_user);
    if (status != FTUN_OK) goto done;
  }
  if (fsync(parent_fd) != 0) {
    status = ftun_file_errno(errno);
    goto done;
  }
  status = hook == NULL ? FTUN_OK :
    hook(FTUN_FILE_STAGE_DIRECTORY_SYNCED, hook_user);

done:
  if (temporary_fd >= 0 && close(temporary_fd) != 0 && status == FTUN_OK) {
    status = FTUN_E_IO;
  }
  if (parent_fd >= 0 && close(parent_fd) != 0 && status == FTUN_OK) {
    status = FTUN_E_IO;
  }
  free(parent);
  (void)ftun_reservation_release(&parent_reservation);
  (void)ftun_reservation_release(&fd_reservation);
  return status;
}

ftun_status_t ftun_file_replace(const char *temporary,
                                const char *destination)
{
  return ftun_file_replace_internal(NULL, temporary, destination, NULL, NULL);
}

static ftun_status_t ftun_file_write_all(int descriptor, ftun_bytes_t contents)
{
  size_t offset = 0u;
  while (offset < contents.length) {
    ssize_t result = write(descriptor, contents.data + offset,
                           contents.length - offset);
    if (result < 0 && errno == EINTR) continue;
    if (result < 0) return ftun_file_errno(errno);
    if (result == 0) return FTUN_E_IO;
    offset += (size_t)result;
  }
  return FTUN_OK;
}

ftun_status_t ftun_file_write_atomic_budget(ftun_budget_t *budget,
  const char *destination, ftun_bytes_t contents, unsigned int mode,
  ftun_file_stage_hook_fn hook, void *hook_user)
{
  static const char suffix[] = "/.ftun.tmp.XXXXXX";
  char *parent = NULL;
  char *temporary = NULL;
  size_t length;
  int descriptor = -1;
  int published = 0;
  int created = 0;
  ftun_reservation_t *parent_reservation = NULL;
  ftun_reservation_t *temporary_reservation = NULL;
  ftun_reservation_t *fd_reservation = NULL;
  ftun_budget_resources_t descriptors = {0u, 1u, 0u};
  ftun_status_t status;
  if (!ftun_file_path_valid(destination) ||
      (contents.length != 0u && contents.data == NULL) ||
      (mode & ~0777u) != 0u) return FTUN_E_INVALID;
  status = ftun_file_parent(budget, destination, &parent, &parent_reservation);
  if (status != FTUN_OK) return status;
  length = strlen(parent);
  if (length > SIZE_MAX - sizeof(suffix)) {
    status = FTUN_E_LIMIT;
    goto done;
  }
  if (budget != NULL) {
    status = ftun_budget_reserve(budget, length + sizeof(suffix), &temporary_reservation);
    if (status != FTUN_OK) goto done;
  }
  temporary = (char *)malloc(length + sizeof(suffix));
  if (temporary == NULL) {
    status = FTUN_E_LIMIT;
    goto done;
  }
  memcpy(temporary, parent, length);
  memcpy(temporary + length, suffix, sizeof(suffix));
  if (budget != NULL) {
    status = ftun_budget_reserve_resources(budget, descriptors, &fd_reservation);
    if (status != FTUN_OK) goto done;
  }
  descriptor = mkstemp(temporary);
  if (descriptor < 0) {
    status = ftun_file_errno(errno);
    goto done;
  }
  created = 1;
  if (fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0 ||
      fchmod(descriptor, (mode_t)mode) != 0) {
    status = ftun_file_errno(errno);
    goto done;
  }
  status = ftun_file_write_all(descriptor, contents);
  if (status != FTUN_OK) goto done;
  if (close(descriptor) != 0) {
    descriptor = -1;
    status = FTUN_E_IO;
    goto done;
  }
  descriptor = -1;
  (void)ftun_reservation_release(&fd_reservation);
  status = ftun_file_replace_internal(budget, temporary, destination, hook, hook_user);
  published = access(temporary, F_OK) != 0 && errno == ENOENT;

done:
  if (descriptor >= 0 && close(descriptor) != 0 && status == FTUN_OK) {
    status = FTUN_E_IO;
  }
  if (created && !published) (void)unlink(temporary);
  free(temporary);
  free(parent);
  (void)ftun_reservation_release(&temporary_reservation);
  (void)ftun_reservation_release(&parent_reservation);
  (void)ftun_reservation_release(&fd_reservation);
  return status;
}

ftun_status_t ftun_file_write_atomic(const char *destination,
                                     ftun_bytes_t contents,
                                     unsigned int mode)
{
  return ftun_file_write_atomic_with_hook(destination, contents, mode,
                                           NULL, NULL);
}

ftun_status_t ftun_file_write_atomic_with_hook(
  const char *destination, ftun_bytes_t contents, unsigned int mode,
  ftun_file_stage_hook_fn hook, void *hook_user)
{
  return ftun_file_write_atomic_budget(NULL, destination, contents, mode,
    hook, hook_user);
}
