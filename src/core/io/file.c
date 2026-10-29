#include "core/io/file.h"
#include "core/limits.h"
#include <stdlib.h>
#include <string.h>

struct ftun_file_lock {
  ftun_platform_file_lock_t native;
  ftun_reservation_t reservation;
};

static int ftun_file_path_valid(const char *path)
{
  return path != NULL && path[0] != '\0';
}

static ftun_status_t ftun_file_parent(ftun_budget_t *budget,
  const char *path, char **out, ftun_reservation_t *reservation)
{
  ftun_string_t view;
  char *parent;
  ftun_status_t status;
  if (out == NULL) return FTUN_E_INVALID;
  *out = NULL;
  status = ftun_platform_file_parent(path, &view);
  if (status != FTUN_OK) return status;
  if (budget != NULL) {
    status = ftun_budget_reserve(budget, view.length + 1u, reservation);
    if (status != FTUN_OK) return status;
  }
  parent = malloc(view.length + 1u);
  if (parent == NULL) {
    (void)ftun_reservation_release(reservation);
    return FTUN_E_LIMIT;
  }
  memcpy(parent, view.data, view.length);
  parent[view.length] = '\0';
  *out = parent;
  return FTUN_OK;
}

ftun_status_t ftun_file_lock_acquire_budget(ftun_budget_t *budget,
  const char *path, ftun_file_lock_t **out)
{
  ftun_file_lock_t *lock;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_budget_resources_t resources = {sizeof(*lock), 1u, 0u};
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (!ftun_file_path_valid(path) || out == NULL) return FTUN_E_INVALID;
  if (budget != NULL) {
    status = ftun_budget_reserve_resources(budget, resources, &reservation);
    if (status != FTUN_OK) return status;
  }
  lock = calloc(1u, sizeof(*lock));
  if (lock == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  status = ftun_platform_file_lock_acquire(path, &lock->native);
  if (status != FTUN_OK) {
    free(lock);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
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
  ftun_reservation_t reservation;
  ftun_status_t status;
  if (lock == NULL) return FTUN_E_INVALID;
  owned = *lock;
  if (owned == NULL) return FTUN_OK;
  status = ftun_platform_file_lock_release(&owned->native);
  reservation = owned->reservation;
  free(owned);
  (void)ftun_reservation_release(&reservation);
  *lock = NULL;
  return status;
}

static ftun_status_t ftun_file_replace_internal(
  ftun_budget_t *budget, const char *temporary, const char *destination,
  ftun_file_stage_hook_fn hook, void *hook_user, bool *published)
{
  char *parent = NULL;
  ftun_reservation_t parent_reservation = (ftun_reservation_t){0}, fd_reservation = (ftun_reservation_t){0};
  ftun_budget_resources_t descriptors = {0u, 2u, 0u};
  ftun_status_t status;
  *published = false;
  if (!ftun_file_path_valid(temporary) || !ftun_file_path_valid(destination) ||
      strcmp(temporary, destination) == 0) return FTUN_E_INVALID;
  status = ftun_file_parent(budget, destination, &parent, &parent_reservation);
  if (status != FTUN_OK) return status;
  if (budget != NULL) {
    status = ftun_budget_reserve_resources(budget, descriptors, &fd_reservation);
    if (status != FTUN_OK) goto done;
  }
  status = ftun_platform_file_replace(temporary, destination, parent, hook, hook_user, published);
done:
  free(parent);
  (void)ftun_reservation_release(&parent_reservation);
  (void)ftun_reservation_release(&fd_reservation);
  return status;
}

ftun_status_t ftun_file_replace(const char *temporary, const char *destination)
{
  bool published;
  return ftun_file_replace_internal(NULL, temporary, destination, NULL, NULL, &published);
}

ftun_status_t ftun_file_write_atomic_budget(ftun_budget_t *budget,
  const char *destination, ftun_bytes_t contents, unsigned int mode,
  ftun_file_stage_hook_fn hook, void *hook_user)
{
  static const char suffix[] = FTUN_FILE_TEMPORARY_SUFFIX;
  char *parent = NULL;
  char *temporary = NULL;
  size_t length;
  bool published = false;
  bool created = false;
  ftun_reservation_t parent_reservation = (ftun_reservation_t){0};
  ftun_reservation_t temporary_reservation = (ftun_reservation_t){0};
  ftun_reservation_t fd_reservation = (ftun_reservation_t){0};
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
  status = ftun_platform_file_write_temporary(temporary, contents, mode, &created);
  (void)ftun_reservation_release(&fd_reservation);
  if (status != FTUN_OK) goto done;
  status = ftun_file_replace_internal(budget, temporary, destination, hook, hook_user, &published);

done:
  if (created && !published) ftun_platform_file_remove_temporary(temporary);
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

