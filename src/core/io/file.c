#include "core/io/file.h"
#include "core/limits.h"
#include "platform/atomic.h"
#include "platform/thread.h"
#include <stdlib.h>
#include <string.h>

struct ftun_file_lock {
  ftun_platform_file_lock_t native;
  ftun_reservation_t reservation;
  ftun_file_lock_pool_t *pool;
  ftun_file_lock_t *next;
  ftun_atomic_size_t references;
  bool ready;
  char path[];
};

struct ftun_file_lock_pool {
  ftun_mutex_t mutex;
  ftun_budget_t *budget;
  ftun_reservation_t reservation;
  ftun_file_lock_t *locks;
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
    ftun_reservation_release(reservation);
    return FTUN_E_LIMIT;
  }
  memcpy(parent, view.data, view.length);
  parent[view.length] = '\0';
  *out = parent;
  return FTUN_OK;
}

static ftun_status_t ftun_file_lock_allocate(ftun_budget_t *budget,
  const char *path, ftun_file_lock_t **out)
{
  ftun_file_lock_t *lock;
  size_t length = strlen(path) + 1u;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_budget_resources_t resources = {sizeof(*lock) + length, 1u, 0u};
  ftun_status_t status;
  if (budget != NULL) {
    status = ftun_budget_reserve_resources(budget, resources, &reservation);
    if (status != FTUN_OK) return status;
  }
  lock = calloc(1u, sizeof(*lock) + length);
  if (lock == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  lock->reservation = reservation;
  lock->native = (ftun_platform_file_lock_t)FTUN_FILE_INVALID;
  memcpy(lock->path, path, length);
  ftun_atomic_init(&lock->references, 1u);
  *out = lock;
  return FTUN_OK;
}

ftun_status_t ftun_file_lock_acquire_budget(ftun_budget_t *budget,
  const char *path, ftun_file_lock_t **out)
{
  ftun_file_lock_t *lock;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (!ftun_file_path_valid(path) || out == NULL) return FTUN_E_INVALID;
  status = ftun_file_lock_allocate(budget, path, &lock);
  if (status != FTUN_OK) return status;
  status = ftun_platform_file_lock_acquire(path, &lock->native);
  if (status != FTUN_OK) {
    ftun_reservation_t reservation = lock->reservation;
    free(lock);
    ftun_reservation_release(&reservation);
    return status;
  }
  lock->ready = true;
  *out = lock;
  return FTUN_OK;
}

ftun_status_t ftun_file_lock_acquire(const char *path, ftun_file_lock_t **out)
{
  return ftun_file_lock_acquire_budget(NULL, path, out);
}

ftun_status_t ftun_file_lock_pool_create(ftun_budget_t *budget,
  ftun_file_lock_pool_t **out)
{
  ftun_file_lock_pool_t *pool;
  ftun_reservation_t reservation = {0};
  ftun_status_t status;
  *out = NULL;
  status = ftun_budget_reserve(budget, sizeof(*pool), &reservation);
  if (status != FTUN_OK) return status;
  pool = calloc(1u, sizeof(*pool));
  if (pool == NULL) { ftun_reservation_release(&reservation); return FTUN_E_LIMIT; }
  if (ftun_mutex_init(&pool->mutex) != FTUN_OK) {
    free(pool);
    ftun_reservation_release(&reservation);
    return FTUN_E_IO;
  }
  pool->budget = budget;
  pool->reservation = reservation;
  *out = pool;
  return FTUN_OK;
}

static void ftun_file_lock_pool_remove(ftun_file_lock_pool_t *pool,
  ftun_file_lock_t *lock)
{
  ftun_file_lock_t **link;
  ftun_mutex_lock(&pool->mutex);
  for (link = &pool->locks; *link != lock; link = &(*link)->next) {}
  *link = lock->next;
  ftun_mutex_unlock(&pool->mutex);
}

ftun_status_t ftun_file_lock_pool_acquire(ftun_file_lock_pool_t *pool,
  const char *path, ftun_file_lock_t **out)
{
  ftun_file_lock_t *lock;
  ftun_status_t status;
  *out = NULL;
  if (!ftun_file_path_valid(path)) return FTUN_E_INVALID;
  ftun_mutex_lock(&pool->mutex);
  for (lock = pool->locks; lock != NULL; lock = lock->next) {
    if (strcmp(lock->path, path) != 0) continue;
    if (lock->ready) {
      (void)ftun_atomic_fetch_add(&lock->references, 1u);
      *out = lock;
    }
    ftun_mutex_unlock(&pool->mutex);
    return *out == NULL ? FTUN_E_AGAIN : FTUN_OK;
  }
  status = ftun_file_lock_allocate(pool->budget, path, &lock);
  if (status == FTUN_OK) {
    lock->pool = pool;
    lock->next = pool->locks;
    pool->locks = lock;
  }
  ftun_mutex_unlock(&pool->mutex);
  if (status != FTUN_OK) return status;
  status = ftun_platform_file_lock_acquire(path, &lock->native);
  if (status != FTUN_OK) {
    ftun_reservation_t reservation = lock->reservation;
    ftun_file_lock_pool_remove(pool, lock);
    free(lock);
    ftun_reservation_release(&reservation);
    return status;
  }
  ftun_mutex_lock(&pool->mutex);
  lock->ready = true;
  ftun_mutex_unlock(&pool->mutex);
  *out = lock;
  return FTUN_OK;
}

void ftun_file_lock_retain(ftun_file_lock_t *lock)
{
  if (lock->pool != NULL) ftun_mutex_lock(&lock->pool->mutex);
  (void)ftun_atomic_fetch_add(&lock->references, 1u);
  if (lock->pool != NULL) ftun_mutex_unlock(&lock->pool->mutex);
}

ftun_status_t ftun_file_lock_pool_destroy(ftun_file_lock_pool_t **pool)
{
  ftun_file_lock_pool_t *owned = *pool;
  ftun_reservation_t reservation;
  if (owned == NULL) return FTUN_OK;
  ftun_mutex_lock(&owned->mutex);
  if (owned->locks != NULL) {
    ftun_mutex_unlock(&owned->mutex);
    return FTUN_E_AGAIN;
  }
  ftun_mutex_unlock(&owned->mutex);
  ftun_mutex_destroy(&owned->mutex);
  reservation = owned->reservation;
  free(owned);
  *pool = NULL;
  ftun_reservation_release(&reservation);
  return FTUN_OK;
}

ftun_status_t ftun_file_lock_release(ftun_file_lock_t **lock)
{
  ftun_file_lock_t *owned;
  ftun_reservation_t reservation;
  ftun_status_t status;
  bool last;
  if (lock == NULL) return FTUN_E_INVALID;
  owned = *lock;
  if (owned == NULL) return FTUN_OK;
  if (owned->pool != NULL) ftun_mutex_lock(&owned->pool->mutex);
  last = ftun_atomic_fetch_sub_explicit(&owned->references, 1u, FTUN_MEMORY_ACQ_REL) == 1u;
  if (last) owned->ready = false;
  if (owned->pool != NULL) ftun_mutex_unlock(&owned->pool->mutex);
  *lock = NULL;
  if (!last) return FTUN_OK;
  status = ftun_platform_file_lock_release(&owned->native);
  if (owned->pool != NULL) ftun_file_lock_pool_remove(owned->pool, owned);
  reservation = owned->reservation;
  free(owned);
  ftun_reservation_release(&reservation);
  return status;
}

static ftun_status_t ftun_file_replace_internal(
  ftun_budget_t *budget, const char *temporary, const char *destination,
  ftun_file_stage_hook_fn hook, void *hook_user, bool replace_existing, bool *published)
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
  status = ftun_platform_file_replace(temporary, destination, parent, hook, hook_user, replace_existing, published);
done:
  free(parent);
  ftun_reservation_release(&parent_reservation);
  ftun_reservation_release(&fd_reservation);
  return status;
}

ftun_status_t ftun_file_replace(const char *temporary, const char *destination)
{
  bool published;
  return ftun_file_replace_internal(NULL, temporary, destination, NULL, NULL, true, &published);
}

static ftun_status_t ftun_file_write_atomic_internal(ftun_budget_t *budget,
  const char *destination, ftun_bytes_t contents, unsigned int mode,
  ftun_file_stage_hook_fn hook, void *hook_user, bool replace_existing)
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
  ftun_reservation_release(&fd_reservation);
  if (status != FTUN_OK) goto done;
  status = ftun_file_replace_internal(budget, temporary, destination, hook, hook_user, replace_existing, &published);

done:
  if (created && !published) ftun_platform_file_remove_temporary(temporary);
  free(temporary);
  free(parent);
  ftun_reservation_release(&temporary_reservation);
  ftun_reservation_release(&parent_reservation);
  ftun_reservation_release(&fd_reservation);
  return status;
}

ftun_status_t ftun_file_write_atomic_budget(ftun_budget_t *budget,
  const char *destination, ftun_bytes_t contents, unsigned int mode,
  ftun_file_stage_hook_fn hook, void *hook_user)
{
  return ftun_file_write_atomic_internal(budget, destination, contents, mode,
    hook, hook_user, true);
}

ftun_status_t ftun_file_create_atomic_budget(ftun_budget_t *budget,
  const char *destination, ftun_bytes_t contents, unsigned int mode)
{
  return ftun_file_write_atomic_internal(budget, destination, contents, mode,
    NULL, NULL, false);
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

