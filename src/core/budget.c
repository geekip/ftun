#include "budget.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

enum {
  FTUN_BUDGET_MEMORY = 0,
  FTUN_BUDGET_DESCRIPTORS,
  FTUN_BUDGET_QUEUE_SLOTS,
  FTUN_BUDGET_RESOURCE_COUNT
};

struct ftun_budget {
  ftun_budget_t *parent;
  struct ftun_budget_root *root;
  size_t limit[FTUN_BUDGET_RESOURCE_COUNT];
  size_t cleanup_reserve[FTUN_BUDGET_RESOURCE_COUNT];
  size_t guarantee[FTUN_BUDGET_RESOURCE_COUNT];
  size_t used[FTUN_BUDGET_RESOURCE_COUNT];
  size_t child_guarantees[FTUN_BUDGET_RESOURCE_COUNT];
  size_t child_guaranteed_used[FTUN_BUDGET_RESOURCE_COUNT];
  size_t high_watermark[FTUN_BUDGET_RESOURCE_COUNT];
  size_t child_count;
  size_t rejected_reservations;
  size_t metadata_bytes;
};

/* 只在根对象中分配同步状态；所有祖先计数由同一把锁保护。 */
struct ftun_budget_root {
  ftun_budget_t budget;
  pthread_mutex_t mutex;
};

struct ftun_reservation {
  ftun_budget_t *budget;
  size_t resources[FTUN_BUDGET_RESOURCE_COUNT];
  int cleanup;
};

/* ftun_budget_reserve; typed reservations preserve the original entry point. */

static void ftun_budget_unpack(ftun_budget_resources_t resources,
                               size_t values[FTUN_BUDGET_RESOURCE_COUNT])
{
  values[FTUN_BUDGET_MEMORY] = resources.memory_bytes;
  values[FTUN_BUDGET_DESCRIPTORS] = resources.descriptors;
  values[FTUN_BUDGET_QUEUE_SLOTS] = resources.queue_slots;
}

static ftun_budget_resources_t ftun_budget_pack(
  const size_t values[FTUN_BUDGET_RESOURCE_COUNT])
{
  ftun_budget_resources_t resources;
  resources.memory_bytes = values[FTUN_BUDGET_MEMORY];
  resources.descriptors = values[FTUN_BUDGET_DESCRIPTORS];
  resources.queue_slots = values[FTUN_BUDGET_QUEUE_SLOTS];
  return resources;
}

static size_t ftun_budget_covered(size_t used, size_t guarantee)
{
  return used < guarantee ? used : guarantee;
}

static int ftun_budget_values_zero(
  const size_t values[FTUN_BUDGET_RESOURCE_COUNT])
{
  size_t index;
  for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) {
    if (values[index] != 0u) return 0;
  }
  return 1;
}

/* 元数据独立于调用方申请的资源额度，记录本子树的实际结构分配。 */
static int ftun_budget_metadata_fits(ftun_budget_t *budget, size_t bytes)
{
  for (; budget != NULL; budget = budget->parent) {
    if (budget->metadata_bytes > SIZE_MAX - bytes) return 0;
  }
  return 1;
}

static void ftun_budget_metadata_add(ftun_budget_t *budget, size_t bytes)
{
  for (; budget != NULL; budget = budget->parent) budget->metadata_bytes += bytes;
}

static int ftun_budget_metadata_can_subtract(ftun_budget_t *budget, size_t bytes)
{
  for (; budget != NULL; budget = budget->parent) {
    if (budget->metadata_bytes < bytes) return 0;
  }
  return 1;
}

static void ftun_budget_metadata_subtract(ftun_budget_t *budget, size_t bytes)
{
  for (; budget != NULL; budget = budget->parent) budget->metadata_bytes -= bytes;
}

static void ftun_budget_rejected(ftun_budget_t *budget)
{
  if (budget->rejected_reservations != SIZE_MAX) budget->rejected_reservations++;
}

/* Check every level before changing a counter.  At an ancestor, path_child
 * names the direct child whose guarantee this request may consume. */
static int ftun_budget_fits(ftun_budget_t *leaf,
                            const size_t requested[FTUN_BUDGET_RESOURCE_COUNT],
                            int cleanup)
{
  ftun_budget_t *budget;
  ftun_budget_t *path_child = NULL;
  size_t index;
  for (budget = leaf; budget != NULL;
       path_child = budget, budget = budget->parent) {
    for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) {
      size_t ceiling;
      size_t protected_unused = 0u;
      size_t path_unused = 0u;
      size_t available;
      /* 未申请的维度不消耗其normal额度；其他维度的cleanup占用不能阻塞它。 */
      if (requested[index] == 0u) continue;
      if (budget->used[index] > budget->limit[index] ||
          budget->cleanup_reserve[index] > budget->limit[index]) return 0;
      ceiling = cleanup ? budget->limit[index]
        : budget->limit[index] - budget->cleanup_reserve[index];
      if (!cleanup) {
        if (budget->child_guaranteed_used[index] >
            budget->child_guarantees[index]) return 0;
        protected_unused = budget->child_guarantees[index] -
          budget->child_guaranteed_used[index];
        if (path_child != NULL) {
          size_t covered = ftun_budget_covered(path_child->used[index],
                                                path_child->guarantee[index]);
          path_unused = path_child->guarantee[index] - covered;
          if (path_unused > protected_unused) return 0;
          protected_unused -= path_unused;
        }
      }
      if (budget->used[index] > ceiling ||
          protected_unused > ceiling - budget->used[index]) return 0;
      available = ceiling - budget->used[index] - protected_unused;
      if (requested[index] > available) return 0;
    }
  }
  return 1;
}

static void ftun_budget_add(ftun_budget_t *leaf,
                            const size_t resources[FTUN_BUDGET_RESOURCE_COUNT])
{
  ftun_budget_t *budget;
  size_t index;
  for (budget = leaf; budget != NULL; budget = budget->parent) {
    for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) {
      size_t before = ftun_budget_covered(budget->used[index],
                                          budget->guarantee[index]);
      budget->used[index] += resources[index];
      if (budget->used[index] > budget->high_watermark[index]) {
        budget->high_watermark[index] = budget->used[index];
      }
      if (budget->parent != NULL) {
        size_t after = ftun_budget_covered(budget->used[index],
                                           budget->guarantee[index]);
        budget->parent->child_guaranteed_used[index] += after - before;
      }
    }
  }
}

static int ftun_budget_can_subtract(
  ftun_budget_t *leaf,
  const size_t resources[FTUN_BUDGET_RESOURCE_COUNT])
{
  ftun_budget_t *budget;
  size_t index;
  for (budget = leaf; budget != NULL; budget = budget->parent) {
    for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) {
      size_t before;
      size_t after;
      if (budget->used[index] < resources[index]) return 0;
      if (budget->parent == NULL) continue;
      before = ftun_budget_covered(budget->used[index],
                                   budget->guarantee[index]);
      after = ftun_budget_covered(budget->used[index] - resources[index],
                                  budget->guarantee[index]);
      if (budget->parent->child_guaranteed_used[index] < before - after) {
        return 0;
      }
    }
  }
  return 1;
}

static void ftun_budget_subtract(
  ftun_budget_t *leaf,
  const size_t resources[FTUN_BUDGET_RESOURCE_COUNT])
{
  ftun_budget_t *budget;
  size_t index;
  for (budget = leaf; budget != NULL; budget = budget->parent) {
    for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) {
      size_t before = ftun_budget_covered(budget->used[index],
                                          budget->guarantee[index]);
      budget->used[index] -= resources[index];
      if (budget->parent != NULL) {
        size_t after = ftun_budget_covered(budget->used[index],
                                           budget->guarantee[index]);
        budget->parent->child_guaranteed_used[index] -= before - after;
      }
    }
  }
}

ftun_status_t ftun_budget_create_resources(
  ftun_budget_t *parent, const ftun_budget_options_t *options,
  ftun_budget_t **out)
{
  ftun_budget_t *budget;
  ftun_status_t status = FTUN_OK;
  size_t limit[FTUN_BUDGET_RESOURCE_COUNT];
  size_t cleanup[FTUN_BUDGET_RESOURCE_COUNT];
  size_t guarantee[FTUN_BUDGET_RESOURCE_COUNT];
  size_t allocation = parent == NULL ? sizeof(struct ftun_budget_root)
                                    : sizeof(*budget);
  size_t index;
  if (out != NULL) *out = NULL;
  if (options == NULL || out == NULL) return FTUN_E_INVALID;
  ftun_budget_unpack(options->limit, limit);
  ftun_budget_unpack(options->cleanup_reserve, cleanup);
  ftun_budget_unpack(options->guarantee, guarantee);
  if (parent == NULL && !ftun_budget_values_zero(guarantee)) {
    return FTUN_E_INVALID;
  }
  for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) {
    if (cleanup[index] > limit[index] ||
        guarantee[index] > limit[index] - cleanup[index] ||
        (parent != NULL && parent->parent != NULL && guarantee[index] != 0u)) {
      return FTUN_E_INVALID;
    }
  }
  budget = (ftun_budget_t *)calloc(1u, allocation);
  if (budget == NULL) return FTUN_E_LIMIT;
  budget->parent = parent;
  memcpy(budget->limit, limit, sizeof(limit));
  memcpy(budget->cleanup_reserve, cleanup, sizeof(cleanup));
  memcpy(budget->guarantee, guarantee, sizeof(guarantee));
  if (parent == NULL) {
    budget->root = (struct ftun_budget_root *)budget;
    if (pthread_mutex_init(&budget->root->mutex, NULL) != 0) {
      free(budget);
      return FTUN_E_IO;
    }
    budget->metadata_bytes = allocation;
    *out = budget;
    return FTUN_OK;
  }
  budget->root = parent->root;
  (void)pthread_mutex_lock(&budget->root->mutex);
  if (parent->child_count == SIZE_MAX ||
      !ftun_budget_metadata_fits(parent, allocation)) {
    status = FTUN_E_LIMIT;
    goto done;
  }
  for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) {
    size_t parent_ceiling;
    size_t protected_unused;
    if (parent->cleanup_reserve[index] > parent->limit[index] ||
        parent->child_guaranteed_used[index] > parent->child_guarantees[index]) {
      status = FTUN_E_STATE_CORRUPT;
      goto done;
    }
    if (parent->child_guarantees[index] > SIZE_MAX - guarantee[index]) {
      status = FTUN_E_LIMIT;
      goto done;
    }
    parent_ceiling = parent->limit[index] - parent->cleanup_reserve[index];
    protected_unused = parent->child_guarantees[index] -
      parent->child_guaranteed_used[index];
    if (parent->used[index] > parent_ceiling ||
        protected_unused > parent_ceiling - parent->used[index] ||
        guarantee[index] > parent_ceiling - parent->used[index] -
          protected_unused) {
      status = FTUN_E_LIMIT;
      goto done;
    }
  }
  parent->child_count++;
  for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) {
    parent->child_guarantees[index] += guarantee[index];
  }
  ftun_budget_metadata_add(budget, allocation);
  *out = budget;
done:
  (void)pthread_mutex_unlock(&budget->root->mutex);
  if (status != FTUN_OK) free(budget);
  return status;
}

ftun_status_t ftun_budget_create(ftun_budget_t *parent, size_t limit,
                                 size_t cleanup_reserve, ftun_budget_t **out)
{
  ftun_budget_options_t options;
  memset(&options, 0, sizeof(options));
  options.limit.memory_bytes = limit;
  options.limit.descriptors = SIZE_MAX;
  options.limit.queue_slots = SIZE_MAX;
  options.cleanup_reserve.memory_bytes = cleanup_reserve;
  return ftun_budget_create_resources(parent, &options, out);
}

static ftun_status_t ftun_budget_reserve_kind(
  ftun_budget_t *budget, ftun_budget_resources_t resources, int cleanup,
  ftun_reservation_t **out)
{
  ftun_reservation_t *reservation;
  size_t requested[FTUN_BUDGET_RESOURCE_COUNT];
  ftun_status_t status = FTUN_OK;
  if (out != NULL) *out = NULL;
  ftun_budget_unpack(resources, requested);
  if (budget == NULL || out == NULL || ftun_budget_values_zero(requested)) {
    return FTUN_E_INVALID;
  }
  /* 分配不持根锁；准入和全祖先记账在随后同一个临界区完成。 */
  reservation = (ftun_reservation_t *)malloc(sizeof(*reservation));
  (void)pthread_mutex_lock(&budget->root->mutex);
  if (reservation == NULL ||
      !ftun_budget_metadata_fits(budget, sizeof(*reservation)) ||
      !ftun_budget_fits(budget, requested, cleanup)) {
    ftun_budget_rejected(budget);
    status = FTUN_E_LIMIT;
  } else {
    reservation->budget = budget;
    reservation->cleanup = cleanup;
    memcpy(reservation->resources, requested, sizeof(requested));
    ftun_budget_add(budget, requested);
    ftun_budget_metadata_add(budget, sizeof(*reservation));
    *out = reservation;
  }
  (void)pthread_mutex_unlock(&budget->root->mutex);
  if (status != FTUN_OK) free(reservation);
  return status;
}

ftun_status_t ftun_budget_reserve_resources(
  ftun_budget_t *budget, ftun_budget_resources_t resources,
  ftun_reservation_t **out)
{
  return ftun_budget_reserve_kind(budget, resources, 0, out);
}

ftun_status_t ftun_budget_reserve_cleanup_resources(
  ftun_budget_t *budget, ftun_budget_resources_t resources,
  ftun_reservation_t **out)
{
  return ftun_budget_reserve_kind(budget, resources, 1, out);
}

ftun_status_t ftun_budget_reserve(ftun_budget_t *budget, size_t bytes,
                                  ftun_reservation_t **out)
{
  ftun_budget_resources_t resources = {bytes, 0u, 0u};
  return ftun_budget_reserve_resources(budget, resources, out);
}

ftun_status_t ftun_budget_reserve_cleanup(ftun_budget_t *budget, size_t bytes,
                                          ftun_reservation_t **out)
{
  ftun_budget_resources_t resources = {bytes, 0u, 0u};
  return ftun_budget_reserve_cleanup_resources(budget, resources, out);
}

static ftun_status_t ftun_budget_get_usage_locked(const ftun_budget_t *budget,
                                                  ftun_budget_usage_t *out)
{
  size_t normal[FTUN_BUDGET_RESOURCE_COUNT];
  size_t total[FTUN_BUDGET_RESOURCE_COUNT];
  size_t borrowed[FTUN_BUDGET_RESOURCE_COUNT];
  size_t index;
  for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) {
    const ftun_budget_t *ancestor;
    const ftun_budget_t *path_child;
    size_t ceiling;
    size_t protected_unused;
    if (budget->used[index] > budget->limit[index] ||
        budget->cleanup_reserve[index] > budget->limit[index] ||
        budget->child_guaranteed_used[index] >
          budget->child_guarantees[index]) return FTUN_E_STATE_CORRUPT;
    ceiling = budget->limit[index] - budget->cleanup_reserve[index];
    protected_unused = budget->child_guarantees[index] -
      budget->child_guaranteed_used[index];
    normal[index] = budget->used[index] < ceiling &&
      protected_unused <= ceiling - budget->used[index]
      ? ceiling - budget->used[index] - protected_unused : 0u;
    total[index] = budget->limit[index] - budget->used[index];
    path_child = budget;
    for (ancestor = budget->parent; ancestor != NULL;
         path_child = ancestor, ancestor = ancestor->parent) {
      size_t ancestor_ceiling;
      size_t ancestor_protected;
      size_t path_covered;
      size_t path_unused;
      size_t ancestor_normal;
      size_t ancestor_total;
      if (ancestor->used[index] > ancestor->limit[index] ||
          ancestor->cleanup_reserve[index] > ancestor->limit[index] ||
          ancestor->child_guaranteed_used[index] >
            ancestor->child_guarantees[index]) {
        return FTUN_E_STATE_CORRUPT;
      }
      ancestor_ceiling = ancestor->limit[index] -
        ancestor->cleanup_reserve[index];
      ancestor_protected = ancestor->child_guarantees[index] -
        ancestor->child_guaranteed_used[index];
      path_covered = ftun_budget_covered(path_child->used[index],
                                          path_child->guarantee[index]);
      path_unused = path_child->guarantee[index] - path_covered;
      if (path_unused > ancestor_protected) return FTUN_E_STATE_CORRUPT;
      ancestor_protected -= path_unused;
      ancestor_normal = ancestor->used[index] < ancestor_ceiling &&
        ancestor_protected <= ancestor_ceiling - ancestor->used[index]
        ? ancestor_ceiling - ancestor->used[index] - ancestor_protected : 0u;
      ancestor_total = ancestor->limit[index] - ancestor->used[index];
      if (normal[index] > ancestor_normal) normal[index] = ancestor_normal;
      if (total[index] > ancestor_total) total[index] = ancestor_total;
    }
    borrowed[index] = budget->used[index] > budget->guarantee[index]
      ? budget->used[index] - budget->guarantee[index] : 0u;
  }
  out->limits = ftun_budget_pack(budget->limit);
  out->cleanup_reserves = ftun_budget_pack(budget->cleanup_reserve);
  out->guarantees = ftun_budget_pack(budget->guarantee);
  out->used_resources = ftun_budget_pack(budget->used);
  out->normal_available_resources = ftun_budget_pack(normal);
  out->total_available_resources = ftun_budget_pack(total);
  out->borrowed_resources = ftun_budget_pack(borrowed);
  out->high_watermarks = ftun_budget_pack(budget->high_watermark);
  out->limit = out->limits.memory_bytes;
  out->cleanup_reserve = out->cleanup_reserves.memory_bytes;
  out->used = out->used_resources.memory_bytes;
  out->normal_available = out->normal_available_resources.memory_bytes;
  out->total_available = out->total_available_resources.memory_bytes;
  out->child_count = budget->child_count;
  out->rejected_reservations = budget->rejected_reservations;
  out->metadata_bytes = budget->metadata_bytes;
  return FTUN_OK;
}

ftun_status_t ftun_budget_get_usage(const ftun_budget_t *budget,
                                    ftun_budget_usage_t *out)
{
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (budget == NULL || out == NULL) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&budget->root->mutex);
  status = ftun_budget_get_usage_locked(budget, out);
  (void)pthread_mutex_unlock(&budget->root->mutex);
  return status;
}

ftun_status_t ftun_budget_same_root(const ftun_budget_t *left,
                                    const ftun_budget_t *right,
                                    bool *out_same)
{
  if (out_same != NULL) *out_same = false;
  if (left == NULL || right == NULL || out_same == NULL) {
    return FTUN_E_INVALID;
  }
  *out_same = left->root == right->root;
  return FTUN_OK;
}

ftun_status_t ftun_reservation_resize(ftun_reservation_t *reservation,
  ftun_budget_resources_t resources)
{
  size_t requested[FTUN_BUDGET_RESOURCE_COUNT];
  size_t increase[FTUN_BUDGET_RESOURCE_COUNT] = {0};
  size_t decrease[FTUN_BUDGET_RESOURCE_COUNT] = {0};
  size_t index;
  ftun_budget_t *budget;
  ftun_status_t status = FTUN_OK;
  ftun_budget_unpack(resources, requested);
  if (reservation == NULL || ftun_budget_values_zero(requested)) return FTUN_E_INVALID;
  budget = reservation->budget;
  if (budget == NULL) return FTUN_E_STATE_CORRUPT;
  (void)pthread_mutex_lock(&budget->root->mutex);
  if (ftun_budget_values_zero(reservation->resources) ||
      !ftun_budget_can_subtract(budget, reservation->resources)) {
    status = FTUN_E_STATE_CORRUPT;
    goto done;
  }
  for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) {
    if (requested[index] >= reservation->resources[index]) {
      increase[index] = requested[index] - reservation->resources[index];
    } else {
      decrease[index] = reservation->resources[index] - requested[index];
    }
  }
  if (!ftun_budget_values_zero(increase) &&
      !ftun_budget_fits(budget, increase, reservation->cleanup)) {
    ftun_budget_rejected(budget);
    status = FTUN_E_LIMIT;
    goto done;
  }
  ftun_budget_add(budget, increase);
  ftun_budget_subtract(budget, decrease);
  memcpy(reservation->resources, requested, sizeof(requested));
done:
  (void)pthread_mutex_unlock(&budget->root->mutex);
  return status;
}

ftun_status_t ftun_reservation_release(ftun_reservation_t **reservation)
{
  ftun_reservation_t *owned;
  ftun_budget_t *budget;
  if (reservation == NULL) return FTUN_E_INVALID;
  owned = *reservation;
  if (owned == NULL) return FTUN_OK;
  budget = owned->budget;
  if (budget == NULL || ftun_budget_values_zero(owned->resources)) {
    return FTUN_E_STATE_CORRUPT;
  }
  (void)pthread_mutex_lock(&budget->root->mutex);
  if (!ftun_budget_can_subtract(budget, owned->resources) ||
      !ftun_budget_metadata_can_subtract(budget, sizeof(*owned))) {
    (void)pthread_mutex_unlock(&budget->root->mutex);
    return FTUN_E_STATE_CORRUPT;
  }
  ftun_budget_subtract(budget, owned->resources);
  ftun_budget_metadata_subtract(budget, sizeof(*owned));
  (void)pthread_mutex_unlock(&budget->root->mutex);
  free(owned);
  *reservation = NULL;
  return FTUN_OK;
}

ftun_status_t ftun_budget_destroy(ftun_budget_t **budget)
{
  ftun_budget_t *owned;
  ftun_status_t status = FTUN_OK;
  size_t index;
  if (budget == NULL) return FTUN_E_INVALID;
  owned = *budget;
  if (owned == NULL) return FTUN_OK;
  (void)pthread_mutex_lock(&owned->root->mutex);
  if (!ftun_budget_values_zero(owned->used) || owned->child_count != 0u) {
    status = FTUN_E_AGAIN;
    goto done;
  }
  if (!ftun_budget_values_zero(owned->child_guarantees) ||
      !ftun_budget_values_zero(owned->child_guaranteed_used) ||
      owned->metadata_bytes != (owned->parent == NULL
        ? sizeof(struct ftun_budget_root) : sizeof(*owned))) {
    status = FTUN_E_STATE_CORRUPT;
    goto done;
  }
  if (owned->parent != NULL) {
    if (owned->parent->child_count == 0u ||
        !ftun_budget_metadata_can_subtract(owned, sizeof(*owned))) {
      status = FTUN_E_STATE_CORRUPT;
      goto done;
    }
    for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) {
      if (owned->parent->child_guarantees[index] < owned->guarantee[index]) {
        status = FTUN_E_STATE_CORRUPT;
        goto done;
      }
    }
    for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) {
      owned->parent->child_guarantees[index] -= owned->guarantee[index];
    }
    owned->parent->child_count--;
    ftun_budget_metadata_subtract(owned, sizeof(*owned));
  }
done:
  (void)pthread_mutex_unlock(&owned->root->mutex);
  if (status != FTUN_OK) return status;
  if (owned->parent == NULL && pthread_mutex_destroy(&owned->root->mutex) != 0) {
    return FTUN_E_STATE_CORRUPT;
  }
  free(owned);
  *budget = NULL;
  return FTUN_OK;
}
