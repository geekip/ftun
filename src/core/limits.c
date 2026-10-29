#include "core/limits.h"
#include "platform/thread.h"
#include "platform/atomic.h"
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
  struct ftun_budget_domain *domain;
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

/* 每个根直系子域独立同步；根直接拥有的资源使用单独的根域。 */
struct ftun_budget_domain {
  ftun_budget_t budget;
  ftun_mutex_t mutex;
  struct ftun_budget_domain *next;
};
struct ftun_budget_root {
  struct ftun_budget_domain domain;
  ftun_mutex_t registry_mutex;
  struct ftun_budget_domain *domains;
  size_t own_used[FTUN_BUDGET_RESOURCE_COUNT];
  ftun_atomic_size_t admitted[FTUN_BUDGET_RESOURCE_COUNT];
  ftun_atomic_size_t committed[FTUN_BUDGET_RESOURCE_COUNT];
  ftun_atomic_size_t borrowed[FTUN_BUDGET_RESOURCE_COUNT];
  ftun_atomic_size_t covered[FTUN_BUDGET_RESOURCE_COUNT];
  ftun_atomic_size_t high[FTUN_BUDGET_RESOURCE_COUNT];
  ftun_atomic_size_t rejected;
};

/* 仅结构变更和一致快照调用。热路径只锁本域，不进入此锁序。 */
static void ftun_budget_lock_snapshot(struct ftun_budget_root *root)
{
  struct ftun_budget_domain *domain;
  size_t index;
  ftun_budget_t *budget = &root->domain.budget;
  ftun_mutex_lock(&root->registry_mutex);
  ftun_mutex_lock(&root->domain.mutex);
  for (domain = root->domains; domain != NULL; domain = domain->next) ftun_mutex_lock(&domain->mutex);
  for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) {
    budget->used[index] = ftun_atomic_load(&root->committed[index]);
    budget->child_guaranteed_used[index] = ftun_atomic_load(&root->covered[index]);
    budget->high_watermark[index] = ftun_atomic_load(&root->high[index]);
  }
  budget->rejected_reservations = ftun_atomic_load(&root->rejected);
}
static void ftun_budget_unlock_domains(struct ftun_budget_root *root)
{
  struct ftun_budget_domain *domain;
  for (domain = root->domains; domain != NULL; domain = domain->next) ftun_mutex_unlock(&domain->mutex);
  ftun_mutex_unlock(&root->domain.mutex);
}

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
  if (budget->parent != NULL) {
    if (budget->rejected_reservations != SIZE_MAX) budget->rejected_reservations++;
  } else {
    size_t count = ftun_atomic_load(&budget->root->rejected);
    while (count != SIZE_MAX && !ftun_atomic_compare_exchange_strong(
      &budget->root->rejected, &count, count + 1u)) { }
  }
}

/* CAS 失败只重新读取竞争后的值，不重试业务操作或分配。 */
static int ftun_budget_atomic_take(ftun_atomic_size_t *counter, size_t amount, size_t ceiling)
{
  size_t value = ftun_atomic_load(counter);
  if (amount == 0u) return 1;
  while (value <= ceiling && amount <= ceiling - value) {
    if (ftun_atomic_compare_exchange_strong(counter, &value, value + amount)) return 1;
  }
  return 0;
}
/* cleanup 可以占用尚未使用的保证份额；普通申请仍须保护其他域的剩余份额。 */
static int ftun_budget_take_shared(ftun_atomic_size_t *counter,
  size_t requested, size_t unused, size_t ceiling)
{
  size_t value = ftun_atomic_load(counter);
  size_t increase = requested > unused ? requested - unused : 0u;
  if (requested == 0u) return 1;
  for (;;) {
    if (value > ceiling) {
      size_t deficit = value - ceiling;
      if (deficit > unused || requested > unused - deficit) return 0;
    } else if (increase > ceiling - value) return 0;
    if (ftun_atomic_compare_exchange_strong(counter, &value, value + increase)) return 1;
  }
}
static size_t ftun_budget_domain_used(const ftun_budget_t *budget, size_t index)
{
  return budget->domain == &budget->root->domain ? budget->root->own_used[index]
    : budget->domain->budget.used[index];
}
static size_t ftun_budget_borrow_increase(const ftun_budget_t *budget, size_t index, size_t amount)
{
  size_t used = ftun_budget_domain_used(budget, index);
  size_t guarantee = budget->domain->budget.guarantee[index];
  size_t unused = used < guarantee ? guarantee - used : 0u;
  return amount > unused ? amount - unused : 0u;
}
static size_t ftun_budget_borrow_decrease(const ftun_budget_t *budget, size_t index, size_t amount)
{
  size_t used = ftun_budget_domain_used(budget, index);
  size_t guarantee = budget->domain->budget.guarantee[index];
  size_t before = used > guarantee ? used - guarantee : 0u;
  size_t after = used - amount > guarantee ? used - amount - guarantee : 0u;
  return before - after;
}

static int ftun_budget_claim(ftun_budget_t *leaf,
  const size_t requested[FTUN_BUDGET_RESOURCE_COUNT], int cleanup)
{
  ftun_budget_t *budget;
  struct ftun_budget_root *root = leaf->root;
  const ftun_budget_t *global = &root->domain.budget;
  size_t index, physical = 0u, borrowed = 0u;
  size_t shares[FTUN_BUDGET_RESOURCE_COUNT];
  for (budget = leaf; budget->parent != NULL; budget = budget->parent) {
    for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) {
      size_t ceiling = cleanup ? budget->limit[index]
        : budget->limit[index] - budget->cleanup_reserve[index];
      if (requested[index] != 0u && (budget->used[index] > ceiling ||
          requested[index] > ceiling - budget->used[index])) return 0;
    }
  }
  for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) {
    size_t ceiling = cleanup ? global->limit[index]
      : global->limit[index] - global->cleanup_reserve[index];
    shares[index] = ftun_budget_borrow_increase(leaf, index, requested[index]);
    if (!ftun_budget_atomic_take(&root->admitted[index], requested[index], ceiling)) goto rollback;
    physical++;
  }
  for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) {
    size_t ceiling = cleanup ? SIZE_MAX : global->limit[index] -
      global->cleanup_reserve[index] - global->child_guarantees[index];
    size_t used = ftun_budget_domain_used(leaf, index);
    size_t guarantee = leaf->domain->budget.guarantee[index];
    size_t unused = used < guarantee ? guarantee - used : 0u;
    if (cleanup ? !ftun_budget_atomic_take(&root->borrowed[index], shares[index], ceiling)
        : !ftun_budget_take_shared(&root->borrowed[index], requested[index], unused, ceiling)) goto rollback;
    borrowed++;
  }
  return 1;
rollback:
  for (index = 0u; index < borrowed; index++)
    (void)ftun_atomic_fetch_sub_explicit(&root->borrowed[index], shares[index], FTUN_MEMORY_SEQ_CST);
  for (index = 0u; index < physical; index++)
    (void)ftun_atomic_fetch_sub_explicit(&root->admitted[index], requested[index], FTUN_MEMORY_SEQ_CST);
  return 0;
}

static void ftun_budget_add(ftun_budget_t *leaf,
  const size_t resources[FTUN_BUDGET_RESOURCE_COUNT])
{
  ftun_budget_t *budget;
  struct ftun_budget_root *root = leaf->root;
  size_t index;
  for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) {
    size_t borrowed = ftun_budget_borrow_increase(leaf, index, resources[index]);
    size_t committed = ftun_atomic_fetch_add(&root->committed[index], resources[index]) + resources[index];
    size_t high = ftun_atomic_load(&root->high[index]);
    (void)ftun_atomic_fetch_add(&root->covered[index], resources[index] - borrowed);
    while (high < committed && !ftun_atomic_compare_exchange_strong(&root->high[index], &high, committed)) { }
  }
  if (leaf->parent == NULL) {
    for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) root->own_used[index] += resources[index];
  }
  for (budget = leaf; budget->parent != NULL; budget = budget->parent) {
    for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) {
      budget->used[index] += resources[index];
      if (budget->used[index] > budget->high_watermark[index]) budget->high_watermark[index] = budget->used[index];
    }
  }
}

static int ftun_budget_can_subtract(ftun_budget_t *leaf,
  const size_t resources[FTUN_BUDGET_RESOURCE_COUNT])
{
  ftun_budget_t *budget;
  size_t index;
  for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) {
    if (ftun_budget_domain_used(leaf, index) < resources[index] ||
        ftun_atomic_load(&leaf->root->committed[index]) < resources[index]) return 0;
  }
  for (budget = leaf; budget->parent != NULL; budget = budget->parent) {
    for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) {
      if (budget->used[index] < resources[index]) return 0;
    }
  }
  return 1;
}

static void ftun_budget_subtract(ftun_budget_t *leaf,
  const size_t resources[FTUN_BUDGET_RESOURCE_COUNT])
{
  ftun_budget_t *budget;
  struct ftun_budget_root *root = leaf->root;
  size_t index;
  for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) {
    size_t borrowed = ftun_budget_borrow_decrease(leaf, index, resources[index]);
    (void)ftun_atomic_fetch_sub_explicit(&root->committed[index], resources[index], FTUN_MEMORY_SEQ_CST);
    (void)ftun_atomic_fetch_sub_explicit(&root->covered[index], resources[index] - borrowed, FTUN_MEMORY_SEQ_CST);
    (void)ftun_atomic_fetch_sub_explicit(&root->borrowed[index], borrowed, FTUN_MEMORY_SEQ_CST);
    (void)ftun_atomic_fetch_sub_explicit(&root->admitted[index], resources[index], FTUN_MEMORY_SEQ_CST);
  }
  if (leaf->parent == NULL) {
    for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) root->own_used[index] -= resources[index];
  }
  for (budget = leaf; budget->parent != NULL; budget = budget->parent) {
    for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) budget->used[index] -= resources[index];
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
    : parent->parent == NULL ? sizeof(struct ftun_budget_domain) : sizeof(*budget);
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
    budget->domain = &budget->root->domain;
    if (ftun_mutex_init(&budget->domain->mutex) != FTUN_OK) { free(budget); return FTUN_E_IO; }
    if (ftun_mutex_init(&budget->root->registry_mutex) != FTUN_OK) {
      ftun_mutex_destroy(&budget->domain->mutex);
      free(budget);
      return FTUN_E_IO;
    }
    budget->metadata_bytes = allocation;
    *out = budget;
    return FTUN_OK;
  }
  budget->root = parent->root;
  budget->domain = parent->parent == NULL ? (struct ftun_budget_domain *)budget : parent->domain;
  if (parent->parent == NULL && ftun_mutex_init(&budget->domain->mutex) != FTUN_OK) {
    free(budget);
    return FTUN_E_IO;
  }
  ftun_budget_lock_snapshot(budget->root);
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
  ftun_budget_unlock_domains(budget->root);
  if (status == FTUN_OK && parent->parent == NULL) {
    budget->domain->next = budget->root->domains;
    budget->root->domains = budget->domain;
  }
  ftun_mutex_unlock(&budget->root->registry_mutex);
  if (status != FTUN_OK) {
    if (parent->parent == NULL) ftun_mutex_destroy(&budget->domain->mutex);
    free(budget);
  }
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
  ftun_reservation_t *out)
{
  size_t requested[FTUN_BUDGET_RESOURCE_COUNT];
  ftun_status_t status = FTUN_OK;
  if (out != NULL) *out = (ftun_reservation_t){0};
  ftun_budget_unpack(resources, requested);
  if (budget == NULL || out == NULL || ftun_budget_values_zero(requested)) return FTUN_E_INVALID;
  ftun_mutex_lock(&budget->domain->mutex);
  if (!ftun_budget_claim(budget, requested, cleanup)) {
    ftun_budget_rejected(budget);
    status = FTUN_E_LIMIT;
  } else {
    out->budget = budget;
    out->cleanup = cleanup;
    memcpy(out->resources, requested, sizeof(requested));
    ftun_budget_add(budget, requested);
  }
  ftun_mutex_unlock(&budget->domain->mutex);
  return status;
}

ftun_status_t ftun_budget_reserve_resources(
  ftun_budget_t *budget, ftun_budget_resources_t resources,
  ftun_reservation_t *out)
{
  return ftun_budget_reserve_kind(budget, resources, 0, out);
}

ftun_status_t ftun_budget_reserve_cleanup_resources(
  ftun_budget_t *budget, ftun_budget_resources_t resources,
  ftun_reservation_t *out)
{
  return ftun_budget_reserve_kind(budget, resources, 1, out);
}

ftun_status_t ftun_budget_reserve(ftun_budget_t *budget, size_t bytes,
                                  ftun_reservation_t *out)
{
  ftun_budget_resources_t resources = {bytes, 0u, 0u};
  return ftun_budget_reserve_resources(budget, resources, out);
}

ftun_status_t ftun_budget_reserve_cleanup(ftun_budget_t *budget, size_t bytes,
                                          ftun_reservation_t *out)
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

ftun_status_t ftun_budget_get_usage(const ftun_budget_t *budget, ftun_budget_usage_t *out)
{
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (budget == NULL || out == NULL) return FTUN_E_INVALID;
  ftun_budget_lock_snapshot(budget->root);
  status = ftun_budget_get_usage_locked(budget, out);
  ftun_budget_unlock_domains(budget->root);
  ftun_mutex_unlock(&budget->root->registry_mutex);
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
  if (budget == NULL) return FTUN_E_INVALID;
  ftun_mutex_lock(&budget->domain->mutex);
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
      !ftun_budget_claim(budget, increase, reservation->cleanup)) {
    ftun_budget_rejected(budget);
    status = FTUN_E_LIMIT;
    goto done;
  }
  ftun_budget_add(budget, increase);
  ftun_budget_subtract(budget, decrease);
  memcpy(reservation->resources, requested, sizeof(requested));
done:
  ftun_mutex_unlock(&budget->domain->mutex);
  return status;
}

ftun_status_t ftun_reservation_release(ftun_reservation_t *reservation)
{
  ftun_budget_t *budget;
  if (reservation == NULL) return FTUN_E_INVALID;
  budget = reservation->budget;
  if (budget == NULL) return FTUN_OK;
  if (ftun_budget_values_zero(reservation->resources)) return FTUN_E_STATE_CORRUPT;
  ftun_mutex_lock(&budget->domain->mutex);
  if (!ftun_budget_can_subtract(budget, reservation->resources)) {
    ftun_mutex_unlock(&budget->domain->mutex);
    return FTUN_E_STATE_CORRUPT;
  }
  ftun_budget_subtract(budget, reservation->resources);
  ftun_mutex_unlock(&budget->domain->mutex);
  *reservation = (ftun_reservation_t){0};
  return FTUN_OK;
}

ftun_status_t ftun_budget_destroy(ftun_budget_t **budget)
{
  ftun_budget_t *owned;
  struct ftun_budget_root *root;
  struct ftun_budget_domain **cursor;
  ftun_status_t status = FTUN_OK;
  size_t index, allocation;
  bool domain;
  if (budget == NULL) return FTUN_E_INVALID;
  owned = *budget;
  if (owned == NULL) return FTUN_OK;
  root = owned->root;
  domain = owned->parent != NULL && owned->parent->parent == NULL;
  allocation = owned->parent == NULL ? sizeof(*root)
    : domain ? sizeof(struct ftun_budget_domain) : sizeof(*owned);
  ftun_budget_lock_snapshot(root);
  if (!ftun_budget_values_zero(owned->used) || owned->child_count != 0u) {
    status = FTUN_E_AGAIN;
    goto done;
  }
  if (!ftun_budget_values_zero(owned->child_guarantees) ||
      !ftun_budget_values_zero(owned->child_guaranteed_used) || owned->metadata_bytes != allocation) {
    status = FTUN_E_STATE_CORRUPT;
    goto done;
  }
  if (owned->parent != NULL) {
    if (owned->parent->child_count == 0u || !ftun_budget_metadata_can_subtract(owned, allocation)) {
      status = FTUN_E_STATE_CORRUPT;
      goto done;
    }
    for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++) {
      if (owned->parent->child_guarantees[index] < owned->guarantee[index]) {
        status = FTUN_E_STATE_CORRUPT;
        goto done;
      }
    }
    for (index = 0u; index < FTUN_BUDGET_RESOURCE_COUNT; index++)
      owned->parent->child_guarantees[index] -= owned->guarantee[index];
    owned->parent->child_count--;
    ftun_budget_metadata_subtract(owned, allocation);
  }
done:
  ftun_budget_unlock_domains(root);
  if (status == FTUN_OK && domain) {
    for (cursor = &root->domains; *cursor != owned->domain; cursor = &(*cursor)->next) { }
    *cursor = owned->domain->next;
  }
  ftun_mutex_unlock(&root->registry_mutex);
  if (status != FTUN_OK) return status;
  if (domain) ftun_mutex_destroy(&owned->domain->mutex);
  if (owned->parent == NULL) {
    ftun_mutex_destroy(&root->domain.mutex);
    ftun_mutex_destroy(&root->registry_mutex);
  }
  free(owned);
  *budget = NULL;
  return FTUN_OK;
}
