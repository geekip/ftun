#include "proxy/slot_pool.h"

#include <stdlib.h>
#include <string.h>

#define FTUN_PROXY_SLOT_NONE SIZE_MAX

typedef union {
  long double wide;
  void *pointer;
  uint64_t integer;
} ftun_proxy_slot_alignment_t;

typedef struct {
  size_t next_free;
  uint64_t generation;
  bool active;
  ftun_proxy_slot_alignment_t alignment;
} ftun_proxy_slot_header_t;

typedef struct {
  ftun_reservation_t reservation;
  unsigned char *storage;
  size_t index;
  size_t slot_count;
  size_t free_head;
  size_t free_count;
  size_t next_available;
  bool available;
} ftun_proxy_slot_slab_t;

struct ftun_proxy_slot_pool {
  ftun_budget_t *budget;
  ftun_reservation_t reservation;
  ftun_proxy_slot_slab_t **slabs;
  uint64_t *generations;
  size_t object_size;
  size_t stride;
  size_t capacity;
  size_t active;
  size_t slab_size;
  size_t maximum_slabs;
  size_t resident_slabs;
  size_t retained_idle_slabs;
  size_t available_head;
  bool trim_needed;
  uint64_t allocations;
  uint64_t releases;
  uint64_t stale_rejections;
};

static int ftun_proxy_slot_add(size_t left, size_t right, size_t *out)
{
  if (out == NULL || left > SIZE_MAX - right) return 0;
  *out = left + right;
  return 1;
}

static int ftun_proxy_slot_mul(size_t left, size_t right, size_t *out)
{
  if (out == NULL || (left != 0u && right > SIZE_MAX / left)) return 0;
  *out = left * right;
  return 1;
}

static ftun_proxy_slot_header_t *ftun_proxy_slot_header(
  const ftun_proxy_slot_pool_t *pool, const ftun_proxy_slot_slab_t *slab,
  size_t offset)
{
  return (ftun_proxy_slot_header_t *)(void *)(slab->storage +
                                               offset * pool->stride);
}

static void *ftun_proxy_slot_object(ftun_proxy_slot_header_t *header)
{
  return (void *)(header + 1u);
}

static void ftun_proxy_slot_available_add(ftun_proxy_slot_pool_t *pool,
                                          ftun_proxy_slot_slab_t *slab)
{
  if (slab->available) return;
  slab->next_available = pool->available_head;
  pool->available_head = slab->index;
  slab->available = true;
}

static void ftun_proxy_slot_available_remove(ftun_proxy_slot_pool_t *pool,
                                             ftun_proxy_slot_slab_t *slab)
{
  size_t *link;
  if (!slab->available) return;
  link = &pool->available_head;
  while (*link != FTUN_PROXY_SLOT_NONE) {
    ftun_proxy_slot_slab_t *current = pool->slabs[*link];
    if (current == slab) {
      *link = slab->next_available;
      slab->next_available = FTUN_PROXY_SLOT_NONE;
      slab->available = false;
      return;
    }
    if (current == NULL) return;
    link = &current->next_available;
  }
}

static ftun_status_t ftun_proxy_slot_slab_create(
  ftun_proxy_slot_pool_t *pool, size_t slab_index,
  ftun_proxy_slot_slab_t **out)
{
  ftun_proxy_slot_slab_t *slab;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  size_t first = slab_index * pool->slab_size;
  size_t remaining = pool->capacity - first;
  size_t slot_count = remaining < pool->slab_size ? remaining : pool->slab_size;
  size_t storage_bytes;
  size_t bytes;
  size_t index;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (out == NULL || slab_index >= pool->maximum_slabs ||
      pool->slabs[slab_index] != NULL || slot_count == 0u ||
      !ftun_proxy_slot_mul(slot_count, pool->stride, &storage_bytes) ||
      !ftun_proxy_slot_add(sizeof(*slab), storage_bytes, &bytes)) {
    return FTUN_E_INVALID;
  }
  status = ftun_budget_reserve(pool->budget, bytes, &reservation);
  if (status != FTUN_OK) return status;
  slab = (ftun_proxy_slot_slab_t *)calloc(1u, bytes);
  if (slab == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  slab->reservation = reservation;
  slab->storage = (unsigned char *)(slab + 1u);
  slab->index = slab_index;
  slab->slot_count = slot_count;
  slab->free_head = 0u;
  slab->free_count = slot_count;
  slab->next_available = FTUN_PROXY_SLOT_NONE;
  for (index = 0u; index < slot_count; index++) {
    ftun_proxy_slot_header_t *header =
      ftun_proxy_slot_header(pool, slab, index);
    header->next_free = index + 1u < slot_count
      ? index + 1u : FTUN_PROXY_SLOT_NONE;
  }
  pool->slabs[slab_index] = slab;
  pool->resident_slabs++;
  ftun_proxy_slot_available_add(pool, slab);
  *out = slab;
  return FTUN_OK;
}

static ftun_status_t ftun_proxy_slot_slab_destroy(
  ftun_proxy_slot_pool_t *pool, ftun_proxy_slot_slab_t *slab)
{
  ftun_reservation_t reservation;
  if (pool == NULL || slab == NULL || slab->free_count != slab->slot_count ||
      slab->index >= pool->maximum_slabs || pool->slabs[slab->index] != slab) {
    return FTUN_E_INVALID;
  }
  ftun_proxy_slot_available_remove(pool, slab);
  pool->slabs[slab->index] = NULL;
  if (pool->resident_slabs != 0u) pool->resident_slabs--;
  reservation = slab->reservation;
  slab->reservation = (ftun_reservation_t){0};
  free(slab);
  ftun_reservation_release(&reservation);
  return FTUN_OK;
}

ftun_status_t ftun_proxy_slot_pool_create(
  ftun_budget_t *budget, size_t object_size, size_t capacity,
  size_t slab_size, size_t retained_idle_slabs,
  ftun_proxy_slot_pool_t **out)
{
  ftun_proxy_slot_pool_t *pool;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  size_t rounded_object;
  size_t pointer_bytes;
  size_t generation_bytes;
  size_t bytes;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (budget == NULL || object_size == 0u || capacity == 0u ||
      slab_size == 0u || out == NULL ||
      capacity > SIZE_MAX - (slab_size - 1u)) return FTUN_E_INVALID;
  rounded_object = object_size;
  if (rounded_object % sizeof(ftun_proxy_slot_alignment_t) != 0u) {
    size_t padding = sizeof(ftun_proxy_slot_alignment_t) -
      rounded_object % sizeof(ftun_proxy_slot_alignment_t);
    if (!ftun_proxy_slot_add(rounded_object, padding, &rounded_object)) {
      return FTUN_E_LIMIT;
    }
  }
  pool = (ftun_proxy_slot_pool_t *)calloc(1u, sizeof(*pool));
  if (pool == NULL) return FTUN_E_LIMIT;
  pool->maximum_slabs = (capacity + slab_size - 1u) / slab_size;
  if (retained_idle_slabs > pool->maximum_slabs ||
      !ftun_proxy_slot_mul(pool->maximum_slabs, sizeof(*pool->slabs),
                           &pointer_bytes) ||
      !ftun_proxy_slot_mul(capacity, sizeof(*pool->generations),
                           &generation_bytes) ||
      !ftun_proxy_slot_add(sizeof(*pool), pointer_bytes, &bytes) ||
      !ftun_proxy_slot_add(bytes, generation_bytes, &bytes) ||
      !ftun_proxy_slot_add(sizeof(ftun_proxy_slot_header_t), rounded_object,
                           &pool->stride)) {
    free(pool);
    return FTUN_E_LIMIT;
  }
  status = ftun_budget_reserve(budget, bytes, &reservation);
  if (status != FTUN_OK) {
    free(pool);
    return status;
  }
  pool->slabs = (ftun_proxy_slot_slab_t **)calloc(
    pool->maximum_slabs, sizeof(*pool->slabs));
  pool->generations = (uint64_t *)calloc(capacity, sizeof(*pool->generations));
  if (pool->slabs == NULL || pool->generations == NULL) {
    free(pool->generations);
    free(pool->slabs);
    free(pool);
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  pool->budget = budget;
  pool->reservation = reservation;
  pool->object_size = object_size;
  pool->capacity = capacity;
  pool->slab_size = slab_size;
  pool->retained_idle_slabs = retained_idle_slabs;
  pool->available_head = FTUN_PROXY_SLOT_NONE;
  *out = pool;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_slot_pool_acquire(
  ftun_proxy_slot_pool_t *pool, void **out,
  ftun_proxy_slot_token_t *out_token)
{
  ftun_proxy_slot_slab_t *slab;
  ftun_proxy_slot_header_t *header;
  size_t slab_index;
  size_t offset;
  size_t logical;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (out_token != NULL) memset(out_token, 0, sizeof(*out_token));
  if (pool == NULL || out == NULL || out_token == NULL) return FTUN_E_INVALID;
  if (pool->active >= pool->capacity) return FTUN_E_LIMIT;
  if (pool->available_head == FTUN_PROXY_SLOT_NONE) {
    for (slab_index = 0u; slab_index < pool->maximum_slabs; slab_index++) {
      if (pool->slabs[slab_index] == NULL) break;
    }
    if (slab_index == pool->maximum_slabs) return FTUN_E_STATE_CORRUPT;
    status = ftun_proxy_slot_slab_create(pool, slab_index, &slab);
    if (status != FTUN_OK) return status;
  }
  slab = pool->slabs[pool->available_head];
  if (slab == NULL || slab->free_count == 0u ||
      slab->free_head == FTUN_PROXY_SLOT_NONE) return FTUN_E_STATE_CORRUPT;
  offset = slab->free_head;
  header = ftun_proxy_slot_header(pool, slab, offset);
  slab->free_head = header->next_free;
  slab->free_count--;
  if (slab->free_count == 0u) ftun_proxy_slot_available_remove(pool, slab);
  logical = slab->index * pool->slab_size + offset;
  pool->generations[logical]++;
  if (pool->generations[logical] == 0u) pool->generations[logical]++;
  header->generation = pool->generations[logical];
  header->next_free = FTUN_PROXY_SLOT_NONE;
  header->active = true;
  memset(ftun_proxy_slot_object(header), 0, pool->object_size);
  pool->active++;
  if (pool->allocations != UINT64_MAX) pool->allocations++;
  out_token->index = logical;
  out_token->generation = header->generation;
  *out = ftun_proxy_slot_object(header);
  return FTUN_OK;
}

ftun_status_t ftun_proxy_slot_pool_get(
  ftun_proxy_slot_pool_t *pool, ftun_proxy_slot_token_t token, void **out)
{
  ftun_proxy_slot_slab_t *slab;
  ftun_proxy_slot_header_t *header;
  size_t slab_index;
  size_t offset;
  if (out != NULL) *out = NULL;
  if (pool == NULL || out == NULL || token.generation == 0u ||
      token.index >= pool->capacity) return FTUN_E_INVALID;
  slab_index = token.index / pool->slab_size;
  offset = token.index % pool->slab_size;
  slab = pool->slabs[slab_index];
  if (slab == NULL || offset >= slab->slot_count) {
    if (pool->stale_rejections != UINT64_MAX) pool->stale_rejections++;
    return FTUN_E_STALE;
  }
  header = ftun_proxy_slot_header(pool, slab, offset);
  if (!header->active || header->generation != token.generation) {
    if (pool->stale_rejections != UINT64_MAX) pool->stale_rejections++;
    return FTUN_E_STALE;
  }
  *out = ftun_proxy_slot_object(header);
  return FTUN_OK;
}

ftun_status_t ftun_proxy_slot_pool_at(
  ftun_proxy_slot_pool_t *pool, size_t index, void **out,
  ftun_proxy_slot_token_t *out_token)
{
  ftun_proxy_slot_slab_t *slab;
  ftun_proxy_slot_header_t *header;
  size_t slab_index;
  size_t offset;
  if (out != NULL) *out = NULL;
  if (out_token != NULL) memset(out_token, 0, sizeof(*out_token));
  if (pool == NULL || out == NULL || out_token == NULL ||
      index >= pool->capacity) return FTUN_E_INVALID;
  slab_index = index / pool->slab_size;
  offset = index % pool->slab_size;
  slab = pool->slabs[slab_index];
  if (slab == NULL || offset >= slab->slot_count) return FTUN_E_STALE;
  header = ftun_proxy_slot_header(pool, slab, offset);
  if (!header->active) return FTUN_E_STALE;
  out_token->index = index;
  out_token->generation = header->generation;
  *out = ftun_proxy_slot_object(header);
  return FTUN_OK;
}

ftun_status_t ftun_proxy_slot_pool_release(
  ftun_proxy_slot_pool_t *pool, ftun_proxy_slot_token_t token, void **object)
{
  ftun_proxy_slot_slab_t *slab;
  ftun_proxy_slot_header_t *header;
  void *owned;
  size_t slab_index;
  size_t offset;
  if (pool == NULL || object == NULL || token.generation == 0u ||
      token.index >= pool->capacity) return FTUN_E_INVALID;
  owned = *object;
  if (owned == NULL) return FTUN_OK;
  slab_index = token.index / pool->slab_size;
  offset = token.index % pool->slab_size;
  slab = pool->slabs[slab_index];
  if (slab == NULL || offset >= slab->slot_count) {
    if (pool->stale_rejections != UINT64_MAX) pool->stale_rejections++;
    return FTUN_E_STALE;
  }
  header = ftun_proxy_slot_header(pool, slab, offset);
  if (!header->active || header->generation != token.generation ||
      ftun_proxy_slot_object(header) != owned) {
    if (pool->stale_rejections != UINT64_MAX) pool->stale_rejections++;
    return FTUN_E_STALE;
  }
  if (slab->free_count == 0u) ftun_proxy_slot_available_add(pool, slab);
  memset(owned, 0, pool->object_size);
  header->active = false;
  header->next_free = slab->free_head;
  slab->free_head = offset;
  slab->free_count++;
  if (slab->free_count == slab->slot_count &&
      pool->resident_slabs > pool->retained_idle_slabs) {
    pool->trim_needed = true;
  }
  if (pool->active != 0u) pool->active--;
  if (pool->releases != UINT64_MAX) pool->releases++;
  *object = NULL;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_slot_pool_trim(ftun_proxy_slot_pool_t *pool)
{
  size_t idle_slabs = 0u;
  size_t index;
  if (pool == NULL) return FTUN_E_INVALID;
  if (!pool->trim_needed) return FTUN_OK;
  for (index = 0u; index < pool->maximum_slabs; index++) {
    ftun_proxy_slot_slab_t *slab = pool->slabs[index];
    if (slab != NULL && slab->free_count == slab->slot_count) idle_slabs++;
  }
  for (index = pool->maximum_slabs; index != 0u &&
       idle_slabs > pool->retained_idle_slabs; index--) {
    ftun_proxy_slot_slab_t *slab = pool->slabs[index - 1u];
    ftun_status_t status;
    if (slab == NULL || slab->free_count != slab->slot_count) continue;
    status = ftun_proxy_slot_slab_destroy(pool, slab);
    if (status != FTUN_OK) return status;
    idle_slabs--;
  }
  pool->trim_needed = false;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_slot_pool_get_info(
  const ftun_proxy_slot_pool_t *pool, ftun_proxy_slot_pool_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (pool == NULL || out == NULL) return FTUN_E_INVALID;
  out->capacity = pool->capacity;
  out->active = pool->active;
  out->slab_size = pool->slab_size;
  out->resident_slabs = pool->resident_slabs;
  out->maximum_slabs = pool->maximum_slabs;
  out->retained_idle_slabs = pool->retained_idle_slabs;
  out->allocations = pool->allocations;
  out->releases = pool->releases;
  out->stale_rejections = pool->stale_rejections;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_slot_pool_destroy(ftun_proxy_slot_pool_t **pool)
{
  ftun_proxy_slot_pool_t *owned;
  ftun_reservation_t reservation;
  size_t index;
  ftun_status_t status;
  if (pool == NULL) return FTUN_E_INVALID;
  owned = *pool;
  if (owned == NULL) return FTUN_OK;
  if (owned->active != 0u) return FTUN_E_AGAIN;
  for (index = 0u; index < owned->maximum_slabs; index++) {
    if (owned->slabs[index] == NULL) continue;
    status = ftun_proxy_slot_slab_destroy(owned, owned->slabs[index]);
    if (status != FTUN_OK) return status;
  }
  reservation = owned->reservation;
  owned->reservation = (ftun_reservation_t){0};
  free(owned->generations);
  free(owned->slabs);
  free(owned);
  *pool = NULL;
  ftun_reservation_release(&reservation);
  return FTUN_OK;
}
