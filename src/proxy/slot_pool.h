#ifndef FTUN_PROXY_SLOT_POOL_H
#define FTUN_PROXY_SLOT_POOL_H

#include "core/limits.h"

typedef struct ftun_proxy_slot_pool ftun_proxy_slot_pool_t;

typedef struct {
  size_t index;
  uint64_t generation;
} ftun_proxy_slot_token_t;

typedef struct {
  size_t capacity;
  size_t active;
  size_t slab_size;
  size_t resident_slabs;
  size_t maximum_slabs;
  size_t retained_idle_slabs;
  uint64_t allocations;
  uint64_t releases;
  uint64_t stale_rejections;
} ftun_proxy_slot_pool_info_t;

ftun_status_t ftun_proxy_slot_pool_create(
  ftun_budget_t *budget, size_t object_size, size_t capacity,
  size_t slab_size, size_t retained_idle_slabs,
  ftun_proxy_slot_pool_t **out);
ftun_status_t ftun_proxy_slot_pool_acquire(
  ftun_proxy_slot_pool_t *pool, void **out,
  ftun_proxy_slot_token_t *out_token);
ftun_status_t ftun_proxy_slot_pool_get(
  ftun_proxy_slot_pool_t *pool, ftun_proxy_slot_token_t token, void **out);
ftun_status_t ftun_proxy_slot_pool_at(
  ftun_proxy_slot_pool_t *pool, size_t index, void **out,
  ftun_proxy_slot_token_t *out_token);
ftun_status_t ftun_proxy_slot_pool_release(
  ftun_proxy_slot_pool_t *pool, ftun_proxy_slot_token_t token, void **object);
ftun_status_t ftun_proxy_slot_pool_trim(ftun_proxy_slot_pool_t *pool);
ftun_status_t ftun_proxy_slot_pool_get_info(
  const ftun_proxy_slot_pool_t *pool, ftun_proxy_slot_pool_info_t *out);
ftun_status_t ftun_proxy_slot_pool_destroy(ftun_proxy_slot_pool_t **pool);

#endif
