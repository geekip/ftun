#ifndef FTUN_CORE_INDEX_H
#define FTUN_CORE_INDEX_H

#include "core/limits.h"
#include "util/types.h"

typedef uint64_t (*ftun_hash_fn)(ftun_bytes_t key, void *user);

#include "util/hash.h"

typedef struct {
  size_t capacity;
  size_t max_entries;
  size_t entries;
  size_t tombstones;
  size_t key_bytes;
} ftun_index_usage_t;

/* 有界完整键索引。
 * 哈希值只用于定位候选，最终等值始终比较完整键。索引复制键并拥有副本；
 * insert 成功后调用者仍拥有输入。扩容先预留新表的峰值预算，成功后才释放旧表。
 */
ftun_status_t ftun_index_create(ftun_budget_t *budget,
                                size_t initial_capacity,
                                size_t max_entries,
                                ftun_hash_fn hash,
                                void *hash_user,
                                ftun_index_t **out);
ftun_status_t ftun_index_insert(ftun_index_t *index, ftun_bytes_t key,
                                uint32_t value);
ftun_status_t ftun_hash_lookup(const ftun_index_t *index, ftun_bytes_t key,
                               uint32_t *out);
ftun_status_t ftun_index_remove(ftun_index_t *index, ftun_bytes_t key,
                                uint32_t *out);
ftun_status_t ftun_index_get_usage(const ftun_index_t *index,
                                   ftun_index_usage_t *out);
ftun_status_t ftun_index_destroy(ftun_index_t **index);

#endif
