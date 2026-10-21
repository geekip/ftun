#include "proxy/slot_pool.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(expression) do { \
  if (!(expression)) { \
    fprintf(stderr, "check failed: %s:%d: %s\n", \
            __FILE__, __LINE__, #expression); \
    return 1; \
  } \
} while (0)

typedef struct {
  uint64_t value;
  unsigned char padding[120];
} test_object_t;

int main(void)
{
  ftun_budget_t *budget = NULL;
  ftun_budget_t *small_budget = NULL;
  ftun_proxy_slot_pool_t *pool = NULL;
  ftun_proxy_slot_pool_t *small_pool = NULL;
  ftun_proxy_slot_pool_info_t info;
  ftun_proxy_slot_token_t tokens[130];
  ftun_proxy_slot_token_t trimmed_token;
  test_object_t *objects[130];
  test_object_t *reused[65];
  test_object_t *first;
  void *value;
  void *stale;
  size_t index;

  memset(tokens, 0, sizeof(tokens));
  memset(objects, 0, sizeof(objects));
  memset(reused, 0, sizeof(reused));
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_proxy_slot_pool_create(budget, sizeof(test_object_t), 130u,
        64u, 1u, &pool) == FTUN_OK);
  for (index = 0u; index < 65u; index++) {
    value = NULL;
    CHECK(ftun_proxy_slot_pool_acquire(pool, &value, &tokens[index]) ==
          FTUN_OK);
    objects[index] = (test_object_t *)value;
    objects[index]->value = index + 1u;
  }
  first = objects[0];
  CHECK(first->value == 1u && objects[64]->value == 65u);
  CHECK(ftun_proxy_slot_pool_get_info(pool, &info) == FTUN_OK &&
        info.capacity == 130u && info.active == 65u &&
        info.slab_size == 64u && info.resident_slabs == 2u);

  stale = objects[0];
  value = objects[0];
  CHECK(ftun_proxy_slot_pool_release(pool, tokens[0], &value) == FTUN_OK &&
        value == NULL);
  value = NULL;
  {
    ftun_proxy_slot_token_t replacement;
    CHECK(ftun_proxy_slot_pool_acquire(pool, &value, &replacement) == FTUN_OK);
    objects[0] = (test_object_t *)value;
    CHECK(objects[0] == first && replacement.index == tokens[0].index &&
          replacement.generation != tokens[0].generation);
    CHECK(ftun_proxy_slot_pool_get(pool, tokens[0], &value) == FTUN_E_STALE &&
          value == NULL);
    value = stale;
    CHECK(ftun_proxy_slot_pool_release(pool, tokens[0], &value) ==
          FTUN_E_STALE && value == stale);
    tokens[0] = replacement;
  }

  /* 一个 active slab 不计入“保留一个 idle slab”的额度；空闲 slab 在
   * 短暂抖动中保留，复用仍保持地址稳定且 generation 前进。 */
  value = objects[64];
  {
    ftun_proxy_slot_token_t previous = tokens[64];
    CHECK(ftun_proxy_slot_pool_release(pool, tokens[64], &value) == FTUN_OK);
    CHECK(ftun_proxy_slot_pool_trim(pool) == FTUN_OK);
    CHECK(ftun_proxy_slot_pool_get_info(pool, &info) == FTUN_OK &&
          info.active == 64u && info.resident_slabs == 2u);
    value = NULL;
    CHECK(ftun_proxy_slot_pool_acquire(pool, &value, &tokens[64]) == FTUN_OK);
    objects[64] = (test_object_t *)value;
    CHECK(tokens[64].index == previous.index &&
          tokens[64].generation != previous.generation);
    CHECK(ftun_proxy_slot_pool_get(pool, previous, &value) == FTUN_E_STALE &&
          value == NULL);
  }

  for (index = 65u; index < 130u; index++) {
    value = NULL;
    CHECK(ftun_proxy_slot_pool_acquire(pool, &value, &tokens[index]) ==
          FTUN_OK);
    objects[index] = (test_object_t *)value;
  }
  value = (void *)(uintptr_t)1u;
  {
    ftun_proxy_slot_token_t rejected;
    CHECK(ftun_proxy_slot_pool_acquire(pool, &value, &rejected) ==
          FTUN_E_LIMIT && value == NULL);
  }
  for (index = 0u; index < 130u; index++) {
    void *at = NULL;
    ftun_proxy_slot_token_t token;
    CHECK(ftun_proxy_slot_pool_at(pool, index, &at, &token) == FTUN_OK &&
          at != NULL && token.index == index);
  }
  for (index = 0u; index < 130u; index++) {
    value = objects[index];
    CHECK(ftun_proxy_slot_pool_release(pool, tokens[index], &value) ==
          FTUN_OK && value == NULL);
  }
  CHECK(ftun_proxy_slot_pool_trim(pool) == FTUN_OK);
  CHECK(ftun_proxy_slot_pool_get_info(pool, &info) == FTUN_OK &&
        info.active == 0u && info.resident_slabs == 1u &&
        info.allocations == 132u && info.releases == 132u &&
        info.stale_rejections >= 3u);

  /* 被 trim 的 slab 重建后继续使用池级 generation，旧 token 不能命中。 */
  trimmed_token = tokens[64];
  for (index = 0u; index < 65u; index++) {
    value = NULL;
    CHECK(ftun_proxy_slot_pool_acquire(pool, &value, &tokens[index]) ==
          FTUN_OK);
    reused[index] = (test_object_t *)value;
  }
  CHECK(tokens[64].index == trimmed_token.index &&
        tokens[64].generation != trimmed_token.generation);
  CHECK(ftun_proxy_slot_pool_get(pool, trimmed_token, &value) ==
        FTUN_E_STALE && value == NULL);
  for (index = 0u; index < 65u; index++) {
    value = reused[index];
    CHECK(ftun_proxy_slot_pool_release(pool, tokens[index], &value) ==
          FTUN_OK && value == NULL);
  }
  CHECK(ftun_proxy_slot_pool_trim(pool) == FTUN_OK);
  CHECK(ftun_proxy_slot_pool_get_info(pool, &info) == FTUN_OK &&
        info.active == 0u && info.resident_slabs == 1u &&
        info.allocations == 197u && info.releases == 197u &&
        info.stale_rejections >= 4u);
  CHECK(ftun_proxy_slot_pool_destroy(&pool) == FTUN_OK && pool == NULL);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK && budget == NULL);

  CHECK(ftun_budget_create(NULL, 1024u, 0u, &small_budget) == FTUN_OK);
  CHECK(ftun_proxy_slot_pool_create(small_budget, sizeof(test_object_t),
        130u, 64u, 0u, &small_pool) == FTUN_E_LIMIT && small_pool == NULL);
  CHECK(ftun_budget_destroy(&small_budget) == FTUN_OK);
  return 0;
}
