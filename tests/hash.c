#include "core/budget.h"
#include "util/hash.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "hash contract failed at line %d: %s\n", __LINE__, #x); \
    return 1; \
  } \
} while (0)

static ftun_bytes_t bytes(const char *value)
{
  ftun_bytes_t result;
  result.data = (const uint8_t *)value;
  result.length = strlen(value);
  return result;
}

static uint64_t collide(ftun_bytes_t key, void *user)
{
  (void)key;
  (void)user;
  return 3u;
}

static int test_full_key_collision_and_growth(void)
{
  ftun_budget_t *budget = NULL;
  ftun_index_t *index = NULL;
  ftun_budget_usage_t budget_usage;
  ftun_index_usage_t usage;
  uint32_t value;
  char mutable[] = "alpha";
  CHECK(ftun_budget_create(NULL, 65536u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_index_create(budget, 1u, 16u, collide, NULL, &index) == FTUN_OK);
  CHECK(ftun_index_insert(index, bytes(mutable), 10u) == FTUN_OK);
  mutable[0] = 'z';
  CHECK(ftun_index_insert(index, bytes("beta"), 20u) == FTUN_OK);
  CHECK(ftun_index_insert(index, bytes("gamma"), 30u) == FTUN_OK);
  CHECK(ftun_index_insert(index, bytes("delta"), 40u) == FTUN_OK);
  CHECK(ftun_index_insert(index, bytes("epsilon"), 50u) == FTUN_OK);
  CHECK(ftun_index_insert(index, bytes("zeta"), 60u) == FTUN_OK);
  CHECK(ftun_hash_lookup(index, bytes("alpha"), &value) == FTUN_OK &&
        value == 10u);
  CHECK(ftun_hash_lookup(index, bytes("beta"), &value) == FTUN_OK &&
        value == 20u);
  CHECK(ftun_hash_lookup(index, bytes("unknown"), &value) == FTUN_E_EOF &&
        value == UINT32_MAX);
  CHECK(ftun_index_insert(index, bytes("beta"), 21u) == FTUN_OK);
  CHECK(ftun_hash_lookup(index, bytes("beta"), &value) == FTUN_OK &&
        value == 21u);
  CHECK(ftun_index_remove(index, bytes("gamma"), &value) == FTUN_OK &&
        value == 30u);
  CHECK(ftun_hash_lookup(index, bytes("gamma"), &value) == FTUN_E_EOF);
  CHECK(ftun_index_insert(index, bytes("eta"), 70u) == FTUN_OK);
  CHECK(ftun_hash_lookup(index, bytes("eta"), &value) == FTUN_OK &&
        value == 70u);
  CHECK(ftun_index_get_usage(index, &usage) == FTUN_OK &&
        usage.entries == 6u && usage.capacity >= 16u &&
        usage.key_bytes != 0u);
  CHECK(ftun_index_destroy(&index) == FTUN_OK && index == NULL);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK &&
        budget_usage.used == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int test_limits_and_persistent_version(void)
{
  ftun_budget_t *budget = NULL;
  ftun_index_t *index = NULL;
  uint64_t first;
  uint64_t second;
  uint32_t value;
  CHECK(ftun_budget_create(NULL, 4096u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_index_create(budget, 1u, 2u, NULL, NULL, &index) == FTUN_OK);
  CHECK(ftun_index_insert(index, bytes("one"), 1u) == FTUN_OK);
  CHECK(ftun_index_insert(index, bytes("two"), 2u) == FTUN_OK);
  CHECK(ftun_index_insert(index, bytes("three"), 3u) == FTUN_E_LIMIT);
  CHECK(ftun_hash_lookup(NULL, bytes("one"), &value) == FTUN_E_INVALID);
  CHECK(ftun_hash_lookup(index, (ftun_bytes_t){NULL, 1u}, &value) ==
        FTUN_E_INVALID);
  CHECK(ftun_persistent_hash(1u, bytes("identity"), &first) == FTUN_OK);
  CHECK(ftun_persistent_hash(1u, bytes("identity"), &second) == FTUN_OK &&
        first == second && first != 0u);
  CHECK(ftun_persistent_hash(2u, bytes("identity"), &second) ==
        FTUN_E_UNSUPPORTED && second == 0u);
  CHECK(ftun_index_destroy(&index) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(void)
{
  CHECK(test_full_key_collision_and_growth() == 0);
  CHECK(test_limits_and_persistent_version() == 0);
  return 0;
}
