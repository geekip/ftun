#include "core/budget.h"
#include <stdint.h>
#include <stdio.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "budget contract failed: %s\n", #x); \
    return 1; \
  } \
} while (0)

static int check_usage(ftun_budget_t *budget, size_t used, size_t normal,
                       size_t total, size_t children)
{
  ftun_budget_usage_t usage;
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
  CHECK(usage.used == used);
  CHECK(usage.normal_available == normal);
  CHECK(usage.total_available == total);
  CHECK(usage.child_count == children);
  return 0;
}

int main(void)
{
  ftun_budget_t *global = (ftun_budget_t *)(uintptr_t)1;
  ftun_budget_t *module = (ftun_budget_t *)(uintptr_t)1;
  ftun_budget_t *nested = (ftun_budget_t *)(uintptr_t)1;
  ftun_reservation_t *normal = (ftun_reservation_t *)(uintptr_t)1;
  ftun_reservation_t *cleanup = (ftun_reservation_t *)(uintptr_t)1;
  ftun_reservation_t *rejected = (ftun_reservation_t *)(uintptr_t)1;
  ftun_budget_usage_t usage;

  CHECK(ftun_budget_create(NULL, 100u, 20u, &global) == FTUN_OK);
  CHECK(ftun_budget_create(global, 60u, 10u, &module) == FTUN_OK);
  CHECK(check_usage(global, 0u, 80u, 100u, 1u) == 0);
  CHECK(check_usage(module, 0u, 50u, 60u, 0u) == 0);
  CHECK(ftun_budget_create(module, 1u, 0u, &nested) == FTUN_E_INVALID);
  CHECK(nested == NULL);

  CHECK(ftun_budget_reserve(module, 40u, &normal) == FTUN_OK);
  CHECK(check_usage(global, 40u, 40u, 60u, 1u) == 0);
  CHECK(check_usage(module, 40u, 10u, 20u, 0u) == 0);
  CHECK(ftun_budget_reserve(module, 11u, &rejected) == FTUN_E_LIMIT);
  CHECK(rejected == NULL);
  CHECK(check_usage(global, 40u, 40u, 60u, 1u) == 0);
  CHECK(check_usage(module, 40u, 10u, 20u, 0u) == 0);

  CHECK(ftun_budget_reserve_cleanup(module, 15u, &cleanup) == FTUN_OK);
  CHECK(check_usage(global, 55u, 25u, 45u, 1u) == 0);
  CHECK(check_usage(module, 55u, 0u, 5u, 0u) == 0);
  CHECK(ftun_budget_reserve(module, 1u, &rejected) == FTUN_E_LIMIT);
  CHECK(rejected == NULL);
  CHECK(ftun_budget_destroy(&module) == FTUN_E_AGAIN && module != NULL);
  CHECK(ftun_budget_destroy(&global) == FTUN_E_AGAIN && global != NULL);

  CHECK(ftun_reservation_release(&cleanup) == FTUN_OK && cleanup == NULL);
  CHECK(ftun_reservation_release(&cleanup) == FTUN_OK);
  CHECK(ftun_reservation_release(&normal) == FTUN_OK && normal == NULL);
  CHECK(check_usage(global, 0u, 80u, 100u, 1u) == 0);
  CHECK(check_usage(module, 0u, 50u, 60u, 0u) == 0);
  CHECK(ftun_budget_destroy(&module) == FTUN_OK && module == NULL);
  CHECK(check_usage(global, 0u, 80u, 100u, 0u) == 0);
  CHECK(ftun_budget_destroy(&global) == FTUN_OK && global == NULL);
  CHECK(ftun_budget_destroy(&global) == FTUN_OK);

  CHECK(ftun_budget_create(NULL, 56u, 0u, &global) == FTUN_OK);
  CHECK(ftun_budget_create(global, 100u, 0u, &module) == FTUN_OK);
  CHECK(ftun_budget_reserve(module, 56u, &normal) == FTUN_OK);
  CHECK(ftun_budget_reserve(module, 1u, &rejected) == FTUN_E_LIMIT);
  CHECK(rejected == NULL);
  CHECK(check_usage(module, 56u, 44u, 44u, 0u) == 0);
  CHECK(ftun_reservation_release(&normal) == FTUN_OK);
  CHECK(ftun_budget_destroy(&module) == FTUN_OK);
  CHECK(ftun_budget_destroy(&global) == FTUN_OK);

  global = (ftun_budget_t *)(uintptr_t)1;
  CHECK(ftun_budget_create(NULL, 10u, 11u, &global) == FTUN_E_INVALID);
  CHECK(global == NULL);
  CHECK(ftun_budget_create(NULL, 0u, 0u, &global) == FTUN_OK);
  CHECK(ftun_budget_reserve(global, 0u, &rejected) == FTUN_E_INVALID);
  CHECK(rejected == NULL);
  CHECK(ftun_budget_reserve(global, 1u, &rejected) == FTUN_E_LIMIT);
  CHECK(rejected == NULL);
  CHECK(ftun_budget_get_usage(NULL, &usage) == FTUN_E_INVALID);
  CHECK(usage.limit == 0u && usage.used == 0u);
  CHECK(ftun_budget_get_usage(global, NULL) == FTUN_E_INVALID);
  CHECK(ftun_budget_reserve(NULL, 1u, &rejected) == FTUN_E_INVALID);
  CHECK(rejected == NULL);
  CHECK(ftun_budget_reserve(global, 1u, NULL) == FTUN_E_INVALID);
  CHECK(ftun_reservation_release(NULL) == FTUN_E_INVALID);
  CHECK(ftun_budget_destroy(NULL) == FTUN_E_INVALID);
  CHECK(ftun_budget_destroy(&global) == FTUN_OK);

  CHECK(ftun_budget_create(NULL, SIZE_MAX, 0u, &global) == FTUN_OK);
  CHECK(ftun_budget_reserve(global, SIZE_MAX, &normal) == FTUN_OK);
  CHECK(check_usage(global, SIZE_MAX, 0u, 0u, 0u) == 0);
  CHECK(ftun_budget_reserve_cleanup(global, 1u, &rejected) == FTUN_E_LIMIT);
  CHECK(rejected == NULL);
  CHECK(ftun_reservation_release(&normal) == FTUN_OK);
  CHECK(ftun_budget_destroy(&global) == FTUN_OK);
  return 0;
}
