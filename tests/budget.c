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
  bool same_root = false;

  CHECK(ftun_budget_create(NULL, 100u, 20u, &global) == FTUN_OK);
  CHECK(ftun_budget_create(global, 60u, 10u, &module) == FTUN_OK);
  CHECK(check_usage(global, 0u, 80u, 100u, 1u) == 0);
  CHECK(check_usage(module, 0u, 50u, 60u, 0u) == 0);
  CHECK(ftun_budget_create(module, 1u, 0u, &nested) == FTUN_OK);
  CHECK(ftun_budget_same_root(global, nested, &same_root) == FTUN_OK &&
        same_root);
  CHECK(check_usage(module, 0u, 50u, 60u, 1u) == 0);

  CHECK(ftun_budget_reserve(module, 40u, &normal) == FTUN_OK);
  CHECK(check_usage(global, 40u, 40u, 60u, 1u) == 0);
  CHECK(check_usage(module, 40u, 10u, 20u, 1u) == 0);
  CHECK(ftun_budget_reserve(module, 11u, &rejected) == FTUN_E_LIMIT);
  CHECK(rejected == NULL);
  CHECK(check_usage(global, 40u, 40u, 60u, 1u) == 0);
  CHECK(check_usage(module, 40u, 10u, 20u, 1u) == 0);

  CHECK(ftun_budget_reserve_cleanup(module, 15u, &cleanup) == FTUN_OK);
  CHECK(check_usage(global, 55u, 25u, 45u, 1u) == 0);
  CHECK(check_usage(module, 55u, 0u, 5u, 1u) == 0);
  CHECK(ftun_budget_reserve(module, 1u, &rejected) == FTUN_E_LIMIT);
  CHECK(rejected == NULL);
  CHECK(ftun_budget_destroy(&module) == FTUN_E_AGAIN && module != NULL);
  CHECK(ftun_budget_destroy(&global) == FTUN_E_AGAIN && global != NULL);

  CHECK(ftun_reservation_release(&cleanup) == FTUN_OK && cleanup == NULL);
  CHECK(ftun_reservation_release(&cleanup) == FTUN_OK);
  CHECK(ftun_reservation_release(&normal) == FTUN_OK && normal == NULL);
  CHECK(check_usage(global, 0u, 80u, 100u, 1u) == 0);
  CHECK(check_usage(module, 0u, 50u, 60u, 1u) == 0);
  CHECK(ftun_budget_destroy(&nested) == FTUN_OK && nested == NULL);
  CHECK(ftun_budget_destroy(&module) == FTUN_OK && module == NULL);
  CHECK(check_usage(global, 0u, 80u, 100u, 0u) == 0);
  CHECK(ftun_budget_destroy(&global) == FTUN_OK && global == NULL);
  CHECK(ftun_budget_destroy(&global) == FTUN_OK);
  CHECK(ftun_budget_same_root(NULL, module, &same_root) == FTUN_E_INVALID &&
        !same_root);

  CHECK(ftun_budget_create(NULL, 56u, 0u, &global) == FTUN_OK);
  CHECK(ftun_budget_create(global, 100u, 0u, &module) == FTUN_OK);
  CHECK(ftun_budget_reserve(module, 56u, &normal) == FTUN_OK);
  CHECK(ftun_budget_reserve(module, 1u, &rejected) == FTUN_E_LIMIT);
  CHECK(rejected == NULL);
  /* Availability is path-effective: the wider child cannot advertise
   * capacity which its root cannot honor. */
  CHECK(check_usage(module, 56u, 0u, 0u, 0u) == 0);
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

  /* Global/module/object hierarchy: unused guarantees are protected while
   * siblings borrow shared memory, descriptors and queue credits. */
  {
    ftun_budget_options_t root_options = {
      {100u, 12u, 10u}, {10u, 2u, 1u}, {0u, 0u, 0u}
    };
    ftun_budget_options_t control_options = {
      {100u, 12u, 10u}, {5u, 1u, 1u}, {20u, 3u, 2u}
    };
    ftun_budget_options_t data_options = {
      {100u, 12u, 10u}, {0u, 0u, 0u}, {30u, 4u, 3u}
    };
    ftun_budget_options_t object_options = {
      {80u, 8u, 8u}, {0u, 0u, 0u}, {0u, 0u, 0u}
    };
    ftun_budget_t *control = NULL;
    ftun_budget_t *data = NULL;
    ftun_budget_t *object = NULL;
    ftun_reservation_t *data_borrow = NULL;
    ftun_reservation_t *object_minimum = NULL;
    ftun_reservation_t *control_work = NULL;
    ftun_reservation_t *emergency = NULL;

    CHECK(ftun_budget_create_resources(NULL, &root_options, &global) == FTUN_OK);
    CHECK(ftun_budget_create_resources(global, &control_options,
                                       &control) == FTUN_OK);
    CHECK(ftun_budget_create_resources(global, &data_options, &data) == FTUN_OK);
    CHECK(ftun_budget_create_resources(data, &object_options,
                                       &object) == FTUN_OK);
    CHECK(ftun_budget_get_usage(global, &usage) == FTUN_OK);
    CHECK(usage.normal_available_resources.memory_bytes == 40u &&
          usage.normal_available_resources.descriptors == 3u &&
          usage.normal_available_resources.queue_slots == 4u &&
          usage.child_count == 2u);

    /* An accepted object converts the module's protected share into a held
     * minimum reservation before later work consumes borrowable capacity. */
    CHECK(ftun_budget_reserve_resources(object,
      (ftun_budget_resources_t){30u, 4u, 3u}, &object_minimum) == FTUN_OK);
    CHECK(ftun_budget_reserve_resources(data,
      (ftun_budget_resources_t){40u, 3u, 4u}, &data_borrow) == FTUN_OK);
    CHECK(ftun_budget_reserve_resources(data,
      (ftun_budget_resources_t){1u, 0u, 0u}, &rejected) == FTUN_E_LIMIT);
    CHECK(rejected == NULL);
    CHECK(ftun_budget_reserve_resources(control,
      (ftun_budget_resources_t){20u, 3u, 2u}, &control_work) == FTUN_OK);
    CHECK(ftun_budget_get_usage(control, &usage) == FTUN_OK);
    CHECK(usage.borrowed_resources.memory_bytes == 0u &&
          usage.borrowed_resources.descriptors == 0u &&
          usage.borrowed_resources.queue_slots == 0u);
    CHECK(ftun_budget_get_usage(global, &usage) == FTUN_OK);
    CHECK(usage.used_resources.memory_bytes == 90u &&
          usage.used_resources.descriptors == 10u &&
          usage.used_resources.queue_slots == 9u &&
          usage.normal_available_resources.memory_bytes == 0u &&
          usage.rejected_reservations == 0u);

    /* Normal admission is closed, but bounded cleanup can use the root's
     * final reserve in all three dimensions. */
    CHECK(ftun_budget_reserve_cleanup_resources(control,
      (ftun_budget_resources_t){5u, 1u, 1u}, &emergency) == FTUN_OK);
    CHECK(ftun_budget_get_usage(global, &usage) == FTUN_OK);
    CHECK(usage.high_watermarks.memory_bytes == 95u &&
          usage.high_watermarks.descriptors == 11u &&
          usage.high_watermarks.queue_slots == 10u);

    CHECK(ftun_reservation_release(&emergency) == FTUN_OK);
    CHECK(ftun_reservation_release(&control_work) == FTUN_OK);
    CHECK(ftun_reservation_release(&object_minimum) == FTUN_OK);
    CHECK(ftun_reservation_release(&data_borrow) == FTUN_OK);
    CHECK(ftun_budget_destroy(&object) == FTUN_OK);
    CHECK(ftun_budget_destroy(&data) == FTUN_OK);
    CHECK(ftun_budget_destroy(&control) == FTUN_OK);
    CHECK(ftun_budget_get_usage(global, &usage) == FTUN_OK &&
          usage.used == 0u && usage.child_count == 0u);
    CHECK(ftun_budget_destroy(&global) == FTUN_OK);
  }
  return 0;
}
