#include "core/limits.h"
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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
  CHECK(usage.used_resources.memory_bytes == used);
  CHECK(usage.normal_available_resources.memory_bytes == normal);
  CHECK(usage.total_available_resources.memory_bytes == total);
  CHECK(usage.child_count == children);
  return 0;
}

typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  size_t arrived;
  size_t generation;
  size_t participants;
} test_barrier_t;

static int barrier_init(test_barrier_t *barrier, size_t participants)
{
  barrier->arrived = 0u;
  barrier->generation = 0u;
  barrier->participants = participants;
  CHECK(pthread_mutex_init(&barrier->mutex, NULL) == 0);
  CHECK(pthread_cond_init(&barrier->condition, NULL) == 0);
  return 0;
}

static void barrier_wait(test_barrier_t *barrier)
{
  size_t generation;
  (void)pthread_mutex_lock(&barrier->mutex);
  generation = barrier->generation;
  if (++barrier->arrived == barrier->participants) {
    barrier->arrived = 0u;
    barrier->generation++;
    (void)pthread_cond_broadcast(&barrier->condition);
  } else {
    while (barrier->generation == generation)
      (void)pthread_cond_wait(&barrier->condition, &barrier->mutex);
  }
  (void)pthread_mutex_unlock(&barrier->mutex);
}

static int barrier_destroy(test_barrier_t *barrier)
{
  CHECK(pthread_cond_destroy(&barrier->condition) == 0);
  CHECK(pthread_mutex_destroy(&barrier->mutex) == 0);
  return 0;
}

#define ADMISSION_ROUNDS 300u

typedef struct {
  ftun_budget_t *leaf;
  test_barrier_t *barrier;
  ftun_reservation_t reservation;
  ftun_status_t status;
} admission_state_t;

static void *admit_concurrently(void *user)
{
  admission_state_t *state = user;
  size_t round;
  for (round = 0u; round < ADMISSION_ROUNDS; round++) {
    barrier_wait(state->barrier);
    state->status = ftun_budget_reserve_resources(state->leaf,
      (ftun_budget_resources_t){1u, 1u, 1u}, &state->reservation);
    barrier_wait(state->barrier);
    /* owner 在第三道屏障前接管并释放成功的 reservation。 */
    barrier_wait(state->barrier);
  }
  return NULL;
}

static int concurrent_admission(void)
{
  ftun_budget_options_t options = {{1u, 1u, 1u}, {0u, 0u, 0u}, {0u, 0u, 0u}};
  ftun_budget_t *root = NULL, *modules[2] = {NULL, NULL};
  ftun_budget_t *leaves[2] = {NULL, NULL};
  admission_state_t states[2];
  pthread_t threads[2];
  test_barrier_t barrier;
  ftun_budget_usage_t usage;
  size_t root_metadata, tree_metadata, index, round;
  CHECK(ftun_budget_create_resources(NULL, &options, &root) == FTUN_OK);
  CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK);
  root_metadata = usage.metadata_bytes;
  CHECK(root_metadata != 0u);
  CHECK(barrier_init(&barrier, 3u) == 0);
  for (index = 0u; index < 2u; index++) {
    CHECK(ftun_budget_create_resources(root, &options, &modules[index]) == FTUN_OK);
    CHECK(ftun_budget_create_resources(modules[index], &options, &leaves[index]) == FTUN_OK);
    states[index].leaf = leaves[index];
    states[index].barrier = &barrier;
    states[index].reservation = (ftun_reservation_t){0};
    states[index].status = FTUN_E_STATE_CORRUPT;
    CHECK(pthread_create(&threads[index], NULL, admit_concurrently, &states[index]) == 0);
  }
  CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK);
  tree_metadata = usage.metadata_bytes;
  CHECK(tree_metadata > root_metadata);
  for (round = 0u; round < ADMISSION_ROUNDS; round++) {
    size_t accepted = 0u;
    barrier_wait(&barrier);
    barrier_wait(&barrier);
    for (index = 0u; index < 2u; index++) {
      CHECK(states[index].status == FTUN_OK || states[index].status == FTUN_E_LIMIT);
      if (states[index].status == FTUN_OK) accepted++;
      else CHECK((states[index].reservation).budget == NULL);
    }
    CHECK(accepted == 1u);
    CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK);
    CHECK(usage.used_resources.memory_bytes == 1u &&
          usage.used_resources.descriptors == 1u &&
          usage.used_resources.queue_slots == 1u &&
          usage.metadata_bytes == tree_metadata);
    for (index = 0u; index < 2u; index++) {
      ftun_reservation_release(&states[index].reservation);
    }
    CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK);
    CHECK(usage.used_resources.memory_bytes == 0u && usage.metadata_bytes == tree_metadata);
    barrier_wait(&barrier);
  }
  for (index = 0u; index < 2u; index++) {
    CHECK(pthread_join(threads[index], NULL) == 0);
    CHECK(ftun_budget_destroy(&leaves[index]) == FTUN_OK);
    CHECK(ftun_budget_destroy(&modules[index]) == FTUN_OK);
  }
  CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK);
  CHECK(usage.metadata_bytes == root_metadata && usage.child_count == 0u);
  CHECK(ftun_budget_destroy(&root) == FTUN_OK);
  CHECK(barrier_destroy(&barrier) == 0);
  return 0;
}

typedef struct {
  pthread_mutex_t mutex;
  ftun_budget_t *root;
  size_t done;
} churn_shared_t;

typedef struct {
  churn_shared_t *shared;
  int result;
} churn_state_t;

static int run_churn(churn_shared_t *shared)
{
  ftun_budget_options_t module_options = {
    {64u, 32u, 32u}, {0u, 0u, 0u}, {8u, 4u, 4u}
  };
  ftun_budget_options_t leaf_options = {
    {64u, 32u, 32u}, {0u, 0u, 0u}, {0u, 0u, 0u}
  };
  size_t round;
  for (round = 0u; round < 300u; round++) {
    ftun_budget_t *module = NULL, *leaf = NULL;
    ftun_reservation_t reservations[8] = {0};
    ftun_reservation_t cleanup = (ftun_reservation_t){0};
    ftun_budget_usage_t usage;
    size_t index;
    CHECK(ftun_budget_create_resources(shared->root, &module_options, &module) == FTUN_OK);
    CHECK(ftun_budget_create_resources(module, &leaf_options, &leaf) == FTUN_OK);
    for (index = 0u; index < 8u; index++) {
      ftun_status_t status = ftun_budget_reserve_resources(leaf,
        (ftun_budget_resources_t){1u, 1u, 1u}, &reservations[index]);
      CHECK(status == FTUN_OK || status == FTUN_E_LIMIT);
      if ((reservations[index]).budget != NULL) {
        status = ftun_reservation_resize(&(reservations[index]),
          (ftun_budget_resources_t){2u, 2u, 2u});
        CHECK(status == FTUN_OK || status == FTUN_E_LIMIT);
        CHECK(ftun_reservation_resize(&(reservations[index]),
          (ftun_budget_resources_t){1u, 1u, 1u}) == FTUN_OK);
      }
      CHECK(ftun_budget_get_usage(leaf, &usage) == FTUN_OK);
      CHECK(usage.used_resources.memory_bytes == usage.used_resources.descriptors &&
            usage.used_resources.memory_bytes == usage.used_resources.queue_slots);
    }
    CHECK(ftun_budget_reserve_cleanup_resources(leaf,
      (ftun_budget_resources_t){1u, 1u, 1u}, &cleanup) == FTUN_OK);
    ftun_reservation_release(&cleanup);
    for (index = 0u; index < 8u; index++)
      ftun_reservation_release(&reservations[index]);
    CHECK(ftun_budget_destroy(&leaf) == FTUN_OK);
    CHECK(ftun_budget_destroy(&module) == FTUN_OK);
  }
  return 0;
}

static void *churn(void *user)
{
  churn_state_t *state = user;
  state->result = run_churn(state->shared);
  (void)pthread_mutex_lock(&state->shared->mutex);
  state->shared->done++;
  (void)pthread_mutex_unlock(&state->shared->mutex);
  return NULL;
}

static int concurrent_tree_lifecycle(void)
{
  ftun_budget_options_t options = {
    {64u, 64u, 64u}, {8u, 8u, 8u}, {0u, 0u, 0u}
  };
  churn_shared_t shared;
  churn_state_t states[4];
  pthread_t threads[4];
  ftun_budget_usage_t usage;
  size_t metadata, index, done = 0u;
  shared.done = 0u;
  CHECK(pthread_mutex_init(&shared.mutex, NULL) == 0);
  CHECK(ftun_budget_create_resources(NULL, &options, &shared.root) == FTUN_OK);
  CHECK(ftun_budget_get_usage(shared.root, &usage) == FTUN_OK);
  metadata = usage.metadata_bytes;
  for (index = 0u; index < 4u; index++) {
    states[index].shared = &shared;
    states[index].result = -1;
    CHECK(pthread_create(&threads[index], NULL, churn, &states[index]) == 0);
  }
  while (done != 4u) {
    CHECK(ftun_budget_get_usage(shared.root, &usage) == FTUN_OK);
    CHECK(usage.used_resources.memory_bytes == usage.used_resources.descriptors &&
          usage.used_resources.memory_bytes == usage.used_resources.queue_slots &&
          usage.used_resources.descriptors <= options.limit.descriptors &&
          usage.child_count <= 4u && usage.metadata_bytes >= metadata);
    (void)pthread_mutex_lock(&shared.mutex);
    done = shared.done;
    (void)pthread_mutex_unlock(&shared.mutex);
    (void)sched_yield();
  }
  for (index = 0u; index < 4u; index++) {
    CHECK(pthread_join(threads[index], NULL) == 0);
    CHECK(states[index].result == 0);
  }
  CHECK(ftun_budget_get_usage(shared.root, &usage) == FTUN_OK);
  CHECK(usage.used_resources.memory_bytes == 0u && usage.child_count == 0u && usage.metadata_bytes == metadata);
  CHECK(ftun_budget_destroy(&shared.root) == FTUN_OK);
  CHECK(pthread_mutex_destroy(&shared.mutex) == 0);
  return 0;
}

static int reservation_resize(void)
{
  ftun_budget_t *root = NULL, *first = NULL, *second = NULL;
  ftun_reservation_t value = (ftun_reservation_t){0}, cleanup = (ftun_reservation_t){0};
  ftun_budget_options_t root_options = {{100u, 10u, 10u}, {10u, 1u, 1u}, {0}};
  ftun_budget_options_t child_options = {{90u, 9u, 9u}, {0}, {20u, 2u, 2u}};
  ftun_budget_usage_t before, after;
  CHECK(ftun_budget_create_resources(NULL, &root_options, &root) == FTUN_OK);
  CHECK(ftun_budget_create_resources(root, &child_options, &first) == FTUN_OK);
  CHECK(ftun_budget_create_resources(root, &child_options, &second) == FTUN_OK);
  CHECK(ftun_budget_reserve_resources(first, (ftun_budget_resources_t){10u, 1u, 1u}, &value) == FTUN_OK);
  CHECK(ftun_budget_get_usage(root, &before) == FTUN_OK);
  CHECK(ftun_reservation_resize(&(value), (ftun_budget_resources_t){70u, 7u, 7u}) == FTUN_OK);
  CHECK(ftun_reservation_resize(&(value), (ftun_budget_resources_t){71u, 6u, 6u}) == FTUN_E_LIMIT);
  CHECK(ftun_budget_get_usage(root, &after) == FTUN_OK && after.used_resources.memory_bytes == 70u &&
    after.used_resources.descriptors == 7u && after.used_resources.queue_slots == 7u);
  CHECK(after.metadata_bytes == before.metadata_bytes);
  CHECK(ftun_reservation_resize(&(value), (ftun_budget_resources_t){5u, 8u, 1u}) == FTUN_E_LIMIT);
  CHECK(ftun_reservation_resize(&(value), (ftun_budget_resources_t){20u, 2u, 2u}) == FTUN_OK);
  CHECK(ftun_reservation_resize(&(value), (ftun_budget_resources_t){10u, 3u, 1u}) == FTUN_OK);
  CHECK(ftun_budget_get_usage(root, &after) == FTUN_OK && after.used_resources.memory_bytes == 10u &&
    after.used_resources.descriptors == 3u && after.used_resources.queue_slots == 1u);
  CHECK(ftun_reservation_resize(&(value), (ftun_budget_resources_t){0}) == FTUN_E_INVALID);
  CHECK(ftun_reservation_resize(NULL, (ftun_budget_resources_t){1u, 0u, 0u}) == FTUN_E_INVALID);
  ftun_reservation_release(&value);
  CHECK(ftun_budget_reserve_cleanup_resources(root, (ftun_budget_resources_t){1u, 1u, 1u}, &cleanup) == FTUN_OK);
  CHECK(ftun_reservation_resize(&(cleanup), (ftun_budget_resources_t){100u, 10u, 10u}) == FTUN_OK);
  CHECK(ftun_reservation_resize(&(cleanup), (ftun_budget_resources_t){101u, 10u, 10u}) == FTUN_E_LIMIT);
  CHECK(ftun_reservation_resize(&(cleanup), (ftun_budget_resources_t){1u, 1u, 1u}) == FTUN_OK);
  ftun_reservation_release(&cleanup);
  CHECK(ftun_budget_destroy(&first) == FTUN_OK && ftun_budget_destroy(&second) == FTUN_OK);
  CHECK(ftun_budget_destroy(&root) == FTUN_OK);
  return 0;
}

static int independent_dimensions(void)
{
  ftun_budget_t *budget = NULL;
  ftun_reservation_t normal = (ftun_reservation_t){0}, cleanup = (ftun_reservation_t){0}, memory = (ftun_reservation_t){0};
  ftun_budget_options_t options = {{100u, 10u, 10u}, {10u, 1u, 1u}, {0}};
  ftun_budget_usage_t usage;
  CHECK(ftun_budget_create_resources(NULL, &options, &budget) == FTUN_OK);
  CHECK(ftun_budget_reserve_resources(budget, (ftun_budget_resources_t){10u, 1u, 0u}, &normal) == FTUN_OK);
  CHECK(ftun_budget_reserve_cleanup_resources(budget, (ftun_budget_resources_t){0u, 9u, 0u}, &cleanup) == FTUN_OK);
  CHECK(ftun_budget_reserve(budget, 1u, &memory) == FTUN_OK);
  ftun_reservation_release(&memory);
  CHECK(ftun_reservation_resize(&(normal), (ftun_budget_resources_t){20u, 0u, 0u}) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 20u && usage.used_resources.descriptors == 9u);
  CHECK(ftun_budget_reserve(budget, 71u, &memory) == FTUN_E_LIMIT && (memory).budget == NULL);
  ftun_reservation_release(&normal); ftun_reservation_release(&cleanup);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int cleanup_and_guarantees(void)
{
  ftun_budget_options_t options = {{100u, 100u, 100u}, {0}, {0}};
  ftun_budget_t *root = NULL, *left = NULL, *right = NULL;
  ftun_reservation_t cleanup = {0}, first = {0}, second = {0}, rejected = {0};
  ftun_budget_usage_t before, after;
  CHECK(ftun_budget_create_resources(NULL, &options, &root) == FTUN_OK);
  options.guarantee = (ftun_budget_resources_t){40u, 40u, 40u};
  CHECK(ftun_budget_create_resources(root, &options, &left) == FTUN_OK);
  CHECK(ftun_budget_create_resources(root, &options, &right) == FTUN_OK);
  CHECK(ftun_budget_reserve_cleanup_resources(root,
    (ftun_budget_resources_t){50u, 50u, 50u}, &cleanup) == FTUN_OK);
  CHECK(ftun_budget_reserve_resources(left, (ftun_budget_resources_t){10u, 10u, 10u}, &first) == FTUN_OK);
  CHECK(ftun_budget_reserve_resources(right, (ftun_budget_resources_t){10u, 10u, 10u}, &second) == FTUN_OK);
  CHECK(ftun_budget_get_usage(root, &before) == FTUN_OK);
  CHECK(ftun_budget_reserve(left, 1u, &rejected) == FTUN_E_LIMIT && rejected.budget == NULL);
  CHECK(ftun_budget_get_usage(root, &after) == FTUN_OK);
  CHECK(memcmp(&before.used_resources, &after.used_resources, sizeof(before.used_resources)) == 0);
  ftun_reservation_release(&first);
  ftun_reservation_release(&second);
  ftun_reservation_release(&cleanup);
  CHECK(ftun_budget_destroy(&right) == FTUN_OK);
  CHECK(ftun_budget_destroy(&left) == FTUN_OK);
  CHECK(ftun_budget_destroy(&root) == FTUN_OK);
  return 0;
}

int main(void)
{
  CHECK(cleanup_and_guarantees() == 0);
  CHECK(reservation_resize() == 0);
  CHECK(independent_dimensions() == 0);
  ftun_budget_t *global = (ftun_budget_t *)(uintptr_t)1;
  ftun_budget_t *module = (ftun_budget_t *)(uintptr_t)1;
  ftun_budget_t *nested = (ftun_budget_t *)(uintptr_t)1;
  ftun_reservation_t normal = {.budget = (ftun_budget_t *)(uintptr_t)1};
  ftun_reservation_t cleanup = {.budget = (ftun_budget_t *)(uintptr_t)1};
  ftun_reservation_t rejected = {.budget = (ftun_budget_t *)(uintptr_t)1};
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
  CHECK((rejected).budget == NULL);
  CHECK(check_usage(global, 40u, 40u, 60u, 1u) == 0);
  CHECK(check_usage(module, 40u, 10u, 20u, 1u) == 0);

  CHECK(ftun_budget_reserve_cleanup(module, 15u, &cleanup) == FTUN_OK);
  CHECK(check_usage(global, 55u, 25u, 45u, 1u) == 0);
  CHECK(check_usage(module, 55u, 0u, 5u, 1u) == 0);
  CHECK(ftun_budget_reserve(module, 1u, &rejected) == FTUN_E_LIMIT);
  CHECK((rejected).budget == NULL);
  CHECK(ftun_budget_destroy(&module) == FTUN_E_AGAIN && module != NULL);
  CHECK(ftun_budget_destroy(&global) == FTUN_E_AGAIN && global != NULL);

  ftun_reservation_release(&cleanup); CHECK((cleanup).budget == NULL);
  ftun_reservation_release(&cleanup);
  ftun_reservation_release(&normal); CHECK((normal).budget == NULL);
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
  CHECK((rejected).budget == NULL);
  /* Availability is path-effective: the wider child cannot advertise
   * capacity which its root cannot honor. */
  CHECK(check_usage(module, 56u, 0u, 0u, 0u) == 0);
  ftun_reservation_release(&normal);
  CHECK(ftun_budget_destroy(&module) == FTUN_OK);
  CHECK(ftun_budget_destroy(&global) == FTUN_OK);

  global = (ftun_budget_t *)(uintptr_t)1;
  CHECK(ftun_budget_create(NULL, 10u, 11u, &global) == FTUN_E_INVALID);
  CHECK(global == NULL);
  CHECK(ftun_budget_create(NULL, 0u, 0u, &global) == FTUN_OK);
  CHECK(ftun_budget_reserve(global, 0u, &rejected) == FTUN_E_INVALID);
  CHECK((rejected).budget == NULL);
  CHECK(ftun_budget_reserve(global, 1u, &rejected) == FTUN_E_LIMIT);
  CHECK((rejected).budget == NULL);
  CHECK(ftun_budget_get_usage(NULL, &usage) == FTUN_E_INVALID);
  CHECK(usage.limits.memory_bytes == 0u && usage.used_resources.memory_bytes == 0u);
  CHECK(ftun_budget_get_usage(global, NULL) == FTUN_E_INVALID);
  CHECK(ftun_budget_reserve(NULL, 1u, &rejected) == FTUN_E_INVALID);
  CHECK((rejected).budget == NULL);
  CHECK(ftun_budget_reserve(global, 1u, NULL) == FTUN_E_INVALID);
  CHECK(ftun_budget_destroy(NULL) == FTUN_E_INVALID);
  CHECK(ftun_budget_destroy(&global) == FTUN_OK);

  CHECK(ftun_budget_create(NULL, SIZE_MAX, 0u, &global) == FTUN_OK);
  CHECK(ftun_budget_reserve(global, SIZE_MAX, &normal) == FTUN_OK);
  CHECK(check_usage(global, SIZE_MAX, 0u, 0u, 0u) == 0);
  CHECK(ftun_budget_reserve_cleanup(global, 1u, &rejected) == FTUN_E_LIMIT);
  CHECK((rejected).budget == NULL);
  ftun_reservation_release(&normal);
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
    ftun_reservation_t data_borrow = (ftun_reservation_t){0};
    ftun_reservation_t object_minimum = (ftun_reservation_t){0};
    ftun_reservation_t control_work = (ftun_reservation_t){0};
    ftun_reservation_t emergency = (ftun_reservation_t){0};

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
    CHECK((rejected).budget == NULL);
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

    ftun_reservation_release(&emergency);
    ftun_reservation_release(&control_work);
    ftun_reservation_release(&object_minimum);
    ftun_reservation_release(&data_borrow);
    CHECK(ftun_budget_destroy(&object) == FTUN_OK);
    CHECK(ftun_budget_destroy(&data) == FTUN_OK);
    CHECK(ftun_budget_destroy(&control) == FTUN_OK);
    CHECK(ftun_budget_get_usage(global, &usage) == FTUN_OK &&
          usage.used_resources.memory_bytes == 0u && usage.child_count == 0u);
    CHECK(ftun_budget_destroy(&global) == FTUN_OK);
  }
  CHECK(concurrent_admission() == 0);
  CHECK(concurrent_tree_lifecycle() == 0);
  return 0;
}
