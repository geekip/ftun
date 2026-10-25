#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include "core/budget.h"

static void *test_malloc(size_t size);
static void *test_calloc(size_t count, size_t size);
static void test_free(void *pointer);
static int test_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);

/* 只替换分配/初始化边界，准入与记账使用原实现。 */
#define malloc test_malloc
#define calloc test_calloc
#define free test_free
#define pthread_mutex_init test_mutex_init
#include "../src/core/budget.c"
#undef malloc
#undef calloc
#undef free
#undef pthread_mutex_init

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "budget fault contract failed at %d: %s\n", __LINE__, #x); \
  return 1; \
} } while (0)

static pthread_mutex_t control = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static pthread_key_t thread_index;
static size_t live_allocations;
static size_t init_calls;
static int fail_malloc, fail_calloc, fail_init;
static int gate_kind, gate_arrived, first_finished;

static void allocation_gate(int kind)
{
  if (gate_kind != kind) return;
  (void)pthread_mutex_lock(&control);
  gate_arrived++;
  (void)pthread_cond_broadcast(&condition);
  while (gate_arrived != 2)
    (void)pthread_cond_wait(&condition, &control);
  if ((size_t)pthread_getspecific(thread_index) == 2u) {
    while (!first_finished)
      (void)pthread_cond_wait(&condition, &control);
  }
  (void)pthread_mutex_unlock(&control);
}

static void *test_malloc(size_t size)
{
  void *result;
  if (fail_malloc) return NULL;
  result = malloc(size);
  (void)pthread_mutex_lock(&control);
  if (result != NULL) live_allocations++;
  (void)pthread_mutex_unlock(&control);
  allocation_gate(1);
  return result;
}

static void *test_calloc(size_t count, size_t size)
{
  void *result;
  if (fail_calloc) return NULL;
  result = calloc(count, size);
  (void)pthread_mutex_lock(&control);
  if (result != NULL) live_allocations++;
  (void)pthread_mutex_unlock(&control);
  allocation_gate(2);
  return result;
}

static void test_free(void *pointer)
{
  (void)pthread_mutex_lock(&control);
  if (pointer != NULL) live_allocations--;
  (void)pthread_mutex_unlock(&control);
  free(pointer);
}

static int test_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr)
{
  init_calls++;
  return fail_init ? EAGAIN : pthread_mutex_init(mutex, attr);
}

static int allocation_failures(void)
{
  ftun_budget_t *root = NULL, *child = NULL;
  ftun_reservation_t *reservation = NULL;
  ftun_budget_usage_t usage;
  fail_calloc = 1;
  CHECK(ftun_budget_create(NULL, 1u, 0u, &root) == FTUN_E_LIMIT && root == NULL);
  CHECK(live_allocations == 0u);
  fail_calloc = 0;
  fail_init = 1;
  CHECK(ftun_budget_create(NULL, 1u, 0u, &root) == FTUN_E_IO && root == NULL);
  CHECK(live_allocations == 0u);
  fail_init = 0;
  CHECK(ftun_budget_create(NULL, 1u, 0u, &root) == FTUN_OK);
  CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK);
  CHECK(usage.metadata_bytes == sizeof(struct ftun_budget_root));
  fail_calloc = 1;
  CHECK(ftun_budget_create(root, 1u, 0u, &child) == FTUN_E_LIMIT && child == NULL);
  fail_calloc = 0;
  fail_malloc = 1;
  CHECK(ftun_budget_reserve(root, 1u, &reservation) == FTUN_E_LIMIT && reservation == NULL);
  fail_malloc = 0;
  CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK);
  CHECK(usage.used == 0u && usage.child_count == 0u &&
        usage.rejected_reservations == 1u &&
        usage.metadata_bytes == sizeof(struct ftun_budget_root));
  CHECK(live_allocations == 1u);
  CHECK(ftun_budget_create(root, 1u, 0u, &child) == FTUN_OK);
  CHECK(ftun_budget_reserve(child, 1u, &reservation) == FTUN_OK);
  CHECK(ftun_budget_get_usage(child, &usage) == FTUN_OK);
  CHECK(usage.metadata_bytes == sizeof(ftun_budget_t) + sizeof(ftun_reservation_t));
  CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK);
  CHECK(usage.metadata_bytes == sizeof(struct ftun_budget_root) +
        sizeof(ftun_budget_t) + sizeof(ftun_reservation_t));
  CHECK(ftun_reservation_release(&reservation) == FTUN_OK);
  CHECK(ftun_budget_destroy(&child) == FTUN_OK);
  CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK);
  CHECK(usage.metadata_bytes == sizeof(struct ftun_budget_root));
  CHECK(ftun_budget_destroy(&root) == FTUN_OK);
  CHECK(init_calls == 2u && live_allocations == 0u);
  return 0;
}

typedef struct {
  ftun_budget_t *root;
  ftun_budget_t *child;
  ftun_reservation_t *reservation;
  ftun_status_t status;
  size_t index;
} admission_t;

static void *admit(void *user)
{
  admission_t *state = user;
  (void)pthread_setspecific(thread_index, (void *)state->index);
  if (gate_kind == 1) {
    state->status = ftun_budget_reserve(state->root, 1u, &state->reservation);
  } else {
    ftun_budget_options_t options = {{1u, 1u, 1u}, {0u, 0u, 0u}, {1u, 1u, 1u}};
    state->status = ftun_budget_create_resources(state->root, &options, &state->child);
  }
  if (state->index == 1u) {
    (void)pthread_mutex_lock(&control);
    first_finished = 1;
    (void)pthread_cond_broadcast(&condition);
    (void)pthread_mutex_unlock(&control);
  }
  return NULL;
}

static int deterministic_admission(int kind)
{
  ftun_budget_options_t options = {{1u, 1u, 1u}, {0u, 0u, 0u}, {0u, 0u, 0u}};
  ftun_budget_t *root = NULL;
  ftun_budget_usage_t usage;
  admission_t states[2] = {{0}};
  pthread_t threads[2];
  size_t index;
  CHECK(ftun_budget_create_resources(NULL, &options, &root) == FTUN_OK);
  gate_arrived = 0;
  first_finished = 0;
  gate_kind = kind;
  for (index = 0u; index < 2u; index++) {
    states[index].root = root;
    states[index].index = index + 1u;
    CHECK(pthread_create(&threads[index], NULL, admit, &states[index]) == 0);
  }
  for (index = 0u; index < 2u; index++) CHECK(pthread_join(threads[index], NULL) == 0);
  gate_kind = 0;
  CHECK(states[0].status == FTUN_OK && states[1].status == FTUN_E_LIMIT);
  CHECK(states[1].reservation == NULL && states[1].child == NULL);
  CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK);
  CHECK(usage.used == (kind == 1 ? 1u : 0u));
  CHECK(usage.child_count == (kind == 2 ? 1u : 0u));
  CHECK(ftun_reservation_release(&states[0].reservation) == FTUN_OK);
  CHECK(ftun_budget_destroy(&states[0].child) == FTUN_OK);
  CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK);
  CHECK(usage.used == 0u && usage.child_count == 0u &&
        usage.metadata_bytes == sizeof(struct ftun_budget_root));
  CHECK(ftun_budget_destroy(&root) == FTUN_OK && live_allocations == 0u);
  return 0;
}

int main(void)
{
  CHECK(pthread_key_create(&thread_index, NULL) == 0);
  CHECK(allocation_failures() == 0);
  CHECK(deterministic_admission(1) == 0);
  CHECK(deterministic_admission(2) == 0);
  CHECK(pthread_key_delete(thread_index) == 0);
  CHECK(pthread_cond_destroy(&condition) == 0);
  CHECK(pthread_mutex_destroy(&control) == 0);
  return 0;
}
