#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "core/limits.h"
#include "platform/thread.h"

static void *test_calloc(size_t count, size_t size);
static void test_free(void *pointer);
static ftun_status_t test_mutex_init(ftun_mutex_t *mutex);

/* 只替换分配/初始化边界，准入与记账使用原实现。 */
#define calloc test_calloc
#define free test_free
#define ftun_mutex_init test_mutex_init
#include "../src/core/limits.c"
#undef calloc
#undef free
#undef ftun_mutex_init

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "budget fault contract failed at %d: %s\n", __LINE__, #x); \
  return 1; \
} } while (0)

static pthread_mutex_t control = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static pthread_key_t thread_index;
static size_t live_allocations;
static size_t init_calls;
static int fail_calloc, fail_init;
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

static ftun_status_t test_mutex_init(ftun_mutex_t *mutex)
{
  init_calls++;
  return fail_init > 0 && --fail_init == 0 ? FTUN_E_IO : ftun_mutex_init(mutex);
}

static int allocation_failures(void)
{
  ftun_budget_t *root = NULL, *child = NULL;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_budget_usage_t usage;
  fail_calloc = 1;
  CHECK(ftun_budget_create(NULL, 1u, 0u, &root) == FTUN_E_LIMIT && root == NULL);
  CHECK(live_allocations == 0u);
  fail_calloc = 0;
  fail_init = 1;
  CHECK(ftun_budget_create(NULL, 1u, 0u, &root) == FTUN_E_IO && root == NULL);
  CHECK(live_allocations == 0u);
  fail_init = 2;
  CHECK(ftun_budget_create(NULL, 1u, 0u, &root) == FTUN_E_IO && root == NULL);
  CHECK(live_allocations == 0u);
  fail_init = 0;
  CHECK(ftun_budget_create(NULL, 1u, 0u, &root) == FTUN_OK);
  CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK);
  CHECK(usage.metadata_bytes == sizeof(struct ftun_budget_root));
  fail_calloc = 1;
  CHECK(ftun_budget_create(root, 1u, 0u, &child) == FTUN_E_LIMIT && child == NULL);
  fail_calloc = 0;
  fail_calloc = 1;
  CHECK(ftun_budget_reserve(root, 1u, &reservation) == FTUN_OK);
  CHECK(live_allocations == 1u);
  CHECK(ftun_reservation_release(&reservation) == FTUN_OK);
  CHECK(ftun_budget_reserve(root, 2u, &reservation) == FTUN_E_LIMIT && reservation.budget == NULL);
  fail_calloc = 0;
  CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK);
  CHECK(usage.used == 0u && usage.child_count == 0u &&
        usage.rejected_reservations == 1u &&
        usage.metadata_bytes == sizeof(struct ftun_budget_root));
  CHECK(live_allocations == 1u);
  CHECK(ftun_budget_create(root, 1u, 0u, &child) == FTUN_OK);
  CHECK(ftun_budget_reserve(child, 1u, &reservation) == FTUN_OK);
  CHECK(ftun_budget_get_usage(child, &usage) == FTUN_OK);
  CHECK(usage.metadata_bytes == sizeof(struct ftun_budget_domain));
  CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK);
  CHECK(usage.metadata_bytes == sizeof(struct ftun_budget_root) +
        sizeof(struct ftun_budget_domain));
  CHECK(ftun_reservation_release(&reservation) == FTUN_OK);
  CHECK(ftun_budget_destroy(&child) == FTUN_OK);
  CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK);
  CHECK(usage.metadata_bytes == sizeof(struct ftun_budget_root));
  CHECK(ftun_budget_destroy(&root) == FTUN_OK);
  CHECK(init_calls == 6u && live_allocations == 0u);
  return 0;
}

typedef struct {
  ftun_budget_t *root;
  ftun_budget_t *child;
  ftun_reservation_t reservation;
  ftun_status_t status;
  size_t index;
} admission_t;

static void *admit(void *user)
{
  admission_t *state = user;
  (void)pthread_setspecific(thread_index, (void *)state->index);
  if (gate_kind == 1) {
    allocation_gate(1);
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
  CHECK((states[1].reservation).budget == NULL && states[1].child == NULL);
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

typedef struct {
  ftun_budget_t *budget;
  ftun_reservation_t reservation;
  ftun_status_t status;
  bool done;
} progress_t;
static void *independent_admit(void *user)
{
  progress_t *progress = user;
  progress->status = ftun_budget_reserve(progress->budget, 1u, &progress->reservation);
  (void)pthread_mutex_lock(&control);
  progress->done = true;
  (void)pthread_cond_broadcast(&condition);
  (void)pthread_mutex_unlock(&control);
  return NULL;
}
static int independent_domains(void)
{
  ftun_budget_t *root = NULL, *left = NULL, *right = NULL;
  progress_t progress = {0};
  pthread_t thread;
  struct timespec deadline;
  bool timely;
  int result = 0;
  CHECK(ftun_budget_create(NULL, 10u, 0u, &root) == FTUN_OK);
  CHECK(ftun_budget_create(root, 10u, 0u, &left) == FTUN_OK);
  CHECK(ftun_budget_create(root, 10u, 0u, &right) == FTUN_OK);
  progress.budget = right;
  /* 结构锁、根直接拥有的域、兄弟域均被持有，right 的准入仍能前进。 */
  ftun_mutex_lock(&root->root->registry_mutex);
  ftun_mutex_lock(&root->domain->mutex);
  ftun_mutex_lock(&left->domain->mutex);
  CHECK(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
  deadline.tv_sec += 2;
  (void)pthread_mutex_lock(&control);
  CHECK(pthread_create(&thread, NULL, independent_admit, &progress) == 0);
  while (!progress.done && result == 0) result = pthread_cond_timedwait(&condition, &control, &deadline);
  timely = progress.done;
  (void)pthread_mutex_unlock(&control);
  ftun_mutex_unlock(&left->domain->mutex);
  ftun_mutex_unlock(&root->domain->mutex);
  ftun_mutex_unlock(&root->root->registry_mutex);
  CHECK(pthread_join(thread, NULL) == 0);
  CHECK(ftun_reservation_release(&progress.reservation) == FTUN_OK);
  CHECK(ftun_budget_destroy(&right) == FTUN_OK);
  CHECK(ftun_budget_destroy(&left) == FTUN_OK);
  CHECK(ftun_budget_destroy(&root) == FTUN_OK);
  CHECK(timely && progress.status == FTUN_OK && live_allocations == 0u);
  return 0;
}

int main(void)
{
  CHECK(pthread_key_create(&thread_index, NULL) == 0);
  CHECK(allocation_failures() == 0);
  CHECK(deterministic_admission(1) == 0);
  CHECK(deterministic_admission(2) == 0);
  CHECK(independent_domains() == 0);
  CHECK(pthread_key_delete(thread_index) == 0);
  CHECK(pthread_cond_destroy(&condition) == 0);
  CHECK(pthread_mutex_destroy(&control) == 0);
  return 0;
}
