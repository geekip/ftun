#include "libs/buffer/buffer.h"
#include "libs/buffer/buffer.c"
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "buffer contract failed at line %d: %s\n", __LINE__, #x); \
    return 1; \
  } \
} while (0)

static size_t fail_calloc_after;
void *__real_calloc(size_t count, size_t size);
void *__wrap_calloc(size_t count, size_t size)
{
  if (fail_calloc_after != 0u && --fail_calloc_after == 0u) return NULL;
  return __real_calloc(count, size);
}

typedef struct {
  ftun_buffer_pool_t *pool;
  ftun_buffer_t *buffer;
  ftun_status_t status;
  size_t calls;
} waiter_state_t;

static void pool_wakeup(void *user)
{
  size_t *calls = (size_t *)user;
  (*calls)++;
}

static void waiter_ready(void *user)
{
  waiter_state_t *state = (waiter_state_t *)user;
  state->calls++;
  state->status = ftun_buffer_pool_acquire(state->pool, 256u,
                                            &state->buffer);
}

static void unavailable_ready(void *user)
{
  (void)user;
  abort();
}

static int test_class_selection_cost(void)
{
  enum { BLOCKED = 1000 };
  ftun_budget_t *budget = NULL;
  ftun_buffer_pool_t *pool = NULL;
  ftun_reservation_t hold = (ftun_reservation_t){0};
  ftun_budget_usage_t usage;
  ftun_buffer_pool_usage_t cost;
  ftun_buffer_wait_token_t tokens[BLOCKED + 1u] = {{0}};
  waiter_state_t waiter = {0};
  size_t i, callbacks;
  CHECK(ftun_budget_create(NULL, 8u * 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_buffer_pool_create_waitable(budget, 0u, 0u, BLOCKED + 1u, 1u, &pool) == FTUN_OK);
  waiter.pool = pool;
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
  CHECK(ftun_budget_reserve(budget, usage.normal_available_resources.memory_bytes, &hold) == FTUN_OK);
  for (i = 0u; i < BLOCKED; i++) {
    CHECK(ftun_buffer_pool_wait(pool, 65536u, unavailable_ready, NULL, &tokens[i]) == FTUN_OK);
  }
  CHECK(ftun_buffer_pool_wait(pool, 256u, waiter_ready, &waiter, &tokens[BLOCKED]) == FTUN_OK);
  CHECK(ftun_reservation_resize(&(hold),
    (ftun_budget_resources_t){usage.normal_available_resources.memory_bytes - 512u, 0u, 0u}) == FTUN_OK);
  CHECK(ftun_buffer_pool_dispatch(pool, 1u, &callbacks) == FTUN_OK && callbacks == 1u);
  CHECK(waiter.calls == 1u && waiter.status == FTUN_OK && waiter.buffer != NULL);
  CHECK(ftun_buffer_pool_get_usage(pool, &cost) == FTUN_OK &&
    cost.waiting == BLOCKED && cost.max_availability_probes == 2u &&
    cost.max_selection_steps <= 5u);
  for (i = 0u; i < BLOCKED; i++) CHECK(ftun_buffer_pool_wait_cancel(&tokens[i]) == FTUN_OK);
  ftun_buffer_release(&waiter.buffer);
  ftun_reservation_release(&hold);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int test_class_boundaries(void)
{
  ftun_budget_t *budget = NULL;
  ftun_buffer_pool_t *pool = NULL;
  ftun_reservation_t hold = (ftun_reservation_t){0};
  ftun_budget_usage_t usage;
  ftun_buffer_wait_token_t first = {0}, stale, rejected = {0};
  size_t capacity, bit;
  CHECK(ftun_buffer_class(0u, &capacity) == FTUN_E_INVALID && capacity == 0u);
  for (bit = 8u; bit < sizeof(size_t) * CHAR_BIT; bit++) {
    size_t value = (size_t)1u << bit;
    CHECK(ftun_buffer_class(value, &capacity) == FTUN_OK && capacity == value);
    CHECK(ftun_buffer_class(value - 1u, &capacity) == FTUN_OK && capacity == value);
    if (bit + 1u < sizeof(size_t) * CHAR_BIT) {
      CHECK(ftun_buffer_class(value + 1u, &capacity) == FTUN_OK && capacity == value * 2u);
    } else CHECK(ftun_buffer_class(value + 1u, &capacity) == FTUN_E_LIMIT);
  }
  CHECK(ftun_buffer_class(SIZE_MAX, &capacity) == FTUN_E_LIMIT);
  CHECK(ftun_budget_create(NULL, 8192u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_buffer_pool_create_waitable(budget, 0u, 0u, 2u, 1u, &pool) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
  CHECK(ftun_budget_reserve(budget, usage.normal_available_resources.memory_bytes, &hold) == FTUN_OK);
  pool->next_waiter_generation = UINT64_MAX - 1u;
  CHECK(ftun_buffer_pool_wait(pool, 256u, unavailable_ready, NULL, &first) == FTUN_OK &&
    first.generation == UINT64_MAX);
  stale = first;
  CHECK(ftun_buffer_pool_wait(pool, 256u, unavailable_ready, NULL, &rejected) == FTUN_E_LIMIT &&
    rejected.pool == NULL && rejected.generation == 0u);
  CHECK(ftun_buffer_pool_wait_cancel(&first) == FTUN_OK);
  CHECK(ftun_buffer_pool_wait_cancel(&stale) == FTUN_E_STALE);
  ftun_reservation_release(&hold);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int test_waiter_budget(void)
{
  ftun_budget_t *root = NULL, *child = NULL;
  ftun_budget_options_t limits = {{65536u, 0u, 4u}, {0u, 0u, 1u}, {0}};
  ftun_budget_options_t child_limits = {{65536u, 0u, 2u}, {0}, {0}};
  ftun_budget_usage_t usage;
  ftun_buffer_pool_t *pool = NULL;
  ftun_reservation_t queue_pressure = (ftun_reservation_t){0}, memory_pressure = (ftun_reservation_t){0}, cleanup = (ftun_reservation_t){0};
  ftun_buffer_wait_token_t first = {0}, second = {0}, rejected = {0};
  waiter_state_t waiter = {0};
  size_t allocation, callbacks, wakeups = 0u;
  CHECK(ftun_budget_create_resources(NULL, &limits, &root) == FTUN_OK);
  CHECK(ftun_budget_create_resources(root, &child_limits, &child) == FTUN_OK);
  CHECK(ftun_buffer_pool_create_waitable(child, 0u, 0u, 3u, 1u, &pool) == FTUN_E_LIMIT && pool == NULL);
  CHECK(ftun_budget_reserve_resources(root, (ftun_budget_resources_t){0u, 0u, 2u},
    &queue_pressure) == FTUN_OK);
  CHECK(ftun_buffer_pool_create_waitable(child, 0u, 0u, 2u, 1u, &pool) == FTUN_E_LIMIT && pool == NULL);
  ftun_reservation_release(&queue_pressure);
  for (allocation = 1u; allocation <= 2u; allocation++) {
    fail_calloc_after = allocation;
    CHECK(ftun_buffer_pool_create_waitable(child, 0u, 0u, 2u, 1u, &pool) == FTUN_E_LIMIT && pool == NULL);
    CHECK(fail_calloc_after == 0u);
    CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK &&
      usage.used_resources.memory_bytes == 0u && usage.used_resources.queue_slots == 0u);
  }
  CHECK(ftun_buffer_pool_create_waitable(child, 0u, 0u, 2u, 1u, &pool) == FTUN_OK);
  CHECK(ftun_budget_get_usage(child, &usage) == FTUN_OK && usage.used_resources.queue_slots == 2u);
  CHECK(ftun_budget_reserve(child, usage.normal_available_resources.memory_bytes, &memory_pressure) == FTUN_OK);
  CHECK(ftun_budget_reserve_resources(root, (ftun_budget_resources_t){0u, 0u, 1u},
    &queue_pressure) == FTUN_OK);
  waiter.pool = pool;
  CHECK(ftun_buffer_pool_set_wakeup(pool, pool_wakeup, &wakeups) == FTUN_OK);
  CHECK(ftun_buffer_pool_wait(pool, 256u, waiter_ready, &waiter, &first) == FTUN_OK);
  CHECK(ftun_buffer_pool_wait(pool, 256u, waiter_ready, &waiter, &second) == FTUN_OK);
  CHECK(ftun_buffer_pool_wait(pool, 256u, waiter_ready, &waiter, &rejected) == FTUN_E_LIMIT);
  CHECK(rejected.pool == NULL);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_E_AGAIN && pool != NULL);
  CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK && usage.used_resources.queue_slots == 3u);
  CHECK(ftun_budget_reserve_cleanup_resources(root, (ftun_budget_resources_t){0u, 0u, 1u}, &cleanup) == FTUN_OK);
  ftun_reservation_release(&cleanup);
  ftun_reservation_release(&memory_pressure);
  /* 队列正常额度仍满，已准入等待者照常唤醒，不再申请推进槽。 */
  CHECK(ftun_buffer_pool_dispatch(pool, SIZE_MAX, &callbacks) == FTUN_OK && callbacks == 1u);
  CHECK(waiter.calls == 1u && waiter.status == FTUN_OK && waiter.buffer != NULL);
  CHECK(ftun_buffer_pool_wait_cancel(&second) == FTUN_OK);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_E_AGAIN && pool != NULL);
  CHECK(ftun_budget_get_usage(child, &usage) == FTUN_OK && usage.used_resources.queue_slots == 2u);
  ftun_buffer_release(&waiter.buffer);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_OK);
  CHECK(ftun_budget_get_usage(child, &usage) == FTUN_OK &&
    usage.used_resources.memory_bytes == 0u && usage.used_resources.queue_slots == 0u);
  CHECK(ftun_buffer_pool_create_waitable(child, 0u, 0u, 2u, 1u, &pool) == FTUN_OK);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_OK);
  ftun_reservation_release(&queue_pressure);
  CHECK(ftun_budget_destroy(&child) == FTUN_OK);
  CHECK(ftun_budget_destroy(&root) == FTUN_OK);
  return 0;
}

static int test_waiters(void)
{
  ftun_budget_t *budget = NULL;
  ftun_buffer_pool_t *pool = NULL;
  ftun_buffer_t *first = NULL;
  ftun_buffer_t *second = NULL;
  ftun_buffer_t *available = NULL;
  ftun_reservation_t blocker = (ftun_reservation_t){0};
  ftun_budget_usage_t budget_usage;
  ftun_buffer_pool_usage_t usage;
  ftun_buffer_wait_token_t first_token;
  ftun_buffer_wait_token_t first_stale;
  ftun_buffer_wait_token_t second_token;
  ftun_buffer_wait_token_t cancelled_token;
  ftun_buffer_wait_token_t rejected_token;
  waiter_state_t first_waiter;
  waiter_state_t second_waiter;
  waiter_state_t cancelled_waiter;
  size_t wakeups = 0u;
  size_t callbacks = SIZE_MAX;

  memset(&first_waiter, 0, sizeof(first_waiter));
  memset(&second_waiter, 0, sizeof(second_waiter));
  memset(&cancelled_waiter, 0, sizeof(cancelled_waiter));
  CHECK(ftun_budget_create(NULL, 8192u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_buffer_pool_create_waitable(budget, 1024u, 4u, 3u, 1u,
                                         &pool) == FTUN_OK);
  first_waiter.pool = pool;
  second_waiter.pool = pool;
  cancelled_waiter.pool = pool;
  CHECK(ftun_buffer_pool_set_wakeup(pool, pool_wakeup, &wakeups) == FTUN_OK);
  CHECK(ftun_buffer_pool_acquire(pool, 256u, &first) == FTUN_OK);
  CHECK(ftun_buffer_pool_acquire(pool, 256u, &second) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  CHECK(ftun_budget_reserve(budget, budget_usage.normal_available_resources.memory_bytes,
                            &blocker) == FTUN_OK);

  CHECK(ftun_buffer_pool_wait(pool, 256u, waiter_ready, &first_waiter,
                              &first_token) == FTUN_OK);
  first_stale = first_token;
  CHECK(ftun_buffer_pool_wait(pool, 256u, waiter_ready, &second_waiter,
                              &second_token) == FTUN_OK);
  CHECK(ftun_buffer_pool_wait(pool, 256u, waiter_ready, &cancelled_waiter,
                              &cancelled_token) == FTUN_OK);
  memset(&rejected_token, 0xff, sizeof(rejected_token));
  CHECK(ftun_buffer_pool_wait(pool, 256u, waiter_ready, &cancelled_waiter,
                              &rejected_token) == FTUN_E_LIMIT);
  CHECK(rejected_token.pool == NULL && rejected_token.generation == 0u);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_E_AGAIN && pool != NULL);

  ftun_buffer_release(&first);
  ftun_buffer_release(&second);
  CHECK(wakeups == 1u);
  CHECK(ftun_buffer_pool_get_usage(pool, &usage) == FTUN_OK);
  CHECK(usage.waiter_capacity == 3u && usage.waiting == 3u &&
        usage.wake_quota == 1u && usage.notifications == 1u &&
        usage.rejected_waiters == 1u && !usage.dispatching);

  CHECK(ftun_buffer_pool_dispatch(pool, SIZE_MAX, &callbacks) == FTUN_OK);
  CHECK(callbacks == 1u && first_waiter.calls == 1u &&
        first_waiter.status == FTUN_OK && first_waiter.buffer != NULL);
  CHECK(wakeups == 2u);
  CHECK(ftun_buffer_pool_wait_cancel(&first_stale) == FTUN_E_STALE);
  CHECK(ftun_buffer_pool_dispatch(pool, SIZE_MAX, &callbacks) == FTUN_OK);
  CHECK(callbacks == 1u && second_waiter.calls == 1u &&
        second_waiter.status == FTUN_OK && second_waiter.buffer != NULL);
  CHECK(cancelled_waiter.calls == 0u && wakeups == 2u);

  ftun_buffer_release(&first_waiter.buffer);
  CHECK(wakeups == 3u);
  CHECK(ftun_buffer_pool_wait_cancel(&cancelled_token) == FTUN_OK);
  CHECK(cancelled_token.pool == NULL && cancelled_token.generation == 0u);
  CHECK(ftun_buffer_pool_get_usage(pool, &usage) == FTUN_OK);
  CHECK(usage.waiting == 0u && usage.wake_callbacks == 2u &&
        usage.cancelled_waiters == 1u && usage.notifications == 3u);

  /* Resource returned before registration: wait reports retry without
   * creating a waiter, closing the release/register lost-wakeup window. */
  memset(&rejected_token, 0xff, sizeof(rejected_token));
  CHECK(ftun_buffer_pool_wait(pool, 256u, waiter_ready, &cancelled_waiter,
                              &rejected_token) == FTUN_E_AGAIN);
  CHECK(rejected_token.pool == NULL && rejected_token.generation == 0u);
  CHECK(ftun_buffer_pool_acquire(pool, 256u, &available) == FTUN_OK);
  /* Cancelling the last notified waiter clears coalescing state.  A later
   * registration and release must produce a fresh notification. */
  CHECK(ftun_buffer_pool_wait(pool, 256u, waiter_ready, &cancelled_waiter,
                              &cancelled_token) == FTUN_OK);
  ftun_buffer_release(&available);
  CHECK(wakeups == 4u);
  CHECK(ftun_buffer_pool_wait_cancel(&cancelled_token) == FTUN_OK);
  CHECK(ftun_buffer_pool_dispatch(pool, SIZE_MAX, &callbacks) == FTUN_OK &&
        callbacks == 0u && cancelled_waiter.calls == 0u);
  CHECK(ftun_buffer_pool_get_usage(pool, &usage) == FTUN_OK &&
        usage.waiting == 0u && usage.cancelled_waiters == 2u &&
        usage.notifications == 4u);
  ftun_buffer_release(&second_waiter.buffer);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_OK && pool == NULL);
  ftun_reservation_release(&blocker);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

typedef struct {
  ftun_buffer_pool_t *pool;
  ftun_buffer_t *buffer;
  size_t capacity;
  size_t calls;
  size_t *order;
  size_t *order_count;
  size_t identity;
  int release;
  ftun_status_t status;
  ftun_status_t recursive;
} mixed_waiter_t;

static void mixed_ready(void *user)
{
  mixed_waiter_t *state = user;
  size_t callbacks = SIZE_MAX;
  state->calls++;
  if (state->order != NULL) state->order[(*state->order_count)++] = state->identity;
  state->recursive = ftun_buffer_pool_dispatch(state->pool, 1u, &callbacks);
  if (callbacks != 0u) state->recursive = FTUN_E_STATE_CORRUPT;
  state->status = ftun_buffer_pool_acquire(state->pool, state->capacity, &state->buffer);
  if (state->status == FTUN_OK && state->release)
    ftun_buffer_release(&state->buffer);
}

static int test_mixed_waiters(void)
{
  ftun_budget_t *budget = NULL;
  ftun_buffer_pool_t *pool = NULL;
  ftun_buffer_t *small[2] = {NULL, NULL};
  ftun_reservation_t blocker = (ftun_reservation_t){0};
  ftun_budget_usage_t budget_usage;
  ftun_buffer_pool_usage_t usage;
  mixed_waiter_t waiters[4] = {{0}};
  ftun_buffer_wait_token_t tokens[4];
  size_t order[4] = {0}, order_count = 0u;
  size_t wakeups = 0u, callbacks, index;
  CHECK(ftun_budget_create(NULL, 8192u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_buffer_pool_create_waitable(budget, 2048u, 8u, 4u, 1u, &pool) == FTUN_OK);
  CHECK(ftun_buffer_pool_set_wakeup(pool, pool_wakeup, &wakeups) == FTUN_OK);
  for (index = 0u; index < 2u; index++)
    CHECK(ftun_buffer_pool_acquire(pool, 256u, &small[index]) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  CHECK(ftun_budget_reserve(budget, budget_usage.normal_available_resources.memory_bytes, &blocker) == FTUN_OK);
  for (index = 0u; index < 4u; index++) {
    waiters[index].pool = pool;
    waiters[index].capacity = index % 2u == 0u ? 512u : 256u;
    waiters[index].order = order;
    waiters[index].order_count = &order_count;
    waiters[index].identity = index + 1u;
    waiters[index].release = 1;
    CHECK(ftun_buffer_pool_wait(pool, waiters[index].capacity, mixed_ready,
      &waiters[index], &tokens[index]) == FTUN_OK);
  }
  ftun_buffer_release(&small[0]); CHECK(wakeups == 1u);
  ftun_buffer_release(&small[1]); CHECK(wakeups == 1u);
  CHECK(ftun_buffer_pool_wait_cancel(&tokens[2]) == FTUN_OK);
  for (index = 0u; index < 3u; index++) {
    CHECK(ftun_buffer_pool_dispatch(pool, SIZE_MAX, &callbacks) == FTUN_OK);
    CHECK(callbacks == 1u);
    CHECK(wakeups == (index < 2u ? index + 2u : 3u));
  }
  CHECK(order_count == 3u && order[0] == 1u && order[1] == 2u && order[2] == 4u);
  CHECK(waiters[2].calls == 0u);
  for (index = 0u; index < 4u; index++) {
    if (index == 2u) continue;
    CHECK(waiters[index].calls == 1u && waiters[index].status == FTUN_OK &&
          waiters[index].recursive == FTUN_E_AGAIN);
    CHECK(ftun_buffer_pool_wait_cancel(&tokens[index]) == FTUN_E_STALE);
  }
  for (index = 0u; index < 20u; index++)
    CHECK(ftun_buffer_pool_dispatch(pool, 1u, &callbacks) == FTUN_OK && callbacks == 0u);
  CHECK(wakeups == 3u);
  CHECK(ftun_buffer_pool_get_usage(pool, &usage) == FTUN_OK && usage.waiting == 0u &&
        usage.cancelled_waiters == 1u && usage.wake_callbacks == 3u && usage.notifications == 3u);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_OK);
  ftun_reservation_release(&blocker);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK && budget_usage.used_resources.memory_bytes == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int test_split_and_rebind(void)
{
  ftun_budget_t *budget = NULL;
  ftun_buffer_pool_t *pool = NULL;
  ftun_buffer_t *large = NULL;
  ftun_reservation_t blocker = (ftun_reservation_t){0};
  ftun_budget_usage_t usage;
  mixed_waiter_t waiters[2] = {{0}};
  ftun_buffer_wait_token_t tokens[2];
  size_t first_wakeups = 0u, second_wakeups = 0u, callbacks, index;
  CHECK(ftun_budget_create(NULL, 8192u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_buffer_pool_create_waitable(budget, 1024u, 4u, 2u, 2u, &pool) == FTUN_OK);
  CHECK(ftun_buffer_pool_set_wakeup(pool, pool_wakeup, &first_wakeups) == FTUN_OK);
  CHECK(ftun_buffer_pool_acquire(pool, 512u, &large) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
  CHECK(ftun_budget_reserve(budget, usage.normal_available_resources.memory_bytes, &blocker) == FTUN_OK);
  for (index = 0u; index < 2u; index++) {
    waiters[index].pool = pool;
    waiters[index].capacity = 256u;
    CHECK(ftun_buffer_pool_wait(pool, 256u, mixed_ready, &waiters[index], &tokens[index]) == FTUN_OK);
  }
  ftun_buffer_release(&large); CHECK(first_wakeups == 1u);
  CHECK(ftun_buffer_pool_set_wakeup(pool, NULL, NULL) == FTUN_OK);
  CHECK(ftun_buffer_pool_set_wakeup(pool, pool_wakeup, &second_wakeups) == FTUN_OK);
  CHECK(ftun_buffer_pool_set_wakeup(pool, pool_wakeup, &second_wakeups) == FTUN_OK);
  CHECK(first_wakeups == 1u && second_wakeups == 1u);
  /* 一个 512 块回收后不足以同时承担两个 256 块各自的结构头。 */
  CHECK(ftun_buffer_pool_dispatch(pool, 8u, &callbacks) == FTUN_OK && callbacks == 1u);
  CHECK(waiters[0].calls == 1u && waiters[0].status == FTUN_OK && waiters[1].calls == 0u);
  CHECK(second_wakeups == 1u);
  ftun_buffer_release(&waiters[0].buffer); CHECK(second_wakeups == 2u);
  CHECK(ftun_buffer_pool_dispatch(pool, 8u, &callbacks) == FTUN_OK && callbacks == 1u);
  CHECK(waiters[1].calls == 1u && waiters[1].status == FTUN_OK && second_wakeups == 2u);
  ftun_buffer_release(&waiters[1].buffer);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_OK);
  ftun_reservation_release(&blocker);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int test_cleanup_ceiling(void)
{
  ftun_budget_t *root = NULL, *child = NULL;
  ftun_buffer_pool_t *pool = NULL;
  ftun_buffer_t *small[2] = {NULL, NULL};
  ftun_reservation_t normal = (ftun_reservation_t){0}, cleanup = (ftun_reservation_t){0};
  ftun_budget_usage_t usage;
  mixed_waiter_t waiter = {0};
  ftun_buffer_wait_token_t token;
  size_t wakeups = 0u, callbacks, index;
  CHECK(ftun_budget_create(NULL, 8192u, 1024u, &root) == FTUN_OK);
  CHECK(ftun_budget_create(root, 8192u, 0u, &child) == FTUN_OK);
  CHECK(ftun_buffer_pool_create_waitable(child, 1024u, 4u, 1u, 1u, &pool) == FTUN_OK);
  CHECK(ftun_buffer_pool_set_wakeup(pool, pool_wakeup, &wakeups) == FTUN_OK);
  for (index = 0u; index < 2u; index++)
    CHECK(ftun_buffer_pool_acquire(pool, 256u, &small[index]) == FTUN_OK);
  CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK);
  CHECK(ftun_budget_reserve(root, usage.normal_available_resources.memory_bytes, &normal) == FTUN_OK);
  CHECK(ftun_budget_reserve_cleanup(root, 1024u, &cleanup) == FTUN_OK);
  waiter.pool = pool;
  waiter.capacity = 512u;
  CHECK(ftun_buffer_pool_wait(pool, 512u, mixed_ready, &waiter, &token) == FTUN_OK);
  for (index = 0u; index < 2u; index++) ftun_buffer_release(&small[index]);
  CHECK(wakeups == 0u);
  for (index = 0u; index < 20u; index++)
    CHECK(ftun_buffer_pool_dispatch(pool, 1u, &callbacks) == FTUN_OK && callbacks == 0u);
  CHECK(wakeups == 0u && waiter.calls == 0u);
  ftun_reservation_release(&cleanup);
  CHECK(ftun_buffer_pool_dispatch(pool, 1u, &callbacks) == FTUN_OK && callbacks == 1u);
  CHECK(waiter.status == FTUN_OK);
  ftun_buffer_release(&waiter.buffer);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_OK);
  ftun_reservation_release(&normal);
  CHECK(ftun_budget_destroy(&child) == FTUN_OK);
  CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u);
  CHECK(ftun_budget_destroy(&root) == FTUN_OK);
  return 0;
}

static int test_wait_with_live_slice(void)
{
  ftun_budget_t *budget = NULL;
  ftun_buffer_pool_t *pool = NULL;
  ftun_buffer_t *first = NULL, *second = NULL;
  ftun_buffer_slice_t slice;
  ftun_bytes_t bytes;
  ftun_reservation_t blocker = (ftun_reservation_t){0};
  ftun_budget_usage_t usage;
  ftun_buffer_pool_usage_t pool_usage;
  mixed_waiter_t waiter = {0};
  ftun_buffer_wait_token_t token;
  size_t wakeups = 0u, callbacks;
  CHECK(ftun_budget_create(NULL, 8192u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_buffer_pool_create_waitable(budget, 1024u, 4u, 1u, 1u, &pool) == FTUN_OK);
  CHECK(ftun_buffer_pool_set_wakeup(pool, pool_wakeup, &wakeups) == FTUN_OK);
  CHECK(ftun_buffer_pool_acquire(pool, 256u, &first) == FTUN_OK);
  CHECK(ftun_buffer_pool_acquire(pool, 256u, &second) == FTUN_OK);
  CHECK(ftun_buffer_slice(first, 0u, 16u, &slice) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
  CHECK(ftun_budget_reserve(budget, usage.normal_available_resources.memory_bytes, &blocker) == FTUN_OK);
  waiter.pool = pool;
  waiter.capacity = 512u;
  CHECK(ftun_buffer_pool_wait(pool, 512u, mixed_ready, &waiter, &token) == FTUN_OK);
  ftun_buffer_release(&first);
  ftun_buffer_release(&second); CHECK(wakeups == 0u);
  CHECK(ftun_buffer_pool_get_usage(pool, &pool_usage) == FTUN_OK &&
        pool_usage.active_buffers == 1u && pool_usage.idle_buffers == 1u &&
        pool_usage.pressure_trims == 0u);
  CHECK(ftun_buffer_pool_trim(pool, 0u) == FTUN_OK && wakeups == 0u);
  CHECK(ftun_buffer_slice_data(&slice, &bytes) == FTUN_OK && bytes.length == 16u);
  ftun_buffer_slice_release(&slice); CHECK(wakeups == 1u);
  CHECK(ftun_buffer_pool_dispatch(pool, 1u, &callbacks) == FTUN_OK && callbacks == 1u);
  CHECK(waiter.status == FTUN_OK);
  ftun_buffer_release(&waiter.buffer);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_OK);
  ftun_reservation_release(&blocker);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  ftun_budget_t *budget;
  size_t amount;
  int phase;
  ftun_status_t status;
} competitor_t;

static void *compete_for_budget(void *user)
{
  competitor_t *state = user;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  state->status = ftun_budget_reserve(state->budget, state->amount, &reservation);
  (void)pthread_mutex_lock(&state->mutex);
  state->phase = 1;
  (void)pthread_cond_broadcast(&state->condition);
  while (state->phase == 1)
    (void)pthread_cond_wait(&state->condition, &state->mutex);
  (void)pthread_mutex_unlock(&state->mutex);
  ftun_reservation_release(&reservation); state->status = FTUN_OK;
  return NULL;
}

static int test_budget_competition(void)
{
  ftun_budget_t *budget = NULL;
  ftun_buffer_pool_t *pool = NULL;
  ftun_buffer_t *small[2] = {NULL, NULL};
  ftun_reservation_t blocker = (ftun_reservation_t){0};
  ftun_budget_usage_t usage;
  ftun_buffer_wait_token_t token;
  mixed_waiter_t waiter = {0};
  competitor_t competitor = {0};
  pthread_t thread;
  size_t wakeups = 0u, callbacks, index;
  CHECK(ftun_budget_create(NULL, 8192u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_buffer_pool_create_waitable(budget, 1024u, 4u, 1u, 1u, &pool) == FTUN_OK);
  CHECK(ftun_buffer_pool_set_wakeup(pool, pool_wakeup, &wakeups) == FTUN_OK);
  for (index = 0u; index < 2u; index++)
    CHECK(ftun_buffer_pool_acquire(pool, 256u, &small[index]) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
  CHECK(ftun_budget_reserve(budget, usage.normal_available_resources.memory_bytes, &blocker) == FTUN_OK);
  waiter.pool = pool;
  waiter.capacity = 512u;
  CHECK(ftun_buffer_pool_wait(pool, 512u, mixed_ready, &waiter, &token) == FTUN_OK);
  for (index = 0u; index < 2u; index++) ftun_buffer_release(&small[index]);
  CHECK(wakeups == 1u);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
  competitor.budget = budget;
  competitor.amount = usage.normal_available_resources.memory_bytes;
  CHECK(pthread_mutex_init(&competitor.mutex, NULL) == 0);
  CHECK(pthread_cond_init(&competitor.condition, NULL) == 0);
  CHECK(pthread_create(&thread, NULL, compete_for_budget, &competitor) == 0);
  (void)pthread_mutex_lock(&competitor.mutex);
  while (competitor.phase != 1)
    (void)pthread_cond_wait(&competitor.condition, &competitor.mutex);
  CHECK(competitor.status == FTUN_OK);
  (void)pthread_mutex_unlock(&competitor.mutex);
  for (index = 0u; index < 20u; index++)
    CHECK(ftun_buffer_pool_dispatch(pool, 1u, &callbacks) == FTUN_OK && callbacks == 0u);
  CHECK(wakeups == 1u && waiter.calls == 0u);
  (void)pthread_mutex_lock(&competitor.mutex);
  competitor.phase = 2;
  (void)pthread_cond_broadcast(&competitor.condition);
  (void)pthread_mutex_unlock(&competitor.mutex);
  for (index = 0u; index < 100000u && waiter.calls == 0u; index++) {
    CHECK(ftun_buffer_pool_dispatch(pool, 1u, &callbacks) == FTUN_OK);
    (void)sched_yield();
  }
  /* 竞争者可在一轮末尾释放额度，此时允许通知下一轮一次。 */
  CHECK(waiter.calls == 1u && waiter.status == FTUN_OK && wakeups >= 1u && wakeups <= 2u);
  CHECK(pthread_join(thread, NULL) == 0 && competitor.status == FTUN_OK);
  CHECK(pthread_cond_destroy(&competitor.condition) == 0);
  CHECK(pthread_mutex_destroy(&competitor.mutex) == 0);
  ftun_buffer_release(&waiter.buffer);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_OK);
  ftun_reservation_release(&blocker);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

/* 分档、slice 所有权和有界闲置保留。 */
int main(void)
{
  CHECK(test_class_boundaries() == 0);
  CHECK(test_class_selection_cost() == 0);
  ftun_budget_t *budget = NULL;
  ftun_buffer_pool_t *pool = (ftun_buffer_pool_t *)(uintptr_t)1;
  ftun_buffer_t *buffer = (ftun_buffer_t *)(uintptr_t)1;
  ftun_buffer_t *first = NULL;
  ftun_buffer_t *second = NULL;
  ftun_buffer_t *large = NULL;
  ftun_buffer_slice_t slice;
  ftun_buffer_slice_t clone;
  ftun_bytes_t bytes;
  ftun_buffer_pool_usage_t pool_usage;
  ftun_budget_usage_t budget_usage;
  uint8_t *data = (uint8_t *)(uintptr_t)1;
  size_t capacity = 99u;
  size_t pool_baseline;
  uintptr_t second_identity;
  ftun_reservation_t blocker = (ftun_reservation_t){0};
  ftun_budget_t *pressure_budget = NULL;
  ftun_buffer_pool_t *pressure_pool = NULL;

  CHECK(ftun_budget_create(NULL, 8192u, 512u, &budget) == FTUN_OK);
  CHECK(ftun_buffer_acquire(budget, 1u, &buffer) == FTUN_OK);
  CHECK(ftun_buffer_data(buffer, &data, &capacity) == FTUN_OK);
  CHECK(data != NULL && capacity == 256u);
  memcpy(data, "hello", 5u);
  CHECK(ftun_buffer_slice(buffer, 1u, 3u, &slice) == FTUN_OK);
  CHECK(ftun_buffer_slice_clone(&slice, &clone) == FTUN_OK);
  ftun_buffer_release(&buffer); CHECK(buffer == NULL);
  CHECK(ftun_buffer_slice_data(&slice, &bytes) == FTUN_OK);
  CHECK(bytes.length == 3u && memcmp(bytes.data, "ell", 3u) == 0);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  CHECK(budget_usage.used_resources.memory_bytes > 0u);
  ftun_buffer_slice_release(&slice);
  ftun_buffer_slice_release(&slice);
  CHECK(ftun_buffer_slice_data(&clone, &bytes) == FTUN_OK);
  CHECK(bytes.length == 3u && memcmp(bytes.data, "ell", 3u) == 0);
  ftun_buffer_slice_release(&clone);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  CHECK(budget_usage.used_resources.memory_bytes == 0u);

  CHECK(ftun_buffer_pool_create(budget, 512u, 2u, &pool) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  pool_baseline = budget_usage.used_resources.memory_bytes;
  CHECK(pool_baseline > 0u);
  CHECK(ftun_buffer_pool_acquire(pool, 10u, &first) == FTUN_OK);
  CHECK(ftun_buffer_pool_acquire(pool, 256u, &second) == FTUN_OK);
  second_identity = (uintptr_t)second;
  CHECK(ftun_buffer_pool_get_usage(pool, &pool_usage) == FTUN_OK);
  CHECK(pool_usage.idle_limit_bytes == 512u && pool_usage.idle_limit_buffers == 2u &&
        pool_usage.active_buffers == 2u && pool_usage.idle_buffers == 0u);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_E_AGAIN && pool != NULL);
  ftun_buffer_release(&first); CHECK(first == NULL);
  ftun_buffer_release(&second); CHECK(second == NULL);
  CHECK(ftun_buffer_pool_get_usage(pool, &pool_usage) == FTUN_OK);
  CHECK(pool_usage.active_buffers == 0u && pool_usage.idle_buffers == 2u &&
        pool_usage.idle_bytes == 512u);
  CHECK(ftun_buffer_pool_acquire(pool, 200u, &second) == FTUN_OK);
  CHECK((uintptr_t)second == second_identity);
  CHECK(ftun_buffer_pool_acquire(pool, 257u, &large) == FTUN_OK);
  CHECK(ftun_buffer_data(large, &data, &capacity) == FTUN_OK && capacity == 512u);
  ftun_buffer_release(&large); CHECK(large == NULL);
  CHECK(ftun_buffer_pool_get_usage(pool, &pool_usage) == FTUN_OK);
  CHECK(pool_usage.active_buffers == 1u && pool_usage.idle_buffers == 1u &&
        pool_usage.idle_bytes == 256u);
  ftun_buffer_release(&second); CHECK(second == NULL);
  CHECK(ftun_buffer_pool_get_usage(pool, &pool_usage) == FTUN_OK);
  CHECK(pool_usage.active_buffers == 0u && pool_usage.idle_buffers == 2u &&
        pool_usage.idle_bytes == 512u);
  CHECK(ftun_buffer_pool_trim(pool, 256u) == FTUN_OK);
  CHECK(ftun_buffer_pool_get_usage(pool, &pool_usage) == FTUN_OK);
  CHECK(pool_usage.idle_buffers == 1u && pool_usage.idle_bytes == 256u);
  CHECK(ftun_buffer_pool_trim(pool, 0u) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  CHECK(budget_usage.used_resources.memory_bytes == pool_baseline);

  CHECK(ftun_buffer_pool_acquire(pool, 256u, &first) == FTUN_OK);
  CHECK(ftun_buffer_retain(first) == FTUN_OK);
  second = first;
  ftun_buffer_release(&first); CHECK(first == NULL);
  CHECK(ftun_buffer_pool_get_usage(pool, &pool_usage) == FTUN_OK);
  CHECK(pool_usage.active_buffers == 1u && pool_usage.idle_buffers == 0u);
  ftun_buffer_release(&second); CHECK(second == NULL);
  CHECK(ftun_buffer_pool_get_usage(pool, &pool_usage) == FTUN_OK);
  CHECK(pool_usage.active_buffers == 0u && pool_usage.idle_buffers == 1u);

  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_OK && pool == NULL);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  CHECK(budget_usage.used_resources.memory_bytes == 0u);

  CHECK(ftun_buffer_pool_create(budget, 1024u, 1u, &pool) == FTUN_OK);
  CHECK(ftun_buffer_pool_acquire(pool, 1u, &first) == FTUN_OK);
  CHECK(ftun_buffer_pool_acquire(pool, 1u, &second) == FTUN_OK);
  ftun_buffer_release(&first);
  ftun_buffer_release(&second);
  CHECK(ftun_buffer_pool_get_usage(pool, &pool_usage) == FTUN_OK);
  CHECK(pool_usage.idle_buffers == 1u && pool_usage.idle_bytes == 256u);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_OK);

  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  CHECK(ftun_budget_reserve(budget, budget_usage.normal_available_resources.memory_bytes, &blocker) == FTUN_OK);
  buffer = (ftun_buffer_t *)(uintptr_t)1;
  CHECK(ftun_buffer_acquire(budget, 1u, &buffer) == FTUN_E_LIMIT && buffer == NULL);
  ftun_reservation_release(&blocker);

  buffer = (ftun_buffer_t *)(uintptr_t)1;
  CHECK(ftun_buffer_acquire(budget, 0u, &buffer) == FTUN_E_INVALID && buffer == NULL);
  CHECK(ftun_buffer_acquire(budget, SIZE_MAX, &buffer) == FTUN_E_LIMIT && buffer == NULL);
  CHECK(ftun_buffer_acquire(NULL, 1u, &buffer) == FTUN_E_INVALID && buffer == NULL);
  CHECK(ftun_buffer_acquire(budget, 32u, &buffer) == FTUN_OK);
  memset(&slice, 0xff, sizeof(slice));
  CHECK(ftun_buffer_slice(buffer, 257u, 0u, &slice) == FTUN_E_INVALID);
  CHECK(slice.owner == NULL && slice.offset == 0u && slice.length == 0u);
  CHECK(ftun_buffer_slice(buffer, 255u, 2u, &slice) == FTUN_E_INVALID);
  CHECK(ftun_buffer_slice(buffer, 256u, 0u, &slice) == FTUN_OK);
  memset(&clone, 0xff, sizeof(clone));
  CHECK(ftun_buffer_slice_clone(&slice, &slice) == FTUN_E_INVALID);
  CHECK(ftun_buffer_slice_clone(NULL, &clone) == FTUN_E_INVALID);
  CHECK(clone.owner == NULL && clone.offset == 0u && clone.length == 0u);
  CHECK(ftun_buffer_slice_data(&slice, &bytes) == FTUN_OK && bytes.length == 0u);
  ftun_buffer_slice_release(&slice);
  ftun_buffer_release(&buffer); CHECK(buffer == NULL);
  ftun_buffer_release(&buffer);

  data = (uint8_t *)(uintptr_t)1;
  capacity = 99u;
  CHECK(ftun_buffer_data(NULL, &data, &capacity) == FTUN_E_INVALID);
  CHECK(data == NULL && capacity == 0u);
  memset(&slice, 0, sizeof(slice));
  bytes.data = (const uint8_t *)(uintptr_t)1;
  bytes.length = 99u;
  CHECK(ftun_buffer_slice_data(&slice, &bytes) == FTUN_E_INVALID);
  CHECK(bytes.data == NULL && bytes.length == 0u);
  CHECK(ftun_buffer_pool_get_usage(NULL, &pool_usage) == FTUN_E_INVALID);
  CHECK(pool_usage.idle_bytes == 0u && pool_usage.active_buffers == 0u);
  CHECK(ftun_buffer_pool_trim(NULL, 0u) == FTUN_E_INVALID);
  CHECK(ftun_buffer_pool_destroy(NULL) == FTUN_E_INVALID);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);

  CHECK(ftun_budget_create(NULL, 90u * 1024u, 0u, &pressure_budget) == FTUN_OK);
  CHECK(ftun_buffer_pool_create(pressure_budget, 90u * 1024u, 4u,
                                &pressure_pool) == FTUN_OK);
  CHECK(ftun_buffer_pool_acquire(pressure_pool, 64u * 1024u, &buffer) == FTUN_OK);
  ftun_buffer_release(&buffer); CHECK(buffer == NULL);
  CHECK(ftun_buffer_pool_acquire(pressure_pool, 32u * 1024u, &buffer) == FTUN_OK);
  CHECK(ftun_buffer_pool_get_usage(pressure_pool, &pool_usage) == FTUN_OK);
  CHECK(pool_usage.cache_misses == 2u && pool_usage.pressure_trims == 1u &&
        pool_usage.pressure_trimmed_buffers == 1u &&
        pool_usage.pressure_trimmed_bytes == 64u * 1024u);
  ftun_buffer_release(&buffer); CHECK(buffer == NULL);
  CHECK(ftun_buffer_pool_destroy(&pressure_pool) == FTUN_OK);
  CHECK(ftun_budget_destroy(&pressure_budget) == FTUN_OK);
  CHECK(test_waiter_budget() == 0);
  CHECK(test_waiters() == 0);
  CHECK(test_mixed_waiters() == 0);
  CHECK(test_split_and_rebind() == 0);
  CHECK(test_cleanup_ceiling() == 0);
  CHECK(test_budget_competition() == 0);
  CHECK(test_wait_with_live_slice() == 0);
  return 0;
}
