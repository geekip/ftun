#include "util/buffer.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "buffer contract failed at line %d: %s\n", __LINE__, #x); \
    return 1; \
  } \
} while (0)

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

static int test_waiters(void)
{
  ftun_budget_t *budget = NULL;
  ftun_buffer_pool_t *pool = NULL;
  ftun_buffer_t *first = NULL;
  ftun_buffer_t *second = NULL;
  ftun_buffer_t *available = NULL;
  ftun_reservation_t *blocker = NULL;
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
  CHECK(ftun_budget_reserve(budget, budget_usage.normal_available,
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

  CHECK(ftun_buffer_release(&first) == FTUN_OK);
  CHECK(ftun_buffer_release(&second) == FTUN_OK);
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

  CHECK(ftun_buffer_release(&first_waiter.buffer) == FTUN_OK);
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
  CHECK(ftun_buffer_release(&available) == FTUN_OK);
  CHECK(wakeups == 4u);
  CHECK(ftun_buffer_pool_wait_cancel(&cancelled_token) == FTUN_OK);
  CHECK(ftun_buffer_pool_dispatch(pool, SIZE_MAX, &callbacks) == FTUN_OK &&
        callbacks == 0u && cancelled_waiter.calls == 0u);
  CHECK(ftun_buffer_pool_get_usage(pool, &usage) == FTUN_OK &&
        usage.waiting == 0u && usage.cancelled_waiters == 2u &&
        usage.notifications == 4u);
  CHECK(ftun_buffer_release(&second_waiter.buffer) == FTUN_OK);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_OK && pool == NULL);
  CHECK(ftun_reservation_release(&blocker) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

/* TASK-UTIL-002 / TEST-UTIL-002：分档、slice 所有权和有界闲置保留。 */
int main(void)
{
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
  ftun_reservation_t *blocker = NULL;
  ftun_budget_t *pressure_budget = NULL;
  ftun_buffer_pool_t *pressure_pool = NULL;

  CHECK(ftun_budget_create(NULL, 8192u, 512u, &budget) == FTUN_OK);
  CHECK(ftun_buffer_acquire(budget, 1u, &buffer) == FTUN_OK);
  CHECK(ftun_buffer_data(buffer, &data, &capacity) == FTUN_OK);
  CHECK(data != NULL && capacity == 256u);
  memcpy(data, "hello", 5u);
  CHECK(ftun_buffer_slice(buffer, 1u, 3u, &slice) == FTUN_OK);
  CHECK(ftun_buffer_slice_clone(&slice, &clone) == FTUN_OK);
  CHECK(ftun_buffer_release(&buffer) == FTUN_OK && buffer == NULL);
  CHECK(ftun_buffer_slice_data(&slice, &bytes) == FTUN_OK);
  CHECK(bytes.length == 3u && memcmp(bytes.data, "ell", 3u) == 0);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  CHECK(budget_usage.used > 0u);
  CHECK(ftun_buffer_slice_release(&slice) == FTUN_OK);
  CHECK(ftun_buffer_slice_release(&slice) == FTUN_OK);
  CHECK(ftun_buffer_slice_data(&clone, &bytes) == FTUN_OK);
  CHECK(bytes.length == 3u && memcmp(bytes.data, "ell", 3u) == 0);
  CHECK(ftun_buffer_slice_release(&clone) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  CHECK(budget_usage.used == 0u);

  CHECK(ftun_buffer_pool_create(budget, 512u, 2u, &pool) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  pool_baseline = budget_usage.used;
  CHECK(pool_baseline > 0u);
  CHECK(ftun_buffer_pool_acquire(pool, 10u, &first) == FTUN_OK);
  CHECK(ftun_buffer_pool_acquire(pool, 256u, &second) == FTUN_OK);
  second_identity = (uintptr_t)second;
  CHECK(ftun_buffer_pool_get_usage(pool, &pool_usage) == FTUN_OK);
  CHECK(pool_usage.idle_limit_bytes == 512u && pool_usage.idle_limit_buffers == 2u &&
        pool_usage.active_buffers == 2u && pool_usage.idle_buffers == 0u);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_E_AGAIN && pool != NULL);
  CHECK(ftun_buffer_release(&first) == FTUN_OK && first == NULL);
  CHECK(ftun_buffer_release(&second) == FTUN_OK && second == NULL);
  CHECK(ftun_buffer_pool_get_usage(pool, &pool_usage) == FTUN_OK);
  CHECK(pool_usage.active_buffers == 0u && pool_usage.idle_buffers == 2u &&
        pool_usage.idle_bytes == 512u);
  CHECK(ftun_buffer_pool_acquire(pool, 200u, &second) == FTUN_OK);
  CHECK((uintptr_t)second == second_identity);
  CHECK(ftun_buffer_pool_acquire(pool, 257u, &large) == FTUN_OK);
  CHECK(ftun_buffer_data(large, &data, &capacity) == FTUN_OK && capacity == 512u);
  CHECK(ftun_buffer_release(&large) == FTUN_OK && large == NULL);
  CHECK(ftun_buffer_pool_get_usage(pool, &pool_usage) == FTUN_OK);
  CHECK(pool_usage.active_buffers == 1u && pool_usage.idle_buffers == 1u &&
        pool_usage.idle_bytes == 256u);
  CHECK(ftun_buffer_release(&second) == FTUN_OK && second == NULL);
  CHECK(ftun_buffer_pool_get_usage(pool, &pool_usage) == FTUN_OK);
  CHECK(pool_usage.active_buffers == 0u && pool_usage.idle_buffers == 2u &&
        pool_usage.idle_bytes == 512u);
  CHECK(ftun_buffer_pool_trim(pool, 256u) == FTUN_OK);
  CHECK(ftun_buffer_pool_get_usage(pool, &pool_usage) == FTUN_OK);
  CHECK(pool_usage.idle_buffers == 1u && pool_usage.idle_bytes == 256u);
  CHECK(ftun_buffer_pool_trim(pool, 0u) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  CHECK(budget_usage.used == pool_baseline);

  CHECK(ftun_buffer_pool_acquire(pool, 256u, &first) == FTUN_OK);
  CHECK(ftun_buffer_retain(first) == FTUN_OK);
  second = first;
  CHECK(ftun_buffer_release(&first) == FTUN_OK && first == NULL);
  CHECK(ftun_buffer_pool_get_usage(pool, &pool_usage) == FTUN_OK);
  CHECK(pool_usage.active_buffers == 1u && pool_usage.idle_buffers == 0u);
  CHECK(ftun_buffer_release(&second) == FTUN_OK && second == NULL);
  CHECK(ftun_buffer_pool_get_usage(pool, &pool_usage) == FTUN_OK);
  CHECK(pool_usage.active_buffers == 0u && pool_usage.idle_buffers == 1u);

  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_OK && pool == NULL);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  CHECK(budget_usage.used == 0u);

  CHECK(ftun_buffer_pool_create(budget, 1024u, 1u, &pool) == FTUN_OK);
  CHECK(ftun_buffer_pool_acquire(pool, 1u, &first) == FTUN_OK);
  CHECK(ftun_buffer_pool_acquire(pool, 1u, &second) == FTUN_OK);
  CHECK(ftun_buffer_release(&first) == FTUN_OK);
  CHECK(ftun_buffer_release(&second) == FTUN_OK);
  CHECK(ftun_buffer_pool_get_usage(pool, &pool_usage) == FTUN_OK);
  CHECK(pool_usage.idle_buffers == 1u && pool_usage.idle_bytes == 256u);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_OK);

  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  CHECK(ftun_budget_reserve(budget, budget_usage.normal_available, &blocker) == FTUN_OK);
  buffer = (ftun_buffer_t *)(uintptr_t)1;
  CHECK(ftun_buffer_acquire(budget, 1u, &buffer) == FTUN_E_LIMIT && buffer == NULL);
  CHECK(ftun_reservation_release(&blocker) == FTUN_OK);

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
  CHECK(ftun_buffer_slice_release(&slice) == FTUN_OK);
  CHECK(ftun_buffer_release(&buffer) == FTUN_OK && buffer == NULL);
  CHECK(ftun_buffer_release(&buffer) == FTUN_OK);

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
  CHECK(ftun_buffer_release(NULL) == FTUN_E_INVALID);
  CHECK(ftun_buffer_slice_release(NULL) == FTUN_E_INVALID);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);

  CHECK(ftun_budget_create(NULL, 90u * 1024u, 0u, &pressure_budget) == FTUN_OK);
  CHECK(ftun_buffer_pool_create(pressure_budget, 90u * 1024u, 4u,
                                &pressure_pool) == FTUN_OK);
  CHECK(ftun_buffer_pool_acquire(pressure_pool, 64u * 1024u, &buffer) == FTUN_OK);
  CHECK(ftun_buffer_release(&buffer) == FTUN_OK && buffer == NULL);
  CHECK(ftun_buffer_pool_acquire(pressure_pool, 32u * 1024u, &buffer) == FTUN_OK);
  CHECK(ftun_buffer_pool_get_usage(pressure_pool, &pool_usage) == FTUN_OK);
  CHECK(pool_usage.cache_misses == 2u && pool_usage.pressure_trims == 1u &&
        pool_usage.pressure_trimmed_buffers == 1u &&
        pool_usage.pressure_trimmed_bytes == 64u * 1024u);
  CHECK(ftun_buffer_release(&buffer) == FTUN_OK && buffer == NULL);
  CHECK(ftun_buffer_pool_destroy(&pressure_pool) == FTUN_OK);
  CHECK(ftun_budget_destroy(&pressure_budget) == FTUN_OK);
  CHECK(test_waiters() == 0);
  return 0;
}
