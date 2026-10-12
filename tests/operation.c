#include "core/operation.h"
#include <stdint.h>
#include <stdio.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "operation contract failed: %s\n", #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  ftun_operation_queue_t *queue;
  int calls;
  int cancel_was_stale;
  int recursive_was_again;
  ftun_status_t expected;
} callback_state_t;

typedef struct {
  int calls;
  int failures;
} cancel_hook_state_t;

static ftun_status_t cancel_hook(void *user)
{
  cancel_hook_state_t *state = (cancel_hook_state_t *)user;
  state->calls++;
  if (state->failures > 0) {
    state->failures--;
    return FTUN_E_IO;
  }
  return FTUN_OK;
}

static void completed(ftun_operation_t *operation, ftun_error_t result, void *user)
{
  callback_state_t *state = (callback_state_t *)user;
  size_t dispatched = 99u;
  state->calls++;
  if (result.status != state->expected) state->calls = -100;
  if (ftun_operation_cancel(operation) == FTUN_E_STALE) state->cancel_was_stale++;
  if (ftun_operation_dispatch(state->queue, 1u, &dispatched) == FTUN_E_AGAIN &&
      dispatched == 0u) state->recursive_was_again++;
}

int main(void)
{
  ftun_budget_t *budget = NULL;
  ftun_operation_queue_t *queue = (ftun_operation_queue_t *)(uintptr_t)1;
  ftun_operation_t *first = (ftun_operation_t *)(uintptr_t)1;
  ftun_operation_t *second = (ftun_operation_t *)(uintptr_t)1;
  ftun_operation_t *third = (ftun_operation_t *)(uintptr_t)1;
  ftun_operation_queue_usage_t queue_usage;
  ftun_budget_usage_t budget_usage;
  callback_state_t one = {0}, two = {0}, three = {0};
  cancel_hook_state_t hook = {0};
  ftun_error_t success = {FTUN_OK, 7u, 9};
  size_t baseline;
  size_t dispatched = 99u;

  CHECK(ftun_budget_create(NULL, 4096u, 256u, &budget) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 2u, &queue) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  baseline = budget_usage.used;
  CHECK(baseline > 0u);
  CHECK(ftun_operation_queue_get_usage(queue, &queue_usage) == FTUN_OK);
  CHECK(queue_usage.capacity == 2u && queue_usage.inflight == 0u && queue_usage.accepting);

  one.queue = queue;
  one.expected = FTUN_E_CANCELLED;
  two.queue = queue;
  two.expected = FTUN_E_CANCELLED;
  CHECK(ftun_operation_accept(queue, completed, &one, &first) == FTUN_OK);
  CHECK(ftun_operation_accept(queue, completed, &two, &second) == FTUN_OK);
  CHECK(one.calls == 0 && two.calls == 0);
  CHECK(ftun_operation_accept(queue, completed, &three, &third) == FTUN_E_LIMIT);
  CHECK(third == NULL);
  CHECK(ftun_operation_complete(first, success) == FTUN_OK);
  CHECK(one.calls == 0);
  CHECK(ftun_operation_cancel(first) == FTUN_OK);
  CHECK(ftun_operation_complete(first, success) == FTUN_E_STALE);
  CHECK(ftun_operation_cancel(second) == FTUN_OK);
  CHECK(ftun_operation_cancel(second) == FTUN_E_STALE);

  CHECK(ftun_operation_dispatch(queue, 1u, &dispatched) == FTUN_OK);
  CHECK(dispatched == 1u && one.calls == 1 && two.calls == 0);
  CHECK(one.cancel_was_stale == 1 && one.recursive_was_again == 1);
  CHECK(ftun_operation_dispatch(queue, 2u, &dispatched) == FTUN_OK);
  CHECK(dispatched == 1u && two.calls == 1);
  CHECK(two.cancel_was_stale == 1 && two.recursive_was_again == 1);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  CHECK(budget_usage.used == baseline);

  three.queue = queue;
  three.expected = FTUN_OK;
  CHECK(ftun_operation_accept(queue, completed, &three, &third) == FTUN_OK);
  CHECK(ftun_operation_dispatch(queue, 1u, &dispatched) == FTUN_OK);
  CHECK(dispatched == 0u && three.calls == 0);
  CHECK(ftun_operation_complete(third, success) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&queue) == FTUN_E_AGAIN && queue != NULL);
  CHECK(ftun_operation_dispatch(queue, 1u, &dispatched) == FTUN_OK);
  CHECK(dispatched == 1u && three.calls == 1);
  CHECK(three.cancel_was_stale == 1 && three.recursive_was_again == 1);

  one.calls = one.cancel_was_stale = one.recursive_was_again = 0;
  one.expected = FTUN_E_CANCELLED;
  hook.calls = 0;
  hook.failures = 1;
  CHECK(ftun_operation_accept(queue, completed, &one, &first) == FTUN_OK);
  CHECK(ftun_operation_set_cancel_hook(first, cancel_hook, &hook) == FTUN_OK);
  CHECK(ftun_operation_cancel(first) == FTUN_E_IO);
  CHECK(hook.calls == 1 && one.calls == 0);
  CHECK(ftun_operation_cancel(first) == FTUN_OK);
  CHECK(hook.calls == 2);
  CHECK(ftun_operation_dispatch(queue, 1u, &dispatched) == FTUN_OK);
  CHECK(dispatched == 1u && one.calls == 1);

  one.calls = one.cancel_was_stale = one.recursive_was_again = 0;
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  baseline = budget_usage.used;
  CHECK(ftun_operation_accept(queue, completed, &one, &first) == FTUN_OK);
  CHECK(ftun_operation_reject(&first) == FTUN_OK && first == NULL);
  CHECK(one.calls == 0);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  CHECK(budget_usage.used == baseline);

  one.calls = one.cancel_was_stale = one.recursive_was_again = 0;
  one.expected = FTUN_E_CANCELLED;
  hook.calls = 0;
  hook.failures = 1;
  CHECK(ftun_operation_accept(queue, completed, &one, &first) == FTUN_OK);
  CHECK(ftun_operation_complete(first, success) == FTUN_OK);
  CHECK(ftun_operation_set_cancel_hook(first, cancel_hook, &hook) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(queue) == FTUN_E_IO);
  CHECK(one.calls == 0 && hook.calls == 1);
  CHECK(ftun_operation_queue_stop(queue) == FTUN_OK);
  CHECK(hook.calls == 2);
  CHECK(ftun_operation_accept(queue, completed, &two, &second) == FTUN_E_CANCELLED);
  CHECK(second == NULL);
  CHECK(ftun_operation_dispatch(queue, SIZE_MAX, &dispatched) == FTUN_OK);
  CHECK(dispatched == 1u && one.calls == 1);
  CHECK(ftun_operation_queue_get_usage(queue, &queue_usage) == FTUN_OK);
  CHECK(queue_usage.inflight == 0u && !queue_usage.accepting && !queue_usage.dispatching);

  CHECK(ftun_operation_cancel(NULL) == FTUN_E_INVALID);
  CHECK(ftun_operation_complete(NULL, success) == FTUN_E_INVALID);
  CHECK(ftun_operation_set_cancel_hook(NULL, cancel_hook, &hook) == FTUN_E_INVALID);
  CHECK(ftun_operation_reject(NULL) == FTUN_E_INVALID);
  CHECK(ftun_operation_dispatch(queue, 0u, &dispatched) == FTUN_E_INVALID);
  CHECK(dispatched == 0u);
  CHECK(ftun_operation_dispatch(queue, 1u, NULL) == FTUN_E_INVALID);
  CHECK(ftun_operation_queue_get_usage(NULL, &queue_usage) == FTUN_E_INVALID);
  CHECK(queue_usage.capacity == 0u && queue_usage.inflight == 0u);
  CHECK(ftun_operation_queue_destroy(&queue) == FTUN_OK && queue == NULL);
  CHECK(ftun_operation_queue_destroy(&queue) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  CHECK(budget_usage.used == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);

  queue = (ftun_operation_queue_t *)(uintptr_t)1;
  CHECK(ftun_operation_queue_create(NULL, 1u, &queue) == FTUN_E_INVALID);
  CHECK(queue == NULL);
  CHECK(ftun_operation_queue_create(budget, 1u, &queue) == FTUN_E_INVALID);
  CHECK(queue == NULL);
  CHECK(ftun_operation_queue_destroy(NULL) == FTUN_E_INVALID);

  {
    ftun_reservation_t *blocker = NULL;
    callback_state_t rejected_state = {0};
    CHECK(ftun_budget_create(NULL, 512u, 0u, &budget) == FTUN_OK);
    CHECK(ftun_operation_queue_create(budget, 1u, &queue) == FTUN_OK);
    CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
    CHECK(budget_usage.normal_available > 0u);
    CHECK(ftun_budget_reserve(budget, budget_usage.normal_available, &blocker) == FTUN_OK);
    rejected_state.queue = queue;
    rejected_state.expected = FTUN_OK;
    third = (ftun_operation_t *)(uintptr_t)1;
    /* Operation 槽位随队列预留，因此稳态接纳不依赖分配器或剩余预算。 */
    CHECK(ftun_operation_accept(queue, completed, &rejected_state, &third) == FTUN_OK);
    CHECK(third != NULL && rejected_state.calls == 0);
    CHECK(ftun_operation_complete(third, success) == FTUN_OK);
    CHECK(ftun_operation_dispatch(queue, 1u, &dispatched) == FTUN_OK);
    CHECK(dispatched == 1u && rejected_state.calls == 1);
    CHECK(ftun_reservation_release(&blocker) == FTUN_OK);
    CHECK(ftun_operation_queue_destroy(&queue) == FTUN_OK);
    CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  }
  return 0;
}
