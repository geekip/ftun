#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#include "core/operation.h"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

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

typedef struct {
  ftun_operation_queue_t *queue;
  ftun_operation_t *operation;
  ftun_operation_token_t token;
  ftun_operation_token_t stale;
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  pthread_t owner;
  int phase;
  int threaded;
  int deferred;
  int failed;
  int calls;
  int hook_calls;
  ftun_status_t hook_result;
  ftun_status_t first_result;
  ftun_status_t duplicate_result;
  ftun_status_t retry_result;
  ftun_status_t stale_result;
  ftun_error_t delivered;
} window_t;

/* 仅测试使用有界握手固定两个线程的相遇窗口；产品 hook 不得等待生产者。 */
static int window_wait(window_t *window, int phase)
{
  struct timespec limit;
  if (clock_gettime(CLOCK_REALTIME, &limit) != 0) return 0;
  limit.tv_sec += 5;
  while (window->phase < phase && !window->failed) {
    if (pthread_cond_timedwait(&window->condition, &window->mutex,
                               &limit) != 0) {
      window->failed = 1;
      (void)pthread_cond_broadcast(&window->condition);
    }
  }
  return !window->failed;
}

static void window_completed(ftun_operation_t *operation,
                               ftun_error_t result, void *user)
{
  window_t *window = (window_t *)user;
  (void)operation;
  if (!pthread_equal(pthread_self(), window->owner)) window->failed = 1;
  window->calls++;
  window->delivered = result;
}

static void *window_producer(void *user)
{
  window_t *window = (window_t *)user;
  const ftun_error_t result = {FTUN_OK, 37u, 91};
  (void)pthread_mutex_lock(&window->mutex);
  if (!window_wait(window, 1)) {
    (void)pthread_mutex_unlock(&window->mutex);
    return NULL;
  }
  (void)pthread_mutex_unlock(&window->mutex);
  window->first_result = window->deferred
    ? ftun_operation_complete_deferred(window->token, result)
    : ftun_operation_complete(window->token, result);
  window->stale_result = ftun_operation_complete_deferred(window->stale, result);
  window->duplicate_result = window->deferred
    ? ftun_operation_complete_deferred(window->token, result)
    : ftun_operation_complete(window->token, result);
  (void)pthread_mutex_lock(&window->mutex);
  window->phase = 2;
  (void)pthread_cond_broadcast(&window->condition);
  if (!window_wait(window, 3)) {
    (void)pthread_mutex_unlock(&window->mutex);
    return NULL;
  }
  (void)pthread_mutex_unlock(&window->mutex);
  /* AGAIN 没有消费结果，必须保留完整结果并在取消调用退出后重交。 */
  window->retry_result = ftun_operation_complete(window->token, result);
  (void)pthread_mutex_lock(&window->mutex);
  window->phase = 4;
  (void)pthread_cond_broadcast(&window->condition);
  (void)pthread_mutex_unlock(&window->mutex);
  return NULL;
}

static ftun_status_t window_cancel(void *user)
{
  window_t *window = (window_t *)user;
  const ftun_error_t result = {FTUN_OK, 37u, 91};
  size_t dispatched = 0u;
  window->hook_calls++;
  if (ftun_operation_cancel(window->operation) != FTUN_E_AGAIN ||
      ftun_operation_set_cancel_hook(window->operation, NULL, NULL) !=
        FTUN_E_AGAIN) window->failed = 1;
  if (window->threaded) {
    (void)pthread_mutex_lock(&window->mutex);
    window->phase = 1;
    (void)pthread_cond_broadcast(&window->condition);
    (void)window_wait(window, 2);
    (void)pthread_mutex_unlock(&window->mutex);
  } else {
    window->first_result = window->deferred
      ? ftun_operation_complete_deferred(window->token, result)
      : ftun_operation_complete(window->token, result);
    window->stale_result = ftun_operation_complete_deferred(window->stale, result);
    window->duplicate_result = window->deferred
      ? ftun_operation_complete_deferred(window->token, result)
      : ftun_operation_complete(window->token, result);
  }
  if (ftun_operation_dispatch(window->queue, 1u, &dispatched) != FTUN_OK ||
      dispatched != 0u) window->failed = 1;
  return window->hook_result;
}

static int test_cancel_window(int threaded, int deferred, int already_terminal,
                               ftun_status_t hook_result)
{
  ftun_budget_t *budget = NULL;
  ftun_operation_queue_usage_t usage;
  ftun_operation_t *unused = NULL;
  ftun_operation_token_t replacement = {0};
  const ftun_error_t result = {FTUN_OK, 37u, 91};
  window_t window;
  pthread_t producer;
  size_t dispatched;
  memset(&window, 0, sizeof(window));
  window.owner = pthread_self();
  window.threaded = threaded;
  window.deferred = deferred;
  window.hook_result = hook_result;
  CHECK(pthread_mutex_init(&window.mutex, NULL) == 0);
  CHECK(pthread_cond_init(&window.condition, NULL) == 0);
  CHECK(ftun_budget_create(NULL, 4096u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 1u, &window.queue) == FTUN_OK);
  CHECK(ftun_operation_accept(window.queue, window_completed, &window,
    &unused, &window.stale) == FTUN_OK);
  CHECK(ftun_operation_reject(&unused) == FTUN_OK);
  CHECK(ftun_operation_accept(window.queue, window_completed, &window,
    &window.operation, &window.token) == FTUN_OK);
  CHECK(window.token.slot == window.stale.slot &&
        window.token.generation != window.stale.generation);
  CHECK(ftun_operation_set_cancel_hook(window.operation, window_cancel,
                                       &window) == FTUN_OK);
  if (already_terminal) {
    CHECK(ftun_operation_complete(window.token, result) == FTUN_OK);
  }
  if (threaded) CHECK(pthread_create(&producer, NULL, window_producer,
                                    &window) == 0);
  CHECK(ftun_operation_cancel(window.operation) == hook_result);
  CHECK(!window.failed && window.hook_calls == 1 && window.calls == 0);
  CHECK(window.first_result == (already_terminal ? FTUN_E_STALE :
                                deferred ? FTUN_OK : FTUN_E_AGAIN));
  CHECK(window.stale_result == FTUN_E_STALE);
  CHECK(window.duplicate_result ==
        (deferred || already_terminal ? FTUN_E_STALE : FTUN_E_AGAIN));
  CHECK(ftun_operation_queue_get_usage(window.queue, &usage) == FTUN_OK);
  CHECK(usage.inflight == 1u &&
        usage.ready == (size_t)(deferred || already_terminal || hook_result == FTUN_OK));
  CHECK(ftun_operation_dispatch(window.queue, 1u, &dispatched) == FTUN_OK);
  CHECK(dispatched == (size_t)(deferred || already_terminal || hook_result == FTUN_OK));
  if (dispatched != 0u) {
    CHECK(window.delivered.status ==
          (hook_result == FTUN_OK ? FTUN_E_CANCELLED : FTUN_OK));
    if (hook_result != FTUN_OK) {
      CHECK(window.delivered.stage == 37u && window.delivered.native_code == 91);
    }
    /* 取消成功后的迟到完成还必须不能污染同槽位的新请求。 */
    CHECK(ftun_operation_accept(window.queue, window_completed, &window,
      &unused, &replacement) == FTUN_OK);
  }
  if (threaded) {
    struct timespec limit;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &limit) == 0);
    limit.tv_sec += 5;
    (void)pthread_mutex_lock(&window.mutex);
    window.phase = 3;
    (void)pthread_cond_broadcast(&window.condition);
    (void)pthread_mutex_unlock(&window.mutex);
    /* 生产者尚未 join 时 owner 实际推进队列。 */
    for (;;) {
      int finished;
      struct timespec now;
      CHECK(ftun_operation_dispatch(window.queue, 1u, &dispatched) == FTUN_OK);
      (void)pthread_mutex_lock(&window.mutex);
      finished = window.phase == 4 || window.failed;
      (void)pthread_mutex_unlock(&window.mutex);
      if (finished) break;
      CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
      CHECK(now.tv_sec < limit.tv_sec ||
            (now.tv_sec == limit.tv_sec && now.tv_nsec < limit.tv_nsec));
    }
    CHECK(pthread_join(producer, NULL) == 0);
  } else {
    window.retry_result = ftun_operation_complete(window.token, result);
  }
  CHECK(!window.failed);
  CHECK(window.retry_result ==
        (deferred || already_terminal || hook_result == FTUN_OK
          ? FTUN_E_STALE : FTUN_OK));
  CHECK(ftun_operation_dispatch(window.queue, 1u, &dispatched) == FTUN_OK);
  CHECK(window.calls == 1);
  if (!already_terminal && hook_result != FTUN_OK) {
    CHECK(window.delivered.status == FTUN_OK && window.delivered.stage == 37u &&
          window.delivered.native_code == 91);
  }
  if (unused != NULL) {
    CHECK(ftun_operation_queue_get_usage(window.queue, &usage) == FTUN_OK &&
          usage.inflight == 1u && usage.ready == 0u);
    CHECK(ftun_operation_reject(&unused) == FTUN_OK);
  }
  CHECK(ftun_operation_complete(window.token, result) == FTUN_E_STALE);
  CHECK(ftun_operation_queue_stop(window.queue) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&window.queue) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(pthread_cond_destroy(&window.condition) == 0);
  CHECK(pthread_mutex_destroy(&window.mutex) == 0);
  return 0;
}

typedef struct {
  ftun_operation_queue_t *queue;
  size_t calls;
  int failed;
} stop_step_t;

static ftun_status_t stop_step_cancel(void *user)
{
  stop_step_t *state = (stop_step_t *)user;
  size_t visited = 99u;
  bool more = true;
  state->calls++;
  if (ftun_operation_queue_stop_step(state->queue, 1u, &visited, &more) !=
        FTUN_E_AGAIN || visited != 0u || more ||
      ftun_operation_queue_reopen(state->queue) != FTUN_E_AGAIN) {
    state->failed = 1;
  }
  return state->calls == 1u ? FTUN_E_AGAIN : FTUN_OK;
}

static int test_stop_steps(void)
{
  ftun_budget_t *budget = NULL;
  ftun_operation_queue_t *queue = NULL;
  ftun_operation_t *operations[65] = {0};
  ftun_operation_token_t tokens[65] = {{0}};
  callback_state_t callbacks[65];
  callback_state_t extra = {0};
  stop_step_t hook;
  ftun_operation_queue_usage_t usage;
  ftun_operation_t *replacement = NULL;
  ftun_operation_token_t replacement_token = {0};
  size_t visited = 0u, dispatched = 0u, index, last = 0u;
  bool more = false;
  const ftun_error_t result = {FTUN_OK, 0u, 0};
  memset(callbacks, 0, sizeof(callbacks));
  memset(&hook, 0, sizeof(hook));
  CHECK(ftun_budget_create(NULL, 65536u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 65u, &queue) == FTUN_OK);
  hook.queue = queue;
  for (index = 0u; index < 65u; index++) {
    callbacks[index].queue = queue;
    callbacks[index].expected = FTUN_E_CANCELLED;
    CHECK(ftun_operation_accept(queue, completed, &callbacks[index],
      &operations[index], &tokens[index]) == FTUN_OK);
    if (tokens[index].slot == 64u) last = index;
  }
  CHECK(ftun_operation_set_cancel_hook(operations[last], stop_step_cancel,
                                        &hook) == FTUN_OK);
  /* 空槽也消耗扫描配额，跨轮派发不能让游标跳过尾部失败项。 */
  for (index = 0u; index < 65u; index++) {
    if (tokens[index].slot < 64u && tokens[index].slot % 2u == 0u) {
      CHECK(ftun_operation_reject(&operations[index]) == FTUN_OK);
    }
  }
  CHECK(ftun_operation_queue_stop_step(queue, 0u, &visited, &more) ==
        FTUN_E_INVALID && visited == 0u && !more);
  CHECK(ftun_operation_queue_stop_step(queue, 32u, &visited, &more) == FTUN_OK);
  CHECK(visited == 32u && more && hook.calls == 0u);
  CHECK(ftun_operation_accept(queue, completed, &callbacks[0],
    &replacement, &replacement_token) == FTUN_E_CANCELLED && replacement == NULL);
  CHECK(ftun_operation_queue_reopen(queue) == FTUN_E_AGAIN);
  CHECK(ftun_operation_dispatch(queue, 32u, &dispatched) == FTUN_OK);
  CHECK(dispatched == 16u);
  CHECK(ftun_operation_queue_stop_step(queue, 32u, &visited, &more) == FTUN_OK);
  CHECK(visited == 32u && more);
  CHECK(ftun_operation_dispatch(queue, 32u, &dispatched) == FTUN_OK);
  CHECK(dispatched == 16u);
  CHECK(ftun_operation_queue_stop_step(queue, 32u, &visited, &more) == FTUN_E_AGAIN);
  CHECK(visited == 1u && !more && hook.calls == 1u && !hook.failed);
  CHECK(ftun_operation_queue_get_usage(queue, &usage) == FTUN_OK &&
        usage.inflight == 1u && usage.ready == 0u);
  CHECK(ftun_operation_queue_stop(queue) == FTUN_OK && hook.calls == 2u);
  CHECK(ftun_operation_dispatch(queue, 1u, &dispatched) == FTUN_OK && dispatched == 1u);
  for (index = 0u; index < 65u; index++) {
    CHECK(callbacks[index].calls ==
      (int)(tokens[index].slot % 2u != 0u || tokens[index].slot == 64u));
  }
  CHECK(ftun_operation_queue_reopen(queue) == FTUN_OK);
  extra.queue = queue;
  extra.expected = FTUN_E_CANCELLED;
  CHECK(ftun_operation_accept(queue, completed, &extra,
    &replacement, &replacement_token) == FTUN_OK);
  CHECK(ftun_operation_complete(tokens[last], result) == FTUN_E_STALE);
  CHECK(ftun_operation_cancel(replacement) == FTUN_OK);
  CHECK(ftun_operation_dispatch(queue, 1u, &dispatched) == FTUN_OK);
  CHECK(extra.calls == 1 && !hook.failed);
  CHECK(ftun_operation_queue_stop_step(queue, 32u, &visited, &more) == FTUN_OK);
  CHECK(visited == 0u && !more);
  CHECK(ftun_operation_queue_destroy(&queue) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

typedef struct {
  int calls;
  int order[4];
} wake_state_t;

static void wake_ready(void *user)
{
  wake_state_t *state = (wake_state_t *)user;
  state->calls++;
}

static void noop_completed(ftun_operation_t *operation, ftun_error_t result, void *user)
{
  (void)operation;
  (void)result;
  (void)user;
}

/* 队列满时的等待：排队、幂等、取消、按序恰好一次通知、有等待者不能销毁。 */
static int test_waiters(void)
{
  ftun_budget_t *budget = NULL;
  ftun_operation_queue_t *queue = NULL;
  ftun_operation_t *first = NULL, *second = NULL, *extra = NULL;
  ftun_operation_token_t first_token = {0}, second_token = {0}, extra_token = {0};
  ftun_operation_waiter_t a, b, c;
  wake_state_t wa = {0}, wb = {0}, wc = {0};
  ftun_error_t success = {FTUN_OK, 0u, 0};
  size_t dispatched = 0u;
  memset(&a, 0, sizeof(a));
  memset(&b, 0, sizeof(b));
  memset(&c, 0, sizeof(c));
  CHECK(ftun_budget_create(NULL, 4096u, 256u, &budget) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 2u, &queue) == FTUN_OK);
  /* 有额度时不排队。 */
  CHECK(ftun_operation_queue_wait(queue, &a, wake_ready, &wa) == FTUN_E_AGAIN);
  CHECK(ftun_operation_accept(queue, noop_completed, NULL, &first, &first_token) == FTUN_OK);
  CHECK(ftun_operation_accept(queue, noop_completed, NULL, &second, &second_token) == FTUN_OK);
  CHECK(ftun_operation_accept(queue, noop_completed, NULL, &extra, &extra_token) == FTUN_E_LIMIT);
  CHECK(ftun_operation_queue_wait(queue, &a, wake_ready, &wa) == FTUN_OK);
  CHECK(ftun_operation_queue_wait(queue, &a, wake_ready, &wa) == FTUN_OK);
  CHECK(ftun_operation_queue_wait(queue, &b, wake_ready, &wb) == FTUN_OK);
  CHECK(ftun_operation_queue_wait(queue, &c, wake_ready, &wc) == FTUN_OK);
  CHECK(ftun_operation_queue_wait_cancel(&b) == FTUN_OK);
  CHECK(ftun_operation_queue_wait_cancel(&b) == FTUN_E_STALE);
  CHECK(ftun_operation_queue_destroy(&queue) == FTUN_E_AGAIN && queue != NULL);
  /* 没有回收出额度之前不通知。 */
  CHECK(ftun_operation_dispatch(queue, 4u, &dispatched) == FTUN_OK && dispatched == 0u);
  CHECK(wa.calls == 0 && wc.calls == 0);
  /* 回收一个额度：两个等待者都被通知一次（额度由重试时的 accept 最终仲裁）。 */
  CHECK(ftun_operation_complete(first_token, success) == FTUN_OK);
  CHECK(ftun_operation_dispatch(queue, 4u, &dispatched) == FTUN_OK && dispatched == 1u);
  CHECK(wa.calls == 1 && wb.calls == 0 && wc.calls == 1);
  CHECK(ftun_operation_queue_wait_cancel(&a) == FTUN_E_STALE);
  /* 通知后可重新排队；额度已回收时直接让调用方重试。 */
  CHECK(ftun_operation_queue_wait(queue, &a, wake_ready, &wa) == FTUN_E_AGAIN);
  CHECK(ftun_operation_accept(queue, noop_completed, NULL, &extra, &extra_token) == FTUN_OK);
  CHECK(ftun_operation_queue_wait(queue, &a, wake_ready, &wa) == FTUN_OK);
  CHECK(ftun_operation_queue_wait_cancel(&a) == FTUN_OK);
  /* 停止后拒绝排队。 */
  CHECK(ftun_operation_complete(second_token, success) == FTUN_OK);
  CHECK(ftun_operation_complete(extra_token, success) == FTUN_OK);
  CHECK(ftun_operation_dispatch(queue, 4u, &dispatched) == FTUN_OK && dispatched == 2u);
  CHECK(ftun_operation_queue_stop(queue) == FTUN_OK);
  CHECK(ftun_operation_queue_wait(queue, &a, wake_ready, &wa) == FTUN_E_CANCELLED);
  CHECK(ftun_operation_queue_destroy(&queue) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(void)
{
  ftun_budget_t *budget = NULL;
  ftun_operation_queue_t *queue = (ftun_operation_queue_t *)(uintptr_t)1;
  ftun_operation_t *first = (ftun_operation_t *)(uintptr_t)1;
  ftun_operation_t *second = (ftun_operation_t *)(uintptr_t)1;
  ftun_operation_t *third = (ftun_operation_t *)(uintptr_t)1;
  ftun_operation_token_t first_completion = {0};
  ftun_operation_token_t second_completion = {0};
  ftun_operation_token_t third_completion = {0};
  ftun_operation_queue_usage_t queue_usage;
  ftun_budget_usage_t budget_usage;
  callback_state_t one = {0}, two = {0}, three = {0};
  cancel_hook_state_t hook = {0};
  ftun_error_t success = {FTUN_OK, 7u, 9};
  size_t baseline;
  size_t dispatched = 99u;

  if (test_waiters() != 0) return 1;
  CHECK(ftun_budget_create(NULL, 4096u, 256u, &budget) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 2u, &queue) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  baseline = budget_usage.used;
  CHECK(baseline > 0u);
  CHECK(ftun_operation_queue_get_usage(queue, &queue_usage) == FTUN_OK);
  CHECK(queue_usage.capacity == 2u && queue_usage.inflight == 0u && queue_usage.accepting);
  CHECK(!ftun_operation_queue_has_ready(queue));

  one.queue = queue;
  one.expected = FTUN_E_CANCELLED;
  two.queue = queue;
  two.expected = FTUN_E_CANCELLED;
  CHECK(ftun_operation_accept(queue, completed, &one, &first,
                              &first_completion) == FTUN_OK);
  CHECK(ftun_operation_accept(queue, completed, &two, &second,
                              &second_completion) == FTUN_OK);
  CHECK(one.calls == 0 && two.calls == 0);
  CHECK(ftun_operation_accept(queue, completed, &three, &third,
                              &third_completion) == FTUN_E_LIMIT);
  CHECK(third == NULL && third_completion.queue == NULL &&
        third_completion.generation == 0u);
  CHECK(ftun_operation_complete(first_completion, success) == FTUN_OK);
  CHECK(one.calls == 0);
  CHECK(ftun_operation_cancel(first) == FTUN_OK);
  CHECK(ftun_operation_complete(first_completion, success) == FTUN_E_STALE);
  CHECK(ftun_operation_cancel(second) == FTUN_OK);
  CHECK(ftun_operation_cancel(second) == FTUN_E_STALE);
  CHECK(ftun_operation_queue_has_ready(queue));

  CHECK(ftun_operation_dispatch(queue, 1u, &dispatched) == FTUN_OK);
  CHECK(dispatched == 1u && one.calls == 1 && two.calls == 0);
  CHECK(one.cancel_was_stale == 1 && one.recursive_was_again == 1);
  CHECK(ftun_operation_queue_has_ready(queue));
  CHECK(ftun_operation_dispatch(queue, 2u, &dispatched) == FTUN_OK);
  CHECK(dispatched == 1u && two.calls == 1);
  CHECK(two.cancel_was_stale == 1 && two.recursive_was_again == 1);
  CHECK(!ftun_operation_queue_has_ready(queue));
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  CHECK(budget_usage.used == baseline);

  three.queue = queue;
  three.expected = FTUN_OK;
  CHECK(ftun_operation_accept(queue, completed, &three, &third,
                              &third_completion) == FTUN_OK);
  CHECK(ftun_operation_dispatch(queue, 1u, &dispatched) == FTUN_OK);
  CHECK(dispatched == 0u && three.calls == 0);
  CHECK(ftun_operation_complete(third_completion, success) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&queue) == FTUN_E_AGAIN && queue != NULL);
  CHECK(ftun_operation_dispatch(queue, 1u, &dispatched) == FTUN_OK);
  CHECK(dispatched == 1u && three.calls == 1);
  CHECK(three.cancel_was_stale == 1 && three.recursive_was_again == 1);

  one.calls = one.cancel_was_stale = one.recursive_was_again = 0;
  one.expected = FTUN_E_CANCELLED;
  hook.calls = 0;
  hook.failures = 1;
  CHECK(ftun_operation_accept(queue, completed, &one, &first,
                              &first_completion) == FTUN_OK);
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
  CHECK(ftun_operation_accept(queue, completed, &one, &first,
                              &first_completion) == FTUN_OK);
  CHECK(ftun_operation_reject(&first) == FTUN_OK && first == NULL);
  CHECK(one.calls == 0);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  CHECK(budget_usage.used == baseline);

  one.calls = one.cancel_was_stale = one.recursive_was_again = 0;
  one.expected = FTUN_E_CANCELLED;
  hook.calls = 0;
  hook.failures = 1;
  CHECK(ftun_operation_accept(queue, completed, &one, &first,
                              &first_completion) == FTUN_OK);
  CHECK(ftun_operation_complete(first_completion, success) == FTUN_OK);
  CHECK(ftun_operation_set_cancel_hook(first, cancel_hook, &hook) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(queue) == FTUN_E_IO);
  CHECK(one.calls == 0 && hook.calls == 1);
  CHECK(ftun_operation_queue_stop(queue) == FTUN_OK);
  CHECK(hook.calls == 2);
  CHECK(ftun_operation_accept(queue, completed, &two, &second,
                              &second_completion) == FTUN_E_CANCELLED);
  CHECK(second == NULL && second_completion.queue == NULL &&
        second_completion.generation == 0u);
  CHECK(ftun_operation_dispatch(queue, SIZE_MAX, &dispatched) == FTUN_OK);
  CHECK(dispatched == 1u && one.calls == 1);
  CHECK(ftun_operation_queue_get_usage(queue, &queue_usage) == FTUN_OK);
  CHECK(queue_usage.inflight == 0u && !queue_usage.accepting && !queue_usage.dispatching);

  CHECK(ftun_operation_cancel(NULL) == FTUN_E_INVALID);
  CHECK(ftun_operation_complete((ftun_operation_token_t){0}, success) ==
        FTUN_E_INVALID);
  CHECK(ftun_operation_set_cancel_hook(NULL, cancel_hook, &hook) == FTUN_E_INVALID);
  CHECK(ftun_operation_reject(NULL) == FTUN_E_INVALID);
  CHECK(ftun_operation_dispatch(queue, 0u, &dispatched) == FTUN_E_INVALID);
  CHECK(dispatched == 0u);
  CHECK(ftun_operation_dispatch(queue, 1u, NULL) == FTUN_E_INVALID);
  CHECK(ftun_operation_queue_get_usage(NULL, &queue_usage) == FTUN_E_INVALID);
  CHECK(!ftun_operation_queue_has_ready(NULL));
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
    ftun_reservation_t blocker = (ftun_reservation_t){0};
    callback_state_t rejected_state = {0};
    ftun_operation_t *reused = NULL;
    ftun_operation_token_t late_completion = {0};
    CHECK(ftun_budget_create(NULL, 512u, 0u, &budget) == FTUN_OK);
    CHECK(ftun_operation_queue_create(budget, 1u, &queue) == FTUN_OK);
    CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
    CHECK(budget_usage.normal_available > 0u);
    CHECK(ftun_budget_reserve(budget, budget_usage.normal_available, &blocker) == FTUN_OK);
    rejected_state.queue = queue;
    rejected_state.expected = FTUN_OK;
    third = (ftun_operation_t *)(uintptr_t)1;
    /* Operation 槽位随队列预留，因此稳态接纳不依赖分配器或剩余预算。 */
    CHECK(ftun_operation_accept(queue, completed, &rejected_state, &third,
                                &third_completion) == FTUN_OK);
    CHECK(third != NULL && rejected_state.calls == 0);
    CHECK(ftun_operation_complete(third_completion, success) == FTUN_OK);
    CHECK(ftun_operation_dispatch(queue, 1u, &dispatched) == FTUN_OK);
    CHECK(dispatched == 1u && rejected_state.calls == 1);
    late_completion = third_completion;
    reused = third;
    CHECK(ftun_operation_accept(queue, completed, &rejected_state, &third,
                                &third_completion) == FTUN_OK);
    CHECK(third == reused &&
          third_completion.generation != late_completion.generation);
    CHECK(ftun_operation_complete(late_completion, success) == FTUN_E_STALE);
    CHECK(rejected_state.calls == 1);
    CHECK(ftun_operation_complete(third_completion, success) == FTUN_OK);
    CHECK(ftun_operation_complete(third_completion, success) == FTUN_E_STALE);
    CHECK(ftun_operation_dispatch(queue, 1u, &dispatched) == FTUN_OK);
    CHECK(dispatched == 1u && rejected_state.calls == 2);
    CHECK(ftun_reservation_release(&blocker) == FTUN_OK);
    CHECK(ftun_operation_queue_destroy(&queue) == FTUN_OK);
    CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  }

  {
    callback_state_t normal_one = {0}, normal_two = {0}, administrative = {0};
    ftun_operation_t *normal_operation_one = NULL;
    ftun_operation_t *normal_operation_two = NULL;
    ftun_operation_t *administrative_operation = NULL;
    ftun_operation_token_t normal_token_one = {0};
    ftun_operation_token_t normal_token_two = {0};
    ftun_operation_token_t administrative_token = {0};
    CHECK(ftun_budget_create(NULL, 4096u, 0u, &budget) == FTUN_OK);
    CHECK(ftun_operation_queue_create_reserved(budget, 3u, 1u,
                                                &queue) == FTUN_OK);
    normal_one.queue = normal_two.queue = administrative.queue = queue;
    normal_one.expected = normal_two.expected = administrative.expected = FTUN_OK;
    CHECK(ftun_operation_accept(queue, completed, &normal_one,
      &normal_operation_one, &normal_token_one) == FTUN_OK);
    CHECK(ftun_operation_accept(queue, completed, &normal_two,
      &normal_operation_two, &normal_token_two) == FTUN_OK);
    third = (ftun_operation_t *)(uintptr_t)1;
    CHECK(ftun_operation_accept(queue, completed, &three, &third,
      &third_completion) == FTUN_E_LIMIT && third == NULL);
    CHECK(ftun_operation_accept_control(queue, completed, &administrative,
      &administrative_operation, &administrative_token) == FTUN_OK);
    CHECK(ftun_operation_queue_get_usage(queue, &queue_usage) == FTUN_OK &&
          queue_usage.capacity == 3u && queue_usage.control_reserve == 1u &&
          queue_usage.normal_inflight == 2u &&
          queue_usage.control_inflight == 1u &&
          queue_usage.rejected_normal == 1u);
    CHECK(ftun_operation_complete(normal_token_one, success) == FTUN_OK);
    CHECK(ftun_operation_complete(normal_token_two, success) == FTUN_OK);
    CHECK(ftun_operation_complete(administrative_token, success) == FTUN_OK);
    CHECK(ftun_operation_dispatch(queue, SIZE_MAX, &dispatched) == FTUN_OK &&
          dispatched == 3u && normal_one.calls == 1 && normal_two.calls == 1 &&
          administrative.calls == 1);
    CHECK(ftun_operation_queue_get_usage(queue, &queue_usage) == FTUN_OK &&
          queue_usage.inflight == 0u && queue_usage.normal_inflight == 0u &&
          queue_usage.control_inflight == 0u);
    CHECK(ftun_operation_queue_destroy(&queue) == FTUN_OK);
    CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
    CHECK(ftun_budget_create(NULL, 4096u, 0u, &budget) == FTUN_OK);
    CHECK(ftun_operation_queue_create_reserved(budget, 1u, 1u,
                                                &queue) == FTUN_E_INVALID &&
          queue == NULL);
    CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  }
  {
    int threaded;
    int terminal;
    int deferred;
    const ftun_status_t results[] = {FTUN_OK, FTUN_E_IO, FTUN_E_AGAIN};
    size_t index;
    for (threaded = 0; threaded <= 1; threaded++) {
      for (deferred = 0; deferred <= 1; deferred++) {
        for (terminal = 0; terminal <= 1; terminal++) {
          for (index = 0u; index < sizeof(results) / sizeof(results[0]); index++) {
            CHECK(test_cancel_window(threaded, deferred, terminal, results[index]) == 0);
          }
        }
      }
    }
  }
  CHECK(test_stop_steps() == 0);
  puts("operation: cancel windows=24; bounded stop and exactly-once passed");
  return 0;
}
