#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "core/operation.h"
#include "core/worker.h"
#include "platform/clock.h"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "worker contract failed: %s\n", #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  int calls;
  ftun_status_t status;
  uint8_t result[32];
  size_t result_size;
  void *owned_result;
  int take_result;
} completion_state_t;

static pthread_mutex_t gate_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_condition = PTHREAD_COND_INITIALIZER;
static int gate_entered;
static int gate_open;
static int gate_saw_copy;
static int execute_calls;
static int input_cleanup_calls;
static int result_cleanup_calls;

static void sleep_one_millisecond(void)
{
  struct timespec delay = {0, 1000000L};
  (void)nanosleep(&delay, NULL);
}

static ftun_status_t gate_execute(ftun_bytes_t input, uint8_t *result,
                                  size_t capacity, size_t *out_size)
{
  (void)pthread_mutex_lock(&gate_mutex);
  gate_entered = 1;
  (void)pthread_cond_broadcast(&gate_condition);
  while (!gate_open) (void)pthread_cond_wait(&gate_condition, &gate_mutex);
  gate_saw_copy = input.length == 4u && memcmp(input.data, "copy", 4u) == 0;
  execute_calls++;
  (void)pthread_mutex_unlock(&gate_mutex);
  if (capacity < input.length) return FTUN_E_LIMIT;
  if (input.length != 0u) memcpy(result, input.data, input.length);
  *out_size = input.length;
  return FTUN_OK;
}

static ftun_status_t gate_owned_execute(ftun_bytes_t input, uint8_t *result,
                                        size_t capacity, size_t *out_size)
{
  void *owned;
  (void)pthread_mutex_lock(&gate_mutex);
  gate_entered = 1;
  (void)pthread_cond_broadcast(&gate_condition);
  while (!gate_open) (void)pthread_cond_wait(&gate_condition, &gate_mutex);
  gate_saw_copy = input.length == 4u && memcmp(input.data, "copy", 4u) == 0;
  execute_calls++;
  (void)pthread_mutex_unlock(&gate_mutex);
  if (capacity < sizeof(owned)) return FTUN_E_LIMIT;
  owned = malloc(1u);
  if (owned == NULL) return FTUN_E_LIMIT;
  memcpy(result, &owned, sizeof(owned));
  *out_size = sizeof(owned);
  return FTUN_OK;
}

static ftun_status_t echo_execute(ftun_bytes_t input, uint8_t *result,
                                  size_t capacity, size_t *out_size)
{
  (void)pthread_mutex_lock(&gate_mutex);
  execute_calls++;
  (void)pthread_mutex_unlock(&gate_mutex);
  if (capacity < input.length) return FTUN_E_LIMIT;
  if (input.length != 0u) memcpy(result, input.data, input.length);
  *out_size = input.length;
  return FTUN_OK;
}

static ftun_status_t fail_execute(ftun_bytes_t input, uint8_t *result,
                                  size_t capacity, size_t *out_size)
{
  (void)input;
  (void)result;
  (void)capacity;
  *out_size = 0u;
  (void)pthread_mutex_lock(&gate_mutex);
  execute_calls++;
  (void)pthread_mutex_unlock(&gate_mutex);
  return FTUN_E_IO;
}

static ftun_status_t owned_execute(ftun_bytes_t input, uint8_t *result,
                                   size_t capacity, size_t *out_size)
{
  void *owned;
  (void)input;
  if (capacity < sizeof(owned)) return FTUN_E_LIMIT;
  owned = malloc(1u);
  if (owned == NULL) return FTUN_E_LIMIT;
  memcpy(result, &owned, sizeof(owned));
  *out_size = sizeof(owned);
  return FTUN_OK;
}

static ftun_status_t input_cleanup(ftun_bytes_t input)
{
  if (input.length == 4u && memcmp(input.data, "hold", 4u) == 0) {
    input_cleanup_calls++;
  }
  return FTUN_OK;
}

static ftun_status_t result_cleanup(ftun_bytes_t result)
{
  void *owned = NULL;
  if (result.length != sizeof(owned)) return FTUN_E_INVALID;
  memcpy(&owned, result.data, sizeof(owned));
  if (owned != NULL) {
    result_cleanup_calls++;
    free(owned);
  }
  return FTUN_OK;
}

static void completed(ftun_operation_t *operation, ftun_error_t error,
                      ftun_bytes_t result, void *user)
{
  completion_state_t *state = (completion_state_t *)user;
  state->calls++;
  state->status = error.status;
  state->result_size = result.length;
  if (result.length <= sizeof(state->result) && result.length != 0u) {
    memcpy(state->result, result.data, result.length);
  }
  if (state->take_result && result.length == sizeof(state->owned_result)) {
    memcpy(&state->owned_result, result.data, sizeof(state->owned_result));
    memset((void *)(uintptr_t)result.data, 0, sizeof(state->owned_result));
  }
  if (ftun_operation_cancel(operation) != FTUN_E_STALE) state->calls = -100;
}

static int wait_for_gate(void)
{
  size_t attempt;
  for (attempt = 0u; attempt < 5000u; attempt++) {
    int entered;
    (void)pthread_mutex_lock(&gate_mutex);
    entered = gate_entered;
    (void)pthread_mutex_unlock(&gate_mutex);
    if (entered) return 1;
    sleep_one_millisecond();
  }
  return 0;
}

static int wait_for_calls(ftun_worker_t *worker, completion_state_t *state,
                          int calls)
{
  size_t attempt;
  for (attempt = 0u; attempt < 5000u; attempt++) {
    size_t dispatched = 0u;
    if (ftun_worker_poll(worker, 8u, &dispatched) != FTUN_OK) return 0;
    if (state->calls == calls) return 1;
    sleep_one_millisecond();
  }
  return 0;
}

static int wait_for_ready(ftun_worker_t *worker)
{
  size_t attempt;
  for (attempt = 0u; attempt < 5000u; attempt++) {
    if (ftun_worker_has_ready(worker)) return 1;
    sleep_one_millisecond();
  }
  return 0;
}

static int wait_for_empty(ftun_worker_t *worker)
{
  size_t attempt;
  for (attempt = 0u; attempt < 5000u; attempt++) {
    ftun_worker_usage_t usage;
    size_t dispatched = 0u;
    if (ftun_worker_poll(worker, 8u, &dispatched) != FTUN_OK ||
        ftun_worker_get_usage(worker, &usage) != FTUN_OK) return 0;
    if (usage.tasks == 0u) return 1;
    sleep_one_millisecond();
  }
  return 0;
}

static int get_execute_calls(void)
{
  int calls;
  (void)pthread_mutex_lock(&gate_mutex);
  calls = execute_calls;
  (void)pthread_mutex_unlock(&gate_mutex);
  return calls;
}

static void reset_gate(void)
{
  (void)pthread_mutex_lock(&gate_mutex);
  gate_entered = 0;
  gate_open = 0;
  gate_saw_copy = 0;
  (void)pthread_mutex_unlock(&gate_mutex);
}

static void open_gate(void)
{
  (void)pthread_mutex_lock(&gate_mutex);
  gate_open = 1;
  (void)pthread_cond_broadcast(&gate_condition);
  (void)pthread_mutex_unlock(&gate_mutex);
}

static ftun_status_t retry_result_status, retry_input_status;
static size_t retry_result_calls, retry_input_calls, retry_freed;

static ftun_status_t retry_result_cleanup(ftun_bytes_t bytes)
{
  void *owned = NULL;
  retry_result_calls++;
  if (retry_result_status != FTUN_OK) return retry_result_status;
  if (bytes.length != sizeof(owned)) return FTUN_E_INVALID;
  memcpy(&owned, bytes.data, sizeof(owned));
  if (owned != NULL) { free(owned); retry_freed++; }
  owned = NULL;
  memcpy((void *)(uintptr_t)bytes.data, &owned, sizeof(owned));
  return FTUN_OK;
}

static ftun_status_t retry_input_cleanup(ftun_bytes_t bytes)
{
  (void)bytes;
  retry_input_calls++;
  return retry_input_status;
}

static ftun_status_t failed_owned_execute(ftun_bytes_t input, uint8_t *result,
                                           size_t capacity, size_t *out_size)
{
  ftun_status_t status = owned_execute(input, result, capacity, out_size);
  return status == FTUN_OK ? FTUN_E_IO : status;
}

/* 结果失败、输入失败、执行错误和迟到取消均保留同一任务槽及额度。 */
static int retry_cleanup(unsigned mode)
{
  ftun_budget_t *budget = NULL;
  ftun_worker_t *worker = NULL;
  ftun_worker_job_t job = {0};
  ftun_worker_usage_t usage;
  ftun_budget_usage_t memory;
  ftun_operation_t *operation = NULL, *rejected = NULL;
  completion_state_t completion = {0}, unused = {0};
  size_t count, baseline, charged;
  retry_result_calls = retry_input_calls = retry_freed = 0u;
  retry_result_status = FTUN_E_AGAIN;
  retry_input_status = FTUN_E_IO;
  CHECK(ftun_budget_create(NULL, 65536u, 1024u, &budget) == FTUN_OK);
  CHECK(ftun_worker_create(budget, 1u, &worker) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &memory) == FTUN_OK);
  baseline = memory.used;
  job.execute = mode == 2u ? gate_owned_execute :
    mode == 1u ? failed_owned_execute : owned_execute;
  job.result_capacity = sizeof(void *);
  job.input = (ftun_bytes_t){(const uint8_t *)"copy", 4u};
  job.result_cleanup = retry_result_cleanup;
  job.input_cleanup = retry_input_cleanup;
  if (mode == 2u) reset_gate();
  CHECK(ftun_worker_submit(worker, &job, completed, &completion, &operation) == FTUN_OK);
  if (mode == 2u) {
    CHECK(wait_for_gate());
    CHECK(ftun_operation_cancel(operation) == FTUN_OK);
    CHECK(ftun_worker_poll(worker, 1u, &count) == FTUN_OK && count == 1u);
    CHECK(retry_result_calls == 0u && retry_input_calls == 0u);
    open_gate();
  }
  CHECK(wait_for_ready(worker));
  CHECK(ftun_worker_poll(worker, 1u, &count) == FTUN_E_AGAIN);
  CHECK(completion.calls == 1 && retry_result_calls == 1u && retry_input_calls == 0u);
  CHECK(completion.status == (mode == 2u ? FTUN_E_CANCELLED :
    mode == 1u ? FTUN_E_IO : FTUN_OK));
  CHECK(completion.result_size == (mode == 0u ? sizeof(void *) : 0u));
  CHECK(ftun_worker_get_usage(worker, &usage) == FTUN_OK &&
    usage.tasks == 1u && usage.cleanup_pending == 1u && usage.running == 0u);
  CHECK(ftun_budget_get_usage(budget, &memory) == FTUN_OK && memory.used > baseline);
  charged = memory.used;
  CHECK(ftun_worker_submit(worker, &job, completed, &unused, &rejected) == FTUN_E_LIMIT && rejected == NULL);
  CHECK(ftun_worker_poll(worker, 8u, &count) == FTUN_E_AGAIN && count == 0u);
  CHECK(retry_result_calls == 2u && retry_freed == 0u && retry_input_calls == 0u);
  CHECK(ftun_budget_get_usage(budget, &memory) == FTUN_OK && memory.used == charged);
  retry_result_status = FTUN_OK;
  CHECK(ftun_worker_poll(worker, 8u, &count) == FTUN_E_IO && count == 0u);
  CHECK(retry_result_calls == 3u && retry_freed == 1u && retry_input_calls == 1u);
  CHECK(ftun_worker_stop(worker) == FTUN_OK);
  CHECK(ftun_worker_join(worker) == FTUN_OK);
  CHECK(ftun_worker_destroy(&worker) == FTUN_E_AGAIN && worker != NULL);
  CHECK(ftun_worker_poll(worker, 8u, &count) == FTUN_E_IO);
  CHECK(retry_result_calls == 3u && retry_input_calls == 2u && completion.calls == 1);
  CHECK(ftun_budget_get_usage(budget, &memory) == FTUN_OK && memory.used == charged);
  retry_input_status = FTUN_OK;
  CHECK(ftun_worker_poll(worker, 8u, &count) == FTUN_OK && count == 0u);
  CHECK(retry_input_calls == 3u && retry_result_calls == 3u && retry_freed == 1u);
  CHECK(ftun_worker_get_usage(worker, &usage) == FTUN_OK && usage.tasks == 0u && usage.cleanup_pending == 0u);
  CHECK(!ftun_worker_has_ready(worker));
  CHECK(ftun_budget_get_usage(budget, &memory) == FTUN_OK && memory.used == baseline);
  CHECK(ftun_worker_destroy(&worker) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &memory) == FTUN_OK && memory.used == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int cleanup_quota(void)
{
  ftun_budget_t *budget = NULL;
  ftun_worker_t *worker = NULL;
  ftun_worker_job_t job = {0};
  ftun_operation_t *operation = NULL;
  completion_state_t first = {0}, second = {0};
  ftun_worker_usage_t usage;
  size_t count, attempts, prior;
  retry_result_calls = retry_freed = 0u;
  retry_result_status = FTUN_E_IO;
  CHECK(ftun_budget_create(NULL, 65536u, 1024u, &budget) == FTUN_OK);
  CHECK(ftun_worker_create(budget, 2u, &worker) == FTUN_OK);
  job.execute = owned_execute;
  job.result_capacity = sizeof(void *);
  job.result_cleanup = retry_result_cleanup;
  CHECK(ftun_worker_submit(worker, &job, completed, &first, &operation) == FTUN_OK);
  CHECK(ftun_worker_submit(worker, &job, completed, &second, &operation) == FTUN_OK);
  for (attempts = 0u; attempts < 5000u; attempts++) {
    CHECK(ftun_worker_get_usage(worker, &usage) == FTUN_OK);
    if (usage.completed == 2u) break;
    sleep_one_millisecond();
  }
  CHECK(usage.completed == 2u);
  CHECK(ftun_worker_poll(worker, 2u, &count) == FTUN_E_IO && count == 2u);
  prior = retry_result_calls;
  CHECK(prior == 2u);
  CHECK(ftun_worker_poll(worker, 1u, &count) == FTUN_E_IO && count == 0u);
  CHECK(retry_result_calls == prior + 1u);
  retry_result_status = FTUN_OK;
  CHECK(ftun_worker_poll(worker, 1u, &count) == FTUN_OK && count == 0u);
  CHECK(ftun_worker_get_usage(worker, &usage) == FTUN_OK && usage.cleanup_pending == 1u && usage.tasks == 1u);
  CHECK(ftun_worker_poll(worker, 1u, &count) == FTUN_OK);
  CHECK(retry_freed == 2u && first.calls == 1 && second.calls == 1);
  CHECK(ftun_worker_stop(worker) == FTUN_OK && ftun_worker_join(worker) == FTUN_OK);
  CHECK(ftun_worker_destroy(&worker) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

/* 复制输入、有界接纳、取消与迟到清理。 */
int main(void)
{
  ftun_budget_t *budget = NULL;
  ftun_worker_t *worker = (ftun_worker_t *)(uintptr_t)1;
  ftun_operation_t *operation = (ftun_operation_t *)(uintptr_t)1;
  ftun_worker_usage_t usage;
  ftun_budget_usage_t budget_usage;
  completion_state_t cancelled = {0};
  completion_state_t echoed = {0};
  completion_state_t timed_out = {0};
  completion_state_t failed = {0};
  completion_state_t stopped = {0};
  completion_state_t discarded_owned = {0};
  completion_state_t taken_owned = {0};
  uint8_t mutable_input[] = "copy";
  uint8_t echo_input[] = "echo";
  ftun_worker_job_t job;
  uint64_t now = 0u;
  size_t dispatched = 99u;
  int calls_before_timeout;

  CHECK(ftun_budget_create(NULL, 65536u, 1024u, &budget) == FTUN_OK);
  CHECK(ftun_worker_create(budget, 1u, &worker) == FTUN_OK);
  CHECK(ftun_worker_get_usage(worker, &usage) == FTUN_OK);
  CHECK(usage.capacity == 1u && usage.tasks == 0u && usage.accepting && !usage.joined);
  CHECK(!ftun_worker_has_ready(worker) && !ftun_worker_has_ready(NULL));
  CHECK(ftun_worker_join(worker) == FTUN_E_AGAIN);
  CHECK(ftun_worker_poll(worker, 0u, &dispatched) == FTUN_E_INVALID && dispatched == 0u);
  CHECK(ftun_worker_submit(worker, NULL, completed, &echoed, &operation) == FTUN_E_INVALID);
  CHECK(operation == NULL && echoed.calls == 0);

  memset(&job, 0, sizeof(job));
  job.execute = gate_owned_execute;
  job.input.data = mutable_input;
  job.input.length = 4u;
  job.result_capacity = sizeof(void *);
  job.result_cleanup = result_cleanup;
  reset_gate();
  CHECK(ftun_worker_submit(worker, &job, completed, &cancelled, &operation) == FTUN_OK);
  memcpy(mutable_input, "xxxx", 4u);
  CHECK(wait_for_gate());
  CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  CHECK(ftun_worker_has_ready(worker));
  CHECK(ftun_worker_poll(worker, 1u, &dispatched) == FTUN_OK);
  CHECK(dispatched == 1u && cancelled.calls == 1 &&
        cancelled.status == FTUN_E_CANCELLED && cancelled.result_size == 0u);
  CHECK(!ftun_worker_has_ready(worker));
  CHECK(ftun_worker_get_usage(worker, &usage) == FTUN_OK);
  CHECK(usage.tasks == 1u && usage.running == 1u);
  operation = (ftun_operation_t *)(uintptr_t)1;
  CHECK(ftun_worker_submit(worker, &job, completed, &echoed, &operation) == FTUN_E_LIMIT);
  CHECK(operation == NULL && echoed.calls == 0);
  CHECK(ftun_worker_destroy(&worker) == FTUN_E_AGAIN && worker != NULL);
  open_gate();
  CHECK(wait_for_empty(worker));
  CHECK(cancelled.calls == 1);
  CHECK(result_cleanup_calls == 1);
  (void)pthread_mutex_lock(&gate_mutex);
  CHECK(gate_saw_copy);
  (void)pthread_mutex_unlock(&gate_mutex);

  job.execute = echo_execute;
  job.input.data = echo_input;
  job.input.length = 4u;
  job.result_capacity = 4u;
  job.deadline_ms = 0u;
  job.result_cleanup = NULL;
  CHECK(ftun_worker_submit(worker, &job, completed, &echoed, &operation) == FTUN_OK);
  CHECK(echoed.calls == 0 && wait_for_ready(worker) &&
        wait_for_calls(worker, &echoed, 1));
  CHECK(echoed.status == FTUN_OK && echoed.result_size == 4u &&
        memcmp(echoed.result, "echo", 4u) == 0);

  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  calls_before_timeout = get_execute_calls();
  job.deadline_ms = now;
  CHECK(ftun_worker_submit(worker, &job, completed, &timed_out, &operation) == FTUN_OK);
  CHECK(wait_for_calls(worker, &timed_out, 1));
  CHECK(timed_out.status == FTUN_E_TIMEOUT && timed_out.result_size == 0u);
  CHECK(get_execute_calls() == calls_before_timeout);

  job.execute = fail_execute;
  job.deadline_ms = 0u;
  CHECK(ftun_worker_submit(worker, &job, completed, &failed, &operation) == FTUN_OK);
  CHECK(wait_for_calls(worker, &failed, 1));
  CHECK(failed.status == FTUN_E_IO && failed.result_size == 0u);

  memset(&job, 0, sizeof(job));
  job.execute = owned_execute;
  job.input.data = (const uint8_t *)"hold";
  job.input.length = 4u;
  job.result_capacity = sizeof(void *);
  job.accounted_extra = 32u;
  job.input_cleanup = input_cleanup;
  job.result_cleanup = result_cleanup;
  CHECK(ftun_worker_submit(worker, &job, completed, &discarded_owned,
                           &operation) == FTUN_OK);
  CHECK(wait_for_calls(worker, &discarded_owned, 1));
  CHECK(result_cleanup_calls == 2 && input_cleanup_calls == 1);
  taken_owned.take_result = 1;
  CHECK(ftun_worker_submit(worker, &job, completed, &taken_owned,
                           &operation) == FTUN_OK);
  CHECK(wait_for_calls(worker, &taken_owned, 1));
  CHECK(taken_owned.owned_result != NULL && result_cleanup_calls == 2 &&
        input_cleanup_calls == 2);
  free(taken_owned.owned_result);
  taken_owned.owned_result = NULL;

  reset_gate();
  memset(&job, 0, sizeof(job));
  job.execute = gate_execute;
  job.input.data = (const uint8_t *)"copy";
  job.input.length = 4u;
  job.result_capacity = 4u;
  CHECK(ftun_worker_submit(worker, &job, completed, &stopped, &operation) == FTUN_OK);
  CHECK(wait_for_gate());
  CHECK(ftun_worker_stop(worker) == FTUN_OK);
  CHECK(ftun_worker_stop(worker) == FTUN_OK);
  CHECK(ftun_worker_poll(worker, 1u, &dispatched) == FTUN_OK);
  CHECK(dispatched == 1u && stopped.calls == 1 && stopped.status == FTUN_E_CANCELLED);
  operation = (ftun_operation_t *)(uintptr_t)1;
  CHECK(ftun_worker_submit(worker, &job, completed, &echoed, &operation) == FTUN_E_CANCELLED);
  CHECK(operation == NULL);
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  CHECK(ftun_worker_join_until(worker, now) == FTUN_E_TIMEOUT);
  CHECK(ftun_worker_get_usage(worker, &usage) == FTUN_OK);
  CHECK(usage.stopping && !usage.exited && !usage.joined &&
        usage.tasks == 1u && usage.running == 1u);
  CHECK(ftun_worker_destroy(&worker) == FTUN_E_AGAIN && worker != NULL);
  open_gate();
  CHECK(ftun_worker_join_until(worker, UINT64_MAX) == FTUN_OK);
  CHECK(ftun_worker_join(worker) == FTUN_OK);
  CHECK(wait_for_empty(worker));
  CHECK(stopped.calls == 1);
  CHECK(ftun_worker_get_usage(worker, &usage) == FTUN_OK);
  CHECK(usage.tasks == 0u && usage.pending == 0u && usage.running == 0u &&
        usage.completed == 0u && !usage.accepting && usage.stopping &&
        usage.exited && usage.joined);

  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  CHECK(budget_usage.used > 0u);
  CHECK(ftun_worker_destroy(&worker) == FTUN_OK && worker == NULL);
  CHECK(ftun_worker_destroy(&worker) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  CHECK(budget_usage.used == 0u);

  /* Completion ingestion and callback dispatch share a finite owner round.
   * Leaving two completions queued after a quota-one poll proves the worker
   * cannot hide an unbounded completion drain behind max_callbacks. */
  {
    completion_state_t burst[3] = {{0}, {0}, {0}};
    size_t index;
    CHECK(ftun_worker_create(budget, 3u, &worker) == FTUN_OK);
    memset(&job, 0, sizeof(job));
    job.execute = echo_execute;
    job.input.data = echo_input;
    job.input.length = 4u;
    job.result_capacity = 4u;
    for (index = 0u; index < 3u; index++) {
      CHECK(ftun_worker_submit(worker, &job, completed, &burst[index],
                               &operation) == FTUN_OK);
    }
    for (index = 0u; index < 5000u; index++) {
      CHECK(ftun_worker_get_usage(worker, &usage) == FTUN_OK);
      if (usage.completed == 3u) break;
      sleep_one_millisecond();
    }
    CHECK(usage.completed == 3u);
    CHECK(ftun_worker_poll(worker, 1u, &dispatched) == FTUN_OK &&
          dispatched == 1u && burst[0].calls == 1);
    CHECK(ftun_worker_get_usage(worker, &usage) == FTUN_OK &&
          usage.completed == 2u);
    CHECK(ftun_worker_poll(worker, 1u, &dispatched) == FTUN_OK &&
          dispatched == 1u);
    CHECK(ftun_worker_poll(worker, 1u, &dispatched) == FTUN_OK &&
          dispatched == 1u && burst[0].calls + burst[1].calls +
          burst[2].calls == 3);
    CHECK(ftun_worker_stop(worker) == FTUN_OK);
    CHECK(ftun_worker_join(worker) == FTUN_OK);
    CHECK(ftun_worker_destroy(&worker) == FTUN_OK && worker == NULL);
  }
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);

  worker = (ftun_worker_t *)(uintptr_t)1;
  CHECK(ftun_worker_create(NULL, 1u, &worker) == FTUN_E_INVALID && worker == NULL);
  CHECK(ftun_worker_create(budget, 1u, &worker) == FTUN_E_INVALID && worker == NULL);
  CHECK(ftun_worker_destroy(NULL) == FTUN_E_INVALID);
  CHECK(ftun_worker_get_usage(NULL, &usage) == FTUN_E_INVALID);
  CHECK(usage.capacity == 0u && usage.tasks == 0u);
  CHECK(retry_cleanup(0u) == 0);
  CHECK(retry_cleanup(1u) == 0);
  CHECK(retry_cleanup(2u) == 0);
  CHECK(cleanup_quota() == 0);
  return 0;
}
