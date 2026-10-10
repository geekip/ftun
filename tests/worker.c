#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "core/operation.h"
#include "core/worker.h"
#include "util/time.h"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
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
} completion_state_t;

static pthread_mutex_t gate_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_condition = PTHREAD_COND_INITIALIZER;
static int gate_entered;
static int gate_open;
static int gate_saw_copy;
static int execute_calls;

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

/* TASK-CORE-006 / TEST-CORE-006：复制输入、有界接纳、取消与迟到清理。 */
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
  CHECK(ftun_worker_join(worker) == FTUN_E_AGAIN);
  CHECK(ftun_worker_poll(worker, 0u, &dispatched) == FTUN_E_INVALID && dispatched == 0u);
  CHECK(ftun_worker_submit(worker, NULL, completed, &echoed, &operation) == FTUN_E_INVALID);
  CHECK(operation == NULL && echoed.calls == 0);

  memset(&job, 0, sizeof(job));
  job.execute = gate_execute;
  job.input.data = mutable_input;
  job.input.length = 4u;
  job.result_capacity = 4u;
  reset_gate();
  CHECK(ftun_worker_submit(worker, &job, completed, &cancelled, &operation) == FTUN_OK);
  memcpy(mutable_input, "xxxx", 4u);
  CHECK(wait_for_gate());
  CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  CHECK(ftun_worker_poll(worker, 1u, &dispatched) == FTUN_OK);
  CHECK(dispatched == 1u && cancelled.calls == 1 &&
        cancelled.status == FTUN_E_CANCELLED && cancelled.result_size == 0u);
  CHECK(ftun_worker_get_usage(worker, &usage) == FTUN_OK);
  CHECK(usage.tasks == 1u && usage.running == 1u);
  operation = (ftun_operation_t *)(uintptr_t)1;
  CHECK(ftun_worker_submit(worker, &job, completed, &echoed, &operation) == FTUN_E_LIMIT);
  CHECK(operation == NULL && echoed.calls == 0);
  CHECK(ftun_worker_destroy(&worker) == FTUN_E_AGAIN && worker != NULL);
  open_gate();
  CHECK(wait_for_empty(worker));
  CHECK(cancelled.calls == 1);
  (void)pthread_mutex_lock(&gate_mutex);
  CHECK(gate_saw_copy);
  (void)pthread_mutex_unlock(&gate_mutex);

  job.execute = echo_execute;
  job.input.data = echo_input;
  job.input.length = 4u;
  job.result_capacity = 4u;
  job.deadline_ms = 0u;
  CHECK(ftun_worker_submit(worker, &job, completed, &echoed, &operation) == FTUN_OK);
  CHECK(echoed.calls == 0 && wait_for_calls(worker, &echoed, 1));
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

  reset_gate();
  job.execute = gate_execute;
  job.input.data = (const uint8_t *)"copy";
  CHECK(ftun_worker_submit(worker, &job, completed, &stopped, &operation) == FTUN_OK);
  CHECK(wait_for_gate());
  CHECK(ftun_worker_stop(worker) == FTUN_OK);
  CHECK(ftun_worker_stop(worker) == FTUN_OK);
  CHECK(ftun_worker_poll(worker, 1u, &dispatched) == FTUN_OK);
  CHECK(dispatched == 1u && stopped.calls == 1 && stopped.status == FTUN_E_CANCELLED);
  operation = (ftun_operation_t *)(uintptr_t)1;
  CHECK(ftun_worker_submit(worker, &job, completed, &echoed, &operation) == FTUN_E_CANCELLED);
  CHECK(operation == NULL);
  open_gate();
  CHECK(ftun_worker_join(worker) == FTUN_OK);
  CHECK(ftun_worker_join(worker) == FTUN_OK);
  CHECK(wait_for_empty(worker));
  CHECK(stopped.calls == 1);
  CHECK(ftun_worker_get_usage(worker, &usage) == FTUN_OK);
  CHECK(usage.tasks == 0u && usage.pending == 0u && usage.running == 0u &&
        usage.completed == 0u && !usage.accepting && usage.joined);

  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  CHECK(budget_usage.used > 0u);
  CHECK(ftun_worker_destroy(&worker) == FTUN_OK && worker == NULL);
  CHECK(ftun_worker_destroy(&worker) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK);
  CHECK(budget_usage.used == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);

  worker = (ftun_worker_t *)(uintptr_t)1;
  CHECK(ftun_worker_create(NULL, 1u, &worker) == FTUN_E_INVALID && worker == NULL);
  CHECK(ftun_worker_create(budget, 1u, &worker) == FTUN_E_INVALID && worker == NULL);
  CHECK(ftun_worker_destroy(NULL) == FTUN_E_INVALID);
  CHECK(ftun_worker_get_usage(NULL, &usage) == FTUN_E_INVALID);
  CHECK(usage.capacity == 0u && usage.tasks == 0u);
  return 0;
}
