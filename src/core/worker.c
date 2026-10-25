#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "worker.h"
#include "core/operation.h"
#include "util/time.h"
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct ftun_worker_task ftun_worker_task_t;

struct ftun_worker_task {
  ftun_worker_t *worker;
  ftun_worker_task_t *next;
  ftun_worker_execute_fn execute;
  ftun_worker_input_cleanup_fn input_cleanup;
  ftun_worker_result_cleanup_fn result_cleanup;
  ftun_worker_completion_fn callback;
  void *user;
  uint8_t *input;
  size_t input_size;
  uint8_t *result;
  size_t result_capacity;
  size_t result_size;
  size_t cleanup_result_size;
  uint64_t deadline_ms;
  ftun_operation_t *operation;
  ftun_operation_token_t completion_token;
  ftun_reservation_t *reservation;
  ftun_error_t error;
  int worker_done;
  int callback_done;
};

struct ftun_worker {
  ftun_budget_t *budget;
  ftun_reservation_t *reservation;
  ftun_operation_queue_t *operations;
  pthread_t thread;
  pthread_mutex_t mutex;
  pthread_cond_t ready;
  ftun_worker_task_t *pending_head;
  ftun_worker_task_t *pending_tail;
  ftun_worker_task_t *completed_head;
  ftun_worker_task_t *completed_tail;
  ftun_worker_task_t *cleanup_head;
  ftun_worker_task_t *cleanup_tail;
  _Atomic size_t cleanup_pending;
  ftun_status_t cleanup_status;
  size_t capacity;
  size_t tasks;
  size_t pending;
  size_t running;
  _Atomic size_t completed;
  ftun_worker_wakeup_fn wakeup;
  void *wakeup_user;
  int accepting;
  int stopping;
  int exited;
  int joined;
  int polling;
  int cleanup_failed;
};

/* TASK-CORE-006 / TEST-CORE-006，目标 0.2.0：有界文件 worker。 */
static ftun_error_t ftun_worker_error(ftun_status_t status)
{
  ftun_error_t error;
  memset(&error, 0, sizeof(error));
  error.status = status;
  return error;
}

static int ftun_worker_expired(uint64_t deadline_ms, ftun_status_t *clock_status)
{
  uint64_t now = 0u;
  if (deadline_ms == 0u) {
    *clock_status = FTUN_OK;
    return 0;
  }
  *clock_status = ftun_monotonic_now(&now);
  return *clock_status == FTUN_OK && now >= deadline_ms;
}

static void ftun_worker_complete_list(ftun_worker_t *worker, ftun_worker_task_t *task)
{
  task->next = NULL;
  if (worker->completed_tail != NULL) worker->completed_tail->next = task;
  else worker->completed_head = task;
  worker->completed_tail = task;
  (void)atomic_fetch_add_explicit(&worker->completed, 1u,
                                  memory_order_release);
}

static ftun_status_t ftun_worker_task_dispose(ftun_worker_task_t *task)
{
  ftun_worker_t *worker = task->worker;
  ftun_status_t status;

  if (task->result_cleanup != NULL && task->worker_done &&
      task->cleanup_result_size != 0u) {
    status = task->result_cleanup((ftun_bytes_t){task->result,
                                                 task->cleanup_result_size});
    if (status != FTUN_OK) return status;
    task->cleanup_result_size = 0u;
  }
  if (task->input_cleanup != NULL) {
    status = task->input_cleanup((ftun_bytes_t){task->input, task->input_size});
    if (status != FTUN_OK) return status;
    task->input_cleanup = NULL;
  }
  status = ftun_reservation_release(&task->reservation);
  if (status != FTUN_OK) return status;
  free(task->result);
  free(task->input);
  task->result = NULL;
  task->input = NULL;
  free(task);

  (void)pthread_mutex_lock(&worker->mutex);
  if (worker->tasks == 0u) worker->cleanup_failed = 1;
  else worker->tasks--;
  (void)pthread_mutex_unlock(&worker->mutex);
  return FTUN_OK;
}

/* 仅 owner 操作；复用已接纳任务槽，不新增分配或解除原预算。 */
static void ftun_worker_task_retire(ftun_worker_task_t *task)
{
  ftun_worker_t *worker = task->worker;
  ftun_status_t status = ftun_worker_task_dispose(task);
  if (status == FTUN_OK) return;
  if (worker->cleanup_status == FTUN_OK) worker->cleanup_status = status;
  task->next = NULL;
  if (worker->cleanup_tail != NULL) worker->cleanup_tail->next = task;
  else worker->cleanup_head = task;
  worker->cleanup_tail = task;
  (void)atomic_fetch_add_explicit(&worker->cleanup_pending, 1u,
                                  memory_order_relaxed);
}

static void ftun_worker_operation_done(ftun_operation_t *operation,
                                       ftun_error_t error, void *user)
{
  ftun_worker_task_t *task = (ftun_worker_task_t *)user;
  ftun_bytes_t result;
  int dispose;

  result.data = NULL;
  result.length = 0u;
  if (error.status == FTUN_OK && task->worker_done) {
    result.data = task->result;
    result.length = task->result_size;
  }
  task->callback(operation, error, result, task->user);
  task->operation = NULL;
  task->callback_done = 1;
  dispose = task->worker_done;
  if (dispose) ftun_worker_task_retire(task);
}

static void ftun_worker_run_task(ftun_worker_task_t *task)
{
  ftun_status_t status;
  size_t result_size = 0u;

  if (ftun_worker_expired(task->deadline_ms, &status)) {
    task->error = ftun_worker_error(FTUN_E_TIMEOUT);
    return;
  }
  if (status != FTUN_OK) {
    task->error = ftun_worker_error(status);
    return;
  }

  status = task->execute((ftun_bytes_t){task->input, task->input_size},
                         task->result, task->result_capacity, &result_size);
  if (result_size > task->result_capacity) {
    status = FTUN_E_STATE_CORRUPT;
    result_size = 0u;
  }
  task->cleanup_result_size = result_size;
  if (status == FTUN_OK && ftun_worker_expired(task->deadline_ms, &status)) {
    status = FTUN_E_TIMEOUT;
  }
  if (status != FTUN_OK) result_size = 0u;
  task->result_size = result_size;
  task->error = ftun_worker_error(status);
}

static void *ftun_worker_thread(void *user)
{
  ftun_worker_t *worker = (ftun_worker_t *)user;
  for (;;) {
    ftun_worker_task_t *task;
    int cancel_without_run;

    (void)pthread_mutex_lock(&worker->mutex);
    while (worker->pending_head == NULL && !worker->stopping) {
      (void)pthread_cond_wait(&worker->ready, &worker->mutex);
    }
    if (worker->pending_head == NULL && worker->stopping) {
      worker->exited = 1;
      (void)pthread_cond_broadcast(&worker->ready);
      (void)pthread_mutex_unlock(&worker->mutex);
      break;
    }
    task = worker->pending_head;
    worker->pending_head = task->next;
    if (worker->pending_head == NULL) worker->pending_tail = NULL;
    task->next = NULL;
    worker->pending--;
    cancel_without_run = worker->stopping;
    if (!cancel_without_run) worker->running++;
    (void)pthread_mutex_unlock(&worker->mutex);

    if (cancel_without_run) task->error = ftun_worker_error(FTUN_E_CANCELLED);
    else ftun_worker_run_task(task);

    (void)pthread_mutex_lock(&worker->mutex);
    if (!cancel_without_run) worker->running--;
    ftun_worker_complete_list(worker, task);
    {
      ftun_worker_wakeup_fn wakeup = worker->wakeup;
      void *wakeup_user = worker->wakeup_user;
      (void)pthread_mutex_unlock(&worker->mutex);
      if (wakeup != NULL) wakeup(wakeup_user);
    }
  }
  return NULL;
}

ftun_status_t ftun_worker_create(ftun_budget_t *budget, size_t capacity,
                                 ftun_worker_t **out)
{
  ftun_worker_t *worker;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  pthread_condattr_t condition_attributes;
  int mutex_ready = 0;
  int condition_ready = 0;
  int condition_attributes_ready = 0;

  if (out != NULL) *out = NULL;
  if (budget == NULL || capacity == 0u || out == NULL) return FTUN_E_INVALID;
  status = ftun_budget_reserve(budget, sizeof(*worker), &reservation);
  if (status != FTUN_OK) return status;
  worker = (ftun_worker_t *)calloc(1u, sizeof(*worker));
  if (worker == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  worker->budget = budget;
  worker->reservation = reservation;
  worker->capacity = capacity;
  worker->accepting = 1;
  atomic_init(&worker->completed, 0u);
  atomic_init(&worker->cleanup_pending, 0u);
  if (pthread_mutex_init(&worker->mutex, NULL) != 0) goto io_error;
  mutex_ready = 1;
  if (pthread_condattr_init(&condition_attributes) != 0) goto io_error;
  condition_attributes_ready = 1;
  if (pthread_condattr_setclock(&condition_attributes, CLOCK_MONOTONIC) != 0 ||
      pthread_cond_init(&worker->ready, &condition_attributes) != 0) {
    goto io_error;
  }
  condition_ready = 1;
  (void)pthread_condattr_destroy(&condition_attributes);
  condition_attributes_ready = 0;
  status = ftun_operation_queue_create(budget, capacity, &worker->operations);
  if (status != FTUN_OK) goto status_error;
  if (pthread_create(&worker->thread, NULL, ftun_worker_thread, worker) != 0) {
    status = FTUN_E_IO;
    goto queue_error;
  }
  *out = worker;
  return FTUN_OK;

queue_error:
  (void)ftun_operation_queue_destroy(&worker->operations);
status_error:
  if (condition_attributes_ready) {
    (void)pthread_condattr_destroy(&condition_attributes);
  }
  if (condition_ready) (void)pthread_cond_destroy(&worker->ready);
  if (mutex_ready) (void)pthread_mutex_destroy(&worker->mutex);
  reservation = worker->reservation;
  worker->reservation = NULL;
  (void)ftun_reservation_release(&reservation);
  free(worker);
  return status;

io_error:
  status = FTUN_E_IO;
  goto status_error;
}

ftun_status_t ftun_worker_set_wakeup(ftun_worker_t *worker,
                                     ftun_worker_wakeup_fn wakeup,
                                     void *user)
{
  if (worker == NULL || (wakeup == NULL && user != NULL)) {
    return FTUN_E_INVALID;
  }
  (void)pthread_mutex_lock(&worker->mutex);
  if (!worker->accepting || worker->tasks != 0u) {
    (void)pthread_mutex_unlock(&worker->mutex);
    return FTUN_E_AGAIN;
  }
  worker->wakeup = wakeup;
  worker->wakeup_user = user;
  (void)pthread_mutex_unlock(&worker->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_worker_submit(ftun_worker_t *worker, const ftun_worker_job_t *job,
                                 ftun_worker_completion_fn callback, void *user,
                                 ftun_operation_t **out)
{
  ftun_worker_task_t *task;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  size_t charge;

  if (out != NULL) *out = NULL;
  if (worker == NULL || job == NULL || callback == NULL || out == NULL ||
      job->execute == NULL || (job->input.length != 0u && job->input.data == NULL)) {
    return FTUN_E_INVALID;
  }
  if (job->input.length > SIZE_MAX - sizeof(*task) ||
      job->result_capacity > SIZE_MAX - sizeof(*task) - job->input.length ||
      job->accounted_extra > SIZE_MAX - sizeof(*task) - job->input.length -
                               job->result_capacity) {
    return FTUN_E_LIMIT;
  }
  charge = sizeof(*task) + job->input.length + job->result_capacity +
           job->accounted_extra;

  (void)pthread_mutex_lock(&worker->mutex);
  if (!worker->accepting) {
    (void)pthread_mutex_unlock(&worker->mutex);
    return FTUN_E_CANCELLED;
  }
  if (worker->tasks >= worker->capacity) {
    (void)pthread_mutex_unlock(&worker->mutex);
    return FTUN_E_LIMIT;
  }
  status = ftun_budget_reserve(worker->budget, charge, &reservation);
  if (status != FTUN_OK) {
    (void)pthread_mutex_unlock(&worker->mutex);
    return status;
  }
  task = (ftun_worker_task_t *)calloc(1u, sizeof(*task));
  if (task == NULL) {
    (void)ftun_reservation_release(&reservation);
    (void)pthread_mutex_unlock(&worker->mutex);
    return FTUN_E_LIMIT;
  }
  if (job->input.length != 0u) {
    task->input = (uint8_t *)malloc(job->input.length);
    if (task->input == NULL) goto allocation_error;
    memcpy(task->input, job->input.data, job->input.length);
  }
  if (job->result_capacity != 0u) {
    task->result = (uint8_t *)malloc(job->result_capacity);
    if (task->result == NULL) goto allocation_error;
  }
  task->worker = worker;
  task->execute = job->execute;
  task->input_cleanup = job->input_cleanup;
  task->result_cleanup = job->result_cleanup;
  task->callback = callback;
  task->user = user;
  task->input_size = job->input.length;
  task->result_capacity = job->result_capacity;
  task->deadline_ms = job->deadline_ms;
  task->reservation = reservation;
  status = ftun_operation_accept(worker->operations, ftun_worker_operation_done,
                                 task, &task->operation,
                                 &task->completion_token);
  if (status != FTUN_OK) goto accept_error;
  worker->tasks++;
  if (worker->pending_tail != NULL) worker->pending_tail->next = task;
  else worker->pending_head = task;
  worker->pending_tail = task;
  worker->pending++;
  *out = task->operation;
  (void)pthread_cond_signal(&worker->ready);
  (void)pthread_mutex_unlock(&worker->mutex);
  return FTUN_OK;

accept_error:
  reservation = task->reservation;
  task->reservation = NULL;
allocation_error:
  free(task->result);
  free(task->input);
  free(task);
  (void)ftun_reservation_release(&reservation);
  (void)pthread_mutex_unlock(&worker->mutex);
  return status == FTUN_OK ? FTUN_E_LIMIT : status;
}

ftun_status_t ftun_worker_poll(ftun_worker_t *worker, size_t max_callbacks,
                               size_t *out_callbacks)
{
  ftun_status_t status = FTUN_OK;
  size_t dispatched = 0u;
  size_t completed = 0u;
  size_t cleanup_count;
  size_t index;

  if (out_callbacks != NULL) *out_callbacks = 0u;
  if (worker == NULL || max_callbacks == 0u || out_callbacks == NULL) {
    return FTUN_E_INVALID;
  }
  if (!ftun_worker_has_ready(worker)) return FTUN_OK;
  if (worker->polling) return FTUN_E_AGAIN;
  worker->polling = 1;
  worker->cleanup_status = FTUN_OK;
  /* 只重试入轮时已积压的对象，每对象每轮最多一次；新失败留到下轮。 */
  cleanup_count = atomic_load_explicit(&worker->cleanup_pending,
                                       memory_order_relaxed);
  if (cleanup_count > max_callbacks) cleanup_count = max_callbacks;
  for (index = 0u; index < cleanup_count; index++) {
    ftun_worker_task_t *task = worker->cleanup_head;
    worker->cleanup_head = task->next;
    if (worker->cleanup_head == NULL) worker->cleanup_tail = NULL;
    task->next = NULL;
    (void)atomic_fetch_sub_explicit(&worker->cleanup_pending, 1u,
                                    memory_order_relaxed);
    ftun_worker_task_retire(task);
  }
  while (completed < max_callbacks) {
    ftun_worker_task_t *task;
    int dispose;

    (void)pthread_mutex_lock(&worker->mutex);
    task = worker->completed_head;
    if (task != NULL) {
      worker->completed_head = task->next;
      if (worker->completed_head == NULL) worker->completed_tail = NULL;
      task->next = NULL;
      (void)atomic_fetch_sub_explicit(&worker->completed, 1u,
                                      memory_order_relaxed);
      task->worker_done = 1;
    }
    (void)pthread_mutex_unlock(&worker->mutex);
    if (task == NULL) break;
    completed++;
    if (task->operation != NULL) {
      ftun_status_t complete_status = ftun_operation_complete(
        task->completion_token, task->error);
      if (complete_status != FTUN_OK && complete_status != FTUN_E_STALE) {
        status = complete_status;
      }
    }
    dispose = task->callback_done;
    if (dispose) ftun_worker_task_retire(task);
  }
  if (status == FTUN_OK) {
    status = ftun_operation_dispatch(worker->operations, max_callbacks, &dispatched);
  }
  worker->polling = 0;
  *out_callbacks = dispatched;
  if (status == FTUN_OK && worker->cleanup_failed) return FTUN_E_STATE_CORRUPT;
  if (status == FTUN_OK) status = worker->cleanup_status;
  return status;
}

bool ftun_worker_has_ready(const ftun_worker_t *worker)
{
  return worker != NULL &&
    (atomic_load_explicit(&worker->cleanup_pending, memory_order_relaxed) != 0u ||
     atomic_load_explicit(&worker->completed, memory_order_acquire) != 0u ||
     ftun_operation_queue_has_ready(worker->operations));
}

ftun_status_t ftun_worker_stop(ftun_worker_t *worker)
{
  if (worker == NULL) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&worker->mutex);
  worker->accepting = 0;
  worker->stopping = 1;
  (void)pthread_cond_broadcast(&worker->ready);
  (void)pthread_mutex_unlock(&worker->mutex);
  return ftun_operation_queue_stop(worker->operations);
}

ftun_status_t ftun_worker_join(ftun_worker_t *worker)
{
  return ftun_worker_join_until(worker, UINT64_MAX);
}

ftun_status_t ftun_worker_join_until(ftun_worker_t *worker,
                                     uint64_t deadline_ms)
{
  int wait_status = 0;
  if (worker == NULL) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&worker->mutex);
  if (worker->joined) {
    (void)pthread_mutex_unlock(&worker->mutex);
    return FTUN_OK;
  }
  if (!worker->stopping) {
    (void)pthread_mutex_unlock(&worker->mutex);
    return FTUN_E_AGAIN;
  }
  while (!worker->exited && wait_status == 0) {
    if (deadline_ms == UINT64_MAX) {
      wait_status = pthread_cond_wait(&worker->ready, &worker->mutex);
    } else {
      struct timespec deadline;
      uint64_t seconds = deadline_ms / UINT64_C(1000);
      deadline.tv_sec = (time_t)seconds;
      if ((uint64_t)deadline.tv_sec != seconds) {
        (void)pthread_mutex_unlock(&worker->mutex);
        return FTUN_E_LIMIT;
      }
      deadline.tv_nsec = (long)((deadline_ms % UINT64_C(1000)) *
                                UINT64_C(1000000));
      wait_status = pthread_cond_timedwait(&worker->ready, &worker->mutex,
                                           &deadline);
    }
  }
  if (!worker->exited) {
    (void)pthread_mutex_unlock(&worker->mutex);
    return wait_status == ETIMEDOUT ? FTUN_E_TIMEOUT : FTUN_E_IO;
  }
  (void)pthread_mutex_unlock(&worker->mutex);
  if (pthread_join(worker->thread, NULL) != 0) return FTUN_E_IO;
  (void)pthread_mutex_lock(&worker->mutex);
  worker->joined = 1;
  (void)pthread_mutex_unlock(&worker->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_worker_get_usage(ftun_worker_t *worker, ftun_worker_usage_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (worker == NULL || out == NULL) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&worker->mutex);
  out->capacity = worker->capacity;
  out->tasks = worker->tasks;
  out->pending = worker->pending;
  out->running = worker->running;
  out->completed = atomic_load_explicit(&worker->completed,
                                        memory_order_acquire);
  out->cleanup_pending = atomic_load_explicit(&worker->cleanup_pending,
                                              memory_order_relaxed);
  out->accepting = worker->accepting != 0;
  out->stopping = worker->stopping != 0;
  out->exited = worker->exited != 0;
  out->joined = worker->joined != 0;
  (void)pthread_mutex_unlock(&worker->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_worker_destroy(ftun_worker_t **worker)
{
  ftun_worker_t *owned;
  ftun_reservation_t *reservation;
  ftun_status_t status;
  int can_destroy;

  if (worker == NULL) return FTUN_E_INVALID;
  owned = *worker;
  if (owned == NULL) return FTUN_OK;
  (void)pthread_mutex_lock(&owned->mutex);
  can_destroy = owned->joined && owned->tasks == 0u && owned->pending == 0u &&
    owned->running == 0u &&
    atomic_load_explicit(&owned->completed, memory_order_relaxed) == 0u &&
    !owned->polling &&
    !owned->cleanup_failed;
  (void)pthread_mutex_unlock(&owned->mutex);
  if (!can_destroy) return FTUN_E_AGAIN;
  status = ftun_operation_queue_destroy(&owned->operations);
  if (status != FTUN_OK) return status;
  reservation = owned->reservation;
  status = ftun_reservation_release(&reservation);
  if (status != FTUN_OK) return status;
  owned->reservation = NULL;
  if (pthread_cond_destroy(&owned->ready) != 0 ||
      pthread_mutex_destroy(&owned->mutex) != 0) return FTUN_E_STATE_CORRUPT;
  free(owned);
  *worker = NULL;
  return FTUN_OK;
}
