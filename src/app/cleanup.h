#ifndef FTUN_APP_CLEANUP_H
#define FTUN_APP_CLEANUP_H

#include "core/operation.h"
#include "core/worker.h"
#include "util/time.h"
#include <pthread.h>
#include <time.h>

#define FTUN_APP_CLEANUP_QUOTA 32u
#define FTUN_APP_CLEANUP_SLICE_MS UINT64_C(5)
#define FTUN_APP_FAILURE_CLEANUP_MS UINT64_C(10000)

typedef struct {
  pthread_mutex_t *mutex;
  uint64_t *deadline_ms;
  ftun_status_t *cleanup_error;
} ftun_app_cleanup_t;

typedef ftun_status_t (*ftun_app_cleanup_step_fn)(
  void *context, bool may_wait, bool *complete, bool *progress);

static void ftun_app_cleanup_record(ftun_app_cleanup_t *cleanup,
                                     ftun_status_t status)
{
  if (status != FTUN_OK && status != FTUN_E_AGAIN && status != FTUN_E_TIMEOUT &&
      *cleanup->cleanup_error == FTUN_OK) *cleanup->cleanup_error = status;
}

static uint64_t ftun_app_cleanup_deadline(ftun_app_cleanup_t *cleanup)
{
  uint64_t deadline;
  (void)pthread_mutex_lock(cleanup->mutex);
  deadline = *cleanup->deadline_ms;
  (void)pthread_mutex_unlock(cleanup->mutex);
  return deadline;
}

static uint64_t ftun_app_cleanup_slice(ftun_app_cleanup_t *cleanup, bool may_wait)
{
  uint64_t now = 0u;
  uint64_t deadline = ftun_app_cleanup_deadline(cleanup);
  if (ftun_monotonic_now(&now) != FTUN_OK) return 0u;
  if (!may_wait) return now;
  if (deadline <= now) return deadline;
  return deadline - now > FTUN_APP_CLEANUP_SLICE_MS
    ? now + FTUN_APP_CLEANUP_SLICE_MS : deadline;
}

/* 没有调用方 stop 的错误路径也必须拥有一个固定总期限。 */
static void ftun_app_cleanup_begin(ftun_app_cleanup_t *cleanup)
{
  uint64_t now = 0u;
  (void)ftun_monotonic_now(&now);
  (void)pthread_mutex_lock(cleanup->mutex);
  if (*cleanup->deadline_ms == UINT64_MAX) {
    *cleanup->deadline_ms = now > UINT64_MAX - FTUN_APP_FAILURE_CLEANUP_MS
      ? UINT64_MAX : now + FTUN_APP_FAILURE_CLEANUP_MS;
  }
  (void)pthread_mutex_unlock(cleanup->mutex);
}

static ftun_status_t ftun_app_cleanup_worker(ftun_worker_t *worker,
  uint64_t deadline, bool *complete, bool *progress)
{
  ftun_status_t status, polled;
  ftun_worker_usage_t usage;
  size_t callbacks = 0u;
  *complete = worker == NULL;
  if (worker == NULL) return FTUN_OK;
  status = ftun_worker_stop(worker);
  polled = ftun_worker_poll(worker, FTUN_APP_CLEANUP_QUOTA, &callbacks);
  if (callbacks != 0u) *progress = true;
  if (status != FTUN_OK) return status;
  if (polled != FTUN_OK) return polled;
  status = ftun_worker_join_until(worker, deadline);
  if (status != FTUN_OK) return status;
  polled = ftun_worker_poll(worker, FTUN_APP_CLEANUP_QUOTA, &callbacks);
  if (callbacks != 0u) *progress = true;
  if (polled != FTUN_OK) return polled;
  status = ftun_worker_get_usage(worker, &usage);
  if (status == FTUN_OK) *complete = usage.tasks == 0u;
  return status;
}

static ftun_status_t ftun_app_cleanup_operations(ftun_operation_queue_t *queue,
  bool *complete, bool *progress)
{
  ftun_operation_queue_usage_t usage;
  size_t visited = 0u, dispatched = 0u;
  bool more = false;
  ftun_status_t status, next;
  *complete = queue == NULL;
  if (queue == NULL) return FTUN_OK;
  status = ftun_operation_queue_stop_step(queue, FTUN_APP_CLEANUP_QUOTA,
                                           &visited, &more);
  next = ftun_operation_dispatch(queue, FTUN_APP_CLEANUP_QUOTA, &dispatched);
  if (more || dispatched != 0u) *progress = true;
  if (next != FTUN_OK) return next;
  next = ftun_operation_queue_get_usage(queue, &usage);
  if (next != FTUN_OK) return next;
  *complete = usage.inflight == 0u;
  return status;
}

static ftun_status_t ftun_app_cleanup_drive(ftun_app_cleanup_t *cleanup,
  ftun_app_cleanup_step_fn step, void *context, bool may_wait)
{
  for (;;) {
    bool complete = false, progress = false;
    uint64_t now = 0u;
    ftun_status_t status = step(context, may_wait, &complete, &progress);
    ftun_app_cleanup_record(cleanup, status);
    if (complete) return FTUN_OK;
    if (!may_wait) return FTUN_E_AGAIN;
    if (ftun_monotonic_now(&now) != FTUN_OK) return FTUN_E_IO;
    if (now >= ftun_app_cleanup_deadline(cleanup)) return FTUN_E_TIMEOUT;
    if (!progress) {
      const struct timespec pause = {0, 1000 * 1000};
      (void)nanosleep(&pause, NULL);
    }
  }
}

#endif
