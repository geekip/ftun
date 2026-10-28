#define _POSIX_C_SOURCE 200809L

#include "app/runtime_internal.h"

void ftun_app_cleanup_record(ftun_app_cleanup_t *cleanup,
                             ftun_status_t status)
{
  if (status != FTUN_OK && status != FTUN_E_AGAIN && status != FTUN_E_TIMEOUT &&
      *cleanup->cleanup_error == FTUN_OK) *cleanup->cleanup_error = status;
}

uint64_t ftun_app_cleanup_deadline(ftun_app_cleanup_t *cleanup)
{
  uint64_t deadline;
  (void)pthread_mutex_lock(cleanup->mutex);
  deadline = *cleanup->deadline_ms;
  (void)pthread_mutex_unlock(cleanup->mutex);
  return deadline;
}

uint64_t ftun_app_cleanup_slice(ftun_app_cleanup_t *cleanup, bool may_wait)
{
  uint64_t now = 0u;
  uint64_t deadline = ftun_app_cleanup_deadline(cleanup);
  if (ftun_monotonic_now(&now) != FTUN_OK) return 0u;
  if (!may_wait) return now;
  if (deadline <= now) return deadline;
  return deadline - now > FTUN_APP_CLEANUP_SLICE_MS
    ? now + FTUN_APP_CLEANUP_SLICE_MS : deadline;
}

void ftun_app_cleanup_begin(ftun_app_cleanup_t *cleanup)
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

ftun_status_t ftun_app_cleanup_worker(ftun_worker_t *worker,
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

ftun_status_t ftun_app_cleanup_operations(ftun_operation_queue_t *queue,
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

ftun_status_t ftun_app_cleanup_drive(ftun_app_cleanup_t *cleanup,
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

ftun_status_t ftun_core_cleanup_step(void *context, bool may_wait,
                                            bool *complete, bool *progress)
{
  ftun_core_control_t *control = (ftun_core_control_t *)context;
  ftun_app_cleanup_t cleanup = ftun_core_cleanup(control);
  bool reload_done = false, state_done = false, operations_done = false;
  ftun_status_t status;
  size_t count;
  uint64_t now = 0u;
  *complete = false;
  for (count = 0u; count < FTUN_APP_CLEANUP_QUOTA; count++) {
    ftun_control_task_t *task;
    (void)pthread_mutex_lock(&control->mutex);
    if (control->task_count == 0u) {
      (void)pthread_mutex_unlock(&control->mutex);
      break;
    }
    task = control->tasks[control->task_head];
    control->tasks[control->task_head] = NULL;
    control->task_head = (control->task_head + 1u) % control->task_capacity;
    control->task_count--;
    if (!task->control_priority) control->normal_task_count--;
    if (task->kind == FTUN_CONTROL_RELOAD) control->reload_pending = 0;
    (void)pthread_mutex_unlock(&control->mutex);
    ftun_control_task_consumed(task);
    *progress = true;
  }
  status = ftun_app_cleanup_worker(control->reload_worker,
    ftun_app_cleanup_slice(&cleanup, may_wait), &reload_done, progress);
  ftun_app_cleanup_record(&cleanup, status);

  (void)ftun_monotonic_now(&now);
  if (!control->state_save_done) {
    ftun_worker_usage_t usage;
    size_t callbacks = 0u;
    memset(&usage, 0, sizeof(usage));
    if (!may_wait || now >= ftun_app_cleanup_deadline(&cleanup) ||
        control->state_worker == NULL) {
      control->state_save_done = true;
    } else {
      status = ftun_worker_poll(control->state_worker,
                                 FTUN_APP_CLEANUP_QUOTA, &callbacks);
      if (callbacks != 0u) *progress = true;
      if (status == FTUN_OK) {
        status = ftun_worker_get_usage(control->state_worker, &usage);
      }
      ftun_app_cleanup_record(&cleanup, status);
      if (status != FTUN_OK) control->state_save_done = true;
      else if (usage.tasks == 0u) {
        const ftun_config_t *active = control->active_config;
        if (!control->state_save_submitted && active != NULL &&
            active->base.state_cache) {
          control->state_save_submitted = true;
          status = ftun_core_state_schedule(control->core, control,
            active->base.cache_file, ftun_app_cleanup_deadline(&cleanup));
          ftun_app_cleanup_record(&cleanup, status);
          if (status != FTUN_OK) control->state_save_done = true;
          *progress = true;
        } else control->state_save_done = true;
      }
    }
  }
  if (control->state_save_done) {
    status = ftun_app_cleanup_worker(control->state_worker,
      ftun_app_cleanup_slice(&cleanup, may_wait), &state_done, progress);
    ftun_app_cleanup_record(&cleanup, status);
  }
  if (reload_done) {
    status = ftun_core_reload_reap(control,
      ftun_app_cleanup_slice(&cleanup, may_wait));
    ftun_app_cleanup_record(&cleanup, status);
  }
  if (control->service.implementation != NULL && !control->service_stopped) {
    status = ftun_core_service_stop_until(&control->service,
      ftun_app_cleanup_slice(&cleanup, may_wait));
    ftun_app_cleanup_record(&cleanup, status);
    if (status == FTUN_OK) {
      control->service_stopped = true;
      *progress = true;
    }
  }
  status = ftun_app_cleanup_operations(control->operations, &operations_done,
                                        progress);
  ftun_app_cleanup_record(&cleanup, status);
  if (reload_done && state_done && operations_done &&
      control->task_count == 0u && !control->retired_busy &&
      (control->service_stopped || control->service.implementation == NULL)) {
    status = ftun_core_service_destroy_until(&control->service,
      ftun_app_cleanup_slice(&cleanup, may_wait));
    ftun_app_cleanup_record(&cleanup, status);
    if (status == FTUN_OK) {
      status = control->startup_candidate == NULL ? FTUN_OK
        : control->support->release(control->core, &control->startup_candidate);
      ftun_app_cleanup_record(&cleanup, status);
      if (status == FTUN_OK) {
        status = ftun_config_destroy(&control->startup_config);
        ftun_app_cleanup_record(&cleanup, status);
      }
      status = ftun_core_owned_path_destroy(&control->startup_path);
      ftun_app_cleanup_record(&cleanup, status);
      status = ftun_worker_destroy(&control->reload_worker);
      ftun_app_cleanup_record(&cleanup, status);
      status = ftun_worker_destroy(&control->state_worker);
      ftun_app_cleanup_record(&cleanup, status);
      if (control->startup_candidate == NULL && control->startup_config == NULL &&
          control->startup_path.value == NULL && control->startup_path.reservation == NULL &&
          control->reload_worker == NULL && control->state_worker == NULL) {
        bool terminal_event;
        (void)pthread_mutex_lock(&control->mutex);
        terminal_event = control->lifecycle_started && !control->runtime_stopped;
        if (terminal_event) control->runtime_stopped = true;
        (void)pthread_mutex_unlock(&control->mutex);
        if (terminal_event) {
          ftun_lifecycle_event_t event = {0};
          event.kind = FTUN_LIFECYCLE_STOPPED;
          event.generation = ftun_core_generation_now(control);
          event.status = control->first_error != FTUN_OK ? control->first_error : control->cleanup_error;
          event.reason = FTUN_LIFECYCLE_REASON_LOG_DRAINING;
          (void)ftun_core_context_finish_logging(control->core, &event);
        } else (void)ftun_core_context_finish_logging(control->core, NULL);
        status = ftun_logger_destroy_until(&control->startup_logger,
          ftun_app_cleanup_slice(&cleanup, may_wait));
        ftun_app_cleanup_record(&cleanup, status);
        status = ftun_logger_destroy_until(&control->logger,
          ftun_app_cleanup_slice(&cleanup, may_wait));
        ftun_app_cleanup_record(&cleanup, status);
      }
    }
  }
  *complete = operations_done && control->task_count == 0u &&
    control->service.implementation == NULL && !control->retired_busy &&
    control->reload_worker == NULL && control->state_worker == NULL &&
    control->startup_config == NULL && control->startup_candidate == NULL &&
    control->startup_path.value == NULL && control->startup_path.reservation == NULL &&
    control->startup_logger == NULL && control->logger == NULL &&
    control->retired_logger == NULL;
  return FTUN_OK;
}

