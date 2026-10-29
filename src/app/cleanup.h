#ifndef FTUN_APP_CLEANUP_H
#define FTUN_APP_CLEANUP_H

#include "core/operation.h"
#include "core/worker.h"
#include "platform/clock.h"
#include "platform/thread.h"

#define FTUN_APP_CLEANUP_QUOTA 32u
#define FTUN_APP_CLEANUP_SLICE_MS UINT64_C(5)
#define FTUN_APP_FAILURE_CLEANUP_MS UINT64_C(10000)

typedef struct {
  ftun_mutex_t *mutex;
  uint64_t *deadline_ms;
  ftun_status_t *cleanup_error;
} ftun_app_cleanup_t;

typedef ftun_status_t (*ftun_app_cleanup_step_fn)(
  void *context, bool may_wait, bool *complete, bool *progress);

void ftun_app_cleanup_record(ftun_app_cleanup_t *cleanup,
                             ftun_status_t status);
uint64_t ftun_app_cleanup_deadline(ftun_app_cleanup_t *cleanup);
uint64_t ftun_app_cleanup_slice(ftun_app_cleanup_t *cleanup, bool may_wait);
void ftun_app_cleanup_begin(ftun_app_cleanup_t *cleanup);
ftun_status_t ftun_app_cleanup_worker(ftun_worker_t *worker,
  uint64_t deadline, bool *complete, bool *progress);
ftun_status_t ftun_app_cleanup_operations(ftun_operation_queue_t *queue,
  bool *complete, bool *progress);
ftun_status_t ftun_app_cleanup_drive(ftun_app_cleanup_t *cleanup,
  ftun_app_cleanup_step_fn step, void *context, bool may_wait);

#endif
