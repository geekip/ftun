#ifndef FTUN_CORE_WORKER_H
#define FTUN_CORE_WORKER_H
#include "internal/contracts.h"
#include "core/budget.h"

typedef ftun_status_t (*ftun_worker_execute_fn)(ftun_bytes_t input,
                                                uint8_t *result,
                                                size_t result_capacity,
                                                size_t *out_result_size);
typedef void (*ftun_worker_completion_fn)(ftun_operation_t *operation,
                                          ftun_error_t error,
                                          ftun_bytes_t result,
                                          void *user);

struct ftun_worker_job {
  ftun_worker_execute_fn execute;
  ftun_bytes_t input;
  size_t result_capacity;
  uint64_t deadline_ms; /* 0 表示无截止时间。 */
};

typedef struct {
  size_t capacity;
  size_t tasks;
  size_t pending;
  size_t running;
  size_t completed;
  bool accepting;
  bool joined;
} ftun_worker_usage_t;

/* 有界文件任务。
 * 需求 REQ-CORE-001；任务 TASK-CORE-006；目标 0.2.0；验收 TEST-CORE-006。
 * 提交时复制输入并预留任务、结果和 completion 预算。execute 只获得
 * 独立字节视图，不得访问 Session 或保留指针。deadline 过期只丢弃结果，
 * 不声称中断正在执行的阻塞调用。poll/join/destroy 只由 owner loop 调用。
 */
ftun_status_t ftun_worker_create(ftun_budget_t *budget, size_t capacity,
                                 ftun_worker_t **out);
ftun_status_t ftun_worker_submit(ftun_worker_t *worker, const ftun_worker_job_t *job,
                                 ftun_worker_completion_fn callback, void *user,
                                 ftun_operation_t **out);
ftun_status_t ftun_worker_poll(ftun_worker_t *worker, size_t max_callbacks,
                               size_t *out_callbacks);
ftun_status_t ftun_worker_stop(ftun_worker_t *worker);
ftun_status_t ftun_worker_join(ftun_worker_t *worker);
ftun_status_t ftun_worker_get_usage(ftun_worker_t *worker, ftun_worker_usage_t *out);
ftun_status_t ftun_worker_destroy(ftun_worker_t **worker);
#endif
