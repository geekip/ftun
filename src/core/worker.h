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
typedef ftun_status_t (*ftun_worker_result_cleanup_fn)(ftun_bytes_t result);
typedef ftun_status_t (*ftun_worker_input_cleanup_fn)(ftun_bytes_t input);
typedef void (*ftun_worker_wakeup_fn)(void *user);

struct ftun_worker_job {
  ftun_worker_execute_fn execute;
  ftun_bytes_t input;
  size_t result_capacity;
  size_t accounted_extra;
  ftun_worker_input_cleanup_fn input_cleanup;
  ftun_worker_result_cleanup_fn result_cleanup;
  uint64_t deadline_ms; /* 0 表示无截止时间。 */
};

typedef struct {
  size_t capacity;
  size_t tasks;
  size_t pending;
  size_t running;
  size_t completed;
  size_t cleanup_pending;
  bool accepting;
  bool stopping;
  bool exited;
  bool joined;
} ftun_worker_usage_t;

/* 有界文件任务。
 * 需求 REQ-CORE-001；任务 TASK-CORE-006；目标 0.2.0；验收 TEST-CORE-006。
 * 提交时复制输入并预留任务、结果、额外输出所有权和 completion 预算。
 * execute 只获得独立字节视图，不得访问 Session。input 若携带由
 * owner 预先保留的不可变快照，必须提供 input_cleanup；它在任务真正结束且
 * 回调完成后执行。输出若携带拥有型对象，必须提供 result_cleanup；回调取走
 * 对象后须清空结果中的所有权字段。
 * execute 失败也可通过有效的 out_result_size 交还待清理结果；错误回调仍无结果。
 * 清理返回错误时须把剩余所有权写回对应字节存储。Worker 保留任务及额度，
 * 下一轮按配额重试；成功阶段不重做，业务回调不重复。结果先于输入清理。
 * deadline 过期只丢弃结果，不声称中断正在执行的阻塞调用。
 * poll/join/destroy 只由 owner loop 调用。
 */
ftun_status_t ftun_worker_create(ftun_budget_t *budget, size_t capacity,
                                 ftun_worker_t **out);
/* wakeup may run on any worker thread and must not block or call owner-only
 * APIs.  Configure it before accepting production work. */
ftun_status_t ftun_worker_set_wakeup(ftun_worker_t *worker,
                                     ftun_worker_wakeup_fn wakeup,
                                     void *user);
ftun_status_t ftun_worker_submit(ftun_worker_t *worker, const ftun_worker_job_t *job,
                                 ftun_worker_completion_fn callback, void *user,
                                 ftun_operation_t **out);
ftun_status_t ftun_worker_poll(ftun_worker_t *worker, size_t max_callbacks,
                               size_t *out_callbacks);
/* Owner 热路径判断完成队列或待派发回调，无锁且不复制完整统计。 */
bool ftun_worker_has_ready(const ftun_worker_t *worker);
ftun_status_t ftun_worker_stop(ftun_worker_t *worker);
/* 等待到绝对单调 deadline；超时保留 worker、任务输入/结果和线程引用，
 * 后续可再次 join_until。UINT64_MAX 保持原无限等待语义。 */
ftun_status_t ftun_worker_join_until(ftun_worker_t *worker,
                                     uint64_t deadline_ms);
ftun_status_t ftun_worker_join(ftun_worker_t *worker);
ftun_status_t ftun_worker_get_usage(ftun_worker_t *worker, ftun_worker_usage_t *out);
ftun_status_t ftun_worker_destroy(ftun_worker_t **worker);
#endif
