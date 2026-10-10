#ifndef FTUN_CORE_OPERATION_H
#define FTUN_CORE_OPERATION_H
#include "internal/contracts.h"
#include "core/budget.h"

typedef struct {
  size_t capacity;
  size_t inflight;
  bool accepting;
  bool dispatching;
} ftun_operation_queue_usage_t;

/* 异步接纳与取消。
 * 需求 REQ-CORE-001；任务 TASK-CORE-005；目标 0.2.0；验收 TEST-CORE-005。
 * 所有可变状态只在 owner loop 中访问。接纳时预留终结槽位和预算，
 * 因此完成/取消不再分配。回调由 dispatch 延迟执行且恰好一次；
 * operation 和 user 在回调返回前有效，返回后 operation 句柄立即失效。
 */
ftun_status_t ftun_operation_queue_create(ftun_budget_t *budget, size_t capacity,
                                          ftun_operation_queue_t **out);
ftun_status_t ftun_operation_accept(ftun_operation_queue_t *queue,
                                    ftun_completion_fn callback, void *user,
                                    ftun_operation_t **out);
ftun_status_t ftun_operation_complete(ftun_operation_t *operation, ftun_error_t result);
ftun_status_t ftun_operation_cancel(ftun_operation_t *operation);
/* max_callbacks 必须大于零；未终结的 operation 不阻塞已终结项。 */
ftun_status_t ftun_operation_dispatch(ftun_operation_queue_t *queue,
                                      size_t max_callbacks, size_t *out_dispatched);
ftun_status_t ftun_operation_queue_stop(ftun_operation_queue_t *queue);
ftun_status_t ftun_operation_queue_get_usage(const ftun_operation_queue_t *queue,
                                              ftun_operation_queue_usage_t *out);
ftun_status_t ftun_operation_queue_destroy(ftun_operation_queue_t **queue);
#endif
