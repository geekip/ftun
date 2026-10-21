#ifndef FTUN_CORE_OPERATION_H
#define FTUN_CORE_OPERATION_H
#include "internal/contracts.h"
#include "core/budget.h"

typedef struct {
  size_t capacity;
  size_t inflight;
  size_t ready;
  size_t control_reserve;
  size_t normal_inflight;
  size_t control_inflight;
  size_t rejected_normal;
  size_t rejected_control;
  bool accepting;
  bool dispatching;
} ftun_operation_queue_usage_t;

/* Completion authority is copied by value when an operation is accepted.
 * The queue storage remains stable until the queue reaches silence and is
 * destroyed; generation prevents a late producer from completing a reused
 * slot.  The token becomes stale after the first terminal transition. */
typedef struct {
  ftun_operation_queue_t *queue;
  size_t slot;
  uint64_t generation;
} ftun_operation_token_t;

/* 取消 hook 在 owner loop 同步释放生产者资源；失败时操作保持原状态，可重试。 */
typedef ftun_status_t (*ftun_operation_cancel_hook_fn)(void *user);

/* 异步接纳与取消。
 * 需求 REQ-CORE-001；任务 TASK-CORE-005；目标 0.2.0；验收 TEST-CORE-005。
 * 所有可变状态只在 owner loop 中访问。接纳时预留终结槽位和预算，
 * 因此完成/取消不再分配。回调由 dispatch 延迟执行且恰好一次；
 * operation 和 user 在回调返回前有效，返回后 operation 句柄立即失效。
 * accept 成功同时交付取消句柄 operation 和只供生产者终结的 completion；
 * 失败时两者清零且没有回调。complete 可来自生产者线程，回调只由 owner 的
 * dispatch 执行；dispatch 不允许重入。complete/cancel 的首个终结可被尚未
 * dispatch 的 cancel 改写为 CANCELLED，回调仍恰好一次。旧 generation 在槽位
 * 复用后只返回 STALE。生产者在 complete 成功后必须丢弃 token；queue 只有在
 * 全部生产者静默、所有回调排空后才能 destroy，destroy 后 token 不得再调用。
 * cancel hook 必须有界且不得阻塞 owner；失败不转移资源，可由 stop 重试。
 */
ftun_status_t ftun_operation_queue_create(ftun_budget_t *budget, size_t capacity,
                                          ftun_operation_queue_t **out);
ftun_status_t ftun_operation_queue_create_reserved(
  ftun_budget_t *budget, size_t capacity, size_t control_reserve,
  ftun_operation_queue_t **out);
ftun_status_t ftun_operation_accept(ftun_operation_queue_t *queue,
                                    ftun_completion_fn callback, void *user,
                                    ftun_operation_t **out,
                                    ftun_operation_token_t *completion);
/* Administrative work may use the queue's preallocated control reserve.
 * It still obeys the total capacity and the same completion contract. */
ftun_status_t ftun_operation_accept_control(
  ftun_operation_queue_t *queue, ftun_completion_fn callback, void *user,
  ftun_operation_t **out, ftun_operation_token_t *completion);
ftun_status_t ftun_operation_set_cancel_hook(
  ftun_operation_t *operation, ftun_operation_cancel_hook_fn hook, void *user);
/* 仅供生产者在入口返回成功前撤销已接纳项；零回调并消费句柄。 */
ftun_status_t ftun_operation_reject(ftun_operation_t **operation);
ftun_status_t ftun_operation_complete(ftun_operation_token_t completion,
                                      ftun_error_t result);
ftun_status_t ftun_operation_cancel(ftun_operation_t *operation);
/* max_callbacks 必须大于零；未终结的 operation 不阻塞已终结项。 */
ftun_status_t ftun_operation_dispatch(ftun_operation_queue_t *queue,
                                      size_t max_callbacks, size_t *out_dispatched);
ftun_status_t ftun_operation_queue_stop(ftun_operation_queue_t *queue);
/* Owner 调度热路径只读取 ready 事实；不复制完整统计，也不争用队列锁。 */
bool ftun_operation_queue_has_ready(const ftun_operation_queue_t *queue);
ftun_status_t ftun_operation_queue_get_usage(const ftun_operation_queue_t *queue,
                                              ftun_operation_queue_usage_t *out);
/* 返回创建时借用的 Budget，供跨 owner 组合器验证统一资源树。 */
ftun_status_t ftun_operation_queue_budget(ftun_operation_queue_t *queue,
                                          ftun_budget_t **out);
ftun_status_t ftun_operation_queue_destroy(ftun_operation_queue_t **queue);
#endif
