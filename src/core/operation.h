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

/* 取消 hook 在 owner loop 同步释放生产者资源；失败且未另有已接纳完成时，
 * 操作保持原状态，可重试。
 * 执行时不持 Operation 队列锁。未终结项在 hook 内同步/并发 complete 返回
 * AGAIN，不接收结果；生产者保留 token、结果和资源，退出窗口后重新提交。
 * 已终结项的重复 complete 和旧 generation 始终返回 STALE。 */
typedef ftun_status_t (*ftun_operation_cancel_hook_fn)(void *user);

/* 异步接纳与取消。
 * 需求 REQ-CORE-001；任务 TASK-CORE-005；目标 0.2.0；验收 TEST-CORE-005。
 * 队列接纳与完成由内部锁仲裁；cancel/hook/reject/dispatch 属于 owner loop。
 * 接纳时预留终结槽位和预算，
 * 因此完成/取消不再分配。回调由 dispatch 延迟执行且恰好一次；
 * operation 和 user 在回调返回前有效，返回后 operation 句柄立即失效。
 * accept 成功同时交付取消句柄 operation 和只供生产者终结的 completion；
 * 失败时两者清零且没有回调。complete 可来自生产者线程，回调只由 owner 的
 * dispatch 执行；dispatch 不允许重入。complete/cancel 的首个终结可被尚未
 * dispatch 的 cancel 改写为 CANCELLED，回调仍恰好一次。旧 generation 在槽位
 * 复用后只返回 STALE。complete 返回 AGAIN 时不转移结果或终结责任，禁止
 * 丢弃待提交结果或在 cancel hook 内自旋重试；由生产者既有调度在窗口结束后
 * 重交。complete 成功后生产者必须丢弃 token；queue 只有在
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
/* 仅供无法向上游反馈 AGAIN 的内部完成适配器使用。与 complete 相同，但
 * 未终结项的 cancel hook 窗口内也能以 OK 接纳一个结果，使用已有预留槽位，
 * 不分配；hook 成功时 CANCELLED 获胜，失败时发布该结果。旧代/重复仍 STALE。
 * OK 后适配器不再提交 token，并将结果所依赖的 payload 保留至 owner callback；
 * 即使取消获胜，callback 仍负责释放 payload。不执行内联用户回调。 */
ftun_status_t ftun_operation_complete_deferred(
  ftun_operation_token_t completion, ftun_error_t result);
ftun_status_t ftun_operation_cancel(ftun_operation_t *operation);
/* max_callbacks 必须大于零；未终结的 operation 不阻塞已终结项。 */
ftun_status_t ftun_operation_dispatch(ftun_operation_queue_t *queue,
                                      size_t max_callbacks, size_t *out_dispatched);
ftun_status_t ftun_operation_queue_stop(ftun_operation_queue_t *queue);
/* owner 有界停止：关闭接纳并检查至多 max_slots 个稳定槽（空槽也计工作）。
 * more 表示本轮扫描尚未完成；一轮结束后下一次调用重试仍未终结的项。
 * 可与两次 step 之间的 dispatch 交替；hook 不持队列锁，重入返回 AGAIN。 */
ftun_status_t ftun_operation_queue_stop_step(ftun_operation_queue_t *queue,
  size_t max_slots, size_t *out_visited, bool *out_more);
/* 仅供启动失败完全回收后的宿主重试：生产者须静默，队列必须已排空。
 * 保留 generation 计数，不允许旧 token 命中重开后的新操作。 */
ftun_status_t ftun_operation_queue_reopen(ftun_operation_queue_t *queue);
/* Owner 调度热路径只读取 ready 事实；不复制完整统计，也不争用队列锁。 */
bool ftun_operation_queue_has_ready(const ftun_operation_queue_t *queue);
ftun_status_t ftun_operation_queue_get_usage(const ftun_operation_queue_t *queue,
                                              ftun_operation_queue_usage_t *out);
/* 返回创建时借用的 Budget，供跨 owner 组合器验证统一资源树。 */
ftun_status_t ftun_operation_queue_budget(ftun_operation_queue_t *queue,
                                          ftun_budget_t **out);
ftun_status_t ftun_operation_queue_destroy(ftun_operation_queue_t **queue);
#endif
