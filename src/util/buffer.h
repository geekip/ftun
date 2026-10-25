#ifndef FTUN_UTIL_BUFFER_H
#define FTUN_UTIL_BUFFER_H
#include "internal/contracts.h"
#include "core/budget.h"

typedef struct {
  size_t idle_limit_bytes;
  size_t idle_limit_buffers;
  size_t idle_bytes;
  size_t idle_buffers;
  size_t active_buffers;
  size_t cache_hits;
  size_t cache_misses;
  size_t pressure_trims;
  size_t pressure_trimmed_bytes;
  size_t pressure_trimmed_buffers;
  size_t waiter_capacity;
  size_t waiting;
  size_t wake_quota;
  size_t notifications;
  size_t wake_callbacks;
  size_t cancelled_waiters;
  size_t rejected_waiters;
  size_t selection_steps;
  size_t max_selection_steps;
  size_t availability_probes;
  size_t max_availability_probes;
  size_t idle_scan_steps;
  size_t max_trim_buffers;
  bool dispatching;
} ftun_buffer_pool_usage_t;

typedef struct {
  ftun_buffer_pool_t *pool;
  size_t slot;
  uint64_t generation;
} ftun_buffer_wait_token_t;

typedef void (*ftun_buffer_ready_fn)(void *user);
/* 只通知 owner 安排一次 dispatch，不得内联 dispatch 或阻塞。 */
typedef void (*ftun_buffer_pool_wakeup_fn)(void *user);

/* 引用缓冲与池。
 * 需求 REQ-PERF-001；任务 TASK-UTIL-002；目标 0.2.0；验收 TEST-UTIL-002。
 * 按 256 字节起的 2 次幂分档申请；直接 acquire 不保留闲置对象。
 * pool 同时用字节与对象数限制闲置保留，闲置期仍占用预算。
 * slice 创建时 retain owner，释放 slice 前数据保持有效。
 * 全部可变状态由 owner loop 串行访问；不提供跨线程引用计数。
 */
ftun_status_t ftun_buffer_acquire(ftun_budget_t *budget, size_t capacity, ftun_buffer_t **out);
ftun_status_t ftun_buffer_pool_create(ftun_budget_t *budget, size_t idle_limit_bytes,
                                      size_t idle_limit_buffers,
                                      ftun_buffer_pool_t **out);
/* 所有 Pool 可变操作由同一 owner 串行调用。waiters 在 create 时预分配，
 * 同时准入对应内存和队列额度，最终 destroy 才释放。
 * wake_quota 限制一次 dispatch 的回调数；waiter_capacity 为零时
 * wake_quota 必须为零。 */
ftun_status_t ftun_buffer_pool_create_waitable(
  ftun_budget_t *budget, size_t idle_limit_bytes, size_t idle_limit_buffers,
  size_t waiter_capacity, size_t wake_quota, ftun_buffer_pool_t **out);
ftun_status_t ftun_buffer_pool_set_wakeup(
  ftun_buffer_pool_t *pool, ftun_buffer_pool_wakeup_fn wakeup, void *user);
ftun_status_t ftun_buffer_pool_acquire(ftun_buffer_pool_t *pool, size_t capacity,
                                       ftun_buffer_t **out);
/* wait 成功表示已排队，除取消外稍后恰好一次 ready；AGAIN 表示资源
 * 当前可重试，不排队。检查可满足性时可像 acquire 一样回收不同尺寸的
 * idle 缓存，再按真实预算复查；不回收 active Buffer 或 slice。
 * ready 是重试提示，不为等待者保留资源；共祖先的其他使用者仍可能先
 * 消耗额度，acquire 的返回值始终是最终准入结果。
 * 按队列顺序通知首个可满足者，每轮受 wake_quota/max_callbacks 限制，
 * 回调内资源变化合并到轮末一次通知。cancel 消费并清空有效 token；
 * 回调开始后 token 只会 STALE。类别队首按到达顺序探测，单次选择不随
 * 等待者总数增长；generation耗尽时拒绝新排队，防止排序回绕与旧token复用。 */
ftun_status_t ftun_buffer_pool_wait(
  ftun_buffer_pool_t *pool, size_t capacity, ftun_buffer_ready_fn ready,
  void *user, ftun_buffer_wait_token_t *out);
ftun_status_t ftun_buffer_pool_wait_cancel(ftun_buffer_wait_token_t *token);
ftun_status_t ftun_buffer_pool_dispatch(
  ftun_buffer_pool_t *pool, size_t max_callbacks, size_t *out_callbacks);
ftun_status_t ftun_buffer_pool_get_usage(const ftun_buffer_pool_t *pool,
                                         ftun_buffer_pool_usage_t *out);
/* 借用实际拥有缓存的预算，供组合器检查统一资源树。 */
ftun_status_t ftun_buffer_pool_budget(const ftun_buffer_pool_t *pool,
  ftun_budget_t **out);
ftun_status_t ftun_buffer_pool_trim(ftun_buffer_pool_t *pool, size_t target_idle_bytes);
ftun_status_t ftun_buffer_pool_destroy(ftun_buffer_pool_t **pool);
ftun_status_t ftun_buffer_retain(ftun_buffer_t *buffer);
ftun_status_t ftun_buffer_data(ftun_buffer_t *buffer, uint8_t **data, size_t *capacity);
ftun_status_t ftun_buffer_release(ftun_buffer_t **buffer);
ftun_status_t ftun_buffer_slice(ftun_buffer_t *buffer, size_t offset, size_t length,
                                ftun_buffer_slice_t *out);
/* slice 是只能通过 clone 复制的所有权值，不得逐字段或 memcpy 复制。 */
ftun_status_t ftun_buffer_slice_clone(const ftun_buffer_slice_t *source,
                                      ftun_buffer_slice_t *out);
ftun_status_t ftun_buffer_slice_data(const ftun_buffer_slice_t *slice, ftun_bytes_t *out);
/* 返回 slice 实际占用的 Budget，供跨 owner 组合器校验统一资源树。 */
ftun_status_t ftun_buffer_slice_budget(const ftun_buffer_slice_t *slice,
                                       ftun_budget_t **out);
ftun_status_t ftun_buffer_slice_release(ftun_buffer_slice_t *slice);
#endif
