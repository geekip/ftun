#ifndef FTUN_EVENT_EVENT_H
#define FTUN_EVENT_EVENT_H
#include "internal/contracts.h"

#define FTUN_EVENT_DEFERRED_CAPACITY 256u

#define FTUN_EVENT_READ 1u
#define FTUN_EVENT_WRITE 2u
#define FTUN_EVENT_ERROR 4u
#define FTUN_EVENT_TIMER 8u
#define FTUN_EVENT_TASK 16u

typedef void (*ftun_event_callback_fn)(ftun_event_source_t *source,
                                       uint32_t events, void *user);
typedef void (*ftun_event_deferred_fn)(void *user);
/* wakeup 可在任意提交线程中被调用，不得回调 loop 或阻塞。 */
typedef void (*ftun_event_wakeup_fn)(void *user);

typedef struct {
  ftun_status_t (*io_start)(void *context, ftun_event_source_t *source,
                            ftun_native_socket_t socket, uint32_t interests);
  ftun_status_t (*io_update)(void *context, ftun_event_source_t *source,
                             uint32_t interests);
  ftun_status_t (*timer_start)(void *context, ftun_event_source_t *source,
                               uint64_t deadline_ms);
  ftun_status_t (*source_cancel)(void *context, ftun_event_source_t *source);
  void (*wakeup)(void *context);
  ftun_status_t (*run_once)(void *context, bool block);
  void (*stop)(void *context);
  void (*destroy)(void *context);
  /* true when the backend itself calls ftun_event_timer_ready(). */
  bool native_timers;
} ftun_event_backend_ops_t;

typedef struct {
  size_t deferred_capacity;
  size_t deferred_count;
  size_t source_capacity;
  size_t source_count;
  size_t ready_count;
  size_t wakeups;
  uint64_t polls;
  uint64_t callbacks;
  uint64_t quota_exhaustions;
  uint64_t last_dispatch_ms;
  uint64_t max_dispatch_ms;
  uint64_t max_timer_lateness_ms;
  size_t max_callbacks_per_poll;
  /* 最近一次 poll/run_once 的实际单元：callback、到期入队、原生通知。 */
  size_t last_work;
  size_t last_backend_work;
  size_t last_timer_work;
  bool backend_quota_exhausted;
  bool accepting;
  bool dispatching;
  bool stopped;
  bool backend_attached;
} ftun_event_loop_usage_t;

/* 可移植事件接口。
 * 需求 REQ-CORE-001；任务 TASK-EVENT-001；目标 0.2.0；验收 TEST-EVENT-001。
 * source 仅是内部句柄，不进入公开 C API。I/O readiness 由后端投递，
 * timer 使用绝对单调毫秒。defer 可跨线程接纳，固定队列从空变为
 * 非空时才唤醒后端。defer/wakeup 可跨线程调用；poll、usage、source 和
 * backend 生命周期由 owner loop 串行访问。业务回调不持队列锁，wakeup
 * 通知按上面的非阻塞、不可重入契约在锁内执行。销毁前须结束所有 producer。
 */
ftun_status_t ftun_event_loop_create(ftun_core_t *core, ftun_event_loop_t **out);
/* source_capacity 在创建后固定；普通调用保留 1024 的兼容默认值。 */
ftun_status_t ftun_event_loop_create_with_capacity(
  ftun_core_t *core, size_t source_capacity, ftun_event_loop_t **out);
/* 显式选择同根域；业务组合使用数据域，独立控制通道使用自己的控制域。 */
ftun_status_t ftun_event_loop_create_with_budget(ftun_core_t *core,
  ftun_budget_t *budget, size_t source_capacity, ftun_event_loop_t **out);
/* Core 非空时从其 Budget 预留 loop/固定 deferred 槽与逐个 source/ready 槽。
 * source 不拥有业务 socket，不重复计 FD；取消失败仍保留额度。
 * 返回创建时绑定的借用预算，寿命至少覆盖 loop；NULL Core 工具用法返回 NULL。 */
ftun_status_t ftun_event_loop_budget(ftun_event_loop_t *loop, ftun_budget_t **out);
ftun_status_t ftun_event_loop_set_wakeup(ftun_event_loop_t *loop,
                                         ftun_event_wakeup_fn wakeup, void *user);
/* backend 必须在创建 source 前附加，ops/context 保持有效至 detach。 */
ftun_status_t ftun_event_loop_attach_backend(ftun_event_loop_t *loop,
                                             const ftun_event_backend_ops_t *ops,
                                             void *context);
ftun_status_t ftun_event_loop_backend_context(ftun_event_loop_t *loop,
                                              const ftun_event_backend_ops_t *ops,
                                              void **out);
ftun_status_t ftun_event_loop_detach_backend(ftun_event_loop_t *loop);
ftun_status_t ftun_event_io_start(ftun_event_loop_t *loop, ftun_native_socket_t socket,
                                  uint32_t interests, ftun_event_callback_fn callback,
                                  void *user, ftun_event_source_t **out);
ftun_status_t ftun_event_io_update(ftun_event_source_t *source,
                                   uint32_t interests);
ftun_status_t ftun_event_timer_start(ftun_event_loop_t *loop, uint64_t deadline_ms,
                                     ftun_event_callback_fn callback, void *user,
                                     ftun_event_source_t **out);
/* owner 专用的可重复任务源。start 占用固定 source 额度；ready 无分配、
 * 合并重复通知，不消耗跨线程 defer 队列。cancel 撤销未派发通知；
 * callback 可再次 ready，遵守与 I/O 相同的单轮配额。 */
ftun_status_t ftun_event_task_start(ftun_event_loop_t *loop,
  ftun_event_callback_fn callback, void *user, ftun_event_source_t **out);
ftun_status_t ftun_event_task_ready(ftun_event_source_t *source);
/* 由后端在 owner loop 上投递 readiness，不直接调用业务回调。 */
ftun_status_t ftun_event_io_ready(ftun_event_source_t *source, uint32_t events);
ftun_status_t ftun_event_timer_ready(ftun_event_source_t *source);
/* 接纳成功后 user 必须保持有效至 callback 返回；同步拒绝零回调。 */
ftun_status_t ftun_event_defer(ftun_event_loop_t *loop,
                               ftun_event_deferred_fn callback, void *user);
/* Thread-safe wakeup without enqueueing a callback. */
ftun_status_t ftun_event_loop_wakeup(ftun_event_loop_t *loop);
ftun_status_t ftun_event_loop_poll(ftun_event_loop_t *loop, uint64_t now_ms,
                                   size_t max_callbacks, size_t *out_callbacks);
ftun_status_t ftun_event_loop_run_once(ftun_event_loop_t *loop, bool block,
                                       size_t max_callbacks, size_t *out_callbacks);
/* owner 后端借用最早尚未入队的 timer；没有 timer 时 present=false。
 * 聚合 native timer 仅用于唤醒，前端按配额从索引交付到期项。 */
ftun_status_t ftun_event_loop_next_deadline(ftun_event_loop_t *loop,
  uint64_t *out_deadline, bool *out_present);
/* 仅由本次 run_once 的后端报告；wait_ms 必须只覆盖内核等待。 */
void ftun_event_loop_backend_report(ftun_event_loop_t *loop,
  uint64_t wait_ms, size_t work, bool quota_exhausted);
ftun_status_t ftun_event_source_cancel(ftun_event_source_t **source);
/* 后端私有的 O(1) watcher 关联，只允许 owner loop 访问。 */
ftun_status_t ftun_event_source_backend_data(
  ftun_event_source_t *source, void **out);
ftun_status_t ftun_event_source_set_backend_data(
  ftun_event_source_t *source, void *data);
ftun_status_t ftun_event_loop_stop(ftun_event_loop_t *loop);
ftun_status_t ftun_event_loop_get_usage(ftun_event_loop_t *loop,
                                        ftun_event_loop_usage_t *out);
/* 必须已 stop、deferred 已排空且所有 source 句柄已取消。 */
ftun_status_t ftun_event_loop_destroy(ftun_event_loop_t **loop);
#endif
