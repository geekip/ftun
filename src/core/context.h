#ifndef FTUN_CORE_CONTEXT_H
#define FTUN_CORE_CONTEXT_H

#include "core/budget.h"
#include "internal/contracts.h"
#include "util/event_log.h"

/* Core 上下文只保存通用 owner-loop 资源和一个类型擦除的业务扩展。
 * 扩展的具体类型与生命周期由 Composition 选择的服务层负责。 */
ftun_status_t ftun_core_context_create(ftun_budget_t *budget,
                                       ftun_core_t **out);
ftun_status_t ftun_core_context_bind(ftun_core_t *core, void *extension);
ftun_status_t ftun_core_context_extension(const ftun_core_t *core,
                                          void **out);
ftun_status_t ftun_core_context_budget(const ftun_core_t *core,
                                       ftun_budget_t **out);
/* 业务扩展已释放后，宿主可把借用预算切回仍存活的根，完成分步清理。
 * context 自身的预留仍属于创建时的预算，该节点必须存活至 context 销毁。 */
ftun_status_t ftun_core_context_set_budget(ftun_core_t *core,
                                           ftun_budget_t *budget);
/* 业务层判断上下文是否可用的公开入口，不暴露私有布局。 */
bool ftun_core_context_is_valid(const ftun_core_t *core);
/* 运行配置代次。读取可跨线程（原子获取）；其余入口只在 owner
 * 线程调用。所有产生新运行配置代次的来源（reload、FRS 更新等）必须先
 * reserve：同一时刻只允许一个预留，已有预留返回 AGAIN，调用方稍后重试；
 * 达到上限返回 LIMIT。owner 是持有者标识（非空，只做相等比较），宿主事务
 * 使用 Core 上下文自身。publish 只能由持有者发布当前预留值并清除预留；
 * release 放弃预留且不改变代次；持有者或代次不符返回 STALE。 */
ftun_status_t ftun_core_context_generation(const ftun_core_t *core,
                                           uint64_t *out);
ftun_status_t ftun_core_context_generation_reserve(ftun_core_t *core,
  const void *owner, uint64_t *out_next);
ftun_status_t ftun_core_context_generation_publish(ftun_core_t *core,
  const void *owner, uint64_t next);
ftun_status_t ftun_core_context_generation_release(ftun_core_t *core,
  const void *owner, uint64_t next);
/* 返回当前预留值，没有预留时为零。 */
ftun_status_t ftun_core_context_generation_reserved(const ftun_core_t *core,
                                                    uint64_t *out);
/* owner 持有预留时返回 OK 并输出预留值；没有预留或由其他来源持有时返回
 * STALE，输出为零。 */
ftun_status_t ftun_core_context_generation_held(const ftun_core_t *core,
  const void *owner, uint64_t *out_next);
/* 发布槽借用 logger。替换返回后旧实例没有 Core emit 借用，拥有者才可
 * stop/destroy。Core 本身的销毁仍须由调用方保证没有并发 API 使用。 */
ftun_status_t ftun_core_context_set_logger(ftun_core_t *core,
                                           ftun_logger_t *logger);
/* 记录器由 App 拥有，此处仅发布借用；撤销返回后没有在途 Core 记录借用。
 * 不在底层 context_create 分配，独立使用 Core 的宿主可不启用。 */
ftun_status_t ftun_core_context_set_event_log(ftun_core_t *core,
                                              ftun_event_log_t *log);
/* 配置 sink 和事件过滤在同一个发布锁中切换。首次输出早期 FIFO，之后
 * 向旧 sink 汇总。输出失败仍发布新 sink，并通过返回值/计数报告；
 * 已关闭事件记录器返回 STALE，不修改槽。silent 可使用 NULL logger。 */
ftun_status_t ftun_core_context_publish_logger(ftun_core_t *core,
  ftun_logger_t *logger, bool silent);
/* 同一发布锁内汇总/记录终止事件并撤销 sink，后续 Core emit 无法插入
 * terminal 之后。拥有者随后在既有期限内 stop/join/destroy logger。 */
ftun_status_t ftun_core_context_finish_logging(ftun_core_t *core,
  const ftun_lifecycle_event_t *terminal);
/* 同时借用事件记录器与 logger，后者在早期/silent 可为 NULL。
 * 成功持发布锁，使用 logger_release 释放；只允许有界记录/快照。 */
ftun_status_t ftun_core_context_events_acquire(ftun_core_t *core,
  ftun_event_log_t **events, ftun_logger_t **logger);
/* 成功 acquire 持锁至同线程 release；期间只允许有界 enqueue，禁止
 * writer、flush、join 或用户回调。失败不持锁。锁序为发布槽→logger。 */
ftun_status_t ftun_core_context_logger_acquire(ftun_core_t *core,
                                               ftun_logger_t **out);
ftun_status_t ftun_core_context_logger_release(ftun_core_t *core);
ftun_status_t ftun_core_context_set_control(ftun_core_t *core, void *control);
ftun_status_t ftun_core_context_control(ftun_core_t *core, void **out);
ftun_status_t ftun_core_context_destroy(ftun_core_t **core);

#endif
