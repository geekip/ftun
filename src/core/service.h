#ifndef FTUN_CORE_SERVICE_H
#define FTUN_CORE_SERVICE_H

#include "config/model.h"
#include "core/budget.h"
#include "core/operation.h"
#include "internal/contracts.h"

typedef struct ftun_core_service_descriptor ftun_core_service_descriptor_t;

typedef struct {
  const ftun_core_service_descriptor_t *descriptor;
  void *implementation;
  ftun_status_t first_error;
  ftun_status_t cleanup_error;
  bool cleanup_only;
  bool prepared;
  bool reload_pending;
  bool reload_ready;
} ftun_core_service_t;

typedef struct {
  const ftun_core_service_descriptor_t *descriptor;
  void *implementation;
  ftun_status_t first_error;
  ftun_status_t cleanup_error;
  bool cleanup_only;
} ftun_core_service_plan_t;

/* Core 只传递 Composition 构造的类型擦除借用，不保存也不解释业务句柄。 */
typedef struct {
  const void *value;
  size_t size;
} ftun_core_service_binding_t;

/* 故障范围：对象 < 监听 < 上游 < 服务 < 安全。范围只用于计数与诊断，
 * 是否停机只看 STATE_CORRUPT 或 fatal（见 run_once 契约）。 */
typedef enum {
  FTUN_FAULT_SCOPE_OBJECT = 0,
  FTUN_FAULT_SCOPE_LISTENER,
  FTUN_FAULT_SCOPE_UPSTREAM,
  FTUN_FAULT_SCOPE_SERVICE,
  FTUN_FAULT_SCOPE_SECURITY,
  FTUN_FAULT_SCOPE_COUNT
} ftun_fault_scope_t;

typedef struct {
  size_t work;
  uint64_t busy_ms;
  uint64_t deadline_lateness_ms;
  bool quota_exhausted;
  /* 本轮在服务内部已就地处理的故障数，按范围累计，宿主只汇总计数。 */
  size_t faults[FTUN_FAULT_SCOPE_COUNT];
  /* 服务确认无法安全继续运行；与返回 STATE_CORRUPT 等效，宿主据此停机。 */
  bool fatal;
} ftun_core_service_run_usage_t;

/* 业务服务只通过静态 descriptor 接入 Core。descriptor 与函数表必须在
 * Core 整个生命周期内保持有效；implementation 由服务拥有并由 destroy
 * 回收。所有方法均在 owner loop 调用，只有 plan_prepare 可在 reload
 * worker 调用，因而只能访问传入的拥有型配置、线程安全预算和不可变 descriptor。
 * plan_prepare 在分配前从显式 budget 准入，直到 plan_destroy 成功才归还；
 * 调用方必须保证 budget 活到候选及退休计划清理完毕。
 * reload_prepare 必须完成所有可能失败的分配和 I/O；跨服务全部 prepare
 * 成功后，reload_commit 只允许执行无分配、无 I/O 的 owner 状态发布。
 * prepare/plan_prepare 的 out 必须初始化为空。失败可返回只供清理的非空
 * 实例，调用者继续拥有其借用依赖直到 destroy 成功；失败且空表示完全
 * 自清理。destroy 失败必须保留实例，成功必须清空。部分实例的 destroy
 * 必须安全且遵守期限；框架不为失败清理附赠无限期限。
 * reload_prepare 一经调用便必须支持 abort，包括该调用返回失败的情况；
 * abort 失败保留 pending 状态并可重试。commit 返回失败表示状态损坏，
 * 不能当作普通运行错误依赖跨服务回滚恢复。 */
struct ftun_core_service_descriptor {
  const char *name;
  ftun_status_t (*plan_prepare)(ftun_budget_t *budget, const ftun_config_t *config,
                                uint32_t socket_mark, void **out);
  ftun_status_t (*plan_destroy)(void **plan);
  ftun_status_t (*prepare)(ftun_core_t *core, ftun_budget_t *budget,
                           ftun_operation_queue_t *operations,
                           const ftun_core_service_binding_t *binding,
                           const ftun_config_t *config, uint64_t generation,
                           void **out);
  ftun_status_t (*activate)(void *implementation);
  ftun_status_t (*reload_prepare)(void *implementation,
                                  const ftun_config_t *config,
                                  uint64_t generation);
  ftun_status_t (*reload_prepare_planned)(
    void *implementation, const ftun_config_t *config, uint64_t generation,
    const void *plan);
  ftun_status_t (*reload_commit)(void *implementation, uint64_t generation);
  ftun_status_t (*reload_abort)(void *implementation);
  ftun_status_t (*run_once)(void *implementation, bool may_block,
                            ftun_core_service_run_usage_t *out_usage);
  ftun_status_t (*wakeup)(void *implementation);
  ftun_status_t (*quiesce)(void *implementation);
  ftun_status_t (*drain_until)(void *implementation, uint64_t deadline_ms);
  ftun_status_t (*stop_until)(void *implementation, uint64_t deadline_ms);
  ftun_status_t (*destroy_until)(void **implementation,
                                 uint64_t deadline_ms);
  /* 可选。服务级故障期间宿主不再调用 run_once（暂停新业务），改为每轮调用
   * maintain_once 驱动恢复、完成分派、隔离区清理和期限巡检；NULL 表示服务
   * 不支持暂停，故障只计数并继续调用 run_once。non-blocking，最多 quota 个动作。 */
  ftun_status_t (*maintain_once)(void *implementation, uint64_t now_ms,
                                 size_t quota,
                                 ftun_core_service_run_usage_t *out_usage);
  /* 可选。网络发生变化（链路、地址、路由或策略规则）时由 owner 调用，位于
   * run_once 之外。只做状态变更（例如把等待中的恢复实体提前到现在），
   * 不得阻塞、不得调用业务回调；NULL 表示服务不关心。 */
  void (*network_changed)(void *implementation,
                          const ftun_network_change_t *change, uint64_t now_ms);
};

/* run_once 返回非 OK 时，只有 STATE_CORRUPT 或 usage.fatal 会让宿主停机；
 * 其他错误都是服务级故障：宿主记录并计数，继续运行。 */
bool ftun_core_service_run_fatal(ftun_status_t status,
                                 const ftun_core_service_run_usage_t *usage);
bool ftun_core_service_can_pause(const ftun_core_service_t *service);
ftun_status_t ftun_core_service_maintain_once(
  ftun_core_service_t *service, uint64_t now_ms, size_t quota,
  ftun_core_service_run_usage_t *out_usage);

bool ftun_core_service_descriptor_valid(
  const ftun_core_service_descriptor_t *descriptor);
ftun_status_t ftun_core_service_plan_prepare(
  const ftun_core_service_descriptor_t *descriptor,
  ftun_budget_t *budget, const ftun_config_t *config, uint32_t socket_mark,
  ftun_core_service_plan_t *out);
ftun_status_t ftun_core_service_plan_destroy(ftun_core_service_plan_t *plan);
ftun_status_t ftun_core_service_prepare(
  ftun_core_service_t *service,
  const ftun_core_service_descriptor_t *descriptor,
  ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations,
  const ftun_core_service_binding_t *binding,
  const ftun_config_t *config,
  uint64_t generation);
ftun_status_t ftun_core_service_activate(ftun_core_service_t *service);
ftun_status_t ftun_core_service_reload_prepare(
  ftun_core_service_t *service, const ftun_config_t *config,
  uint64_t generation);
ftun_status_t ftun_core_service_reload_prepare_planned(
  ftun_core_service_t *service, const ftun_config_t *config,
  uint64_t generation, const ftun_core_service_plan_t *plan);
ftun_status_t ftun_core_service_reload_commit(ftun_core_service_t *service,
                                              uint64_t generation);
ftun_status_t ftun_core_service_reload_abort(ftun_core_service_t *service);
ftun_status_t ftun_core_service_run_once(
  ftun_core_service_t *service, bool may_block,
  ftun_core_service_run_usage_t *out_usage);
ftun_status_t ftun_core_service_wakeup(ftun_core_service_t *service);
void ftun_core_service_network_changed(ftun_core_service_t *service,
  const ftun_network_change_t *change, uint64_t now_ms);
ftun_status_t ftun_core_service_quiesce(ftun_core_service_t *service);
ftun_status_t ftun_core_service_drain_until(ftun_core_service_t *service,
                                            uint64_t deadline_ms);
ftun_status_t ftun_core_service_stop_until(ftun_core_service_t *service,
                                           uint64_t deadline_ms);
ftun_status_t ftun_core_service_destroy_until(ftun_core_service_t *service,
                                              uint64_t deadline_ms);

#endif
