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
} ftun_core_service_t;

typedef struct {
  const ftun_core_service_descriptor_t *descriptor;
  void *implementation;
} ftun_core_service_plan_t;

/* Core 只传递 Composition 构造的类型擦除借用，不保存也不解释业务句柄。 */
typedef struct {
  const void *value;
  size_t size;
} ftun_core_service_binding_t;

typedef struct {
  size_t work;
  uint64_t busy_ms;
  uint64_t deadline_lateness_ms;
  bool quota_exhausted;
} ftun_core_service_run_usage_t;

/* 业务服务只通过静态 descriptor 接入 Core。descriptor 与函数表必须在
 * Core 整个生命周期内保持有效；implementation 由服务拥有并由 destroy
 * 回收。所有方法均在 owner loop 调用，只有 plan_prepare 可在 reload
 * worker 调用，因而只能访问传入的拥有型配置和不可变 descriptor。
 * reload_prepare 必须完成所有可能失败的分配和 I/O；跨服务全部 prepare
 * 成功后，reload_commit 只允许执行无分配、无 I/O 的 owner 状态发布。
 * prepare 失败按逆序 abort；commit 返回失败表示状态损坏，不能当作普通
 * 运行错误依赖跨服务回滚恢复。 */
struct ftun_core_service_descriptor {
  const char *name;
  ftun_status_t (*plan_prepare)(const ftun_config_t *config,
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
};

bool ftun_core_service_descriptor_valid(
  const ftun_core_service_descriptor_t *descriptor);
ftun_status_t ftun_core_service_plan_prepare(
  const ftun_core_service_descriptor_t *descriptor,
  const ftun_config_t *config, uint32_t socket_mark,
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
ftun_status_t ftun_core_service_quiesce(ftun_core_service_t *service);
ftun_status_t ftun_core_service_drain_until(ftun_core_service_t *service,
                                            uint64_t deadline_ms);
ftun_status_t ftun_core_service_stop_until(ftun_core_service_t *service,
                                           uint64_t deadline_ms);
ftun_status_t ftun_core_service_destroy_until(ftun_core_service_t *service,
                                              uint64_t deadline_ms);
ftun_status_t ftun_core_service_destroy(ftun_core_service_t *service);

#endif
