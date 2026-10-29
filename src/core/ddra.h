#ifndef FTUN_CORE_DDRA_H
#define FTUN_CORE_DDRA_H

#include "core/config/document.h"
#include "core/lifecycle.h"

#define FTUN_CORE_MODULE_LIMIT 16u

typedef struct ftun_core_module_runtime ftun_core_module_runtime_t;
typedef struct ftun_core_module_reload_plan ftun_core_module_reload_plan_t;

typedef struct {
  const char *name;
  uint32_t capability;
  uint32_t dependencies;
  /* 依赖允许的节点之间按较小值先 prepare/activate；逆序生命周期自然让
   * consumer 先于 provider 停止。零值保持既有 capability 稳定顺序。 */
  uint32_t startup_order;
  /* NULL 表示能力当前嵌入其他服务，只参与依赖闭包与能力诊断。 */
  const ftun_core_service_descriptor_t *service;
  /* 由 Composition 静态绑定；Core 只按值传给对应 service prepare。 */
  ftun_core_service_binding_t binding;
} ftun_core_module_descriptor_t;

typedef struct {
  const ftun_core_module_descriptor_t *modules;
  size_t module_count;
  /* 独立可选根缺席时进入 skipped_optional，不扩大配置 required 集合。 */
  uint32_t optional_modules;
} ftun_core_module_catalog_t;

typedef struct {
  uint32_t required_modules;
  uint32_t selected_modules;
  uint32_t skipped_optional;
  size_t module_count;
  size_t service_count;
  size_t prepared_count;
  size_t active_count;
  size_t quiesced_count;
  size_t drained_count;
  bool reload_prepared;
  bool rolled_back;
  bool cleanup_only;
  size_t reload_pending_count;
  ftun_status_t first_error;
  ftun_status_t cleanup_error;
} ftun_core_module_info_t;

bool ftun_core_module_catalog_valid(
  const ftun_core_module_catalog_t *catalog);

ftun_status_t ftun_core_module_reload_plan_prepare(
  const ftun_core_module_catalog_t *catalog, ftun_budget_t *budget, const ftun_config_t *config,
  uint32_t socket_mark, ftun_core_module_reload_plan_t **out,
  ftun_diagnostic_t *diagnostic);
ftun_status_t ftun_core_module_reload_plan_destroy(
  ftun_core_module_reload_plan_t **plan);
ftun_status_t ftun_core_module_reload_plan_get_errors(
  const ftun_core_module_reload_plan_t *plan,
  ftun_status_t *first_error, ftun_status_t *cleanup_error);

/* prepare 的 out 必须初始化为空。失败后的非空输出仍归调用者拥有，
 * 仅可清理；所有 descriptor、binding 和借用依赖必须保留至 destroy 成功。 */
ftun_status_t ftun_core_module_runtime_prepare(
  const ftun_core_module_catalog_t *catalog, ftun_core_t *core,
  ftun_budget_t *budget, ftun_operation_queue_t *operations,
  const ftun_config_t *config, uint64_t generation,
  ftun_core_module_runtime_t **out, ftun_diagnostic_t *diagnostic);
ftun_status_t ftun_core_module_runtime_activate(
  ftun_core_module_runtime_t *runtime, uint64_t rollback_deadline_ms);
ftun_status_t ftun_core_module_runtime_reload_prepare(
  ftun_core_module_runtime_t *runtime, const ftun_config_t *config,
  uint64_t generation);
ftun_status_t ftun_core_module_runtime_reload_prepare_planned(
  ftun_core_module_runtime_t *runtime, const ftun_config_t *config,
  uint64_t generation, const ftun_core_module_reload_plan_t *plan);
ftun_status_t ftun_core_module_runtime_reload_commit(
  ftun_core_module_runtime_t *runtime, uint64_t generation);
ftun_status_t ftun_core_module_runtime_reload_abort(
  ftun_core_module_runtime_t *runtime);
ftun_status_t ftun_core_module_runtime_run_once(
  ftun_core_module_runtime_t *runtime, bool may_block,
  ftun_core_service_run_usage_t *out_usage);
/* 把网络变化转交给每个已准备的服务（它们的 network_changed 钩子）。 */
void ftun_core_module_runtime_network_changed(
  ftun_core_module_runtime_t *runtime, const ftun_network_change_t *change,
  uint64_t now_ms);
ftun_status_t ftun_core_module_runtime_wakeup(
  ftun_core_module_runtime_t *runtime);
ftun_status_t ftun_core_module_runtime_quiesce(
  ftun_core_module_runtime_t *runtime);
ftun_status_t ftun_core_module_runtime_drain_until(
  ftun_core_module_runtime_t *runtime, uint64_t deadline_ms);
ftun_status_t ftun_core_module_runtime_stop_until(
  ftun_core_module_runtime_t *runtime, uint64_t deadline_ms);
ftun_status_t ftun_core_module_runtime_destroy_until(
  ftun_core_module_runtime_t **runtime, uint64_t deadline_ms);
ftun_status_t ftun_core_module_runtime_get_info(
  const ftun_core_module_runtime_t *runtime, ftun_core_module_info_t *out);

#endif
