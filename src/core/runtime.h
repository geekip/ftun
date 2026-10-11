#ifndef FTUN_CORE_RUNTIME_H
#define FTUN_CORE_RUNTIME_H
#include "core/budget.h"
#include "group/url_test.h"
#include "internal/contracts.h"

typedef enum {
  FTUN_RUNTIME_CANDIDATE = 1,
  FTUN_RUNTIME_ACTIVE,
  FTUN_RUNTIME_RETAINED
} ftun_runtime_state_t;

typedef struct {
  ftun_runtime_state_t state;
  uint64_t generation;
  size_t reference_count;
  size_t accounted_bytes;
  size_t prepared_item_count;
} ftun_runtime_info_t;

typedef struct {
  uint64_t generation;
  bool has_active;
  bool has_candidate;
  size_t retained_count;
  size_t retained_limit;
} ftun_runtime_manager_info_t;

typedef enum {
  FTUN_RUNTIME_GROUP_SELECT = 1,
  FTUN_RUNTIME_GROUP_URL_TEST
} ftun_runtime_group_kind_t;

typedef struct {
  ftun_string_t group;
  ftun_string_t member;
  ftun_runtime_group_kind_t kind;
  bool degraded;
  bool health_valid;
  bool health_success;
  uint32_t latency_ms;
  uint64_t observed_ms;
} ftun_runtime_group_record_t;

/* 0.2 内部 owner-loop 管理器；budget 借用且必须比 manager 长寿。 */
ftun_status_t ftun_runtime_manager_create(ftun_budget_t *budget,
                                          size_t retained_limit,
                                          ftun_core_t **out);
ftun_status_t ftun_runtime_manager_get_info(const ftun_core_t *core,
                                            ftun_runtime_manager_info_t *out);
/* 返回 manager 创建时借用的全局 Budget，供同一 owner loop 的 Session 准入。 */
ftun_status_t ftun_runtime_manager_budget(ftun_core_t *core,
                                          ftun_budget_t **out);
/* FakeIP 服务由装配层拥有；manager 仅借用并为公共 ftun_fakeip_acquire
 * 提供唯一入口。替换或清空必须在 owner loop、无并发调用时完成。 */
ftun_status_t ftun_runtime_manager_set_fakeip(ftun_core_t *core,
                                              ftun_fakeip_service_t *service);
ftun_status_t ftun_runtime_manager_fakeip(ftun_core_t *core,
                                          ftun_fakeip_service_t **out);
ftun_status_t ftun_runtime_manager_set_dns(ftun_core_t *core,
                                           ftun_dns_dispatcher_t *dispatcher);
ftun_status_t ftun_runtime_manager_dns(ftun_core_t *core,
                                       ftun_dns_dispatcher_t **out);
ftun_status_t ftun_runtime_manager_set_logger(ftun_core_t *core,
                                              ftun_logger_t *logger);
ftun_status_t ftun_runtime_manager_logger(ftun_core_t *core,
                                          ftun_logger_t **out);
/* candidate/retained 或 active 外部引用存在时返回 AGAIN。 */
ftun_status_t ftun_runtime_manager_destroy(ftun_core_t **core);
/* 编译结果的准备与快照生命周期。
 * 需求 REQ-CONF-001；任务 TASK-CORE-001；目标 0.2.0；验收 TEST-CORE-001。
 * 实现路径：引用配置计划，检查 active/candidate/retained 总预算；准备必需对象；由 loop 提交，旧代按引用回收。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；成功后 candidate 保留 config，调用者用 commit 转移或 abort 回滚。
 */
ftun_status_t ftun_runtime_prepare(ftun_core_t *core, const ftun_config_t *config, ftun_runtime_t **out);
/* FRS 更新事务使用已完整校验的候选 view 重新准备同一配置；Runtime 成功
 * 后拥有 view 引用。普通启动必须调用 ftun_runtime_prepare。 */
ftun_status_t ftun_runtime_prepare_with_frs(ftun_core_t *core,
                                            const ftun_config_t *config,
                                            ftun_frs_view_t *view,
                                            ftun_runtime_t **out);
/* commit 不分配；成功清空 candidate 句柄并由 manager 持有 active。 */
ftun_status_t ftun_runtime_commit(ftun_core_t *core, ftun_runtime_t **candidate);
/* 持久化先于指针切换的事务可先执行只读提交门禁；成功后到 commit 之间不得
 * 穿插其他 Runtime 操作。 */
ftun_status_t ftun_runtime_can_commit(const ftun_core_t *core,
                                      const ftun_runtime_t *candidate);
ftun_status_t ftun_runtime_abort(ftun_core_t *core, ftun_runtime_t **candidate);
/* acquire/release 表示 Session 等旧代消费者的引用。 */
ftun_status_t ftun_runtime_active_acquire(ftun_core_t *core, ftun_runtime_t **out);
ftun_status_t ftun_runtime_release(ftun_runtime_t **runtime);
ftun_status_t ftun_runtime_get_info(const ftun_runtime_t *runtime,
                                    ftun_runtime_info_t *out);
/* 返回 Runtime 拥有的不可变规则表；借用期不超过 Runtime 引用。 */
ftun_status_t ftun_runtime_route_table(const ftun_runtime_t *runtime,
                                       const ftun_route_table_t **out);
/* 返回指定 Runtime 拥有的不可变配置；调用方必须持有 Runtime 引用。 */
ftun_status_t ftun_runtime_config(const ftun_runtime_t *runtime,
                                  const ftun_config_t **out);
/* 将内置或配置名称解析为该 Runtime 的稳定出口 ID。 */
ftun_status_t ftun_runtime_resolve_outbound_name(
  const ftun_runtime_t *runtime, ftun_string_t name, uint32_t *out);
/* 借用不可变 FRSView；仅在 Runtime 引用期内有效。无 FRS 返回 AGAIN。 */
ftun_status_t ftun_runtime_frs_view(const ftun_runtime_t *runtime,
                                    ftun_frs_view_t **out);
/* 0.4 代理组 owner-loop 状态。group/member 使用稳定 outbound ID。 */
ftun_status_t ftun_runtime_select_set(ftun_core_t *core,
                                      uint32_t group_id,
                                      uint32_t member_id);
ftun_status_t ftun_runtime_select_names(ftun_core_t *core,
                                        ftun_string_t group,
                                        ftun_string_t member);
ftun_status_t ftun_runtime_group_selected(const ftun_runtime_t *runtime,
                                           uint32_t group_id,
                                           uint32_t *member_id,
                                           bool *is_group,
                                           bool *degraded,
                                           ftun_string_t *dns_server);
ftun_status_t ftun_runtime_group_publish(ftun_core_t *core,
                                         uint32_t group_id,
                                         const ftun_group_choice_t *choice);
/* 状态缓存桥接。返回值中的字符串借用 active Runtime；只允许 owner loop
 * 同步读取。restore 再次校验组类型和成员身份。 */
ftun_status_t ftun_runtime_active_config(const ftun_core_t *core,
                                         const ftun_config_t **out);
ftun_status_t ftun_runtime_group_records(const ftun_core_t *core,
                                         ftun_runtime_group_record_t *records,
                                         size_t capacity, size_t *out_count);
ftun_status_t ftun_runtime_group_restore(ftun_core_t *core,
                                         const ftun_runtime_group_record_t *record,
                                         bool restore_health);
ftun_status_t ftun_runtime_candidate_group_restore(
  ftun_core_t *core, const ftun_runtime_group_record_t *record,
  bool restore_health);
ftun_status_t ftun_runtime_group_publish_health(
  ftun_core_t *core, uint32_t group_id, const ftun_group_choice_t *choice,
  const ftun_health_sample_t *sample);
/* 公共 Core 生命周期的私有 sidecar；普通 Runtime manager 使用者保持 NULL。 */
ftun_status_t ftun_runtime_manager_set_control(ftun_core_t *core,
                                               void *control);
ftun_status_t ftun_runtime_manager_control(ftun_core_t *core, void **out);
#endif
