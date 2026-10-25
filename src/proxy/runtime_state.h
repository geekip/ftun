#ifndef FTUN_PROXY_RUNTIME_STATE_H
#define FTUN_PROXY_RUNTIME_STATE_H
#include "core/context.h"
#include "proxy/group/url_test.h"
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
  bool has_cleanup;
  size_t retained_count;
  size_t retained_limit;
  size_t retained_bytes;
  size_t retained_bytes_limit;
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
/* Core 使用数量和字节双额度；兼容入口的字节额度为 SIZE_MAX。 */
ftun_status_t ftun_runtime_manager_create_limits(
  ftun_budget_t *budget, size_t retained_limit, size_t retained_bytes_limit,
  ftun_core_t **out);
/* 宿主先创建中立 Core，再附着唯一快照扩展；失败不改变已有 Core。
 * 调用由 owner 串行执行，已有扩展返回 STALE，不覆盖其他模块状态。 */
ftun_status_t ftun_runtime_manager_attach(ftun_core_t *core,
  size_t retained_limit, size_t retained_bytes_limit);
ftun_status_t ftun_runtime_manager_get_info(const ftun_core_t *core,
                                            ftun_runtime_manager_info_t *out);
/* candidate/retained 或 active 外部引用存在时返回 AGAIN。
 * 已消费句柄的清理失败对象由 manager 保留；后续 prepare/clear 重试，
 * 每次最多回收一个积压对象，未排空前拒绝新增候选。 */
ftun_status_t ftun_runtime_manager_destroy(ftun_core_t **core);
/* 只释放快照扩展，保留通用 Core 供宿主完成其他可重试清理。 */
ftun_status_t ftun_runtime_manager_clear(ftun_core_t *core);
/* 编译结果的准备与快照生命周期。
 * 需求 REQ-CONF-001；任务 TASK-CORE-001；目标 0.2.0；验收 TEST-CORE-001。
 * 实现路径：引用配置计划，检查 active/candidate/retained 总预算；准备必需对象；由 loop 提交，旧代按引用回收。
 * 调用边界：不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；成功后 candidate 保留 config，调用者用 commit 转移或 abort 回滚。
 */
ftun_status_t ftun_runtime_prepare(ftun_core_t *core, const ftun_config_t *config, ftun_runtime_t **out);
/* FRS 更新事务使用已完整校验的候选 view 重新准备同一配置；Runtime 成功
 * 后拥有 view 引用。普通启动必须调用 ftun_runtime_prepare。 */
ftun_status_t ftun_runtime_prepare_with_frs(ftun_core_t *core,
                                            const ftun_config_t *config,
                                            ftun_frs_view_t *view,
                                            ftun_runtime_t **out);
#if defined(FTUN_HAVE_MODULE_FRS)
/* FRS 更新 worker 使用的脱离态候选。prepare 在 worker 内完成规则表和
 * label 绑定，成功时接管 view；配置只借用至 attach 或 release 完成。
 * 已绑定配置使用其预算在分配前准入；宿主保证预算活到候选回收结束。
 * attach 在 owner loop 保留配置并提交 manager，复用同根已有额度；
 * 独立未绑定配置仍在 attach 时准入。清理失败保留候选和额度供重试。 */
ftun_status_t ftun_runtime_prepare_detached(
  const ftun_config_t *config, ftun_frs_view_t *view, ftun_runtime_t **out);
ftun_status_t ftun_runtime_prepare_detached_frs(
  const ftun_config_t *config, ftun_frs_view_t *view, ftun_runtime_t **out);
ftun_status_t ftun_runtime_attach_prepared(ftun_core_t *core,
                                           ftun_runtime_t **prepared,
                                           ftun_runtime_t **out);
ftun_status_t ftun_runtime_prepared_frs_bytes(
  const ftun_runtime_t *prepared, ftun_bytes_t *out);
ftun_status_t ftun_runtime_prepared_release(ftun_runtime_t **prepared);
#endif
ftun_status_t ftun_runtime_accounted_bytes(const ftun_config_t *config,
                                            size_t *out);
/* commit 不分配；成功清空 candidate 句柄并由 manager 持有 active。 */
ftun_status_t ftun_runtime_commit(ftun_core_t *core, ftun_runtime_t **candidate);
/* 持久化先于指针切换的事务可先执行只读提交门禁；成功后到 commit 之间不得
 * 穿插其他 Runtime 操作。 */
ftun_status_t ftun_runtime_can_commit(const ftun_core_t *core,
                                      const ftun_runtime_t *candidate);
/* 在其他子系统提交前固定候选代次。成功后 commit 只执行常数次指针切换；
 * 若后续 prepare/commit 失败，abort 可安全丢弃尚未公开的候选。 */
ftun_status_t ftun_runtime_stage_commit(ftun_core_t *core,
                                        ftun_runtime_t *candidate,
                                        uint64_t generation);
/* 合法句柄即被消费；叶清理失败仍由 manager 持有对象和预算。 */
ftun_status_t ftun_runtime_abort(ftun_core_t *core, ftun_runtime_t **candidate);
/* acquire/release 表示 Session 等旧代消费者的引用。
 * 最后消费者释放后，即使叶清理失败也消费句柄，由 manager 负责重试。 */
ftun_status_t ftun_runtime_active_acquire(ftun_core_t *core, ftun_runtime_t **out);
ftun_status_t ftun_runtime_retain(ftun_runtime_t *runtime);
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
#endif
