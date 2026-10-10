#ifndef FTUN_CORE_RUNTIME_H
#define FTUN_CORE_RUNTIME_H
#include "core/budget.h"
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

/* 0.2 内部 owner-loop 管理器；budget 借用且必须比 manager 长寿。 */
ftun_status_t ftun_runtime_manager_create(ftun_budget_t *budget,
                                          size_t retained_limit,
                                          ftun_core_t **out);
ftun_status_t ftun_runtime_manager_get_info(const ftun_core_t *core,
                                            ftun_runtime_manager_info_t *out);
/* 返回 manager 创建时借用的全局 Budget，供同一 owner loop 的 Session 准入。 */
ftun_status_t ftun_runtime_manager_budget(ftun_core_t *core,
                                          ftun_budget_t **out);
/* candidate/retained 或 active 外部引用存在时返回 AGAIN。 */
ftun_status_t ftun_runtime_manager_destroy(ftun_core_t **core);
/* 编译结果的准备与快照生命周期。
 * 需求 REQ-CONF-001；任务 TASK-CORE-001；目标 0.2.0；验收 TEST-CORE-001。
 * 实现路径：引用配置计划，检查 active/candidate/retained 总预算；准备必需对象；由 loop 提交，旧代按引用回收。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；成功后 candidate 保留 config，调用者用 commit 转移或 abort 回滚。
 */
ftun_status_t ftun_runtime_prepare(ftun_core_t *core, const ftun_config_t *config, ftun_runtime_t **out);
/* commit 不分配；成功清空 candidate 句柄并由 manager 持有 active。 */
ftun_status_t ftun_runtime_commit(ftun_core_t *core, ftun_runtime_t **candidate);
ftun_status_t ftun_runtime_abort(ftun_core_t *core, ftun_runtime_t **candidate);
/* acquire/release 表示 Session 等旧代消费者的引用。 */
ftun_status_t ftun_runtime_active_acquire(ftun_core_t *core, ftun_runtime_t **out);
ftun_status_t ftun_runtime_release(ftun_runtime_t **runtime);
ftun_status_t ftun_runtime_get_info(const ftun_runtime_t *runtime,
                                    ftun_runtime_info_t *out);
#endif
