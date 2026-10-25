#ifndef FTUN_CORE_BUDGET_H
#define FTUN_CORE_BUDGET_H
#include "internal/contracts.h"

typedef struct {
  size_t memory_bytes;
  size_t descriptors;
  size_t queue_slots;
} ftun_budget_resources_t;

typedef struct {
  ftun_budget_resources_t limit;
  ftun_budget_resources_t cleanup_reserve;
  ftun_budget_resources_t guarantee;
} ftun_budget_options_t;

typedef struct {
  /* Legacy memory fields remain available to existing callers. */
  size_t limit;
  size_t cleanup_reserve;
  size_t used;
  size_t normal_available;
  size_t total_available;
  size_t child_count;
  ftun_budget_resources_t limits;
  ftun_budget_resources_t cleanup_reserves;
  ftun_budget_resources_t guarantees;
  ftun_budget_resources_t used_resources;
  ftun_budget_resources_t normal_available_resources;
  ftun_budget_resources_t total_available_resources;
  ftun_budget_resources_t borrowed_resources;
  ftun_budget_resources_t high_watermarks;
  size_t rejected_reservations;
  /* 本子树已接纳 Budget/Reservation 结构的分配字节，含根锁；不含
   * 准入前/释放后的临时分配及 allocator 开销。独立于资源额度，
   * 不能解释为 RSS 或进程内存硬上限。 */
  size_t metadata_bytes;
} ftun_budget_usage_t;

/* ftun_budget_reserve implements TASK-CORE-004 / TEST-CORE-004, target
 * 0.2.0; Core v1.0 extends the same admission contract to typed resources. */
/* Hierarchical resource admission.  Each resource is checked independently.
 * A child's guarantee is protected at its parent while unused; the child can
 * consume that share first and borrow only genuinely shared capacity.  A
 * normal reservation cannot consume cleanup reserve or another child's
 * unused guarantee.  Cleanup reservations may use the full limit and are for
 * bounded termination/rollback paths only.
 *
 * Guaranteed shares belong to
 * direct children of the global root; deeper object budgets scope actual
 * reservations and use a zero guarantee, so the module's aggregate guarantee
 * remains the single source of protected capacity.  Every child and
 * reservation must be destroyed before its parent.  Counters are logical
 * admission evidence; they do not claim to measure RSS, kernel socket memory,
 * or third-party allocator retention. */
/* 同一棵树的准入、释放、子节点登记和 usage 快照由共同根锁串行化，
 * 可由 owner、producer、worker 调用；内部不调用回调或取得调用方锁。
 * 外部锁可先于根锁持有，不允许相反锁序。每个拥有句柄仍只能单方消费。
 * 销毁节点前必须停止针对该节点的新调用并等待已有调用结束；销毁与继续
 * 使用同一指针不是合法并发。父节点在所有子节点和 reservation 之后销毁。 */
ftun_status_t ftun_budget_create_resources(
  ftun_budget_t *parent, const ftun_budget_options_t *options,
  ftun_budget_t **out);

/* Compatibility constructor for memory-only callers.  Descriptor and queue
 * resources are unbounded for this budget; new production roots use the
 * resource-vector constructor. */
ftun_status_t ftun_budget_create(ftun_budget_t *parent, size_t limit,
                                 size_t cleanup_reserve, ftun_budget_t **out);

ftun_status_t ftun_budget_reserve_resources(
  ftun_budget_t *budget, ftun_budget_resources_t resources,
  ftun_reservation_t **out);
ftun_status_t ftun_budget_reserve_cleanup_resources(
  ftun_budget_t *budget, ftun_budget_resources_t resources,
  ftun_reservation_t **out);
ftun_status_t ftun_budget_reserve(ftun_budget_t *budget, size_t bytes,
                                  ftun_reservation_t **out);
ftun_status_t ftun_budget_reserve_cleanup(ftun_budget_t *budget, size_t bytes,
                                          ftun_reservation_t **out);
ftun_status_t ftun_budget_get_usage(const ftun_budget_t *budget,
                                    ftun_budget_usage_t *out);
/* Returns whether both budgets belong to the same global admission tree. */
ftun_status_t ftun_budget_same_root(const ftun_budget_t *left,
                                    const ftun_budget_t *right,
                                    bool *out_same);
/* release consumes and clears a non-NULL handle; a NULL handle is idempotent. */
ftun_status_t ftun_reservation_release(ftun_reservation_t **reservation);
/* 在同一根锁内改变拥有额度，不重新分配句柄；失败保持原额度。
 * 每一维独立准入，保留原 normal/cleanup 类型和祖先保障规则。
 * 全零目标无效，最终归还使用 release。调用者仍独占 reservation 句柄。 */
ftun_status_t ftun_reservation_resize(ftun_reservation_t *reservation,
  ftun_budget_resources_t resources);
/* An active reservation or child returns AGAIN and preserves the handle. */
ftun_status_t ftun_budget_destroy(ftun_budget_t **budget);
#endif
