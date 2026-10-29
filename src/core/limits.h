#ifndef FTUN_CORE_LIMITS_H
#define FTUN_CORE_LIMITS_H
#include "util/types.h"

/* 凭据内嵌于唯一 owner，零值表示没有资源；转交后清空源或结束源生命周期，禁止再次访问或释放源。 */
struct ftun_reservation {
  ftun_budget_t *budget;
  size_t resources[3];
  int cleanup;
};

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
  /* 本子树已接纳 Budget 结构的分配字节，含根锁；不含
   * 准入前/释放后的临时分配及 allocator 开销。独立于资源额度，
   * 不能解释为 RSS 或进程内存硬上限。 */
  size_t metadata_bytes;
} ftun_budget_usage_t;

/* ftun_budget_reserve; Core v1.0 extends the same admission contract to typed resources. */
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
/* 根直系子域独立同步，后代共享本域；普通准入、resize、释放不取得根结构锁。
 * 全局上限以原子额度仲裁，向量部分失败归还临时额度，不分配额外对象。
 * 结构变更和一致 usage 快照按“结构锁→根域→直系子域”锁序短暂锁定全部域；
 * 实现不回调或取得调用方锁，外部锁可以先持有，禁止相反锁序。
 * 凭据只能由唯一 owner 消费；销毁预算前停止新调用并等待已有调用结束。
 * 父预算在全部子预算和凭据归还后销毁，销毁与继续使用同一指针不是合法并发。 */
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
  ftun_reservation_t *out);
ftun_status_t ftun_budget_reserve_cleanup_resources(
  ftun_budget_t *budget, ftun_budget_resources_t resources,
  ftun_reservation_t *out);
ftun_status_t ftun_budget_reserve(ftun_budget_t *budget, size_t bytes,
                                  ftun_reservation_t *out);
ftun_status_t ftun_budget_reserve_cleanup(ftun_budget_t *budget, size_t bytes,
                                          ftun_reservation_t *out);
ftun_status_t ftun_budget_get_usage(const ftun_budget_t *budget,
                                    ftun_budget_usage_t *out);
/* Returns whether both budgets belong to the same global admission tree. */
ftun_status_t ftun_budget_same_root(const ftun_budget_t *left,
                                    const ftun_budget_t *right,
                                    bool *out_same);
/* 消费并清零凭据；空凭据幂等，调用方必须传入有效 owner 存储。 */
void ftun_reservation_release(ftun_reservation_t *reservation);
/* 在本域同步范围内改变拥有额度，不分配凭据；失败保持原额度。
 * 每一维独立准入，保留原 normal/cleanup 类型和祖先保障规则。
 * 全零目标无效，最终归还使用 release。调用者仍独占 reservation 句柄。 */
ftun_status_t ftun_reservation_resize(ftun_reservation_t *reservation,
  ftun_budget_resources_t resources);
/* An active reservation or child returns AGAIN and preserves the handle. */
ftun_status_t ftun_budget_destroy(ftun_budget_t **budget);
#endif
