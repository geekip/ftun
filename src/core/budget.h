#ifndef FTUN_CORE_BUDGET_H
#define FTUN_CORE_BUDGET_H
#include "internal/contracts.h"

typedef struct {
  size_t limit;
  size_t cleanup_reserve;
  size_t used;
  size_t normal_available;
  size_t total_available;
  size_t child_count;
} ftun_budget_usage_t;

/* 统一资源准入。
 * 需求 REQ-PERF-001；任务 TASK-CORE-004；目标 0.2.0；验收 TEST-CORE-004。
 * 所有可变计数只由 owner loop 串行访问，本模块不提供跨线程同步。
 * parent 为全局预算的借用指针，必须比子预算和它的全部预留长寿。
 * cleanup_reserve 不可被普通请求使用，保留给清理和终结通知路径。
 * 计数是逻辑准入证据，不是 RSS/PSS 测量。
 */
ftun_status_t ftun_budget_create(ftun_budget_t *parent, size_t limit,
                                 size_t cleanup_reserve, ftun_budget_t **out);
ftun_status_t ftun_budget_reserve(ftun_budget_t *budget, size_t bytes, ftun_reservation_t **out);
ftun_status_t ftun_budget_reserve_cleanup(ftun_budget_t *budget, size_t bytes,
                                          ftun_reservation_t **out);
ftun_status_t ftun_budget_get_usage(const ftun_budget_t *budget, ftun_budget_usage_t *out);
/* release 将调用者句柄置空；NULL 句柄是幂等成功。 */
ftun_status_t ftun_reservation_release(ftun_reservation_t **reservation);
/* 仍有子预算或活动预留时返回 AGAIN 并保留句柄。 */
ftun_status_t ftun_budget_destroy(ftun_budget_t **budget);
#endif
