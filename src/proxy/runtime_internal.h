#ifndef FTUN_PROXY_RUNTIME_INTERNAL_H
#define FTUN_PROXY_RUNTIME_INTERNAL_H

#include "config/model.h"
#include "core/context.h"
#include "proxy/route/router.h"
#include "proxy/runtime_state.h"

#define FTUN_RUNTIME_MANAGER_MAGIC UINT32_C(0x4654524d)

typedef struct {
  uint64_t feature;
  size_t ordinal;
} ftun_runtime_prepared_item_t;

typedef struct {
  uint32_t selected_member_id;
  uint32_t latency_ms;
  uint64_t observed_ms;
  bool selected;
  bool degraded;
  bool health_valid;
  bool health_success;
} ftun_runtime_group_choice_state_t;

/* Snapshot 在提交前完成构造，发布后只读。 */
typedef struct {
  const ftun_config_t *config;
  ftun_runtime_prepared_item_t *prepared_items;
  ftun_route_table_t *routes;
  ftun_frs_view_t *frs_view;
  size_t prepared_item_count;
  size_t accounted_bytes;
} ftun_runtime_snapshot_t;

/* 组选择和健康结果属于 owner 可变状态，不污染旧 Flow 持有的快照。 */
typedef struct {
  ftun_runtime_group_choice_state_t *group_choices;
  size_t group_choice_count;
} ftun_runtime_owner_state_t;

struct ftun_runtime {
  ftun_core_t *owner;
  ftun_reservation_t *reservation;
  ftun_runtime_snapshot_t snapshot;
  ftun_runtime_owner_state_t owner_state;
  size_t reference_count;
  uint64_t generation;
  ftun_runtime_state_t state;
  ftun_runtime_t *next_retained;
  bool retention_reserved;
  bool blocks_active_acquire;
  bool cleanup_pending;
};

typedef struct {
  uint32_t runtime_magic;
  ftun_reservation_t *reservation;
  ftun_runtime_t *active;
  ftun_runtime_t *candidate;
  ftun_runtime_t *retained;
  ftun_runtime_t *cleanup;
  size_t retained_count;
  size_t retained_limit;
  size_t retained_bytes;
  size_t retained_bytes_limit;
} ftun_snapshot_manager_t;

/* Proxy 只经 Core 上下文的公开接口取得扩展、预算与代次，不读写其私有布局。 */
static inline ftun_snapshot_manager_t *ftun_runtime_manager_of(
  const ftun_core_t *core)
{
  void *extension = NULL;
  return ftun_core_context_extension(core, &extension) == FTUN_OK
    ? (ftun_snapshot_manager_t *)extension : NULL;
}

#define FTUN_MANAGER(core) ftun_runtime_manager_of(core)

static inline ftun_budget_t *ftun_runtime_core_budget(const ftun_core_t *core)
{
  ftun_budget_t *budget = NULL;
  (void)ftun_core_context_budget(core, &budget);
  return budget;
}

static inline uint64_t ftun_runtime_core_generation(const ftun_core_t *core)
{
  uint64_t generation = 0u;
  (void)ftun_core_context_generation(core, &generation);
  return generation;
}

static inline int ftun_runtime_core_valid(const ftun_core_t *core)
{
  const ftun_snapshot_manager_t *manager = ftun_runtime_manager_of(core);
  return manager != NULL &&
         manager->runtime_magic == FTUN_RUNTIME_MANAGER_MAGIC;
}

#endif
