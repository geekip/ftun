#ifndef FTUN_PROXY_RUNTIME_INTERNAL_H
#define FTUN_PROXY_RUNTIME_INTERNAL_H

#include "config/model.h"
#include "core/context_internal.h"
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
};

typedef struct {
  uint32_t runtime_magic;
  ftun_runtime_t *active;
  ftun_runtime_t *candidate;
  ftun_runtime_t *retained;
  size_t retained_count;
  size_t retained_limit;
  size_t retained_bytes;
  size_t retained_bytes_limit;
} ftun_snapshot_manager_t;

#define FTUN_MANAGER(core) ((ftun_snapshot_manager_t *)(core)->extension)

static inline int ftun_runtime_core_valid(const ftun_core_t *core)
{
  return ftun_core_context_valid(core) && core->extension != NULL &&
         FTUN_MANAGER(core)->runtime_magic == FTUN_RUNTIME_MANAGER_MAGIC;
}

#endif
