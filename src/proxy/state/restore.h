#ifndef FTUN_PROXY_STATE_RESTORE_H
#define FTUN_PROXY_STATE_RESTORE_H
#include "internal/contracts.h"
#include "proxy/state/group_cache.h"

/* 
 * ftun_state_restore_at 不得让缓存覆盖当前配置身份。 */

typedef struct {
  size_t restored_groups;
  size_t restored_health;
  bool cache_missing;
  bool cache_discarded;
  bool fingerprint_mismatch;
} ftun_state_restore_info_t;

ftun_status_t ftun_state_restore_at(ftun_core_t *core,
                                    const ftun_config_t *config,
                                    uint64_t now_ms,
                                    uint64_t health_max_age_ms,
                                    ftun_state_restore_info_t *out);
ftun_status_t ftun_state_restore_candidate_at(
  ftun_core_t *core, const ftun_config_t *config, uint64_t now_ms,
  uint64_t health_max_age_ms, ftun_state_restore_info_t *out);
/* reload worker 读取并解析缓存，owner 只把借用快照应用到未公开候选。 */
ftun_status_t ftun_state_restore_candidate_snapshot_at(
  ftun_core_t *core, const ftun_config_t *config,
  const ftun_group_cache_snapshot_t *snapshot, ftun_status_t load_status,
  uint64_t now_ms, uint64_t health_max_age_ms,
  ftun_state_restore_info_t *out);
#endif
