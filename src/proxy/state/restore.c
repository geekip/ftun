#include "proxy/state/restore.h"
#include "core/context.h"
#include "proxy/config/transport.h"
#include "proxy/config/plan.h"
#include "proxy/config/model.h"
#include "libs/resolver/config.h"
#include "proxy/state/group_cache.h"
#include "platform/clock.h"
#include <string.h>

/* 
 * ftun_state_restore_at 按配置身份恢复可丢弃的 Group/Health 状态。 */

static ftun_status_t ftun_state_restore_target(
  ftun_core_t *core, const ftun_config_t *config, uint64_t now_ms,
  uint64_t health_max_age_ms, ftun_state_restore_info_t *out,
  bool candidate);

static ftun_status_t ftun_state_apply_snapshot(
  ftun_core_t *core, const ftun_config_t *config,
  const ftun_group_cache_snapshot_t *snapshot, ftun_status_t load_status,
  uint64_t now_ms, uint64_t health_max_age_ms,
  ftun_state_restore_info_t *out, bool candidate)
{
  ftun_state_restore_info_t info;
  uint64_t fingerprint;
  size_t index;
  ftun_status_t status;
  memset(&info, 0, sizeof(info));
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (core == NULL || config == NULL || health_max_age_ms == 0u) {
    return FTUN_E_INVALID;
  }
  if (!ftun_config_base(config)->state_cache) return FTUN_OK;
  if (ftun_config_base(config)->cache_file == NULL || ftun_config_base(config)->cache_file[0] == '\0') {
    return FTUN_E_INVALID;
  }
  if (load_status != FTUN_OK) {
    info.cache_missing = load_status == FTUN_E_EOF;
    info.cache_discarded = load_status != FTUN_E_EOF;
    if (out != NULL) *out = info;
    return FTUN_OK;
  }
  if (snapshot == NULL) return FTUN_E_STATE_CORRUPT;
  status = ftun_group_cache_fingerprint(config, &fingerprint);
  if (status != FTUN_OK) return status;
  if (fingerprint != snapshot->fingerprint) {
    info.fingerprint_mismatch = true;
    info.cache_discarded = true;
    if (out != NULL) *out = info;
    return FTUN_OK;
  }
  for (index = 0u; index < snapshot->record_count; index++) {
    const ftun_runtime_group_record_t *record = &snapshot->records[index];
    bool fresh = snapshot->health_clock_valid && record->health_valid &&
      snapshot->saved_ms <= now_ms &&
      record->observed_ms <= snapshot->saved_ms &&
      record->observed_ms <= now_ms &&
      now_ms - record->observed_ms <= health_max_age_ms;
    status = candidate
      ? ftun_runtime_candidate_group_restore(core, record, fresh)
      : ftun_runtime_group_restore(core, record, fresh);
    if (status == FTUN_E_REJECTED || status == FTUN_E_STALE) {
      info.cache_discarded = true;
      continue;
    }
    if (status != FTUN_OK) {
      if (out != NULL) *out = info;
      return status;
    }
    info.restored_groups++;
    if (fresh && record->kind == FTUN_RUNTIME_GROUP_URL_TEST) {
      info.restored_health++;
    }
  }
  if (out != NULL) *out = info;
  return FTUN_OK;
}

ftun_status_t ftun_state_restore_at(ftun_core_t *core,
                                    const ftun_config_t *config,
                                    uint64_t now_ms,
                                    uint64_t health_max_age_ms,
                                    ftun_state_restore_info_t *out)
{
  return ftun_state_restore_target(core, config, now_ms,
                                   health_max_age_ms, out, false);
}

static ftun_status_t ftun_state_restore_target(
  ftun_core_t *core, const ftun_config_t *config, uint64_t now_ms,
  uint64_t health_max_age_ms, ftun_state_restore_info_t *out,
  bool candidate)
{
  ftun_group_cache_snapshot_t *snapshot = NULL;
  ftun_budget_t *budget = NULL;
  ftun_status_t status;
  if (core == NULL || config == NULL || health_max_age_ms == 0u) {
    return FTUN_E_INVALID;
  }
  if (!ftun_config_base(config)->state_cache) return FTUN_OK;
  if (ftun_config_base(config)->cache_file == NULL || ftun_config_base(config)->cache_file[0] == '\0') {
    return FTUN_E_INVALID;
  }
  status = ftun_core_context_budget(core, &budget);
  if (status == FTUN_OK) status = ftun_group_cache_load_budget(budget, ftun_config_base(config)->cache_file, &snapshot);
  status = ftun_state_apply_snapshot(core, config, snapshot, status, now_ms,
                                     health_max_age_ms, out, candidate);
  (void)ftun_group_cache_destroy(&snapshot);
  return status;
}

ftun_status_t ftun_state_restore_candidate_at(
  ftun_core_t *core, const ftun_config_t *config, uint64_t now_ms,
  uint64_t health_max_age_ms, ftun_state_restore_info_t *out)
{
  return ftun_state_restore_target(core, config, now_ms,
                                   health_max_age_ms, out, true);
}

ftun_status_t ftun_state_restore_candidate_snapshot_at(
  ftun_core_t *core, const ftun_config_t *config,
  const ftun_group_cache_snapshot_t *snapshot, ftun_status_t load_status,
  uint64_t now_ms, uint64_t health_max_age_ms,
  ftun_state_restore_info_t *out)
{
  return ftun_state_apply_snapshot(core, config, snapshot, load_status,
                                   now_ms, health_max_age_ms, out, true);
}
