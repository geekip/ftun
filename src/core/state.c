#include "state.h"
#include "config/model.h"
#include "state/group_cache.h"
#include "util/time.h"
#include <string.h>

/* REQ-STATE-001 / TASK-CORE-003 / TEST-CORE-003，目标 0.5.0：
 * ftun_state_restore 按配置身份恢复可丢弃的 Group/Health 状态。 */

static ftun_status_t ftun_state_restore_target(
  ftun_core_t *core, const ftun_config_t *config, uint64_t now_ms,
  uint64_t health_max_age_ms, ftun_state_restore_info_t *out,
  bool candidate);

ftun_status_t ftun_state_restore(ftun_core_t *core, const ftun_config_t *config)
{
  uint64_t now_ms;
  ftun_status_t status = ftun_monotonic_now(&now_ms);
  if (status != FTUN_OK) return status;
  return ftun_state_restore_at(core, config, now_ms, 15u * 60u * 1000u, NULL);
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
  ftun_state_restore_info_t info;
  uint64_t fingerprint;
  size_t index;
  ftun_status_t status;
  memset(&info, 0, sizeof(info));
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (core == NULL || config == NULL || health_max_age_ms == 0u) {
    return FTUN_E_INVALID;
  }
  if (!config->base.state_cache) return FTUN_OK;
  if (config->base.cache_file == NULL || config->base.cache_file[0] == '\0') {
    return FTUN_E_INVALID;
  }
  status = ftun_group_cache_load(config->base.cache_file, &snapshot);
  if (status != FTUN_OK) {
    info.cache_missing = status == FTUN_E_EOF;
    info.cache_discarded = status != FTUN_E_EOF;
    if (out != NULL) *out = info;
    return FTUN_OK;
  }
  status = ftun_group_cache_fingerprint(config, &fingerprint);
  if (status != FTUN_OK) goto done;
  if (fingerprint != snapshot->fingerprint) {
    info.fingerprint_mismatch = true;
    info.cache_discarded = true;
    status = FTUN_OK;
    goto done;
  }
  for (index = 0u; index < snapshot->record_count; index++) {
    ftun_runtime_group_record_t *record = &snapshot->records[index];
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
      status = FTUN_OK;
      continue;
    }
    if (status != FTUN_OK) goto done;
    info.restored_groups++;
    if (fresh && record->kind == FTUN_RUNTIME_GROUP_URL_TEST) {
      info.restored_health++;
    }
  }

done:
  (void)ftun_group_cache_destroy(&snapshot);
  if (out != NULL) *out = info;
  return status;
}

ftun_status_t ftun_state_restore_candidate_at(
  ftun_core_t *core, const ftun_config_t *config, uint64_t now_ms,
  uint64_t health_max_age_ms, ftun_state_restore_info_t *out)
{
  return ftun_state_restore_target(core, config, now_ms,
                                   health_max_age_ms, out, true);
}
