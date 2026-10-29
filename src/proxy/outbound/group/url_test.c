/* ftun_url_test_choose。 */
#include "proxy/outbound/group/url_test.h"
#include <string.h>

static int ftun_group_member(const ftun_group_spec_t *group,
                             uint32_t member_id)
{
  size_t index;
  for (index = 0u; index < group->member_count; index++) {
    if (group->members[index] == member_id) return 1;
  }
  return 0;
}

static const ftun_health_sample_t *ftun_group_sample(
  const ftun_health_snapshot_t *health, uint32_t member_id)
{
  size_t index;
  for (index = 0u; index < health->sample_count; index++) {
    if (health->samples[index].member_id == member_id) {
      return &health->samples[index];
    }
  }
  return NULL;
}

ftun_status_t ftun_url_test_choose(const ftun_group_spec_t *group, const ftun_health_snapshot_t *health, ftun_group_choice_t *out)
{
  const ftun_health_sample_t *best = NULL;
  const ftun_health_sample_t *previous = NULL;
  uint32_t fallback;
  size_t index;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (group == NULL || health == NULL || out == NULL ||
      group->generation == 0u || group->members == NULL ||
      group->member_count == 0u || health->generation == 0u ||
      (health->sample_count != 0u && health->samples == NULL) ||
      !ftun_group_member(group, group->default_member_id)) {
    return FTUN_E_INVALID;
  }
  if (group->generation != health->generation) return FTUN_E_STALE;
  fallback = ftun_group_member(group, group->previous_member_id)
    ? group->previous_member_id : group->default_member_id;
  for (index = 0u; index < group->member_count; index++) {
    const ftun_health_sample_t *sample =
      ftun_group_sample(health, group->members[index]);
    if (sample == NULL || !sample->success ||
        sample->observed_ms > group->now_ms ||
        group->now_ms - sample->observed_ms > group->sample_max_age_ms) {
      continue;
    }
    if (sample->member_id == fallback) previous = sample;
    if (best == NULL || sample->latency_ms < best->latency_ms ||
        (sample->latency_ms == best->latency_ms &&
         sample->member_id < best->member_id)) best = sample;
  }
  out->generation = group->generation;
  if (best == NULL) {
    out->leaf_id = fallback;
    out->degraded = true;
    return FTUN_OK;
  }
  out->leaf_id = best->member_id;
  if (previous != NULL) {
    uint64_t held = group->now_ms >= group->previous_since_ms
      ? group->now_ms - group->previous_since_ms : 0u;
    uint64_t threshold = (uint64_t)best->latency_ms + group->tolerance_ms;
    if (held < group->minimum_hold_ms ||
        (uint64_t)previous->latency_ms <= threshold) {
      out->leaf_id = fallback;
    }
  }
  return FTUN_OK;
}
