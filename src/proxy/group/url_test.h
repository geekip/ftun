#ifndef FTUN_PROXY_GROUP_URL_TEST_H
#define FTUN_PROXY_GROUP_URL_TEST_H
/* ftun_url_test_choose。 */
#include "internal/contracts.h"

typedef struct {
  uint32_t member_id;
  uint32_t latency_ms;
  uint64_t observed_ms;
  bool success;
  bool tcp_only;
} ftun_health_sample_t;

struct ftun_health_snapshot {
  uint64_t generation;
  const ftun_health_sample_t *samples;
  size_t sample_count;
};

struct ftun_group_spec {
  uint64_t generation;
  uint32_t group_id;
  const uint32_t *members;
  size_t member_count;
  uint32_t default_member_id;
  uint32_t previous_member_id;
  uint64_t previous_since_ms;
  uint64_t now_ms;
  uint64_t sample_max_age_ms;
  uint64_t minimum_hold_ms;
  uint32_t tolerance_ms;
};

/* 只比较同代新鲜成功样本；容差与保持
 * 时间抑制抖动。全失败保留上次合法成员（否则 default）并标 degraded。 */
ftun_status_t ftun_url_test_choose(const ftun_group_spec_t *group, const ftun_health_snapshot_t *health, ftun_group_choice_t *out);
#endif
