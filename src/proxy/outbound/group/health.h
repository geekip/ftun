#ifndef FTUN_PROXY_OUTBOUND_GROUP_HEALTH_H
#define FTUN_PROXY_OUTBOUND_GROUP_HEALTH_H
#include "util/types.h"
#include "proxy/outbound/group/url_test.h"

typedef struct {
  uint32_t failures;
  uint64_t next_due_ms;
  size_t consumers;
} ftun_health_schedule_t;

ftun_status_t ftun_health_schedule(ftun_health_schedule_t *state,
                                   uint64_t now_ms,
                                   uint64_t interval_ms,
                                   uint64_t maximum_backoff_ms,
                                   uint32_t jitter_seed,
                                   bool success);
#endif
