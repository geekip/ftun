#ifndef FTUN_PROXY_GROUP_HEALTH_H
#define FTUN_PROXY_GROUP_HEALTH_H
/* TASK-GROUP-003 / TEST-GROUP-003：ftun_health_probe，目标 0.4.0。 */
#include "internal/contracts.h"
#include "proxy/group/url_test.h"

typedef struct {
  uint16_t http_status;
  uint32_t latency_ms;
  uint64_t finished_ms;
  uint32_t path_member_id;
  bool tls_verified;
} ftun_probe_result_t;

typedef ftun_status_t (*ftun_probe_perform_fn)(
  void *user, ftun_string_t url, uint32_t member_id,
  uint64_t deadline_ms, ftun_probe_result_t *out);

struct ftun_probe_request {
  uint64_t generation;
  uint32_t member_id;
  ftun_string_t url;
  uint16_t expected_status;
  uint64_t now_ms;
  uint64_t deadline_ms;
  ftun_operation_queue_t *operations;
  ftun_completion_fn completion;
  void *completion_user;
  ftun_probe_perform_fn perform;
  void *perform_user;
  ftun_health_sample_t *sample;
};

typedef struct {
  uint32_t failures;
  uint64_t next_due_ms;
  size_t consumers;
} ftun_health_schedule_t;

/* 成功样本只证明该节点 TCP/HTTP(S) 路径，tcp_only 始终为 true。perform 必须
 * 实际经过 member_id；HTTPS 必须返回 tls_verified。接纳后结果延迟到 operation
 * queue，失败也恰好一次完成。 */
ftun_status_t ftun_health_probe(ftun_core_t *core, const ftun_probe_request_t *request, ftun_operation_t **out);
ftun_status_t ftun_health_schedule(ftun_health_schedule_t *state,
                                   uint64_t now_ms,
                                   uint64_t interval_ms,
                                   uint64_t maximum_backoff_ms,
                                   uint32_t jitter_seed,
                                   bool success);
#endif
