#include "core/recovery.h"
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "recovery contract failed: %s (line %d)\n", #x, __LINE__); \
    return 1; \
  } \
} while (0)

typedef struct {
  ftun_recovery_scheduler_t *scheduler;
  int attempts;
  int cancels;
  ftun_recovery_id_t last;
  ftun_status_t start_status;
} entity_t;

static ftun_status_t entity_attempt(void *user, ftun_recovery_id_t id)
{
  entity_t *entity = (entity_t *)user;
  entity->attempts++;
  entity->last = id;
  return entity->start_status;
}

static void entity_cancel(void *user, ftun_recovery_id_t id)
{
  entity_t *entity = (entity_t *)user;
  entity->cancels++;
  entity->last = id;
}

static ftun_recovery_policy_t policy(uint32_t jitter)
{
  ftun_recovery_policy_t value;
  memset(&value, 0, sizeof(value));
  value.initial_ms = 1000u;
  value.maximum_ms = 8000u;
  value.stable_ms = 60000u;
  value.jitter_permille = jitter;
  value.auth_retry_ms = 30000u;
  value.seed = 12345u;
  return value;
}

static ftun_recovery_spec_t spec(entity_t *entity, uint32_t kind, uint64_t timeout)
{
  ftun_recovery_spec_t value;
  memset(&value, 0, sizeof(value));
  value.kind = kind;
  value.attempt_timeout_ms = timeout;
  value.attempt = entity_attempt;
  value.cancel = entity_cancel;
  value.user = entity;
  return value;
}

static int make(ftun_budget_t **budget, ftun_recovery_scheduler_t **scheduler,
  size_t capacity, uint32_t jitter)
{
  ftun_recovery_policy_t p = policy(jitter);
  CHECK(ftun_budget_create(NULL, 1u << 20, 4096u, budget) == FTUN_OK);
  CHECK(ftun_recovery_scheduler_create(*budget, capacity, &p, scheduler) == FTUN_OK);
  return 0;
}

static int finish(ftun_budget_t **budget, ftun_recovery_scheduler_t **scheduler)
{
  ftun_budget_usage_t usage;
  CHECK(ftun_recovery_scheduler_destroy(scheduler) == FTUN_OK && *scheduler == NULL);
  CHECK(ftun_budget_get_usage(*budget, &usage) == FTUN_OK && usage.used == 0u);
  CHECK(ftun_budget_destroy(budget) == FTUN_OK);
  return 0;
}

static int test_backoff_and_stable_window(void)
{
  ftun_budget_t *budget;
  ftun_recovery_scheduler_t *s;
  ftun_recovery_spec_t sp;
  entity_t e = {0};
  ftun_recovery_id_t id;
  ftun_recovery_info_t info;
  uint64_t deadline;
  bool present;
  uint64_t now = 100u;
  static const uint64_t expected[] = {1000u, 2000u, 4000u, 8000u, 8000u};
  size_t i;
  if (make(&budget, &s, 4u, 0u)) return 1;
  e.scheduler = s;
  sp = spec(&e, 1u, 0u);
  CHECK(ftun_recovery_entity_register(s, &sp, now, &id) == FTUN_OK);
  CHECK(ftun_recovery_next_deadline(s, &deadline, &present) == FTUN_OK && !present);
  CHECK(ftun_recovery_report_failure(s, id, now, FTUN_RECOVERY_FAULT_NETWORK) == FTUN_OK);
  for (i = 0u; i < 5u; i++) {
    size_t work;
    CHECK(ftun_recovery_query(s, 0u, &info) == FTUN_OK);
    CHECK(info.state == FTUN_RECOVERY_WAITING && info.failures == i + 1u);
    CHECK(info.next_ms == now + expected[i]);
    CHECK(ftun_recovery_next_deadline(s, &deadline, &present) == FTUN_OK &&
          present && deadline == info.next_ms);
    CHECK(ftun_recovery_run(s, info.next_ms - 1u, 4u, &work) == FTUN_OK && work == 0u);
    now = info.next_ms;
    CHECK(ftun_recovery_run(s, now, 4u, &work) == FTUN_OK && work == 1u);
    CHECK(e.attempts == (int)i + 1);
    CHECK(ftun_recovery_attempt_finish(s, id, now, FTUN_E_IO,
          FTUN_RECOVERY_FAULT_NETWORK) == FTUN_OK);
  }
  /* 成功后未满稳定窗口再失败，退避继续增长。 */
  {
    size_t work;
    CHECK(ftun_recovery_query(s, 0u, &info) == FTUN_OK);
    now = info.next_ms;
    CHECK(ftun_recovery_run(s, now, 4u, &work) == FTUN_OK && work == 1u);
    CHECK(ftun_recovery_attempt_finish(s, id, now, FTUN_OK,
          FTUN_RECOVERY_FAULT_NETWORK) == FTUN_OK);
    CHECK(ftun_recovery_query(s, 0u, &info) == FTUN_OK &&
          info.state == FTUN_RECOVERY_AVAILABLE && info.failures == 6u);
    CHECK(ftun_recovery_report_failure(s, id, now + 59999u,
          FTUN_RECOVERY_FAULT_NETWORK) == FTUN_OK);
    CHECK(ftun_recovery_query(s, 0u, &info) == FTUN_OK &&
          info.failures == 7u && info.next_ms == now + 59999u + 8000u);
    now = info.next_ms;
    CHECK(ftun_recovery_run(s, now, 4u, &work) == FTUN_OK && work == 1u);
    CHECK(ftun_recovery_attempt_finish(s, id, now, FTUN_OK,
          FTUN_RECOVERY_FAULT_NETWORK) == FTUN_OK);
    /* 持续可用满窗口后再失败，从头开始。 */
    CHECK(ftun_recovery_report_failure(s, id, now + 60000u,
          FTUN_RECOVERY_FAULT_NETWORK) == FTUN_OK);
    CHECK(ftun_recovery_query(s, 0u, &info) == FTUN_OK &&
          info.failures == 1u && info.next_ms == now + 60000u + 1000u);
  }
  CHECK(ftun_recovery_entity_unregister(s, id) == FTUN_OK);
  return finish(&budget, &s);
}

static int test_jitter_range_and_slow_faults(void)
{
  ftun_budget_t *budget;
  ftun_recovery_scheduler_t *s;
  ftun_recovery_spec_t sp;
  entity_t e = {0};
  ftun_recovery_id_t id;
  ftun_recovery_info_t info;
  size_t i;
  bool varied = false;
  uint64_t first = 0u;
  if (make(&budget, &s, 2u, 200u)) return 1;
  sp = spec(&e, 1u, 0u);
  CHECK(ftun_recovery_entity_register(s, &sp, 0u, &id) == FTUN_OK);
  for (i = 0u; i < 64u; i++) {
    /* 每个新实体的首次失败，间隔应落在 1000 ± 20%。 */
    CHECK(ftun_recovery_report_failure(s, id, 0u, FTUN_RECOVERY_FAULT_NETWORK) == FTUN_OK);
    CHECK(ftun_recovery_query(s, 0u, &info) == FTUN_OK);
    CHECK(info.next_ms >= 800u && info.next_ms <= 1200u);
    if (i == 0u) first = info.next_ms; else if (info.next_ms != first) varied = true;
    CHECK(ftun_recovery_entity_unregister(s, id) == FTUN_OK);
    CHECK(ftun_recovery_entity_register(s, &sp, 0u, &id) == FTUN_OK);
  }
  CHECK(varied);
  /* AUTH 固定低频，且不被 trigger 提前。 */
  CHECK(ftun_recovery_report_failure(s, id, 1000u, FTUN_RECOVERY_FAULT_AUTH) == FTUN_OK);
  CHECK(ftun_recovery_query(s, 0u, &info) == FTUN_OK);
  CHECK(info.next_ms >= 1000u + 24000u && info.next_ms <= 1000u + 36000u);
  ftun_recovery_trigger_kind(s, 1u, 2000u);
  CHECK(ftun_recovery_query(s, 0u, &info) == FTUN_OK && info.next_ms > 2000u);
  CHECK(ftun_recovery_entity_unregister(s, id) == FTUN_OK);
  return finish(&budget, &s);
}

static int test_trigger_and_quota(void)
{
  ftun_budget_t *budget;
  ftun_recovery_scheduler_t *s;
  entity_t a = {0}, b = {0}, c = {0};
  ftun_recovery_spec_t spa, spb, spc;
  ftun_recovery_id_t ia, ib, ic;
  size_t work;
  if (make(&budget, &s, 4u, 0u)) return 1;
  spa = spec(&a, 1u, 0u); spb = spec(&b, 2u, 0u); spc = spec(&c, 1u, 0u);
  CHECK(ftun_recovery_entity_register(s, &spa, 0u, &ia) == FTUN_OK);
  CHECK(ftun_recovery_entity_register(s, &spb, 0u, &ib) == FTUN_OK);
  CHECK(ftun_recovery_entity_register(s, &spc, 0u, &ic) == FTUN_OK);
  CHECK(ftun_recovery_report_failure(s, ia, 0u, FTUN_RECOVERY_FAULT_NETWORK) == FTUN_OK);
  CHECK(ftun_recovery_report_failure(s, ib, 0u, FTUN_RECOVERY_FAULT_NETWORK) == FTUN_OK);
  CHECK(ftun_recovery_report_failure(s, ic, 0u, FTUN_RECOVERY_FAULT_RESOURCE) == FTUN_OK);
  /* 重复失败报告对 WAITING 实体无影响。 */
  CHECK(ftun_recovery_report_failure(s, ia, 10u, FTUN_RECOVERY_FAULT_NETWORK) == FTUN_OK);
  ftun_recovery_trigger_kind(s, 1u, 50u);
  ftun_recovery_trigger_kind(s, 1u, 50u);
  CHECK(ftun_recovery_run(s, 50u, 1u, &work) == FTUN_OK && work == 1u);
  CHECK(a.attempts + c.attempts == 1 && b.attempts == 0);
  CHECK(ftun_recovery_run(s, 50u, 8u, &work) == FTUN_OK && work == 1u);
  CHECK(a.attempts == 1 && c.attempts == 1 && b.attempts == 0);
  CHECK(ftun_recovery_attempt_finish(s, ia, 51u, FTUN_OK, FTUN_RECOVERY_FAULT_NETWORK) == FTUN_OK);
  CHECK(ftun_recovery_attempt_finish(s, ic, 51u, FTUN_OK, FTUN_RECOVERY_FAULT_NETWORK) == FTUN_OK);
  /* 尝试回调同步失败等同于立即失败，仍在等待。 */
  b.start_status = FTUN_E_IO;
  CHECK(ftun_recovery_run(s, 1000u, 8u, &work) == FTUN_OK && work == 1u && b.attempts == 1);
  {
    ftun_recovery_info_t info;
    CHECK(ftun_recovery_query(s, 1u, &info) == FTUN_OK &&
          info.state == FTUN_RECOVERY_WAITING && info.failures == 2u);
  }
  CHECK(ftun_recovery_entity_unregister(s, ia) == FTUN_OK);
  CHECK(ftun_recovery_entity_unregister(s, ib) == FTUN_OK);
  CHECK(ftun_recovery_entity_unregister(s, ic) == FTUN_OK);
  return finish(&budget, &s);
}

static int test_timeout_and_retire(void)
{
  ftun_budget_t *budget;
  ftun_recovery_scheduler_t *s;
  entity_t e = {0}, r = {0};
  ftun_recovery_spec_t sp, sr;
  ftun_recovery_id_t id, rid, stale;
  ftun_recovery_info_t info;
  uint64_t deadline;
  bool present;
  size_t work;
  if (make(&budget, &s, 2u, 0u)) return 1;
  sp = spec(&e, 1u, 500u);
  CHECK(ftun_recovery_entity_register(s, &sp, 0u, &id) == FTUN_OK);
  CHECK(ftun_recovery_report_failure(s, id, 0u, FTUN_RECOVERY_FAULT_NETWORK) == FTUN_OK);
  CHECK(ftun_recovery_run(s, 1000u, 4u, &work) == FTUN_OK && work == 1u && e.attempts == 1);
  CHECK(ftun_recovery_next_deadline(s, &deadline, &present) == FTUN_OK &&
        present && deadline == 1500u);
  CHECK(ftun_recovery_run(s, 1499u, 4u, &work) == FTUN_OK && work == 0u && e.cancels == 0);
  CHECK(ftun_recovery_run(s, 1500u, 4u, &work) == FTUN_OK && work == 1u && e.cancels == 1);
  CHECK(ftun_recovery_query(s, 0u, &info) == FTUN_OK &&
        info.state == FTUN_RECOVERY_ATTEMPTING && info.failures == 2u);
  /* 取消未结束前，即使到了下次时间也不开始新尝试，也不再重复取消。 */
  CHECK(ftun_recovery_run(s, 100000u, 4u, &work) == FTUN_OK && work == 0u);
  CHECK(e.attempts == 1 && e.cancels == 1);
  CHECK(ftun_recovery_next_deadline(s, &deadline, &present) == FTUN_OK && !present);
  CHECK(ftun_recovery_scheduler_destroy(&s) == FTUN_E_AGAIN && s != NULL);
  /* 超时后的结果无论成败都按失败处理，进入 WAITING。 */
  CHECK(ftun_recovery_attempt_finish(s, id, 1600u, FTUN_OK, FTUN_RECOVERY_FAULT_NETWORK) == FTUN_OK);
  CHECK(ftun_recovery_query(s, 0u, &info) == FTUN_OK &&
        info.state == FTUN_RECOVERY_WAITING && info.failures == 2u);
  CHECK(ftun_recovery_attempt_finish(s, id, 1600u, FTUN_OK, FTUN_RECOVERY_FAULT_NETWORK) == FTUN_E_STALE);
  /* 退休中的槽在 finish 之前不可复用，旧令牌在复用后 STALE。 */
  CHECK(ftun_recovery_run(s, 200000u, 4u, &work) == FTUN_OK && work == 1u && e.attempts == 2);
  CHECK(ftun_recovery_entity_unregister(s, id) == FTUN_OK && e.cancels == 2);
  CHECK(ftun_recovery_entity_unregister(s, id) == FTUN_E_STALE);
  sr = spec(&r, 2u, 0u);
  CHECK(ftun_recovery_entity_register(s, &sr, 0u, &rid) == FTUN_OK && rid.slot != id.slot);
  CHECK(ftun_recovery_entity_register(s, &sr, 0u, &stale) == FTUN_E_LIMIT);
  CHECK(ftun_recovery_attempt_finish(s, id, 200001u, FTUN_OK, FTUN_RECOVERY_FAULT_NETWORK) == FTUN_OK);
  CHECK(ftun_recovery_report_failure(s, id, 0u, FTUN_RECOVERY_FAULT_NETWORK) == FTUN_E_STALE);
  CHECK(ftun_recovery_entity_register(s, &sr, 0u, &stale) == FTUN_OK && stale.slot == id.slot &&
        stale.generation != id.generation);
  CHECK(ftun_recovery_entity_unregister(s, rid) == FTUN_OK);
  CHECK(ftun_recovery_entity_unregister(s, stale) == FTUN_OK);
  return finish(&budget, &s);
}

static int test_stop_and_invalid(void)
{
  ftun_budget_t *budget;
  ftun_recovery_scheduler_t *s;
  entity_t e = {0};
  ftun_recovery_spec_t sp;
  ftun_recovery_id_t id;
  ftun_recovery_policy_t bad = policy(0u);
  ftun_recovery_scheduler_t *none = NULL;
  size_t work;
  if (make(&budget, &s, 2u, 0u)) return 1;
  bad.maximum_ms = 1u;
  CHECK(ftun_recovery_scheduler_create(budget, 2u, &bad, &none) == FTUN_E_INVALID && none == NULL);
  bad = policy(1001u);
  CHECK(ftun_recovery_scheduler_create(budget, 2u, &bad, &none) == FTUN_E_INVALID);
  sp = spec(&e, 0u, 0u);
  CHECK(ftun_recovery_entity_register(s, &sp, 0u, &id) == FTUN_E_INVALID);
  sp = spec(&e, 1u, 0u);
  CHECK(ftun_recovery_entity_register(s, &sp, 0u, &id) == FTUN_OK);
  CHECK(ftun_recovery_report_failure(s, id, 0u, (ftun_recovery_fault_t)0) == FTUN_E_INVALID);
  CHECK(ftun_recovery_report_failure(s, id, 0u, FTUN_RECOVERY_FAULT_NETWORK) == FTUN_OK);
  CHECK(ftun_recovery_run(s, 5000u, 4u, &work) == FTUN_OK && work == 1u);
  ftun_recovery_scheduler_stop(s);
  CHECK(e.cancels == 1);
  ftun_recovery_scheduler_stop(s);
  CHECK(e.cancels == 1);
  CHECK(ftun_recovery_entity_register(s, &sp, 0u, &id) == FTUN_E_CANCELLED);
  ftun_recovery_trigger_kind(s, 1u, 6000u);
  CHECK(ftun_recovery_run(s, 9000u, 4u, &work) == FTUN_OK && work == 0u);
  CHECK(ftun_recovery_scheduler_destroy(&s) == FTUN_E_AGAIN);
  {
    ftun_recovery_info_t info;
    CHECK(ftun_recovery_query(s, 0u, &info) == FTUN_OK && info.in_use);
    CHECK(ftun_recovery_attempt_finish(s, info.id, 9000u, FTUN_E_IO, FTUN_RECOVERY_FAULT_NETWORK) == FTUN_OK);
  }
  return finish(&budget, &s);
}

int main(void)
{
  if (test_backoff_and_stable_window()) return 1;
  if (test_jitter_range_and_slow_faults()) return 1;
  if (test_trigger_and_quota()) return 1;
  if (test_timeout_and_retire()) return 1;
  if (test_stop_and_invalid()) return 1;
  puts("recovery contract passed");
  return 0;
}
