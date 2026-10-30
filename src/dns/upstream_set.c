#include "dns/upstream_set.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct ftun_upstream_set;
typedef struct {
  struct ftun_upstream_set *set;
  ftun_recovery_id_t id;
} ftun_upstream_entity_t;

struct ftun_upstream_set {
  ftun_reservation_t reservation;
  ftun_recovery_scheduler_t *scheduler;
  ftun_upstream_now_fn now;
  void *now_user;
  size_t count;
  ftun_endpoint_t endpoints[FTUN_UPSTREAM_SET_MAX];
  ftun_upstream_entity_t entities[FTUN_UPSTREAM_SET_MAX];
};

/* A0 到期只表示“可以再试一次”，不发起任何查询：同步结束尝试，实体回到
 * AVAILABLE，下一次真实查询自然会选到它；失败再次触发退避。 */
static ftun_status_t ftun_upstream_set_attempt(void *user, ftun_recovery_id_t id)
{
  ftun_upstream_entity_t *entity = (ftun_upstream_entity_t *)user;
  ftun_upstream_set_t *set = entity->set;
  uint64_t now;
  ftun_status_t status = set->now(set->now_user, &now);
  if (status != FTUN_OK) return status;
  return ftun_recovery_attempt_finish(set->scheduler, id, now,
    FTUN_OK, FTUN_RECOVERY_FAULT_NETWORK);
}

ftun_status_t ftun_upstream_set_create(ftun_budget_t *budget,
  ftun_recovery_scheduler_t *scheduler, const ftun_endpoint_t *endpoints,
  size_t count, ftun_upstream_now_fn now, void *now_user,
  ftun_upstream_set_t **out)
{
  ftun_upstream_set_t *set;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_status_t status;
  size_t index;
  if (out != NULL) *out = NULL;
  if (budget == NULL || scheduler == NULL || endpoints == NULL || now == NULL ||
      out == NULL || count == 0u || count > FTUN_UPSTREAM_SET_MAX) {
    return FTUN_E_INVALID;
  }
  status = ftun_budget_reserve(budget, sizeof(*set), &reservation);
  if (status != FTUN_OK) return status;
  set = (ftun_upstream_set_t *)calloc(1u, sizeof(*set));
  if (set == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  set->reservation = reservation;
  set->scheduler = scheduler;
  set->now = now;
  set->now_user = now_user;
  for (index = 0u; index < count; index++) {
    ftun_recovery_spec_t spec;
    set->endpoints[index] = endpoints[index];
    set->entities[index].set = set;
    memset(&spec, 0, sizeof(spec));
    spec.kind = FTUN_UPSTREAM_SET_RECOVERY_KIND;
    spec.attempt = ftun_upstream_set_attempt;
    spec.user = &set->entities[index];
    uint64_t now_ms;
    status = now(now_user, &now_ms);
    if (status == FTUN_OK) status = ftun_recovery_entity_register(scheduler, &spec, now_ms,
      &set->entities[index].id);
    if (status != FTUN_OK) break;
    set->count++;
  }
  if (status != FTUN_OK) {
    ftun_upstream_set_destroy(&set);
    return status;
  }
  *out = set;
  return FTUN_OK;
}

void ftun_upstream_set_destroy(ftun_upstream_set_t **out)
{
  ftun_upstream_set_t *set;
  ftun_reservation_t reservation;
  size_t index;
  set = *out;
  if (set == NULL) return;
  for (index = 0u; index < set->count; index++) {
    ftun_status_t status = ftun_recovery_entity_unregister(set->scheduler, set->entities[index].id);
    assert(status == FTUN_OK);
    (void)status;
  }
  reservation = set->reservation;
  memset(set, 0, sizeof(*set));
  free(set);
  ftun_reservation_release(&reservation);
  *out = NULL;
}

const ftun_endpoint_t *ftun_upstream_set_endpoint(
  const ftun_upstream_set_t *set, size_t index)
{
  return set == NULL || index >= set->count ? NULL : &set->endpoints[index];
}

ftun_status_t ftun_upstream_set_pick(ftun_upstream_set_t *set, size_t after,
  size_t *out_index, bool *out_recovering)
{
  size_t index = after == SIZE_MAX ? 0u : after + 1u;
  if (out_index != NULL) *out_index = 0u;
  if (out_recovering != NULL) *out_recovering = false;
  if (set == NULL || out_index == NULL || out_recovering == NULL) return FTUN_E_INVALID;
  for (; index < set->count; index++) {
    ftun_recovery_info_t info;
    if (ftun_recovery_query(set->scheduler, set->entities[index].id.slot, &info) !=
          FTUN_OK || !info.in_use) continue;
    if (info.state != FTUN_RECOVERY_AVAILABLE) continue;
    *out_index = index;
    *out_recovering = info.failures != 0u;
    return FTUN_OK;
  }
  return FTUN_E_IO;
}

ftun_status_t ftun_upstream_set_report_failure(ftun_upstream_set_t *set, size_t index)
{
  uint64_t now;
  assert(index < set->count);
  ftun_status_t status = set->now(set->now_user, &now);
  if (status != FTUN_OK) return status;
  return ftun_recovery_report_failure(set->scheduler, set->entities[index].id,
    now, FTUN_RECOVERY_FAULT_NETWORK);
}
