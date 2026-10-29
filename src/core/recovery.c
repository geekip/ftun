#include "core/recovery.h"
#include <stdlib.h>
#include <string.h>

#define FTUN_RECOVERY_MAX_CAPACITY 65536u
#define FTUN_RECOVERY_DEFAULT_SEED UINT64_C(0x9E3779B97F4A7C15)

typedef struct {
  ftun_recovery_spec_t spec;
  uint64_t generation;
  uint64_t next_ms;
  uint64_t deadline_ms;
  uint64_t available_since_ms;
  uint32_t failures;
  ftun_recovery_state_t state;
  ftun_recovery_fault_t fault;
  bool in_use;
  bool retiring;
  bool cancel_sent;
  bool timed_out;
} ftun_recovery_slot_t;

struct ftun_recovery_scheduler {
  ftun_reservation_t reservation;
  ftun_recovery_policy_t policy;
  ftun_recovery_slot_t *slots;
  size_t capacity;
  size_t cursor;
  uint64_t random;
  bool stopped;
};

static uint64_t ftun_recovery_add(uint64_t left, uint64_t right)
{
  return left > UINT64_MAX - right ? UINT64_MAX : left + right;
}

static uint64_t ftun_recovery_random(ftun_recovery_scheduler_t *scheduler)
{
  uint64_t value = scheduler->random;
  value ^= value << 13;
  value ^= value >> 7;
  value ^= value << 17;
  scheduler->random = value;
  return value;
}

static bool ftun_recovery_slow_fault(ftun_recovery_fault_t fault)
{
  return fault == FTUN_RECOVERY_FAULT_AUTH ||
         fault == FTUN_RECOVERY_FAULT_CONFIG;
}

static ftun_recovery_slot_t *ftun_recovery_find(
  const ftun_recovery_scheduler_t *scheduler, ftun_recovery_id_t id)
{
  ftun_recovery_slot_t *slot;
  if (id.slot >= scheduler->capacity) return NULL;
  slot = &scheduler->slots[id.slot];
  return slot->in_use && slot->generation == id.generation ? slot : NULL;
}

static ftun_recovery_id_t ftun_recovery_id(
  const ftun_recovery_scheduler_t *scheduler, const ftun_recovery_slot_t *slot)
{
  ftun_recovery_id_t id;
  id.slot = (size_t)(slot - scheduler->slots);
  id.generation = slot->generation;
  return id;
}

static void ftun_recovery_free(ftun_recovery_slot_t *slot)
{
  uint64_t generation = slot->generation + 1u;
  memset(slot, 0, sizeof(*slot));
  slot->generation = generation;
}

/* 记录一次失败并算出下次尝试时间；状态由调用方设置。 */
static void ftun_recovery_note_failure(ftun_recovery_scheduler_t *scheduler,
  ftun_recovery_slot_t *slot, ftun_recovery_fault_t fault, uint64_t now_ms)
{
  const ftun_recovery_policy_t *policy = &scheduler->policy;
  uint64_t interval;
  uint64_t spread;
  if (slot->state == FTUN_RECOVERY_AVAILABLE && slot->failures != 0u &&
      now_ms - slot->available_since_ms >= policy->stable_ms) {
    slot->failures = 0u;
  }
  if (slot->failures != UINT32_MAX) slot->failures++;
  slot->fault = fault;
  if (ftun_recovery_slow_fault(fault)) {
    interval = policy->auth_retry_ms;
  } else {
    uint32_t shift = slot->failures - 1u;
    if (shift > 62u || policy->initial_ms > (policy->maximum_ms >> shift)) {
      interval = policy->maximum_ms;
    } else {
      interval = policy->initial_ms << shift;
    }
  }
  spread = interval / 1000u * policy->jitter_permille;
  if (spread != 0u) {
    uint64_t offset = ftun_recovery_random(scheduler) % (2u * spread + 1u);
    interval = interval - spread + offset;
  }
  if (interval == 0u) interval = 1u;
  slot->next_ms = ftun_recovery_add(now_ms, interval);
}

static void ftun_recovery_request_cancel(ftun_recovery_scheduler_t *scheduler,
  ftun_recovery_slot_t *slot)
{
  ftun_recovery_id_t id = ftun_recovery_id(scheduler, slot);
  if (slot->cancel_sent) return;
  slot->cancel_sent = true;
  if (slot->spec.cancel != NULL) slot->spec.cancel(slot->spec.user, id);
}

ftun_status_t ftun_recovery_scheduler_create(ftun_budget_t *budget,
  size_t capacity, const ftun_recovery_policy_t *policy,
  ftun_recovery_scheduler_t **out)
{
  ftun_recovery_scheduler_t *scheduler;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  size_t charge;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (budget == NULL || policy == NULL || out == NULL || capacity == 0u ||
      capacity > FTUN_RECOVERY_MAX_CAPACITY || policy->initial_ms == 0u ||
      policy->maximum_ms < policy->initial_ms || policy->auth_retry_ms == 0u ||
      policy->jitter_permille > 1000u) return FTUN_E_INVALID;
  charge = sizeof(*scheduler) + capacity * sizeof(ftun_recovery_slot_t);
  status = ftun_budget_reserve(budget, charge, &reservation);
  if (status != FTUN_OK) return status;
  scheduler = (ftun_recovery_scheduler_t *)calloc(1u, sizeof(*scheduler));
  if (scheduler != NULL) {
    scheduler->slots = (ftun_recovery_slot_t *)calloc(capacity,
                                                      sizeof(*scheduler->slots));
  }
  if (scheduler == NULL || scheduler->slots == NULL) {
    free(scheduler);
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  scheduler->reservation = reservation;
  scheduler->policy = *policy;
  scheduler->capacity = capacity;
  scheduler->random = policy->seed != 0u ? policy->seed
                                         : FTUN_RECOVERY_DEFAULT_SEED;
  *out = scheduler;
  return FTUN_OK;
}

void ftun_recovery_scheduler_stop(ftun_recovery_scheduler_t *scheduler)
{
  size_t index;
  if (scheduler == NULL || scheduler->stopped) return;
  scheduler->stopped = true;
  for (index = 0u; index < scheduler->capacity; index++) {
    ftun_recovery_slot_t *slot = &scheduler->slots[index];
    if (slot->in_use && slot->state == FTUN_RECOVERY_ATTEMPTING) {
      ftun_recovery_request_cancel(scheduler, slot);
    }
  }
}

ftun_status_t ftun_recovery_scheduler_destroy(
  ftun_recovery_scheduler_t **scheduler)
{
  ftun_recovery_scheduler_t *owned;
  ftun_reservation_t reservation;
  size_t index;
  if (scheduler == NULL) return FTUN_E_INVALID;
  owned = *scheduler;
  if (owned == NULL) return FTUN_OK;
  for (index = 0u; index < owned->capacity; index++) {
    if (owned->slots[index].in_use &&
        owned->slots[index].state == FTUN_RECOVERY_ATTEMPTING) {
      return FTUN_E_AGAIN;
    }
  }
  reservation = owned->reservation;
  free(owned->slots);
  free(owned);
  (void)ftun_reservation_release(&reservation);
  *scheduler = NULL;
  return FTUN_OK;
}

ftun_status_t ftun_recovery_entity_register(
  ftun_recovery_scheduler_t *scheduler, const ftun_recovery_spec_t *spec,
  uint64_t now_ms, ftun_recovery_id_t *out)
{
  size_t index;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (scheduler == NULL || spec == NULL || out == NULL || spec->kind == 0u ||
      spec->attempt == NULL) return FTUN_E_INVALID;
  if (scheduler->stopped) return FTUN_E_CANCELLED;
  for (index = 0u; index < scheduler->capacity; index++) {
    ftun_recovery_slot_t *slot = &scheduler->slots[index];
    if (slot->in_use) continue;
    slot->in_use = true;
    slot->spec = *spec;
    slot->state = FTUN_RECOVERY_AVAILABLE;
    slot->available_since_ms = now_ms;
    *out = ftun_recovery_id(scheduler, slot);
    return FTUN_OK;
  }
  return FTUN_E_LIMIT;
}

ftun_status_t ftun_recovery_entity_unregister(
  ftun_recovery_scheduler_t *scheduler, ftun_recovery_id_t id)
{
  ftun_recovery_slot_t *slot;
  if (scheduler == NULL) return FTUN_E_INVALID;
  slot = ftun_recovery_find(scheduler, id);
  if (slot == NULL || slot->retiring) return FTUN_E_STALE;
  if (slot->state != FTUN_RECOVERY_ATTEMPTING) {
    ftun_recovery_free(slot);
    return FTUN_OK;
  }
  slot->retiring = true;
  ftun_recovery_request_cancel(scheduler, slot);
  return FTUN_OK;
}

ftun_status_t ftun_recovery_report_failure(
  ftun_recovery_scheduler_t *scheduler, ftun_recovery_id_t id,
  uint64_t now_ms, ftun_recovery_fault_t fault)
{
  ftun_recovery_slot_t *slot;
  if (scheduler == NULL || fault < FTUN_RECOVERY_FAULT_NETWORK ||
      fault > FTUN_RECOVERY_FAULT_PROTOCOL) return FTUN_E_INVALID;
  slot = ftun_recovery_find(scheduler, id);
  if (slot == NULL || slot->retiring) return FTUN_E_STALE;
  if (scheduler->stopped) return FTUN_E_CANCELLED;
  if (slot->state != FTUN_RECOVERY_AVAILABLE) return FTUN_OK;
  ftun_recovery_note_failure(scheduler, slot, fault, now_ms);
  slot->state = FTUN_RECOVERY_WAITING;
  return FTUN_OK;
}

ftun_status_t ftun_recovery_report_success(
  ftun_recovery_scheduler_t *scheduler, ftun_recovery_id_t id,
  uint64_t now_ms)
{
  ftun_recovery_slot_t *slot;
  if (scheduler == NULL) return FTUN_E_INVALID;
  slot = ftun_recovery_find(scheduler, id);
  if (slot == NULL || slot->retiring) return FTUN_E_STALE;
  if (slot->state == FTUN_RECOVERY_WAITING) {
    slot->state = FTUN_RECOVERY_AVAILABLE;
    slot->available_since_ms = now_ms;
  }
  return FTUN_OK;
}

ftun_status_t ftun_recovery_attempt_finish(
  ftun_recovery_scheduler_t *scheduler, ftun_recovery_id_t id,
  uint64_t now_ms, ftun_status_t status, ftun_recovery_fault_t fault)
{
  ftun_recovery_slot_t *slot;
  if (scheduler == NULL) return FTUN_E_INVALID;
  slot = ftun_recovery_find(scheduler, id);
  if (slot == NULL || slot->state != FTUN_RECOVERY_ATTEMPTING) return FTUN_E_STALE;
  if (slot->retiring) {
    ftun_recovery_free(slot);
    return FTUN_OK;
  }
  slot->cancel_sent = false;
  if (slot->timed_out) {
    /* 失败与下次时间已在期限到达时记下。 */
    slot->timed_out = false;
    slot->state = FTUN_RECOVERY_WAITING;
    return FTUN_OK;
  }
  if (status == FTUN_OK) {
    slot->state = FTUN_RECOVERY_AVAILABLE;
    slot->available_since_ms = now_ms;
    return FTUN_OK;
  }
  if (fault < FTUN_RECOVERY_FAULT_NETWORK || fault > FTUN_RECOVERY_FAULT_PROTOCOL) {
    fault = FTUN_RECOVERY_FAULT_NETWORK;
  }
  /* 尝试中的失败不属于“稳定可用后再失败”，不触发稳定窗口重置。 */
  ftun_recovery_note_failure(scheduler, slot, fault, now_ms);
  slot->state = FTUN_RECOVERY_WAITING;
  return FTUN_OK;
}

void ftun_recovery_trigger_kind(ftun_recovery_scheduler_t *scheduler,
  uint32_t kind_mask, uint64_t now_ms)
{
  size_t index;
  if (scheduler == NULL || scheduler->stopped) return;
  for (index = 0u; index < scheduler->capacity; index++) {
    ftun_recovery_slot_t *slot = &scheduler->slots[index];
    if (slot->in_use && !slot->retiring && slot->state == FTUN_RECOVERY_WAITING &&
        (slot->spec.kind & kind_mask) != 0u && !ftun_recovery_slow_fault(slot->fault) &&
        slot->next_ms > now_ms) {
      slot->next_ms = now_ms;
    }
  }
}

ftun_status_t ftun_recovery_run(ftun_recovery_scheduler_t *scheduler,
  uint64_t now_ms, size_t quota, size_t *out_work)
{
  size_t work = 0u;
  size_t visited;
  if (out_work != NULL) *out_work = 0u;
  if (scheduler == NULL || out_work == NULL || quota == 0u) return FTUN_E_INVALID;
  if (scheduler->stopped) return FTUN_OK;
  for (visited = 0u; visited < scheduler->capacity && work < quota; visited++) {
    ftun_recovery_slot_t *slot = &scheduler->slots[scheduler->cursor];
    scheduler->cursor = (scheduler->cursor + 1u) % scheduler->capacity;
    if (!slot->in_use || slot->retiring) continue;
    if (slot->state == FTUN_RECOVERY_ATTEMPTING) {
      if (slot->timed_out || now_ms < slot->deadline_ms) continue;
      /* 期限到：记为失败并请求取消，但不开始下一次，直到 attempt_finish。 */
      slot->timed_out = true;
      ftun_recovery_note_failure(scheduler, slot, FTUN_RECOVERY_FAULT_NETWORK, now_ms);
      ftun_recovery_request_cancel(scheduler, slot);
      work++;
    } else if (slot->state == FTUN_RECOVERY_WAITING && now_ms >= slot->next_ms) {
      ftun_recovery_id_t id = ftun_recovery_id(scheduler, slot);
      ftun_status_t status;
      slot->state = FTUN_RECOVERY_ATTEMPTING;
      slot->cancel_sent = false;
      slot->timed_out = false;
      slot->deadline_ms = slot->spec.attempt_timeout_ms == 0u ? UINT64_MAX
        : ftun_recovery_add(now_ms, slot->spec.attempt_timeout_ms);
      work++;
      status = slot->spec.attempt(slot->spec.user, id);
      /* 回调可能已同步结束、注销或复用槽，所以按令牌重新确认。 */
      if (status != FTUN_OK && ftun_recovery_find(scheduler, id) == slot &&
          slot->state == FTUN_RECOVERY_ATTEMPTING) {
        (void)ftun_recovery_attempt_finish(scheduler, id, now_ms, status,
                                           FTUN_RECOVERY_FAULT_NETWORK);
      }
    }
  }
  *out_work = work;
  return FTUN_OK;
}

ftun_status_t ftun_recovery_next_deadline(
  const ftun_recovery_scheduler_t *scheduler, uint64_t *out, bool *present)
{
  size_t index;
  uint64_t best = UINT64_MAX;
  if (present != NULL) *present = false;
  if (scheduler == NULL || out == NULL || present == NULL) return FTUN_E_INVALID;
  *out = 0u;
  if (scheduler->stopped) return FTUN_OK;
  for (index = 0u; index < scheduler->capacity; index++) {
    const ftun_recovery_slot_t *slot = &scheduler->slots[index];
    uint64_t when;
    if (!slot->in_use || slot->retiring) continue;
    if (slot->state == FTUN_RECOVERY_WAITING) when = slot->next_ms;
    else if (slot->state == FTUN_RECOVERY_ATTEMPTING && !slot->timed_out &&
             slot->deadline_ms != UINT64_MAX) when = slot->deadline_ms;
    else continue;
    if (!*present || when < best) { best = when; *present = true; }
  }
  if (*present) *out = best;
  return FTUN_OK;
}

ftun_status_t ftun_recovery_query(const ftun_recovery_scheduler_t *scheduler,
  size_t index, ftun_recovery_info_t *out)
{
  const ftun_recovery_slot_t *slot;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (scheduler == NULL || out == NULL || index >= scheduler->capacity) {
    return FTUN_E_INVALID;
  }
  slot = &scheduler->slots[index];
  if (!slot->in_use) return FTUN_OK;
  out->in_use = true;
  out->retiring = slot->retiring;
  out->id = ftun_recovery_id(scheduler, slot);
  out->kind = slot->spec.kind;
  out->state = slot->state;
  out->fault = slot->fault;
  out->failures = slot->failures;
  out->next_ms = slot->next_ms;
  return FTUN_OK;
}
