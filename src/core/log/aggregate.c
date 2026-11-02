#include "core/log/aggregate.h"
#include "core/limits.h"
#include "core/status.h"
#include "core/context.h"
#include "core/event/loop.h"
#include "platform/clock.h"
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  const ftun_log_event_t *event;
  uint64_t entity, generation, due_ms, window_start_ms, visible_start_ms;
  uint64_t count, total;
  ftun_error_t error;
  ftun_status_label_t label;
  bool visible, pending;
} entry_t;

struct ftun_log_aggregate {
  ftun_reservation_t reservation;
  ftun_core_t *core;
  ftun_event_loop_t *loop;
  ftun_event_source_t *timer;
  ftun_log_aggregate_usage_t usage;
  size_t initialized;
  entry_t overflow[FTUN_LOG_MODULE_COUNT];
  entry_t entries[FTUN_LOG_AGGREGATE_CAPACITY];
};

#define OVERFLOW(module) {module, FTUN_LOG_WARN, "log.aggregate-overflow", "additional failures"}
static const ftun_log_event_t overflow_events[] = {
  OVERFLOW(FTUN_LOG_APP), OVERFLOW(FTUN_LOG_CONFIG), OVERFLOW(FTUN_LOG_CTL),
  OVERFLOW(FTUN_LOG_DNS), OVERFLOW(FTUN_LOG_PROXY), OVERFLOW(FTUN_LOG_FRS),
  OVERFLOW(FTUN_LOG_FAKEIP), OVERFLOW(FTUN_LOG_TUN), OVERFLOW(FTUN_LOG_NET),
  OVERFLOW(FTUN_LOG_LOG)
};
#undef OVERFLOW

static bool matches(const entry_t *entry, const ftun_log_event_t *event, uint64_t entity)
{
  return entry->event != NULL && entry->entity == entity &&
    entry->event->module == event->module && strcmp(entry->event->id, event->id) == 0;
}

/* 保留逻辑故障键，但丢弃不可见周期，不能在切换级别后重放。 */
static void hide(entry_t *entry)
{
  entry->visible = entry->pending = false;
  entry->count = entry->total = 0u;
  entry->due_ms = UINT64_MAX;
}

static ftun_status_t emit(entry_t *entry, ftun_logger_t *logger,
  const ftun_log_record_t *source, bool first, bool recovered, bool overflow,
  uint64_t now_ms)
{
  ftun_log_field_t fields[FTUN_LOG_MAX_FIELDS];
  ftun_log_record_t record = *source;
  ftun_log_event_t event = *source->event;
  char phrase[256], interval[32];
  size_t count = 0u;
  if (!overflow) {
    fields[count++] = (ftun_log_field_t){.key = "entity", .kind = FTUN_LOG_TEXT,
      .value.text = {entry->label.text, strlen(entry->label.text)}};
    fields[count++] = (ftun_log_field_t){.key = "entity_id", .kind = FTUN_LOG_U64, .value.u64 = entry->entity};
    if (entry->label.truncated) fields[count++] = (ftun_log_field_t){
      .key = "truncated", .kind = FTUN_LOG_TEXT, .value.text = {"true", 4u}};
  } else fields[count++] = (ftun_log_field_t){.key = "overflow", .kind = FTUN_LOG_TEXT,
    .value.text = {"true", 4u}};
  if (first) {
    (void)snprintf(phrase, sizeof(phrase), "%s (first)", event.phrase);
    event.phrase = phrase;
  } else {
    fields[count++] = (ftun_log_field_t){.key = "count", .kind = FTUN_LOG_U64,
      .value.u64 = recovered ? entry->total : entry->count};
    if (recovered) fields[count++] = (ftun_log_field_t){.key = "duration_ms", .kind = FTUN_LOG_U64,
      .value.u64 = now_ms - entry->visible_start_ms};
    else {
      uint64_t elapsed = now_ms - entry->window_start_ms;
      int length = elapsed % 1000u == 0u
        ? snprintf(interval, sizeof(interval), "%llus", (unsigned long long)(elapsed / 1000u))
        : snprintf(interval, sizeof(interval), "%llums", (unsigned long long)elapsed);
      fields[count++] = (ftun_log_field_t){.key = "in", .kind = FTUN_LOG_TEXT,
        .value.text = {interval, (size_t)length}};
    }
  }
  if (source->field_count != 0u) {
    memcpy(fields + count, source->fields, source->field_count * sizeof(*fields));
    count += source->field_count;
  }
  record.event = &event;
  record.fields = fields;
  record.field_count = count;
  return ftun_logger_record(logger, &record);
}

ftun_status_t ftun_log_aggregate_create(ftun_budget_t *budget, ftun_log_aggregate_t **out)
{
  ftun_reservation_t reservation = {0};
  if (budget == NULL || out == NULL) return FTUN_E_INVALID;
  *out = NULL;
  ftun_status_t status = ftun_budget_reserve(budget, sizeof(**out), &reservation);
  if (status != FTUN_OK) return status;
  ftun_log_aggregate_t *aggregate = malloc(sizeof(*aggregate));
  if (aggregate == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  /* 固定容量一次准入；只初始化头部和溢出槽，实体项在首次使用时清零。 */
  memset(aggregate, 0, offsetof(ftun_log_aggregate_t, entries));
  aggregate->reservation = reservation;
  *out = aggregate;
  return FTUN_OK;
}

void ftun_log_aggregate_destroy(ftun_log_aggregate_t **aggregate)
{
  if (*aggregate == NULL) return;
  ftun_reservation_t reservation = (*aggregate)->reservation;
  free(*aggregate);
  *aggregate = NULL;
  ftun_reservation_release(&reservation);
}

ftun_status_t ftun_log_aggregate_failure(ftun_log_aggregate_t *aggregate,
  ftun_logger_t *logger, const ftun_log_record_t *record, uint64_t entity,
  ftun_string_t label, uint64_t now_ms)
{
  entry_t *entry = NULL, *empty = NULL;
  size_t index;
  bool overflow = false;
  if (record->field_count > FTUN_LOG_AGGREGATE_DETAIL_FIELDS ||
      record->event->module >= FTUN_LOG_MODULE_COUNT) return FTUN_E_INVALID;
  aggregate->usage.failures++;
  for (index = 0u; index < aggregate->initialized; index++) {
    entry_t *candidate = &aggregate->entries[index];
    if (matches(candidate, record->event, entity)) { entry = candidate; break; }
    if (empty == NULL && candidate->event == NULL) empty = candidate;
  }
  if (entry == NULL) {
    entry = empty;
    if (entry == NULL && aggregate->initialized < FTUN_LOG_AGGREGATE_CAPACITY) {
      entry = &aggregate->entries[aggregate->initialized++];
      memset(entry, 0, sizeof(*entry));
    }
    if (entry == NULL) {
      overflow = true;
      entry = &aggregate->overflow[record->event->module];
      aggregate->usage.overflowed++;
    }
    if (entry->event == NULL) {
      entry->event = overflow ? &overflow_events[record->event->module] : record->event;
      entry->entity = entity;
      entry->due_ms = UINT64_MAX;
      if (!overflow) {
        ftun_status_label_set_span(&entry->label, label.data, label.length);
        aggregate->usage.active++;
      }
    }
  }
  entry->error = record->error;
  entry->generation = record->generation;
  if (!ftun_logger_enabled(logger, entry->event->level)) {
    hide(entry);
    aggregate->usage.filtered++;
    return FTUN_OK;
  }
  if (!entry->visible) {
    entry->visible = true;
    entry->visible_start_ms = entry->window_start_ms = now_ms;
    entry->total = entry->count = 1u;
    entry->due_ms = now_ms + FTUN_LOG_AGGREGATE_WINDOW_MS;
    ftun_log_record_t first = *record;
    first.event = entry->event;
    if (overflow) { first.fields = NULL; first.field_count = 0u; }
    aggregate->usage.first++;
    return emit(entry, logger, &first, true, false, overflow, now_ms);
  }
  entry->total++;
  entry->count++;
  entry->pending = true;
  aggregate->usage.suppressed++;
  if (entry->due_ms == UINT64_MAX) {
    entry->window_start_ms = now_ms;
    entry->due_ms = now_ms + FTUN_LOG_AGGREGATE_WINDOW_MS;
  }
  return FTUN_OK;
}

ftun_status_t ftun_log_aggregate_recovery(ftun_log_aggregate_t *aggregate,
  ftun_logger_t *logger, const ftun_log_event_t *failure, uint64_t entity,
  const ftun_log_record_t *record, uint64_t now_ms)
{
  if (record->field_count > FTUN_LOG_AGGREGATE_DETAIL_FIELDS) return FTUN_E_INVALID;
  for (size_t index = 0u; index < aggregate->initialized; index++) {
    entry_t *entry = &aggregate->entries[index];
    if (!matches(entry, failure, entity)) continue;
    ftun_status_t status = FTUN_OK;
    if (entry->visible && ftun_logger_enabled(logger, failure->level) &&
        ftun_logger_enabled(logger, record->event->level))
      status = emit(entry, logger, record, false, true, false, now_ms);
    memset(entry, 0, sizeof(*entry));
    aggregate->usage.active--;
    aggregate->usage.recovered++;
    return status;
  }
  return FTUN_OK;
}

uint64_t ftun_log_aggregate_deadline(const ftun_log_aggregate_t *aggregate)
{
  uint64_t deadline = UINT64_MAX;
  for (size_t index = 0u; index < aggregate->initialized + FTUN_LOG_MODULE_COUNT; index++) {
    const entry_t *entry = index < aggregate->initialized ? &aggregate->entries[index] :
      &aggregate->overflow[index - aggregate->initialized];
    if (entry->event != NULL && entry->due_ms < deadline) deadline = entry->due_ms;
  }
  return deadline;
}

static ftun_status_t summarize(ftun_log_aggregate_t *aggregate,
  ftun_logger_t *logger, uint64_t now_ms, bool flush)
{
  ftun_status_t result = FTUN_OK;
  for (size_t index = 0u; index < aggregate->initialized + FTUN_LOG_MODULE_COUNT; index++) {
    bool overflow = index >= aggregate->initialized;
    entry_t *entry = overflow ? &aggregate->overflow[index - aggregate->initialized] :
      &aggregate->entries[index];
    if (entry->event == NULL) continue;
    if (!ftun_logger_enabled(logger, entry->event->level)) hide(entry);
    if (flush || now_ms >= entry->due_ms) {
      if (entry->pending) {
        ftun_log_record_t record = {.event = entry->event, .error = entry->error,
          .generation = entry->generation};
        ftun_status_t status = emit(entry, logger, &record, false, false, overflow, now_ms);
        aggregate->usage.summaries++;
        if (result == FTUN_OK) result = status;
      }
      entry->pending = false;
      entry->count = 0u;
      entry->due_ms = UINT64_MAX;
    }
    if (flush) memset(entry, 0, sizeof(*entry));
  }
  if (flush) { aggregate->usage.active = 0u; aggregate->initialized = 0u; }
  return result;
}

ftun_status_t ftun_log_aggregate_retire(ftun_log_aggregate_t *aggregate,
  ftun_logger_t *logger, ftun_log_module_t module, uint64_t entity, uint64_t now_ms)
{
  ftun_status_t result = FTUN_OK;
  for (size_t index = 0u; index < aggregate->initialized; index++) {
    entry_t *entry = &aggregate->entries[index];
    if (entry->event == NULL || entry->event->module != module || entry->entity != entity) continue;
    if (entry->pending && entry->visible && ftun_logger_enabled(logger, entry->event->level)) {
      ftun_log_record_t record = {.event = entry->event, .error = entry->error, .generation = entry->generation};
      ftun_status_t status = emit(entry, logger, &record, false, false, false, now_ms);
      aggregate->usage.summaries++;
      if (result == FTUN_OK) result = status;
    }
    memset(entry, 0, sizeof(*entry));
    aggregate->usage.active--;
  }
  return result;
}

ftun_status_t ftun_log_aggregate_tick(ftun_log_aggregate_t *aggregate,
  ftun_logger_t *logger, uint64_t now_ms)
{
  return summarize(aggregate, logger, now_ms, false);
}

ftun_status_t ftun_log_aggregate_flush(ftun_log_aggregate_t *aggregate,
  ftun_logger_t *logger, uint64_t now_ms)
{
  return summarize(aggregate, logger, now_ms, true);
}

void ftun_log_aggregate_usage(const ftun_log_aggregate_t *aggregate,
  ftun_log_aggregate_usage_t *out)
{
  *out = aggregate->usage;
}

static void scheduling_error(ftun_core_t *core, ftun_status_t status)
{
  ftun_log_aggregate_t *aggregate;
  ftun_logger_t *logger;
  if (status == FTUN_OK) return;
  if (ftun_core_context_aggregate_acquire(core, &aggregate, &logger) == FTUN_OK) {
    aggregate->usage.errors++;
    (void)ftun_core_context_logger_release(core);
  }
}

static ftun_status_t arm(ftun_log_aggregate_t *aggregate);
static void timer_ready(ftun_event_source_t *source, uint32_t events, void *user)
{
  ftun_log_aggregate_t *aggregate = user;
  ftun_log_aggregate_t *borrowed;
  ftun_logger_t *logger;
  uint64_t now_ms;
  (void)source; (void)events;
  ftun_status_t status = ftun_event_source_cancel(&aggregate->timer);
  if (status == FTUN_OK) status = ftun_monotonic_now(&now_ms);
  if (status == FTUN_OK) status = ftun_core_context_aggregate_acquire(aggregate->core, &borrowed, &logger);
  if (status == FTUN_OK) {
    status = ftun_log_aggregate_tick(borrowed, logger, now_ms);
    (void)ftun_core_context_logger_release(aggregate->core);
  }
  if (status == FTUN_OK) status = arm(aggregate);
  scheduling_error(aggregate->core, status);
}

static ftun_status_t arm(ftun_log_aggregate_t *aggregate)
{
  if (aggregate->loop == NULL || aggregate->timer != NULL) return FTUN_OK;
  uint64_t deadline = ftun_log_aggregate_deadline(aggregate);
  if (deadline == UINT64_MAX) return FTUN_OK;
  return ftun_event_timer_start(aggregate->loop, deadline, timer_ready, aggregate, &aggregate->timer);
}

ftun_status_t ftun_log_aggregate_attach(ftun_core_t *core, ftun_event_loop_t *loop)
{
  ftun_log_aggregate_t *aggregate;
  ftun_logger_t *logger;
  ftun_status_t status = ftun_core_context_aggregate_acquire(core, &aggregate, &logger);
  if (status != FTUN_OK) return status == FTUN_E_AGAIN ? FTUN_OK : status;
  if (aggregate->loop != NULL) status = FTUN_E_STALE;
  else { aggregate->core = core; aggregate->loop = loop; }
  (void)ftun_core_context_logger_release(core);
  if (status == FTUN_OK) status = arm(aggregate);
  scheduling_error(core, status);
  return status;
}

ftun_status_t ftun_log_aggregate_detach(ftun_core_t *core)
{
  ftun_log_aggregate_t *aggregate;
  ftun_logger_t *logger;
  ftun_status_t status = ftun_core_context_aggregate_acquire(core, &aggregate, &logger);
  if (status != FTUN_OK) return status == FTUN_E_AGAIN ? FTUN_OK : status;
  (void)ftun_core_context_logger_release(core);
  status = ftun_event_source_cancel(&aggregate->timer);
  if (status == FTUN_OK) { aggregate->loop = NULL; aggregate->core = NULL; }
  scheduling_error(core, status);
  return status;
}

ftun_status_t ftun_log_failure(ftun_core_t *core, const ftun_log_record_t *record,
  uint64_t entity, ftun_string_t label, uint64_t now_ms)
{
  ftun_log_aggregate_t *aggregate;
  ftun_logger_t *logger;
  ftun_status_t status = ftun_core_context_aggregate_acquire(core, &aggregate, &logger);
  if (status != FTUN_OK) return status;
  status = ftun_log_aggregate_failure(aggregate, logger, record, entity, label, now_ms);
  (void)ftun_core_context_logger_release(core);
  if (status == FTUN_OK) status = arm(aggregate);
  scheduling_error(core, status);
  return status;
}

ftun_status_t ftun_log_recovery(ftun_core_t *core, const ftun_log_event_t *failure,
  uint64_t entity, const ftun_log_record_t *record, uint64_t now_ms)
{
  ftun_log_aggregate_t *aggregate;
  ftun_logger_t *logger;
  ftun_status_t status = ftun_core_context_aggregate_acquire(core, &aggregate, &logger);
  if (status != FTUN_OK) return status;
  status = ftun_log_aggregate_recovery(aggregate, logger, failure, entity, record, now_ms);
  (void)ftun_core_context_logger_release(core);
  return status;
}

ftun_status_t ftun_log_aggregate_query(ftun_core_t *core, ftun_log_aggregate_usage_t *out)
{
  ftun_log_aggregate_t *aggregate;
  ftun_logger_t *logger;
  memset(out, 0, sizeof(*out));
  ftun_status_t status = ftun_core_context_aggregate_acquire(core, &aggregate, &logger);
  if (status != FTUN_OK) return status;
  ftun_log_aggregate_usage(aggregate, out);
  (void)ftun_core_context_logger_release(core);
  return FTUN_OK;
}

ftun_status_t ftun_log_retire(ftun_core_t *core, ftun_log_module_t module,
  uint64_t entity, uint64_t now_ms)
{
  ftun_log_aggregate_t *aggregate;
  ftun_logger_t *logger;
  ftun_status_t status = ftun_core_context_aggregate_acquire(core, &aggregate, &logger);
  if (status != FTUN_OK) return status;
  status = ftun_log_aggregate_retire(aggregate, logger, module, entity, now_ms);
  (void)ftun_core_context_logger_release(core);
  if (ftun_log_aggregate_deadline(aggregate) == UINT64_MAX) {
    ftun_status_t cancelled = ftun_event_source_cancel(&aggregate->timer);
    if (status == FTUN_OK) status = cancelled;
  }
  scheduling_error(core, status);
  return status;
}
