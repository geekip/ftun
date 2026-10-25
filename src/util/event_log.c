#include "util/event_log.h"
#include "core/context.h"
#include "util/time.h"

#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FTUN_EVENT_MODULES 7u
#define FTUN_EVENT_BURST 4u
#define FTUN_EVENT_WINDOW_MS UINT64_C(1000)

typedef struct {
  ftun_lifecycle_event_t event;
  uint64_t started_ms;
  uint64_t suppressed;
  unsigned int emitted;
} ftun_event_rate_t;

typedef struct {
  ftun_diagnostic_event_t event;
  uint64_t started_ms;
  uint64_t suppressed;
  unsigned int emitted;
} ftun_diagnostic_rate_t;

typedef struct {
  bool diagnostic;
  union {
    ftun_lifecycle_event_t lifecycle;
    ftun_diagnostic_event_t diagnostic;
  } value;
} ftun_early_event_t;

struct ftun_event_log {
  pthread_mutex_t mutex;
  ftun_reservation_t *reservation;
  ftun_early_event_t early[FTUN_EVENT_LOG_EARLY_CAPACITY];
  ftun_event_rate_t rates[FTUN_LIFECYCLE_COUNT][FTUN_EVENT_MODULES];
  ftun_diagnostic_rate_t diagnostics[FTUN_DIAGNOSTIC_COUNT];
  ftun_event_log_usage_t usage;
  bool silent;
};

static const char *const ftun_event_names[FTUN_LIFECYCLE_COUNT] = {
  "invalid", "starting", "config.read", "config.parsed", "config.validated",
  "config.compiled", "config.failed", "module.selected", "module.disabled",
  "module.preparing", "module.prepared", "module.active", "module.quiesced",
  "module.drained", "module.stopped", "module.failed", "rollback", "running",
  "reload.requested", "reload.committed", "reload.rejected", "stopping",
  "runtime.stopped", "stop.failed", "reload.cancelled"
};
static const char *const ftun_event_modules[FTUN_EVENT_MODULES] = {
  "app", "core", "dns", "tun", "frs", "fakeip", "proxy"
};
static const char *const ftun_event_reasons[FTUN_LIFECYCLE_REASON_COUNT] = {
  "none", "required", "dependency", "optional", "not-selected", "not-built", "not-registered",
  "read", "parse", "paths", "validate", "compile", "log-draining", "admission",
  "run", "quiesce", "drain", "destroy", "reload-prepare", "reload-commit", "reload-abort"
};

static void ftun_event_count(uint64_t *counter, uint64_t amount)
{
  *counter = amount > UINT64_MAX - *counter ? UINT64_MAX : *counter + amount;
}

static size_t ftun_event_module(uint32_t module)
{
  size_t index = 0u;
  while (module != 0u) { module >>= 1u; index++; }
  return index;
}

static bool ftun_event_valid(const ftun_lifecycle_event_t *event)
{
  return event != NULL && event->kind > 0 && event->kind < FTUN_LIFECYCLE_COUNT &&
    event->status >= FTUN_OK && event->status <= FTUN_E_STATE_CORRUPT &&
    event->reason >= 0 && event->reason < FTUN_LIFECYCLE_REASON_COUNT &&
    (event->module & ~(uint32_t)FTUN_BUILD_MODULE_ALL) == 0u &&
    (event->module == 0u || (event->module & (event->module - 1u)) == 0u);
}

static ftun_status_t ftun_event_forward(ftun_event_log_t *log,
  ftun_logger_t *logger, const ftun_lifecycle_event_t *event, uint64_t suppressed)
{
  ftun_diagnostic_t diagnostic;
  char message[256];
  int length;
  ftun_status_t status;
  if (log->silent) {
    ftun_event_count(&log->usage.filtered_without_sink, 1u);
    return FTUN_OK;
  }
  if (logger == NULL) {
    ftun_event_count(&log->usage.unavailable, 1u);
    return FTUN_E_AGAIN;
  }
  length = snprintf(message, sizeof(message),
    "event=%s module=%s generation=%" PRIu64 " reason=%s suppressed=%" PRIu64,
    ftun_event_names[event->kind], ftun_event_modules[ftun_event_module(event->module)],
    event->generation, ftun_event_reasons[event->reason], suppressed);
  if (length < 0 || (size_t)length >= sizeof(message)) return FTUN_E_LIMIT;
  memset(&diagnostic, 0, sizeof(diagnostic));
  diagnostic.error.status = event->status;
  diagnostic.error.stage = (event->kind == FTUN_LIFECYCLE_CONFIG_READ ||
    (event->kind == FTUN_LIFECYCLE_CONFIG_FAILED &&
     event->reason == FTUN_LIFECYCLE_REASON_CONFIG_READ)) ?
    FTUN_STAGE_CONFIG_READ :
    (event->kind >= FTUN_LIFECYCLE_CONFIG_PARSED && event->kind <= FTUN_LIFECYCLE_CONFIG_FAILED ?
      FTUN_STAGE_CONFIG_PREPARE : FTUN_STAGE_CONTROL);
  diagnostic.message = (ftun_string_t){message, (size_t)length};
  status = ftun_logger_write(logger, event->status == FTUN_OK ? FTUN_LOG_INFO : FTUN_LOG_ERROR,
    &diagnostic);
  if (status == FTUN_OK) ftun_event_count(&log->usage.forwarded, 1u);
  else ftun_event_count(&log->usage.unavailable, 1u);
  return status;
}

static ftun_status_t ftun_event_summary(ftun_event_log_t *log,
  ftun_logger_t *logger, ftun_event_rate_t *rate)
{
  ftun_status_t status = FTUN_OK;
  if (rate->suppressed != 0u) {
    status = ftun_event_forward(log, logger, &rate->event, rate->suppressed);
    rate->suppressed = 0u;
  }
  return status;
}

static ftun_status_t ftun_diagnostic_forward(ftun_event_log_t *log,
  ftun_logger_t *logger, const ftun_diagnostic_event_t *event, uint64_t suppressed)
{
  ftun_diagnostic_t diagnostic = {0};
  ftun_status_t status;
  char summary[384];
  if (log->silent) {
    ftun_event_count(&log->usage.filtered_without_sink, 1u);
    return FTUN_OK;
  }
  if (logger == NULL) {
    ftun_event_count(&log->usage.unavailable, 1u);
    return FTUN_E_AGAIN;
  }
  diagnostic.error = event->error;
  if (suppressed != 0u) {
    int length = snprintf(summary, sizeof(summary),
      "diagnostic=%u generation=%" PRIu64 " suppressed=%" PRIu64 " %s",
      (unsigned int)event->kind, event->generation, suppressed, event->message);
    if (length < 0 || (size_t)length >= sizeof(summary)) return FTUN_E_LIMIT;
    diagnostic.message = (ftun_string_t){summary, (size_t)length};
  } else diagnostic.message = (ftun_string_t){event->message, strlen(event->message)};
  status = ftun_logger_write(logger, event->error.status == FTUN_OK ? FTUN_LOG_INFO : FTUN_LOG_ERROR,
    &diagnostic);
  if (status == FTUN_OK) ftun_event_count(&log->usage.forwarded, 1u);
  else ftun_event_count(&log->usage.unavailable, 1u);
  return status;
}

static ftun_status_t ftun_diagnostic_summary(ftun_event_log_t *log,
  ftun_logger_t *logger, ftun_diagnostic_rate_t *rate)
{
  ftun_status_t status = FTUN_OK;
  if (rate->suppressed != 0u) {
    status = ftun_diagnostic_forward(log, logger, &rate->event, rate->suppressed);
    rate->suppressed = 0u;
  }
  return status;
}

static ftun_status_t ftun_event_summaries(ftun_event_log_t *log,
  ftun_logger_t *logger)
{
  ftun_status_t first = FTUN_OK;
  size_t kind, module;
  for (kind = 1u; kind < FTUN_LIFECYCLE_COUNT; kind++) {
    for (module = 0u; module < FTUN_EVENT_MODULES; module++) {
      ftun_status_t status = ftun_event_summary(log, logger, &log->rates[kind][module]);
      if (first == FTUN_OK) first = status;
    }
  }
  for (kind = 1u; kind < FTUN_DIAGNOSTIC_COUNT; kind++) {
    ftun_status_t status = ftun_diagnostic_summary(log, logger, &log->diagnostics[kind]);
    if (first == FTUN_OK) first = status;
  }
  return first;
}

ftun_status_t ftun_event_log_create(ftun_budget_t *budget, ftun_event_log_t **out)
{
  ftun_event_log_t *log;
  ftun_reservation_t *reservation = NULL;
  ftun_budget_resources_t resources = {sizeof(*log), 0u, FTUN_EVENT_LOG_EARLY_CAPACITY};
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (budget == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_budget_reserve_resources(budget, resources, &reservation);
  if (status != FTUN_OK) return status;
  log = calloc(1u, sizeof(*log));
  if (log == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  if (pthread_mutex_init(&log->mutex, NULL) != 0) {
    free(log);
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_IO;
  }
  log->reservation = reservation;
  *out = log;
  return FTUN_OK;
}

ftun_status_t ftun_event_log_record(ftun_event_log_t *log,
  ftun_logger_t *logger, const ftun_lifecycle_event_t *event, uint64_t now_ms)
{
  ftun_status_t status = FTUN_OK;
  ftun_event_rate_t *rate;
  if (log == NULL || !ftun_event_valid(event)) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&log->mutex);
  if (log->usage.closed) { status = FTUN_E_CANCELLED; goto done; }
  ftun_event_count(&log->usage.recorded, 1u);
  log->usage.has_last = true;
  log->usage.last = *event;
  if (event->status != FTUN_OK) {
    log->usage.has_error = true;
    log->usage.last_error = *event;
  }
  if (!log->usage.configured) {
    if (log->usage.buffered == FTUN_EVENT_LOG_EARLY_CAPACITY) {
      ftun_event_count(&log->usage.early_dropped, 1u);
    } else {
      ftun_early_event_t *early = &log->early[log->usage.buffered++];
      early->diagnostic = false;
      early->value.lifecycle = *event;
    }
    goto done;
  }
  rate = &log->rates[event->kind][ftun_event_module(event->module)];
  if (rate->emitted != 0u && (event->status == FTUN_OK ||
      rate->event.status != event->status || rate->event.generation != event->generation ||
      rate->event.reason != event->reason ||
      now_ms < rate->started_ms || now_ms - rate->started_ms >= FTUN_EVENT_WINDOW_MS)) {
    (void)ftun_event_summary(log, logger, rate);
    memset(rate, 0, sizeof(*rate));
  }
  if (event->status != FTUN_OK) {
    if (rate->emitted == 0u) { rate->started_ms = now_ms; rate->event = *event; }
    if (rate->emitted == FTUN_EVENT_BURST) {
      ftun_event_count(&rate->suppressed, 1u);
      ftun_event_count(&log->usage.suppressed, 1u);
      goto done;
    }
    rate->emitted++;
  }
  status = ftun_event_forward(log, logger, event, 0u);
done:
  (void)pthread_mutex_unlock(&log->mutex);
  return status;
}

static bool ftun_diagnostic_valid(const ftun_diagnostic_event_t *event)
{
  return event != NULL && event->kind > 0 && event->kind < FTUN_DIAGNOSTIC_COUNT &&
    event->error.status >= FTUN_OK && event->error.status <= FTUN_E_STATE_CORRUPT &&
    memchr(event->message, '\0', sizeof(event->message)) != NULL;
}

ftun_status_t ftun_event_log_diagnostic(ftun_event_log_t *log,
  ftun_logger_t *logger, const ftun_diagnostic_event_t *event, uint64_t now_ms)
{
  ftun_status_t status = FTUN_OK;
  ftun_diagnostic_rate_t *rate;
  if (log == NULL || !ftun_diagnostic_valid(event)) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&log->mutex);
  if (log->usage.closed) { status = FTUN_E_CANCELLED; goto done; }
  ftun_event_count(&log->usage.diagnostics, 1u);
  log->usage.has_diagnostic = true;
  log->usage.last_diagnostic = *event;
  if (!log->usage.configured) {
    if (log->usage.buffered == FTUN_EVENT_LOG_EARLY_CAPACITY) {
      ftun_event_count(&log->usage.early_dropped, 1u);
    } else {
      ftun_early_event_t *early = &log->early[log->usage.buffered++];
      early->diagnostic = true;
      early->value.diagnostic = *event;
    }
    goto done;
  }
  rate = &log->diagnostics[event->kind];
  if (rate->emitted != 0u && (event->error.status == FTUN_OK ||
      rate->event.error.status != event->error.status ||
      rate->event.error.stage != event->error.stage ||
      rate->event.error.native_code != event->error.native_code ||
      rate->event.generation != event->generation ||
      strcmp(rate->event.message, event->message) != 0 || now_ms < rate->started_ms ||
      now_ms - rate->started_ms >= FTUN_EVENT_WINDOW_MS)) {
    (void)ftun_diagnostic_summary(log, logger, rate);
    memset(rate, 0, sizeof(*rate));
  }
  if (event->error.status != FTUN_OK) {
    if (rate->emitted == 0u) { rate->started_ms = now_ms; rate->event = *event; }
    if (rate->emitted == FTUN_EVENT_BURST) {
      ftun_event_count(&rate->suppressed, 1u);
      ftun_event_count(&log->usage.diagnostic_suppressed, 1u);
      goto done;
    }
    rate->emitted++;
  }
  status = ftun_diagnostic_forward(log, logger, event, 0u);
done:
  (void)pthread_mutex_unlock(&log->mutex);
  return status;
}

ftun_status_t ftun_event_log_publish(ftun_event_log_t *log,
  ftun_logger_t *logger, bool silent)
{
  ftun_status_t first = FTUN_OK;
  size_t index;
  if (log == NULL || (!silent && logger == NULL)) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&log->mutex);
  if (log->usage.closed || log->usage.configured) {
    first = FTUN_E_STALE;
  } else {
    log->usage.configured = true;
    log->silent = silent;
    for (index = 0u; index < log->usage.buffered; index++) {
      ftun_early_event_t *early = &log->early[index];
      ftun_status_t status = early->diagnostic ?
        ftun_diagnostic_forward(log, logger, &early->value.diagnostic, 0u) :
        ftun_event_forward(log, logger, &early->value.lifecycle, 0u);
      if (first == FTUN_OK) first = status;
    }
    log->usage.buffered = 0u;
  }
  (void)pthread_mutex_unlock(&log->mutex);
  return first;
}

ftun_status_t ftun_event_log_reconfigure(ftun_event_log_t *log,
  ftun_logger_t *old_logger, bool silent)
{
  ftun_status_t status;
  if (log == NULL) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&log->mutex);
  if (log->usage.closed || !log->usage.configured) status = FTUN_E_STALE;
  else {
    status = ftun_event_summaries(log, old_logger);
    memset(log->rates, 0, sizeof(log->rates));
    memset(log->diagnostics, 0, sizeof(log->diagnostics));
    log->silent = silent;
  }
  (void)pthread_mutex_unlock(&log->mutex);
  return status;
}

ftun_status_t ftun_event_log_finish(ftun_event_log_t *log, ftun_logger_t *logger)
{
  return ftun_event_log_finish_with(log, logger, NULL);
}

ftun_status_t ftun_event_log_finish_with(ftun_event_log_t *log, ftun_logger_t *logger,
  const ftun_lifecycle_event_t *terminal)
{
  ftun_status_t first = FTUN_OK;
  if (log == NULL || (terminal != NULL && !ftun_event_valid(terminal))) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&log->mutex);
  if (!log->usage.closed) {
    first = ftun_event_summaries(log, logger);
    if (terminal != NULL) {
      ftun_event_count(&log->usage.recorded, 1u);
      log->usage.has_last = true;
      log->usage.last = *terminal;
      if (terminal->status != FTUN_OK) {
        log->usage.has_error = true;
        log->usage.last_error = *terminal;
      }
      if (log->usage.configured) {
        ftun_status_t status = ftun_event_forward(log, logger, terminal, 0u);
        if (first == FTUN_OK) first = status;
      } else ftun_event_count(&log->usage.early_dropped, 1u);
    }
    ftun_event_count(&log->usage.early_dropped, log->usage.buffered);
    log->usage.buffered = 0u;
    log->usage.closed = true;
  }
  (void)pthread_mutex_unlock(&log->mutex);
  return first;
}

ftun_status_t ftun_event_log_get_usage(ftun_event_log_t *log, ftun_event_log_usage_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (log == NULL || out == NULL) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&log->mutex);
  *out = log->usage;
  (void)pthread_mutex_unlock(&log->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_event_log_begin(ftun_event_log_t *log)
{
  if (log == NULL) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&log->mutex);
  if (!log->usage.closed && (log->usage.configured || log->usage.has_last)) {
    (void)pthread_mutex_unlock(&log->mutex);
    return FTUN_E_AGAIN;
  }
  log->usage.buffered = 0u;
  log->usage.configured = false;
  log->usage.closed = false;
  log->usage.has_last = false;
  log->usage.has_error = false;
  memset(&log->usage.last, 0, sizeof(log->usage.last));
  memset(&log->usage.last_error, 0, sizeof(log->usage.last_error));
  memset(log->rates, 0, sizeof(log->rates));
  memset(log->diagnostics, 0, sizeof(log->diagnostics));
  log->usage.has_diagnostic = false;
  memset(&log->usage.last_diagnostic, 0, sizeof(log->usage.last_diagnostic));
  log->silent = false;
  (void)pthread_mutex_unlock(&log->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_event_log_destroy(ftun_event_log_t **log)
{
  ftun_event_log_t *owned;
  ftun_reservation_t *reservation;
  if (log == NULL) return FTUN_E_INVALID;
  owned = *log;
  if (owned == NULL) return FTUN_OK;
  if (pthread_mutex_destroy(&owned->mutex) != 0) return FTUN_E_AGAIN;
  reservation = owned->reservation;
  free(owned);
  *log = NULL;
  return ftun_reservation_release(&reservation);
}

ftun_status_t ftun_lifecycle_emit(ftun_core_t *core,
  const ftun_lifecycle_event_t *event)
{
  ftun_event_log_t *events = NULL;
  ftun_logger_t *logger = NULL;
  uint64_t now = 0u;
  ftun_status_t status;
  if (!ftun_event_valid(event)) return FTUN_E_INVALID;
  status = ftun_monotonic_now(&now);
  if (status != FTUN_OK) return status;
  status = ftun_core_context_events_acquire(core, &events, &logger);
  if (status != FTUN_OK) return status;
  status = ftun_event_log_record(events, logger, event, now);
  (void)ftun_core_context_logger_release(core);
  return status;
}

ftun_status_t ftun_diagnostic_emit(ftun_core_t *core,
  const ftun_diagnostic_event_t *event)
{
  ftun_event_log_t *events = NULL;
  ftun_logger_t *logger = NULL;
  uint64_t now = 0u;
  ftun_status_t status;
  if (!ftun_diagnostic_valid(event)) return FTUN_E_INVALID;
  status = ftun_monotonic_now(&now);
  if (status != FTUN_OK) return status;
  status = ftun_core_context_events_acquire(core, &events, &logger);
  if (status != FTUN_OK) return status;
  status = ftun_event_log_diagnostic(events, logger, event, now);
  (void)ftun_core_context_logger_release(core);
  return status;
}

ftun_status_t ftun_diagnostic_report(ftun_core_t *core, ftun_diagnostic_kind_t kind,
  uint64_t generation, ftun_error_t error, const char *message)
{
  ftun_diagnostic_event_t event = {0};
  size_t length = 0u;
  if (message == NULL) return FTUN_E_INVALID;
  while (length < sizeof(event.message) && message[length] != '\0') length++;
  if (length == sizeof(event.message)) return FTUN_E_LIMIT;
  event.kind = kind;
  event.generation = generation;
  event.error = error;
  memcpy(event.message, message, length);
  return ftun_diagnostic_emit(core, &event);
}
