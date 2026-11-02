#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "core/log/log.h"
#include "core/context.h"
#include "core/io/file.h"
#include "platform/thread.h"
#include "platform/file.h"
#include "platform/clock.h"
#include "platform/process.h"

#include <inttypes.h>
#include "platform/atomic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * ftun_log_emit 进入有界异步日志并保留丢弃/错误计数。 */

#define FTUN_LOG_DEFAULT_QUEUE 64u
#define FTUN_LOG_DEFAULT_LINE 512u
#define FTUN_LOG_MAX_QUEUE 4096u
#define FTUN_LOG_MAX_LINE 4096u
#define FTUN_LOG_MAX_FIELD 4096u

/* 进程级标识：序号和关联 ID 在一次启动内单调递增，boot 在进程内固定。 */
static ftun_atomic_u64_t ftun_log_sequence;
static ftun_atomic_u64_t ftun_log_boot;
static ftun_atomic_u64_t ftun_log_correlation;

uint64_t ftun_log_boot_id(void)
{
  uint64_t value = ftun_atomic_load(&ftun_log_boot);
  if (value == 0u) {
    uint64_t fresh = ftun_process_boot_token();
    if (ftun_atomic_compare_exchange_strong(&ftun_log_boot, &value, fresh)) value = fresh;
  }
  return value;
}

uint64_t ftun_correlation_next(void)
{
  return ftun_atomic_fetch_add(&ftun_log_correlation, 1u) + 1u;
}

uint64_t ftun_log_last_sequence(void)
{
  return ftun_atomic_load_explicit(&ftun_log_sequence, FTUN_MEMORY_RELAXED);
}

static int ftun_log_stamp(char *out, size_t capacity)
{
  ftun_local_time_t now;
  int offset;
  if (ftun_wallclock_local(&now) != FTUN_OK) return -1;
  offset = abs(now.offset_minutes);
  return snprintf(out, capacity, "[%04d-%02d-%02d %02d:%02d:%02d.%03u %c%02d%02d]",
    now.calendar.year, now.calendar.month, now.calendar.day, now.calendar.hour,
    now.calendar.minute, now.calendar.second, now.calendar.millisecond,
    now.offset_minutes < 0 ? '-' : '+', offset / 60, offset % 60);
}

struct ftun_log_ledger {
  ftun_mutex_t mutex;
  ftun_reservation_t reservation;
  ftun_budget_t *budget;
  ftun_log_totals_t usage;
  ftun_file_lock_pool_t *file_locks;
};

/* 文件 sink：只被写入线程访问（计数用原子量，供用量查询读取）。 */
typedef struct {
  ftun_file_handle_t handle;
  ftun_file_lock_t *lock;
  ftun_log_ledger_t *ledger;
  char *path;
  uint64_t max_size;
  size_t max_files;
  uint64_t size;
  ftun_atomic_u64_t rotations;
  ftun_atomic_u64_t reopens;
  ftun_atomic_u64_t rotate_errors;
  ftun_status_t rotation_error;
  int write_native_error;
  bool rotation_recovered;
} ftun_log_file_t;

struct ftun_logger {
  ftun_mutex_t mutex;
  ftun_condition_t available;
  ftun_condition_t drained;
  ftun_thread_t thread;
  char *lines;
  size_t *lengths;
  size_t capacity;
  size_t line_capacity;
  size_t head;
  size_t tail;
  size_t count;
  size_t writing;
  uint64_t emitted;
  uint64_t filtered;
  uint64_t dropped;
  uint64_t io_errors;
  uint64_t redacted;
  uint64_t oversized;
  uint64_t truncated;
  ftun_atomic_size_t level;
  bool stderr_output, journal, color;
  ftun_log_writer_fn writer;
  void *writer_user;
  ftun_log_file_t file;
  ftun_atomic_bool_t reopen_requested;
  int accepting;
  int stopping;
  int exited;
  int joined;
  ftun_log_ledger_t *ledger;
  ftun_reservation_t reservation;
  bool stamp;
};

static const char *const ftun_log_names[] = {
  "silent", "error", "warn", "info", "debug", "trace"
};

static void ftun_log_counter_increment(uint64_t *value)
{
  if (*value != UINT64_MAX) (*value)++;
}

ftun_status_t ftun_log_ledger_create(ftun_budget_t *budget, ftun_log_ledger_t **out)
{
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_log_ledger_t *ledger;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (budget == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_budget_reserve(budget, sizeof(*ledger), &reservation);
  if (status != FTUN_OK) return status;
  ledger = calloc(1u, sizeof(*ledger));
  if (ledger == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  if (ftun_mutex_init(&ledger->mutex) != FTUN_OK) {
    free(ledger);
    ftun_reservation_release(&reservation);
    return FTUN_E_IO;
  }
  ledger->reservation = reservation;
  ledger->budget = budget;
  status = ftun_file_lock_pool_create(budget, &ledger->file_locks);
  if (status != FTUN_OK) {
    ftun_mutex_destroy(&ledger->mutex);
    free(ledger);
    ftun_reservation_release(&reservation);
    return status;
  }
  *out = ledger;
  return FTUN_OK;
}

ftun_status_t ftun_log_ledger_get_usage(ftun_log_ledger_t *ledger, ftun_log_totals_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (ledger == NULL || out == NULL) return FTUN_E_INVALID;
  ftun_mutex_lock(&ledger->mutex);
  *out = ledger->usage;
  ftun_mutex_unlock(&ledger->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_log_ledger_destroy(ftun_log_ledger_t **ledger)
{
  ftun_log_ledger_t *owned;
  ftun_reservation_t reservation;
  ftun_status_t status;
  if (ledger == NULL) return FTUN_E_INVALID;
  owned = *ledger;
  if (owned == NULL) return FTUN_OK;
  ftun_mutex_lock(&owned->mutex);
  if (owned->usage.instances != 0u) {
    ftun_mutex_unlock(&owned->mutex);
    return FTUN_E_AGAIN;
  }
  ftun_mutex_unlock(&owned->mutex);
  status = ftun_file_lock_pool_destroy(&owned->file_locks);
  if (status != FTUN_OK) return status;
  ftun_mutex_destroy(&owned->mutex);
  reservation = owned->reservation;
  free(owned);
  *ledger = NULL;
  ftun_reservation_release(&reservation);
  return FTUN_OK;
}

typedef enum {
  FTUN_LOG_LEDGER_FILTER, FTUN_LOG_LEDGER_DROP, FTUN_LOG_LEDGER_REJECT,
  FTUN_LOG_LEDGER_ACCEPT, FTUN_LOG_LEDGER_WRITTEN, FTUN_LOG_LEDGER_FAILED
} ftun_log_ledger_action_t;

/* 锁序只允许 logger→ledger；查询 ledger 不回访 logger，不执行回调。 */
static void ftun_log_ledger_record(ftun_logger_t *logger,
  ftun_log_ledger_action_t action, bool redacted, bool oversized, bool truncated)
{
  ftun_log_ledger_t *ledger = logger->ledger;
  if (ledger == NULL) return;
  ftun_mutex_lock(&ledger->mutex);
  switch (action) {
    case FTUN_LOG_LEDGER_FILTER: ftun_log_counter_increment(&ledger->usage.filtered); break;
    case FTUN_LOG_LEDGER_DROP: ftun_log_counter_increment(&ledger->usage.dropped); break;
    case FTUN_LOG_LEDGER_REJECT: ftun_log_counter_increment(&ledger->usage.rejected); break;
    case FTUN_LOG_LEDGER_ACCEPT:
      ledger->usage.queued++;
      ftun_log_counter_increment(&ledger->usage.emitted);
      if (redacted) ftun_log_counter_increment(&ledger->usage.redacted);
      if (oversized) ftun_log_counter_increment(&ledger->usage.oversized);
      if (truncated) ftun_log_counter_increment(&ledger->usage.truncated);
      break;
    case FTUN_LOG_LEDGER_WRITTEN:
    case FTUN_LOG_LEDGER_FAILED:
      ledger->usage.queued--;
      if (action == FTUN_LOG_LEDGER_WRITTEN) ftun_log_counter_increment(&ledger->usage.written);
      else ftun_log_counter_increment(&ledger->usage.io_errors);
      break;
  }
  ftun_mutex_unlock(&ledger->mutex);
}

static ftun_status_t ftun_log_ledger_attach(ftun_logger_t *logger, ftun_log_ledger_t *ledger)
{
  if (ledger == NULL) return FTUN_OK;
  ftun_mutex_lock(&ledger->mutex);
  if (ledger->usage.instances == SIZE_MAX || logger->capacity > SIZE_MAX - ledger->usage.capacity) {
    ftun_mutex_unlock(&ledger->mutex);
    return FTUN_E_LIMIT;
  }
  ledger->usage.instances++;
  ledger->usage.capacity += logger->capacity;
  logger->ledger = ledger;
  logger->file.ledger = ledger;
  ftun_mutex_unlock(&ledger->mutex);
  return FTUN_OK;
}

static void ftun_log_ledger_detach(ftun_logger_t *logger, bool created, bool close_failed)
{
  ftun_log_ledger_t *ledger = logger->ledger;
  if (ledger == NULL) return;
  ftun_mutex_lock(&ledger->mutex);
  ledger->usage.instances--;
  ledger->usage.capacity -= logger->capacity;
  if (created) ftun_log_counter_increment(&ledger->usage.destroyed);
  if (close_failed) ftun_log_counter_increment(&ledger->usage.close_errors);
  ftun_mutex_unlock(&ledger->mutex);
}

ftun_status_t ftun_log_level_parse(const char *name, ftun_log_level_t *out)
{
  size_t index;
  if (out != NULL) *out = FTUN_LOG_SILENT;
  if (name == NULL || out == NULL) return FTUN_E_INVALID;
  for (index = 0u; index < sizeof(ftun_log_names) / sizeof(ftun_log_names[0]);
       index++) {
    if (strcmp(name, ftun_log_names[index]) == 0) {
      *out = (ftun_log_level_t)index;
      return FTUN_OK;
    }
  }
  return FTUN_E_INVALID;
}

#define FTUN_LOG_PATH_MAX 4096u

static ftun_status_t ftun_log_file_open(ftun_log_file_t *file, bool truncate)
{
  return ftun_platform_file_open_append(file->path, truncate, &file->handle, &file->size);
}

typedef enum { FTUN_LOG_FILE_ROTATED, FTUN_LOG_FILE_REOPENED, FTUN_LOG_FILE_FAILED } ftun_log_file_action_t;

static void ftun_log_file_count(ftun_log_file_t *file, ftun_log_file_action_t action)
{
  ftun_atomic_u64_t *counter = action == FTUN_LOG_FILE_ROTATED ? &file->rotations :
    action == FTUN_LOG_FILE_REOPENED ? &file->reopens : &file->rotate_errors;
  ftun_atomic_fetch_add(counter, 1u);
  if (file->ledger != NULL) {
    uint64_t *total;
    ftun_mutex_lock(&file->ledger->mutex);
    total = action == FTUN_LOG_FILE_ROTATED ? &file->ledger->usage.rotations :
      action == FTUN_LOG_FILE_REOPENED ? &file->ledger->usage.reopens : &file->ledger->usage.rotate_errors;
    ftun_log_counter_increment(total);
    ftun_mutex_unlock(&file->ledger->mutex);
  }
}

/* 候选FD打开成功才消费旧FD；峰值两个FD已在logger创建前准入。 */
static ftun_status_t ftun_log_file_replace(ftun_log_file_t *file, bool truncate)
{
  ftun_file_handle_t next = FTUN_FILE_INVALID;
  uint64_t size;
  ftun_status_t status = ftun_platform_file_open_append(file->path, truncate, &next, &size);
  if (status != FTUN_OK) return status;
  status = ftun_platform_file_close(&file->handle);
  file->handle = next;
  file->size = size;
  return status;
}

/* 改名或候选打开失败仍写原FD；已改名的旧文件不因失败被截断或丢弃。 */
static void ftun_log_file_rotate(ftun_log_file_t *file)
{
  char from[FTUN_LOG_PATH_MAX + 16u], to[FTUN_LOG_PATH_MAX + 16u];
  size_t index;
  ftun_status_t status = FTUN_OK;
  for (index = file->max_files; index > 1u && status == FTUN_OK; index--) {
    if (index == 2u) (void)snprintf(from, sizeof(from), "%s", file->path);
    else (void)snprintf(from, sizeof(from), "%s.%zu", file->path, index - 2u);
    (void)snprintf(to, sizeof(to), "%s.%zu", file->path, index - 1u);
    status = ftun_platform_file_rename_if_exists(from, to);
  }
  if (status == FTUN_OK) status = ftun_log_file_replace(file, file->max_files <= 1u);
  if (status != FTUN_OK) {
    file->rotation_error = status;
    file->rotation_recovered = false;
    ftun_log_file_count(file, FTUN_LOG_FILE_FAILED);
  }
  else {
    file->rotation_recovered = true;
    ftun_log_file_count(file, FTUN_LOG_FILE_ROTATED);
  }
}

static void ftun_log_file_reopen(ftun_log_file_t *file)
{
  ftun_status_t status = ftun_log_file_replace(file, false);
  if (status != FTUN_OK) {
    file->rotation_error = status;
    file->rotation_recovered = false;
    ftun_log_file_count(file, FTUN_LOG_FILE_FAILED);
  }
  else {
    file->rotation_recovered = true;
    ftun_log_file_count(file, FTUN_LOG_FILE_REOPENED);
  }
}

static ftun_status_t ftun_logger_file_write(void *user, ftun_bytes_t line)
{
  ftun_log_file_t *file = (ftun_log_file_t *)user;
  size_t written;
  ftun_status_t status;
  if (file->max_size != 0u && file->size != 0u &&
      file->size + line.length > file->max_size) {
    ftun_log_file_rotate(file);
  }
  ftun_error_t error = ftun_platform_file_write_error(&file->handle, line, &written);
  status = error.status;
  file->write_native_error = error.native_code;
  file->size += written;
  return status == FTUN_OK ? FTUN_OK : FTUN_E_IO;
}

static ftun_status_t ftun_logger_stderr_write(ftun_logger_t *logger, ftun_bytes_t line)
{
  ftun_file_handle_t error = {ftun_file_standard_error()};
  size_t written;
  /* 排队文本保留文件时间；journald只在stderr副本中去掉第一个时间括号。 */
  if (logger->journal && logger->stamp && line.length != 0u && line.data[0] == '[') {
    const uint8_t *end = (const uint8_t *)memchr(line.data, ']', line.length);
    if (end != NULL) {
      size_t skipped = (size_t)(end - line.data) + 1u;
      line.data += skipped;
      line.length -= skipped;
    }
  }
  if (logger->color) {
    char colored[FTUN_LOG_MAX_LINE + 32u];
    const uint8_t *cursor = line.data;
    const uint8_t *end = line.data + line.length;
    const char *color = "\033[90m";
    size_t prefix, used;
    /* 时间可选，模块必有；只给级别文字着色，括号与字段保持普通文本。 */
    if (logger->stamp && !logger->journal) {
      cursor = (const uint8_t *)memchr(cursor, ']', (size_t)(end - cursor));
      if (cursor != NULL) cursor++;
    }
    if (cursor != NULL) cursor = (const uint8_t *)memchr(cursor, ']', (size_t)(end - cursor));
    if (cursor != NULL && (size_t)(end - cursor) >= 8u) {
      cursor += 2u;
      if (memcmp(cursor, "ERROR", 5u) == 0) color = "\033[31m";
      else if (memcmp(cursor, "WARN ", 5u) == 0) color = "\033[33m";
      else if (memcmp(cursor, "INFO ", 5u) == 0) color = "\033[32m";
      else if (memcmp(cursor, "DEBUG", 5u) == 0) color = "\033[36m";
      prefix = (size_t)(cursor - line.data);
      memcpy(colored, line.data, prefix);
      used = prefix;
      memcpy(colored + used, color, 5u); used += 5u;
      memcpy(colored + used, cursor, 5u); used += 5u;
      memcpy(colored + used, "\033[0m", 4u); used += 4u;
      memcpy(colored + used, cursor + 5u, (size_t)(end - cursor) - 5u);
      used += (size_t)(end - cursor) - 5u;
      return ftun_platform_file_write(&error, (ftun_bytes_t){(const uint8_t *)colored, used}, &written);
    }
  }
  return ftun_platform_file_write(&error, line, &written);
}

static ftun_status_t ftun_logger_output_write(void *user, ftun_bytes_t line)
{
  ftun_logger_t *logger = (ftun_logger_t *)user;
  ftun_status_t result = FTUN_OK;
  if (logger->file.path != NULL) result = ftun_logger_file_write(&logger->file, line);
  if (logger->stderr_output) {
    ftun_status_t status = ftun_logger_stderr_write(logger, line);
    if (result == FTUN_OK) result = status;
  }
  return result;
}

typedef struct {
  uint64_t observed, total, pending, start_ms, due_ms;
  bool active;
  ftun_status_t error;
  int native_code;
} ftun_log_notice_t;

/* writer拥有三个固定故障类别；诊断不递归入队，不借Core或业务聚合表。 */
static void ftun_logger_notice(ftun_logger_t *logger, ftun_log_notice_t *notice,
  uint64_t observed, const char *phrase, ftun_log_level_t level, ftun_status_t error, int native_code, bool recovered, bool stopping)
{
  char stamp[64] = "", message[256], native[32] = "";
  uint64_t now;
  uint64_t added = observed - notice->observed;
  const char *suffix = "";
  int length;
  if (added == 0u && !notice->active) return;
  if (ftun_monotonic_now(&now) != FTUN_OK) return;
  notice->observed = observed;
  if (added != 0u) { notice->error = error; notice->native_code = native_code; }
  notice->total += added;
  notice->pending += added;
  if (!notice->active) {
    notice->active = true;
    notice->start_ms = now;
    notice->due_ms = now + UINT64_C(60000);
    suffix = " (first)";
  } else if (recovered) suffix = " recovered";
  else if (notice->pending == 0u || (!stopping && now < notice->due_ms)) return;
  uint64_t count = recovered ? notice->total : notice->pending;
  notice->pending = 0u;
  notice->due_ms = now + UINT64_C(60000);
  if (recovered) { notice->active = false; notice->total = 0u; }
  if (recovered) level = FTUN_LOG_INFO;
  if (!ftun_logger_enabled(logger, level)) return;
  if (logger->stamp && !logger->journal && ftun_log_stamp(stamp, sizeof(stamp)) < 0) return;
  if (notice->native_code != 0) (void)snprintf(native, sizeof(native), " native=%d", notice->native_code);
  length = snprintf(message, sizeof(message), "%s[log   ][%s] %s%s: count=%llu duration_ms=%llu err=%s%s\n",
    stamp, level == FTUN_LOG_ERROR ? "ERROR" : level == FTUN_LOG_INFO ? "INFO " : "WARN ", phrase, suffix,
    (unsigned long long)count, (unsigned long long)(now - notice->start_ms), ftun_status_name(notice->error), native);
  (void)ftun_platform_file_write_ready(ftun_file_standard_error(),
    (ftun_bytes_t){(const uint8_t *)message, (size_t)length});
}

static void *ftun_logger_thread(void *argument)
{
  ftun_logger_t *logger = (ftun_logger_t *)argument;
  ftun_log_notice_t notices[3] = {{0}};
  ftun_status_t signal_status = ftun_thread_block_sigpipe();
  for (;;) {
    size_t slot;
    size_t length;
    ftun_status_t status;
    ftun_mutex_lock(&logger->mutex);
    while (logger->count == 0u && !logger->stopping &&
           !ftun_atomic_load(&logger->reopen_requested)) {
      ftun_condition_wait(&logger->available, &logger->mutex);
    }
    if (ftun_atomic_exchange(&logger->reopen_requested, false) &&
        logger->file.path != NULL) {
      ftun_mutex_unlock(&logger->mutex);
      ftun_log_file_reopen(&logger->file);
      ftun_logger_notice(logger, &notices[1], ftun_atomic_load(&logger->file.rotate_errors),
        "rotate failed", FTUN_LOG_WARN, logger->file.rotation_error, 0, logger->file.rotation_recovered, false);
      continue;
    }
    if (logger->count == 0u && logger->stopping) {
      ftun_mutex_unlock(&logger->mutex);
      ftun_logger_notice(logger, &notices[0], logger->dropped, "records dropped", FTUN_LOG_WARN, FTUN_E_LIMIT, 0, true, true);
      ftun_logger_notice(logger, &notices[2], logger->io_errors, "write failed", FTUN_LOG_ERROR, FTUN_E_IO, logger->file.write_native_error, false, true);
      ftun_logger_notice(logger, &notices[1], ftun_atomic_load(&logger->file.rotate_errors), "rotate failed", FTUN_LOG_WARN, logger->file.rotation_error, 0, logger->file.rotation_recovered, true);
      ftun_mutex_lock(&logger->mutex);
      logger->exited = 1;
      ftun_condition_broadcast(&logger->drained);
      ftun_mutex_unlock(&logger->mutex);
      return NULL;
    }
    slot = logger->head;
    length = logger->lengths[slot];
    logger->writing = 1u;
    ftun_mutex_unlock(&logger->mutex);
    status = signal_status == FTUN_OK ? logger->writer(logger->writer_user,
      (ftun_bytes_t){(const uint8_t *)(logger->lines + slot * logger->line_capacity),
                     length}) : FTUN_E_IO;
    ftun_mutex_lock(&logger->mutex);
    uint64_t dropped = logger->dropped, failed = logger->io_errors;
    if (status != FTUN_OK) ftun_log_counter_increment(&failed);
    bool drained = logger->count == 1u;
    ftun_mutex_unlock(&logger->mutex);
    ftun_logger_notice(logger, &notices[0], dropped, "records dropped", FTUN_LOG_WARN, FTUN_E_LIMIT, 0, drained, false);
    if (logger->file.path != NULL) {
      ftun_logger_notice(logger, &notices[1], ftun_atomic_load(&logger->file.rotate_errors), "rotate failed", FTUN_LOG_WARN, logger->file.rotation_error, 0, logger->file.rotation_recovered, false);
      ftun_logger_notice(logger, &notices[2], failed, "write failed", FTUN_LOG_ERROR, FTUN_E_IO, logger->file.write_native_error, status == FTUN_OK, false);
    }
    ftun_mutex_lock(&logger->mutex);
    if (status != FTUN_OK) ftun_log_counter_increment(&logger->io_errors);
    ftun_log_ledger_record(logger, status == FTUN_OK ? FTUN_LOG_LEDGER_WRITTEN :
      FTUN_LOG_LEDGER_FAILED, false, false, false);
    logger->head = (logger->head + 1u) % logger->capacity;
    logger->count--;
    logger->writing = 0u;
    if (logger->count == 0u) ftun_condition_broadcast(&logger->drained);
    ftun_mutex_unlock(&logger->mutex);
  }
}

ftun_status_t ftun_logger_create(const ftun_logger_options_t *options,
                                 ftun_logger_t **out)
{
  ftun_logger_t *logger;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_status_t failure = FTUN_E_IO;
  size_t capacity;
  size_t line_capacity;
  size_t path_length;
  bool file_output;
  if (out != NULL) *out = NULL;
  if (options == NULL || out == NULL || options->level < FTUN_LOG_SILENT ||
      options->level > FTUN_LOG_TRACE ||
      (options->writer == NULL &&
       (options->path == NULL || options->path[0] == '\0') && !options->stderr_output) ||
      (options->writer != NULL && (options->path != NULL || options->stderr_output)) ||
      (options->writer != NULL && (options->max_size != 0u || options->max_files != 0u))) {
    return FTUN_E_INVALID;
  }
  file_output = options->path != NULL && options->path[0] != '\0';
  path_length = file_output ? strlen(options->path) : 0u;
  if (path_length >= FTUN_LOG_PATH_MAX) return FTUN_E_LIMIT;
  capacity = options->queue_capacity == 0u
    ? FTUN_LOG_DEFAULT_QUEUE : options->queue_capacity;
  line_capacity = options->line_capacity == 0u
    ? FTUN_LOG_DEFAULT_LINE : options->line_capacity;
  if (capacity > FTUN_LOG_MAX_QUEUE || line_capacity < 128u ||
      line_capacity > FTUN_LOG_MAX_LINE ||
      capacity > (SIZE_MAX - sizeof(*logger)) / (line_capacity + sizeof(size_t))) return FTUN_E_LIMIT;
  if (options->ledger != NULL) {
    ftun_budget_resources_t resources = {
      sizeof(*logger) + capacity * (line_capacity + sizeof(size_t)) +
        (file_output ? path_length + 1u : 0u),
      file_output ? 2u : 0u, capacity
    };
    failure = ftun_budget_reserve_resources(options->ledger->budget, resources, &reservation);
    if (failure != FTUN_OK) return failure;
  }
  logger = (ftun_logger_t *)calloc(1u, sizeof(*logger));
  if (logger == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  logger->reservation = reservation;
  failure = FTUN_E_IO;
  logger->file.handle = (ftun_file_handle_t)FTUN_FILE_INVALID;
  logger->lines = (char *)malloc(capacity * line_capacity);
  logger->lengths = (size_t *)calloc(capacity, sizeof(*logger->lengths));
  if (logger->lines == NULL || logger->lengths == NULL) goto limit;
  if (ftun_mutex_init(&logger->mutex) != FTUN_OK) goto io;
  if (ftun_condition_init(&logger->available) != FTUN_OK) goto mutex_io;
  if (ftun_condition_init(&logger->drained) != FTUN_OK) goto available_io;
  logger->capacity = capacity;
  logger->line_capacity = line_capacity;
  ftun_atomic_init(&logger->level, (size_t)options->level);
  logger->stderr_output = options->stderr_output;
  logger->journal = getenv("JOURNAL_STREAM") != NULL;
  logger->stamp = options->stamp;
  logger->writer = options->writer;
  logger->writer_user = options->writer_user;
  if (file_output) {
    char lock_path[FTUN_LOG_PATH_MAX + sizeof(".lock")];
    logger->file.path = (char *)malloc(path_length + 1u);
    if (logger->file.path == NULL) {
      failure = FTUN_E_LIMIT;
      goto drained_io;
    }
    memcpy(logger->file.path, options->path, path_length + 1u);
    logger->file.max_size = options->max_size;
    logger->file.max_files = options->max_files == 0u ? 1u : options->max_files;
    (void)snprintf(lock_path, sizeof(lock_path), "%s.lock", options->path);
    failure = options->ledger == NULL
      ? ftun_file_lock_acquire(lock_path, &logger->file.lock)
      : ftun_file_lock_pool_acquire(options->ledger->file_locks, lock_path, &logger->file.lock);
    if (failure != FTUN_OK) goto drained_io;
    failure = ftun_log_file_open(&logger->file, false);
    if (failure != FTUN_OK) goto drained_io;
  }
  if (logger->writer == NULL) {
    logger->writer = ftun_logger_output_write;
    logger->writer_user = logger;
  }
  logger->color = logger->stderr_output && !options->no_color && getenv("NO_COLOR") == NULL &&
    ftun_file_is_terminal(ftun_file_standard_error()) && ftun_file_enable_ansi(ftun_file_standard_error());
  logger->accepting = 1;
  failure = ftun_log_ledger_attach(logger, options->ledger);
  if (failure != FTUN_OK) goto descriptor_io;
  failure = FTUN_E_IO;
  if (ftun_thread_create(&logger->thread, ftun_logger_thread, logger) != FTUN_OK) {
    ftun_log_ledger_detach(logger, false, false);
    goto descriptor_io;
  }
  if (logger->ledger != NULL) {
    ftun_mutex_lock(&logger->ledger->mutex);
    ftun_log_counter_increment(&logger->ledger->usage.created);
    ftun_mutex_unlock(&logger->ledger->mutex);
  }
  *out = logger;
  return FTUN_OK;

descriptor_io:
  if (ftun_platform_file_is_open(&logger->file.handle) &&
      ftun_platform_file_close(&logger->file.handle) != FTUN_OK) failure = FTUN_E_IO;
drained_io:
  (void)ftun_file_lock_release(&logger->file.lock);
  free(logger->file.path);
  ftun_condition_destroy(&logger->drained);
  ftun_condition_destroy(&logger->available);
mutex_io:
  ftun_mutex_destroy(&logger->mutex);
io:
  free(logger->lengths);
  free(logger->lines);
  free(logger);
  ftun_reservation_release(&reservation);
  return failure;
available_io:
  ftun_condition_destroy(&logger->available);
  goto mutex_io;
limit:
  free(logger->lengths);
  free(logger->lines);
  free(logger);
  ftun_reservation_release(&reservation);
  return FTUN_E_LIMIT;
}

static int ftun_log_sensitive(ftun_string_t value)
{
  static const char *const words[] = {
    "password", "authorization", "proxy-authorization", "token", "secret"
  };
  size_t word;
  for (word = 0u; word < sizeof(words) / sizeof(words[0]); word++) {
    size_t index;
    size_t length = strlen(words[word]);
    if (value.length < length) continue;
    for (index = 0u; index <= value.length - length; index++) {
      size_t offset;
      for (offset = 0u; offset < length; offset++) {
        unsigned char byte = (unsigned char)value.data[index + offset];
        if (byte >= 'A' && byte <= 'Z') byte += (unsigned char)('a' - 'A');
        if (byte != (unsigned char)words[word][offset]) break;
      }
      if (offset == length) return 1;
    }
  }
  return 0;
}

static size_t ftun_log_escape(unsigned char byte, char output[4])
{
  static const char digits[] = "0123456789abcdef";
  output[0] = '\\';
  if (byte == '\\' || byte == '"') output[1] = (char)byte;
  else if (byte == '\n') output[1] = 'n';
  else if (byte == '\r') output[1] = 'r';
  else if (byte == '\t') output[1] = 't';
  else if (byte == 0u) output[1] = '0';
  else if (byte < 0x20u || byte == 0x7fu) {
    output[1] = 'x';
    output[2] = digits[byte >> 4u];
    output[3] = digits[byte & 0x0fu];
    return 4u;
  } else {
    output[0] = (char)byte;
    return 1u;
  }
  return 2u;
}

/* 输入已完成固定上限和敏感检查；截断不切开转义序列。 */
static size_t ftun_log_field(char *output, size_t capacity,
                              ftun_string_t value, bool *truncated)
{
  size_t needed = 0u;
  size_t written = 0u;
  size_t limit;
  size_t index;
  char escaped[4];
  for (index = 0u; index < value.length; index++) {
    needed += ftun_log_escape((unsigned char)value.data[index], escaped);
  }
  limit = needed <= capacity ? capacity :
    (capacity > 3u ? capacity - 3u : 0u);
  for (index = 0u; index < value.length; index++) {
    size_t length = ftun_log_escape((unsigned char)value.data[index], escaped);
    if (length > limit - written) break;
    memcpy(output + written, escaped, length);
    written += length;
  }
  if (needed > capacity) {
    *truncated = true;
    for (index = 0u; index < 3u && written < capacity; index++) {
      output[written++] = '.';
    }
  }
  return written;
}

bool ftun_logger_enabled(const ftun_logger_t *logger, ftun_log_level_t level)
{
  return logger != NULL && level >= FTUN_LOG_ERROR && level <= FTUN_LOG_TRACE &&
    (size_t)level <= ftun_atomic_load_explicit(&logger->level, FTUN_MEMORY_RELAXED);
}

typedef struct { char *data; size_t used, capacity; bool truncated; } ftun_log_line_t;

static void line_text(ftun_log_line_t *line, ftun_string_t text, bool quote)
{
  size_t index;
  if (quote && line->capacity - line->used >= 2u) line->data[line->used++] = '"';
  else if (quote) { line->truncated = true; return; }
  index = ftun_log_field(line->data + line->used,
    line->capacity - line->used - (quote ? 1u : 0u), text, &line->truncated);
  line->used += index;
  if (quote) line->data[line->used++] = '"';
}

static void line_fixed(ftun_log_line_t *line, const char *text)
{
  line_text(line, (ftun_string_t){text, strlen(text)}, false);
}

static bool field_quoted(ftun_string_t text)
{
  size_t index;
  if (text.length == 0u) return true;
  for (index = 0u; index < text.length; ++index) {
    unsigned char byte = (unsigned char)text.data[index];
    if (byte <= 0x20u || byte == 0x7fu || byte == '"' || byte == '=' || byte == '\\') return true;
  }
  return false;
}

static void line_number(ftun_log_line_t *line, const char *key, uint64_t number)
{
  char buffer[64];
  (void)snprintf(buffer, sizeof(buffer), " %s=%" PRIu64, key, number);
  line_fixed(line, buffer);
}

ftun_status_t ftun_logger_record(ftun_logger_t *logger, const ftun_log_record_t *record)
{
  static const char *const modules[] = {"app", "config", "ctl", "dns", "proxy", "frs", "fakeip", "tun", "net", "log"};
  static const char *const levels[] = {"", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"};
  const ftun_log_event_t *event;
  size_t index, slot;
  bool oversized = false, redacted = false, enabled;
  char prefix[128], stamp[64] = "";
  ftun_log_line_t line;
  if (logger == NULL || record == NULL || record->event == NULL) return FTUN_E_INVALID;
  event = record->event;
  if (event->level < FTUN_LOG_ERROR || event->level > FTUN_LOG_TRACE ||
      event->module >= FTUN_LOG_MODULE_COUNT || event->module < FTUN_LOG_APP ||
      event->id == NULL || event->phrase == NULL || record->field_count > FTUN_LOG_MAX_FIELDS ||
      (record->field_count != 0u && record->fields == NULL)) return FTUN_E_INVALID;
  enabled = ftun_logger_enabled(logger, event->level);
  ftun_mutex_lock(&logger->mutex);
  if (!logger->accepting) {
    ftun_log_ledger_record(logger, FTUN_LOG_LEDGER_REJECT, false, false, false);
    ftun_mutex_unlock(&logger->mutex);
    return FTUN_E_CANCELLED;
  }
  if (!enabled) {
    ftun_log_counter_increment(&logger->filtered);
    ftun_log_ledger_record(logger, FTUN_LOG_LEDGER_FILTER, false, false, false);
    ftun_mutex_unlock(&logger->mutex);
    return FTUN_OK;
  }
  /* 普通记录不借用最后1/8队列额度，给WARN/ERROR保留进展能力。 */
  if (logger->count == logger->capacity ||
      (event->level > FTUN_LOG_WARN && logger->count >= logger->capacity - logger->capacity / 8u)) {
    ftun_log_counter_increment(&logger->dropped);
    ftun_log_ledger_record(logger, FTUN_LOG_LEDGER_DROP, false, false, false);
    ftun_mutex_unlock(&logger->mutex);
    return FTUN_OK;
  }
  for (index = 0u; index < record->field_count; ++index) {
    const ftun_log_field_t *field = &record->fields[index];
    size_t key_length = 0u;
    if (field->key == NULL) break;
    while (key_length < 32u && field->key[key_length] != '\0') {
      char byte = field->key[key_length];
      if (!((byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') || byte == '_')) break;
      key_length++;
    }
    if (key_length == 0u || key_length == 32u || field->key[key_length] != '\0' ||
        field->kind < FTUN_LOG_TEXT || field->kind > FTUN_LOG_I64) break;
    if (field->kind == FTUN_LOG_TEXT) {
      if (field->value.text.length != 0u && field->value.text.data == NULL) break;
      oversized |= field->value.text.length > FTUN_LOG_MAX_FIELD;
    }
  }
  if (index != record->field_count) {
    ftun_mutex_unlock(&logger->mutex);
    return FTUN_E_INVALID;
  }
  if (!oversized) for (index = 0u; index < record->field_count; ++index) {
    const ftun_log_field_t *field = &record->fields[index];
    redacted |= ftun_log_sensitive((ftun_string_t){field->key, strlen(field->key)}) != 0;
    if (field->kind == FTUN_LOG_TEXT) redacted |= ftun_log_sensitive(field->value.text) != 0;
  }
  redacted |= oversized;
  if (logger->stamp && ftun_log_stamp(stamp, sizeof(stamp)) < 0) {
    ftun_mutex_unlock(&logger->mutex);
    return FTUN_E_IO;
  }
  slot = logger->tail;
  line = (ftun_log_line_t){logger->lines + slot * logger->line_capacity,
    0u, logger->line_capacity - 2u, false};
  (void)snprintf(prefix, sizeof(prefix), "%s[%-6s][%-5s] ", stamp, modules[event->module], levels[event->level]);
  line_fixed(&line, prefix);
  line_fixed(&line, redacted ? "[redacted diagnostic]" : event->phrase);
  line_fixed(&line, ":");
  if (record->sid != 0u) line_number(&line, "sid", record->sid);
  if (record->operation != 0u) line_number(&line, "op", record->operation);
  if (record->generation != 0u) line_number(&line, "gen", record->generation);
  if (record->error.status != FTUN_OK) {
    line_fixed(&line, " err="); line_fixed(&line, ftun_status_name(record->error.status));
  }
  if (record->error.status != FTUN_OK || record->error.stage != 0u)
    line_number(&line, "stage", record->error.stage);
  if (record->error.native_code != 0) {
    char native[40];
    (void)snprintf(native, sizeof(native), " native=%d", record->error.native_code);
    line_fixed(&line, native);
  }
  for (index = 0u; !redacted && index < record->field_count; ++index) {
    const ftun_log_field_t *field = &record->fields[index];
    line_fixed(&line, " "); line_fixed(&line, field->key); line_fixed(&line, "=");
    if (field->kind == FTUN_LOG_TEXT) line_text(&line, field->value.text, field_quoted(field->value.text));
    else {
      char number[32];
      if (field->kind == FTUN_LOG_U64) (void)snprintf(number, sizeof(number), "%" PRIu64, field->value.u64);
      else (void)snprintf(number, sizeof(number), "%" PRId64, field->value.i64);
      line_fixed(&line, number);
    }
    if (line.truncated) break;
  }
  line.data[line.used++] = '\n'; line.data[line.used] = '\0';
  logger->lengths[slot] = line.used;
  logger->tail = (logger->tail + 1u) % logger->capacity;
  logger->count++;
  (void)ftun_atomic_fetch_add(&ftun_log_sequence, 1u);
  ftun_log_counter_increment(&logger->emitted);
  if (redacted) ftun_log_counter_increment(&logger->redacted);
  if (oversized) ftun_log_counter_increment(&logger->oversized);
  if (line.truncated) ftun_log_counter_increment(&logger->truncated);
  ftun_log_ledger_record(logger, FTUN_LOG_LEDGER_ACCEPT, redacted, oversized, line.truncated);
  ftun_condition_signal(&logger->available);
  ftun_mutex_unlock(&logger->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_logger_write(ftun_logger_t *logger, ftun_log_level_t level,
  const ftun_diagnostic_t *diagnostic)
{
  ftun_log_event_t event = {FTUN_LOG_LOG, level, "diagnostic", "diagnostic"};
  ftun_log_field_t fields[2];
  ftun_log_record_t record = {0};
  if (diagnostic == NULL) return FTUN_E_INVALID;
  fields[0] = (ftun_log_field_t){.key = "path", .kind = FTUN_LOG_TEXT, .value.text = diagnostic->path};
  fields[1] = (ftun_log_field_t){.key = "message", .kind = FTUN_LOG_TEXT, .value.text = diagnostic->message};
  record.event = &event;
  record.error = diagnostic->error;
  record.operation = diagnostic->correlation;
  record.fields = fields;
  record.field_count = 2u;
  return ftun_logger_record(logger, &record);
}

ftun_status_t ftun_log_record(ftun_core_t *core, const ftun_log_record_t *record)
{
  ftun_logger_t *logger = NULL;
  ftun_status_t status = ftun_core_context_logger_acquire(core, &logger);
  if (status != FTUN_OK) return status;
  status = ftun_logger_record(logger, record);
  {
    ftun_status_t released = ftun_core_context_logger_release(core);
    return status == FTUN_OK ? released : status;
  }
}

ftun_status_t ftun_logger_flush(ftun_logger_t *logger)
{
  return ftun_logger_flush_until(logger, UINT64_MAX);
}

ftun_status_t ftun_logger_flush_until(ftun_logger_t *logger,
                                      uint64_t deadline_ms)
{
  ftun_status_t wait_status = FTUN_OK;
  if (logger == NULL) return FTUN_E_INVALID;
  ftun_mutex_lock(&logger->mutex);
  while ((logger->count != 0u || logger->writing != 0u) && wait_status == FTUN_OK) {
    wait_status = ftun_condition_wait_until(&logger->drained, &logger->mutex, deadline_ms);
  }
  if (logger->count != 0u || logger->writing != 0u) {
    ftun_mutex_unlock(&logger->mutex);
    return wait_status;
  }
  ftun_mutex_unlock(&logger->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_logger_stop(ftun_logger_t *logger)
{
  if (logger == NULL) return FTUN_E_INVALID;
  ftun_mutex_lock(&logger->mutex);
  logger->accepting = 0;
  logger->stopping = 1;
  ftun_condition_broadcast(&logger->available);
  ftun_mutex_unlock(&logger->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_logger_join_until(ftun_logger_t *logger,
                                     uint64_t deadline_ms)
{
  ftun_status_t wait_status = FTUN_OK;
  if (logger == NULL) return FTUN_E_INVALID;
  ftun_mutex_lock(&logger->mutex);
  if (logger->joined) {
    ftun_mutex_unlock(&logger->mutex);
    return FTUN_OK;
  }
  if (!logger->stopping) {
    ftun_mutex_unlock(&logger->mutex);
    return FTUN_E_AGAIN;
  }
  while (!logger->exited && wait_status == FTUN_OK) {
    wait_status = ftun_condition_wait_until(&logger->drained, &logger->mutex, deadline_ms);
  }
  if (!logger->exited) {
    ftun_mutex_unlock(&logger->mutex);
    return wait_status;
  }
  ftun_mutex_unlock(&logger->mutex);
  if (ftun_thread_join(&logger->thread) != FTUN_OK) return FTUN_E_IO;
  ftun_mutex_lock(&logger->mutex);
  logger->joined = 1;
  ftun_mutex_unlock(&logger->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_logger_get_usage(ftun_logger_t *logger,
                                    ftun_logger_usage_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (logger == NULL || out == NULL) return FTUN_E_INVALID;
  ftun_mutex_lock(&logger->mutex);
  out->capacity = logger->capacity;
  out->queued = logger->count;
  out->emitted = logger->emitted;
  out->filtered = logger->filtered;
  out->dropped = logger->dropped;
  out->io_errors = logger->io_errors;
  out->redacted = logger->redacted;
  out->oversized = logger->oversized;
  out->truncated = logger->truncated;
  out->rotations = ftun_atomic_load(&logger->file.rotations);
  out->reopens = ftun_atomic_load(&logger->file.reopens);
  out->rotate_errors = ftun_atomic_load(&logger->file.rotate_errors);
  out->accepting = logger->accepting != 0;
  out->stopping = logger->stopping != 0;
  out->exited = logger->exited != 0;
  out->joined = logger->joined != 0;
  ftun_mutex_unlock(&logger->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_logger_reopen(ftun_logger_t *logger)
{
  if (logger == NULL) return FTUN_E_INVALID;
  if (logger->file.path == NULL) return FTUN_E_UNSUPPORTED;
  ftun_mutex_lock(&logger->mutex);
  ftun_atomic_store(&logger->reopen_requested, true);
  ftun_condition_signal(&logger->available);
  ftun_mutex_unlock(&logger->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_log_reopen(ftun_core_t *core)
{
  ftun_logger_t *logger = NULL;
  ftun_status_t status;
  if (core == NULL) return FTUN_E_INVALID;
  status = ftun_core_context_logger_acquire(core, &logger);
  if (status != FTUN_OK) return status;
  status = ftun_logger_reopen(logger);
  {
    ftun_status_t released = ftun_core_context_logger_release(core);
    return status == FTUN_OK ? released : status;
  }
}

ftun_status_t ftun_logger_destroy(ftun_logger_t **logger)
{
  return ftun_logger_destroy_until(logger, UINT64_MAX);
}

ftun_status_t ftun_logger_destroy_until(ftun_logger_t **logger,
                                        uint64_t deadline_ms)
{
  ftun_logger_t *owned;
  ftun_status_t status;
  ftun_reservation_t reservation;
  ftun_status_t close_status = FTUN_OK;
  if (logger == NULL) return FTUN_E_INVALID;
  owned = *logger;
  if (owned == NULL) return FTUN_OK;
  status = ftun_logger_stop(owned);
  if (status == FTUN_OK) status = ftun_logger_join_until(owned, deadline_ms);
  if (status != FTUN_OK) return status;
  if (ftun_platform_file_is_open(&owned->file.handle)) {
    close_status = ftun_platform_file_close(&owned->file.handle);
  }
  {
    ftun_status_t released = ftun_file_lock_release(&owned->file.lock);
    if (close_status == FTUN_OK) close_status = released;
  }
  free(owned->file.path);
  ftun_log_ledger_detach(owned, true, close_status != FTUN_OK);
  ftun_condition_destroy(&owned->drained);
  ftun_condition_destroy(&owned->available);
  ftun_mutex_destroy(&owned->mutex);
  free(owned->lengths);
  free(owned->lines);
  reservation = owned->reservation;
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *logger = NULL;
  ftun_reservation_release(&reservation);
  return close_status == FTUN_OK ? FTUN_OK : FTUN_E_IO;
}

ftun_status_t ftun_log_emit(ftun_core_t *core, const ftun_diagnostic_t *diagnostic)
{
  ftun_logger_t *logger = NULL;
  ftun_status_t status;
  if (core == NULL || diagnostic == NULL) return FTUN_E_INVALID;
  status = ftun_core_context_logger_acquire(core, &logger);
  if (status != FTUN_OK) return status;
  status = ftun_logger_write(logger,
    (diagnostic->error.status == FTUN_OK || diagnostic->error.status == FTUN_E_CANCELLED) ? FTUN_LOG_INFO : FTUN_LOG_ERROR,
    diagnostic);
  {
    ftun_status_t released = ftun_core_context_logger_release(core);
    return status == FTUN_OK ? released : status;
  }
}
