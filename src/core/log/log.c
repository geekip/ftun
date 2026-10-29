#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "core/log/log.h"
#include "core/context.h"
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

/* "ts=… seq=… boot=… [id=…] " 前缀；时间为 UTC，不依赖时区数据库。 */
static int ftun_log_stamp(char *out, size_t capacity, uint64_t correlation)
{
  ftun_calendar_time_t now;
  char id[40] = "";
  if (ftun_wallclock_utc(&now) != FTUN_OK) {
    return -1;
  }
  if (correlation != 0u) (void)snprintf(id, sizeof(id), "id=%" PRIu64 " ", correlation);
  return snprintf(out, capacity,
    "ts=%04d-%02d-%02dT%02d:%02d:%02d.%03uZ seq=%" PRIu64 " boot=%016" PRIx64 " %s",
    now.year, now.month, now.day, now.hour, now.minute, now.second, now.millisecond,
    ftun_atomic_fetch_add(&ftun_log_sequence, 1u) + 1u, ftun_log_boot_id(), id);
}

struct ftun_log_ledger {
  ftun_mutex_t mutex;
  ftun_reservation_t reservation;
  ftun_budget_t *budget;
  ftun_log_totals_t usage;
};

/* 文件 sink：只被写入线程访问（计数用原子量，供用量查询读取）。 */
typedef struct {
  ftun_file_handle_t handle;
  char *path;
  uint64_t max_size;
  size_t max_files;
  uint64_t size;
  ftun_atomic_u64_t rotations;
  ftun_atomic_u64_t reopens;
  ftun_atomic_u64_t rotate_errors;
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
  ftun_log_level_t level;
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
  if (ledger == NULL) return FTUN_E_INVALID;
  owned = *ledger;
  if (owned == NULL) return FTUN_OK;
  ftun_mutex_lock(&owned->mutex);
  if (owned->usage.instances != 0u) {
    ftun_mutex_unlock(&owned->mutex);
    return FTUN_E_AGAIN;
  }
  ftun_mutex_unlock(&owned->mutex);
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

/* 轮转：path.(n-2) -> path.(n-1) … path -> path.1，最旧的被覆盖；然后新建 path。
 * 某一步改名失败不阻止新建（日志要继续写），只记一次错误。 */
static void ftun_log_file_rotate(ftun_log_file_t *file)
{
  char from[FTUN_LOG_PATH_MAX + 16u];
  char to[FTUN_LOG_PATH_MAX + 16u];
  size_t index;
  bool failed = false;
  if (ftun_platform_file_is_open(&file->handle) &&
      ftun_platform_file_close(&file->handle) != FTUN_OK) failed = true;
  for (index = file->max_files; index > 1u; index--) {
    if (index == 2u) (void)snprintf(from, sizeof(from), "%s", file->path);
    else (void)snprintf(from, sizeof(from), "%s.%zu", file->path, index - 2u);
    (void)snprintf(to, sizeof(to), "%s.%zu", file->path, index - 1u);
    if (ftun_platform_file_rename_if_exists(from, to) != FTUN_OK) failed = true;
  }
  if (ftun_log_file_open(file, file->max_files <= 1u) != FTUN_OK) failed = true;
  if (failed) ftun_atomic_fetch_add(&file->rotate_errors, 1u);
  else ftun_atomic_fetch_add(&file->rotations, 1u);
}

static void ftun_log_file_reopen(ftun_log_file_t *file)
{
  bool failed = ftun_platform_file_is_open(&file->handle) &&
    ftun_platform_file_close(&file->handle) != FTUN_OK;
  if (ftun_log_file_open(file, false) != FTUN_OK || failed) {
    ftun_atomic_fetch_add(&file->rotate_errors, 1u);
  } else {
    ftun_atomic_fetch_add(&file->reopens, 1u);
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
  /* 轮转/显式 reopen 失败后，下一条日志仍独立尝试打开目标。 */
  if (!ftun_platform_file_is_open(&file->handle) && ftun_log_file_open(file, false) != FTUN_OK) {
    return FTUN_E_IO;
  }
  status = ftun_platform_file_write(&file->handle, line, &written);
  file->size += written;
  return status == FTUN_OK ? FTUN_OK : FTUN_E_IO;
}

static void *ftun_logger_thread(void *argument)
{
  ftun_logger_t *logger = (ftun_logger_t *)argument;
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
        logger->writer == ftun_logger_file_write) {
      ftun_mutex_unlock(&logger->mutex);
      ftun_log_file_reopen(&logger->file);
      continue;
    }
    if (logger->count == 0u && logger->stopping) {
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
  if (out != NULL) *out = NULL;
  if (options == NULL || out == NULL || options->level < FTUN_LOG_SILENT ||
      options->level > FTUN_LOG_TRACE ||
      (options->writer == NULL &&
       (options->path == NULL || options->path[0] == '\0')) ||
      (options->writer != NULL && options->path != NULL) ||
      (options->writer != NULL && (options->max_size != 0u || options->max_files != 0u))) {
    return FTUN_E_INVALID;
  }
  capacity = options->queue_capacity == 0u
    ? FTUN_LOG_DEFAULT_QUEUE : options->queue_capacity;
  line_capacity = options->line_capacity == 0u
    ? FTUN_LOG_DEFAULT_LINE : options->line_capacity;
  if (capacity > FTUN_LOG_MAX_QUEUE || line_capacity < 128u ||
      line_capacity > FTUN_LOG_MAX_LINE ||
      capacity > (SIZE_MAX - sizeof(*logger)) / (line_capacity + sizeof(size_t))) return FTUN_E_LIMIT;
  if (options->ledger != NULL) {
    ftun_budget_resources_t resources = {
      sizeof(*logger) + capacity * (line_capacity + sizeof(size_t)),
      options->writer == NULL ? 1u : 0u, capacity
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
  logger->lines = (char *)calloc(capacity, line_capacity);
  logger->lengths = (size_t *)calloc(capacity, sizeof(*logger->lengths));
  if (logger->lines == NULL || logger->lengths == NULL) goto limit;
  if (ftun_mutex_init(&logger->mutex) != FTUN_OK) goto io;
  if (ftun_condition_init(&logger->available) != FTUN_OK) goto mutex_io;
  if (ftun_condition_init(&logger->drained) != FTUN_OK) goto available_io;
  logger->capacity = capacity;
  logger->line_capacity = line_capacity;
  logger->level = options->level;
  logger->stamp = options->stamp;
  logger->writer = options->writer;
  logger->writer_user = options->writer_user;
  if (logger->writer == NULL) {
    size_t path_length = strlen(options->path);
    if (path_length >= FTUN_LOG_PATH_MAX) {
      failure = FTUN_E_LIMIT;
      goto drained_io;
    }
    logger->file.path = (char *)malloc(path_length + 1u);
    if (logger->file.path == NULL) {
      failure = FTUN_E_LIMIT;
      goto drained_io;
    }
    memcpy(logger->file.path, options->path, path_length + 1u);
    logger->file.max_size = options->max_size;
    logger->file.max_files = options->max_files == 0u ? 1u : options->max_files;
    if (ftun_log_file_open(&logger->file, false) != FTUN_OK) goto drained_io;
    logger->writer = ftun_logger_file_write;
    logger->writer_user = &logger->file;
  }
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
  if (byte == '\\') output[1] = '\\';
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

ftun_status_t ftun_logger_write(ftun_logger_t *logger, ftun_log_level_t level,
                                const ftun_diagnostic_t *diagnostic)
{
  static const char separator[] = " message=";
  static const char redaction[] = "[redacted diagnostic]";
  char *line;
  int length;
  ftun_string_t message;
  ftun_string_t path;
  size_t slot;
  size_t written;
  size_t available;
  bool oversized;
  bool redacted;
  bool truncated = false;
  if (logger == NULL || diagnostic == NULL || level < FTUN_LOG_ERROR ||
      level > FTUN_LOG_TRACE ||
      (diagnostic->message.length != 0u && diagnostic->message.data == NULL) ||
      (diagnostic->path.length != 0u && diagnostic->path.data == NULL)) {
    return FTUN_E_INVALID;
  }
  ftun_mutex_lock(&logger->mutex);
  if (!logger->accepting) {
    ftun_log_ledger_record(logger, FTUN_LOG_LEDGER_REJECT, false, false, false);
    ftun_mutex_unlock(&logger->mutex);
    return FTUN_E_CANCELLED;
  }
  if (logger->level == FTUN_LOG_SILENT || level > logger->level) {
    ftun_log_counter_increment(&logger->filtered);
    ftun_log_ledger_record(logger, FTUN_LOG_LEDGER_FILTER, false, false, false);
    ftun_mutex_unlock(&logger->mutex);
    return FTUN_OK;
  }
  if (logger->count == logger->capacity) {
    ftun_log_counter_increment(&logger->dropped);
    ftun_log_ledger_record(logger, FTUN_LOG_LEDGER_DROP, false, false, false);
    ftun_mutex_unlock(&logger->mutex);
    return FTUN_OK;
  }
  slot = logger->tail;
  line = logger->lines + slot * logger->line_capacity;
  oversized = diagnostic->message.length > FTUN_LOG_MAX_FIELD ||
    diagnostic->path.length > FTUN_LOG_MAX_FIELD;
  /* 超长时不读取任何字段；不能只检查可输出的前缀而漏过后面的敏感键。 */
  redacted = oversized || ftun_log_sensitive(diagnostic->message) ||
    ftun_log_sensitive(diagnostic->path);
  if (redacted) {
    message = (ftun_string_t){redaction, sizeof(redaction) - 1u};
    path = (ftun_string_t){NULL, 0u};
  } else {
    message = diagnostic->message;
    path = diagnostic->path;
  }
  {
    char stamp[128] = "";
    if (logger->stamp && ftun_log_stamp(stamp, sizeof(stamp), diagnostic->correlation) < 0) {
      ftun_mutex_unlock(&logger->mutex);
      return FTUN_E_IO;
    }
    length = snprintf(line, logger->line_capacity,
      "%slevel=%s status=%s stage=%u native=%d path=", stamp,
      ftun_log_names[level], ftun_status_name(diagnostic->error.status),
      diagnostic->error.stage, diagnostic->error.native_code);
  }
  if (length < 0 || (size_t)length > logger->line_capacity -
      sizeof(separator) - 1u) {
    ftun_mutex_unlock(&logger->mutex);
    return FTUN_E_IO;
  }
  written = (size_t)length;
  /* 始终保留 message 字段分隔、换行和 NUL。 */
  available = logger->line_capacity - written - sizeof(separator) - 1u;
  written += ftun_log_field(line + written, available, path, &truncated);
  memcpy(line + written, separator, sizeof(separator) - 1u);
  written += sizeof(separator) - 1u;
  available = logger->line_capacity - written - 2u;
  written += ftun_log_field(line + written, available, message, &truncated);
  line[written++] = '\n';
  line[written] = '\0';
  logger->lengths[slot] = written;
  logger->tail = (logger->tail + 1u) % logger->capacity;
  logger->count++;
  ftun_log_counter_increment(&logger->emitted);
  if (redacted) ftun_log_counter_increment(&logger->redacted);
  if (oversized) ftun_log_counter_increment(&logger->oversized);
  if (truncated) ftun_log_counter_increment(&logger->truncated);
  ftun_log_ledger_record(logger, FTUN_LOG_LEDGER_ACCEPT, redacted, oversized, truncated);
  ftun_condition_signal(&logger->available);
  ftun_mutex_unlock(&logger->mutex);
  return FTUN_OK;
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
  if (logger->writer != ftun_logger_file_write) return FTUN_E_UNSUPPORTED;
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
    diagnostic->error.status == FTUN_OK ? FTUN_LOG_INFO : FTUN_LOG_ERROR,
    diagnostic);
  {
    ftun_status_t released = ftun_core_context_logger_release(core);
    return status == FTUN_OK ? released : status;
  }
}
