#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "logger.h"
#include "core/runtime.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* REQ-OBS-001 / TASK-UTIL-001 / TEST-UTIL-001，目标 0.5.0：
 * ftun_log_emit 进入有界异步日志并保留丢弃/错误计数。 */

#define FTUN_LOG_DEFAULT_QUEUE 64u
#define FTUN_LOG_DEFAULT_LINE 512u
#define FTUN_LOG_MAX_QUEUE 4096u
#define FTUN_LOG_MAX_LINE 4096u

struct ftun_logger {
  pthread_mutex_t mutex;
  pthread_cond_t available;
  pthread_cond_t drained;
  pthread_t thread;
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
  ftun_log_level_t level;
  ftun_log_writer_fn writer;
  void *writer_user;
  int descriptor;
  int accepting;
  int stopping;
};

static const char *const ftun_log_names[] = {
  "silent", "error", "warn", "info", "debug", "trace"
};

static void ftun_log_counter_increment(uint64_t *value)
{
  if (*value != UINT64_MAX) (*value)++;
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

static ftun_status_t ftun_logger_file_write(void *user, ftun_bytes_t line)
{
  int descriptor = *(int *)user;
  size_t offset = 0u;
  while (offset < line.length) {
    ssize_t written = write(descriptor, line.data + offset,
                            line.length - offset);
    if (written < 0 && errno == EINTR) continue;
    if (written <= 0) return FTUN_E_IO;
    offset += (size_t)written;
  }
  return FTUN_OK;
}

static void *ftun_logger_thread(void *argument)
{
  ftun_logger_t *logger = (ftun_logger_t *)argument;
  for (;;) {
    size_t slot;
    size_t length;
    ftun_status_t status;
    (void)pthread_mutex_lock(&logger->mutex);
    while (logger->count == 0u && !logger->stopping) {
      (void)pthread_cond_wait(&logger->available, &logger->mutex);
    }
    if (logger->count == 0u && logger->stopping) {
      (void)pthread_mutex_unlock(&logger->mutex);
      break;
    }
    slot = logger->head;
    length = logger->lengths[slot];
    logger->writing = 1u;
    (void)pthread_mutex_unlock(&logger->mutex);
    status = logger->writer(logger->writer_user,
      (ftun_bytes_t){(const uint8_t *)(logger->lines + slot * logger->line_capacity),
                     length});
    (void)pthread_mutex_lock(&logger->mutex);
    if (status != FTUN_OK) ftun_log_counter_increment(&logger->io_errors);
    logger->head = (logger->head + 1u) % logger->capacity;
    logger->count--;
    logger->writing = 0u;
    if (logger->count == 0u) (void)pthread_cond_broadcast(&logger->drained);
    (void)pthread_mutex_unlock(&logger->mutex);
  }
  return NULL;
}

ftun_status_t ftun_logger_create(const ftun_logger_options_t *options,
                                 ftun_logger_t **out)
{
  ftun_logger_t *logger;
  size_t capacity;
  size_t line_capacity;
  if (out != NULL) *out = NULL;
  if (options == NULL || out == NULL || options->level > FTUN_LOG_TRACE ||
      (options->writer == NULL &&
       (options->path == NULL || options->path[0] == '\0')) ||
      (options->writer != NULL && options->path != NULL)) return FTUN_E_INVALID;
  capacity = options->queue_capacity == 0u
    ? FTUN_LOG_DEFAULT_QUEUE : options->queue_capacity;
  line_capacity = options->line_capacity == 0u
    ? FTUN_LOG_DEFAULT_LINE : options->line_capacity;
  if (capacity > FTUN_LOG_MAX_QUEUE || line_capacity < 128u ||
      line_capacity > FTUN_LOG_MAX_LINE ||
      capacity > SIZE_MAX / line_capacity) return FTUN_E_LIMIT;
  logger = (ftun_logger_t *)calloc(1u, sizeof(*logger));
  if (logger == NULL) return FTUN_E_LIMIT;
  logger->descriptor = -1;
  logger->lines = (char *)calloc(capacity, line_capacity);
  logger->lengths = (size_t *)calloc(capacity, sizeof(*logger->lengths));
  if (logger->lines == NULL || logger->lengths == NULL) goto limit;
  if (pthread_mutex_init(&logger->mutex, NULL) != 0) goto io;
  if (pthread_cond_init(&logger->available, NULL) != 0) goto mutex_io;
  if (pthread_cond_init(&logger->drained, NULL) != 0) goto available_io;
  logger->capacity = capacity;
  logger->line_capacity = line_capacity;
  logger->level = options->level;
  logger->writer = options->writer;
  logger->writer_user = options->writer_user;
  if (logger->writer == NULL) {
    logger->descriptor = open(options->path,
      O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (logger->descriptor < 0) goto drained_io;
    logger->writer = ftun_logger_file_write;
    logger->writer_user = &logger->descriptor;
  }
  logger->accepting = 1;
  if (pthread_create(&logger->thread, NULL, ftun_logger_thread, logger) != 0) {
    goto descriptor_io;
  }
  *out = logger;
  return FTUN_OK;

descriptor_io:
  if (logger->descriptor >= 0) (void)close(logger->descriptor);
drained_io:
  (void)pthread_cond_destroy(&logger->drained);
available_io:
  (void)pthread_cond_destroy(&logger->available);
mutex_io:
  (void)pthread_mutex_destroy(&logger->mutex);
io:
  free(logger->lengths);
  free(logger->lines);
  free(logger);
  return FTUN_E_IO;
limit:
  free(logger->lengths);
  free(logger->lines);
  free(logger);
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

ftun_status_t ftun_logger_write(ftun_logger_t *logger, ftun_log_level_t level,
                                const ftun_diagnostic_t *diagnostic)
{
  char *line;
  int length;
  const char *message;
  const char *path;
  int message_length;
  int path_length;
  size_t slot;
  if (logger == NULL || diagnostic == NULL || level < FTUN_LOG_ERROR ||
      level > FTUN_LOG_TRACE ||
      (diagnostic->message.length != 0u && diagnostic->message.data == NULL) ||
      (diagnostic->path.length != 0u && diagnostic->path.data == NULL)) {
    return FTUN_E_INVALID;
  }
  (void)pthread_mutex_lock(&logger->mutex);
  if (!logger->accepting) {
    (void)pthread_mutex_unlock(&logger->mutex);
    return FTUN_E_CANCELLED;
  }
  if (logger->level == FTUN_LOG_SILENT || level > logger->level) {
    ftun_log_counter_increment(&logger->filtered);
    (void)pthread_mutex_unlock(&logger->mutex);
    return FTUN_OK;
  }
  if (logger->count == logger->capacity) {
    ftun_log_counter_increment(&logger->dropped);
    (void)pthread_mutex_unlock(&logger->mutex);
    return FTUN_OK;
  }
  slot = logger->tail;
  line = logger->lines + slot * logger->line_capacity;
  if (ftun_log_sensitive(diagnostic->message) ||
      ftun_log_sensitive(diagnostic->path)) {
    message = "[redacted diagnostic]";
    message_length = (int)strlen(message);
    path = "";
    path_length = 0;
  } else {
    message = diagnostic->message.data == NULL ? "" : diagnostic->message.data;
    message_length = diagnostic->message.length > (size_t)INT32_MAX
      ? INT32_MAX : (int)diagnostic->message.length;
    path = diagnostic->path.data == NULL ? "" : diagnostic->path.data;
    path_length = diagnostic->path.length > (size_t)INT32_MAX
      ? INT32_MAX : (int)diagnostic->path.length;
  }
  length = snprintf(line, logger->line_capacity,
    "level=%s status=%s stage=%u native=%d path=%.*s message=%.*s\n",
    ftun_log_names[level], ftun_status_name(diagnostic->error.status),
    diagnostic->error.stage, diagnostic->error.native_code,
    path_length, path, message_length, message);
  if (length < 0) {
    (void)pthread_mutex_unlock(&logger->mutex);
    return FTUN_E_IO;
  }
  logger->lengths[slot] = (size_t)length >= logger->line_capacity
    ? logger->line_capacity - 1u : (size_t)length;
  logger->tail = (logger->tail + 1u) % logger->capacity;
  logger->count++;
  ftun_log_counter_increment(&logger->emitted);
  (void)pthread_cond_signal(&logger->available);
  (void)pthread_mutex_unlock(&logger->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_logger_flush(ftun_logger_t *logger)
{
  if (logger == NULL) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&logger->mutex);
  while (logger->count != 0u || logger->writing != 0u) {
    (void)pthread_cond_wait(&logger->drained, &logger->mutex);
  }
  (void)pthread_mutex_unlock(&logger->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_logger_get_usage(ftun_logger_t *logger,
                                    ftun_logger_usage_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (logger == NULL || out == NULL) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&logger->mutex);
  out->capacity = logger->capacity;
  out->queued = logger->count;
  out->emitted = logger->emitted;
  out->filtered = logger->filtered;
  out->dropped = logger->dropped;
  out->io_errors = logger->io_errors;
  out->accepting = logger->accepting != 0;
  (void)pthread_mutex_unlock(&logger->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_logger_destroy(ftun_logger_t **logger)
{
  ftun_logger_t *owned;
  int close_status = 0;
  if (logger == NULL) return FTUN_E_INVALID;
  owned = *logger;
  if (owned == NULL) return FTUN_OK;
  (void)pthread_mutex_lock(&owned->mutex);
  owned->accepting = 0;
  owned->stopping = 1;
  (void)pthread_cond_broadcast(&owned->available);
  (void)pthread_mutex_unlock(&owned->mutex);
  if (pthread_join(owned->thread, NULL) != 0) return FTUN_E_IO;
  if (owned->descriptor >= 0) close_status = close(owned->descriptor);
  (void)pthread_cond_destroy(&owned->drained);
  (void)pthread_cond_destroy(&owned->available);
  (void)pthread_mutex_destroy(&owned->mutex);
  free(owned->lengths);
  free(owned->lines);
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *logger = NULL;
  return close_status == 0 ? FTUN_OK : FTUN_E_IO;
}

ftun_status_t ftun_log_emit(ftun_core_t *core, const ftun_diagnostic_t *diagnostic)
{
  ftun_logger_t *logger = NULL;
  ftun_status_t status;
  if (core == NULL || diagnostic == NULL) return FTUN_E_INVALID;
  status = ftun_runtime_manager_logger(core, &logger);
  if (status != FTUN_OK) return status;
  return ftun_logger_write(logger,
    diagnostic->error.status == FTUN_OK ? FTUN_LOG_INFO : FTUN_LOG_ERROR,
    diagnostic);
}
