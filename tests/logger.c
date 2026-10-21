#define _POSIX_C_SOURCE 200809L
#include "core/budget.h"
#include "proxy/runtime_state.h"
#include "util/logger.h"
#include "util/time.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "logger contract failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  int blocked;
  int entered;
  size_t calls;
  char output[4096];
  size_t length;
} writer_t;

static ftun_status_t write_line(void *user, ftun_bytes_t line)
{
  writer_t *writer = (writer_t *)user;
  (void)pthread_mutex_lock(&writer->mutex);
  writer->entered = 1;
  (void)pthread_cond_broadcast(&writer->condition);
  while (writer->blocked) {
    (void)pthread_cond_wait(&writer->condition, &writer->mutex);
  }
  if (line.length > sizeof(writer->output) - writer->length) {
    (void)pthread_mutex_unlock(&writer->mutex);
    return FTUN_E_LIMIT;
  }
  memcpy(writer->output + writer->length, line.data, line.length);
  writer->length += line.length;
  writer->calls++;
  (void)pthread_mutex_unlock(&writer->mutex);
  return FTUN_OK;
}

static ftun_diagnostic_t diagnostic(const char *path, const char *message)
{
  ftun_diagnostic_t result;
  memset(&result, 0, sizeof(result));
  result.error.status = FTUN_E_IO;
  result.error.stage = 7u;
  result.error.native_code = 28;
  result.path.data = path;
  result.path.length = strlen(path);
  result.message.data = message;
  result.message.length = strlen(message);
  return result;
}

static int contains(const char *data, size_t data_length,
                    const char *needle)
{
  size_t needle_length = strlen(needle);
  size_t index;
  if (needle_length > data_length) return 0;
  for (index = 0u; index <= data_length - needle_length; index++) {
    if (memcmp(data + index, needle, needle_length) == 0) return 1;
  }
  return 0;
}

int main(void)
{
  writer_t writer;
  ftun_logger_options_t options;
  ftun_logger_t *logger = NULL;
  ftun_logger_usage_t usage;
  ftun_log_level_t level;
  ftun_diagnostic_t item;
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  size_t index;
  memset(&writer, 0, sizeof(writer));
  CHECK(pthread_mutex_init(&writer.mutex, NULL) == 0);
  CHECK(pthread_cond_init(&writer.condition, NULL) == 0);
  memset(&options, 0, sizeof(options));
  options.level = FTUN_LOG_DEBUG;
  options.queue_capacity = 2u;
  options.line_capacity = 256u;
  options.writer = write_line;
  options.writer_user = &writer;
  CHECK(ftun_logger_create(&options, &logger) == FTUN_OK);
  item = diagnostic("/config", "ordinary failure");
  CHECK(ftun_logger_write(logger, FTUN_LOG_TRACE, &item) == FTUN_OK);
  CHECK(ftun_logger_get_usage(logger, &usage) == FTUN_OK &&
        usage.filtered == 1u && usage.emitted == 0u);

  (void)pthread_mutex_lock(&writer.mutex);
  writer.blocked = 1;
  (void)pthread_mutex_unlock(&writer.mutex);
  CHECK(ftun_logger_write(logger, FTUN_LOG_ERROR, &item) == FTUN_OK);
  (void)pthread_mutex_lock(&writer.mutex);
  while (!writer.entered) {
    (void)pthread_cond_wait(&writer.condition, &writer.mutex);
  }
  (void)pthread_mutex_unlock(&writer.mutex);
  for (index = 0u; index < 8u; index++) {
    CHECK(ftun_logger_write(logger, FTUN_LOG_ERROR, &item) == FTUN_OK);
  }
  CHECK(ftun_logger_get_usage(logger, &usage) == FTUN_OK &&
        usage.dropped > 0u && usage.queued <= usage.capacity);
  (void)pthread_mutex_lock(&writer.mutex);
  writer.blocked = 0;
  (void)pthread_cond_broadcast(&writer.condition);
  (void)pthread_mutex_unlock(&writer.mutex);
  CHECK(ftun_logger_flush(logger) == FTUN_OK);

  item = diagnostic("/outbounds/0/password", "password=hunter2");
  CHECK(ftun_logger_write(logger, FTUN_LOG_ERROR, &item) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK);
  (void)pthread_mutex_lock(&writer.mutex);
  CHECK(!contains(writer.output, writer.length, "hunter2"));
  CHECK(contains(writer.output, writer.length, "redacted diagnostic"));
  (void)pthread_mutex_unlock(&writer.mutex);

  CHECK(ftun_budget_create(NULL, 65536u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 1u, &core) == FTUN_OK);
  CHECK(ftun_core_context_set_logger(core, logger) == FTUN_OK);
  item = diagnostic("/runtime", "reload failed");
  CHECK(ftun_log_emit(core, &item) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK);
  CHECK(ftun_core_context_set_logger(core, NULL) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(ftun_logger_destroy(&logger) == FTUN_OK && logger == NULL);

  /* writer 进入不可硬取消调用后，到期回收必须保留 logger；writer 静默后
   * 同一个对象可以重试回收，且不会重复 join 或提前释放队列内存。 */
  writer.entered = 0;
  (void)pthread_mutex_lock(&writer.mutex);
  writer.blocked = 1;
  (void)pthread_mutex_unlock(&writer.mutex);
  CHECK(ftun_logger_create(&options, &logger) == FTUN_OK);
  item = diagnostic("/blocked", "slow writer");
  CHECK(ftun_logger_write(logger, FTUN_LOG_ERROR, &item) == FTUN_OK);
  (void)pthread_mutex_lock(&writer.mutex);
  while (!writer.entered) {
    (void)pthread_cond_wait(&writer.condition, &writer.mutex);
  }
  (void)pthread_mutex_unlock(&writer.mutex);
  {
    uint64_t now_ms = 0u;
    CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK);
    CHECK(ftun_logger_flush_until(logger, now_ms) == FTUN_E_TIMEOUT);
    CHECK(ftun_logger_stop(logger) == FTUN_OK);
    CHECK(ftun_logger_join_until(logger, now_ms) == FTUN_E_TIMEOUT);
    CHECK(ftun_logger_destroy_until(&logger, now_ms) == FTUN_E_TIMEOUT &&
          logger != NULL);
  }
  CHECK(ftun_logger_get_usage(logger, &usage) == FTUN_OK &&
        !usage.accepting && usage.stopping && !usage.exited && !usage.joined);
  (void)pthread_mutex_lock(&writer.mutex);
  writer.blocked = 0;
  (void)pthread_cond_broadcast(&writer.condition);
  (void)pthread_mutex_unlock(&writer.mutex);
  CHECK(ftun_logger_destroy_until(&logger, UINT64_MAX) == FTUN_OK &&
        logger == NULL);

  options.level = FTUN_LOG_SILENT;
  CHECK(ftun_logger_create(&options, &logger) == FTUN_OK);
  item = diagnostic("/x", "message");
  CHECK(ftun_logger_write(logger, FTUN_LOG_ERROR, &item) == FTUN_OK);
  CHECK(ftun_logger_get_usage(logger, &usage) == FTUN_OK &&
        usage.filtered == 1u && usage.emitted == 0u);
  CHECK(ftun_logger_destroy(&logger) == FTUN_OK);
  CHECK(ftun_log_level_parse("trace", &level) == FTUN_OK &&
        level == FTUN_LOG_TRACE);
  CHECK(ftun_log_level_parse("TRACE", &level) == FTUN_E_INVALID);
  CHECK(ftun_logger_create(&(ftun_logger_options_t){
          FTUN_LOG_INFO, "/no/such/directory/ftun.log", 1u, 128u, NULL, NULL},
        &logger) == FTUN_E_IO && logger == NULL);
  CHECK(pthread_cond_destroy(&writer.condition) == 0);
  CHECK(pthread_mutex_destroy(&writer.mutex) == 0);
  return 0;
}
