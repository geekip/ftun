#include "core/log/event_log.h"
#include "core/context.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "event log failed at %d: %s\n", __LINE__, #x); \
  return 1; \
} } while (0)

typedef struct {
  char output[65536];
  size_t length;
  size_t calls;
  bool fail;
} writer_t;

/* writer 单线程写入；主线程只在 flush/join 完成后访问。 */
static ftun_status_t write_line(void *user, ftun_bytes_t bytes)
{
  writer_t *writer = user;
  writer->calls++;
  if (writer->fail) return FTUN_E_IO;
  if (bytes.length >= sizeof(writer->output) - writer->length) return FTUN_E_LIMIT;
  memcpy(writer->output + writer->length, bytes.data, bytes.length);
  writer->length += bytes.length;
  writer->output[writer->length] = '\0';
  return FTUN_OK;
}

static ftun_status_t make_logger(writer_t *writer, ftun_log_level_t level,
  ftun_logger_t **out)
{
  ftun_logger_options_t options = {0};
  options.level = level;
  options.queue_capacity = 256u;
  options.line_capacity = 512u;
  options.writer = write_line;
  options.writer_user = writer;
  return ftun_logger_create(&options, out);
}

static ftun_lifecycle_event_t event(ftun_lifecycle_kind_t kind, uint64_t generation,
  ftun_status_t status)
{
  ftun_lifecycle_event_t item = {0};
  item.kind = kind;
  item.generation = generation;
  item.status = status;
  return item;
}

static int test_early(void)
{
  ftun_budget_t *budget = NULL;
  ftun_event_log_t *log = NULL;
  ftun_logger_t *logger = NULL;
  ftun_event_log_usage_t usage;
  ftun_logger_usage_t output;
  ftun_budget_usage_t resources;
  writer_t writer = {0};
  ftun_lifecycle_event_t item;
  const char *cursor;
  unsigned int index;
  CHECK(ftun_budget_create(NULL, 131072u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_event_log_create(budget, &log) == FTUN_OK);
  CHECK(ftun_event_log_module_name(log, 0u, "app") == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &resources) == FTUN_OK && resources.used > 0u &&
    resources.used_resources.queue_slots == FTUN_EVENT_LOG_EARLY_CAPACITY);
  CHECK(ftun_event_log_begin(log) == FTUN_OK);
  CHECK(ftun_event_log_reconfigure(log, NULL, true) == FTUN_E_STALE);
  for (index = 1u; index <= FTUN_EVENT_LOG_EARLY_CAPACITY; index++) {
    item = event(FTUN_LIFECYCLE_CONFIG_PARSED, index, FTUN_OK);
    CHECK(ftun_event_log_record(log, NULL, &item, 0u) == FTUN_OK);
    memset(&item, 0xff, sizeof(item));
  }
  item = event(FTUN_LIFECYCLE_CONFIG_FAILED, 99u, FTUN_E_INVALID);
  CHECK(ftun_event_log_record(log, NULL, &item, 0u) == FTUN_OK);
  CHECK(ftun_event_log_begin(log) == FTUN_E_AGAIN);
  CHECK(ftun_event_log_get_usage(log, &usage) == FTUN_OK && usage.recorded == 17u &&
    usage.buffered == 16u && usage.early_dropped == 1u && usage.has_error &&
    usage.last_error.generation == 99u && usage.last_error.status == FTUN_E_INVALID);
  CHECK(ftun_event_log_publish(log, NULL, false) == FTUN_E_INVALID);
  CHECK(make_logger(&writer, FTUN_LOG_INFO, &logger) == FTUN_OK);
  CHECK(ftun_event_log_publish(log, logger, false) == FTUN_OK);
  CHECK(ftun_event_log_publish(log, logger, false) == FTUN_E_STALE);
  CHECK(ftun_logger_flush(logger) == FTUN_OK);
  CHECK(ftun_logger_get_usage(logger, &output) == FTUN_OK && output.dropped == 0u &&
    output.emitted == 16u && output.io_errors == 0u);
  CHECK(writer.calls == 16u);
  cursor = writer.output;
  for (index = 1u; index <= 16u; index++) {
    char marker[128];
    (void)snprintf(marker, sizeof(marker),
      "event=config.parsed module=app generation=%u reason=none suppressed=0", index);
    cursor = strstr(cursor, marker);
    CHECK(cursor != NULL);
    cursor += strlen(marker);
  }
  CHECK(strstr(writer.output, "generation=99 ") == NULL);
  CHECK(ftun_event_log_finish(log, logger) == FTUN_OK);
  CHECK(ftun_event_log_record(log, logger, &item, 0u) == FTUN_E_CANCELLED);
  CHECK(ftun_event_log_finish(log, logger) == FTUN_OK);
  CHECK(ftun_event_log_begin(log) == FTUN_OK);
  CHECK(ftun_event_log_get_usage(log, &usage) == FTUN_OK && usage.recorded == 17u &&
    usage.forwarded == 16u && usage.buffered == 0u && !usage.has_error && !usage.closed);
  /* 配置失败后无 sink：保留失败值，finish 如实计入未输出事件。 */
  CHECK(ftun_event_log_record(log, NULL, &item, 0u) == FTUN_OK);
  CHECK(ftun_event_log_finish(log, NULL) == FTUN_OK);
  CHECK(ftun_event_log_get_usage(log, &usage) == FTUN_OK && usage.early_dropped == 2u &&
    usage.has_error && usage.last_error.status == FTUN_E_INVALID);
  CHECK(ftun_event_log_destroy(&log) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &resources) == FTUN_OK && resources.used == 0u &&
    resources.used_resources.queue_slots == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(ftun_logger_destroy(&logger) == FTUN_OK);
  return 0;
}

static int test_filter_and_switch(void)
{
  ftun_budget_t *budget = NULL;
  ftun_event_log_t *log = NULL;
  ftun_logger_t *logger = NULL;
  ftun_event_log_usage_t usage;
  ftun_logger_usage_t output;
  writer_t writer = {0};
  ftun_lifecycle_event_t item = event(FTUN_LIFECYCLE_STARTING, 1u, FTUN_OK);
  unsigned int index;
  CHECK(ftun_budget_create(NULL, 131072u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_event_log_create(budget, &log) == FTUN_OK);
  CHECK(ftun_event_log_module_name(log, 0u, "app") == FTUN_OK);
  CHECK(make_logger(&writer, FTUN_LOG_WARN, &logger) == FTUN_OK);
  CHECK(ftun_event_log_record(log, NULL, &item, 0u) == FTUN_OK);
  CHECK(ftun_event_log_publish(log, logger, false) == FTUN_OK);
  CHECK(ftun_logger_get_usage(logger, &output) == FTUN_OK && output.filtered == 1u);
  item = event(FTUN_LIFECYCLE_MODULE_FAILED, 1u, FTUN_E_IO);
  item.module = FTUN_BUILD_MODULE_DNS;
  for (index = 0u; index < 10u; index++) {
    CHECK(ftun_event_log_record(log, logger, &item, 100u) == FTUN_OK);
  }
  CHECK(ftun_event_log_get_usage(log, &usage) == FTUN_OK && usage.suppressed == 6u);
  /* 旧的错误汇总在进入 silent 前交给旧 sink；silent 内的事件不泄漏到新 sink。 */
  CHECK(ftun_event_log_reconfigure(log, logger, true) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK);
  CHECK(writer.calls == 5u && strstr(writer.output, "suppressed=6") != NULL);
  for (index = 0u; index < 8u; index++) {
    CHECK(ftun_event_log_record(log, NULL, &item, 101u) == FTUN_OK);
  }
  CHECK(ftun_event_log_reconfigure(log, NULL, false) == FTUN_OK);
  CHECK(ftun_event_log_record(log, logger, &item, 102u) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && writer.calls == 6u);
  CHECK(ftun_event_log_get_usage(log, &usage) == FTUN_OK &&
    usage.filtered_without_sink == 5u && usage.suppressed == 10u);
  CHECK(strstr(writer.output, "suppressed=4") == NULL);
  CHECK(ftun_event_log_finish(log, logger) == FTUN_OK);
  CHECK(ftun_event_log_reconfigure(log, logger, true) == FTUN_E_STALE);
  CHECK(ftun_event_log_destroy(&log) == FTUN_OK);
  CHECK(ftun_logger_destroy(&logger) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int test_rate_and_failures(void)
{
  ftun_budget_t *budget = NULL;
  ftun_event_log_t *log = NULL;
  ftun_logger_t *logger = NULL;
  ftun_event_log_usage_t usage;
  ftun_logger_usage_t output;
  writer_t writer = {0};
  ftun_lifecycle_event_t item = event(FTUN_LIFECYCLE_STOP_FAILED, 5u, FTUN_E_IO);
  unsigned int index;
  CHECK(ftun_budget_create(NULL, 131072u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_event_log_create(budget, &log) == FTUN_OK);
  CHECK(ftun_event_log_module_name(log, 0u, "app") == FTUN_OK);
  CHECK(make_logger(&writer, FTUN_LOG_INFO, &logger) == FTUN_OK);
  CHECK(ftun_event_log_publish(log, logger, false) == FTUN_OK);
  for (index = 0u; index < 100u; index++) {
    CHECK(ftun_event_log_record(log, logger, &item, 100u) == FTUN_OK);
  }
  CHECK(ftun_event_log_record(log, logger, &item, 1099u) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && writer.calls == 4u);
  CHECK(ftun_event_log_record(log, logger, &item, 1100u) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && writer.calls == 6u);
  CHECK(strstr(writer.output, "generation=5 reason=none suppressed=97") != NULL);
  for (index = 0u; index < 4u; index++) {
    CHECK(ftun_event_log_record(log, logger, &item, 1100u) == FTUN_OK);
  }
  item.generation = 6u;
  CHECK(ftun_event_log_record(log, logger, &item, 1100u) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && writer.calls == 11u);
  CHECK(strstr(writer.output, "generation=5 reason=none suppressed=1") != NULL);
  CHECK(strstr(writer.output, "generation=6 reason=none suppressed=0") != NULL);
  /* 时钟回退开启新窗口，不能把减法下溢当作无限期压制。 */
  CHECK(ftun_event_log_record(log, logger, &item, 10u) == FTUN_OK);
  CHECK(ftun_event_log_finish(log, logger) == FTUN_OK);
  CHECK(ftun_event_log_get_usage(log, &usage) == FTUN_OK && usage.suppressed == 98u);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && writer.calls == 12u);
  CHECK(ftun_event_log_begin(log) == FTUN_OK);
  CHECK(ftun_event_log_publish(log, logger, false) == FTUN_OK);
  /* 缺失句柄与异步 writer IO 是不同状态，不把 enqueue 当作交付。 */
  CHECK(ftun_event_log_record(log, NULL, &item, 20u) == FTUN_E_AGAIN);
  CHECK(ftun_event_log_get_usage(log, &usage) == FTUN_OK && usage.unavailable == 1u);
  CHECK(ftun_logger_destroy(&logger) == FTUN_OK);
  memset(&writer, 0, sizeof(writer));
  writer.fail = true;
  CHECK(make_logger(&writer, FTUN_LOG_INFO, &logger) == FTUN_OK);
  CHECK(ftun_event_log_record(log, logger, &item, 21u) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK);
  CHECK(ftun_logger_get_usage(logger, &output) == FTUN_OK && output.io_errors == 1u);
  CHECK(ftun_event_log_finish(log, logger) == FTUN_OK);
  CHECK(ftun_logger_destroy(&logger) == FTUN_OK);
  CHECK(ftun_event_log_destroy(&log) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int test_limits(void)
{
  ftun_budget_t *budget = NULL;
  ftun_event_log_t *log = NULL;
  ftun_budget_options_t options = {0};
  ftun_budget_usage_t resources;
  ftun_event_log_usage_t usage;
  ftun_lifecycle_event_t item = event(FTUN_LIFECYCLE_STARTING, 1u, FTUN_OK);
  options.limit.memory_bytes = 65536u;
  options.limit.queue_slots = 15u;
  CHECK(ftun_budget_create_resources(NULL, &options, &budget) == FTUN_OK);
  CHECK(ftun_event_log_create(budget, &log) == FTUN_E_LIMIT && log == NULL);
  CHECK(ftun_budget_get_usage(budget, &resources) == FTUN_OK && resources.used == 0u &&
    resources.used_resources.queue_slots == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  options.limit.memory_bytes = 1u;
  options.limit.queue_slots = 16u;
  CHECK(ftun_budget_create_resources(NULL, &options, &budget) == FTUN_OK);
  CHECK(ftun_event_log_create(budget, &log) == FTUN_E_LIMIT && log == NULL);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(ftun_budget_create(NULL, 131072u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_event_log_create(budget, &log) == FTUN_OK);
  CHECK(ftun_event_log_module_name(log, 0u, "app") == FTUN_OK);
  item.kind = FTUN_LIFECYCLE_COUNT;
  CHECK(ftun_event_log_record(log, NULL, &item, 0u) == FTUN_E_INVALID);
  item.kind = FTUN_LIFECYCLE_STARTING;
  item.reason = FTUN_LIFECYCLE_REASON_COUNT;
  CHECK(ftun_event_log_record(log, NULL, &item, 0u) == FTUN_E_INVALID);
  item.reason = FTUN_LIFECYCLE_REASON_NONE;
  item.module = FTUN_BUILD_MODULE_PROXY | FTUN_BUILD_MODULE_DNS;
  CHECK(ftun_event_log_record(log, NULL, &item, 0u) == FTUN_E_INVALID);

  item.module = 0u;
  item.status = (ftun_status_t)999;
  CHECK(ftun_event_log_record(log, NULL, &item, 0u) == FTUN_E_INVALID);
  CHECK(ftun_event_log_get_usage(log, &usage) == FTUN_OK && usage.recorded == 0u);
  item.module = UINT32_C(0x80000000);
  item.status = FTUN_OK;
  CHECK(ftun_event_log_module_name(log, item.module, "independent") == FTUN_OK);
  CHECK(ftun_event_log_record(log, NULL, &item, 0u) == FTUN_OK);
  CHECK(ftun_event_log_get_usage(log, &usage) == FTUN_OK && usage.recorded == 1u);
  CHECK(ftun_event_log_destroy(&log) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

typedef struct {
  ftun_event_log_t *log;
  ftun_logger_t *logger;
  unsigned int index;
  int failed;
} producer_t;

static void *produce(void *user)
{
  producer_t *producer = user;
  ftun_lifecycle_event_t item = event(FTUN_LIFECYCLE_MODULE_FAILED, 7u, FTUN_E_IO);
  unsigned int index;
  item.module = (uint32_t)1u << producer->index;
  for (index = 0u; index < 2000u; index++) {
    ftun_event_log_usage_t usage;
    if (ftun_event_log_record(producer->log, producer->logger, &item, 0u) != FTUN_OK ||
        ftun_event_log_get_usage(producer->log, &usage) != FTUN_OK ||
        !usage.has_error || usage.last_error.status != FTUN_E_IO) producer->failed = 1;
  }
  return NULL;
}

static void *produce_diagnostics(void *user)
{
  producer_t *producer = user;
  ftun_diagnostic_event_t item = {0};
  unsigned int index;
  item.kind = (ftun_diagnostic_kind_t)(1u + producer->index);
  item.error.status = FTUN_E_IO;
  item.generation = 7u;
  memcpy(item.message, "background failure", 19u);
  for (index = 0u; index < 2000u; index++) {
    ftun_event_log_usage_t usage;
    if (ftun_event_log_diagnostic(producer->log, producer->logger, &item, 0u) != FTUN_OK ||
        ftun_event_log_get_usage(producer->log, &usage) != FTUN_OK ||
        !usage.has_diagnostic || usage.last_diagnostic.error.status != FTUN_E_IO) producer->failed = 1;
  }
  return NULL;
}

static int test_concurrent(void)
{
  ftun_budget_t *budget = NULL;
  ftun_event_log_t *log = NULL;
  ftun_logger_t *logger = NULL;
  ftun_event_log_usage_t usage;
  writer_t writer = {0};
  producer_t producers[4];
  pthread_t threads[4];
  unsigned int index;
  CHECK(ftun_budget_create(NULL, 131072u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_event_log_create(budget, &log) == FTUN_OK);
  CHECK(ftun_event_log_module_name(log, 0u, "app") == FTUN_OK);
  CHECK(make_logger(&writer, FTUN_LOG_INFO, &logger) == FTUN_OK);
  CHECK(ftun_event_log_publish(log, logger, false) == FTUN_OK);
  for (index = 0u; index < 4u; index++) {
    producers[index] = (producer_t){log, logger, index, 0};
    CHECK(pthread_create(&threads[index], NULL, produce, &producers[index]) == 0);
  }
  for (index = 0u; index < 4u; index++) {
    CHECK(pthread_join(threads[index], NULL) == 0 && !producers[index].failed);
  }
  CHECK(ftun_event_log_finish(log, logger) == FTUN_OK);
  CHECK(ftun_event_log_get_usage(log, &usage) == FTUN_OK && usage.recorded == 8000u &&
    usage.suppressed == 7984u && usage.forwarded == 20u);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && writer.calls == 20u);
  CHECK(ftun_event_log_begin(log) == FTUN_OK);
  CHECK(ftun_event_log_publish(log, logger, false) == FTUN_OK);
  for (index = 0u; index < 4u; index++) {
    CHECK(pthread_create(&threads[index], NULL, produce_diagnostics, &producers[index]) == 0);
  }
  for (index = 0u; index < 4u; index++) {
    CHECK(pthread_join(threads[index], NULL) == 0 && !producers[index].failed);
  }
  CHECK(ftun_event_log_finish(log, logger) == FTUN_OK);
  CHECK(ftun_event_log_get_usage(log, &usage) == FTUN_OK && usage.diagnostics == 8000u &&
    usage.diagnostic_suppressed == 7984u && usage.forwarded == 40u);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && writer.calls == 40u);
  CHECK(ftun_event_log_destroy(&log) == FTUN_OK);
  CHECK(ftun_logger_destroy(&logger) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  ftun_core_t *core;
  uint64_t accepted;
  bool started;
  bool detached;
  bool stop;
  int failed;
} core_producer_t;

static void *produce_core(void *user)
{
  core_producer_t *producer = user;
  ftun_lifecycle_event_t item = event(FTUN_LIFECYCLE_MODULE_FAILED, 9u, FTUN_E_IO);
  for (;;) {
    ftun_status_t status = ftun_lifecycle_emit(producer->core, &item);
    bool stop;
    (void)pthread_mutex_lock(&producer->mutex);
    if (status == FTUN_OK) producer->accepted++;
    else if (status == FTUN_E_AGAIN) producer->detached = true;
    else producer->failed = 1;
    producer->started = true;
    stop = producer->stop;
    (void)pthread_cond_signal(&producer->condition);
    (void)pthread_mutex_unlock(&producer->mutex);
    if (stop) return NULL;
  }
}

static int test_core_retirement(void)
{
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_event_log_t *log = NULL;
  ftun_logger_t *logger = NULL;
  ftun_logger_t *next = NULL;
  ftun_event_log_usage_t usage;
  writer_t writers[2] = {0};
  ftun_lifecycle_event_t item = event(FTUN_LIFECYCLE_STARTING, 9u, FTUN_OK);
  core_producer_t producer;
  pthread_t thread;
  unsigned int index;
  memset(&producer, 0, sizeof(producer));
  CHECK(pthread_mutex_init(&producer.mutex, NULL) == 0);
  CHECK(pthread_cond_init(&producer.condition, NULL) == 0);
  CHECK(ftun_budget_create(NULL, 131072u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_lifecycle_emit(core, &item) == FTUN_E_AGAIN);
  CHECK(ftun_event_log_create(budget, &log) == FTUN_OK);
  CHECK(ftun_event_log_module_name(log, 0u, "app") == FTUN_OK);
  CHECK(ftun_core_context_set_event_log(core, log) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_E_AGAIN && core != NULL);
  CHECK(ftun_lifecycle_emit(core, &item) == FTUN_OK);
  CHECK(make_logger(&writers[0], FTUN_LOG_INFO, &logger) == FTUN_OK);
  CHECK(ftun_core_context_publish_logger(core, logger, false) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && writers[0].calls == 1u);
  producer.core = core;
  CHECK(pthread_create(&thread, NULL, produce_core, &producer) == 0);
  (void)pthread_mutex_lock(&producer.mutex);
  while (!producer.started) (void)pthread_cond_wait(&producer.condition, &producer.mutex);
  (void)pthread_mutex_unlock(&producer.mutex);
  for (index = 1u; index <= 20u; index++) {
    memset(&writers[index % 2u], 0, sizeof(writers[0]));
    CHECK(make_logger(&writers[index % 2u], FTUN_LOG_INFO, &next) == FTUN_OK);
    CHECK(ftun_core_context_publish_logger(core, next, false) == FTUN_OK);
    CHECK(ftun_logger_destroy(&logger) == FTUN_OK);
    logger = next;
    next = NULL;
  }
  CHECK(ftun_core_context_set_event_log(core, NULL) == FTUN_OK);
  CHECK(ftun_event_log_finish(log, logger) == FTUN_OK);
  CHECK(ftun_event_log_get_usage(log, &usage) == FTUN_OK);
  CHECK(ftun_event_log_destroy(&log) == FTUN_OK);
  /* 生产线程在撤销及释放后继续调用，确认不会借用已经释放的记录器。 */
  (void)pthread_mutex_lock(&producer.mutex);
  while (!producer.detached) (void)pthread_cond_wait(&producer.condition, &producer.mutex);
  producer.stop = true;
  (void)pthread_mutex_unlock(&producer.mutex);
  CHECK(pthread_join(thread, NULL) == 0 && !producer.failed);
  CHECK(usage.recorded == producer.accepted + 1u);
  CHECK(ftun_core_context_set_logger(core, NULL) == FTUN_OK);
  CHECK(ftun_logger_destroy(&logger) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(pthread_cond_destroy(&producer.condition) == 0);
  CHECK(pthread_mutex_destroy(&producer.mutex) == 0);
  return 0;
}

static int test_terminal(void)
{
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_event_log_t *log = NULL;
  ftun_logger_t *logger = NULL;
  ftun_event_log_usage_t usage;
  writer_t writer = {0};
  ftun_lifecycle_event_t item = event(FTUN_LIFECYCLE_MODULE_FAILED, 8u, FTUN_E_IO);
  ftun_lifecycle_event_t terminal = event(FTUN_LIFECYCLE_STOPPED, 8u, FTUN_OK);
  ftun_diagnostic_t diagnostic = {0};
  const char *summary, *last;
  unsigned int index;
  terminal.reason = FTUN_LIFECYCLE_REASON_LOG_DRAINING;
  CHECK(ftun_budget_create(NULL, 131072u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_event_log_create(budget, &log) == FTUN_OK);
  CHECK(ftun_event_log_module_name(log, 0u, "app") == FTUN_OK);
  CHECK(ftun_core_context_set_event_log(core, log) == FTUN_OK);
  CHECK(make_logger(&writer, FTUN_LOG_INFO, &logger) == FTUN_OK);
  CHECK(ftun_core_context_publish_logger(core, logger, false) == FTUN_OK);
  for (index = 0u; index < 10u; index++) {
    CHECK(ftun_event_log_record(log, logger, &item, 0u) == FTUN_OK);
  }
  CHECK(ftun_core_context_finish_logging(core, &terminal) == FTUN_OK);
  CHECK(ftun_core_context_finish_logging(core, &terminal) == FTUN_OK);
  CHECK(ftun_lifecycle_emit(core, &item) == FTUN_E_CANCELLED);
  CHECK(ftun_log_emit(core, &diagnostic) == FTUN_E_AGAIN);
  CHECK(ftun_core_context_publish_logger(core, logger, false) == FTUN_E_STALE);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && writer.calls == 6u);
  summary = strstr(writer.output, "suppressed=6");
  last = strstr(writer.output, "event=runtime.stopped module=app generation=8 reason=log-draining");
  CHECK(summary != NULL && last != NULL && summary < last &&
    strchr(last, '\n') == writer.output + writer.length - 1u);
  CHECK(ftun_event_log_get_usage(log, &usage) == FTUN_OK && usage.closed &&
    usage.recorded == 11u && usage.last.kind == FTUN_LIFECYCLE_STOPPED &&
    usage.last_error.kind == FTUN_LIFECYCLE_MODULE_FAILED);
  CHECK(ftun_event_log_begin(log) == FTUN_OK);
  terminal.status = FTUN_E_IO;
  CHECK(ftun_core_context_finish_logging(core, &terminal) == FTUN_OK);
  CHECK(ftun_event_log_get_usage(log, &usage) == FTUN_OK && usage.closed &&
    usage.early_dropped == 1u && usage.recorded == 12u &&
    usage.last_error.kind == FTUN_LIFECYCLE_STOPPED);
  CHECK(ftun_core_context_set_event_log(core, NULL) == FTUN_OK);
  CHECK(ftun_event_log_destroy(&log) == FTUN_OK);
  CHECK(ftun_logger_destroy(&logger) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int test_diagnostics(void)
{
  ftun_budget_t *budget = NULL;
  ftun_event_log_t *log = NULL;
  ftun_logger_t *logger = NULL;
  ftun_event_log_usage_t usage;
  writer_t writer = {0};
  ftun_diagnostic_event_t item = {0};
  ftun_lifecycle_event_t first = event(FTUN_LIFECYCLE_STARTING, 1u, FTUN_OK);
  ftun_lifecycle_event_t terminal = event(FTUN_LIFECYCLE_STOPPED, 2u, FTUN_OK);
  unsigned int index;
  size_t before;
  CHECK(ftun_budget_create(NULL, 131072u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_event_log_create(budget, &log) == FTUN_OK);
  CHECK(ftun_event_log_module_name(log, 0u, "app") == FTUN_OK);
  CHECK(make_logger(&writer, FTUN_LOG_INFO, &logger) == FTUN_OK);
  item.kind = 1u;
  item.generation = 1u;
  item.error.status = FTUN_E_IO;
  item.error.stage = FTUN_STAGE_CONTROL;
  memcpy(item.message, "state save failed", 18u);
  CHECK(ftun_event_log_record(log, NULL, &first, 0u) == FTUN_OK);
  CHECK(ftun_event_log_diagnostic(log, NULL, &item, 0u) == FTUN_OK);
  memset(item.message, 0, sizeof(item.message));
  memcpy(item.message, "changed diagnostic", 19u);
  CHECK(ftun_event_log_publish(log, logger, false) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && writer.calls == 2u);
  CHECK(strstr(writer.output, "event=starting ") != NULL &&
    strstr(writer.output, "message=state save failed") != NULL &&
    strstr(writer.output, "event=starting ") < strstr(writer.output, "message=state save failed"));
  CHECK(strstr(writer.output, "changed diagnostic") == NULL);
  for (index = 0u; index < 100u; index++) {
    CHECK(ftun_event_log_diagnostic(log, logger, &item, 1u) == FTUN_OK);
  }
  CHECK(ftun_event_log_get_usage(log, &usage) == FTUN_OK &&
    usage.diagnostics == 101u && usage.diagnostic_suppressed == 96u &&
    usage.last_diagnostic.error.status == FTUN_E_IO);
  /* 窗口变化、代次和原生错误变化均保留新诊断，旧汇总先输出。 */
  CHECK(ftun_event_log_diagnostic(log, logger, &item, 1001u) == FTUN_OK);
  for (index = 0u; index < 9u; index++) {
    CHECK(ftun_event_log_diagnostic(log, logger, &item, 1001u) == FTUN_OK);
  }
  item.generation = 2u;
  CHECK(ftun_event_log_diagnostic(log, logger, &item, 1001u) == FTUN_OK);
  item.error.native_code = 5;
  CHECK(ftun_event_log_diagnostic(log, logger, &item, 1001u) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK);
  CHECK(strstr(writer.output, "generation=1 suppressed=96 changed diagnostic") != NULL &&
    strstr(writer.output, "generation=1 suppressed=6 changed diagnostic") != NULL);
  CHECK(ftun_event_log_reconfigure(log, logger, true) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK);
  before = writer.calls;
  for (index = 0u; index < 10u; index++) {
    CHECK(ftun_event_log_diagnostic(log, NULL, &item, 1001u) == FTUN_OK);
  }
  CHECK(ftun_event_log_reconfigure(log, NULL, false) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && writer.calls == before);
  for (index = 0u; index < 10u; index++) {
    CHECK(ftun_event_log_diagnostic(log, logger, &item, 1001u) == FTUN_OK);
  }
  CHECK(ftun_event_log_finish_with(log, logger, &terminal) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && writer.calls == before + 6u);
  CHECK(strstr(writer.output, "generation=2 suppressed=6 changed diagnostic") != NULL);
  CHECK(ftun_event_log_diagnostic(log, logger, &item, 1001u) == FTUN_E_CANCELLED);
  item.kind = FTUN_DIAGNOSTIC_COUNT;
  CHECK(ftun_event_log_diagnostic(log, logger, &item, 1001u) == FTUN_E_INVALID);
  item.kind = 2u;
  memset(item.message, 'x', sizeof(item.message));
  CHECK(ftun_event_log_diagnostic(log, logger, &item, 1001u) == FTUN_E_INVALID);
  CHECK(ftun_event_log_destroy(&log) == FTUN_OK);
  CHECK(ftun_logger_destroy(&logger) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(void)
{
  CHECK(test_early() == 0);
  CHECK(test_filter_and_switch() == 0);
  CHECK(test_rate_and_failures() == 0);
  CHECK(test_limits() == 0);
  CHECK(test_concurrent() == 0);
  CHECK(test_core_retirement() == 0);
  CHECK(test_terminal() == 0);
  CHECK(test_diagnostics() == 0);
  puts("Event log contract OK");
  return 0;
}
