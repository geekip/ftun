#define _GNU_SOURCE 1
#include <sys/types.h>
#include "core/limits.h"
#include "core/context.h"
#include "core/log/log.h"
#include "platform/clock.h"

#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
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

static int test_basic(void)
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
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_core_context_set_logger(core, logger) == FTUN_OK);
  item = diagnostic("/runtime", "reload failed");
  CHECK(ftun_log_emit(core, &item) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK);
  CHECK(ftun_core_context_set_logger(core, NULL) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
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
          FTUN_LOG_INFO, "/no/such/directory/ftun.log", 1u, 128u, NULL, NULL, NULL, false, 0u, 0u},
        &logger) == FTUN_E_IO && logger == NULL);
  CHECK(pthread_cond_destroy(&writer.condition) == 0);
  CHECK(pthread_mutex_destroy(&writer.mutex) == 0);
  return 0;
}

static int capture_init(writer_t *writer)
{
  memset(writer, 0, sizeof(*writer));
  CHECK(pthread_mutex_init(&writer->mutex, NULL) == 0);
  CHECK(pthread_cond_init(&writer->condition, NULL) == 0);
  return 0;
}

static int capture_reset(writer_t *writer)
{
  CHECK(pthread_mutex_lock(&writer->mutex) == 0);
  writer->length = 0u;
  writer->calls = 0u;
  CHECK(pthread_mutex_unlock(&writer->mutex) == 0);
  return 0;
}

static int capture_destroy(writer_t *writer)
{
  CHECK(pthread_cond_destroy(&writer->condition) == 0);
  CHECK(pthread_mutex_destroy(&writer->mutex) == 0);
  return 0;
}

static int record_valid(const writer_t *writer)
{
  size_t index;
  if (writer->calls != 1u || writer->length == 0u ||
      writer->output[writer->length - 1u] != '\n' ||
      !contains(writer->output, writer->length, " message=")) return 0;
  for (index = 0u; index + 1u < writer->length; index++) {
    unsigned char byte = (unsigned char)writer->output[index];
    if (byte < 0x20u || byte == 0x7fu) return 0;
  }
  return 1;
}

/* 带时间戳的前缀：ts 为 UTC 毫秒，seq 单调，boot 在进程内固定，id 仅在非零时出现。 */
static int stamped_line(writer_t *writer, uint64_t *seq, char *boot, bool *has_id,
  uint64_t *id, size_t *ts_ms)
{
  unsigned int year, month, day, hour, minute, second, millis;
  unsigned long long sequence, correlation = 0u;
  char hex[32];
  const char *cursor = writer->output;
  int consumed = 0;
  if (sscanf(cursor, "ts=%4u-%2u-%2uT%2u:%2u:%2u.%3uZ seq=%llu boot=%16[0-9a-f] %n",
             &year, &month, &day, &hour, &minute, &second, &millis, &sequence,
             hex, &consumed) != 9 || consumed == 0 || strlen(hex) != 16u) return 0;
  if (year < 2024u || month < 1u || month > 12u || day < 1u || day > 31u ||
      hour > 23u || minute > 59u || second > 60u || millis > 999u) return 0;
  *has_id = sscanf(cursor + consumed, "id=%llu ", &correlation) == 1;
  if (*has_id) {
    char text[40];
    int id_width = snprintf(text, sizeof(text), "id=%llu ", correlation);
    consumed += id_width;
  }
  if (strncmp(cursor + consumed, "level=", 6u) != 0) return 0;
  *seq = sequence;
  *id = correlation;
  *ts_ms = ((size_t)hour * 3600u + (size_t)minute * 60u + second) * 1000u + millis;
  memcpy(boot, hex, 17u);
  return 1;
}

static int test_stamp(void)
{
  writer_t writer;
  ftun_logger_t *logger = NULL;
  ftun_logger_options_t options;
  ftun_diagnostic_t item;
  uint64_t sequence[3], id = 0u, first_id;
  char boot[3][17];
  bool has_id = false;
  size_t ts = 0u, round;
  CHECK(capture_init(&writer) == 0);
  memset(&options, 0, sizeof(options));
  options.level = FTUN_LOG_ERROR;
  options.queue_capacity = 4u;
  options.line_capacity = 256u;
  options.writer = write_line;
  options.writer_user = &writer;
  options.stamp = true;
  CHECK(ftun_logger_create(&options, &logger) == FTUN_OK);
  for (round = 0u; round < 3u; round++) {
    item = diagnostic("", "stamped");
    item.correlation = round == 1u ? ftun_correlation_next() : 0u;
    if (round == 1u) first_id = item.correlation;
    CHECK(ftun_logger_write(logger, FTUN_LOG_ERROR, &item) == FTUN_OK);
    CHECK(ftun_logger_flush(logger) == FTUN_OK);
    CHECK(stamped_line(&writer, &sequence[round], boot[round], &has_id, &id, &ts) == 1);
    CHECK(has_id == (round == 1u));
    if (round == 1u) CHECK(id == first_id && id != 0u);
    CHECK(capture_reset(&writer) == 0);
  }
  CHECK(sequence[1] > sequence[0] && sequence[2] > sequence[1]);
  CHECK(strcmp(boot[0], boot[1]) == 0 && strcmp(boot[1], boot[2]) == 0);
  CHECK(ftun_log_boot_id() != 0u && ftun_correlation_next() > first_id);
  CHECK(ftun_logger_destroy(&logger) == FTUN_OK);
  return 0;
}

static int test_format_and_bound(void)
{
  static const char path[] = {'/', 'x', '\n', '\r', '\t', '\\', 0, 1, 127};
  static const char expected[] =
    "level=error status=io stage=7 native=28 "
    "path=/x\\n\\r\\t\\\\\\0\\x01\\x7f message=a\\nb\\rc\\t\\\\\n";
  writer_t writer;
  ftun_logger_t *logger = NULL;
  ftun_logger_options_t options;
  ftun_logger_usage_t usage;
  ftun_diagnostic_t item;
  long page = sysconf(_SC_PAGESIZE);
  char *mapping;
  char *field;
  size_t index;
  CHECK(page >= 4096);
  mapping = (char *)mmap(NULL, (size_t)page * 2u, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(mapping != MAP_FAILED);
  CHECK(mprotect(mapping + page, (size_t)page, PROT_NONE) == 0);
  field = mapping + page - 4096;
  CHECK(capture_init(&writer) == 0);
  memset(&options, 0, sizeof(options));
  options.level = FTUN_LOG_ERROR;
  options.queue_capacity = 2u;
  options.line_capacity = 256u;
  options.writer = write_line;
  options.writer_user = &writer;
  CHECK(ftun_logger_create(&options, &logger) == FTUN_OK);
  item = diagnostic("/plain", "ordinary failure");
  CHECK(ftun_logger_write(logger, FTUN_LOG_ERROR, &item) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK);
  CHECK(writer.length == strlen("level=error status=io stage=7 native=28 "
    "path=/plain message=ordinary failure\n"));
  CHECK(memcmp(writer.output, "level=error status=io stage=7 native=28 "
    "path=/plain message=ordinary failure\n", writer.length) == 0);
  CHECK(capture_reset(&writer) == 0);
  item = diagnostic("", "a\nb\rc\t\\");
  item.path = (ftun_string_t){path, sizeof(path)};
  CHECK(ftun_logger_write(logger, FTUN_LOG_ERROR, &item) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK);
  CHECK(record_valid(&writer));
  CHECK(writer.length == sizeof(expected) - 1u &&
        memcmp(writer.output, expected, writer.length) == 0);
  CHECK(capture_reset(&writer) == 0);

  /* 敏感键位于最终显示边界之后，并恰好在 guard page 前结束。 */
  memset(field, 'a', 4096u);
  memcpy(field + 4088u, "PaSsWoRd", 8u);
  item = diagnostic("/safe", "");
  item.message = (ftun_string_t){field, 4096u};
  CHECK(ftun_logger_write(logger, FTUN_LOG_ERROR, &item) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK);
  CHECK(record_valid(&writer) &&
        contains(writer.output, writer.length, "[redacted diagnostic]") &&
        !contains(writer.output, writer.length, "aaaa"));
  CHECK(capture_reset(&writer) == 0);
  item.path = item.message;
  item.message = (ftun_string_t){"private-value", 13u};
  CHECK(ftun_logger_write(logger, FTUN_LOG_ERROR, &item) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK);
  CHECK(record_valid(&writer) &&
        !contains(writer.output, writer.length, "private-value"));
  CHECK(capture_reset(&writer) == 0);

  /* 超长字段不得探测任何前缀；另一个字段也不可先进入敏感扫描。 */
  item.path = (ftun_string_t){mapping + page, 4096u};
  item.message = (ftun_string_t){mapping + page, SIZE_MAX};
  CHECK(ftun_logger_write(logger, FTUN_LOG_ERROR, &item) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK);
  CHECK(record_valid(&writer) &&
        contains(writer.output, writer.length, "[redacted diagnostic]"));
  CHECK(capture_reset(&writer) == 0);
  item.path.length = SIZE_MAX;
  item.message.length = 4096u;
  CHECK(ftun_logger_write(logger, FTUN_LOG_ERROR, &item) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK);
  CHECK(ftun_logger_get_usage(logger, &usage) == FTUN_OK &&
        usage.redacted == 4u && usage.oversized == 2u &&
        usage.truncated == 0u);
  CHECK(ftun_logger_destroy(&logger) == FTUN_OK);

  for (index = 128u; index <= 132u; index++) {
    CHECK(capture_reset(&writer) == 0);
    options.line_capacity = index;
    CHECK(ftun_logger_create(&options, &logger) == FTUN_OK);
    memset(field, 1, 4096u);
    item = diagnostic("/path", "");
    item.message = (ftun_string_t){field, 4096u};
    CHECK(ftun_logger_write(logger, FTUN_LOG_ERROR, &item) == FTUN_OK);
    CHECK(ftun_logger_flush(logger) == FTUN_OK);
    CHECK(record_valid(&writer) && writer.length < index &&
          contains(writer.output, writer.length, "...\n"));
    CHECK(ftun_logger_get_usage(logger, &usage) == FTUN_OK &&
          usage.truncated == 1u && usage.redacted == 0u);
    CHECK(capture_reset(&writer) == 0);
    item.path = item.message;
    item.message = (ftun_string_t){"last", 4u};
    CHECK(ftun_logger_write(logger, FTUN_LOG_ERROR, &item) == FTUN_OK);
    CHECK(ftun_logger_flush(logger) == FTUN_OK);
    CHECK(record_valid(&writer) && writer.length < index);
    CHECK(ftun_logger_destroy(&logger) == FTUN_OK);
  }
  CHECK(munmap(mapping, (size_t)page * 2u) == 0);
  CHECK(capture_destroy(&writer) == 0);
  return 0;
}

typedef struct {
  ftun_logger_t *logger;
  uint64_t calls;
  int invalid;
} counting_writer_t;

static ftun_status_t count_line(void *user, ftun_bytes_t line)
{
  counting_writer_t *writer = (counting_writer_t *)user;
  ftun_logger_usage_t usage;
  size_t index;
  /* writer 可重新取得 queue mutex：I/O 不能在队列锁内执行。 */
  if (ftun_logger_get_usage(writer->logger, &usage) != FTUN_OK ||
      usage.queued == 0u || line.length == 0u ||
      line.data[line.length - 1u] != '\n') writer->invalid = 1;
  for (index = 0u; index + 1u < line.length; index++) {
    if (line.data[index] < 0x20u || line.data[index] == 0x7fu) {
      writer->invalid = 1;
    }
  }
  writer->calls++;
  return FTUN_OK;
}

typedef struct {
  ftun_core_t *core;
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  unsigned int ready;
  int started;
  int stopped;
  int invalid;
  uint64_t accepted;
  uint64_t absent;
} producers_t;

static void *produce_lines(void *user)
{
  producers_t *state = (producers_t *)user;
  ftun_diagnostic_t item = diagnostic("/concurrent", "reload failure");
  (void)pthread_mutex_lock(&state->mutex);
  state->ready++;
  (void)pthread_cond_broadcast(&state->condition);
  while (!state->started) {
    (void)pthread_cond_wait(&state->condition, &state->mutex);
  }
  (void)pthread_mutex_unlock(&state->mutex);
  for (;;) {
    ftun_status_t status;
    (void)pthread_mutex_lock(&state->mutex);
    if (state->stopped) {
      (void)pthread_mutex_unlock(&state->mutex);
      break;
    }
    (void)pthread_mutex_unlock(&state->mutex);
    status = ftun_log_emit(state->core, &item);
    (void)pthread_mutex_lock(&state->mutex);
    if (status == FTUN_OK) state->accepted++;
    else if (status == FTUN_E_AGAIN) state->absent++;
    else state->invalid = 1;
    (void)pthread_mutex_unlock(&state->mutex);
  }
  return NULL;
}

static int wait_producers(producers_t *state, uint64_t minimum, int absent)
{
  uint64_t start = 0u;
  uint64_t now = 0u;
  struct timespec pause = {0, 1000000};
  CHECK(ftun_monotonic_now(&start) == FTUN_OK);
  do {
    uint64_t count;
    CHECK(pthread_mutex_lock(&state->mutex) == 0);
    count = absent ? state->absent : state->accepted;
    CHECK(pthread_mutex_unlock(&state->mutex) == 0);
    if (count >= minimum) return 0;
    (void)nanosleep(&pause, NULL);
    CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  } while (now - start < 5000u);
  return 1;
}

static int test_publish_concurrency(void)
{
  enum { PRODUCERS = 4, ROUNDS = 32 };
  producers_t state;
  counting_writer_t writers[ROUNDS + 1];
  ftun_log_ledger_t *ledger = NULL;
  ftun_log_totals_t totals;
  ftun_budget_t *budget = NULL;
  ftun_budget_t *alternate_budget = NULL;
  ftun_core_t *core = NULL;
  ftun_logger_t *active = NULL;
  ftun_logger_t *next = NULL;
  ftun_logger_options_t options;
  pthread_t threads[PRODUCERS];
  ftun_logger_usage_t usage;
  uint64_t emitted = 0u;
  uint64_t dropped = 0u;
  uint64_t target = 0u;
  unsigned int round;
  unsigned int index;
  memset(&state, 0, sizeof(state));
  memset(writers, 0, sizeof(writers));
  memset(&options, 0, sizeof(options));
  CHECK(pthread_mutex_init(&state.mutex, NULL) == 0);
  CHECK(pthread_cond_init(&state.condition, NULL) == 0);
  CHECK(ftun_budget_create(NULL, 65536u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_budget_create(NULL, 65536u, 0u, &alternate_budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  state.core = core;
  CHECK(ftun_log_ledger_create(budget, &ledger) == FTUN_OK);
  options.ledger = ledger;
  options.level = FTUN_LOG_ERROR;
  options.line_capacity = 128u;
  options.queue_capacity = 8u;
  options.writer = count_line;
  options.writer_user = &writers[0];
  CHECK(ftun_logger_create(&options, &active) == FTUN_OK);
  writers[0].logger = active;
  CHECK(ftun_core_context_set_logger(core, active) == FTUN_OK);
  for (index = 0u; index < PRODUCERS; index++) {
    CHECK(pthread_create(&threads[index], NULL, produce_lines, &state) == 0);
  }
  CHECK(pthread_mutex_lock(&state.mutex) == 0);
  while (state.ready != PRODUCERS) {
    CHECK(pthread_cond_wait(&state.condition, &state.mutex) == 0);
  }
  state.started = 1;
  CHECK(pthread_cond_broadcast(&state.condition) == 0);
  CHECK(pthread_mutex_unlock(&state.mutex) == 0);
  for (round = 1u; round <= ROUNDS; round++) {
    uint64_t deadline = 0u;
    CHECK(pthread_mutex_lock(&state.mutex) == 0);
    target = state.accepted + 64u;
    CHECK(pthread_mutex_unlock(&state.mutex) == 0);
    CHECK(wait_producers(&state, target, 0) == 0);
    CHECK(ftun_core_context_set_budget(core,
          (round % 2u) ? alternate_budget : budget) == FTUN_OK);
    options.writer_user = &writers[round];
    CHECK(ftun_logger_create(&options, &next) == FTUN_OK);
    CHECK(ftun_log_ledger_get_usage(ledger, &totals) == FTUN_OK &&
      totals.instances == 2u && totals.capacity == 16u &&
      totals.emitted == totals.written + totals.io_errors + totals.queued);
    writers[round].logger = next;
    if ((round % 4u) == 0u) {
      uint64_t absent;
      CHECK(pthread_mutex_lock(&state.mutex) == 0);
      absent = state.absent;
      CHECK(pthread_mutex_unlock(&state.mutex) == 0);
      CHECK(ftun_core_context_set_logger(core, NULL) == FTUN_OK);
      CHECK(wait_producers(&state, absent + 16u, 1) == 0);
    }
    CHECK(ftun_core_context_set_logger(core, next) == FTUN_OK);
    CHECK(ftun_logger_stop(active) == FTUN_OK);
    CHECK(ftun_monotonic_now(&deadline) == FTUN_OK);
    deadline += 5000u;
    CHECK(ftun_logger_join_until(active, deadline) == FTUN_OK);
    CHECK(ftun_logger_get_usage(active, &usage) == FTUN_OK &&
          usage.io_errors == 0u && usage.queued == 0u &&
          usage.emitted == writers[round - 1u].calls &&
          !writers[round - 1u].invalid);
    emitted += usage.emitted;
    dropped += usage.dropped;
    CHECK(ftun_logger_destroy_until(&active, deadline) == FTUN_OK);
    active = next;
    next = NULL;
  }
  CHECK(pthread_mutex_lock(&state.mutex) == 0);
  state.stopped = 1;
  CHECK(pthread_mutex_unlock(&state.mutex) == 0);
  for (index = 0u; index < PRODUCERS; index++) {
    CHECK(pthread_join(threads[index], NULL) == 0);
  }
  CHECK(ftun_core_context_set_logger(core, NULL) == FTUN_OK);
  CHECK(ftun_logger_stop(active) == FTUN_OK);
  CHECK(ftun_logger_join_until(active, UINT64_MAX) == FTUN_OK);
  CHECK(ftun_logger_get_usage(active, &usage) == FTUN_OK &&
        usage.io_errors == 0u && usage.emitted == writers[ROUNDS].calls &&
        !writers[ROUNDS].invalid);
  emitted += usage.emitted;
  dropped += usage.dropped;
  CHECK(!state.invalid && state.accepted >= ROUNDS * 64u &&
        state.absent >= 16u && state.accepted == emitted + dropped);
  printf("logger concurrency: producers=%u swaps=%u accepted=%llu "
         "absent=%llu emitted=%llu dropped=%llu\n", PRODUCERS, ROUNDS,
         (unsigned long long)state.accepted, (unsigned long long)state.absent,
         (unsigned long long)emitted, (unsigned long long)dropped);
  CHECK(ftun_logger_destroy(&active) == FTUN_OK);
  CHECK(ftun_log_ledger_get_usage(ledger, &totals) == FTUN_OK &&
    totals.created == ROUNDS + 1u && totals.destroyed == ROUNDS + 1u &&
    totals.instances == 0u && totals.capacity == 0u && totals.queued == 0u &&
    totals.emitted == emitted && totals.dropped == dropped &&
    totals.written == emitted && totals.io_errors == 0u);
  CHECK(ftun_log_ledger_destroy(&ledger) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&alternate_budget) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(pthread_cond_destroy(&state.condition) == 0);
  CHECK(pthread_mutex_destroy(&state.mutex) == 0);
  return 0;
}

typedef struct {
  ftun_core_t *core;
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  int entered;
  int done;
  ftun_status_t status;
} setter_t;

static void *clear_logger(void *user)
{
  setter_t *setter = (setter_t *)user;
  (void)pthread_mutex_lock(&setter->mutex);
  setter->entered = 1;
  (void)pthread_cond_broadcast(&setter->condition);
  (void)pthread_mutex_unlock(&setter->mutex);
  setter->status = ftun_core_context_set_logger(setter->core, NULL);
  (void)pthread_mutex_lock(&setter->mutex);
  setter->done = 1;
  (void)pthread_mutex_unlock(&setter->mutex);
  return NULL;
}

static int test_guard_scope(void)
{
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_logger_t *logger = NULL;
  ftun_logger_t *borrowed = NULL;
  ftun_logger_options_t options;
  ftun_diagnostic_t item = diagnostic("/guard", "bounded borrow");
  writer_t writer;
  setter_t setter;
  pthread_t thread;
  struct timespec pause = {0, 10000000};
  memset(&setter, 0, sizeof(setter));
  memset(&options, 0, sizeof(options));
  CHECK(capture_init(&writer) == 0);
  CHECK(pthread_mutex_init(&setter.mutex, NULL) == 0);
  CHECK(pthread_cond_init(&setter.condition, NULL) == 0);
  CHECK(ftun_budget_create(NULL, 65536u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_log_emit(core, &item) == FTUN_E_AGAIN);
  setter.core = core;
  options.level = FTUN_LOG_ERROR;
  options.writer = write_line;
  options.writer_user = &writer;
  CHECK(ftun_logger_create(&options, &logger) == FTUN_OK);
  CHECK(ftun_core_context_set_logger(core, logger) == FTUN_OK);
  item.message = (ftun_string_t){NULL, 1u};
  CHECK(ftun_log_emit(core, &item) == FTUN_E_INVALID);
  item.message = (ftun_string_t){"bounded borrow", 14u};
  CHECK(ftun_core_context_logger_acquire(core, &borrowed) == FTUN_OK &&
        borrowed == logger);
  CHECK(pthread_create(&thread, NULL, clear_logger, &setter) == 0);
  CHECK(pthread_mutex_lock(&setter.mutex) == 0);
  while (!setter.entered) {
    CHECK(pthread_cond_wait(&setter.condition, &setter.mutex) == 0);
  }
  CHECK(pthread_mutex_unlock(&setter.mutex) == 0);
  (void)nanosleep(&pause, NULL);
  CHECK(pthread_mutex_lock(&setter.mutex) == 0);
  CHECK(!setter.done);
  CHECK(pthread_mutex_unlock(&setter.mutex) == 0);
  CHECK(ftun_logger_write(borrowed, FTUN_LOG_ERROR, &item) == FTUN_OK);
  CHECK(ftun_core_context_logger_release(core) == FTUN_OK);
  CHECK(pthread_join(thread, NULL) == 0 && setter.status == FTUN_OK);
  CHECK(ftun_logger_destroy(&logger) == FTUN_OK);
  CHECK(record_valid(&writer));
  CHECK(ftun_log_emit(core, &item) == FTUN_E_AGAIN);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(pthread_cond_destroy(&setter.condition) == 0);
  CHECK(pthread_mutex_destroy(&setter.mutex) == 0);
  CHECK(capture_destroy(&writer) == 0);
  return 0;
}

static int test_real_sinks(void)
{
  char directory[] = "/tmp/ftun-logger-XXXXXX";
  char path[256];
  char bytes[4096];
  ftun_logger_options_t options;
  ftun_logger_t *logger = NULL;
  ftun_logger_usage_t usage;
  ftun_diagnostic_t item = diagnostic("/sink", "write failed");
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  struct sigaction before;
  struct sigaction after;
  uint64_t now = 0u;
  uint64_t started = 0u;
  int reader;
  int filler;
  size_t filled = 0u;
  size_t received = 0u;
  size_t newlines = 0u;
  ssize_t count;
  CHECK(mkdtemp(directory) != NULL);
  CHECK(snprintf(path, sizeof(path), "%s/output", directory) > 0);
  memset(&options, 0, sizeof(options));
  options.level = FTUN_LOG_ERROR;
  options.queue_capacity = 2u;
  options.line_capacity = sizeof(bytes);
  options.path = path;

  /* 普通文件仍 append；默认 writer 错误只计数，不伪称 flush 持久化。 */
  filler = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  CHECK(filler >= 0 && write(filler, "prefix\n", 7u) == 7);
  CHECK(close(filler) == 0);
  CHECK(ftun_logger_create(&options, &logger) == FTUN_OK);
  CHECK(ftun_logger_write(logger, FTUN_LOG_ERROR, &item) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK);
  CHECK(ftun_logger_destroy(&logger) == FTUN_OK);
  reader = open(path, O_RDONLY);
  CHECK(reader >= 0);
  count = read(reader, bytes, sizeof(bytes));
  CHECK(count > 7 && memcmp(bytes, "prefix\n", 7u) == 0 &&
        contains(bytes + 7u, (size_t)count - 7u, "message=write failed\n"));
  CHECK(close(reader) == 0 && unlink(path) == 0);

  options.path = "/dev/full";
  CHECK(ftun_logger_create(&options, &logger) == FTUN_OK);
  CHECK(ftun_logger_write(logger, FTUN_LOG_ERROR, &item) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK);
  CHECK(ftun_logger_get_usage(logger, &usage) == FTUN_OK &&
        usage.emitted == 1u && usage.io_errors == 1u && usage.queued == 0u);
  CHECK(ftun_logger_destroy(&logger) == FTUN_OK);

  options.path = path;
  CHECK(mkfifo(path, 0600) == 0);
  reader = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
  CHECK(reader >= 0 && sigaction(SIGPIPE, NULL, &before) == 0);
  CHECK(ftun_logger_create(&options, &logger) == FTUN_OK);
  CHECK(close(reader) == 0);
  CHECK(ftun_logger_write(logger, FTUN_LOG_ERROR, &item) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK);
  CHECK(ftun_logger_get_usage(logger, &usage) == FTUN_OK &&
        usage.io_errors == 1u && usage.emitted == 1u);
  CHECK(ftun_logger_destroy(&logger) == FTUN_OK);
  CHECK(sigaction(SIGPIPE, NULL, &after) == 0 &&
        before.sa_handler == after.sa_handler);

  /* 真正填满内核 pipe；阻塞写不妨碍 Core enqueue、撤销发布或限时销毁。 */
  reader = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
  filler = open(path, O_WRONLY | O_NONBLOCK | O_CLOEXEC);
  CHECK(reader >= 0 && filler >= 0);
  memset(bytes, 'x', sizeof(bytes));
  for (;;) {
    count = write(filler, bytes, sizeof(bytes));
    if (count < 0 && errno == EAGAIN) break;
    CHECK(count > 0);
    filled += (size_t)count;
  }
  CHECK(filled != 0u && close(filler) == 0);
  CHECK(ftun_budget_create(NULL, 65536u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_logger_create(&options, &logger) == FTUN_OK);
  CHECK(ftun_core_context_set_logger(core, logger) == FTUN_OK);
  item.message = (ftun_string_t){bytes, sizeof(bytes)};
  CHECK(ftun_log_emit(core, &item) == FTUN_OK);
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  CHECK(ftun_logger_flush_until(logger, now + 20u) == FTUN_E_TIMEOUT);
  CHECK(ftun_monotonic_now(&started) == FTUN_OK);
  CHECK(ftun_log_emit(core, &item) == FTUN_OK);
  CHECK(ftun_core_context_set_logger(core, NULL) == FTUN_OK);
  CHECK(ftun_logger_destroy_until(&logger, started) == FTUN_E_TIMEOUT &&
        logger != NULL);
  CHECK(ftun_monotonic_now(&now) == FTUN_OK && now - started < 1000u);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  started = now;
  for (;;) {
    size_t index;
    count = read(reader, bytes, sizeof(bytes));
    if (count > 0) {
      received += (size_t)count;
      for (index = 0u; index < (size_t)count; index++) {
        if (bytes[index] == '\n') newlines++;
      }
    }
    else CHECK(count == 0 || errno == EAGAIN);
    CHECK(ftun_logger_get_usage(logger, &usage) == FTUN_OK);
    /* writer 退出仅表示已写入 pipe；内核仍可能留有尚未读取的记录。 */
    if (usage.exited && count <= 0) break;
    {
      struct pollfd wait = {reader, POLLIN, 0};
      (void)poll(&wait, 1u, 1);
    }
    CHECK(ftun_monotonic_now(&now) == FTUN_OK && now - started < 5000u);
  }
  printf("logger fifo: filled=%zu received=%zu emitted=%llu errors=%llu\n",
         filled, received, (unsigned long long)usage.emitted,
         (unsigned long long)usage.io_errors);
  CHECK(received == filled + 2u * (sizeof(bytes) - 1u) && newlines == 2u &&
        usage.io_errors == 0u && usage.emitted == 2u);
  CHECK(ftun_logger_destroy(&logger) == FTUN_OK);
  CHECK(close(reader) == 0 && unlink(path) == 0 && rmdir(directory) == 0);
  return 0;
}

static size_t file_size(const char *path)
{
  struct stat info;
  return stat(path, &info) == 0 ? (size_t)info.st_size : SIZE_MAX;
}

static int file_has(const char *path, const char *needle)
{
  char bytes[8192];
  int descriptor = open(path, O_RDONLY);
  ssize_t count;
  if (descriptor < 0) return 0;
  count = read(descriptor, bytes, sizeof(bytes) - 1u);
  (void)close(descriptor);
  if (count < 0) return 0;
  bytes[count] = '\0';
  return strstr(bytes, needle) != NULL;
}

/* 按大小轮转（保留 max_files 个文件）、截断模式、外部移走文件后重新打开。 */
static int test_rotation_and_reopen(void)
{
  char directory[] = "/tmp/ftun-logrotate-XXXXXX";
  char path[256], older[300], oldest[300], beyond[300], moved[300];
  ftun_logger_options_t options;
  ftun_logger_t *logger = NULL;
  ftun_logger_usage_t usage;
  ftun_diagnostic_t item = diagnostic("/rotate", "line");
  size_t index;
  CHECK(mkdtemp(directory) != NULL);
  CHECK(snprintf(path, sizeof(path), "%s/ftun.log", directory) > 0);
  CHECK(snprintf(older, sizeof(older), "%s.1", path) > 0);
  CHECK(snprintf(oldest, sizeof(oldest), "%s.2", path) > 0);
  CHECK(snprintf(beyond, sizeof(beyond), "%s.3", path) > 0);
  CHECK(snprintf(moved, sizeof(moved), "%s/moved.log", directory) > 0);
  memset(&options, 0, sizeof(options));
  options.level = FTUN_LOG_ERROR;
  options.queue_capacity = 64u;
  options.line_capacity = 512u;
  options.path = path;
  options.max_size = 600u;
  options.max_files = 3u;
  CHECK(ftun_logger_create(&options, &logger) == FTUN_OK);
  for (index = 0u; index < 40u; index++) {
    item = diagnostic("/rotate", "line");
    CHECK(ftun_logger_write(logger, FTUN_LOG_ERROR, &item) == FTUN_OK);
    CHECK(ftun_logger_flush(logger) == FTUN_OK);
  }
  CHECK(ftun_logger_get_usage(logger, &usage) == FTUN_OK &&
        usage.rotations >= 3u && usage.rotate_errors == 0u);
  /* 只保留 3 个文件，每个都不超过上限，最旧的被覆盖。 */
  CHECK(file_size(path) <= 600u && file_size(older) <= 600u &&
        file_size(oldest) <= 600u && file_size(beyond) == SIZE_MAX);
  CHECK(file_size(older) > 0u && file_size(oldest) > 0u);
  /* 外部把文件移走（logrotate）：重新打开之后写入落在新建的文件上。 */
  CHECK(rename(path, moved) == 0);
  CHECK(ftun_logger_reopen(logger) == FTUN_OK);
  item = diagnostic("/after-reopen", "fresh");
  CHECK(ftun_logger_write(logger, FTUN_LOG_ERROR, &item) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK);
  CHECK(file_has(path, "/after-reopen") && !file_has(moved, "/after-reopen"));
  CHECK(ftun_logger_get_usage(logger, &usage) == FTUN_OK && usage.reopens >= 1u);
  CHECK(ftun_logger_destroy(&logger) == FTUN_OK);
  CHECK(unlink(path) == 0 && unlink(older) == 0 && unlink(oldest) == 0 &&
        unlink(moved) == 0);

  /* max_files 为 1：超限直接截断重写，不产生其他文件。 */
  options.max_files = 1u;
  CHECK(ftun_logger_create(&options, &logger) == FTUN_OK);
  for (index = 0u; index < 20u; index++) {
    CHECK(ftun_logger_write(logger, FTUN_LOG_ERROR, &item) == FTUN_OK);
    CHECK(ftun_logger_flush(logger) == FTUN_OK);
  }
  CHECK(file_size(path) <= 600u && file_size(older) == SIZE_MAX);
  CHECK(ftun_logger_destroy(&logger) == FTUN_OK);
  CHECK(unlink(path) == 0 && rmdir(directory) == 0);

  /* 自定义 writer 不支持轮转与重新打开。 */
  {
    writer_t writer;
    ftun_logger_t *custom = NULL;
    memset(&options, 0, sizeof(options));
    options.level = FTUN_LOG_ERROR;
    options.writer = write_line;
    options.max_size = 1000u;
    CHECK(capture_init(&writer) == 0);
    options.writer_user = &writer;
    CHECK(ftun_logger_create(&options, &custom) == FTUN_E_INVALID && custom == NULL);
    options.max_size = 0u;
    CHECK(ftun_logger_create(&options, &custom) == FTUN_OK);
    CHECK(ftun_logger_reopen(custom) == FTUN_E_UNSUPPORTED);
    CHECK(ftun_logger_destroy(&custom) == FTUN_OK);
    CHECK(capture_destroy(&writer) == 0);
  }
  return 0;
}

int main(void)
{
  CHECK(test_rotation_and_reopen() == 0);
  CHECK(test_basic() == 0);
  CHECK(test_format_and_bound() == 0);
  CHECK(test_stamp() == 0);
  CHECK(test_guard_scope() == 0);
  CHECK(test_real_sinks() == 0);
  CHECK(test_publish_concurrency() == 0);
  puts("logger contract: formatting, bounded fields, guarded publication and sinks passed");
  return 0;
}
