#include "core/log/aggregate.h"
#include "core/limits.h"
#include "platform/thread.h"
#include "platform/atomic.h"
#include "core/context.h"
#include "core/event/loop.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "aggregate failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

static const ftun_log_event_t failed = {FTUN_LOG_DNS, FTUN_LOG_WARN, "dns.upstream.failed", "upstream failed"};
static const ftun_log_event_t healthy = {FTUN_LOG_DNS, FTUN_LOG_INFO, "dns.upstream.recovered", "upstream recovered"};
static const ftun_log_event_t proxy = {FTUN_LOG_PROXY, FTUN_LOG_WARN, "proxy.dial.failed", "dial failed"};
typedef struct { char text[1048576]; size_t used, lines; } capture_t;
static ftun_status_t capture(void *user, ftun_bytes_t bytes)
{
  capture_t *out = user;
  if (bytes.length >= sizeof(out->text) - out->used) return FTUN_E_LIMIT;
  memcpy(out->text + out->used, bytes.data, bytes.length);
  out->used += bytes.length;
  out->text[out->used] = '\0';
  out->lines++;
  return FTUN_OK;
}
static ftun_status_t fail(ftun_log_aggregate_t *aggregate, ftun_logger_t *logger,
  const ftun_log_event_t *event, uint64_t entity, const char *label, uint64_t now)
{
  ftun_log_record_t record = {.event = event, .error = {.status = FTUN_E_TIMEOUT}, .generation = 9u, .sid = 101u};
  return ftun_log_aggregate_failure(aggregate, logger, &record, entity,
    (ftun_string_t){label, strlen(label)}, now);
}
static ftun_status_t recover(ftun_log_aggregate_t *aggregate, ftun_logger_t *logger,
  const ftun_log_event_t *event, uint64_t entity, uint64_t now)
{
  ftun_log_record_t record = {.event = &healthy, .generation = 9u};
  return ftun_log_aggregate_recovery(aggregate, logger, event, entity, &record, now);
}
static int sequence(ftun_log_aggregate_t *aggregate, ftun_logger_t *logger, capture_t *output)
{
  char label[] = "upstream-a";
  CHECK(fail(aggregate, logger, &failed, 1u, label, 100u) == FTUN_OK);
  memset(label, 'x', sizeof(label) - 1u);
  CHECK(fail(aggregate, logger, &failed, 1u, "changed", 200u) == FTUN_OK);
  CHECK(fail(aggregate, logger, &failed, 1u, "changed", 300u) == FTUN_OK);
  CHECK(ftun_log_aggregate_deadline(aggregate) == 60100u);
  CHECK(ftun_log_aggregate_tick(aggregate, logger, 60099u) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && output->lines == 1u);
  CHECK(strstr(output->text, "upstream failed (first)") && strstr(output->text, "entity=upstream-a"));
  size_t summary_start = output->used;
  CHECK(ftun_log_aggregate_tick(aggregate, logger, 60100u) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && output->lines == 2u);
  CHECK(strstr(output->text + summary_start, "count=3 in=60s") &&
    strstr(output->text + summary_start, "entity=upstream-a") &&
    strstr(output->text + summary_start, "entity=changed") == NULL);
  CHECK(ftun_log_aggregate_deadline(aggregate) == UINT64_MAX);
  CHECK(ftun_log_aggregate_tick(aggregate, logger, 120100u) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && output->lines == 2u);
  CHECK(fail(aggregate, logger, &failed, 1u, "changed", 130100u) == FTUN_OK);
  CHECK(ftun_log_aggregate_deadline(aggregate) == 190100u);
  CHECK(recover(aggregate, logger, &failed, 1u, 130200u) == FTUN_OK);
  CHECK(recover(aggregate, logger, &failed, 999u, 130300u) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && output->lines == 3u);
  CHECK(strstr(output->text, "upstream recovered") && strstr(output->text, "count=4 duration_ms=130100"));
  ftun_log_aggregate_usage_t usage;
  ftun_log_aggregate_usage(aggregate, &usage);
  CHECK(usage.failures == 4u && usage.suppressed == 3u && usage.first == 1u &&
    usage.summaries == 1u && usage.recovered == 1u && usage.active == 0u);
  return 0;
}
static int visibility(ftun_log_aggregate_t *aggregate, ftun_logger_t *logger, capture_t *output)
{
  size_t before = output->lines;
  CHECK(fail(aggregate, NULL, &failed, 2u, "hidden", 300000u) == FTUN_OK);
  CHECK(ftun_log_aggregate_tick(aggregate, logger, 360000u) == FTUN_OK);
  CHECK(recover(aggregate, logger, &failed, 2u, 360001u) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && output->lines == before);
  CHECK(fail(aggregate, logger, &failed, 2u, "visible", 400000u) == FTUN_OK);
  CHECK(fail(aggregate, logger, &failed, 2u, "visible", 400010u) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && output->lines == before + 1u);
  CHECK(fail(aggregate, NULL, &failed, 2u, "visible", 400020u) == FTUN_OK);
  CHECK(ftun_log_aggregate_tick(aggregate, logger, 500000u) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && output->lines == before + 1u);
  size_t start = output->used;
  CHECK(fail(aggregate, logger, &failed, 2u, "visible", 500100u) == FTUN_OK);
  CHECK(recover(aggregate, logger, &failed, 2u, 500200u) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && output->lines == before + 3u);
  CHECK(strstr(output->text + start, "count=1 duration_ms=100"));
  CHECK(strstr(output->text, "entity=hidden") == NULL);
  ftun_log_aggregate_usage_t usage;
  ftun_log_aggregate_usage(aggregate, &usage);
  CHECK(usage.failures == 9u && usage.filtered == 2u && usage.active == 0u);
  return 0;
}
static int capacity(ftun_log_aggregate_t *aggregate, ftun_logger_t *logger, capture_t *output)
{
  CHECK(ftun_log_aggregate_flush(aggregate, logger, 600000u) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK);
  size_t start = output->used, before = output->lines;
  for (size_t i = 0u; i < FTUN_LOG_AGGREGATE_CAPACITY; i++)
    CHECK(fail(aggregate, logger, &failed, i + 100u, "configured", 700000u) == FTUN_OK);
  CHECK(fail(aggregate, logger, &failed, 1000u, "excess", 700001u) == FTUN_OK);
  CHECK(fail(aggregate, logger, &failed, 1001u, "excess", 700002u) == FTUN_OK);
  CHECK(fail(aggregate, logger, &proxy, 1000u, "excess", 700001u) == FTUN_OK);
  CHECK(fail(aggregate, logger, &proxy, 1001u, "excess", 700002u) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && output->lines == before + 258u);
  CHECK(ftun_log_aggregate_tick(aggregate, logger, 760002u) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && output->lines == before + 260u);
  CHECK(strstr(output->text + start, "additional failures (first)") &&
    strstr(output->text + start, "overflow=true count=2"));
  ftun_log_aggregate_usage_t usage;
  ftun_log_aggregate_usage(aggregate, &usage);
  CHECK(usage.active == 256u && usage.overflowed == 4u);
  CHECK(recover(aggregate, logger, &failed, 1000u, 760003u) == FTUN_OK);
  ftun_log_aggregate_usage(aggregate, &usage);
  CHECK(usage.active == 256u);
  CHECK(recover(aggregate, logger, &failed, 100u, 760004u) == FTUN_OK);
  CHECK(fail(aggregate, logger, &failed, 9999u, "new", 760005u) == FTUN_OK);
  CHECK(fail(aggregate, logger, &failed, 101u, "configured", 760010u) == FTUN_OK);
  CHECK(ftun_log_aggregate_flush(aggregate, logger, 760020u) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && output->lines == before + 263u);
  CHECK(ftun_log_aggregate_deadline(aggregate) == UINT64_MAX);
  ftun_log_aggregate_usage(aggregate, &usage);
  CHECK(usage.active == 0u);
  return 0;
}
static int identity(ftun_log_aggregate_t *aggregate, ftun_logger_t *logger, capture_t *output)
{
  static const char duplicate_id[] = "dns.upstream.failed";
  static const ftun_log_event_t same = {FTUN_LOG_DNS, FTUN_LOG_WARN, duplicate_id, "upstream failed"};
  size_t before = output->lines;
  char name[271];
  for (size_t i = 0u; i < 270u; i += 3u) memcpy(name + i, "\xe4\xb8\xad", 3u);
  name[270] = '\0';
  CHECK(fail(aggregate, logger, &failed, 3u, name, 800000u) == FTUN_OK);
  CHECK(fail(aggregate, logger, &same, 3u, "same-id", 800010u) == FTUN_OK);
  CHECK(fail(aggregate, logger, &proxy, 3u, "separate-module", 800010u) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && output->lines == before + 2u);
  CHECK(strstr(output->text, "truncated=true"));
  CHECK(recover(aggregate, logger, &same, 3u, 800020u) == FTUN_OK);
  CHECK(ftun_log_aggregate_flush(aggregate, logger, 800030u) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && output->lines == before + 3u);
  return 0;
}
#if defined(FTUN_TEST_AGGREGATE_OWNER)
static ftun_atomic_u64_t clock_ms;
ftun_status_t __wrap_ftun_monotonic_now(uint64_t *out)
{
  *out = ftun_atomic_load(&clock_ms);
  return FTUN_OK;
}
typedef struct { ftun_core_t *core; ftun_atomic_bool_t done, started; bool failed; } reader_t;
static void *read_usage(void *user)
{
  reader_t *reader = user;
  do {
    ftun_log_aggregate_usage_t usage;
    if (ftun_log_aggregate_query(reader->core, &usage) != FTUN_OK || usage.first > usage.failures ||
        usage.suppressed > usage.failures || usage.active > FTUN_LOG_AGGREGATE_CAPACITY) reader->failed = true;
    ftun_atomic_store(&reader->started, true);
  } while (!ftun_atomic_load(&reader->done));
  return NULL;
}
static void blocked_timer(ftun_event_source_t *source, uint32_t events, void *user)
{
  (void)source; (void)events; (void)user;
}
static int owner(ftun_logger_t *logger, capture_t *output)
{
  ftun_core_t *core = NULL;
  ftun_budget_t *budget = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_log_aggregate_t *aggregate = NULL;
  ftun_event_log_t *events = NULL;
  ftun_log_aggregate_usage_t usage;
  ftun_log_record_t record = {.event = &failed, .error = {.status = FTUN_E_TIMEOUT}, .generation = 2u};
  size_t callbacks, before = output->lines;
  uint64_t deadline;
  bool present;
  ftun_atomic_init(&clock_ms, 100u);
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_event_loop_create_with_budget(core, budget, 1u, &loop) == FTUN_OK);
  CHECK(ftun_log_failure(core, &record, 1u, (ftun_string_t){"one", 3u}, 100u) == FTUN_E_AGAIN);
  CHECK(ftun_log_aggregate_attach(core, loop) == FTUN_OK);
  CHECK(ftun_log_aggregate_create(budget, &aggregate) == FTUN_OK);
  CHECK(ftun_core_context_set_aggregate(core, aggregate) == FTUN_OK);
  CHECK(ftun_event_log_create(budget, &events) == FTUN_OK);
  CHECK(ftun_core_context_set_event_log(core, events) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_E_AGAIN);
  CHECK(ftun_core_context_set_logger(core, logger) == FTUN_OK);
  CHECK(ftun_log_aggregate_attach(core, loop) == FTUN_OK);
  ftun_event_source_t *occupied = NULL;
  CHECK(ftun_event_timer_start(loop, 900000u, blocked_timer, NULL, &occupied) == FTUN_OK);
  CHECK(ftun_log_failure(core, &record, 1u, (ftun_string_t){"one", 3u}, 100u) == FTUN_E_LIMIT);
  CHECK(ftun_log_aggregate_query(core, &usage) == FTUN_OK && usage.failures == 1u && usage.errors == 1u);
  CHECK(ftun_event_source_cancel(&occupied) == FTUN_OK);
  CHECK(ftun_log_failure(core, &record, 1u, (ftun_string_t){"one", 3u}, 200u) == FTUN_OK);
  CHECK(ftun_event_loop_next_deadline(loop, &deadline, &present) == FTUN_OK && present && deadline == 60100u);
  ftun_atomic_store(&clock_ms, 60100u);
  CHECK(ftun_event_loop_poll(loop, 60100u, 1u, &callbacks) == FTUN_OK && callbacks == 1u);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && output->lines == before + 2u);
  CHECK(ftun_event_loop_next_deadline(loop, &deadline, &present) == FTUN_OK && !present);
  reader_t reader = {.core = core};
  ftun_thread_t thread;
  ftun_atomic_init(&reader.done, false);
  ftun_atomic_init(&reader.started, false);
  CHECK(ftun_thread_create(&thread, read_usage, &reader) == FTUN_OK);
  while (!ftun_atomic_load(&reader.started)) ftun_thread_pause(1u);
  for (size_t i = 0u; i < 1000u; i++)
    CHECK(ftun_log_failure(core, &record, 1u, (ftun_string_t){"one", 3u}, 60200u + i) == FTUN_OK);
  ftun_atomic_store(&reader.done, true);
  CHECK(ftun_thread_join(&thread) == FTUN_OK && !reader.failed);
  CHECK(ftun_log_aggregate_query(core, &usage) == FTUN_OK && usage.failures == 1002u && usage.active == 1u);
  /* 重新发布只汇总旧的可见周期，silent期间的新故障不在之后的sink出现。 */
  ftun_atomic_store(&clock_ms, 62000u);
  CHECK(ftun_core_context_publish_logger(core, NULL, true) == FTUN_OK);
  CHECK(ftun_log_failure(core, &record, 2u, (ftun_string_t){"hidden-owner", 12u}, 62000u) == FTUN_OK);
  CHECK(ftun_core_context_publish_logger(core, logger, false) == FTUN_OK);
  CHECK(ftun_log_aggregate_query(core, &usage) == FTUN_OK && usage.failures == 1003u && usage.filtered == 1u);
  CHECK(ftun_log_failure(core, &record, 3u, (ftun_string_t){"final", 5u}, 63000u) == FTUN_OK);
  CHECK(ftun_log_failure(core, &record, 3u, (ftun_string_t){"final", 5u}, 63010u) == FTUN_OK);
  ftun_atomic_store(&clock_ms, 64000u);
  CHECK(ftun_logger_flush(logger) == FTUN_OK);
  size_t final_start = output->used;
  ftun_lifecycle_event_t terminal = {.kind = FTUN_LIFECYCLE_STOPPED, .generation = 2u};
  CHECK(ftun_core_context_finish_logging(core, &terminal) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK && strstr(output->text, "hidden-owner") == NULL);
  const char *summary = strstr(output->text + final_start, "count=2");
  const char *stopped = strstr(output->text + final_start, "runtime stopped");
  CHECK(summary != NULL && stopped != NULL && summary < stopped && strchr(stopped, '\n')[1] == '\0');
  CHECK(ftun_log_aggregate_query(core, &usage) == FTUN_OK && usage.active == 0u && usage.summaries == 3u);
  CHECK(ftun_log_aggregate_detach(core) == FTUN_OK);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_core_context_set_aggregate(core, NULL) == FTUN_OK);
  CHECK(ftun_core_context_set_event_log(core, NULL) == FTUN_OK);
  CHECK(ftun_event_log_destroy(&events) == FTUN_OK);
  ftun_log_aggregate_destroy(&aggregate);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}
#endif

static int retire(ftun_log_aggregate_t *aggregate, ftun_logger_t *logger, capture_t *output)
{
  ftun_log_aggregate_usage_t before, after;
  CHECK(ftun_log_aggregate_flush(aggregate, logger, 1u) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK);
  memset(output, 0, sizeof(*output));
  ftun_log_aggregate_usage(aggregate, &before);
  CHECK(fail(aggregate, logger, &proxy, 5000u, "retiring-outbound", 10u) == FTUN_OK);
  CHECK(fail(aggregate, logger, &proxy, 5000u, "retiring-outbound", 20u) == FTUN_OK);
  CHECK(fail(aggregate, logger, &failed, 5000u, "different-module", 20u) == FTUN_OK);
  CHECK(ftun_log_aggregate_retire(aggregate, logger, FTUN_LOG_PROXY, 5000u, 30u) == FTUN_OK);
  CHECK(ftun_logger_flush(logger) == FTUN_OK);
  CHECK(strstr(output->text, "entity=retiring-outbound entity_id=5000 count=2") != NULL);
  CHECK(strstr(output->text, "recovered") == NULL);
  ftun_log_aggregate_usage(aggregate, &after);
  CHECK(after.active == 1u && after.recovered == before.recovered && after.summaries == before.summaries + 1u);
  CHECK(ftun_log_aggregate_retire(aggregate, logger, FTUN_LOG_PROXY, 5000u, 40u) == FTUN_OK);
  CHECK(ftun_log_aggregate_flush(aggregate, logger, 50u) == FTUN_OK);
  return 0;
}

int main(void)
{
  ftun_budget_t *budget = NULL;
  ftun_log_aggregate_t *aggregate = NULL;
  ftun_budget_usage_t before, after;
  capture_t *output = calloc(1u, sizeof(*output));
  ftun_logger_t *logger = NULL;
  ftun_logger_options_t options = {.level = FTUN_LOG_INFO, .queue_capacity = 512u,
    .line_capacity = 1024u, .writer = capture, .writer_user = output};
  CHECK(output != NULL);
  CHECK(ftun_budget_create(NULL, 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_log_aggregate_create(budget, &aggregate) == FTUN_E_LIMIT && aggregate == NULL);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_log_aggregate_create(budget, &aggregate) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &before) == FTUN_OK && before.used_resources.memory_bytes != 0u);
  CHECK(ftun_logger_create(&options, &logger) == FTUN_OK);
  CHECK(sequence(aggregate, logger, output) == 0);
  CHECK(visibility(aggregate, logger, output) == 0);
  CHECK(capacity(aggregate, logger, output) == 0);
  CHECK(identity(aggregate, logger, output) == 0);
  CHECK(retire(aggregate, logger, output) == 0);
  CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK &&
    before.used_resources.memory_bytes == after.used_resources.memory_bytes);
#if defined(FTUN_TEST_AGGREGATE_OWNER)
  CHECK(owner(logger, output) == 0);
#endif
  CHECK(ftun_logger_destroy(&logger) == FTUN_OK);
  ftun_log_aggregate_destroy(&aggregate);
  CHECK(aggregate == NULL);
  CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK && after.used_resources.memory_bytes == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  free(output);
  return 0;
}
