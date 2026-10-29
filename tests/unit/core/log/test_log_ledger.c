#define _POSIX_C_SOURCE 200809L
#include "core/log/log.h"
#include "platform/clock.h"
#include "core/limits.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "log ledger failed at %d: %s\n", __LINE__, #x); \
  return 1; \
} } while (0)

/* 仅在 logger writer join 后注入 close 返回错误，真实关闭仍执行一次。 */
static bool fail_close;
int __real_close(int descriptor);
int __wrap_close(int descriptor)
{
  int result = __real_close(descriptor);
  if (fail_close && result == 0) { errno = EIO; return -1; }
  return result;
}

typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  bool entered;
  bool release;
} writer_t;

static ftun_status_t slow_write(void *user, ftun_bytes_t bytes)
{
  writer_t *writer = user;
  (void)bytes;
  (void)pthread_mutex_lock(&writer->mutex);
  writer->entered = true;
  (void)pthread_cond_broadcast(&writer->condition);
  while (!writer->release) (void)pthread_cond_wait(&writer->condition, &writer->mutex);
  (void)pthread_mutex_unlock(&writer->mutex);
  return FTUN_OK;
}

static ftun_status_t failed_write(void *user, ftun_bytes_t bytes)
{
  (void)user;
  (void)bytes;
  return FTUN_E_IO;
}

static int test_retirement(void)
{
  ftun_budget_t *budget = NULL;
  ftun_log_ledger_t *ledger = NULL;
  ftun_logger_t *slow = NULL, *failed = NULL;
  ftun_logger_options_t options = {0};
  ftun_log_totals_t totals;
  ftun_budget_usage_t resources;
  ftun_diagnostic_t diagnostic = {0};
  writer_t writer = {0};
  uint64_t now;
  size_t ledger_bytes;
  CHECK(pthread_mutex_init(&writer.mutex, NULL) == 0);
  CHECK(pthread_cond_init(&writer.condition, NULL) == 0);
  CHECK(ftun_budget_create(NULL, 65536u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_log_ledger_create(budget, &ledger) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &resources) == FTUN_OK && resources.used > 0u);
  ledger_bytes = resources.used;
  options.level = FTUN_LOG_ERROR;
  options.queue_capacity = 2u;
  options.line_capacity = 128u;
  options.ledger = ledger;
  options.writer = slow_write;
  options.writer_user = &writer;
  diagnostic.error.status = FTUN_E_IO;
  diagnostic.message = (ftun_string_t){"failure", 7u};
  CHECK(ftun_logger_create(&options, &slow) == FTUN_OK);
  CHECK(ftun_logger_write(slow, FTUN_LOG_ERROR, &diagnostic) == FTUN_OK);
  (void)pthread_mutex_lock(&writer.mutex);
  while (!writer.entered) (void)pthread_cond_wait(&writer.condition, &writer.mutex);
  (void)pthread_mutex_unlock(&writer.mutex);
  CHECK(ftun_logger_write(slow, FTUN_LOG_ERROR, &diagnostic) == FTUN_OK);
  CHECK(ftun_logger_write(slow, FTUN_LOG_ERROR, &diagnostic) == FTUN_OK);
  CHECK(ftun_logger_write(slow, FTUN_LOG_INFO, &diagnostic) == FTUN_OK);
  options.writer = failed_write;
  options.writer_user = NULL;
  CHECK(ftun_logger_create(&options, &failed) == FTUN_OK);
  diagnostic.message = (ftun_string_t){"password=private", 16u};
  CHECK(ftun_logger_write(failed, FTUN_LOG_ERROR, &diagnostic) == FTUN_OK);
  CHECK(ftun_logger_flush(failed) == FTUN_OK);
  CHECK(ftun_logger_destroy(&failed) == FTUN_OK);
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  CHECK(ftun_logger_destroy_until(&slow, now) == FTUN_E_TIMEOUT && slow != NULL);
  CHECK(ftun_logger_destroy_until(&slow, now) == FTUN_E_TIMEOUT && slow != NULL);
  CHECK(ftun_logger_write(slow, FTUN_LOG_ERROR, &diagnostic) == FTUN_E_CANCELLED);
  CHECK(ftun_log_ledger_destroy(&ledger) == FTUN_E_AGAIN && ledger != NULL);
  CHECK(ftun_budget_get_usage(budget, &resources) == FTUN_OK &&
    resources.used > ledger_bytes && resources.used_resources.queue_slots == 2u &&
    resources.used_resources.descriptors == 0u);
  CHECK(ftun_log_ledger_get_usage(ledger, &totals) == FTUN_OK);
  CHECK(totals.created == 2u && totals.destroyed == 1u && totals.instances == 1u &&
    totals.capacity == 2u && totals.queued == 2u && totals.emitted == 3u &&
    totals.written == 0u && totals.io_errors == 1u && totals.dropped == 1u &&
    totals.filtered == 1u && totals.rejected == 1u && totals.redacted == 1u);
  (void)pthread_mutex_lock(&writer.mutex);
  writer.release = true;
  (void)pthread_cond_broadcast(&writer.condition);
  (void)pthread_mutex_unlock(&writer.mutex);
  CHECK(ftun_logger_destroy(&slow) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &resources) == FTUN_OK &&
    resources.used == ledger_bytes && resources.used_resources.queue_slots == 0u);
  CHECK(ftun_log_ledger_get_usage(ledger, &totals) == FTUN_OK);
  CHECK(totals.created == 2u && totals.destroyed == 2u && totals.instances == 0u &&
    totals.capacity == 0u && totals.queued == 0u && totals.written == 2u &&
    totals.io_errors == 1u && totals.emitted == totals.written + totals.io_errors);
  /* 构造失败不虚增成功实例；真实 writer 与 close 失败在销毁后仍可查询。 */
  options.writer = NULL;
  options.path = "/no/such/directory/log-ledger";
  CHECK(ftun_logger_create(&options, &failed) == FTUN_E_IO && failed == NULL);
  options.path = "/dev/full";
  CHECK(ftun_logger_create(&options, &failed) == FTUN_OK);
  CHECK(ftun_logger_write(failed, FTUN_LOG_ERROR, &diagnostic) == FTUN_OK);
  CHECK(ftun_logger_flush(failed) == FTUN_OK);
  fail_close = true;
  CHECK(ftun_logger_destroy(&failed) == FTUN_E_IO && failed == NULL);
  fail_close = false;
  CHECK(ftun_log_ledger_get_usage(ledger, &totals) == FTUN_OK);
  CHECK(totals.created == 3u && totals.destroyed == 3u && totals.instances == 0u &&
    totals.capacity == 0u && totals.queued == 0u && totals.io_errors == 2u &&
    totals.close_errors == 1u && totals.emitted == 4u && totals.redacted == 2u);
  CHECK(ftun_log_ledger_destroy(&ledger) == FTUN_OK && ledger == NULL);
  CHECK(ftun_budget_get_usage(budget, &resources) == FTUN_OK && resources.used == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(pthread_cond_destroy(&writer.condition) == 0);
  CHECK(pthread_mutex_destroy(&writer.mutex) == 0);
  return 0;
}

static int test_admission(void)
{
  ftun_budget_options_t limits = {0};
  ftun_budget_t *budget = NULL;
  ftun_log_ledger_t *ledger = NULL;
  ftun_logger_t *first = NULL, *second = NULL;
  ftun_logger_options_t options = {0};
  ftun_budget_usage_t base, usage;
  ftun_log_totals_t totals;
  ftun_reservation_t hold = (ftun_reservation_t){0};
  size_t logger_bytes;
  limits.limit = (ftun_budget_resources_t){65536u, 1u, 4u};
  CHECK(ftun_budget_create_resources(NULL, &limits, &budget) == FTUN_OK);
  CHECK(ftun_log_ledger_create(budget, &ledger) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &base) == FTUN_OK);
  options.level = FTUN_LOG_ERROR;
  options.queue_capacity = 2u;
  options.line_capacity = 128u;
  options.path = "/dev/null";
  options.ledger = ledger;
  CHECK(ftun_logger_create(&options, &first) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used > base.used &&
    usage.used_resources.descriptors == 1u && usage.used_resources.queue_slots == 2u);
  logger_bytes = usage.used - base.used;
  /* 文件 FD 达限，在 open/线程创建之前拒绝候选，旧 sink 仍存活。 */
  CHECK(ftun_logger_create(&options, &second) == FTUN_E_LIMIT && second == NULL);
  CHECK(ftun_log_ledger_get_usage(ledger, &totals) == FTUN_OK && totals.created == 1u && totals.instances == 1u);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == base.used + logger_bytes &&
    usage.used_resources.descriptors == 1u && usage.used_resources.queue_slots == 2u);
  CHECK(ftun_logger_destroy(&first) == FTUN_OK);
  options.path = NULL;
  options.writer = failed_write;
  CHECK(ftun_logger_create(&options, &first) == FTUN_OK);
  options.queue_capacity = 3u;
  CHECK(ftun_logger_create(&options, &second) == FTUN_E_LIMIT && second == NULL);
  options.queue_capacity = 2u;
  CHECK(ftun_logger_create(&options, &second) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == base.used + 2u * logger_bytes &&
    usage.used_resources.descriptors == 0u && usage.used_resources.queue_slots == 4u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_E_AGAIN);
  CHECK(ftun_logger_destroy(&first) == FTUN_OK && ftun_logger_destroy(&second) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == base.used &&
    usage.used_resources.queue_slots == 0u && usage.used_resources.descriptors == 0u);
  CHECK(ftun_budget_reserve(budget, usage.normal_available - 1u, &hold) == FTUN_OK);
  CHECK(ftun_logger_create(&options, &first) == FTUN_E_LIMIT && first == NULL);
  CHECK(ftun_reservation_release(&hold) == FTUN_OK);
  options.writer = NULL;
  options.path = "/no/such/directory/ledger";
  CHECK(ftun_logger_create(&options, &first) == FTUN_E_IO && first == NULL);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == base.used &&
    usage.used_resources.queue_slots == 0u && usage.used_resources.descriptors == 0u);
  CHECK(ftun_log_ledger_destroy(&ledger) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(void)
{
  CHECK(test_retirement() == 0);
  CHECK(test_admission() == 0);
  puts("log ledger: pending writes, retirement, drop, filter, write and close failures passed");
  return 0;
}
