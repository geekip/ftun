#define _POSIX_C_SOURCE 200809L
#include <sys/types.h>
#include "core/core.h"
#include "app/config/model.h"
#include "core/log/log.h"
#include "platform/clock.h"
#include "app/control.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define CHECK(value) do { if (!(value)) { \
  fprintf(stderr, "app host failed at %d: %s\n", __LINE__, #value); \
  return 1; } } while (0)
#define REQUIRE(value) do { if (!(value)) { \
  fprintf(stderr, "app host owner failed at %d: %s\n", __LINE__, #value); \
  return FTUN_E_STATE_CORRUPT; } } while (0)

typedef struct {
  ftun_core_t *core;
  const ftun_config_t *config;
  const ftun_config_t *candidate;
  char paths[4][256];
  unsigned int step;
  unsigned int callbacks;
  unsigned int posts;
  unsigned int commits;
  ftun_status_t result;
  uint64_t expires;
  bool blocked;
  bool destroyed;
  bool limited;
  ftun_reservation_t hold;
} host_test_t;

static host_test_t test;

static uint64_t now_ms(void)
{
  uint64_t now = 0u;
  if (ftun_monotonic_now(&now) != FTUN_OK) abort();
  return now;
}

static void pause_once(void)
{
  struct timespec pause = {0, 1000000};
  (void)nanosleep(&pause, NULL);
}

static size_t descriptors(void)
{
  DIR *directory = opendir("/proc/self/fd");
  struct dirent *entry;
  size_t count = 0u;
  if (directory == NULL) abort();
  while ((entry = readdir(directory)) != NULL) {
    if (entry->d_name[0] != '.') count++;
  }
  (void)closedir(directory);
  return count;
}

static ftun_status_t emit(const char *message)
{
  ftun_diagnostic_t diagnostic;
  memset(&diagnostic, 0, sizeof(diagnostic));
  diagnostic.error.status = FTUN_E_IO;
  diagnostic.message = (ftun_string_t){message, strlen(message)};
  return ftun_log_emit(test.core, &diagnostic);
}

static ftun_status_t plan_prepare(ftun_budget_t *budget,
  const ftun_config_t *config,
  uint32_t mark, void **out)
{
  (void)budget;
  /* 仅有顶层设备配置而无 TUN 消费者，不应施加 Underlay mark。 */
  if (mark != 0u) return FTUN_E_STATE_CORRUPT;
  *out = (void *)config;
  return FTUN_OK;
}

static ftun_status_t plan_destroy(void **plan)
{
  const ftun_config_t *config = *plan;
  if (config != NULL && config->source_path == NULL) return FTUN_E_STATE_CORRUPT;
  *plan = NULL;
  return FTUN_OK;
}

static ftun_status_t prepare(ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations, const ftun_core_service_binding_t *binding,
  const ftun_config_t *config, uint64_t generation, void **out)
{
  (void)budget;
  (void)operations;
  (void)binding;
  REQUIRE(generation == 1u && config != NULL);
  test.core = core;
  test.config = config;
  *out = &test;
  return FTUN_OK;
}

static ftun_status_t success(void *instance)
{
  return instance == &test ? FTUN_OK : FTUN_E_INVALID;
}

static ftun_status_t reload_prepare(void *instance, const ftun_config_t *config,
  uint64_t generation)
{
  REQUIRE(instance == &test && generation >= 2u);
  test.candidate = config;
  return FTUN_OK;
}

static ftun_status_t reload_planned(void *instance, const ftun_config_t *config,
  uint64_t generation, const void *plan)
{
  REQUIRE(config == plan);
  return reload_prepare(instance, config, generation);
}

static ftun_status_t reload_commit(void *instance, uint64_t generation)
{
  REQUIRE(instance == &test && generation == test.commits + 2u);
  REQUIRE(test.candidate != NULL && test.candidate->source_path != NULL);
  test.config = test.candidate;
  test.candidate = NULL;
  test.commits++;
  return FTUN_OK;
}

static ftun_status_t reload_abort(void *instance)
{
  REQUIRE(instance == &test);
  test.candidate = NULL;
  return FTUN_OK;
}

static void reloaded(ftun_operation_t *operation, ftun_error_t result, void *user)
{
  (void)operation;
  (void)user;
  test.result = result.status;
  test.callbacks++;
}

static void posted(ftun_operation_t *operation, ftun_error_t result, void *user)
{
  (void)operation;
  (void)user;
  if (result.status == FTUN_OK) test.posts++;
}

static ftun_status_t reload(unsigned int index)
{
  ftun_operation_t *operation = NULL;
  return ftun_core_reload(test.core, test.paths[index], reloaded, NULL, &operation);
}

static ftun_status_t limited_round(const ftun_core_info_t *info)
{
  ftun_budget_t *budget = NULL;
  ftun_budget_usage_t resources;
  ftun_app_control_snapshot_t snapshot;
  ftun_operation_t *operation = NULL;
  REQUIRE(ftun_core_context_budget(test.core, &budget) == FTUN_OK);
  if (test.step == 0u) {
    ftun_budget_resources_t charge = {0};
    REQUIRE(ftun_budget_get_usage(budget, &resources) == FTUN_OK);
    charge.descriptors = resources.normal_available_resources.descriptors;
    REQUIRE(charge.descriptors > 0u);
    REQUIRE(ftun_budget_reserve_resources(budget, charge, &test.hold) == FTUN_OK);
    REQUIRE(reload(1u) == FTUN_OK);
    test.step = 1u;
  } else if (test.step == 1u && test.callbacks == 1u) {
    REQUIRE(test.result == FTUN_E_LIMIT && info->generation == 1u && test.commits == 0u);
    REQUIRE(!strcmp(test.config->source_path, test.paths[0]));
    REQUIRE(ftun_app_control_query(test.core, &snapshot) == FTUN_OK);
    REQUIRE(snapshot.log_totals.instances == 1u && snapshot.log_totals.created == 1u);
    REQUIRE(emit("old sink survives budget rejection") == FTUN_OK);
    REQUIRE(ftun_core_post(test.core, posted, NULL, &operation) == FTUN_OK);
    test.step = 2u;
  } else if (test.step == 2u && test.posts == 1u) {
    /* 控制完成发生在 FD 仍耗尽时；归还额度后同一 reload 可恢复。 */
    REQUIRE(ftun_reservation_release(&test.hold) == FTUN_OK);
    REQUIRE(reload(1u) == FTUN_OK);
    test.step = 3u;
  } else if (test.step == 3u && test.callbacks == 2u) {
    REQUIRE(test.result == FTUN_OK && info->generation == 2u && test.commits == 1u);
    REQUIRE(!strcmp(test.config->source_path, test.paths[1]));
    REQUIRE(emit("new sink after budget recovery") == FTUN_OK);
    test.step = 4u;
    return ftun_core_stop(test.core, now_ms() + 1000u);
  }
  pause_once();
  return FTUN_OK;
}

static ftun_status_t run_once(void *instance, bool may_block,
  ftun_core_service_run_usage_t *usage)
{
  ftun_core_info_t info;
  uint64_t context_generation = 0u;
  ftun_operation_t *operation = NULL;
  (void)may_block;
  REQUIRE(instance == &test && now_ms() < test.expires);
  memset(usage, 0, sizeof(*usage));
  REQUIRE(ftun_core_get_info(test.core, &info) == FTUN_OK);
  REQUIRE(ftun_core_context_generation(test.core, &context_generation) == FTUN_OK);
  REQUIRE(context_generation == info.generation);
  REQUIRE(info.state == FTUN_CORE_RUNNING && test.config->source_path != NULL);
  usage->work = 1u;
  if (test.limited) return limited_round(&info);
  if (test.step == 0u) {
    REQUIRE(!strcmp(test.config->source_path, test.paths[0]));
    REQUIRE(emit("before switch marker") == FTUN_OK);
    test.step = 1u;
  } else if (test.step == 1u) {
    if (test.blocked) {
      ftun_logger_t *logger = NULL;
      ftun_logger_usage_t logs;
      REQUIRE(ftun_core_context_logger_acquire(test.core, &logger) == FTUN_OK);
      REQUIRE(ftun_logger_get_usage(logger, &logs) == FTUN_OK);
      REQUIRE(logs.emitted == 1u && logs.queued == 1u);
      REQUIRE(ftun_logger_flush_until(logger, now_ms()) == FTUN_E_TIMEOUT);
      REQUIRE(ftun_core_context_logger_release(test.core) == FTUN_OK);
    }
    REQUIRE(reload(1u) == FTUN_OK);
    test.step = 2u;
  } else if (test.step == 2u && test.callbacks == 1u) {
    REQUIRE(test.result == FTUN_OK && info.generation == 2u);
    REQUIRE(!strcmp(test.config->source_path, test.paths[1]));
    REQUIRE(emit("after switch marker") == FTUN_OK);
    if (test.blocked) {
      REQUIRE(ftun_core_reload(test.core, test.paths[2], reloaded, NULL,
                                &operation) == FTUN_E_AGAIN);
      REQUIRE(operation == NULL);
      test.step = 5u;
      return ftun_core_stop(test.core, now_ms() + 40u);
    }
    /* 旧 logger 可在下一轮回收；AGAIN 不代表本次配置被接纳。 */
    {
      ftun_status_t status = reload(2u);
      if (status == FTUN_E_AGAIN) return FTUN_OK;
      REQUIRE(status == FTUN_OK);
    }
    test.step = 3u;
  } else if (test.step == 3u && test.callbacks == 2u) {
    REQUIRE(test.result == FTUN_E_IO && info.generation == 2u);
    REQUIRE(!strcmp(test.config->source_path, test.paths[1]));
    REQUIRE(emit("after reject marker") == FTUN_OK);
    {
      ftun_status_t status = reload(3u);
      if (status == FTUN_E_AGAIN) return FTUN_OK;
      REQUIRE(status == FTUN_OK);
    }
    test.step = 4u;
  } else if (test.step == 4u && test.callbacks == 3u) {
    REQUIRE(test.result == FTUN_OK && info.generation == 3u);
    REQUIRE(!strcmp(test.config->source_path, test.paths[3]));
    REQUIRE(emit("silent marker") == FTUN_E_AGAIN);
    REQUIRE(ftun_core_post(test.core, posted, NULL, &operation) == FTUN_OK);
    test.step = 5u;
  } else if (test.step == 5u && test.posts == 1u) {
    return ftun_core_stop(test.core, now_ms() + 1000u);
  }
  pause_once();
  return FTUN_OK;
}

static ftun_status_t stop_until(void *instance, uint64_t deadline)
{
  (void)deadline;
  return success(instance);
}

static ftun_status_t destroy_until(void **instance, uint64_t deadline)
{
  (void)deadline;
  REQUIRE(*instance == &test && test.config != NULL);
  REQUIRE(test.config->source_path != NULL && test.candidate == NULL);
  test.config = NULL;
  test.destroyed = true;
  *instance = NULL;
  return FTUN_OK;
}

static const ftun_core_service_descriptor_t descriptor = {
  "host-test", plan_prepare, plan_destroy, prepare, success,
  reload_prepare, reload_planned, reload_commit, reload_abort,
  run_once, success, success, stop_until, stop_until, destroy_until,
  NULL,
  NULL /* network_changed */
};

static int write_config(const char *path, const char *level, const char *log)
{
  FILE *file = fopen(path, "w");
  CHECK(file != NULL);
  CHECK(fprintf(file, "{\"base\":{\"state-cache\":false},"
    "\"tun\":{\"interface\":\"ftun-unused0\",\"mtu\":1400,"
    "\"ipv4\":{\"address\":\"10.88.0.1/30\"},\"auto-route\":false},"
    "\"dns\":{\"enable\":false},\"log\":{\"level\":\"%s\",\"file\":\"%s\"}}",
    level, log) > 0);
  CHECK(fclose(file) == 0);
  return 0;
}

static int read_log(const char *path, char *out, size_t capacity)
{
  FILE *file = fopen(path, "r");
  size_t length;
  CHECK(file != NULL);
  length = fread(out, 1u, capacity - 1u, file);
  out[length] = '\0';
  CHECK(!ferror(file) && feof(file));
  CHECK(fclose(file) == 0);
  return 0;
}

static int scenario(bool blocked)
{
  char directory[] = "/tmp/ftun-host-XXXXXX";
  char first[256], second[256];
  char buffer[8192];
  ftun_core_options_t options;
  ftun_core_info_t info;
  ftun_core_t *core = NULL;
  size_t baseline = descriptors();
  unsigned int index;
  uint64_t started;
  int fifo = -1;
  memset(&test, 0, sizeof(test));
  test.blocked = blocked;
  CHECK(mkdtemp(directory) != NULL);
  CHECK(snprintf(first, sizeof(first), "%s/first.log", directory) > 0);
  CHECK(snprintf(second, sizeof(second), "%s/second.log", directory) > 0);
  for (index = 0u; index < 4u; index++) {
    CHECK(snprintf(test.paths[index], sizeof(test.paths[index]),
                     "%s/config-%u.json", directory, index) > 0);
  }
  CHECK(write_config(test.paths[0], "warn", first) == 0);
  CHECK(write_config(test.paths[1], "warn", second) == 0);
  CHECK(write_config(test.paths[2], "warn", "/dev/null/invalid.log") == 0);
  CHECK(write_config(test.paths[3], "silent", second) == 0);
  if (blocked) {
    ssize_t written;
    CHECK(mkfifo(first, 0600) == 0);
    fifo = open(first, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    CHECK(fifo >= 0);
    memset(buffer, 'x', sizeof(buffer));
    while ((written = write(fifo, buffer, sizeof(buffer))) > 0) {}
    CHECK(written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
  }
  memset(&options, 0, sizeof(options));
  options.struct_size = sizeof(options);
  options.abi_version = FTUN_ABI_VERSION;
  CHECK(ftun_core_create_with_service(&options, &descriptor, &core) == FTUN_OK);
  test.expires = now_ms() + 5000u;
  started = now_ms();
  CHECK(ftun_core_run(core, test.paths[0]) == (blocked ? FTUN_E_TIMEOUT : FTUN_OK));
  CHECK(now_ms() - started < 2000u && test.step == 5u);
  CHECK(ftun_core_get_info(core, &info) == FTUN_OK);
  CHECK(info.generation == (blocked ? 2u : 3u));
  {
    ftun_app_control_snapshot_t snapshot;
    CHECK(ftun_app_control_query(core, &snapshot) == FTUN_OK);
    CHECK(snapshot.run_returned && snapshot.run_result == (blocked ? FTUN_E_TIMEOUT : FTUN_OK));
    CHECK(snapshot.log_totals.emitted == snapshot.log_totals.written +
      snapshot.log_totals.io_errors + snapshot.log_totals.queued);
    if (blocked) {
      CHECK(snapshot.log_totals.instances >= 1u && snapshot.log_totals.queued > 0u);
    } else {
      CHECK(snapshot.runtime_stopped && snapshot.events.closed && !snapshot.logger_present);
      CHECK(snapshot.log_totals.created == 2u && snapshot.log_totals.destroyed == 2u &&
        snapshot.log_totals.instances == 0u && snapshot.log_totals.queued == 0u &&
        snapshot.log_totals.written > 0u && snapshot.log_totals.io_errors == 0u);
    }
  }
  if (blocked) {
    ftun_status_t status;
    CHECK(info.state == FTUN_CORE_STOPPING && test.callbacks == 1u);
    CHECK(ftun_core_destroy(&core) == FTUN_E_AGAIN && core != NULL);
    do {
      while (read(fifo, buffer, sizeof(buffer)) > 0) {}
      status = ftun_core_destroy(&core);
      CHECK(status == FTUN_OK || status == FTUN_E_AGAIN);
      CHECK(now_ms() < test.expires);
      if (status != FTUN_OK) pause_once();
    } while (status != FTUN_OK);
    CHECK(close(fifo) == 0);
  } else {
    CHECK(info.state == FTUN_CORE_STOPPED && test.callbacks == 3u);
    CHECK(test.posts == 1u && test.commits == 2u);
    CHECK(ftun_core_destroy(&core) == FTUN_OK);
    CHECK(read_log(first, buffer, sizeof(buffer)) == 0);
    CHECK(strstr(buffer, "before switch marker") != NULL);
    CHECK(strstr(buffer, "after switch marker") == NULL);
    CHECK(strstr(buffer, "silent marker") == NULL);
  }
  CHECK(core == NULL && test.destroyed);
  CHECK(read_log(second, buffer, sizeof(buffer)) == 0);
  CHECK(strstr(buffer, "after switch marker") != NULL);
  CHECK(strstr(buffer, "before switch marker") == NULL);
  CHECK(strstr(buffer, "silent marker") == NULL);
  if (!blocked) CHECK(strstr(buffer, "after reject marker") != NULL);
  CHECK(unlink(first) == 0 && unlink(second) == 0);
  for (index = 0u; index < 4u; index++) CHECK(unlink(test.paths[index]) == 0);
  CHECK(rmdir(directory) == 0 && descriptors() == baseline);
  return 0;
}

static int limited_scenario(void)
{
  char directory[] = "/tmp/ftun-host-budget-XXXXXX";
  char first[256], second[256], buffer[8192];
  ftun_core_t *core = NULL;
  ftun_core_options_t options = {0};
  ftun_budget_t *budget = NULL;
  ftun_budget_usage_t before, after;
  ftun_app_control_snapshot_t snapshot;
  size_t baseline = descriptors();
  memset(&test, 0, sizeof(test));
  test.limited = true;
  CHECK(mkdtemp(directory) != NULL);
  CHECK(snprintf(first, sizeof(first), "%s/first.log", directory) > 0);
  CHECK(snprintf(second, sizeof(second), "%s/second.log", directory) > 0);
  CHECK(snprintf(test.paths[0], sizeof(test.paths[0]), "%s/first.json", directory) > 0);
  CHECK(snprintf(test.paths[1], sizeof(test.paths[1]), "%s/second.json", directory) > 0);
  CHECK(write_config(test.paths[0], "warn", first) == 0);
  CHECK(write_config(test.paths[1], "warn", second) == 0);
  options.struct_size = sizeof(options);
  options.abi_version = FTUN_ABI_VERSION;
  CHECK(ftun_core_create_with_service(&options, &descriptor, &core) == FTUN_OK);
  CHECK(ftun_core_context_budget(core, &budget) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &before) == FTUN_OK);
  test.expires = now_ms() + 5000u;
  CHECK(ftun_core_run(core, test.paths[0]) == FTUN_OK);
  CHECK(test.step == 4u && test.destroyed && (test.hold).budget == NULL && test.posts == 1u);
  CHECK(ftun_app_control_query(core, &snapshot) == FTUN_OK);
  CHECK(snapshot.log_totals.created == 2u && snapshot.log_totals.destroyed == 2u &&
    snapshot.log_totals.instances == 0u && snapshot.log_totals.queued == 0u);
  CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK);
  CHECK(after.used_resources.descriptors == before.used_resources.descriptors &&
    after.used_resources.queue_slots == before.used_resources.queue_slots);
  CHECK(ftun_core_destroy(&core) == FTUN_OK);
  CHECK(read_log(first, buffer, sizeof(buffer)) == 0 &&
    strstr(buffer, "old sink survives budget rejection") != NULL);
  CHECK(read_log(second, buffer, sizeof(buffer)) == 0 &&
    strstr(buffer, "new sink after budget recovery") != NULL);
  CHECK(unlink(first) == 0 && unlink(second) == 0 &&
    unlink(test.paths[0]) == 0 && unlink(test.paths[1]) == 0);
  CHECK(rmdir(directory) == 0 && descriptors() == baseline);
  return 0;
}

int main(void)
{
  CHECK(scenario(false) == 0);
  CHECK(scenario(true) == 0);
  CHECK(limited_scenario() == 0);
  puts("App host: logger switch, rejected reload, silent, blocked retirement and cleanup passed");
  return 0;
}
