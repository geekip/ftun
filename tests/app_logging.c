#define _POSIX_C_SOURCE 200809L
#include "core/core.h"
#include "app/control.h"
#include "util/time.h"
#include "core/worker.h"
#include "config/compile.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "app logging failed at %d: %s\n", __LINE__, #x); \
  return 1; \
} } while (0)

typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  ftun_core_t *core;
  bool slow, fail, release, fail_prepare;
  unsigned int destroyed;
  unsigned int fail_poll_at, polls, rounds;
  char text[32768];
  size_t length;
} test_t;

static test_t test;

static uint64_t now_ms(void)
{
  uint64_t now = 0u;
  if (ftun_monotonic_now(&now) != FTUN_OK) abort();
  return now;
}

static ftun_status_t write_line(void *user, ftun_bytes_t line)
{
  test_t *state = user;
  (void)pthread_mutex_lock(&state->mutex);
  while (state->slow && !state->release) {
    (void)pthread_cond_wait(&state->condition, &state->mutex);
  }
  (void)pthread_mutex_unlock(&state->mutex);
  if (state->fail) return FTUN_E_IO;
  if (line.length >= sizeof(state->text) - state->length) return FTUN_E_LIMIT;
  memcpy(state->text + state->length, line.data, line.length);
  state->length += line.length;
  state->text[state->length] = '\0';
  return FTUN_OK;
}

ftun_status_t __real_ftun_logger_create(const ftun_logger_options_t *options,
  ftun_logger_t **out);
ftun_status_t __wrap_ftun_logger_create(const ftun_logger_options_t *options,
  ftun_logger_t **out)
{
  ftun_logger_options_t copy = *options;
  /* 仅替换外部 writer；保留生产容量、level 和共享 ledger 绑定。 */
  copy.path = NULL;
  copy.writer = write_line;
  copy.writer_user = &test;
  return __real_ftun_logger_create(&copy, out);
}

ftun_status_t __real_ftun_worker_poll(ftun_worker_t *worker, size_t maximum, size_t *callbacks);
ftun_status_t __wrap_ftun_worker_poll(ftun_worker_t *worker, size_t maximum, size_t *callbacks)
{
  test.polls++;
  if (test.polls == test.fail_poll_at) {
    *callbacks = 0u;
    return FTUN_E_IO;
  }
  return __real_ftun_worker_poll(worker, maximum, callbacks);
}

static ftun_status_t plan_prepare(ftun_budget_t *budget,
  const ftun_config_t *config, uint32_t mark, void **out)
{
  (void)budget;
  (void)mark;
  *out = (void *)config;
  return FTUN_OK;
}

static ftun_status_t plan_destroy(void **out)
{
  *out = NULL;
  return FTUN_OK;
}

static ftun_status_t prepare(ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations, const ftun_core_service_binding_t *binding,
  const ftun_config_t *config, uint64_t generation, void **out)
{
  (void)budget; (void)operations; (void)binding; (void)config; (void)generation;
  test.core = core;
  *out = &test;
  return test.fail_prepare ? FTUN_E_IO : FTUN_OK;
}

static ftun_status_t success(void *instance)
{
  return instance == &test ? FTUN_OK : FTUN_E_INVALID;
}

static ftun_status_t reload_prepare(void *instance, const ftun_config_t *config,
  uint64_t generation)
{
  (void)config; (void)generation;
  return success(instance);
}

static ftun_status_t reload_planned(void *instance, const ftun_config_t *config,
  uint64_t generation, const void *plan)
{
  (void)plan;
  return reload_prepare(instance, config, generation);
}

static ftun_status_t reload_commit(void *instance, uint64_t generation)
{
  (void)generation;
  return success(instance);
}

static ftun_status_t run_once(void *instance, bool may_block,
  ftun_core_service_run_usage_t *usage)
{
  (void)instance; (void)may_block;
  memset(usage, 0, sizeof(*usage));
  test.rounds++;
  return ftun_core_stop(test.core, now_ms() + (test.slow ? 50u : 5000u));
}

static ftun_status_t stop_until(void *instance, uint64_t deadline)
{
  (void)deadline;
  return success(instance);
}

static ftun_status_t destroy_until(void **instance, uint64_t deadline)
{
  (void)deadline;
  if (*instance != &test) return FTUN_E_INVALID;
  test.destroyed++;
  *instance = NULL;
  return FTUN_OK;
}

static const ftun_core_service_descriptor_t descriptor = {
  "logging-test", plan_prepare, plan_destroy, prepare, success,
  reload_prepare, reload_planned, reload_commit, success, run_once,
  success, success, stop_until, stop_until, destroy_until
};

static int scenario(const char *path, bool slow, bool fail, bool fail_prepare,
  unsigned int fail_poll_at)
{
  ftun_core_t *core = NULL;
  ftun_core_options_t options = {0};
  ftun_app_control_snapshot_t snapshot;
  uint64_t started;
  ftun_status_t expected = slow ? FTUN_E_TIMEOUT :
    (fail_prepare || fail_poll_at != 0u) ? FTUN_E_IO : FTUN_OK;
  memset(&test, 0, sizeof(test));
  test.slow = slow;
  test.fail = fail;
  test.fail_prepare = fail_prepare;
  test.fail_poll_at = fail_poll_at;
  CHECK(pthread_mutex_init(&test.mutex, NULL) == 0);
  CHECK(pthread_cond_init(&test.condition, NULL) == 0);
  options.struct_size = sizeof(options);
  options.abi_version = FTUN_ABI_VERSION;
  CHECK(ftun_core_create_with_service(&options, &descriptor, &core) == FTUN_OK);
  CHECK(ftun_app_control_query(core, &snapshot) == FTUN_OK &&
    !snapshot.run_returned && !snapshot.runtime_stopped && snapshot.log_totals.created == 0u);
  started = now_ms();
  CHECK(ftun_core_run(core, path) == expected);
  CHECK(!slow || now_ms() - started < 1000u);
  CHECK(ftun_app_control_query(core, &snapshot) == FTUN_OK);
  CHECK(snapshot.run_returned && snapshot.runtime_stopped && snapshot.events.closed &&
    !snapshot.logger_present && test.destroyed == 1u);
  CHECK(snapshot.run_result == expected);
  CHECK(snapshot.events.last.kind == FTUN_LIFECYCLE_STOPPED &&
    snapshot.events.last.status == (fail_prepare || fail_poll_at != 0u ? FTUN_E_IO : FTUN_OK));
  CHECK(snapshot.log_totals.created == 1u && snapshot.log_totals.dropped == 0u);
  if (slow) {
    CHECK(snapshot.core.state == FTUN_CORE_STOPPING && snapshot.log_totals.instances == 1u &&
      snapshot.log_totals.queued > 0u && snapshot.log_totals.written == 0u);
    CHECK(ftun_core_destroy(&core) == FTUN_E_AGAIN && core != NULL);
    (void)pthread_mutex_lock(&test.mutex);
    test.release = true;
    (void)pthread_cond_broadcast(&test.condition);
    (void)pthread_mutex_unlock(&test.mutex);
    do {
      const struct timespec pause = {0, 1000000};
      (void)nanosleep(&pause, NULL);
      CHECK(ftun_app_control_query(core, &snapshot) == FTUN_OK);
      CHECK(now_ms() - started < 5000u);
    } while (snapshot.log_totals.queued != 0u);
    CHECK(snapshot.core.state == FTUN_CORE_STOPPING && snapshot.run_result == FTUN_E_TIMEOUT);
  } else {
    CHECK(snapshot.core.state == (fail_prepare ? FTUN_CORE_CREATED : FTUN_CORE_STOPPED));
    CHECK(snapshot.log_totals.instances == 0u && snapshot.log_totals.destroyed == 1u &&
      snapshot.log_totals.queued == 0u && snapshot.log_totals.emitted > 0u);
    CHECK(snapshot.log_totals.emitted == (fail ? snapshot.log_totals.io_errors : snapshot.log_totals.written));
  }
  if (fail_prepare) {
    uint64_t previous = snapshot.log_totals.emitted;
    test.fail_prepare = false;
    CHECK(ftun_core_run(core, path) == FTUN_OK);
    CHECK(ftun_app_control_query(core, &snapshot) == FTUN_OK && snapshot.runtime_stopped &&
      snapshot.run_returned && snapshot.run_result == FTUN_OK &&
      snapshot.core.state == FTUN_CORE_STOPPED && snapshot.log_totals.created == 2u &&
      snapshot.log_totals.destroyed == 2u && snapshot.log_totals.emitted > previous);
  }
  for (;;) {
    ftun_status_t status = ftun_core_destroy(&core);
    if (status == FTUN_OK) break;
    CHECK(status == FTUN_E_AGAIN && now_ms() - started < 5000u);
  }
  if (!fail) {
    const char *terminal = strstr(test.text, "event=runtime.stopped ");
    CHECK(terminal != NULL);
    if (!fail_prepare) CHECK(strchr(terminal, '\n') == test.text + test.length - 1u);
  }
  if (fail_poll_at != 0u) {
    CHECK(test.rounds == 0u && strstr(test.text, "production data plane failed") == NULL);
    if (fail_poll_at == 1u) {
      CHECK(strstr(test.text, "message=reload worker failed\n") != NULL &&
        strstr(test.text, "state worker failed") == NULL);
    } else CHECK(strstr(test.text, "message=state worker failed\n") != NULL &&
      strstr(test.text, "reload worker failed") == NULL);
  }
  CHECK(pthread_cond_destroy(&test.condition) == 0);
  CHECK(pthread_mutex_destroy(&test.mutex) == 0);
  return 0;
}

int main(void)
{
  char directory[] = "/tmp/ftun-app-logging-XXXXXX";
  char path[256];
  FILE *file;
  CHECK(mkdtemp(directory) != NULL);
  CHECK(snprintf(path, sizeof(path), "%s/config.json", directory) > 0);
  file = fopen(path, "w");
  CHECK(file != NULL);
  CHECK(fprintf(file, "{\"base\":{\"state-cache\":false},\"dns\":{\"enable\":false},"
    "\"log\":{\"level\":\"info\",\"file\":\"%s/output.log\"}}", directory) > 0);
  CHECK(fclose(file) == 0);
  CHECK(scenario(path, false, false, false, 0u) == 0);
  CHECK(scenario(path, true, false, false, 0u) == 0);
  CHECK(scenario(path, false, true, false, 0u) == 0);
  CHECK(scenario(path, false, false, true, 0u) == 0);
  CHECK(scenario(path, false, false, false, 1u) == 0);
  if ((ftun_build_capabilities()->builtins & FTUN_BUILD_MODULE_PROXY) != 0u) {
    CHECK(scenario(path, false, false, false, 2u) == 0);
  }
  CHECK(unlink(path) == 0 && rmdir(directory) == 0);
  puts("App logging: terminal ordering, slow/failed writer, retained results and startup retry passed");
  return 0;
}
