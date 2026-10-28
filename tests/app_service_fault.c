#define _POSIX_C_SOURCE 200809L
#include "app/control.h"
#include "core/core.h"
#include "util/time.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "service fault failed at %d: %s\n", __LINE__, #x); return 1; } } while (0)
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "service fault owner failed at %d: %s\n", __LINE__, #x); return FTUN_E_STATE_CORRUPT; } } while (0)

typedef enum {
  MODE_FAULTS_NO_PAUSE,   /* 非致命错误，不支持暂停：计数并继续 */
  MODE_FAULTS_PAUSE,      /* 非致命错误，支持暂停：run_once 暂停，maintain_once 继续 */
  MODE_STATE_CORRUPT,     /* 返回 STATE_CORRUPT：停机 */
  MODE_FATAL_FLAG,        /* usage.fatal：停机 */
  MODE_SCOPED_FAULTS      /* 返回 OK 但上报范围计数：计数并继续 */
} mode_t_;

typedef struct {
  ftun_core_t *core;
  mode_t_ mode;
  unsigned int run_calls, maintain_calls, faults_left;
  uint64_t first_fault_ms, resumed_ms;
  bool saw_paused, run_while_paused, stop_sent, failed;
  uint64_t deadline;
} fault_test_t;
static fault_test_t test;

static uint64_t now(void)
{
  uint64_t value = 0u;
  if (ftun_monotonic_now(&value) != FTUN_OK) abort();
  return value;
}
static ftun_status_t prepare(ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations, const ftun_core_service_binding_t *binding,
  const ftun_config_t *config, uint64_t generation, void **out)
{
  (void)core; (void)budget; (void)operations; (void)binding; (void)config; (void)generation;
  *out = &test;
  return FTUN_OK;
}
static ftun_status_t plan_prepare(ftun_budget_t *budget, const ftun_config_t *config,
  uint32_t mark, void **out)
{
  (void)budget; (void)mark;
  *out = (void *)config;
  return FTUN_OK;
}
static ftun_status_t plan_destroy(void **plan)
{
  *plan = NULL;
  return FTUN_OK;
}
static ftun_status_t success(void *instance)
{
  return instance == &test ? FTUN_OK : FTUN_E_INVALID;
}
static ftun_status_t reload_prepare(void *instance, const ftun_config_t *config, uint64_t generation)
{
  (void)instance; (void)config; (void)generation;
  return FTUN_OK;
}
static ftun_status_t reload_planned(void *instance, const ftun_config_t *config,
  uint64_t generation, const void *plan)
{
  (void)plan;
  return reload_prepare(instance, config, generation);
}
static ftun_status_t reload_commit(void *instance, uint64_t generation)
{
  (void)instance; (void)generation;
  return FTUN_OK;
}
static ftun_status_t stop_core(void)
{
  if (!test.stop_sent) {
    test.stop_sent = true;
    return ftun_core_stop(test.core, now() + 2000u);
  }
  return FTUN_OK;
}
static ftun_status_t run_once(void *instance, bool may_block, ftun_core_service_run_usage_t *usage)
{
  ftun_app_control_snapshot_t snapshot;
  (void)may_block;
  REQUIRE(instance == &test && now() < test.deadline);
  memset(usage, 0, sizeof(*usage));
  usage->work = 1u;
  test.run_calls++;
  switch (test.mode) {
  case MODE_FAULTS_NO_PAUSE:
    if (test.faults_left != 0u) { test.faults_left--; return FTUN_E_IO; }
    REQUIRE(ftun_app_control_query(test.core, &snapshot) == FTUN_OK);
    REQUIRE(snapshot.service_faults[FTUN_FAULT_SCOPE_SERVICE] == 5u && !snapshot.service_paused &&
            snapshot.service_pauses == 0u);
    return stop_core();
  case MODE_FAULTS_PAUSE:
    if (test.faults_left != 0u) {
      test.faults_left--;
      test.first_fault_ms = now();
      return FTUN_E_IO;
    }
    /* 暂停期间不得调用 run_once；能再次进入说明恢复门已放行。 */
    if (test.maintain_calls == 0u) test.run_while_paused = true;
    test.resumed_ms = now();
    REQUIRE(ftun_app_control_query(test.core, &snapshot) == FTUN_OK);
    REQUIRE(!snapshot.service_paused && snapshot.service_pauses == 1u);
    return stop_core();
  case MODE_STATE_CORRUPT:
    return test.run_calls == 3u ? FTUN_E_STATE_CORRUPT : FTUN_E_IO;
  case MODE_FATAL_FLAG:
    usage->fatal = test.run_calls == 2u;
    return FTUN_OK;
  case MODE_SCOPED_FAULTS:
    usage->faults[FTUN_FAULT_SCOPE_LISTENER] = 2u;
    usage->faults[FTUN_FAULT_SCOPE_OBJECT] = 1u;
    if (test.run_calls < 4u) return FTUN_OK;
    REQUIRE(ftun_app_control_query(test.core, &snapshot) == FTUN_OK);
    REQUIRE(snapshot.service_faults[FTUN_FAULT_SCOPE_LISTENER] >= 6u &&
            snapshot.service_faults[FTUN_FAULT_SCOPE_OBJECT] >= 3u &&
            snapshot.service_faults[FTUN_FAULT_SCOPE_SERVICE] == 0u);
    return stop_core();
  }
  return FTUN_E_STATE_CORRUPT;
}
static ftun_status_t maintain_once(void *instance, uint64_t now_ms, size_t quota,
  ftun_core_service_run_usage_t *usage)
{
  ftun_app_control_snapshot_t snapshot;
  REQUIRE(instance == &test && quota != 0u && now_ms != 0u);
  memset(usage, 0, sizeof(*usage));
  test.maintain_calls++;
  if (!test.saw_paused) {
    REQUIRE(ftun_app_control_query(test.core, &snapshot) == FTUN_OK && snapshot.service_paused);
    test.saw_paused = true;
  }
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
  REQUIRE(*instance == &test);
  *instance = NULL;
  return FTUN_OK;
}
static const ftun_core_service_descriptor_t plain = {
  "fault-plain", plan_prepare, plan_destroy, prepare, success, reload_prepare, reload_planned,
  reload_commit, success, run_once, success, success, stop_until, stop_until, destroy_until,
  NULL,
  NULL /* network_changed */
};
static const ftun_core_service_descriptor_t pausable = {
  "fault-pausable", plan_prepare, plan_destroy, prepare, success, reload_prepare, reload_planned,
  reload_commit, success, run_once, success, success, stop_until, stop_until, destroy_until,
  maintain_once,
  NULL /* network_changed */
};

static int run_mode(const char *path, mode_t_ mode, bool pausable_service, ftun_status_t expected)
{
  ftun_core_options_t options;
  ftun_status_t status;
  memset(&test, 0, sizeof(test));
  test.mode = mode;
  test.faults_left = mode == MODE_FAULTS_NO_PAUSE ? 5u : 1u;
  test.deadline = now() + 8000u;
  memset(&options, 0, sizeof(options));
  options.struct_size = sizeof(options);
  options.abi_version = FTUN_ABI_VERSION;
  CHECK(ftun_core_create_with_service(&options, pausable_service ? &pausable : &plain, &test.core) == FTUN_OK);
  status = ftun_core_run(test.core, path);
  CHECK(status == expected);
  CHECK(ftun_core_destroy(&test.core) == FTUN_OK);
  return 0;
}

int main(void)
{
  char directory[] = "/tmp/ftun-fault-XXXXXX";
  char path[256];
  FILE *file;
  CHECK(mkdtemp(directory) != NULL);
  CHECK(snprintf(path, sizeof(path), "%s/config.json", directory) > 0);
  file = fopen(path, "w");
  CHECK(file != NULL);
  CHECK(fputs("{\"base\":{\"state-cache\":false},\"dns\":{\"enable\":false},\"log\":{\"level\":\"silent\"}}", file) >= 0);
  CHECK(fclose(file) == 0);

  /* 非致命错误：不停机，计数，没有暂停能力时继续调用 run_once。 */
  if (run_mode(path, MODE_FAULTS_NO_PAUSE, false, FTUN_OK)) return 1;
  CHECK(test.run_calls == 6u && test.maintain_calls == 0u);

  /* 支持暂停：首次故障后进入暂停，maintain_once 继续被调用，run_once 不被调用；
   * 约 1s（1000ms ± 20%）后恢复，之后正常运行。 */
  if (run_mode(path, MODE_FAULTS_PAUSE, true, FTUN_OK)) return 1;
  CHECK(test.run_calls == 2u && test.saw_paused && test.maintain_calls > 10u && !test.run_while_paused);
  CHECK(test.resumed_ms - test.first_fault_ms >= 790u && test.resumed_ms - test.first_fault_ms < 1600u);

  /* STATE_CORRUPT 与 usage.fatal 才停机，错误原样返回。 */
  if (run_mode(path, MODE_STATE_CORRUPT, false, FTUN_E_STATE_CORRUPT)) return 1;
  CHECK(test.run_calls == 3u);
  if (run_mode(path, MODE_FATAL_FLAG, false, FTUN_E_STATE_CORRUPT)) return 1;
  CHECK(test.run_calls == 2u);

  /* 服务内部就地处理的故障只累计计数。 */
  if (run_mode(path, MODE_SCOPED_FAULTS, false, FTUN_OK)) return 1;

  CHECK(unlink(path) == 0);
  CHECK(rmdir(directory) == 0);
  puts("App service fault: non-fatal faults continue, pause/resume, fatal stops passed");
  return 0;
}
