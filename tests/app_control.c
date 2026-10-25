#define _POSIX_C_SOURCE 200809L
#include "app/control.h"
#include "core/core.h"
#include "config/config.h"
#include "config/compile.h"
#include "util/time.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "app control failed at %d: %s\n", __LINE__, #x); return 1; } } while (0)
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "app control owner failed at %d: %s\n", __LINE__, #x); return FTUN_E_STATE_CORRUPT; } } while (0)

typedef struct {
  ftun_core_t *core;
  char paths[2][256];
  unsigned int step, reload_done, stale_done, cancel_done;
  bool select_supported, failed;
  uint64_t deadline;
  atomic_bool reader_stop;
  atomic_uint reader_errors, reader_queries;
  ftun_app_control_snapshot_t saved;
} control_test_t;
static control_test_t test;

static uint64_t now(void)
{
  uint64_t value = 0u;
  if (ftun_monotonic_now(&value) != FTUN_OK) abort();
  return value;
}
static void pause_once(void)
{
  struct timespec delay = {0, 1000000};
  (void)nanosleep(&delay, NULL);
}
static void completed(ftun_operation_t *operation, ftun_app_command_result_t result, void *user)
{
  unsigned int kind = (unsigned int)(uintptr_t)user;
  if (operation == NULL) test.failed = true;
  if (kind == 0u) {
    if (result.kind != FTUN_APP_COMMAND_RELOAD || result.error.status != FTUN_OK ||
        result.phase != FTUN_APP_COMMAND_COMPLETED || result.generation != 2u) test.failed = true;
    test.reload_done++;
  } else if (kind == 1u) {
    if (result.kind != FTUN_APP_COMMAND_SELECT || result.error.status != FTUN_E_STALE ||
        result.phase != FTUN_APP_COMMAND_FAILED || result.generation != 2u) test.failed = true;
    test.stale_done++;
  } else {
    if (result.kind != FTUN_APP_COMMAND_RELOAD || result.error.status != FTUN_E_CANCELLED ||
        result.phase != FTUN_APP_COMMAND_CANCELLED || result.generation != 2u) test.failed = true;
    test.cancel_done++;
  }
}
static ftun_status_t submit(ftun_app_command_kind_t kind, const char *first,
  const char *second, uint64_t generation, unsigned int tag, ftun_operation_t **out)
{
  ftun_app_command_t command;
  memset(&command, 0, sizeof(command));
  command.kind = kind;
  command.first = first;
  command.second = second;
  command.expected.present = true;
  command.expected.generation = generation;
  return ftun_app_control_submit(test.core, &command, completed, (void *)(uintptr_t)tag, out);
}
static ftun_status_t prepare(ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations, const ftun_core_service_binding_t *binding,
  const ftun_config_t *config, uint64_t generation, void **out)
{
  (void)budget; (void)operations; (void)binding; (void)config;
  REQUIRE(core == test.core && generation == 1u);
  *out = &test;
  return FTUN_OK;
}
static ftun_status_t plan_prepare(ftun_budget_t *budget,
  const ftun_config_t *config, uint32_t mark, void **out)
{
  (void)budget;
  (void)mark;
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
  REQUIRE(instance == &test && config != NULL && generation == 2u);
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
  ftun_operation_t *operation = NULL;
  REQUIRE(instance == &test && generation == 2u);
  /* 此时宿主尚未发布新代次。接纳后，下一 owner 轮必须拒绝旧代命令。 */
  if (test.select_supported) {
    REQUIRE(submit(FTUN_APP_COMMAND_SELECT, "missing", "missing", 1u, 1u, &operation) == FTUN_OK);
  }
  return FTUN_OK;
}
static ftun_status_t run_once(void *instance, bool may_block, ftun_core_service_run_usage_t *usage)
{
  ftun_app_control_snapshot_t snapshot;
  ftun_app_command_result_t result;
  ftun_app_generation_guard_t guard = {true, 1u};
  ftun_operation_t *operation = NULL;
  (void)may_block;
  REQUIRE(instance == &test && !test.failed && now() < test.deadline);
  memset(usage, 0, sizeof(*usage));
  usage->work = 1u;
  REQUIRE(ftun_app_control_query(test.core, &snapshot) == FTUN_OK);
  if (test.step == 0u) {
    char path[256];
    char oversized[FTUN_APP_CONTROL_PATH_CAPACITY + 1u];
    REQUIRE(snapshot.core.generation == 1u && !strcmp(snapshot.config_path, test.paths[0]));
    test.saved = snapshot;
    REQUIRE(submit(FTUN_APP_COMMAND_RELOAD, test.paths[1], NULL, 0u, 0u, &operation) == FTUN_E_STALE && operation == NULL);
    memset(oversized, 'x', sizeof(oversized));
    REQUIRE(submit(FTUN_APP_COMMAND_RELOAD, oversized, NULL, 1u, 0u, &operation) == FTUN_E_LIMIT && operation == NULL);
    REQUIRE(ftun_app_control_query(test.core, &snapshot) == FTUN_OK &&
      snapshot.events.last.kind == FTUN_LIFECYCLE_RELOAD_REJECTED &&
      snapshot.events.last.reason == FTUN_LIFECYCLE_REASON_ADMISSION &&
      snapshot.events.last.status == FTUN_E_LIMIT);
    guard.generation = 0u;
    REQUIRE(ftun_app_control_stop(test.core, now() + 1000u, guard, &result) == FTUN_E_STALE);
    REQUIRE(result.phase == FTUN_APP_COMMAND_FAILED && result.generation == 1u);
    REQUIRE(ftun_app_control_query(test.core, &snapshot) == FTUN_OK && !snapshot.stop_requested);
    memcpy(path, test.paths[1], sizeof(path));
    REQUIRE(submit(FTUN_APP_COMMAND_RELOAD, path, NULL, 1u, 0u, &operation) == FTUN_OK);
    memset(path, 'z', sizeof(path)); /* 接纳后不再借用命令字符串。 */
    test.step = 1u;
  } else if (test.step == 1u && test.reload_done == 1u &&
      (!test.select_supported || test.stale_done == 1u)) {
    REQUIRE(snapshot.core.generation == 2u && !strcmp(snapshot.config_path, test.paths[1]));
    REQUIRE(!snapshot.reload_pending && test.saved.core.generation == 1u &&
      !strcmp(test.saved.config_path, test.paths[0]));
    REQUIRE(submit(FTUN_APP_COMMAND_RELOAD, test.paths[0], NULL, 2u, 2u, &operation) == FTUN_OK);
    REQUIRE(ftun_operation_cancel(operation) == FTUN_OK);
    test.step = 2u;
  } else if (test.step == 2u && test.cancel_done == 1u) {
    REQUIRE(snapshot.events.last.kind == FTUN_LIFECYCLE_RELOAD_CANCELLED &&
      snapshot.events.last.generation == 2u && snapshot.events.last.status == FTUN_E_CANCELLED);
    REQUIRE(snapshot.core.generation == 2u && !snapshot.reload_pending);
    guard.generation = 2u;
    REQUIRE(ftun_app_control_stop(test.core, now() + 1000u, guard, &result) == FTUN_OK);
    REQUIRE(result.kind == FTUN_APP_COMMAND_STOP && result.phase == FTUN_APP_COMMAND_REQUESTED);
    REQUIRE(ftun_app_control_query(test.core, &snapshot) == FTUN_OK && snapshot.stop_requested);
    REQUIRE(submit(FTUN_APP_COMMAND_RELOAD, test.paths[0], NULL, 2u, 2u, &operation) == FTUN_E_STALE && operation == NULL);
    test.step = 3u;
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
  REQUIRE(*instance == &test);
  *instance = NULL;
  return FTUN_OK;
}
static const ftun_core_service_descriptor_t descriptor = {
  "control-test", plan_prepare, plan_destroy, prepare, success, reload_prepare, reload_planned,
  reload_commit, success, run_once, success, success, stop_until, stop_until, destroy_until
};
static void *reader(void *unused)
{
  (void)unused;
  while (!atomic_load(&test.reader_stop)) {
    ftun_app_control_snapshot_t snapshot;
    if (ftun_app_control_query(test.core, &snapshot) != FTUN_OK ||
        (snapshot.core.generation == 0u && snapshot.config_path[0] != '\0') ||
        (snapshot.core.generation == 1u && strcmp(snapshot.config_path, test.paths[0])) ||
        (snapshot.core.generation == 2u && strcmp(snapshot.config_path, test.paths[1])) ||
        snapshot.core.generation > 2u) atomic_fetch_add(&test.reader_errors, 1u);
    atomic_fetch_add(&test.reader_queries, 1u);
    pause_once();
  }
  return NULL;
}
int main(void)
{
  char directory[] = "/tmp/ftun-control-XXXXXX";
  ftun_core_options_t options;
  ftun_app_control_snapshot_t snapshot;
  ftun_app_command_result_t result;
  ftun_app_generation_guard_t guard = {true, 2u};
  ftun_core_info_t public_info;
  pthread_t thread;
  unsigned int i;
  memset(&test, 0, sizeof(test));
  atomic_init(&test.reader_stop, false);
  atomic_init(&test.reader_errors, 0u);
  atomic_init(&test.reader_queries, 0u);
  CHECK(mkdtemp(directory) != NULL);
  for (i = 0u; i < 2u; i++) {
    FILE *file;
    CHECK(snprintf(test.paths[i], sizeof(test.paths[i]), "%s/config-%u.json", directory, i) > 0);
    file = fopen(test.paths[i], "w");
    CHECK(file != NULL);
    CHECK(fputs("{\"base\":{\"state-cache\":false},\"dns\":{\"enable\":false},\"log\":{\"level\":\"silent\"}}", file) >= 0);
    CHECK(fclose(file) == 0);
  }
  memset(&options, 0, sizeof(options));
  options.struct_size = sizeof(options);
  options.abi_version = FTUN_ABI_VERSION;
  CHECK(ftun_core_create_with_service(&options, &descriptor, &test.core) == FTUN_OK);
  CHECK(ftun_app_control_query(test.core, &snapshot) == FTUN_OK);
  CHECK(snapshot.core.state == FTUN_CORE_CREATED && snapshot.core.generation == 0u && !snapshot.config_path[0]);
  CHECK(snapshot.build_modules == ftun_build_capabilities()->builtins);
  CHECK((snapshot.commands & (FTUN_APP_CONTROL_RELOAD | FTUN_APP_CONTROL_STOP)) ==
    (FTUN_APP_CONTROL_RELOAD | FTUN_APP_CONTROL_STOP));
  test.select_supported = (snapshot.commands & FTUN_APP_CONTROL_SELECT) != 0u;
  CHECK(pthread_create(&thread, NULL, reader, NULL) == 0);
  test.deadline = now() + 5000u;
  CHECK(ftun_core_run(test.core, test.paths[0]) == FTUN_OK);
  atomic_store(&test.reader_stop, true);
  CHECK(pthread_join(thread, NULL) == 0);
  CHECK(test.step == 3u && !test.failed && test.reload_done == 1u && test.cancel_done == 1u);
  CHECK(atomic_load(&test.reader_errors) == 0u && atomic_load(&test.reader_queries) != 0u);
  CHECK(ftun_app_control_query(test.core, &snapshot) == FTUN_OK && snapshot.core.state == FTUN_CORE_STOPPED);
  CHECK(ftun_core_get_info(test.core, &public_info) == FTUN_OK && public_info.generation == snapshot.core.generation);
  CHECK(ftun_app_control_stop(test.core, now() + 1000u, guard, &result) == FTUN_OK && result.phase == FTUN_APP_COMMAND_COMPLETED);
  CHECK(ftun_core_destroy(&test.core) == FTUN_OK);
  CHECK(!strcmp(test.saved.config_path, test.paths[0]) && !strcmp(snapshot.config_path, test.paths[1]));
  for (i = 0u; i < 2u; i++) CHECK(unlink(test.paths[i]) == 0);
  CHECK(rmdir(directory) == 0);
  puts("App control: owned snapshots, generation guards, cancellation and stop phases passed");
  return 0;
}
