#define _POSIX_C_SOURCE 200809L
#include "app/control.h"
#include "core/io/file.h"
#include "platform/clock.h"
#include "proxy/state/group_cache.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "state lock failed at %d: %s\n", __LINE__, #x); abort(); } } while (0)

static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static bool entered, released;
static atomic_uint completions;
static ftun_core_t *core;
static const char *config_path;
static ftun_status_t run_result;

static uint64_t now(void)
{
  uint64_t value;
  CHECK(ftun_monotonic_now(&value) == FTUN_OK);
  return value;
}

static void pause_once(void)
{
  struct timespec delay = {0, 1000000};
  CHECK(nanosleep(&delay, NULL) == 0);
}

ftun_status_t __real_ftun_group_cache_publish(ftun_budget_t *, const char *, ftun_bytes_t);
ftun_status_t __wrap_ftun_group_cache_publish(ftun_budget_t *budget,
  const char *path, ftun_bytes_t captured)
{
  uint64_t deadline = now() + 10000u;
  /* 阻塞真实发布，取消回调不能使执行中的输入先行释放。 */
  for (;;) {
    bool finished;
    CHECK(pthread_mutex_lock(&gate) == 0);
    entered = true;
    finished = released;
    CHECK(pthread_mutex_unlock(&gate) == 0);
    if (finished) break;
    CHECK(now() < deadline);
    pause_once();
  }
  return __real_ftun_group_cache_publish(budget, path, captured);
}

static void *run(void *unused)
{
  (void)unused;
  run_result = ftun_core_run(core, config_path);
  return NULL;
}

static void completed(ftun_operation_t *operation, ftun_app_command_result_t result, void *unused)
{
  (void)unused;
  CHECK(operation != NULL && result.error.status == FTUN_OK);
  atomic_fetch_add(&completions, 1u);
}

static void submit(ftun_app_command_kind_t kind, const char *first, const char *second)
{
  ftun_app_command_t command = {0};
  ftun_operation_t *operation = NULL;
  command.kind = kind;
  command.first = first;
  command.second = second;
  CHECK(ftun_app_control_submit(core, &command, completed, NULL, &operation) == FTUN_OK);
}

static void wait_completions(unsigned int expected)
{
  uint64_t deadline = now() + 5000u;
  while (atomic_load(&completions) != expected) {
    CHECK(now() < deadline);
    pause_once();
  }
}

static void write_config(const char *cache)
{
  FILE *file = fopen(config_path, "w");
  CHECK(file != NULL);
  CHECK(fprintf(file, "{\"base\":{\"state-cache\":true,\"cache-file\":\"%s\"},"
    "\"log\":{\"level\":\"silent\"},\"dns\":{\"enable\":false,\"fake-ip\":{\"persist\":false}},"
    "\"outbounds\":[{\"name\":\"selector\",\"type\":\"select\","
    "\"outbounds\":[\"DIRECT\",\"REJECT\"],\"default\":\"DIRECT\"}],"
    "\"rules\":[\"MATCH,selector\"]}", cache) > 0);
  CHECK(fclose(file) == 0);
}

int main(void)
{
  char directory[] = "/tmp/ftun-state-lock-XXXXXX";
  char config[256], cache[2][256], lock_path[2][300];
  ftun_core_options_t options = {0};
  ftun_app_control_snapshot_t snapshot;
  ftun_file_lock_t *contender = NULL;
  pthread_t thread;
  uint64_t deadline;
  unsigned int i;
  CHECK(mkdtemp(directory) != NULL);
  CHECK(snprintf(config, sizeof(config), "%s/config.json", directory) > 0);
  config_path = config;
  for (i = 0u; i < 2u; i++) {
    CHECK(snprintf(cache[i], sizeof(cache[i]), "%s/cache-%u", directory, i) > 0);
    CHECK(snprintf(lock_path[i], sizeof(lock_path[i]), "%s.lock", cache[i]) > 0);
  }
  atomic_init(&completions, 0u);
  write_config(cache[0]);
  options.struct_size = sizeof(options);
  options.abi_version = FTUN_ABI_VERSION;
  CHECK(ftun_core_create(&options, &core) == FTUN_OK);
  CHECK(pthread_create(&thread, NULL, run, NULL) == 0);
  deadline = now() + 5000u;
  do {
    CHECK(now() < deadline);
    CHECK(ftun_app_control_query(core, &snapshot) == FTUN_OK);
    pause_once();
  } while (snapshot.core.state != FTUN_CORE_RUNNING);
  submit(FTUN_APP_COMMAND_SELECT, "selector", "REJECT");
  wait_completions(1u);
  deadline = now() + 5000u;
  for (;;) {
    bool running;
    CHECK(pthread_mutex_lock(&gate) == 0);
    running = entered;
    CHECK(pthread_mutex_unlock(&gate) == 0);
    if (running) break;
    CHECK(now() < deadline);
    pause_once();
  }
  submit(FTUN_APP_COMMAND_RELOAD, config, NULL);
  wait_completions(2u);
  CHECK(ftun_app_control_query(core, &snapshot) == FTUN_OK && snapshot.core.generation == 2u);
  write_config(cache[1]);
  submit(FTUN_APP_COMMAND_RELOAD, config, NULL);
  wait_completions(3u);
  CHECK(ftun_app_control_query(core, &snapshot) == FTUN_OK && snapshot.core.generation == 3u);
  CHECK(ftun_file_lock_acquire(lock_path[0], &contender) == FTUN_E_AGAIN);
  CHECK(ftun_file_lock_acquire(lock_path[1], &contender) == FTUN_E_AGAIN);
  CHECK(ftun_core_stop(core, now() + 50u) == FTUN_OK);
  CHECK(pthread_join(thread, NULL) == 0 && run_result == FTUN_E_TIMEOUT);
  CHECK(ftun_core_destroy(&core) == FTUN_E_AGAIN && core != NULL);
  CHECK(ftun_file_lock_acquire(lock_path[0], &contender) == FTUN_E_AGAIN);
  CHECK(pthread_mutex_lock(&gate) == 0);
  released = true;
  CHECK(pthread_mutex_unlock(&gate) == 0);
  deadline = now() + 5000u;
  while (core != NULL) {
    ftun_status_t status = ftun_core_destroy(&core);
    CHECK(status == FTUN_OK || status == FTUN_E_AGAIN);
    CHECK(now() < deadline);
    pause_once();
  }
  for (i = 0u; i < 2u; i++) {
    CHECK(ftun_file_lock_acquire(lock_path[i], &contender) == FTUN_OK);
    CHECK(ftun_file_lock_release(&contender) == FTUN_OK);
    CHECK(unlink(lock_path[i]) == 0);
  }
  CHECK(unlink(cache[0]) == 0);
  CHECK(access(cache[1], F_OK) != 0);
  CHECK(unlink(config) == 0 && rmdir(directory) == 0);
  CHECK(pthread_mutex_destroy(&gate) == 0);
  puts("State locks: same-path reload, path swap, timed stop and true Worker completion passed");
  return 0;
}
