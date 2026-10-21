#define _POSIX_C_SOURCE 200809L

#include "ftun/ftun.h"
#include "proxy/runtime_state.h"
#include "proxy/state/group_cache.h"
#include "util/time.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "v0.5 integration failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  ftun_core_t *core;
  ftun_runtime_t *old_runtime;
  ftun_operation_t *cancel_target;
  ftun_status_t status;
  uint32_t stage;
  size_t callbacks;
  int entered;
  int target_ready;
  int callback_failed;
} test_context_t;

typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  ftun_core_t *core;
  const char *path;
  ftun_status_t result;
  int done;
} run_context_t;

static int write_text(const char *path, const char *text)
{
  FILE *file = fopen(path, "wb");
  size_t length = strlen(text);
  int ok;
  if (file == NULL) return 0;
  ok = fwrite(text, 1u, length, file) == length && fflush(file) == 0;
  if (fclose(file) != 0) ok = 0;
  return ok;
}

static int unblock_fifo(const char *path)
{
  int descriptor = open(path, O_WRONLY | O_CLOEXEC);
  if (descriptor < 0) return 0;
  return close(descriptor) == 0;
}

static void signal_result(test_context_t *context, ftun_error_t result)
{
  (void)pthread_mutex_lock(&context->mutex);
  context->status = result.status;
  context->stage = result.stage;
  context->callbacks++;
  (void)pthread_cond_broadcast(&context->condition);
  (void)pthread_mutex_unlock(&context->mutex);
}

static void normal_done(ftun_operation_t *operation, ftun_error_t result,
                        void *user)
{
  (void)operation;
  signal_result((test_context_t *)user, result);
}

static void acquire_done(ftun_operation_t *operation, ftun_error_t result,
                         void *user)
{
  test_context_t *context = (test_context_t *)user;
  (void)operation;
  if (result.status == FTUN_OK &&
      ftun_runtime_active_acquire(context->core,
                                  &context->old_runtime) != FTUN_OK) {
    context->callback_failed = 1;
  }
  signal_result(context, result);
}

static void reload_done(ftun_operation_t *operation, ftun_error_t result,
                        void *user)
{
  test_context_t *context = (test_context_t *)user;
  ftun_runtime_info_t info;
  (void)operation;
  if (result.status != FTUN_OK || context->old_runtime == NULL ||
      ftun_runtime_get_info(context->old_runtime, &info) != FTUN_OK ||
      info.state != FTUN_RUNTIME_RETAINED || info.generation != 1u ||
      ftun_runtime_release(&context->old_runtime) != FTUN_OK) {
    context->callback_failed = 1;
  }
  signal_result(context, result);
}

static void select_done(ftun_operation_t *operation, ftun_error_t result,
                        void *user)
{
  test_context_t *context = (test_context_t *)user;
  ftun_runtime_group_record_t records[1];
  size_t count = 0u;
  (void)operation;
  if (result.status != FTUN_OK ||
      ftun_runtime_group_records(context->core, records, 1u, &count) != FTUN_OK ||
      count != 1u || records[0].member.length != 6u ||
      memcmp(records[0].member.data, "node-b", 6u) != 0) {
    context->callback_failed = 1;
  }
  signal_result(context, result);
}

static void cancelling_done(ftun_operation_t *operation, ftun_error_t result,
                            void *user)
{
  test_context_t *context = (test_context_t *)user;
  (void)operation;
  (void)pthread_mutex_lock(&context->mutex);
  context->entered = 1;
  (void)pthread_cond_broadcast(&context->condition);
  while (!context->target_ready) {
    (void)pthread_cond_wait(&context->condition, &context->mutex);
  }
  (void)pthread_mutex_unlock(&context->mutex);
  if (result.status != FTUN_OK ||
      ftun_operation_cancel(context->cancel_target) != FTUN_OK) {
    context->callback_failed = 1;
  }
  signal_result(context, result);
}

static void *run_core(void *user)
{
  run_context_t *context = (run_context_t *)user;
  context->result = ftun_core_run(context->core, context->path);
  (void)pthread_mutex_lock(&context->mutex);
  context->done = 1;
  (void)pthread_cond_broadcast(&context->condition);
  (void)pthread_mutex_unlock(&context->mutex);
  return NULL;
}

static int wait_run_done(run_context_t *context, time_t seconds)
{
  struct timespec deadline;
  if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) return 0;
  deadline.tv_sec += seconds;
  (void)pthread_mutex_lock(&context->mutex);
  while (!context->done) {
    if (pthread_cond_timedwait(&context->condition, &context->mutex,
                               &deadline) != 0) {
      (void)pthread_mutex_unlock(&context->mutex);
      return 0;
    }
  }
  (void)pthread_mutex_unlock(&context->mutex);
  return 1;
}

static int wait_callbacks(test_context_t *context, size_t expected)
{
  struct timespec deadline;
  if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) return 0;
  deadline.tv_sec += 5;
  (void)pthread_mutex_lock(&context->mutex);
  while (context->callbacks < expected) {
    if (pthread_cond_timedwait(&context->condition, &context->mutex,
                               &deadline) != 0) {
      (void)pthread_mutex_unlock(&context->mutex);
      return 0;
    }
  }
  (void)pthread_mutex_unlock(&context->mutex);
  return 1;
}

static int wait_entered(test_context_t *context)
{
  struct timespec deadline;
  if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) return 0;
  deadline.tv_sec += 5;
  (void)pthread_mutex_lock(&context->mutex);
  while (!context->entered) {
    if (pthread_cond_timedwait(&context->condition, &context->mutex,
                               &deadline) != 0) {
      (void)pthread_mutex_unlock(&context->mutex);
      return 0;
    }
  }
  (void)pthread_mutex_unlock(&context->mutex);
  return 1;
}

static int wait_running(ftun_core_t *core)
{
  size_t attempts;
  for (attempts = 0u; attempts < 500u; attempts++) {
    ftun_core_info_t info;
    struct timespec pause = {0, 10 * 1000 * 1000};
    if (ftun_core_get_info(core, &info) == FTUN_OK &&
        info.state == FTUN_CORE_RUNNING && info.generation == 1u) return 1;
    (void)nanosleep(&pause, NULL);
  }
  return 0;
}

int main(void)
{
  static const char config_template[] =
    "{\"base\":{\"cache-file\":\"%s\",\"state-cache\":true},"
    "\"log\":{\"level\":\"silent\"},\"dns\":{\"enable\":false},"
    "\"outbounds\":["
    "{\"name\":\"node-a\",\"type\":\"socks5\",\"server\":\"127.0.0.1:1080\"},"
    "{\"name\":\"node-b\",\"type\":\"socks5\",\"server\":\"127.0.0.1:1081\"},"
    "{\"name\":\"manual\",\"type\":\"select\","
    "\"outbounds\":[\"node-a\",\"node-b\"],\"default\":\"node-a\"}],"
    "\"rules\":[\"MATCH,%s\"]}";
  char directory[] = "/tmp/ftun-v05-XXXXXX";
  char first_path[256];
  char second_path[256];
  char invalid_path[256];
  char restart_path[256];
  char cache_path[256];
  char stuck_path[256];
  char stuck_cache_path[256];
  char first[2048];
  char second[2048];
  char stuck[2048];
  ftun_core_options_t options;
  ftun_core_t *core = NULL;
  ftun_operation_t *operation = NULL;
  ftun_operation_t *pressure_operations[5];
  ftun_core_info_t info;
  test_context_t context;
  run_context_t run;
  pthread_t thread;
  size_t index;
  size_t before;

  CHECK(mkdtemp(directory) != NULL);
  CHECK(snprintf(first_path, sizeof(first_path), "%s/first.json", directory) > 0);
  CHECK(snprintf(second_path, sizeof(second_path), "%s/second.json", directory) > 0);
  CHECK(snprintf(invalid_path, sizeof(invalid_path), "%s/invalid.json", directory) > 0);
  CHECK(snprintf(restart_path, sizeof(restart_path), "%s/restart.json", directory) > 0);
  CHECK(snprintf(cache_path, sizeof(cache_path), "%s/state.cache", directory) > 0);
  CHECK(snprintf(stuck_path, sizeof(stuck_path), "%s/stuck.json", directory) > 0);
  CHECK(snprintf(stuck_cache_path, sizeof(stuck_cache_path),
                 "%s/stuck.cache", directory) > 0);
  CHECK(snprintf(first, sizeof(first), config_template,
                 cache_path, "manual") > 0);
  CHECK(snprintf(second, sizeof(second), config_template,
                 cache_path, "REJECT") > 0);
  CHECK(snprintf(stuck, sizeof(stuck), config_template,
                 stuck_cache_path, "REJECT") > 0);
  CHECK(write_text(first_path, first));
  CHECK(write_text(second_path, second));
  CHECK(write_text(stuck_path, stuck));
  CHECK(write_text(invalid_path, "{\"dns\":"));
  CHECK(write_text(restart_path,
    "{\"base\":{\"state-cache\":false},\"log\":{\"level\":\"silent\"},"
    "\"dns\":{\"enable\":false},\"inbounds\":[{\"name\":\"new\","
    "\"type\":\"socks5\",\"listen\":\"127.0.0.1:19081\"}]}"));

  memset(&options, 0, sizeof(options));
  options.struct_size = sizeof(options);
  options.abi_version = FTUN_ABI_VERSION;
  options.owned_memory_limit = 4u * 1024u * 1024u;
  options.operation_capacity = 8u;
  options.retained_runtime_limit = 1u;
  CHECK(ftun_core_create(&options, &core) == FTUN_OK && core != NULL);
  memset(&context, 0, sizeof(context));
  CHECK(pthread_mutex_init(&context.mutex, NULL) == 0);
  CHECK(pthread_cond_init(&context.condition, NULL) == 0);
  context.core = core;
  run.core = core;
  run.path = first_path;
  run.result = FTUN_E_STATE_CORRUPT;
  run.done = 0;
  CHECK(pthread_mutex_init(&run.mutex, NULL) == 0);
  CHECK(pthread_cond_init(&run.condition, NULL) == 0);
  CHECK(ftun_core_run(core, invalid_path) != FTUN_OK);
  CHECK(ftun_core_get_info(core, &info) == FTUN_OK &&
        info.state == FTUN_CORE_CREATED && info.generation == 0u);
  CHECK(pthread_create(&thread, NULL, run_core, &run) == 0);
  CHECK(wait_running(core));

  before = context.callbacks;
  CHECK(ftun_core_post(core, normal_done, &context, &operation) == FTUN_OK &&
        operation != NULL);
  CHECK(wait_callbacks(&context, before + 1u));
  CHECK(context.status == FTUN_OK && context.stage == FTUN_STAGE_CONTROL);

  before = context.callbacks;
  CHECK(ftun_core_select(core, "manual", "node-b", select_done, &context,
                         &operation) == FTUN_OK);
  CHECK(wait_callbacks(&context, before + 1u));
  CHECK(context.status == FTUN_OK && !context.callback_failed);

  before = context.callbacks;
  CHECK(ftun_core_post(core, acquire_done, &context, &operation) == FTUN_OK);
  CHECK(wait_callbacks(&context, before + 1u));
  CHECK(context.old_runtime != NULL && !context.callback_failed);

  before = context.callbacks;
  CHECK(ftun_core_reload(core, invalid_path, normal_done, &context,
                         &operation) == FTUN_OK);
  CHECK(wait_callbacks(&context, before + 1u));
  CHECK(context.status != FTUN_OK);
  CHECK(ftun_core_get_info(core, &info) == FTUN_OK &&
        info.state == FTUN_CORE_RUNNING && info.generation == 1u);

  before = context.callbacks;
  CHECK(ftun_core_reload(core, second_path, reload_done, &context,
                         &operation) == FTUN_OK);
  CHECK(wait_callbacks(&context, before + 1u));
  CHECK(context.status == FTUN_OK && context.stage == FTUN_STAGE_COMMIT &&
        context.old_runtime == NULL && !context.callback_failed);
  CHECK(ftun_core_get_info(core, &info) == FTUN_OK && info.generation == 2u);

  before = context.callbacks;
  CHECK(ftun_core_reload(core, restart_path, normal_done, &context,
                         &operation) == FTUN_OK);
  CHECK(wait_callbacks(&context, before + 1u));
  CHECK(context.status == FTUN_E_RESTART_REQUIRED &&
        context.stage == FTUN_STAGE_CONFIG_PREPARE);
  CHECK(ftun_core_get_info(core, &info) == FTUN_OK && info.generation == 2u);

  /* Hold the owner in a callback and saturate the normal lane.  The reserved
   * control slot must still admit SELECT; every accepted operation then gets
   * exactly one terminal callback, including the cancelled target. */
  before = context.callbacks;
  context.entered = 0;
  context.target_ready = 0;
  context.cancel_target = NULL;
  CHECK(ftun_core_post(core, cancelling_done, &context, &operation) == FTUN_OK);
  CHECK(wait_entered(&context));
  CHECK(ftun_core_post(core, normal_done, &context,
                       &context.cancel_target) == FTUN_OK);
  for (index = 0u; index < sizeof(pressure_operations) /
       sizeof(pressure_operations[0]); index++) {
    CHECK(ftun_core_post(core, normal_done, &context,
                         &pressure_operations[index]) == FTUN_OK);
  }
  operation = (ftun_operation_t *)(uintptr_t)1;
  CHECK(ftun_core_post(core, normal_done, &context, &operation) ==
        FTUN_E_LIMIT && operation == NULL);
  CHECK(ftun_core_select(core, "manual", "node-b", select_done, &context,
                         &operation) == FTUN_OK && operation != NULL);
  (void)pthread_mutex_lock(&context.mutex);
  context.target_ready = 1;
  (void)pthread_cond_broadcast(&context.condition);
  (void)pthread_mutex_unlock(&context.mutex);
  CHECK(wait_callbacks(&context, before + 8u));
  CHECK(context.status == FTUN_OK && !context.callback_failed);

  CHECK(ftun_core_stop(core, UINT64_MAX) == FTUN_OK);
  CHECK(wait_run_done(&run, 5) && pthread_join(thread, NULL) == 0 &&
        run.result == FTUN_OK);
  CHECK(ftun_core_get_info(core, &info) == FTUN_OK &&
        info.state == FTUN_CORE_STOPPED && info.generation == 2u &&
        info.pending_operations == 0u && info.owner_rounds != 0u &&
        info.owner_max_work != 0u && info.owner_quota_exhaustions != 0u);
  CHECK(ftun_core_destroy(&core) == FTUN_OK && core == NULL);
  CHECK(pthread_cond_destroy(&run.condition) == 0);
  CHECK(pthread_mutex_destroy(&run.mutex) == 0);
  CHECK(pthread_cond_destroy(&context.condition) == 0);
  CHECK(pthread_mutex_destroy(&context.mutex) == 0);
  CHECK(unlink(cache_path) == 0);

  /* 有效候选的状态缓存 FIFO 无 writer 时，reload worker 会阻塞在真实
   * ftun_group_cache_load。owner 仍须服务，停止期限也不能释放 worker
   * 仍可能访问的候选快照。 */
  CHECK(mkfifo(stuck_cache_path, 0600) == 0);
  CHECK(ftun_core_create(&options, &core) == FTUN_OK && core != NULL);
  memset(&context, 0, sizeof(context));
  CHECK(pthread_mutex_init(&context.mutex, NULL) == 0);
  CHECK(pthread_cond_init(&context.condition, NULL) == 0);
  context.core = core;
  memset(&run, 0, sizeof(run));
  run.core = core;
  run.path = first_path;
  run.result = FTUN_E_STATE_CORRUPT;
  CHECK(pthread_mutex_init(&run.mutex, NULL) == 0);
  CHECK(pthread_cond_init(&run.condition, NULL) == 0);
  CHECK(pthread_create(&thread, NULL, run_core, &run) == 0);
  CHECK(wait_running(core));
  before = context.callbacks;
  CHECK(ftun_core_reload(core, stuck_path, normal_done, &context,
                         &operation) == FTUN_OK);
  {
    struct timespec pause = {0, 50 * 1000 * 1000};
    (void)nanosleep(&pause, NULL);
  }
  CHECK(ftun_core_select(core, "manual", "node-b", select_done, &context,
                         &operation) == FTUN_OK);
  CHECK(wait_callbacks(&context, before + 1u));
  CHECK(context.status == FTUN_OK);
  {
    ftun_group_cache_snapshot_t *snapshot = NULL;
    int latest = 0;
    for (index = 0u; index < 2000u && !latest; index++) {
      struct timespec pause = {0, 1000 * 1000};
      if (ftun_group_cache_load(cache_path, &snapshot) == FTUN_OK &&
          snapshot != NULL && snapshot->record_count == 1u &&
          snapshot->records[0].member.length == 6u &&
          memcmp(snapshot->records[0].member.data, "node-b", 6u) == 0) {
        latest = 1;
      }
      (void)ftun_group_cache_destroy(&snapshot);
      if (latest) break;
      (void)nanosleep(&pause, NULL);
    }
    CHECK(latest);
  }
  {
    uint64_t now_ms = 0u;
    CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK &&
          now_ms <= UINT64_MAX - 200u);
    CHECK(ftun_core_stop(core, now_ms + 200u) == FTUN_OK);
    CHECK(ftun_core_stop(core, now_ms + 100u) == FTUN_OK);
  }
  CHECK(wait_run_done(&run, 2));
  CHECK(run.result == FTUN_E_TIMEOUT);
  CHECK(ftun_core_get_info(core, &info) == FTUN_OK &&
        info.state == FTUN_CORE_STOPPING && info.pending_operations == 0u);
  CHECK(ftun_core_destroy(&core) == FTUN_E_AGAIN && core != NULL);
  before = context.callbacks;
  /* writer open 足以解除 reader 的阻塞；reader 会因 FIFO 不是普通文件而拒绝。
   * 不向已经关闭读端的 FIFO 写入，避免测试进程收到 SIGPIPE。 */
  CHECK(unblock_fifo(stuck_cache_path));
  for (index = 0u; index < 5000u && core != NULL; index++) {
    ftun_status_t destroy_status = ftun_core_destroy(&core);
    struct timespec pause = {0, 1000 * 1000};
    CHECK(destroy_status == FTUN_OK || destroy_status == FTUN_E_AGAIN);
    if (core != NULL) (void)nanosleep(&pause, NULL);
  }
  CHECK(core == NULL && context.callbacks == before);
  CHECK(pthread_join(thread, NULL) == 0);
  CHECK(pthread_cond_destroy(&run.condition) == 0);
  CHECK(pthread_mutex_destroy(&run.mutex) == 0);
  CHECK(pthread_cond_destroy(&context.condition) == 0);
  CHECK(pthread_mutex_destroy(&context.mutex) == 0);

  CHECK(unlink(first_path) == 0);
  CHECK(unlink(second_path) == 0);
  CHECK(unlink(invalid_path) == 0);
  CHECK(unlink(restart_path) == 0);
  CHECK(unlink(cache_path) == 0);
  CHECK(unlink(stuck_path) == 0);
  CHECK(unlink(stuck_cache_path) == 0);
  CHECK(rmdir(directory) == 0);
  return 0;
}
