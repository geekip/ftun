#define _POSIX_C_SOURCE 200809L
#include "frs_fixture.h"
#include "ftun/ftun.h"
#include "platform/file.h"
#include "proxy/frs/format.h"
#include "proxy/http_fetch.h"
#include "proxy/route/router.h"
#include "proxy/runtime_state.h"
#include "util/time.h"

#include <dirent.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "App FRS failed at %d: %s\n", __LINE__, #x); \
  return 1; } } while (0)

typedef struct {
  ftun_core_t *core;
  const char *path;
  ftun_status_t result;
  bool finished;
  pthread_t owner;
} run_t;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static uint8_t *download_bytes;
static size_t download_length;
static unsigned int downloads, publishes;
static ftun_file_stage_t fail_stage;
static bool block_publish, publish_entered, release_publish;
static unsigned int completions;
static ftun_status_t completion_status;
static bool wrong_owner;
static run_t run_state;
static ftun_runtime_t *held;
static unsigned int reject_octet;
static uint64_t expected_generation;
static bool hold_active;
static bool expect_not_ready;

static uint64_t now_ms(void)
{
  uint64_t now = 0u;
  if (ftun_monotonic_now(&now) != FTUN_OK) abort();
  return now;
}

static void pause_once(void)
{
  struct timespec duration = {0, 1000000};
  (void)nanosleep(&duration, NULL);
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

/* 只替换下载源和文件阶段注入。解析、预算、快照、服务、Worker、原子
 * 文件替换和 App 提交均使用生产实现；不依赖外网或宿主网络改动。 */
ftun_status_t __wrap_ftun_http_fetch(const ftun_http_fetch_spec_t *spec,
  ftun_http_fetch_result_t *out)
{
  memset(out, 0, sizeof(*out));
  (void)pthread_mutex_lock(&mutex);
  downloads++;
  /* 后台下载（NOT_READY 启动后的两次尝试）使用当前生效的第一代；reload 按
   * 候选代执行：规则文件发布后生效代次为 2，其后候选代为 3；最后一段是新启动的实例，候选代为 2。
   * 本夹具没有 TUN，显式装配控制通道工厂并允许系统解析。 */
  if (spec->generation != (downloads <= 2u ? 1u : downloads <= 5u ? 3u : 2u) ||
      !spec->allow_system_resolver || spec->path.open == NULL ||
      spec->resolver.socket_mark != 0u || spec->budget == NULL) abort();
  if (spec->maximum_bytes < download_length) {
    (void)pthread_mutex_unlock(&mutex);
    return FTUN_E_LIMIT;
  }
  out->data = malloc(download_length);
  if (out->data == NULL) {
    (void)pthread_mutex_unlock(&mutex);
    return FTUN_E_LIMIT;
  }
  memcpy(out->data, download_bytes, download_length);
  out->length = download_length;
  out->status = 200u;
  (void)pthread_mutex_unlock(&mutex);
  return FTUN_OK;
}

typedef struct {
  ftun_file_stage_hook_fn original;
  void *user;
  ftun_file_stage_t fail;
} file_hook_t;

static ftun_status_t file_stage(ftun_file_stage_t stage, void *user)
{
  file_hook_t *hook = user;
  ftun_status_t status = hook->original == NULL ? FTUN_OK
    : hook->original(stage, hook->user);
  if (status != FTUN_OK) return status;
  (void)pthread_mutex_lock(&mutex);
  if (stage == FTUN_FILE_STAGE_TEMP_SYNCED && block_publish) {
    publish_entered = true;
    while (!release_publish) (void)pthread_cond_wait(&condition, &mutex);
  }
  (void)pthread_mutex_unlock(&mutex);
  return stage == hook->fail ? FTUN_E_IO : FTUN_OK;
}

ftun_status_t __real_ftun_file_write_atomic_budget(ftun_budget_t *, const char *,
  ftun_bytes_t, unsigned int, ftun_file_stage_hook_fn, void *);

ftun_status_t __wrap_ftun_file_write_atomic_budget(ftun_budget_t *budget, const char *path,
  ftun_bytes_t bytes, unsigned int mode, ftun_file_stage_hook_fn hook, void *user)
{
  file_hook_t intercepted = {hook, user, 0};
  (void)pthread_mutex_lock(&mutex);
  publishes++;
  intercepted.fail = fail_stage;
  (void)pthread_mutex_unlock(&mutex);
  return __real_ftun_file_write_atomic_budget(budget, path, bytes, mode,
    file_stage, &intercepted);
}

static void inject(uint8_t *bytes, ftun_file_stage_t stage)
{
  (void)pthread_mutex_lock(&mutex);
  download_bytes = bytes;
  fail_stage = stage;
  (void)pthread_mutex_unlock(&mutex);
}

static void *run(void *unused)
{
  ftun_status_t status;
  (void)unused;
  run_state.owner = pthread_self();
  status = ftun_core_run(run_state.core, run_state.path);
  (void)pthread_mutex_lock(&mutex);
  run_state.result = status;
  run_state.finished = true;
  (void)pthread_mutex_unlock(&mutex);
  return NULL;
}

static int start(const char *path, pthread_t *thread)
{
  ftun_core_options_t options;
  uint64_t expires = now_ms() + 5000u;
  memset(&options, 0, sizeof(options));
  options.struct_size = sizeof(options);
  options.abi_version = FTUN_ABI_VERSION;
  memset(&run_state, 0, sizeof(run_state));
  run_state.path = path;
  completions = 0u;
  wrong_owner = false;
  CHECK(ftun_core_create(&options, &run_state.core) == FTUN_OK);
  CHECK(pthread_create(thread, NULL, run, NULL) == 0);
  for (;;) {
    ftun_core_info_t info;
    bool finished;
    CHECK(ftun_core_get_info(run_state.core, &info) == FTUN_OK);
    if (info.state == FTUN_CORE_RUNNING) return 0;
    (void)pthread_mutex_lock(&mutex);
    finished = run_state.finished;
    (void)pthread_mutex_unlock(&mutex);
    CHECK(!finished && now_ms() < expires);
    pause_once();
  }
}

static void completed(ftun_operation_t *operation, ftun_error_t result, void *user)
{
  (void)operation;
  (void)user;
  (void)pthread_mutex_lock(&mutex);
  wrong_owner |= !pthread_equal(pthread_self(), run_state.owner);
  completion_status = result.status;
  completions++;
  (void)pthread_mutex_unlock(&mutex);
}

static int wait_done(unsigned int expected, ftun_status_t status)
{
  uint64_t expires = now_ms() + 5000u;
  for (;;) {
    unsigned int count;
    ftun_status_t result;
    bool wrong;
    (void)pthread_mutex_lock(&mutex);
    count = completions;
    result = completion_status;
    wrong = wrong_owner;
    (void)pthread_mutex_unlock(&mutex);
    CHECK(!wrong && count <= expected);
    if (count == expected) {
      if (result != status) fprintf(stderr, "got %s expected %s\n",
        ftun_status_name(result), ftun_status_name(status));
      CHECK(result == status);
      return 0;
    }
    CHECK(now_ms() < expires);
    pause_once();
  }
}

static int route(ftun_runtime_t *runtime, unsigned int octet, uint32_t outbound)
{
  ftun_runtime_info_t info;
  ftun_metadata_t metadata;
  ftun_route_result_t result;
  CHECK(ftun_runtime_get_info(runtime, &info) == FTUN_OK);
  memset(&metadata, 0, sizeof(metadata));
  metadata.generation = info.generation;
  metadata.original_target.kind = FTUN_ADDRESS_IPV4;
  metadata.original_target.address[0] = (uint8_t)octet;
  metadata.original_target.address[1] = 1u;
  CHECK(ftun_route_evaluate(runtime, &metadata, 0u, &result) == FTUN_OK);
  CHECK(result.outbound_id == outbound);
  return 0;
}

static void probe(ftun_operation_t *operation, ftun_error_t result, void *user)
{
  ftun_runtime_t *active = NULL;
  ftun_core_info_t info;
  (void)user;
  if (result.status == FTUN_OK &&
      (ftun_core_get_info(run_state.core, &info) != FTUN_OK ||
       info.generation != expected_generation ||
       ftun_runtime_active_acquire(run_state.core, &active) != FTUN_OK)) {
    result.status = FTUN_E_STATE_CORRUPT;
  }
  if (active != NULL) {
    /* FRS 尚未就绪时，第一条 FRS 规则对任何目标都拒绝新连接。 */
    if (route(active, reject_octet, FTUN_OUTBOUND_ID_REJECT) != 0 ||
        route(active, reject_octet == 10u ? 11u : 10u,
          expect_not_ready ? FTUN_OUTBOUND_ID_REJECT : FTUN_OUTBOUND_ID_DIRECT) != 0) {
      result.status = FTUN_E_STATE_CORRUPT;
    }
    if (hold_active) {
      held = active;
      active = NULL;
      hold_active = false;
    }
    (void)ftun_runtime_release(&active);
  }
  if (held != NULL && route(held, 10u, FTUN_OUTBOUND_ID_REJECT) != 0) {
    result.status = FTUN_E_STATE_CORRUPT;
  }
  completed(operation, result, NULL);
}

static int check_active(unsigned int callback, uint64_t generation,
  unsigned int octet, bool retain)
{
  ftun_operation_t *operation = NULL;
  expected_generation = generation;
  reject_octet = octet;
  hold_active = retain;
  CHECK(ftun_core_post(run_state.core, probe, NULL, &operation) == FTUN_OK);
  CHECK(wait_done(callback, FTUN_OK) == 0);
  return 0;
}

static int reload(const char *path, unsigned int callback, ftun_status_t expected)
{
  ftun_operation_t *operation = NULL;
  uint64_t expires = now_ms() + 5000u;
  ftun_status_t status;
  do {
    status = ftun_core_reload(run_state.core, path, completed, NULL, &operation);
    if (status != FTUN_E_AGAIN) break;
    CHECK(operation == NULL && now_ms() < expires);
    pause_once();
  } while (1);
  CHECK(status == FTUN_OK && operation != NULL);
  return wait_done(callback, expected);
}

static int stop(pthread_t thread)
{
  CHECK(ftun_core_stop(run_state.core, now_ms() + 2000u) == FTUN_OK);
  CHECK(pthread_join(thread, NULL) == 0 && run_state.result == FTUN_OK);
  CHECK(ftun_runtime_release(&held) == FTUN_OK);
  CHECK(ftun_core_destroy(&run_state.core) == FTUN_OK);
  return 0;
}

static int same_file(const char *path, const uint8_t *bytes);

/* 等后台下载走到指定次数（含失败的尝试）。 */
static int wait_downloads(unsigned int expected)
{
  uint64_t expires = now_ms() + 8000u;
  for (;;) {
    unsigned int current;
    (void)pthread_mutex_lock(&mutex);
    current = downloads;
    (void)pthread_mutex_unlock(&mutex);
    if (current >= expected) return 0;
    CHECK(now_ms() < expires);
    pause_once();
  }
}

/* 等后台发布的规则文件出现且内容一致。 */
static int wait_file(const char *path, const uint8_t *bytes)
{
  uint64_t expires = now_ms() + 8000u;
  while (access(path, F_OK) != 0) {
    CHECK(now_ms() < expires);
    pause_once();
  }
  return same_file(path, bytes);
}

static int config(const char *path, const char *frs, const char *log)
{
  FILE *file = fopen(path, "w");
  char logging[512];
  CHECK(file != NULL);
  if (log == NULL) (void)snprintf(logging, sizeof(logging), "\"level\":\"silent\"");
  else CHECK(snprintf(logging, sizeof(logging), "\"level\":\"warn\",\"file\":\"%s\"", log) > 0);
  CHECK(fprintf(file, "{\"base\":{\"state-cache\":false},"
    "\"dns\":{\"enable\":false},\"log\":{%s},"
    "\"frs\":{\"path\":\"%s\",\"url\":\"http://127.0.0.1/rules.frs\","
    "\"auto-update\":true,\"update-interval\":\"24h\"},"
    "\"rules\":[\"frs-ip,CN,REJECT\",\"MATCH,DIRECT\"]}\n",
    logging, frs) > 0);
  CHECK(fclose(file) == 0);
  return 0;
}

static int same_file(const char *path, const uint8_t *bytes)
{
  uint8_t *readback = malloc(download_length);
  FILE *file = fopen(path, "rb");
  CHECK(file != NULL && readback != NULL);
  CHECK(fread(readback, 1u, download_length, file) == download_length);
  CHECK(fgetc(file) == EOF && memcmp(readback, bytes, download_length) == 0);
  CHECK(fclose(file) == 0);
  free(readback);
  return 0;
}

int main(void)
{
  char directory[] = "/tmp/ftun-app-frs-XXXXXX";
  char original[256], next[256], bad[256], first_file[256], next_file[256], log[256];
  uint8_t *first = NULL, *second;
  pthread_t thread;
  ftun_core_info_t info;
  ftun_core_options_t options;
  ftun_operation_t *operation = NULL;
  uint64_t expires;
  size_t baseline = descriptors();
  CHECK(mkdtemp(directory) != NULL);
  CHECK(ftun_test_frs_fixture(&first, &download_length));
  second = malloc(download_length);
  CHECK(second != NULL);
  memcpy(second, first, download_length);
  ftun_frs_write_u32(second + 680u, UINT32_C(0x0b000000));
  ftun_frs_write_u32(second + 684u, UINT32_C(0x0bffffff));
  ftun_frs_write_u64(second + 48u,
    ftun_frs_file_checksum((ftun_bytes_t){second, download_length}));
  CHECK(snprintf(original, sizeof(original), "%s/original.json", directory) > 0);
  CHECK(snprintf(next, sizeof(next), "%s/next.json", directory) > 0);
  CHECK(snprintf(bad, sizeof(bad), "%s/bad.json", directory) > 0);
  CHECK(snprintf(first_file, sizeof(first_file), "%s/first.frs", directory) > 0);
  CHECK(snprintf(next_file, sizeof(next_file), "%s/next.frs", directory) > 0);
  CHECK(config(original, first_file, NULL) == 0);
  CHECK(config(next, next_file, NULL) == 0 && config(bad, next_file, "/dev/null/invalid.log") == 0);

  /* 本地规则文件缺失：不再同步下载，以 NOT_READY 启动，命中 FRS 规则的新连接
   * 被拒绝；后台下载在 rename 前失败时没有留下文件，服务继续运行并按退避重试。 */
  CHECK(snprintf(log, sizeof(log), "%s/startup.log", directory) > 0);
  CHECK(config(original, first_file, log) == 0);
  inject(first, FTUN_FILE_STAGE_TEMP_SYNCED);
  CHECK(start(original, &thread) == 0);
  CHECK(wait_downloads(1u) == 0);
  CHECK(access(first_file, F_OK) != 0);
  expect_not_ready = true;
  CHECK(check_active(1u, 1u, 10u, false) == 0);
  expect_not_ready = false;
  /* 退避重试在 rename 后出错：仍采用已发布的文件，并写出持久性警告；
   * 发布后产生新的运行配置代次。 */
  inject(first, FTUN_FILE_STAGE_RENAMED);
  CHECK(wait_downloads(2u) == 0);
  CHECK(wait_file(first_file, first) == 0);
  CHECK(check_active(2u, 2u, 10u, true) == 0);

  inject(second, 0);
  CHECK(reload(bad, 3u, FTUN_E_IO) == 0 && access(next_file, F_OK) != 0);
  CHECK(check_active(4u, 2u, 10u, false) == 0);
  inject(second, FTUN_FILE_STAGE_TEMP_SYNCED);
  CHECK(reload(next, 5u, FTUN_E_IO) == 0 && access(next_file, F_OK) != 0);
  CHECK(check_active(6u, 2u, 10u, false) == 0);
  inject(second, FTUN_FILE_STAGE_RENAMED);
  CHECK(reload(next, 7u, FTUN_OK) == 0 && same_file(next_file, second) == 0);
  CHECK(check_active(8u, 3u, 11u, false) == 0);
  inject(second, 0);
  CHECK(reload(original, 9u, FTUN_OK) == 0);
  CHECK(check_active(10u, 4u, 10u, false) == 0);
  CHECK(stop(thread) == 0);
  {
    char text[8192];
    const char *warning = "FRS update applied but directory durability is uncertain";
    FILE *file = fopen(log, "r");
    size_t length;
    CHECK(file != NULL);
    length = fread(text, 1u, sizeof(text) - 1u, file);
    text[length] = '\0';
    CHECK(!ferror(file) && feof(file) && fclose(file) == 0);
    CHECK(strstr(text, warning) != NULL && strstr(strstr(text, warning) + strlen(warning), warning) == NULL);
    CHECK(strstr(text, "level=error status=io ") != NULL);
  }
  CHECK(downloads == 5u && publishes == 4u);
  CHECK(descriptors() == baseline);
  CHECK(unlink(next_file) == 0);

  /* publish 正在文件阶段阻塞：stop 按期限返回，迟到结果只清理。 */
  inject(second, FTUN_FILE_STAGE_TEMP_SYNCED);
  (void)pthread_mutex_lock(&mutex);
  block_publish = true;
  (void)pthread_mutex_unlock(&mutex);
  CHECK(start(original, &thread) == 0);
  CHECK(ftun_core_reload(run_state.core, next, completed, NULL, &operation) == FTUN_OK);
  expires = now_ms() + 5000u;
  for (;;) {
    bool entered;
    (void)pthread_mutex_lock(&mutex);
    entered = publish_entered;
    (void)pthread_mutex_unlock(&mutex);
    if (entered) break;
    CHECK(now_ms() < expires);
    pause_once();
  }
  CHECK(ftun_core_stop(run_state.core, now_ms() + 40u) == FTUN_OK);
  CHECK(pthread_join(thread, NULL) == 0 && run_state.result == FTUN_E_TIMEOUT);
  CHECK(wait_done(1u, FTUN_E_CANCELLED) == 0);
  CHECK(ftun_core_get_info(run_state.core, &info) == FTUN_OK &&
    info.state == FTUN_CORE_STOPPING && info.generation == 1u);
  CHECK(ftun_core_destroy(&run_state.core) == FTUN_E_AGAIN);
  (void)pthread_mutex_lock(&mutex);
  release_publish = true;
  (void)pthread_cond_signal(&condition);
  (void)pthread_mutex_unlock(&mutex);
  expires = now_ms() + 5000u;
  while (run_state.core != NULL) {
    ftun_status_t status = ftun_core_destroy(&run_state.core);
    if (status == FTUN_OK) break;
    CHECK(status == FTUN_E_AGAIN && now_ms() < expires);
    pause_once();
  }
  CHECK(completions == 1u && downloads == 6u && publishes == 5u);
  CHECK(access(next_file, F_OK) != 0 && descriptors() == baseline);
  CHECK(unlink(first_file) == 0);
  CHECK(unlink(original) == 0 && unlink(next) == 0 && unlink(bad) == 0 && unlink(log) == 0);
  CHECK(rmdir(directory) == 0);
  free(first);
  free(second);
  puts("App FRS: startup retry, prepare rejection, publish boundaries, retained generation and late publish cleanup passed");
  return 0;
}
