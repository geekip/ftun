#define _POSIX_C_SOURCE 200809L
#include "frs_fixture.h"
#include "ftun/ftun.h"
#include "proxy/http_fetch.h"
#include "proxy/runtime_state.h"
#include "core/context.h"
#include "util/time.h"
#include <dirent.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "runtime worker cleanup failed at %d: %s\n", __LINE__, #x); \
  return 1; } } while (0)

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static bool entered, proceed, fail_cleanup, oversized_etag;
static size_t release_failures, released;
static uint8_t *fixture;
static size_t fixture_length;
static ftun_budget_t *fetch_budget;
typedef struct {
  ftun_core_t *core;
  const char *path;
  ftun_status_t status;
} run_t;

static uint64_t now_ms(void)
{
  uint64_t result = 0u;
  if (ftun_monotonic_now(&result) != FTUN_OK) abort();
  return result;
}

static void pause_once(void)
{
  struct timespec delay = {0, 1000000};
  (void)nanosleep(&delay, NULL);
}

static size_t descriptors(void)
{
  DIR *directory = opendir("/proc/self/fd");
  struct dirent *entry;
  size_t count = 0u;
  if (directory == NULL) abort();
  while ((entry = readdir(directory)) != NULL) if (entry->d_name[0] != '.') count++;
  (void)closedir(directory);
  return count;
}

/* 仅替换下载和一次可重试叶清理；真实定时更新、Worker与停止链保持。 */
ftun_status_t __wrap_ftun_http_fetch(const ftun_http_fetch_spec_t *spec,
                                     ftun_http_fetch_result_t *out)
{
  memset(out, 0, sizeof(*out));
  (void)pthread_mutex_lock(&mutex);
  fetch_budget = spec->budget;
  entered = true;
  (void)pthread_cond_broadcast(&condition);
  while (!proceed) (void)pthread_cond_wait(&condition, &mutex);
  (void)pthread_mutex_unlock(&mutex);
  if (ftun_budget_reserve(spec->budget, fixture_length, &out->reservation) != FTUN_OK) return FTUN_E_LIMIT;
  out->data = malloc(fixture_length);
  if (out->data == NULL) return FTUN_E_LIMIT;
  memcpy(out->data, fixture, fixture_length);
  out->length = fixture_length;
  out->status = 200u;
  if (oversized_etag) {
    if (ftun_budget_reserve(spec->budget, 65538u, &out->etag_reservation) != FTUN_OK) return FTUN_E_LIMIT;
    out->etag = malloc(65538u);
    if (out->etag == NULL) return FTUN_E_LIMIT;
    memset(out->etag, 'x', 65537u);
    out->etag[65537u] = '\0';
  }
  return FTUN_OK;
}

ftun_status_t __real_ftun_runtime_prepared_release(ftun_runtime_t **prepared);
ftun_status_t __wrap_ftun_runtime_prepared_release(ftun_runtime_t **prepared)
{
  ftun_status_t status;
  bool owned = prepared != NULL && *prepared != NULL;
  (void)pthread_mutex_lock(&mutex);
  if (owned && fail_cleanup) {
    release_failures++;
    (void)pthread_mutex_unlock(&mutex);
    return FTUN_E_AGAIN;
  }
  (void)pthread_mutex_unlock(&mutex);
  status = __real_ftun_runtime_prepared_release(prepared);
  if (owned && status == FTUN_OK) {
    (void)pthread_mutex_lock(&mutex);
    released++;
    (void)pthread_mutex_unlock(&mutex);
  }
  return status;
}

static void *run(void *user)
{
  run_t *state = user;
  state->status = ftun_core_run(state->core, state->path);
  return NULL;
}

static int scenario(const char *path, bool invalid_etag)
{
  ftun_core_options_t options = {0};
  run_t state = {0};
  pthread_t thread;
  uint64_t deadline;
  size_t failures, i;
  ftun_budget_t *host_budget = NULL;
  bool same = false;
  (void)pthread_mutex_lock(&mutex);
  entered = proceed = false;
  fail_cleanup = true;
  oversized_etag = invalid_etag;
  release_failures = released = 0u;
  fetch_budget = NULL;
  (void)pthread_mutex_unlock(&mutex);
  options.struct_size = sizeof(options);
  options.abi_version = FTUN_ABI_VERSION;
  CHECK(ftun_core_create(&options, &state.core) == FTUN_OK);
  state.path = path;
  CHECK(pthread_create(&thread, NULL, run, &state) == 0);
  deadline = now_ms() + 5000u;
  for (;;) {
    bool ready;
    (void)pthread_mutex_lock(&mutex);
    ready = entered;
    (void)pthread_mutex_unlock(&mutex);
    if (ready) break;
    CHECK(now_ms() < deadline);
    pause_once();
  }
  CHECK(ftun_core_context_budget(state.core, &host_budget) == FTUN_OK);
  CHECK(ftun_budget_same_root(host_budget, fetch_budget, &same) == FTUN_OK && same);
  CHECK(ftun_core_stop(state.core, now_ms() + 40u) == FTUN_OK);
  CHECK(pthread_join(thread, NULL) == 0 && state.status == FTUN_E_TIMEOUT);
  CHECK(ftun_core_destroy(&state.core) == FTUN_E_AGAIN && state.core != NULL);
  (void)pthread_mutex_lock(&mutex);
  proceed = true;
  (void)pthread_cond_broadcast(&condition);
  (void)pthread_mutex_unlock(&mutex);
  deadline = now_ms() + 5000u;
  for (;;) {
    CHECK(ftun_core_destroy(&state.core) == FTUN_E_AGAIN && state.core != NULL);
    (void)pthread_mutex_lock(&mutex);
    failures = release_failures;
    (void)pthread_mutex_unlock(&mutex);
    if (failures >= 2u) break;
    CHECK(now_ms() < deadline);
    pause_once();
  }
  /* 持续失败不能越过仍拥有候选的Worker释放宿主。 */
  for (i = 0u; i < 3u; i++) CHECK(ftun_core_destroy(&state.core) == FTUN_E_AGAIN && state.core != NULL);
  (void)pthread_mutex_lock(&mutex);
  CHECK(released == 0u);
  fail_cleanup = false;
  (void)pthread_mutex_unlock(&mutex);
  deadline = now_ms() + 5000u;
  while (state.core != NULL) {
    ftun_status_t status = ftun_core_destroy(&state.core);
    CHECK(status == FTUN_OK || status == FTUN_E_AGAIN);
    CHECK(now_ms() < deadline);
    if (state.core != NULL) pause_once();
  }
  CHECK(released == 1u);
  return 0;
}

int main(void)
{
  char directory[] = "/tmp/ftun-runtime-worker-XXXXXX";
  char path[256], frs[256];
  FILE *file;
  size_t baseline = descriptors();
  CHECK(ftun_test_frs_fixture(&fixture, &fixture_length));
  CHECK(mkdtemp(directory) != NULL);
  CHECK(snprintf(path, sizeof(path), "%s/config.json", directory) > 0);
  CHECK(snprintf(frs, sizeof(frs), "%s/rules.frs", directory) > 0);
  file = fopen(frs, "wb");
  CHECK(file != NULL && fwrite(fixture, 1u, fixture_length, file) == fixture_length && fclose(file) == 0);
  file = fopen(path, "w");
  CHECK(file != NULL);
  CHECK(fprintf(file, "{\"base\":{\"state-cache\":false},\"dns\":{\"enable\":false},"
    "\"log\":{\"level\":\"silent\"},\"frs\":{\"path\":\"%s\","
    "\"url\":\"http://127.0.0.1/rules.frs\",\"auto-update\":true,\"update-interval\":\"1s\"},"
    "\"rules\":[\"FRS-IP,CN,REJECT\",\"MATCH,DIRECT\"]}", frs) > 0);
  CHECK(fclose(file) == 0);
  CHECK(scenario(path, false) == 0 && descriptors() == baseline);
  CHECK(scenario(path, true) == 0 && descriptors() == baseline);
  CHECK(unlink(path) == 0 && unlink(frs) == 0 && rmdir(directory) == 0);
  free(fixture);
  return 0;
}
