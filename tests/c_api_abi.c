#define _GNU_SOURCE
#include "ftun/ftun.h"
#include "c_api_abi_fixture.h"
#include "c_api_abi_layout.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expression) do { \
  if (!(expression)) { \
    fprintf(stderr, "C API ABI failed: %s:%d: %s\n", \
            __FILE__, __LINE__, #expression); \
    return 1; \
  } \
} while (0)

typedef struct {
  unsigned char before[32];
  ftun_core_info_t info;
  unsigned char after[32];
} guarded_info_t;

static uint64_t now_ms(void)
{
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0u;
  return (uint64_t)value.tv_sec * 1000u + (uint64_t)value.tv_nsec / 1000000u;
}

static int bytes_are(const void *data, size_t length, unsigned char value)
{
  const unsigned char *bytes = data;
  for (size_t index = 0u; index < length; index++) {
    if (bytes[index] != value) return 0;
  }
  return 1;
}

static int get_info(ftun_core_t *core, ftun_status_t expected,
                      ftun_core_info_t *out)
{
  guarded_info_t guarded;
  memset(&guarded, 0xa5, sizeof(guarded));
  CHECK(ftun_core_get_info(core, &guarded.info) == expected);
  CHECK(bytes_are(guarded.before, sizeof(guarded.before), 0xa5));
  CHECK(bytes_are(guarded.after, sizeof(guarded.after), 0xa5));
  if (expected != FTUN_OK) CHECK(bytes_are(&guarded.info, sizeof(guarded.info), 0));
  if (out != NULL) *out = guarded.info;
  return 0;
}

static ftun_core_options_t default_options(void)
{
  ftun_core_options_t options;
  memset(&options, 0, sizeof(options));
  options.struct_size = sizeof(options);
  options.abi_version = FTUN_ABI_VERSION;
  return options;
}

static int check_create(const ftun_core_options_t *options,
                          ftun_status_t expected)
{
  ftun_core_t *core = (ftun_core_t *)(uintptr_t)1u;
  CHECK(ftun_core_create(options, &core) == expected);
  if (expected == FTUN_OK) {
    ftun_core_info_t info;
    CHECK(core != NULL && get_info(core, FTUN_OK, &info) == 0);
    CHECK(info.state == FTUN_CORE_CREATED && info.generation == 0u &&
          info.pending_operations == 0u && info.owner_rounds == 0u &&
          info.owner_max_busy_ms == 0u && info.owner_max_deadline_lateness_ms == 0u &&
          info.owner_max_work == 0u && info.owner_quota_exhaustions == 0u);
  } else {
    CHECK(core == NULL);
  }
  CHECK(ftun_core_destroy(&core) == FTUN_OK && core == NULL);
  return 0;
}

static int options_boundaries(void)
{
  ftun_core_options_t options = default_options();
  const size_t minimum = offsetof(ftun_core_options_t, operation_capacity);
  const size_t alignment = FTUN_TEST_ABI_ALIGNMENT(ftun_core_options_t);
  long page_size = sysconf(_SC_PAGESIZE);
  unsigned char *pages;
  CHECK(page_size > 0 && (size_t)page_size > sizeof(options));
  pages = mmap(NULL, (size_t)page_size * 2u, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(pages != MAP_FAILED);
  CHECK(mprotect(pages + page_size, (size_t)page_size, PROT_NONE) == 0);
  for (size_t length = sizeof(size_t); length <= sizeof(options); length++) {
    size_t storage = (length + alignment - 1u) / alignment * alignment;
    unsigned char *prefix = pages + page_size - storage;
    options.struct_size = length;
    memset(prefix, 0xff, storage);
    memcpy(prefix, &options, length);
    CHECK(check_create((const ftun_core_options_t *)prefix,
      length < minimum ? FTUN_E_INVALID : FTUN_OK) == 0);
    CHECK(bytes_are(prefix + length, storage - length, 0xff));
  }
  options.struct_size = SIZE_MAX;
  memcpy(pages + page_size - sizeof(options), &options, sizeof(options));
  CHECK(check_create((const ftun_core_options_t *)(pages + page_size -
                      sizeof(options)), FTUN_OK) == 0);
  CHECK(munmap(pages, (size_t)page_size * 2u) == 0);
  options = default_options();
  CHECK(check_create(NULL, FTUN_E_INVALID) == 0);
  CHECK(ftun_core_create(&options, NULL) == FTUN_E_INVALID);
  options.abi_version++;
  CHECK(check_create(&options, FTUN_E_INVALID) == 0);
  options = default_options();
  options.operation_capacity = 1u;
  CHECK(check_create(&options, FTUN_E_LIMIT) == 0);
  options.operation_capacity = 3u;
  CHECK(check_create(&options, FTUN_E_LIMIT) == 0);
  options.operation_capacity = 4u;
  CHECK(check_create(&options, FTUN_OK) == 0);
  options.operation_capacity = 4096u;
  /* 数据域保障和清理保留同样占根额度，控制队列需独立容纳全部槽位。 */
  options.owned_queue_limit = 16384u;
  CHECK(check_create(&options, FTUN_OK) == 0);
  options.operation_capacity = 4097u;
  CHECK(check_create(&options, FTUN_E_LIMIT) == 0);
  options = default_options();
  options.operation_capacity = 4u;
  options.owned_memory_limit = 1024u * 1024u - 1u;
  CHECK(check_create(&options, FTUN_E_LIMIT) == 0);
  options.owned_memory_limit++;
  CHECK(check_create(&options, FTUN_OK) == 0);
  options.owned_descriptor_limit = 15u;
  CHECK(check_create(&options, FTUN_E_LIMIT) == 0);
  options.owned_descriptor_limit++;
  CHECK(check_create(&options, FTUN_OK) == 0);
  options.owned_queue_limit = 63u;
  CHECK(check_create(&options, FTUN_E_LIMIT) == 0);
  options.owned_queue_limit++;
  options.retained_runtime_limit = 1u;
  options.retained_runtime_bytes_limit = 1u;
  CHECK(check_create(&options, FTUN_OK) == 0);
  return 0;
}

static size_t refused_callbacks;

static void refused_done(ftun_operation_t *operation, ftun_error_t error,
                           void *user)
{
  (void)operation;
  (void)error;
  (void)user;
  refused_callbacks++;
}

static int synchronous_edges(void)
{
  ftun_core_options_t options = default_options();
  ftun_core_t *core = NULL;
  ftun_operation_t *operation = (ftun_operation_t *)(uintptr_t)1u;
  size_t limits[3];
  long page_size = sysconf(_SC_PAGESIZE);
  unsigned char *pages;
  ftun_core_info_t *info;
  CHECK(ftun_core_create(&options, &core) == FTUN_OK);
  CHECK(ftun_test_budget_limits(core, limits) == FTUN_OK);
  CHECK(limits[0] == 64u * 1024u * 1024u && limits[2] == 4096u);
  {
    size_t descriptors = 4096u;
#if defined(FTUN_TEST_PROXY)
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur != RLIM_INFINITY &&
        limit.rlim_cur < descriptors) descriptors = (size_t)limit.rlim_cur;
#endif
    CHECK(limits[1] == descriptors);
  }
  CHECK(get_info(NULL, FTUN_E_INVALID, NULL) == 0);
  CHECK(ftun_core_get_info(core, NULL) == FTUN_E_INVALID);
  CHECK(ftun_core_get_info(NULL, NULL) == FTUN_E_INVALID);
  CHECK(ftun_test_control_detach(core, 1) == FTUN_OK);
  CHECK(get_info(core, FTUN_E_INVALID, NULL) == 0);
  CHECK(ftun_test_control_detach(core, 0) == FTUN_OK);
  ftun_test_fail_usage();
  CHECK(get_info(core, FTUN_E_IO, NULL) == 0);
  CHECK(page_size > 0);
  pages = mmap(NULL, (size_t)page_size * 2u, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(pages != MAP_FAILED);
  CHECK(mprotect(pages + page_size, (size_t)page_size, PROT_NONE) == 0);
  info = (ftun_core_info_t *)(pages + page_size - sizeof(*info));
  for (unsigned int path = 0u; path < 3u; path++) {
    memset(pages, 0xa5, (size_t)page_size);
    if (path == 2u) ftun_test_fail_usage();
    CHECK(ftun_core_get_info(path == 1u ? NULL : core, info) ==
          (path == 0u ? FTUN_OK : path == 1u ? FTUN_E_INVALID : FTUN_E_IO));
    CHECK(bytes_are(pages, (size_t)page_size - sizeof(*info), 0xa5));
    if (path != 0u) CHECK(bytes_are(info, sizeof(*info), 0));
  }
  CHECK(munmap(pages, (size_t)page_size * 2u) == 0);
  CHECK(ftun_core_post(core, refused_done, NULL, &operation) == FTUN_E_STALE);
  CHECK(operation == NULL && refused_callbacks == 0u);
  operation = (ftun_operation_t *)(uintptr_t)1u;
  CHECK(ftun_core_reload(core, "unused.json", refused_done, NULL, &operation) ==
        FTUN_E_STALE);
  CHECK(operation == NULL && refused_callbacks == 0u);
  operation = (ftun_operation_t *)(uintptr_t)1u;
#if defined(FTUN_TEST_PROXY)
  CHECK(ftun_core_select(core, "group", "node", refused_done, NULL, &operation) ==
        FTUN_E_STALE);
#else
  CHECK(ftun_core_select(core, "group", "node", refused_done, NULL, &operation) ==
        FTUN_E_UNSUPPORTED);
#endif
  CHECK(operation == NULL && refused_callbacks == 0u);
  CHECK(ftun_operation_cancel(NULL) == FTUN_E_INVALID);
  CHECK(ftun_core_run(NULL, "unused.json") == FTUN_E_INVALID);
  CHECK(ftun_core_run(core, NULL) == FTUN_E_INVALID);
  CHECK(ftun_core_run(core, "") == FTUN_E_INVALID);
  CHECK(ftun_core_stop(core, now_ms() + 1000u) == FTUN_E_STALE);
  CHECK(ftun_core_destroy(&core) == FTUN_OK && core == NULL);
  CHECK(ftun_core_destroy(&core) == FTUN_OK);
  CHECK(ftun_core_destroy(NULL) == FTUN_E_INVALID);
  return 0;
}

typedef struct {
  const char *path;
  pthread_t owner;
  uint64_t expires;
  uint64_t stop_deadline;
  unsigned int step;
  unsigned int post_callbacks;
  unsigned int reload_callbacks;
  int failed;
  int timeout;
} lifecycle_t;

static void post_done(ftun_operation_t *operation, ftun_error_t result, void *user)
{
  lifecycle_t *test = user;
  if (operation == NULL || result.status != FTUN_OK ||
      result.stage != FTUN_STAGE_CONTROL || !pthread_equal(test->owner, pthread_self())) {
    test->failed = 1;
  }
  test->post_callbacks++;
}

static void reload_done(ftun_operation_t *operation, ftun_error_t result, void *user)
{
  lifecycle_t *test = user;
  if (operation == NULL || result.status != FTUN_OK ||
      result.stage != FTUN_STAGE_COMMIT || !pthread_equal(test->owner, pthread_self())) {
    test->failed = 1;
  }
  test->reload_callbacks++;
}

static int owner_tick(void *raw, void *user)
{
  ftun_core_t *core = raw;
  lifecycle_t *test = user;
  ftun_operation_t *operation = NULL;
  ftun_core_info_t info;
  CHECK(!test->failed && now_ms() < test->expires);
  CHECK(get_info(core, FTUN_OK, &info) == 0 && info.state == FTUN_CORE_RUNNING);
  if (test->step == 0u) {
    CHECK(ftun_core_post(core, post_done, test, &operation) == FTUN_OK);
    CHECK(operation != NULL);
    test->step++;
  } else if (test->step == 1u && test->post_callbacks == 1u) {
    CHECK(ftun_core_reload(core, test->path, reload_done, test, &operation) == FTUN_OK);
    CHECK(operation != NULL);
    test->step++;
  } else if (test->step == 2u && test->reload_callbacks == 1u) {
    CHECK(info.generation == 2u && info.owner_rounds > 0u &&
          info.owner_max_busy_ms > 0u && info.owner_max_deadline_lateness_ms == 13u &&
          info.owner_max_work >= 7u && info.owner_quota_exhaustions > 0u);
    test->stop_deadline = now_ms() + 1000u;
    CHECK(ftun_core_stop(core, test->stop_deadline + 1000u) == FTUN_OK);
    CHECK(ftun_core_stop(core, test->stop_deadline) == FTUN_OK);
    test->step++;
  }
  return 0;
}

static int lifecycle(const char *path, int timeout)
{
  ftun_core_options_t options = default_options();
  ftun_core_t *core;
  ftun_core_info_t info;
  void *raw = NULL;
  lifecycle_t test;
  memset(&test, 0, sizeof(test));
  test.path = path;
  test.owner = pthread_self();
  test.expires = now_ms() + 5000u;
  test.timeout = timeout;
  options.operation_capacity = 16u;
  ftun_test_service_begin(owner_tick, &test, timeout);
  CHECK(ftun_test_service_create(&options, &raw) == FTUN_OK);
  core = raw;
  /* 启动前的参数错误不消耗 Core；同一对象随后可成功进入 run。 */
  CHECK(ftun_core_run(core, "") == FTUN_E_INVALID);
  CHECK(ftun_core_run(core, path) == (timeout ? FTUN_E_TIMEOUT : FTUN_OK));
  CHECK(!test.failed && test.step == 3u && test.post_callbacks == 1u &&
        test.reload_callbacks == 1u);
  /* 宿主可将剩余期限分成有界片段；不能给予超过调用方总期限的等待。 */
  CHECK(ftun_test_service_deadline() != 0u &&
        ftun_test_service_deadline() <= test.stop_deadline);
  CHECK(get_info(core, FTUN_OK, &info) == 0 && info.generation == 2u &&
        info.pending_operations == 0u &&
        info.state == (timeout ? FTUN_CORE_STOPPING : FTUN_CORE_STOPPED));
  if (timeout) {
    ftun_core_t *retained = core;
    CHECK(ftun_core_destroy(&core) == FTUN_E_AGAIN && core == retained);
    ftun_test_service_release();
  } else {
    CHECK(ftun_core_stop(core, now_ms() + 1000u) == FTUN_OK);
  }
  CHECK(ftun_core_destroy(&core) == FTUN_OK && core == NULL);
  CHECK(test.post_callbacks == 1u && test.reload_callbacks == 1u);
  return 0;
}

int main(void)
{
  static const char *const names[] = {
    "ok", "invalid", "not-implemented", "unsupported", "again", "eof",
    "cancelled", "timeout", "limit", "io", "resolve", "rejected", "protocol",
    "restart-required", "stale", "state-corrupt"
  };
  const char config[] = "{\"base\":{\"state-cache\":false},"
    "\"log\":{\"level\":\"silent\"},\"dns\":{\"enable\":false}}\n";
  char path[] = "/tmp/ftun-abi-config-XXXXXX";
  size_t old_layout[128], current_layout[128];
  size_t count = ftun_test_abi_layout(old_layout, 128u);
  int descriptor;
  CHECK(count <= 128u && ftun_test_current_layout(current_layout, 128u) == count);
  CHECK(memcmp(old_layout, current_layout, count * sizeof(size_t)) == 0);
  CHECK(FTUN_ABI_VERSION == 1u && ftun_version() != NULL);
  for (size_t index = 0u; index < sizeof(names) / sizeof(names[0]); index++) {
    CHECK(strcmp(ftun_status_name((ftun_status_t)index), names[index]) == 0);
  }
  CHECK(strcmp(ftun_status_name((ftun_status_t)-1), "unknown") == 0);
  CHECK(options_boundaries() == 0);
  CHECK(synchronous_edges() == 0);
  descriptor = mkstemp(path);
  CHECK(descriptor >= 0);
  CHECK(write(descriptor, config, sizeof(config) - 1u) == (ssize_t)(sizeof(config) - 1u));
  CHECK(close(descriptor) == 0);
  CHECK(lifecycle(path, 0) == 0);
  CHECK(lifecycle(path, 1) == 0);
  CHECK(unlink(path) == 0);
  printf("C API ABI OK: header=%s library=%s info=%zu options=%zu layout=%zu\n",
         FTUN_VERSION, ftun_version(), sizeof(ftun_core_info_t),
         sizeof(ftun_core_options_t), count);
  return 0;
}
