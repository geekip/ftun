#define _POSIX_C_SOURCE 200809L
#include <sys/types.h>
#include "app/config/config.h"
#include "app/config/parser.h"
#include "app/config/model.h"
#include "app/config/compile.h"
#include "core/limits.h"
#if defined(FTUN_HAVE_MODULE_PROXY)
#include "proxy/runtime_state.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <pwd.h>
#include <sys/stat.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "config memory failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

static struct { void *pointer; size_t bytes; } heap[8192];
static size_t live_bytes, allocation_calls, fail_at;
static bool tracking, tracker_failed;
/* 跟踪阶段只在本夹具的单线程路径运行，跳过libc内部的嵌套分配。 */
static unsigned int allocation_depth;
int __real_getpwuid_r(uid_t uid, struct passwd *record, char *buffer,
  size_t capacity, struct passwd **result);
int __wrap_getpwuid_r(uid_t uid, struct passwd *record, char *buffer,
  size_t capacity, struct passwd **result)
{
  int status;
  if (!tracking) return __real_getpwuid_r(uid, record, buffer, capacity, result);
  /* 调用方工作区仍计量；libc/NSS内部临时对象与回退不属于第一方分配。 */
  allocation_depth++;
  status = __real_getpwuid_r(uid, record, buffer, capacity, result);
  allocation_depth--;
  return status;
}
static bool small_stat;
int __real_fstat(int fd, struct stat *info);
int __wrap_fstat(int fd, struct stat *info)
{
  int result = __real_fstat(fd, info);
  if (result == 0 && small_stat) info->st_size = 0;
  return result;
}
void *__real_malloc(size_t bytes);
void *__real_calloc(size_t count, size_t bytes);
void *__real_realloc(void *value, size_t bytes);
void __real_free(void *value);
static bool fail(void)
{
  if (!tracking) return false;
  allocation_calls++;
  return fail_at != 0u && allocation_calls == fail_at;
}
static void record(void *value, size_t bytes)
{
  size_t i;
  if (!tracking || value == NULL) return;
  for (i = 0u; i < sizeof(heap) / sizeof(heap[0]); i++) {
    if (heap[i].pointer == NULL) {
      heap[i].pointer = value; heap[i].bytes = bytes; live_bytes += bytes; return;
    }
  }
  tracker_failed = true;
}
static void forget(void *value)
{
  size_t i;
  if (value == NULL) return;
  for (i = 0u; i < sizeof(heap) / sizeof(heap[0]); i++) {
    if (heap[i].pointer == value) {
      live_bytes -= heap[i].bytes; heap[i].pointer = NULL; heap[i].bytes = 0u; return;
    }
  }
}
void *__wrap_malloc(size_t bytes)
{
  void *value;
  if (!tracking || allocation_depth != 0u) return __real_malloc(bytes);
  if (fail()) return NULL;
  allocation_depth++;
  value = __real_malloc(bytes);
  allocation_depth--;
  record(value, bytes); return value;
}
void *__wrap_calloc(size_t count, size_t bytes)
{
  void *value;
  if (!tracking || allocation_depth != 0u) return __real_calloc(count, bytes);
  if (fail()) return NULL;
  allocation_depth++;
  value = __real_calloc(count, bytes);
  allocation_depth--;
  record(value, count * bytes); return value;
}
void *__wrap_realloc(void *value, size_t bytes)
{
  void *next;
  size_t i, slot = sizeof(heap) / sizeof(heap[0]);
  if (!tracking || allocation_depth != 0u) return __real_realloc(value, bytes);
  if (fail()) return NULL;
  for (i = 0u; i < sizeof(heap) / sizeof(heap[0]); i++) if (heap[i].pointer == value && value != NULL) { slot = i; break; }
  allocation_depth++;
  next = __real_realloc(value, bytes);
  allocation_depth--;
  if (next != NULL) {
    if (slot != sizeof(heap) / sizeof(heap[0])) {
      live_bytes -= heap[slot].bytes; heap[slot].pointer = NULL; heap[slot].bytes = 0u;
    }
    record(next, bytes);
  }
  return next;
}
void __wrap_free(void *value)
{
  if (allocation_depth != 0u) { __real_free(value); return; }
  forget(value); __real_free(value);
}

static const char model[] =
  "{\"dns\":{\"enable\":false},\"tun\":{\"interface\":\"ftun0\",\"ipv4\":{\"address\":\"172.19.0.1/30\"}},"
  "\"inbounds\":[{\"type\":\"tun\",\"name\":\"  tunnel  \",\"outbound\":\"  DIRECT  \"}],"
  "\"outbounds\":[{\"type\":\"select\",\"name\":\"  selector  \",\"outbounds\":[\" DIRECT \"],\"default\":\" DIRECT \"}],"
  "\"rules\":[\"MATCH,  DIRECT  \"],\"base\":{\"state-cache\":false}}";
static const char minimal[] = "{\"dns\":{\"enable\":false},\"base\":{\"state-cache\":false}}";
static ftun_status_t parse(ftun_budget_t *budget, const char *text, ftun_config_t **out)
{ return ftun_config_parse_budget(budget, (ftun_bytes_t){(const uint8_t *)text, strlen(text)}, out); }
static int check_usage(ftun_budget_t *budget, size_t expected)
{
  ftun_budget_usage_t usage;
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == expected);
  CHECK(usage.used_resources.descriptors == 0u);
  return 0;
}

static int allocations(void)
{
  ftun_budget_t *budget = NULL;
  ftun_config_t *config = NULL, *copy;
  ftun_budget_usage_t before, after;
  size_t attempts, i;
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &before) == FTUN_OK);
  tracking = true; allocation_calls = 0u;
  CHECK(parse(budget, model, &config) == FTUN_OK);
  attempts = allocation_calls;
  CHECK(strcmp(config->inbounds[0].name, "tunnel") == 0);
  CHECK(strcmp(config->rules.items[0], "MATCH,DIRECT") == 0);
  CHECK(config->tun.interface_name != config->inbounds[0].interface_name);
  CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK && after.used_resources.memory_bytes == config->document.owned_bytes);
  /* 跟踪真实malloc/calloc请求；包括被裁剪的尾部与两份TUN副本。 */
  CHECK(live_bytes == after.used_resources.memory_bytes + after.metadata_bytes - before.metadata_bytes && !tracker_failed);
  CHECK(ftun_config_retain(config) == FTUN_OK);
  copy = config;
  CHECK(ftun_config_destroy(&copy) == FTUN_OK && check_usage(budget, after.used_resources.memory_bytes) == 0);
  CHECK(ftun_config_destroy(&config) == FTUN_OK && live_bytes == 0u && check_usage(budget, 0u) == 0);
  for (i = 1u; i <= attempts; i++) {
    fail_at = i; allocation_calls = 0u;
    CHECK(parse(budget, model, &config) != FTUN_OK && config == NULL);
    CHECK(live_bytes == 0u && check_usage(budget, 0u) == 0 && !tracker_failed);
  }
  fail_at = 0u;
  /* 独立feature_plan有自己的拥有期，模型仍可继续被引用。 */
  CHECK(parse(budget, minimal, &config) == FTUN_OK);
  allocation_calls = 0u;
  CHECK(ftun_config_compile(config, &config->plan) == FTUN_OK);
  attempts = allocation_calls;
  CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK);
  CHECK(after.used_resources.memory_bytes == config->document.owned_bytes + config->plan->owned_bytes);
  CHECK(live_bytes == after.used_resources.memory_bytes + after.metadata_bytes - before.metadata_bytes);
  CHECK(ftun_feature_plan_destroy(&config->plan) == FTUN_OK);
  for (i = 1u; i <= attempts; i++) {
    fail_at = i; allocation_calls = 0u;
    CHECK(ftun_config_compile(config, &config->plan) != FTUN_OK && config->plan == NULL);
    CHECK(check_usage(budget, config->document.owned_bytes) == 0);
  }
  fail_at = 0u;
  CHECK(ftun_config_destroy(&config) == FTUN_OK && live_bytes == 0u);
  tracking = false;
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  /* 从不足以创建模型到可完成解析，逐档验证预算拒绝后的完整回滚。 */
  for (i = 64u; i <= after.high_watermarks.memory_bytes + 128u; i += 127u) {
    ftun_status_t status;
    CHECK(ftun_budget_create(NULL, i, 0u, &budget) == FTUN_OK);
    status = parse(budget, model, &config);
    CHECK(status == FTUN_OK || status == FTUN_E_LIMIT);
    CHECK(ftun_config_destroy(&config) == FTUN_OK && check_usage(budget, 0u) == 0);
    CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
    if (status == FTUN_OK) break;
  }
  return 0;
}

static int limits(void)
{
  ftun_budget_t *budget = NULL;
  ftun_config_t *config = NULL;
  char *oversize;
  size_t i, length = 7u + FTUN_CONFIG_MAX_NODES * 3u + 2u;
  CHECK(ftun_budget_create(NULL, 1u, 0u, &budget) == FTUN_OK);
  CHECK(parse(budget, minimal, &config) == FTUN_E_LIMIT && config == NULL);
  CHECK(check_usage(budget, 0u) == 0 && ftun_budget_destroy(&budget) == FTUN_OK);
  oversize = malloc(length + 1u);
  CHECK(oversize != NULL);
  memcpy(oversize, "{\"x\":[", 6u);
  for (i = 0u; i < FTUN_CONFIG_MAX_NODES; i++) memcpy(oversize + 6u + i * 3u, "{},", 3u);
  memcpy(oversize + 6u + FTUN_CONFIG_MAX_NODES * 3u - 1u, "]}", 3u);
  tracking = true; allocation_calls = 0u;
  CHECK(parse(NULL, oversize, &config) == FTUN_E_LIMIT && config == NULL && allocation_calls == 0u);
  tracking = false; free(oversize);
  return 0;
}

static int loading(void)
{
  char path[] = "/tmp/ftun-config-memory-XXXXXX";
  const char content[] = "{\"dns\":{\"enable\":false},\"log\":{\"file\":\"./run.log\"},\"base\":{\"cache-file\":\"~/.ftun-memory-test.cache\",\"state-cache\":false}}";
  int fd = mkstemp(path);
  ftun_budget_t *budget = NULL;
  ftun_config_t *config = NULL;
  ftun_budget_options_t options = {{65536u, 0u, 0u}, {0}, {0}};
  ftun_budget_usage_t before, after;
  ftun_config_trace_t trace;
  size_t attempts, i;
  CHECK(fd >= 0 && write(fd, content, sizeof(content) - 1u) == (ssize_t)(sizeof(content) - 1u) && close(fd) == 0);
  CHECK(ftun_budget_create_resources(NULL, &options, &budget) == FTUN_OK);
  CHECK(ftun_config_load_budget_traced(budget, path, &config, &trace) == FTUN_E_LIMIT && config == NULL);
  CHECK(trace.failed == FTUN_CONFIG_STEP_READ && check_usage(budget, 0u) == 0);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  options.limit.descriptors = 1u;
  CHECK(ftun_budget_create_resources(NULL, &options, &budget) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &before) == FTUN_OK);
  tracking = true; allocation_calls = 0u;
  CHECK(ftun_config_load_budget_traced(budget, path, &config, &trace) == FTUN_OK);
  attempts = allocation_calls;
  CHECK(trace.completed == FTUN_CONFIG_STEP_COMPILE && trace.failed == FTUN_CONFIG_STEP_NONE);
  CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK && after.high_watermarks.memory_bytes < 16384u);
  CHECK(after.used_resources.memory_bytes == config->document.owned_bytes + config->plan->owned_bytes);
  CHECK(live_bytes == after.used_resources.memory_bytes + after.metadata_bytes - before.metadata_bytes);
  CHECK(ftun_config_destroy(&config) == FTUN_OK && live_bytes == 0u && check_usage(budget, 0u) == 0);
  for (i = 1u; i <= attempts; i++) {
    fail_at = i; allocation_calls = 0u;
    CHECK(ftun_config_load_budget_traced(budget, path, &config, &trace) != FTUN_OK && config == NULL);
    CHECK(live_bytes == 0u && check_usage(budget, 0u) == 0);
  }
  fail_at = 0u; tracking = false;
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK && unlink(path) == 0);
  return 0;
}

#if defined(FTUN_HAVE_MODULE_PROXY)
static int retention(void)
{
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_config_t *config = NULL;
  ftun_runtime_t *candidate = NULL, *old = NULL;
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(parse(budget, minimal, &config) == FTUN_OK && ftun_config_compile(config, &config->plan) == FTUN_OK);
  CHECK(ftun_runtime_manager_create_limits(budget, 1u,
    config->document.owned_bytes + config->plan->owned_bytes, &core) == FTUN_OK);
  CHECK(ftun_runtime_prepare(core, config, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_active_acquire(core, &old) == FTUN_OK);
  CHECK(ftun_runtime_prepare(core, config, &candidate) == FTUN_E_LIMIT && candidate == NULL);
  CHECK(ftun_runtime_release(&old) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_config_destroy(&config) == FTUN_OK && check_usage(budget, 0u) == 0);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int shared(void)
{
  ftun_budget_t *budget = NULL, *other = NULL;
  ftun_core_t *core = NULL, *foreign = NULL;
  ftun_config_t *config = NULL;
  ftun_runtime_t *candidate = NULL;
  ftun_budget_usage_t usage;
  size_t baseline, own;
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(parse(budget, minimal, &config) == FTUN_OK && ftun_config_compile(config, &config->plan) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 2u, &core) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK); baseline = usage.used_resources.memory_bytes;
  CHECK(ftun_runtime_accounted_bytes(config, &own) == FTUN_OK);
  own -= config->document.owned_bytes + config->plan->owned_bytes;
  {
    ftun_config_t *unbound = NULL;
    size_t covered;
    CHECK(parse(NULL, minimal, &unbound) == FTUN_OK);
    CHECK(ftun_config_compile(unbound, &unbound->plan) == FTUN_OK);
    CHECK(ftun_runtime_accounted_bytes(unbound, &covered) == FTUN_OK);
    CHECK(covered == own + config->document.owned_bytes + config->plan->owned_bytes);
    CHECK(ftun_config_destroy(&unbound) == FTUN_OK);
  }
  CHECK(ftun_runtime_prepare(core, config, &candidate) == FTUN_OK && check_usage(budget, baseline + own) == 0);
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_prepare(core, config, &candidate) == FTUN_OK && check_usage(budget, baseline + 2u * own) == 0);
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK && check_usage(budget, baseline + own) == 0);
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &other) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(other, 1u, &foreign) == FTUN_OK);
  CHECK(ftun_runtime_prepare(foreign, config, &candidate) == FTUN_E_INVALID && candidate == NULL);
  CHECK(ftun_runtime_manager_destroy(&foreign) == FTUN_OK && ftun_budget_destroy(&other) == FTUN_OK);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK && check_usage(budget, 0u) == 0);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}
#endif
typedef struct { ftun_budget_t *budget; bool failed; } parse_thread_t;
static void *parse_thread(void *user)
{
  parse_thread_t *state = user;
  size_t i;
  for (i = 0u; i < 200u; i++) {
    ftun_config_t *config = NULL;
    if (parse(state->budget, minimal, &config) != FTUN_OK || config == NULL ||
        ftun_config_destroy(&config) != FTUN_OK ||
        parse(state->budget, "{bad}", &config) != FTUN_E_INVALID || config != NULL) {
      state->failed = true;
      break;
    }
  }
  return NULL;
}
static int concurrent_parsing(void)
{
  ftun_budget_t *budget = NULL;
  parse_thread_t states[4];
  pthread_t threads[4];
  size_t i;
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  for (i = 0u; i < 4u; i++) {
    states[i].budget = budget; states[i].failed = false;
    CHECK(pthread_create(&threads[i], NULL, parse_thread, &states[i]) == 0);
  }
  for (i = 0u; i < 4u; i++) CHECK(pthread_join(threads[i], NULL) == 0 && !states[i].failed);
  CHECK(check_usage(budget, 0u) == 0 && ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(int argc, char **argv)
{
#if defined(FTUN_HAVE_MODULE_PROXY)
  if (argc == 2 && strcmp(argv[1], "retention") == 0) return retention();
#else
  (void)argc; (void)argv;
#endif
  CHECK(allocations() == 0);
  CHECK(limits() == 0);
  CHECK(concurrent_parsing() == 0);
  CHECK(loading() == 0);
  small_stat = true;
  CHECK(loading() == 0);
  small_stat = false;
#if defined(FTUN_HAVE_MODULE_PROXY)
  CHECK(shared() == 0);
  CHECK(retention() == 0);
#endif
  return 0;
}
