#define _POSIX_C_SOURCE 200809L
/* 真实组合附件及其叶对象；只替换分配观察、下载源和失败释放。 */
#include "app/composition/proxy_runtime.c"
#include "config/parser.h"
#include "platform/file.h"
#include <stdio.h>
#include <stdarg.h>
#if defined(FTUN_HAVE_MODULE_FRS)
#include "frs_fixture.h"
#endif

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "app proxy memory failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

static struct { void *value; size_t bytes; } heap[256];
static size_t live_bytes, fail_size, watch_size, watched_used, open_calls;
static bool tracking, broken, hold_routes, fail_read;
/* 跟踪阶段只在本夹具的单线程路径运行，跳过libc内部的嵌套分配。 */
static unsigned int allocation_depth;
static ftun_budget_t *budget;
static ftun_app_runtime_candidate_t *records_target;
static ftun_budget_usage_t tracked_baseline;
static size_t verified_reads;
static struct { int descriptor; bool active; } descriptors[16];
static size_t live_descriptors, peak_descriptors;

static void descriptor_admission(void)
{
  ftun_budget_usage_t usage;
  if (!tracking) return;
  if (ftun_budget_get_usage(budget, &usage) != FTUN_OK ||
      usage.used_resources.descriptors < live_descriptors + 1u ||
      usage.used < tracked_baseline.used || usage.metadata_bytes < tracked_baseline.metadata_bytes ||
      live_bytes > usage.used - tracked_baseline.used + usage.metadata_bytes - tracked_baseline.metadata_bytes) broken = true;
}
static int descriptor_record(int descriptor)
{
  size_t i;
  if (!tracking || descriptor < 0) return descriptor;
  for (i = 0u; i < 16u; i++) {
    if (descriptors[i].active && descriptors[i].descriptor == descriptor) return descriptor;
  }
  for (i = 0u; i < 16u; i++) if (!descriptors[i].active) {
    descriptors[i].active = true; descriptors[i].descriptor = descriptor;
    live_descriptors++;
    if (live_descriptors > peak_descriptors) peak_descriptors = live_descriptors;
    return descriptor;
  }
  broken = true;
  return descriptor;
}
void *__real_malloc(size_t size);
void *__real_calloc(size_t count, size_t size);
void __real_free(void *value);
static void record(void *value, size_t bytes)
{
  size_t i;
  if (!tracking || value == NULL) return;
  for (i = 0u; i < 256u; i++) if (heap[i].value == NULL) {
    heap[i].value = value; heap[i].bytes = bytes; live_bytes += bytes; return;
  }
  broken = true;
}
void *__wrap_malloc(size_t size)
{
  void *value;
  if (allocation_depth != 0u) return __real_malloc(size);
  allocation_depth++;
  value = __real_malloc(size);
  allocation_depth--;
  record(value, size); return value;
}
void *__wrap_calloc(size_t count, size_t size)
{
  void *value;
  size_t bytes = count * size;
  bool eligible = records_target == NULL || records_target->records_reservation != NULL;
  if (allocation_depth != 0u) return __real_calloc(count, size);
  if (eligible && watch_size != 0u && bytes == watch_size) {
    ftun_budget_usage_t usage;
    if (ftun_budget_get_usage(budget, &usage) != FTUN_OK) abort();
    watched_used = usage.used; watch_size = 0u;
  }
  if (eligible && fail_size != 0u && bytes == fail_size) { fail_size = 0u; return NULL; }
  allocation_depth++;
  value = __real_calloc(count, size);
  allocation_depth--;
  record(value, bytes);
  if (tracking && value != NULL) {
    ftun_budget_usage_t usage;
    if (ftun_budget_get_usage(budget, &usage) != FTUN_OK ||
        usage.used < tracked_baseline.used || usage.metadata_bytes < tracked_baseline.metadata_bytes ||
        live_bytes > usage.used - tracked_baseline.used + usage.metadata_bytes - tracked_baseline.metadata_bytes) broken = true;
  }
  return value;
}
void __wrap_free(void *value)
{
  size_t i;
  if (allocation_depth != 0u) { __real_free(value); return; }
  for (i = 0u; value != NULL && i < 256u; i++) if (heap[i].value == value) {
    live_bytes -= heap[i].bytes; heap[i].value = NULL; break;
  }
  __real_free(value);
}
int __real_open(const char *path, int flags, ...);
int __wrap_open(const char *path, int flags, ...)
{
  mode_t mode = 0;
  if ((flags & O_CREAT) != 0) {
    va_list arguments;
    va_start(arguments, flags); mode = (mode_t)va_arg(arguments, int); va_end(arguments);
  }
  if (tracking) {
    ftun_budget_usage_t usage;
    open_calls++;
    if (ftun_budget_get_usage(budget, &usage) != FTUN_OK ||
        usage.used_resources.descriptors == 0u) broken = true;
  }
  descriptor_admission();
  return descriptor_record(__real_open(path, flags, mode));
}
int __real_mkstemp(char *path);
int __wrap_mkstemp(char *path)
{
  descriptor_admission();
  return descriptor_record(__real_mkstemp(path));
}
int __real_close(int descriptor);
int __wrap_close(int descriptor)
{
  size_t i;
  for (i = 0u; i < 16u; i++) if (descriptors[i].active && descriptors[i].descriptor == descriptor) {
    descriptors[i].active = false; live_descriptors--; break;
  }
  return __real_close(descriptor);
}
ssize_t __real_read(int descriptor, void *data, size_t length);
ssize_t __wrap_read(int descriptor, void *data, size_t length)
{
  if (tracking) {
    ftun_budget_usage_t usage;
    verified_reads++;
    if (ftun_budget_get_usage(budget, &usage) != FTUN_OK ||
        usage.used < tracked_baseline.used || usage.metadata_bytes < tracked_baseline.metadata_bytes ||
        live_bytes != usage.used - tracked_baseline.used + usage.metadata_bytes - tracked_baseline.metadata_bytes) {
      broken = true;
    }
  }
  if (fail_read) { errno = EIO; return -1; }
  return __real_read(descriptor, data, length);
}
ftun_status_t __real_ftun_route_table_destroy(ftun_route_table_t **table);
ftun_status_t __wrap_ftun_route_table_destroy(ftun_route_table_t **table)
{
  if (hold_routes && table != NULL && *table != NULL) return FTUN_E_AGAIN;
  return __real_ftun_route_table_destroy(table);
}

static int balance(const ftun_budget_usage_t *before)
{
  ftun_budget_usage_t after;
  CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK);
  CHECK(!broken && after.used >= before->used && after.metadata_bytes >= before->metadata_bytes);
  CHECK(live_bytes == after.used - before->used + after.metadata_bytes - before->metadata_bytes);
  CHECK(after.used_resources.descriptors == before->used_resources.descriptors);
  CHECK(live_descriptors == 0u);
  return 0;
}
static ftun_config_t *config_make(const char *text)
{
  ftun_config_t *config = NULL;
  if (ftun_config_parse_budget(budget,
        (ftun_bytes_t){(const uint8_t *)text, strlen(text)}, &config) != FTUN_OK) return NULL;
  if (ftun_config_compile(config, &config->plan) != FTUN_OK) {
    (void)ftun_config_destroy(&config); return NULL;
  }
  return config;
}
static int attachments(void)
{
  const char text[] = "{\"base\":{\"state-cache\":false},\"dns\":{\"enable\":false},"
    "\"outbounds\":[{\"type\":\"select\",\"name\":\"selector\","
    "\"outbounds\":[\"DIRECT\"],\"default\":\"DIRECT\"}],\"rules\":[\"MATCH,selector\"]}";
  ftun_config_t *config;
  ftun_core_t *core = NULL;
  ftun_runtime_t *active = NULL;
  ftun_app_runtime_candidate_t *attachment = NULL;
  ftun_app_prepare_context_t context = {2u, 0u, true};
  ftun_reservation_t *hold = NULL;
  ftun_budget_usage_t before;
  bool publish;
  CHECK(ftun_budget_create(NULL, 8u * 1024u * 1024u, 0u, &budget) == FTUN_OK);
  config = config_make(text); CHECK(config != NULL);
  CHECK(ftun_runtime_manager_create(budget, 2u, &core) == FTUN_OK);
  CHECK(ftun_runtime_prepare(core, config, &active) == FTUN_OK);
  CHECK(ftun_runtime_commit(core, &active) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &before) == FTUN_OK);
  CHECK(ftun_budget_reserve(budget, before.normal_available, &hold) == FTUN_OK);
  watch_size = sizeof(*attachment);
  CHECK(ftun_proxy_attachment_create(budget, config, &attachment) == FTUN_E_LIMIT && attachment == NULL);
  CHECK(watch_size != 0u);
  CHECK(ftun_reservation_release(&hold) == FTUN_OK);
  fail_size = sizeof(*attachment);
  CHECK(ftun_proxy_attachment_create(budget, config, &attachment) == FTUN_E_LIMIT && attachment == NULL);
  CHECK(fail_size == 0u && watch_size == 0u && watched_used == before.used + sizeof(*attachment));
  tracked_baseline = before;
  tracking = true;
  CHECK(ftun_proxy_support_prepare(budget, config, 1024u * 1024u, &context, &attachment, &publish) == FTUN_OK);
  CHECK(attachment != NULL && !publish && balance(&before) == 0);
  CHECK(ftun_proxy_support_adopt(core, attachment, 1u, NULL) == FTUN_OK);
  CHECK(attachment->group_record_capacity == 1u && balance(&before) == 0);
  CHECK(ftun_proxy_support_release(core, &attachment) == FTUN_OK && attachment == NULL);
  CHECK(live_bytes == 0u && balance(&before) == 0);
  /* 数组准入后分配失败，额度仍由可回收附件持有。 */
  CHECK(ftun_proxy_support_prepare(budget, config, 1024u * 1024u, &context, &attachment, &publish) == FTUN_OK);
  records_target = attachment;
  fail_size = watch_size = sizeof(ftun_runtime_group_record_t);
  CHECK(ftun_proxy_support_adopt(core, attachment, 1u, NULL) == FTUN_E_LIMIT);
  CHECK(fail_size == 0u && watch_size == 0u && attachment->records_reservation != NULL);
  records_target = NULL;
  CHECK(ftun_proxy_support_release(core, &attachment) == FTUN_OK);
  CHECK(live_bytes == 0u && balance(&before) == 0);
  tracking = false;
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

#if defined(FTUN_HAVE_MODULE_FRS)
static uint8_t *download;
static size_t download_length, downloads;
ftun_status_t __wrap_ftun_http_fetch(const ftun_http_fetch_spec_t *spec,
  ftun_http_fetch_result_t *out)
{
  ftun_status_t status;
  memset(out, 0, sizeof(*out));
  if (spec->budget != budget) { broken = true; return FTUN_E_INVALID; }
  downloads++;
  status = ftun_budget_reserve(spec->budget, download_length, &out->reservation);
  if (status != FTUN_OK) return status;
  out->data = malloc(download_length);
  if (out->data == NULL) { ftun_http_fetch_release(out); return FTUN_E_LIMIT; }
  memcpy(out->data, download, download_length);
  out->length = download_length; out->status = 200u;
  return FTUN_OK;
}
static int frs_prepare(void)
{
  char directory[] = "/tmp/ftun-app-memory-XXXXXX", path[128], text[512];
  ftun_budget_options_t options = {{8u * 1024u * 1024u, 2u, 16u}, {0}, {0}};
  ftun_budget_resources_t descriptor = {0u, 2u, 0u};
  ftun_app_prepare_context_t context = {2u, 0u, true};
  ftun_app_runtime_candidate_t *attachment = NULL;
  ftun_config_t *config;
  ftun_budget_usage_t before;
  ftun_reservation_t *hold = NULL;
  bool publish;
  CHECK(ftun_test_frs_fixture(&download, &download_length));
  CHECK(mkdtemp(directory) != NULL);
  CHECK(snprintf(path, sizeof(path), "%s/rules.frs", directory) > 0);
  CHECK(ftun_test_write_file(path, download, download_length));
  CHECK(snprintf(text, sizeof(text), "{\"base\":{\"state-cache\":false},\"dns\":{\"enable\":false},"
    "\"frs\":{\"path\":\"%s\",\"auto-update\":true,\"url\":\"http://127.0.0.1/rules\"},"
    "\"rules\":[\"FRS-IP,CN,DIRECT\"]}", path) > 0);
  CHECK(ftun_budget_create_resources(NULL, &options, &budget) == FTUN_OK);
  config = config_make(text); CHECK(config != NULL);
  CHECK(ftun_budget_get_usage(budget, &before) == FTUN_OK);
  tracked_baseline = before;
  open_calls = 0u;
  verified_reads = 0u;
  tracking = true;
  CHECK(ftun_proxy_support_prepare(budget, config, 1024u * 1024u, &context, &attachment, &publish) == FTUN_OK);
  CHECK(!publish && downloads == 0u && open_calls == 1u && verified_reads != 0u && balance(&before) == 0);
  hold_routes = true;
  CHECK(ftun_proxy_support_release(NULL, &attachment) == FTUN_E_AGAIN && attachment != NULL);
  CHECK(balance(&before) == 0);
  hold_routes = false;
  CHECK(ftun_proxy_support_release(NULL, &attachment) == FTUN_OK && live_bytes == 0u);
  CHECK(balance(&before) == 0);
  fail_read = true;
  CHECK(ftun_proxy_support_prepare(budget, config, 1024u * 1024u, &context, &attachment, &publish) == FTUN_E_IO);
  fail_read = false;
  CHECK(open_calls == 2u && attachment != NULL && downloads == 0u);
  CHECK(ftun_proxy_support_release(NULL, &attachment) == FTUN_OK && live_bytes == 0u);
  CHECK(balance(&before) == 0);
  CHECK(ftun_budget_reserve_resources(budget, descriptor, &hold) == FTUN_OK);
  CHECK(ftun_proxy_support_prepare(budget, config, 1024u * 1024u, &context, &attachment, &publish) == FTUN_E_LIMIT);
  CHECK(open_calls == 2u && attachment != NULL && downloads == 0u);
  CHECK(ftun_proxy_support_release(NULL, &attachment) == FTUN_OK);
  CHECK(ftun_reservation_release(&hold) == FTUN_OK);
  CHECK(live_bytes == 0u && balance(&before) == 0);
  CHECK(unlink(path) == 0);
  CHECK(ftun_proxy_support_prepare(budget, config, 1024u * 1024u, &context, &attachment, &publish) == FTUN_OK);
  CHECK(publish && downloads == 1u && open_calls == 3u && balance(&before) == 0);
  {
    ftun_core_t *core = NULL;
    ftun_worker_job_t job = {0};
    ftun_reservation_t *input_reservation = NULL;
    ftun_app_publish_result_t result;
    size_t result_length = 0u;
    CHECK(ftun_runtime_manager_create(budget, 2u, &core) == FTUN_OK);
    CHECK(ftun_runtime_attach_prepared(core, &attachment->detached, &attachment->candidate) == FTUN_OK);
    CHECK(ftun_proxy_support_publish_job(attachment, &job, &input_reservation) == FTUN_OK);
    CHECK(input_reservation != NULL && balance(&before) == 0);
    CHECK(job.execute(job.input, (uint8_t *)&result, sizeof(result), &result_length) == FTUN_OK);
    CHECK(result_length == sizeof(result) && result.status == FTUN_OK && result.published);
    CHECK(balance(&before) == 0 && peak_descriptors == 2u);
    free((void *)job.input.data);
    CHECK(ftun_reservation_release(&input_reservation) == FTUN_OK);
    CHECK(ftun_proxy_support_release(core, &attachment) == FTUN_OK);
    CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK && live_bytes == 0u);
    CHECK(unlink(path) == 0);
  }
  CHECK(balance(&before) == 0);
  tracking = false;
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  free(download);
  CHECK(rmdir(directory) == 0);
  return 0;
}
#endif
/* 捕获、任务输入、发布临时副本、缓存快照分别保留各自的额度。 */
static int persistence(void)
{
  char directory[] = "/tmp/ftun-cache-memory-XXXXXX", path[128], sentinel[128], text[512];
  ftun_budget_options_t options = {{8u * 1024u * 1024u, 2u, 16u}, {0}, {0}};
  ftun_budget_resources_t both = {0u, 2u, 0u}, one = {0u, 1u, 0u};
  ftun_core_t *core = NULL;
  ftun_config_t *config;
  ftun_runtime_t *runtime = NULL;
  ftun_app_runtime_candidate_t *attachment = NULL;
  ftun_app_prepare_context_t context = {2u, 0u, true};
  ftun_group_cache_snapshot_t *snapshot = NULL;
  ftun_reservation_t *input_reservation = NULL, *hold = NULL;
  ftun_worker_job_t job = {0};
  ftun_budget_usage_t before, usage;
  size_t result_size = 0u;
  bool publish;
  FILE *file;
  CHECK(mkdtemp(directory) != NULL);
  CHECK(snprintf(path, sizeof(path), "%s/groups.cache", directory) > 0);
  CHECK(snprintf(sentinel, sizeof(sentinel), "%s/.ftun.tmp.XXXXXX", directory) > 0);
  file = fopen(sentinel, "w"); CHECK(file != NULL);
  CHECK(fputs("sentinel", file) >= 0 && fclose(file) == 0);
  CHECK(snprintf(text, sizeof(text), "{\"base\":{\"cache-file\":\"%s\",\"state-cache\":true},"
    "\"dns\":{\"enable\":false},\"outbounds\":[{\"type\":\"select\",\"name\":\"selector\","
    "\"outbounds\":[\"DIRECT\"],\"default\":\"DIRECT\"}],\"rules\":[\"MATCH,selector\"]}", path) > 0);
  CHECK(ftun_budget_create_resources(NULL, &options, &budget) == FTUN_OK);
  config = config_make(text); CHECK(config != NULL);
  CHECK(ftun_runtime_manager_create(budget, 2u, &core) == FTUN_OK);
  CHECK(ftun_runtime_prepare(core, config, &runtime) == FTUN_OK);
  CHECK(ftun_runtime_commit(core, &runtime) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &before) == FTUN_OK);
  tracked_baseline = before;
  tracking = true;
  CHECK(ftun_proxy_support_state_job(core, budget, path, UINT64_MAX, &job, &input_reservation) == FTUN_OK);
  CHECK(input_reservation != NULL && balance(&before) == 0);
  CHECK(job.execute(job.input, NULL, 0u, &result_size) == FTUN_OK && result_size == 0u);
  CHECK(balance(&before) == 0 && peak_descriptors == 2u);
  free((void *)job.input.data);
  CHECK(ftun_reservation_release(&input_reservation) == FTUN_OK && live_bytes == 0u);
  memset(&job, 0, sizeof(job));
  CHECK(ftun_proxy_support_prepare(budget, config, 1024u * 1024u, &context, &attachment, &publish) == FTUN_OK);
  ftun_proxy_support_load_state(attachment);
  CHECK(attachment->group_cache_status == FTUN_OK && attachment->group_cache != NULL);
  CHECK(balance(&before) == 0);
  CHECK(ftun_proxy_support_release(core, &attachment) == FTUN_OK && live_bytes == 0u);
  /* 缓存快照分配失败，原始文件和FD的临时额度仍必须完整回收。 */
  fail_size = sizeof(*snapshot) + sizeof(ftun_runtime_group_record_t) + sizeof("selector") + sizeof("DIRECT");
  CHECK(ftun_group_cache_load_budget(budget, path, &snapshot) == FTUN_E_LIMIT && snapshot == NULL);
  CHECK(fail_size == 0u && live_bytes == 0u && balance(&before) == 0);
  /* 分配或FD准入拒绝均不得删除未由本调用创建的模板同名文件。 */
  CHECK(ftun_budget_reserve_resources(budget, both, &hold) == FTUN_OK);
  CHECK(ftun_file_write_atomic_budget(budget, path, (ftun_bytes_t){(const uint8_t *)"bad", 3u}, 0600u, NULL, NULL) == FTUN_E_LIMIT);
  CHECK(access(sentinel, F_OK) == 0);
  CHECK(ftun_reservation_release(&hold) == FTUN_OK && live_bytes == 0u);
  CHECK(ftun_budget_reserve_resources(budget, one, &hold) == FTUN_OK);
  CHECK(ftun_file_write_atomic_budget(budget, path, (ftun_bytes_t){(const uint8_t *)"bad", 3u}, 0600u, NULL, NULL) == FTUN_E_LIMIT);
  CHECK(ftun_reservation_release(&hold) == FTUN_OK && live_bytes == 0u);
  CHECK(ftun_group_cache_load_budget(budget, path, &snapshot) == FTUN_OK);
  CHECK(snapshot->record_count == 1u && snapshot->reservation != NULL && balance(&before) == 0);
  CHECK(ftun_group_cache_destroy(&snapshot) == FTUN_OK && live_bytes == 0u);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
  CHECK(ftun_budget_reserve(budget, usage.normal_available, &hold) == FTUN_OK);
  CHECK(ftun_proxy_support_state_job(core, budget, path, UINT64_MAX, &job, &input_reservation) == FTUN_E_LIMIT);
  CHECK(input_reservation == NULL && job.input.data == NULL);
  CHECK(ftun_reservation_release(&hold) == FTUN_OK && live_bytes == 0u);
  CHECK(balance(&before) == 0);
  tracking = false;
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(unlink(path) == 0 && unlink(sentinel) == 0 && rmdir(directory) == 0);
  return 0;
}

int main(void)
{
  CHECK(attachments() == 0);
  CHECK(persistence() == 0);
#if defined(FTUN_HAVE_MODULE_FRS)
  CHECK(frs_prepare() == 0);
#endif
  return 0;
}
