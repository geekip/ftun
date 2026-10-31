#define _POSIX_C_SOURCE 200809L
#include "app/config/compile.h"
#include "app/config/model.h"
#include "app/config/parser.h"
#include "core/limits.h"
#include "proxy/runtime_state.h"
#include "proxy/route/router.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(FTUN_HAVE_MODULE_FRS)
#include "frs_fixture.h"
#include "proxy/frs/frs.h"
#include "platform/file.h"
#include <unistd.h>
#endif

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "runtime cleanup failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

static bool fail_routes, consume_routes;
static size_t route_failures;
ftun_status_t __real_ftun_route_table_destroy(ftun_route_table_t **table);
ftun_status_t __wrap_ftun_route_table_destroy(ftun_route_table_t **table)
{
  if (table != NULL && *table != NULL && fail_routes) {
    route_failures++;
    if (consume_routes) {
      ftun_status_t status = __real_ftun_route_table_destroy(table);
      if (status != FTUN_OK) return status;
    }
    return FTUN_E_AGAIN;
  }
  return __real_ftun_route_table_destroy(table);
}

static ftun_config_t *make_config(void)
{
  const char text[] = "{\"dns\":{\"enable\":false},\"rules\":[\"MATCH,DIRECT\"]}";
  ftun_config_t *config = NULL;
  if (ftun_config_parse((ftun_bytes_t){(const uint8_t *)text, sizeof(text) - 1u}, &config) != FTUN_OK) return NULL;
  if (ftun_config_compile(config, &config->plan) != FTUN_OK) {
    (void)ftun_config_destroy(&config);
    return NULL;
  }
  return config;
}

static int memory(ftun_budget_t *budget, size_t expected)
{
  ftun_budget_usage_t usage;
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == expected);
  return 0;
}

/* 已消费句柄必须转交管理器；新接纳失败不影响当前活动快照。 */
static int retirement(unsigned mode)
{
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_config_t *config = make_config();
  ftun_runtime_t *candidate = NULL, *old = NULL, *active = NULL;
  ftun_runtime_manager_info_t info;
  ftun_budget_usage_t usage;
  size_t baseline, charged;
  CHECK(config != NULL);
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 2u, &core) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
  baseline = usage.used_resources.memory_bytes;
  CHECK(ftun_runtime_prepare(core, config, &candidate) == FTUN_OK);
  if (mode != 0u) CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK);
  if (mode == 3u) CHECK(ftun_runtime_active_acquire(core, &old) == FTUN_OK);
  if (mode >= 2u) CHECK(ftun_runtime_prepare(core, config, &candidate) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
  charged = usage.used_resources.memory_bytes;
  fail_routes = true;
  route_failures = 0u;
  if (mode == 0u) {
    CHECK(ftun_runtime_abort(core, &candidate) == FTUN_E_AGAIN && candidate == NULL);
  } else if (mode == 1u) {
    CHECK(ftun_runtime_manager_clear(core) == FTUN_E_AGAIN);
  } else {
    CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK && candidate == NULL);
    if (mode == 3u) CHECK(ftun_runtime_release(&old) == FTUN_E_AGAIN && old == NULL);
  }
  CHECK(route_failures == 1u && memory(budget, charged) == 0);
  CHECK(config->document.reference_count == (mode >= 2u ? 3u : 2u));
  CHECK(ftun_runtime_manager_get_info(core, &info) == FTUN_OK && info.has_cleanup);
  CHECK(!info.has_candidate && info.retained_count == 0u && info.retained_bytes == 0u);
  CHECK(info.has_active == (mode >= 2u));
  if (!consume_routes) {
    CHECK(ftun_runtime_prepare(core, config, &candidate) == FTUN_E_AGAIN && candidate == NULL);
    CHECK(memory(budget, charged) == 0);
  }
  if (mode >= 2u) {
    CHECK(ftun_runtime_active_acquire(core, &active) == FTUN_OK);
    CHECK(ftun_runtime_release(&active) == FTUN_OK);
  } else CHECK(ftun_runtime_active_acquire(core, &active) == FTUN_E_AGAIN && active == NULL);
  fail_routes = false;
  CHECK(ftun_runtime_prepare(core, config, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_manager_get_info(core, &info) == FTUN_OK && !info.has_cleanup);
  CHECK(ftun_runtime_abort(core, &candidate) == FTUN_OK);
  if (mode < 2u) CHECK(memory(budget, baseline) == 0);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK && memory(budget, 0u) == 0);
  CHECK(config->document.reference_count == 1u && ftun_config_destroy(&config) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int bounded_collection(void)
{
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_config_t *config = make_config();
  ftun_runtime_t *candidate = NULL, *first = NULL, *second = NULL;
  ftun_runtime_manager_info_t info;
  CHECK(config != NULL);
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 2u, &core) == FTUN_OK);
  CHECK(ftun_runtime_prepare(core, config, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_active_acquire(core, &first) == FTUN_OK);
  CHECK(ftun_runtime_prepare(core, config, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_active_acquire(core, &second) == FTUN_OK);
  CHECK(ftun_runtime_prepare(core, config, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK);
  fail_routes = true;
  CHECK(ftun_runtime_release(&first) == FTUN_E_AGAIN && first == NULL);
  CHECK(ftun_runtime_release(&second) == FTUN_E_AGAIN && second == NULL);
  fail_routes = false;
  CHECK(config->document.reference_count == 4u);
  CHECK(ftun_runtime_manager_clear(core) == FTUN_E_AGAIN);
  CHECK(config->document.reference_count == 3u);
  CHECK(ftun_runtime_manager_get_info(core, &info) == FTUN_OK && info.has_cleanup && info.has_active);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK && memory(budget, 0u) == 0);
  CHECK(config->document.reference_count == 1u && ftun_config_destroy(&config) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

#if defined(FTUN_HAVE_MODULE_FRS)
static bool fail_unmap;
static size_t failed_unmaps, released_maps;
static size_t allocation_at, allocation_calls;
static bool allocation_failed;
void *__real_calloc(size_t count, size_t size);
void *__wrap_calloc(size_t count, size_t size)
{
  if (allocation_at != 0u && ++allocation_calls == allocation_at) {
    allocation_failed = true;
    return NULL;
  }
  return __real_calloc(count, size);
}
ftun_status_t __real_ftun_file_unmap(const void *address, size_t length);
ftun_status_t __wrap_ftun_file_unmap(const void *address, size_t length)
{
  /* 只注入业务映射的释放，不能阻断 musl 分配器内部的 munmap。 */
  if (fail_unmap) { failed_unmaps++; return FTUN_E_IO; }
  {
    ftun_status_t result = __real_ftun_file_unmap(address, length);
    if (result == FTUN_OK) released_maps++;
    return result;
  }
}

static int detached(void)
{
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_config_t *config = make_config();
  ftun_runtime_t *prepared = NULL, *candidate = NULL;
  CHECK(config != NULL);
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 2u, &core) == FTUN_OK);
  CHECK(ftun_runtime_prepare_detached(config, NULL, &prepared) == FTUN_OK);
  fail_routes = true;
  CHECK(ftun_runtime_prepared_release(&prepared) == FTUN_E_AGAIN && prepared != NULL);
  CHECK(ftun_runtime_attach_prepared(core, &prepared, &candidate) == FTUN_E_INVALID && candidate == NULL);
  CHECK(config->document.reference_count == 1u);
  fail_routes = false;
  CHECK(ftun_runtime_prepared_release(&prepared) == FTUN_OK && prepared == NULL);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_config_destroy(&config) == FTUN_OK && memory(budget, 0u) == 0);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int mapping(void)
{
  uint8_t *fixture = NULL;
  size_t length;
  char directory[] = "/tmp/ftun-runtime-cleanup-XXXXXX", path[128];
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_frs_view_t *view = NULL;
  ftun_frs_set_t *set = NULL;
  ftun_frs_view_info_t info;
  ftun_budget_usage_t usage;
  ftun_bytes_t bytes;
  size_t baseline, charged;
  CHECK(ftun_test_frs_fixture(&fixture, &length));
  CHECK(mkdtemp(directory) != NULL);
  CHECK(snprintf(path, sizeof(path), "%s/rules.frs", directory) > 0);
  CHECK(ftun_test_write_file(path, fixture, length));
  free(fixture);
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 2u, &core) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK); baseline = usage.used_resources.memory_bytes;
  CHECK(ftun_frs_open(core, path, &view) == FTUN_OK);
  CHECK(ftun_frs_view_get_info(view, &info) == FTUN_OK && info.storage == FTUN_FRS_STORAGE_MMAP);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK); charged = usage.used_resources.memory_bytes;
  fail_unmap = true;
  CHECK(ftun_frs_view_release(&view) == FTUN_E_IO && view != NULL && failed_unmaps == 1u);
  CHECK(memory(budget, charged) == 0);
  CHECK(ftun_frs_view_retain(view) == FTUN_E_AGAIN);
  CHECK(ftun_frs_view_get_info(view, &info) == FTUN_E_AGAIN);
  CHECK(ftun_frs_view_bytes(view, &bytes) == FTUN_E_AGAIN && bytes.data == NULL);
  CHECK(ftun_frs_bind(view, FTUN_FRS_SET_IP, (ftun_string_t){"test", 4u}, &set) == FTUN_E_AGAIN && set == NULL);
  fail_unmap = false;
  CHECK(ftun_frs_view_release(&view) == FTUN_OK && view == NULL && memory(budget, baseline) == 0);
  /* 真实路由集合先释放引用，最后由 Runtime 撤销映射；失败后 manager 重试。 */
  {
    const char text[] = "{\"dns\":{\"enable\":false},\"rules\":[\"FRS-IP,CN,DIRECT\",\"MATCH,REJECT\"]}";
    ftun_config_t *config = NULL;
    ftun_runtime_t *candidate = NULL;
    ftun_runtime_manager_info_t manager_info;
    CHECK(ftun_config_parse((ftun_bytes_t){(const uint8_t *)text, sizeof(text) - 1u}, &config) == FTUN_OK);
    CHECK(ftun_config_compile(config, &config->plan) == FTUN_OK);
    CHECK(ftun_frs_open(core, path, &view) == FTUN_OK);
    CHECK(ftun_runtime_prepare_with_frs(core, config, view, &candidate) == FTUN_OK);
    CHECK(ftun_frs_view_release(&view) == FTUN_OK && view == NULL);
    CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK); charged = usage.used_resources.memory_bytes;
    fail_unmap = true;
    CHECK(ftun_runtime_abort(core, &candidate) == FTUN_E_IO && candidate == NULL);
    CHECK(ftun_runtime_manager_get_info(core, &manager_info) == FTUN_OK && manager_info.has_cleanup);
    CHECK(memory(budget, charged) == 0 && config->document.reference_count == 2u);
    fail_unmap = false;
    CHECK(ftun_runtime_prepare(core, config, &candidate) == FTUN_E_INVALID && candidate == NULL);
    CHECK(memory(budget, baseline) == 0 && config->document.reference_count == 1u);
    CHECK(ftun_config_destroy(&config) == FTUN_OK);
  }
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK && memory(budget, 0u) == 0);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(unlink(path) == 0 && rmdir(directory) == 0);
  return 0;
}

/* 正常规则绑定后缺失标签，或文件格式错误，叠加映射清理失败。 */
static int construction(unsigned mode)
{
  uint8_t *fixture = NULL;
  size_t length, baseline, charged, released;
  char directory[] = "/tmp/ftun-construction-XXXXXX", path[128], text[512];
  int count;
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_config_t *config = NULL, *healthy = make_config();
  ftun_runtime_t *candidate = NULL, *active = NULL;
  ftun_runtime_manager_info_t info;
  ftun_budget_usage_t usage;
  ftun_frs_view_t *view = NULL;
  ftun_frs_view_info_t view_info;
  ftun_bytes_t bytes;
  ftun_status_t expected = mode == 0u ? FTUN_E_EOF : FTUN_E_PROTOCOL;
  CHECK(healthy != NULL && ftun_test_frs_fixture(&fixture, &length));
  CHECK(mkdtemp(directory) != NULL);
  CHECK(snprintf(path, sizeof(path), "%s/rules.frs", directory) > 0);
  if (mode != 0u) fixture[0] ^= 1u;
  CHECK(ftun_test_write_file(path, fixture, length));
  free(fixture);
  count = snprintf(text, sizeof(text), "{\"dns\":{\"enable\":false},"
    "\"frs\":{\"path\":\"%s\"},\"rules\":[\"FRS-IP,CN,DIRECT\","
    "\"FRS-IP,missing,REJECT\"]}", path);
  CHECK(count > 0 && (size_t)count < sizeof(text));
  CHECK(ftun_config_parse((ftun_bytes_t){(const uint8_t *)text, (size_t)count}, &config) == FTUN_OK);
  CHECK(ftun_config_compile(config, &config->plan) == FTUN_OK);
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 2u, &core) == FTUN_OK);
  CHECK(ftun_runtime_prepare(core, healthy, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
  baseline = usage.used_resources.memory_bytes;
  fail_unmap = true;
  failed_unmaps = 0u;
  released = released_maps;
  if (mode == 2u) {
    CHECK(ftun_frs_open(core, path, &view) == expected && view != NULL);
    CHECK(ftun_frs_view_get_info(view, &view_info) == FTUN_E_AGAIN);
    CHECK(ftun_frs_view_bytes(view, &bytes) == FTUN_E_AGAIN && bytes.data == NULL);
    CHECK(ftun_frs_view_retain(view) == FTUN_E_AGAIN);
  } else {
    CHECK(ftun_runtime_prepare(core, config, &candidate) == expected && candidate == NULL);
    CHECK(ftun_runtime_manager_get_info(core, &info) == FTUN_OK && info.has_cleanup);
    CHECK(!info.has_candidate && info.has_active);
    CHECK(config->document.reference_count == 2u);
    CHECK(ftun_runtime_active_acquire(core, &active) == FTUN_OK);
    CHECK(ftun_runtime_release(&active) == FTUN_OK && active == NULL);
  }
  CHECK(failed_unmaps >= 1u && released_maps == released);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes > baseline);
  charged = usage.used_resources.memory_bytes;
  if (mode == 2u) CHECK(ftun_frs_view_release(&view) == FTUN_E_IO && view != NULL);
  else {
    CHECK(ftun_runtime_prepare(core, healthy, &candidate) == FTUN_E_IO && candidate == NULL);
    CHECK(ftun_runtime_manager_destroy(&core) == FTUN_E_IO && core != NULL);
    /* 用户可释放自己的配置引用，失败候选仍持有它直到回收完成。 */
    CHECK(ftun_config_destroy(&config) == FTUN_OK && config == NULL);
  }
  CHECK(memory(budget, charged) == 0);
  fail_unmap = false;
  if (mode == 2u) {
    CHECK(ftun_frs_view_release(&view) == FTUN_OK && view == NULL);
    CHECK(memory(budget, baseline) == 0);
  }
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK && core == NULL);
  CHECK(released_maps == released + 1u && memory(budget, 0u) == 0);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(healthy->document.reference_count == 1u && ftun_config_destroy(&healthy) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(unlink(path) == 0 && rmdir(directory) == 0);
  return 0;
}

/* 逐个拒绝拥有者/布局/校验工作区分配，已映射时必须留下清理句柄。 */
static int construction_allocations(void)
{
  uint8_t *fixture = NULL;
  size_t length, index, early = 0u, retained = 0u;
  char directory[] = "/tmp/ftun-frs-allocate-XXXXXX", path[128];
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_budget_usage_t baseline, usage;
  CHECK(ftun_test_frs_fixture(&fixture, &length));
  CHECK(mkdtemp(directory) != NULL);
  CHECK(snprintf(path, sizeof(path), "%s/rules.frs", directory) > 0);
  CHECK(ftun_test_write_file(path, fixture, length));
  free(fixture);
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 2u, &core) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &baseline) == FTUN_OK);
  for (index = 1u; index < 32u; index++) {
    ftun_frs_view_t *view = NULL;
    ftun_status_t status;
    size_t released = released_maps;
    failed_unmaps = 0u;
    fail_unmap = true;
    allocation_at = index;
    allocation_calls = 0u;
    allocation_failed = false;
    status = ftun_frs_open(core, path, &view);
    allocation_at = 0u;
    if (allocation_failed) {
      CHECK(status == FTUN_E_LIMIT && released_maps == released);
      if (failed_unmaps != 0u) {
        size_t charged;
        retained++;
        CHECK(view != NULL && failed_unmaps == 1u);
        CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes > baseline.used_resources.memory_bytes);
        charged = usage.used_resources.memory_bytes;
        CHECK(ftun_frs_view_release(&view) == FTUN_E_IO && view != NULL);
        CHECK(memory(budget, charged) == 0);
      } else { early++; CHECK(view == NULL); }
    } else CHECK(status == FTUN_OK && view != NULL);
    fail_unmap = false;
    CHECK(ftun_frs_view_release(&view) == FTUN_OK && view == NULL);
    CHECK(released_maps == released + (failed_unmaps != 0u || !allocation_failed ? 1u : 0u));
    CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
    CHECK(usage.used_resources.memory_bytes == baseline.used_resources.memory_bytes && usage.metadata_bytes == baseline.metadata_bytes);
    CHECK(usage.used_resources.descriptors == baseline.used_resources.descriptors);
    if (!allocation_failed) break;
  }
  CHECK(index < 32u && early != 0u && retained != 0u);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK && memory(budget, 0u) == 0);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(unlink(path) == 0 && rmdir(directory) == 0);
  return 0;
}
#endif

int main(void)
{
  unsigned mode;
  for (mode = 0u; mode < 4u; mode++) CHECK(retirement(mode) == 0);
  /* 叶清理报告错误但已消费句柄时，重试同样不得重复销毁。 */
  consume_routes = true;
  for (mode = 0u; mode < 4u; mode++) CHECK(retirement(mode) == 0);
  consume_routes = false;
  CHECK(bounded_collection() == 0);
#if defined(FTUN_HAVE_MODULE_FRS)
  CHECK(detached() == 0);
  CHECK(mapping() == 0);
  for (mode = 0u; mode < 3u; mode++) CHECK(construction(mode) == 0);
  CHECK(construction_allocations() == 0);
#endif
  return 0;
}
