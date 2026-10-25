#define _POSIX_C_SOURCE 200809L
#include "config/compile.h"
#include "config/parser.h"
#include "core/budget.h"
#include "proxy/runtime_internal.h"
#include "proxy/frs/frs.h"
#include "frs_fixture.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "runtime detached failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

static struct { void *pointer; size_t bytes; } heap[128];
static size_t live_bytes, allocation_calls, calloc_calls, fail_at;
static bool tracking, tracker_failed, hold_routes;
/* 跟踪阶段只在本夹具的单线程路径运行，跳过libc内部的嵌套分配。 */
static unsigned int allocation_depth;
void *__real_malloc(size_t bytes);
void *__real_calloc(size_t count, size_t bytes);
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
  if (tracking) calloc_calls++;
  if (fail()) return NULL;
  allocation_depth++;
  value = __real_calloc(count, bytes);
  allocation_depth--;
  record(value, count * bytes); return value;
}
void __wrap_free(void *value)
{
  size_t i;
  if (allocation_depth != 0u) { __real_free(value); return; }
  for (i = 0u; i < sizeof(heap) / sizeof(heap[0]); i++) {
    if (heap[i].pointer == value && value != NULL) {
      live_bytes -= heap[i].bytes; heap[i].pointer = NULL; heap[i].bytes = 0u; break;
    }
  }
  __real_free(value);
}
ftun_status_t __real_ftun_route_table_destroy(ftun_route_table_t **table);
ftun_status_t __wrap_ftun_route_table_destroy(ftun_route_table_t **table)
{
  if (hold_routes && table != NULL && *table != NULL) return FTUN_E_AGAIN;
  return __real_ftun_route_table_destroy(table);
}

static const char text[] = "{\"dns\":{\"enable\":false},"
  "\"outbounds\":[{\"type\":\"select\",\"name\":\"selector\",\"outbounds\":[\"DIRECT\"],\"default\":\"DIRECT\"}],"
  "\"rules\":[\"DOMAIN,example.org,selector\",\"MATCH,DIRECT\"]}";
static int make_config(ftun_budget_t *budget, const char *json, ftun_config_t **out)
{
  CHECK(ftun_config_parse_budget(budget,
    (ftun_bytes_t){(const uint8_t *)json, strlen(json)}, out) == FTUN_OK);
  CHECK(ftun_config_compile(*out, &(*out)->plan) == FTUN_OK);
  return 0;
}
static int memory(ftun_budget_t *budget, size_t expected)
{
  ftun_budget_usage_t usage;
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == expected);
  return 0;
}
static int block_memory(ftun_budget_t *budget, ftun_reservation_t **out)
{
  ftun_budget_usage_t usage;
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.normal_available > 128u);
  CHECK(ftun_budget_reserve(budget, usage.normal_available - 128u, out) == FTUN_OK);
  return 0;
}

static int construction(void)
{
  ftun_budget_t *budget = NULL;
  ftun_config_t *config = NULL;
  ftun_runtime_t *prepared = NULL;
  ftun_reservation_t *blocker = NULL;
  ftun_budget_usage_t before, after;
  size_t charge, attempts, i;
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(make_config(budget, text, &config) == 0);
  CHECK(ftun_runtime_accounted_bytes(config, &charge) == FTUN_OK);
  charge -= config->owned_bytes + config->plan->owned_bytes;
  CHECK(ftun_budget_get_usage(budget, &before) == FTUN_OK);
  tracking = true; allocation_calls = 0u;
  CHECK(ftun_runtime_prepare_detached(config, NULL, &prepared) == FTUN_OK);
  attempts = allocation_calls;
  CHECK(prepared->reservation != NULL && config->reference_count == 1u);
  CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK && after.used == before.used + charge);
  /* 此样例只使用拥有字符串的DOMAIN与MATCH规则，按实际申请核对。 */
  CHECK(live_bytes == charge + after.metadata_bytes - before.metadata_bytes && !tracker_failed);
  hold_routes = true;
  CHECK(ftun_runtime_prepared_release(&prepared) == FTUN_E_AGAIN && prepared != NULL);
  CHECK(memory(budget, after.used) == 0 && prepared->reservation != NULL);
  hold_routes = false;
  CHECK(ftun_runtime_prepared_release(&prepared) == FTUN_OK && prepared == NULL);
  CHECK(live_bytes == 0u && memory(budget, before.used) == 0);
  for (i = 1u; i <= attempts; i++) {
    fail_at = i; allocation_calls = 0u;
    CHECK(ftun_runtime_prepare_detached(config, NULL, &prepared) == FTUN_E_LIMIT && prepared == NULL);
    CHECK(live_bytes == 0u && !tracker_failed && memory(budget, before.used) == 0);
    CHECK(config->reference_count == 1u);
  }
  fail_at = 0u; tracking = false;
  CHECK(block_memory(budget, &blocker) == 0);
  tracking = true; calloc_calls = 0u;
  CHECK(ftun_runtime_prepare_detached(config, NULL, &prepared) == FTUN_E_LIMIT && prepared == NULL);
  CHECK(calloc_calls == 0u && live_bytes == 0u);
  tracking = false;
  CHECK(ftun_reservation_release(&blocker) == FTUN_OK);
  CHECK(ftun_config_destroy(&config) == FTUN_OK && memory(budget, 0u) == 0);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int adoption(void)
{
  ftun_budget_t *budget = NULL, *child = NULL, *foreign = NULL;
  ftun_config_t *config = NULL;
  ftun_core_t *core = NULL, *other = NULL;
  ftun_runtime_t *first = NULL, *second = NULL, *candidate = NULL;
  ftun_reservation_t *blocker = NULL, *first_reservation;
  ftun_budget_usage_t before, after, child_before, child_after;
  size_t charge;
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_budget_create(budget, 1024u * 1024u, 0u, &child) == FTUN_OK);
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &foreign) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 2u, &core) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(foreign, 2u, &other) == FTUN_OK);
  CHECK(make_config(child, text, &config) == 0);
  CHECK(ftun_budget_get_usage(budget, &before) == FTUN_OK);
  CHECK(ftun_runtime_accounted_bytes(config, &charge) == FTUN_OK);
  charge -= config->owned_bytes + config->plan->owned_bytes;
  CHECK(ftun_runtime_prepare_detached(config, NULL, &first) == FTUN_OK);
  CHECK(ftun_runtime_prepare_detached(config, NULL, &second) == FTUN_OK);
  CHECK(memory(budget, before.used + 2u * charge) == 0 && config->reference_count == 1u);
  first_reservation = first->reservation;
  CHECK(ftun_runtime_attach_prepared(other, &first, &candidate) == FTUN_E_INVALID);
  CHECK(first != NULL && candidate == NULL && first->reservation == first_reservation);
  CHECK(block_memory(budget, &blocker) == 0);
  CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK);
  CHECK(ftun_budget_get_usage(child, &child_before) == FTUN_OK);
  /* 同根父子预算复用已有句柄；没有新增额度的空间也能附着。 */
  CHECK(ftun_runtime_attach_prepared(core, &first, &candidate) == FTUN_OK);
  CHECK(first == NULL && candidate->reservation == first_reservation);
  CHECK(config->reference_count == 2u && memory(budget, after.used) == 0);
  CHECK(ftun_budget_get_usage(child, &child_after) == FTUN_OK && child_after.used == child_before.used);
  CHECK(ftun_runtime_attach_prepared(core, &second, &first) == FTUN_E_AGAIN);
  CHECK(first == NULL && second != NULL && memory(budget, after.used) == 0);
  CHECK(ftun_runtime_abort(core, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_attach_prepared(core, &second, &candidate) == FTUN_OK && second == NULL);
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_manager_clear(core) == FTUN_OK);
  CHECK(ftun_reservation_release(&blocker) == FTUN_OK);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK && memory(budget, 0u) == 0);
  CHECK(ftun_runtime_manager_destroy(&other) == FTUN_OK);
  CHECK(ftun_budget_destroy(&child) == FTUN_OK && ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(ftun_budget_destroy(&foreign) == FTUN_OK);
  return 0;
}

static int frs_admission(void)
{
  static const char json[] = "{\"dns\":{\"enable\":false},\"rules\":[\"FRS-IP,CN,DIRECT\",\"MATCH,REJECT\"]}";
  uint8_t *fixture = NULL;
  size_t length;
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_config_t *config = NULL;
  ftun_runtime_t *prepared = NULL, *candidate = NULL;
  ftun_frs_view_t *view = NULL;
  ftun_reservation_t *blocker = NULL, *reservation;
  ftun_budget_usage_t before, after;
  CHECK(ftun_test_frs_fixture(&fixture, &length));
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 2u, &core) == FTUN_OK);
  CHECK(make_config(budget, json, &config) == 0);
  CHECK(ftun_budget_get_usage(budget, &before) == FTUN_OK);
  CHECK(ftun_frs_open_bytes((ftun_bytes_t){fixture, length}, &view) == FTUN_OK);
  free(fixture);
  CHECK(ftun_runtime_prepare_detached_frs(config, view, &prepared) == FTUN_OK);
  view = NULL;
  reservation = prepared->reservation;
  CHECK(reservation != NULL);
  CHECK(block_memory(budget, &blocker) == 0);
  CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK);
  CHECK(ftun_runtime_attach_prepared(core, &prepared, &candidate) == FTUN_E_LIMIT);
  CHECK(prepared != NULL && candidate == NULL && prepared->reservation == reservation);
  CHECK(config->reference_count == 1u && memory(budget, after.used) == 0);
  CHECK(ftun_reservation_release(&blocker) == FTUN_OK);
  CHECK(ftun_runtime_attach_prepared(core, &prepared, &candidate) == FTUN_OK && prepared == NULL);
  CHECK(candidate->reservation == reservation && config->reference_count == 2u);
  CHECK(ftun_runtime_abort(core, &candidate) == FTUN_OK && memory(budget, before.used) == 0);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK && memory(budget, 0u) == 0);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(void)
{
  CHECK(construction() == 0);
  CHECK(adoption() == 0);
  CHECK(frs_admission() == 0);
  return 0;
}
