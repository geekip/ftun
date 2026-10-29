#define _POSIX_C_SOURCE 200809L
#include <sys/types.h>
#include "app/config/compile.h"
#include "app/config/model.h"
#include "app/config/parser.h"
#include "core/limits.h"
#include "proxy/runtime_state.h"
#include "proxy/route/router.h"
#if defined(FTUN_HAVE_MODULE_FRS)
#include "proxy/frs/frs.h"
#include "frs_fixture.h"
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "route memory failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

static struct { void *pointer; size_t bytes; } heap[128];
static size_t live_bytes, allocation_calls, calloc_calls, fail_at;
static bool tracking, tracker_failed;
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

static const char *const rules[] = {
  "SRC-IP-CIDR,192.168.1.0/24,DIRECT", "IP-CIDR,10.0.0.0/8,DIRECT",
  "DOMAIN,Example.org,DIRECT", "DOMAIN-SUFFIX,example.net,DIRECT",
  "DOMAIN-KEYWORD,example,DIRECT", "DST-PORT,443,DIRECT",
  "NETWORK,tcp,DIRECT", "NETWORK,udp,DIRECT", "MATCH,DIRECT",
#if defined(FTUN_HAVE_MODULE_FRS)
  "FRS-IP,CN,DIRECT", "FRS-DOMAIN,CN,DIRECT"
#endif
};

static ftun_status_t bind_set(uint16_t kind, ftun_string_t label,
  ftun_frs_set_t **out, void *user)
{
#if defined(FTUN_HAVE_MODULE_FRS)
  return ftun_frs_bind((ftun_frs_view_t *)user,
    (ftun_frs_set_kind_t)kind, label, out);
#else
  (void)kind; (void)label; (void)out; (void)user;
  return FTUN_E_UNSUPPORTED;
#endif
}

static int rule_allocations(ftun_frs_view_t *view)
{
  ftun_rule_t *rule = NULL;
  ftun_route_table_t *table = NULL;
  size_t i, j, bytes, attempts;
  tracking = true;
  for (i = 0u; i < sizeof(rules) / sizeof(rules[0]); i++) {
    CHECK(ftun_rule_accounted_bytes(rules[i], &bytes) == FTUN_OK);
    allocation_calls = 0u;
    CHECK(ftun_rule_compile_with_frs(rules[i], NULL, NULL, bind_set, view, &rule) == FTUN_OK);
    attempts = allocation_calls;
    CHECK(live_bytes == bytes && !tracker_failed);
    CHECK(ftun_rule_destroy(&rule) == FTUN_OK && live_bytes == 0u);
    for (j = 1u; j <= attempts; j++) {
      fail_at = j; allocation_calls = 0u;
      CHECK(ftun_rule_compile_with_frs(rules[i], NULL, NULL, bind_set, view, &rule) != FTUN_OK);
      CHECK(rule == NULL && live_bytes == 0u && !tracker_failed);
    }
    fail_at = 0u;
  }
  CHECK(ftun_route_table_accounted_bytes(rules, sizeof(rules) / sizeof(rules[0]), &bytes) == FTUN_OK);
  allocation_calls = 0u;
  CHECK(ftun_route_table_create_with_frs(0u, rules, sizeof(rules) / sizeof(rules[0]),
    NULL, NULL, bind_set, view, &table) == FTUN_OK);
  attempts = allocation_calls;
  CHECK(live_bytes == bytes && !tracker_failed);
  CHECK(ftun_route_table_destroy(&table) == FTUN_OK && live_bytes == 0u);
  for (j = 1u; j <= attempts; j++) {
    fail_at = j; allocation_calls = 0u;
    CHECK(ftun_route_table_create_with_frs(0u, rules, sizeof(rules) / sizeof(rules[0]),
      NULL, NULL, bind_set, view, &table) != FTUN_OK);
    CHECK(table == NULL && live_bytes == 0u && !tracker_failed);
  }
  fail_at = 0u; tracking = false;
  CHECK(ftun_rule_accounted_bytes("MATCH", &bytes) == FTUN_E_INVALID && bytes == 0u);
  CHECK(ftun_rule_accounted_bytes("MATCH,,DIRECT", &bytes) == FTUN_E_INVALID);
  CHECK(ftun_rule_accounted_bytes("DOMAIN,,DIRECT", &bytes) == FTUN_E_INVALID);
  CHECK(ftun_rule_accounted_bytes("UNKNOWN,x,DIRECT", &bytes) == FTUN_E_UNSUPPORTED);
  return 0;
}

#if defined(FTUN_HAVE_MODULE_FRS)
static int usage(ftun_budget_t *budget, size_t memory, size_t descriptors)
{
  ftun_budget_usage_t current;
  CHECK(ftun_budget_get_usage(budget, &current) == FTUN_OK);
  CHECK(current.used == memory && current.used_resources.descriptors == descriptors);
  return 0;
}

static int view_allocations(ftun_bytes_t bytes)
{
  ftun_budget_t *budget = NULL, *child = NULL, *foreign = NULL;
  ftun_frs_view_t *view = NULL;
  ftun_budget_usage_t before, after;
  size_t attempts, i;
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_budget_create(budget, 1024u * 1024u, 0u, &child) == FTUN_OK);
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &foreign) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &before) == FTUN_OK);
  tracking = true; allocation_calls = 0u;
  CHECK(ftun_frs_open_bytes_budget(child, bytes, &view) == FTUN_OK);
  attempts = allocation_calls;
  CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK);
  CHECK(live_bytes == after.used + after.metadata_bytes - before.metadata_bytes && !tracker_failed);
  CHECK(ftun_frs_view_bind_budget(view, budget) == FTUN_OK);
  CHECK(ftun_frs_view_bind_budget(view, child) == FTUN_OK);
  CHECK(usage(budget, after.used, 0u) == 0 && usage(child, after.used, 0u) == 0);
  CHECK(ftun_frs_view_bind_budget(view, foreign) == FTUN_E_INVALID && usage(foreign, 0u, 0u) == 0);
  CHECK(ftun_frs_view_release(&view) == FTUN_OK && live_bytes == 0u && usage(budget, 0u, 0u) == 0);
  for (i = 1u; i <= attempts; i++) {
    fail_at = i; allocation_calls = 0u;
    CHECK(ftun_frs_open_bytes_budget(child, bytes, &view) != FTUN_OK);
    CHECK(view == NULL && live_bytes == 0u && !tracker_failed && usage(budget, 0u, 0u) == 0);
  }
  fail_at = 0u; tracking = false;
  /* 独立视图后绑定同样只收一次实际保留容量。 */
  CHECK(ftun_frs_open_bytes(bytes, &view) == FTUN_OK);
  CHECK(ftun_frs_view_bind_budget(view, child) == FTUN_OK && usage(budget, after.used, 0u) == 0);
  CHECK(ftun_frs_view_bind_budget(view, budget) == FTUN_OK && usage(budget, after.used, 0u) == 0);
  CHECK(ftun_frs_view_release(&view) == FTUN_OK);
  CHECK(ftun_budget_destroy(&child) == FTUN_OK && ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(ftun_budget_destroy(&foreign) == FTUN_OK);
  return 0;
}

static ftun_budget_t *fd_budget;
static bool watch_fd, fd_charged, fail_read;
static size_t open_calls;
static int last_fd;
int __real_open(const char *path, int flags, ...);
int __wrap_open(const char *path, int flags, ...)
{
  int fd;
  mode_t mode = 0;
  if ((flags & O_CREAT) != 0) {
    va_list arguments;
    va_start(arguments, flags); mode = (mode_t)va_arg(arguments, int); va_end(arguments);
  }
  if (watch_fd) {
    ftun_budget_usage_t current;
    open_calls++;
    if (ftun_budget_get_usage(fd_budget, &current) != FTUN_OK ||
        current.used_resources.descriptors != 1u) fd_charged = false;
  }
  fd = __real_open(path, flags, mode);
  if (watch_fd) last_fd = fd;
  return fd;
}
ssize_t __real_read(int fd, void *data, size_t bytes);
ssize_t __wrap_read(int fd, void *data, size_t bytes)
{
  if (watch_fd && fail_read && fd == last_fd) { errno = EIO; return -1; }
  return __real_read(fd, data, bytes);
}

static int file_admission(ftun_bytes_t bytes)
{
  char path[] = "/tmp/ftun-frs-memory.XXXXXX";
  int fd = mkstemp(path);
  ftun_budget_options_t options = {{1024u * 1024u, 0u, 0u}, {0}, {0}};
  ftun_core_t *core = NULL;
  ftun_frs_view_t *view = NULL;
  ftun_budget_usage_t before;
  ftun_reservation_t blocker = (ftun_reservation_t){0};
  unsigned int limit;
  CHECK(fd >= 0 && close(fd) == 0);
  CHECK(ftun_test_write_file(path, bytes.data, bytes.length));
  for (limit = 0u; limit < 2u; limit++) {
    options.limit.descriptors = limit;
    CHECK(ftun_budget_create_resources(NULL, &options, &fd_budget) == FTUN_OK);
    CHECK(ftun_runtime_manager_create(fd_budget, 2u, &core) == FTUN_OK);
    CHECK(ftun_budget_get_usage(fd_budget, &before) == FTUN_OK);
    watch_fd = true; fd_charged = true; open_calls = 0u;
    if (limit == 0u) {
      CHECK(ftun_frs_open(core, path, &view) == FTUN_E_LIMIT && view == NULL && open_calls == 0u);
    } else {
      CHECK(ftun_frs_open(core, path, &view) == FTUN_OK && fd_charged && open_calls == 1u);
      CHECK(fcntl(last_fd, F_GETFD) == -1 && errno == EBADF);
      CHECK(ftun_frs_view_release(&view) == FTUN_OK && usage(fd_budget, before.used, 0u) == 0);
      CHECK(ftun_frs_open_mode(core, path, FTUN_FRS_OPEN_READ, &view) == FTUN_OK);
      CHECK(ftun_frs_view_release(&view) == FTUN_OK && usage(fd_budget, before.used, 0u) == 0);
      fail_read = true;
      CHECK(ftun_frs_open_mode(core, path, FTUN_FRS_OPEN_READ, &view) == FTUN_E_IO && view == NULL);
      CHECK(fcntl(last_fd, F_GETFD) == -1 && errno == EBADF);
      CHECK(usage(fd_budget, before.used, 0u) == 0);
      fail_read = false;
      CHECK(ftun_budget_reserve(fd_budget, before.normal_available - 256u, &blocker) == FTUN_OK);
      CHECK(ftun_frs_open(core, path, &view) == FTUN_E_LIMIT && view == NULL);
      CHECK(ftun_reservation_release(&blocker) == FTUN_OK && usage(fd_budget, before.used, 0u) == 0);
      CHECK(unlink(path) == 0);
      CHECK(ftun_frs_open(core, path, &view) == FTUN_E_EOF && view == NULL && fd_charged);
      CHECK(usage(fd_budget, before.used, 0u) == 0);
    }
    watch_fd = false;
    CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK && usage(fd_budget, 0u, 0u) == 0);
    CHECK(ftun_budget_destroy(&fd_budget) == FTUN_OK);
  }
  return 0;
}

static int prebound_runtime(ftun_bytes_t bytes)
{
  const char json[] = "{\"dns\":{\"enable\":false},\"rules\":[\"FRS-IP,CN,DIRECT\",\"FRS-DOMAIN,CN,DIRECT\",\"MATCH,REJECT\"]}";
  ftun_budget_t *budget = NULL;
  ftun_config_t *config = NULL;
  ftun_core_t *core = NULL;
  ftun_frs_view_t *view = NULL;
  ftun_runtime_t *prepared = NULL, *candidate = NULL;
  ftun_reservation_t blocker = (ftun_reservation_t){0};
  ftun_budget_usage_t before, after;
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 2u, &core) == FTUN_OK);
  CHECK(ftun_config_parse_budget(budget, (ftun_bytes_t){(const uint8_t *)json, sizeof(json) - 1u}, &config) == FTUN_OK);
  CHECK(ftun_config_compile(config, &config->plan) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &before) == FTUN_OK);
  CHECK(ftun_frs_open_bytes_budget(budget, bytes, &view) == FTUN_OK);
  CHECK(ftun_runtime_prepare_detached_frs(config, view, &prepared) == FTUN_OK);
  view = NULL;
  CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK);
  CHECK(ftun_budget_reserve(budget, after.normal_available - 128u, &blocker) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK);
  CHECK(ftun_runtime_attach_prepared(core, &prepared, &candidate) == FTUN_OK && prepared == NULL);
  CHECK(usage(budget, after.used, 0u) == 0);
  CHECK(ftun_reservation_release(&blocker) == FTUN_OK);
  CHECK(ftun_runtime_abort(core, &candidate) == FTUN_OK && usage(budget, before.used, 0u) == 0);
  CHECK(ftun_config_destroy(&config) == FTUN_OK && ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(usage(budget, 0u, 0u) == 0 && ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}
#endif

int main(void)
{
  ftun_frs_view_t *view = NULL;
#if defined(FTUN_HAVE_MODULE_FRS)
  uint8_t *fixture = NULL;
  size_t length;
  CHECK(ftun_test_frs_fixture(&fixture, &length));
  CHECK(ftun_frs_open_bytes((ftun_bytes_t){fixture, length}, &view) == FTUN_OK);
#endif
  CHECK(rule_allocations(view) == 0);
#if defined(FTUN_HAVE_MODULE_FRS)
  CHECK(ftun_frs_view_release(&view) == FTUN_OK);
  CHECK(view_allocations((ftun_bytes_t){fixture, length}) == 0);
  CHECK(file_admission((ftun_bytes_t){fixture, length}) == 0);
  CHECK(prebound_runtime((ftun_bytes_t){fixture, length}) == 0);
  free(fixture);
#endif
  return 0;
}
