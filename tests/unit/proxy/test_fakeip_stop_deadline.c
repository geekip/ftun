#define _GNU_SOURCE 1
#include "proxy/engine_internal.h"
#include "core/limits.h"
#include "core/worker.h"
#include "platform/atomic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "FakeIP stop deadline failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

enum { COMPLETE_OK, COMPLETE_IO, COMPLETE_TIMEOUT, PENDING };
static int scenario;
static ftun_atomic_bool_t active;
static bool expired;
static unsigned int cancellations;
ftun_status_t __real_ftun_worker_poll(ftun_worker_t *, size_t, size_t *);
ftun_status_t __real_ftun_operation_cancel(ftun_operation_t *);
ftun_status_t __real_ftun_monotonic_now(uint64_t *);
ftun_status_t __real_ftun_file_write_atomic_budget(ftun_budget_t *, const char *,
  ftun_bytes_t, unsigned int, ftun_file_stage_hook_fn, void *);

ftun_status_t __wrap_ftun_monotonic_now(uint64_t *out)
{
  if (!ftun_atomic_load(&active)) return __real_ftun_monotonic_now(out);
  *out = expired ? 10u : 9u;
  return FTUN_OK;
}
ftun_status_t __wrap_ftun_worker_poll(ftun_worker_t *worker, size_t maximum, size_t *callbacks)
{
  ftun_status_t status;
  if (ftun_atomic_load(&active) && scenario == PENDING) {
    *callbacks = 0u;
    expired = true;
    return FTUN_OK;
  }
  status = __real_ftun_worker_poll(worker, maximum, callbacks);
  /* 回调已由真实队列交付并回收句柄，再推进同一轮的截止时间。 */
  if (ftun_atomic_load(&active) && *callbacks != 0u) expired = true;
  return status;
}
ftun_status_t __wrap_ftun_operation_cancel(ftun_operation_t *operation)
{
  cancellations++;
  return __real_ftun_operation_cancel(operation);
}
ftun_status_t __wrap_ftun_file_write_atomic_budget(ftun_budget_t *budget, const char *path,
  ftun_bytes_t contents, unsigned int mode, ftun_file_stage_hook_fn hook, void *user)
{
  if (ftun_atomic_load(&active) && scenario == COMPLETE_IO) return FTUN_E_IO;
  if (ftun_atomic_load(&active) && scenario == COMPLETE_TIMEOUT) return FTUN_E_TIMEOUT;
  return __real_ftun_file_write_atomic_budget(budget, path, contents, mode, hook, user);
}
static int run_case(int current)
{
  char directory[] = "/tmp/ftun-stop-deadline.XXXXXX", path[256];
  static const char *const files[] = {"identity", "reservations", "mappings", "lock"};
  ftun_fakeip_store_identity_t identity = {0};
  ftun_fakeip_store_options_t store_options = {0};
  ftun_fakeip_service_options_t service_options = {0};
  ftun_fakeip_snapshot_t *snapshot = NULL;
  ftun_proxy_runtime_t engine = {0};
  ftun_budget_t *budget = NULL;
  ftun_budget_usage_t usage;
  ftun_status_t status, expected;
  size_t callbacks, index;
  ftun_atomic_store(&active, false);
  expired = false;
  scenario = current;
  cancellations = 0u;
  identity.uuid[0] = 1u;
  identity.first_address = UINT32_C(0xc6120001);
  identity.end_address_exclusive = UINT32_C(0xc6120010);
  CHECK(mkdtemp(directory) != NULL && rmdir(directory) == 0);
  CHECK(ftun_fakeip_store_initialize(directory, &identity) == FTUN_OK);
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_worker_create(budget, 2u, &engine.fakeip_worker) == FTUN_OK);
  store_options.directory = directory;
  store_options.budget = budget;
  store_options.worker = engine.fakeip_worker;
  store_options.completion = ftun_proxy_runtime_fakeip_store_completed;
  store_options.user = &engine;
  CHECK(ftun_fakeip_store_open(&store_options, &engine.fakeip_store) == FTUN_OK);
  CHECK(ftun_fakeip_snapshot_load(engine.fakeip_store, 16u, &snapshot) == FTUN_OK);
  service_options.budget = budget;
  service_options.store = engine.fakeip_store;
  service_options.snapshot = snapshot;
  service_options.max_entries = 16u;
  CHECK(ftun_fakeip_service_create(&service_options, &engine.fakeip) == FTUN_OK);
  CHECK(ftun_fakeip_snapshot_destroy(&snapshot) == FTUN_OK);
  printf("FakeIP stop deadline scenario=%d\n", scenario);
  fflush(stdout);
  ftun_atomic_store(&active, true);
  status = ftun_proxy_runtime_stop_until(&engine, 10u);
  ftun_atomic_store(&active, false);
  expected = scenario == COMPLETE_OK ? FTUN_OK : scenario == COMPLETE_IO ? FTUN_E_IO : FTUN_E_TIMEOUT;
  CHECK(status == expected && engine.stopped);
  CHECK(cancellations == (scenario == PENDING ? 1u : 0u));
  CHECK(engine.fakeip_store_completions == (scenario == PENDING ? 0u : 1u));
  CHECK(ftun_worker_stop(engine.fakeip_worker) == FTUN_OK);
  CHECK(ftun_worker_join(engine.fakeip_worker) == FTUN_OK);
  CHECK(ftun_worker_poll(engine.fakeip_worker, 16u, &callbacks) == FTUN_OK);
  CHECK(engine.fakeip_store_completions == 1u);
  CHECK(ftun_fakeip_service_destroy(&engine.fakeip) == FTUN_OK);
  CHECK(ftun_fakeip_store_destroy(&engine.fakeip_store) == FTUN_OK);
  CHECK(ftun_worker_destroy(&engine.fakeip_worker) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  for (index = 0u; index < sizeof(files) / sizeof(files[0]); index++) {
    CHECK(snprintf(path, sizeof(path), "%s/%s", directory, files[index]) > 0);
    CHECK(unlink(path) == 0);
  }
  CHECK(rmdir(directory) == 0);
  return 0;
}
int main(void)
{
  int current;
  for (current = COMPLETE_OK; current <= PENDING; current++) CHECK(run_case(current) == 0);
  return 0;
}
