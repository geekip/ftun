#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "core/budget.h"
#include "core/runtime.h"
#include "core/worker.h"
#include "dns/fakeip.h"

#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "fakeip contract failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  unsigned int calls;
  ftun_status_t status;
} completion_t;

static void completed(ftun_operation_t *operation, ftun_error_t error,
                      ftun_fakeip_store_operation_t kind,
                      uint64_t sequence, uint32_t reserved_end, void *user)
{
  completion_t *completion = (completion_t *)user;
  (void)operation;
  (void)kind;
  (void)sequence;
  (void)reserved_end;
  completion->calls++;
  completion->status = error.status;
}

static int poll_until(ftun_worker_t *worker, completion_t *completion,
                      unsigned int calls)
{
  unsigned int attempt;
  for (attempt = 0u; attempt < 100000u && completion->calls < calls; attempt++) {
    size_t callbacks = 0u;
    if (ftun_worker_poll(worker, 8u, &callbacks) != FTUN_OK) return 0;
    if (callbacks == 0u) sched_yield();
  }
  return completion->calls == calls;
}

static int remove_store(const char *directory)
{
  const char *names[] = {"identity", "reservations", "mappings", "lock"};
  char path[256];
  size_t index;
  for (index = 0u; index < sizeof(names) / sizeof(names[0]); index++) {
    int length = snprintf(path, sizeof(path), "%s/%s", directory, names[index]);
    if (length <= 0 || (size_t)length >= sizeof(path) || unlink(path) != 0) return 0;
  }
  return rmdir(directory) == 0;
}

static int test_nonpersistent_identity(void)
{
  ftun_budget_t *budget = NULL;
  ftun_fakeip_service_t *service = NULL;
  ftun_fakeip_handle_t *first = NULL;
  ftun_fakeip_handle_t *same = NULL;
  ftun_fakeip_handle_t *reverse = NULL;
  ftun_fakeip_handle_t *second = NULL;
  ftun_fakeip_service_options_t options;
  ftun_fakeip_service_info_t info;
  ftun_string_t domain;
  uint32_t address;
  memset(&options, 0, sizeof(options));
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  options.budget = budget;
  options.first_address = UINT32_C(0xc6120001);
  options.end_address_exclusive = UINT32_C(0xc6120003);
  options.max_entries = 2u;
  CHECK(ftun_fakeip_service_create(&options, &service) == FTUN_OK);
  CHECK(ftun_fakeip_service_acquire(service,
    (ftun_string_t){"Example.COM.", 12u}, &first) == FTUN_OK);
  CHECK(ftun_fakeip_handle_get(first, &address, &domain) == FTUN_OK &&
        address == UINT32_C(0xc6120001) && domain.length == 11u &&
        memcmp(domain.data, "example.com", 11u) == 0);
  CHECK(ftun_fakeip_service_acquire(service,
    (ftun_string_t){"example.com", 11u}, &same) == FTUN_OK);
  CHECK(ftun_fakeip_reverse(service, address, &reverse) == FTUN_OK);
  CHECK(ftun_fakeip_service_destroy(&service) == FTUN_E_AGAIN);
  CHECK(ftun_fakeip_handle_release(&first) == FTUN_OK);
  CHECK(ftun_fakeip_handle_release(&same) == FTUN_OK);
  CHECK(ftun_fakeip_handle_release(&reverse) == FTUN_OK);
  CHECK(ftun_fakeip_service_acquire(service,
    (ftun_string_t){"second.test", 11u}, &second) == FTUN_OK);
  CHECK(ftun_fakeip_handle_get(second, &address, &domain) == FTUN_OK &&
        address == UINT32_C(0xc6120002));
  CHECK(ftun_fakeip_handle_release(&second) == FTUN_OK);
  CHECK(ftun_fakeip_service_acquire(service,
    (ftun_string_t){"third.test", 10u}, &second) == FTUN_E_LIMIT);
  CHECK(ftun_fakeip_service_get_info(service, &info) == FTUN_OK &&
        info.entries == 2u && info.references == 0u && !info.persistent);
  CHECK(ftun_fakeip_service_destroy(&service) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int test_persistent_boundary_and_core(void)
{
  char directory[] = "/tmp/ftun-fakeip-service.XXXXXX";
  ftun_fakeip_store_identity_t identity;
  ftun_fakeip_store_options_t store_options;
  ftun_fakeip_service_options_t service_options;
  ftun_fakeip_snapshot_t empty;
  ftun_fakeip_snapshot_t *snapshot = NULL;
  ftun_budget_t *budget = NULL;
  ftun_worker_t *worker = NULL;
  ftun_fakeip_store_t *store = NULL;
  ftun_fakeip_service_t *service = NULL;
  ftun_fakeip_handle_t *handle = NULL;
  ftun_operation_t *operation = NULL;
  ftun_core_t *core = NULL;
  completion_t completion;
  ftun_string_t domain;
  uint32_t address;
  size_t callbacks;
  memset(&identity, 0, sizeof(identity));
  memset(&store_options, 0, sizeof(store_options));
  memset(&service_options, 0, sizeof(service_options));
  memset(&empty, 0, sizeof(empty));
  memset(&completion, 0, sizeof(completion));
  identity.uuid[0] = 7u;
  identity.first_address = 100u;
  identity.end_address_exclusive = 110u;
  memcpy(empty.uuid, identity.uuid, FTUN_FAKEIP_UUID_BYTES);
  CHECK(mkdtemp(directory) != NULL && rmdir(directory) == 0);
  CHECK(ftun_fakeip_store_initialize(directory, &identity) == FTUN_OK);
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_worker_create(budget, 4u, &worker) == FTUN_OK);
  store_options.directory = directory;
  store_options.budget = budget;
  store_options.worker = worker;
  store_options.completion = completed;
  store_options.user = &completion;
  CHECK(ftun_fakeip_store_open(&store_options, &store) == FTUN_OK);
  service_options.budget = budget;
  service_options.store = store;
  service_options.snapshot = &empty;
  service_options.max_entries = 8u;
  CHECK(ftun_fakeip_service_create(&service_options, &service) == FTUN_OK);
  CHECK(ftun_fakeip_service_acquire(service,
    (ftun_string_t){"one.test", 8u}, &handle) == FTUN_E_AGAIN);
  CHECK(ftun_fakeip_store_reserve(store, 104u, &operation) == FTUN_OK);
  CHECK(poll_until(worker, &completion, 1u) && completion.status == FTUN_OK);
  CHECK(ftun_fakeip_service_acquire(service,
    (ftun_string_t){"one.test", 8u}, &handle) == FTUN_OK);
  CHECK(ftun_fakeip_handle_get(handle, &address, &domain) == FTUN_OK &&
        address == 100u);
  CHECK(ftun_runtime_manager_create(budget, 1u, &core) == FTUN_OK);
  CHECK(ftun_runtime_manager_set_fakeip(core, service) == FTUN_OK);
  CHECK(ftun_fakeip_handle_release(&handle) == FTUN_OK);
  CHECK(ftun_fakeip_acquire(core, (ftun_string_t){"one.test", 8u},
                            &handle) == FTUN_OK);
  CHECK(ftun_fakeip_handle_release(&handle) == FTUN_OK);
  CHECK(ftun_fakeip_service_snapshot(service, &snapshot) == FTUN_OK &&
        snapshot->mapping_count == 1u && snapshot->sequence == 1u);
  CHECK(ftun_fakeip_snapshot_destroy(&snapshot) == FTUN_OK);
  CHECK(ftun_runtime_manager_set_fakeip(core, NULL) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_fakeip_service_destroy(&service) == FTUN_OK);
  CHECK(ftun_fakeip_store_destroy(&store) == FTUN_OK);
  CHECK(ftun_worker_stop(worker) == FTUN_OK);
  CHECK(ftun_worker_join(worker) == FTUN_OK);
  CHECK(ftun_worker_poll(worker, 8u, &callbacks) == FTUN_OK);
  CHECK(ftun_worker_destroy(&worker) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(remove_store(directory));
  return 0;
}

int main(void)
{
  CHECK(test_nonpersistent_identity() == 0);
  CHECK(test_persistent_boundary_and_core() == 0);
  return 0;
}
