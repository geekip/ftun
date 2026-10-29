#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include <sys/types.h>
#include "core/limits.h"
#include "core/worker.h"
#include "proxy/fakeip/store.h"
#include "proxy/fakeip/snapshot.h"

#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <pthread.h>

static ftun_budget_t *observed_budget;
static pthread_mutex_t descriptor_mutex = PTHREAD_MUTEX_INITIALIZER;
static int observed_fds[16];
static size_t observed_count, observed_opens;
int __real_open(const char *path, int flags, ...);
int __real_close(int descriptor);
int __real_mkstemp(char *path);
static void descriptor_admission(void)
{
  ftun_budget_usage_t usage;
  if (ftun_budget_get_usage(observed_budget, &usage) != FTUN_OK ||
      usage.used_resources.descriptors < observed_count + 1u) {
    fputs("File descriptor was not admitted\n", stderr);
    abort();
  }
  observed_opens++;
}
int __wrap_open(const char *path, int flags, ...)
{
  int descriptor;
  mode_t mode = 0;
  if ((flags & O_CREAT) != 0) {
    va_list args; va_start(args, flags); mode = (mode_t)va_arg(args, int); va_end(args);
  }
  if (observed_budget == NULL) return __real_open(path, flags, mode);
  (void)pthread_mutex_lock(&descriptor_mutex);
  descriptor_admission();
  descriptor = __real_open(path, flags, mode);
  if (descriptor >= 0) { if (observed_count == 16u) abort(); observed_fds[observed_count++] = descriptor; }
  (void)pthread_mutex_unlock(&descriptor_mutex);
  return descriptor;
}
int __wrap_mkstemp(char *path)
{
  int descriptor;
  size_t index;
  if (observed_budget == NULL) return __real_mkstemp(path);
  (void)pthread_mutex_lock(&descriptor_mutex);
  descriptor_admission();
  (void)pthread_mutex_unlock(&descriptor_mutex);
  /* 静态libc的mkstemp会进入open包装器，不能持锁调用或重复登记。 */
  descriptor = __real_mkstemp(path);
  (void)pthread_mutex_lock(&descriptor_mutex);
  for (index = 0u; index < observed_count; index++) {
    if (observed_fds[index] == descriptor) break;
  }
  if (descriptor >= 0 && index == observed_count) {
    if (observed_count == 16u) abort();
    observed_fds[observed_count++] = descriptor;
  }
  (void)pthread_mutex_unlock(&descriptor_mutex);
  return descriptor;
}
int __wrap_close(int descriptor)
{
  size_t i;
  int result;
  if (observed_budget == NULL) return __real_close(descriptor);
  (void)pthread_mutex_lock(&descriptor_mutex);
  result = __real_close(descriptor);
  for (i = 0u; i < observed_count; i++) if (observed_fds[i] == descriptor) {
    observed_fds[i] = observed_fds[--observed_count]; break;
  }
  (void)pthread_mutex_unlock(&descriptor_mutex);
  return result;
}

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "fakeip store contract failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  unsigned int calls;
  ftun_status_t status;
  ftun_fakeip_store_operation_t kind;
  uint64_t sequence;
  uint32_t reserved_end;
} completion_t;

static void completed(ftun_operation_t *operation, ftun_error_t error,
                      ftun_fakeip_store_operation_t kind,
                      uint64_t sequence, uint32_t reserved_end, void *user)
{
  completion_t *completion = (completion_t *)user;
  (void)operation;
  completion->calls++;
  completion->status = error.status;
  completion->kind = kind;
  completion->sequence = sequence;
  completion->reserved_end = reserved_end;
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

static int test_durable_reservation_and_recovery(void)
{
  char directory[] = "/tmp/ftun-fakeip-store.XXXXXX";
  ftun_fakeip_store_identity_t identity;
  ftun_fakeip_store_options_t options;
  ftun_fakeip_store_info_t info;
  ftun_budget_t *budget = NULL;
  ftun_worker_t *worker = NULL;
  ftun_fakeip_store_t *store = NULL;
  ftun_fakeip_store_t *duplicate = NULL;
  ftun_operation_t *operation = NULL;
  completion_t completion;
  size_t callbacks;
  memset(&identity, 0, sizeof(identity));
  memset(&options, 0, sizeof(options));
  memset(&completion, 0, sizeof(completion));
  identity.uuid[0] = 1u;
  identity.first_address = UINT32_C(0xc6120001);
  identity.end_address_exclusive = UINT32_C(0xc6120010);
  CHECK(mkdtemp(directory) != NULL && rmdir(directory) == 0);
  CHECK(ftun_fakeip_store_initialize(directory, &identity) == FTUN_OK);
  CHECK(ftun_fakeip_store_initialize(directory, &identity) == FTUN_E_INVALID);
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_worker_create(budget, 4u, &worker) == FTUN_OK);
  options.directory = directory;
  options.budget = budget;
  options.worker = worker;
  options.completion = completed;
  options.user = &completion;
  CHECK(ftun_fakeip_store_open(&options, &store) == FTUN_OK);
  CHECK(ftun_fakeip_store_open(&options, &duplicate) == FTUN_E_AGAIN &&
        duplicate == NULL);
  CHECK(ftun_fakeip_store_get_info(store, &info) == FTUN_OK &&
        info.sequence == 0u && info.reserved_end == identity.first_address &&
        !info.halted && !info.pending);
  CHECK(ftun_fakeip_store_reserve(store, identity.first_address + 4u,
                                  &operation) == FTUN_OK && operation != NULL);
  CHECK(ftun_fakeip_store_get_info(store, &info) == FTUN_OK && info.pending &&
        info.sequence == 0u && info.reserved_end == identity.first_address);
  CHECK(ftun_fakeip_store_reserve(store, identity.first_address + 5u,
                                  &operation) == FTUN_E_AGAIN);
  CHECK(poll_until(worker, &completion, 1u));
  CHECK(completion.status == FTUN_OK &&
        completion.kind == FTUN_FAKEIP_STORE_RESERVATION &&
        completion.sequence == 1u &&
        completion.reserved_end == identity.first_address + 4u);
  CHECK(ftun_fakeip_store_get_info(store, &info) == FTUN_OK &&
        !info.pending && info.sequence == 1u &&
        info.reserved_end == identity.first_address + 4u);
  CHECK(ftun_fakeip_store_destroy(&store) == FTUN_OK);
  CHECK(ftun_fakeip_store_open(&options, &store) == FTUN_OK);
  CHECK(ftun_fakeip_store_get_info(store, &info) == FTUN_OK &&
        info.sequence == 1u && info.reserved_end == identity.first_address + 4u);
  CHECK(ftun_fakeip_store_destroy(&store) == FTUN_OK);
  CHECK(ftun_worker_stop(worker) == FTUN_OK);
  CHECK(ftun_worker_join(worker) == FTUN_OK);
  CHECK(ftun_worker_poll(worker, 8u, &callbacks) == FTUN_OK);
  CHECK(ftun_worker_destroy(&worker) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(remove_store(directory));
  return 0;
}

static int test_cancel_halts_new_issuance(void)
{
  char directory[] = "/tmp/ftun-fakeip-cancel.XXXXXX";
  ftun_fakeip_store_identity_t identity;
  ftun_fakeip_store_options_t options;
  ftun_fakeip_store_info_t info;
  ftun_budget_t *budget = NULL;
  ftun_worker_t *worker = NULL;
  ftun_fakeip_store_t *store = NULL;
  ftun_operation_t *operation = NULL;
  completion_t completion;
  ftun_worker_usage_t usage;
  size_t callbacks;
  unsigned int attempt;
  CHECK(mkdtemp(directory) != NULL && rmdir(directory) == 0);
  memset(&identity, 0, sizeof(identity));
  identity.uuid[0] = 2u;
  identity.first_address = 100u;
  identity.end_address_exclusive = 120u;
  CHECK(ftun_fakeip_store_initialize(directory, &identity) == FTUN_OK);
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_worker_create(budget, 2u, &worker) == FTUN_OK);
  memset(&completion, 0, sizeof(completion));
  memset(&options, 0, sizeof(options));
  options.directory = directory;
  options.budget = budget;
  options.worker = worker;
  options.completion = completed;
  options.user = &completion;
  CHECK(ftun_fakeip_store_open(&options, &store) == FTUN_OK);
  CHECK(ftun_fakeip_store_reserve(store, 104u, &operation) == FTUN_OK);
  CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  CHECK(poll_until(worker, &completion, 1u));
  CHECK(completion.status == FTUN_E_CANCELLED);
  CHECK(ftun_fakeip_store_get_info(store, &info) == FTUN_OK && info.halted);
  CHECK(ftun_fakeip_store_reserve(store, 108u, &operation) ==
        FTUN_E_STATE_CORRUPT);
  memset(&usage, 0, sizeof(usage));
  for (attempt = 0u; attempt < 100000u; attempt++) {
    CHECK(ftun_worker_poll(worker, 8u, &callbacks) == FTUN_OK);
    CHECK(ftun_worker_get_usage(worker, &usage) == FTUN_OK);
    if (usage.tasks == 0u) break;
    sched_yield();
  }
  CHECK(usage.tasks == 0u);
  CHECK(ftun_fakeip_store_destroy(&store) == FTUN_OK);
  CHECK(ftun_worker_stop(worker) == FTUN_OK);
  CHECK(ftun_worker_join(worker) == FTUN_OK);
  CHECK(ftun_worker_poll(worker, 8u, &callbacks) == FTUN_OK);
  CHECK(ftun_worker_destroy(&worker) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(remove_store(directory));
  return 0;
}

static int test_bounded_resources(void)
{
  char directory[] = "/tmp/ftun-fakeip-budget.XXXXXX";
  const size_t limits[] = {0u, 1u, 3u};
  ftun_fakeip_store_identity_t identity = {{7u}, 100u, 200u};
  size_t round;
  CHECK(mkdtemp(directory) != NULL && rmdir(directory) == 0);
  for (round = 0u; round < 3u; round++) {
    ftun_budget_options_t options = {{1024u * 1024u, 0u, 64u}, {0}, {0}};
    ftun_budget_usage_t usage, before;
    ftun_reservation_t hold = (ftun_reservation_t){0};
    ftun_budget_resources_t full = {0u, 2u, 0u}, one = {0u, 1u, 0u};
    ftun_fakeip_store_options_t store_options = {0};
    ftun_fakeip_store_t *store = NULL;
    ftun_worker_t *worker = NULL;
    ftun_fakeip_snapshot_t empty = {0}, *loaded = NULL;
    ftun_fakeip_store_info_t info;
    ftun_operation_t *operation = NULL;
    completion_t completion = {0};
    size_t opens;
    options.limit.descriptors = limits[round];
    CHECK(ftun_budget_create_resources(NULL, &options, &observed_budget) == FTUN_OK);
    observed_count = observed_opens = 0u;
    if (round < 2u) {
      CHECK(ftun_fakeip_store_initialize_budget(observed_budget, directory, &identity) == FTUN_E_LIMIT);
      CHECK(access(directory, F_OK) != 0 && observed_count == 0u);
      CHECK(ftun_budget_get_usage(observed_budget, &usage) == FTUN_OK &&
        usage.used == 0u && usage.used_resources.descriptors == 0u);
    } else {
      CHECK(ftun_fakeip_store_initialize_budget(observed_budget, directory, &identity) == FTUN_OK);
      CHECK(ftun_worker_create(observed_budget, 2u, &worker) == FTUN_OK);
      store_options.directory = directory; store_options.budget = observed_budget;
      store_options.worker = worker; store_options.completion = completed; store_options.user = &completion;
      CHECK(ftun_budget_get_usage(observed_budget, &before) == FTUN_OK);
      CHECK(ftun_fakeip_store_open(&store_options, &store) == FTUN_OK);
      CHECK(ftun_budget_get_usage(observed_budget, &usage) == FTUN_OK &&
        usage.used > before.used && usage.used_resources.descriptors == 1u && observed_count == 1u);
      CHECK(ftun_budget_reserve(observed_budget, usage.normal_available, &hold) == FTUN_OK);
      CHECK(ftun_fakeip_store_reserve(store, 110u, &operation) == FTUN_E_LIMIT && operation == NULL);
      CHECK(ftun_reservation_release(&hold) == FTUN_OK);
      CHECK(ftun_budget_reserve_resources(observed_budget, full, &hold) == FTUN_OK);
      opens = observed_opens;
      CHECK(ftun_fakeip_snapshot_load(store, 16u, &loaded) == FTUN_E_LIMIT && loaded == NULL);
      CHECK(observed_opens == opens && ftun_reservation_release(&hold) == FTUN_OK);
      memcpy(empty.uuid, identity.uuid, sizeof(empty.uuid));
      CHECK(ftun_budget_reserve_resources(observed_budget, one, &hold) == FTUN_OK);
      CHECK(ftun_fakeip_snapshot_save(store, &empty, &operation) == FTUN_OK);
      CHECK(poll_until(worker, &completion, 1u) && completion.status == FTUN_E_LIMIT);
      CHECK(ftun_reservation_release(&hold) == FTUN_OK);
      CHECK(ftun_fakeip_snapshot_load(store, 16u, &loaded) == FTUN_OK && loaded->mapping_count == 0u);
      CHECK(ftun_fakeip_snapshot_destroy(&loaded) == FTUN_OK);
      CHECK(ftun_fakeip_snapshot_save(store, &empty, &operation) == FTUN_OK);
      CHECK(poll_until(worker, &completion, 2u) && completion.status == FTUN_OK);
      CHECK(ftun_budget_reserve_resources(observed_budget, full, &hold) == FTUN_OK);
      CHECK(ftun_fakeip_store_reserve(store, 110u, &operation) == FTUN_OK);
      CHECK(poll_until(worker, &completion, 3u) && completion.status == FTUN_E_LIMIT);
      CHECK(ftun_fakeip_store_get_info(store, &info) == FTUN_OK && info.halted && info.sequence == 0u && info.reserved_end == 100u);
      CHECK(ftun_reservation_release(&hold) == FTUN_OK);
      CHECK(ftun_fakeip_store_destroy(&store) == FTUN_OK && observed_count == 0u);
      CHECK(ftun_budget_get_usage(observed_budget, &usage) == FTUN_OK &&
        usage.used == before.used && usage.metadata_bytes == before.metadata_bytes &&
        usage.used_resources.descriptors == before.used_resources.descriptors);
      CHECK(ftun_worker_stop(worker) == FTUN_OK && ftun_worker_join(worker) == FTUN_OK);
      CHECK(ftun_worker_destroy(&worker) == FTUN_OK);
      CHECK(remove_store(directory));
    }
    { ftun_budget_t *budget = observed_budget; observed_budget = NULL;
      CHECK(ftun_budget_destroy(&budget) == FTUN_OK); }
  }
  return 0;
}

int main(void)
{
  CHECK(test_bounded_resources() == 0);
  CHECK(test_durable_reservation_and_recovery() == 0);
  CHECK(test_cancel_halts_new_issuance() == 0);
  return 0;
}
