#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "core/budget.h"
#include "core/worker.h"
#include "proxy/state/fakeip_store.h"
#include "proxy/state/fakeip_snapshot.h"

#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "fakeip snapshot contract failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  unsigned int calls;
  ftun_status_t status;
  ftun_fakeip_store_operation_t kind;
} completion_t;

static void completed(ftun_operation_t *operation, ftun_error_t error,
                      ftun_fakeip_store_operation_t kind,
                      uint64_t sequence, uint32_t end, void *user)
{
  completion_t *completion = (completion_t *)user;
  (void)operation;
  (void)sequence;
  (void)end;
  completion->calls++;
  completion->status = error.status;
  completion->kind = kind;
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

static int cleanup(const char *directory)
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

int main(void)
{
  char directory[] = "/tmp/ftun-fakeip-snapshot.XXXXXX";
  ftun_fakeip_store_identity_t identity;
  ftun_fakeip_store_options_t options;
  ftun_budget_t *budget = NULL;
  ftun_worker_t *worker = NULL;
  ftun_fakeip_store_t *store = NULL;
  ftun_fakeip_snapshot_t source;
  ftun_fakeip_snapshot_t *loaded = NULL;
  ftun_fakeip_mapping_t mappings[2];
  ftun_operation_t *operation = NULL;
  completion_t completion;
  char first[] = "one.example";
  char second[] = "two.example";
  char mapping_path[256];
  size_t callbacks;
  int descriptor;
  uint8_t corrupt;
  memset(&identity, 0, sizeof(identity));
  identity.uuid[0] = 9u;
  identity.first_address = 1000u;
  identity.end_address_exclusive = 1100u;
  CHECK(mkdtemp(directory) != NULL && rmdir(directory) == 0);
  CHECK(ftun_fakeip_store_initialize(directory, &identity) == FTUN_OK);
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_worker_create(budget, 4u, &worker) == FTUN_OK);
  memset(&completion, 0, sizeof(completion));
  memset(&options, 0, sizeof(options));
  options.directory = directory;
  options.budget = budget;
  options.worker = worker;
  options.completion = completed;
  options.user = &completion;
  CHECK(ftun_fakeip_store_open(&options, &store) == FTUN_OK);
  CHECK(ftun_fakeip_store_reserve(store, 1010u, &operation) == FTUN_OK);
  CHECK(poll_until(worker, &completion, 1u));
  CHECK(completion.status == FTUN_OK &&
        completion.kind == FTUN_FAKEIP_STORE_RESERVATION);

  memset(&source, 0, sizeof(source));
  memcpy(source.uuid, identity.uuid, sizeof(source.uuid));
  source.sequence = 1u;
  source.mappings = mappings;
  source.mapping_count = 2u;
  mappings[0].address = 1001u;
  mappings[0].domain = (ftun_string_t){first, strlen(first)};
  mappings[1].address = 1002u;
  mappings[1].domain = (ftun_string_t){second, strlen(second)};
  CHECK(ftun_fakeip_snapshot_save(store, &source, &operation) == FTUN_OK);
  first[0] = 'x';
  second[0] = 'y';
  CHECK(poll_until(worker, &completion, 2u));
  CHECK(completion.status == FTUN_OK &&
        completion.kind == FTUN_FAKEIP_STORE_SNAPSHOT);
  CHECK(ftun_fakeip_snapshot_load(store, 4u, &loaded) == FTUN_OK);
  CHECK(loaded != NULL && loaded->sequence == 1u &&
        loaded->mapping_count == 2u && loaded->mappings[0].address == 1001u &&
        loaded->mappings[0].domain.length == strlen("one.example") &&
        memcmp(loaded->mappings[0].domain.data, "one.example",
               strlen("one.example")) == 0 &&
        loaded->mappings[1].address == 1002u);
  CHECK(ftun_fakeip_snapshot_destroy(&loaded) == FTUN_OK);

  first[0] = 'o';
  second[0] = 't';
  mappings[1].address = 1001u;
  CHECK(ftun_fakeip_snapshot_save(store, &source, &operation) == FTUN_E_INVALID &&
        operation == NULL);
  mappings[1].address = 1011u;
  CHECK(ftun_fakeip_snapshot_save(store, &source, &operation) == FTUN_E_INVALID);
  mappings[1].address = 1002u;
  source.uuid[0] = 8u;
  CHECK(ftun_fakeip_snapshot_save(store, &source, &operation) == FTUN_E_INVALID);
  source.uuid[0] = 9u;

  CHECK(snprintf(mapping_path, sizeof(mapping_path), "%s/mappings", directory) > 0);
  descriptor = open(mapping_path, O_RDWR | O_CLOEXEC);
  CHECK(descriptor >= 0 && pread(descriptor, &corrupt, 1u, 10) == 1);
  corrupt ^= 0x55u;
  CHECK(pwrite(descriptor, &corrupt, 1u, 10) == 1 && fsync(descriptor) == 0 &&
        close(descriptor) == 0);
  CHECK(ftun_fakeip_snapshot_load(store, 4u, &loaded) == FTUN_E_STATE_CORRUPT &&
        loaded == NULL);

  CHECK(ftun_fakeip_store_destroy(&store) == FTUN_OK);
  CHECK(ftun_worker_stop(worker) == FTUN_OK);
  CHECK(ftun_worker_join(worker) == FTUN_OK);
  CHECK(ftun_worker_poll(worker, 8u, &callbacks) == FTUN_OK);
  CHECK(ftun_worker_destroy(&worker) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(cleanup(directory));
  return 0;
}
