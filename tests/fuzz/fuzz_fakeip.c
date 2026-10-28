#define _POSIX_C_SOURCE 200809L

#include "fuzz_common.h"

#include "core/budget.h"
#include "core/worker.h"
#include "proxy/state/fakeip_snapshot.h"
#include "proxy/state/fakeip_store.h"

#include <fcntl.h>
#include <sched.h>
#include <string.h>
#include <unistd.h>

/* FakeIP 快照读取：磁盘上的快照是不可信输入（可能被截断、损坏或被篡改）。
 * 每个输入都写成 mappings 文件后调用 load；损坏返回 STATE_CORRUPT 是正确结果，
 * 要求只是不崩溃、不越界、不泄漏。 */
static char directory[] = "/tmp/ftun-fuzz-fakeip.XXXXXX";
static char mapping_path[256];
static ftun_budget_t *budget;
static ftun_worker_t *worker;
static ftun_fakeip_store_t *store;
static unsigned int completions;

static void completed(ftun_operation_t *operation, ftun_error_t error,
                      ftun_fakeip_store_operation_t kind, uint64_t sequence,
                      uint32_t end, void *user)
{
  (void)operation; (void)error; (void)kind; (void)sequence; (void)end; (void)user;
  completions++;
}

static void wait_for(unsigned int calls)
{
  unsigned int attempt;
  for (attempt = 0u; attempt < 1000000u && completions < calls; attempt++) {
    size_t callbacks = 0u;
    FUZZ_REQUIRE(ftun_worker_poll(worker, 8u, &callbacks) == FTUN_OK);
    if (callbacks == 0u) sched_yield();
  }
  FUZZ_REQUIRE(completions >= calls);
}

static void cleanup(void)
{
  static const char *names[] = {"identity", "reservations", "mappings", "lock"};
  char path[300];
  size_t index;
  if (store != NULL) (void)ftun_fakeip_store_destroy(&store);
  if (worker != NULL) {
    (void)ftun_worker_stop(worker);
    (void)ftun_worker_join(worker);
    (void)ftun_worker_destroy(&worker);
  }
  for (index = 0u; index < sizeof(names) / sizeof(names[0]); index++) {
    (void)snprintf(path, sizeof(path), "%s/%s", directory, names[index]);
    (void)unlink(path);
  }
  (void)rmdir(directory);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  ftun_fakeip_store_identity_t identity;
  ftun_fakeip_store_options_t options;
  (void)argc;
  (void)argv;
  memset(&identity, 0, sizeof(identity));
  identity.uuid[0] = 9u;
  identity.first_address = 1000u;
  identity.end_address_exclusive = 1100u;
  FUZZ_REQUIRE(mkdtemp(directory) != NULL && rmdir(directory) == 0);
  FUZZ_REQUIRE(ftun_fakeip_store_initialize(directory, &identity) == FTUN_OK);
  FUZZ_REQUIRE(ftun_budget_create(NULL, 8u * 1024u * 1024u, 0u, &budget) == FTUN_OK);
  FUZZ_REQUIRE(ftun_worker_create(budget, 4u, &worker) == FTUN_OK);
  memset(&options, 0, sizeof(options));
  options.directory = directory;
  options.budget = budget;
  options.worker = worker;
  options.completion = completed;
  FUZZ_REQUIRE(ftun_fakeip_store_open(&options, &store) == FTUN_OK);
  (void)snprintf(mapping_path, sizeof(mapping_path), "%s/mappings", directory);
  (void)atexit(cleanup);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  ftun_fakeip_snapshot_t *snapshot = NULL;
  ftun_status_t status;
  int descriptor = open(mapping_path, O_WRONLY | O_TRUNC | O_CLOEXEC);
  FUZZ_REQUIRE(descriptor >= 0);
  FUZZ_REQUIRE(size == 0u || write(descriptor, data, size) == (ssize_t)size);
  FUZZ_REQUIRE(close(descriptor) == 0);
  status = ftun_fakeip_snapshot_load(store, 64u, &snapshot);
  if (status == FTUN_OK) {
    FUZZ_REQUIRE(snapshot != NULL);
    FUZZ_REQUIRE(ftun_fakeip_snapshot_destroy(&snapshot) == FTUN_OK);
  } else {
    FUZZ_REQUIRE(snapshot == NULL);
  }
  return 0;
}

/* 有效快照：先让 store 保存一份，再读回磁盘上的字节。 */
void ftun_fuzz_seeds(ftun_fuzz_seed_fn add)
{
  ftun_fakeip_snapshot_t source;
  ftun_fakeip_mapping_t mappings[2];
  ftun_operation_t *operation = NULL;
  char first[] = "one.example";
  char second[] = "two.example";
  uint8_t buffer[4096];
  ssize_t count;
  int descriptor;
  completions = 0u;
  FUZZ_REQUIRE(ftun_fakeip_store_reserve(store, 1010u, &operation) == FTUN_OK);
  wait_for(1u);
  memset(&source, 0, sizeof(source));
  source.uuid[0] = 9u;
  source.sequence = 1u;
  source.mappings = mappings;
  source.mapping_count = 2u;
  mappings[0].address = 1001u;
  mappings[0].domain = (ftun_string_t){first, strlen(first)};
  mappings[1].address = 1002u;
  mappings[1].domain = (ftun_string_t){second, strlen(second)};
  FUZZ_REQUIRE(ftun_fakeip_snapshot_save(store, &source, &operation) == FTUN_OK);
  wait_for(2u);
  descriptor = open(mapping_path, O_RDONLY | O_CLOEXEC);
  FUZZ_REQUIRE(descriptor >= 0);
  count = read(descriptor, buffer, sizeof(buffer));
  (void)close(descriptor);
  FUZZ_REQUIRE(count > 0);
  add(buffer, (size_t)count);
}
