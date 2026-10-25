#define _POSIX_C_SOURCE 200809L
#include "core/core.h"
#include "core/worker.h"
#include "util/time.h"
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "budget consumers failed at %d: %s\n", __LINE__, #x); \
  return 1; \
} } while (0)
#define PRODUCERS 4u
#define SUBMISSIONS 500u

typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  ftun_core_t *core;
  ftun_budget_t *root;
  ftun_budget_t *budget;
  ftun_worker_t *workers[2];
  const char *path;
  size_t callbacks;
  size_t initial_metadata;
  size_t initial_used;
  int started;
  int failed;
  ftun_status_t run_status;
} state_t;

static state_t state;

static ftun_status_t success(void *implementation)
{ return implementation == &state ? FTUN_OK : FTUN_E_INVALID; }

static ftun_status_t plan_prepare(ftun_budget_t *budget,
  const ftun_config_t *config,
                                   uint32_t mark, void **out)
{
  (void)budget; (void)config; (void)mark; *out = &state; return FTUN_OK; }

static ftun_status_t plan_destroy(void **implementation)
{ *implementation = NULL; return FTUN_OK; }

static ftun_status_t prepare(ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations, const ftun_core_service_binding_t *binding,
  const ftun_config_t *config, uint64_t generation, void **out)
{
  ftun_budget_usage_t usage;
  ftun_budget_options_t options = {0};
  ftun_status_t status;
  (void)core; (void)operations; (void)binding; (void)config; (void)generation;
  state.root = budget;
  status = ftun_budget_get_usage(budget, &usage);
  if (status != FTUN_OK) return status;
  options.limit = usage.limits;
  status = ftun_budget_create_resources(budget, &options, &state.budget);
  if (status != FTUN_OK) return status;
  *out = &state;
  status = ftun_budget_get_usage(state.budget, &usage);
  if (status != FTUN_OK) return status;
  state.initial_metadata = usage.metadata_bytes;
  state.initial_used = usage.used;
  status = ftun_worker_create(state.budget, 16u, &state.workers[0]);
  if (status != FTUN_OK) return status;
  status = ftun_worker_create(state.budget, 16u, &state.workers[1]);
  return status;
}

static ftun_status_t reload_prepare(void *implementation,
  const ftun_config_t *config, uint64_t generation)
{ (void)config; (void)generation; return success(implementation); }

static ftun_status_t reload_planned(void *implementation,
  const ftun_config_t *config, uint64_t generation, const void *plan)
{ (void)plan; return reload_prepare(implementation, config, generation); }

static ftun_status_t reload_commit(void *implementation, uint64_t generation)
{ (void)generation; return success(implementation); }

static ftun_status_t run_once(void *implementation, bool block,
                               ftun_core_service_run_usage_t *out)
{
  ftun_budget_usage_t usage;
  size_t index;
  (void)block;
  if (success(implementation) != FTUN_OK) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&state.mutex);
  state.started = 1;
  (void)pthread_cond_broadcast(&state.condition);
  (void)pthread_mutex_unlock(&state.mutex);
  for (index = 0u; index < 2u; index++) {
    size_t callbacks = 0u;
    ftun_status_t status = ftun_worker_poll(state.workers[index], 8u, &callbacks);
    if (status != FTUN_OK) return status;
    out->work += callbacks;
  }
  if (ftun_budget_get_usage(state.budget, &usage) != FTUN_OK ||
      usage.used > usage.limit || usage.metadata_bytes < state.initial_metadata) {
    return FTUN_E_STATE_CORRUPT;
  }
  if (ftun_budget_get_usage(state.root, &usage) != FTUN_OK || usage.used > usage.limit)
    return FTUN_E_STATE_CORRUPT;
  (void)sched_yield();
  return FTUN_OK;
}

static ftun_status_t drain(void *implementation, uint64_t deadline)
{ (void)deadline; return success(implementation); }

static ftun_status_t stop(void *implementation, uint64_t deadline)
{
  size_t index;
  if (success(implementation) != FTUN_OK) return FTUN_E_INVALID;
  for (index = 0u; index < 2u; index++) {
    ftun_status_t status;
    if (state.workers[index] == NULL) continue;
    status = ftun_worker_stop(state.workers[index]);
    if (status == FTUN_OK) status = ftun_worker_join_until(state.workers[index], deadline);
    if (status != FTUN_OK) return status;
  }
  return FTUN_OK;
}

static ftun_status_t destroy(void **implementation, uint64_t deadline)
{
  ftun_budget_usage_t usage;
  ftun_status_t status = stop(*implementation, deadline);
  size_t index;
  if (status != FTUN_OK) return status;
  for (index = 0u; index < 2u; index++) {
    status = ftun_worker_destroy(&state.workers[index]);
    if (status != FTUN_OK) return status;
  }
  status = ftun_budget_get_usage(state.budget, &usage);
  if (status != FTUN_OK || usage.used != state.initial_used ||
      usage.metadata_bytes != state.initial_metadata) {
    fprintf(stderr, "service budget mismatch: status=%d used=%zu/%zu metadata=%zu/%zu\n",
      (int)status, usage.used, state.initial_used, usage.metadata_bytes, state.initial_metadata);
    return FTUN_E_STATE_CORRUPT;
  }
  status = ftun_budget_destroy(&state.budget);
  if (status != FTUN_OK) return status;
  *implementation = NULL;
  return FTUN_OK;
}

static const ftun_core_service_descriptor_t descriptor = {
  "budget-consumers", plan_prepare, plan_destroy, prepare, success,
  reload_prepare, reload_planned, reload_commit, success,
  run_once, success, success, drain, stop, destroy
};

static void completed(ftun_operation_t *operation, ftun_error_t error, void *user)
{
  (void)operation; (void)user;
  (void)pthread_mutex_lock(&state.mutex);
  if (error.status != FTUN_OK) state.failed = 1;
  state.callbacks++;
  (void)pthread_cond_broadcast(&state.condition);
  (void)pthread_mutex_unlock(&state.mutex);
}

static void worker_completed(ftun_operation_t *operation, ftun_error_t error,
                              ftun_bytes_t result, void *user)
{
  if (result.length != 4u || memcmp(result.data, "echo", 4u) != 0)
    error.status = FTUN_E_STATE_CORRUPT;
  completed(operation, error, user);
}

static ftun_status_t echo(ftun_bytes_t input, uint8_t *result,
                          size_t capacity, size_t *out)
{
  if (capacity < input.length) return FTUN_E_LIMIT;
  memcpy(result, input.data, input.length);
  *out = input.length;
  return FTUN_OK;
}

typedef struct { size_t index; ftun_status_t status; } producer_t;

static void *produce(void *user)
{
  producer_t *producer = user;
  ftun_worker_job_t job = {0};
  size_t index;
  job.execute = echo;
  job.input = (ftun_bytes_t){(const uint8_t *)"echo", 4u};
  job.result_capacity = 4u;
  producer->status = FTUN_OK;
  for (index = 0u; index < SUBMISSIONS; index++) {
    ftun_operation_t *operation = NULL;
    do {
      producer->status = ftun_core_post(state.core, completed, NULL, &operation);
      if (producer->status == FTUN_E_LIMIT) (void)sched_yield();
    } while (producer->status == FTUN_E_LIMIT);
    if (producer->status != FTUN_OK) break;
    do {
      producer->status = ftun_worker_submit(state.workers[producer->index % 2u],
        &job, worker_completed, NULL, &operation);
      if (producer->status == FTUN_E_LIMIT) (void)sched_yield();
    } while (producer->status == FTUN_E_LIMIT);
    if (producer->status != FTUN_OK) break;
  }
  return NULL;
}

static void *owner(void *unused)
{
  (void)unused;
  state.run_status = ftun_core_run(state.core, state.path);
  return NULL;
}

int main(void)
{
  static const char config[] = "{\"base\":{\"state-cache\":false},"
    "\"log\":{\"level\":\"silent\"},\"dns\":{\"enable\":false}}\n";
  char path[] = "/tmp/ftun-budget-consumers-XXXXXX";
  ftun_core_options_t options = {0};
  ftun_core_info_t info;
  pthread_t owner_thread, producers[PRODUCERS];
  producer_t contexts[PRODUCERS];
  struct timespec deadline;
  uint64_t now;
  size_t index;
  int file = mkstemp(path);
  CHECK(file >= 0 && write(file, config, sizeof(config) - 1u) == (ssize_t)(sizeof(config) - 1u));
  CHECK(close(file) == 0);
  CHECK(pthread_mutex_init(&state.mutex, NULL) == 0);
  CHECK(pthread_cond_init(&state.condition, NULL) == 0);
  state.path = path;
  options.struct_size = sizeof(options);
  options.abi_version = FTUN_ABI_VERSION;
  options.owned_memory_limit = 16u * 1024u * 1024u;
  options.operation_capacity = 64u;
  CHECK(ftun_core_create_with_service(&options, &descriptor, &state.core) == FTUN_OK);
  CHECK(pthread_create(&owner_thread, NULL, owner, NULL) == 0);
  CHECK(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
  deadline.tv_sec += 20;
  (void)pthread_mutex_lock(&state.mutex);
  while (!state.started)
    CHECK(pthread_cond_timedwait(&state.condition, &state.mutex, &deadline) == 0);
  (void)pthread_mutex_unlock(&state.mutex);
  for (index = 0u; index < PRODUCERS; index++) {
    contexts[index].index = index;
    CHECK(pthread_create(&producers[index], NULL, produce, &contexts[index]) == 0);
  }
  for (index = 0u; index < PRODUCERS; index++) {
    CHECK(pthread_join(producers[index], NULL) == 0 && contexts[index].status == FTUN_OK);
  }
  (void)pthread_mutex_lock(&state.mutex);
  while (state.callbacks != 2u * PRODUCERS * SUBMISSIONS)
    CHECK(pthread_cond_timedwait(&state.condition, &state.mutex, &deadline) == 0);
  CHECK(!state.failed);
  (void)pthread_mutex_unlock(&state.mutex);
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  CHECK(ftun_core_stop(state.core, now + 5000u) == FTUN_OK);
  CHECK(pthread_join(owner_thread, NULL) == 0 && state.run_status == FTUN_OK);
  CHECK(ftun_core_get_info(state.core, &info) == FTUN_OK &&
        info.pending_operations == 0u && info.state == FTUN_CORE_STOPPED);
  CHECK(ftun_core_destroy(&state.core) == FTUN_OK && state.core == NULL);
  CHECK(pthread_cond_destroy(&state.condition) == 0);
  CHECK(pthread_mutex_destroy(&state.mutex) == 0);
  CHECK(unlink(path) == 0);
  return 0;
}
