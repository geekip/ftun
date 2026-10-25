#define _POSIX_C_SOURCE 200809L
#include "core/core.h"
#include "config/model.h"
#include "config/compile.h"
#include "util/time.h"
#include "app/control.h"
#if defined(FTUN_TEST_PROXY)
#include "proxy/runtime_state.h"
#endif

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHECK(value) do { if (!(value)) { \
  fprintf(stderr, "app cleanup failed at %d: %s\n", __LINE__, #value); \
  return 1; } } while (0)

typedef enum {
  CANCEL_RETRY, CANCEL_BLOCKED, PREPARE_BLOCKED, ACTIVATE_BLOCKED,
  PREPARE_RETRY, SHORTEN_STOP, LATE_RELOAD, ABORT_RETRY, PLAN_FAILED,
  ABORT_BLOCKED, CANCEL_IO, BUDGET_HELD, RUNTIME_HELD
} app_mode_t;

typedef struct {
  const ftun_config_t *config;
  ftun_reservation_t *reservation;
} instance_t;

typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  ftun_core_t *core;
  ftun_operation_queue_t *operations;
  const char *path;
  const ftun_config_t *reload_config;
  const ftun_config_t *prepared_config;
  ftun_reservation_t *held_reservation;
  ftun_runtime_t *held_runtime;
  app_mode_t mode;
  int allow_cleanup;
  int worker_entered;
  int allow_worker;
  int allow_plan;
  int stop_started;
  int run_returned;
  int failed;
  bool service_stopping;
  size_t late_wakeups;
  size_t prepares, activates, stops, destroys, cancels, internal_callbacks;
  size_t reload_callbacks, plans_destroyed, aborts, rounds;
  uint64_t stop_deadline;
} test_t;

static test_t test;

static uint64_t now_ms(void)
{
  uint64_t now = 0u;
  if (ftun_monotonic_now(&now) != FTUN_OK) abort();
  return now;
}

static void pause_ms(long milliseconds)
{
  struct timespec duration = {milliseconds / 1000,
                              (milliseconds % 1000) * 1000000};
  (void)nanosleep(&duration, NULL);
}

static ftun_status_t plan_prepare(ftun_budget_t *budget,
  const ftun_config_t *config,
                                   uint32_t mark, void **out)
{
  (void)budget;
  (void)mark;
  *out = (void *)config;
  (void)pthread_mutex_lock(&test.mutex);
  test.prepared_config = config;
  test.worker_entered = 1;
  (void)pthread_cond_broadcast(&test.condition);
  while (test.mode == LATE_RELOAD && !test.allow_worker) {
    (void)pthread_cond_wait(&test.condition, &test.mutex);
  }
  (void)pthread_mutex_unlock(&test.mutex);
  return test.mode == PLAN_FAILED ? FTUN_E_IO : FTUN_OK;
}

static ftun_status_t plan_destroy(void **out)
{
  const ftun_config_t *config = *out;
  if (config == NULL) return FTUN_OK;
  if (config->source_path == NULL || strcmp(config->source_path, test.path)) {
    test.failed = 1;
  }
  if (!test.allow_plan) return FTUN_E_AGAIN;
  test.plans_destroyed++;
  *out = NULL;
  return FTUN_OK;
}

static ftun_status_t prepare(ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations, const ftun_core_service_binding_t *binding,
  const ftun_config_t *config, uint64_t generation, void **out)
{
  instance_t *instance;
  ftun_reservation_t *reservation = NULL;
  (void)binding;
  (void)generation;
  *out = NULL;
  if (ftun_budget_reserve(budget, sizeof(*instance), &reservation) != FTUN_OK) {
    return FTUN_E_LIMIT;
  }
  instance = calloc(1u, sizeof(*instance));
  if (instance == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  instance->reservation = reservation;
  instance->config = config;
  *out = instance;
  test.core = core;
  test.operations = operations;
  test.prepares++;
  if (test.mode == BUDGET_HELD &&
      ftun_budget_reserve(budget, 17u, &test.held_reservation) != FTUN_OK) {
    return FTUN_E_LIMIT;
  }
  if (test.mode == PREPARE_BLOCKED) {
    test.stop_deadline = now_ms() + 30u;
    if (ftun_core_stop(core, test.stop_deadline) != FTUN_OK) test.failed = 1;
    return FTUN_E_IO;
  }
  if (test.mode == PREPARE_RETRY && test.prepares == 1u) return FTUN_E_IO;
  return FTUN_OK;
}

static ftun_status_t activate(void *instance)
{
  if (instance == NULL) return FTUN_E_INVALID;
  test.activates++;
  if (test.mode == ACTIVATE_BLOCKED) {
    test.stop_deadline = now_ms() + 30u;
    if (ftun_core_stop(test.core, test.stop_deadline) != FTUN_OK) test.failed = 1;
    return FTUN_E_PROTOCOL;
  }
  return FTUN_OK;
}

static ftun_status_t cancel(void *user)
{
  (void)user;
  test.cancels++;
  if (test.mode == CANCEL_IO) return test.cancels == 1u ? FTUN_E_IO : FTUN_OK;
  if (test.mode == CANCEL_RETRY || test.mode == PREPARE_RETRY ||
      test.mode == BUDGET_HELD || test.mode == RUNTIME_HELD) {
    return test.cancels == 1u ? FTUN_E_AGAIN : FTUN_OK;
  }
  return test.allow_cleanup ? FTUN_OK : FTUN_E_AGAIN;
}

static void internal_completed(ftun_operation_t *operation,
                                ftun_error_t error, void *user)
{
  (void)operation;
  (void)user;
  if (error.status != FTUN_E_CANCELLED) test.failed = 1;
  test.internal_callbacks++;
}

static void reload_completed(ftun_operation_t *operation,
                              ftun_error_t error, void *user)
{
  (void)operation;
  (void)user;
  test.reload_callbacks++;
  if ((test.mode == ABORT_RETRY || test.mode == PLAN_FAILED ||
       test.mode == ABORT_BLOCKED) && error.status != FTUN_E_IO) test.failed = 1;
}

static ftun_status_t reload_prepare(void *instance,
  const ftun_config_t *config, uint64_t generation)
{
  (void)instance;
  (void)generation;
  test.reload_config = config;
  return test.mode == ABORT_RETRY || test.mode == ABORT_BLOCKED
    ? FTUN_E_IO : FTUN_OK;
}

static ftun_status_t reload_planned(void *instance,
  const ftun_config_t *config, uint64_t generation, const void *plan)
{
  if (plan != config) return FTUN_E_STATE_CORRUPT;
  return reload_prepare(instance, config, generation);
}

static ftun_status_t reload_commit(void *instance, uint64_t generation)
{
  (void)instance;
  (void)generation;
  test.failed = 1;
  return FTUN_E_IO;
}

static ftun_status_t success(void *instance)
{
  return instance == NULL ? FTUN_E_INVALID : FTUN_OK;
}

static ftun_status_t reload_abort(void *instance)
{
  (void)instance;
  test.aborts++;
  if (test.reload_config == NULL || test.reload_config->source_path == NULL ||
      strcmp(test.reload_config->source_path, test.path)) test.failed = 1;
  if (test.mode == ABORT_BLOCKED && !test.allow_cleanup) return FTUN_E_AGAIN;
  return test.mode == ABORT_RETRY && test.aborts < 3u
    ? FTUN_E_AGAIN : FTUN_OK;
}

static ftun_status_t run_once(void *instance, bool may_block,
                               ftun_core_service_run_usage_t *usage)
{
  ftun_operation_t *operation = NULL;
  ftun_operation_token_t token = {0};
  ftun_status_t status;
  int entered;
  (void)instance;
  (void)may_block;
  memset(usage, 0, sizeof(*usage));
  test.rounds++;
#if defined(FTUN_TEST_PROXY)
  if (test.mode == RUNTIME_HELD && test.rounds == 1u) {
    status = ftun_runtime_active_acquire(test.core, &test.held_runtime);
    if (status != FTUN_OK) return status;
  }
#endif
  if (test.mode == LATE_RELOAD || test.mode == ABORT_RETRY ||
      test.mode == PLAN_FAILED || test.mode == ABORT_BLOCKED) {
    if (test.rounds == 1u) {
      return ftun_core_reload(test.core, test.path, reload_completed,
                               NULL, &operation);
    }
    (void)pthread_mutex_lock(&test.mutex);
    entered = test.worker_entered;
    (void)pthread_mutex_unlock(&test.mutex);
    if (test.mode == PLAN_FAILED && test.reload_callbacks != 0u &&
        !test.allow_plan) {
      if (ftun_core_reload(test.core, test.path, reload_completed, NULL,
                            &operation) != FTUN_E_AGAIN || operation != NULL) {
        test.failed = 1;
      }
      test.allow_plan = 1;
    }
    if ((test.mode == LATE_RELOAD && entered) ||
        (test.mode == ABORT_BLOCKED && test.reload_callbacks != 0u) ||
        (test.mode == PLAN_FAILED && test.plans_destroyed != 0u) ||
        (test.mode == ABORT_RETRY && test.aborts >= 3u &&
         test.plans_destroyed != 0u)) {
      test.stop_deadline = now_ms() + 30u;
      return ftun_core_stop(test.core, test.stop_deadline);
    }
    pause_ms(1);
    return FTUN_OK;
  }
  status = ftun_operation_accept(test.operations, internal_completed, NULL,
                                  &operation, &token);
  if (status == FTUN_OK) status = ftun_operation_set_cancel_hook(operation, cancel, NULL);
  if (status != FTUN_OK) return status;
  test.stop_deadline = now_ms() + (test.mode == SHORTEN_STOP ? 2000u : 30u);
  status = ftun_core_stop(test.core, test.stop_deadline);
  (void)pthread_mutex_lock(&test.mutex);
  test.stop_started = 1;
  (void)pthread_cond_broadcast(&test.condition);
  (void)pthread_mutex_unlock(&test.mutex);
  return status;
}

static ftun_status_t stop_until(void *instance, uint64_t deadline)
{
  (void)instance;
  (void)pthread_mutex_lock(&test.mutex);
  test.service_stopping = true;
  (void)pthread_mutex_unlock(&test.mutex);
  test.stops++;
  if (!test.run_returned && deadline > test.stop_deadline &&
      test.stop_deadline != 0u) test.failed = 1;
  return FTUN_OK;
}

static ftun_status_t wakeup(void *instance)
{
  (void)instance;
  (void)pthread_mutex_lock(&test.mutex);
  if (test.service_stopping) test.late_wakeups++;
  (void)pthread_mutex_unlock(&test.mutex);
  return FTUN_OK;
}

static ftun_status_t destroy_until(void **out, uint64_t deadline)
{
  instance_t *instance = *out;
  (void)deadline;
  if (instance == NULL) return FTUN_OK;
  if (instance->config->source_path == NULL ||
      strcmp(instance->config->source_path, test.path)) test.failed = 1;
  if (!test.allow_cleanup) return FTUN_E_AGAIN;
  (void)ftun_reservation_release(&instance->reservation);
  free(instance);
  *out = NULL;
  test.destroys++;
  return FTUN_OK;
}

static const ftun_core_service_descriptor_t descriptor = {
  "cleanup-test", plan_prepare, plan_destroy, prepare, activate,
  reload_prepare, reload_planned, reload_commit, reload_abort,
  run_once, wakeup, success, stop_until, stop_until, destroy_until
};

static void *shorten_stop(void *user)
{
  ftun_core_t *core = user;
  (void)pthread_mutex_lock(&test.mutex);
  while (!test.stop_started) (void)pthread_cond_wait(&test.condition, &test.mutex);
  (void)pthread_mutex_unlock(&test.mutex);
  pause_ms(20);
  if (ftun_core_stop(core, now_ms() + 30u) != FTUN_OK) abort();
  return NULL;
}

static int scenario(app_mode_t mode, const char *path)
{
  ftun_core_t *core = NULL;
  ftun_core_options_t options;
  ftun_core_info_t info;
  ftun_status_t status;
  uint64_t started;
  size_t callbacks;
  pthread_t thread;
  memset(&test, 0, sizeof(test));
  memset(&options, 0, sizeof(options));
  test.mode = mode;
  test.path = path;
  test.allow_cleanup = mode == CANCEL_RETRY || mode == PREPARE_RETRY ||
                       mode == LATE_RELOAD || mode == ABORT_RETRY ||
                       mode == PLAN_FAILED || mode == BUDGET_HELD ||
                       mode == RUNTIME_HELD || mode == CANCEL_IO;
  test.allow_plan = mode != LATE_RELOAD && mode != PLAN_FAILED;
  CHECK(pthread_mutex_init(&test.mutex, NULL) == 0);
  CHECK(pthread_cond_init(&test.condition, NULL) == 0);
  options.struct_size = sizeof(options);
  options.abi_version = FTUN_ABI_VERSION;
  CHECK(ftun_core_create_with_service(&options, &descriptor, &core) == FTUN_OK);
  if (mode == SHORTEN_STOP) CHECK(pthread_create(&thread, NULL, shorten_stop, core) == 0);
  started = now_ms();
  status = ftun_core_run(core, path);
  test.run_returned = 1;
  if (mode == SHORTEN_STOP) CHECK(pthread_join(thread, NULL) == 0);
  CHECK(now_ms() - started < 1000u);
  if (mode == PREPARE_RETRY) {
    CHECK(status == FTUN_E_IO && test.destroys == 1u);
    CHECK(ftun_core_get_info(core, &info) == FTUN_OK && info.state == FTUN_CORE_CREATED);
    test.run_returned = 0;
    status = ftun_core_run(core, path);
    test.run_returned = 1;
    CHECK(test.prepares == 2u && test.activates == 1u);
  }
  CHECK(ftun_core_get_info(core, &info) == FTUN_OK);
  printf("app cleanup mode=%d status=%s state=%u cancels=%zu destroys=%zu\n",
    (int)mode, ftun_status_name(status), (unsigned int)info.state,
    test.cancels, test.destroys);
  if (mode == CANCEL_RETRY || mode == PREPARE_RETRY || mode == ABORT_RETRY ||
      mode == PLAN_FAILED || mode == BUDGET_HELD || mode == RUNTIME_HELD ||
      mode == CANCEL_IO) {
    CHECK(status == (mode == CANCEL_IO ? FTUN_E_IO : FTUN_OK) &&
          info.state == FTUN_CORE_STOPPED);
    if (mode == ABORT_RETRY) {
      CHECK(test.reload_callbacks == 1u && test.aborts == 3u && test.plans_destroyed == 1u);
    } else if (mode == PLAN_FAILED) {
      CHECK(test.reload_callbacks == 1u && test.plans_destroyed == 1u && test.aborts == 0u);
    } else CHECK(test.cancels == 2u && test.internal_callbacks == 1u);
  } else {
    ftun_app_control_snapshot_t snapshot;
    CHECK(status == FTUN_E_TIMEOUT && info.state == FTUN_CORE_STOPPING);
    CHECK(ftun_app_control_query(core, &snapshot) == FTUN_OK &&
      snapshot.run_returned && snapshot.run_result == FTUN_E_TIMEOUT &&
      !snapshot.runtime_stopped && !snapshot.events.closed &&
      snapshot.events.last.kind == FTUN_LIFECYCLE_STOP_FAILED &&
      snapshot.events.last.status == FTUN_E_TIMEOUT);
    CHECK(ftun_core_destroy(&core) == FTUN_E_AGAIN && core != NULL);
  }
  if (mode == PREPARE_BLOCKED) CHECK(test.activates == 0u && test.stops == 0u);
  if (mode == ACTIVATE_BLOCKED) CHECK(test.activates == 1u && test.stops != 0u);
  if (mode == BUDGET_HELD || mode == RUNTIME_HELD) {
    ftun_operation_t *rejected = NULL;
    ftun_core_t *retained = core;
    CHECK(ftun_core_destroy(&core) == FTUN_E_AGAIN && core == retained);
    CHECK(ftun_core_get_info(core, &info) == FTUN_OK &&
          info.state == FTUN_CORE_STOPPED && info.pending_operations == 0u);
    CHECK(ftun_core_post(core, reload_completed, NULL, &rejected) == FTUN_E_STALE &&
          rejected == NULL);
    CHECK(ftun_reservation_release(&test.held_reservation) == FTUN_OK);
#if defined(FTUN_TEST_PROXY)
    if (test.held_runtime != NULL) CHECK(ftun_runtime_release(&test.held_runtime) == FTUN_OK);
#endif
  }
  callbacks = test.reload_callbacks;
  if (mode == LATE_RELOAD) {
    ftun_budget_t *budget = NULL;
    ftun_budget_usage_t usage;
    uint64_t limit = now_ms() + 1000u;
    (void)pthread_mutex_lock(&test.mutex);
    test.allow_worker = 1;
    (void)pthread_cond_broadcast(&test.condition);
    (void)pthread_mutex_unlock(&test.mutex);
    while (now_ms() < limit) {
      CHECK(ftun_core_destroy(&core) == FTUN_E_AGAIN && core != NULL);
      CHECK(ftun_core_context_budget(core, &budget) == FTUN_OK);
      CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
      CHECK(test.prepared_config != NULL &&
        test.prepared_config->reservation != NULL &&
        test.prepared_config->plan != NULL &&
        test.prepared_config->plan->reservation != NULL);
      CHECK(usage.used >= test.prepared_config->owned_bytes +
        test.prepared_config->plan->owned_bytes);
      pause_ms(1);
      if (now_ms() + 950u >= limit) break;
    }
    CHECK(test.plans_destroyed == 0u);
    test.allow_plan = 1;
  }
  test.allow_cleanup = 1;
  {
    uint64_t limit = now_ms() + 1000u;
    do {
      status = ftun_core_destroy(&core);
      CHECK(status == FTUN_OK || status == FTUN_E_AGAIN);
      if (status == FTUN_E_AGAIN) pause_ms(1);
    } while (core != NULL && now_ms() < limit);
  }
  CHECK(core == NULL && test.reload_callbacks == callbacks && !test.failed);
  CHECK(test.late_wakeups == 0u);
  CHECK(test.destroys == (mode == PREPARE_RETRY ? 2u : 1u));
  if (mode == LATE_RELOAD) CHECK(test.plans_destroyed == 1u);
  CHECK(pthread_cond_destroy(&test.condition) == 0);
  CHECK(pthread_mutex_destroy(&test.mutex) == 0);
  return 0;
}

int main(void)
{
  char path[] = "/tmp/ftun-app-cleanup-XXXXXX";
  const char config[] = "{\"base\":{\"state-cache\":false},"
    "\"log\":{\"level\":\"silent\"},\"dns\":{\"enable\":false}}";
  int descriptor_fd = mkstemp(path);
  int mode;
  CHECK(descriptor_fd >= 0);
  CHECK(write(descriptor_fd, config, sizeof(config) - 1u) == (ssize_t)sizeof(config) - 1);
  CHECK(close(descriptor_fd) == 0);
  for (mode = CANCEL_RETRY; mode <= RUNTIME_HELD; mode++) {
#if !defined(FTUN_TEST_PROXY)
    if (mode == RUNTIME_HELD) continue;
#endif
    CHECK(scenario((app_mode_t)mode, path) == 0);
  }
  CHECK(unlink(path) == 0);
  puts("app cleanup: stop, prepare, reload, late-result and final-reference scenarios passed");
  return 0;
}
