#define _POSIX_C_SOURCE 200809L

#include "core/core.h"

#include "config/config.h"
#include "config/compile.h"
#include "config/model.h"
#include "config/parser.h"
#include "core/budget.h"
#include "core/operation.h"
#include "core/worker.h"
#include "util/time.h"

#include <stddef.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define FTUN_SERVICE_DEFAULT_MEMORY (64u * 1024u * 1024u)
#define FTUN_SERVICE_MIN_MEMORY (1024u * 1024u)
#define FTUN_SERVICE_DEFAULT_OPERATIONS 1024u
#define FTUN_SERVICE_MIN_OPERATIONS 4u
#define FTUN_SERVICE_MAX_OPERATIONS 4096u
#define FTUN_SERVICE_DEFAULT_DESCRIPTORS 4096u
#define FTUN_SERVICE_MIN_DESCRIPTORS 16u
#define FTUN_SERVICE_DEFAULT_QUEUE_SLOTS 4096u
#define FTUN_SERVICE_MIN_QUEUE_SLOTS 64u
#define FTUN_SERVICE_DISPATCH_QUOTA 32u
#define FTUN_SERVICE_RELOAD_MAGIC UINT32_C(0x46545352)
#define FTUN_SERVICE_RELOAD_CAPACITY 1u
#define FTUN_SERVICE_TUN_MARK UINT32_C(0x4654)

typedef struct {
  uint32_t magic;
  uint32_t path_length;
  uint64_t base_generation;
  uintptr_t descriptor;
  uint32_t socket_mark;
} ftun_service_reload_work_t;

typedef struct {
  ftun_status_t status;
  uint32_t stage;
  uint64_t base_generation;
  uintptr_t config;
  ftun_core_service_plan_t service_plan;
} ftun_service_reload_result_t;

typedef struct {
  pthread_mutex_t mutex;
  ftun_budget_t *budget;
  ftun_operation_queue_t *operations;
  ftun_worker_t *reload_worker;
  const ftun_core_service_descriptor_t *descriptor;
  ftun_core_service_t service;
  ftun_core_t *core;
  ftun_config_t *active_config;
  ftun_completion_fn reload_callback;
  void *reload_user;
  uint64_t generation;
  uint64_t owner_rounds;
  uint64_t owner_max_busy_ms;
  uint64_t owner_max_deadline_lateness_ms;
  size_t owner_max_work;
  uint64_t owner_quota_exhaustions;
  uint64_t stop_deadline_ms;
  ftun_core_state_t state;
  bool owner_valid;
  bool stop_requested;
  bool reload_pending;
} ftun_service_control_t;

static int ftun_service_string_equal(const char *left, const char *right)
{
  if (left == NULL || right == NULL) return left == right;
  return strcmp(left, right) == 0;
}

static int ftun_service_tun_device_equal(const ftun_config_t *left,
                                          const ftun_config_t *right)
{
  if (left == NULL || right == NULL) return 0;
  return left->tun.present == right->tun.present &&
    (!left->tun.present ||
      (ftun_service_string_equal(left->tun.interface_name,
                                 right->tun.interface_name) &&
       ftun_service_string_equal(left->tun.ipv4_address,
                                 right->tun.ipv4_address) &&
       left->tun.mtu == right->tun.mtu &&
       left->tun.auto_route == right->tun.auto_route &&
       left->tun.strict_route == right->tun.strict_route));
}

static ftun_status_t ftun_service_reload_compatible(
  const ftun_config_t *active, const ftun_config_t *next)
{
  const uint32_t roots = FTUN_BUILD_MODULE_PROXY | FTUN_BUILD_MODULE_DNS |
    FTUN_BUILD_MODULE_TUN;
  if (active == NULL || next == NULL || active->plan == NULL ||
      next->plan == NULL) return FTUN_E_INVALID;
  if (((active->plan->required_modules ^ next->plan->required_modules) &
       roots) != 0u) return FTUN_E_RESTART_REQUIRED;
  if ((active->plan->required_modules & FTUN_BUILD_MODULE_TUN) != 0u &&
      !ftun_service_tun_device_equal(active, next)) {
    return FTUN_E_RESTART_REQUIRED;
  }
  return FTUN_OK;
}

static void ftun_service_reload_result_release(
  ftun_service_reload_result_t *result)
{
  ftun_config_t *config;
  if (result == NULL) return;
  config = (ftun_config_t *)result->config;
  (void)ftun_core_service_plan_destroy(&result->service_plan);
  (void)ftun_config_destroy(&config);
  memset(result, 0, sizeof(*result));
}

static void ftun_service_reload_result_cleanup(ftun_bytes_t bytes)
{
  ftun_service_reload_result_t result;
  if (bytes.data == NULL || bytes.length != sizeof(result)) return;
  memcpy(&result, bytes.data, sizeof(result));
  ftun_service_reload_result_release(&result);
}

static ftun_status_t ftun_service_reload_execute(
  ftun_bytes_t input, uint8_t *output, size_t output_capacity,
  size_t *out_output_size)
{
  const ftun_service_reload_work_t *work;
  const ftun_core_service_descriptor_t *descriptor;
  const char *path;
  ftun_service_reload_result_t result;
  ftun_config_t *config = NULL;
  ftun_status_t status;
  if (out_output_size != NULL) *out_output_size = 0u;
  if (input.data == NULL || input.length < sizeof(*work) || output == NULL ||
      output_capacity < sizeof(result) || out_output_size == NULL) {
    return FTUN_E_INVALID;
  }
  work = (const ftun_service_reload_work_t *)input.data;
  if (work->magic != FTUN_SERVICE_RELOAD_MAGIC || work->path_length == 0u ||
      work->descriptor == 0u ||
      input.length != sizeof(*work) + (size_t)work->path_length + 1u ||
      input.data[input.length - 1u] != 0u) return FTUN_E_INVALID;
  descriptor = (const ftun_core_service_descriptor_t *)work->descriptor;
  path = (const char *)(input.data + sizeof(*work));
  memset(&result, 0, sizeof(result));
  result.stage = FTUN_STAGE_CONFIG_READ;
  result.base_generation = work->base_generation;
  status = ftun_config_load(NULL, path, &config);
  if (status == FTUN_OK) {
    result.stage = FTUN_STAGE_CONFIG_PREPARE;
    status = ftun_core_service_plan_prepare(descriptor, config,
      work->socket_mark, &result.service_plan);
  }
  result.status = status;
  result.config = (uintptr_t)config;
  memcpy(output, &result, sizeof(result));
  *out_output_size = sizeof(result);
  return FTUN_OK;
}

static void ftun_service_reload_wakeup(void *user)
{
  ftun_service_control_t *control = (ftun_service_control_t *)user;
  if (control != NULL && control->service.implementation != NULL) {
    (void)ftun_core_service_wakeup(&control->service);
  }
}

static ftun_status_t ftun_service_control(
  ftun_core_t *core, ftun_service_control_t **out)
{
  void *value = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_core_context_control(core, &value);
  if (status != FTUN_OK || value == NULL) return FTUN_E_INVALID;
  *out = (ftun_service_control_t *)value;
  return FTUN_OK;
}

ftun_status_t ftun_core_create_with_service(
  const ftun_core_options_t *options,
  const ftun_core_service_descriptor_t *descriptor,
  ftun_core_t **out)
{
  const size_t minimum = offsetof(ftun_core_options_t, operation_capacity);
  ftun_budget_options_t budget_options;
  ftun_service_control_t *control = NULL;
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  size_t memory_limit;
  size_t descriptor_limit = FTUN_SERVICE_DEFAULT_DESCRIPTORS;
  size_t queue_limit = FTUN_SERVICE_DEFAULT_QUEUE_SLOTS;
  size_t operation_capacity = FTUN_SERVICE_DEFAULT_OPERATIONS;
  bool mutex_initialized = false;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (options == NULL || out == NULL || options->struct_size < minimum ||
      options->abi_version != FTUN_ABI_VERSION ||
      !ftun_core_service_descriptor_valid(descriptor)) {
    return FTUN_E_INVALID;
  }
  memory_limit = options->owned_memory_limit == 0u
    ? FTUN_SERVICE_DEFAULT_MEMORY : options->owned_memory_limit;
  if (options->struct_size >= offsetof(ftun_core_options_t,
      operation_capacity) + sizeof(options->operation_capacity) &&
      options->operation_capacity != 0u) {
    operation_capacity = options->operation_capacity;
  }
  if (options->struct_size >= offsetof(ftun_core_options_t,
      owned_descriptor_limit) + sizeof(options->owned_descriptor_limit) &&
      options->owned_descriptor_limit != 0u) {
    descriptor_limit = options->owned_descriptor_limit;
  }
  if (options->struct_size >= offsetof(ftun_core_options_t,
      owned_queue_limit) + sizeof(options->owned_queue_limit) &&
      options->owned_queue_limit != 0u) {
    queue_limit = options->owned_queue_limit;
  }
  if (memory_limit < FTUN_SERVICE_MIN_MEMORY ||
      descriptor_limit < FTUN_SERVICE_MIN_DESCRIPTORS ||
      queue_limit < FTUN_SERVICE_MIN_QUEUE_SLOTS ||
      operation_capacity < FTUN_SERVICE_MIN_OPERATIONS ||
      operation_capacity > FTUN_SERVICE_MAX_OPERATIONS) {
    return FTUN_E_LIMIT;
  }
  memset(&budget_options, 0, sizeof(budget_options));
  budget_options.limit.memory_bytes = memory_limit;
  budget_options.limit.descriptors = descriptor_limit;
  budget_options.limit.queue_slots = queue_limit;
  budget_options.cleanup_reserve.memory_bytes = memory_limit / 64u;
  if (budget_options.cleanup_reserve.memory_bytes < 64u * 1024u) {
    budget_options.cleanup_reserve.memory_bytes = 64u * 1024u;
  }
  if (budget_options.cleanup_reserve.memory_bytes > 1024u * 1024u) {
    budget_options.cleanup_reserve.memory_bytes = 1024u * 1024u;
  }
  budget_options.cleanup_reserve.descriptors = 4u;
  budget_options.cleanup_reserve.queue_slots = 8u;
  status = ftun_budget_create_resources(NULL, &budget_options, &budget);
  if (status == FTUN_OK) status = ftun_core_context_create(budget, &core);
  if (status != FTUN_OK) goto fail;
  control = (ftun_service_control_t *)calloc(1u, sizeof(*control));
  if (control == NULL) {
    status = FTUN_E_LIMIT;
    goto fail;
  }
  if (pthread_mutex_init(&control->mutex, NULL) != 0) {
    status = FTUN_E_IO;
    goto fail;
  }
  mutex_initialized = true;
  status = ftun_operation_queue_create(
    budget, operation_capacity, &control->operations);
  if (status != FTUN_OK) goto fail;
  control->budget = budget;
  control->descriptor = descriptor;
  control->core = core;
  control->state = FTUN_CORE_CREATED;
  control->stop_deadline_ms = UINT64_MAX;
  status = ftun_core_context_set_control(core, control);
  if (status != FTUN_OK) goto fail;
  *out = core;
  return FTUN_OK;

fail:
  if (core != NULL) (void)ftun_core_context_set_control(core, NULL);
  if (control != NULL) {
    (void)ftun_operation_queue_destroy(&control->operations);
    if (mutex_initialized) (void)pthread_mutex_destroy(&control->mutex);
    free(control);
  }
  (void)ftun_core_context_destroy(&core);
  (void)ftun_budget_destroy(&budget);
  return status;
}

static void ftun_service_reset_start_failure(ftun_service_control_t *control)
{
  (void)pthread_mutex_lock(&control->mutex);
  control->state = FTUN_CORE_CREATED;
  control->owner_valid = false;
  control->stop_requested = false;
  control->stop_deadline_ms = UINT64_MAX;
  (void)pthread_mutex_unlock(&control->mutex);
}

static void ftun_service_reload_completed(
  ftun_operation_t *operation, ftun_error_t error, ftun_bytes_t bytes,
  void *user)
{
  ftun_service_control_t *control = (ftun_service_control_t *)user;
  ftun_service_reload_result_t prepared;
  ftun_config_t *next = NULL;
  ftun_config_t *previous = NULL;
  ftun_completion_fn callback = NULL;
  void *callback_user = NULL;
  ftun_error_t result;
  bool deliver = false;
  bool service_prepared = false;
  uint64_t next_generation = 0u;
  memset(&prepared, 0, sizeof(prepared));
  memset(&result, 0, sizeof(result));
  result.status = error.status;
  result.stage = FTUN_STAGE_CONFIG_READ;
  if (result.status == FTUN_OK && bytes.data != NULL &&
      bytes.length == sizeof(prepared)) {
    memcpy(&prepared, bytes.data, sizeof(prepared));
    next = (ftun_config_t *)prepared.config;
    prepared.config = 0u;
    memset((void *)bytes.data, 0, bytes.length);
    result.status = prepared.status;
    result.stage = prepared.stage;
  } else if (result.status == FTUN_OK) {
    result.status = FTUN_E_STATE_CORRUPT;
  }
  (void)pthread_mutex_lock(&control->mutex);
  if (control->state != FTUN_CORE_RUNNING || control->stop_requested) {
    if (result.status == FTUN_OK) result.status = FTUN_E_CANCELLED;
  } else if (result.status == FTUN_OK &&
             prepared.base_generation != control->generation) {
    result.status = FTUN_E_STALE;
  }
  if (result.status == FTUN_OK) {
    result.status = ftun_service_reload_compatible(
      control->active_config, next);
  }
  if (result.status == FTUN_OK && control->generation == UINT64_MAX) {
    result.status = FTUN_E_LIMIT;
  }
  if (result.status == FTUN_OK) next_generation = control->generation + 1u;
  (void)pthread_mutex_unlock(&control->mutex);
  if (result.status == FTUN_OK) {
    result.stage = FTUN_STAGE_CONFIG_PREPARE;
    result.status = ftun_core_service_reload_prepare_planned(
      &control->service, next, next_generation,
      &prepared.service_plan);
    service_prepared = result.status == FTUN_OK;
  }
  if (result.status == FTUN_OK) {
    (void)pthread_mutex_lock(&control->mutex);
    if (control->state != FTUN_CORE_RUNNING || control->stop_requested ||
        control->generation + 1u != next_generation) {
      result.status = FTUN_E_CANCELLED;
    }
    (void)pthread_mutex_unlock(&control->mutex);
  }
  if (result.status == FTUN_OK) {
    result.stage = FTUN_STAGE_COMMIT;
    result.status = ftun_core_service_reload_commit(
      &control->service, next_generation);
  }
  if (result.status == FTUN_OK) {
    (void)pthread_mutex_lock(&control->mutex);
    previous = control->active_config;
    control->active_config = next;
    next = NULL;
    control->generation = next_generation;
    (void)ftun_core_context_set_generation(control->core,
                                            control->generation);
    (void)pthread_mutex_unlock(&control->mutex);
    service_prepared = false;
  } else if (service_prepared) {
    (void)ftun_core_service_reload_abort(&control->service);
  }
  (void)ftun_core_service_plan_destroy(&prepared.service_plan);
  (void)ftun_config_destroy(&previous);
  (void)ftun_config_destroy(&next);
  (void)pthread_mutex_lock(&control->mutex);
  callback = control->reload_callback;
  callback_user = control->reload_user;
  deliver = control->state == FTUN_CORE_RUNNING && !control->stop_requested;
  control->reload_callback = NULL;
  control->reload_user = NULL;
  control->reload_pending = false;
  (void)pthread_mutex_unlock(&control->mutex);
  if (deliver && callback != NULL) callback(operation, result, callback_user);
}

static ftun_status_t ftun_service_worker_stop_until(
  ftun_service_control_t *control, uint64_t deadline_ms)
{
  ftun_status_t status;
  if (control == NULL || control->reload_worker == NULL) return FTUN_OK;
  status = ftun_worker_stop(control->reload_worker);
  if (status == FTUN_OK) {
    status = ftun_worker_join_until(control->reload_worker, deadline_ms);
  }
  if (status != FTUN_OK) return status;
  for (;;) {
    ftun_worker_usage_t usage;
    size_t callbacks = 0u;
    status = ftun_worker_poll(control->reload_worker, SIZE_MAX, &callbacks);
    if (status != FTUN_OK) return status;
    status = ftun_worker_get_usage(control->reload_worker, &usage);
    if (status != FTUN_OK || usage.tasks == 0u) return status;
    if (callbacks == 0u) return FTUN_E_STATE_CORRUPT;
  }
}

ftun_status_t ftun_core_run(ftun_core_t *core, const char *path)
{
  ftun_service_control_t *control = NULL;
  ftun_config_t *config = NULL;
  uint64_t deadline_ms = UINT64_MAX;
  ftun_status_t status;
  if (core == NULL || path == NULL || path[0] == '\0') return FTUN_E_INVALID;
  status = ftun_service_control(core, &control);
  if (status != FTUN_OK) return status;
  (void)pthread_mutex_lock(&control->mutex);
  if (control->state != FTUN_CORE_CREATED) {
    (void)pthread_mutex_unlock(&control->mutex);
    return FTUN_E_STALE;
  }
  control->state = FTUN_CORE_STARTING;
  control->owner_valid = true;
  control->stop_requested = false;
  control->stop_deadline_ms = UINT64_MAX;
  (void)pthread_mutex_unlock(&control->mutex);
  status = ftun_config_load(core, path, &config);
  if (status == FTUN_OK) {
    status = ftun_core_service_prepare(&control->service,
      control->descriptor, core, control->budget, control->operations,
      NULL, config, 1u);
  }
  if (status == FTUN_OK) {
    status = ftun_core_service_activate(&control->service);
  }
  if (status == FTUN_OK) {
    status = ftun_worker_create(control->budget,
      FTUN_SERVICE_RELOAD_CAPACITY, &control->reload_worker);
  }
  if (status == FTUN_OK) {
    status = ftun_worker_set_wakeup(control->reload_worker,
      ftun_service_reload_wakeup, control);
  }
  if (status != FTUN_OK) {
    if (control->reload_worker != NULL) {
      (void)ftun_worker_stop(control->reload_worker);
      (void)ftun_worker_join(control->reload_worker);
      (void)ftun_worker_destroy(&control->reload_worker);
    }
    (void)ftun_core_service_destroy(&control->service);
    (void)ftun_config_destroy(&config);
    ftun_service_reset_start_failure(control);
    return status;
  }
  control->active_config = config;
  config = NULL;
  control->generation = 1u;
  (void)ftun_core_context_set_generation(core, 1u);
  (void)pthread_mutex_lock(&control->mutex);
  control->state = FTUN_CORE_RUNNING;
  (void)pthread_mutex_unlock(&control->mutex);
  for (;;) {
    ftun_core_service_run_usage_t usage;
    uint64_t started_ms = 0u;
    uint64_t finished_ms = 0u;
    size_t reload_callbacks = 0u;
    size_t dispatched = 0u;
    bool stop_requested;
    bool has_ready;
    (void)pthread_mutex_lock(&control->mutex);
    stop_requested = control->stop_requested;
    (void)pthread_mutex_unlock(&control->mutex);
    if (stop_requested) break;
    status = ftun_worker_poll(control->reload_worker, 1u,
                              &reload_callbacks);
    if (status != FTUN_OK) break;
    has_ready = reload_callbacks != 0u ||
      ftun_worker_has_ready(control->reload_worker) ||
      ftun_operation_queue_has_ready(control->operations);
    (void)ftun_monotonic_now(&started_ms);
    status = ftun_core_service_run_once(
      &control->service, !has_ready, &usage);
    (void)ftun_monotonic_now(&finished_ms);
    if (status == FTUN_OK) {
      status = ftun_operation_dispatch(control->operations,
        FTUN_SERVICE_DISPATCH_QUOTA, &dispatched);
    }
    (void)pthread_mutex_lock(&control->mutex);
    if (control->owner_rounds != UINT64_MAX) control->owner_rounds++;
    if (finished_ms >= started_ms &&
        finished_ms - started_ms > control->owner_max_busy_ms) {
      control->owner_max_busy_ms = finished_ms - started_ms;
    }
    if (usage.deadline_lateness_ms >
        control->owner_max_deadline_lateness_ms) {
      control->owner_max_deadline_lateness_ms = usage.deadline_lateness_ms;
    }
    if (usage.work + dispatched + reload_callbacks >
        control->owner_max_work) {
      control->owner_max_work = usage.work + dispatched + reload_callbacks;
    }
    if ((usage.quota_exhausted ||
         dispatched == FTUN_SERVICE_DISPATCH_QUOTA ||
         reload_callbacks == 1u) &&
        control->owner_quota_exhaustions != UINT64_MAX) {
      control->owner_quota_exhaustions++;
    }
    if (status != FTUN_OK) control->stop_requested = true;
    (void)pthread_mutex_unlock(&control->mutex);
    if (status != FTUN_OK) break;
  }
  (void)pthread_mutex_lock(&control->mutex);
  control->state = FTUN_CORE_STOPPING;
  deadline_ms = control->stop_deadline_ms;
  (void)pthread_mutex_unlock(&control->mutex);
  {
    ftun_status_t worker_status = ftun_service_worker_stop_until(
      control, deadline_ms);
    if (worker_status != FTUN_OK && status == FTUN_OK) status = worker_status;
  }
  (void)ftun_operation_queue_stop(control->operations);
  if (status != FTUN_OK) {
    (void)pthread_mutex_lock(&control->mutex);
    control->owner_valid = false;
    (void)pthread_mutex_unlock(&control->mutex);
    return status;
  }
  {
    ftun_status_t stop_status = ftun_core_service_stop_until(
      &control->service, deadline_ms);
    if (stop_status != FTUN_OK && status == FTUN_OK) status = stop_status;
  }
  for (;;) {
    ftun_operation_queue_usage_t usage;
    size_t dispatched = 0u;
    if (ftun_operation_dispatch(control->operations,
        FTUN_SERVICE_DISPATCH_QUOTA, &dispatched) != FTUN_OK ||
        ftun_operation_queue_get_usage(control->operations, &usage) != FTUN_OK ||
        usage.inflight == 0u) break;
  }
  {
    ftun_status_t destroy_status = ftun_core_service_destroy_until(
      &control->service, deadline_ms);
    if (destroy_status != FTUN_OK && status == FTUN_OK) {
      status = destroy_status;
    }
  }
  if (control->service.implementation == NULL) {
    ftun_status_t cleanup_status = ftun_config_destroy(
      &control->active_config);
    if (cleanup_status == FTUN_OK) {
      cleanup_status = ftun_worker_destroy(&control->reload_worker);
    }
    if (cleanup_status != FTUN_OK && status == FTUN_OK) {
      status = cleanup_status;
    }
  }
  (void)pthread_mutex_lock(&control->mutex);
  control->state = control->service.implementation == NULL &&
    control->reload_worker == NULL && control->active_config == NULL
    ? FTUN_CORE_STOPPED : FTUN_CORE_STOPPING;
  control->owner_valid = false;
  (void)pthread_mutex_unlock(&control->mutex);
  return status;
}

ftun_status_t ftun_core_stop(ftun_core_t *core, uint64_t deadline_ms)
{
  ftun_service_control_t *control = NULL;
  uint64_t now_ms = 0u;
  ftun_status_t status = ftun_service_control(core, &control);
  if (status != FTUN_OK) return status;
  status = ftun_monotonic_now(&now_ms);
  if (status != FTUN_OK) return status;
  if (deadline_ms < now_ms) return FTUN_E_TIMEOUT;
  (void)pthread_mutex_lock(&control->mutex);
  if (control->state == FTUN_CORE_STOPPED) {
    (void)pthread_mutex_unlock(&control->mutex);
    return FTUN_OK;
  }
  if (control->state != FTUN_CORE_STARTING &&
      control->state != FTUN_CORE_RUNNING) {
    (void)pthread_mutex_unlock(&control->mutex);
    return FTUN_E_STALE;
  }
  control->stop_requested = true;
  if (deadline_ms < control->stop_deadline_ms) {
    control->stop_deadline_ms = deadline_ms;
  }
  if (control->service.implementation != NULL) {
    (void)ftun_core_service_wakeup(&control->service);
  }
  (void)pthread_mutex_unlock(&control->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_core_post(ftun_core_t *core, ftun_completion_fn callback,
                             void *user, ftun_operation_t **out)
{
  ftun_service_control_t *control = NULL;
  ftun_operation_token_t completion;
  ftun_operation_t *operation = NULL;
  ftun_error_t result;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core == NULL || callback == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_service_control(core, &control);
  if (status != FTUN_OK) return status;
  (void)pthread_mutex_lock(&control->mutex);
  if (control->state != FTUN_CORE_RUNNING || control->stop_requested) {
    (void)pthread_mutex_unlock(&control->mutex);
    return FTUN_E_STALE;
  }
  status = ftun_operation_accept(control->operations, callback, user,
                                  &operation, &completion);
  if (status == FTUN_OK) {
    memset(&result, 0, sizeof(result));
    result.status = FTUN_OK;
    result.stage = FTUN_STAGE_CONTROL;
    status = ftun_operation_complete(completion, result);
  }
  if (status == FTUN_OK && control->service.implementation != NULL) {
    (void)ftun_core_service_wakeup(&control->service);
  }
  (void)pthread_mutex_unlock(&control->mutex);
  if (status != FTUN_OK) {
    if (operation != NULL) (void)ftun_operation_reject(&operation);
    return status;
  }
  *out = operation;
  return FTUN_OK;
}

ftun_status_t ftun_core_reload(ftun_core_t *core, const char *path,
                               ftun_completion_fn callback, void *user,
                               ftun_operation_t **out)
{
  ftun_service_control_t *control = NULL;
  ftun_service_reload_work_t *work;
  ftun_worker_job_t job;
  ftun_operation_t *operation = NULL;
  uint8_t *input;
  size_t path_length;
  size_t input_length;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core == NULL || path == NULL || path[0] == '\0' || callback == NULL ||
      out == NULL) return FTUN_E_INVALID;
  path_length = strlen(path);
  if (path_length > FTUN_CONFIG_MAX_PATH_BYTES || path_length > UINT32_MAX ||
      path_length > SIZE_MAX - sizeof(*work) - 1u) return FTUN_E_LIMIT;
  status = ftun_service_control(core, &control);
  if (status != FTUN_OK) return status;
  input_length = sizeof(*work) + path_length + 1u;
  input = (uint8_t *)calloc(1u, input_length);
  if (input == NULL) return FTUN_E_LIMIT;
  work = (ftun_service_reload_work_t *)input;
  work->magic = FTUN_SERVICE_RELOAD_MAGIC;
  work->path_length = (uint32_t)path_length;
  work->descriptor = (uintptr_t)control->descriptor;
  memcpy(input + sizeof(*work), path, path_length + 1u);
  memset(&job, 0, sizeof(job));
  job.execute = ftun_service_reload_execute;
  job.input = (ftun_bytes_t){input, input_length};
  job.result_capacity = sizeof(ftun_service_reload_result_t);
  job.accounted_extra = 4u * FTUN_CONFIG_MAX_JSON_BYTES;
  job.result_cleanup = ftun_service_reload_result_cleanup;
  (void)pthread_mutex_lock(&control->mutex);
  if (control->state != FTUN_CORE_RUNNING || control->stop_requested) {
    status = FTUN_E_STALE;
  } else if (control->reload_pending) {
    status = FTUN_E_AGAIN;
  } else {
    work->base_generation = control->generation;
    if (control->active_config != NULL &&
        control->active_config->plan != NULL &&
        (control->active_config->plan->required_modules &
         FTUN_BUILD_MODULE_TUN) != 0u) {
      work->socket_mark = FTUN_SERVICE_TUN_MARK;
    }
    control->reload_callback = callback;
    control->reload_user = user;
    control->reload_pending = true;
    status = ftun_worker_submit(control->reload_worker, &job,
      ftun_service_reload_completed, control, &operation);
    if (status != FTUN_OK) {
      control->reload_callback = NULL;
      control->reload_user = NULL;
      control->reload_pending = false;
    }
  }
  (void)pthread_mutex_unlock(&control->mutex);
  free(input);
  if (status != FTUN_OK) return status;
  *out = operation;
  return FTUN_OK;
}

ftun_status_t ftun_core_select(ftun_core_t *core, const char *group_name,
                               const char *member_name,
                               ftun_completion_fn callback, void *user,
                               ftun_operation_t **out)
{
  (void)core;
  (void)group_name;
  (void)member_name;
  (void)callback;
  (void)user;
  if (out != NULL) *out = NULL;
  return FTUN_E_UNSUPPORTED;
}

ftun_status_t ftun_core_get_info(ftun_core_t *core, ftun_core_info_t *out)
{
  ftun_service_control_t *control = NULL;
  ftun_operation_queue_usage_t usage;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (core == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_service_control(core, &control);
  if (status != FTUN_OK) return status;
  (void)pthread_mutex_lock(&control->mutex);
  out->state = control->state;
  out->generation = control->generation;
  out->owner_rounds = control->owner_rounds;
  out->owner_max_busy_ms = control->owner_max_busy_ms;
  out->owner_max_deadline_lateness_ms =
    control->owner_max_deadline_lateness_ms;
  out->owner_max_work = control->owner_max_work;
  out->owner_quota_exhaustions = control->owner_quota_exhaustions;
  (void)pthread_mutex_unlock(&control->mutex);
  status = ftun_operation_queue_get_usage(control->operations, &usage);
  if (status != FTUN_OK) {
    memset(out, 0, sizeof(*out));
    return status;
  }
  out->pending_operations = usage.inflight;
  return FTUN_OK;
}

ftun_status_t ftun_core_destroy(ftun_core_t **core)
{
  ftun_core_t *owned;
  ftun_service_control_t *control = NULL;
  ftun_budget_t *budget;
  ftun_core_state_t state;
  uint64_t now_ms = 0u;
  ftun_status_t status;
  if (core == NULL) return FTUN_E_INVALID;
  owned = *core;
  if (owned == NULL) return FTUN_OK;
  status = ftun_service_control(owned, &control);
  if (status != FTUN_OK) return status;
  (void)pthread_mutex_lock(&control->mutex);
  state = control->state;
  if (state != FTUN_CORE_CREATED && state != FTUN_CORE_STOPPED &&
      !(state == FTUN_CORE_STOPPING && !control->owner_valid)) {
    (void)pthread_mutex_unlock(&control->mutex);
    return FTUN_E_AGAIN;
  }
  (void)pthread_mutex_unlock(&control->mutex);
  if (state == FTUN_CORE_STOPPING) {
    status = ftun_monotonic_now(&now_ms);
    if (status != FTUN_OK) return status;
    status = ftun_service_worker_stop_until(control, now_ms);
    if (status == FTUN_E_TIMEOUT) return FTUN_E_AGAIN;
    if (status != FTUN_OK) return status;
    if (control->service.implementation != NULL) {
      status = ftun_core_service_stop_until(&control->service, now_ms);
      if (status == FTUN_E_TIMEOUT) return FTUN_E_AGAIN;
      if (status != FTUN_OK) return status;
      status = ftun_core_service_destroy_until(&control->service, now_ms);
      if (status == FTUN_E_TIMEOUT) return FTUN_E_AGAIN;
      if (status != FTUN_OK) return status;
    }
    (void)ftun_config_destroy(&control->active_config);
    status = ftun_worker_destroy(&control->reload_worker);
    if (status != FTUN_OK) return status;
    (void)pthread_mutex_lock(&control->mutex);
    control->state = FTUN_CORE_STOPPED;
    (void)pthread_mutex_unlock(&control->mutex);
  }
  budget = control->budget;
  status = ftun_core_service_destroy(&control->service);
  if (status != FTUN_OK) return status;
  status = ftun_operation_queue_destroy(&control->operations);
  if (status != FTUN_OK) return status;
  (void)ftun_core_context_set_control(owned, NULL);
  status = ftun_core_context_destroy(core);
  if (status != FTUN_OK) {
    (void)ftun_core_context_set_control(owned, control);
    return status;
  }
  (void)pthread_mutex_destroy(&control->mutex);
  free(control);
  return ftun_budget_destroy(&budget);
}
