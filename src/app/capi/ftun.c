#define _POSIX_C_SOURCE 200809L

#include "platform/process.h"
#include "platform/file.h"
#include "app/runtime_internal.h"
#include "proxy/diagnostics.h"


ftun_app_cleanup_t ftun_core_cleanup(ftun_core_control_t *control)
{
  ftun_app_cleanup_t cleanup = {&control->mutex, &control->stop_deadline_ms,
                               &control->cleanup_error};
  return cleanup;
}

ftun_status_t ftun_core_control(ftun_core_t *core,
                                       ftun_core_control_t **out)
{
  void *value = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_core_context_control(core, &value);
  if (status != FTUN_OK || value == NULL) return FTUN_E_INVALID;
  *out = (ftun_core_control_t *)value;
  return FTUN_OK;
}

/* 运行配置代次唯一保存在 Core 上下文，宿主不再维护影子计数。 */
uint64_t ftun_core_generation_now(const ftun_core_control_t *control)
{
  uint64_t generation = 0u;
  (void)ftun_core_context_generation(control->core, &generation);
  return generation;
}

/* 宿主事务以 Core 上下文自身为预留持有者。业务提交可能已消费该预留
 * （Proxy Runtime 提交即发布）；仍持有时由宿主发布。两种情况结束后当前
 * 代次都必须等于 next。 */
ftun_status_t ftun_core_generation_settle(ftun_core_t *core,
                                                 uint64_t next)
{
  uint64_t held = 0u;
  uint64_t current = 0u;
  ftun_status_t status = ftun_core_context_generation_held(core, core, &held);
  if (status == FTUN_OK && held == next) {
    status = ftun_core_context_generation_publish(core, core, next);
  } else if (status == FTUN_E_STALE) {
    status = FTUN_OK;
  }
  if (status == FTUN_OK) status = ftun_core_context_generation(core, &current);
  if (status == FTUN_OK && current != next) status = FTUN_E_STATE_CORRUPT;
  return status;
}

void ftun_core_event(ftun_core_control_t *control,
  ftun_lifecycle_kind_t kind, uint64_t generation, ftun_status_t status)
{
  ftun_lifecycle_event_t item = {0};
  item.kind = kind;
  item.generation = generation;
  item.status = status;
  /* 同一次 reload 的请求/提交/拒绝/取消事件共用一个关联 ID。 */
  if (kind == FTUN_LIFECYCLE_RELOAD_REQUESTED) control->reload_correlation = ftun_correlation_next();
  if (kind == FTUN_LIFECYCLE_RELOAD_REQUESTED || kind == FTUN_LIFECYCLE_RELOAD_COMMITTED ||
      kind == FTUN_LIFECYCLE_RELOAD_REJECTED || kind == FTUN_LIFECYCLE_RELOAD_CANCELLED) {
    item.correlation = control->reload_correlation;
  }
  (void)ftun_lifecycle_emit(control->core, &item);
}

void ftun_core_config_trace(ftun_core_control_t *control,
  const ftun_config_trace_t *trace, uint64_t generation)
{
  ftun_mutex_lock(&control->mutex);
  control->config_trace = *trace;
  control->config_trace_generation = generation;
  ftun_mutex_unlock(&control->mutex);
  ftun_config_trace_emit(control->core, trace, generation);
}

static char *ftun_core_copy_string(const char *value)
{
  size_t length;
  char *copy;
  if (value == NULL) return NULL;
  length = strnlen(value, FTUN_CORE_CONTROL_STRING + 1u);
  if (length == 0u || length > FTUN_CORE_CONTROL_STRING) return NULL;
  copy = (char *)malloc(length + 1u);
  if (copy != NULL) memcpy(copy, value, length + 1u);
  return copy;
}

/* 路径副本随候选和活动配置转移；任务内已计量的字符串仍用原复制函数。 */
ftun_status_t ftun_core_owned_path_copy(ftun_budget_t *budget,
  const char *value, ftun_core_owned_path_t *out)
{
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_status_t status;
  size_t length;
  char *copy;
  if (budget == NULL || value == NULL || out == NULL) return FTUN_E_INVALID;
  if (out->value != NULL || (out->reservation).budget != NULL) return FTUN_E_AGAIN;
  length = strnlen(value, FTUN_CORE_CONTROL_STRING + 1u);
  if (length == 0u || length > FTUN_CORE_CONTROL_STRING) return FTUN_E_LIMIT;
  status = ftun_budget_reserve(budget, length + 1u, &reservation);
  if (status != FTUN_OK) return status;
  copy = (char *)malloc(length + 1u);
  if (copy == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  memcpy(copy, value, length + 1u);
  out->value = copy;
  out->reservation = reservation;
  return FTUN_OK;
}

ftun_status_t ftun_core_owned_path_destroy(ftun_core_owned_path_t *path)
{
  if (path == NULL) return FTUN_E_INVALID;
  ftun_reservation_release(&path->reservation);
  free(path->value);
  path->value = NULL;
  return FTUN_OK;
}

ftun_status_t ftun_core_prepare_parent(const char *path)
{
  char *copy;
  char *cursor;
  if (path == NULL || path[0] != '/') return FTUN_E_INVALID;
  copy = strdup(path);
  if (copy == NULL) return FTUN_E_LIMIT;
  cursor = strrchr(copy, '/');
  if (cursor == NULL || cursor == copy) {
    free(copy);
    return FTUN_OK;
  }
  *cursor = '\0';
  for (cursor = copy + 1u; ; cursor++) {
    if (*cursor != '/' && *cursor != '\0') continue;
    {
      char saved = *cursor;
      *cursor = '\0';
      if (ftun_directory_ensure(copy, 0700) != FTUN_OK) {
        free(copy);
        return FTUN_E_IO;
      }
      *cursor = saved;
      if (saved == '\0') break;
    }
  }
  free(copy);
  return FTUN_OK;
}

ftun_status_t ftun_core_logger_create(const ftun_config_t *config,
                                              ftun_log_ledger_t *ledger,
                                              ftun_logger_t **out)
{
  ftun_logger_options_t options;
  ftun_log_level_t level;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (config == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_log_level_parse(config->log.level, &level);
  if (status != FTUN_OK) return status;
  if (level == FTUN_LOG_SILENT) return FTUN_OK;
  status = ftun_core_prepare_parent(config->log.file);
  if (status != FTUN_OK) return status;
  memset(&options, 0, sizeof(options));
  options.level = level;
  options.path = config->log.file;
  options.max_size = config->log.max_size;
  options.max_files = config->log.max_files;
  options.queue_capacity = 128u;
  options.stamp = true;
  options.line_capacity = 1024u;
  options.ledger = ledger;
  return ftun_logger_create(&options, out);
}

ftun_status_t ftun_core_logger_reap(ftun_core_control_t *control,
                                           uint64_t deadline_ms)
{
  if (control == NULL) return FTUN_E_INVALID;
  return ftun_logger_destroy_until(&control->retired_logger, deadline_ms);
}

ftun_status_t ftun_core_logger_retire(ftun_core_control_t *control,
                                             ftun_logger_t **logger)
{
  ftun_status_t status;
  if (control == NULL || logger == NULL) return FTUN_E_INVALID;
  if (*logger == NULL) return FTUN_OK;
  if (control->retired_logger != NULL) return FTUN_E_AGAIN;
  control->retired_logger = *logger;
  *logger = NULL;
  status = ftun_logger_stop(control->retired_logger);
  return status;
}

static size_t ftun_core_default_descriptor_limit(void)
{
  return ftun_platform_descriptor_limit(FTUN_CORE_DEFAULT_DESCRIPTORS);
}

static size_t ftun_core_control_operation_reserve(size_t capacity)
{
  size_t reserve;
  if (capacity < 4u) return 0u;
  reserve = capacity / 8u;
  if (reserve == 0u) reserve = 1u;
  if (reserve > 16u) reserve = 16u;
  return reserve;
}

ftun_status_t ftun_core_create_with_service(
  const ftun_core_options_t *options,
  const ftun_core_service_descriptor_t *descriptor,
  ftun_core_t **out)
{
  const size_t minimum = offsetof(ftun_core_options_t, operation_capacity);
  ftun_core_control_t *control = NULL;
  ftun_budget_t *root_budget = NULL;
  ftun_budget_t *budget = NULL;
  ftun_budget_t *data_budget = NULL;
  ftun_core_t *core = NULL;
  ftun_reservation_t control_reservation = (ftun_reservation_t){0};
  ftun_budget_usage_t context_usage;
  ftun_budget_options_t root_options;
  ftun_budget_options_t control_options;
  ftun_budget_options_t data_options;
  size_t memory_limit;
  size_t descriptor_limit = ftun_core_default_descriptor_limit();
  size_t queue_limit = FTUN_CORE_DEFAULT_QUEUE_SLOTS;
  size_t operation_capacity = FTUN_CORE_DEFAULT_OPERATIONS;
  size_t retained_limit = FTUN_CORE_DEFAULT_RETAINED;
  size_t retained_bytes_limit;
  size_t operation_control_reserve;
  size_t control_bytes;
  int mutex_initialized = 0;
  int condition_initialized = 0;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (options == NULL || out == NULL || options->struct_size < minimum ||
      !ftun_core_service_descriptor_valid(descriptor) ||
      options->abi_version != FTUN_ABI_VERSION) return FTUN_E_INVALID;
  memory_limit = options->owned_memory_limit == 0u
    ? FTUN_CORE_DEFAULT_MEMORY : options->owned_memory_limit;
  retained_bytes_limit = memory_limit / 2u;
  if (options->struct_size >= offsetof(ftun_core_options_t, operation_capacity) +
      sizeof(options->operation_capacity) && options->operation_capacity != 0u) {
    operation_capacity = options->operation_capacity;
  }
  if (options->struct_size >= offsetof(ftun_core_options_t,
      retained_runtime_limit) + sizeof(options->retained_runtime_limit) &&
      options->retained_runtime_limit != 0u) {
    retained_limit = options->retained_runtime_limit;
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
  if (options->struct_size >= offsetof(ftun_core_options_t,
      retained_runtime_bytes_limit) +
      sizeof(options->retained_runtime_bytes_limit) &&
      options->retained_runtime_bytes_limit != 0u) {
    retained_bytes_limit = options->retained_runtime_bytes_limit;
  }
  if (operation_capacity < FTUN_CORE_MIN_OPERATIONS ||
      operation_capacity > FTUN_CORE_MAX_OPERATIONS ||
      memory_limit < FTUN_CORE_MIN_MEMORY ||
      descriptor_limit < FTUN_CORE_MIN_DESCRIPTORS ||
      queue_limit < FTUN_CORE_MIN_QUEUE_SLOTS) return FTUN_E_LIMIT;
  operation_control_reserve =
    ftun_core_control_operation_reserve(operation_capacity);
  memset(&root_options, 0, sizeof(root_options));
  root_options.limit = (ftun_budget_resources_t){
    memory_limit, descriptor_limit, queue_limit
  };
  root_options.cleanup_reserve.memory_bytes = memory_limit / 64u;
  if (root_options.cleanup_reserve.memory_bytes < 64u * 1024u) {
    root_options.cleanup_reserve.memory_bytes = 64u * 1024u;
  }
  if (root_options.cleanup_reserve.memory_bytes > 1024u * 1024u) {
    root_options.cleanup_reserve.memory_bytes = 1024u * 1024u;
  }
  root_options.cleanup_reserve.descriptors = 4u;
  root_options.cleanup_reserve.queue_slots = 8u;
  memset(&control_options, 0, sizeof(control_options));
  control_options.limit = root_options.limit;
  control_options.cleanup_reserve = root_options.cleanup_reserve;
  control_options.guarantee.memory_bytes =
    (memory_limit - root_options.cleanup_reserve.memory_bytes) / 8u;
  if (control_options.guarantee.memory_bytes > 8u * 1024u * 1024u) {
    control_options.guarantee.memory_bytes = 8u * 1024u * 1024u;
  }
  control_options.guarantee.descriptors =
    (descriptor_limit - root_options.cleanup_reserve.descriptors) / 4u;
  if (control_options.guarantee.descriptors > 8u) {
    control_options.guarantee.descriptors = 8u;
  }
  control_options.guarantee.queue_slots =
    (queue_limit - root_options.cleanup_reserve.queue_slots) / 4u;
  if (control_options.guarantee.queue_slots > 32u) {
    control_options.guarantee.queue_slots = 32u;
  }
  memset(&data_options, 0, sizeof(data_options));
  data_options.limit = root_options.limit;
  data_options.guarantee.memory_bytes =
    (memory_limit - root_options.cleanup_reserve.memory_bytes) / 2u;
  data_options.guarantee.descriptors =
    (descriptor_limit - root_options.cleanup_reserve.descriptors) / 2u;
  data_options.guarantee.queue_slots =
    (queue_limit - root_options.cleanup_reserve.queue_slots) / 2u;
  status = ftun_budget_create_resources(NULL, &root_options, &root_budget);
  if (status == FTUN_OK) {
    status = ftun_budget_create_resources(root_budget, &control_options,
                                          &budget);
  }
  if (status == FTUN_OK) {
    status = ftun_budget_create_resources(root_budget, &data_options,
                                          &data_budget);
  }
  if (status != FTUN_OK) goto fail;
  status = ftun_core_context_create(budget, &core);
  /* 尚未发布 Core，独立预算中目前仅有 context 自身预留。保留这个
   * 基线，最终清理只允许它与 control/tasks 存活，拒绝遗留借用者。 */
  if (status == FTUN_OK) status = ftun_budget_get_usage(budget, &context_usage);
  if (status == FTUN_OK && ftun_app_runtime_support() != NULL) {
    status = ftun_app_runtime_support()->attach(core, retained_limit,
                                                retained_bytes_limit);
  }
  if (status != FTUN_OK) goto fail;
  control_bytes = sizeof(*control) + operation_capacity * sizeof(*control->tasks);
  status = ftun_budget_reserve(budget, control_bytes, &control_reservation);
  if (status != FTUN_OK) goto fail;
  control = (ftun_core_control_t *)calloc(1u, sizeof(*control));
  if (control == NULL) {
    status = FTUN_E_LIMIT;
    goto fail;
  }
  control->tasks = (ftun_control_task_t **)calloc(
    operation_capacity, sizeof(*control->tasks));
  if (control->tasks == NULL) {
    status = FTUN_E_LIMIT;
    goto fail;
  }
  if (ftun_mutex_init(&control->mutex) != FTUN_OK) {
    status = FTUN_E_IO;
    goto fail;
  }
  mutex_initialized = 1;
  if (ftun_condition_init(&control->condition) != FTUN_OK) {
    status = FTUN_E_IO;
    goto fail;
  }
  condition_initialized = 1;
  status = ftun_operation_queue_create_reserved(
    budget, operation_capacity, operation_control_reserve,
    &control->operations);
  if (status != FTUN_OK) {
    goto fail;
  }
  control->root_budget = root_budget;
  control->reservation = control_reservation;
  control->bootstrap_bytes = context_usage.used_resources.memory_bytes + control_bytes;
  control->budget = budget;
  control->data_budget = data_budget;
  control->service_descriptor = descriptor;
  control->support = ftun_app_runtime_support();
  control->core = core;
  control->task_capacity = operation_capacity;
  control->task_control_reserve = operation_control_reserve;
  control->state = FTUN_CORE_CREATED;
  control->stop_deadline_ms = UINT64_MAX;
  status = ftun_event_log_create(budget, &control->events);
  if (status == FTUN_OK) {
    static const struct { uint32_t bit; const char *name; } names[] = {
      {0u, "app"}, {FTUN_BUILD_MODULE_CORE, "core"}, {FTUN_BUILD_MODULE_DNS, "dns"},
      {FTUN_BUILD_MODULE_TUN, "tun"}, {FTUN_BUILD_MODULE_FRS, "frs"},
      {FTUN_BUILD_MODULE_FAKEIP, "fakeip"}, {FTUN_BUILD_MODULE_PROXY, "proxy"}
    };
    size_t index;
    for (index = 0u; status == FTUN_OK && index < sizeof(names) / sizeof(names[0]); index++) {
      status = ftun_event_log_module_name(control->events, names[index].bit, names[index].name);
    }
  }
  if (status == FTUN_OK) status = ftun_event_log_reason_name(control->events,
    FTUN_LIFECYCLE_REASON_FRS_UPDATE, "frs-update");
  if (status == FTUN_OK) status = ftun_log_ledger_create(budget, &control->log_ledger);
  if (status == FTUN_OK) status = ftun_core_context_set_event_log(core, control->events);
  if (status != FTUN_OK) goto fail;
  status = ftun_core_context_set_control(core, control);
  if (status != FTUN_OK) goto fail;
  *out = core;
  return FTUN_OK;

fail:
  if (control != NULL) {
    if (core != NULL) (void)ftun_core_context_set_event_log(core, NULL);
    (void)ftun_event_log_destroy(&control->events);
    if (control->reload_worker != NULL) {
      (void)ftun_worker_stop(control->reload_worker);
      (void)ftun_worker_join(control->reload_worker);
      (void)ftun_worker_destroy(&control->reload_worker);
    }
    if (control->state_worker != NULL) {
      (void)ftun_worker_stop(control->state_worker);
      (void)ftun_worker_join(control->state_worker);
      (void)ftun_worker_destroy(&control->state_worker);
    }
    (void)ftun_log_ledger_destroy(&control->log_ledger);
    (void)ftun_operation_queue_destroy(&control->operations);
    if (condition_initialized) {
      ftun_condition_destroy(&control->condition);
    }
    if (mutex_initialized) ftun_mutex_destroy(&control->mutex);
    free(control->tasks);
    free(control);
  }
  ftun_reservation_release(&control_reservation);
  if (core != NULL && ftun_app_runtime_support() != NULL) {
    (void)ftun_app_runtime_support()->clear(core);
  }
  (void)ftun_core_context_destroy(&core);
  (void)ftun_budget_destroy(&data_budget);
  (void)ftun_budget_destroy(&budget);
  (void)ftun_budget_destroy(&root_budget);
  return status;
}

static ftun_status_t ftun_control_task_cancel(void *user)
{
  ftun_control_task_t *task = (ftun_control_task_t *)user;
  ftun_operation_t *prepare_operation;
  if (task == NULL) return FTUN_E_INVALID;
  ftun_mutex_lock(&task->mutex);
  task->cancelled = 1;
  prepare_operation = task->prepare_operation;
  ftun_mutex_unlock(&task->mutex);
  if (prepare_operation != NULL) {
    ftun_status_t status = ftun_operation_cancel(prepare_operation);
    if (status != FTUN_OK && status != FTUN_E_STALE) return status;
  }
  return FTUN_OK;
}

void ftun_control_task_destroy(ftun_control_task_t *task)
{
  ftun_reservation_t reservation;
  if (task == NULL) return;
  reservation = task->reservation;
  task->reservation = (ftun_reservation_t){0};
  ftun_mutex_destroy(&task->mutex);
  free(task->first);
  free(task->second);
  free(task);
  ftun_reservation_release(&reservation);
}

void ftun_control_task_consumed(ftun_control_task_t *task)
{
  int destroy;
  if (task == NULL) return;
  ftun_mutex_lock(&task->mutex);
  task->ring_consumed = 1;
  destroy = task->callback_complete &&
    (!task->async_started || task->async_complete);
  ftun_mutex_unlock(&task->mutex);
  if (destroy) ftun_control_task_destroy(task);
}

static void ftun_control_task_complete(ftun_operation_t *operation,
                                       ftun_error_t result, void *user)
{
  ftun_control_task_t *task = (ftun_control_task_t *)user;
  int destroy;
  ftun_core_control_t *control = NULL;
  bool deliver = false;
  if (ftun_core_control(task->core, &control) == FTUN_OK) {
    ftun_mutex_lock(&control->mutex);
    deliver = control->callbacks_enabled && control->owner_valid;
    ftun_mutex_unlock(&control->mutex);
    if (task->kind == FTUN_CONTROL_RELOAD && result.status == FTUN_E_CANCELLED) {
      ftun_core_reload_event(task, control, result.status);
    }
  }
  if (deliver && task->command_completion != NULL) {
    ftun_app_command_result_t value;
    memset(&value, 0, sizeof(value));
    value.kind = task->kind == FTUN_CONTROL_RELOAD ?
      FTUN_APP_COMMAND_RELOAD : FTUN_APP_COMMAND_SELECT;
    value.phase = result.status == FTUN_OK ? FTUN_APP_COMMAND_COMPLETED :
      (result.status == FTUN_E_CANCELLED ? FTUN_APP_COMMAND_CANCELLED : FTUN_APP_COMMAND_FAILED);
    value.error = result;
    value.generation = task->result_generation;
    if (value.generation == 0u) {
      ftun_mutex_lock(&control->mutex);
      value.generation = ftun_core_generation_now(control);
      ftun_mutex_unlock(&control->mutex);
    }
    task->command_completion(operation, value, task->completion_user);
  } else if (deliver) task->completion(operation, result, task->completion_user);
  ftun_mutex_lock(&task->mutex);
  task->callback_complete = 1;
  destroy = task->ring_consumed &&
    (!task->async_started || task->async_complete);
  ftun_mutex_unlock(&task->mutex);
  if (destroy) ftun_control_task_destroy(task);
}

static ftun_status_t ftun_core_submit(ftun_core_t *core,
                                      ftun_control_kind_t kind,
                                      const char *first, const char *second,
                                      ftun_completion_fn completion, void *user,
                                      ftun_operation_t **out,
                                      const ftun_app_generation_guard_t *expected,
                                      ftun_app_command_completion_fn command_completion)
{
  ftun_core_control_t *control = NULL;
  ftun_control_task_t *task = NULL;
  ftun_operation_t *operation = NULL;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  size_t charge = sizeof(*task);
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core == NULL || (completion == NULL && command_completion == NULL) || out == NULL ||
      (kind != FTUN_CONTROL_POST &&
       (first == NULL || first[0] == '\0')) ||
      (kind == FTUN_CONTROL_SELECT &&
       (second == NULL || second[0] == '\0'))) return FTUN_E_INVALID;
  status = ftun_core_control(core, &control);
  if (status != FTUN_OK) return status;
  if (kind == FTUN_CONTROL_SELECT && control->support == NULL) {
    return FTUN_E_UNSUPPORTED;
  }
  ftun_mutex_lock(&control->mutex);
  if (control->state != FTUN_CORE_RUNNING || control->stop_requested) {
    ftun_mutex_unlock(&control->mutex);
    return FTUN_E_STALE;
  }
  ftun_mutex_unlock(&control->mutex);
  if (first != NULL) {
    size_t length = strnlen(first, FTUN_CORE_CONTROL_STRING + 1u);
    if (length == 0u || length > FTUN_CORE_CONTROL_STRING ||
        length + 1u > SIZE_MAX - charge) return FTUN_E_LIMIT;
    charge += length + 1u;
  }
  if (second != NULL) {
    size_t length = strnlen(second, FTUN_CORE_CONTROL_STRING + 1u);
    if (length == 0u || length > FTUN_CORE_CONTROL_STRING ||
        length + 1u > SIZE_MAX - charge) return FTUN_E_LIMIT;
    charge += length + 1u;
  }
  status = kind == FTUN_CONTROL_POST
    ? ftun_budget_reserve(control->budget, charge, &reservation)
    : ftun_budget_reserve_cleanup(control->budget, charge, &reservation);
  if (status != FTUN_OK) return status;
  task = (ftun_control_task_t *)calloc(1u, sizeof(*task));
  if (task == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  task->reservation = reservation;
  task->control_priority = kind != FTUN_CONTROL_POST;
  if (ftun_mutex_init(&task->mutex) != FTUN_OK) {
    task->reservation = (ftun_reservation_t){0};
    free(task);
    ftun_reservation_release(&reservation);
    return FTUN_E_IO;
  }
  if (first != NULL) task->first = ftun_core_copy_string(first);
  if (second != NULL) task->second = ftun_core_copy_string(second);
  if ((first != NULL && task->first == NULL) ||
      (second != NULL && task->second == NULL)) {
    status = FTUN_E_LIMIT;
    goto fail;
  }
  task->core = core;
  task->completion = completion;
  task->command_completion = command_completion;
  if (expected != NULL) task->expected = *expected;
  task->completion_user = user;
  task->kind = kind;
  ftun_mutex_lock(&control->mutex);
  if (control->state != FTUN_CORE_RUNNING || control->stop_requested) {
    ftun_mutex_unlock(&control->mutex);
    status = FTUN_E_STALE;
    goto fail;
  }
  if (task->expected.present && task->expected.generation != ftun_core_generation_now(control)) {
    ftun_mutex_unlock(&control->mutex);
    status = FTUN_E_STALE;
    goto fail;
  }
  if (control->task_count >= control->task_capacity ||
      (!task->control_priority && control->normal_task_count >=
        control->task_capacity - control->task_control_reserve)) {
    ftun_mutex_unlock(&control->mutex);
    status = FTUN_E_LIMIT;
    goto fail;
  }
  if (kind == FTUN_CONTROL_RELOAD &&
      (control->reload_pending || control->retired_busy)) {
    ftun_mutex_unlock(&control->mutex);
    status = FTUN_E_AGAIN;
    goto fail;
  }
  status = task->control_priority
    ? ftun_operation_accept_control(control->operations,
        ftun_control_task_complete, task, &operation,
        &task->completion_token)
    : ftun_operation_accept(control->operations,
        ftun_control_task_complete, task, &operation,
        &task->completion_token);
  if (status == FTUN_OK) {
    status = ftun_operation_set_cancel_hook(operation,
                                             ftun_control_task_cancel, task);
  }
  if (status != FTUN_OK) {
    if (operation != NULL) (void)ftun_operation_reject(&operation);
    ftun_mutex_unlock(&control->mutex);
    goto fail;
  }
  task->operation = operation;
  control->tasks[control->task_tail] = task;
  control->task_tail = (control->task_tail + 1u) % control->task_capacity;
  control->task_count++;
  if (!task->control_priority) control->normal_task_count++;
  if (kind == FTUN_CONTROL_RELOAD) {
    control->reload_pending = 1;
    ftun_core_event(control, FTUN_LIFECYCLE_RELOAD_REQUESTED, ftun_core_generation_now(control), FTUN_OK);
  }
  if (control->service.implementation != NULL) {
    (void)ftun_core_service_wakeup(&control->service);
  }
  ftun_condition_signal(&control->condition);
  ftun_mutex_unlock(&control->mutex);
  *out = operation;
  return FTUN_OK;

fail:
  ftun_control_task_destroy(task);
  return status;
}

ftun_status_t ftun_core_post(ftun_core_t *core, ftun_completion_fn callback,
                             void *user, ftun_operation_t **out)
{
  return ftun_core_submit(core, FTUN_CONTROL_POST, NULL, NULL,
                          callback, user, out, NULL, NULL);
}

static ftun_status_t ftun_core_reload_admission(ftun_core_t *core, ftun_status_t status)
{
  ftun_core_control_t *control = NULL;
  if (status != FTUN_OK && ftun_core_control(core, &control) == FTUN_OK) {
    ftun_lifecycle_event_t event = {0};
    event.kind = FTUN_LIFECYCLE_RELOAD_REJECTED;
    event.reason = FTUN_LIFECYCLE_REASON_ADMISSION;
    event.status = status;
    /* 接纳入口可跨线程；代次与发布在 control 锁内捕获。 */
    ftun_mutex_lock(&control->mutex);
    if (control->lifecycle_started) {
      event.generation = ftun_core_generation_now(control);
      (void)ftun_lifecycle_emit(core, &event);
    }
    ftun_mutex_unlock(&control->mutex);
  }
  return status;
}

ftun_status_t ftun_core_reload(ftun_core_t *core, const char *path,
                               ftun_completion_fn callback, void *user,
                               ftun_operation_t **out)
{
  return ftun_core_reload_admission(core, ftun_core_submit(core, FTUN_CONTROL_RELOAD, path, NULL,
                          callback, user, out, NULL, NULL));
}

ftun_status_t ftun_core_select(ftun_core_t *core, const char *group_name,
                               const char *member_name,
                               ftun_completion_fn callback, void *user,
                               ftun_operation_t **out)
{
  return ftun_core_submit(core, FTUN_CONTROL_SELECT, group_name, member_name,
                          callback, user, out, NULL, NULL);
}

ftun_status_t ftun_app_control_submit(ftun_core_t *core,
  const ftun_app_command_t *command, ftun_app_command_completion_fn completion,
  void *user, ftun_operation_t **out)
{
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (command == NULL || completion == NULL || out == NULL ||
      (command->kind != FTUN_APP_COMMAND_RELOAD && command->kind != FTUN_APP_COMMAND_SELECT) ||
      (command->kind == FTUN_APP_COMMAND_RELOAD && command->second != NULL)) return FTUN_E_INVALID;
  status = ftun_core_submit(core, command->kind == FTUN_APP_COMMAND_RELOAD ?
    FTUN_CONTROL_RELOAD : FTUN_CONTROL_SELECT, command->first, command->second,
    NULL, user, out, &command->expected, completion);
  return command->kind == FTUN_APP_COMMAND_RELOAD ? ftun_core_reload_admission(core, status) : status;
}

int ftun_control_task_cancelled(ftun_control_task_t *task)
{
  int cancelled;
  ftun_mutex_lock(&task->mutex);
  cancelled = task->cancelled;
  ftun_mutex_unlock(&task->mutex);
  return cancelled;
}

static void ftun_core_process_task(ftun_core_t *core,
                                   ftun_core_control_t *control,
                                   ftun_control_task_t *task)
{
  ftun_error_t result;
  ftun_status_t status = FTUN_OK;
  uint32_t stage = FTUN_STAGE_CONTROL;
  memset(&result, 0, sizeof(result));
  if (ftun_control_task_cancelled(task)) {
    if (task->kind == FTUN_CONTROL_RELOAD) {
      ftun_mutex_lock(&control->mutex);
      control->reload_pending = 0;
      ftun_mutex_unlock(&control->mutex);
    }
    return;
  }
  if (task->expected.present && task->expected.generation != ftun_core_generation_now(control)) {
    status = FTUN_E_STALE;
    goto completed;
  }
  if (task->kind == FTUN_CONTROL_RELOAD) {
    const ftun_config_t *active = control->active_config;
    if (active != NULL && active->base.proxy.state_cache) {
      ftun_status_t save_status = ftun_core_state_schedule(
        core, control, active->base.proxy.cache_file, 0u);
      if (save_status != FTUN_OK) {
        ftun_core_log_status(core, save_status, FTUN_STAGE_STATE_RESTORE,
                             FTUN_DIAGNOSTIC_STATE_SAVE, control->support->state_failure_message);
      }
    }
    status = ftun_core_reload_schedule(control, task);
    if (status == FTUN_OK) return;
  } else if (task->kind == FTUN_CONTROL_SELECT) {
    status = control->support->select(core,
      (ftun_string_t){task->first, strlen(task->first)},
      (ftun_string_t){task->second, strlen(task->second)});
    if (status == FTUN_OK) {
      const ftun_config_t *active = control->active_config;
      if (active != NULL && active->base.proxy.state_cache) {
        ftun_status_t save_status = ftun_core_state_schedule(
          core, control, active->base.proxy.cache_file, 0u);
        if (save_status != FTUN_OK) {
          ftun_core_log_status(core, save_status, FTUN_STAGE_STATE_RESTORE,
                               FTUN_DIAGNOSTIC_STATE_SAVE, control->support->state_failure_message);
        }
      }
    }
  }
completed:
  task->result_generation = ftun_core_generation_now(control);
  if (status != FTUN_OK) {
    ftun_core_log_status(core, status, stage, FTUN_DIAGNOSTIC_CONTROL, "control operation failed");
  }
  result.status = status;
  result.stage = stage;
  if (task->kind == FTUN_CONTROL_RELOAD) {
    ftun_core_reload_event(task, control, status);
    ftun_mutex_lock(&control->mutex);
    control->reload_pending = 0;
    ftun_mutex_unlock(&control->mutex);
  }
  (void)ftun_operation_complete(task->completion_token, result);
}

/* 服务级故障后的恢复门：尝试即“允许恢复运行”，同步结束。 */
/* 看门狗线程调用：不得阻塞也不得等待 control->mutex。拿不到锁说明 owner
 * 正在处理或已卡住，跳过这次唤醒即可，心跳判定不依赖唤醒成功。 */
static void ftun_core_watchdog_wake(void *user)
{
  ftun_core_control_t *control = (ftun_core_control_t *)user;
  if (!ftun_mutex_trylock(&control->mutex)) return;
  if (control->state == FTUN_CORE_RUNNING &&
      control->service.implementation != NULL) {
    (void)ftun_core_service_wakeup(&control->service);
  }
  ftun_mutex_unlock(&control->mutex);
}

static ftun_status_t ftun_core_watchdog_open(ftun_core_control_t *control)
{
  ftun_watchdog_spec_t spec;
  ftun_watchdog_owner_t owner;
  ftun_status_t status;
  memset(&spec, 0, sizeof(spec));
  spec.timeout_ms = control->active_config->base.watchdog_ms;
  spec.stop_ms = FTUN_CORE_WATCHDOG_STOP_MS;
  spec.grace_ms = FTUN_CORE_WATCHDOG_GRACE_MS;
  spec.arm_alarm = true;
  spec.diagnostic_fd = ftun_file_standard_error();
  status = ftun_watchdog_create(&spec, &control->watchdog);
  if (status != FTUN_OK || control->watchdog == NULL) return status;
  owner.wake = ftun_core_watchdog_wake;
  owner.context = control;
  status = ftun_watchdog_register(control->watchdog, &owner,
                                  &control->watchdog_slot);
  if (status != FTUN_OK) (void)ftun_watchdog_destroy(&control->watchdog);
  return status;
}

static ftun_status_t ftun_core_recovery_attempt(void *user, ftun_recovery_id_t id)
{
  ftun_core_control_t *control = (ftun_core_control_t *)user;
  uint64_t now_ms = 0u;
  (void)ftun_monotonic_now(&now_ms);
  return ftun_recovery_attempt_finish(control->recovery, id, now_ms, FTUN_OK,
                                      FTUN_RECOVERY_FAULT_NETWORK);
}

static ftun_status_t ftun_core_recovery_open(ftun_core_control_t *control)
{
  ftun_recovery_policy_t policy;
  ftun_recovery_spec_t spec;
  uint64_t now_ms = 0u;
  ftun_status_t status;
  if (control->service_descriptor == NULL ||
      control->service_descriptor->maintain_once == NULL) return FTUN_OK;
  (void)ftun_monotonic_now(&now_ms);
  memset(&policy, 0, sizeof(policy));
  policy.initial_ms = FTUN_CORE_SERVICE_RETRY_INITIAL_MS;
  policy.maximum_ms = FTUN_CORE_SERVICE_RETRY_MAXIMUM_MS;
  policy.stable_ms = FTUN_CORE_SERVICE_RETRY_STABLE_MS;
  policy.jitter_permille = 200u;
  policy.auth_retry_ms = FTUN_CORE_SERVICE_RETRY_MAXIMUM_MS;
  policy.seed = now_ms;
  memset(&spec, 0, sizeof(spec));
  spec.kind = 1u;
  spec.attempt = ftun_core_recovery_attempt;
  spec.user = control;
  status = ftun_recovery_scheduler_create(control->budget, 1u, &policy,
                                          &control->recovery);
  if (status == FTUN_OK) {
    status = ftun_recovery_entity_register(control->recovery, &spec, now_ms,
                                           &control->recovery_id);
  }
  if (status != FTUN_OK) {
    (void)ftun_recovery_scheduler_destroy(&control->recovery);
  }
  return status;
}

static void ftun_core_recovery_close(ftun_core_control_t *control)
{
  if (control->recovery == NULL) return;
  ftun_recovery_scheduler_stop(control->recovery);
  (void)ftun_recovery_scheduler_destroy(&control->recovery);
}

/* 一轮服务运行。只有 STATE_CORRUPT 或 usage.fatal 返回错误让宿主停机；
 * 其他错误都是服务级故障：计数、记录，并在服务支持时暂停新业务，
 * 由 maintain_once 继续驱动恢复，按 A0 退避后再恢复 run_once。 */
static ftun_status_t ftun_core_service_round(ftun_core_t *core,
  ftun_core_control_t *control, bool may_block, uint64_t now_ms,
  ftun_core_service_run_usage_t *usage)
{
  ftun_recovery_info_t info;
  size_t resumed = 0u;
  bool paused = false;
  ftun_status_t status;
  size_t scope;
  if (control->recovery != NULL) {
    (void)ftun_recovery_run(control->recovery, now_ms, 1u, &resumed);
    paused = ftun_recovery_query(control->recovery, 0u, &info) == FTUN_OK &&
             info.state != FTUN_RECOVERY_AVAILABLE;
  }
  ftun_mutex_lock(&control->mutex);
  control->service_paused = paused;
  ftun_mutex_unlock(&control->mutex);
  status = paused
    ? ftun_core_service_maintain_once(&control->service, now_ms,
                                      FTUN_CORE_MAINTAIN_QUOTA, usage)
    : ftun_core_service_run_once(&control->service, may_block, usage);
  ftun_mutex_lock(&control->mutex);
  for (scope = 0u; scope < FTUN_FAULT_SCOPE_COUNT; scope++) {
    control->service_faults[scope] += usage->faults[scope];
  }
  if (status != FTUN_OK && !ftun_core_service_run_fatal(status, usage)) {
    control->service_faults[FTUN_FAULT_SCOPE_SERVICE]++;
  }
  ftun_mutex_unlock(&control->mutex);
  if (ftun_core_service_run_fatal(status, usage)) {
    ftun_core_log_status(core, status == FTUN_OK ? FTUN_E_STATE_CORRUPT : status,
      FTUN_STAGE_CONTROL, FTUN_DIAGNOSTIC_SERVICE_RUN,
      "production data plane failed");
    return status == FTUN_OK ? FTUN_E_STATE_CORRUPT : status;
  }
  if (status != FTUN_OK) {
    ftun_core_log_status(core, status, FTUN_STAGE_CONTROL,
      FTUN_DIAGNOSTIC_SERVICE_FAULT, "service fault; continuing");
    if (control->recovery != NULL && !paused) {
      (void)ftun_recovery_report_failure(control->recovery,
        control->recovery_id, now_ms, FTUN_RECOVERY_FAULT_NETWORK);
      ftun_mutex_lock(&control->mutex);
      control->service_pauses++;
      ftun_mutex_unlock(&control->mutex);
    }
    /* 失败的服务不会阻塞，避免空转占满 CPU。 */
    ftun_thread_pause(1u);
  } else if (paused) {
    ftun_thread_pause(2u);
  }
  return FTUN_OK;
}

ftun_status_t ftun_core_run(ftun_core_t *core, const char *path)
{
  ftun_core_control_t *control = NULL;
  ftun_app_cleanup_t cleanup;
  uint32_t stage = FTUN_STAGE_CONFIG_READ;
  ftun_status_t status;
  if (core == NULL || path == NULL || path[0] == '\0') return FTUN_E_INVALID;
  status = ftun_core_control(core, &control);
  if (status != FTUN_OK) return status;
  cleanup = ftun_core_cleanup(control);
  ftun_mutex_lock(&control->mutex);
  if (control->state != FTUN_CORE_CREATED) {
    ftun_mutex_unlock(&control->mutex);
    return FTUN_E_STALE;
  }
  control->state = FTUN_CORE_STARTING;
  control->owner_valid = 1;
  control->callbacks_enabled = true;
  control->service_stopped = false;
  control->state_save_done = false;
  control->state_save_submitted = false;
  control->first_error = FTUN_OK;
  control->cleanup_error = FTUN_OK;
  control->stop_deadline_ms = UINT64_MAX;
  control->lifecycle_started = true;
  control->runtime_stopped = false;
  control->run_returned = false;
  control->run_result = FTUN_OK;
  ftun_mutex_unlock(&control->mutex);
  (void)ftun_event_log_begin(control->events);
  ftun_core_event(control, FTUN_LIFECYCLE_STARTING, ftun_core_generation_now(control), FTUN_OK);
  /* Create owner-side workers only after the caller has entered run().  The
   * CLI blocks its control signals immediately before this call, so workers
   * inherit the same mask and SIGHUP remains dedicated to sigwait(). */
  /* 一个 reload 最多包含 prepare/publish 两阶段；prepare 回调提交 publish
   * 时自身槽尚未 dispose。接纳门仍只允许一个事务，交接最多占两个槽。 */
  status = ftun_worker_create(control->budget, 2u,
                              &control->reload_worker);
  if (status == FTUN_OK && control->support != NULL) {
    status = ftun_worker_create(control->budget,
      FTUN_CORE_STATE_WORKER_CAPACITY, &control->state_worker);
  }
  if (status == FTUN_OK) {
    status = ftun_worker_set_wakeup(control->reload_worker,
                                    ftun_core_reload_wakeup, control);
  }
  if (status == FTUN_OK && control->state_worker != NULL) {
    status = ftun_worker_set_wakeup(control->state_worker,
                                    ftun_core_reload_wakeup, control);
  }
  if (status == FTUN_OK) status = ftun_core_recovery_open(control);
  if (status == FTUN_OK) {
    status = ftun_core_transaction(core, control, path, &stage);
  }
  if (status == FTUN_OK) status = ftun_core_watchdog_open(control);
  if (status != FTUN_OK) {
    ftun_status_t cleanup_status;
    ftun_core_recovery_close(control);
    control->first_error = status;
    control->state_save_done = true;
    ftun_core_event(control, FTUN_LIFECYCLE_ROLLBACK, ftun_core_generation_now(control), status);
    ftun_mutex_lock(&control->mutex);
    control->state = FTUN_CORE_STOPPING;
    ftun_mutex_unlock(&control->mutex);
    ftun_app_cleanup_begin(&cleanup);
    cleanup_status = ftun_app_cleanup_drive(&cleanup, ftun_core_cleanup_step,
                                             control, true);
    if (cleanup_status != FTUN_OK) {
      ftun_core_event(control, FTUN_LIFECYCLE_STOP_FAILED, ftun_core_generation_now(control), cleanup_status);
    }
    if (cleanup_status == FTUN_OK) {
      cleanup_status = ftun_operation_queue_reopen(control->operations);
    }
    ftun_mutex_lock(&control->mutex);
    if (cleanup_status == FTUN_OK) {
      control->state = FTUN_CORE_CREATED;
      control->stop_requested = 0;
    }
    control->owner_valid = 0;
    control->callbacks_enabled = false;
    control->run_returned = true;
    control->run_result = cleanup_status == FTUN_E_TIMEOUT ? cleanup_status : status;
    ftun_mutex_unlock(&control->mutex);
    return cleanup_status == FTUN_E_TIMEOUT ? cleanup_status : status;
  }
  ftun_mutex_lock(&control->mutex);
  control->state = FTUN_CORE_RUNNING;
  ftun_core_event(control, FTUN_LIFECYCLE_RUNNING, ftun_core_generation_now(control), FTUN_OK);
  ftun_watchdog_ready(control->watchdog);
  while (!control->stop_requested) {
    ftun_core_service_run_usage_t service_usage;
    ftun_control_task_t *task = NULL;
    uint64_t round_started_ms = 0u;
    uint64_t before_engine_ms = 0u;
    uint64_t after_engine_ms = 0u;
    uint64_t round_finished_ms = 0u;
    uint64_t round_busy_ms = 0u;
    size_t reload_callbacks = 0u;
    size_t state_callbacks = 0u;
    size_t dispatched = 0u;
    size_t round_work = 0u;
    int pending_control = 0;
    bool may_block;
    bool quota_exhausted = false;
    bool cleanup_retry = false;
    memset(&service_usage, 0, sizeof(service_usage));
    if (ftun_watchdog_stop_requested(control->watchdog)) {
      control->stop_requested = 1;
      control->watchdog_fired = true;
    }
    if (control->stop_requested) break;
    if (control->task_count != 0u) {
      task = control->tasks[control->task_head];
      control->tasks[control->task_head] = NULL;
      control->task_head = (control->task_head + 1u) % control->task_capacity;
      control->task_count--;
      if (!task->control_priority) control->normal_task_count--;
    }
    pending_control = control->task_count != 0u;
    ftun_mutex_unlock(&control->mutex);
    (void)ftun_monotonic_now(&round_started_ms);
    if (task != NULL) {
      ftun_core_process_task(core, control, task);
      ftun_control_task_consumed(task);
      round_work++;
    }
    status = ftun_worker_poll(control->reload_worker, 1u,
                              &reload_callbacks);
    round_work += reload_callbacks;
    if (reload_callbacks == 1u) quota_exhausted = true;
    if (status != FTUN_OK) {
      ftun_core_log_status(core, status, FTUN_STAGE_CONTROL,
                           FTUN_DIAGNOSTIC_RELOAD_WORKER, "reload worker failed");
      if (status != FTUN_E_STATE_CORRUPT) status = FTUN_OK;
    }
    if (status == FTUN_OK && control->state_worker != NULL) {
      status = ftun_worker_poll(control->state_worker, 1u,
                                &state_callbacks);
      round_work += state_callbacks;
      if (state_callbacks == 1u) quota_exhausted = true;
      if (status != FTUN_OK) {
        ftun_core_log_status(core, status, FTUN_STAGE_STATE_RESTORE,
                             FTUN_DIAGNOSTIC_STATE_WORKER, "state worker failed");
        if (status != FTUN_E_STATE_CORRUPT) status = FTUN_OK;
      }
    }
    if (status == FTUN_OK && control->retired_busy) {
      uint64_t now_ms = 0u;
      ftun_status_t reap_status;
      (void)ftun_monotonic_now(&now_ms);
      reap_status = ftun_core_reload_reap(control, now_ms);
      ftun_app_cleanup_record(&cleanup, reap_status);
      cleanup_retry = reap_status != FTUN_OK;
      if (reap_status != FTUN_OK) {
        ftun_thread_pause(1u);
      }
    }
    may_block = task == NULL && reload_callbacks == 0u &&
      state_callbacks == 0u && !pending_control &&
      !ftun_operation_queue_has_ready(control->operations) &&
      !cleanup_retry;
    (void)ftun_monotonic_now(&before_engine_ms);
    if (status == FTUN_OK) {
      status = ftun_core_service_round(core, control, may_block,
                                       before_engine_ms, &service_usage);
    }
    (void)ftun_monotonic_now(&after_engine_ms);
    round_work += service_usage.work;
    if (service_usage.quota_exhausted) quota_exhausted = true;
    /* A callback may cancel a later queued task. Dispatching one completion
     * per removed task keeps that task's context alive until its ring entry
     * has also been consumed. */
    if (status == FTUN_OK) {
      status = ftun_operation_dispatch(control->operations,
        FTUN_CORE_OPERATION_DISPATCH_QUOTA, &dispatched);
      if (status != FTUN_OK && status != FTUN_E_STATE_CORRUPT) {
        ftun_core_log_status(core, status, FTUN_STAGE_CONTROL,
                             FTUN_DIAGNOSTIC_SERVICE_FAULT, "operation dispatch failed");
        status = FTUN_OK;
      }
    }
    round_work += dispatched;
    if (dispatched == FTUN_CORE_OPERATION_DISPATCH_QUOTA) {
      quota_exhausted = true;
    }
    if (status != FTUN_OK) {
      ftun_mutex_lock(&control->mutex);
      control->stop_requested = 1;
      break;
    }
    (void)ftun_monotonic_now(&round_finished_ms);
    if (before_engine_ms >= round_started_ms) {
      round_busy_ms = before_engine_ms - round_started_ms;
    }
    round_busy_ms += service_usage.busy_ms;
    if (round_finished_ms >= after_engine_ms) {
      round_busy_ms += round_finished_ms - after_engine_ms;
    }
    ftun_watchdog_ack(control->watchdog, control->watchdog_slot);
    ftun_mutex_lock(&control->mutex);
    if (control->owner_rounds != UINT64_MAX) control->owner_rounds++;
    if (round_busy_ms > control->owner_max_busy_ms) {
      control->owner_max_busy_ms = round_busy_ms;
    }
    if (service_usage.deadline_lateness_ms >
        control->owner_max_deadline_lateness_ms) {
      control->owner_max_deadline_lateness_ms =
        service_usage.deadline_lateness_ms;
    }
    if (round_work > control->owner_max_work) {
      control->owner_max_work = round_work;
    }
    if (quota_exhausted && control->owner_quota_exhaustions != UINT64_MAX) {
      control->owner_quota_exhaustions++;
    }
  }
  control->state = FTUN_CORE_STOPPING;
  control->first_error = status;
  ftun_mutex_unlock(&control->mutex);
  ftun_watchdog_stopping(control->watchdog);
  ftun_core_recovery_close(control);
  ftun_core_event(control, FTUN_LIFECYCLE_STOPPING, ftun_core_generation_now(control), status);
  ftun_app_cleanup_begin(&cleanup);
  {
    ftun_status_t cleanup_status = ftun_app_cleanup_drive(&cleanup,
      ftun_core_cleanup_step, control, true);
    if (cleanup_status != FTUN_OK) {
      ftun_core_event(control, FTUN_LIFECYCLE_STOP_FAILED, ftun_core_generation_now(control), cleanup_status);
    }
    if (cleanup_status == FTUN_E_TIMEOUT || status == FTUN_OK) {
      status = cleanup_status;
    }
    if (status == FTUN_OK) status = control->cleanup_error;
    ftun_mutex_lock(&control->mutex);
    control->state = cleanup_status == FTUN_OK
      ? FTUN_CORE_STOPPED : FTUN_CORE_STOPPING;
    control->owner_valid = 0;
    control->callbacks_enabled = false;
    control->run_returned = true;
    control->run_result = status;
    ftun_condition_broadcast(&control->condition);
    ftun_mutex_unlock(&control->mutex);
  }
  if (ftun_watchdog_fired(control->watchdog)) control->watchdog_fired = true;
  (void)ftun_watchdog_destroy(&control->watchdog);
  return status;
}

static ftun_status_t ftun_core_stop_request(ftun_core_t *core, uint64_t deadline_ms,
  const ftun_app_generation_guard_t *expected, ftun_app_command_result_t *out)
{
  ftun_core_control_t *control = NULL;
  uint64_t now_ms;
  ftun_status_t status;
  status = ftun_core_control(core, &control);
  if (status != FTUN_OK) return status;
  status = ftun_monotonic_now(&now_ms);
  if (status != FTUN_OK) return status;
  if (deadline_ms < now_ms) return FTUN_E_TIMEOUT;
  ftun_mutex_lock(&control->mutex);
  if (out != NULL) {
    out->generation = ftun_core_generation_now(control);
    out->phase = control->state == FTUN_CORE_STOPPED ?
      FTUN_APP_COMMAND_COMPLETED : FTUN_APP_COMMAND_REQUESTED;
  }
  if (expected != NULL && expected->present && expected->generation != ftun_core_generation_now(control)) {
    ftun_mutex_unlock(&control->mutex);
    return FTUN_E_STALE;
  }
  if (control->state == FTUN_CORE_STOPPED) {
    ftun_mutex_unlock(&control->mutex);
    return FTUN_OK;
  }
  if (control->stop_requested) {
    if (deadline_ms < control->stop_deadline_ms) {
      control->stop_deadline_ms = deadline_ms;
    }
    if (control->state == FTUN_CORE_RUNNING &&
        control->service.implementation != NULL) {
      (void)ftun_core_service_wakeup(&control->service);
    }
    ftun_condition_broadcast(&control->condition);
    ftun_mutex_unlock(&control->mutex);
    return FTUN_OK;
  }
  if (control->state != FTUN_CORE_RUNNING &&
      control->state != FTUN_CORE_STARTING &&
      control->state != FTUN_CORE_STOPPING) {
    ftun_mutex_unlock(&control->mutex);
    return FTUN_E_STALE;
  }
  control->stop_requested = 1;
  control->stop_deadline_ms = deadline_ms;
  if (control->state == FTUN_CORE_RUNNING &&
        control->service.implementation != NULL) {
    (void)ftun_core_service_wakeup(&control->service);
  }
  ftun_condition_broadcast(&control->condition);
  ftun_mutex_unlock(&control->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_core_stop(ftun_core_t *core, uint64_t deadline_ms)
{
  return ftun_core_stop_request(core, deadline_ms, NULL, NULL);
}

ftun_status_t ftun_app_control_stop(ftun_core_t *core, uint64_t deadline_ms,
  ftun_app_generation_guard_t expected, ftun_app_command_result_t *out)
{
  ftun_status_t status;
  if (out == NULL) return FTUN_E_INVALID;
  memset(out, 0, sizeof(*out));
  out->kind = FTUN_APP_COMMAND_STOP;
  out->error.stage = FTUN_STAGE_CONTROL;
  status = ftun_core_stop_request(core, deadline_ms, &expected, out);
  out->error.status = status;
  if (status != FTUN_OK) out->phase = FTUN_APP_COMMAND_FAILED;
  return status;
}

ftun_status_t ftun_app_control_query(ftun_core_t *core,
  ftun_app_control_snapshot_t *out)
{
  ftun_core_control_t *control = NULL;
  ftun_operation_queue_usage_t operations;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (out == NULL) return FTUN_E_INVALID;
  status = ftun_core_control(core, &control);
  if (status != FTUN_OK) return status;
  ftun_mutex_lock(&control->mutex);
  if (control->config_path.value != NULL) {
    size_t length = strnlen(control->config_path.value, sizeof(out->config_path));
    if (length >= sizeof(out->config_path)) {
      ftun_mutex_unlock(&control->mutex);
      return FTUN_E_LIMIT;
    }
    memcpy(out->config_path, control->config_path.value, length + 1u);
  }
  out->core.state = control->state;
  out->core.generation = ftun_core_generation_now(control);
  out->core.owner_rounds = control->owner_rounds;
  out->core.owner_max_busy_ms = control->owner_max_busy_ms;
  out->core.owner_max_deadline_lateness_ms = control->owner_max_deadline_lateness_ms;
  out->core.owner_max_work = control->owner_max_work;
  out->core.owner_quota_exhaustions = control->owner_quota_exhaustions;
  memcpy(out->service_faults, control->service_faults, sizeof(out->service_faults));
  out->service_pauses = control->service_pauses;
  out->service_paused = control->service_paused;
  out->build_modules = ftun_build_capabilities()->builtins;
  out->commands = FTUN_APP_CONTROL_RELOAD | FTUN_APP_CONTROL_STOP;
  if (control->support != NULL && control->support->select != NULL) out->commands |= FTUN_APP_CONTROL_SELECT;
  out->queued_commands = control->task_count;
  out->reload_pending = control->reload_pending != 0;
  out->stop_requested = control->stop_requested != 0;
  out->runtime_stopped = control->runtime_stopped;
  out->run_returned = control->run_returned;
  out->run_result = control->run_result;
  (void)ftun_log_ledger_get_usage(control->log_ledger, &out->log_totals);
  out->config_trace = control->config_trace;
  out->config_trace_generation = control->config_trace_generation;
  (void)ftun_event_log_get_usage(control->events, &out->events);
  {
    ftun_logger_t *logger = NULL;
    if (ftun_core_context_logger_acquire(core, &logger) == FTUN_OK) {
      out->logger_present = true;
      (void)ftun_logger_get_usage(logger, &out->logger);
      (void)ftun_core_context_logger_release(core);
    }
  }
  status = control->operations == NULL ? FTUN_OK :
    ftun_operation_queue_get_usage(control->operations, &operations);
  if (status == FTUN_OK && control->operations != NULL) out->core.pending_operations = operations.inflight;
  ftun_mutex_unlock(&control->mutex);
  if (status != FTUN_OK) memset(out, 0, sizeof(*out));
  return status;
}

bool ftun_app_control_watchdog_fired(ftun_core_t *core)
{
  ftun_core_control_t *control = NULL;
  bool fired;
  if (ftun_core_control(core, &control) != FTUN_OK) return false;
  ftun_mutex_lock(&control->mutex);
  fired = control->watchdog_fired;
  ftun_mutex_unlock(&control->mutex);
  return fired;
}

ftun_status_t ftun_core_get_info(ftun_core_t *core, ftun_core_info_t *out)
{
  ftun_core_control_t *control = NULL;
  ftun_operation_queue_usage_t operations;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (core == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_core_control(core, &control);
  if (status != FTUN_OK) return status;
  ftun_mutex_lock(&control->mutex);
  out->state = control->state;
  out->generation = ftun_core_generation_now(control);
  out->owner_rounds = control->owner_rounds;
  out->owner_max_busy_ms = control->owner_max_busy_ms;
  out->owner_max_deadline_lateness_ms =
    control->owner_max_deadline_lateness_ms;
  out->owner_max_work = control->owner_max_work;
  out->owner_quota_exhaustions = control->owner_quota_exhaustions;
  ftun_mutex_unlock(&control->mutex);
  if (control->operations == NULL) return FTUN_OK;
  status = ftun_operation_queue_get_usage(control->operations, &operations);
  if (status != FTUN_OK) {
    memset(out, 0, sizeof(*out));
    return status;
  }
  out->pending_operations = operations.inflight;
  return FTUN_OK;
}

ftun_status_t ftun_core_destroy(ftun_core_t **core)
{
  ftun_core_t *owned;
  ftun_core_control_t *control = NULL;
  ftun_core_state_t state;
  ftun_app_cleanup_t cleanup;
  ftun_status_t status;
  ftun_budget_usage_t root_usage;
  ftun_budget_usage_t control_usage;
  ftun_budget_t *root_budget;
  ftun_budget_t *control_budget;
  ftun_reservation_t reservation;
  if (core == NULL) return FTUN_E_INVALID;
  owned = *core;
  if (owned == NULL) return FTUN_OK;
  status = ftun_core_control(owned, &control);
  if (status != FTUN_OK) return status;
  ftun_mutex_lock(&control->mutex);
  state = control->state;
  if (state != FTUN_CORE_CREATED && state != FTUN_CORE_STOPPED &&
      !(state == FTUN_CORE_STOPPING && !control->owner_valid)) {
    ftun_mutex_unlock(&control->mutex);
    return FTUN_E_AGAIN;
  }
  ftun_mutex_unlock(&control->mutex);
  cleanup = ftun_core_cleanup(control);
  status = ftun_app_cleanup_drive(&cleanup, ftun_core_cleanup_step,
                                  control, false);
  if (status != FTUN_OK) return status;
  ftun_mutex_lock(&control->mutex);
  control->state = FTUN_CORE_STOPPED;
  ftun_mutex_unlock(&control->mutex);
  status = ftun_operation_queue_destroy(&control->operations);
  if (status != FTUN_OK) return status;
  (void)ftun_core_context_set_logger(owned, NULL);
  if (control->support != NULL) {
    status = control->support->clear(owned);
    if (status != FTUN_OK) return status;
  }
  status = ftun_config_destroy(&control->active_config);
  if (status != FTUN_OK) return status;
  ftun_mutex_lock(&control->mutex);
  status = ftun_core_owned_path_destroy(&control->config_path);
  ftun_mutex_unlock(&control->mutex);
  if (status != FTUN_OK) return status;
  status = ftun_core_context_set_budget(owned, control->root_budget);
  if (status != FTUN_OK) return status;
  (void)ftun_core_context_set_event_log(owned, NULL);
  status = ftun_event_log_destroy(&control->events);
  if (status != FTUN_OK) return status;
  status = ftun_log_ledger_destroy(&control->log_ledger);
  if (status != FTUN_OK) return status;
  status = ftun_budget_destroy(&control->data_budget);
  if (status != FTUN_OK) return status;
  /* 生产者已静默且所有服务已销毁。外部借用若仍持有 reservation/子
   * budget，保留整个宿主供重试；不得先释放其句柄或创建时预算。 */
  status = ftun_budget_get_usage(control->budget, &control_usage);
  if (status == FTUN_OK) status = ftun_budget_get_usage(control->root_budget, &root_usage);
  if (status != FTUN_OK) return status;
  if (control_usage.child_count != 0u || root_usage.child_count != 1u ||
      control_usage.used_resources.memory_bytes != control->bootstrap_bytes ||
      root_usage.used_resources.memory_bytes != control->bootstrap_bytes ||
      control_usage.used_resources.descriptors != 0u ||
      control_usage.used_resources.queue_slots != 0u ||
      root_usage.used_resources.descriptors != 0u ||
      root_usage.used_resources.queue_slots != 0u) return FTUN_E_AGAIN;
  root_budget = control->root_budget;
  control_budget = control->budget;
  reservation = control->reservation;
  (void)ftun_core_context_set_control(owned, NULL);
  status = ftun_core_context_destroy(core);
  if (status != FTUN_OK) {
    if (*core != NULL) (void)ftun_core_context_set_control(*core, control);
    return status;
  }
  free(control->tasks);
  ftun_condition_destroy(&control->condition);
  ftun_mutex_destroy(&control->mutex);
  free(control);
  ftun_reservation_release(&reservation);
  status = ftun_budget_destroy(&control_budget);
  if (status == FTUN_OK) status = ftun_budget_destroy(&root_budget);
  return status;
}
