#define _POSIX_C_SOURCE 200809L

#include "core/core.h"
#include "app/cleanup.h"
#include "app/control.h"
#include "app/runtime_support.h"

#include "config/config.h"
#include "config/compile.h"
#include "config/model.h"
#include "config/parser.h"
#include "core/budget.h"
#include "core/operation.h"
#include "core/worker.h"
#include "util/logger.h"
#include "util/event_log.h"
#include "core/context.h"
#include "util/time.h"

#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#define FTUN_CORE_DEFAULT_MEMORY (64u * 1024u * 1024u)
#define FTUN_CORE_DEFAULT_OPERATIONS 1024u
#define FTUN_CORE_MIN_OPERATIONS 4u
#define FTUN_CORE_MAX_OPERATIONS 4096u
#define FTUN_CORE_DEFAULT_RETAINED 4u
#define FTUN_CORE_DEFAULT_DESCRIPTORS 4096u
#define FTUN_CORE_DEFAULT_QUEUE_SLOTS 4096u
#define FTUN_CORE_MIN_MEMORY (1024u * 1024u)
#define FTUN_CORE_MIN_DESCRIPTORS 16u
#define FTUN_CORE_MIN_QUEUE_SLOTS 64u
#define FTUN_CORE_CONTROL_STRING 4096u
#define FTUN_CORE_RELOAD_WORK_MAGIC UINT32_C(0x4654524c)
#define FTUN_CORE_OPERATION_DISPATCH_QUOTA 32u
#define FTUN_CORE_STATE_WORKER_CAPACITY 4u

typedef enum {
  FTUN_CONTROL_POST = 1,
  FTUN_CONTROL_RELOAD,
  FTUN_CONTROL_SELECT
} ftun_control_kind_t;

typedef struct {
  char *value;
  ftun_reservation_t *reservation;
} ftun_core_owned_path_t;

typedef struct ftun_control_task {
  ftun_core_t *core;
  ftun_operation_t *operation;
  ftun_operation_token_t completion_token;
  ftun_completion_fn completion;
  ftun_app_command_completion_fn command_completion;
  ftun_app_generation_guard_t expected;
  uint64_t result_generation;
  void *completion_user;
  char *first;
  char *second;
  ftun_control_kind_t kind;
  ftun_operation_t *prepare_operation;
  ftun_reservation_t *reservation;
  pthread_mutex_t mutex;
  int cancelled;
  int ring_consumed;
  int callback_complete;
  int async_started;
  int async_complete;
  int control_priority;
  bool reload_event_recorded; /* 只由 owner 的完成/取消派发使用。 */
  void *reload_transaction;
} ftun_control_task_t;

typedef struct {
  uint32_t magic;
  uint32_t socket_mark;
  bool allow_system_resolver;
  uint64_t base_generation;
  uint64_t maximum_bytes;
  uintptr_t service_descriptor;
  uintptr_t owner;
  uintptr_t log_ledger;
  uintptr_t plan_budget;
  uint32_t path_length;
} ftun_core_reload_work_t;

typedef struct {
  uint64_t base_generation;
  uintptr_t owner;
  ftun_status_t status;
  uintptr_t config;
  uintptr_t attachment;
  ftun_core_service_plan_t service_plan;
  uintptr_t logger;
  ftun_core_owned_path_t source_path;
  bool publish_required;
  ftun_config_trace_t config_trace;
} ftun_core_reload_result_t;

typedef struct {
  ftun_config_t *config;
  ftun_app_runtime_candidate_t *candidate;
  ftun_core_service_plan_t service_plan;
  ftun_logger_t *next_logger;
  ftun_core_owned_path_t next_path;
  ftun_reservation_t *reservation;
  uint64_t next_generation;
  bool replace_logger;
  bool service_prepared;
} ftun_core_reload_transaction_t;

typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  pthread_t owner;
  ftun_budget_t *root_budget;
  ftun_budget_t *budget;
  ftun_budget_t *data_budget;
  ftun_reservation_t *reservation;
  size_t bootstrap_bytes;
  ftun_operation_queue_t *operations;
  ftun_logger_t *logger;
  ftun_logger_t *retired_logger;
  const ftun_core_service_descriptor_t *service_descriptor;
  ftun_core_service_t service;
  ftun_core_t *core;
  ftun_worker_t *reload_worker;
  ftun_worker_t *state_worker;
  ftun_core_reload_result_t retired_result;
  ftun_core_reload_transaction_t *retired_transaction;
  const ftun_app_runtime_support_t *support;
  ftun_config_t *active_config;
  ftun_config_t *startup_config;
  ftun_app_runtime_candidate_t *startup_candidate;
  ftun_logger_t *startup_logger;
  ftun_event_log_t *events;
  ftun_log_ledger_t *log_ledger;
  bool lifecycle_started;
  bool runtime_stopped;
  bool run_returned;
  ftun_status_t run_result;
  ftun_config_trace_t config_trace;
  uint64_t config_trace_generation;
  ftun_control_task_t **tasks;
  ftun_core_owned_path_t config_path;
  ftun_core_owned_path_t startup_path;
  size_t task_capacity;
  size_t task_head;
  size_t task_tail;
  size_t task_count;
  size_t normal_task_count;
  size_t task_control_reserve;
  uint64_t generation;
  uint64_t owner_rounds;
  uint64_t owner_max_busy_ms;
  uint64_t owner_max_deadline_lateness_ms;
  uint64_t stop_deadline_ms;
  size_t owner_max_work;
  uint64_t owner_quota_exhaustions;
  ftun_core_state_t state;
  int owner_valid;
  int stop_requested;
  int reload_pending;
  bool callbacks_enabled;
  bool service_stopped;
  bool state_save_done;
  bool state_save_submitted;
  bool retired_busy;
  ftun_status_t first_error;
  ftun_status_t cleanup_error;
} ftun_core_control_t;

static int ftun_control_task_cancelled(ftun_control_task_t *task);
static void ftun_control_task_destroy(ftun_control_task_t *task);
static void ftun_control_task_consumed(ftun_control_task_t *task);

static ftun_app_cleanup_t ftun_core_cleanup(ftun_core_control_t *control)
{
  ftun_app_cleanup_t cleanup = {&control->mutex, &control->stop_deadline_ms,
                               &control->cleanup_error};
  return cleanup;
}

static ftun_status_t ftun_core_control(ftun_core_t *core,
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

static void ftun_core_event(ftun_core_control_t *control,
  ftun_lifecycle_kind_t kind, uint64_t generation, ftun_status_t status)
{
  ftun_lifecycle_event_t item = {0};
  item.kind = kind;
  item.generation = generation;
  item.status = status;
  (void)ftun_lifecycle_emit(control->core, &item);
}

static void ftun_core_config_trace(ftun_core_control_t *control,
  const ftun_config_trace_t *trace, uint64_t generation)
{
  (void)pthread_mutex_lock(&control->mutex);
  control->config_trace = *trace;
  control->config_trace_generation = generation;
  (void)pthread_mutex_unlock(&control->mutex);
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
static ftun_status_t ftun_core_owned_path_copy(ftun_budget_t *budget,
  const char *value, ftun_core_owned_path_t *out)
{
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  size_t length;
  char *copy;
  if (budget == NULL || value == NULL || out == NULL) return FTUN_E_INVALID;
  if (out->value != NULL || out->reservation != NULL) return FTUN_E_AGAIN;
  length = strnlen(value, FTUN_CORE_CONTROL_STRING + 1u);
  if (length == 0u || length > FTUN_CORE_CONTROL_STRING) return FTUN_E_LIMIT;
  status = ftun_budget_reserve(budget, length + 1u, &reservation);
  if (status != FTUN_OK) return status;
  copy = (char *)malloc(length + 1u);
  if (copy == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  memcpy(copy, value, length + 1u);
  out->value = copy;
  out->reservation = reservation;
  return FTUN_OK;
}

static ftun_status_t ftun_core_owned_path_destroy(ftun_core_owned_path_t *path)
{
  ftun_status_t status;
  if (path == NULL) return FTUN_E_INVALID;
  status = ftun_reservation_release(&path->reservation);
  if (status != FTUN_OK) return status;
  free(path->value);
  path->value = NULL;
  return FTUN_OK;
}

static ftun_status_t ftun_core_prepare_parent(const char *path)
{
  char *copy;
  char *cursor;
  struct stat info;
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
      if (mkdir(copy, 0700) != 0 && errno != EEXIST) {
        free(copy);
        return FTUN_E_IO;
      }
      if (stat(copy, &info) != 0 || !S_ISDIR(info.st_mode)) {
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

static ftun_status_t ftun_core_logger_create(const ftun_config_t *config,
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
  options.queue_capacity = 128u;
  options.line_capacity = 1024u;
  options.ledger = ledger;
  return ftun_logger_create(&options, out);
}

static ftun_status_t ftun_core_logger_reap(ftun_core_control_t *control,
                                           uint64_t deadline_ms)
{
  if (control == NULL) return FTUN_E_INVALID;
  return ftun_logger_destroy_until(&control->retired_logger, deadline_ms);
}

static ftun_status_t ftun_core_logger_retire(ftun_core_control_t *control,
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

static int ftun_core_string_equal(const char *left, const char *right)
{
  if (left == NULL || right == NULL) return left == right;
  return strcmp(left, right) == 0;
}

static int ftun_core_tun_device_equal(const ftun_config_t *left,
                                      const ftun_config_t *right)
{
  if (left == NULL || right == NULL) return 0;
  return left->tun.present == right->tun.present &&
    (!left->tun.present ||
      (ftun_core_string_equal(left->tun.interface_name,
                              right->tun.interface_name) &&
       ftun_core_string_equal(left->tun.ipv4_address,
                              right->tun.ipv4_address) &&
       left->tun.mtu == right->tun.mtu &&
       left->tun.auto_route == right->tun.auto_route &&
       left->tun.strict_route == right->tun.strict_route));
}

static ftun_status_t ftun_core_reload_compatible(const ftun_config_t *active,
                                                  const ftun_config_t *next)
{
  if (active == NULL || next == NULL) return FTUN_E_INVALID;
  if (active->plan == NULL || next->plan == NULL) return FTUN_E_INVALID;
  if (((active->plan->required_modules ^ next->plan->required_modules) &
       (FTUN_BUILD_MODULE_PROXY | FTUN_BUILD_MODULE_DNS |
        FTUN_BUILD_MODULE_TUN)) != 0u) {
    return FTUN_E_RESTART_REQUIRED;
  }
  if ((active->plan->required_modules & FTUN_BUILD_MODULE_TUN) != 0u &&
      !ftun_core_tun_device_equal(active, next)) {
    return FTUN_E_RESTART_REQUIRED;
  }
  return FTUN_OK;
}

static void ftun_core_log_status(ftun_core_t *core, ftun_status_t status,
                                 uint32_t stage, ftun_diagnostic_kind_t kind, const char *message)
{
  ftun_error_t error = {0};
  uint64_t generation = 0u;
  /* 这些生产入口只由 owner 调用；提交前使用当前生效代次。 */
  (void)ftun_core_context_generation(core, &generation);
  error.status = status;
  error.stage = stage;
  (void)ftun_diagnostic_report(core, kind, generation, error, message);
}

static void ftun_core_state_completed(ftun_operation_t *operation,
                                      ftun_error_t error,
                                      ftun_bytes_t result, void *user)
{
  ftun_core_control_t *control = (ftun_core_control_t *)user;
  (void)operation;
  (void)result;
  if (control != NULL && error.status != FTUN_OK &&
      error.status != FTUN_E_CANCELLED) {
    ftun_core_log_status(control->core, error.status,
      FTUN_STAGE_STATE_RESTORE, FTUN_DIAGNOSTIC_STATE_SAVE, control->support->state_failure_message);
  }
}

static ftun_status_t ftun_core_state_schedule(
  ftun_core_t *core, ftun_core_control_t *control, const char *path,
  uint64_t deadline_ms)
{
  ftun_worker_job_t job;
  ftun_reservation_t *input_reservation = NULL;
  ftun_operation_t *operation = NULL;
  ftun_status_t status;
  if (control->support == NULL || control->state_worker == NULL) return FTUN_OK;
  memset(&job, 0, sizeof(job));
  status = control->support->state_job(core, control->budget, path, deadline_ms, &job, &input_reservation);
  if (status != FTUN_OK) return status;
  status = ftun_worker_submit(control->state_worker, &job,
    ftun_core_state_completed, control, &operation);
  free((void *)job.input.data);
  (void)ftun_reservation_release(&input_reservation);
  return status;
}

static ftun_status_t ftun_core_reload_result_release(
  ftun_core_reload_result_t *result, uint64_t deadline)
{
  const ftun_app_runtime_support_t *support = ftun_app_runtime_support();
  ftun_config_t *config;
  ftun_app_runtime_candidate_t *attachment;
  ftun_logger_t *logger;
  ftun_status_t status;
  if (result == NULL) return FTUN_OK;
  config = (ftun_config_t *)result->config;
  attachment = (ftun_app_runtime_candidate_t *)result->attachment;
  logger = (ftun_logger_t *)result->logger;
  status = ftun_core_service_plan_destroy(&result->service_plan);
  if (status != FTUN_OK) return status;
  if (attachment != NULL) {
    if (support == NULL) return FTUN_E_STATE_CORRUPT;
    status = support->release(NULL, &attachment);
    result->attachment = (uintptr_t)attachment;
    if (status != FTUN_OK) return status;
  }
  status = ftun_logger_destroy_until(&logger, deadline);
  result->logger = (uintptr_t)logger;
  if (status != FTUN_OK) return status;
  status = ftun_config_destroy(&config);
  result->config = (uintptr_t)config;
  if (status != FTUN_OK) return status;
  status = ftun_core_owned_path_destroy(&result->source_path);
  if (status != FTUN_OK) return status;
  memset(result, 0, sizeof(*result));
  return FTUN_OK;
}

static void ftun_core_reload_result_retire(ftun_core_reload_result_t *result)
{
  ftun_core_control_t *control;
  ftun_app_cleanup_t cleanup;
  ftun_status_t status;
  uint64_t now = 0u;
  if (result == NULL || result->owner == 0u) return;
  control = (ftun_core_control_t *)result->owner;
  cleanup = ftun_core_cleanup(control);
  (void)ftun_monotonic_now(&now);
  status = ftun_core_reload_result_release(result, now);
  if (status == FTUN_OK) return;
  ftun_app_cleanup_record(&cleanup, status);
  /* 一个 reload 的接纳门保持到 Worker、候选与退休对象全部释放。
   * 因而该固定槽在接收本次唯一结果时必为空，不需要分配清理队列。 */
  control->retired_result = *result;
  memset(result, 0, sizeof(*result));
}

static ftun_status_t ftun_core_reload_result_cleanup(ftun_bytes_t bytes)
{
  ftun_core_reload_result_t result;
  if (bytes.data == NULL || bytes.length != sizeof(result)) return FTUN_E_INVALID;
  memcpy(&result, bytes.data, sizeof(result));
  ftun_core_reload_result_retire(&result);
  memcpy((void *)(uintptr_t)bytes.data, &result, sizeof(result));
  return FTUN_OK;
}

static ftun_status_t ftun_core_reload_execute(
  ftun_bytes_t input, uint8_t *output, size_t output_capacity,
  size_t *out_output_size)
{
  const ftun_core_reload_work_t *work;
  const char *path;
  ftun_core_reload_result_t result;
  ftun_config_t *config = NULL;
  const ftun_app_runtime_support_t *support = ftun_app_runtime_support();
  ftun_app_runtime_candidate_t *attachment = NULL;
  ftun_core_service_plan_t service_plan;
  ftun_logger_t *logger = NULL;
  ftun_core_owned_path_t source_path = {0};
  ftun_status_t status;
  memset(&service_plan, 0, sizeof(service_plan));
  if (out_output_size != NULL) *out_output_size = 0u;
  if (input.data == NULL || input.length < sizeof(*work) || output == NULL ||
      output_capacity < sizeof(result) || out_output_size == NULL) {
    return FTUN_E_INVALID;
  }
  work = (const ftun_core_reload_work_t *)input.data;
  if (work->magic != FTUN_CORE_RELOAD_WORK_MAGIC || work->path_length == 0u ||
      work->service_descriptor == 0u || work->plan_budget == 0u ||
      input.length != sizeof(*work) + (size_t)work->path_length + 1u ||
      input.data[input.length - 1u] != 0u) return FTUN_E_INVALID;
  path = (const char *)(input.data + sizeof(*work));
  memset(&result, 0, sizeof(result));
  status = ftun_config_load_budget_traced((ftun_budget_t *)work->plan_budget, path, &config, &result.config_trace);
  if (status != FTUN_OK) goto done;
  if (support != NULL) {
    ftun_app_prepare_context_t context = {work->base_generation + 1u,
      work->socket_mark, work->allow_system_resolver};
    status = support->prepare((ftun_budget_t *)work->plan_budget,
                              config, work->maximum_bytes, &context,
                              &attachment, &result.publish_required);
    if (status != FTUN_OK) goto done;
  }
  status = ftun_core_service_plan_prepare(
    (const ftun_core_service_descriptor_t *)work->service_descriptor,
    (ftun_budget_t *)work->plan_budget, config, work->socket_mark, &service_plan);
  if (status == FTUN_OK) status = ftun_core_logger_create(config,
    (ftun_log_ledger_t *)work->log_ledger, &logger);
  if (status == FTUN_OK) {
    status = ftun_core_owned_path_copy((ftun_budget_t *)work->plan_budget,
      config->source_path == NULL ? path : config->source_path, &source_path);
  }
  if (status == FTUN_OK && support != NULL) support->load_state(attachment);

done:
  result.owner = work->owner;
  result.status = status;
  result.base_generation = work->base_generation;
  result.config = (uintptr_t)config;
  result.attachment = (uintptr_t)attachment;
  result.service_plan = service_plan;
  result.logger = (uintptr_t)logger;
  result.source_path = source_path;
  /* 即使 prepare 失败，拥有型结果也必须交给 owner 清理。 */
  memcpy(output, &result, sizeof(result));
  *out_output_size = sizeof(result);
  return FTUN_OK;
}

static ftun_status_t ftun_core_transaction(ftun_core_t *core,
                                           ftun_core_control_t *control,
                                           const char *path,
                                           uint32_t *out_stage)
{
  ftun_config_t *config = NULL;
  ftun_app_runtime_candidate_t *candidate = NULL;
  ftun_logger_t *next_logger = NULL;
  ftun_core_service_t next_service;
  ftun_core_owned_path_t next_path = {0};
  uint64_t next_generation = 0u;
  ftun_status_t status;
  ftun_config_trace_t trace;
  memset(&next_service, 0, sizeof(next_service));
  if (out_stage != NULL) *out_stage = FTUN_STAGE_CONFIG_READ;
  if (control->generation == UINT64_MAX) return FTUN_E_LIMIT;
  next_generation = control->generation + 1u;
  status = ftun_config_load_budget_traced(control->budget, path, &config, &trace);
  ftun_core_config_trace(control, &trace, next_generation);
  if (status != FTUN_OK) return status;
  if (out_stage != NULL) *out_stage = FTUN_STAGE_CONFIG_PREPARE;
  status = ftun_core_logger_create(config, control->log_ledger, &next_logger);
  if (status != FTUN_OK) goto done;
  /* 启动附件及模块准备前发布已配置 sink；失败仍由 startup_logger 拥有。
   * 普通日志接纳不改变事务结果，输出失败由日志 usage 表达。 */
  (void)ftun_core_context_publish_logger(core, next_logger, next_logger == NULL);
  status = ftun_core_owned_path_copy(control->budget,
    config->source_path == NULL ? path : config->source_path, &next_path);
  if (status != FTUN_OK) goto done;
  if (control->support != NULL) {
    status = control->support->start(core, control->budget, config,
                                      next_generation, &candidate, out_stage);
    if (status != FTUN_OK) goto done;
  }
  if (out_stage != NULL) *out_stage = FTUN_STAGE_COMMIT;
  status = ftun_core_service_prepare(&next_service,
    control->service_descriptor, core, control->data_budget,
    control->operations, NULL, config, next_generation);
  if (status != FTUN_OK) goto done;
  if (control->support != NULL) {
    status = control->support->stage(core, candidate, next_generation);
    if (status != FTUN_OK) goto done;
  }
  status = ftun_core_service_activate(&next_service);
  if (status != FTUN_OK) goto done;
  /* 服务激活后发布业务候选，随后切换宿主拥有的配置与代次。 */
  if (control->support != NULL) {
    status = control->support->commit(core, candidate);
    if (status != FTUN_OK) goto done;
  }
  control->active_config = config;
  config = NULL;
  control->service = next_service;
  memset(&next_service, 0, sizeof(next_service));
  (void)pthread_mutex_lock(&control->mutex);
  control->generation = next_generation;
  (void)ftun_core_context_set_generation(core, next_generation);
  {
    ftun_core_owned_path_t previous = control->config_path;
    control->config_path = next_path;
    next_path = previous;
  }
  (void)pthread_mutex_unlock(&control->mutex);
  control->logger = next_logger;
  next_logger = NULL;
  (void)ftun_core_context_set_logger(core, control->logger);
  if (control->support != NULL) {
    control->support->committed(core, candidate);
    /* 启动附件已经发布，release 只释放其空壳；失败仍保留给清理驱动。 */
    (void)control->support->release(core, &candidate);
    control->startup_candidate = candidate;
  }

done:
  {
    ftun_status_t cleanup_status = ftun_core_owned_path_destroy(&next_path);
    if (cleanup_status != FTUN_OK) {
      ftun_app_cleanup_t cleanup = ftun_core_cleanup(control);
      control->startup_path = next_path;
      ftun_app_cleanup_record(&cleanup, cleanup_status);
    }
  }
  if (status != FTUN_OK) {
    /* prepare 的清理实例继续借用配置和候选，交给统一 stop 驱动回收。 */
    control->service = next_service;
    control->startup_config = config;
    control->startup_candidate = candidate;
    control->startup_logger = next_logger;
  } else {
    (void)ftun_config_destroy(&config);
  }
  return status;
}

static ftun_status_t ftun_core_reload_transaction_cleanup(
  ftun_core_t *core, ftun_core_control_t *control,
  ftun_core_reload_transaction_t **transaction, uint64_t deadline)
{
  ftun_core_reload_transaction_t *owned;
  ftun_status_t status;
  if (transaction == NULL || *transaction == NULL) return FTUN_OK;
  owned = *transaction;
  if (owned->service_prepared) {
    status = ftun_core_service_reload_abort(&control->service);
    if (status != FTUN_OK) return status;
    owned->service_prepared = false;
  }
  status = ftun_core_service_plan_destroy(&owned->service_plan);
  if (status != FTUN_OK) return status;
  if (owned->candidate != NULL) {
    status = control->support->release(core, &owned->candidate);
    if (status != FTUN_OK) return status;
  }
  status = ftun_logger_destroy_until(&owned->next_logger, deadline);
  if (status != FTUN_OK) return status;
  status = ftun_config_destroy(&owned->config);
  if (status != FTUN_OK) return status;
  status = ftun_core_owned_path_destroy(&owned->next_path);
  if (status != FTUN_OK) return status;
  status = ftun_reservation_release(&owned->reservation);
  if (status != FTUN_OK) return status;
  free(owned);
  *transaction = NULL;
  return FTUN_OK;
}

static void ftun_core_reload_transaction_release(
  ftun_core_t *core, ftun_core_control_t *control,
  ftun_core_reload_transaction_t **transaction)
{
  uint64_t now = 0u;
  ftun_status_t status;
  ftun_app_cleanup_t cleanup = ftun_core_cleanup(control);
  (void)ftun_monotonic_now(&now);
  status = ftun_core_reload_transaction_cleanup(core, control, transaction, now);
  if (status == FTUN_OK) return;
  ftun_app_cleanup_record(&cleanup, status);
  control->retired_transaction = *transaction;
  *transaction = NULL;
}

/* 退休槽与预算覆盖整个 reload，而不是仅覆盖 Worker 回调的栈帧。 */
static ftun_status_t ftun_core_reload_reap(ftun_core_control_t *control,
                                           uint64_t deadline)
{
  ftun_status_t status;
  ftun_worker_usage_t usage;
  bool pending;
  status = ftun_core_reload_transaction_cleanup(control->core, control,
    &control->retired_transaction, deadline);
  if (status != FTUN_OK) return status;
  status = ftun_core_reload_result_release(&control->retired_result, deadline);
  if (status != FTUN_OK) return status;
  status = ftun_core_logger_reap(control, deadline);
  if (status != FTUN_OK) return status;
  memset(&usage, 0, sizeof(usage));
  if (control->reload_worker != NULL) {
    status = ftun_worker_get_usage(control->reload_worker, &usage);
    if (status != FTUN_OK) return status;
  }
  (void)pthread_mutex_lock(&control->mutex);
  pending = control->reload_pending != 0;
  (void)pthread_mutex_unlock(&control->mutex);
  if (!pending && usage.tasks == 0u) {
    (void)pthread_mutex_lock(&control->mutex);
    control->retired_busy = false;
    (void)pthread_mutex_unlock(&control->mutex);
  }
  return FTUN_OK;
}

static ftun_status_t ftun_core_reload_prepare_transaction(
  ftun_core_t *core, ftun_core_control_t *control,
  ftun_core_reload_result_t *prepared,
  ftun_core_reload_transaction_t **out, uint32_t *out_stage)
{
  const ftun_config_t *active;
  ftun_core_reload_transaction_t *transaction = NULL;
  ftun_reservation_t *reservation = NULL;
  uint64_t now_ms = 0u;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core == NULL || control == NULL || prepared == NULL || out == NULL) {
    return FTUN_E_INVALID;
  }
  active = control->active_config;
  status = ftun_budget_reserve(control->budget, sizeof(*transaction), &reservation);
  if (status != FTUN_OK) return status;
  transaction = (ftun_core_reload_transaction_t *)calloc(
    1u, sizeof(*transaction));
  if (transaction == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  transaction->reservation = reservation;
  transaction->candidate = (ftun_app_runtime_candidate_t *)prepared->attachment;
  transaction->service_plan = prepared->service_plan;
  transaction->config = (ftun_config_t *)prepared->config;
  transaction->next_logger = (ftun_logger_t *)prepared->logger;
  transaction->next_path = prepared->source_path;
  prepared->config = 0u;
  prepared->attachment = 0u;
  memset(&prepared->service_plan, 0, sizeof(prepared->service_plan));
  prepared->logger = 0u;
  memset(&prepared->source_path, 0, sizeof(prepared->source_path));
  if (out_stage != NULL) *out_stage = FTUN_STAGE_CONFIG_PREPARE;
  status = transaction->config == NULL || transaction->next_path.value == NULL
    ? FTUN_E_STATE_CORRUPT : FTUN_OK;
  if (status == FTUN_OK) {
    status = ftun_core_reload_compatible(active, transaction->config);
  }
  if (status == FTUN_OK && control->support != NULL) {
    status = control->support->compatible(active, transaction->config);
  }
  if (status == FTUN_OK && control->generation != prepared->base_generation) {
    status = FTUN_E_STALE;
  }
  if (status == FTUN_OK) {
    transaction->replace_logger =
      !ftun_core_string_equal(active->log.level,
                              transaction->config->log.level) ||
      !ftun_core_string_equal(active->log.file,
                              transaction->config->log.file);
    status = ftun_monotonic_now(&now_ms);
  }
  /* Worker 创建的 logger 无论是否采用都必须有一个有界退休槽。 */
  if (status == FTUN_OK && control->retired_logger != NULL) {
    status = ftun_core_logger_reap(control, now_ms);
    if (status == FTUN_E_TIMEOUT) status = FTUN_E_AGAIN;
  }
  if (status == FTUN_OK && control->support != NULL) {
    status = control->support->adopt(core, transaction->candidate, now_ms, out_stage);
  }
  if (status == FTUN_OK && out_stage != NULL) *out_stage = FTUN_STAGE_COMMIT;
  if (status == FTUN_OK) {
    if (control->generation == UINT64_MAX) status = FTUN_E_LIMIT;
    else transaction->next_generation = control->generation + 1u;
  }
  if (status == FTUN_OK) {
    transaction->service_prepared = true;
    status = ftun_core_service_reload_prepare_planned(&control->service,
      transaction->config, transaction->next_generation, &transaction->service_plan);
  }
  if (status == FTUN_OK && control->support != NULL) {
    status = control->support->stage(core, transaction->candidate,
                                      transaction->next_generation);
  }
  if (status != FTUN_OK) {
    ftun_core_reload_transaction_release(core, control, &transaction);
    return status;
  }
  *out = transaction;
  return FTUN_OK;
}

static ftun_status_t ftun_core_reload_commit_transaction(
  ftun_core_t *core, ftun_core_control_t *control,
  ftun_core_reload_transaction_t *transaction)
{
  ftun_logger_t *old_logger = NULL;
  ftun_status_t status;
  if (core == NULL || control == NULL || transaction == NULL ||
      !transaction->service_prepared) {
    return FTUN_E_INVALID;
  }
  if (control->support != NULL) {
    status = control->support->inherit(core, transaction->candidate);
    if (status != FTUN_OK) return status;
  }
  status = ftun_core_service_reload_commit(&control->service,
                                           transaction->next_generation);
  if (status != FTUN_OK) return status;
  transaction->service_prepared = false;
  /* stage 已完成业务候选的可失败准备；owner 串行发布后接管新配置。 */
  if (control->support != NULL) {
    status = control->support->commit(core, transaction->candidate);
    if (status != FTUN_OK) return status;
  }
  {
    ftun_config_t *previous = control->active_config;
    control->active_config = transaction->config;
    transaction->config = previous;
  }
  (void)pthread_mutex_lock(&control->mutex);
  control->generation = transaction->next_generation;
  (void)ftun_core_context_set_generation(core, transaction->next_generation);
  {
    ftun_core_owned_path_t previous = control->config_path;
    control->config_path = transaction->next_path;
    transaction->next_path = previous;
  }
  (void)pthread_mutex_unlock(&control->mutex);
  if (transaction->replace_logger) {
    old_logger = control->logger;
    control->logger = transaction->next_logger;
    transaction->next_logger = NULL;
    (void)ftun_core_context_publish_logger(core, control->logger, control->logger == NULL);
  }
  if (old_logger != NULL) {
    (void)ftun_core_logger_retire(control, &old_logger);
  }
  if (control->support != NULL) {
    control->support->committed(core, transaction->candidate);
  }
  return FTUN_OK;
}

static void ftun_core_reload_event(ftun_control_task_t *task,
  ftun_core_control_t *control, ftun_status_t status)
{
  if (task->reload_event_recorded) return;
  task->reload_event_recorded = true;
  ftun_core_event(control, status == FTUN_OK ? FTUN_LIFECYCLE_RELOAD_COMMITTED :
    (status == FTUN_E_CANCELLED ? FTUN_LIFECYCLE_RELOAD_CANCELLED : FTUN_LIFECYCLE_RELOAD_REJECTED),
    control->generation, status);
}

static void ftun_core_reload_finish(ftun_control_task_t *task,
                                    ftun_core_control_t *control,
                                    ftun_error_t result)
{
  int destroy;
  if (control != NULL) {
    ftun_core_reload_event(task, control, result.status);
    if (result.status != FTUN_OK && result.status != FTUN_E_CANCELLED) {
      ftun_core_log_status(task->core, result.status, result.stage,
                           FTUN_DIAGNOSTIC_CONTROL, "control operation failed");
    }
    (void)pthread_mutex_lock(&control->mutex);
    control->reload_pending = 0;
    (void)pthread_mutex_unlock(&control->mutex);
  }
  task->result_generation = control->generation;
  if (!ftun_control_task_cancelled(task)) {
    (void)ftun_operation_complete(task->completion_token, result);
  }
  (void)pthread_mutex_lock(&task->mutex);
  task->async_complete = 1;
  destroy = task->ring_consumed && task->callback_complete;
  (void)pthread_mutex_unlock(&task->mutex);
  if (destroy) ftun_control_task_destroy(task);
}

static void ftun_core_reload_publish_completed(
  ftun_operation_t *operation, ftun_error_t error, ftun_bytes_t bytes,
  void *user)
{
  ftun_control_task_t *task = (ftun_control_task_t *)user;
  ftun_core_control_t *control = NULL;
  ftun_core_reload_transaction_t *transaction;
  const ftun_app_publish_result_t *published = NULL;
  ftun_error_t result = error;
  ftun_status_t durability_status = FTUN_OK;
  (void)operation;
  result.stage = FTUN_STAGE_COMMIT;
  (void)pthread_mutex_lock(&task->mutex);
  task->prepare_operation = NULL;
  transaction = (ftun_core_reload_transaction_t *)task->reload_transaction;
  task->reload_transaction = NULL;
  (void)pthread_mutex_unlock(&task->mutex);
  if (ftun_core_control(task->core, &control) != FTUN_OK) {
    result.status = FTUN_E_STATE_CORRUPT;
  }
  if (result.status == FTUN_OK) {
    if (bytes.data == NULL || bytes.length != sizeof(*published)) {
      result.status = FTUN_E_PROTOCOL;
    } else {
      published = (const ftun_app_publish_result_t *)bytes.data;
      result.status = published->status;
      if (result.status != FTUN_OK && published->published) {
        durability_status = result.status;
        result.status = FTUN_OK;
      }
    }
  }
  if (result.status == FTUN_OK && !ftun_control_task_cancelled(task)) {
    result.status = ftun_core_reload_commit_transaction(task->core, control,
                                                        transaction);
  } else if (result.status == FTUN_OK) {
    result.status = FTUN_E_CANCELLED;
  }
  if (result.status == FTUN_OK && durability_status != FTUN_OK) {
    ftun_core_log_status(task->core, durability_status, FTUN_STAGE_COMMIT,
      FTUN_DIAGNOSTIC_RELOAD_PUBLISH, control->support->publish_warning_message);
  }
  ftun_core_reload_transaction_release(task->core, control, &transaction);
  ftun_core_reload_finish(task, control, result);
}

static ftun_status_t ftun_core_reload_publish_schedule(
  ftun_core_control_t *control, ftun_control_task_t *task,
  ftun_core_reload_transaction_t *transaction)
{
  ftun_worker_job_t job;
  ftun_reservation_t *input_reservation = NULL;
  ftun_operation_t *operation = NULL;
  ftun_status_t status;
  if (control->support == NULL) return FTUN_E_UNSUPPORTED;
  memset(&job, 0, sizeof(job));
  status = control->support->publish_job(transaction->candidate, &job, &input_reservation);
  if (status != FTUN_OK) return status;
  (void)pthread_mutex_lock(&task->mutex);
  task->reload_transaction = transaction;
  (void)pthread_mutex_unlock(&task->mutex);
  status = ftun_worker_submit(control->reload_worker, &job,
    ftun_core_reload_publish_completed, task, &operation);
  free((void *)job.input.data);
  (void)ftun_reservation_release(&input_reservation);
  if (status != FTUN_OK) {
    (void)pthread_mutex_lock(&task->mutex);
    task->reload_transaction = NULL;
    (void)pthread_mutex_unlock(&task->mutex);
    return status;
  }
  (void)pthread_mutex_lock(&task->mutex);
  task->prepare_operation = operation;
  {
    int cancelled = task->cancelled;
    (void)pthread_mutex_unlock(&task->mutex);
    if (cancelled) (void)ftun_operation_cancel(operation);
  }
  return FTUN_OK;
}

static void ftun_core_reload_worker_completed(
  ftun_operation_t *operation, ftun_error_t error, ftun_bytes_t bytes,
  void *user)
{
  ftun_control_task_t *task = (ftun_control_task_t *)user;
  ftun_core_control_t *control = NULL;
  ftun_core_reload_result_t prepared;
  ftun_core_reload_transaction_t *transaction = NULL;
  ftun_error_t result;
  uint32_t stage = FTUN_STAGE_CONFIG_READ;
  bool publish_required = false;
  memset(&prepared, 0, sizeof(prepared));
  memset(&result, 0, sizeof(result));
  (void)operation;
  (void)pthread_mutex_lock(&task->mutex);
  task->prepare_operation = NULL;
  (void)pthread_mutex_unlock(&task->mutex);
  result.status = error.status;
  result.stage = stage;
  if (result.status == FTUN_OK && bytes.data != NULL &&
      bytes.length == sizeof(prepared)) {
    memcpy(&prepared, bytes.data, sizeof(prepared));
    publish_required = prepared.publish_required;
    result.status = prepared.status;
  } else if (result.status == FTUN_OK) {
    result.status = FTUN_E_STATE_CORRUPT;
  }
  if (ftun_core_control(task->core, &control) != FTUN_OK) {
    result.status = FTUN_E_STATE_CORRUPT;
  }
  if (control != NULL && bytes.data != NULL && bytes.length == sizeof(prepared)) {
    ftun_core_config_trace(control, &prepared.config_trace,
      prepared.base_generation == UINT64_MAX ? UINT64_MAX : prepared.base_generation + 1u);
  }
  if (result.status == FTUN_OK && !ftun_control_task_cancelled(task)) {
    result.status = ftun_core_reload_prepare_transaction(task->core, control,
      &prepared, &transaction, &stage);
    result.stage = stage;
  } else if (result.status == FTUN_OK) {
    result.status = FTUN_E_CANCELLED;
  }
  ftun_core_reload_result_retire(&prepared);
  if (bytes.data != NULL && bytes.length == sizeof(prepared)) {
    memset((void *)bytes.data, 0, bytes.length);
  }
  if (result.status == FTUN_OK && publish_required) {
    result.status = ftun_core_reload_publish_schedule(control, task,
                                                      transaction);
    if (result.status == FTUN_OK) return;
  }
  if (result.status == FTUN_OK) {
    if (ftun_control_task_cancelled(task)) result.status = FTUN_E_CANCELLED;
    else result.status = ftun_core_reload_commit_transaction(
      task->core, control, transaction);
  }
  ftun_core_reload_transaction_release(task->core, control, &transaction);
  ftun_core_reload_finish(task, control, result);
}

static ftun_status_t ftun_core_reload_schedule(ftun_core_control_t *control,
                                               ftun_control_task_t *task)
{
  ftun_core_reload_work_t *work;
  ftun_worker_job_t job;
  ftun_budget_usage_t usage;
  uint8_t *input;
  ftun_operation_t *prepare_operation = NULL;
  ftun_reservation_t *input_reservation = NULL;
  size_t path_length = strlen(task->first);
  size_t input_length;
  ftun_status_t status;
  uint64_t now_ms;
  if (control->generation == UINT64_MAX) return FTUN_E_LIMIT;
  status = ftun_monotonic_now(&now_ms);
  if (status == FTUN_OK && control->retired_logger != NULL) {
    status = ftun_core_logger_reap(control, now_ms);
    if (status == FTUN_E_TIMEOUT) status = FTUN_E_AGAIN;
  }
  if (status != FTUN_OK) return status;
  if (path_length > UINT32_MAX || path_length > SIZE_MAX - sizeof(*work) - 1u) {
    return FTUN_E_LIMIT;
  }
  status = ftun_budget_get_usage(control->budget, &usage);
  if (status != FTUN_OK || usage.normal_available < 512u * 1024u) {
    return status == FTUN_OK ? FTUN_E_LIMIT : status;
  }
  input_length = sizeof(*work) + path_length + 1u;
  status = ftun_budget_reserve(control->budget, input_length, &input_reservation);
  if (status != FTUN_OK) return status;
  input = (uint8_t *)calloc(1u, input_length);
  if (input == NULL) {
    (void)ftun_reservation_release(&input_reservation);
    return FTUN_E_LIMIT;
  }
  work = (ftun_core_reload_work_t *)input;
  work->magic = FTUN_CORE_RELOAD_WORK_MAGIC;
  work->maximum_bytes = usage.normal_available / 2u;
  work->service_descriptor = (uintptr_t)control->service_descriptor;
  work->owner = (uintptr_t)control;
  /* 独立线程安全计数器，不借 Core/logger；App 在全部 Worker 及其拥有型
   * 结果回收后才销毁 ledger。候选即使取消，也由同一计数器保留关闭结果。 */
  work->log_ledger = (uintptr_t)control->log_ledger;
  work->plan_budget = (uintptr_t)control->budget;
  work->path_length = (uint32_t)path_length;
  memcpy(input + sizeof(*work), task->first, path_length + 1u);
  work->base_generation = control->generation;
  work->allow_system_resolver = true;
  if (control->active_config != NULL) {
    size_t index;
    for (index = 0u; index < control->active_config->inbound_count; index++) {
      const ftun_config_inbound_t *inbound = &control->active_config->inbounds[index];
      if (inbound->kind == FTUN_CONFIG_INBOUND_TUN && inbound->auto_route) {
        work->allow_system_resolver = false;
      }
    }
  }
  if (control->active_config != NULL && control->active_config->plan != NULL &&
      (control->active_config->plan->required_modules & FTUN_BUILD_MODULE_TUN) != 0u) {
    work->socket_mark = UINT32_C(0x4654);
  }
  memset(&job, 0, sizeof(job));
  job.execute = ftun_core_reload_execute;
  job.input.data = input;
  job.input.length = input_length;
  job.result_capacity = sizeof(ftun_core_reload_result_t);
  /* 候选、文件及附件按各自拥有期准入；maximum_bytes只限制业务输入，
   * 不再重复预留同一批对象的总占位。接纳门仍保持至全部结果回收。 */
  (void)pthread_mutex_lock(&control->mutex);
  control->retired_busy = true;
  (void)pthread_mutex_unlock(&control->mutex);
  job.result_cleanup = ftun_core_reload_result_cleanup;
  (void)pthread_mutex_lock(&task->mutex);
  task->async_started = 1;
  (void)pthread_mutex_unlock(&task->mutex);
  status = ftun_worker_submit(control->reload_worker, &job,
    ftun_core_reload_worker_completed, task, &prepare_operation);
  free(input);
  (void)ftun_reservation_release(&input_reservation);
  if (status != FTUN_OK) {
    (void)pthread_mutex_lock(&task->mutex);
    task->async_started = 0;
    (void)pthread_mutex_unlock(&task->mutex);
  } else {
    int cancelled;
    (void)pthread_mutex_lock(&task->mutex);
    task->prepare_operation = prepare_operation;
    cancelled = task->cancelled;
    (void)pthread_mutex_unlock(&task->mutex);
    if (cancelled) (void)ftun_operation_cancel(prepare_operation);
  }
  return status;
}

static void ftun_core_reload_wakeup(void *user)
{
  ftun_core_control_t *control = (ftun_core_control_t *)user;
  if (control == NULL) return;
  /* 与 owner 进入 STOPPING 的边界串行化。停止期间服务可修改或释放
   * 内部对象，迟到 Worker 不再穿透服务；清理驱动使用自身期限推进。 */
  (void)pthread_mutex_lock(&control->mutex);
  if (control->state == FTUN_CORE_RUNNING &&
      control->service.implementation != NULL) {
    (void)ftun_core_service_wakeup(&control->service);
  }
  (void)pthread_mutex_unlock(&control->mutex);
}

static ftun_status_t ftun_core_cleanup_step(void *context, bool may_wait,
                                            bool *complete, bool *progress)
{
  ftun_core_control_t *control = (ftun_core_control_t *)context;
  ftun_app_cleanup_t cleanup = ftun_core_cleanup(control);
  bool reload_done = false, state_done = false, operations_done = false;
  ftun_status_t status;
  size_t count;
  uint64_t now = 0u;
  *complete = false;
  for (count = 0u; count < FTUN_APP_CLEANUP_QUOTA; count++) {
    ftun_control_task_t *task;
    (void)pthread_mutex_lock(&control->mutex);
    if (control->task_count == 0u) {
      (void)pthread_mutex_unlock(&control->mutex);
      break;
    }
    task = control->tasks[control->task_head];
    control->tasks[control->task_head] = NULL;
    control->task_head = (control->task_head + 1u) % control->task_capacity;
    control->task_count--;
    if (!task->control_priority) control->normal_task_count--;
    if (task->kind == FTUN_CONTROL_RELOAD) control->reload_pending = 0;
    (void)pthread_mutex_unlock(&control->mutex);
    ftun_control_task_consumed(task);
    *progress = true;
  }
  status = ftun_app_cleanup_worker(control->reload_worker,
    ftun_app_cleanup_slice(&cleanup, may_wait), &reload_done, progress);
  ftun_app_cleanup_record(&cleanup, status);

  (void)ftun_monotonic_now(&now);
  if (!control->state_save_done) {
    ftun_worker_usage_t usage;
    size_t callbacks = 0u;
    memset(&usage, 0, sizeof(usage));
    if (!may_wait || now >= ftun_app_cleanup_deadline(&cleanup) ||
        control->state_worker == NULL) {
      control->state_save_done = true;
    } else {
      status = ftun_worker_poll(control->state_worker,
                                 FTUN_APP_CLEANUP_QUOTA, &callbacks);
      if (callbacks != 0u) *progress = true;
      if (status == FTUN_OK) {
        status = ftun_worker_get_usage(control->state_worker, &usage);
      }
      ftun_app_cleanup_record(&cleanup, status);
      if (status != FTUN_OK) control->state_save_done = true;
      else if (usage.tasks == 0u) {
        const ftun_config_t *active = control->active_config;
        if (!control->state_save_submitted && active != NULL &&
            active->base.state_cache) {
          control->state_save_submitted = true;
          status = ftun_core_state_schedule(control->core, control,
            active->base.cache_file, ftun_app_cleanup_deadline(&cleanup));
          ftun_app_cleanup_record(&cleanup, status);
          if (status != FTUN_OK) control->state_save_done = true;
          *progress = true;
        } else control->state_save_done = true;
      }
    }
  }
  if (control->state_save_done) {
    status = ftun_app_cleanup_worker(control->state_worker,
      ftun_app_cleanup_slice(&cleanup, may_wait), &state_done, progress);
    ftun_app_cleanup_record(&cleanup, status);
  }
  if (reload_done) {
    status = ftun_core_reload_reap(control,
      ftun_app_cleanup_slice(&cleanup, may_wait));
    ftun_app_cleanup_record(&cleanup, status);
  }
  if (control->service.implementation != NULL && !control->service_stopped) {
    status = ftun_core_service_stop_until(&control->service,
      ftun_app_cleanup_slice(&cleanup, may_wait));
    ftun_app_cleanup_record(&cleanup, status);
    if (status == FTUN_OK) {
      control->service_stopped = true;
      *progress = true;
    }
  }
  status = ftun_app_cleanup_operations(control->operations, &operations_done,
                                        progress);
  ftun_app_cleanup_record(&cleanup, status);
  if (reload_done && state_done && operations_done &&
      control->task_count == 0u && !control->retired_busy &&
      (control->service_stopped || control->service.implementation == NULL)) {
    status = ftun_core_service_destroy_until(&control->service,
      ftun_app_cleanup_slice(&cleanup, may_wait));
    ftun_app_cleanup_record(&cleanup, status);
    if (status == FTUN_OK) {
      status = control->startup_candidate == NULL ? FTUN_OK
        : control->support->release(control->core, &control->startup_candidate);
      ftun_app_cleanup_record(&cleanup, status);
      if (status == FTUN_OK) {
        status = ftun_config_destroy(&control->startup_config);
        ftun_app_cleanup_record(&cleanup, status);
      }
      status = ftun_core_owned_path_destroy(&control->startup_path);
      ftun_app_cleanup_record(&cleanup, status);
      status = ftun_worker_destroy(&control->reload_worker);
      ftun_app_cleanup_record(&cleanup, status);
      status = ftun_worker_destroy(&control->state_worker);
      ftun_app_cleanup_record(&cleanup, status);
      if (control->startup_candidate == NULL && control->startup_config == NULL &&
          control->startup_path.value == NULL && control->startup_path.reservation == NULL &&
          control->reload_worker == NULL && control->state_worker == NULL) {
        bool terminal_event;
        (void)pthread_mutex_lock(&control->mutex);
        terminal_event = control->lifecycle_started && !control->runtime_stopped;
        if (terminal_event) control->runtime_stopped = true;
        (void)pthread_mutex_unlock(&control->mutex);
        if (terminal_event) {
          ftun_lifecycle_event_t event = {0};
          event.kind = FTUN_LIFECYCLE_STOPPED;
          event.generation = control->generation;
          event.status = control->first_error != FTUN_OK ? control->first_error : control->cleanup_error;
          event.reason = FTUN_LIFECYCLE_REASON_LOG_DRAINING;
          (void)ftun_core_context_finish_logging(control->core, &event);
        } else (void)ftun_core_context_finish_logging(control->core, NULL);
        status = ftun_logger_destroy_until(&control->startup_logger,
          ftun_app_cleanup_slice(&cleanup, may_wait));
        ftun_app_cleanup_record(&cleanup, status);
        status = ftun_logger_destroy_until(&control->logger,
          ftun_app_cleanup_slice(&cleanup, may_wait));
        ftun_app_cleanup_record(&cleanup, status);
      }
    }
  }
  *complete = operations_done && control->task_count == 0u &&
    control->service.implementation == NULL && !control->retired_busy &&
    control->reload_worker == NULL && control->state_worker == NULL &&
    control->startup_config == NULL && control->startup_candidate == NULL &&
    control->startup_path.value == NULL && control->startup_path.reservation == NULL &&
    control->startup_logger == NULL && control->logger == NULL &&
    control->retired_logger == NULL;
  return FTUN_OK;
}

static size_t ftun_core_default_descriptor_limit(void)
{
  struct rlimit limit;
  size_t result = FTUN_CORE_DEFAULT_DESCRIPTORS;
  if (getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur != RLIM_INFINITY &&
      limit.rlim_cur < (rlim_t)result) result = (size_t)limit.rlim_cur;
  return result;
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
  ftun_reservation_t *control_reservation = NULL;
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
  if (pthread_mutex_init(&control->mutex, NULL) != 0) {
    status = FTUN_E_IO;
    goto fail;
  }
  mutex_initialized = 1;
  if (pthread_cond_init(&control->condition, NULL) != 0) {
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
  control->bootstrap_bytes = context_usage.used + control_bytes;
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
      (void)pthread_cond_destroy(&control->condition);
    }
    if (mutex_initialized) (void)pthread_mutex_destroy(&control->mutex);
    free(control->tasks);
    free(control);
  }
  (void)ftun_reservation_release(&control_reservation);
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
  (void)pthread_mutex_lock(&task->mutex);
  task->cancelled = 1;
  prepare_operation = task->prepare_operation;
  (void)pthread_mutex_unlock(&task->mutex);
  if (prepare_operation != NULL) {
    ftun_status_t status = ftun_operation_cancel(prepare_operation);
    if (status != FTUN_OK && status != FTUN_E_STALE) return status;
  }
  return FTUN_OK;
}

static void ftun_control_task_destroy(ftun_control_task_t *task)
{
  ftun_reservation_t *reservation;
  if (task == NULL) return;
  reservation = task->reservation;
  task->reservation = NULL;
  (void)pthread_mutex_destroy(&task->mutex);
  free(task->first);
  free(task->second);
  free(task);
  (void)ftun_reservation_release(&reservation);
}

static void ftun_control_task_consumed(ftun_control_task_t *task)
{
  int destroy;
  if (task == NULL) return;
  (void)pthread_mutex_lock(&task->mutex);
  task->ring_consumed = 1;
  destroy = task->callback_complete &&
    (!task->async_started || task->async_complete);
  (void)pthread_mutex_unlock(&task->mutex);
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
    (void)pthread_mutex_lock(&control->mutex);
    deliver = control->callbacks_enabled && control->owner_valid;
    (void)pthread_mutex_unlock(&control->mutex);
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
      (void)pthread_mutex_lock(&control->mutex);
      value.generation = control->generation;
      (void)pthread_mutex_unlock(&control->mutex);
    }
    task->command_completion(operation, value, task->completion_user);
  } else if (deliver) task->completion(operation, result, task->completion_user);
  (void)pthread_mutex_lock(&task->mutex);
  task->callback_complete = 1;
  destroy = task->ring_consumed &&
    (!task->async_started || task->async_complete);
  (void)pthread_mutex_unlock(&task->mutex);
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
  ftun_reservation_t *reservation = NULL;
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
  (void)pthread_mutex_lock(&control->mutex);
  if (control->state != FTUN_CORE_RUNNING || control->stop_requested) {
    (void)pthread_mutex_unlock(&control->mutex);
    return FTUN_E_STALE;
  }
  (void)pthread_mutex_unlock(&control->mutex);
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
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  task->reservation = reservation;
  task->control_priority = kind != FTUN_CONTROL_POST;
  if (pthread_mutex_init(&task->mutex, NULL) != 0) {
    task->reservation = NULL;
    free(task);
    (void)ftun_reservation_release(&reservation);
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
  (void)pthread_mutex_lock(&control->mutex);
  if (control->state != FTUN_CORE_RUNNING || control->stop_requested) {
    (void)pthread_mutex_unlock(&control->mutex);
    status = FTUN_E_STALE;
    goto fail;
  }
  if (task->expected.present && task->expected.generation != control->generation) {
    (void)pthread_mutex_unlock(&control->mutex);
    status = FTUN_E_STALE;
    goto fail;
  }
  if (control->task_count >= control->task_capacity ||
      (!task->control_priority && control->normal_task_count >=
        control->task_capacity - control->task_control_reserve)) {
    (void)pthread_mutex_unlock(&control->mutex);
    status = FTUN_E_LIMIT;
    goto fail;
  }
  if (kind == FTUN_CONTROL_RELOAD &&
      (control->reload_pending || control->retired_busy)) {
    (void)pthread_mutex_unlock(&control->mutex);
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
    (void)pthread_mutex_unlock(&control->mutex);
    goto fail;
  }
  task->operation = operation;
  control->tasks[control->task_tail] = task;
  control->task_tail = (control->task_tail + 1u) % control->task_capacity;
  control->task_count++;
  if (!task->control_priority) control->normal_task_count++;
  if (kind == FTUN_CONTROL_RELOAD) {
    control->reload_pending = 1;
    ftun_core_event(control, FTUN_LIFECYCLE_RELOAD_REQUESTED, control->generation, FTUN_OK);
  }
  if (control->service.implementation != NULL) {
    (void)ftun_core_service_wakeup(&control->service);
  }
  (void)pthread_cond_signal(&control->condition);
  (void)pthread_mutex_unlock(&control->mutex);
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
    (void)pthread_mutex_lock(&control->mutex);
    if (control->lifecycle_started) {
      event.generation = control->generation;
      (void)ftun_lifecycle_emit(core, &event);
    }
    (void)pthread_mutex_unlock(&control->mutex);
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

static int ftun_control_task_cancelled(ftun_control_task_t *task)
{
  int cancelled;
  (void)pthread_mutex_lock(&task->mutex);
  cancelled = task->cancelled;
  (void)pthread_mutex_unlock(&task->mutex);
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
      (void)pthread_mutex_lock(&control->mutex);
      control->reload_pending = 0;
      (void)pthread_mutex_unlock(&control->mutex);
    }
    return;
  }
  if (task->expected.present && task->expected.generation != control->generation) {
    status = FTUN_E_STALE;
    goto completed;
  }
  if (task->kind == FTUN_CONTROL_RELOAD) {
    const ftun_config_t *active = control->active_config;
    if (active != NULL && active->base.state_cache) {
      ftun_status_t save_status = ftun_core_state_schedule(
        core, control, active->base.cache_file, 0u);
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
      if (active != NULL && active->base.state_cache) {
        ftun_status_t save_status = ftun_core_state_schedule(
          core, control, active->base.cache_file, 0u);
        if (save_status != FTUN_OK) {
          ftun_core_log_status(core, save_status, FTUN_STAGE_STATE_RESTORE,
                               FTUN_DIAGNOSTIC_STATE_SAVE, control->support->state_failure_message);
        }
      }
    }
  }
completed:
  task->result_generation = control->generation;
  if (status != FTUN_OK) {
    ftun_core_log_status(core, status, stage, FTUN_DIAGNOSTIC_CONTROL, "control operation failed");
  }
  result.status = status;
  result.stage = stage;
  if (task->kind == FTUN_CONTROL_RELOAD) {
    ftun_core_reload_event(task, control, status);
    (void)pthread_mutex_lock(&control->mutex);
    control->reload_pending = 0;
    (void)pthread_mutex_unlock(&control->mutex);
  }
  (void)ftun_operation_complete(task->completion_token, result);
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
  (void)pthread_mutex_lock(&control->mutex);
  if (control->state != FTUN_CORE_CREATED) {
    (void)pthread_mutex_unlock(&control->mutex);
    return FTUN_E_STALE;
  }
  control->state = FTUN_CORE_STARTING;
  control->owner = pthread_self();
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
  (void)pthread_mutex_unlock(&control->mutex);
  (void)ftun_event_log_begin(control->events);
  ftun_core_event(control, FTUN_LIFECYCLE_STARTING, control->generation, FTUN_OK);
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
  if (status == FTUN_OK) {
    status = ftun_core_transaction(core, control, path, &stage);
  }
  if (status != FTUN_OK) {
    ftun_status_t cleanup_status;
    control->first_error = status;
    control->state_save_done = true;
    ftun_core_event(control, FTUN_LIFECYCLE_ROLLBACK, control->generation, status);
    (void)pthread_mutex_lock(&control->mutex);
    control->state = FTUN_CORE_STOPPING;
    (void)pthread_mutex_unlock(&control->mutex);
    ftun_app_cleanup_begin(&cleanup);
    cleanup_status = ftun_app_cleanup_drive(&cleanup, ftun_core_cleanup_step,
                                             control, true);
    if (cleanup_status != FTUN_OK) {
      ftun_core_event(control, FTUN_LIFECYCLE_STOP_FAILED, control->generation, cleanup_status);
    }
    if (cleanup_status == FTUN_OK) {
      cleanup_status = ftun_operation_queue_reopen(control->operations);
    }
    (void)pthread_mutex_lock(&control->mutex);
    if (cleanup_status == FTUN_OK) {
      control->state = FTUN_CORE_CREATED;
      control->stop_requested = 0;
    }
    control->owner_valid = 0;
    control->callbacks_enabled = false;
    control->run_returned = true;
    control->run_result = cleanup_status == FTUN_E_TIMEOUT ? cleanup_status : status;
    (void)pthread_mutex_unlock(&control->mutex);
    return cleanup_status == FTUN_E_TIMEOUT ? cleanup_status : status;
  }
  (void)pthread_mutex_lock(&control->mutex);
  control->state = FTUN_CORE_RUNNING;
  ftun_core_event(control, FTUN_LIFECYCLE_RUNNING, control->generation, FTUN_OK);
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
    if (control->stop_requested) break;
    if (control->task_count != 0u) {
      task = control->tasks[control->task_head];
      control->tasks[control->task_head] = NULL;
      control->task_head = (control->task_head + 1u) % control->task_capacity;
      control->task_count--;
      if (!task->control_priority) control->normal_task_count--;
    }
    pending_control = control->task_count != 0u;
    (void)pthread_mutex_unlock(&control->mutex);
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
    }
    if (status == FTUN_OK && control->state_worker != NULL) {
      status = ftun_worker_poll(control->state_worker, 1u,
                                &state_callbacks);
      round_work += state_callbacks;
      if (state_callbacks == 1u) quota_exhausted = true;
      if (status != FTUN_OK) {
        ftun_core_log_status(core, status, FTUN_STAGE_STATE_RESTORE,
                             FTUN_DIAGNOSTIC_STATE_WORKER, "state worker failed");
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
        const struct timespec pause = {0, 1000 * 1000};
        (void)nanosleep(&pause, NULL);
      }
    }
    may_block = task == NULL && reload_callbacks == 0u &&
      state_callbacks == 0u && !pending_control &&
      !ftun_operation_queue_has_ready(control->operations) &&
      !cleanup_retry;
    (void)ftun_monotonic_now(&before_engine_ms);
    if (status == FTUN_OK) {
      status = ftun_core_service_run_once(&control->service, may_block,
                                          &service_usage);
      if (status != FTUN_OK) {
        ftun_core_log_status(core, status, FTUN_STAGE_CONTROL,
                             FTUN_DIAGNOSTIC_SERVICE_RUN, "production data plane failed");
      }
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
    }
    round_work += dispatched;
    if (dispatched == FTUN_CORE_OPERATION_DISPATCH_QUOTA) {
      quota_exhausted = true;
    }
    if (status != FTUN_OK) {
      (void)pthread_mutex_lock(&control->mutex);
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
    (void)pthread_mutex_lock(&control->mutex);
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
  (void)pthread_mutex_unlock(&control->mutex);
  ftun_core_event(control, FTUN_LIFECYCLE_STOPPING, control->generation, status);
  ftun_app_cleanup_begin(&cleanup);
  {
    ftun_status_t cleanup_status = ftun_app_cleanup_drive(&cleanup,
      ftun_core_cleanup_step, control, true);
    if (cleanup_status != FTUN_OK) {
      ftun_core_event(control, FTUN_LIFECYCLE_STOP_FAILED, control->generation, cleanup_status);
    }
    if (cleanup_status == FTUN_E_TIMEOUT || status == FTUN_OK) {
      status = cleanup_status;
    }
    if (status == FTUN_OK) status = control->cleanup_error;
    (void)pthread_mutex_lock(&control->mutex);
    control->state = cleanup_status == FTUN_OK
      ? FTUN_CORE_STOPPED : FTUN_CORE_STOPPING;
    control->owner_valid = 0;
    control->callbacks_enabled = false;
    control->run_returned = true;
    control->run_result = status;
    (void)pthread_cond_broadcast(&control->condition);
    (void)pthread_mutex_unlock(&control->mutex);
  }
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
  (void)pthread_mutex_lock(&control->mutex);
  if (out != NULL) {
    out->generation = control->generation;
    out->phase = control->state == FTUN_CORE_STOPPED ?
      FTUN_APP_COMMAND_COMPLETED : FTUN_APP_COMMAND_REQUESTED;
  }
  if (expected != NULL && expected->present && expected->generation != control->generation) {
    (void)pthread_mutex_unlock(&control->mutex);
    return FTUN_E_STALE;
  }
  if (control->state == FTUN_CORE_STOPPED) {
    (void)pthread_mutex_unlock(&control->mutex);
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
    (void)pthread_cond_broadcast(&control->condition);
    (void)pthread_mutex_unlock(&control->mutex);
    return FTUN_OK;
  }
  if (control->state != FTUN_CORE_RUNNING &&
      control->state != FTUN_CORE_STARTING &&
      control->state != FTUN_CORE_STOPPING) {
    (void)pthread_mutex_unlock(&control->mutex);
    return FTUN_E_STALE;
  }
  control->stop_requested = 1;
  control->stop_deadline_ms = deadline_ms;
  if (control->state == FTUN_CORE_RUNNING &&
        control->service.implementation != NULL) {
    (void)ftun_core_service_wakeup(&control->service);
  }
  (void)pthread_cond_broadcast(&control->condition);
  (void)pthread_mutex_unlock(&control->mutex);
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
  (void)pthread_mutex_lock(&control->mutex);
  if (control->config_path.value != NULL) {
    size_t length = strnlen(control->config_path.value, sizeof(out->config_path));
    if (length >= sizeof(out->config_path)) {
      (void)pthread_mutex_unlock(&control->mutex);
      return FTUN_E_LIMIT;
    }
    memcpy(out->config_path, control->config_path.value, length + 1u);
  }
  out->core.state = control->state;
  out->core.generation = control->generation;
  out->core.owner_rounds = control->owner_rounds;
  out->core.owner_max_busy_ms = control->owner_max_busy_ms;
  out->core.owner_max_deadline_lateness_ms = control->owner_max_deadline_lateness_ms;
  out->core.owner_max_work = control->owner_max_work;
  out->core.owner_quota_exhaustions = control->owner_quota_exhaustions;
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
  (void)pthread_mutex_unlock(&control->mutex);
  if (status != FTUN_OK) memset(out, 0, sizeof(*out));
  return status;
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
  ftun_reservation_t *reservation;
  if (core == NULL) return FTUN_E_INVALID;
  owned = *core;
  if (owned == NULL) return FTUN_OK;
  status = ftun_core_control(owned, &control);
  if (status != FTUN_OK) return status;
  (void)pthread_mutex_lock(&control->mutex);
  state = control->state;
  if (state != FTUN_CORE_CREATED && state != FTUN_CORE_STOPPED &&
      !(state == FTUN_CORE_STOPPING && !control->owner_valid)) {
    (void)pthread_mutex_unlock(&control->mutex);
    return FTUN_E_AGAIN;
  }
  (void)pthread_mutex_unlock(&control->mutex);
  cleanup = ftun_core_cleanup(control);
  status = ftun_app_cleanup_drive(&cleanup, ftun_core_cleanup_step,
                                  control, false);
  if (status != FTUN_OK) return status;
  (void)pthread_mutex_lock(&control->mutex);
  control->state = FTUN_CORE_STOPPED;
  (void)pthread_mutex_unlock(&control->mutex);
  status = ftun_operation_queue_destroy(&control->operations);
  if (status != FTUN_OK) return status;
  (void)ftun_core_context_set_logger(owned, NULL);
  if (control->support != NULL) {
    status = control->support->clear(owned);
    if (status != FTUN_OK) return status;
  }
  status = ftun_config_destroy(&control->active_config);
  if (status != FTUN_OK) return status;
  (void)pthread_mutex_lock(&control->mutex);
  status = ftun_core_owned_path_destroy(&control->config_path);
  (void)pthread_mutex_unlock(&control->mutex);
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
  (void)pthread_cond_destroy(&control->condition);
  (void)pthread_mutex_destroy(&control->mutex);
  free(control);
  status = ftun_reservation_release(&reservation);
  if (status == FTUN_OK) status = ftun_budget_destroy(&control_budget);
  if (status == FTUN_OK) status = ftun_budget_destroy(&root_budget);
  return status;
}
