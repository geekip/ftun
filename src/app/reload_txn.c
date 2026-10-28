#define _POSIX_C_SOURCE 200809L

#include "app/runtime_internal.h"

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
  const ftun_config_t *next, bool proxy_runtime)
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
  if (!proxy_runtime) return FTUN_OK;
  if (active->dns.fake_ip.persist != next->dns.fake_ip.persist ||
      !ftun_core_string_equal(active->dns.fake_ip.range,
                              next->dns.fake_ip.range) ||
      ((active->dns.fake_ip.persist || next->dns.fake_ip.persist) &&
       !ftun_core_string_equal(active->base.cache_file,
                               next->base.cache_file))) {
    return FTUN_E_RESTART_REQUIRED;
  }
  if (active->inbound_count != next->inbound_count) {
    return FTUN_E_RESTART_REQUIRED;
  }
  {
    size_t left_index;
    for (left_index = 0u; left_index < active->inbound_count; left_index++) {
      const ftun_config_inbound_t *left = &active->inbounds[left_index];
      const ftun_config_inbound_t *right = NULL;
      size_t right_index;
      for (right_index = 0u; right_index < next->inbound_count; right_index++) {
        if (ftun_core_string_equal(left->name, next->inbounds[right_index].name)) {
          right = &next->inbounds[right_index];
          break;
        }
      }
      if (right == NULL || left->kind != right->kind) {
        return FTUN_E_RESTART_REQUIRED;
      }
      if (left->kind == FTUN_CONFIG_INBOUND_TUN) {
        if (!ftun_core_string_equal(left->name, right->name) ||
            !ftun_core_string_equal(left->interface_name, right->interface_name) ||
            !ftun_core_string_equal(left->stack, right->stack) ||
            !ftun_core_string_equal(left->ipv4_address, right->ipv4_address) ||
            left->mtu != right->mtu || left->tcp != right->tcp ||
            left->udp != right->udp || left->auto_route != right->auto_route ||
            left->strict_route != right->strict_route ||
            left->dns_hijack != right->dns_hijack) {
          return FTUN_E_RESTART_REQUIRED;
        }
      } else if (!ftun_core_string_equal(left->listen, right->listen) ||
                 left->udp != right->udp) {
        return FTUN_E_RESTART_REQUIRED;
      }
    }
  }
  return FTUN_OK;
}

void ftun_core_log_status(ftun_core_t *core, ftun_status_t status,
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

ftun_status_t ftun_core_state_schedule(
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

ftun_status_t ftun_core_reload_result_release(
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

ftun_status_t ftun_core_transaction(ftun_core_t *core,
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
  status = ftun_core_context_generation_reserve(core, core, &next_generation);
  if (status != FTUN_OK) return status;
  status = ftun_config_load_budget_traced(control->budget, path, &config, &trace);
  ftun_core_config_trace(control, &trace, next_generation);
  if (status != FTUN_OK) {
    (void)ftun_core_context_generation_release(core, core, next_generation);
    return status;
  }
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
  status = ftun_core_generation_settle(core, next_generation);
  if (status != FTUN_OK) goto done;
  control->active_config = config;
  config = NULL;
  control->service = next_service;
  memset(&next_service, 0, sizeof(next_service));
  (void)pthread_mutex_lock(&control->mutex);
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
    (void)ftun_core_context_generation_release(core, core, next_generation);
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

ftun_status_t ftun_core_reload_transaction_cleanup(
  ftun_core_t *core, ftun_core_control_t *control,
  ftun_core_reload_transaction_t **transaction, uint64_t deadline)
{
  ftun_core_reload_transaction_t *owned;
  ftun_status_t status;
  if (transaction == NULL || *transaction == NULL) return FTUN_OK;
  owned = *transaction;
  if (owned->generation_reserved) {
    status = ftun_core_context_generation_release(core, core, owned->next_generation);
    if (status != FTUN_OK && status != FTUN_E_STALE) return status;
    owned->generation_reserved = false;
  }
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
ftun_status_t ftun_core_reload_reap(ftun_core_control_t *control,
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

ftun_status_t ftun_core_reload_prepare_transaction(
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
    status = ftun_core_reload_compatible(active, transaction->config,
      control->support != NULL);
  }
  if (status == FTUN_OK && ftun_core_generation_now(control) != prepared->base_generation) {
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
    /* 预留下一代次：FRS 等其他来源正在发布时返回 AGAIN，可重试。 */
    status = ftun_core_context_generation_reserve(core, core,
      &transaction->next_generation);
    if (status == FTUN_OK) transaction->generation_reserved = true;
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

ftun_status_t ftun_core_reload_commit_transaction(
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
  status = ftun_core_generation_settle(core, transaction->next_generation);
  if (status != FTUN_OK) return status;
  transaction->generation_reserved = false;
  {
    ftun_config_t *previous = control->active_config;
    control->active_config = transaction->config;
    transaction->config = previous;
  }
  (void)pthread_mutex_lock(&control->mutex);
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

void ftun_core_reload_event(ftun_control_task_t *task,
  ftun_core_control_t *control, ftun_status_t status)
{
  if (task->reload_event_recorded) return;
  task->reload_event_recorded = true;
  ftun_core_event(control, status == FTUN_OK ? FTUN_LIFECYCLE_RELOAD_COMMITTED :
    (status == FTUN_E_CANCELLED ? FTUN_LIFECYCLE_RELOAD_CANCELLED : FTUN_LIFECYCLE_RELOAD_REJECTED),
    ftun_core_generation_now(control), status);
}

static void ftun_core_reload_finish(ftun_control_task_t *task,
                                    ftun_core_control_t *control,
                                    ftun_error_t result)
{
  int destroy;
  if (control != NULL) {
    ftun_core_reload_event(task, control, result.status);
    if (result.status != FTUN_OK && result.status != FTUN_E_CANCELLED) {
      /* LIMIT 常见于旧代次仍被连接占用、保留数已满：把原因写出来，
       * 否则运维只看到一个笼统的失败。 */
      ftun_core_log_status(task->core, result.status, result.stage,
                           FTUN_DIAGNOSTIC_CONTROL,
        result.status == FTUN_E_LIMIT
          ? "control operation rejected: resource limit reached (older generations "
            "still hold connections; see base.reload-retain)"
          : "control operation failed");
    }
    (void)pthread_mutex_lock(&control->mutex);
    control->reload_pending = 0;
    (void)pthread_mutex_unlock(&control->mutex);
  }
  task->result_generation = ftun_core_generation_now(control);
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

ftun_status_t ftun_core_reload_schedule(ftun_core_control_t *control,
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
  if (ftun_core_generation_now(control) == UINT64_MAX) return FTUN_E_LIMIT;
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
  work->base_generation = ftun_core_generation_now(control);
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
    work->socket_mark = control->active_config->base.routing_mark;
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

void ftun_core_reload_wakeup(void *user)
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
