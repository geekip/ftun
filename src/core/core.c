#define _POSIX_C_SOURCE 200809L

#include "ftun/ftun.h"

#include "config/config.h"
#include "config/model.h"
#include "config/parser.h"
#include "core/budget.h"
#include "core/engine.h"
#include "core/http_fetch.h"
#include "core/operation.h"
#include "core/runtime.h"
#include "core/state.h"
#include "state/group_cache.h"
#if defined(FTUN_HAVE_MODULE_FRS)
#include "frs/frs.h"
#include "platform/file.h"
#endif
#include "util/logger.h"
#include "util/time.h"

#include <stddef.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define FTUN_CORE_DEFAULT_MEMORY (64u * 1024u * 1024u)
#define FTUN_CORE_DEFAULT_OPERATIONS 1024u
#define FTUN_CORE_MAX_OPERATIONS 4096u
#define FTUN_CORE_DEFAULT_RETAINED 4u
#define FTUN_CORE_CONTROL_STRING 4096u

typedef enum {
  FTUN_CONTROL_POST = 1,
  FTUN_CONTROL_RELOAD,
  FTUN_CONTROL_SELECT
} ftun_control_kind_t;

typedef struct ftun_control_task {
  ftun_core_t *core;
  ftun_operation_t *operation;
  ftun_completion_fn completion;
  void *completion_user;
  char *first;
  char *second;
  ftun_control_kind_t kind;
  pthread_mutex_t mutex;
  int cancelled;
  int ring_consumed;
  int callback_complete;
} ftun_control_task_t;

typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  pthread_t owner;
  ftun_budget_t *budget;
  ftun_operation_queue_t *operations;
  ftun_logger_t *logger;
  ftun_engine_t *engine;
  ftun_control_task_t **tasks;
  char *config_path;
  size_t task_capacity;
  size_t task_head;
  size_t task_tail;
  size_t task_count;
  uint64_t generation;
  ftun_core_state_t state;
  int owner_valid;
  int stop_requested;
  int reload_pending;
} ftun_core_control_t;

const char *ftun_version(void)
{
  return FTUN_VERSION;
}

static ftun_status_t ftun_core_control(ftun_core_t *core,
                                       ftun_core_control_t **out)
{
  void *value = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_runtime_manager_control(core, &value);
  if (status != FTUN_OK || value == NULL) return FTUN_E_INVALID;
  *out = (ftun_core_control_t *)value;
  return FTUN_OK;
}

static char *ftun_core_copy_string(const char *value)
{
  size_t length;
  char *copy;
  if (value == NULL) return NULL;
  length = strlen(value);
  if (length == 0u || length > FTUN_CORE_CONTROL_STRING) return NULL;
  copy = (char *)malloc(length + 1u);
  if (copy != NULL) memcpy(copy, value, length + 1u);
  return copy;
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
  return ftun_logger_create(&options, out);
}

static int ftun_core_string_equal(const char *left, const char *right)
{
  if (left == NULL || right == NULL) return left == right;
  return strcmp(left, right) == 0;
}

static int ftun_core_tun_equal(const ftun_config_inbound_t *left,
                               const ftun_config_inbound_t *right)
{
  return left->kind == right->kind &&
    ftun_core_string_equal(left->name, right->name) &&
    ftun_core_string_equal(left->interface_name, right->interface_name) &&
    ftun_core_string_equal(left->stack, right->stack) &&
    ftun_core_string_equal(left->ipv4_address, right->ipv4_address) &&
    left->mtu == right->mtu && left->tcp == right->tcp &&
    left->udp == right->udp && left->auto_route == right->auto_route &&
    left->strict_route == right->strict_route &&
    left->dns_hijack == right->dns_hijack;
}

static ftun_status_t ftun_core_reload_compatible(const ftun_config_t *active,
                                                  const ftun_config_t *next)
{
  size_t left_index;
  if (active == NULL || next == NULL) return FTUN_E_INVALID;
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
      if (!ftun_core_tun_equal(left, right)) return FTUN_E_RESTART_REQUIRED;
    } else if (!ftun_core_string_equal(left->listen, right->listen) ||
               left->udp != right->udp) {
      return FTUN_E_RESTART_REQUIRED;
    }
  }
  return FTUN_OK;
}

static void ftun_core_log_status(ftun_core_t *core, ftun_status_t status,
                                 uint32_t stage, const char *message)
{
  ftun_diagnostic_t diagnostic;
  memset(&diagnostic, 0, sizeof(diagnostic));
  diagnostic.error.status = status;
  diagnostic.error.stage = stage;
  diagnostic.message.data = message;
  diagnostic.message.length = strlen(message);
  (void)ftun_log_emit(core, &diagnostic);
}

#if defined(FTUN_HAVE_MODULE_FRS)
typedef struct {
  ftun_file_stage_t reached;
} ftun_core_file_publish_t;

static ftun_status_t ftun_core_file_stage(ftun_file_stage_t stage, void *user)
{
  ftun_core_file_publish_t *publish = (ftun_core_file_publish_t *)user;
  if (publish == NULL) return FTUN_E_INVALID;
  publish->reached = stage;
  return FTUN_OK;
}
#endif

static ftun_status_t ftun_core_runtime_prepare(
  ftun_core_t *core, ftun_core_control_t *control,
  const ftun_config_t *config, ftun_runtime_t **out)
{
#if defined(FTUN_HAVE_MODULE_FRS)
  struct stat info;
  ftun_budget_usage_t usage;
  ftun_http_fetch_spec_t fetch_spec;
  ftun_http_fetch_result_t fetched;
  ftun_frs_view_t *view = NULL;
  ftun_core_file_publish_t publish;
  uint64_t now_ms;
  ftun_status_t status;
  if (config != NULL && config->frs.active && config->frs.path != NULL &&
      stat(config->frs.path, &info) != 0 && errno == ENOENT &&
      config->frs.auto_update && config->frs.url != NULL &&
      config->frs.url[0] != '\0') {
    memset(&fetch_spec, 0, sizeof(fetch_spec));
    memset(&fetched, 0, sizeof(fetched));
    memset(&publish, 0, sizeof(publish));
    status = ftun_budget_get_usage(control->budget, &usage);
    if (status == FTUN_OK && usage.normal_available <= 2u * 1024u * 1024u) {
      status = FTUN_E_LIMIT;
    }
    if (status == FTUN_OK) status = ftun_monotonic_now(&now_ms);
    if (status == FTUN_OK && now_ms > UINT64_MAX - UINT64_C(30000)) {
      status = FTUN_E_LIMIT;
    }
    if (status == FTUN_OK) {
      fetch_spec.budget = control->budget;
      fetch_spec.url.data = config->frs.url;
      fetch_spec.url.length = strlen(config->frs.url);
      fetch_spec.maximum_bytes = usage.normal_available -
        1024u * 1024u;
      fetch_spec.deadline_ms = now_ms + UINT64_C(30000);
      fetch_spec.socket_mark = UINT32_C(0x4654);
      {
        ftun_string_t resolver = {NULL, 0u};
        if (config->frs.dns_server != NULL &&
            config->frs.dns_server[0] != '\0') {
          resolver.data = config->frs.dns_server;
          resolver.length = strlen(config->frs.dns_server);
        }
        status = ftun_http_fetch_resolver(config, NULL, resolver,
                                          &fetch_spec);
      }
      if (status == FTUN_OK) {
        status = ftun_http_fetch_route(config, NULL,
                                        config->frs.update_outbound,
                                        &fetch_spec);
      }
    }
    if (status == FTUN_OK) status = ftun_http_fetch(&fetch_spec, &fetched);
    if (status == FTUN_OK && fetched.status != 200u) {
      status = FTUN_E_PROTOCOL;
    }
    if (status == FTUN_OK) {
      status = ftun_frs_open_bytes(
        (ftun_bytes_t){fetched.data, fetched.length}, &view);
    }
    if (status == FTUN_OK) {
      status = ftun_runtime_prepare_with_frs(core, config, view, out);
    }
    if (status == FTUN_OK) {
      status = ftun_runtime_can_commit(core, *out);
    }
    if (status == FTUN_OK) {
      status = ftun_file_write_atomic_with_hook(config->frs.path,
        (ftun_bytes_t){fetched.data, fetched.length}, 0644u,
        ftun_core_file_stage, &publish);
      if (status != FTUN_OK && publish.reached >= FTUN_FILE_STAGE_RENAMED) {
        ftun_core_log_status(core, status, FTUN_STAGE_COMMIT,
          "FRS startup publish succeeded but directory durability is uncertain");
        status = FTUN_OK;
      }
    }
    if (status != FTUN_OK && out != NULL && *out != NULL) {
      (void)ftun_runtime_abort(core, out);
    }
    (void)ftun_frs_view_release(&view);
    ftun_http_fetch_release(&fetched);
    return status;
  }
#else
  (void)control;
#endif
  return ftun_runtime_prepare(core, config, out);
}

static ftun_status_t ftun_core_transaction(ftun_core_t *core,
                                           ftun_core_control_t *control,
                                           const char *path, int reload,
                                           uint32_t *out_stage)
{
  const ftun_config_t *active = NULL;
  ftun_config_t *config = NULL;
  ftun_runtime_t *candidate = NULL;
  ftun_logger_t *next_logger = NULL;
  ftun_engine_t *next_engine = NULL;
  ftun_logger_t *old_logger;
  char *next_path = NULL;
  ftun_state_restore_info_t restore_info;
  uint64_t now_ms = 0u;
  uint64_t next_generation = 0u;
  int replace_logger = 1;
  ftun_status_t status;
  memset(&restore_info, 0, sizeof(restore_info));
  if (out_stage != NULL) *out_stage = FTUN_STAGE_CONFIG_READ;
  status = ftun_config_load(core, path, &config);
  if (status != FTUN_OK) return status;
  if (out_stage != NULL) *out_stage = FTUN_STAGE_CONFIG_PREPARE;
  if (reload) {
    status = ftun_runtime_active_config(core, &active);
    if (status == FTUN_OK) status = ftun_core_reload_compatible(active, config);
    if (status != FTUN_OK) goto done;
    replace_logger = !ftun_core_string_equal(active->log.level,
                                              config->log.level) ||
      !ftun_core_string_equal(active->log.file, config->log.file);
  }
  if (replace_logger) {
    status = ftun_core_logger_create(config, &next_logger);
    if (status != FTUN_OK) goto done;
  }
  next_path = ftun_core_copy_string(config->source_path == NULL
    ? path : config->source_path);
  if (next_path == NULL) {
    status = FTUN_E_LIMIT;
    goto done;
  }
  status = ftun_core_runtime_prepare(core, control, config, &candidate);
  if (status != FTUN_OK) goto done;
  if (out_stage != NULL) *out_stage = FTUN_STAGE_STATE_RESTORE;
  status = ftun_monotonic_now(&now_ms);
  if (status == FTUN_OK) {
    status = ftun_state_restore_candidate_at(core, config, now_ms,
      15u * 60u * 1000u, &restore_info);
  }
  if (status != FTUN_OK) goto done;
  if (out_stage != NULL) *out_stage = FTUN_STAGE_COMMIT;
  {
    ftun_runtime_manager_info_t info;
    status = ftun_runtime_manager_get_info(core, &info);
    if (status != FTUN_OK || info.generation == UINT64_MAX) {
      if (status == FTUN_OK) status = FTUN_E_LIMIT;
      goto done;
    }
    next_generation = info.generation + 1u;
  }
  if (!reload) {
    status = ftun_engine_prepare(core, control->budget, control->operations,
                                 config, next_generation, &next_engine);
    if (status != FTUN_OK) goto done;
  } else {
    status = ftun_engine_reload_prepare(control->engine, config,
                                        next_generation);
    if (status != FTUN_OK) goto done;
  }
  status = ftun_runtime_commit(core, &candidate);
  if (status != FTUN_OK) goto done;
  if (reload) {
    status = ftun_engine_reload_commit(control->engine, next_generation);
  } else {
    control->engine = next_engine;
    next_engine = NULL;
    status = ftun_engine_activate(control->engine);
  }
  if (status != FTUN_OK) goto done;
  (void)pthread_mutex_lock(&control->mutex);
  control->generation = next_generation;
  (void)pthread_mutex_unlock(&control->mutex);
  old_logger = NULL;
  if (replace_logger) {
    old_logger = control->logger;
    control->logger = next_logger;
    next_logger = NULL;
  }
  free(control->config_path);
  control->config_path = next_path;
  next_path = NULL;
  if (replace_logger) {
    (void)ftun_runtime_manager_set_logger(core, control->logger);
  }
  (void)ftun_logger_destroy(&old_logger);
  if (restore_info.cache_discarded) {
    ftun_core_log_status(core, FTUN_E_STALE, FTUN_STAGE_STATE_RESTORE,
                         "discarded incompatible group cache");
  }

done:
  if (candidate != NULL) (void)ftun_runtime_abort(core, &candidate);
  if (reload && control->engine != NULL) {
    (void)ftun_engine_reload_abort(control->engine);
  }
  (void)ftun_engine_destroy(&next_engine);
  (void)ftun_logger_destroy(&next_logger);
  free(next_path);
  (void)ftun_config_destroy(&config);
  return status;
}

ftun_status_t ftun_core_create(const ftun_core_options_t *options,
                               ftun_core_t **out)
{
  const size_t minimum = offsetof(ftun_core_options_t, operation_capacity);
  ftun_core_control_t *control = NULL;
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  size_t memory_limit;
  size_t operation_capacity = FTUN_CORE_DEFAULT_OPERATIONS;
  size_t retained_limit = FTUN_CORE_DEFAULT_RETAINED;
  int mutex_initialized = 0;
  int condition_initialized = 0;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (options == NULL || out == NULL || options->struct_size < minimum ||
      options->abi_version != FTUN_ABI_VERSION) return FTUN_E_INVALID;
  memory_limit = options->owned_memory_limit == 0u
    ? FTUN_CORE_DEFAULT_MEMORY : options->owned_memory_limit;
  if (options->struct_size >= offsetof(ftun_core_options_t, operation_capacity) +
      sizeof(options->operation_capacity) && options->operation_capacity != 0u) {
    operation_capacity = options->operation_capacity;
  }
  if (options->struct_size >= offsetof(ftun_core_options_t,
      retained_runtime_limit) + sizeof(options->retained_runtime_limit) &&
      options->retained_runtime_limit != 0u) {
    retained_limit = options->retained_runtime_limit;
  }
  if (operation_capacity > FTUN_CORE_MAX_OPERATIONS) return FTUN_E_LIMIT;
  status = ftun_budget_create(NULL, memory_limit, 0u, &budget);
  if (status != FTUN_OK) return status;
  status = ftun_runtime_manager_create(budget, retained_limit, &core);
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
  status = ftun_operation_queue_create(budget, operation_capacity,
                                       &control->operations);
  if (status != FTUN_OK) {
    goto fail;
  }
  control->budget = budget;
  control->task_capacity = operation_capacity;
  control->state = FTUN_CORE_CREATED;
  status = ftun_runtime_manager_set_control(core, control);
  if (status != FTUN_OK) goto fail;
  *out = core;
  return FTUN_OK;

fail:
  if (control != NULL) {
    (void)ftun_operation_queue_destroy(&control->operations);
    if (condition_initialized) {
      (void)pthread_cond_destroy(&control->condition);
    }
    if (mutex_initialized) (void)pthread_mutex_destroy(&control->mutex);
    free(control->tasks);
    free(control);
  }
  (void)ftun_runtime_manager_destroy(&core);
  (void)ftun_budget_destroy(&budget);
  return status;
}

static ftun_status_t ftun_control_task_cancel(void *user)
{
  ftun_control_task_t *task = (ftun_control_task_t *)user;
  if (task == NULL) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&task->mutex);
  task->cancelled = 1;
  (void)pthread_mutex_unlock(&task->mutex);
  return FTUN_OK;
}

static void ftun_control_task_destroy(ftun_control_task_t *task)
{
  if (task == NULL) return;
  (void)pthread_mutex_destroy(&task->mutex);
  free(task->first);
  free(task->second);
  free(task);
}

static void ftun_control_task_consumed(ftun_control_task_t *task)
{
  int destroy;
  if (task == NULL) return;
  (void)pthread_mutex_lock(&task->mutex);
  task->ring_consumed = 1;
  destroy = task->callback_complete;
  (void)pthread_mutex_unlock(&task->mutex);
  if (destroy) ftun_control_task_destroy(task);
}

static void ftun_control_task_complete(ftun_operation_t *operation,
                                       ftun_error_t result, void *user)
{
  ftun_control_task_t *task = (ftun_control_task_t *)user;
  int destroy;
  task->completion(operation, result, task->completion_user);
  (void)pthread_mutex_lock(&task->mutex);
  task->callback_complete = 1;
  destroy = task->ring_consumed;
  (void)pthread_mutex_unlock(&task->mutex);
  if (destroy) ftun_control_task_destroy(task);
}

static ftun_status_t ftun_core_submit(ftun_core_t *core,
                                      ftun_control_kind_t kind,
                                      const char *first, const char *second,
                                      ftun_completion_fn completion, void *user,
                                      ftun_operation_t **out)
{
  ftun_core_control_t *control = NULL;
  ftun_control_task_t *task = NULL;
  ftun_operation_t *operation = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core == NULL || completion == NULL || out == NULL ||
      (kind != FTUN_CONTROL_POST &&
       (first == NULL || first[0] == '\0')) ||
      (kind == FTUN_CONTROL_SELECT &&
       (second == NULL || second[0] == '\0'))) return FTUN_E_INVALID;
  status = ftun_core_control(core, &control);
  if (status != FTUN_OK) return status;
  task = (ftun_control_task_t *)calloc(1u, sizeof(*task));
  if (task == NULL) return FTUN_E_LIMIT;
  if (pthread_mutex_init(&task->mutex, NULL) != 0) {
    free(task);
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
  task->completion_user = user;
  task->kind = kind;
  (void)pthread_mutex_lock(&control->mutex);
  if (control->state != FTUN_CORE_RUNNING || control->stop_requested) {
    (void)pthread_mutex_unlock(&control->mutex);
    status = FTUN_E_STALE;
    goto fail;
  }
  if (control->task_count >= control->task_capacity) {
    (void)pthread_mutex_unlock(&control->mutex);
    status = FTUN_E_LIMIT;
    goto fail;
  }
  if (kind == FTUN_CONTROL_RELOAD && control->reload_pending) {
    (void)pthread_mutex_unlock(&control->mutex);
    status = FTUN_E_AGAIN;
    goto fail;
  }
  status = ftun_operation_accept(control->operations,
    ftun_control_task_complete, task, &operation);
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
  if (kind == FTUN_CONTROL_RELOAD) control->reload_pending = 1;
  (void)pthread_cond_signal(&control->condition);
  (void)pthread_mutex_unlock(&control->mutex);
  *out = operation;
  return FTUN_OK;

fail:
  (void)pthread_mutex_destroy(&task->mutex);
  free(task->first);
  free(task->second);
  free(task);
  return status;
}

ftun_status_t ftun_core_post(ftun_core_t *core, ftun_completion_fn callback,
                             void *user, ftun_operation_t **out)
{
  return ftun_core_submit(core, FTUN_CONTROL_POST, NULL, NULL,
                          callback, user, out);
}

ftun_status_t ftun_core_reload(ftun_core_t *core, const char *path,
                               ftun_completion_fn callback, void *user,
                               ftun_operation_t **out)
{
  return ftun_core_submit(core, FTUN_CONTROL_RELOAD, path, NULL,
                          callback, user, out);
}

ftun_status_t ftun_core_select(ftun_core_t *core, const char *group_name,
                               const char *member_name,
                               ftun_completion_fn callback, void *user,
                               ftun_operation_t **out)
{
  return ftun_core_submit(core, FTUN_CONTROL_SELECT, group_name, member_name,
                          callback, user, out);
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
  if (task->kind == FTUN_CONTROL_RELOAD) {
    const ftun_config_t *active = NULL;
    if (ftun_runtime_active_config(core, &active) == FTUN_OK &&
        active->base.state_cache) {
      ftun_status_t save_status = ftun_group_cache_save(
        core, active->base.cache_file);
      if (save_status != FTUN_OK) {
        ftun_core_log_status(core, save_status, FTUN_STAGE_STATE_RESTORE,
                             "group cache save failed");
      }
    }
    status = ftun_core_transaction(core, control, task->first, 1, &stage);
  } else if (task->kind == FTUN_CONTROL_SELECT) {
    status = ftun_runtime_select_names(core,
      (ftun_string_t){task->first, strlen(task->first)},
      (ftun_string_t){task->second, strlen(task->second)});
    if (status == FTUN_OK) {
      const ftun_config_t *active = NULL;
      if (ftun_runtime_active_config(core, &active) == FTUN_OK &&
          active->base.state_cache) {
        ftun_status_t save_status = ftun_group_cache_save(
          core, active->base.cache_file);
        if (save_status != FTUN_OK) {
          ftun_core_log_status(core, save_status, FTUN_STAGE_STATE_RESTORE,
                               "group cache save failed");
        }
      }
    }
  }
  if (status != FTUN_OK) {
    ftun_core_log_status(core, status, stage, "control operation failed");
  }
  result.status = status;
  result.stage = stage;
  if (task->kind == FTUN_CONTROL_RELOAD) {
    (void)pthread_mutex_lock(&control->mutex);
    control->reload_pending = 0;
    (void)pthread_mutex_unlock(&control->mutex);
  }
  (void)ftun_operation_complete(task->operation, result);
}

ftun_status_t ftun_core_run(ftun_core_t *core, const char *path)
{
  ftun_core_control_t *control = NULL;
  uint32_t stage = FTUN_STAGE_CONFIG_READ;
  ftun_status_t status;
  if (core == NULL || path == NULL || path[0] == '\0') return FTUN_E_INVALID;
  status = ftun_core_control(core, &control);
  if (status != FTUN_OK) return status;
  (void)pthread_mutex_lock(&control->mutex);
  if (control->state != FTUN_CORE_CREATED) {
    (void)pthread_mutex_unlock(&control->mutex);
    return FTUN_E_STALE;
  }
  control->state = FTUN_CORE_STARTING;
  control->owner = pthread_self();
  control->owner_valid = 1;
  (void)pthread_mutex_unlock(&control->mutex);
  status = ftun_core_transaction(core, control, path, 0, &stage);
  if (status != FTUN_OK) {
    (void)pthread_mutex_lock(&control->mutex);
    control->state = FTUN_CORE_CREATED;
    control->owner_valid = 0;
    control->stop_requested = 0;
    (void)pthread_mutex_unlock(&control->mutex);
    return status;
  }
  (void)pthread_mutex_lock(&control->mutex);
  control->state = FTUN_CORE_RUNNING;
  while (!control->stop_requested) {
    ftun_control_task_t *task = NULL;
    size_t dispatched = 0u;
    if (control->stop_requested) break;
    if (control->task_count != 0u) {
      task = control->tasks[control->task_head];
      control->tasks[control->task_head] = NULL;
      control->task_head = (control->task_head + 1u) % control->task_capacity;
      control->task_count--;
    }
    (void)pthread_mutex_unlock(&control->mutex);
    if (task != NULL) {
      ftun_core_process_task(core, control, task);
      ftun_control_task_consumed(task);
    }
    status = ftun_engine_run_once(control->engine);
    if (status != FTUN_OK) {
      ftun_core_log_status(core, status, FTUN_STAGE_CONTROL,
                           "production data plane failed");
    } else {
      ftun_runtime_manager_info_t info;
      if (ftun_runtime_manager_get_info(core, &info) == FTUN_OK &&
          info.generation != control->generation) {
        (void)pthread_mutex_lock(&control->mutex);
        control->generation = info.generation;
        (void)pthread_mutex_unlock(&control->mutex);
      }
    }
    /* A callback may cancel a later queued task. Dispatching one completion
     * per removed task keeps that task's context alive until its ring entry
     * has also been consumed. */
    if (status == FTUN_OK) {
      status = ftun_operation_dispatch(control->operations,
        control->task_capacity, &dispatched);
    }
    if (status != FTUN_OK) {
      (void)pthread_mutex_lock(&control->mutex);
      control->stop_requested = 1;
      break;
    }
    (void)pthread_mutex_lock(&control->mutex);
  }
  control->state = FTUN_CORE_STOPPING;
  while (control->task_count != 0u) {
    ftun_control_task_t *task = control->tasks[control->task_head];
    control->tasks[control->task_head] = NULL;
    control->task_head = (control->task_head + 1u) % control->task_capacity;
    control->task_count--;
    ftun_control_task_consumed(task);
  }
  (void)pthread_mutex_unlock(&control->mutex);
  (void)ftun_engine_stop(control->engine);
  (void)ftun_operation_queue_stop(control->operations);
  for (;;) {
    ftun_operation_queue_usage_t usage;
    size_t dispatched = 0u;
    if (ftun_operation_dispatch(control->operations,
                                control->task_capacity, &dispatched) != FTUN_OK ||
        ftun_operation_queue_get_usage(control->operations, &usage) != FTUN_OK ||
        usage.inflight == 0u) break;
  }
  {
    ftun_status_t destroy_status = ftun_engine_destroy(&control->engine);
    if (destroy_status != FTUN_OK && status == FTUN_OK) {
      status = destroy_status;
    }
  }
  {
    const ftun_config_t *active = NULL;
    if (ftun_runtime_active_config(core, &active) == FTUN_OK &&
        active->base.state_cache) {
      ftun_status_t save_status = ftun_group_cache_save(
        core, active->base.cache_file);
      if (save_status != FTUN_OK) {
        ftun_core_log_status(core, save_status, FTUN_STAGE_STATE_RESTORE,
                             "group cache save failed during stop");
      }
    }
  }
  if (control->logger != NULL) (void)ftun_logger_flush(control->logger);
  (void)pthread_mutex_lock(&control->mutex);
  control->state = FTUN_CORE_STOPPED;
  control->owner_valid = 0;
  (void)pthread_cond_broadcast(&control->condition);
  (void)pthread_mutex_unlock(&control->mutex);
  return status;
}

ftun_status_t ftun_core_stop(ftun_core_t *core, uint64_t deadline_ms)
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
  if (control->state == FTUN_CORE_STOPPED || control->stop_requested) {
    (void)pthread_mutex_unlock(&control->mutex);
    return FTUN_OK;
  }
  if (control->state != FTUN_CORE_RUNNING &&
      control->state != FTUN_CORE_STARTING) {
    (void)pthread_mutex_unlock(&control->mutex);
    return FTUN_E_STALE;
  }
  control->stop_requested = 1;
  (void)pthread_cond_broadcast(&control->condition);
  (void)pthread_mutex_unlock(&control->mutex);
  return FTUN_OK;
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
  (void)pthread_mutex_unlock(&control->mutex);
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
  ftun_core_t *manager;
  ftun_core_control_t *control = NULL;
  ftun_budget_t *budget;
  ftun_status_t status;
  if (core == NULL) return FTUN_E_INVALID;
  owned = *core;
  if (owned == NULL) return FTUN_OK;
  status = ftun_core_control(owned, &control);
  if (status != FTUN_OK) return status;
  (void)pthread_mutex_lock(&control->mutex);
  if (control->state != FTUN_CORE_CREATED &&
      control->state != FTUN_CORE_STOPPED) {
    (void)pthread_mutex_unlock(&control->mutex);
    return FTUN_E_AGAIN;
  }
  (void)pthread_mutex_unlock(&control->mutex);
  budget = control->budget;
  (void)ftun_runtime_manager_set_logger(owned, NULL);
  (void)ftun_runtime_manager_set_control(owned, NULL);
  manager = owned;
  status = ftun_runtime_manager_destroy(&manager);
  if (status != FTUN_OK) {
    (void)ftun_runtime_manager_set_control(owned, control);
    (void)ftun_runtime_manager_set_logger(owned, control->logger);
    return status;
  }
  *core = NULL;
  (void)ftun_engine_destroy(&control->engine);
  (void)ftun_logger_destroy(&control->logger);
  status = ftun_operation_queue_destroy(&control->operations);
  if (status != FTUN_OK) return status;
  free(control->config_path);
  free(control->tasks);
  (void)pthread_cond_destroy(&control->condition);
  (void)pthread_mutex_destroy(&control->mutex);
  free(control);
  status = ftun_budget_destroy(&budget);
  if (status != FTUN_OK) return status;
  return FTUN_OK;
}
