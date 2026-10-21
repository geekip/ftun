#define _POSIX_C_SOURCE 200809L

#include "core/core.h"

#include "config/config.h"
#include "config/compile.h"
#include "config/model.h"
#include "config/parser.h"
#include "core/budget.h"
#include "proxy/http_fetch.h"
#include "core/operation.h"
#include "proxy/runtime_state.h"
#include "proxy/state/restore.h"
#include "core/worker.h"
#include "proxy/state/group_cache.h"
#if defined(FTUN_HAVE_MODULE_FRS)
#include "proxy/frs/frs.h"
#include "platform/file.h"
#endif
#include "util/logger.h"
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
#define FTUN_CORE_RELOAD_PUBLISH_MAGIC UINT32_C(0x46545042)
#define FTUN_CORE_STATE_WORK_MAGIC UINT32_C(0x46545343)
#define FTUN_CORE_OPERATION_DISPATCH_QUOTA 32u
#define FTUN_CORE_STATE_WORKER_CAPACITY 4u

typedef enum {
  FTUN_CONTROL_POST = 1,
  FTUN_CONTROL_RELOAD,
  FTUN_CONTROL_SELECT
} ftun_control_kind_t;

typedef struct ftun_control_task {
  ftun_core_t *core;
  ftun_operation_t *operation;
  ftun_operation_token_t completion_token;
  ftun_completion_fn completion;
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
  void *reload_transaction;
} ftun_control_task_t;

typedef struct {
  uint32_t magic;
  uint32_t socket_mark;
  uint64_t base_generation;
  uint64_t maximum_bytes;
  uintptr_t service_descriptor;
  uint32_t path_length;
} ftun_core_reload_work_t;

typedef struct {
  uint64_t base_generation;
  uintptr_t config;
  uintptr_t runtime;
  ftun_core_service_plan_t service_plan;
  uintptr_t logger;
  uintptr_t group_cache;
  uintptr_t source_path;
  ftun_status_t group_cache_status;
  bool publish_frs;
} ftun_core_reload_result_t;

typedef struct {
  uint32_t magic;
  uint32_t path_length;
  uint64_t body_length;
} ftun_core_reload_publish_work_t;

typedef struct {
  ftun_status_t status;
  bool renamed;
} ftun_core_reload_publish_result_t;

typedef struct {
  ftun_config_t *config;
  ftun_runtime_t *candidate;
  ftun_logger_t *next_logger;
  char *next_path;
  ftun_runtime_group_record_t *group_records;
  size_t group_record_capacity;
  ftun_state_restore_info_t restore_info;
  uint64_t next_generation;
  bool replace_logger;
  bool service_prepared;
} ftun_core_reload_transaction_t;

typedef struct {
  uint32_t magic;
  uint32_t path_length;
  uint64_t contents_length;
} ftun_core_state_work_t;

typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  pthread_t owner;
  ftun_budget_t *root_budget;
  ftun_budget_t *budget;
  ftun_budget_t *data_budget;
  ftun_operation_queue_t *operations;
  ftun_logger_t *logger;
  ftun_logger_t *retired_logger;
  const ftun_core_service_descriptor_t *service_descriptor;
  ftun_core_service_t service;
  ftun_core_t *core;
  ftun_worker_t *reload_worker;
  ftun_worker_t *state_worker;
  ftun_control_task_t **tasks;
  char *config_path;
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
} ftun_core_control_t;

static int ftun_control_task_cancelled(ftun_control_task_t *task);
static void ftun_control_task_destroy(ftun_control_task_t *task);

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
  size_t left_index;
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

static ftun_status_t ftun_core_state_execute(
  ftun_bytes_t input, uint8_t *output, size_t output_capacity,
  size_t *out_output_size)
{
  const ftun_core_state_work_t *work;
  const char *path;
  size_t contents_length;
  size_t prefix;
  (void)output;
  if (out_output_size != NULL) *out_output_size = 0u;
  if (input.data == NULL || input.length < sizeof(*work) ||
      output_capacity != 0u || out_output_size == NULL) {
    return FTUN_E_INVALID;
  }
  work = (const ftun_core_state_work_t *)input.data;
  if (work->magic != FTUN_CORE_STATE_WORK_MAGIC || work->path_length == 0u) {
    return FTUN_E_INVALID;
  }
  contents_length = (size_t)work->contents_length;
  if ((uint64_t)contents_length != work->contents_length) {
    return FTUN_E_LIMIT;
  }
  if ((size_t)work->path_length > SIZE_MAX - sizeof(*work) ||
      contents_length > SIZE_MAX - sizeof(*work) - work->path_length) {
    return FTUN_E_LIMIT;
  }
  prefix = sizeof(*work) + (size_t)work->path_length;
  if (input.length != prefix + contents_length ||
      input.data[prefix - 1u] != 0u) return FTUN_E_INVALID;
  path = (const char *)(input.data + sizeof(*work));
  return ftun_group_cache_publish(path,
    (ftun_bytes_t){input.data + prefix, contents_length});
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
      FTUN_STAGE_STATE_RESTORE, "group cache save failed");
  }
}

static ftun_status_t ftun_core_state_schedule(
  ftun_core_t *core, ftun_core_control_t *control, const char *path,
  uint64_t deadline_ms)
{
  ftun_core_state_work_t *work;
  ftun_worker_job_t job;
  ftun_operation_t *operation = NULL;
  uint8_t *captured = NULL;
  uint8_t *input = NULL;
  size_t captured_length = 0u;
  size_t path_length;
  size_t input_length;
  ftun_status_t status;
  if (core == NULL || control == NULL || control->state_worker == NULL ||
      path == NULL || path[0] == '\0') return FTUN_E_INVALID;
  path_length = strlen(path) + 1u;
  if (path_length > UINT32_MAX) return FTUN_E_LIMIT;
  status = ftun_group_cache_capture(core, &captured, &captured_length);
  if (status != FTUN_OK) return status;
  if (path_length > SIZE_MAX - sizeof(*work) ||
      captured_length > SIZE_MAX - sizeof(*work) - path_length) {
    free(captured);
    return FTUN_E_LIMIT;
  }
  input_length = sizeof(*work) + path_length + captured_length;
  input = (uint8_t *)calloc(1u, input_length);
  if (input == NULL) {
    free(captured);
    return FTUN_E_LIMIT;
  }
  work = (ftun_core_state_work_t *)input;
  work->magic = FTUN_CORE_STATE_WORK_MAGIC;
  work->path_length = (uint32_t)path_length;
  work->contents_length = (uint64_t)captured_length;
  memcpy(input + sizeof(*work), path, path_length);
  memcpy(input + sizeof(*work) + path_length, captured, captured_length);
  memset(&job, 0, sizeof(job));
  job.execute = ftun_core_state_execute;
  job.input = (ftun_bytes_t){input, input_length};
  job.deadline_ms = deadline_ms;
  status = ftun_worker_submit(control->state_worker, &job,
    ftun_core_state_completed, control, &operation);
  free(input);
  free(captured);
  return status;
}

static ftun_status_t ftun_core_state_drain_until(
  ftun_worker_t *worker, uint64_t deadline_ms)
{
  ftun_status_t status;
  if (worker == NULL) return FTUN_OK;
  for (;;) {
    ftun_worker_usage_t usage;
    uint64_t now_ms;
    size_t callbacks = 0u;
    status = ftun_worker_poll(worker, SIZE_MAX, &callbacks);
    if (status != FTUN_OK) return status;
    status = ftun_worker_get_usage(worker, &usage);
    if (status != FTUN_OK) return status;
    if (usage.tasks == 0u) return FTUN_OK;
    status = ftun_monotonic_now(&now_ms);
    if (status != FTUN_OK) return status;
    if (now_ms >= deadline_ms) return FTUN_E_TIMEOUT;
    if (callbacks == 0u) sched_yield();
  }
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
      size_t inbound_index;
      uint32_t socket_mark = 0u;
      for (inbound_index = 0u; inbound_index < config->inbound_count;
           inbound_index++) {
        if (config->inbounds[inbound_index].kind == FTUN_CONFIG_INBOUND_TUN) {
          socket_mark = UINT32_C(0x4654);
          break;
        }
      }
      fetch_spec.budget = control->budget;
      fetch_spec.url.data = config->frs.url;
      fetch_spec.url.length = strlen(config->frs.url);
      fetch_spec.maximum_bytes = usage.normal_available -
        1024u * 1024u;
      fetch_spec.deadline_ms = now_ms + UINT64_C(30000);
      fetch_spec.socket_mark = socket_mark;
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
      status = ftun_frs_open_bytes_budget(control->budget,
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

#if defined(FTUN_HAVE_MODULE_FRS)
static ftun_status_t ftun_core_reload_read_file(const char *path,
                                                uint64_t maximum_bytes,
                                                uint8_t **out,
                                                size_t *out_length)
{
  struct stat info;
  uint8_t *data;
  size_t length;
  size_t offset = 0u;
  int descriptor;
  if (out != NULL) *out = NULL;
  if (out_length != NULL) *out_length = 0u;
  if (path == NULL || out == NULL || out_length == NULL) return FTUN_E_INVALID;
  descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) return errno == ENOENT ? FTUN_E_EOF : FTUN_E_IO;
  if (fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode) ||
      info.st_size < 0 || (uintmax_t)info.st_size > (uintmax_t)SIZE_MAX ||
      (uintmax_t)info.st_size > maximum_bytes / 2u) {
    (void)close(descriptor);
    return FTUN_E_LIMIT;
  }
  length = (size_t)info.st_size;
  data = (uint8_t *)malloc(length == 0u ? 1u : length);
  if (data == NULL) {
    (void)close(descriptor);
    return FTUN_E_LIMIT;
  }
  while (offset < length) {
    ssize_t received = read(descriptor, data + offset, length - offset);
    if (received > 0) offset += (size_t)received;
    else if (received < 0 && errno == EINTR) continue;
    else {
      free(data);
      (void)close(descriptor);
      return FTUN_E_IO;
    }
  }
  if (close(descriptor) != 0) {
    free(data);
    return FTUN_E_IO;
  }
  *out = data;
  *out_length = length;
  return FTUN_OK;
}
#endif

static void ftun_core_reload_result_release(ftun_core_reload_result_t *result)
{
  ftun_config_t *config;
  ftun_runtime_t *runtime;
  ftun_logger_t *logger;
  ftun_group_cache_snapshot_t *group_cache;
  char *source_path;
  if (result == NULL) return;
  config = (ftun_config_t *)result->config;
  runtime = (ftun_runtime_t *)result->runtime;
  logger = (ftun_logger_t *)result->logger;
  group_cache = (ftun_group_cache_snapshot_t *)result->group_cache;
  source_path = (char *)result->source_path;
#if defined(FTUN_HAVE_MODULE_FRS)
  (void)ftun_runtime_prepared_release(&runtime);
#else
  (void)runtime;
#endif
  (void)ftun_core_service_plan_destroy(&result->service_plan);
  (void)ftun_logger_destroy(&logger);
  (void)ftun_group_cache_destroy(&group_cache);
  (void)ftun_config_destroy(&config);
  free(source_path);
  memset(result, 0, sizeof(*result));
}

static void ftun_core_reload_result_cleanup(ftun_bytes_t bytes)
{
  ftun_core_reload_result_t result;
  if (bytes.data == NULL || bytes.length != sizeof(result)) return;
  memcpy(&result, bytes.data, sizeof(result));
  ftun_core_reload_result_release(&result);
}

static ftun_status_t ftun_core_reload_execute(
  ftun_bytes_t input, uint8_t *output, size_t output_capacity,
  size_t *out_output_size)
{
  const ftun_core_reload_work_t *work;
  const char *path;
  ftun_core_reload_result_t result;
  ftun_config_t *config = NULL;
  ftun_runtime_t *runtime = NULL;
  ftun_core_service_plan_t service_plan;
  ftun_logger_t *logger = NULL;
  ftun_group_cache_snapshot_t *group_cache = NULL;
  char *source_path = NULL;
  ftun_status_t group_cache_status = FTUN_OK;
  ftun_status_t status;
  memset(&service_plan, 0, sizeof(service_plan));
  if (out_output_size != NULL) *out_output_size = 0u;
  if (input.data == NULL || input.length < sizeof(*work) || output == NULL ||
      output_capacity < sizeof(result) || out_output_size == NULL) {
    return FTUN_E_INVALID;
  }
  work = (const ftun_core_reload_work_t *)input.data;
  if (work->magic != FTUN_CORE_RELOAD_WORK_MAGIC || work->path_length == 0u ||
      work->service_descriptor == 0u ||
      input.length != sizeof(*work) + (size_t)work->path_length + 1u ||
      input.data[input.length - 1u] != 0u) return FTUN_E_INVALID;
  path = (const char *)(input.data + sizeof(*work));
  memset(&result, 0, sizeof(result));
  status = ftun_config_load(NULL, path, &config);
  if (status != FTUN_OK) goto done;
#if defined(FTUN_HAVE_MODULE_FRS)
  {
    ftun_frs_view_t *view = NULL;
    uint8_t *file = NULL;
    size_t file_length = 0u;
    ftun_http_fetch_result_t fetched;
    ftun_budget_t *fetch_budget = NULL;
    bool publish = false;
    memset(&fetched, 0, sizeof(fetched));
    if ((config->plan->prepare & FTUN_PLAN_FRS) != 0u) {
      status = ftun_core_reload_read_file(config->frs.path,
        work->maximum_bytes, &file, &file_length);
      if (status == FTUN_E_EOF && config->frs.auto_update &&
          config->frs.url != NULL && config->frs.url[0] != '\0') {
        ftun_http_fetch_spec_t fetch_spec;
        uint64_t now_ms;
        memset(&fetch_spec, 0, sizeof(fetch_spec));
        status = ftun_budget_create(NULL, (size_t)work->maximum_bytes, 0u,
                                    &fetch_budget);
        if (status == FTUN_OK) status = ftun_monotonic_now(&now_ms);
        if (status == FTUN_OK && now_ms > UINT64_MAX - UINT64_C(30000)) {
          status = FTUN_E_LIMIT;
        }
        if (status == FTUN_OK) {
          ftun_string_t resolver = {NULL, 0u};
          fetch_spec.budget = fetch_budget;
          fetch_spec.url.data = config->frs.url;
          fetch_spec.url.length = strlen(config->frs.url);
          fetch_spec.maximum_bytes = (size_t)work->maximum_bytes / 2u;
          fetch_spec.deadline_ms = now_ms + UINT64_C(30000);
          fetch_spec.socket_mark = work->socket_mark;
          if (config->frs.dns_server != NULL &&
              config->frs.dns_server[0] != '\0') {
            resolver.data = config->frs.dns_server;
            resolver.length = strlen(config->frs.dns_server);
          }
          status = ftun_http_fetch_resolver(config, NULL, resolver,
                                            &fetch_spec);
          if (status == FTUN_OK) status = ftun_http_fetch_route(config, NULL,
            config->frs.update_outbound, &fetch_spec);
          if (status == FTUN_OK) status = ftun_http_fetch(&fetch_spec, &fetched);
          if (status == FTUN_OK && fetched.status != 200u) {
            status = FTUN_E_PROTOCOL;
          }
          if (status == FTUN_OK) publish = true;
        }
      }
      if (status == FTUN_OK) {
        ftun_bytes_t bytes = publish
          ? (ftun_bytes_t){fetched.data, fetched.length}
          : (ftun_bytes_t){file, file_length};
        status = ftun_frs_open_bytes(bytes, &view);
      }
      if (status == FTUN_OK) {
        status = ftun_runtime_prepare_detached(config, view, &runtime);
        if (status == FTUN_OK) view = NULL;
      }
      result.publish_frs = publish;
    } else {
      status = ftun_runtime_prepare_detached(config, NULL, &runtime);
    }
    free(file);
    (void)ftun_frs_view_release(&view);
    ftun_http_fetch_release(&fetched);
    (void)ftun_budget_destroy(&fetch_budget);
    if (status != FTUN_OK) goto done;
  }
#endif
  status = ftun_core_service_plan_prepare(
    (const ftun_core_service_descriptor_t *)work->service_descriptor,
    config, work->socket_mark, &service_plan);
  if (status == FTUN_OK) status = ftun_core_logger_create(config, &logger);
  if (status == FTUN_OK) {
    source_path = ftun_core_copy_string(config->source_path == NULL
      ? path : config->source_path);
    if (source_path == NULL) status = FTUN_E_LIMIT;
  }
  if (status == FTUN_OK && config->base.state_cache) {
    group_cache_status = ftun_group_cache_load(config->base.cache_file,
                                                &group_cache);
  }

done:
  if (status == FTUN_OK) {
    result.base_generation = work->base_generation;
    result.config = (uintptr_t)config;
    result.runtime = (uintptr_t)runtime;
    result.service_plan = service_plan;
    memset(&service_plan, 0, sizeof(service_plan));
    result.logger = (uintptr_t)logger;
    result.group_cache = (uintptr_t)group_cache;
    result.source_path = (uintptr_t)source_path;
    result.group_cache_status = group_cache_status;
    /* publish_frs 在 FRS 分支准备候选时设置；owner 验证基线并保留
     * candidate 后才会提交第二阶段耐久发布。 */
    memcpy(output, &result, sizeof(result));
    *out_output_size = sizeof(result);
    return FTUN_OK;
  }
  result.config = (uintptr_t)config;
  result.runtime = (uintptr_t)runtime;
  result.service_plan = service_plan;
  result.logger = (uintptr_t)logger;
  result.group_cache = (uintptr_t)group_cache;
  result.source_path = (uintptr_t)source_path;
  result.group_cache_status = group_cache_status;
  ftun_core_reload_result_release(&result);
  return status;
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
  ftun_core_service_t next_service;
  ftun_logger_t *old_logger;
  char *next_path = NULL;
  ftun_state_restore_info_t restore_info;
  uint64_t now_ms = 0u;
  uint64_t next_generation = 0u;
  int replace_logger = 1;
  ftun_status_t status;
  memset(&next_service, 0, sizeof(next_service));
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
    status = ftun_core_service_prepare(&next_service,
      control->service_descriptor, core, control->data_budget,
      control->operations, NULL, config, next_generation);
    if (status != FTUN_OK) goto done;
  } else {
    status = ftun_core_service_reload_prepare(&control->service, config,
                                              next_generation);
    if (status != FTUN_OK) goto done;
  }
  status = ftun_runtime_stage_commit(core, candidate, next_generation);
  if (status != FTUN_OK) goto done;
  if (reload) {
    status = ftun_core_service_reload_commit(&control->service,
                                             next_generation);
  } else {
    status = ftun_core_service_activate(&next_service);
  }
  if (status != FTUN_OK) goto done;
  /* Runtime 指针切换是事务唯一的运行态可见性点；stage 成功且 owner
   * 串行期间，下面的 commit 不分配且不能再被容量条件拒绝。 */
  status = ftun_runtime_commit(core, &candidate);
  if (status != FTUN_OK) goto done;
  if (!reload) {
    control->service = next_service;
    memset(&next_service, 0, sizeof(next_service));
  }
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
    (void)ftun_core_context_set_logger(core, control->logger);
  }
  (void)ftun_logger_destroy(&old_logger);
  if (restore_info.cache_discarded) {
    ftun_core_log_status(core, FTUN_E_STALE, FTUN_STAGE_STATE_RESTORE,
                         "discarded incompatible group cache");
  }

done:
  if (candidate != NULL) (void)ftun_runtime_abort(core, &candidate);
  if (reload && control->service.implementation != NULL) {
    (void)ftun_core_service_reload_abort(&control->service);
  }
  (void)ftun_core_service_destroy(&next_service);
  (void)ftun_logger_destroy(&next_logger);
  free(next_path);
  (void)ftun_config_destroy(&config);
  return status;
}

static void ftun_core_reload_transaction_release(
  ftun_core_t *core, ftun_core_control_t *control,
  ftun_core_reload_transaction_t **transaction)
{
  ftun_core_reload_transaction_t *owned;
  if (transaction == NULL || *transaction == NULL) return;
  owned = *transaction;
  if (owned->service_prepared && control != NULL &&
      control->service.implementation != NULL) {
    (void)ftun_core_service_reload_abort(&control->service);
  }
  if (owned->candidate != NULL && core != NULL) {
    (void)ftun_runtime_abort(core, &owned->candidate);
  }
  if (owned->next_logger != NULL && control != NULL) {
    (void)ftun_core_logger_retire(control, &owned->next_logger);
  }
  /* reload 接纳和 prepare 都要求 retired 槽为空；因此上面的转移在 owner
   * 串行域内不会冲突，也不能退回到无期限 join。 */
  (void)ftun_config_destroy(&owned->config);
  free(owned->group_records);
  free(owned->next_path);
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *transaction = NULL;
}

static ftun_status_t ftun_core_reload_prepare_transaction(
  ftun_core_t *core, ftun_core_control_t *control,
  ftun_core_reload_result_t *prepared,
  ftun_core_reload_transaction_t **out, uint32_t *out_stage)
{
  const ftun_config_t *active = NULL;
  ftun_runtime_t *detached = (ftun_runtime_t *)prepared->runtime;
  ftun_core_service_plan_t service_plan = prepared->service_plan;
  ftun_group_cache_snapshot_t *group_cache =
    (ftun_group_cache_snapshot_t *)prepared->group_cache;
  ftun_core_reload_transaction_t *transaction = NULL;
  uint64_t now_ms = 0u;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core == NULL || control == NULL || prepared == NULL || out == NULL) {
    return FTUN_E_INVALID;
  }
  transaction = (ftun_core_reload_transaction_t *)calloc(
    1u, sizeof(*transaction));
  if (transaction == NULL) return FTUN_E_LIMIT;
  transaction->config = (ftun_config_t *)prepared->config;
  transaction->next_logger = (ftun_logger_t *)prepared->logger;
  transaction->next_path = (char *)prepared->source_path;
  prepared->config = 0u;
  prepared->runtime = 0u;
  memset(&prepared->service_plan, 0, sizeof(prepared->service_plan));
  prepared->logger = 0u;
  prepared->group_cache = 0u;
  prepared->source_path = 0u;
  if (out_stage != NULL) *out_stage = FTUN_STAGE_CONFIG_PREPARE;
  status = transaction->config == NULL || transaction->next_path == NULL
    ? FTUN_E_STATE_CORRUPT : FTUN_OK;
  if (status == FTUN_OK) {
    status = ftun_runtime_active_config(core, &active);
  }
  if (status == FTUN_OK) {
    status = ftun_core_reload_compatible(active, transaction->config);
  }
  if (status == FTUN_OK) {
    ftun_runtime_manager_info_t info;
    status = ftun_runtime_manager_get_info(core, &info);
    if (status == FTUN_OK && info.generation != prepared->base_generation) {
      status = FTUN_E_STALE;
    }
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
#if defined(FTUN_HAVE_MODULE_FRS)
  if (status == FTUN_OK) {
    status = ftun_runtime_attach_prepared(core, &detached,
                                          &transaction->candidate);
  }
#else
  (void)detached;
  if (status == FTUN_OK) {
    status = ftun_runtime_prepare(core, transaction->config,
                                  &transaction->candidate);
  }
#endif
  if (status == FTUN_OK && out_stage != NULL) {
    *out_stage = FTUN_STAGE_STATE_RESTORE;
  }
  if (status == FTUN_OK) {
    status = ftun_state_restore_candidate_snapshot_at(core,
      transaction->config, group_cache, prepared->group_cache_status, now_ms,
      15u * 60u * 1000u, &transaction->restore_info);
  }
  if (status == FTUN_OK) {
    size_t count = 0u;
    ftun_status_t records_status = ftun_runtime_group_records(
      core, NULL, 0u, &count);
    if (records_status != FTUN_OK && records_status != FTUN_E_LIMIT) {
      status = records_status;
    } else if (count > SIZE_MAX / sizeof(*transaction->group_records)) {
      status = FTUN_E_LIMIT;
    } else if (count != 0u) {
      transaction->group_records = (ftun_runtime_group_record_t *)calloc(
        count, sizeof(*transaction->group_records));
      if (transaction->group_records == NULL) status = FTUN_E_LIMIT;
      else transaction->group_record_capacity = count;
    }
  }
  if (status == FTUN_OK && out_stage != NULL) *out_stage = FTUN_STAGE_COMMIT;
  if (status == FTUN_OK) {
    ftun_runtime_manager_info_t info;
    status = ftun_runtime_manager_get_info(core, &info);
    if (status == FTUN_OK && info.generation != UINT64_MAX) {
      transaction->next_generation = info.generation + 1u;
    } else if (status == FTUN_OK) {
      status = FTUN_E_LIMIT;
    }
  }
  if (status == FTUN_OK) {
    status = ftun_core_service_reload_prepare_planned(&control->service,
      transaction->config, transaction->next_generation, &service_plan);
    if (status == FTUN_OK) transaction->service_prepared = true;
  }
  if (status == FTUN_OK) {
    status = ftun_runtime_stage_commit(core, transaction->candidate,
                                       transaction->next_generation);
  }
#if defined(FTUN_HAVE_MODULE_FRS)
  (void)ftun_runtime_prepared_release(&detached);
#endif
  (void)ftun_core_service_plan_destroy(&service_plan);
  (void)ftun_group_cache_destroy(&group_cache);
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
      transaction->candidate == NULL || !transaction->service_prepared) {
    return FTUN_E_INVALID;
  }
  if (transaction->group_record_capacity != 0u) {
    size_t count = 0u;
    size_t index;
    status = ftun_runtime_group_records(core, transaction->group_records,
      transaction->group_record_capacity, &count);
    for (index = 0u; status == FTUN_OK && index < count; index++) {
      status = ftun_runtime_candidate_group_restore(core,
        &transaction->group_records[index], true);
      if (status == FTUN_E_REJECTED || status == FTUN_E_STALE) {
        status = FTUN_OK;
      }
    }
    if (status != FTUN_OK) return status;
  }
  status = ftun_core_service_reload_commit(&control->service,
                                           transaction->next_generation);
  if (status != FTUN_OK) return status;
  transaction->service_prepared = false;
  /* stage 已完成所有可能失败的 Runtime 工作；此处是唯一公开点。 */
  status = ftun_runtime_commit(core, &transaction->candidate);
  if (status != FTUN_OK) return status;
  (void)pthread_mutex_lock(&control->mutex);
  control->generation = transaction->next_generation;
  (void)pthread_mutex_unlock(&control->mutex);
  if (transaction->replace_logger) {
    old_logger = control->logger;
    control->logger = transaction->next_logger;
    transaction->next_logger = NULL;
    (void)ftun_core_context_set_logger(core, control->logger);
  }
  free(control->config_path);
  control->config_path = transaction->next_path;
  transaction->next_path = NULL;
  if (old_logger != NULL) {
    (void)ftun_core_logger_retire(control, &old_logger);
  }
  if (transaction->restore_info.cache_discarded) {
    ftun_core_log_status(core, FTUN_E_STALE, FTUN_STAGE_STATE_RESTORE,
                         "discarded incompatible group cache");
  }
  return FTUN_OK;
}

#if defined(FTUN_HAVE_MODULE_FRS)
static ftun_status_t ftun_core_reload_publish_execute(
  ftun_bytes_t input, uint8_t *output, size_t output_capacity,
  size_t *out_output_size)
{
  const ftun_core_reload_publish_work_t *work;
  const char *path;
  const uint8_t *body;
  size_t expected;
  ftun_core_file_publish_t publish;
  ftun_core_reload_publish_result_t result;
  if (out_output_size != NULL) *out_output_size = 0u;
  if (input.data == NULL || input.length < sizeof(*work) || output == NULL ||
      output_capacity < sizeof(result) || out_output_size == NULL) {
    return FTUN_E_INVALID;
  }
  work = (const ftun_core_reload_publish_work_t *)input.data;
  if (work->magic != FTUN_CORE_RELOAD_PUBLISH_MAGIC ||
      work->path_length == 0u || work->body_length > SIZE_MAX) {
    return FTUN_E_INVALID;
  }
  expected = sizeof(*work);
  if ((size_t)work->path_length > SIZE_MAX - expected - 1u) {
    return FTUN_E_LIMIT;
  }
  expected += (size_t)work->path_length + 1u;
  if ((size_t)work->body_length > SIZE_MAX - expected) return FTUN_E_LIMIT;
  expected += (size_t)work->body_length;
  if (expected != input.length) return FTUN_E_INVALID;
  path = (const char *)(input.data + sizeof(*work));
  if (path[work->path_length] != '\0' ||
      memchr(path, '\0', work->path_length) != NULL) return FTUN_E_INVALID;
  body = input.data + sizeof(*work) + (size_t)work->path_length + 1u;
  memset(&publish, 0, sizeof(publish));
  memset(&result, 0, sizeof(result));
  result.status = ftun_file_write_atomic_with_hook(path,
    (ftun_bytes_t){body, (size_t)work->body_length}, 0644u,
    ftun_core_file_stage, &publish);
  result.renamed = publish.reached >= FTUN_FILE_STAGE_RENAMED;
  memcpy(output, &result, sizeof(result));
  *out_output_size = sizeof(result);
  return FTUN_OK;
}
#endif

static void ftun_core_reload_finish(ftun_control_task_t *task,
                                    ftun_core_control_t *control,
                                    ftun_error_t result)
{
  int destroy;
  if (control != NULL) {
    if (result.status != FTUN_OK && result.status != FTUN_E_CANCELLED) {
      ftun_core_log_status(task->core, result.status, result.stage,
                           "control operation failed");
    }
    (void)pthread_mutex_lock(&control->mutex);
    control->reload_pending = 0;
    (void)pthread_mutex_unlock(&control->mutex);
  }
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
  const ftun_core_reload_publish_result_t *published = NULL;
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
      published = (const ftun_core_reload_publish_result_t *)bytes.data;
      result.status = published->status;
      if (result.status != FTUN_OK && published->renamed) {
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
      "FRS reload applied but directory durability is uncertain");
  }
  ftun_core_reload_transaction_release(task->core, control, &transaction);
  ftun_core_reload_finish(task, control, result);
}

static ftun_status_t ftun_core_reload_publish_schedule(
  ftun_core_control_t *control, ftun_control_task_t *task,
  ftun_core_reload_transaction_t *transaction)
{
#if defined(FTUN_HAVE_MODULE_FRS)
  ftun_core_reload_publish_work_t *work;
  ftun_worker_job_t job;
  ftun_operation_t *operation = NULL;
  ftun_bytes_t body;
  const char *path;
  uint8_t *input;
  size_t path_length;
  size_t input_length;
  ftun_status_t status;
  status = ftun_runtime_prepared_frs_bytes(transaction->candidate, &body);
  path = transaction->config->frs.path;
  if (status != FTUN_OK || path == NULL || path[0] == '\0') {
    return status == FTUN_OK ? FTUN_E_INVALID : status;
  }
  path_length = strlen(path);
  if (path_length > UINT32_MAX || body.length > UINT64_MAX ||
      path_length > SIZE_MAX - sizeof(*work) - 1u ||
      body.length > SIZE_MAX - sizeof(*work) - path_length - 1u) {
    return FTUN_E_LIMIT;
  }
  input_length = sizeof(*work) + path_length + 1u + body.length;
  input = (uint8_t *)malloc(input_length);
  if (input == NULL) return FTUN_E_LIMIT;
  work = (ftun_core_reload_publish_work_t *)input;
  memset(work, 0, sizeof(*work));
  work->magic = FTUN_CORE_RELOAD_PUBLISH_MAGIC;
  work->path_length = (uint32_t)path_length;
  work->body_length = (uint64_t)body.length;
  memcpy(input + sizeof(*work), path, path_length + 1u);
  memcpy(input + sizeof(*work) + path_length + 1u, body.data, body.length);
  memset(&job, 0, sizeof(job));
  job.execute = ftun_core_reload_publish_execute;
  job.input = (ftun_bytes_t){input, input_length};
  job.result_capacity = sizeof(ftun_core_reload_publish_result_t);
  (void)pthread_mutex_lock(&task->mutex);
  task->reload_transaction = transaction;
  (void)pthread_mutex_unlock(&task->mutex);
  status = ftun_worker_submit(control->reload_worker, &job,
    ftun_core_reload_publish_completed, task, &operation);
  free(input);
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
#else
  (void)control;
  (void)task;
  (void)transaction;
  return FTUN_E_UNSUPPORTED;
#endif
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
  bool publish_frs = false;
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
    publish_frs = prepared.publish_frs;
  } else if (result.status == FTUN_OK) {
    result.status = FTUN_E_STATE_CORRUPT;
  }
  if (ftun_core_control(task->core, &control) != FTUN_OK) {
    result.status = FTUN_E_STATE_CORRUPT;
  }
  if (result.status == FTUN_OK && !ftun_control_task_cancelled(task)) {
    result.status = ftun_core_reload_prepare_transaction(task->core, control,
      &prepared, &transaction, &stage);
    result.stage = stage;
  } else if (result.status == FTUN_OK) {
    result.status = FTUN_E_CANCELLED;
  }
  ftun_core_reload_result_release(&prepared);
  if (bytes.data != NULL && bytes.length == sizeof(prepared)) {
    memset((void *)bytes.data, 0, bytes.length);
  }
  if (result.status == FTUN_OK && publish_frs) {
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
  size_t path_length = strlen(task->first);
  size_t input_length;
  ftun_status_t status;
  uint64_t now_ms;
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
  input = (uint8_t *)calloc(1u, input_length);
  if (input == NULL) return FTUN_E_LIMIT;
  work = (ftun_core_reload_work_t *)input;
  work->magic = FTUN_CORE_RELOAD_WORK_MAGIC;
  work->maximum_bytes = usage.normal_available / 2u;
  work->service_descriptor = (uintptr_t)control->service_descriptor;
  work->path_length = (uint32_t)path_length;
  memcpy(input + sizeof(*work), task->first, path_length + 1u);
  {
    const ftun_config_t *active = NULL;
    size_t index;
    ftun_runtime_manager_info_t info;
    if (ftun_runtime_manager_get_info(task->core, &info) != FTUN_OK) {
      free(input);
      return FTUN_E_STATE_CORRUPT;
    }
    work->base_generation = info.generation;
    if (ftun_runtime_active_config(task->core, &active) == FTUN_OK) {
      for (index = 0u; index < active->inbound_count; index++) {
        if (active->inbounds[index].kind == FTUN_CONFIG_INBOUND_TUN) {
          work->socket_mark = UINT32_C(0x4654);
          break;
        }
      }
    }
  }
  memset(&job, 0, sizeof(job));
  job.execute = ftun_core_reload_execute;
  job.input.data = input;
  job.input.length = input_length;
  job.result_capacity = sizeof(ftun_core_reload_result_t);
  job.accounted_extra = (size_t)work->maximum_bytes;
  job.result_cleanup = ftun_core_reload_result_cleanup;
  (void)pthread_mutex_lock(&task->mutex);
  task->async_started = 1;
  (void)pthread_mutex_unlock(&task->mutex);
  status = ftun_worker_submit(control->reload_worker, &job,
    ftun_core_reload_worker_completed, task, &prepare_operation);
  free(input);
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
  if (control != NULL && control->service.implementation != NULL) {
    (void)ftun_core_service_wakeup(&control->service);
  }
}

static ftun_status_t ftun_core_worker_stop_until(ftun_worker_t *worker,
                                                  uint64_t deadline_ms)
{
  size_t callbacks = 0u;
  ftun_status_t status;
  if (worker == NULL) return FTUN_OK;
  status = ftun_worker_stop(worker);
  if (status != FTUN_OK) return status;
  status = ftun_worker_poll(worker, SIZE_MAX, &callbacks);
  if (status != FTUN_OK) return status;
  status = ftun_worker_join_until(worker, deadline_ms);
  if (status != FTUN_OK) return status;
  callbacks = 0u;
  return ftun_worker_poll(worker, SIZE_MAX, &callbacks);
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
  status = ftun_runtime_manager_create_limits(budget, retained_limit,
                                               retained_bytes_limit, &core);
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
  control->budget = budget;
  control->data_budget = data_budget;
  control->service_descriptor = descriptor;
  control->core = core;
  control->task_capacity = operation_capacity;
  control->task_control_reserve = operation_control_reserve;
  control->state = FTUN_CORE_CREATED;
  control->stop_deadline_ms = UINT64_MAX;
  status = ftun_core_context_set_control(core, control);
  if (status != FTUN_OK) goto fail;
  *out = core;
  return FTUN_OK;

fail:
  if (control != NULL) {
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
    (void)ftun_operation_queue_destroy(&control->operations);
    if (condition_initialized) {
      (void)pthread_cond_destroy(&control->condition);
    }
    if (mutex_initialized) (void)pthread_mutex_destroy(&control->mutex);
    free(control->tasks);
    free(control);
  }
  (void)ftun_runtime_manager_destroy(&core);
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
  task->completion(operation, result, task->completion_user);
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
                                      ftun_operation_t **out)
{
  ftun_core_control_t *control = NULL;
  ftun_control_task_t *task = NULL;
  ftun_operation_t *operation = NULL;
  ftun_reservation_t *reservation = NULL;
  size_t charge = sizeof(*task);
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core == NULL || completion == NULL || out == NULL ||
      (kind != FTUN_CONTROL_POST &&
       (first == NULL || first[0] == '\0')) ||
      (kind == FTUN_CONTROL_SELECT &&
       (second == NULL || second[0] == '\0'))) return FTUN_E_INVALID;
  status = ftun_core_control(core, &control);
  if (status != FTUN_OK) return status;
  if (first != NULL) {
    size_t length = strlen(first);
    if (length == 0u || length > FTUN_CORE_CONTROL_STRING ||
        length + 1u > SIZE_MAX - charge) return FTUN_E_LIMIT;
    charge += length + 1u;
  }
  if (second != NULL) {
    size_t length = strlen(second);
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
  task->completion_user = user;
  task->kind = kind;
  (void)pthread_mutex_lock(&control->mutex);
  if (control->state != FTUN_CORE_RUNNING || control->stop_requested) {
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
  if (kind == FTUN_CONTROL_RELOAD && control->reload_pending) {
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
  if (kind == FTUN_CONTROL_RELOAD) control->reload_pending = 1;
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
      ftun_status_t save_status = ftun_core_state_schedule(
        core, control, active->base.cache_file, 0u);
      if (save_status != FTUN_OK) {
        ftun_core_log_status(core, save_status, FTUN_STAGE_STATE_RESTORE,
                             "group cache save failed");
      }
    }
    status = ftun_core_reload_schedule(control, task);
    if (status == FTUN_OK) return;
  } else if (task->kind == FTUN_CONTROL_SELECT) {
    status = ftun_runtime_select_names(core,
      (ftun_string_t){task->first, strlen(task->first)},
      (ftun_string_t){task->second, strlen(task->second)});
    if (status == FTUN_OK) {
      const ftun_config_t *active = NULL;
      if (ftun_runtime_active_config(core, &active) == FTUN_OK &&
          active->base.state_cache) {
        ftun_status_t save_status = ftun_core_state_schedule(
          core, control, active->base.cache_file, 0u);
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
  (void)ftun_operation_complete(task->completion_token, result);
}

ftun_status_t ftun_core_run(ftun_core_t *core, const char *path)
{
  ftun_core_control_t *control = NULL;
  uint64_t stop_deadline_ms = UINT64_MAX;
  uint32_t stage = FTUN_STAGE_CONFIG_READ;
  bool reload_stopped = true;
  bool state_stopped = true;
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
  control->stop_deadline_ms = UINT64_MAX;
  (void)pthread_mutex_unlock(&control->mutex);
  /* Create owner-side workers only after the caller has entered run().  The
   * CLI blocks its control signals immediately before this call, so workers
   * inherit the same mask and SIGHUP remains dedicated to sigwait(). */
  status = ftun_worker_create(control->budget, 1u,
                              &control->reload_worker);
  if (status == FTUN_OK) {
    status = ftun_worker_create(control->budget,
      FTUN_CORE_STATE_WORKER_CAPACITY, &control->state_worker);
  }
  if (status == FTUN_OK) {
    status = ftun_worker_set_wakeup(control->reload_worker,
                                    ftun_core_reload_wakeup, control);
  }
  if (status == FTUN_OK) {
    status = ftun_worker_set_wakeup(control->state_worker,
                                    ftun_core_reload_wakeup, control);
  }
  if (status != FTUN_OK) {
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
    (void)pthread_mutex_lock(&control->mutex);
    control->state = FTUN_CORE_CREATED;
    control->owner_valid = 0;
    control->stop_requested = 0;
    (void)pthread_mutex_unlock(&control->mutex);
    return status;
  }
  status = ftun_core_transaction(core, control, path, 0, &stage);
  if (status != FTUN_OK) {
    (void)ftun_worker_stop(control->reload_worker);
    (void)ftun_worker_join(control->reload_worker);
    (void)ftun_worker_destroy(&control->reload_worker);
    (void)ftun_worker_stop(control->state_worker);
    (void)ftun_worker_join(control->state_worker);
    (void)ftun_worker_destroy(&control->state_worker);
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
                           "reload worker failed");
    }
    if (status == FTUN_OK) {
      status = ftun_worker_poll(control->state_worker, 1u,
                                &state_callbacks);
      round_work += state_callbacks;
      if (state_callbacks == 1u) quota_exhausted = true;
    }
    if (status != FTUN_OK) {
      ftun_core_log_status(core, status, FTUN_STAGE_STATE_RESTORE,
                           "state worker failed");
    }
    if (status == FTUN_OK && control->retired_logger != NULL) {
      uint64_t now_ms = 0u;
      status = ftun_monotonic_now(&now_ms);
      if (status == FTUN_OK) {
        ftun_status_t reap_status = ftun_core_logger_reap(control, now_ms);
        if (reap_status != FTUN_OK && reap_status != FTUN_E_TIMEOUT) {
          status = reap_status;
        }
      }
    }
    may_block = task == NULL && reload_callbacks == 0u &&
      state_callbacks == 0u && !pending_control &&
      !ftun_operation_queue_has_ready(control->operations);
    (void)ftun_monotonic_now(&before_engine_ms);
    if (status == FTUN_OK) {
      status = ftun_core_service_run_once(&control->service, may_block,
                                          &service_usage);
    }
    (void)ftun_monotonic_now(&after_engine_ms);
    round_work += service_usage.work;
    if (service_usage.quota_exhausted) quota_exhausted = true;
    if (status != FTUN_OK) {
      ftun_core_log_status(core, status, FTUN_STAGE_CONTROL,
                           "production data plane failed");
    }
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
  stop_deadline_ms = control->stop_deadline_ms;
  while (control->task_count != 0u) {
    ftun_control_task_t *task = control->tasks[control->task_head];
    control->tasks[control->task_head] = NULL;
    control->task_head = (control->task_head + 1u) % control->task_capacity;
    control->task_count--;
    if (!task->control_priority) control->normal_task_count--;
    ftun_control_task_consumed(task);
  }
  (void)pthread_mutex_unlock(&control->mutex);
  {
    ftun_status_t state_status = ftun_core_state_drain_until(
      control->state_worker, stop_deadline_ms);
    if (state_status == FTUN_OK) {
      const ftun_config_t *active = NULL;
      if (ftun_runtime_active_config(core, &active) == FTUN_OK &&
          active->base.state_cache) {
        state_status = ftun_core_state_schedule(
          core, control, active->base.cache_file, stop_deadline_ms);
        if (state_status == FTUN_OK) {
          state_status = ftun_core_state_drain_until(
            control->state_worker, stop_deadline_ms);
        }
      }
    }
    if (state_status != FTUN_OK && state_status != FTUN_E_TIMEOUT) {
      ftun_core_log_status(core, state_status, FTUN_STAGE_STATE_RESTORE,
                           "group cache save failed during stop");
    }
    {
      ftun_status_t worker_status = ftun_core_worker_stop_until(
        control->state_worker, stop_deadline_ms);
      state_stopped = worker_status == FTUN_OK;
      if ((state_status == FTUN_E_TIMEOUT || worker_status == FTUN_E_TIMEOUT) &&
          status == FTUN_OK) status = FTUN_E_TIMEOUT;
      else if (worker_status != FTUN_OK && status == FTUN_OK) {
        status = worker_status;
      }
    }
  }
  {
    ftun_status_t worker_status = ftun_core_worker_stop_until(
      control->reload_worker, stop_deadline_ms);
    reload_stopped = worker_status == FTUN_OK;
    if (worker_status != FTUN_OK && status == FTUN_OK) status = worker_status;
  }
  {
    ftun_status_t stop_status = ftun_core_service_stop_until(
      &control->service, stop_deadline_ms);
    if (stop_status != FTUN_OK && status == FTUN_OK) status = stop_status;
  }
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
    ftun_status_t destroy_status = ftun_core_service_destroy_until(
      &control->service, stop_deadline_ms);
    if (destroy_status != FTUN_OK && status == FTUN_OK) {
      status = destroy_status;
    }
  }
  (void)ftun_core_context_set_logger(core, NULL);
  {
    ftun_status_t logger_status = ftun_logger_destroy_until(
      &control->logger, stop_deadline_ms);
    if (logger_status != FTUN_OK && status == FTUN_OK) {
      status = logger_status;
    }
  }
  {
    ftun_status_t logger_status = ftun_logger_destroy_until(
      &control->retired_logger, stop_deadline_ms);
    if (logger_status != FTUN_OK && status == FTUN_OK) {
      status = logger_status;
    }
  }
  (void)pthread_mutex_lock(&control->mutex);
  control->state = control->service.implementation == NULL &&
                   reload_stopped && state_stopped &&
    control->logger == NULL && control->retired_logger == NULL
      ? FTUN_CORE_STOPPED : FTUN_CORE_STOPPING;
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
  if (control->state == FTUN_CORE_STOPPED) {
    (void)pthread_mutex_unlock(&control->mutex);
    return FTUN_OK;
  }
  if (control->stop_requested) {
    if (deadline_ms < control->stop_deadline_ms) {
      control->stop_deadline_ms = deadline_ms;
    }
    if (control->service.implementation != NULL) {
      (void)ftun_core_service_wakeup(&control->service);
    }
    (void)pthread_cond_broadcast(&control->condition);
    (void)pthread_mutex_unlock(&control->mutex);
    return FTUN_OK;
  }
  if (control->state != FTUN_CORE_RUNNING &&
      control->state != FTUN_CORE_STARTING) {
    (void)pthread_mutex_unlock(&control->mutex);
    return FTUN_E_STALE;
  }
  control->stop_requested = 1;
  control->stop_deadline_ms = deadline_ms;
  if (control->service.implementation != NULL) {
    (void)ftun_core_service_wakeup(&control->service);
  }
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
  out->owner_rounds = control->owner_rounds;
  out->owner_max_busy_ms = control->owner_max_busy_ms;
  out->owner_max_deadline_lateness_ms =
    control->owner_max_deadline_lateness_ms;
  out->owner_max_work = control->owner_max_work;
  out->owner_quota_exhaustions = control->owner_quota_exhaustions;
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
  ftun_budget_t *root_budget;
  ftun_budget_t *budget;
  ftun_budget_t *data_budget;
  ftun_core_state_t state;
  uint64_t now_ms = 0u;
  ftun_status_t status;
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
  if (ftun_monotonic_now(&now_ms) != FTUN_OK) return FTUN_E_IO;
  if (state == FTUN_CORE_STOPPING) {
    status = ftun_core_worker_stop_until(control->state_worker, now_ms);
    if (status == FTUN_E_TIMEOUT) return FTUN_E_AGAIN;
    if (status != FTUN_OK) return status;
    status = ftun_core_worker_stop_until(control->reload_worker, now_ms);
    if (status == FTUN_E_TIMEOUT) return FTUN_E_AGAIN;
    if (status != FTUN_OK) return status;
    status = ftun_core_service_destroy_until(&control->service, now_ms);
    if (status == FTUN_E_TIMEOUT) return FTUN_E_AGAIN;
    if (status != FTUN_OK) return status;
    status = ftun_logger_destroy_until(&control->logger, now_ms);
    if (status == FTUN_E_TIMEOUT) return FTUN_E_AGAIN;
    if (status != FTUN_OK) return status;
    status = ftun_logger_destroy_until(&control->retired_logger, now_ms);
    if (status == FTUN_E_TIMEOUT) return FTUN_E_AGAIN;
    if (status != FTUN_OK) return status;
    (void)pthread_mutex_lock(&control->mutex);
    control->state = FTUN_CORE_STOPPED;
    (void)pthread_mutex_unlock(&control->mutex);
  }
  root_budget = control->root_budget;
  budget = control->budget;
  data_budget = control->data_budget;
  if (control->reload_worker != NULL) {
    status = ftun_core_worker_stop_until(control->reload_worker, now_ms);
    if (status == FTUN_E_TIMEOUT) return FTUN_E_AGAIN;
    if (status == FTUN_OK) status = ftun_worker_destroy(&control->reload_worker);
    if (status != FTUN_OK) return status;
  }
  if (control->state_worker != NULL) {
    status = ftun_core_worker_stop_until(control->state_worker, now_ms);
    if (status == FTUN_E_TIMEOUT) return FTUN_E_AGAIN;
    if (status == FTUN_OK) status = ftun_worker_destroy(&control->state_worker);
    if (status != FTUN_OK) return status;
  }
  (void)ftun_core_context_set_logger(owned, NULL);
  (void)ftun_core_context_set_control(owned, NULL);
  manager = owned;
  status = ftun_runtime_manager_destroy(&manager);
  if (status != FTUN_OK) {
    (void)ftun_core_context_set_control(owned, control);
    (void)ftun_core_context_set_logger(owned, control->logger);
    return status;
  }
  *core = NULL;
  (void)ftun_core_service_destroy(&control->service);
  (void)ftun_logger_destroy(&control->logger);
  (void)ftun_logger_destroy(&control->retired_logger);
  status = ftun_operation_queue_destroy(&control->operations);
  if (status != FTUN_OK) return status;
  free(control->config_path);
  free(control->tasks);
  (void)pthread_cond_destroy(&control->condition);
  (void)pthread_mutex_destroy(&control->mutex);
  free(control);
  status = ftun_budget_destroy(&data_budget);
  if (status == FTUN_OK) status = ftun_budget_destroy(&budget);
  if (status == FTUN_OK) status = ftun_budget_destroy(&root_budget);
  if (status != FTUN_OK) return status;
  return FTUN_OK;
}
