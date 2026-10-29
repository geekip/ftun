#define _POSIX_C_SOURCE 200809L

#include "platform/file.h"
#include "app/control/diagnostics.h"
#include "app/runtime_support.h"
#include "app/config/compile.h"
#include "app/config/model.h"
#include "proxy/http_route.h"
#include "proxy/runtime_state.h"
#include "proxy/state/group_cache.h"
#include "proxy/state/restore.h"
#include "core/log/log.h"
#include "core/log/event_log.h"
#include "core/context.h"
#include "platform/clock.h"
#include "libs/transport/socket_path.h"
#if defined(FTUN_HAVE_MODULE_FRS)
#include "proxy/frs/frs.h"
#include "core/io/file.h"
#endif

#include <stdlib.h>
#include <string.h>

#define FTUN_CORE_STATE_WORK_MAGIC UINT32_C(0x46545343)
#define FTUN_CORE_RELOAD_PUBLISH_MAGIC UINT32_C(0x46545042)

struct ftun_app_runtime_candidate {
  ftun_budget_t *budget;
  ftun_reservation_t reservation;
  ftun_reservation_t records_reservation;
  const ftun_config_t *config;
  ftun_runtime_t *candidate;
  ftun_runtime_t *detached;
  ftun_group_cache_snapshot_t *group_cache;
  ftun_status_t group_cache_status;
  ftun_runtime_group_record_t *group_records;
  size_t group_record_capacity;
  ftun_state_restore_info_t restore_info;
#if defined(FTUN_HAVE_MODULE_FRS)
  ftun_frs_view_t *cleanup_view;
#endif
};

static ftun_status_t ftun_proxy_attachment_create(ftun_budget_t *budget,
  const ftun_config_t *config, ftun_app_runtime_candidate_t **out)
{
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_app_runtime_candidate_t *attachment;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (budget == NULL || config == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_budget_reserve(budget, sizeof(*attachment), &reservation);
  if (status != FTUN_OK) return status;
  attachment = (ftun_app_runtime_candidate_t *)calloc(1u, sizeof(*attachment));
  if (attachment == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  attachment->budget = budget;
  attachment->reservation = reservation;
  attachment->config = config;
  *out = attachment;
  return FTUN_OK;
}

typedef struct {
  uint32_t magic;
  uint32_t path_length;
  uint64_t contents_length;
  uintptr_t budget;
} ftun_core_state_work_t;

#if defined(FTUN_HAVE_MODULE_FRS)
typedef struct {
  uint32_t magic;
  uint32_t path_length;
  uint64_t body_length;
  uintptr_t budget;
} ftun_core_reload_publish_work_t;

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

static ftun_status_t ftun_core_runtime_prepare(
  ftun_core_t *core, ftun_budget_t *budget,
  const ftun_config_t *config, uint64_t generation, ftun_runtime_t **out)
{
#if defined(FTUN_HAVE_MODULE_FRS)
  ftun_file_info_t info;
  /* 本地规则文件存在就直接使用（无网络也能启动）。文件缺失且开启自动更新时
   * 不再同步下载：FRS 以 NOT_READY 启动，命中其规则的新连接被拒绝，后台
   * 下载成功后经正常发布入口切换。 */
  if (config != NULL && config->frs.active && config->frs.path != NULL &&
      ftun_file_inspect_path(config->frs.path, &info) == FTUN_E_EOF &&
      config->frs.auto_update && config->frs.url != NULL &&
      config->frs.url[0] != '\0') {
    (void)budget;
    (void)generation;
    ftun_core_log_status(core, FTUN_OK, FTUN_STAGE_STATE_RESTORE,
      FTUN_DIAGNOSTIC_STARTUP_PUBLISH,
      "FRS rule file is missing; starting NOT_READY and downloading in background");
    return ftun_runtime_prepare_frs_pending(core, config, out);
  }
#else
  (void)budget;
#endif
  (void)generation;
  return ftun_runtime_prepare(core, config, out);
}

#if defined(FTUN_HAVE_MODULE_FRS)

static ftun_status_t ftun_core_reload_read_file(ftun_budget_t *budget,
  const char *path, uint64_t maximum_bytes, uint8_t **out,
  size_t *out_length, ftun_reservation_t *out_reservation)
{
  ftun_file_info_t info;
  uint8_t *data = NULL;
  size_t length;
  size_t offset = 0u;
  int descriptor = -1;
  ftun_reservation_t descriptor_reservation = (ftun_reservation_t){0};
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_budget_resources_t resources = {0u, 1u, 0u};
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (out_length != NULL) *out_length = 0u;
  if (out_reservation != NULL) *out_reservation = (ftun_reservation_t){0};
  if (budget == NULL || path == NULL || out == NULL || out_length == NULL ||
      out_reservation == NULL) return FTUN_E_INVALID;
  status = ftun_budget_reserve_resources(budget, resources, &descriptor_reservation);
  if (status != FTUN_OK) return status;
  status = ftun_file_open(path, FTUN_FILE_READ_NOFOLLOW, &descriptor);
  if (descriptor < 0) {
    status = status == FTUN_E_EOF ? FTUN_E_EOF : FTUN_E_IO;
    goto done;
  }
  if (ftun_file_inspect(descriptor, &info) != FTUN_OK || !info.regular ||
      (uintmax_t)info.size > (uintmax_t)SIZE_MAX ||
      (uintmax_t)info.size > maximum_bytes / 2u) {
    status = FTUN_E_LIMIT;
    goto done;
  }
  length = (size_t)info.size;
  status = ftun_budget_reserve(budget, length == 0u ? 1u : length, &reservation);
  if (status != FTUN_OK) goto done;
  data = (uint8_t *)malloc(length == 0u ? 1u : length);
  if (data == NULL) {
    status = FTUN_E_LIMIT;
    goto done;
  }
  while (offset < length) {
    ptrdiff_t received = ftun_file_read(descriptor, data + offset, length - offset);
    if (received > 0) offset += (size_t)received;
    else {
      status = FTUN_E_IO;
      goto done;
    }
  }
  if (ftun_file_close(descriptor) != 0) {
    descriptor = -1;
    status = FTUN_E_IO;
    goto done;
  }
  descriptor = -1;
  *out = data;
  *out_length = length;
  *out_reservation = reservation;
  data = NULL;
  reservation = (ftun_reservation_t){0};
  status = FTUN_OK;

done:
  if (descriptor >= 0) (void)ftun_file_close(descriptor);
  (void)ftun_reservation_release(&descriptor_reservation);
  free(data);
  (void)ftun_reservation_release(&reservation);
  return status;
}

#endif

static ftun_status_t ftun_proxy_support_prepare(
  ftun_budget_t *budget, const ftun_config_t *config,
  uint64_t maximum_bytes, const ftun_app_prepare_context_t *context,
  ftun_app_runtime_candidate_t **out, bool *publish_required)
{
  ftun_app_runtime_candidate_t *attachment;
  ftun_runtime_t *runtime = NULL;
  ftun_status_t status = FTUN_OK;
  *out = NULL;
  *publish_required = false;
  status = ftun_proxy_attachment_create(budget, config, out);
  if (status != FTUN_OK) return status;
  attachment = *out;
#if defined(FTUN_HAVE_MODULE_FRS)
  {
    ftun_frs_view_t *view = NULL;
    uint8_t *file = NULL;
    size_t file_length = 0u;
    ftun_http_fetch_result_t fetched;
    ftun_reservation_t file_reservation = (ftun_reservation_t){0};
    bool publish = false;
    memset(&fetched, 0, sizeof(fetched));
    if ((config->plan->prepare & FTUN_PLAN_FRS) != 0u) {
      status = ftun_core_reload_read_file(budget, config->frs.path,
        maximum_bytes, &file, &file_length, &file_reservation);
      if (status == FTUN_E_EOF && config->frs.auto_update &&
          config->frs.url != NULL && config->frs.url[0] != '\0') {
        ftun_http_fetch_spec_t fetch_spec;
        uint64_t now_ms;
        memset(&fetch_spec, 0, sizeof(fetch_spec));
        status = ftun_monotonic_now(&now_ms);
        if (status == FTUN_OK && now_ms > UINT64_MAX - UINT64_C(30000)) {
          status = FTUN_E_LIMIT;
        }
        if (status == FTUN_OK) {
          ftun_string_t resolver = {NULL, 0u};
          fetch_spec.budget = budget;
          fetch_spec.url.data = config->frs.url;
          fetch_spec.url.length = strlen(config->frs.url);
          fetch_spec.maximum_bytes = (size_t)maximum_bytes / 2u;
          fetch_spec.deadline_ms = now_ms + UINT64_C(30000);
          fetch_spec.socket_mark = context->socket_mark;
          fetch_spec.generation = context->generation;
          fetch_spec.allow_system_resolver = context->allow_system_resolver;
          fetch_spec.path.open = ftun_socket_path_open;
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
        status = ftun_frs_open_bytes_budget(budget, bytes, &view);
      }
      if (status == FTUN_OK) {
        status = ftun_runtime_prepare_detached(config, view, &runtime);
        if (status == FTUN_OK) view = NULL;
      }
      *publish_required = publish;
    } else {
      status = ftun_runtime_prepare_detached(config, NULL, &runtime);
    }
    free(file);
    (void)ftun_reservation_release(&file_reservation);
    {
      ftun_status_t cleanup = ftun_frs_view_release(&view);
      attachment->cleanup_view = view;
      if (status == FTUN_OK) status = cleanup;
    }
    ftun_http_fetch_release(&fetched);
  }
#endif
  (void)maximum_bytes;
  (void)context;
  attachment->detached = runtime;
  return status;
}

static void ftun_proxy_support_load_state(ftun_app_runtime_candidate_t *attachment)
{
  if (attachment->config->base.proxy.state_cache) {
    attachment->group_cache_status = ftun_group_cache_load_budget(
      attachment->budget, attachment->config->base.proxy.cache_file, &attachment->group_cache);
  }
}

static ftun_status_t ftun_proxy_support_start(ftun_core_t *core,
  ftun_budget_t *budget, const ftun_config_t *config, uint64_t generation,
  ftun_app_runtime_candidate_t **out, uint32_t *stage)
{
  ftun_app_runtime_candidate_t *attachment;
  uint64_t now = 0u;
  ftun_status_t status;
  *out = NULL;
  status = ftun_proxy_attachment_create(budget, config, out);
  if (status != FTUN_OK) return status;
  attachment = *out;
  status = ftun_core_runtime_prepare(core, budget, config, generation, &attachment->candidate);
  if (status != FTUN_OK) return status;
  if (stage != NULL) *stage = FTUN_STAGE_STATE_RESTORE;
  status = ftun_monotonic_now(&now);
  if (status == FTUN_OK) {
    status = ftun_state_restore_candidate_at(core, config, now,
      15u * 60u * 1000u, &attachment->restore_info);
  }
  return status;
}

static ftun_status_t ftun_proxy_support_adopt(ftun_core_t *core,
  ftun_app_runtime_candidate_t *attachment, uint64_t now_ms, uint32_t *out_stage)
{
  ftun_status_t status;
#if defined(FTUN_HAVE_MODULE_FRS)
  status = ftun_runtime_attach_prepared(core, &attachment->detached,
                                        &attachment->candidate);
#else
  status = ftun_runtime_prepare(core, attachment->config, &attachment->candidate);
#endif
  if (status == FTUN_OK && out_stage != NULL) *out_stage = FTUN_STAGE_STATE_RESTORE;
  if (status == FTUN_OK) {
    status = ftun_state_restore_candidate_snapshot_at(core, attachment->config,
      attachment->group_cache, attachment->group_cache_status, now_ms,
      15u * 60u * 1000u, &attachment->restore_info);
  }
  if (status == FTUN_OK) {
    size_t count = 0u;
    ftun_status_t records_status = ftun_runtime_group_records(core, NULL, 0u, &count);
    if (records_status != FTUN_OK && records_status != FTUN_E_LIMIT) {
      status = records_status;
    } else if (count > SIZE_MAX / sizeof(*attachment->group_records)) {
      status = FTUN_E_LIMIT;
    } else if (count != 0u) {
      status = ftun_budget_reserve(attachment->budget,
        count * sizeof(*attachment->group_records), &attachment->records_reservation);
      if (status == FTUN_OK) {
        attachment->group_records = (ftun_runtime_group_record_t *)calloc(
          count, sizeof(*attachment->group_records));
        if (attachment->group_records == NULL) status = FTUN_E_LIMIT;
        else attachment->group_record_capacity = count;
      }
    }
  }
  return status;
}

static ftun_status_t ftun_proxy_support_stage(ftun_core_t *core,
  ftun_app_runtime_candidate_t *attachment, uint64_t generation)
{
  return ftun_runtime_stage_commit(core, attachment->candidate, generation);
}

static ftun_status_t ftun_proxy_support_inherit(ftun_core_t *core,
  ftun_app_runtime_candidate_t *attachment)
{
  size_t count = 0u;
  size_t index;
  ftun_status_t status;
  if (attachment->group_record_capacity == 0u) return FTUN_OK;
  status = ftun_runtime_group_records(core, attachment->group_records,
    attachment->group_record_capacity, &count);
  for (index = 0u; status == FTUN_OK && index < count; index++) {
    status = ftun_runtime_candidate_group_restore(core,
      &attachment->group_records[index], true);
    if (status == FTUN_E_REJECTED || status == FTUN_E_STALE) status = FTUN_OK;
  }
  return status;
}

static ftun_status_t ftun_proxy_support_commit(ftun_core_t *core,
  ftun_app_runtime_candidate_t *attachment)
{
  /* 宿主事务已以 Core 上下文为持有者预留代次。 */
  return ftun_runtime_commit_reserved(core, &attachment->candidate, core);
}

static void ftun_proxy_support_committed(ftun_core_t *core,
  const ftun_app_runtime_candidate_t *attachment)
{
  if (attachment->restore_info.cache_discarded) {
    ftun_core_log_status(core, FTUN_E_STALE, FTUN_STAGE_STATE_RESTORE,
                         FTUN_DIAGNOSTIC_STATE_DISCARD, "discarded incompatible group cache");
  }
}

static ftun_status_t ftun_proxy_support_release(ftun_core_t *core,
  ftun_app_runtime_candidate_t **attachment_ptr)
{
  ftun_app_runtime_candidate_t *attachment = *attachment_ptr;
  ftun_status_t status;
  if (attachment == NULL) return FTUN_OK;
  if (attachment->candidate != NULL) {
    status = ftun_runtime_abort(core, &attachment->candidate);
    if (status != FTUN_OK) return status;
  }
#if defined(FTUN_HAVE_MODULE_FRS)
  status = ftun_runtime_prepared_release(&attachment->detached);
  if (status != FTUN_OK) return status;
  status = ftun_frs_view_release(&attachment->cleanup_view);
  if (status != FTUN_OK) return status;
#endif
  status = ftun_group_cache_destroy(&attachment->group_cache);
  if (status != FTUN_OK) return status;
  free(attachment->group_records);
  attachment->group_records = NULL;
  attachment->group_record_capacity = 0u;
  status = ftun_reservation_release(&attachment->records_reservation);
  if (status != FTUN_OK) return status;
  status = ftun_reservation_release(&attachment->reservation);
  if (status != FTUN_OK) return status;
  free(attachment);
  *attachment_ptr = NULL;
  return FTUN_OK;
}

static ftun_status_t ftun_proxy_support_check(ftun_core_t *core,
  const ftun_config_t *config, bool for_run)
{
  ftun_runtime_t *candidate = NULL;
  ftun_status_t status = ftun_runtime_prepare(core, config, &candidate);
  if (status == FTUN_E_EOF && for_run && config->frs.active &&
      config->frs.auto_update && config->frs.url != NULL &&
      config->frs.url[0] != '\0') status = FTUN_OK;
  if (candidate != NULL) {
    ftun_status_t cleanup = ftun_runtime_abort(core, &candidate);
    if (status == FTUN_OK) status = cleanup;
  }
  return status;
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
  if (work->magic != FTUN_CORE_STATE_WORK_MAGIC || work->budget == 0u || work->path_length == 0u) {
    return FTUN_E_INVALID;
  }
  contents_length = (size_t)work->contents_length;
  if ((uint64_t)contents_length != work->contents_length) {
    return FTUN_E_LIMIT;
  }
  if (contents_length > SIZE_MAX - sizeof(*work) ||
      work->path_length > SIZE_MAX - sizeof(*work) - contents_length) {
    return FTUN_E_LIMIT;
  }
  prefix = sizeof(*work) + (size_t)work->path_length;
  if (input.length != prefix + contents_length ||
      input.data[prefix - 1u] != 0u) return FTUN_E_INVALID;
  path = (const char *)(input.data + sizeof(*work));
  return ftun_group_cache_publish((ftun_budget_t *)work->budget, path,
    (ftun_bytes_t){input.data + prefix, contents_length});
}

static ftun_status_t ftun_proxy_support_state_job(
  ftun_core_t *core, ftun_budget_t *budget, const char *path,
  uint64_t deadline_ms, ftun_worker_job_t *out, ftun_reservation_t *out_reservation)
{
  ftun_core_state_work_t *work;
  ftun_worker_job_t job;
  uint8_t *captured = NULL;
  uint8_t *input = NULL;
  size_t captured_length = 0u;
  size_t path_length;
  size_t input_length;
  ftun_reservation_t captured_reservation = (ftun_reservation_t){0}, reservation = (ftun_reservation_t){0};
  ftun_status_t status;
  if (out_reservation != NULL) *out_reservation = (ftun_reservation_t){0};
  if (core == NULL || budget == NULL || out == NULL || out_reservation == NULL ||
      path == NULL || path[0] == '\0') return FTUN_E_INVALID;
  path_length = strlen(path) + 1u;
  if (path_length > UINT32_MAX) return FTUN_E_LIMIT;
  status = ftun_group_cache_capture(core, budget, &captured, &captured_length, &captured_reservation);
  if (status != FTUN_OK) return status;
  if (path_length > SIZE_MAX - sizeof(*work) ||
      captured_length > SIZE_MAX - sizeof(*work) - path_length) {
    status = FTUN_E_LIMIT;
    goto done;
  }
  input_length = sizeof(*work) + path_length + captured_length;
  status = ftun_budget_reserve(budget, input_length, &reservation);
  if (status != FTUN_OK) goto done;
  input = (uint8_t *)calloc(1u, input_length);
  if (input == NULL) {
    status = FTUN_E_LIMIT;
    goto done;
  }
  work = (ftun_core_state_work_t *)input;
  work->magic = FTUN_CORE_STATE_WORK_MAGIC;
  work->budget = (uintptr_t)budget;
  work->path_length = (uint32_t)path_length;
  work->contents_length = (uint64_t)captured_length;
  memcpy(input + sizeof(*work), path, path_length);
  memcpy(input + sizeof(*work) + path_length, captured, captured_length);
  memset(&job, 0, sizeof(job));
  job.execute = ftun_core_state_execute;
  job.input = (ftun_bytes_t){input, input_length};
  job.deadline_ms = deadline_ms;
  *out = job;
  *out_reservation = reservation; reservation = (ftun_reservation_t){0};
  input = NULL;
done:
  free(input);
  free(captured);
  (void)ftun_reservation_release(&reservation);
  (void)ftun_reservation_release(&captured_reservation);
  return status;
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
  ftun_app_publish_result_t result;
  if (out_output_size != NULL) *out_output_size = 0u;
  if (input.data == NULL || input.length < sizeof(*work) || output == NULL ||
      output_capacity < sizeof(result) || out_output_size == NULL) {
    return FTUN_E_INVALID;
  }
  work = (const ftun_core_reload_publish_work_t *)input.data;
  if (work->magic != FTUN_CORE_RELOAD_PUBLISH_MAGIC || work->budget == 0u ||
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
  result.status = ftun_file_write_atomic_budget((ftun_budget_t *)work->budget, path,
    (ftun_bytes_t){body, (size_t)work->body_length}, 0644u,
    ftun_core_file_stage, &publish);
  result.published = publish.reached >= FTUN_FILE_STAGE_RENAMED;
  memcpy(output, &result, sizeof(result));
  *out_output_size = sizeof(result);
  return FTUN_OK;
}

#endif

static ftun_status_t ftun_proxy_support_publish_job(
  ftun_app_runtime_candidate_t *transaction, ftun_worker_job_t *out,
  ftun_reservation_t *out_reservation)
{
#if defined(FTUN_HAVE_MODULE_FRS)
  ftun_core_reload_publish_work_t *work;
  ftun_worker_job_t job;
  ftun_bytes_t body;
  const char *path;
  uint8_t *input;
  size_t path_length;
  size_t input_length;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_status_t status;
  if (out_reservation != NULL) *out_reservation = (ftun_reservation_t){0};
  if (transaction == NULL || out == NULL || out_reservation == NULL) return FTUN_E_INVALID;
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
  status = ftun_budget_reserve(transaction->budget, input_length, &reservation);
  if (status != FTUN_OK) return status;
  input = (uint8_t *)malloc(input_length);
  if (input == NULL) { (void)ftun_reservation_release(&reservation); return FTUN_E_LIMIT; }
  work = (ftun_core_reload_publish_work_t *)input;
  memset(work, 0, sizeof(*work));
  work->magic = FTUN_CORE_RELOAD_PUBLISH_MAGIC;
  work->budget = (uintptr_t)transaction->budget;
  work->path_length = (uint32_t)path_length;
  work->body_length = (uint64_t)body.length;
  memcpy(input + sizeof(*work), path, path_length + 1u);
  memcpy(input + sizeof(*work) + path_length + 1u, body.data, body.length);
  memset(&job, 0, sizeof(job));
  job.execute = ftun_core_reload_publish_execute;
  job.input = (ftun_bytes_t){input, input_length};
  job.result_capacity = sizeof(ftun_app_publish_result_t);
  *out = job;
  *out_reservation = reservation;
  return FTUN_OK;
#else
  (void)out_reservation;
  (void)out;
  (void)transaction;
  return FTUN_E_UNSUPPORTED;
#endif
}

const ftun_app_runtime_support_t ftun_proxy_runtime_support = {
  ftun_runtime_manager_attach,
  ftun_runtime_manager_clear,
  ftun_proxy_support_check,
  ftun_proxy_support_start,
  ftun_proxy_support_prepare,
  ftun_proxy_support_load_state,
  ftun_proxy_support_adopt,
  ftun_proxy_support_stage,
  ftun_proxy_support_inherit,
  ftun_proxy_support_commit,
  ftun_proxy_support_committed,
  ftun_proxy_support_release,
  ftun_runtime_select_names,
  ftun_proxy_support_state_job,
  ftun_proxy_support_publish_job,
  "group cache save failed",
  "FRS reload applied but directory durability is uncertain"
};
