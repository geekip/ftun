#include "update.h"

/* TASK-FRS-004 / TEST-FRS-004：FRS 下载、发布与 Runtime 更新，目标 0.4.0。 */

#include "config/model.h"
#include "core/operation.h"
#include "core/runtime.h"
#include "frs/format.h"
#include "frs/frs.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
  ftun_file_stage_t reached;
  ftun_file_stage_hook_fn user_hook;
  void *user;
} ftun_frs_publish_state_t;

static int ftun_frs_url_scheme(ftun_string_t url, int *https)
{
  static const char http_prefix[] = "http://";
  static const char https_prefix[] = "https://";
  if (https != NULL) *https = 0;
  if (url.data == NULL) return 0;
  if (url.length > sizeof(https_prefix) - 1u &&
      memcmp(url.data, https_prefix, sizeof(https_prefix) - 1u) == 0) {
    if (https != NULL) *https = 1;
    return 1;
  }
  return url.length > sizeof(http_prefix) - 1u &&
    memcmp(url.data, http_prefix, sizeof(http_prefix) - 1u) == 0;
}

static ftun_status_t ftun_frs_publish_hook(ftun_file_stage_t stage, void *user)
{
  ftun_frs_publish_state_t *state = (ftun_frs_publish_state_t *)user;
  state->reached = stage;
  return state->user_hook == NULL ? FTUN_OK :
    state->user_hook(stage, state->user);
}

static ftun_status_t ftun_frs_etag_replace(char **state, ftun_string_t value)
{
  char *copy = NULL;
  if (state == NULL) return FTUN_OK;
  if (value.length != 0u) {
    if (value.data == NULL || value.length == SIZE_MAX) return FTUN_E_INVALID;
    copy = (char *)malloc(value.length + 1u);
    if (copy == NULL) return FTUN_E_LIMIT;
    memcpy(copy, value.data, value.length);
    copy[value.length] = '\0';
  }
  free(*state);
  *state = copy;
  return FTUN_OK;
}

static ftun_status_t ftun_frs_download_once(
  const ftun_frs_update_request_t *request, int conditional,
  ftun_frs_download_t *download)
{
  ftun_frs_download_request_t input;
  memset(&input, 0, sizeof(input));
  memset(download, 0, sizeof(*download));
  input.url = request->url;
  input.deadline_ms = request->deadline_ms;
  input.outbound_id = request->outbound_id;
  input.dns_server_id = request->dns_server_id;
  input.conditional = conditional != 0;
  if (conditional && request->etag != NULL) {
    input.if_none_match.data = request->etag;
    input.if_none_match.length = strlen(request->etag);
  }
  return request->download(request->download_user, &input, download);
}

ftun_status_t ftun_frs_update(ftun_core_t *core,
                              const ftun_frs_update_request_t *request,
                              ftun_operation_t **out)
{
  ftun_runtime_t *baseline_runtime = NULL;
  ftun_frs_view_t *baseline = NULL;
  ftun_frs_view_t *candidate_view = NULL;
  ftun_runtime_t *candidate_runtime = NULL;
  ftun_budget_t *budget = NULL;
  ftun_operation_t *operation = NULL;
  ftun_frs_download_t download;
  ftun_frs_publish_state_t publish;
  ftun_error_t result;
  ftun_status_t status;
  int https = 0;
  int conditional;
  int retry = 0;
  if (out != NULL) *out = NULL;
  if (request != NULL && request->outcome != NULL) {
    *request->outcome = FTUN_FRS_UPDATE_NONE;
  }
  if (core == NULL || request == NULL || out == NULL ||
      !ftun_frs_url_scheme(request->url, &https) ||
      request->destination == NULL || request->destination[0] == '\0' ||
      request->config == NULL || request->maximum_bytes < FTUN_FRS_HEADER_BYTES ||
      request->deadline_ms <= request->now_ms || request->outcome == NULL ||
      request->operations == NULL || request->completion == NULL ||
      request->download == NULL || request->release == NULL) return FTUN_E_INVALID;
  status = ftun_operation_accept(request->operations, request->completion,
                                 request->completion_user, &operation);
  if (status != FTUN_OK) return status;
  memset(&download, 0, sizeof(download));
  memset(&result, 0, sizeof(result));
  memset(&publish, 0, sizeof(publish));
  publish.user_hook = request->publish_hook;
  publish.user = request->publish_hook_user;
  status = ftun_runtime_active_acquire(core, &baseline_runtime);
  if (status == FTUN_OK) {
    status = ftun_runtime_frs_view(baseline_runtime, &baseline);
    if (status == FTUN_E_AGAIN) {
      baseline = NULL;
      status = FTUN_OK;
    }
  } else if (status == FTUN_E_AGAIN) {
    baseline_runtime = NULL;
    status = FTUN_OK;
  }
  conditional = status == FTUN_OK && baseline != NULL &&
    request->etag != NULL && request->etag[0] != '\0';
  while (status == FTUN_OK) {
    status = ftun_frs_download_once(request, conditional, &download);
    if (status != FTUN_OK) break;
    if (download.finished_ms < request->now_ms ||
        download.finished_ms > request->deadline_ms ||
        download.outbound_id != request->outbound_id ||
        download.dns_server_id != request->dns_server_id ||
        (https && !download.tls_verified)) {
      status = FTUN_E_REJECTED;
      break;
    }
    if (download.http_status == 304u) {
      if (conditional && baseline != NULL) {
        *request->outcome = FTUN_FRS_UPDATE_UNCHANGED;
        break;
      }
      request->release(request->download_user, &download);
      memset(&download, 0, sizeof(download));
      if (retry != 0) {
        status = FTUN_E_PROTOCOL;
        break;
      }
      retry = 1;
      conditional = 0;
      continue;
    }
    if (download.http_status != 200u || download.data == NULL ||
        download.length < FTUN_FRS_HEADER_BYTES ||
        download.length > request->maximum_bytes) {
      status = download.length > request->maximum_bytes ?
        FTUN_E_LIMIT : FTUN_E_PROTOCOL;
      break;
    }
    if (baseline != NULL) {
      ftun_bytes_t baseline_bytes;
      if (ftun_frs_view_bytes(baseline, &baseline_bytes) != FTUN_OK) {
        status = FTUN_E_STATE_CORRUPT;
        break;
      }
      if (baseline_bytes.length == download.length &&
          ftun_frs_file_checksum((ftun_bytes_t){download.data, download.length}) ==
            ftun_frs_file_checksum(baseline_bytes) &&
          memcmp(baseline_bytes.data, download.data, download.length) == 0) {
        status = ftun_frs_etag_replace(request->accepted_etag, download.etag);
        if (status == FTUN_OK) *request->outcome = FTUN_FRS_UPDATE_UNCHANGED;
        break;
      }
    }
    status = ftun_runtime_manager_budget(core, &budget);
    if (status == FTUN_OK) status = ftun_frs_open_bytes_budget(budget,
      (ftun_bytes_t){download.data, download.length}, &candidate_view);
    if (status == FTUN_OK) {
      status = ftun_runtime_prepare_with_frs(core, request->config,
                                             candidate_view,
                                             &candidate_runtime);
    }
    if (status == FTUN_OK) {
      status = ftun_file_write_atomic_with_hook(
        request->destination,
        (ftun_bytes_t){download.data, download.length}, 0644u,
        ftun_frs_publish_hook, &publish);
    }
    if (status == FTUN_OK || publish.reached >= FTUN_FILE_STAGE_RENAMED) {
      ftun_status_t commit_status = ftun_runtime_commit(core,
                                                        &candidate_runtime);
      if (commit_status != FTUN_OK) {
        status = commit_status;
        break;
      }
      if (status == FTUN_OK) {
        *request->outcome = FTUN_FRS_UPDATE_UPDATED;
      } else {
        *request->outcome = FTUN_FRS_UPDATE_DURABILITY_UNCERTAIN;
      }
      {
        ftun_status_t etag_status = ftun_frs_etag_replace(
          request->accepted_etag, download.etag);
        if (status == FTUN_OK && etag_status != FTUN_OK) status = etag_status;
      }
    }
    break;
  }
  if (candidate_runtime != NULL) {
    (void)ftun_runtime_abort(core, &candidate_runtime);
  }
  (void)ftun_frs_view_release(&candidate_view);
  if (download.data != NULL || download.http_status != 0u) {
    request->release(request->download_user, &download);
  }
  if (baseline_runtime != NULL) (void)ftun_runtime_release(&baseline_runtime);
  result.status = status;
  {
    ftun_status_t complete_status = ftun_operation_complete(operation, result);
    if (complete_status != FTUN_OK) {
      (void)ftun_operation_reject(&operation);
      return complete_status;
    }
  }
  *out = operation;
  return FTUN_OK;
}
