#define _POSIX_C_SOURCE 200809L

#include "frs_fixture.h"

#include "config/compile.h"
#include "config/model.h"
#include "config/parser.h"
#include "core/budget.h"
#include "core/operation.h"
#include "core/runtime.h"
#include "frs/format.h"
#include "frs/update.h"
#include "route/router.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x) do { \
  if (!(x)) { fprintf(stderr, "frs update failed: %s\n", #x); return 1; } \
} while (0)

typedef struct {
  const uint8_t *data;
  size_t length;
  unsigned int status;
  unsigned int first_status;
  int require_conditional;
  size_t calls;
  size_t releases;
} download_context_t;

typedef struct {
  size_t calls;
  ftun_status_t status;
} completion_t;

typedef struct {
  ftun_file_stage_t fail_at;
  size_t calls;
} publish_context_t;

static ftun_string_t text(const char *value)
{
  return (ftun_string_t){value, strlen(value)};
}

static void completed(ftun_operation_t *operation, ftun_error_t error,
                      void *user)
{
  completion_t *completion = (completion_t *)user;
  (void)operation;
  completion->calls++;
  completion->status = error.status;
}

static ftun_status_t download(void *user,
                              const ftun_frs_download_request_t *request,
                              ftun_frs_download_t *out)
{
  download_context_t *context = (download_context_t *)user;
  unsigned int status;
  memset(out, 0, sizeof(*out));
  context->calls++;
  if (context->require_conditional &&
      (!request->conditional || request->if_none_match.length == 0u)) {
    return FTUN_E_REJECTED;
  }
  status = context->first_status != 0u && context->calls == 1u ?
    context->first_status : context->status;
  out->http_status = status;
  out->finished_ms = request->deadline_ms - 1u;
  out->outbound_id = request->outbound_id;
  out->dns_server_id = request->dns_server_id;
  out->tls_verified = true;
  out->etag = text("\"fixture-v2\"");
  if (status == 200u) {
    out->data = (uint8_t *)malloc(context->length);
    if (out->data == NULL) return FTUN_E_LIMIT;
    memcpy(out->data, context->data, context->length);
    out->length = context->length;
  }
  return FTUN_OK;
}

static ftun_status_t fail_publish(ftun_file_stage_t stage, void *user)
{
  publish_context_t *context = (publish_context_t *)user;
  context->calls++;
  return stage == context->fail_at ? FTUN_E_IO : FTUN_OK;
}

static void release_download(void *user, ftun_frs_download_t *downloaded)
{
  download_context_t *context = (download_context_t *)user;
  context->releases++;
  free(downloaded->data);
  memset(downloaded, 0, sizeof(*downloaded));
}

static ftun_config_t *make_config(const char *path)
{
  char json[1024];
  ftun_bytes_t bytes;
  ftun_config_t *config = NULL;
  ftun_feature_plan_t *plan = NULL;
  int length = snprintf(json, sizeof(json),
    "{\"dns\":{\"enable\":false},\"frs\":{\"path\":\"%s\"},"
    "\"rules\":[\"frs-ip,CN,REJECT\",\"MATCH,DIRECT\"]}", path);
  if (length <= 0 || (size_t)length >= sizeof(json)) return NULL;
  bytes.data = (const uint8_t *)json;
  bytes.length = (size_t)length;
  if (ftun_config_parse(bytes, &config) != FTUN_OK ||
      ftun_config_compile(config, &plan) != FTUN_OK) {
    (void)ftun_config_destroy(&config);
    return NULL;
  }
  config->plan = plan;
  return config;
}

static int route_address(ftun_core_t *core, uint8_t first,
                         uint32_t expected_outbound)
{
  ftun_runtime_t *runtime = NULL;
  ftun_runtime_info_t info;
  ftun_metadata_t metadata;
  ftun_route_result_t result;
  if (ftun_runtime_active_acquire(core, &runtime) != FTUN_OK) return 0;
  if (ftun_runtime_get_info(runtime, &info) != FTUN_OK) return 0;
  memset(&metadata, 0, sizeof(metadata));
  metadata.generation = info.generation;
  metadata.original_target.kind = FTUN_ADDRESS_IPV4;
  metadata.original_target.address[0] = first;
  metadata.original_target.address[1] = 1u;
  metadata.original_target.address[2] = 2u;
  metadata.original_target.address[3] = 3u;
  if (ftun_route_evaluate(runtime, &metadata, 0u, &result) != FTUN_OK ||
      result.outbound_id != expected_outbound ||
      ftun_runtime_release(&runtime) != FTUN_OK) return 0;
  return 1;
}

static int run_update_with_hook(ftun_core_t *core,
                      ftun_operation_queue_t *operations,
                      ftun_config_t *config, const char *path,
                      download_context_t *download_context,
                      char **etag, ftun_frs_update_outcome_t *outcome,
                      completion_t *completion,
                      ftun_file_stage_hook_fn publish_hook,
                      void *publish_hook_user)
{
  ftun_frs_update_request_t request;
  ftun_operation_t *operation = NULL;
  size_t dispatched = 0u;
  memset(&request, 0, sizeof(request));
  request.url = text("http://updates.example/rules.frs");
  request.destination = path;
  request.config = config;
  request.maximum_bytes = 1024u * 1024u;
  request.now_ms = 100u;
  request.deadline_ms = 200u;
  request.outbound_id = 0u;
  request.dns_server_id = 0u;
  request.etag = *etag;
  request.accepted_etag = etag;
  request.outcome = outcome;
  request.operations = operations;
  request.completion = completed;
  request.completion_user = completion;
  request.download = download;
  request.release = release_download;
  request.download_user = download_context;
  request.publish_hook = publish_hook;
  request.publish_hook_user = publish_hook_user;
  if (ftun_frs_update(core, &request, &operation) != FTUN_OK ||
      operation == NULL ||
      ftun_operation_dispatch(operations, 1u, &dispatched) != FTUN_OK ||
      dispatched != 1u) return 0;
  return 1;
}

static int run_update(ftun_core_t *core, ftun_operation_queue_t *operations,
                      ftun_config_t *config, const char *path,
                      download_context_t *download_context,
                      char **etag, ftun_frs_update_outcome_t *outcome,
                      completion_t *completion)
{
  return run_update_with_hook(core, operations, config, path,
                              download_context, etag, outcome, completion,
                              NULL, NULL);
}

int main(void)
{
  char directory[] = "/tmp/ftun-frs-update-XXXXXX";
  char path[256];
  uint8_t *old_file = NULL;
  uint8_t *new_file = NULL;
  size_t file_bytes = 0u;
  ftun_config_t *config = NULL;
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_runtime_t *runtime = NULL;
  ftun_operation_queue_t *operations = NULL;
  download_context_t context;
  completion_t completion;
  publish_context_t publish;
  ftun_frs_update_outcome_t outcome;
  char *etag = NULL;
  CHECK(mkdtemp(directory) != NULL);
  CHECK(snprintf(path, sizeof(path), "%s/rules.frs", directory) > 0);
  CHECK(ftun_test_frs_fixture(&old_file, &file_bytes));
  CHECK(ftun_test_write_file(path, old_file, file_bytes));
  config = make_config(path);
  CHECK(config != NULL);
  CHECK(ftun_budget_create(NULL, 4u * 1024u * 1024u, 4096u, &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 2u, &core) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 4u, &operations) == FTUN_OK);
  CHECK(ftun_runtime_prepare(core, config, &runtime) == FTUN_OK);
  CHECK(ftun_runtime_commit(core, &runtime) == FTUN_OK && runtime == NULL);
  CHECK(route_address(core, 10u, FTUN_OUTBOUND_ID_REJECT));
  CHECK(route_address(core, 11u, FTUN_OUTBOUND_ID_DIRECT));

  memset(&context, 0, sizeof(context));
  memset(&completion, 0, sizeof(completion));
  context.data = old_file;
  context.length = file_bytes;
  context.status = 200u;
  CHECK(run_update(core, operations, config, path, &context, &etag,
                   &outcome, &completion));
  CHECK(outcome == FTUN_FRS_UPDATE_UNCHANGED && completion.calls == 1u &&
        completion.status == FTUN_OK && etag != NULL && context.releases == 1u);

  context.status = 304u;
  context.require_conditional = 1;
  CHECK(run_update(core, operations, config, path, &context, &etag,
                   &outcome, &completion));
  CHECK(outcome == FTUN_FRS_UPDATE_UNCHANGED && completion.calls == 2u &&
        completion.status == FTUN_OK && context.releases == 2u);

  new_file = (uint8_t *)malloc(file_bytes);
  CHECK(new_file != NULL);
  memcpy(new_file, old_file, file_bytes);
  ftun_frs_write_u32(new_file + 680u, UINT32_C(0x0b000000));
  ftun_frs_write_u32(new_file + 684u, UINT32_C(0x0bffffff));
  ftun_frs_write_u64(new_file + 48u,
    ftun_frs_file_checksum((ftun_bytes_t){new_file, file_bytes}));
  context.data = new_file;
  context.status = 200u;
  context.require_conditional = 0;
  CHECK(run_update(core, operations, config, path, &context, &etag,
                   &outcome, &completion));
  CHECK(outcome == FTUN_FRS_UPDATE_UPDATED && completion.calls == 3u &&
        completion.status == FTUN_OK && context.releases == 3u);
  CHECK(route_address(core, 10u, FTUN_OUTBOUND_ID_DIRECT));
  CHECK(route_address(core, 11u, FTUN_OUTBOUND_ID_REJECT));

  new_file[48] ^= 1u;
  CHECK(run_update(core, operations, config, path, &context, &etag,
                   &outcome, &completion));
  CHECK(outcome == FTUN_FRS_UPDATE_NONE && completion.calls == 4u &&
        completion.status == FTUN_E_PROTOCOL && context.releases == 4u);
  CHECK(route_address(core, 11u, FTUN_OUTBOUND_ID_REJECT));

  context.data = old_file;
  context.status = 200u;
  memset(&publish, 0, sizeof(publish));
  publish.fail_at = FTUN_FILE_STAGE_TEMP_SYNCED;
  CHECK(run_update_with_hook(core, operations, config, path, &context, &etag,
                             &outcome, &completion, fail_publish, &publish));
  CHECK(outcome == FTUN_FRS_UPDATE_NONE && completion.calls == 5u &&
        completion.status == FTUN_E_IO && publish.calls == 1u &&
        context.releases == 5u);
  CHECK(route_address(core, 11u, FTUN_OUTBOUND_ID_REJECT));

  memset(&publish, 0, sizeof(publish));
  publish.fail_at = FTUN_FILE_STAGE_RENAMED;
  CHECK(run_update_with_hook(core, operations, config, path, &context, &etag,
                             &outcome, &completion, fail_publish, &publish));
  CHECK(outcome == FTUN_FRS_UPDATE_DURABILITY_UNCERTAIN &&
        completion.calls == 6u && completion.status == FTUN_E_IO &&
        publish.calls == 2u && context.releases == 6u);
  CHECK(route_address(core, 10u, FTUN_OUTBOUND_ID_REJECT));

  free(etag);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);

  CHECK(unlink(path) == 0);
  CHECK(snprintf(path, sizeof(path), "%s/startup.frs", directory) > 0);
  config = make_config(path);
  CHECK(config != NULL);
  CHECK(ftun_runtime_manager_create(budget, 2u, &core) == FTUN_OK);
  CHECK(ftun_runtime_prepare(core, config, &runtime) == FTUN_E_EOF &&
        runtime == NULL);
  memset(&context, 0, sizeof(context));
  memset(&completion, 0, sizeof(completion));
  context.data = old_file;
  context.length = file_bytes;
  context.first_status = 304u;
  context.status = 200u;
  etag = NULL;
  CHECK(run_update(core, operations, config, path, &context, &etag,
                   &outcome, &completion));
  CHECK(outcome == FTUN_FRS_UPDATE_UPDATED && completion.calls == 1u &&
        completion.status == FTUN_OK && context.calls == 2u &&
        context.releases == 2u);
  CHECK(route_address(core, 10u, FTUN_OUTBOUND_ID_REJECT));
  free(etag);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  free(new_file);
  free(old_file);
  CHECK(unlink(path) == 0 && rmdir(directory) == 0);
  return 0;
}
