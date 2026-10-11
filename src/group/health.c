/* TASK-GROUP-003 / TEST-GROUP-003：ftun_health_probe，目标 0.4.0。 */
#include "health.h"
#include "core/operation.h"
#include <string.h>

static int ftun_probe_https(ftun_string_t url)
{
  static const char prefix[] = "https://";
  return url.length >= sizeof(prefix) - 1u &&
         memcmp(url.data, prefix, sizeof(prefix) - 1u) == 0;
}

static int ftun_probe_http(ftun_string_t url)
{
  static const char prefix[] = "http://";
  return url.length >= sizeof(prefix) - 1u &&
         memcmp(url.data, prefix, sizeof(prefix) - 1u) == 0;
}

ftun_status_t ftun_health_probe(ftun_core_t *core, const ftun_probe_request_t *request, ftun_operation_t **out)
{
  ftun_probe_result_t result;
  ftun_error_t completion;
  ftun_operation_t *operation = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core == NULL || request == NULL || out == NULL ||
      request->generation == 0u ||
      request->url.data == NULL || request->url.length == 0u ||
      request->url.length > 2048u ||
      (!ftun_probe_http(request->url) && !ftun_probe_https(request->url)) ||
      request->expected_status < 100u || request->expected_status > 599u ||
      request->deadline_ms <= request->now_ms ||
      request->operations == NULL || request->completion == NULL ||
      request->perform == NULL || request->sample == NULL) {
    return FTUN_E_INVALID;
  }
  memset(request->sample, 0, sizeof(*request->sample));
  status = ftun_operation_accept(request->operations, request->completion,
                                 request->completion_user, &operation);
  if (status != FTUN_OK) return status;
  memset(&result, 0, sizeof(result));
  memset(&completion, 0, sizeof(completion));
  status = request->perform(request->perform_user, request->url,
                            request->member_id, request->deadline_ms, &result);
  if (status == FTUN_OK &&
      (result.path_member_id != request->member_id ||
       result.finished_ms < request->now_ms ||
       result.finished_ms > request->deadline_ms)) {
    status = result.finished_ms > request->deadline_ms
      ? FTUN_E_TIMEOUT : FTUN_E_STATE_CORRUPT;
  }
  if (status == FTUN_OK && ftun_probe_https(request->url) &&
      !result.tls_verified) status = FTUN_E_REJECTED;
  request->sample->member_id = request->member_id;
  request->sample->latency_ms = result.latency_ms;
  request->sample->observed_ms = result.finished_ms;
  request->sample->tcp_only = true;
  request->sample->success = status == FTUN_OK &&
    result.http_status == request->expected_status;
  if (status == FTUN_OK && !request->sample->success) status = FTUN_E_REJECTED;
  completion.status = status;
  status = ftun_operation_complete(operation, completion);
  if (status != FTUN_OK) {
    (void)ftun_operation_reject(&operation);
    return status;
  }
  *out = operation;
  return FTUN_OK;
}

ftun_status_t ftun_health_schedule(ftun_health_schedule_t *state,
                                   uint64_t now_ms,
                                   uint64_t interval_ms,
                                   uint64_t maximum_backoff_ms,
                                   uint32_t jitter_seed,
                                   bool success)
{
  uint64_t delay;
  uint64_t jitter;
  uint32_t shifts;
  if (state == NULL || interval_ms == 0u ||
      maximum_backoff_ms < interval_ms) return FTUN_E_INVALID;
  if (state->consumers == 0u) {
    state->next_due_ms = 0u;
    state->failures = 0u;
    return FTUN_OK;
  }
  if (success) state->failures = 0u;
  else if (state->failures != UINT32_MAX) state->failures++;
  delay = interval_ms;
  shifts = state->failures > 16u ? 16u : state->failures;
  while (shifts-- != 0u && delay < maximum_backoff_ms) {
    delay = delay > maximum_backoff_ms / 2u
      ? maximum_backoff_ms : delay * 2u;
  }
  jitter = interval_ms / 10u;
  if (jitter != 0u) jitter = (uint64_t)jitter_seed % (jitter + 1u);
  if (delay > UINT64_MAX - jitter || now_ms > UINT64_MAX - delay - jitter) {
    return FTUN_E_LIMIT;
  }
  state->next_due_ms = now_ms + delay + jitter;
  return FTUN_OK;
}
