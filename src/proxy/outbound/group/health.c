#include "proxy/outbound/group/health.h"

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
