#define _GNU_SOURCE 1

#include "proxy/engine_internal.h"

void ftun_proxy_runtime_deadline_consider(uint64_t candidate,
                                           uint64_t *deadline,
                                           bool *present)
{
  if (!*present || candidate < *deadline) {
    *deadline = candidate;
    *present = true;
  }
}

ftun_status_t ftun_proxy_runtime_next_deadline(ftun_proxy_runtime_t *engine,
                                                uint64_t *out_deadline,
                                                bool *out_present)
{
  uint64_t deadline = 0u;
  bool present = false;
  ftun_status_t status;
  if (out_deadline != NULL) *out_deadline = 0u;
  if (out_present != NULL) *out_present = false;
  if (engine == NULL || out_deadline == NULL || out_present == NULL) {
    return FTUN_E_INVALID;
  }
#if defined(FTUN_HAVE_MODULE_TUN)
  if (engine->tun_resetting) {
    if (engine->tun_reset_due_ms != UINT64_MAX) {
      ftun_proxy_runtime_deadline_consider(engine->tun_reset_due_ms, &deadline, &present);
    }
  } else if (engine->has_tun) {
    uint64_t candidate = 0u;
    status = ftun_tun_ingress_next_deadline(engine->tun_ingress, &candidate);
    if (status != FTUN_OK) return status;
    ftun_proxy_runtime_deadline_consider(candidate, &deadline, &present);
  }
#endif
  if (engine->udp_flows != NULL) {
    uint64_t candidate = 0u;
    bool candidate_present = false;
    status = ftun_udp_flow_next_deadline(engine->udp_flows, &candidate,
                                         &candidate_present);
    if (status != FTUN_OK) return status;
    if (candidate_present) {
      ftun_proxy_runtime_deadline_consider(candidate, &deadline, &present);
    }
  }
#if defined(FTUN_HAVE_MODULE_FRS)
  if (engine->frs_enabled && engine->frs_operation == NULL) {
    ftun_proxy_runtime_deadline_consider(engine->frs_due_ms, &deadline, &present);
  }
#endif
  if (engine->quarantined_flows != 0u) {
    ftun_proxy_runtime_deadline_consider(engine->quarantine_due_ms, &deadline, &present);
  }
  if (ftun_proxy_runtime_idle_possible(engine) &&
      (engine->active_tcp_flows != 0u || engine->tun_flow_count != 0u)) {
    ftun_proxy_runtime_deadline_consider(engine->idle_next_ms, &deadline, &present);
  }
  if (engine->recovery != NULL) {
    uint64_t candidate = 0u;
    bool candidate_present = false;
    status = ftun_recovery_next_deadline(engine->recovery, &candidate,
                                         &candidate_present);
    if (status != FTUN_OK) return status;
    if (candidate_present) {
      ftun_proxy_runtime_deadline_consider(candidate, &deadline, &present);
    }
  }
  ftun_proxy_runtime_health_deadline_refresh(engine);
  if (engine->health_deadline_present) {
    ftun_proxy_runtime_deadline_consider(engine->health_deadline_ms, &deadline,
                                  &present);
  }
  *out_deadline = deadline;
  *out_present = present;
  return FTUN_OK;
}

void ftun_proxy_runtime_deadline_ready(ftun_event_source_t *source,
                                       uint32_t events, void *user)
{
  ftun_proxy_runtime_t *engine = (ftun_proxy_runtime_t *)user;
  if (engine != NULL && engine->deadline_source == source &&
      (events & FTUN_EVENT_TIMER) != 0u) engine->deadline_ready = true;
}

ftun_status_t ftun_proxy_runtime_deadline_schedule(ftun_proxy_runtime_t *engine)
{
  uint64_t deadline = 0u;
  bool present = false;
  ftun_status_t status = ftun_proxy_runtime_next_deadline(engine, &deadline,
                                                   &present);
  if (status != FTUN_OK) return status;
  if (engine->deadline_source != NULL && !engine->deadline_ready && present &&
      engine->deadline_ms == deadline) return FTUN_OK;
  status = ftun_event_source_cancel(&engine->deadline_source);
  if (status != FTUN_OK) return status;
  engine->deadline_ms = 0u;
  engine->deadline_ready = false;
  if (!present) return FTUN_OK;
  status = ftun_event_timer_start(engine->loop, deadline,
    ftun_proxy_runtime_deadline_ready, engine, &engine->deadline_source);
  if (status == FTUN_OK) engine->deadline_ms = deadline;
  return status;
}

ftun_status_t ftun_proxy_runtime_deadline_run(
  ftun_proxy_runtime_t *engine, uint64_t now_ms, size_t *out_work,
  uint64_t *out_lateness, bool *out_quota_exhausted)
{
  size_t work = 0u;
  size_t health_work = 0u;
  ftun_status_t status;
  if (out_work != NULL) *out_work = 0u;
  if (out_lateness != NULL) *out_lateness = 0u;
  if (out_quota_exhausted != NULL) *out_quota_exhausted = false;
  if (engine == NULL || out_work == NULL || out_lateness == NULL ||
      out_quota_exhausted == NULL) return FTUN_E_INVALID;
  if (!engine->deadline_ready && (engine->deadline_source == NULL ||
      now_ms < engine->deadline_ms)) return FTUN_OK;
  if (engine->deadline_ms != 0u && now_ms > engine->deadline_ms) {
    *out_lateness = now_ms - engine->deadline_ms;
  }
  status = ftun_event_source_cancel(&engine->deadline_source);
  if (status != FTUN_OK) return status;
  engine->deadline_ready = false;
  engine->deadline_ms = 0u;
  engine->now_ms = now_ms;
#if defined(FTUN_HAVE_MODULE_TUN)
  if (engine->has_tun && !engine->tun_resetting) {
    uint64_t deadline = 0u;
    status = ftun_tun_ingress_next_deadline(engine->tun_ingress, &deadline);
    if (status == FTUN_OK && deadline <= now_ms) {
      status = ftun_tun_ingress_tick(engine->tun_ingress, now_ms);
      work++;
    }
    if (status != FTUN_OK) return status;
  }
#endif
  if (engine->udp_flows != NULL) {
    uint64_t deadline = 0u;
    bool present = false;
    status = ftun_udp_flow_next_deadline(engine->udp_flows, &deadline,
                                         &present);
    if (status == FTUN_OK && present && deadline <= now_ms) {
      status = ftun_udp_flow_tick(engine->udp_flows, now_ms);
      work++;
    }
    if (status != FTUN_OK) return status;
  }
#if defined(FTUN_HAVE_MODULE_FRS)
  if (engine->frs_enabled && engine->frs_operation == NULL &&
      now_ms >= engine->frs_due_ms) {
    status = ftun_proxy_runtime_frs_schedule(engine);
    work++;
    if (status != FTUN_OK) {
      if (engine->frs_interval_ms <= UINT64_MAX - now_ms) {
        engine->frs_due_ms = now_ms + engine->frs_interval_ms;
      } else {
        engine->frs_due_ms = UINT64_MAX;
      }
      ftun_proxy_runtime_background_log(engine, status,
                                 FTUN_DIAGNOSTIC_FRS_SCHEDULE, "FRS update could not be scheduled");
      status = FTUN_OK;
    }
  }
#endif
  status = ftun_proxy_runtime_health_run(engine, FTUN_PROXY_RUNTIME_HEALTH_QUOTA,
                                  &health_work);
  if (status != FTUN_OK) return status;
  work += health_work;
  if (health_work == FTUN_PROXY_RUNTIME_HEALTH_QUOTA) {
    *out_quota_exhausted = true;
  }
  *out_work = work;
  return FTUN_OK;
}

