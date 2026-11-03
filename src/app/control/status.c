#include "app/control/status.h"
#include "app/runtime_internal.h"
#include <stdio.h>

ftun_status_t ftun_ctl_status_fill(ftun_core_t *core, ftun_ctl_status_t *out)
{
  ftun_core_control_t *control;
  uint64_t now;
  ftun_status_t status;
  memset(out, 0, sizeof(*out));
  status = ftun_core_control(core, &control);
  if (status == FTUN_OK) status = ftun_app_control_query(core, &out->host);
  if (status == FTUN_OK) status = ftun_budget_get_usage(control->root_budget, &out->resources);
  if (status == FTUN_OK) status = ftun_monotonic_now(&now);
  if (status != FTUN_OK) return status;
  ftun_mutex_lock(&control->mutex);
  out->log_sequence = ftun_log_last_sequence();
  out->uptime_ms = now - control->run_started_ms;
  out->reload_sequence = control->reload_sequence;
  out->reload_generation = control->last_reload_generation;
  out->reload_result = control->last_reload_result;
  out->reload_time = control->last_reload_time;
  out->reload_time_valid = control->last_reload_time_valid;
  ftun_mutex_unlock(&control->mutex);
  if (control->active_config != NULL) {
    const char *level = control->log_level_override == FTUN_LOG_DEBUG ? "debug" :
      control->log_level_override == FTUN_LOG_TRACE ? "trace" : control->active_config->log.level;
    (void)snprintf(out->log_level, sizeof(out->log_level), "%s", level);
    (void)snprintf(out->log_output, sizeof(out->log_output), "%s", !out->host.logger_present ? "disabled" :
      control->log_file_only ? "file" : control->active_config->log.output);
    if (out->host.logger_present && ftun_config_uses_log_file(control->active_config, control->log_file_only))
      (void)snprintf(out->log_file, sizeof(out->log_file), "%s", control->active_config->log.file);
  }
  return ftun_app_default_status_fill(core, out);
}
