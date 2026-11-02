#include "proxy/status.h"
#include "proxy/engine_internal.h"
#include "proxy/runtime_internal.h"

static ftun_status_t outbound_status(const ftun_runtime_t *runtime, uint32_t id,
  const char *name, ftun_proxy_status_t *out)
{
  ftun_outbound_stats_t stats;
  ftun_proxy_outbound_status_t *item;
  out->outbounds_total++;
  if (out->outbounds_count == FTUN_STATUS_MAX_ITEMS) return FTUN_OK;
  if (ftun_runtime_outbound_stats(runtime, id, &stats) != FTUN_OK) return FTUN_E_STATE_CORRUPT;
  item = &out->outbounds[out->outbounds_count++];
  ftun_status_label_set(&item->name, name);
  item->active = stats.active;
  item->connections = stats.connections;
  memcpy(item->failures, stats.failures, sizeof(item->failures));
  return FTUN_OK;
}

ftun_status_t ftun_proxy_status_fill(ftun_proxy_runtime_t *proxy, ftun_proxy_status_t *out)
{
  ftun_runtime_t *runtime = NULL;
  const ftun_config_t *config;
  ftun_runtime_group_record_t records[FTUN_STATUS_MAX_ITEMS];
  size_t index, waiting = 0u;
  ftun_status_t result;
  memset(out, 0, sizeof(*out));
  out->status.state = out->frs_status.state = out->fakeip_status.state = FTUN_SERVICE_DISABLED;
  out->frs_known = true;
  if (proxy == NULL) return FTUN_OK;
  out->generation = proxy->generation;
  out->status.state = proxy->cleanup_only ? FTUN_SERVICE_FAILED :
    proxy->accepting ? FTUN_SERVICE_ACTIVE : FTUN_SERVICE_NOT_READY;
  result = ftun_proxy_runtime_get_capacity_info(proxy, &out->sessions);
  if (result != FTUN_OK) return result;
  result = ftun_runtime_active_acquire(proxy->core, &runtime);
  if (result != FTUN_OK) return result;
  result = ftun_runtime_config(runtime, &config);
  if (result != FTUN_OK) goto finish;
  out->listeners_total = proxy->listener_count;
  out->listeners_count = proxy->listener_count < FTUN_STATUS_MAX_ITEMS
    ? proxy->listener_count : FTUN_STATUS_MAX_ITEMS;
  for (index = 0u; index < proxy->listener_count; ++index) {
    const ftun_proxy_runtime_listener_t *listener = &proxy->listeners[index];
    ftun_proxy_listener_status_t *item;
    ftun_recovery_info_t recovery;
    if (listener->waiting || listener->paused) waiting++;
    if (index >= out->listeners_count) continue;
    item = &out->listeners[index];
    ftun_status_label_set(&item->name, listener->name);
    item->address = listener->address;
    item->udp = listener->udp;
    item->status.state = listener->waiting || listener->paused
      ? FTUN_SERVICE_WAITING : out->status.state;
    if (listener->waiting || listener->paused) {
      result = ftun_recovery_query(proxy->recovery, listener->recovery.slot, &recovery);
      if (result != FTUN_OK) goto finish;
      item->status.reason = listener->paused ? FTUN_E_LIMIT : FTUN_E_IO;
      item->status.retry_at_ms = recovery.next_ms;
    }
  }
  if (waiting != 0u && out->status.state == FTUN_SERVICE_ACTIVE) {
    out->status.state = waiting == proxy->listener_count ? FTUN_SERVICE_WAITING : FTUN_SERVICE_DEGRADED;
    out->status.reason = FTUN_E_IO;
  }
  result = ftun_runtime_group_records(proxy->core, records, FTUN_STATUS_MAX_ITEMS, &out->groups_total);
  if (result != FTUN_OK && result != FTUN_E_LIMIT) goto finish;
  out->groups_count = out->groups_total < FTUN_STATUS_MAX_ITEMS ? out->groups_total : FTUN_STATUS_MAX_ITEMS;
  for (index = 0u; index < out->groups_count; ++index) {
    const ftun_runtime_group_record_t *record = &records[index];
    ftun_proxy_group_status_t *item = &out->groups[index];
    ftun_status_label_set_span(&item->name, record->group.data, record->group.length);
    ftun_status_label_set_span(&item->selected, record->member.data, record->member.length);
    item->degraded = record->degraded;
    item->health_valid = record->health_valid;
    item->health_success = record->health_success;
    item->latency_ms = record->latency_ms;
    item->observed_ms = record->observed_ms;
  }
  result = outbound_status(runtime, FTUN_OUTBOUND_ID_DIRECT, "DIRECT", out);
  if (result == FTUN_OK) result = outbound_status(runtime, FTUN_OUTBOUND_ID_REJECT, "REJECT", out);
  for (index = 0u; result == FTUN_OK && index < ftun_config_outbound_count(config); ++index) {
    const ftun_config_outbound_t *item = &ftun_config_outbounds(config)[index];
    if (runtime->owner_state.group_choices[index].degraded && out->status.state == FTUN_SERVICE_ACTIVE) {
      out->status.state = FTUN_SERVICE_DEGRADED;
      out->status.reason = FTUN_E_IO;
    }
    if (item->kind == FTUN_CONFIG_OUTBOUND_SOCKS5)
      result = outbound_status(runtime, (uint32_t)index + FTUN_OUTBOUND_ID_NAMED_BASE, item->name, out);
  }
  if (result != FTUN_OK) goto finish;
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  if (ftun_config_resolver(config).enable && ftun_config_resolver(config).fake_ip.enable) {
    out->fakeip_status.state = proxy->fakeip != NULL ? FTUN_SERVICE_ACTIVE : FTUN_SERVICE_NOT_READY;
    if (proxy->fakeip_store_status != FTUN_OK) {
      out->fakeip_status.state = FTUN_SERVICE_DEGRADED;
      out->fakeip_status.reason = proxy->fakeip_store_status;
    }
  }
#endif
#if defined(FTUN_HAVE_MODULE_FRS)
  if (ftun_config_frs(config)->active) {
    ftun_frs_view_t *view = NULL;
    out->frs_status.state = proxy->frs_not_ready ? FTUN_SERVICE_NOT_READY : FTUN_SERVICE_ACTIVE;
    out->frs_status.reason = proxy->frs_not_ready ? FTUN_E_AGAIN : FTUN_OK;
    out->frs_status.retry_at_ms = proxy->frs_due_ms;
    result = ftun_runtime_frs_view(runtime, &view);
    out->frs_known = result == FTUN_OK;
    if (result == FTUN_OK) {
      ftun_frs_view_info_t info;
      result = ftun_frs_view_get_info(view, &info);
      if (result != FTUN_OK) goto finish;
      out->frs_total = info.set_count;
      out->frs_count = info.set_count < FTUN_STATUS_MAX_ITEMS ? info.set_count : FTUN_STATUS_MAX_ITEMS;
      for (index = 0u; index < out->frs_count; ++index) {
        ftun_frs_set_info_t set;
        ftun_proxy_frs_status_t *item = &out->frs[index];
        result = ftun_frs_view_set_info(view, index, &set);
        if (result != FTUN_OK) goto finish;
        ftun_status_label_set_span(&item->name, set.label.data, set.label.length);
        item->status = out->frs_status;
        item->ranges = set.ranges;
        item->nodes = set.nodes;
        item->keywords = set.keywords;
        item->updated_unix_ms = info.modified_valid ? info.modified_unix_ms : proxy->frs_updated_unix_ms;
        item->updated_valid = info.modified_valid || proxy->frs_updated_valid;
      }
    } else if (result == FTUN_E_AGAIN) result = FTUN_OK;
    if (out->frs_status.state != FTUN_SERVICE_ACTIVE && out->status.state == FTUN_SERVICE_ACTIVE) {
      out->status.state = FTUN_SERVICE_DEGRADED;
      out->status.reason = FTUN_E_AGAIN;
    }
  }
#endif
finish:
  if (ftun_runtime_release(&runtime) != FTUN_OK) return FTUN_E_STATE_CORRUPT;
  return result;
}
