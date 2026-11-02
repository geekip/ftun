#include "app/control/status.h"
#include "app/control/request.h"
#include "ftun/version.h"
#include "util/endpoint.h"
#include "cJSON.h"
#include <stdarg.h>
#include <stdio.h>

typedef struct { char *data; size_t used, capacity; bool ok; } writer_t;

#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 2, 3)))
#endif
static void append(writer_t *writer, const char *format, ...)
{
  int count;
  va_list args;
  if (!writer->ok) return;
  va_start(args, format);
  count = vsnprintf(writer->data + writer->used, writer->capacity - writer->used, format, args);
  va_end(args);
  if (count < 0 || (size_t)count >= writer->capacity - writer->used) writer->ok = false;
  else writer->used += (size_t)count;
}

static void quote(writer_t *writer, const char *text)
{
  cJSON value = {0};
  if (!writer->ok) return;
  value.type = cJSON_String;
  value.valuestring = (char *)text;
  if (!cJSON_PrintPreallocated(&value, writer->data + writer->used,
      (int)(writer->capacity - writer->used), false)) writer->ok = false;
  else writer->used += strlen(writer->data + writer->used);
}

#if defined(FTUN_HAVE_MODULE_DNS) || defined(FTUN_HAVE_MODULE_PROXY)
static void label(writer_t *writer, const char *key, const ftun_status_label_t *value)
{
  append(writer, "\"%s\":", key);
  quote(writer, value->text);
  append(writer, ",\"%s_truncated\":%s", key, value->truncated ? "true" : "false");
}

#endif

static void state(writer_t *writer, ftun_service_status_t status)
{
  append(writer, "\"state\":\"%s\",\"reason\":\"%s\",\"retry_at_ms\":%llu",
    ftun_service_state_name(status.state), ftun_status_name(status.reason),
    (unsigned long long)status.retry_at_ms);
}

#if defined(FTUN_HAVE_MODULE_DNS) || defined(FTUN_HAVE_MODULE_PROXY)
static void endpoint(writer_t *writer, const ftun_endpoint_t *address)
{
  ftun_ip_t ip = ftun_endpoint_ip(address);
  char host[FTUN_IP_TEXT_BYTES], text[64];
  if (ftun_ip_format(&ip, host, sizeof(host)) == 0u) { writer->ok = false; return; }
  (void)snprintf(text, sizeof(text), address->kind == FTUN_ADDRESS_IPV6 ? "[%s]:%u" : "%s:%u", host, address->port);
  quote(writer, text);
}

static void failures(writer_t *writer, const uint64_t *counts)
{
  size_t index, printed = 0u;
  append(writer, "{");
  for (index = 1u; index <= FTUN_E_STATE_CORRUPT; ++index) {
    if (counts[index] == 0u) continue;
    append(writer, "%s\"%s\":%llu", printed++ == 0u ? "" : ",",
      ftun_status_name((ftun_status_t)index), (unsigned long long)counts[index]);
  }
  append(writer, "}");
}

/* 每个列表共享余下字节额度；一项放不下时回到项前，完整关闭JSON并注明截断。
 * 只改变输出明细数量，不改变快照中的总数或服务状态。 */
typedef void (*item_fn)(writer_t *, const void *);
static void items(writer_t *writer, const char *key, const void *data, size_t stride,
  size_t count, size_t total, bool known, size_t lists_left, item_fn item)
{
  size_t full_capacity = writer->capacity, printed = 0u;
  size_t bytes = writer->capacity - writer->used;
  append(writer, ",\"%s\":{\"total\":", key);
  if (known) append(writer, "%zu", total); else append(writer, "null");
  append(writer, ",\"items\":[");
  if (!writer->ok) return;
  /* 后续固定字段、列表尾部及空列表合计小于4KiB。 */
  if (bytes > 4096u) {
    size_t end = writer->used + (bytes - 4096u) / lists_left;
    writer->capacity = end < full_capacity ? end : full_capacity;
    while (printed < count) {
      size_t before = writer->used;
      if (printed != 0u) append(writer, ",");
      item(writer, (const uint8_t *)data + printed * stride);
      if (!writer->ok) {
        writer->used = before;
        writer->ok = true;
        break;
      }
      printed++;
    }
    writer->capacity = full_capacity;
  }
  append(writer, "],\"count\":%zu,\"truncated\":%s}", printed, known && printed < total ? "true" : "false");
}

#endif

#if defined(FTUN_HAVE_MODULE_DNS)
static void dns_listener(writer_t *writer, const void *value)
{
  const ftun_dns_listener_status_t *item = value;
  append(writer, "{\"address\":"); endpoint(writer, &item->address);
  append(writer, ","); label(writer, "server", &item->server);
  append(writer, ","); state(writer, item->status); append(writer, "}");
}
static void dns_upstream(writer_t *writer, const void *value)
{
  const ftun_dns_upstream_status_t *item = value;
  append(writer, "{"); label(writer, "server", &item->server);
  append(writer, ","); label(writer, "group", &item->group);
  append(writer, ",\"address\":"); endpoint(writer, &item->address);
  append(writer, ","); state(writer, item->status);
  append(writer, ",\"success\":%llu,\"failures\":%llu,\"last_failure\":\"%s\",\"latency_ms\":",
    (unsigned long long)item->success, (unsigned long long)item->failures, ftun_status_name(item->last_failure));
  if (item->latency_valid) append(writer, "%llu", (unsigned long long)item->latency_ms);
  else append(writer, "null");
  append(writer, "}");
}
static void dns(writer_t *writer, const ftun_dns_status_t *snapshot)
{
  append(writer, ","); state(writer, snapshot->status);
  append(writer, ",\"stats_generation\":%llu,\"queries\":{\"total\":%llu,\"success\":%llu,\"failures\":",
    (unsigned long long)snapshot->generation, (unsigned long long)snapshot->queries.queries,
    (unsigned long long)snapshot->queries.success);
  failures(writer, snapshot->queries.failures);
  append(writer, "},\"cache\":{\"entries\":%zu,\"capacity\":%zu,\"hits\":%llu,\"misses\":%llu,\"hit_rate\":",
    snapshot->cache.entries, snapshot->cache.capacity, (unsigned long long)snapshot->cache.hits,
    (unsigned long long)snapshot->cache.misses);
  if (snapshot->cache.hits + snapshot->cache.misses == 0u) append(writer, "null");
  else append(writer, "%.6f", (double)snapshot->cache.hits / (double)(snapshot->cache.hits + snapshot->cache.misses));
  append(writer, "}");
  items(writer, "listeners", snapshot->listeners, sizeof(snapshot->listeners[0]),
    snapshot->listeners_count, snapshot->listeners_total, true, 2u, dns_listener);
  items(writer, "upstreams", snapshot->upstreams, sizeof(snapshot->upstreams[0]),
    snapshot->upstreams_count, snapshot->upstreams_total, true, 1u, dns_upstream);
}
#endif

#if defined(FTUN_HAVE_MODULE_PROXY)
static void proxy_listener(writer_t *writer, const void *value)
{
  const ftun_proxy_listener_status_t *item = value;
  append(writer, "{"); label(writer, "name", &item->name);
  append(writer, ",\"address\":"); endpoint(writer, &item->address);
  append(writer, ",\"udp\":%s,", item->udp ? "true" : "false");
  state(writer, item->status); append(writer, "}");
}
static void proxy_group(writer_t *writer, const void *value)
{
  const ftun_proxy_group_status_t *item = value;
  append(writer, "{"); label(writer, "name", &item->name);
  append(writer, ","); label(writer, "selected", &item->selected);
  append(writer, ",\"degraded\":%s,\"health\":", item->degraded ? "true" : "false");
  if (!item->health_valid) append(writer, "null");
  else append(writer, "{\"success\":%s,\"latency_ms\":%u,\"observed_ms\":%llu}",
    item->health_success ? "true" : "false", item->latency_ms, (unsigned long long)item->observed_ms);
  append(writer, "}");
}
static void proxy_outbound(writer_t *writer, const void *value)
{
  const ftun_proxy_outbound_status_t *item = value;
  append(writer, "{"); label(writer, "name", &item->name);
  append(writer, ",\"tcp_active\":%llu,\"tcp_connections\":%llu,\"tcp_failures\":",
    (unsigned long long)item->active, (unsigned long long)item->connections);
  failures(writer, item->failures); append(writer, "}");
}
static void proxy_frs(writer_t *writer, const void *value)
{
  const ftun_proxy_frs_status_t *item = value;
  append(writer, "{"); label(writer, "name", &item->name);
  append(writer, ","); state(writer, item->status);
  append(writer, ",\"ranges\":%zu,\"nodes\":%zu,\"keywords\":%zu,\"updated_unix_ms\":", item->ranges, item->nodes, item->keywords);
  if (item->updated_valid) append(writer, "%lld", (long long)item->updated_unix_ms);
  else append(writer, "null");
  append(writer, "}");
}
static void proxy(writer_t *writer, const ftun_proxy_status_t *snapshot)
{
  append(writer, ","); state(writer, snapshot->status);
  append(writer, ",\"stats_generation\":%llu,\"sessions\":{\"tcp\":%zu,\"udp\":%zu,\"associations\":%zu},\"frs_state\":{",
    (unsigned long long)snapshot->generation, snapshot->sessions.tcp_active,
    snapshot->sessions.udp_flow_active, snapshot->sessions.udp_association_active);
  state(writer, snapshot->frs_status); append(writer, "}");
  items(writer, "listeners", snapshot->listeners, sizeof(snapshot->listeners[0]),
    snapshot->listeners_count, snapshot->listeners_total, true, 4u, proxy_listener);
  items(writer, "groups", snapshot->groups, sizeof(snapshot->groups[0]),
    snapshot->groups_count, snapshot->groups_total, true, 3u, proxy_group);
  items(writer, "outbounds", snapshot->outbounds, sizeof(snapshot->outbounds[0]),
    snapshot->outbounds_count, snapshot->outbounds_total, true, 2u, proxy_outbound);
  items(writer, "frs", snapshot->frs, sizeof(snapshot->frs[0]),
    snapshot->frs_count, snapshot->frs_total, snapshot->frs_known, 1u, proxy_frs);
}
#endif

static void root(writer_t *writer, const ftun_ctl_status_t *snapshot)
{
  static const char *const states[] = {"unknown", "created", "starting", "running", "stopping", "stopped"};
  const ftun_log_totals_t *logs = &snapshot->host.log_totals;
  size_t index;
  append(writer, ",\"version\":"); quote(writer, ftun_version());
  append(writer, ",\"state\":\"%s\",\"uptime_ms\":%llu,\"reload_pending\":%s,\"queued_commands\":%zu,\"config\":",
    states[snapshot->host.core.state], (unsigned long long)snapshot->uptime_ms,
    snapshot->host.reload_pending ? "true" : "false", snapshot->host.queued_commands);
  quote(writer, snapshot->host.config_path);
  append(writer, ",\"last_reload\":");
  if (snapshot->reload_sequence == 0u) append(writer, "null");
  else {
    const ftun_calendar_time_t *time = &snapshot->reload_time;
    append(writer, "{\"sequence\":%llu,\"generation\":%llu,\"result\":\"%s\",\"status\":\"%s\",\"at\":",
      (unsigned long long)snapshot->reload_sequence, (unsigned long long)snapshot->reload_generation,
      snapshot->reload_result == FTUN_OK ? "committed" : snapshot->reload_result == FTUN_E_RESTART_REQUIRED ? "restart-required" : "rejected",
      ftun_status_name(snapshot->reload_result));
    if (snapshot->reload_time_valid) append(writer, "\"%04d-%02d-%02dT%02d:%02d:%02d.%03uZ\"", time->year, time->month,
      time->day, time->hour, time->minute, time->second, time->millisecond);
    else append(writer, "null");
    append(writer, "}");
  }
  append(writer, ",\"services\":[");
  for (index = 0u; index < snapshot->service_count; ++index) {
    append(writer, "%s{\"name\":\"%s\",", index == 0u ? "" : ",", snapshot->services[index].name);
    state(writer, snapshot->services[index].status); append(writer, "}");
  }
  append(writer, "],\"resources\":{\"scope\":\"admitted\",\"memory\":{\"used\":%zu,\"limit\":%zu},"
    "\"descriptors\":{\"used\":%zu,\"limit\":%zu},\"queues\":{\"used\":%zu,\"limit\":%zu},\"rejections\":%zu}",
    snapshot->resources.used_resources.memory_bytes, snapshot->resources.limits.memory_bytes,
    snapshot->resources.used_resources.descriptors, snapshot->resources.limits.descriptors,
    snapshot->resources.used_resources.queue_slots, snapshot->resources.limits.queue_slots,
    snapshot->resources.rejected_reservations);
  append(writer, ",\"logs\":{\"level\":\"%s\",\"output\":\"%s\",\"file\":", snapshot->log_level, snapshot->log_output);
  quote(writer, snapshot->log_file);
  append(writer, ",\"sequence\":%llu,\"rotations\":%llu,\"reopens\":%llu,\"rotate_errors\":%llu",
    (unsigned long long)snapshot->log_sequence, (unsigned long long)logs->rotations,
    (unsigned long long)logs->reopens, (unsigned long long)logs->rotate_errors);
  append(writer, ",\"accepted\":%llu,\"written\":%llu,\"dropped\":%llu,\"write_failed\":%llu,\"queued\":%zu,\"capacity\":%zu",
    (unsigned long long)logs->emitted, (unsigned long long)logs->written,
    (unsigned long long)logs->dropped, (unsigned long long)logs->io_errors, logs->queued, logs->capacity);
  const ftun_log_aggregate_usage_t *aggregation = &snapshot->host.aggregation;
  append(writer, ",\"aggregation\":{\"failures\":%llu,\"suppressed\":%llu,\"overflowed\":%llu,"
    "\"filtered\":%llu,\"first\":%llu,\"summaries\":%llu,\"recovered\":%llu,\"errors\":%llu,\"active\":%zu}}",
    (unsigned long long)aggregation->failures, (unsigned long long)aggregation->suppressed,
    (unsigned long long)aggregation->overflowed, (unsigned long long)aggregation->filtered,
    (unsigned long long)aggregation->first, (unsigned long long)aggregation->summaries,
    (unsigned long long)aggregation->recovered, (unsigned long long)aggregation->errors, aggregation->active);
#if defined(FTUN_HAVE_MODULE_PROXY)
  append(writer, ",\"sessions\":{\"tcp\":%zu,\"udp\":%zu,\"associations\":%zu}", snapshot->proxy.sessions.tcp_active,
    snapshot->proxy.sessions.udp_flow_active, snapshot->proxy.sessions.udp_association_active);
#else
  append(writer, ",\"sessions\":{\"tcp\":0,\"udp\":0,\"associations\":0}");
#endif
}

ftun_status_t ftun_ctl_status_json(const ftun_ctl_status_t *snapshot, ftun_ctl_operation_t operation,
  char *out, size_t capacity, size_t *length)
{
  writer_t writer = {out, 0u, capacity, true};
  if (operation == FTUN_CTL_STATUS) root(&writer, snapshot);
#if defined(FTUN_HAVE_MODULE_DNS)
  else if (operation == FTUN_CTL_DNS_STATUS) dns(&writer, &snapshot->dns);
#endif
#if defined(FTUN_HAVE_MODULE_PROXY)
  else if (operation == FTUN_CTL_PROXY_STATUS) proxy(&writer, &snapshot->proxy);
#endif
  else return FTUN_E_UNSUPPORTED;
  append(&writer, "}\n");
  *length = writer.used;
  return writer.ok ? FTUN_OK : FTUN_E_LIMIT;
}
