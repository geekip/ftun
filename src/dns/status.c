#include "dns/status.h"
#include "dns/service_internal.h"
#include "util/endpoint.h"

static void query_stats_add(ftun_dns_query_stats_t *total, const ftun_dns_listener_t *listener)
{
  ftun_dns_listener_info_t info;
  size_t index;
  if (listener == NULL) return;
  (void)ftun_dns_listener_get_info(listener, &info);
  total->queries += info.queries.queries;
  total->success += info.queries.success;
  for (index = 0u; index <= FTUN_E_STATE_CORRUPT; ++index)
    total->failures[index] += info.queries.failures[index];
}

static const char *server_name(const ftun_dns_runtime_t *dns, size_t index)
{
  const ftun_config_dns_t *config = ftun_config_dns(dns->config);
  return config->server_count == 0u ? "bootstrap" : config->servers[index].name;
}

static ftun_status_t upstream_info(const ftun_dns_runtime_t *dns, size_t server,
  size_t address, ftun_upstream_info_t *out)
{
  ftun_dns_server_info_t info;
  ftun_status_t status;
  if (dns->upstream_sets[server] != NULL)
    return ftun_upstream_set_get_info(dns->upstream_sets[server], address, out);
  if (address != 0u) return FTUN_E_EOF;
  status = ftun_dns_server_get_info(dns->servers[server], &info);
  if (status != FTUN_OK) return status;
  memset(out, 0, sizeof(*out));
  out->address = info.upstream;
  out->success = info.upstream_success;
  out->failures = info.upstream_failures;
  out->latency_ms = info.latency_ms;
  out->latency_valid = info.latency_valid;
  out->last_failure = info.last_failure;
  out->recovery.state = info.unhealthy ? FTUN_RECOVERY_WAITING : FTUN_RECOVERY_AVAILABLE;
  return FTUN_OK;
}

static ftun_status_t matching_counts(const ftun_dns_runtime_t *source,
  const char *name, ftun_upstream_info_t *info)
{
  size_t server, address;
  if (source == NULL) return FTUN_OK;
  for (server = 0u; server < source->server_count; ++server) {
    if (strcmp(server_name(source, server), name) != 0) continue;
    for (address = 0u; ; ++address) {
      ftun_upstream_info_t previous;
      ftun_status_t status = upstream_info(source, server, address, &previous);
      if (status == FTUN_E_EOF) break;
      if (status != FTUN_OK) return status;
      if (ftun_endpoint_equal(&info->address, &previous.address)) {
        info->success += previous.success;
        info->failures += previous.failures;
        return FTUN_OK;
      }
    }
  }
  return FTUN_OK;
}

static ftun_status_t lifetime_add(const ftun_dns_runtime_t *dns,
  ftun_dns_lifetime_stats_t *total)
{
  size_t index;
  if (dns == NULL) return FTUN_OK;
  query_stats_add(&total->queries, dns->hijack);
  for (index = 0u; index < dns->listener_count; ++index)
    query_stats_add(&total->queries, dns->listeners[index].protocol);
  if (dns->cache != NULL) {
    ftun_dns_cache_usage_t usage;
    ftun_status_t status = ftun_dns_cache_get_usage(dns->cache, &usage);
    if (status != FTUN_OK) return status;
    total->cache_hits += usage.hits;
    total->cache_misses += usage.misses;
    total->cache_evictions += usage.evictions;
    total->cache_expirations += usage.expirations;
  }
  return FTUN_OK;
}

static ftun_status_t status_fill(const ftun_dns_runtime_t *dns,
  const ftun_dns_runtime_t *retired, ftun_dns_status_t *out)
{
  const ftun_config_dns_t *config;
  size_t index, waiting = 0u;
  ftun_service_state_t base;
  ftun_status_t result;
  memset(out, 0, sizeof(*out));
  out->status.state = FTUN_SERVICE_DISABLED;
  if (dns == NULL) return FTUN_OK;
  config = ftun_config_dns(dns->config);
  out->generation = dns->generation;
  out->status.state = dns->cleanup_only ? FTUN_SERVICE_FAILED :
    dns->active && dns->accepting ? FTUN_SERVICE_ACTIVE : FTUN_SERVICE_NOT_READY;
  base = out->status.state;
  out->listeners_total = dns->listener_count;
  out->listeners_count = dns->listener_count < FTUN_STATUS_MAX_ITEMS
    ? dns->listener_count : FTUN_STATUS_MAX_ITEMS;
  if (dns->cache != NULL) {
    result = ftun_dns_cache_get_usage(dns->cache, &out->cache);
    if (result != FTUN_OK) return result;
  }
  query_stats_add(&out->queries, dns->hijack);
  for (index = 0u; index < dns->listener_count; ++index) {
    const ftun_dns_runtime_listener_slot_t *slot = &dns->listeners[index];
    query_stats_add(&out->queries, slot->protocol);
    if (index < out->listeners_count) {
      ftun_dns_listener_status_t *item = &out->listeners[index];
      result = ftun_dns_runtime_parse_endpoint(config->listeners[index].listen, &item->address);
      if (result != FTUN_OK) return result;
      ftun_status_label_set(&item->server, slot->policy ? "policy" :
        config->server_count == 0u ? "bootstrap" : config->servers[slot->fixed_server].name);
      item->status.state = slot->waiting ? FTUN_SERVICE_WAITING : base;
      if (slot->waiting) {
        ftun_recovery_info_t recovery;
        result = ftun_recovery_query(dns->recovery, slot->recovery.slot, &recovery);
        if (result != FTUN_OK) return result;
        item->status.reason = FTUN_E_IO;
        item->status.retry_at_ms = recovery.next_ms;
        waiting++;
      }
    }
  }
  if (waiting != 0u && base == FTUN_SERVICE_ACTIVE) {
    out->status.state = waiting == dns->listener_count && dns->hijack == NULL
      ? FTUN_SERVICE_WAITING : FTUN_SERVICE_DEGRADED;
    out->status.reason = FTUN_E_IO;
  }
  for (index = 0u; index < dns->server_count; ++index) {
    size_t address;
    for (address = 0u; ; ++address) {
      ftun_upstream_info_t info;
      ftun_dns_upstream_status_t *item;
      result = upstream_info(dns, index, address, &info);
      if (result == FTUN_E_EOF) break;
      if (result != FTUN_OK) return result;
      result = matching_counts(retired, server_name(dns, index), &info);
      if (result != FTUN_OK) return result;
      out->upstreams_total++;
      if (info.recovery.state != FTUN_RECOVERY_AVAILABLE && out->status.state == FTUN_SERVICE_ACTIVE) {
        out->status.state = FTUN_SERVICE_DEGRADED;
        out->status.reason = info.last_failure == FTUN_OK ? FTUN_E_IO : info.last_failure;
      }
      if (out->upstreams_count == FTUN_STATUS_MAX_ITEMS) continue;
      item = &out->upstreams[out->upstreams_count++];
      ftun_status_label_set(&item->server, config->server_count == 0u ? "bootstrap" : config->servers[index].name);
      item->group = item->server;
      item->address = info.address;
      item->success = info.success;
      item->failures = info.failures;
      item->latency_ms = info.latency_ms;
      item->latency_valid = info.latency_valid;
      item->last_failure = info.last_failure;
      item->status.state = info.recovery.state == FTUN_RECOVERY_AVAILABLE
        ? FTUN_SERVICE_ACTIVE : FTUN_SERVICE_DEGRADED;
      item->status.reason = item->status.state == FTUN_SERVICE_ACTIVE ? FTUN_OK :
        info.last_failure == FTUN_OK ? FTUN_E_IO : info.last_failure;
      item->status.retry_at_ms = info.recovery.next_ms;
    }
  }
  return FTUN_OK;
}

ftun_status_t ftun_dns_status_fill(const ftun_dns_runtime_t *dns, ftun_dns_status_t *out)
{
  return status_fill(dns, NULL, out);
}

ftun_status_t ftun_dns_service_status_fill(const ftun_dns_service_slot_t *slot,
  ftun_dns_status_t *out)
{
  ftun_dns_lifetime_stats_t total = slot->history;
  size_t index;
  ftun_status_t result = status_fill(slot->active, slot->retired, out);
  if (result == FTUN_OK) result = lifetime_add(slot->retired, &total);
  if (result != FTUN_OK) return result;
  out->queries.queries += total.queries.queries;
  out->queries.success += total.queries.success;
  for (index = 0u; index <= FTUN_E_STATE_CORRUPT; ++index)
    out->queries.failures[index] += total.queries.failures[index];
  out->cache.hits += total.cache_hits;
  out->cache.misses += total.cache_misses;
  out->cache.evictions += total.cache_evictions;
  out->cache.expirations += total.cache_expirations;
  return FTUN_OK;
}

ftun_status_t ftun_dns_status_archive(const ftun_dns_runtime_t *source,
  ftun_dns_runtime_t *target, ftun_dns_lifetime_stats_t *history)
{
  size_t server, address;
  ftun_dns_lifetime_stats_t total = *history;
  ftun_status_t result = lifetime_add(source, &total);
  if (result != FTUN_OK) return result;
  if (target != NULL) for (server = 0u; server < target->server_count; ++server) {
    for (address = 0u; ; ++address) {
      ftun_upstream_info_t info;
      result = upstream_info(target, server, address, &info);
      if (result == FTUN_E_EOF) break;
      if (result != FTUN_OK) return result;
      info.success = info.failures = 0u;
      result = matching_counts(source, server_name(target, server), &info);
      if (result != FTUN_OK) return result;
      if (target->upstream_sets[server] != NULL)
        ftun_upstream_set_add_counts(target->upstream_sets[server], address, info.success, info.failures);
      else ftun_dns_server_add_counts(target->servers[server], info.success, info.failures);
    }
  }
  *history = total;
  return FTUN_OK;
}
