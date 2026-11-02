#ifndef FTUN_DNS_STATUS_H
#define FTUN_DNS_STATUS_H
#include "core/status.h"
#include "dns/service.h"
#include "dns/module.h"
#include "dns/cache.h"

#include "dns/stats.h"

typedef struct {
  ftun_endpoint_t address;
  ftun_status_label_t server;
  ftun_service_status_t status;
} ftun_dns_listener_status_t;

typedef struct {
  ftun_status_label_t server, group;
  ftun_endpoint_t address;
  ftun_service_status_t status;
  uint64_t success, failures, latency_ms;
  ftun_status_t last_failure;
  bool latency_valid;
} ftun_dns_upstream_status_t;

typedef struct {
  ftun_service_status_t status;
  uint64_t generation;
  ftun_dns_query_stats_t queries;
  ftun_dns_cache_usage_t cache;
  size_t listeners_total, listeners_count, upstreams_total, upstreams_count;
  ftun_dns_listener_status_t listeners[FTUN_STATUS_MAX_ITEMS];
  ftun_dns_upstream_status_t upstreams[FTUN_STATUS_MAX_ITEMS];
} ftun_dns_status_t;

/* 只在owner同步调用，不分配、不I/O；所有数组和名称归out，不借用Runtime。
 * 端点只复制已解析IP，domain为空；NULL表示业务未启用。 */
ftun_status_t ftun_dns_status_fill(const ftun_dns_runtime_t *dns, ftun_dns_status_t *out);
ftun_status_t ftun_dns_service_status_fill(const ftun_dns_service_slot_t *slot,
  ftun_dns_status_t *out);
/* 旧代已idle；归并后由service撤下retired发布，再执行可能分步失败的销毁。 */
ftun_status_t ftun_dns_status_archive(const ftun_dns_runtime_t *source,
  ftun_dns_runtime_t *target, ftun_dns_lifetime_stats_t *history);
#endif
