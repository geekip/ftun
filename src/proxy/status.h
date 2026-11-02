#ifndef FTUN_PROXY_STATUS_H
#define FTUN_PROXY_STATUS_H
#include "core/status.h"
#include "proxy/runtime.h"

typedef struct {
  ftun_status_label_t name;
  ftun_endpoint_t address;
  ftun_service_status_t status;
  bool udp;
} ftun_proxy_listener_status_t;

typedef struct {
  ftun_status_label_t name, selected;
  bool degraded, health_valid, health_success;
  uint32_t latency_ms;
  uint64_t observed_ms;
} ftun_proxy_group_status_t;

typedef struct {
  ftun_status_label_t name;
  uint64_t active, connections;
  uint64_t failures[FTUN_E_STATE_CORRUPT + 1u];
} ftun_proxy_outbound_status_t;

typedef struct {
  ftun_status_label_t name;
  ftun_service_status_t status;
  size_t ranges, nodes, keywords;
  int64_t updated_unix_ms;
  bool updated_valid;
} ftun_proxy_frs_status_t;

typedef struct {
  ftun_service_status_t status, frs_status, fakeip_status;
  uint64_t generation;
  bool frs_known;
  ftun_proxy_runtime_capacity_info_t sessions;
  size_t listeners_total, listeners_count, groups_total, groups_count;
  size_t outbounds_total, outbounds_count, frs_total, frs_count;
  ftun_proxy_listener_status_t listeners[FTUN_STATUS_MAX_ITEMS];
  ftun_proxy_group_status_t groups[FTUN_STATUS_MAX_ITEMS];
  ftun_proxy_outbound_status_t outbounds[FTUN_STATUS_MAX_ITEMS];
  ftun_proxy_frs_status_t frs[FTUN_STATUS_MAX_ITEMS];
} ftun_proxy_status_t;

/* owner同步填充有界拥有型快照，不分配、不I/O，不向控制层暴露运行时布局。 */
ftun_status_t ftun_proxy_status_fill(ftun_proxy_runtime_t *proxy, ftun_proxy_status_t *out);
#endif
