#ifndef FTUN_PROXY_EGRESS_INTERNAL_H
#define FTUN_PROXY_EGRESS_INTERNAL_H
#include "proxy/egress.h"
#include "proxy/config/transport.h"
#include "proxy/outbound/socks5.h"
#include "libs/resolver/control.h"
#include "platform/atomic.h"
#include "proxy/egress_resolution.h"

typedef struct {
  ftun_config_outbound_kind_t kind;
  ftun_string_t name, resolver;
  ftun_socks5_proxy_t proxy;
  ftun_endpoint_t endpoint;
  uint32_t *members;
  size_t member_count;
  uint32_t default_id;
  bool resolved;
  ftun_proxy_resolution_t *resolution;
  char domain[FTUN_CONTROL_ENDPOINT_TEXT_BYTES];
  uint8_t username[256], password[256];
} ftun_proxy_egress_node_t;

typedef struct {
  ftun_egress_provider_t provider, worker;
  ftun_atomic_size_t references;
  ftun_reservation_t reservation;
  ftun_proxy_egress_node_t *nodes;
  size_t count;
  ftun_control_resolver_plan_t bootstrap;
  ftun_path_provider_ops_t physical;
  void *physical_context;
  uint64_t generation;
  ftun_proxy_egress_select_fn select;
  void *select_context;
} ftun_proxy_egress_t;

ftun_status_t ftun_proxy_egress_open(void *context, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *spec,
  ftun_operation_t **out);
ftun_status_t ftun_proxy_egress_worker_open(void *context, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *spec,
  ftun_operation_t **out);
bool ftun_proxy_resolution_valid(const ftun_proxy_egress_node_t *node, uint64_t now);
bool ftun_proxy_resolution_cached(const ftun_proxy_egress_node_t *node,
  const ftun_dial_request_t *request, uint64_t now, ftun_endpoint_t *out);
ftun_status_t ftun_proxy_resolution_start(ftun_proxy_egress_t *plan,
  ftun_proxy_egress_node_t *node, ftun_core_t *core,
  const ftun_dial_request_t *request, uint64_t now,
  ftun_proxy_resolution_waiter_t *waiter);
ftun_status_t ftun_proxy_resolution_cancel(ftun_proxy_resolution_waiter_t *waiter,
  ftun_status_t reason);
void ftun_proxy_resolution_destroy(ftun_proxy_resolution_t *resolution);
#endif
