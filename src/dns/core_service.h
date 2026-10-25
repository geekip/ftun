#ifndef FTUN_DNS_CORE_SERVICE_H
#define FTUN_DNS_CORE_SERVICE_H

#include "core/service.h"
#include "dns/service.h"

/* Composition 拥有发布槽；DNS service 在 activate/commit 时发布当前代，
 * quiesce/destroy 时先关闭接纳。消费者只借用，不拥有 DNS runtime。 */
typedef struct {
  ftun_dns_runtime_t *active;
  uint64_t generation;
  bool accepting;
} ftun_dns_service_slot_t;

typedef struct {
  ftun_event_loop_t *loop;
  ftun_dns_service_slot_t *slot;
  ftun_dns_runtime_adapter_t adapter;
  uint32_t socket_mark;
  ftun_path_provider_ops_t path;
  void *path_context;
} ftun_dns_service_binding_t;

bool ftun_dns_service_binding_valid(const ftun_dns_service_binding_t *binding);
ftun_status_t ftun_dns_service_slot_get(
  const ftun_dns_service_slot_t *slot, ftun_dns_runtime_t **out);

extern const ftun_core_service_descriptor_t ftun_dns_core_service;
const ftun_core_service_descriptor_t *ftun_dns_service_descriptor(void);

#endif
