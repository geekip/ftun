#ifndef FTUN_LIBS_RESOLVER_CONTROL_H
#define FTUN_LIBS_RESOLVER_CONTROL_H
#include "libs/resolver/basic.h"
#include "libs/resolver/control_transport.h"

#define FTUN_CONTROL_ENDPOINT_TEXT_BYTES 260u

typedef struct {
  ftun_endpoint_t bootstrap[FTUN_BOOTSTRAP_MAX_SERVERS];
  size_t bootstrap_count;
  char name[256];
  char upstream[FTUN_CONTROL_ENDPOINT_TEXT_BYTES];
  ftun_egress_id_t egress_id;
  uint32_t socket_mark;
  bool ipv6;
  uint16_t query_type;
  bool named;
  bool tcp;
} ftun_control_resolver_plan_t;

/* Synchronous worker/control-endpoint resolver.  Result is one IP endpoint
 * with caller supplied port; no fallback occurs after a selected source fails. */
ftun_status_t ftun_control_resolve(
  const ftun_control_execution_t *execution,
  const ftun_control_resolver_plan_t *plan, ftun_string_t domain,
  uint16_t port, ftun_endpoint_t *out);

/* Resolve specifically through the plan's Bootstrap/SystemResolver source,
 * ignoring a named resolver.  上游地址名 use this to
 * avoid resolver recursion. */
ftun_status_t ftun_control_resolve_bootstrap(
  const ftun_control_execution_t *execution,
  const ftun_control_resolver_plan_t *plan, ftun_string_t domain,
  uint16_t port, ftun_endpoint_t *out);

/* Parse IP/domain plus optional port without performing resolution. */
ftun_status_t ftun_control_parse_endpoint(
  const char *text, uint16_t default_port, ftun_endpoint_t *out,
  char domain[FTUN_CONTROL_ENDPOINT_TEXT_BYTES]);

#endif
