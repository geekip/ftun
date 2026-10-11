#ifndef FTUN_CORE_CONTROL_RESOLVER_H
#define FTUN_CORE_CONTROL_RESOLVER_H

#include "config/model.h"
#include "core/runtime.h"
#include "dns/bootstrap.h"

#define FTUN_CONTROL_ENDPOINT_TEXT_BYTES 260u
#define FTUN_CONTROL_CREDENTIAL_BYTES 256u

typedef struct {
  ftun_endpoint_t bootstrap[FTUN_BOOTSTRAP_MAX_SERVERS];
  size_t bootstrap_count;
  char upstream[FTUN_CONTROL_ENDPOINT_TEXT_BYTES];
  char proxy[FTUN_CONTROL_ENDPOINT_TEXT_BYTES];
  char proxy_username[FTUN_CONTROL_CREDENTIAL_BYTES];
  char proxy_password[FTUN_CONTROL_CREDENTIAL_BYTES];
  uint32_t socket_mark;
  bool named;
  bool tcp;
  bool use_proxy;
} ftun_control_resolver_plan_t;

/* Build an owning, worker-safe REAL resolver plan.  Empty server selects
 * Bootstrap; DNS disabled selects SystemResolver regardless of server. */
ftun_status_t ftun_control_resolver_plan(
  const ftun_config_t *config, const ftun_runtime_t *runtime,
  ftun_string_t server, uint32_t socket_mark,
  ftun_control_resolver_plan_t *out);

/* Synchronous worker/control-endpoint resolver.  Result is one IPv4 endpoint
 * with caller supplied port; no fallback occurs after a selected source fails. */
ftun_status_t ftun_control_resolve(
  const ftun_control_resolver_plan_t *plan, ftun_string_t domain,
  uint16_t port, ftun_endpoint_t *out);

/* Resolve specifically through the plan's Bootstrap/SystemResolver source,
 * ignoring a named resolver.  Proxy and upstream endpoint names use this to
 * avoid resolver recursion. */
ftun_status_t ftun_control_resolve_bootstrap(
  const ftun_control_resolver_plan_t *plan, ftun_string_t domain,
  uint16_t port, ftun_endpoint_t *out);

/* Parse IPv4/domain plus optional port without performing resolution. */
ftun_status_t ftun_control_parse_endpoint(
  const char *text, uint16_t default_port, ftun_endpoint_t *out,
  char domain[FTUN_CONTROL_ENDPOINT_TEXT_BYTES]);

#endif
