#ifndef FTUN_PROXY_CONTROL_RESOLVER_H
#define FTUN_PROXY_CONTROL_RESOLVER_H

#include "proxy/config/transport.h"
#include "proxy/config/plan.h"
#include "proxy/config/model.h"
#include "libs/resolver/config.h"
#include "proxy/runtime_state.h"
#include "libs/resolver/basic.h"
#include "libs/resolver/control.h"

/* Build an owning, worker-safe REAL resolver plan.  Empty server selects
 * Bootstrap; DNS disabled selects SystemResolver regardless of server. */
ftun_status_t ftun_control_resolver_plan(
  const ftun_config_t *config, const ftun_runtime_t *runtime,
  ftun_string_t server, uint32_t socket_mark,
  ftun_control_resolver_plan_t *out);


#endif
