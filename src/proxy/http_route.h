#ifndef FTUN_PROXY_HTTP_ROUTE_H
#define FTUN_PROXY_HTTP_ROUTE_H
#include "libs/http/http.h"
#include "proxy/control_resolver.h"

/* Resolve a configured DIRECT/SOCKS5/group path into the transport fields in
 * spec.  runtime may be NULL during initial FRS bootstrap; group defaults are
 * used until an active Runtime exists. */
ftun_status_t ftun_http_fetch_route(const ftun_config_t *config,
                                    const ftun_runtime_t *runtime,
                                    const char *outbound_name,
                                    ftun_http_fetch_spec_t *spec);
/* Select the local resolver used for every URL host, including redirects.
 * Empty server means Bootstrap (or SystemResolver when DNS is disabled). */
ftun_status_t ftun_http_fetch_resolver(const ftun_config_t *config,
                                       const ftun_runtime_t *runtime,
                                       ftun_string_t server,
                                       ftun_http_fetch_spec_t *spec);

#endif
