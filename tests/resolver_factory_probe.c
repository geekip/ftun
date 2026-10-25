#include "network/resolver.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

ftun_status_t __real_ftun_resolver_scope_start(ftun_resolver_scope_t *scope,
  ftun_core_t *core, const ftun_resolver_provider_request_t *request,
  ftun_operation_t **out);

ftun_status_t __wrap_ftun_resolver_scope_start(ftun_resolver_scope_t *scope,
  ftun_core_t *core, const ftun_resolver_provider_request_t *request,
  ftun_operation_t **out)
{
  fprintf(stderr, "resolver probe source=%d generation=%" PRIu64
    " purpose=%d domain=%.*s\n", (int)request->source, request->generation,
    (int)request->purpose, (int)request->system.domain.length,
    request->system.domain.data);
  if (request->system.domain.length == 12u &&
      memcmp(request->system.domain.data, "blocked.test", 12u) == 0) {
    *out = NULL;
    return FTUN_E_REJECTED;
  }
  return __real_ftun_resolver_scope_start(scope, core, request, out);
}
