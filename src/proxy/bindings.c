#include "proxy/bindings.h"

bool ftun_proxy_bindings_valid(const ftun_proxy_bindings_t *bindings)
{
  bool l3_bound;
  bool l3_empty;
  if (bindings == NULL || bindings->loop == NULL ||
      bindings->resolver.start == NULL || bindings->path.start == NULL ||
      bindings->fakeip_slot == NULL) {
    return false;
  }
#if defined(FTUN_HAVE_MODULE_DNS)
  if (!ftun_proxy_dns_runtime_adapter_valid(bindings->dns)) return false;
#endif
  if (bindings->l3 == NULL) return !bindings->l3_deferred;
  l3_bound = bindings->l3->service != NULL &&
    bindings->l3->budget != NULL && bindings->l3->generation != 0u;
  l3_empty = bindings->l3->service == NULL &&
    bindings->l3->budget == NULL && bindings->l3->generation == 0u &&
    bindings->l3->pending_generation == 0u &&
    !bindings->l3->reload_prepared;
  return l3_bound || (bindings->l3_deferred && l3_empty);
}
