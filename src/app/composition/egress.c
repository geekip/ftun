#include "app/composition/egress.h"
#if defined(FTUN_HAVE_MODULE_PROXY)
#include "proxy/egress.h"
#include "proxy/runtime_state.h"

static ftun_status_t select_member(void *context, uint64_t generation,
  uint32_t group, uint32_t *member)
{
  ftun_runtime_t *runtime = NULL;
  ftun_runtime_info_t info;
  bool is_group, degraded;
  ftun_string_t resolver;
  ftun_status_t status = ftun_runtime_active_acquire(context, &runtime);
  if (status == FTUN_OK) status = ftun_runtime_get_info(runtime, &info);
  if (status == FTUN_OK && info.generation != generation) status = FTUN_E_STALE;
  if (status == FTUN_OK) status = ftun_runtime_group_selected(runtime, group,
    member, &is_group, &degraded, &resolver);
  if (status == FTUN_OK && !is_group) status = FTUN_E_REJECTED;
  {
    ftun_status_t released = ftun_runtime_release(&runtime);
    if (status == FTUN_OK) status = released;
  }
  return status;
}
#endif

ftun_status_t ftun_app_egress_prepare(ftun_budget_t *budget,
  const ftun_config_t *config, uint32_t mark, const ftun_egress_provider_t **out)
{
#if defined(FTUN_HAVE_MODULE_PROXY)
  return ftun_proxy_egress_prepare(budget, config, mark, out);
#else
  (void)budget; (void)config; (void)mark;
  *out = ftun_egress_direct_provider();
  return FTUN_OK;
#endif
}

void ftun_app_egress_bind(const ftun_egress_provider_t *provider,
  ftun_core_t *core, uint64_t generation)
{
#if defined(FTUN_HAVE_MODULE_PROXY)
  ftun_proxy_egress_bind(provider, generation, select_member, core);
#else
  (void)provider; (void)core; (void)generation;
#endif
}
