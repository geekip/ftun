#ifndef FTUN_APP_COMPOSITION_EGRESS_H
#define FTUN_APP_COMPOSITION_EGRESS_H
#include "libs/transport/egress.h"

/* 准备与bind分开：准备只复制/解析配置，bind在主owner发布前设置代次。 */
ftun_status_t ftun_app_egress_prepare(ftun_budget_t *budget,
  const ftun_config_t *config, uint32_t mark, const ftun_egress_provider_t **out);
void ftun_app_egress_bind(const ftun_egress_provider_t *provider,
  ftun_core_t *core, uint64_t generation);
#endif
