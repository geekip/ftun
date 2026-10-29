#ifndef FTUN_PROXY_CONFIG_VALIDATE_H
#define FTUN_PROXY_CONFIG_VALIDATE_H
#include "proxy/config/model.h"
/* owner同步调用；输入仅借用。图工作区按budget先准入，所有路径归还。 */
ftun_status_t ftun_config_validate_proxy_base(const ftun_config_proxy_base_t *base,
  const ftun_config_inbound_t *inbounds, size_t inbound_count, ftun_diagnostic_t *out);
ftun_status_t ftun_config_validate_outbounds(ftun_budget_t *budget,
  const ftun_config_outbound_t *outbounds, size_t outbound_count,
                                             ftun_diagnostic_t *out);
ftun_status_t ftun_config_validate_inbounds(const ftun_config_inbound_t *inbounds, size_t inbound_count,
  const ftun_config_outbound_t *outbounds, size_t outbound_count,
                                            ftun_diagnostic_t *out);
ftun_status_t ftun_config_validate_frs(const ftun_config_frs_t *frs,
  const ftun_config_outbound_t *outbounds, size_t outbound_count,
                                       ftun_diagnostic_t *out);
ftun_status_t ftun_config_validate_rule(const ftun_config_outbound_t *outbounds, size_t outbound_count,
                                        const char *rule,
                                        ftun_diagnostic_t *out);
#endif
