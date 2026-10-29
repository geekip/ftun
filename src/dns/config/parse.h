#ifndef FTUN_DNS_CONFIG_PARSE_H
#define FTUN_DNS_CONFIG_PARSE_H
#include "dns/config/model.h"
/* 只修改构造中的 dns 段；owner 负责预算与部分失败的最终析构。
 * JSON 在调用期间借用，不保留 AST、不做 I/O、不调用业务回调。 */
ftun_status_t ftun_config_parse_dns(const cJSON *item, ftun_config_t *owner,
  ftun_config_dns_t *dns);
/* 缺省值按 owner 预算准入；clear 仅用于最终 payload 析构。 */
ftun_status_t ftun_config_defaults_dns(ftun_config_t *owner, ftun_config_dns_t *dns);
void ftun_config_clear_dns(ftun_config_dns_t *dns);
#endif
