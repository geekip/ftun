#ifndef FTUN_DNS_CONFIG_VALIDATE_H
#define FTUN_DNS_CONFIG_VALIDATE_H
#include "dns/config/model.h"
/* 同步借用段，不分配，不启动服务；诊断文本为静态借用。 */
int ftun_dns_server_exists(const ftun_config_dns_t *dns, const char *name);
ftun_status_t ftun_config_validate_dns(const ftun_config_dns_t *dns, ftun_diagnostic_t *out);
#endif
