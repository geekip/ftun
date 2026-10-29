#ifndef FTUN_PROXY_CONFIG_PARSE_H
#define FTUN_PROXY_CONFIG_PARSE_H
#include "proxy/config/model.h"
/* 配置构造阶段同步借用 JSON；只读写显式传入的段。
 * 分配归 owner，部分失败由宿主析构处理，不启动任何业务或网络工作。 */
ftun_status_t ftun_config_parse_frs(const cJSON *item, ftun_config_t *owner,
  ftun_config_frs_t *frs);
ftun_status_t ftun_config_parse_sniff(const cJSON *item, ftun_config_sniff_t *sniff);
ftun_status_t ftun_config_parse_inbounds(const cJSON *array, ftun_config_t *owner,
  ftun_config_inbound_t **items, size_t *item_count);
ftun_status_t ftun_config_parse_outbounds(const cJSON *array, ftun_config_t *owner,
  ftun_config_outbound_t **items, size_t *item_count);
/* 缺省值按 owner 预算准入；clear 仅用于最终 payload 析构。 */
ftun_status_t ftun_config_defaults_frs(ftun_config_t *owner, ftun_config_frs_t *frs);
void ftun_config_clear_frs(ftun_config_frs_t *frs);
void ftun_config_clear_inbounds(ftun_config_inbound_t *items, size_t count);
void ftun_config_clear_outbounds(ftun_config_outbound_t *items, size_t count);
#endif
