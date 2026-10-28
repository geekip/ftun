#ifndef FTUN_PROXY_SNIFF_SNIFF_H
#define FTUN_PROXY_SNIFF_SNIFF_H
#include "internal/contracts.h"
/* 
 * ftun_sniff_domain 保留真实目标和已有域名。 */
/* 仅在 metadata 没有域名时根据预读字节分派 TLS/HTTP。未识别
 * 或畸形协议不改变原 metadata；本函数不消费 preread。 */
ftun_status_t ftun_sniff_domain_with_budget(ftun_budget_t *budget, const ftun_metadata_t *metadata, ftun_bytes_t preread, ftun_sniff_result_t *out);
/* 纯解析兼容入口不计预算；生产路径须传拥有者预算。 */
ftun_status_t ftun_sniff_domain(const ftun_metadata_t *metadata, ftun_bytes_t preread, ftun_sniff_result_t *out);
#endif
