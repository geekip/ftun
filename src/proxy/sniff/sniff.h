#ifndef FTUN_PROXY_SNIFF_SNIFF_H
#define FTUN_PROXY_SNIFF_SNIFF_H
#include "internal/contracts.h"
/* REQ-SNIFF-001 / TASK-SNIFF-001 / TEST-SNIFF-001，目标 0.5.0：
 * ftun_sniff_domain 保留真实目标和已有域名。 */
/* 仅在 metadata 没有域名时根据预读字节分派 TLS/HTTP。未识别
 * 或畸形协议不改变原 metadata；本函数不消费 preread。 */
ftun_status_t ftun_sniff_domain(const ftun_metadata_t *metadata, ftun_bytes_t preread, ftun_sniff_result_t *out);
#endif
