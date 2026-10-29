#ifndef FTUN_PROXY_SNIFF_TLS_SNI_H
#define FTUN_PROXY_SNIFF_TLS_SNI_H
#include "util/types.h"
/* 
 * ftun_sniff_tls_sni 只返回明文 SNI 提示。 */
/* 纯字节 TLS ClientHello 解析，不启动 TLS 库。支持跨 record 的
 * handshake 分片；不完整输入以 need_more 表示，畸形输入返回
 * PROTOCOL。输出域名保存在 result 内，不借用临时聚合缓冲。 */
ftun_status_t ftun_sniff_tls_sni_with_budget(ftun_budget_t *budget, ftun_bytes_t preread, ftun_sniff_result_t *out);
/* 纯解析兼容入口不计预算；生产路径须传拥有者预算。 */
ftun_status_t ftun_sniff_tls_sni(ftun_bytes_t preread, ftun_sniff_result_t *out);
#endif
