#ifndef FTUN_PROXY_SNIFF_HTTP_HOST_H
#define FTUN_PROXY_SNIFF_HTTP_HOST_H
#include "internal/contracts.h"
/* REQ-SNIFF-001 / TASK-SNIFF-003 / TEST-SNIFF-003，目标 0.5.0：
 * ftun_sniff_http_host 严格验证并规范化域名提示。 */
/* 有界 HTTP/1 头部解析。Host 大小写不敏感，域名小写化；重复
 * 冲突、非法 authority 或超限返回 PROTOCOL。输入只读。 */
ftun_status_t ftun_sniff_http_host(ftun_bytes_t preread, ftun_sniff_result_t *out);
#endif
