#ifndef FTUN_PLATFORM_SYSRESOLVE_H
#define FTUN_PLATFORM_SYSRESOLVE_H
#include "util/types.h"
/* 阻塞调用，仅在上层 Worker 上运行；输入 NUL 终止并已校验的域名。
 * 返回去重 IPv4 地址，调用方提供 maximum*4 字节，不保留输入/输出。
 * 超出容量返回 LIMIT，不截短冒充成功；原生解析器的临时存储在返回前释放。 */
ftun_status_t ftun_sysresolve_ipv4(const char *domain, uint8_t *addresses,
  size_t maximum, size_t *out_count);
ftun_status_t ftun_sysresolve_first_ipv4(const char *domain, uint16_t port, ftun_endpoint_t *out);
ftun_status_t ftun_system_nameserver(ftun_endpoint_t *out);
#endif
