#ifndef FTUN_PROXY_DNS_CONTROL_PATH_ADAPTER_H
#define FTUN_PROXY_DNS_CONTROL_PATH_ADAPTER_H

#include "dns/control_transport.h"

typedef struct {
  ftun_dns_blocking_query_t direct;
  ftun_endpoint_t proxy;
  ftun_string_t proxy_username;
  ftun_string_t proxy_password;
  bool use_proxy;
} ftun_proxy_dns_blocking_query_t;

/* 控制任务借用 execution 的预算和身份；DIRECT 与 SOCKS5 都通过公共
 * Path 通道交换。认证、UDP 包装和 relay 校验全部留在 Proxy 边界。 */
ftun_status_t ftun_proxy_dns_query_blocking(
  const ftun_control_execution_t *execution,
  const ftun_proxy_dns_blocking_query_t *query, ftun_bytes_t wire,
  uint8_t *response, size_t response_capacity, size_t *out_response_size);

#endif
