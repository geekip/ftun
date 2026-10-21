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

/* Proxy 控制路径的 SOCKS5 DNS 封装。DIRECT 请求转交中立 DNS transport；
 * SOCKS5 连接、认证、UDP 包装和 relay 校验全部留在 Proxy 边界。 */
ftun_status_t ftun_proxy_dns_query_blocking(
  const ftun_proxy_dns_blocking_query_t *query, ftun_bytes_t wire,
  uint8_t *response, size_t response_capacity, size_t *out_response_size);

#endif
