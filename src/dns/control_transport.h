#ifndef FTUN_DNS_CONTROL_TRANSPORT_H
#define FTUN_DNS_CONTROL_TRANSPORT_H

#include "transport/control_channel.h"

typedef struct {
  ftun_endpoint_t upstream;
  uint32_t socket_mark;
  bool tcp;
} ftun_dns_blocking_query_t;

/* 控制端点解析使用的同步传输，只能在 blocking worker 中调用。调用期间
 * 所有输入视图由调用方保有，响应写入调用方提供的有界缓冲。 */
ftun_status_t ftun_dns_query_blocking(
  const ftun_control_execution_t *execution,
  const ftun_dns_blocking_query_t *query, ftun_bytes_t wire,
  uint8_t *response, size_t response_capacity, size_t *out_response_size);

/* 在已连接的流上交换 DNS 长度前缀与消息；调用方保有通道与清理责任。
 * SOCKS 等上层封装完成握手后可复用，不在 DNS 层引入代理协议。 */
ftun_status_t ftun_dns_query_stream(ftun_control_channel_t *channel,
  ftun_bytes_t wire, uint8_t *response, size_t response_capacity,
  size_t *out_response_size);

#endif
