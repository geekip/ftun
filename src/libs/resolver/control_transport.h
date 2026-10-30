#ifndef FTUN_LIBS_RESOLVER_CONTROL_TRANSPORT_H
#define FTUN_LIBS_RESOLVER_CONTROL_TRANSPORT_H

#include "libs/resolver/control_channel.h"

typedef struct {
  ftun_endpoint_t upstream;
  uint32_t socket_mark;
  bool tcp;
  ftun_egress_id_t egress_id;
} ftun_dns_blocking_query_t;

/* 控制端点解析使用的同步传输，只能在 blocking worker 中调用。调用期间
 * 所有输入视图由调用方保有，响应写入调用方提供的有界缓冲。 */
ftun_status_t ftun_dns_query_blocking(
  const ftun_control_execution_t *execution,
  const ftun_dns_blocking_query_t *query, ftun_bytes_t wire,
  uint8_t *response, size_t response_capacity, size_t *out_response_size);

/* 在已连接的流上交换 DNS 长度前缀与消息；调用方保有通道与清理责任。
 * 出口交付最终目标的流，不在解析器中解释封装。 */
ftun_status_t ftun_dns_query_stream(ftun_control_channel_t *channel,
  ftun_bytes_t wire, uint8_t *response, size_t response_capacity,
  size_t *out_response_size);

#endif
