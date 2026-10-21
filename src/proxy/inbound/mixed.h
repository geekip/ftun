#ifndef FTUN_PROXY_INBOUND_MIXED_H
#define FTUN_PROXY_INBOUND_MIXED_H
/* TASK-INBOUND-002 / TEST-INBOUND-002：ftun_mixed_accept，目标 0.4.0。 */
#include "proxy/inbound/inbound.h"
#include "proxy/inbound/socks5.h"
#include "protocol/http.h"

typedef struct ftun_mixed_connection ftun_mixed_connection_t;

typedef enum {
  FTUN_MIXED_PROTOCOL_SOCKS5 = 1,
  FTUN_MIXED_PROTOCOL_HTTP
} ftun_mixed_protocol_t;

typedef enum {
  FTUN_MIXED_EVENT_HTTP_REQUEST = 1,
  FTUN_MIXED_EVENT_HTTP_BODY,
  FTUN_MIXED_EVENT_HTTP_REPLY,
  FTUN_MIXED_EVENT_SOCKS5
} ftun_mixed_event_kind_t;

typedef struct {
  ftun_mixed_event_kind_t kind;
  ftun_http_request_t http;
  ftun_socks5_server_event_t socks5;
  ftun_bytes_t wire; /* HTTP header+预读 body、body chunk 或响应。 */
  uint64_t body_remaining;
} ftun_mixed_event_t;

/* 有界首字节分流；空输入为 AGAIN，SOCKS 固定 0x05，HTTP 必须以合法大写
 * method token 开始，TLS/控制字节和未知协议明确拒绝。 */
ftun_status_t ftun_mixed_classify(ftun_bytes_t input,
                                  ftun_mixed_protocol_t *out);

ftun_status_t ftun_mixed_connection_create(const ftun_inbound_spec_t *spec,
                                            ftun_mixed_connection_t **out);
ftun_status_t ftun_mixed_connection_feed(ftun_mixed_connection_t *connection,
                                         ftun_bytes_t input,
                                         size_t *consumed,
                                         ftun_mixed_event_t *event);
/* HTTP REQUEST 下游已按本次目标完成选路/连接后调用。CONNECT 成功在此生成
 * 200，普通请求进入有界 body 透传；失败生成 403/502 并关闭。 */
ftun_status_t ftun_mixed_http_finish(ftun_mixed_connection_t *connection,
                                     ftun_status_t downstream_status,
                                     ftun_mixed_event_t *event);
ftun_status_t ftun_mixed_socks5_finish_request(
  ftun_mixed_connection_t *connection, ftun_status_t downstream_status,
  const ftun_endpoint_t *bound, ftun_mixed_event_t *event);
ftun_status_t ftun_mixed_socks5_udp(ftun_mixed_connection_t *connection,
                                    ftun_bytes_t packet,
                                    ftun_socks5_udp_datagram_t *out);
ftun_status_t ftun_mixed_connection_destroy(ftun_mixed_connection_t **connection);

/* TASK-INBOUND-002 / TEST-INBOUND-002：从 Stream 增量读取并调用共享 SOCKS5
 * 或 HTTP parser。该入口只完成协议准入；统一协调层随后按解析出的每个 HTTP
 * 请求重新创建 Metadata/Session，不把首个目标固定到 keep-alive 连接。 */
ftun_status_t ftun_mixed_accept(ftun_core_t *core, ftun_stream_t *client, const ftun_inbound_spec_t *spec);
#endif
