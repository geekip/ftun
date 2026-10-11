#ifndef FTUN_INBOUND_SOCKS5_H
#define FTUN_INBOUND_SOCKS5_H
/* TASK-INBOUND-003 / TEST-INBOUND-003：ftun_socks5_accept，目标 0.4.0。 */
#include "inbound/inbound.h"
#include "protocol/socks5.h"

typedef struct ftun_socks5_server ftun_socks5_server_t;

typedef enum {
  FTUN_SOCKS5_SERVER_METHOD_REPLY = 1,
  FTUN_SOCKS5_SERVER_AUTH_REPLY,
  FTUN_SOCKS5_SERVER_REQUEST,
  FTUN_SOCKS5_SERVER_COMMAND_REPLY
} ftun_socks5_server_event_kind_t;

typedef struct {
  ftun_socks5_server_event_kind_t kind;
  ftun_bytes_t wire; /* 借用 server 内部固定缓冲，下一调用前有效。 */
  ftun_bytes_t preread; /* REQUEST 后已收 TCP payload，借用 server。 */
  ftun_socks5_command_t command;
  ftun_endpoint_t target; /* DOMAIN 借用 server。 */
} ftun_socks5_server_event_t;

/* TASK-INBOUND-003 / TEST-INBOUND-003：每个连接独立持有有界增量状态与认证
 * 副本。feed 每次最多产生一个事件；REQUEST 不含成功响应，必须等下游连接
 * 结果后调用 finish_request。BIND/禁用的 UDP 明确返回
 * 0x07，IPv6 返回 0x08；REQUEST.preread 不丢失握手后字节。 */
ftun_status_t ftun_socks5_server_create(const ftun_inbound_spec_t *spec,
                                        ftun_socks5_server_t **out);
ftun_status_t ftun_socks5_server_feed(ftun_socks5_server_t *server,
                                      ftun_bytes_t input,
                                      size_t *consumed,
                                      ftun_socks5_server_event_t *event);
ftun_status_t ftun_socks5_server_finish_request(
  ftun_socks5_server_t *server, ftun_status_t downstream_status,
  const ftun_endpoint_t *bound, ftun_socks5_server_event_t *event);
ftun_status_t ftun_socks5_server_udp(ftun_socks5_server_t *server,
                                     ftun_bytes_t packet,
                                     ftun_socks5_udp_datagram_t *out);
/* Mixed HTTP Basic 认证复用同一份已拷贝凭据和常量时间比较。 */
ftun_status_t ftun_socks5_server_authorize(
  const ftun_socks5_server_t *server, ftun_bytes_t username,
  ftun_bytes_t password, bool *out);
ftun_status_t ftun_socks5_server_requires_auth(
  const ftun_socks5_server_t *server, bool *out);
ftun_status_t ftun_socks5_server_destroy(ftun_socks5_server_t **server);

/* 为 Stream 建立同一状态机；成功后 server 保留 client，destroy 时释放。 */
ftun_status_t ftun_socks5_accept(ftun_core_t *core, ftun_stream_t *client,
                                 const ftun_inbound_spec_t *spec,
                                 ftun_socks5_server_t **out);
ftun_status_t ftun_socks5_server_pump(ftun_socks5_server_t *server,
                                      ftun_socks5_server_event_t *event);
#endif
