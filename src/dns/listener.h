#ifndef FTUN_DNS_LISTENER_H
#define FTUN_DNS_LISTENER_H

#include "dns/dns.h"

typedef void (*ftun_dns_listener_reply_fn)(
  ftun_dns_transport_t transport, uint64_t peer_id, ftun_error_t error,
  ftun_bytes_t response, void *user);

struct ftun_dns_listener_spec {
  ftun_budget_t *budget;
  ftun_dns_entry_t entry;
  size_t fixed_server;
  uint32_t inbound_id;
  uint64_t query_timeout_ms;
  size_t udp_payload_limit;
  size_t max_tcp_connections;
  size_t max_tcp_inflight;
  size_t max_tcp_frame_bytes;
  ftun_dns_listener_reply_fn reply;
  void *reply_user;
};

typedef struct {
  size_t tcp_connections;
  size_t inflight;
  bool accepting;
} ftun_dns_listener_info_t;

/* UDP 和 TCP DNS 接入。
 * 需求 REQ-DNSWIRE-001；任务 TASK-DNS-003；目标 0.3.0；验收 TEST-DNS-003。
 * listen 建立无平台 fd 的协议接入器，宿主把完整 UDP 数据报或 TCP 字节流
 * 喂入；响应经 reply 返回。UDP 超限时重建仅含 Question 的合法 TC 响应，
 * TCP 处理二字节长度、半包、粘包和每连接在途上限。stop 后关闭新接纳。
 */
ftun_status_t ftun_dns_listen(ftun_core_t *core,
                              const ftun_dns_listener_spec_t *spec,
                              ftun_dns_listener_t **out);
ftun_status_t ftun_dns_listener_receive_udp(ftun_dns_listener_t *listener,
                                            uint64_t peer_id,
                                            ftun_bytes_t datagram,
                                            ftun_operation_t **out);
ftun_status_t ftun_dns_listener_tcp_open(ftun_dns_listener_t *listener,
                                         uint64_t peer_id,
                                         ftun_dns_connection_t **out);
ftun_status_t ftun_dns_connection_feed(ftun_dns_connection_t *connection,
                                       ftun_bytes_t bytes,
                                       size_t *out_consumed,
                                       size_t *out_frames);
/* 有在途请求时返回 AGAIN；成功从 listener 移除并消费连接。 */
ftun_status_t ftun_dns_connection_close(ftun_dns_connection_t **connection);
ftun_status_t ftun_dns_listener_stop(ftun_dns_listener_t *listener);
ftun_status_t ftun_dns_listener_get_info(const ftun_dns_listener_t *listener,
                                         ftun_dns_listener_info_t *out);
ftun_status_t ftun_dns_listener_destroy(ftun_dns_listener_t **listener);

#endif
