#ifndef FTUN_PROXY_OUTBOUND_SOCKS5_H
#define FTUN_PROXY_OUTBOUND_SOCKS5_H

#include "libs/transport/socks5_codec.h"
#include "libs/transport/path.h"

typedef struct ftun_socks5_connection ftun_socks5_connection_t;

typedef struct {
  ftun_endpoint_t server;
  const ftun_endpoint_t *resolved;
  size_t resolved_count;
  ftun_bytes_t username;
  ftun_bytes_t password;
  bool udp_enabled;
} ftun_socks5_proxy_t;

typedef void (*ftun_socks5_completion_fn)(
  ftun_operation_t *operation, ftun_error_t error,
  ftun_socks5_connection_t *connection, void *user);

typedef struct {
  ftun_event_loop_t *loop;
  ftun_operation_queue_t *operations;
  ftun_budget_t *budget;
  const ftun_socks5_proxy_t *proxy;
  const ftun_target_t *target;
  const ftun_network_view_t *network_view;
  uint64_t network_generation;
  ftun_dial_domain_t requested_domain;
  ftun_socket_policy_t protection;
  uint64_t deadline_ms;
  ftun_dial_transport_t transport;
  ftun_socks5_completion_fn completion;
  void *user;
  /* 拥有型控制通道；scope 必须与 target 同代。握手使用 Stream，
   * 完成后 connection 继续拥有 Path 与通知状态，直至 close 成功。
   * stream 的 budget/operations 可为空，沿用本请求；用户回调不能内联
   * 销毁通知栈中的对象，须安排 owner 后续清理。 */
  ftun_path_scope_t *scope;
  ftun_stream_options_t stream;
  ftun_datagram_options_t datagram;
  ftun_path_notify_fn notify;
  void *notify_user;
} ftun_socks5_connect_request_t;

typedef struct {
  ftun_dial_transport_t transport;
  ftun_native_socket_t control_socket;
  ftun_native_socket_t data_socket;
  ftun_endpoint_t target;
  ftun_endpoint_t relay;
  ftun_dial_domain_t proxy_domain;
  uint64_t network_generation;
} ftun_socks5_connection_info_t;

typedef struct {
  /* OK 必须产生 1..length 字节；AGAIN 和 EOF 产生零字节。 */
  ftun_status_t (*send_socket)(void *context, ftun_native_socket_t socket,
                               const void *data, size_t length,
                               size_t *out_sent);
  ftun_status_t (*receive_socket)(void *context, ftun_native_socket_t socket,
                                  void *data, size_t capacity,
                                  size_t *out_received);
  void *context;
} ftun_socks5_io_t;

/* SOCKS5 出站。
 * 代理节点必须先成为本次真实 IPv4 候选，再由受保护 Dialer
 * 建立控制 TCP。目标已有真实 allowed 候选时发送 IPv4，只有完全
 * 没有真实候选时才允许发送 DOMAIN。UDP 关联同时保留控制 TCP
 * 和已连接到回复 relay 的受保护 UDP socket。
 * request/proxy/target/认证和保护策略在返回前复制。同步拒绝清空
 * out 且零回调；接纳后由 Event/Operation 恰好一次终结。
 * OK 回调把 connection 所有权转移给调用方，最终必须 close。
 */
ftun_status_t ftun_socks5_connect(
  ftun_core_t *core, const ftun_socks5_connect_request_t *request,
  ftun_operation_t **out);

/* 测试与受控宿主注入；两组操作表都按值复制。 */
ftun_status_t ftun_socks5_connect_with_io(
  ftun_core_t *core, const ftun_socks5_connect_request_t *request,
  const ftun_dial_io_t *dial_io, const ftun_socks5_io_t *protocol_io,
  ftun_operation_t **out);

/* socket 只借用至 connection close，不由调用方单独关闭。 */
ftun_status_t ftun_socks5_connection_get_info(
  const ftun_socks5_connection_t *connection,
  ftun_socks5_connection_info_t *out);
/* UDP 编码使用已固定 target；解码前先核验物理报文来源等于 relay。 */
ftun_status_t ftun_socks5_connection_encode_udp(
  const ftun_socks5_connection_t *connection, ftun_bytes_t payload,
  uint8_t *output, size_t capacity, size_t *written);
ftun_status_t ftun_socks5_connection_decode_udp(
  const ftun_socks5_connection_t *connection,
  const ftun_endpoint_t *physical_source, ftun_bytes_t input,
  ftun_socks5_udp_datagram_t *out, size_t *consumed);
/* 拥有型 TCP 成功后的借用 Path，生命期由 connection 保证；不能转移或
 * 单独 destroy。Relay 等额外 Stream 引用必须先释放，再 close connection。 */
ftun_status_t ftun_socks5_connection_path(ftun_socks5_connection_t *connection,
  ftun_path_t **out);
/* 拥有型 UDP 关联的逻辑 Datagram，封装/来源及固定目标核验归协议对象。
 * 通道仅借用，不能单独 destroy。接收回调返回 AGAIN 后由 resume 恢复。 */
ftun_status_t ftun_socks5_connection_channel(ftun_socks5_connection_t *connection,
  ftun_channel_t **out);
ftun_status_t ftun_socks5_connection_resume(ftun_socks5_connection_t *connection);
/* native close 消费 connection；拥有型 close 失败保留 Path、通道与回调状态
 * 供重试，成功才消费 connection。 */
ftun_status_t ftun_socks5_connection_close(
  ftun_socks5_connection_t **connection);

#endif
