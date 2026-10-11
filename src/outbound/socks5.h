#ifndef FTUN_OUTBOUND_SOCKS5_H
#define FTUN_OUTBOUND_SOCKS5_H

#include "protocol/socks5.h"
#include "transport/dialer.h"

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
  ftun_socket_policy_t protection;
  uint64_t deadline_ms;
  ftun_dial_transport_t transport;
  ftun_socks5_completion_fn completion;
  void *user;
} ftun_socks5_connect_request_t;

typedef struct {
  ftun_dial_transport_t transport;
  ftun_native_socket_t control_socket;
  ftun_native_socket_t data_socket;
  ftun_endpoint_t target;
  ftun_endpoint_t relay;
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
 * 需求 REQ-OUT-001；任务 TASK-OUTBOUND-004；目标 0.2.0；验收 TEST-OUTBOUND-004。
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
/* TCP 成功后把已协商的数据 socket 转移给统一 Relay，并消费 connection。
 * UDP association 不能经此入口拆分控制/数据 socket。 */
ftun_status_t ftun_socks5_connection_take_tcp(
  ftun_socks5_connection_t **connection, ftun_native_socket_t *out);
/* close 总是消费 connection，并尝试关闭控制与数据 socket。 */
ftun_status_t ftun_socks5_connection_close(
  ftun_socks5_connection_t **connection);

#endif
