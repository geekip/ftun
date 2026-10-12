#ifndef FTUN_INBOUND_TUN_H
#define FTUN_INBOUND_TUN_H
#include "core/budget.h"
#include "core/operation.h"
#include "transport/datagram.h"
#include "transport/stream.h"
#include "tun/lwip_adapter.h"
#include "tun/tun.h"

typedef struct ftun_tun_ingress_context ftun_tun_ingress_context_t;

typedef enum {
  FTUN_TUN_STREAM_READABLE = 1,
  FTUN_TUN_STREAM_PEER_FIN,
  FTUN_TUN_STREAM_WRITABLE,
  FTUN_TUN_STREAM_CLOSED
} ftun_tun_stream_event_t;

typedef ftun_status_t (*ftun_tun_stream_accept_fn)(
  void *user, const ftun_metadata_t *metadata, ftun_stream_t *stream);
typedef void (*ftun_tun_stream_event_fn)(
  void *user, ftun_stream_t *stream, ftun_tun_stream_event_t event,
  ftun_status_t status);
typedef ftun_status_t (*ftun_tun_datagram_receive_fn)(
  void *user, const ftun_metadata_t *metadata, ftun_datagram_t *channel,
  const ftun_endpoint_t *source, const ftun_packet_t *packet);
typedef ftun_status_t (*ftun_tun_output_fn)(
  void *user, ftun_packet_port_t *port, ftun_bytes_t packet);

typedef struct {
  ftun_core_t *core;
  ftun_packet_port_t *port;
  ftun_budget_t *budget;
  ftun_operation_queue_t *operations;
  uint64_t generation;
  uint64_t now_ms;
  uint32_t inbound_id;
  uint32_t mtu;
  size_t max_pending_stream_writes;
  size_t max_pending_stream_bytes;
  size_t max_pending_datagrams;
  size_t max_pending_datagram_bytes;
  bool tcp;
  bool udp;
  ftun_completion_fn stream_write_completion;
  ftun_tun_stream_accept_fn stream_accept;
  ftun_tun_stream_event_fn stream_event;
  ftun_tun_datagram_receive_fn datagram_receive;
  ftun_tun_output_fn output;
  void *user;
} ftun_tun_ingress_spec_t;

typedef struct {
  size_t tcp_streams;
  size_t udp_channels;
  bool accepting;
  bool corrupt;
} ftun_tun_ingress_usage_t;

/* TUN 到协议栈入口。
 * 需求 REQ-IN-001；任务 TASK-INBOUND-005；目标 0.2.0；验收 TEST-INBOUND-005。
 * 实现路径：保留来源、设备身份及完整 IP 包；仅支持 IPv4 TCP/UDP；将包交 lwIP，生成统一 Stream/Datagram。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * bind 创建唯一 owner-loop 上下文；输入同步借用，lwIP 在返回前取得独立
 * slice 引用。TCP accept 成功后 Stream 初始引用交给回调；UDP Datagram 仍由
 * ingress 拥有。close 会停止 Stream，须由接纳方销毁后重试 close。
 */
ftun_status_t ftun_tun_ingress_bind(
  const ftun_tun_ingress_spec_t *spec, ftun_tun_ingress_context_t **out);
ftun_status_t ftun_tun_ingress(ftun_core_t *core, ftun_packet_port_t *port,
                               ftun_packet_t *packet);
ftun_status_t ftun_tun_ingress_tick(ftun_tun_ingress_context_t *context,
                                    uint64_t now_ms);
/* owner loop 异常终止：中止 PCB，并立即完成保留的写令牌。
 * 正常半关闭仍由 Stream/Relay 继续排空。 */
ftun_status_t ftun_tun_ingress_abort_stream(
  ftun_tun_ingress_context_t *context, ftun_stream_t *stream);
ftun_status_t ftun_tun_ingress_stream_ready(
  ftun_tun_ingress_context_t *context, ftun_stream_t *stream,
  bool *readable, bool *writable);
/* 事务重载提交后只影响后续新 flow；已有 Stream/Datagram 已固定旧代。 */
ftun_status_t ftun_tun_ingress_set_generation(
  ftun_tun_ingress_context_t *context, uint64_t generation);
ftun_status_t ftun_tun_ingress_set_identity(
  ftun_tun_ingress_context_t *context, uint64_t generation,
  uint32_t inbound_id);
ftun_status_t ftun_tun_ingress_get_usage(
  const ftun_tun_ingress_context_t *context, ftun_tun_ingress_usage_t *out);
ftun_status_t ftun_tun_ingress_close(ftun_tun_ingress_context_t **context);
#endif
