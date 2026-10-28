#ifndef FTUN_PROXY_TUN_INGRESS_H
#define FTUN_PROXY_TUN_INGRESS_H
#include "core/budget.h"
#include "core/operation.h"
#include "transport/datagram.h"
#include "transport/stream.h"
#include "proxy/tun/lwip_adapter.h"
#include "network/socket_policy.h"
#include "util/buffer.h"

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
  void *user, ftun_bytes_t packet);

typedef struct {
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
  ftun_socket_liveness_t liveness;
  void *user;
} ftun_tun_ingress_spec_t;

typedef struct {
  size_t tcp_streams;
  size_t udp_channels;
  bool accepting;
  bool corrupt;
} ftun_tun_ingress_usage_t;

/* TUN 到协议栈入口。
 * 实现路径：保留来源、设备身份及完整 IP 包；仅支持 IPv4 TCP/UDP；将包交 lwIP，生成统一 Stream/Datagram。
 * 调用边界：不访问配置 AST，不跨线程修改 Session。
 * bind 创建 owner-loop 消费者上下文；输入同步借用，lwIP 在返回前取得独立
 * slice 引用。TCP accept 成功后 Stream 初始引用交给回调；UDP Datagram 仍由
 * ingress 拥有；异步消费者必须 retain，在静默后 release。close 会停止
 * Stream/Datagram，须由接纳方销毁 Stream 或归还 Datagram 引用后重试 close。
 */
ftun_status_t ftun_tun_ingress_bind(
  const ftun_tun_ingress_spec_t *spec, ftun_tun_ingress_context_t **out);
ftun_status_t ftun_tun_ingress(ftun_tun_ingress_context_t *context,
                               ftun_packet_t *packet);
/* TUN service 的整包适配入口。同步借用 bytes，使用共享 Pool 构造拥有型
 * Packet 后再进入实际 lwIP/Proxy ingress。 */
ftun_status_t ftun_tun_ingress_bytes(ftun_tun_ingress_context_t *context,
                                     ftun_buffer_pool_t *buffers,
                                     ftun_bytes_t bytes);
ftun_status_t ftun_tun_ingress_tick(ftun_tun_ingress_context_t *context,
                                    uint64_t now_ms);
ftun_status_t ftun_tun_ingress_next_deadline(
  const ftun_tun_ingress_context_t *context, uint64_t *out_deadline_ms);
/* owner loop 异常终止：中止 PCB，并立即完成保留的写令牌。
 * 正常半关闭仍由 Stream/Relay 继续排空。 */
ftun_status_t ftun_tun_ingress_abort_stream(
  ftun_tun_ingress_context_t *context, ftun_stream_t *stream);
ftun_status_t ftun_tun_ingress_stream_ready(
  ftun_tun_ingress_context_t *context, ftun_stream_t *stream,
  bool *readable, bool *writable);
ftun_status_t ftun_tun_ingress_set_identity(
  ftun_tun_ingress_context_t *context, uint64_t generation,
  uint32_t inbound_id);
ftun_status_t ftun_tun_ingress_can_set_identity(
  ftun_tun_ingress_context_t *context, uint64_t generation,
  uint32_t inbound_id);
ftun_status_t ftun_tun_ingress_get_usage(
  const ftun_tun_ingress_context_t *context, ftun_tun_ingress_usage_t *out);
/* quiesce 仅关闭 IP 输入/输出；不在事件回调内释放消费者。
 * close_step 每次至多处理 quota 个 bridge，未静默对象保留并返回 AGAIN。 */
ftun_status_t ftun_tun_ingress_quiesce(ftun_tun_ingress_context_t *context);
ftun_status_t ftun_tun_ingress_close_step(ftun_tun_ingress_context_t **context,
  size_t quota, size_t *out_work);
ftun_status_t ftun_tun_ingress_close(ftun_tun_ingress_context_t **context);
#endif
