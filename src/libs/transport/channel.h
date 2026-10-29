#ifndef FTUN_LIBS_TRANSPORT_CHANNEL_H
#define FTUN_LIBS_TRANSPORT_CHANNEL_H
#include "libs/transport/stream.h"
#include "libs/transport/datagram.h"
#include "platform/socket.h"
typedef struct ftun_channel ftun_channel_t;
typedef struct {
  ftun_dial_transport_t transport;
  size_t pending_items;
  size_t pending_bytes;
  size_t references;
  bool accepting;
  bool in_callback;
  bool in_backend;
} ftun_channel_usage_t;
/* Channel 是同一 owner 上的唯一数据通道，内嵌于 Path 或协议连接，不额外分配。
 * 借用者不得复制或销毁 owner；操作保留 Stream/Datagram 的原有准入、完成和取消语义。
 * 字节流接纳前缀并由 Operation 派发完成；报文整包接纳，沿创建时的回调交付结果。
 * 类型不符返回 UNSUPPORTED，所有同步拒绝零接纳、零回调，不改变任何拥有权。 */
ftun_status_t ftun_channel_get_usage(const ftun_channel_t *channel, ftun_channel_usage_t *out);
ftun_dial_transport_t ftun_channel_transport(const ftun_channel_t *channel);
ftun_status_t ftun_channel_read(ftun_channel_t *channel, void *buffer, size_t capacity, size_t *length);
ftun_status_t ftun_channel_write_ref(ftun_channel_t *channel,
  const ftun_buffer_slice_t *slice, size_t *accepted, ftun_operation_t **out);
ftun_status_t ftun_channel_write_ref_with_completion(ftun_channel_t *channel,
  const ftun_buffer_slice_t *slice, ftun_completion_fn completion, void *user,
  size_t *accepted, ftun_operation_t **out);
ftun_status_t ftun_channel_shutdown_write(ftun_channel_t *channel);
ftun_status_t ftun_channel_send(ftun_channel_t *channel,
  const ftun_endpoint_t *target, ftun_packet_t *packet);
/* 协议后端交付完整报文；source/packet 仅同步借用。 */
ftun_status_t ftun_channel_deliver(ftun_channel_t *channel,
  const ftun_endpoint_t *source, const ftun_packet_t *packet);
/* 关闭接纳并发起有界取消；失败保留资源，由 owner 继续排空。 */
ftun_status_t ftun_channel_stop(ftun_channel_t *channel);
/* Relay/协议后端需要的窄借用，不转移初始引用，生命期不超过 Channel owner。 */
ftun_status_t ftun_channel_stream(ftun_channel_t *channel, ftun_stream_t **out);
ftun_status_t ftun_channel_datagram(ftun_channel_t *channel, ftun_datagram_t **out);
#endif
