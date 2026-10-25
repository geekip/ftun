#ifndef FTUN_PROXY_INBOUND_ADAPTER_H
#define FTUN_PROXY_INBOUND_ADAPTER_H

#include "proxy/inbound/inbound.h"
#include "protocol/socks5.h"
#include "transport/stream.h"

typedef struct ftun_inbound_adapter ftun_inbound_adapter_t;
typedef enum {
  FTUN_INBOUND_EVENT_NONE = 0,
  FTUN_INBOUND_EVENT_CONNECT,
  FTUN_INBOUND_EVENT_ASSOCIATE
} ftun_inbound_event_kind_t;

typedef struct {
  ftun_inbound_event_kind_t kind;
  ftun_endpoint_t target; /* 域名借用 adapter，Session 接纳时复制。 */
  ftun_buffer_slice_t preread; /* 拥有值，调用方最终 release；不会重复交付。 */
} ftun_inbound_event_t;

typedef struct {
  uint64_t deadline_ms;
  bool reply_pending;
  bool close_after_reply;
  bool waiting_downstream;
  bool stopped;
  /* 已接纳的写等待完成，不应再用可写事件驱动同一份回复。 */
  bool write_pending;
} ftun_inbound_adapter_info_t;

/* 同一 owner 的生产入站协调器：保留 client、复制协议/凭据，不读取路由
 * 配置。wakeup 只能安排后续 drive，不得内联 drive/destroy。user 存活到
 * adapter destroy；readable 只控制新读，已有缓冲和回复可无网络事件推进。 */
ftun_status_t ftun_inbound_adapter_create(ftun_stream_t *client,
  const ftun_inbound_spec_t *spec, uint64_t handshake_deadline_ms,
  uint64_t reply_timeout_ms, void (*wakeup)(void *), void *user,
  ftun_inbound_adapter_t **out);
/* 可选池必须同根、同 owner，宿主在 adapter 及所有预读/回复引用释放后
 * 才能销毁它；缓存仍按池的真实拥有者计量。 */
ftun_status_t ftun_inbound_adapter_create_with_pool(ftun_stream_t *client,
  const ftun_inbound_spec_t *spec, ftun_buffer_pool_t *pool,
  uint64_t handshake_deadline_ms, uint64_t reply_timeout_ms,
  void (*wakeup)(void *), void *user, ftun_inbound_adapter_t **out);
ftun_status_t ftun_inbound_adapter_drive(ftun_inbound_adapter_t *adapter,
  bool readable, ftun_inbound_event_t *out);
ftun_status_t ftun_inbound_adapter_finish(ftun_inbound_adapter_t *adapter,
  ftun_status_t downstream, const ftun_endpoint_t *bound);
ftun_status_t ftun_inbound_adapter_udp(ftun_inbound_adapter_t *adapter,
  ftun_bytes_t packet, ftun_socks5_udp_datagram_t *out);
ftun_status_t ftun_inbound_adapter_get_info(const ftun_inbound_adapter_t *adapter,
  ftun_inbound_adapter_info_t *out);
/* 只取消本 adapter 的回复，不停止共享队列/其他流；取消失败保留状态。
 * destroy 要求 stop 且回复 completion 已派发，失败保留拥有者句柄。 */
ftun_status_t ftun_inbound_adapter_stop(ftun_inbound_adapter_t *adapter);
ftun_status_t ftun_inbound_adapter_destroy(ftun_inbound_adapter_t **adapter);

#endif
