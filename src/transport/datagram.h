#ifndef FTUN_TRANSPORT_DATAGRAM_H
#define FTUN_TRANSPORT_DATAGRAM_H
#include "internal/contracts.h"
#include "core/budget.h"
#include "util/buffer.h"

#define FTUN_DATAGRAM_DOMAIN_BYTES 254u

typedef struct ftun_datagram_send ftun_datagram_send_t;

typedef struct {
  ftun_datagram_t *channel;
  size_t slot;
  uint64_t generation;
} ftun_datagram_send_token_t;

/* Packet 拥有一个 BufferSlice 引用；零长度 payload 是有效报文。 */
struct ftun_packet {
  ftun_buffer_slice_t payload;
  uint32_t source_id;
};

typedef void (*ftun_datagram_result_fn)(ftun_datagram_t *channel,
                                        ftun_error_t error,
                                        const ftun_endpoint_t *target,
                                        const ftun_packet_t *packet,
                                        void *user);
typedef ftun_status_t (*ftun_datagram_receive_fn)(
  ftun_datagram_t *channel, const ftun_endpoint_t *source,
  const ftun_packet_t *packet, void *user);

typedef struct {
  /* OK 表示整包已发送或由 backend 保留；其他状态必须零接纳。
   * backend 可在 start 内 complete OK，回调会延至 start 返回后执行。 */
  ftun_status_t (*send_start)(void *context, ftun_datagram_send_token_t send,
                              const ftun_endpoint_t *target,
                              const ftun_packet_t *packet);
  /* cancel 内不得重入 complete；此时 complete 返回 AGAIN。OK 后 backend
   * 不再访问 send；失败保持所有权，可由 stop 重试。 */
  ftun_status_t (*send_cancel)(void *context, ftun_datagram_send_token_t send);
  void (*destroy)(void *context);
  void *context;
} ftun_datagram_backend_t;

typedef struct {
  ftun_budget_t *budget;
  /* 创建时一次性准入发送槽的内存与队列额度，最终 destroy 才释放。 */
  size_t max_pending_packets;
  size_t max_pending_bytes;
  ftun_datagram_result_fn result;
  ftun_datagram_receive_fn receive;
  void *user;
} ftun_datagram_options_t;

typedef struct {
  size_t max_pending_packets;
  size_t max_pending_bytes;
  size_t pending_packets;
  size_t pending_bytes;
  size_t reference_count;
  size_t completed_packets;
  size_t failed_packets;
  bool accepting;
  bool in_callback;
  bool in_backend;
} ftun_datagram_usage_t;

ftun_status_t ftun_packet_init(ftun_packet_t *packet,
                               const ftun_buffer_slice_t *payload,
                               uint32_t source_id);
ftun_status_t ftun_packet_clone(const ftun_packet_t *source,
                                ftun_packet_t *out);
ftun_status_t ftun_packet_view(const ftun_packet_t *packet, ftun_bytes_t *out);
ftun_status_t ftun_packet_release(ftun_packet_t *packet);

/* 整包发送接口。
 * OK 只表示整包已发送或进入有界 backend 队列，不表示远端收到；AGAIN 和
 * 其他同步错误都完全未接纳。目标、payload 边界和 source_id 在完成前保留。
 * send token 按值复制并带 generation；complete/cancel 成功即为 backend 静默点，
 * 旧 token 在槽位复用后返回 STALE。backend 可在 send_start 内同步 complete OK，
 * result 会在 start 返回后、send 返回前调用；异步完成也在调用 complete 的 owner
 * 栈内调用 result。同一 channel 的 result 回调只允许查询及引用计数操作，返回后再 send、
 * stop 或 destroy。stop 至多访问 max_pending_packets 个条目，cancel 必须有界且
 * 非阻塞；所有 token 静默且回调返回后方可 destroy，destroy 后不得再使用 token。
 */
ftun_status_t ftun_datagram_create(const ftun_datagram_options_t *options,
                                   const ftun_datagram_backend_t *backend,
                                   ftun_datagram_t **out);
ftun_status_t ftun_datagram_send(ftun_datagram_t *channel,
                                 const ftun_endpoint_t *target,
                                 ftun_packet_t *packet);
/* backend 在 start 后可借用所接纳的完整目标和报文。 */
ftun_status_t ftun_datagram_send_view(ftun_datagram_send_token_t send,
                                      const ftun_endpoint_t **target,
                                      const ftun_packet_t **packet);
/* complete 成功后 backend 立即放弃 send；AGAIN 不是终结状态，且 cancel
 * 调用栈内固定返回 AGAIN。 */
ftun_status_t ftun_datagram_send_complete(ftun_datagram_send_token_t send,
                                          ftun_error_t error);
/* 接收同步借用 source/packet，只在 receive 回调期间有效。 */
ftun_status_t ftun_datagram_deliver(ftun_datagram_t *channel,
                                    const ftun_endpoint_t *source,
                                    const ftun_packet_t *packet);
/* 返回创建时借用的 Budget，供 flow 组合器验证统一资源账本。 */
ftun_status_t ftun_datagram_budget(ftun_datagram_t *channel,
                                   ftun_budget_t **out);
/* owner-loop 引用；异步消费者保存通道时 retain，静默后 release。
 * receive/result 回调允许 retain/release；初始所有者引用只能由 destroy 释放。
 * stop 不等待额外引用，destroy 在引用未归还时返回 AGAIN 并保留对象及 backend。 */
ftun_status_t ftun_datagram_retain(ftun_datagram_t *channel);
ftun_status_t ftun_datagram_release(ftun_datagram_t **channel);
/* stop 关闭接纳并取消全部 backend 在途包；取消失败保留待重试项。 */
ftun_status_t ftun_datagram_stop(ftun_datagram_t *channel);
ftun_status_t ftun_datagram_get_usage(const ftun_datagram_t *channel,
                                      ftun_datagram_usage_t *out);
ftun_status_t ftun_datagram_destroy(ftun_datagram_t **channel);

#endif
