#ifndef FTUN_PROXY_OUTBOUND_DIRECT_H
#define FTUN_PROXY_OUTBOUND_DIRECT_H
#include "transport/dialer.h"

struct ftun_direct_request {
  ftun_event_loop_t *loop;
  ftun_operation_queue_t *operations;
  ftun_budget_t *budget;
  const ftun_target_t *target;
  const ftun_network_view_t *network_view;
  uint64_t network_generation;
  ftun_dial_domain_t requested_domain;
  ftun_socket_policy_t protection;
  uint64_t deadline_ms;
  ftun_dial_transport_t transport;
  ftun_dial_completion_fn completion;
  void *user;
};

/* 直连出口。
 * 需求 REQ-OUT-001；任务 TASK-OUTBOUND-002；目标 0.2.0；验收 TEST-OUTBOUND-002。
 * 使用受保护 Dialer；仅当本次没有任何真实候选时返回 RESOLVE。
 * TCP 只在已固定 allowed 集合内串行重试，UDP 只拨号第一个允许目标。
 * 本层不发送业务字节，因此重试不会重放业务数据。
 * request/target/候选/绑定设备在返回前复制；成功 socket 仅在
 * completion 的 OK 结果中转移。同步拒绝清空 out 且零回调。
 */
ftun_status_t ftun_direct_open(ftun_core_t *core,
                               const ftun_direct_request_t *request,
                               ftun_operation_t **out);
/* 测试与受控宿主注入；操作表按值复制。 */
ftun_status_t ftun_direct_open_with_io(ftun_core_t *core,
                                       const ftun_direct_request_t *request,
                                       const ftun_dial_io_t *io,
                                       ftun_operation_t **out);
#endif
