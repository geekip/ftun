#ifndef FTUN_OUTBOUND_REJECT_H
#define FTUN_OUTBOUND_REJECT_H

#include "internal/contracts.h"

typedef enum {
  FTUN_REJECT_TCP_REFUSE = 1,
  FTUN_REJECT_UDP_DROP,
  FTUN_REJECT_DNS_REFUSED
} ftun_reject_action_t;

typedef struct {
  ftun_reject_action_t action;
  ftun_status_t terminal_status;
  uint8_t dns_rcode;
} ftun_reject_result_t;

/* 策略拒绝。
 * 需求 REQ-OUT-001；任务 TASK-OUTBOUND-003；目标 0.2.0；验收 TEST-OUTBOUND-003。
 * dns_query=true 只接受 NETWORK 未知的 DNS 阶段 Metadata，返回 RCODE REFUSED；
 * 业务 TCP 映射为显式拒绝，UDP 映射为静默丢包。所有动作的内部终结状态均为
 * REJECTED；调用方按 action 生成协议响应，函数本身不创建 socket 或异步操作。
 */
ftun_status_t ftun_reject_classify(const ftun_metadata_t *metadata,
                                   bool dns_query,
                                   ftun_reject_result_t *out);
/* 兼容业务入口；成功分类后直接返回 REJECTED，DNS 调用方使用 classify。 */
ftun_status_t ftun_reject_request(const ftun_metadata_t *metadata);

#endif
