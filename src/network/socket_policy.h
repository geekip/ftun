#ifndef FTUN_NETWORK_SOCKET_POLICY_H
#define FTUN_NETWORK_SOCKET_POLICY_H
#include "internal/contracts.h"

#define FTUN_SOCKET_INTERFACE_BYTES 16u

/* TCP 存活策略（base.timeouts 的套接字部分）：全零表示不设置。 */
typedef struct {
  bool keepalive_enabled;
  uint32_t idle_s;
  uint32_t interval_s;
  uint32_t count;
  /* 已发送的数据在此期限内一直没有被确认则判为失联；0 表示不设置。 */
  uint32_t user_timeout_ms;
} ftun_socket_liveness_t;

/* 所需出口约束由平台实现；协议和通道不依赖平台操作表。 */
struct ftun_socket_policy {
  uint32_t mark;
  ftun_string_t interface_name;
  ftun_socket_liveness_t liveness;
};
#endif
