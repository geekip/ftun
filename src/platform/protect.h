#ifndef FTUN_PLATFORM_PROTECT_H
#define FTUN_PLATFORM_PROTECT_H
#include "util/types.h"

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

/* 原生TCP确认期限是可选增强；DNS仍保持应用层绝对期限。 */
bool ftun_socket_has_user_timeout(void);

/* 所需出口约束由平台实现；协议和通道不依赖平台操作表。 */
struct ftun_socket_policy {
  uint32_t mark;
  ftun_string_t interface_name;
  ftun_socket_liveness_t liveness;
};
#endif
