#ifndef FTUN_NETWORK_SOCKET_POLICY_H
#define FTUN_NETWORK_SOCKET_POLICY_H
#include "internal/contracts.h"

#define FTUN_SOCKET_INTERFACE_BYTES 16u

/* 所需出口约束由平台实现；协议和通道不依赖平台操作表。 */
struct ftun_socket_policy {
  uint32_t mark;
  ftun_string_t interface_name;
};
#endif
