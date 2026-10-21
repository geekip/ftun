#ifndef FTUN_TRANSPORT_BLOCKING_H
#define FTUN_TRANSPORT_BLOCKING_H

#include "internal/contracts.h"

#include <sys/types.h>

/* 仅供隔离后的 blocking worker 使用；owner loop 不得调用这些接口。 */
ftun_status_t ftun_blocking_socket_status(int error_code);
bool ftun_blocking_socket_wait(int descriptor, short events,
                               uint64_t deadline_ms);
bool ftun_blocking_socket_send_all(int descriptor, const uint8_t *data,
                                   size_t length, uint64_t deadline_ms);
bool ftun_blocking_socket_recv_all(int descriptor, uint8_t *data,
                                   size_t length, uint64_t deadline_ms);
ftun_status_t ftun_blocking_socket_connect_ipv4(
  int type, const uint8_t address[4], uint16_t port, uint32_t mark,
  uint64_t deadline_ms, int *out);

#endif
