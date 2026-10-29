#ifndef FTUN_PLATFORM_SOCKET_H
#define FTUN_PLATFORM_SOCKET_H

#include "util/types.h"
#include "platform/protect.h"

#include "platform/poller.h"
#include "platform/posix/error.h"

/* 仅供隔离后的 blocking worker 使用；owner loop 不得调用这些接口。 */
ftun_status_t ftun_blocking_socket_status(int error_code);
bool ftun_blocking_socket_wait(int descriptor, uint32_t events,
                               uint64_t deadline_ms);
bool ftun_blocking_socket_send_all(int descriptor, const uint8_t *data,
                                   size_t length, uint64_t deadline_ms);

#define FTUN_INVALID_SOCKET ((ftun_native_socket_t)UINTPTR_MAX)
typedef enum {
  FTUN_DIAL_TCP = 1,
  FTUN_DIAL_UDP
} ftun_dial_transport_t;

typedef struct {
  ftun_status_t (*open_socket)(void *context, ftun_dial_transport_t transport,
                               ftun_native_socket_t *out);
  ftun_status_t (*protect_socket)(void *context, ftun_native_socket_t socket,
                                  const ftun_socket_policy_t *policy);
  /* connect 只返回 OK、AGAIN 或终结错误。 */
  ftun_status_t (*connect_socket)(void *context, ftun_native_socket_t socket,
                                  const ftun_endpoint_t *endpoint);
  ftun_status_t (*get_socket_error)(void *context, ftun_native_socket_t socket);
  /* close 总是消费 socket，即使返回错误。 */
  ftun_status_t (*close_socket)(void *context, ftun_native_socket_t socket);
  void *context;
} ftun_socket_io_t;
/* 默认表只执行原生 socket 操作；不含准入、网络视图或异步任务策略。 */
const ftun_socket_io_t *ftun_socket_default_io(void);
ftun_status_t ftun_socket_datagram_send(void *context, ftun_native_socket_t socket,
  const void *data, size_t length, size_t *sent);
ftun_status_t ftun_socket_datagram_receive(void *context, ftun_native_socket_t socket,
  void *data, size_t capacity, size_t *received, ftun_endpoint_t *source);
ftun_status_t ftun_socket_close(ftun_native_socket_t socket);
ptrdiff_t ftun_socket_send_nowait(int descriptor, const void *data, size_t length,
  ftun_status_t *status);
ptrdiff_t ftun_socket_receive_nowait(int descriptor, void *data, size_t capacity,
  ftun_status_t *status);
ptrdiff_t ftun_socket_stream_send(int descriptor, const void *data, size_t length,
  ftun_status_t *status);
ptrdiff_t ftun_socket_stream_receive(int descriptor, void *data, size_t capacity,
  ftun_status_t *status);
ftun_status_t ftun_socket_shutdown_write(int descriptor);
ftun_status_t ftun_socket_name(int descriptor, ftun_endpoint_t *out);
/* 同步借用地址/缓冲；open/accept/duplicate 成功交付一个 FD，失败不交付。
 * 监听和接纳的 FD 均为非阻塞、close-on-exec；调用方先完成资源准入。
 * bind_issue 只描述恢复所需的原因，不暴露原生 errno。 */
typedef enum {
  FTUN_SOCKET_BIND_OTHER = 0,
  FTUN_SOCKET_BIND_ADDRESS_UNAVAILABLE,
  FTUN_SOCKET_BIND_PERMISSION
} ftun_socket_bind_issue_t;
ftun_status_t ftun_socket_listen(const ftun_endpoint_t *address,
  ftun_dial_transport_t transport, int backlog, int *out,
  ftun_socket_bind_issue_t *bind_issue);
ftun_status_t ftun_socket_accept(int listener, int *out, ftun_endpoint_t *peer,
  ftun_socket_accept_disposition_t *disposition);
ftun_status_t ftun_socket_duplicate(int descriptor, int *out);
ftun_status_t ftun_socket_pair(int out[2]);
/* 保留零长 UDP 与 recvfrom 的截断语义；收到的数据和来源同步交付。 */
ptrdiff_t ftun_socket_receive_from(int descriptor, void *buffer, size_t capacity,
  ftun_endpoint_t *peer, ftun_status_t *status);
ptrdiff_t ftun_socket_send_to(int descriptor, const void *buffer, size_t length,
  const ftun_endpoint_t *peer, ftun_status_t *status);
/* 仅给隔离的 bootstrap worker 使用；不解析名字、不包含业务授权。 */
ftun_status_t ftun_socket_connect_udp(const ftun_endpoint_t *peer, uint32_t mark,
  int *out);
#endif
