#ifndef FTUN_PLATFORM_SOCKET_H
#define FTUN_PLATFORM_SOCKET_H

#include "util/types.h"
#include "platform/protect.h"

#include "platform/poller.h"


typedef enum {
  FTUN_SOCKET_ACCEPT_RETRY = 1, /* 被信号打断，立即重试。 */
  FTUN_SOCKET_ACCEPT_DRAINED,   /* 当前没有待接纳连接。 */
  FTUN_SOCKET_ACCEPT_SKIP,      /* 单个待接纳连接失败，监听本身仍可用。 */
  FTUN_SOCKET_ACCEPT_BACKOFF,   /* 资源暂缺或未知错误：有界退避后再接纳。 */
  FTUN_SOCKET_ACCEPT_FATAL      /* 监听句柄本身无效，由调用方按故障域处理。 */
} ftun_socket_accept_disposition_t;


/* 仅供隔离后的 blocking worker 使用；owner loop 不得调用这些接口。 */
ftun_status_t ftun_blocking_socket_status(int error_code);
bool ftun_blocking_socket_wait(ftun_handle_t descriptor, uint32_t events,
                               uint64_t deadline_ms);

#define FTUN_INVALID_SOCKET ((ftun_native_socket_t)UINTPTR_MAX)
typedef enum {
  FTUN_DIAL_TCP = 1,
  FTUN_DIAL_UDP
} ftun_dial_transport_t;

typedef struct {
  ftun_status_t (*open_socket)(void *context, ftun_address_kind_t family, ftun_dial_transport_t transport,
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
ptrdiff_t ftun_socket_send_nowait(ftun_handle_t descriptor, const void *data, size_t length,
  ftun_status_t *status);
ptrdiff_t ftun_socket_receive_nowait(ftun_handle_t descriptor, void *data, size_t capacity,
  ftun_status_t *status);
ptrdiff_t ftun_socket_stream_send(ftun_handle_t descriptor, const void *data, size_t length,
  ftun_status_t *status);
ptrdiff_t ftun_socket_stream_receive(ftun_handle_t descriptor, void *data, size_t capacity,
  ftun_status_t *status);
ftun_status_t ftun_socket_shutdown_write(ftun_handle_t descriptor);
ftun_status_t ftun_socket_name(ftun_handle_t descriptor, ftun_endpoint_t *out);
/* 同步借用地址/缓冲；open/accept/duplicate 成功交付一个 FD，失败不交付。
 * 监听和接纳的 FD 均为非阻塞、close-on-exec；调用方先完成资源准入。
 * bind_issue 只描述恢复所需的原因，不暴露原生 errno。 */
typedef enum {
  FTUN_SOCKET_BIND_OTHER = 0,
  FTUN_SOCKET_BIND_ADDRESS_UNAVAILABLE,
  FTUN_SOCKET_BIND_PERMISSION
} ftun_socket_bind_issue_t;
ftun_status_t ftun_socket_listen(const ftun_endpoint_t *address,
  ftun_dial_transport_t transport, int backlog, ftun_handle_t *out,
  ftun_socket_bind_issue_t *bind_issue);
/* peer可为空：调用方不需要保存对端地址。 */
ftun_status_t ftun_socket_accept(ftun_handle_t listener, ftun_handle_t *out, ftun_endpoint_t *peer,
  ftun_socket_accept_disposition_t *disposition);
ftun_status_t ftun_socket_duplicate(ftun_handle_t descriptor, ftun_handle_t *out);
ftun_status_t ftun_socket_pair(ftun_handle_t out[2]);
/* 保留零长 UDP 与 recvfrom 的截断语义；收到的数据和来源同步交付。 */
ptrdiff_t ftun_socket_receive_from(ftun_handle_t descriptor, void *buffer, size_t capacity,
  ftun_endpoint_t *peer, ftun_status_t *status);
ptrdiff_t ftun_socket_send_to(ftun_handle_t descriptor, const void *buffer, size_t length,
  const ftun_endpoint_t *peer, ftun_status_t *status);
/* 仅给隔离的 bootstrap worker 使用；不解析名字、不包含业务授权。 */
/* 在已创建的 TCP socket 上设置存活探测与发送确认期限：
 * SO_KEEPALIVE、TCP_KEEPIDLE、TCP_KEEPINTVL、TCP_KEEPCNT，以及 TCP_USER_TIMEOUT
 * （已发送的数据在 user_timeout_ms 内一直没有被确认则由内核关闭连接）。
 * 注意 TCP_USER_TIMEOUT 在零窗口阶段按队首数据的入队时间计时，会关闭慢速但仍在
 * 读取的对端，因此长连接转发（Proxy）不设置它，改由应用层按
 * ftun_socket_send_progress 判定；它只适用于小报文的短连接（如 DNS TCP）。
 * keepalive_enabled 为 false 且 user_timeout_ms 为 0 时什么也不做。 */
ftun_status_t ftun_socket_apply_liveness(ftun_handle_t descriptor,
  const ftun_socket_liveness_t *liveness);

/* 发送方向的确认进展：queued 为已写入内核但尚未被对端确认的字节数，
 * acked 为连接建立以来累计被确认的字节数。上层据此判断“有积压且确认长时间
 * 不前进”，慢速但仍在读的对端 acked 会持续增长。内核不支持时返回 UNSUPPORTED。 */
ftun_status_t ftun_socket_send_progress(ftun_handle_t descriptor, uint64_t *acked,
  uint32_t *queued);


#endif
