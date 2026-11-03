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


/* 仅供隔离后的 blocking worker 或独立命令进程使用；owner loop 不得调用。 */
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
/* 原生SO_ERROR只读一次，立即按值保留系统码；不在清理后查询errno。 */
ftun_error_t ftun_socket_connect_error(ftun_native_socket_t socket);
const char *ftun_socket_error_name(int code);
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
/* accept 出来的 TCP 连接是否继承监听套接字上的存活参数（SO_KEEPALIVE 与
 * TCP_KEEPIDLE/INTVL/CNT）。首次调用在回环上做一次探测并缓存，不靠内核版本猜测；
 * 探测失败（没有回环、描述符不足、平台不支持相关选项）一律按“不继承”处理。 */
bool ftun_socket_accept_inherits_liveness(void);
/* 与 ftun_socket_listen 相同，但对 TCP 先于 listen 把存活参数设到监听套接字上，
 * 接入连接直接继承，省掉每条连接 4 次 setsockopt；先于 listen 设置才不会漏掉
 * listen 与设置之间已完成握手的连接。
 * *inherited 为 true 仅当参数已设置成功且 ftun_socket_accept_inherits_liveness()
 * 为真；此时调用方可以不再对接入连接调用 ftun_socket_apply_liveness。
 * 为 false 时监听套接字照常可用，调用方必须继续逐连接设置。liveness 为空、未启用
 * 保活或 user_timeout_ms 非零（确认期限不走继承路径）时恒为 false，且不改动套接字。 */
ftun_status_t ftun_socket_listen_liveness(const ftun_endpoint_t *address,
  ftun_dial_transport_t transport, int backlog, const ftun_socket_liveness_t *liveness,
  ftun_handle_t *out, ftun_socket_bind_issue_t *bind_issue, bool *inherited);
/* 撤销 ftun_socket_listen_liveness 设在监听套接字上的存活参数（SO_KEEPALIVE 置 0），
 * 此后接入的连接不再从监听套接字得到保活，由调用方按当前策略逐连接设置。
 * 用于存活策略在运行中改变：只靠逐连接设置无法“关闭”已被继承的保活。 */
ftun_status_t ftun_socket_clear_liveness(ftun_handle_t descriptor);
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
