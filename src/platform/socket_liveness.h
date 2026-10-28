#ifndef FTUN_PLATFORM_SOCKET_LIVENESS_H
#define FTUN_PLATFORM_SOCKET_LIVENESS_H
#include "internal/contracts.h"
#include "network/socket_policy.h"

/* 在已创建的 TCP socket 上设置存活探测与发送确认期限：
 * SO_KEEPALIVE、TCP_KEEPIDLE、TCP_KEEPINTVL、TCP_KEEPCNT，以及 TCP_USER_TIMEOUT
 * （已发送的数据在 user_timeout_ms 内一直没有被确认则由内核关闭连接）。
 * 注意 TCP_USER_TIMEOUT 在零窗口阶段按队首数据的入队时间计时，会关闭慢速但仍在
 * 读取的对端，因此长连接转发（Proxy）不设置它，改由应用层按
 * ftun_socket_send_progress 判定；它只适用于小报文的短连接（如 DNS TCP）。
 * keepalive_enabled 为 false 且 user_timeout_ms 为 0 时什么也不做。 */
ftun_status_t ftun_socket_apply_liveness(int descriptor,
  const ftun_socket_liveness_t *liveness);

/* 发送方向的确认进展：queued 为已写入内核但尚未被对端确认的字节数，
 * acked 为连接建立以来累计被确认的字节数。上层据此判断“有积压且确认长时间
 * 不前进”，慢速但仍在读的对端 acked 会持续增长。内核不支持时返回 UNSUPPORTED。 */
ftun_status_t ftun_socket_send_progress(int descriptor, uint64_t *acked,
  uint32_t *queued);

#endif
