#define _GNU_SOURCE 1

#include "platform/socket_liveness.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

static ftun_status_t ftun_socket_option(int descriptor, int level, int name,
                                        int value)
{
  if (setsockopt(descriptor, level, name, &value, (socklen_t)sizeof(value)) != 0) {
    return errno == EBADF || errno == ENOTSOCK ? FTUN_E_INVALID : FTUN_E_IO;
  }
  return FTUN_OK;
}

ftun_status_t ftun_socket_apply_liveness(int descriptor,
  const ftun_socket_liveness_t *liveness)
{
  ftun_status_t status = FTUN_OK;
  if (descriptor < 0 || liveness == NULL) return FTUN_E_INVALID;
  if (liveness->keepalive_enabled) {
    status = ftun_socket_option(descriptor, SOL_SOCKET, SO_KEEPALIVE, 1);
#if defined(TCP_KEEPIDLE)
    if (status == FTUN_OK) status = ftun_socket_option(descriptor, IPPROTO_TCP,
      TCP_KEEPIDLE, (int)liveness->idle_s);
#endif
#if defined(TCP_KEEPINTVL)
    if (status == FTUN_OK) status = ftun_socket_option(descriptor, IPPROTO_TCP,
      TCP_KEEPINTVL, (int)liveness->interval_s);
#endif
#if defined(TCP_KEEPCNT)
    if (status == FTUN_OK) status = ftun_socket_option(descriptor, IPPROTO_TCP,
      TCP_KEEPCNT, (int)liveness->count);
#endif
  }
#if defined(TCP_USER_TIMEOUT)
  if (status == FTUN_OK && liveness->user_timeout_ms != 0u) {
    status = ftun_socket_option(descriptor, IPPROTO_TCP, TCP_USER_TIMEOUT,
                                (int)liveness->user_timeout_ms);
  }
#endif
  return status;
}

/* 内核 struct tcp_info 的稳定 ABI：tcpi_bytes_acked 是偏移 120 处的 u64。
 * 不使用 libc 的 struct tcp_info（glibc 与部分 musl 版本缺这个字段，
 * 也不依赖 linux/tcp.h 是否存在于交叉工具链）。 */
#define FTUN_TCPI_BYTES_ACKED_OFFSET 120u
#define FTUN_TCP_INFO_BUFFER_BYTES 256u

ftun_status_t ftun_socket_send_progress(int descriptor, uint64_t *acked,
  uint32_t *queued)
{
#if defined(TCP_INFO) && defined(TIOCOUTQ)
  unsigned char info[FTUN_TCP_INFO_BUFFER_BYTES];
  socklen_t length = (socklen_t)sizeof(info);
  int outstanding = 0;
  if (descriptor < 0 || acked == NULL || queued == NULL) return FTUN_E_INVALID;
  memset(info, 0, sizeof(info));
  if (getsockopt(descriptor, IPPROTO_TCP, TCP_INFO, info, &length) != 0 ||
      ioctl(descriptor, TIOCOUTQ, &outstanding) != 0) {
    return errno == EBADF || errno == ENOTSOCK ? FTUN_E_INVALID : FTUN_E_IO;
  }
  if (length < FTUN_TCPI_BYTES_ACKED_OFFSET + sizeof(*acked)) return FTUN_E_UNSUPPORTED;
  memcpy(acked, info + FTUN_TCPI_BYTES_ACKED_OFFSET, sizeof(*acked));
  *queued = outstanding < 0 ? 0u : (uint32_t)outstanding;
  return FTUN_OK;
#else
  (void)descriptor; (void)acked; (void)queued;
  return FTUN_E_UNSUPPORTED;
#endif
}
