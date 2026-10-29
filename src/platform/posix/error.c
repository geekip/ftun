#include "platform/posix/error.h"

#include <errno.h>

ftun_socket_accept_disposition_t ftun_socket_accept_classify(int error_code)
{
  switch (error_code) {
    case EINTR:
      return FTUN_SOCKET_ACCEPT_RETRY;
    case EAGAIN:
#if EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
      return FTUN_SOCKET_ACCEPT_DRAINED;
    /* Linux 会把新连接上已挂起的网络错误由 accept 返回，防火墙拒绝返回
     * EPERM；这些只影响被出队的那一个连接，监听继续可用。 */
    case ECONNABORTED:
    case ECONNRESET:
    case ECONNREFUSED:
    case EPROTO:
    case EPERM:
    case ETIMEDOUT:
    case ENETDOWN:
    case ENETUNREACH:
    case EHOSTDOWN:
    case EHOSTUNREACH:
    case ENOPROTOOPT:
    case EOPNOTSUPP:
#if defined(ENONET)
    case ENONET:
#endif
      return FTUN_SOCKET_ACCEPT_SKIP;
    case EBADF:
    case EINVAL:
    case ENOTSOCK:
    case EFAULT:
      return FTUN_SOCKET_ACCEPT_FATAL;
    case EMFILE:
    case ENFILE:
    case ENOBUFS:
    case ENOMEM:
    default:
      /* 未知错误不能确定是否已出队，用退避避免热循环，也不升级为进程退出。 */
      return FTUN_SOCKET_ACCEPT_BACKOFF;
  }
}
