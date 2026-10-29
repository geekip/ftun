#include "platform/posix/error.h"

#include <errno.h>
#include <stdio.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "socket error failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

int main(void)
{
  static const int skipped[] = {ECONNABORTED, ECONNRESET, ECONNREFUSED,
    EPROTO, EPERM, ETIMEDOUT, ENETDOWN, ENETUNREACH, EHOSTDOWN,
    EHOSTUNREACH, ENOPROTOOPT, EOPNOTSUPP};
  static const int fatal[] = {EBADF, EINVAL, ENOTSOCK, EFAULT};
  static const int backoff[] = {EMFILE, ENFILE, ENOBUFS, ENOMEM, EIO, 0};
  size_t index;
  CHECK(ftun_socket_accept_classify(EINTR) == FTUN_SOCKET_ACCEPT_RETRY);
  CHECK(ftun_socket_accept_classify(EAGAIN) == FTUN_SOCKET_ACCEPT_DRAINED);
  CHECK(ftun_socket_accept_classify(EWOULDBLOCK) == FTUN_SOCKET_ACCEPT_DRAINED);
  for (index = 0u; index < sizeof(skipped) / sizeof(skipped[0]); index++) {
    CHECK(ftun_socket_accept_classify(skipped[index]) == FTUN_SOCKET_ACCEPT_SKIP);
  }
#if defined(ENONET)
  CHECK(ftun_socket_accept_classify(ENONET) == FTUN_SOCKET_ACCEPT_SKIP);
#endif
  for (index = 0u; index < sizeof(fatal) / sizeof(fatal[0]); index++) {
    CHECK(ftun_socket_accept_classify(fatal[index]) == FTUN_SOCKET_ACCEPT_FATAL);
  }
  /* 资源不足和未知错误都只退避，不升级为监听或进程故障。 */
  for (index = 0u; index < sizeof(backoff) / sizeof(backoff[0]); index++) {
    CHECK(ftun_socket_accept_classify(backoff[index]) == FTUN_SOCKET_ACCEPT_BACKOFF);
  }
  puts("Socket accept errors: retry, drained, per-connection skip, bounded backoff and fatal classes passed");
  return 0;
}
