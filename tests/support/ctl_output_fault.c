#define _POSIX_C_SOURCE 200809L
#include "platform/socket.h"
#include "platform/atomic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static ftun_atomic_u64_t blocked = {UINT64_MAX};
ftun_status_t __real_ftun_socket_close(ftun_native_socket_t);
ftun_status_t __wrap_ftun_socket_close(ftun_native_socket_t socket)
{
  /* 关闭即消费流身份；故障不得污染随后复用同一FD的连接。 */
  uint64_t expected = (uint64_t)socket;
  (void)ftun_atomic_compare_exchange_strong(&blocked, &expected, UINT64_MAX);
  return __real_ftun_socket_close(socket);
}

ptrdiff_t __real_ftun_socket_send_nowait(ftun_handle_t, const void *, size_t, ftun_status_t *);
ptrdiff_t __wrap_ftun_socket_send_nowait(ftun_handle_t socket, const void *data,
  size_t length, ftun_status_t *status)
{
  static unsigned int responses;
  static bool injected;
  const char *mode = getenv("FTUN_CTL_TEST_WRITE");
  struct sockaddr_storage address;
  socklen_t size = sizeof(address);
  if (mode == NULL || getsockname((int)socket, (struct sockaddr *)&address, &size) != 0 ||
      address.ss_family != AF_UNIX) return __real_ftun_socket_send_nowait(socket, data, length, status);
  if (strcmp(mode, "short") == 0) {
    return __real_ftun_socket_send_nowait(socket, data, length > 7u ? 7u : length, status);
  }
  /* 背压持续到连接关闭，不在与服务端相同的5秒边界自行解除。
   * 否则期限前进入、受抢占后恢复的写调用会被注入器错误放行。 */
  if ((uint64_t)socket == ftun_atomic_load(&blocked)) { *status = FTUN_E_AGAIN; return -1; }
  if (!injected && length >= 10u && memcmp(data, "{\"result\":", 10u) == 0 && ++responses == 2u) {
    injected = true;
    fputs("ctl write injection armed\n", stderr);
    if (strcmp(mode, "error") == 0) { *status = FTUN_E_IO; return -1; }
    if (strcmp(mode, "kernel") == 0) {
      int capacity = 1024;
      if (setsockopt((int)socket, SOL_SOCKET, SO_SNDBUF, &capacity, sizeof(capacity)) != 0) abort();
      return __real_ftun_socket_send_nowait(socket, data, length, status);
    }
    ftun_atomic_store(&blocked, (uint64_t)socket);
    *status = FTUN_E_AGAIN;
    return -1;
  }
  return __real_ftun_socket_send_nowait(socket, data, length, status);
}
