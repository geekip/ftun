#define _GNU_SOURCE 1

#include "platform/socket_liveness.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "socket liveness failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

static int option(int descriptor, int level, int name)
{
  int value = -1;
  socklen_t length = (socklen_t)sizeof(value);
  if (getsockopt(descriptor, level, name, &value, &length) != 0) return -2;
  return value;
}

/* 回环 TCP 连接对：发送方填满对端接收窗口后，积压不为零且确认不再前进；
 * 对端读走一部分后确认继续增长（慢速但有进展）。 */
static int test_send_progress(void)
{
  struct sockaddr_in address = {0};
  socklen_t length = (socklen_t)sizeof(address);
  int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
  int sender = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
  int receiver;
  char chunk[4096] = {0};
  uint64_t acked = 0u, later = 0u;
  uint32_t queued = 0u;
  int size = 4096;
  CHECK(listener >= 0 && sender >= 0);
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0 &&
        listen(listener, 1) == 0 &&
        getsockname(listener, (struct sockaddr *)&address, &length) == 0);
  /* 小缓冲让窗口很快变零。 */
  CHECK(setsockopt(listener, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) == 0);
  CHECK(setsockopt(sender, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0);
  CHECK(connect(sender, (struct sockaddr *)&address, sizeof(address)) == 0);
  receiver = accept(listener, NULL, NULL);
  CHECK(receiver >= 0);
  CHECK(ftun_socket_send_progress(sender, &acked, &queued) == FTUN_OK && queued == 0u);
  for (int round = 0; round < 4096; round++) {
    ssize_t written = send(sender, chunk, sizeof(chunk), MSG_DONTWAIT);
    if (written < 0) break;
  }
  CHECK(ftun_socket_send_progress(sender, &acked, &queued) == FTUN_OK && queued > 0u);
  CHECK(ftun_socket_send_progress(sender, &later, &queued) == FTUN_OK && later == acked);
  CHECK(recv(receiver, chunk, sizeof(chunk), 0) > 0);
  nanosleep(&(struct timespec){0, 200000000}, NULL);
  CHECK(ftun_socket_send_progress(sender, &later, &queued) == FTUN_OK && later > acked);
  CHECK(ftun_socket_send_progress(-1, &later, &queued) == FTUN_E_INVALID);
  CHECK(ftun_socket_send_progress(sender, NULL, &queued) == FTUN_E_INVALID);
  CHECK(close(receiver) == 0 && close(sender) == 0 && close(listener) == 0);
  return 0;
}

int main(void)
{
  CHECK(test_send_progress() == 0);
  ftun_socket_liveness_t liveness = {0};
  int stream = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
  int other = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
  CHECK(stream >= 0 && other >= 0);

  /* 全零策略什么也不改。 */
  CHECK(ftun_socket_apply_liveness(stream, &liveness) == FTUN_OK);
  CHECK(option(stream, SOL_SOCKET, SO_KEEPALIVE) == 0);
  CHECK(option(stream, IPPROTO_TCP, TCP_USER_TIMEOUT) == 0);

  /* 存活探测和确认期限都按策略设置。 */
  liveness.keepalive_enabled = true;
  liveness.idle_s = 30u;
  liveness.interval_s = 15u;
  liveness.count = 4u;
  liveness.user_timeout_ms = 120000u;
  CHECK(ftun_socket_apply_liveness(stream, &liveness) == FTUN_OK);
  CHECK(option(stream, SOL_SOCKET, SO_KEEPALIVE) == 1);
  CHECK(option(stream, IPPROTO_TCP, TCP_KEEPIDLE) == 30);
  CHECK(option(stream, IPPROTO_TCP, TCP_KEEPINTVL) == 15);
  CHECK(option(stream, IPPROTO_TCP, TCP_KEEPCNT) == 4);
  CHECK(option(stream, IPPROTO_TCP, TCP_USER_TIMEOUT) == 120000);

  /* 只关探测、保留确认期限。 */
  liveness.keepalive_enabled = false;
  liveness.user_timeout_ms = 5000u;
  CHECK(ftun_socket_apply_liveness(other, &liveness) == FTUN_OK);
  CHECK(option(other, SOL_SOCKET, SO_KEEPALIVE) == 0);
  CHECK(option(other, IPPROTO_TCP, TCP_USER_TIMEOUT) == 5000);

  /* 参数错误与失效描述符是调用错误。 */
  CHECK(ftun_socket_apply_liveness(-1, &liveness) == FTUN_E_INVALID);
  CHECK(ftun_socket_apply_liveness(stream, NULL) == FTUN_E_INVALID);
  CHECK(close(stream) == 0 && close(other) == 0);
  CHECK(ftun_socket_apply_liveness(stream, &liveness) == FTUN_E_INVALID);
  puts("Socket liveness: keepalive, user timeout and error handling passed");
  return 0;
}
