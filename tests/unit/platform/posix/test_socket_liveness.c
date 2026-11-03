#define _GNU_SOURCE 1

#include <sys/types.h>
#include "platform/socket.h"
#include "util/endpoint.h"

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

/* 在监听套接字上先于 listen 设置存活参数，接入连接继承；平台不继承或策略不适用时
 * 监听套接字仍可用且 inherited 为 false，调用方回退逐连接设置。 */
static int test_listen_inherits_liveness(void)
{
  ftun_endpoint_t endpoint;
  ftun_socket_liveness_t liveness = {.keepalive_enabled = true, .idle_s = 30u, .interval_s = 15u, .count = 4u};
  ftun_handle_t listener = -1;
  ftun_socket_bind_issue_t issue;
  bool inherited = true;
  bool platform = ftun_socket_accept_inherits_liveness();
  struct sockaddr_in address = {0};
  socklen_t length = (socklen_t)sizeof(address);
  int client, accepted;
  memset(&endpoint, 0, sizeof(endpoint));
  endpoint.kind = FTUN_ADDRESS_IPV4;
  endpoint.address[0] = 127u; endpoint.address[3] = 1u;
  /* 本测试环境（Linux）必须继承；其他系统由探测决定，探测结果与下面的观测必须一致。 */
#if defined(__linux__)
  CHECK(platform);
#endif
  CHECK(ftun_socket_listen_liveness(&endpoint, FTUN_DIAL_TCP, 8, &liveness, &listener, &issue, &inherited) == FTUN_OK);
  CHECK(inherited == platform);
  CHECK(getsockname((int)listener, (struct sockaddr *)&address, &length) == 0);
  client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
  CHECK(client >= 0 && connect(client, (struct sockaddr *)&address, sizeof(address)) == 0);
  accepted = accept((int)listener, NULL, NULL);
  CHECK(accepted >= 0);
  if (inherited) {
    CHECK(option(accepted, SOL_SOCKET, SO_KEEPALIVE) == 1);
    CHECK(option(accepted, IPPROTO_TCP, TCP_KEEPIDLE) == 30);
    CHECK(option(accepted, IPPROTO_TCP, TCP_KEEPINTVL) == 15);
    CHECK(option(accepted, IPPROTO_TCP, TCP_KEEPCNT) == 4);
  } else {
    CHECK(option(accepted, SOL_SOCKET, SO_KEEPALIVE) == 0);
  }
  CHECK(close(accepted) == 0 && close(client) == 0);
  /* 撤销后，新接入的连接不再带保活。 */
  CHECK(ftun_socket_clear_liveness(listener) == FTUN_OK);
  CHECK(option((int)listener, SOL_SOCKET, SO_KEEPALIVE) == 0);
  client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
  CHECK(client >= 0 && connect(client, (struct sockaddr *)&address, sizeof(address)) == 0);
  accepted = accept((int)listener, NULL, NULL);
  CHECK(accepted >= 0 && option(accepted, SOL_SOCKET, SO_KEEPALIVE) == 0);
  CHECK(ftun_socket_clear_liveness(-1) == FTUN_E_INVALID);
  CHECK(close(accepted) == 0 && close(client) == 0 && close((int)listener) == 0);
  /* 不适用的策略：未启用保活、或带确认期限，监听套接字不被改动，inherited 为 false。 */
  {
    ftun_socket_liveness_t off = {0};
    ftun_socket_liveness_t timed = liveness;
    timed.user_timeout_ms = 1000u;
    inherited = true;
    CHECK(ftun_socket_listen_liveness(&endpoint, FTUN_DIAL_TCP, 8, &off, &listener, &issue, &inherited) == FTUN_OK);
    CHECK(!inherited && option((int)listener, SOL_SOCKET, SO_KEEPALIVE) == 0);
    CHECK(close((int)listener) == 0);
    inherited = true;
    CHECK(ftun_socket_listen_liveness(&endpoint, FTUN_DIAL_TCP, 8, &timed, &listener, &issue, &inherited) == FTUN_OK);
    CHECK(!inherited && option((int)listener, SOL_SOCKET, SO_KEEPALIVE) == 0);
    CHECK(close((int)listener) == 0);
    /* UDP 与空策略同样不受影响。 */
    inherited = true;
    CHECK(ftun_socket_listen_liveness(&endpoint, FTUN_DIAL_UDP, 0, &liveness, &listener, &issue, &inherited) == FTUN_OK);
    CHECK(!inherited);
    CHECK(close((int)listener) == 0);
    inherited = true;
    CHECK(ftun_socket_listen_liveness(&endpoint, FTUN_DIAL_TCP, 8, NULL, &listener, &issue, &inherited) == FTUN_OK);
    CHECK(!inherited && option((int)listener, SOL_SOCKET, SO_KEEPALIVE) == 0);
    CHECK(close((int)listener) == 0);
  }
  return 0;
}

int main(void)
{
  CHECK(test_send_progress() == 0);
  CHECK(test_listen_inherits_liveness() == 0);
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
