#define _GNU_SOURCE 1

#include "platform/socket.h"
#include "platform/atomic.h"
#include "platform/posix/socket_native.h"

#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
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

bool ftun_socket_has_user_timeout(void)
{
#if defined(TCP_USER_TIMEOUT)
  return true;
#else
  return false;
#endif
}
ftun_status_t ftun_socket_apply_liveness(ftun_handle_t descriptor,
  const ftun_socket_liveness_t *liveness)
{
  ftun_status_t status = FTUN_OK;
  if (descriptor < 0 || liveness == NULL) return FTUN_E_INVALID;
  if (liveness->keepalive_enabled) {
    status = ftun_socket_option((int)descriptor, SOL_SOCKET, SO_KEEPALIVE, 1);
#if defined(TCP_KEEPIDLE)
    if (status == FTUN_OK) status = ftun_socket_option((int)descriptor, IPPROTO_TCP,
      TCP_KEEPIDLE, (int)liveness->idle_s);
#elif defined(TCP_KEEPALIVE)
    if (status == FTUN_OK) status = ftun_socket_option((int)descriptor, IPPROTO_TCP,
      TCP_KEEPALIVE, (int)liveness->idle_s);
#endif
#if defined(TCP_KEEPINTVL)
    if (status == FTUN_OK) status = ftun_socket_option((int)descriptor, IPPROTO_TCP,
      TCP_KEEPINTVL, (int)liveness->interval_s);
#endif
#if defined(TCP_KEEPCNT)
    if (status == FTUN_OK) status = ftun_socket_option((int)descriptor, IPPROTO_TCP,
      TCP_KEEPCNT, (int)liveness->count);
#endif
  }
#if defined(TCP_USER_TIMEOUT)
  if (status == FTUN_OK && liveness->user_timeout_ms != 0u) {
    status = ftun_socket_option((int)descriptor, IPPROTO_TCP, TCP_USER_TIMEOUT,
                                (int)liveness->user_timeout_ms);
  }
#else
  if (status == FTUN_OK && liveness->user_timeout_ms != 0u) status = FTUN_E_UNSUPPORTED;
#endif
  return status;
}

ftun_status_t ftun_socket_clear_liveness(ftun_handle_t descriptor)
{
  if (descriptor < 0) return FTUN_E_INVALID;
  return ftun_socket_option((int)descriptor, SOL_SOCKET, SO_KEEPALIVE, 0);
}

/* ---- 接入连接是否继承监听套接字的存活参数 ---- */

#if defined(TCP_KEEPINTVL) && defined(TCP_KEEPCNT) && (defined(TCP_KEEPIDLE) || defined(TCP_KEEPALIVE))
#if defined(TCP_KEEPIDLE)
#define FTUN_PROBE_IDLE_OPTION TCP_KEEPIDLE
#else
#define FTUN_PROBE_IDLE_OPTION TCP_KEEPALIVE
#endif
#define FTUN_PROBE_WAIT_MS 200

static int ftun_socket_probe_option(int descriptor, int level, int name)
{
  int value = -1;
  socklen_t length = (socklen_t)sizeof(value);
  if (getsockopt(descriptor, level, name, &value, &length) != 0) return -1;
  return value;
}

static bool ftun_socket_probe_wait(int descriptor, short events)
{
  struct pollfd entry;
  int result;
  entry.fd = descriptor;
  entry.events = events;
  entry.revents = 0;
  do {
    result = poll(&entry, 1, FTUN_PROBE_WAIT_MS);
  } while (result < 0 && errno == EINTR);
  return result == 1;
}

/* 在回环上建一对真实连接，用与默认值明显不同的参数观察接入连接实际得到什么。
 * 任何一步失败都按“不继承”处理，调用方回退逐连接设置，行为不变。 */
static bool ftun_socket_probe_inheritance(void)
{
  struct sockaddr_in address;
  socklen_t length = (socklen_t)sizeof(address);
  ftun_socket_liveness_t probe = {0};
  int listener, client = -1, accepted = -1;
  bool inherited = false;
  probe.keepalive_enabled = true;
  probe.idle_s = 61u;
  probe.interval_s = 13u;
  probe.count = 3u;
  listener = ftun_posix_socket(AF_INET, SOCK_STREAM, 0);
  if (listener < 0) return false;
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
      getsockname(listener, (struct sockaddr *)&address, &length) != 0 ||
      ftun_socket_apply_liveness((ftun_handle_t)listener, &probe) != FTUN_OK ||
      listen(listener, 1) != 0) goto done;
  client = ftun_posix_socket(AF_INET, SOCK_STREAM, 0);
  if (client < 0) goto done;
  if (connect(client, (struct sockaddr *)&address, sizeof(address)) != 0 &&
      (errno != EINPROGRESS || !ftun_socket_probe_wait(client, POLLOUT))) goto done;
  if (!ftun_socket_probe_wait(listener, POLLIN)) goto done;
  accepted = ftun_posix_accept(listener, NULL, NULL);
  if (accepted < 0) goto done;
  inherited = ftun_socket_probe_option(accepted, SOL_SOCKET, SO_KEEPALIVE) > 0 &&
    ftun_socket_probe_option(accepted, IPPROTO_TCP, FTUN_PROBE_IDLE_OPTION) == (int)probe.idle_s &&
    ftun_socket_probe_option(accepted, IPPROTO_TCP, TCP_KEEPINTVL) == (int)probe.interval_s &&
    ftun_socket_probe_option(accepted, IPPROTO_TCP, TCP_KEEPCNT) == (int)probe.count;
done:
  if (accepted >= 0) (void)close(accepted);
  if (client >= 0) (void)close(client);
  (void)close(listener);
  return inherited;
}
#else
static bool ftun_socket_probe_inheritance(void)
{
  return false;
}
#endif

/* 0 未探测，1 继承，2 不继承。探测结果是幂等的，并发首次调用最多重复探测一次。 */
static ftun_atomic_size_t ftun_socket_inherit_state;

bool ftun_socket_accept_inherits_liveness(void)
{
  size_t state = ftun_atomic_load(&ftun_socket_inherit_state);
  if (state == 0u) {
    state = ftun_socket_probe_inheritance() ? 1u : 2u;
    ftun_atomic_store(&ftun_socket_inherit_state, state);
  }
  return state == 1u;
}

/* 内核 struct tcp_info 的稳定 ABI：tcpi_bytes_acked 是偏移 120 处的 u64。
 * 不使用 libc 的 struct tcp_info（glibc 与部分 musl 版本缺这个字段，
 * 也不依赖 linux/tcp.h 是否存在于交叉工具链）。 */
#define FTUN_TCPI_BYTES_ACKED_OFFSET 120u
#define FTUN_TCP_INFO_BUFFER_BYTES 256u

ftun_status_t ftun_socket_send_progress(ftun_handle_t descriptor, uint64_t *acked,
  uint32_t *queued)
{
#if defined(__linux__) && defined(TCP_INFO) && defined(TIOCOUTQ)
  unsigned char info[FTUN_TCP_INFO_BUFFER_BYTES];
  socklen_t length = (socklen_t)sizeof(info);
  int outstanding = 0;
  if (descriptor < 0 || acked == NULL || queued == NULL) return FTUN_E_INVALID;
  memset(info, 0, sizeof(info));
  if (getsockopt((int)descriptor, IPPROTO_TCP, TCP_INFO, info, &length) != 0 ||
      ioctl((int)descriptor, TIOCOUTQ, &outstanding) != 0) {
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
