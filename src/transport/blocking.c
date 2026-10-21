#define _GNU_SOURCE 1

#include "transport/blocking.h"

#include "util/time.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

ftun_status_t ftun_blocking_socket_status(int error_code)
{
  if (error_code == EAGAIN || error_code == EWOULDBLOCK ||
      error_code == EINTR) return FTUN_E_AGAIN;
  if (error_code == ENOMEM || error_code == ENOBUFS ||
      error_code == EMFILE || error_code == ENFILE) return FTUN_E_LIMIT;
  if (error_code == ETIMEDOUT) return FTUN_E_TIMEOUT;
  if (error_code == ECONNREFUSED || error_code == ECONNRESET ||
      error_code == EHOSTUNREACH || error_code == ENETUNREACH) {
    return FTUN_E_REJECTED;
  }
  return FTUN_E_IO;
}

bool ftun_blocking_socket_wait(int descriptor, short events,
                               uint64_t deadline_ms)
{
  struct pollfd item;
  uint64_t now;
  int timeout;
  int result;
  if (ftun_monotonic_now(&now) != FTUN_OK || now >= deadline_ms) return false;
  timeout = deadline_ms - now > (uint64_t)INT32_MAX
    ? INT32_MAX : (int)(deadline_ms - now);
  memset(&item, 0, sizeof(item));
  item.fd = descriptor;
  item.events = events;
  do {
    result = poll(&item, 1u, timeout);
  } while (result < 0 && errno == EINTR);
  return result == 1 &&
    (item.revents & (events | POLLERR | POLLHUP | POLLNVAL)) != 0;
}

bool ftun_blocking_socket_send_all(int descriptor, const uint8_t *data,
                                   size_t length, uint64_t deadline_ms)
{
  size_t offset = 0u;
  while (offset < length) {
    ssize_t sent = send(descriptor, data + offset, length - offset,
                        MSG_NOSIGNAL);
    if (sent > 0) offset += (size_t)sent;
    else if (sent < 0 && errno == EINTR) continue;
    else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) &&
             ftun_blocking_socket_wait(descriptor, POLLOUT, deadline_ms)) {
      continue;
    } else return false;
  }
  return true;
}

bool ftun_blocking_socket_recv_all(int descriptor, uint8_t *data,
                                   size_t length, uint64_t deadline_ms)
{
  size_t offset = 0u;
  while (offset < length) {
    ssize_t received = recv(descriptor, data + offset, length - offset, 0);
    if (received > 0) offset += (size_t)received;
    else if (received < 0 && errno == EINTR) continue;
    else if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) &&
             ftun_blocking_socket_wait(descriptor, POLLIN, deadline_ms)) {
      continue;
    } else return false;
  }
  return true;
}

ftun_status_t ftun_blocking_socket_connect_ipv4(
  int type, const uint8_t address[4], uint16_t port, uint32_t mark,
  uint64_t deadline_ms, int *out)
{
  struct sockaddr_in target;
  int descriptor;
  int flags;
  int error_code = 0;
  socklen_t error_length = (socklen_t)sizeof(error_code);
  if (out != NULL) *out = -1;
  if (address == NULL || port == 0u || out == NULL) return FTUN_E_INVALID;
  descriptor = socket(AF_INET, type | SOCK_CLOEXEC, 0);
  if (descriptor < 0) return ftun_blocking_socket_status(errno);
#if defined(SO_MARK)
  if (mark != 0u && setsockopt(descriptor, SOL_SOCKET, SO_MARK, &mark,
                 (socklen_t)sizeof(mark)) != 0) {
    error_code = errno;
    (void)close(descriptor);
    return ftun_blocking_socket_status(error_code);
  }
#else
  (void)mark;
#endif
  flags = fcntl(descriptor, F_GETFL, 0);
  if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0) {
    (void)close(descriptor);
    return FTUN_E_IO;
  }
  memset(&target, 0, sizeof(target));
  target.sin_family = AF_INET;
  target.sin_port = htons(port);
  memcpy(&target.sin_addr.s_addr, address, 4u);
  if (connect(descriptor, (const struct sockaddr *)&target,
              (socklen_t)sizeof(target)) != 0 && errno != EINPROGRESS) {
    error_code = errno;
    (void)close(descriptor);
    return ftun_blocking_socket_status(error_code);
  }
  if (!ftun_blocking_socket_wait(descriptor, POLLOUT, deadline_ms) ||
      getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error_code,
                 &error_length) != 0 || error_code != 0) {
    (void)close(descriptor);
    return error_code == 0 ? FTUN_E_TIMEOUT :
      ftun_blocking_socket_status(error_code);
  }
  *out = descriptor;
  return FTUN_OK;
}
