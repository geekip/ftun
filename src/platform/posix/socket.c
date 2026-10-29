#define _GNU_SOURCE 1

#include "platform/socket.h"

#include "platform/clock.h"

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

bool ftun_blocking_socket_wait(int descriptor, uint32_t events,
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
  item.events = (short)(((events & FTUN_POLLER_READ) != 0u ? POLLIN : 0) |
                        ((events & FTUN_POLLER_WRITE) != 0u ? POLLOUT : 0));
  do {
    result = poll(&item, 1u, timeout);
  } while (result < 0 && errno == EINTR);
  return result == 1 &&
    (item.revents & (item.events | POLLERR | POLLHUP | POLLNVAL)) != 0;
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
             ftun_blocking_socket_wait(descriptor, FTUN_POLLER_WRITE, deadline_ms)) {
      continue;
    } else return false;
  }
  return true;
}
