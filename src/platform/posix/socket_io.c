#define _GNU_SOURCE 1
#include "platform/socket.h"
#include "platform/posix/error.h"
#if defined(__linux__)
#include "platform/linux/socket_protect.h"
#endif
#include "platform/posix/socket_native.h"
#include "util/endpoint.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static socklen_t ftun_socket_address(const ftun_endpoint_t *endpoint,
  struct sockaddr_storage *storage)
{
  memset(storage, 0, sizeof(*storage));
  if (endpoint->kind == FTUN_ADDRESS_IPV6) {
    struct sockaddr_in6 *address = (struct sockaddr_in6 *)storage;
    address->sin6_family = AF_INET6;
    address->sin6_port = htons(endpoint->port);
    memcpy(&address->sin6_addr, endpoint->address, 16u);
    return sizeof(*address);
  }
  struct sockaddr_in *address = (struct sockaddr_in *)storage;
  address->sin_family = AF_INET;
  address->sin_port = htons(endpoint->port);
  memcpy(&address->sin_addr, endpoint->address, 4u);
  return sizeof(*address);
}
static ftun_status_t ftun_socket_endpoint(const struct sockaddr_storage *storage,
  socklen_t length, ftun_endpoint_t *endpoint)
{
  memset(endpoint, 0, sizeof(*endpoint));
  if (storage->ss_family == AF_INET6 && length >= sizeof(struct sockaddr_in6)) {
    const struct sockaddr_in6 *address = (const struct sockaddr_in6 *)storage;
    endpoint->kind = FTUN_ADDRESS_IPV6;
    endpoint->port = ntohs(address->sin6_port);
    memcpy(endpoint->address, &address->sin6_addr, 16u);
    /* 双栈监听将映射的IPv4还原为IPv4身份。 */
    if (IN6_IS_ADDR_V4MAPPED(&address->sin6_addr)) {
      memmove(endpoint->address, endpoint->address + 12u, 4u);
      memset(endpoint->address + 4u, 0, 12u);
      endpoint->kind = FTUN_ADDRESS_IPV4;
    }
    return FTUN_OK;
  }
  if (storage->ss_family == AF_INET && length >= sizeof(struct sockaddr_in)) {
    const struct sockaddr_in *address = (const struct sockaddr_in *)storage;
    endpoint->kind = FTUN_ADDRESS_IPV4;
    endpoint->port = ntohs(address->sin_port);
    memcpy(endpoint->address, &address->sin_addr, 4u);
    return FTUN_OK;
  }
  return FTUN_E_PROTOCOL;
}

static ftun_status_t ftun_dial_errno_status(int error_code)
{
  if (error_code == 0) return FTUN_OK;
  if (error_code == EINPROGRESS || error_code == EALREADY ||
      error_code == EAGAIN) return FTUN_E_AGAIN;
#if EWOULDBLOCK != EAGAIN
  if (error_code == EWOULDBLOCK) return FTUN_E_AGAIN;
#endif
  if (error_code == ETIMEDOUT) return FTUN_E_TIMEOUT;
  if (error_code == ENOMEM || error_code == ENOBUFS || error_code == EMFILE ||
      error_code == ENFILE) return FTUN_E_LIMIT;
  if (error_code == EAFNOSUPPORT || error_code == EPROTONOSUPPORT ||
      error_code == EOPNOTSUPP) return FTUN_E_UNSUPPORTED;
  if (error_code == EBADF || error_code == ENOTSOCK || error_code == EINVAL) {
    return FTUN_E_INVALID;
  }
  if (error_code == EACCES || error_code == EPERM || error_code == ECONNREFUSED ||
      error_code == ENETUNREACH || error_code == EHOSTUNREACH) {
    return FTUN_E_REJECTED;
  }
  return FTUN_E_IO;
}

static ftun_status_t ftun_system_open_socket(void *context,
                                               ftun_address_kind_t family, ftun_dial_transport_t transport,
                                               ftun_native_socket_t *out)
{
  int descriptor;
  int type;
  int protocol;
  (void)context;
  if (out != NULL) *out = FTUN_INVALID_SOCKET;
  if (out == NULL || (transport != FTUN_DIAL_TCP && transport != FTUN_DIAL_UDP)) return FTUN_E_INVALID;
  type = transport == FTUN_DIAL_TCP ? SOCK_STREAM : SOCK_DGRAM;
  protocol = transport == FTUN_DIAL_TCP ? IPPROTO_TCP : IPPROTO_UDP;
  descriptor = ftun_posix_socket(family == FTUN_ADDRESS_IPV6 ? AF_INET6 : AF_INET, type, protocol);
  if (descriptor < 0) return ftun_dial_errno_status(errno);
  *out = (ftun_native_socket_t)(unsigned int)descriptor;
  return FTUN_OK;
}

static ftun_status_t ftun_system_protect_socket(
  void *context, ftun_native_socket_t socket,
  const ftun_socket_policy_t *policy)
{
  (void)context;
#if defined(__linux__)
  return ftun_linux_socket_protect(socket, policy);
#else
  (void)socket; (void)policy;
  return FTUN_E_UNSUPPORTED;
#endif
}

static ftun_status_t ftun_system_connect_socket(
  void *context, ftun_native_socket_t socket, const ftun_endpoint_t *endpoint)
{
  struct sockaddr_storage address;
  socklen_t length;
  (void)context;
  if (socket > (ftun_native_socket_t)INT_MAX || endpoint == NULL ||
      !ftun_endpoint_is_ip(endpoint) || endpoint->port == 0u) return FTUN_E_INVALID;
  length = ftun_socket_address(endpoint, &address);
  if (connect((int)socket, (const struct sockaddr *)&address, length) == 0) return FTUN_OK;
  if (errno == EISCONN) return FTUN_OK;
  return ftun_dial_errno_status(errno);
}

static ftun_status_t ftun_system_get_socket_error(void *context,
                                                   ftun_native_socket_t socket)
{
  socklen_t length;
  int descriptor;
  int error_code = 0;
  (void)context;
  if (socket > (ftun_native_socket_t)INT_MAX) return FTUN_E_INVALID;
  descriptor = (int)socket;
  length = (socklen_t)sizeof(error_code);
  if (getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error_code, &length) < 0) {
    return ftun_dial_errno_status(errno);
  }
  if (length != (socklen_t)sizeof(error_code)) return FTUN_E_IO;
  return ftun_dial_errno_status(error_code);
}

static ftun_status_t ftun_system_close_socket(void *context,
                                               ftun_native_socket_t socket)
{
  int descriptor;
  (void)context;
  if (socket > (ftun_native_socket_t)INT_MAX) return FTUN_E_INVALID;
  descriptor = (int)socket;
  if (close(descriptor) != 0) return ftun_dial_errno_status(errno);
  return FTUN_OK;
}

static const ftun_socket_io_t ftun_system_dial_io = {
  ftun_system_open_socket,
  ftun_system_protect_socket,
  ftun_system_connect_socket,
  ftun_system_get_socket_error,
  ftun_system_close_socket,
  NULL
};

const ftun_socket_io_t *ftun_socket_default_io(void)
{
  return &ftun_system_dial_io;
}

static ftun_status_t ftun_bootstrap_errno_status(int error_code)
{
  if (error_code == EINTR || error_code == EAGAIN ||
      error_code == EWOULDBLOCK) return FTUN_E_AGAIN;
  if (error_code == ETIMEDOUT) return FTUN_E_TIMEOUT;
  if (error_code == ENOMEM || error_code == ENOBUFS) return FTUN_E_LIMIT;
  if (error_code == EBADF || error_code == ENOTSOCK || error_code == EINVAL) {
    return FTUN_E_INVALID;
  }
  if (error_code == EACCES || error_code == EPERM ||
      error_code == ECONNREFUSED || error_code == ENETUNREACH ||
      error_code == EHOSTUNREACH) return FTUN_E_REJECTED;
  return FTUN_E_IO;
}

ftun_status_t ftun_socket_datagram_send(
  void *user, ftun_native_socket_t socket, const void *data, size_t length,
  size_t *out_sent)
{
  ssize_t result;
  int descriptor;
  (void)user;
  if (out_sent != NULL) *out_sent = 0u;
  if (out_sent == NULL || data == NULL || length == 0u ||
      socket > (ftun_native_socket_t)INT_MAX) return FTUN_E_INVALID;
  descriptor = (int)socket;
  do {
    result = send(descriptor, data, length, 0);
  } while (result < 0 && errno == EINTR);
  if (result < 0) return ftun_bootstrap_errno_status(errno);
  if (result == 0) return FTUN_E_IO;
  *out_sent = (size_t)result;
  return FTUN_OK;
}

ftun_status_t ftun_socket_datagram_receive(
  void *user, ftun_native_socket_t socket, void *data, size_t capacity,
  size_t *out_received, ftun_endpoint_t *out_source)
{
  struct sockaddr_storage source;
  struct iovec vector;
  struct msghdr message;
  ssize_t result;
  int descriptor;
  (void)user;
  if (out_received != NULL) *out_received = 0u;
  if (out_source != NULL) memset(out_source, 0, sizeof(*out_source));
  if (data == NULL || capacity == 0u || out_received == NULL ||
      out_source == NULL || socket > (ftun_native_socket_t)INT_MAX) {
    return FTUN_E_INVALID;
  }
  descriptor = (int)socket;
  memset(&source, 0, sizeof(source));
  memset(&message, 0, sizeof(message));
  vector.iov_base = data;
  vector.iov_len = capacity;
  message.msg_name = &source;
  message.msg_namelen = (socklen_t)sizeof(source);
  message.msg_iov = &vector;
  message.msg_iovlen = 1u;
  do {
    result = recvmsg(descriptor, &message, MSG_TRUNC);
  } while (result < 0 && errno == EINTR);
  if (result < 0) return ftun_bootstrap_errno_status(errno);
  if (result == 0) return FTUN_E_IO;
  if ((size_t)result > capacity || (message.msg_flags & MSG_TRUNC) != 0) {
    return FTUN_E_LIMIT;
  }
  ftun_status_t status = ftun_socket_endpoint(&source, message.msg_namelen, out_source);
  if (status != FTUN_OK) return status;
  *out_received = (size_t)result;
  return FTUN_OK;
}

ftun_status_t ftun_socket_close(ftun_native_socket_t socket)
{
  int descriptor;
  if (socket > (ftun_native_socket_t)INT_MAX) return FTUN_E_INVALID;
  descriptor = (int)socket;
  if (close(descriptor) == 0) return FTUN_OK;
  if (errno == EBADF) return FTUN_E_INVALID;
  return FTUN_E_IO;
}

static ftun_status_t ftun_socket_stream_status(int error)
{
  if (error == EAGAIN || error == EWOULDBLOCK || error == EINTR) return FTUN_E_AGAIN;
  if (error == ENOMEM || error == ENOBUFS || error == EMSGSIZE ||
      error == EMFILE || error == ENFILE) return FTUN_E_LIMIT;
  if (error == EACCES || error == EPERM || error == ECONNREFUSED ||
      error == ECONNRESET || error == EPIPE || error == EHOSTUNREACH ||
      error == ENETUNREACH) return FTUN_E_REJECTED;
  if (error == ETIMEDOUT) return FTUN_E_TIMEOUT;
  if (error == EBADF || error == EINVAL || error == ENOTSOCK) return FTUN_E_INVALID;
  return FTUN_E_IO;
}

static ftun_status_t ftun_socket_status(int error)
{
  if (error == EAGAIN || error == EWOULDBLOCK || error == EINTR) return FTUN_E_AGAIN;
  if (error == ENOMEM || error == ENOBUFS || error == EMSGSIZE) return FTUN_E_LIMIT;
  if (error == EACCES || error == EPERM || error == ECONNREFUSED) return FTUN_E_REJECTED;
  if (error == ETIMEDOUT) return FTUN_E_TIMEOUT;
  return FTUN_E_IO;
}

ptrdiff_t ftun_socket_send_nowait(ftun_handle_t descriptor, const void *data, size_t length,
  ftun_status_t *status)
{
  ssize_t count;
  do {
    count = send((int)descriptor, data, length, MSG_DONTWAIT | MSG_NOSIGNAL);
  } while (count < 0 && errno == EINTR);
  *status = count < 0 ? ftun_socket_status(errno) : FTUN_OK;
  return (ptrdiff_t)count;
}
ptrdiff_t ftun_socket_receive_nowait(ftun_handle_t descriptor, void *data, size_t capacity,
  ftun_status_t *status)
{
  ssize_t count;
  do {
    count = recv((int)descriptor, data, capacity, MSG_DONTWAIT);
  } while (count < 0 && errno == EINTR);
  *status = count < 0 ? ftun_socket_status(errno) : FTUN_OK;
  return (ptrdiff_t)count;
}
ptrdiff_t ftun_socket_stream_send(ftun_handle_t descriptor, const void *data, size_t length,
  ftun_status_t *status)
{
  ssize_t count;
  do {
    count = send((int)descriptor, data, length, MSG_DONTWAIT | MSG_NOSIGNAL);
  } while (count < 0 && errno == EINTR);
  *status = count < 0 ? ftun_socket_stream_status(errno) : FTUN_OK;
  return (ptrdiff_t)count;
}
ptrdiff_t ftun_socket_stream_receive(ftun_handle_t descriptor, void *data, size_t capacity,
  ftun_status_t *status)
{
  ssize_t count;
  do {
    count = recv((int)descriptor, data, capacity, MSG_DONTWAIT);
  } while (count < 0 && errno == EINTR);
  *status = count < 0 ? ftun_socket_stream_status(errno) : FTUN_OK;
  return (ptrdiff_t)count;
}
ftun_status_t ftun_socket_shutdown_write(ftun_handle_t descriptor)
{
  if (shutdown((int)descriptor, SHUT_WR) == 0 || errno == ENOTCONN) return FTUN_OK;
  return ftun_socket_status(errno);
}
ftun_status_t ftun_socket_name(ftun_handle_t descriptor, ftun_endpoint_t *out)
{
  struct sockaddr_storage address;
  socklen_t length = sizeof(address);
  if (getsockname((int)descriptor, (struct sockaddr *)&address, &length) != 0) return ftun_socket_status(errno);
  return ftun_socket_endpoint(&address, length, out);
}

ftun_status_t ftun_socket_listen(const ftun_endpoint_t *endpoint,
  ftun_dial_transport_t transport, int backlog, ftun_handle_t *out,
  ftun_socket_bind_issue_t *issue)
{
  struct sockaddr_storage address;
  int descriptor;
  int one = 1;
  int error;
  *out = -1;
  *issue = FTUN_SOCKET_BIND_OTHER;
  if (!ftun_endpoint_is_ip(endpoint) ||
      (transport != FTUN_DIAL_TCP && transport != FTUN_DIAL_UDP)) return FTUN_E_INVALID;
  descriptor = ftun_posix_socket(endpoint->kind == FTUN_ADDRESS_IPV6 ? AF_INET6 : AF_INET,
    transport == FTUN_DIAL_TCP ? SOCK_STREAM : SOCK_DGRAM, 0);
  if (descriptor < 0) return ftun_blocking_socket_status(errno);
  (void)setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  socklen_t length = ftun_socket_address(endpoint, &address);
  if (bind(descriptor, (const struct sockaddr *)&address, length) != 0 ||
      (transport == FTUN_DIAL_TCP && listen(descriptor, backlog) != 0)) {
    error = errno;
    if (error == EADDRNOTAVAIL) *issue = FTUN_SOCKET_BIND_ADDRESS_UNAVAILABLE;
    if (error == EACCES || error == EPERM) *issue = FTUN_SOCKET_BIND_PERMISSION;
    (void)close(descriptor);
    return ftun_blocking_socket_status(error);
  }
  *out = descriptor;
  return FTUN_OK;
}

ftun_status_t ftun_socket_accept(ftun_handle_t listener, ftun_handle_t *out, ftun_endpoint_t *peer,
  ftun_socket_accept_disposition_t *disposition)
{
  struct sockaddr_storage address;
  socklen_t length = sizeof(address);
  int descriptor = ftun_posix_accept((int)listener, (struct sockaddr *)&address, &length);
  int error = errno;
  *out = -1;
  *disposition = FTUN_SOCKET_ACCEPT_FATAL;
  if (descriptor < 0) {
    *disposition = ftun_socket_accept_classify(error);
    return ftun_socket_stream_status(error);
  }
  if (peer != NULL && ftun_socket_endpoint(&address, length, peer) != FTUN_OK) {
    (void)close(descriptor);
    return FTUN_E_PROTOCOL;
  }
  *out = descriptor;
  return FTUN_OK;
}

ftun_status_t ftun_socket_duplicate(ftun_handle_t descriptor, ftun_handle_t *out)
{
  *out = fcntl((int)descriptor, F_DUPFD_CLOEXEC, 0);
  return *out < 0 ? ftun_socket_stream_status(errno) : FTUN_OK;
}

ftun_status_t ftun_socket_pair(ftun_handle_t out[2])
{
  int pair[2];
  out[0] = out[1] = -1;
  if (ftun_posix_socket_pair(pair) != 0) {
    return ftun_socket_stream_status(errno);
  }
  out[0] = pair[0];
  out[1] = pair[1];
  return FTUN_OK;
}

ptrdiff_t ftun_socket_receive_from(ftun_handle_t descriptor, void *buffer, size_t capacity,
  ftun_endpoint_t *peer, ftun_status_t *status)
{
  struct sockaddr_storage address;
  socklen_t length = sizeof(address);
  ssize_t count;
  do {
    count = recvfrom((int)descriptor, buffer, capacity, MSG_DONTWAIT,
      (struct sockaddr *)&address, &length);
  } while (count < 0 && errno == EINTR);
  *status = count < 0 ? ftun_socket_stream_status(errno)
    : ftun_socket_endpoint(&address, length, peer);
  return *status == FTUN_OK ? (ptrdiff_t)count : -1;
}

ptrdiff_t ftun_socket_send_to(ftun_handle_t descriptor, const void *buffer, size_t length,
  const ftun_endpoint_t *peer, ftun_status_t *status)
{
  struct sockaddr_storage address;
  ssize_t count;
  socklen_t address_length = ftun_socket_address(peer, &address);
  do {
    count = sendto((int)descriptor, buffer, length, MSG_DONTWAIT | MSG_NOSIGNAL,
      (const struct sockaddr *)&address, address_length);
  } while (count < 0 && errno == EINTR);
  *status = count < 0 ? ftun_socket_stream_status(errno) : FTUN_OK;
  return (ptrdiff_t)count;
}

ftun_status_t ftun_socket_connect_udp(const ftun_endpoint_t *peer, uint32_t mark,
  ftun_handle_t *out)
{
  struct sockaddr_storage address;
  int descriptor;
  ftun_status_t status;
  *out = -1;
  descriptor = ftun_posix_socket(peer->kind == FTUN_ADDRESS_IPV6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
  if (descriptor < 0) return ftun_blocking_socket_status(errno);
  if (mark != 0u) {
    ftun_socket_policy_t policy = {0};
    policy.mark = mark;
    status = ftun_system_protect_socket(NULL, (ftun_native_socket_t)descriptor, &policy);
    if (status != FTUN_OK) { close(descriptor); return status; }
  }
  socklen_t address_length = ftun_socket_address(peer, &address);
  if (connect(descriptor, (const struct sockaddr *)&address, address_length) != 0 &&
      errno != EINPROGRESS) {
    status = ftun_blocking_socket_status(errno);
    (void)close(descriptor);
    return status;
  }
  *out = descriptor;
  return FTUN_OK;
}
