#include "platform/socket.h"
#include "platform/clock.h"
#include "util/endpoint.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mstcpip.h>
#include <limits.h>
#include <string.h>

static INIT_ONCE socket_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK socket_initialize(PINIT_ONCE once, void *parameter, void **context)
{
  WSADATA data;
  (void)once; (void)parameter; (void)context;
  return WSAStartup(MAKEWORD(2, 2), &data) == 0;
}
ftun_status_t ftun_windows_sockets_initialize(void)
{
  return InitOnceExecuteOnce(&socket_once, socket_initialize, NULL, NULL) ? FTUN_OK : FTUN_E_IO;
}
static ftun_status_t socket_status(int error)
{
  if (error == 0) return FTUN_OK;
  if (error == WSAEWOULDBLOCK || error == WSAEINPROGRESS || error == WSAEALREADY || error == WSAEINTR) return FTUN_E_AGAIN;
  if (error == WSAETIMEDOUT) return FTUN_E_TIMEOUT;
  if (error == WSAENOBUFS || error == WSAEMFILE) return FTUN_E_LIMIT;
  if (error == WSAEACCES || error == WSAECONNREFUSED || error == WSAECONNRESET ||
      error == WSAEHOSTUNREACH || error == WSAENETUNREACH) return FTUN_E_REJECTED;
  if (error == WSAENOTSOCK || error == WSAEINVAL) return FTUN_E_INVALID;
  if (error == WSAEAFNOSUPPORT || error == WSAEOPNOTSUPP || error == WSAENOPROTOOPT) return FTUN_E_UNSUPPORTED;
  return FTUN_E_IO;
}
ftun_status_t ftun_blocking_socket_status(int error) { return socket_status(error); }

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
  if (storage->ss_family == AF_INET6 && length >= (socklen_t)sizeof(struct sockaddr_in6)) {
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
  if (storage->ss_family == AF_INET && length >= (socklen_t)sizeof(struct sockaddr_in)) {
    const struct sockaddr_in *address = (const struct sockaddr_in *)storage;
    endpoint->kind = FTUN_ADDRESS_IPV4;
    endpoint->port = ntohs(address->sin_port);
    memcpy(endpoint->address, &address->sin_addr, 4u);
    return FTUN_OK;
  }
  return FTUN_E_PROTOCOL;
}
static ftun_status_t make_socket(int family, int type, SOCKET *out)
{
  ftun_status_t status = ftun_windows_sockets_initialize();
  if (status != FTUN_OK) return status;
  *out = WSASocketW(family, type, 0, NULL, 0u, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
  if (*out == INVALID_SOCKET) return socket_status(WSAGetLastError());
  u_long one = 1u;
  if (ioctlsocket(*out, FIONBIO, &one) == 0) return FTUN_OK;
  status = socket_status(WSAGetLastError());
  closesocket(*out);
  *out = INVALID_SOCKET;
  return status;
}
static ftun_status_t open_socket(void *context, ftun_address_kind_t family,
  ftun_dial_transport_t transport, ftun_native_socket_t *out)
{
  SOCKET socket;
  (void)context;
  *out = FTUN_INVALID_SOCKET;
  ftun_status_t status = make_socket(family == FTUN_ADDRESS_IPV6 ? AF_INET6 : AF_INET,
    transport == FTUN_DIAL_TCP ? SOCK_STREAM : SOCK_DGRAM, &socket);
  if (status == FTUN_OK) *out = (ftun_native_socket_t)socket;
  return status;
}
bool ftun_socket_has_user_timeout(void) { return false; }
ftun_status_t ftun_socket_apply_liveness(ftun_handle_t descriptor, const ftun_socket_liveness_t *liveness)
{
  SOCKET socket = (SOCKET)descriptor;
  if (liveness->user_timeout_ms != 0u) return FTUN_E_UNSUPPORTED;
  if (!liveness->keepalive_enabled) return FTUN_OK;
  int one = 1;
  if (setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, (const char *)&one, sizeof(one)) != 0)
    return socket_status(WSAGetLastError());
  const int keys[] = {TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT};
  const uint32_t values[] = {liveness->idle_s, liveness->interval_s, liveness->count};
  for (size_t i = 0u; i < 3u; i++) {
    DWORD value = values[i];
    if (setsockopt(socket, IPPROTO_TCP, keys[i], (const char *)&value, sizeof(value)) != 0)
      return socket_status(WSAGetLastError());
  }
  return FTUN_OK;
}
static ftun_status_t protect_socket(void *context, ftun_native_socket_t socket,
  const ftun_socket_policy_t *policy)
{
  (void)context;
  if (policy->mark != 0u || policy->interface_name.length != 0u) return FTUN_E_UNSUPPORTED;
  int type, length = sizeof(type);
  if (getsockopt((SOCKET)socket, SOL_SOCKET, SO_TYPE, (char *)&type, &length) != 0) return socket_status(WSAGetLastError());
  return type == SOCK_STREAM ? ftun_socket_apply_liveness((ftun_handle_t)socket, &policy->liveness) : FTUN_OK;
}
static ftun_status_t connect_socket(void *context, ftun_native_socket_t socket, const ftun_endpoint_t *endpoint)
{
  struct sockaddr_storage address;
  (void)context;
  int length = ftun_socket_address(endpoint, &address);
  if (connect((SOCKET)socket, (struct sockaddr *)&address, length) == 0) return FTUN_OK;
  return socket_status(WSAGetLastError());
}
static ftun_status_t socket_error(void *context, ftun_native_socket_t socket)
{
  int error = 0, length = sizeof(error);
  (void)context;
  if (getsockopt((SOCKET)socket, SOL_SOCKET, SO_ERROR, (char *)&error, &length) != 0)
    return socket_status(WSAGetLastError());
  return socket_status(error);
}
static ftun_status_t close_socket(void *context, ftun_native_socket_t socket)
{
  (void)context;
  return ftun_socket_close(socket);
}
const ftun_socket_io_t *ftun_socket_default_io(void)
{
  static const ftun_socket_io_t io = {open_socket, protect_socket, connect_socket, socket_error, close_socket, NULL};
  return &io;
}
ftun_status_t ftun_socket_close(ftun_native_socket_t socket)
{
  return closesocket((SOCKET)socket) == 0 ? FTUN_OK : socket_status(WSAGetLastError());
}
ftun_status_t ftun_socket_datagram_send(void *context, ftun_native_socket_t socket,
  const void *data, size_t length, size_t *sent)
{
  (void)context;
  *sent = 0u;
  if (length > INT_MAX) return FTUN_E_LIMIT;
  int result = send((SOCKET)socket, data, (int)length, 0);
  if (result < 0) return socket_status(WSAGetLastError());
  *sent = (size_t)result;
  return FTUN_OK;
}
ftun_status_t ftun_socket_datagram_receive(void *context, ftun_native_socket_t socket,
  void *data, size_t capacity, size_t *received, ftun_endpoint_t *source)
{
  struct sockaddr_storage address;
  int length = sizeof(address);
  (void)context;
  *received = 0u;
  if (capacity > INT_MAX) return FTUN_E_LIMIT;
  int result = recvfrom((SOCKET)socket, data, (int)capacity, 0, (struct sockaddr *)&address, &length);
  if (result < 0) return WSAGetLastError() == WSAEMSGSIZE ? FTUN_E_LIMIT : socket_status(WSAGetLastError());
  if (result == 0) return FTUN_E_IO;
  ftun_status_t status = ftun_socket_endpoint(&address, length, source);
  if (status == FTUN_OK) *received = (size_t)result;
  return status;
}
static ptrdiff_t send_bytes(ftun_handle_t socket, const void *data, size_t length, ftun_status_t *status)
{
  if (length > INT_MAX) length = INT_MAX;
  int result = send((SOCKET)socket, data, (int)length, 0);
  *status = result < 0 ? socket_status(WSAGetLastError()) : FTUN_OK;
  return result;
}
static ptrdiff_t receive_bytes(ftun_handle_t socket, void *data, size_t length, ftun_status_t *status)
{
  if (length > INT_MAX) length = INT_MAX;
  int result = recv((SOCKET)socket, data, (int)length, 0);
  *status = result < 0 ? socket_status(WSAGetLastError()) : result == 0 ? FTUN_E_EOF : FTUN_OK;
  return result;
}
ptrdiff_t ftun_socket_send_nowait(ftun_handle_t socket, const void *data, size_t length, ftun_status_t *status)
{ return send_bytes(socket, data, length, status); }
ptrdiff_t ftun_socket_stream_send(ftun_handle_t socket, const void *data, size_t length, ftun_status_t *status)
{ return send_bytes(socket, data, length, status); }
ptrdiff_t ftun_socket_receive_nowait(ftun_handle_t socket, void *data, size_t length, ftun_status_t *status)
{ return receive_bytes(socket, data, length, status); }
ptrdiff_t ftun_socket_stream_receive(ftun_handle_t socket, void *data, size_t length, ftun_status_t *status)
{ return receive_bytes(socket, data, length, status); }
ftun_status_t ftun_socket_shutdown_write(ftun_handle_t socket)
{
  if (shutdown((SOCKET)socket, SD_SEND) == 0 || WSAGetLastError() == WSAENOTCONN) return FTUN_OK;
  return socket_status(WSAGetLastError());
}
ftun_status_t ftun_socket_name(ftun_handle_t socket, ftun_endpoint_t *out)
{
  struct sockaddr_storage address;
  int length = sizeof(address);
  if (getsockname((SOCKET)socket, (struct sockaddr *)&address, &length) != 0) return socket_status(WSAGetLastError());
  return ftun_socket_endpoint(&address, length, out);
}
ftun_status_t ftun_socket_listen(const ftun_endpoint_t *endpoint,
  ftun_dial_transport_t transport, int backlog, ftun_handle_t *out, ftun_socket_bind_issue_t *issue)
{
  SOCKET socket;
  struct sockaddr_storage address;
  *out = -1;
  *issue = FTUN_SOCKET_BIND_OTHER;
  ftun_status_t status = make_socket(endpoint->kind == FTUN_ADDRESS_IPV6 ? AF_INET6 : AF_INET,
    transport == FTUN_DIAL_TCP ? SOCK_STREAM : SOCK_DGRAM, &socket);
  if (status != FTUN_OK) return status;
  int one = 1;
  if (setsockopt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&one, sizeof(one)) != 0) goto error;
  if (endpoint->kind == FTUN_ADDRESS_IPV6 &&
      setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&one, sizeof(one)) != 0) goto error;
  int length = ftun_socket_address(endpoint, &address);
  if (bind(socket, (struct sockaddr *)&address, length) != 0) {
    int code = WSAGetLastError();
    *issue = code == WSAEADDRNOTAVAIL ? FTUN_SOCKET_BIND_ADDRESS_UNAVAILABLE :
      code == WSAEACCES ? FTUN_SOCKET_BIND_PERMISSION : FTUN_SOCKET_BIND_OTHER;
    status = socket_status(code);
    closesocket(socket);
    return status;
  }
  if (transport == FTUN_DIAL_TCP && listen(socket, backlog) != 0) goto error;
  *out = (ftun_handle_t)socket;
  return FTUN_OK;
error:
  status = socket_status(WSAGetLastError());
  closesocket(socket);
  return status;
}
ftun_status_t ftun_socket_accept(ftun_handle_t listener, ftun_handle_t *out,
  ftun_endpoint_t *peer, ftun_socket_accept_disposition_t *disposition)
{
  struct sockaddr_storage address;
  int length = sizeof(address);
  *out = -1;
  SOCKET socket = accept((SOCKET)listener, (struct sockaddr *)&address, &length);
  if (socket == INVALID_SOCKET) {
    int error = WSAGetLastError();
    *disposition = error == WSAEWOULDBLOCK ? FTUN_SOCKET_ACCEPT_DRAINED :
      error == WSAECONNRESET || error == WSAECONNABORTED ? FTUN_SOCKET_ACCEPT_SKIP :
      error == WSAENOTSOCK || error == WSAEINVAL ? FTUN_SOCKET_ACCEPT_FATAL : FTUN_SOCKET_ACCEPT_BACKOFF;
    return socket_status(error);
  }
  u_long one = 1u;
  ftun_status_t status = peer == NULL ? FTUN_OK : ftun_socket_endpoint(&address, length, peer);
  if (status == FTUN_OK && (!SetHandleInformation((HANDLE)socket, HANDLE_FLAG_INHERIT, 0u) ||
      ioctlsocket(socket, FIONBIO, &one) != 0)) status = FTUN_E_IO;
  if (status != FTUN_OK) { closesocket(socket); return status; }
  *out = (ftun_handle_t)socket;
  return FTUN_OK;
}
ftun_status_t ftun_socket_duplicate(ftun_handle_t source, ftun_handle_t *out)
{
  WSAPROTOCOL_INFOW info;
  *out = -1;
  if (WSADuplicateSocketW((SOCKET)source, GetCurrentProcessId(), &info) != 0) return socket_status(WSAGetLastError());
  SOCKET socket = WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &info,
    0u, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
  if (socket == INVALID_SOCKET) return socket_status(WSAGetLastError());
  *out = (ftun_handle_t)socket;
  return FTUN_OK;
}
bool ftun_blocking_socket_wait(ftun_handle_t socket, uint32_t events, uint64_t deadline_ms)
{
  uint64_t now = GetTickCount64();
  if (now >= deadline_ms) return false;
  WSAPOLLFD item = {(SOCKET)socket, (short)(((events & FTUN_POLLER_READ) ? POLLRDNORM : 0) |
    ((events & FTUN_POLLER_WRITE) ? POLLWRNORM : 0)), 0};
  int timeout = deadline_ms - now > INT_MAX ? INT_MAX : (int)(deadline_ms - now);
  return WSAPoll(&item, 1u, timeout) > 0;
}
ftun_status_t ftun_socket_pair(ftun_handle_t out[2])
{
  ftun_endpoint_t loopback = {.kind = FTUN_ADDRESS_IPV4, .address = {127u, 0u, 0u, 1u}};
  ftun_handle_t listener = -1;
  ftun_socket_bind_issue_t issue;
  SOCKET client = INVALID_SOCKET;
  ftun_status_t status = ftun_socket_listen(&loopback, FTUN_DIAL_TCP, 1, &listener, &issue);
  out[0] = out[1] = -1;
  if (status == FTUN_OK) status = ftun_socket_name(listener, &loopback);
  if (status == FTUN_OK) status = make_socket(AF_INET, SOCK_STREAM, &client);
  if (status == FTUN_OK) status = connect_socket(NULL, client, &loopback);
  if (status == FTUN_E_AGAIN && ftun_blocking_socket_wait((ftun_handle_t)client,
      FTUN_POLLER_WRITE, GetTickCount64() + 1000u)) status = socket_error(NULL, client);
  if (status == FTUN_OK) {
    ftun_endpoint_t peer;
    ftun_socket_accept_disposition_t disposition;
    status = ftun_socket_accept(listener, &out[0], &peer, &disposition);
  }
  if (listener >= 0) closesocket((SOCKET)listener);
  if (status != FTUN_OK) { if (client != INVALID_SOCKET) closesocket(client); return status; }
  out[1] = (ftun_handle_t)client;
  return FTUN_OK;
}
ptrdiff_t ftun_socket_receive_from(ftun_handle_t socket, void *data, size_t capacity,
  ftun_endpoint_t *peer, ftun_status_t *status)
{
  struct sockaddr_storage address;
  int length = sizeof(address);
  if (capacity > INT_MAX) capacity = INT_MAX;
  int count = recvfrom((SOCKET)socket, data, (int)capacity, 0, (struct sockaddr *)&address, &length);
  if (count < 0 && WSAGetLastError() == WSAEMSGSIZE) count = (int)capacity;
  *status = count < 0 ? socket_status(WSAGetLastError()) : ftun_socket_endpoint(&address, length, peer);
  return *status == FTUN_OK ? count : -1;
}
ptrdiff_t ftun_socket_send_to(ftun_handle_t socket, const void *data, size_t length,
  const ftun_endpoint_t *peer, ftun_status_t *status)
{
  struct sockaddr_storage address;
  int size = ftun_socket_address(peer, &address);
  if (length > INT_MAX) { *status = FTUN_E_LIMIT; return -1; }
  int count = sendto((SOCKET)socket, data, (int)length, 0, (struct sockaddr *)&address, size);
  *status = count < 0 ? socket_status(WSAGetLastError()) : FTUN_OK;
  return count;
}
ftun_status_t ftun_socket_send_progress(ftun_handle_t socket, uint64_t *acked, uint32_t *queued)
{
  (void)socket; (void)acked; (void)queued;
  return FTUN_E_UNSUPPORTED;
}
