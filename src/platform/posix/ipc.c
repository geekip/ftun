#define _GNU_SOURCE 1
#include "platform/ipc.h"
#include "platform/posix/socket_native.h"
#include "platform/socket.h"
#include "platform/clock.h"
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/un.h>

ftun_status_t ftun_ipc_connect(const char *path, uint64_t deadline_ms,
  ftun_handle_t *out)
{
  struct sockaddr_un address;
  size_t length = strlen(path);
  int descriptor, error = 0;
  socklen_t size = sizeof(error);
  ftun_status_t status;
  uint64_t now;
  *out = -1;
  if (ftun_monotonic_now(&now) != FTUN_OK) return FTUN_E_IO;
  if (now >= deadline_ms) return FTUN_E_TIMEOUT;
  if (length >= sizeof(address.sun_path)) return FTUN_E_LIMIT;
  descriptor = ftun_posix_socket(AF_UNIX, SOCK_STREAM, 0);
  if (descriptor < 0) return ftun_blocking_socket_status(errno);
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path, path, length + 1u);
  if (connect(descriptor, (const struct sockaddr *)&address,
      (socklen_t)(offsetof(struct sockaddr_un, sun_path) + length + 1u)) != 0) {
    error = errno;
    if (error == EINPROGRESS) {
      if (!ftun_blocking_socket_wait(descriptor, FTUN_POLLER_WRITE, deadline_ms)) {
        (void)close(descriptor);
        return FTUN_E_TIMEOUT;
      }
      if (getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error, &size) != 0) error = errno;
    }
  }
  if (error == 0) { *out = descriptor; return FTUN_OK; }
  status = error == ENOENT || error == ECONNREFUSED ? FTUN_E_EOF
    : error == EACCES || error == EPERM ? FTUN_E_REJECTED
    : ftun_blocking_socket_status(error);
  (void)close(descriptor);
  return status;
}

ftun_status_t ftun_ipc_listen(const char *path, ftun_ipc_listener_t *out)
{
  struct sockaddr_un address;
  struct stat info;
  size_t length;
  int descriptor;
  ftun_status_t status;
  *out = (ftun_ipc_listener_t)FTUN_IPC_LISTENER_INVALID;
  if (path == NULL || path[0] == '\0') return FTUN_E_INVALID;
  length = strlen(path);
  if (length >= sizeof(address.sun_path)) return FTUN_E_LIMIT;
  if (lstat(path, &info) == 0) {
    if (!S_ISSOCK(info.st_mode)) return FTUN_E_REJECTED;
    if (unlink(path) != 0) return FTUN_E_IO;
  } else if (errno != ENOENT) return FTUN_E_IO;
  descriptor = ftun_posix_socket(AF_UNIX, SOCK_STREAM, 0);
  if (descriptor < 0) return ftun_blocking_socket_status(errno);
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path, path, length + 1u);
  if (bind(descriptor, (const struct sockaddr *)&address,
      (socklen_t)(offsetof(struct sockaddr_un, sun_path) + length + 1u)) != 0) {
    status = ftun_blocking_socket_status(errno);
    (void)close(descriptor);
    return status;
  }
  if (lstat(path, &info) != 0) {
    (void)close(descriptor);
    (void)unlink(path);
    return FTUN_E_IO;
  }
  *out = (ftun_ipc_listener_t){descriptor, path, (uint64_t)info.st_dev, (uint64_t)info.st_ino};
  if (chmod(path, 0600) != 0 || listen(descriptor, 8) != 0) {
    (void)ftun_ipc_listener_close(out);
    return FTUN_E_IO;
  }
  return FTUN_OK;
}

ftun_status_t ftun_ipc_listener_discard(ftun_ipc_listener_t *listener)
{
  ftun_status_t status = listener->socket < 0 || close((int)listener->socket) == 0 ? FTUN_OK : FTUN_E_IO;
  *listener = (ftun_ipc_listener_t)FTUN_IPC_LISTENER_INVALID;
  return status;
}

ftun_status_t ftun_ipc_listener_close(ftun_ipc_listener_t *listener)
{
  struct stat info;
  ftun_status_t status = FTUN_OK;
  if (listener->socket < 0) return FTUN_OK;
  if (lstat(listener->path, &info) == 0) {
    if ((uint64_t)info.st_dev == listener->device &&
        (uint64_t)info.st_ino == listener->inode && unlink(listener->path) != 0) {
      status = FTUN_E_IO;
    }
  } else if (errno != ENOENT) status = FTUN_E_IO;
  if (close((int)listener->socket) != 0) status = FTUN_E_IO;
  *listener = (ftun_ipc_listener_t)FTUN_IPC_LISTENER_INVALID;
  return status;
}

ftun_status_t ftun_ipc_peer_allowed(ftun_handle_t socket, bool *allowed, uint64_t *user_id)
{
  uid_t uid;
  *allowed = false;
  *user_id = UINT64_MAX;
#if defined(__APPLE__)
  gid_t group;
  if (getpeereid((int)socket, &uid, &group) != 0) return FTUN_E_IO;
#else
  struct ucred credential;
  socklen_t size = sizeof(credential);
  if (getsockopt((int)socket, SOL_SOCKET, SO_PEERCRED, &credential, &size) != 0 ||
      size != sizeof(credential)) return FTUN_E_IO;
  uid = credential.uid;
#endif
  *allowed = uid == 0u || uid == geteuid();
  *user_id = (uint64_t)uid;
  return FTUN_OK;
}
