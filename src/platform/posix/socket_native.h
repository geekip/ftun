#ifndef FTUN_PLATFORM_POSIX_SOCKET_NATIVE_H
#define FTUN_PLATFORM_POSIX_SOCKET_NATIVE_H
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#if defined(__APPLE__)
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
static inline int ftun_posix_socket_flags(int descriptor)
{
  int one = 1;
  if (descriptor < 0) return descriptor;
  if (fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0 &&
      fcntl(descriptor, F_SETFL, O_NONBLOCK) == 0 &&
      setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) == 0) return descriptor;
  int error = errno;
  close(descriptor);
  errno = error;
  return -1;
}
#endif
static inline int ftun_posix_socket(int family, int type, int protocol)
{
#if defined(__APPLE__)
  return ftun_posix_socket_flags(socket(family, type, protocol));
#else
  return socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
#endif
}
static inline int ftun_posix_accept(int listener, struct sockaddr *address, socklen_t *length)
{
#if defined(__APPLE__)
  return ftun_posix_socket_flags(accept(listener, address, length));
#else
  return accept4(listener, address, length, SOCK_CLOEXEC | SOCK_NONBLOCK);
#endif
}
static inline int ftun_posix_socket_pair(int pair[2])
{
#if defined(__APPLE__)
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return -1;
  pair[0] = ftun_posix_socket_flags(pair[0]);
  if (pair[0] < 0) { close(pair[1]); return -1; }
  pair[1] = ftun_posix_socket_flags(pair[1]);
  if (pair[1] < 0) { close(pair[0]); return -1; }
  return 0;
#else
  return socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair);
#endif
}
#endif
