#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include "platform/posix/socket_native.h"
#include "platform/process.h"
#include "platform/clock.h"
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static const int native_signals[] = {SIGHUP, SIGINT, SIGTERM, SIGUSR1};
static void signal_set(uint32_t signals, sigset_t *set)
{
  size_t index;
  (void)sigemptyset(set);
  for (index = 0u; index < sizeof(native_signals) / sizeof(native_signals[0]); index++) {
    if ((signals & (1u << index)) != 0u) (void)sigaddset(set, native_signals[index]);
  }
}
static int native_signal(uint32_t signal)
{
  size_t index;
  for (index = 0u; index < sizeof(native_signals) / sizeof(native_signals[0]); index++) {
    if (signal == (1u << index)) return native_signals[index];
  }
  return 0;
}
ftun_status_t ftun_signals_block(uint32_t signals, ftun_signal_mask_t *previous)
{
  sigset_t set, old;
  size_t index;
  signal_set(signals, &set);
  if (pthread_sigmask(SIG_BLOCK, &set, &old) != 0) return FTUN_E_IO;
  previous->signals = signals;
  previous->blocked = 0u;
  for (index = 0u; index < sizeof(native_signals) / sizeof(native_signals[0]); index++) {
    if (sigismember(&old, native_signals[index]) == 1) previous->blocked |= 1u << index;
  }
  return FTUN_OK;
}
ftun_status_t ftun_signals_restore(const ftun_signal_mask_t *previous)
{
  sigset_t block, unblock;
  signal_set(previous->signals & previous->blocked, &block);
  signal_set(previous->signals & ~previous->blocked, &unblock);
  if (pthread_sigmask(SIG_BLOCK, &block, NULL) != 0) return FTUN_E_IO;
  return pthread_sigmask(SIG_UNBLOCK, &unblock, NULL) == 0 ? FTUN_OK : FTUN_E_IO;
}
ftun_status_t ftun_signal_wait(uint32_t signals, uint32_t *received)
{
  sigset_t set;
  int value;
  size_t index;
  signal_set(signals, &set);
  if (sigwait(&set, &value) != 0) return FTUN_E_IO;
  for (index = 0u; index < sizeof(native_signals) / sizeof(native_signals[0]); index++) {
    if (value == native_signals[index]) { *received = 1u << index; return FTUN_OK; }
  }
  return FTUN_E_STATE_CORRUPT;
}
ftun_status_t ftun_thread_signal(ftun_thread_t *thread, uint32_t signal)
{
  int native = native_signal(signal);
  if (native == 0) return FTUN_E_INVALID;
  return pthread_kill(thread->native, native) == 0 ? FTUN_OK : FTUN_E_IO;
}
ftun_status_t ftun_process_signal(uint32_t pid, uint32_t signal, int *native_error)
{
  int native = native_signal(signal);
  if (pid <= 1u || pid > INT_MAX || native == 0) return FTUN_E_INVALID;
  *native_error = 0;
  if (kill((pid_t)pid, native) == 0) return FTUN_OK;
  *native_error = errno;
  return FTUN_E_IO;
}
uint32_t ftun_process_id(void)
{
  return (uint32_t)getpid();
}
void ftun_process_exit(int code)
{
  _exit(code);
}
ftun_status_t ftun_process_notify(const char *state)
{
  const char *path = getenv("NOTIFY_SOCKET");
  struct sockaddr_un address;
  socklen_t length;
  size_t path_length;
  ssize_t sent;
  int descriptor;
  if (state == NULL) return FTUN_E_INVALID;
  if (path == NULL || path[0] == '\0') return FTUN_OK;
  path_length = strlen(path);
  if ((path[0] != '/' && path[0] != '@') || path_length >= sizeof(address.sun_path)) {
    return FTUN_E_INVALID;
  }
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path, path, path_length);
  /* '@' 开头是抽象命名空间，首字节置 0，长度不含结尾 NUL。 */
  if (path[0] == '@') address.sun_path[0] = '\0';
  length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_length +
                       (path[0] == '@' ? 0u : 1u));
  descriptor = ftun_posix_socket(AF_UNIX, SOCK_DGRAM, 0);
  if (descriptor < 0) return FTUN_E_IO;
  sent = sendto(descriptor, state, strlen(state), MSG_NOSIGNAL,
                (const struct sockaddr *)&address, length);
  (void)close(descriptor);
  return sent < 0 ? FTUN_E_IO : FTUN_OK;
}


ftun_status_t ftun_process_background_fork(ftun_handle_t *channel, bool *child, uint32_t *pid)
{
  int descriptors[2];
  pid_t created;
  *channel = -1;
  *child = false;
  *pid = 0u;
  if (pipe(descriptors) != 0) return FTUN_E_IO;
  if (fcntl(descriptors[0], F_SETFD, FD_CLOEXEC) != 0 ||
      fcntl(descriptors[1], F_SETFD, FD_CLOEXEC) != 0 ||
      fcntl(descriptors[0], F_SETFL, O_NONBLOCK) != 0 ||
      fcntl(descriptors[1], F_SETFL, O_NONBLOCK) != 0) {
    (void)close(descriptors[0]); (void)close(descriptors[1]);
    return FTUN_E_IO;
  }
  created = fork();
  if (created < 0) {
    (void)close(descriptors[0]); (void)close(descriptors[1]);
    return FTUN_E_IO;
  }
  *child = created == 0;
  *pid = created == 0 ? (uint32_t)getpid() : (uint32_t)created;
  *channel = descriptors[created == 0 ? 1 : 0];
  (void)close(descriptors[created == 0 ? 0 : 1]);
  return FTUN_OK;
}
ftun_status_t ftun_process_standard_ensure(void)
{
  int descriptor;
  for (descriptor = 0; descriptor < 3; descriptor++) {
    if (fcntl(descriptor, F_GETFD) >= 0) continue;
    if (errno != EBADF || open("/dev/null", O_RDWR) < 0) return FTUN_E_IO;
  }
  return FTUN_OK;
}
ftun_status_t ftun_process_background_session(void)
{
  return setsid() < 0 ? FTUN_E_IO : FTUN_OK;
}

static ftun_status_t ftun_process_pipe_io(ftun_handle_t descriptor, void *data,
  size_t length, uint64_t deadline_ms, bool writing)
{
  size_t offset = 0u;
  while (offset < length) {
    uint64_t now;
    struct pollfd observed = {(int)descriptor, writing ? POLLOUT : POLLIN, 0};
    int ready, milliseconds;
    if (ftun_monotonic_now(&now) != FTUN_OK) return FTUN_E_IO;
    if (now >= deadline_ms) return FTUN_E_TIMEOUT;
    milliseconds = deadline_ms - now > 100u ? 100 : (int)(deadline_ms - now);
    ready = poll(&observed, 1u, milliseconds);
    if (ready < 0) { if (errno == EINTR) continue; return FTUN_E_IO; }
    if (ready == 0) continue;
    if (ftun_monotonic_now(&now) != FTUN_OK) return FTUN_E_IO;
    if (now >= deadline_ms) return FTUN_E_TIMEOUT;
    ssize_t count = writing ? write((int)descriptor, (const uint8_t *)data + offset, length - offset) :
      read((int)descriptor, (uint8_t *)data + offset, length - offset);
    if (count > 0) offset += (size_t)count;
    else if (count == 0) return FTUN_E_EOF;
    else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) return FTUN_E_IO;
  }
  return FTUN_OK;
}
ftun_status_t ftun_process_pipe_read(ftun_handle_t channel, void *data, size_t length, uint64_t deadline_ms)
{
  return ftun_process_pipe_io(channel, data, length, deadline_ms, false);
}
ftun_status_t ftun_process_pipe_write(ftun_handle_t channel, const void *data, size_t length, uint64_t deadline_ms)
{
  return ftun_process_pipe_io(channel, (void *)data, length, deadline_ms, true);
}

ftun_status_t ftun_process_null_open(ftun_handle_t *out)
{
  *out = open("/dev/null", O_RDWR | O_CLOEXEC);
  return *out >= 0 ? FTUN_OK : FTUN_E_IO;
}
ftun_status_t ftun_process_stdio_null(ftun_handle_t descriptor)
{
  int target;
  for (target = 0; target < 3; target++) {
    if (dup2((int)descriptor, target) < 0) return FTUN_E_IO;
  }
  return FTUN_OK;
}
