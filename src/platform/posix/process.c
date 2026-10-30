#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include "platform/posix/socket_native.h"
#include "platform/process.h"
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

