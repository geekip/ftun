#define _POSIX_C_SOURCE 200809L
#include "platform/process.h"
#include "platform/clock.h"
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "process pipe failed at %d: %s\n", __LINE__, #x); return 1; } } while (0)
static uint64_t now_ms;
static bool expire_on_poll;
static size_t polls;

ftun_status_t __wrap_ftun_monotonic_now(uint64_t *out)
{
  *out = now_ms;
  return FTUN_OK;
}

int __real_poll(struct pollfd *fds, nfds_t count, int timeout);
int __wrap_poll(struct pollfd *fds, nfds_t count, int timeout)
{
  int ready = __real_poll(fds, count, timeout);
  polls++;
  if (expire_on_poll) now_ms = 101u;
  return ready;
}

int main(void)
{
  int channel[2];
  char byte;
  CHECK(pipe(channel) == 0);
  CHECK(write(channel[1], "x", 1u) == 1);
  now_ms = 100u;
  CHECK(ftun_process_pipe_read(channel[0], &byte, 1u, 101u) == FTUN_OK && byte == 'x');
  CHECK(close(channel[1]) == 0);
  CHECK(ftun_process_pipe_read(channel[0], &byte, 1u, 101u) == FTUN_E_EOF);
  /* EOF已就绪，但poll返回时期限已到，不能把超时误报成提前退出。 */
  expire_on_poll = true;
  CHECK(ftun_process_pipe_read(channel[0], &byte, 1u, 101u) == FTUN_E_TIMEOUT);
  CHECK(close(channel[0]) == 0);
  CHECK(pipe(channel) == 0 && write(channel[1], "y", 1u) == 1);
  now_ms = 100u;
  CHECK(ftun_process_pipe_read(channel[0], &byte, 1u, 101u) == FTUN_E_TIMEOUT);
  CHECK(read(channel[0], &byte, 1u) == 1 && byte == 'y');
  now_ms = 100u;
  CHECK(ftun_process_pipe_write(channel[1], "z", 1u, 101u) == FTUN_E_TIMEOUT);
  CHECK(close(channel[1]) == 0);
  CHECK(read(channel[0], &byte, 1u) == 0 && close(channel[0]) == 0);
  polls = 0u;
  CHECK(ftun_process_pipe_read(-1, &byte, 1u, 101u) == FTUN_E_TIMEOUT && polls == 0u);
  puts("process pipe: ready, early EOF and deadline after poll passed");
  return 0;
}
