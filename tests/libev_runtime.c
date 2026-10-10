#include <signal.h>
#include <stdio.h>

#include <ev.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "libev runtime failed: %s\n", #x); \
    return 1; \
  } \
} while (0)

static int signal_calls;

static void signal_ready(EV_P_ ev_signal *watcher, int revents)
{
  (void)watcher;
  if ((revents & EV_SIGNAL) != 0) signal_calls++;
  ev_break(loop, EVBREAK_ONE);
}

/* TASK-EVENT-002 / TEST-EVENT-002：验证所选 epoll 构建的信号和退出路径。 */
int main(void)
{
  struct ev_loop *loop;
  ev_signal watcher;

  loop = ev_loop_new(EVFLAG_NOENV | EVBACKEND_EPOLL);
  CHECK(loop != NULL);
  CHECK(ev_backend(loop) == EVBACKEND_EPOLL);
  ev_signal_init(&watcher, signal_ready, SIGUSR1);
  ev_signal_start(loop, &watcher);
  CHECK(raise(SIGUSR1) == 0);
  (void)ev_run(loop, EVRUN_ONCE);
  CHECK(signal_calls == 1);
  ev_signal_stop(loop, &watcher);
  ev_loop_destroy(loop);
  return 0;
}
