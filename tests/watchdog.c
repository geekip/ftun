#define _GNU_SOURCE 1
#include "app/watchdog.h"
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "watchdog failed at %d: %s\n", __LINE__, #x); return 1; } } while (0)

static void sleep_ms(unsigned int value)
{
  struct timespec pause = {value / 1000u, (long)(value % 1000u) * 1000000L};
  (void)nanosleep(&pause, NULL);
}

/* 模拟 owner：mode 0 每轮确认，1 死循环不确认，2 持锁卡死。 */
typedef struct {
  ftun_watchdog_t *watchdog;
  size_t slot;
  int mode;
  pthread_mutex_t mutex;
  _Atomic bool run;
  _Atomic unsigned int wakes;
  _Atomic bool terminated;
  _Atomic bool saw_stop;
} owner_t;

static void owner_wake(void *user)
{
  owner_t *owner = user;
  atomic_fetch_add(&owner->wakes, 1u);
  /* 与产品一致：拿不到锁就跳过，绝不等待。 */
  if (pthread_mutex_trylock(&owner->mutex) == 0) (void)pthread_mutex_unlock(&owner->mutex);
}

static void *owner_thread(void *user)
{
  owner_t *owner = user;
  if (owner->mode == 2) (void)pthread_mutex_lock(&owner->mutex);
  while (atomic_load(&owner->run)) {
    if (owner->mode == 0) ftun_watchdog_ack(owner->watchdog, owner->slot);
    if (ftun_watchdog_stop_requested(owner->watchdog)) atomic_store(&owner->saw_stop, true);
    sleep_ms(5u);
  }
  if (owner->mode == 2) (void)pthread_mutex_unlock(&owner->mutex);
  return NULL;
}

static void terminated(void *user)
{
  atomic_store(&((owner_t *)user)->terminated, true);
}

static int start(owner_t *owner, ftun_watchdog_spec_t spec, int mode, pthread_t *thread)
{
  ftun_watchdog_owner_t registration;
  memset(owner, 0, sizeof(*owner));
  owner->mode = mode;
  atomic_store(&owner->run, true);
  pthread_mutex_init(&owner->mutex, NULL);
  spec.terminate = terminated;
  spec.terminate_context = owner;
  if (ftun_watchdog_create(&spec, &owner->watchdog) != FTUN_OK || owner->watchdog == NULL) return 1;
  registration.wake = owner_wake;
  registration.context = owner;
  if (ftun_watchdog_register(owner->watchdog, &registration, &owner->slot) != FTUN_OK) return 1;
  ftun_watchdog_ready(owner->watchdog);
  return pthread_create(thread, NULL, owner_thread, owner) != 0;
}

static int finish(owner_t *owner, pthread_t thread)
{
  atomic_store(&owner->run, false);
  pthread_join(thread, NULL);
  CHECK(ftun_watchdog_destroy(&owner->watchdog) == FTUN_OK && owner->watchdog == NULL);
  pthread_mutex_destroy(&owner->mutex);
  return 0;
}

static ftun_watchdog_spec_t base_spec(void)
{
  ftun_watchdog_spec_t spec;
  memset(&spec, 0, sizeof(spec));
  spec.timeout_ms = 300u;
  spec.stop_ms = 200u;
  spec.grace_ms = 100u;
  spec.diagnostic_fd = -1;
  return spec;
}

static int test_healthy(void)
{
  owner_t owner;
  pthread_t thread;
  CHECK(start(&owner, base_spec(), 0, &thread) == 0);
  sleep_ms(1200u);
  CHECK(!ftun_watchdog_fired(owner.watchdog) && !ftun_watchdog_stop_requested(owner.watchdog));
  CHECK(atomic_load(&owner.wakes) >= 5u && !atomic_load(&owner.terminated));
  return finish(&owner, thread);
}

static int test_notify(void)
{
  struct sockaddr_un address;
  char path[64];
  char buffer[32];
  int server;
  ssize_t length;
  snprintf(path, sizeof(path), "/tmp/ftun-wd-%d.sock", (int)getpid());
  unlink(path);
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  strcpy(address.sun_path, path);
  server = socket(AF_UNIX, SOCK_DGRAM, 0);
  CHECK(server >= 0 && bind(server, (struct sockaddr *)&address, sizeof(address)) == 0);
  setenv("NOTIFY_SOCKET", path, 1);
  CHECK(ftun_watchdog_notify("READY=1") == FTUN_OK);
  length = recv(server, buffer, sizeof(buffer) - 1u, MSG_DONTWAIT);
  CHECK(length == 7 && memcmp(buffer, "READY=1", 7u) == 0);
  CHECK(ftun_watchdog_notify("STOPPING=1") == FTUN_OK);
  length = recv(server, buffer, sizeof(buffer) - 1u, MSG_DONTWAIT);
  CHECK(length == 10 && memcmp(buffer, "STOPPING=1", 10u) == 0);
  /* 未设置时什么也不做；路径形式非法时报错。 */
  unsetenv("NOTIFY_SOCKET");
  CHECK(ftun_watchdog_notify("READY=1") == FTUN_OK);
  setenv("NOTIFY_SOCKET", "relative/path", 1);
  CHECK(ftun_watchdog_notify("READY=1") == FTUN_E_INVALID);
  /* 抽象命名空间。 */
  close(server);
  unlink(path);
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1u, "ftun-wd-%d", (int)getpid());
  server = socket(AF_UNIX, SOCK_DGRAM, 0);
  CHECK(bind(server, (struct sockaddr *)&address,
             (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1u +
                         strlen(address.sun_path + 1))) == 0);
  snprintf(path, sizeof(path), "@ftun-wd-%d", (int)getpid());
  setenv("NOTIFY_SOCKET", path, 1);
  CHECK(ftun_watchdog_notify("READY=1") == FTUN_OK);
  length = recv(server, buffer, sizeof(buffer) - 1u, MSG_DONTWAIT);
  CHECK(length == 7 && memcmp(buffer, "READY=1", 7u) == 0);
  close(server);
  unsetenv("NOTIFY_SOCKET");
  return 0;
}

/* 服务管理器要求喂狗时（timeout 为 0 也创建线程），每次确认后发送 WATCHDOG=1。 */
static int test_manager_ping(void)
{
  struct sockaddr_un address;
  char path[64];
  char buffer[32];
  char usec[16] = "200000";
  char pid[16];
  owner_t owner;
  pthread_t thread;
  ftun_watchdog_spec_t spec = base_spec();
  int server;
  ssize_t length;
  int pings = 0;
  int tries;
  snprintf(path, sizeof(path), "/tmp/ftun-wd-ping-%d.sock", (int)getpid());
  unlink(path);
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  strcpy(address.sun_path, path);
  server = socket(AF_UNIX, SOCK_DGRAM, 0);
  CHECK(server >= 0 && bind(server, (struct sockaddr *)&address, sizeof(address)) == 0);
  snprintf(pid, sizeof(pid), "%d", (int)getpid());
  setenv("NOTIFY_SOCKET", path, 1);
  setenv("WATCHDOG_USEC", usec, 1);
  setenv("WATCHDOG_PID", pid, 1);
  spec.timeout_ms = 0u;
  CHECK(start(&owner, spec, 0, &thread) == 0);
  for (tries = 0; tries < 40 && pings < 3; tries++) {
    sleep_ms(50u);
    while ((length = recv(server, buffer, sizeof(buffer) - 1u, MSG_DONTWAIT)) > 0) {
      if (length == 10 && memcmp(buffer, "WATCHDOG=1", 10u) == 0) pings++;
    }
  }
  CHECK(pings >= 3 && !ftun_watchdog_fired(owner.watchdog));
  CHECK(finish(&owner, thread) == 0);
  /* WATCHDOG_PID 指向别的进程时忽略，且 timeout 为 0 时不创建。 */
  setenv("WATCHDOG_PID", "1", 1);
  {
    ftun_watchdog_t *none = (ftun_watchdog_t *)(uintptr_t)1;
    CHECK(ftun_watchdog_create(&spec, &none) == FTUN_OK && none == NULL);
  }
  close(server);
  unlink(path);
  unsetenv("NOTIFY_SOCKET");
  unsetenv("WATCHDOG_USEC");
  unsetenv("WATCHDOG_PID");
  return 0;
}

int main(void)
{
  int pipe_fds[2];
  char filler[4096];
  ssize_t written;
  unsetenv("NOTIFY_SOCKET");
  unsetenv("WATCHDOG_USEC");
  unsetenv("WATCHDOG_PID");
  if (test_healthy() != 0) return 1;
  if (test_notify() != 0) return 1;
  if (test_manager_ping() != 0) return 1;

  /* owner 死循环：判定、请求停止，宽限结束后调用终止函数。 */
  {
    owner_t owner;
    pthread_t thread;
    CHECK(start(&owner, base_spec(), 1, &thread) == 0);
    sleep_ms(500u);
    CHECK(ftun_watchdog_fired(owner.watchdog) && atomic_load(&owner.saw_stop));
    CHECK(!atomic_load(&owner.terminated));
    sleep_ms(500u);
    CHECK(atomic_load(&owner.terminated));
    if (finish(&owner, thread) != 0) return 1;
  }

  /* owner 持锁卡死：唤醒不得等待该锁，判定与终止照常。 */
  {
    owner_t owner;
    pthread_t thread;
    CHECK(start(&owner, base_spec(), 2, &thread) == 0);
    sleep_ms(1000u);
    CHECK(ftun_watchdog_fired(owner.watchdog) && atomic_load(&owner.terminated));
    if (finish(&owner, thread) != 0) return 1;
  }

  /* 诊断输出被堵住（管道写满、没有读端消费）：不阻塞后续步骤。 */
  CHECK(pipe2(pipe_fds, O_NONBLOCK) == 0);
  memset(filler, 'x', sizeof(filler));
  while ((written = write(pipe_fds[1], filler, sizeof(filler))) > 0) {}
  {
    owner_t owner;
    pthread_t thread;
    ftun_watchdog_spec_t spec = base_spec();
    spec.diagnostic_fd = pipe_fds[1];
    CHECK(start(&owner, spec, 1, &thread) == 0);
    sleep_ms(1000u);
    CHECK(ftun_watchdog_fired(owner.watchdog) && atomic_load(&owner.terminated));
    if (finish(&owner, thread) != 0) return 1;
  }
  close(pipe_fds[0]);
  close(pipe_fds[1]);

  /* 诊断可写时输出一行，且不超过 512 字节。 */
  CHECK(pipe2(pipe_fds, O_NONBLOCK) == 0);
  {
    owner_t owner;
    pthread_t thread;
    char line[1024];
    ssize_t length;
    ftun_watchdog_spec_t spec = base_spec();
    spec.diagnostic_fd = pipe_fds[1];
    CHECK(start(&owner, spec, 1, &thread) == 0);
    sleep_ms(600u);
    length = read(pipe_fds[0], line, sizeof(line) - 1u);
    CHECK(length > 0 && length <= 512 && strstr(line, "watchdog") != NULL);
    if (finish(&owner, thread) != 0) return 1;
  }
  close(pipe_fds[0]);
  close(pipe_fds[1]);

  /* owner 在期限内恢复并退出：销毁取消终止，不调用终止函数。 */
  {
    owner_t owner;
    pthread_t thread;
    CHECK(start(&owner, base_spec(), 1, &thread) == 0);
    sleep_ms(450u);
    CHECK(ftun_watchdog_fired(owner.watchdog));
    CHECK(finish(&owner, thread) == 0);
    sleep_ms(300u);
    CHECK(!atomic_load(&owner.terminated));
  }
  puts("Watchdog: heartbeat, hang, mutex hang, blocked diagnostics, notify passed");
  return 0;
}
