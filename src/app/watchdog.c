#define _GNU_SOURCE 1
#include "app/watchdog.h"
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define FTUN_WATCHDOG_MAGIC UINT32_C(0x46545744)
#define FTUN_WATCHDOG_MIN_INTERVAL_MS 50u
#define FTUN_WATCHDOG_DIAGNOSTIC_BYTES 512u

typedef struct {
  ftun_watchdog_owner_t owner;
  _Atomic uint64_t request;
  _Atomic uint64_t ack;
} ftun_watchdog_slot_t;

struct ftun_watchdog {
  uint32_t magic;
  ftun_watchdog_spec_t spec;
  uint32_t interval_ms;
  /* 服务管理器要求喂狗（WATCHDOG_USEC）。 */
  bool manager_watchdog;
  ftun_watchdog_slot_t slots[FTUN_WATCHDOG_MAX_OWNERS];
  _Atomic size_t slot_count;
  _Atomic int phase; /* 0 未就绪，1 判定中，2 停止中 */
  _Atomic bool stop;
  _Atomic bool fired;
  pthread_t thread;
  bool thread_started;
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  bool quit;
  timer_t timer;
  bool timer_armed;
  char diagnostic[FTUN_WATCHDOG_DIAGNOSTIC_BYTES];
};

static uint64_t ftun_watchdog_now_ms(void)
{
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0u;
  return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}

ftun_status_t ftun_watchdog_notify(const char *state)
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
  descriptor = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (descriptor < 0) return FTUN_E_IO;
  sent = sendto(descriptor, state, strlen(state), MSG_NOSIGNAL,
                (const struct sockaddr *)&address, length);
  (void)close(descriptor);
  return sent < 0 ? FTUN_E_IO : FTUN_OK;
}

static void ftun_watchdog_default_terminate(void *context)
{
  (void)context;
  _exit(FTUN_WATCHDOG_EXIT_CODE);
}

/* 诊断只做一次有界的尽力写入：描述符不可写就放弃，绝不阻塞后续步骤。 */
static void ftun_watchdog_diagnose(ftun_watchdog_t *watchdog, uint64_t silent_ms)
{
  struct pollfd entry;
  int length;
  if (watchdog->spec.diagnostic_fd < 0) return;
  length = snprintf(watchdog->diagnostic, sizeof(watchdog->diagnostic),
    "ftun: watchdog: owner unresponsive for %llu ms; requesting stop\n",
    (unsigned long long)silent_ms);
  if (length <= 0) return;
  entry.fd = watchdog->spec.diagnostic_fd;
  entry.events = POLLOUT;
  entry.revents = 0;
  if (poll(&entry, 1, 0) == 1 && (entry.revents & POLLOUT) != 0) {
    ssize_t written = write(entry.fd, watchdog->diagnostic, (size_t)length);
    (void)written;
  }
}

/* 内核按 CLOCK_MONOTONIC 递送 SIGALRM，进程不安装处理函数，默认处置终止进程。
 * 即使看门狗线程之后被阻塞，也会交给服务管理器重新拉起。 */
static void ftun_watchdog_arm_alarm(ftun_watchdog_t *watchdog)
{
  struct sigevent event;
  struct itimerspec value;
  uint64_t total = (uint64_t)watchdog->spec.stop_ms + watchdog->spec.grace_ms;
  if (!watchdog->spec.arm_alarm) return;
  memset(&event, 0, sizeof(event));
  event.sigev_notify = SIGEV_SIGNAL;
  event.sigev_signo = SIGALRM;
  if (timer_create(CLOCK_MONOTONIC, &event, &watchdog->timer) != 0) return;
  memset(&value, 0, sizeof(value));
  value.it_value.tv_sec = (time_t)(total / 1000u);
  value.it_value.tv_nsec = (long)(total % 1000u) * 1000000L;
  if (timer_settime(watchdog->timer, 0, &value, NULL) == 0) {
    watchdog->timer_armed = true;
  } else {
    (void)timer_delete(watchdog->timer);
  }
}

static void ftun_watchdog_wake_all(ftun_watchdog_t *watchdog)
{
  size_t count = atomic_load(&watchdog->slot_count);
  size_t index;
  for (index = 0u; index < count; index++) {
    ftun_watchdog_slot_t *slot = &watchdog->slots[index];
    if (slot->owner.wake != NULL) slot->owner.wake(slot->owner.context);
  }
}

/* 所有 owner 的确认序号都追上了上一次请求。 */
static bool ftun_watchdog_acked(ftun_watchdog_t *watchdog, uint64_t request)
{
  size_t count = atomic_load(&watchdog->slot_count);
  size_t index;
  for (index = 0u; index < count; index++) {
    if (atomic_load(&watchdog->slots[index].ack) < request) return false;
  }
  return true;
}

static int ftun_watchdog_wait(ftun_watchdog_t *watchdog, uint32_t wait_ms)
{
  struct timespec deadline;
  bool quit;
  int result = 0;
  (void)clock_gettime(CLOCK_MONOTONIC, &deadline);
  deadline.tv_sec += (time_t)(wait_ms / 1000u);
  deadline.tv_nsec += (long)(wait_ms % 1000u) * 1000000L;
  if (deadline.tv_nsec >= 1000000000L) {
    deadline.tv_sec++;
    deadline.tv_nsec -= 1000000000L;
  }
  (void)pthread_mutex_lock(&watchdog->mutex);
  while (!watchdog->quit && result == 0) {
    result = pthread_cond_timedwait(&watchdog->condition, &watchdog->mutex,
                                    &deadline);
  }
  quit = watchdog->quit;
  (void)pthread_mutex_unlock(&watchdog->mutex);
  return quit ? 1 : 0;
}

static void *ftun_watchdog_thread(void *user)
{
  ftun_watchdog_t *watchdog = (ftun_watchdog_t *)user;
  uint64_t last_ack_ms = ftun_watchdog_now_ms();
  uint64_t previous_request = 0u;
  bool judged = false;
  for (;;) {
    int phase;
    if (ftun_watchdog_wait(watchdog, watchdog->interval_ms)) break;
    phase = atomic_load(&watchdog->phase);
    if (phase == 0) {
      last_ack_ms = ftun_watchdog_now_ms();
      continue;
    }
    if (phase == 2) continue;
    if (!judged) {
      judged = true;
      last_ack_ms = ftun_watchdog_now_ms();
    } else if (ftun_watchdog_acked(watchdog, previous_request)) {
      last_ack_ms = ftun_watchdog_now_ms();
      if (watchdog->manager_watchdog) (void)ftun_watchdog_notify("WATCHDOG=1");
    } else if (watchdog->spec.timeout_ms != 0u &&
               ftun_watchdog_now_ms() - last_ack_ms >= watchdog->spec.timeout_ms) {
      /* 先设置独立的最终期限，再做可能受阻的动作。 */
      ftun_watchdog_arm_alarm(watchdog);
      atomic_store(&watchdog->fired, true);
      ftun_watchdog_diagnose(watchdog, ftun_watchdog_now_ms() - last_ack_ms);
      atomic_store(&watchdog->stop, true);
      ftun_watchdog_wake_all(watchdog);
      if (!ftun_watchdog_wait(watchdog,
            watchdog->spec.stop_ms + watchdog->spec.grace_ms)) {
        if (watchdog->spec.terminate != NULL) {
          watchdog->spec.terminate(watchdog->spec.terminate_context);
        } else {
          ftun_watchdog_default_terminate(NULL);
        }
      }
      break;
    }
    {
      size_t count = atomic_load(&watchdog->slot_count);
      size_t index;
      for (index = 0u; index < count; index++) {
        previous_request = atomic_fetch_add(&watchdog->slots[index].request, 1u) + 1u;
      }
    }
    ftun_watchdog_wake_all(watchdog);
  }
  return NULL;
}

static bool ftun_watchdog_parse_manager(uint32_t *interval_ms)
{
  const char *usec = getenv("WATCHDOG_USEC");
  const char *pid = getenv("WATCHDOG_PID");
  char *end = NULL;
  unsigned long long value;
  if (usec == NULL || usec[0] == '\0') return false;
  if (pid != NULL && pid[0] != '\0') {
    unsigned long long owner = strtoull(pid, &end, 10);
    if (end == pid || owner != (unsigned long long)getpid()) return false;
  }
  value = strtoull(usec, &end, 10);
  if (end == usec || *end != '\0' || value < 2000u) return false;
  value /= 2000u; /* 微秒折半后转毫秒 */
  *interval_ms = value > UINT32_MAX ? UINT32_MAX : (uint32_t)value;
  return true;
}

ftun_status_t ftun_watchdog_create(const ftun_watchdog_spec_t *spec,
                                   ftun_watchdog_t **out)
{
  ftun_watchdog_t *watchdog;
  uint32_t manager_ms = 0u;
  bool manager;
  if (out != NULL) *out = NULL;
  if (spec == NULL || out == NULL) return FTUN_E_INVALID;
  manager = ftun_watchdog_parse_manager(&manager_ms);
  if (spec->timeout_ms == 0u && !manager) return FTUN_OK;
  watchdog = (ftun_watchdog_t *)calloc(1u, sizeof(*watchdog));
  if (watchdog == NULL) return FTUN_E_LIMIT;
  watchdog->magic = FTUN_WATCHDOG_MAGIC;
  watchdog->spec = *spec;
  watchdog->manager_watchdog = manager;
  watchdog->interval_ms = spec->timeout_ms != 0u ? spec->timeout_ms / 3u : UINT32_MAX;
  if (manager && manager_ms < watchdog->interval_ms) watchdog->interval_ms = manager_ms;
  if (watchdog->interval_ms < FTUN_WATCHDOG_MIN_INTERVAL_MS) {
    watchdog->interval_ms = FTUN_WATCHDOG_MIN_INTERVAL_MS;
  }
  if (pthread_mutex_init(&watchdog->mutex, NULL) != 0) {
    free(watchdog);
    return FTUN_E_IO;
  }
  {
    pthread_condattr_t attribute;
    int result = pthread_condattr_init(&attribute);
    if (result == 0) {
      result = pthread_condattr_setclock(&attribute, CLOCK_MONOTONIC);
      if (result == 0) result = pthread_cond_init(&watchdog->condition, &attribute);
      (void)pthread_condattr_destroy(&attribute);
    }
    if (result != 0) {
      (void)pthread_mutex_destroy(&watchdog->mutex);
      free(watchdog);
      return FTUN_E_IO;
    }
  }
  if (pthread_create(&watchdog->thread, NULL, ftun_watchdog_thread,
                     watchdog) != 0) {
    (void)pthread_cond_destroy(&watchdog->condition);
    (void)pthread_mutex_destroy(&watchdog->mutex);
    free(watchdog);
    return FTUN_E_IO;
  }
  watchdog->thread_started = true;
  *out = watchdog;
  return FTUN_OK;
}

ftun_status_t ftun_watchdog_register(ftun_watchdog_t *watchdog,
                                     const ftun_watchdog_owner_t *owner,
                                     size_t *slot)
{
  size_t index;
  if (watchdog == NULL || owner == NULL || slot == NULL) return FTUN_E_INVALID;
  index = atomic_load(&watchdog->slot_count);
  if (index >= FTUN_WATCHDOG_MAX_OWNERS) return FTUN_E_LIMIT;
  watchdog->slots[index].owner = *owner;
  atomic_store(&watchdog->slot_count, index + 1u);
  *slot = index;
  return FTUN_OK;
}

void ftun_watchdog_ack(ftun_watchdog_t *watchdog, size_t slot)
{
  if (watchdog == NULL || slot >= FTUN_WATCHDOG_MAX_OWNERS) return;
  atomic_store(&watchdog->slots[slot].ack,
               atomic_load(&watchdog->slots[slot].request));
}

bool ftun_watchdog_stop_requested(const ftun_watchdog_t *watchdog)
{
  return watchdog != NULL && atomic_load(&watchdog->stop);
}

bool ftun_watchdog_fired(const ftun_watchdog_t *watchdog)
{
  return watchdog != NULL && atomic_load(&watchdog->fired);
}

void ftun_watchdog_ready(ftun_watchdog_t *watchdog)
{
  (void)ftun_watchdog_notify("READY=1");
  if (watchdog != NULL) atomic_store(&watchdog->phase, 1);
}

void ftun_watchdog_stopping(ftun_watchdog_t *watchdog)
{
  (void)ftun_watchdog_notify("STOPPING=1");
  if (watchdog != NULL) atomic_store(&watchdog->phase, 2);
}

ftun_status_t ftun_watchdog_destroy(ftun_watchdog_t **out)
{
  ftun_watchdog_t *watchdog;
  if (out == NULL) return FTUN_E_INVALID;
  watchdog = *out;
  if (watchdog == NULL) return FTUN_OK;
  if (watchdog->magic != FTUN_WATCHDOG_MAGIC) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&watchdog->mutex);
  watchdog->quit = true;
  (void)pthread_cond_broadcast(&watchdog->condition);
  (void)pthread_mutex_unlock(&watchdog->mutex);
  if (watchdog->thread_started) (void)pthread_join(watchdog->thread, NULL);
  if (watchdog->timer_armed) (void)timer_delete(watchdog->timer);
  (void)pthread_cond_destroy(&watchdog->condition);
  (void)pthread_mutex_destroy(&watchdog->mutex);
  watchdog->magic = 0u;
  free(watchdog);
  *out = NULL;
  return FTUN_OK;
}
