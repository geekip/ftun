#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "event/event.h"
#include "event/libev_adapter.h"
#include "util/time.h"
#include <pthread.h>
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "libev adapter failed: %s\n", #x); \
    return 1; \
  } \
} while (0)

static size_t native_ready_calls;
static bool capture_wake_writes, inject_wake_read, wake_injection_failed;
static size_t wake_writes;
static ftun_event_loop_t *wake_injection_loop;
static size_t *wake_injection_count;
static void count_control(void *user);
ssize_t __real_write(int fd, const void *data, size_t length);
ssize_t __wrap_write(int fd, const void *data, size_t length)
{
  if (capture_wake_writes && length == sizeof(uint64_t)) wake_writes++;
  return __real_write(fd, data, length);
}
ssize_t __real_read(int fd, void *data, size_t length);
ssize_t __wrap_read(int fd, void *data, size_t length)
{
  ssize_t result = __real_read(fd, data, length);
  if (inject_wake_read && result == (ssize_t)sizeof(uint64_t) && length == sizeof(uint64_t)) {
    inject_wake_read = false;
    wake_injection_failed = ftun_event_defer(wake_injection_loop,
      count_control, wake_injection_count) != FTUN_OK;
  }
  return result;
}
static int tracked_ctl_fd = -1;
static size_t tracked_ctl_calls, tracked_ctl_adds;
int __real_epoll_ctl(int epoll_fd, int operation, int fd, struct epoll_event *event);
int __wrap_epoll_ctl(int epoll_fd, int operation, int fd, struct epoll_event *event)
{
  if (fd == tracked_ctl_fd) {
    tracked_ctl_calls++;
    if (operation == EPOLL_CTL_ADD) tracked_ctl_adds++;
  }
  return __real_epoll_ctl(epoll_fd, operation, fd, event);
}
static size_t kernel_ready_events;
static int kernel_wait_timeout;
int __real_epoll_wait(int fd, struct epoll_event *events, int maximum, int timeout);
int __wrap_epoll_wait(int fd, struct epoll_event *events, int maximum, int timeout)
{
  int count;
  kernel_wait_timeout = timeout;
  count = __real_epoll_wait(fd, events, maximum, timeout);
  if (count > 0) kernel_ready_events += (size_t)count;
  return count;
}
static bool delay_native_ready;
ftun_status_t __real_ftun_event_io_ready(ftun_event_source_t *source, uint32_t events);
ftun_status_t __wrap_ftun_event_io_ready(ftun_event_source_t *source, uint32_t events)
{
  native_ready_calls++;
  if (delay_native_ready) {
    struct timespec delay = {0, 25000000L};
    (void)nanosleep(&delay, NULL);
  }
  return __real_ftun_event_io_ready(source, events);
}

typedef struct {
  ftun_event_loop_t *loop;
  int read_fd;
  int io_calls;
  int timer_calls;
  int deferred_calls;
  int task_calls;
  int recursive_again;
  ftun_status_t producer_status;
} adapter_state_t;

static void ready(ftun_event_source_t *source, uint32_t events, void *user)
{
  adapter_state_t *state = (adapter_state_t *)user;
  char byte;
  (void)source;
  if ((events & FTUN_EVENT_TASK) != 0u) {
    size_t callbacks = 99u;
    state->task_calls++;
    if (ftun_event_loop_run_once(state->loop, true, 1u, &callbacks) == FTUN_E_AGAIN && callbacks == 0u) state->recursive_again++;
  }
  if ((events & FTUN_EVENT_TIMER) != 0u) state->timer_calls++;
  if ((events & FTUN_EVENT_READ) != 0u) {
    if (read(state->read_fd, &byte, 1u) == 1 && byte == 'x') state->io_calls++;
  }
}

static void deferred(void *user)
{
  adapter_state_t *state = (adapter_state_t *)user;
  state->deferred_calls++;
}

static void *produce(void *user)
{
  adapter_state_t *state = (adapter_state_t *)user;
  struct timespec delay = {0, 5000000L};
  (void)nanosleep(&delay, NULL);
  state->producer_status = ftun_event_defer(state->loop, deferred, state);
  return NULL;
}

typedef struct {
  size_t calls;
  int fd;
} hot_source_t;

static void hot_ready(ftun_event_source_t *source, uint32_t events, void *user)
{
  hot_source_t *state = user;
  (void)source;
  (void)events;
  state->calls++;
}

static void count_control(void *user)
{
  size_t *count = user;
  (*count)++;
}

static int bounded_collection(void)
{
  ftun_event_loop_t *loop = NULL;
  ftun_event_source_t *sources[256] = {0};
  hot_source_t states[256] = {{0}};
  ftun_event_loop_usage_t usage;
  size_t index, round, callbacks, control = 0u;
  uint64_t now;
  CHECK(ftun_event_loop_create_with_capacity(NULL, 256u, &loop) == FTUN_OK);
  CHECK(ftun_libev_attach(loop) == FTUN_OK);
  for (index = 0u; index < 256u; index++) {
    states[index].fd = eventfd(1u, EFD_NONBLOCK | EFD_CLOEXEC);
    CHECK(states[index].fd >= 0);
    CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)states[index].fd, FTUN_EVENT_READ,
      hot_ready, &states[index], &sources[index]) == FTUN_OK);
  }
  /* 持续热 FD 不消耗数据，内核须轮转；控制 defer 仍在两个回调内推进。 */
  for (round = 0u; round < 512u; round++) {
    if (round == 100u) CHECK(ftun_event_defer(loop, count_control, &control) == FTUN_OK);
    native_ready_calls = 0u;
    kernel_ready_events = 0u;
    CHECK(ftun_event_loop_run_once(loop, true, 1u, &callbacks) == FTUN_OK && callbacks == 1u);
    CHECK(native_ready_calls > 0u && native_ready_calls <= 64u);
    CHECK(kernel_ready_events > 0u && kernel_ready_events <= 64u);
    if (round >= 101u) CHECK(control == 1u);
    CHECK(ftun_event_loop_get_usage(loop, &usage) == FTUN_OK &&
      usage.last_backend_work >= native_ready_calls && usage.last_backend_work <= native_ready_calls + 65u &&
      usage.backend_quota_exhausted);
  }
  for (index = 0u; index < 256u; index++) {
    CHECK(states[index].calls > 0u);
    CHECK(ftun_event_source_cancel(&sources[index]) == FTUN_OK);
    CHECK(close(states[index].fd) == 0);
  }
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  for (index = 0u; index < 256u; index++) {
    states[index].calls = 0u;
    CHECK(ftun_event_timer_start(loop, now, hot_ready, &states[index], &sources[index]) == FTUN_OK);
  }
  for (round = 0u; round < 256u; round++) {
    CHECK(ftun_event_loop_run_once(loop, true, 1u, &callbacks) == FTUN_OK && callbacks == 1u);
    CHECK(ftun_event_loop_get_usage(loop, &usage) == FTUN_OK &&
      usage.last_timer_work == 1u && usage.ready_count == 0u && usage.last_backend_work <= 1u);
  }
  for (index = 0u; index < 256u; index++) {
    CHECK(states[index].calls == 1u);
    CHECK(ftun_event_source_cancel(&sources[index]) == FTUN_OK);
  }
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_libev_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  return 0;
}

typedef struct {
  size_t calls;
  uint32_t events;
  ftun_event_source_t **self;
  ftun_event_source_t **cancel_cursor;
  ftun_event_source_t **cancel_ready;
  bool failed;
} duplicate_state_t;

static void duplicate_ready(ftun_event_source_t *source, uint32_t events, void *user)
{
  duplicate_state_t *state = user;
  (void)source;
  state->calls++;
  state->events |= events;
  if (state->cancel_cursor != NULL) {
    if (ftun_event_source_cancel(state->cancel_cursor) != FTUN_OK ||
        ftun_event_source_cancel(state->cancel_ready) != FTUN_OK ||
        ftun_event_source_cancel(state->self) != FTUN_OK) state->failed = true;
    state->cancel_cursor = NULL;
  }
}

static int duplicate_collection(void)
{
  ftun_event_loop_t *loop = NULL;
  ftun_event_source_t *sources[1024] = {0}, *cold = NULL;
  duplicate_state_t states[1024] = {{0}}, cold_state = {0};
  ftun_event_loop_usage_t usage;
  size_t index, round, callbacks, control = 0u;
  int fd = eventfd(1u, EFD_NONBLOCK | EFD_CLOEXEC);
  int cold_fd = eventfd(1u, EFD_NONBLOCK | EFD_CLOEXEC);
  CHECK(fd >= 0 && cold_fd >= 0);
  CHECK(ftun_event_loop_create_with_capacity(NULL, 1025u, &loop) == FTUN_OK);
  CHECK(ftun_libev_attach(loop) == FTUN_OK);
  for (index = 0u; index < 1024u; index++) {
    CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)fd, FTUN_EVENT_READ,
      duplicate_ready, &states[index], &sources[index]) == FTUN_OK);
  }
  /* 读事件仍持续，更新不能重启当前成员游标。第一轮回调同时撤销
   * native batch游标、已入前端队列的另一项及自身。 */
  states[1023].self = &sources[1023];
  states[1023].cancel_cursor = &sources[959];
  states[1023].cancel_ready = &sources[1000];
  CHECK(ftun_event_loop_run_once(loop, false, 16u, &callbacks) == FTUN_OK);
  /* 热batch已保留未完成游标后才接纳冷FD，避免冷FD先完成掩盖饥饿。 */
  CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)cold_fd, FTUN_EVENT_READ,
    duplicate_ready, &cold_state, &cold) == FTUN_OK);
  CHECK(ftun_event_defer(loop, count_control, &control) == FTUN_OK);
  for (round = 0u; round < 96u; round++) {
    native_ready_calls = 0u;
    kernel_ready_events = 0u;
    CHECK(ftun_event_loop_run_once(loop, true, 16u, &callbacks) == FTUN_OK && callbacks <= 16u);
    CHECK(native_ready_calls <= 64u && kernel_ready_events <= 3u);
    CHECK(ftun_event_loop_get_usage(loop, &usage) == FTUN_OK && usage.last_backend_work <= 130u);
    if (round >= 1u) CHECK(control == 1u);
    if (round >= 7u) CHECK(cold_state.calls > 0u);
  }
  CHECK(sources[1023] == NULL && sources[959] == NULL && sources[1000] == NULL && !states[1023].failed);
  CHECK(states[959].calls == 0u && states[1000].calls == 0u);
  for (index = 0u; index < 1024u; index++) {
    if (sources[index] != NULL) CHECK(states[index].calls > 0u && states[index].events == FTUN_EVENT_READ);
    CHECK(ftun_event_source_cancel(&sources[index]) == FTUN_OK);
  }
  CHECK(ftun_event_source_cancel(&cold) == FTUN_OK);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_libev_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(close(fd) == 0 && close(cold_fd) == 0);
  return 0;
}

static int shared_member_replacement(void)
{
  ftun_event_loop_t *loop = NULL;
  ftun_event_source_t *first = NULL, *guard = NULL, *replacement = NULL;
  duplicate_state_t old = {0}, kept = {0}, fresh = {0};
  int fd[2];
  char byte;
  size_t callbacks;
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
  CHECK(ftun_event_loop_create_with_capacity(NULL, 3u, &loop) == FTUN_OK);
  CHECK(ftun_libev_attach(loop) == FTUN_OK);
  CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)fd[0], FTUN_EVENT_READ,
    duplicate_ready, &old, &first) == FTUN_OK);
  CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)fd[0], FTUN_EVENT_READ,
    duplicate_ready, &kept, &guard) == FTUN_OK);
  CHECK(write(fd[1], "x", 1u) == 1);
  CHECK(ftun_event_loop_run_once(loop, false, 1u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 1u && kept.calls == 1u && old.calls == 0u);
  CHECK(read(fd[0], &byte, 1u) == 1);
  /* 取消尚未派发的首成员；共享 FD 继续存活，新成员不得继承旧通知。 */
  CHECK(ftun_event_source_cancel(&first) == FTUN_OK);
  CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)fd[0], FTUN_EVENT_READ,
    duplicate_ready, &fresh, &replacement) == FTUN_OK);
  CHECK(ftun_event_loop_run_once(loop, false, 8u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 0u && fresh.calls == 0u && old.calls == 0u);
  CHECK(write(fd[1], "x", 1u) == 1);
  CHECK(ftun_event_loop_run_once(loop, false, 8u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 2u && fresh.calls == 1u && kept.calls == 2u && old.calls == 0u);
  CHECK(ftun_event_source_cancel(&replacement) == FTUN_OK);
  CHECK(ftun_event_source_cancel(&guard) == FTUN_OK);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_libev_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(close(fd[0]) == 0 && close(fd[1]) == 0);
  return 0;
}

static int duplicate_interests(void)
{
  ftun_event_loop_t *loop = NULL;
  ftun_event_source_t *read_source = NULL, *write_source = NULL, *error_source = NULL;
  duplicate_state_t reader = {0}, writer = {0}, error = {0};
  int fd[2];
  char byte;
  size_t callbacks, previous;
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
  CHECK(ftun_event_loop_create_with_capacity(NULL, 3u, &loop) == FTUN_OK);
  CHECK(ftun_libev_attach(loop) == FTUN_OK);
  CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)fd[0], FTUN_EVENT_READ | FTUN_EVENT_ERROR, duplicate_ready, &reader, &read_source) == FTUN_OK);
  CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)fd[0], FTUN_EVENT_WRITE | FTUN_EVENT_ERROR, duplicate_ready, &writer, &write_source) == FTUN_OK);
  CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)fd[0], FTUN_EVENT_ERROR, duplicate_ready, &error, &error_source) == FTUN_OK);
  CHECK(write(fd[1], "x", 1u) == 1);
  CHECK(ftun_event_loop_run_once(loop, false, 8u, &callbacks) == FTUN_OK && callbacks == 2u);
  CHECK(reader.events == FTUN_EVENT_READ && writer.events == FTUN_EVENT_WRITE && error.calls == 0u);
  CHECK(read(fd[0], &byte, 1u) == 1 && byte == 'x');
  CHECK(ftun_event_io_update(read_source, FTUN_EVENT_ERROR) == FTUN_OK);
  CHECK(ftun_event_io_update(write_source, FTUN_EVENT_READ | FTUN_EVENT_ERROR) == FTUN_OK);
  previous = writer.calls;
  writer.events = 0u;
  kernel_ready_events = 0u;
  CHECK(ftun_event_loop_run_once(loop, false, 8u, &callbacks) == FTUN_OK && callbacks == 0u);
  CHECK(kernel_ready_events == 0u);
  CHECK(write(fd[1], "x", 1u) == 1);
  CHECK(ftun_event_loop_run_once(loop, true, 8u, &callbacks) == FTUN_OK && callbacks == 1u);
  CHECK(reader.calls == 1u && writer.calls == previous + 1u && writer.events == FTUN_EVENT_READ && error.calls == 0u);
  CHECK(read(fd[0], &byte, 1u) == 1);
  CHECK(ftun_event_source_cancel(&write_source) == FTUN_OK);
  CHECK(ftun_event_loop_run_once(loop, false, 8u, &callbacks) == FTUN_OK && callbacks == 0u);
  CHECK(ftun_event_io_update(read_source, FTUN_EVENT_WRITE) == FTUN_OK);
  reader.events = 0u;
  CHECK(ftun_event_loop_run_once(loop, false, 8u, &callbacks) == FTUN_OK && callbacks == 1u);
  CHECK(reader.events == FTUN_EVENT_WRITE && error.calls == 0u);
  CHECK(ftun_event_source_cancel(&read_source) == FTUN_OK);
  CHECK(ftun_event_source_cancel(&error_source) == FTUN_OK);
  /* 对端关闭时，仍有效的本端FD须通知所有活动reader，并可读取EOF。 */
  CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)fd[0], FTUN_EVENT_READ | FTUN_EVENT_ERROR, duplicate_ready, &reader, &read_source) == FTUN_OK);
  CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)fd[0], FTUN_EVENT_READ | FTUN_EVENT_ERROR, duplicate_ready, &writer, &write_source) == FTUN_OK);
  CHECK(close(fd[1]) == 0);
  reader.events = writer.events = 0u;
  CHECK(ftun_event_loop_run_once(loop, false, 8u, &callbacks) == FTUN_OK && callbacks == 2u);
  CHECK(reader.events == FTUN_EVENT_READ && writer.events == FTUN_EVENT_READ);
  CHECK(read(fd[0], &byte, 1u) == 0);
  CHECK(ftun_event_source_cancel(&read_source) == FTUN_OK);
  CHECK(ftun_event_source_cancel(&write_source) == FTUN_OK);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_libev_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(close(fd[0]) == 0);
  return 0;
}

static int fd_index_lifecycle(void)
{
  ftun_event_loop_t *loop = NULL;
  ftun_event_source_t *sources[257] = {0}, *extra = NULL;
  duplicate_state_t states[257] = {{0}}, extra_state = {0};
  int fds[257];
  ftun_event_loop_usage_t usage;
  size_t order[257], index, round, callbacks;
  uint32_t seed = 173u;
  CHECK(ftun_event_loop_create_with_capacity(NULL, 258u, &loop) == FTUN_OK);
  CHECK(ftun_libev_attach(loop) == FTUN_OK);
  for (index = 0u; index < 257u; index++) {
    fds[index] = eventfd(1u, EFD_NONBLOCK | EFD_CLOEXEC);
    order[index] = index;
    CHECK(fds[index] >= 0);
  }
  for (index = 256u; index != 0u; index--) {
    size_t selected, saved;
    seed = seed * 1664525u + 1013904223u;
    selected = seed % (index + 1u);
    saved = order[index]; order[index] = order[selected]; order[selected] = saved;
  }
  for (index = 0u; index < 257u; index++) {
    size_t slot = order[index];
    CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)fds[slot], FTUN_EVENT_READ, duplicate_ready, &states[slot], &sources[slot]) == FTUN_OK);
  }
  for (round = 0u; round < 8u; round++) CHECK(ftun_event_loop_run_once(loop, false, 64u, &callbacks) == FTUN_OK);
  CHECK(ftun_event_loop_get_usage(loop, &usage) == FTUN_OK && usage.quota_exhaustions == 8u);
  for (index = 0u; index < 257u; index++) CHECK(states[index].calls != 0u);
  for (index = 0u; index < 257u; index++) {
    size_t slot = order[index];
    CHECK(ftun_event_source_cancel(&sources[slot]) == FTUN_OK);
    if (index + 1u < 257u) {
      size_t next = order[index + 1u];
      CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)fds[next], FTUN_EVENT_READ, duplicate_ready, &extra_state, &extra) == FTUN_OK);
      CHECK(ftun_event_source_cancel(&extra) == FTUN_OK);
    }
  }
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_libev_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  for (index = 0u; index < 257u; index++) CHECK(close(fds[index]) == 0);
  return 0;
}

typedef struct {
  int fd;
  size_t calls;
  bool failed;
} retained_state_t;

static void retained_ready(ftun_event_source_t *source, uint32_t events, void *user)
{
  retained_state_t *state = user;
  uint64_t value;
  ssize_t count;
  (void)source;
  state->calls++;
  count = read(state->fd, &value, sizeof(value));
  if (events != FTUN_EVENT_READ || (count != (ssize_t)sizeof(value) &&
      !(count < 0 && errno == EAGAIN))) state->failed = true;
}

static int retained_batch_wakeup(void)
{
  ftun_event_loop_t *loop = NULL;
  ftun_event_source_t *sources[257] = {0}, *guard = NULL;
  ftun_event_loop_usage_t usage;
  retained_state_t state = {0};
  size_t index, callbacks;
  hot_source_t guard_state = {0};
  uint64_t now;
  state.fd = eventfd(1u, EFD_NONBLOCK | EFD_CLOEXEC);
  CHECK(state.fd >= 0);
  CHECK(ftun_event_loop_create_with_capacity(NULL, 258u, &loop) == FTUN_OK);
  CHECK(ftun_libev_attach(loop) == FTUN_OK);
  for (index = 0u; index < 257u; index++) CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)state.fd,
    FTUN_EVENT_READ, retained_ready, &state, &sources[index]) == FTUN_OK);
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  CHECK(ftun_event_timer_start(loop, now + 250u, hot_ready, &guard_state, &guard) == FTUN_OK);
  CHECK(ftun_event_loop_run_once(loop, false, 64u, &callbacks) == FTUN_OK && callbacks == 64u);
  CHECK(state.calls == 64u && !state.failed);
  CHECK(ftun_event_loop_get_usage(loop, &usage) == FTUN_OK && usage.ready_count == 0u && usage.backend_quota_exhausted);
  /* 首个业务回调已排空FD；backend保留的成员本身必须禁止再次阻塞。 */
  while (state.calls < 257u) {
    kernel_wait_timeout = -1;
    CHECK(ftun_event_loop_run_once(loop, true, 64u, &callbacks) == FTUN_OK && callbacks > 0u && callbacks <= 64u);
    CHECK(kernel_wait_timeout == 0 && !state.failed);
  }
  CHECK(state.calls == 257u && guard_state.calls == 0u);
  for (index = 0u; index < 257u; index++) CHECK(ftun_event_source_cancel(&sources[index]) == FTUN_OK);
  CHECK(ftun_event_source_cancel(&guard) == FTUN_OK);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_libev_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(close(state.fd) == 0);
  return 0;
}

static void *wake_pipe(void *user)
{
  int fd = *(int *)user;
  struct timespec delay = {0, 60000000L};
  (void)nanosleep(&delay, NULL);
  return write(fd, "x", 1u) == 1 ? NULL : (void *)(uintptr_t)1;
}

static int native_busy_accounting(void)
{
  ftun_event_loop_t *loop = NULL;
  ftun_event_source_t *io = NULL;
  ftun_event_loop_usage_t usage;
  adapter_state_t state;
  pthread_t producer;
  void *result;
  uint64_t start, finish;
  size_t callbacks;
  int descriptors[2];
  memset(&state, 0, sizeof(state));
  CHECK(pipe(descriptors) == 0);
  state.read_fd = descriptors[0];
  CHECK(ftun_event_loop_create(NULL, &loop) == FTUN_OK);
  CHECK(ftun_libev_attach(loop) == FTUN_OK);
  CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)descriptors[0], FTUN_EVENT_READ, ready, &state, &io) == FTUN_OK);
  CHECK(pthread_create(&producer, NULL, wake_pipe, &descriptors[1]) == 0);
  CHECK(ftun_monotonic_now(&start) == FTUN_OK);
  delay_native_ready = true;
  CHECK(ftun_event_loop_run_once(loop, true, 8u, &callbacks) == FTUN_OK && callbacks == 1u);
  delay_native_ready = false;
  CHECK(ftun_monotonic_now(&finish) == FTUN_OK);
  CHECK(pthread_join(producer, &result) == 0 && result == NULL && state.io_calls == 1);
  CHECK(ftun_event_loop_get_usage(loop, &usage) == FTUN_OK && usage.last_dispatch_ms >= 24u);
  CHECK(finish >= start + 84u && usage.last_dispatch_ms + 30u < finish - start);
  CHECK(ftun_event_source_cancel(&io) == FTUN_OK);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_libev_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(close(descriptors[0]) == 0 && close(descriptors[1]) == 0);
  return 0;
}

static int stable_fd_interest_changes(void)
{
  ftun_event_loop_t *loop = NULL;
  ftun_event_source_t *source = NULL;
  hot_source_t state = {0};
  size_t callbacks, before, adds;
  int fd[2];
  CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd) == 0);
  CHECK(ftun_event_loop_create(NULL, &loop) == FTUN_OK);
  CHECK(ftun_libev_attach(loop) == FTUN_OK);
  tracked_ctl_fd = fd[0];
  tracked_ctl_calls = tracked_ctl_adds = 0u;
  CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)fd[0], FTUN_EVENT_READ,
    hot_ready, &state, &source) == FTUN_OK);
  CHECK(ftun_event_loop_run_once(loop, false, 8u, &callbacks) == FTUN_OK);
  before = tracked_ctl_calls;
  adds = tracked_ctl_adds;
  CHECK(before != 0u);
  /* 同一轮先暂停再恢复，最终内核兴趣没有变化，不应重新ADD。 */
  CHECK(ftun_event_io_update(source, FTUN_EVENT_ERROR) == FTUN_OK);
  CHECK(ftun_event_io_update(source, FTUN_EVENT_READ) == FTUN_OK);
  CHECK(ftun_event_loop_run_once(loop, false, 8u, &callbacks) == FTUN_OK);
  CHECK(tracked_ctl_calls == before && tracked_ctl_adds == adds);
  CHECK(ftun_event_io_update(source, FTUN_EVENT_READ | FTUN_EVENT_WRITE) == FTUN_OK);
  CHECK(ftun_event_loop_run_once(loop, false, 8u, &callbacks) == FTUN_OK);
  CHECK(tracked_ctl_calls == before + 1u && tracked_ctl_adds == adds && state.calls != 0u);
  CHECK(ftun_event_source_cancel(&source) == FTUN_OK);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_libev_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(close(fd[0]) == 0 && close(fd[1]) == 0);
  tracked_ctl_fd = -1;
  return 0;
}

static int wakeup_coalescing(void)
{
  ftun_event_loop_t *loop = NULL;
  size_t count = 0u, callbacks, index;
  CHECK(ftun_event_loop_create(NULL, &loop) == FTUN_OK);
  CHECK(ftun_libev_attach(loop) == FTUN_OK);
  wake_writes = 0u;
  capture_wake_writes = true;
  for (index = 0u; index < 32u; index++) {
    CHECK(ftun_event_defer(loop, count_control, &count) == FTUN_OK);
  }
  capture_wake_writes = false;
  CHECK(wake_writes == 1u);
  /* 内核通知已读但尚未退出callback时再提交，front poll仍须看到它。 */
  wake_injection_loop = loop;
  wake_injection_count = &count;
  inject_wake_read = true;
  wake_injection_failed = false;
  CHECK(ftun_event_loop_run_once(loop, false, 64u, &callbacks) == FTUN_OK);
  CHECK(!inject_wake_read && !wake_injection_failed && callbacks == 33u && count == 33u);
  wake_writes = 0u;
  capture_wake_writes = true;
  CHECK(ftun_event_defer(loop, count_control, &count) == FTUN_OK);
  capture_wake_writes = false;
  CHECK(wake_writes == 1u);
  CHECK(ftun_event_loop_run_once(loop, false, 64u, &callbacks) == FTUN_OK && count == 34u);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_libev_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  wake_injection_loop = NULL;
  wake_injection_count = NULL;
  return 0;
}

/* TASK-EVENT-002 / TEST-EVENT-002：epoll I/O、timer 与跨线程 ev_async。 */
int main(void)
{
  ftun_event_loop_t *loop = NULL;
  ftun_event_source_t *io = NULL;
  ftun_event_source_t *timer = NULL;
  ftun_event_source_t *guard_timer = NULL;
  ftun_event_source_t *task = NULL;
  ftun_libev_info_t info;
  ftun_event_loop_usage_t usage;
  adapter_state_t state;
  pthread_t producer;
  uint64_t now_ms = 0u;
  size_t callbacks = 99u;
  int descriptors[2] = {-1, -1};

  CHECK(bounded_collection() == 0);
  CHECK(duplicate_collection() == 0);
  CHECK(duplicate_interests() == 0);
  CHECK(shared_member_replacement() == 0);
  CHECK(retained_batch_wakeup() == 0);
  CHECK(fd_index_lifecycle() == 0);
  CHECK(native_busy_accounting() == 0);
  CHECK(stable_fd_interest_changes() == 0);
  CHECK(wakeup_coalescing() == 0);
  memset(&state, 0, sizeof(state));
  CHECK(pipe(descriptors) == 0);
  state.read_fd = descriptors[0];
  state.producer_status = FTUN_E_STATE_CORRUPT;
  CHECK(ftun_event_loop_create(NULL, &loop) == FTUN_OK);
  state.loop = loop;
  CHECK(ftun_libev_attach(loop) == FTUN_OK);
  CHECK(ftun_libev_attach(loop) == FTUN_E_AGAIN);
  CHECK(ftun_libev_get_info(loop, &info) == FTUN_OK);
  CHECK(info.version_major == 4u && info.version_minor == 33u &&
        strcmp(info.backend, "epoll") == 0 && info.async_thread_safe);
  CHECK(ftun_event_loop_get_usage(loop, &usage) == FTUN_OK && usage.backend_attached);

  CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)descriptors[0],
                            FTUN_EVENT_READ | FTUN_EVENT_ERROR,
                            ready, &state, &io) == FTUN_OK);
  CHECK(write(descriptors[1], "x", 1u) == 1);
  CHECK(ftun_event_loop_run_once(loop, true, 8u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 1u && state.io_calls == 1);

  CHECK(ftun_event_io_update(io, FTUN_EVENT_ERROR) == FTUN_OK);
  CHECK(write(descriptors[1], "x", 1u) == 1);
  /* Drain any readiness which was already queued by epoll before READ was
   * disabled; inactive watcher callbacks must not affect the timing check. */
  CHECK(ftun_event_loop_run_once(loop, false, 8u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 0u && state.io_calls == 1);
  /* 模拟循环外准备工作，绝对期限不能相对于过期的后端时间提前触发。 */
  {
    struct timespec delay = {0, 80000000L};
    CHECK(nanosleep(&delay, NULL) == 0);
  }
  CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK);
  {
    uint64_t started_ms = now_ms;
    uint64_t finished_ms = 0u;
    /* With READ disabled, only this explicit absolute deadline may wake the
     * blocking backend.  This rejects the former hidden 10 ms poll timer. */
    CHECK(ftun_event_timer_start(loop, now_ms + 40u, ready, &state,
                                 &guard_timer) == FTUN_OK);
    CHECK(ftun_event_loop_run_once(loop, true, 8u, &callbacks) == FTUN_OK);
    CHECK(ftun_monotonic_now(&finished_ms) == FTUN_OK &&
          finished_ms >= started_ms + 40u);
  }
  CHECK(callbacks == 1u && state.io_calls == 1 && state.timer_calls == 1);
  CHECK(ftun_event_source_cancel(&guard_timer) == FTUN_OK);
  CHECK(ftun_event_io_update(io, FTUN_EVENT_READ | FTUN_EVENT_ERROR) ==
        FTUN_OK);
  CHECK(ftun_event_loop_run_once(loop, true, 8u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 1u && state.io_calls == 2);

  CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK);
  CHECK(ftun_event_timer_start(loop, now_ms + 5u, ready, &state, &timer) == FTUN_OK);
  CHECK(ftun_event_loop_run_once(loop, true, 8u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 1u && state.timer_calls == 2);

  CHECK(pthread_create(&producer, NULL, produce, &state) == 0);
  CHECK(ftun_event_loop_run_once(loop, true, 8u, &callbacks) == FTUN_OK);
  CHECK(pthread_join(producer, NULL) == 0);
  CHECK(state.producer_status == FTUN_OK && callbacks == 1u &&
        state.deferred_calls == 1);

  CHECK(ftun_event_task_start(loop, ready, &state, &task) == FTUN_OK);
  CHECK(ftun_event_task_ready(task) == FTUN_OK);
  CHECK(ftun_event_task_ready(task) == FTUN_OK);
  CHECK(ftun_event_loop_run_once(loop, true, 8u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 1u && state.task_calls == 1);
  CHECK(ftun_event_task_ready(task) == FTUN_OK);
  CHECK(ftun_event_loop_run_once(loop, true, 8u, &callbacks) == FTUN_OK);
  CHECK(callbacks == 1u && state.task_calls == 2 && state.recursive_again == 2);
  CHECK(ftun_event_task_ready(task) == FTUN_OK);
  CHECK(ftun_event_source_cancel(&task) == FTUN_OK);
  CHECK(ftun_event_loop_run_once(loop, false, 8u, &callbacks) == FTUN_OK && callbacks == 0u);

  CHECK(ftun_libev_detach(loop) == FTUN_E_AGAIN);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_source_cancel(&timer) == FTUN_OK);
  CHECK(ftun_event_source_cancel(&io) == FTUN_OK);
  CHECK(ftun_libev_detach(loop) == FTUN_OK);
  CHECK(ftun_libev_get_info(loop, &info) == FTUN_E_UNSUPPORTED);
  CHECK(info.version_major == 0u && info.backend == NULL);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK && loop == NULL);
  CHECK(close(descriptors[0]) == 0);
  CHECK(close(descriptors[1]) == 0);
  CHECK(ftun_libev_attach(NULL) == FTUN_E_INVALID);
  CHECK(ftun_libev_get_info(NULL, &info) == FTUN_E_INVALID);
  CHECK(ftun_libev_detach(NULL) == FTUN_E_INVALID);
  return 0;
}
