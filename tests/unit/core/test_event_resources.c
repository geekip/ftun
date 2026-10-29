#define _POSIX_C_SOURCE 200809L
#include <sys/types.h>
#include "core/context.h"
#include "core/event/loop.h"
#include "core/event/backend.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "event resources failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

static bool fail_native;
static bool fail_cancel;
static unsigned int calls;
int __real_eventfd(unsigned int initial, int flags);
int __wrap_eventfd(unsigned int initial, int flags)
{
  if (fail_native) { errno = EMFILE; return -1; }
  return __real_eventfd(initial, flags);
}
int __real_pipe(int descriptors[2]);
int __wrap_pipe(int descriptors[2])
{
  if (fail_native) { errno = EMFILE; return -1; }
  return __real_pipe(descriptors);
}

ftun_status_t __real_ftun_event_source_backend_data(ftun_event_source_t *source, void **out);
ftun_status_t __wrap_ftun_event_source_backend_data(ftun_event_source_t *source, void **out)
{
  if (fail_cancel) { *out = NULL; return FTUN_E_IO; }
  return __real_ftun_event_source_backend_data(source, out);
}

static void wakeup(void *user) { (void)user; }

static size_t fd_count(void)
{
  DIR *directory = opendir("/proc/self/fd");
  struct dirent *entry;
  size_t count = 0u;
  if (directory == NULL) return SIZE_MAX;
  while ((entry = readdir(directory)) != NULL) if (entry->d_name[0] != '.') count++;
  (void)closedir(directory);
  return count;
}

static void ready(ftun_event_source_t *source, uint32_t events, void *user)
{
  (void)source; (void)events; (void)user;
  calls++;
}

static int native_failure(void)
{
  ftun_event_loop_t *loop = NULL;
  ftun_event_loop_usage_t events;
  size_t baseline = fd_count();
  CHECK(ftun_event_loop_create(NULL, &loop) == FTUN_OK);
  fail_native = true;
  CHECK(ftun_event_backend_attach(loop) == FTUN_E_LIMIT);
  fail_native = false;
  CHECK(ftun_event_loop_get_usage(loop, &events) == FTUN_OK && !events.backend_attached);
  CHECK(fd_count() == baseline);
  CHECK(ftun_event_backend_attach(loop) == FTUN_OK && fd_count() == baseline + 2u);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_backend_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK && fd_count() == baseline);
  return 0;
}

/* 只在子进程降低 RLIMIT；保留一个空位以验证 eventfd 成功、epoll 失败的回滚。 */
static int kernel_fd_failure(void)
{
  pid_t child = fork();
  int result;
  CHECK(child >= 0);
  if (child == 0) {
    struct rlimit limit;
    ftun_event_loop_t *loop = NULL;
    int descriptors[64], count = 0;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0) _exit(2);
    if (limit.rlim_cur > 32u) limit.rlim_cur = 32u;
    if (setrlimit(RLIMIT_NOFILE, &limit) != 0 || ftun_event_loop_create(NULL, &loop) != FTUN_OK) _exit(3);
    while (count < 64 && (descriptors[count] = open("/dev/null", O_RDONLY | O_CLOEXEC)) >= 0) count++;
    if (count == 0 || count == 64 || errno != EMFILE) _exit(4);
    (void)close(descriptors[--count]);
    if (ftun_event_backend_attach(loop) != FTUN_E_LIMIT) _exit(5);
    while (count > 0) (void)close(descriptors[--count]);
    if (ftun_event_backend_attach(loop) != FTUN_OK || ftun_event_loop_stop(loop) != FTUN_OK ||
        ftun_event_backend_detach(loop) != FTUN_OK || ftun_event_loop_destroy(&loop) != FTUN_OK) _exit(6);
    _exit(0);
  }
  CHECK(waitpid(child, &result, 0) == child && WIFEXITED(result) && WEXITSTATUS(result) == 0);
  return 0;
}

static int admission(void)
{
  ftun_budget_options_t limits = {0};
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_event_loop_t *loop = NULL, *rejected = NULL;
  ftun_event_source_t *task = NULL, *io = NULL, *timer = NULL;
  ftun_reservation_t hold = (ftun_reservation_t){0};
  ftun_budget_usage_t base, front, attached, usage;
  ftun_event_loop_usage_t events;
  size_t callbacks, source_bytes, baseline = fd_count();
  int descriptors[2];
  limits.limit = (ftun_budget_resources_t){1024u * 1024u, 2u, 258u};
  CHECK(ftun_budget_create_resources(NULL, &limits, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &base) == FTUN_OK);
  CHECK(ftun_event_loop_create_with_capacity(core, 8u, &loop) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &front) == FTUN_OK && front.used_resources.memory_bytes > base.used_resources.memory_bytes &&
    front.used_resources.queue_slots == 256u && front.used_resources.descriptors == 0u);
  CHECK(ftun_event_loop_create(core, &rejected) == FTUN_E_LIMIT && rejected == NULL);
  CHECK(ftun_budget_reserve_resources(budget, (ftun_budget_resources_t){0u, 1u, 0u}, &hold) == FTUN_OK);
  CHECK(ftun_event_backend_attach(loop) == FTUN_E_LIMIT && fd_count() == baseline);
  ftun_reservation_release(&hold);
  fail_native = true;
  CHECK(ftun_event_backend_attach(loop) == FTUN_E_LIMIT);
  fail_native = false;
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == front.used_resources.memory_bytes &&
    usage.used_resources.descriptors == 0u);
  CHECK(ftun_event_loop_set_wakeup(loop, wakeup, NULL) == FTUN_OK);
  CHECK(ftun_event_backend_attach(loop) == FTUN_E_AGAIN && fd_count() == baseline);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == front.used_resources.memory_bytes &&
    usage.used_resources.descriptors == 0u);
  CHECK(ftun_event_loop_set_wakeup(loop, NULL, NULL) == FTUN_OK);
  CHECK(ftun_event_backend_attach(loop) == FTUN_OK && fd_count() == baseline + 2u);
  CHECK(ftun_budget_get_usage(budget, &attached) == FTUN_OK && attached.used_resources.memory_bytes > front.used_resources.memory_bytes &&
    attached.used_resources.descriptors == 2u);
  CHECK(ftun_event_backend_attach(loop) == FTUN_E_AGAIN);
  CHECK(ftun_event_task_start(loop, ready, NULL, &task) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
  source_bytes = usage.used_resources.memory_bytes - attached.used_resources.memory_bytes;
  CHECK(source_bytes > 0u && usage.used_resources.queue_slots == 257u);
  CHECK(ftun_event_source_cancel(&task) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == attached.used_resources.memory_bytes);
  CHECK(ftun_budget_reserve(budget, usage.normal_available_resources.memory_bytes - source_bytes, &hold) == FTUN_OK);
  /* 聚合 timer 不逐个分配 native watcher；相同余量的 IO 仍应回滚两层。 */
  CHECK(ftun_event_timer_start(loop, UINT64_MAX, ready, NULL, &timer) == FTUN_OK);
  CHECK(ftun_event_source_cancel(&timer) == FTUN_OK);
  CHECK(pipe(descriptors) == 0);
  CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)descriptors[0], FTUN_EVENT_READ, ready, NULL, &io) == FTUN_E_LIMIT && io == NULL);
  CHECK(ftun_event_loop_get_usage(loop, &events) == FTUN_OK && events.source_count == 0u);
  ftun_reservation_release(&hold);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == attached.used_resources.memory_bytes &&
    usage.used_resources.queue_slots == 256u);
  CHECK(ftun_event_task_start(loop, ready, NULL, &task) == FTUN_OK);
  CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)descriptors[0], FTUN_EVENT_READ, ready, NULL, &io) == FTUN_OK);
  CHECK(ftun_event_timer_start(loop, UINT64_MAX, ready, NULL, &timer) == FTUN_E_LIMIT && timer == NULL);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.descriptors == 2u &&
    usage.used_resources.queue_slots == 258u);
  CHECK(ftun_event_task_ready(task) == FTUN_OK);
  CHECK(ftun_event_loop_run_once(loop, false, 1u, &callbacks) == FTUN_OK && callbacks == 1u && calls == 1u);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_backend_detach(loop) == FTUN_E_AGAIN && ftun_event_loop_destroy(&loop) == FTUN_E_AGAIN);
  CHECK(ftun_budget_destroy(&budget) == FTUN_E_AGAIN);
  fail_cancel = true;
  CHECK(ftun_event_source_cancel(&io) == FTUN_E_STATE_CORRUPT && io != NULL);
  fail_cancel = false;
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.descriptors == 2u &&
    usage.used_resources.queue_slots == 258u);
  CHECK(ftun_event_source_cancel(&task) == FTUN_OK && ftun_event_source_cancel(&io) == FTUN_OK);
  CHECK(ftun_event_backend_detach(loop) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == front.used_resources.memory_bytes &&
    usage.used_resources.descriptors == 0u && usage.used_resources.queue_slots == 256u);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == base.used_resources.memory_bytes &&
    usage.used_resources.queue_slots == 0u);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(close(descriptors[0]) == 0 && close(descriptors[1]) == 0 && fd_count() == baseline);
  return 0;
}

static int budget_domains(void)
{
  ftun_budget_t *root = NULL, *data = NULL, *foreign = NULL, *bound = NULL;
  ftun_core_t *core = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_budget_usage_t usage;
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &root) == FTUN_OK);
  CHECK(ftun_budget_create(root, 512u * 1024u, 0u, &data) == FTUN_OK);
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &foreign) == FTUN_OK);
  CHECK(ftun_core_context_create(root, &core) == FTUN_OK);
  CHECK(ftun_event_loop_create_with_budget(core, foreign, 8u, &loop) == FTUN_E_INVALID && loop == NULL);
  CHECK(ftun_event_loop_create_with_budget(core, data, 8u, &loop) == FTUN_OK);
  CHECK(ftun_event_loop_budget(loop, &bound) == FTUN_OK && bound == data);
  CHECK(ftun_budget_get_usage(data, &usage) == FTUN_OK && usage.used_resources.memory_bytes > 0u &&
    usage.used_resources.queue_slots == 256u);
  CHECK(ftun_budget_destroy(&data) == FTUN_E_AGAIN);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK && ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_budget_get_usage(data, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u &&
    usage.used_resources.queue_slots == 0u);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&foreign) == FTUN_OK && ftun_budget_destroy(&data) == FTUN_OK);
  CHECK(ftun_budget_destroy(&root) == FTUN_OK);
  return 0;
}

static int shared_fd_admission(void)
{
  ftun_event_loop_t *loop = NULL;
  ftun_event_source_t *first = NULL, *second = NULL, *rejected = NULL;
  ftun_budget_t *budget = NULL;
  ftun_reservation_t hold = (ftun_reservation_t){0};
  ftun_budget_usage_t base, single, duplicate, usage;
  int fd = eventfd(0u, EFD_NONBLOCK | EFD_CLOEXEC);
  int other = eventfd(0u, EFD_NONBLOCK | EFD_CLOEXEC);
  size_t member_bytes;
  CHECK(fd >= 0 && other >= 0);
  CHECK(ftun_budget_create(NULL, 128u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_event_loop_create_with_budget(NULL, budget, 8u, &loop) == FTUN_OK);
  CHECK(ftun_event_backend_attach(loop) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &base) == FTUN_OK);
  CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)fd, FTUN_EVENT_READ, ready, NULL, &first) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &single) == FTUN_OK);
  CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)fd, FTUN_EVENT_READ, ready, NULL, &second) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &duplicate) == FTUN_OK && duplicate.used_resources.memory_bytes > single.used_resources.memory_bytes);
  member_bytes = duplicate.used_resources.memory_bytes - single.used_resources.memory_bytes;
  CHECK(ftun_event_source_cancel(&second) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == single.used_resources.memory_bytes);
  CHECK(ftun_budget_reserve(budget, usage.normal_available_resources.memory_bytes - member_bytes, &hold) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &single) == FTUN_OK);
  /* source与member可分配，但新FD的group额度不足；失败不留下索引或额度。 */
  CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)other, FTUN_EVENT_READ, ready, NULL, &rejected) == FTUN_E_LIMIT && rejected == NULL);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == single.used_resources.memory_bytes &&
    usage.used_resources.queue_slots == single.used_resources.queue_slots);
  CHECK(ftun_event_io_start(loop, (ftun_native_socket_t)fd, FTUN_EVENT_READ, ready, NULL, &second) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &duplicate) == FTUN_OK);
  fail_cancel = true;
  CHECK(ftun_event_source_cancel(&first) == FTUN_E_STATE_CORRUPT && first != NULL);
  fail_cancel = false;
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == duplicate.used_resources.memory_bytes);
  CHECK(ftun_event_source_cancel(&first) == FTUN_OK);
  CHECK(ftun_event_source_cancel(&second) == FTUN_OK);
  ftun_reservation_release(&hold);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == base.used_resources.memory_bytes &&
    usage.used_resources.queue_slots == base.used_resources.queue_slots);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_backend_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(close(fd) == 0 && close(other) == 0);
  return 0;
}

int main(void)
{
  CHECK(shared_fd_admission() == 0);
  CHECK(native_failure() == 0);
  CHECK(kernel_fd_failure() == 0);
  CHECK(admission() == 0);
  CHECK(budget_domains() == 0);
  puts("Event resources: native failure, three-dimensional admission, rollback and ownership passed");
  return 0;
}
