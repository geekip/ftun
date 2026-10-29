#define _POSIX_C_SOURCE 200809L

#include <sys/types.h>
#include "app/cli/result.h"
#include "core/core.h"
#include "platform/clock.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expression) do { \
  if (!(expression)) { \
    fprintf(stderr, "CLI result contract failed: %s:%d: %s\n", \
            __FILE__, __LINE__, #expression); \
    return 1; \
  } \
} while (0)

static pthread_mutex_t write_fault_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct stat write_fault_identity;
static unsigned int write_fault_calls;
static int write_fault_active;
static pthread_cond_t write_fault_condition = PTHREAD_COND_INITIALIZER;
static int write_fault_blocked;
static int write_fault_entered;
static int resource_tracking;
static ftun_budget_t *tracked_budget;
static unsigned int tracked_destroyed;
static int resource_failure;

ftun_status_t __real_ftun_budget_reserve_resources(ftun_budget_t *budget,
  ftun_budget_resources_t resources, ftun_reservation_t *out);
ftun_status_t __wrap_ftun_budget_reserve_resources(ftun_budget_t *budget,
  ftun_budget_resources_t resources, ftun_reservation_t *out)
{
  ftun_status_t status = __real_ftun_budget_reserve_resources(budget, resources, out);
  (void)pthread_mutex_lock(&write_fault_mutex);
  if (resource_tracking && status == FTUN_OK && resources.descriptors == 1u &&
      resources.queue_slots == 34u) tracked_budget = budget;
  (void)pthread_mutex_unlock(&write_fault_mutex);
  return status;
}

ftun_status_t __real_ftun_budget_destroy(ftun_budget_t **budget);
ftun_status_t __wrap_ftun_budget_destroy(ftun_budget_t **budget)
{
  ftun_status_t status;
  ftun_budget_usage_t usage;
  int tracked;
  int invalid = 0;
  (void)pthread_mutex_lock(&write_fault_mutex);
  tracked = resource_tracking && budget != NULL && *budget != NULL && *budget == tracked_budget;
  (void)pthread_mutex_unlock(&write_fault_mutex);
  if (tracked && (ftun_budget_get_usage(*budget, &usage) != FTUN_OK ||
      usage.used != 0u || usage.used_resources.descriptors != 0u ||
      usage.used_resources.queue_slots != 0u)) invalid = 1;
  status = __real_ftun_budget_destroy(budget);
  if (tracked) {
    (void)pthread_mutex_lock(&write_fault_mutex);
    if (invalid) resource_failure = 1;
    if (status == FTUN_OK) { tracked_destroyed++; tracked_budget = NULL; }
    else resource_failure = 1;
    (void)pthread_cond_broadcast(&write_fault_condition);
    (void)pthread_mutex_unlock(&write_fault_mutex);
  }
  return status;
}

ssize_t __real_write(int descriptor, const void *bytes, size_t length);
ssize_t __wrap_write(int descriptor, const void *bytes, size_t length)
{
  struct stat identity;
  unsigned int call = 0u;
  (void)pthread_mutex_lock(&write_fault_mutex);
  if (write_fault_active && fstat(descriptor, &identity) == 0 &&
      identity.st_dev == write_fault_identity.st_dev &&
      identity.st_ino == write_fault_identity.st_ino) {
    call = ++write_fault_calls;
    if (write_fault_blocked) {
      write_fault_entered = 1;
      (void)pthread_cond_broadcast(&write_fault_condition);
      while (write_fault_blocked) {
        (void)pthread_cond_wait(&write_fault_condition, &write_fault_mutex);
      }
    }
  }
  (void)pthread_mutex_unlock(&write_fault_mutex);
  if (call == 1u || call == 3u) {
    errno = call == 1u ? EINTR : EAGAIN;
    return -1;
  }
  if (call == 2u && length > 2u) length = 2u;
  return __real_write(descriptor, bytes, length);
}

static size_t fd_count(void)
{
  DIR *directory = opendir("/proc/self/fd");
  struct dirent *entry;
  size_t count = 0u;
  if (directory == NULL) return SIZE_MAX;
  while ((entry = readdir(directory)) != NULL) {
    if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
      count++;
    }
  }
  (void)closedir(directory);
  return count;
}

static int ordered_output(void)
{
  static const char expected[] =
    "ftun: reload committed\n"
    "ftun: reload rejected at stage 7: io\n"
    "ftun: reload request rejected: limit\n";
  ftun_cli_result_sink_t *sink = NULL;
  ftun_cli_result_ticket_t *tickets[4] = {NULL, NULL, NULL, NULL};
  int descriptors[2];
  char output[256];
  size_t used = 0u;
  ssize_t got;
  CHECK(pipe(descriptors) == 0);
  CHECK(ftun_cli_result_sink_create(descriptors[1], &sink) == FTUN_OK);
  CHECK(close(descriptors[1]) == 0);
  CHECK(ftun_cli_result_reserve(sink, &tickets[0]) == FTUN_OK);
  CHECK(ftun_cli_result_reserve(sink, &tickets[1]) == FTUN_OK);
  CHECK(ftun_cli_result_reserve(sink, &tickets[2]) == FTUN_OK);
  CHECK(ftun_cli_result_reserve(sink, &tickets[3]) == FTUN_OK);
  CHECK(ftun_cli_result_publish(tickets[0], FTUN_CLI_RESULT_RELOAD_COMMITTED,
                                FTUN_OK, 0u) == FTUN_OK);
  CHECK(ftun_cli_result_publish(tickets[1], FTUN_CLI_RESULT_RELOAD_REJECTED,
                                FTUN_E_IO, 7u) == FTUN_OK);
  CHECK(ftun_cli_result_publish(tickets[2],
    FTUN_CLI_RESULT_RELOAD_REQUEST_REJECTED, FTUN_E_LIMIT, 0u) == FTUN_OK);
  CHECK(ftun_cli_result_abandon(tickets[3]) == FTUN_OK);
  CHECK(ftun_cli_result_sink_stop_until(&sink, UINT64_MAX) == FTUN_OK &&
        sink == NULL);
  while ((got = read(descriptors[0], output + used, sizeof(output) - used)) > 0) {
    used += (size_t)got;
  }
  CHECK(got == 0 && used == sizeof(expected) - 1u);
  CHECK(memcmp(output, expected, used) == 0);
  CHECK(close(descriptors[0]) == 0);
  return 0;
}

static int bounded_admission(void)
{
  ftun_cli_result_sink_t *sink = NULL;
  ftun_cli_result_ticket_t *tickets[32];
  ftun_cli_result_ticket_t *extra = NULL;
  ftun_cli_result_usage_t usage;
  int descriptors[2];
  size_t index;
  CHECK(pipe(descriptors) == 0);
  CHECK(ftun_cli_result_sink_create(descriptors[1], &sink) == FTUN_OK);
  CHECK(close(descriptors[1]) == 0);
  for (index = 0u; index < 32u; index++) {
    CHECK(ftun_cli_result_reserve(sink, &tickets[index]) == FTUN_OK);
  }
  CHECK(ftun_cli_result_reserve(sink, &extra) == FTUN_E_LIMIT && extra == NULL);
  CHECK(ftun_cli_result_report_admission_rejected(sink, FTUN_E_LIMIT) ==
        FTUN_OK);
  CHECK(ftun_cli_result_get_usage(sink, &usage) == FTUN_OK);
  CHECK(usage.capacity == 34u && usage.reserved == 32u &&
        usage.admission_rejected == 1u && usage.ready == 0u &&
        usage.rejection_notices <= 1u);
  CHECK(usage.owned_resources.memory_bytes > 0u &&
        usage.owned_resources.descriptors == 1u &&
        usage.owned_resources.queue_slots == 34u && usage.budget_metadata_bytes > 0u);
  for (index = 0u; index < 32u; index++) {
    CHECK(ftun_cli_result_abandon(tickets[index]) == FTUN_OK);
  }
  CHECK(ftun_cli_result_sink_stop_until(&sink, UINT64_MAX) == FTUN_OK);
  {
    static const char expected[] =
      "ftun: reload request rejected: limit\n";
    char output[sizeof(expected)];
    ssize_t got = read(descriptors[0], output, sizeof(output));
    CHECK(got == (ssize_t)(sizeof(expected) - 1u));
    CHECK(memcmp(output, expected, sizeof(expected) - 1u) == 0);
    CHECK(read(descriptors[0], output, sizeof(output)) == 0);
  }
  CHECK(close(descriptors[0]) == 0);
  return 0;
}

static int broken_sink(void)
{
  ftun_cli_result_sink_t *sink = NULL;
  ftun_cli_result_ticket_t *ticket = NULL;
  ftun_cli_result_usage_t usage;
  struct timespec pause = {0, 1000000L};
  int descriptors[2];
  unsigned int attempt;
  CHECK(pipe(descriptors) == 0);
  CHECK(ftun_cli_result_sink_create(descriptors[1], &sink) == FTUN_OK);
  CHECK(close(descriptors[0]) == 0 && close(descriptors[1]) == 0);
  CHECK(ftun_cli_result_reserve(sink, &ticket) == FTUN_OK);
  CHECK(ftun_cli_result_publish(ticket, FTUN_CLI_RESULT_RELOAD_COMMITTED,
                                FTUN_OK, 0u) == FTUN_OK);
  for (attempt = 0u; attempt < 1000u; attempt++) {
    CHECK(ftun_cli_result_get_usage(sink, &usage) == FTUN_OK);
    if (usage.write_failed != 0u) break;
    (void)nanosleep(&pause, NULL);
  }
  CHECK(usage.write_failed == 1u && usage.undelivered == 1u);
  CHECK(ftun_cli_result_reserve(sink, &ticket) == FTUN_E_IO && ticket == NULL);
  CHECK(ftun_cli_result_sink_stop_until(&sink, UINT64_MAX) == FTUN_E_IO &&
        sink == NULL);
  return 0;
}

static int blocked_sink_timeout(void)
{
  ftun_cli_result_sink_t *sink = NULL;
  ftun_cli_result_ticket_t *ticket = NULL;
  struct timespec pause = {0, 1000000L};
  char bytes[4096];
  size_t baseline = fd_count();
  size_t filled = 0u;
  uint64_t now_ms = 0u;
  int descriptors[2];
  int flags;
  unsigned int attempt;
  memset(bytes, 'x', sizeof(bytes));
  CHECK(baseline != SIZE_MAX && pipe(descriptors) == 0);
  flags = fcntl(descriptors[1], F_GETFL, 0);
  CHECK(flags >= 0 && fcntl(descriptors[1], F_SETFL, flags | O_NONBLOCK) == 0);
  for (;;) {
    ssize_t written = write(descriptors[1], bytes, sizeof(bytes));
    if (written > 0) {
      filled += (size_t)written;
      continue;
    }
    CHECK(written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
    break;
  }
  CHECK(filled != 0u && fcntl(descriptors[1], F_SETFL, flags) == 0);
  CHECK(ftun_cli_result_sink_create(descriptors[1], &sink) == FTUN_OK);
  CHECK(close(descriptors[1]) == 0);
  CHECK(ftun_cli_result_reserve(sink, &ticket) == FTUN_OK);
  CHECK(ftun_cli_result_publish(ticket, FTUN_CLI_RESULT_RELOAD_COMMITTED,
                                FTUN_OK, 0u) == FTUN_OK);
  CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK);
  CHECK(ftun_cli_result_sink_stop_until(&sink, now_ms) == FTUN_E_TIMEOUT &&
        sink == NULL);
  while (filled != 0u) {
    size_t request = filled < sizeof(bytes) ? filled : sizeof(bytes);
    ssize_t received = read(descriptors[0], bytes, request);
    CHECK(received > 0);
    filled -= (size_t)received;
  }
  CHECK(close(descriptors[0]) == 0);
  for (attempt = 0u; attempt < 1000u && fd_count() != baseline; attempt++) {
    (void)nanosleep(&pause, NULL);
  }
  CHECK(fd_count() == baseline);
  return 0;
}

static int terminal_reserve(void)
{
  ftun_cli_result_sink_t *sink = NULL;
  ftun_cli_result_ticket_t *tickets[32];
  ftun_cli_result_ticket_t *stop = NULL;
  ftun_cli_result_ticket_t *run = NULL;
  ftun_cli_result_ticket_t *extra = NULL;
  ftun_cli_result_usage_t usage;
  char output[160];
  static const char expected[] = "ftun: stop request failed: io\n"
    "ftun: run: timeout\n";
  size_t index;
  int fds[2];
  CHECK(pipe(fds) == 0);
  CHECK(ftun_cli_result_sink_create(fds[1], &sink) == FTUN_OK);
  CHECK(close(fds[1]) == 0);
  for (index = 0u; index < 32u; index++) {
    CHECK(ftun_cli_result_reserve(sink, &tickets[index]) == FTUN_OK);
  }
  CHECK(ftun_cli_result_reserve(sink, &extra) == FTUN_E_LIMIT);
  CHECK(ftun_cli_result_reserve_terminal(sink, FTUN_CLI_RESULT_STOP_FAILED,
                                         &stop) == FTUN_OK);
  CHECK(ftun_cli_result_reserve_terminal(sink, FTUN_CLI_RESULT_RUN_FAILED,
                                         &run) == FTUN_OK);
  CHECK(ftun_cli_result_reserve_terminal(sink, FTUN_CLI_RESULT_RUN_FAILED,
                                         &extra) == FTUN_E_LIMIT);
  CHECK(ftun_cli_result_get_usage(sink, &usage) == FTUN_OK &&
        usage.reserved == usage.capacity && usage.capacity == 34u);
  CHECK(ftun_cli_result_publish(stop, FTUN_CLI_RESULT_STOP_FAILED,
                                 FTUN_E_IO, 0u) == FTUN_OK);
  CHECK(ftun_cli_result_publish(run, FTUN_CLI_RESULT_RUN_FAILED,
                                 FTUN_E_TIMEOUT, 0u) == FTUN_OK);
  for (index = 0u; index < 32u; index++) {
    CHECK(ftun_cli_result_abandon(tickets[index]) == FTUN_OK);
  }
  CHECK(ftun_cli_result_sink_stop_until(&sink, UINT64_MAX) == FTUN_OK);
  CHECK(read(fds[0], output, sizeof(output)) == (ssize_t)sizeof(expected) - 1);
  CHECK(memcmp(output, expected, sizeof(expected) - 1u) == 0);
  CHECK(close(fds[0]) == 0);
  return 0;
}

static int descriptor_semantics(void)
{
  ftun_cli_result_sink_t *sink = NULL;
  ftun_cli_result_ticket_t *ticket = NULL;
  char path[] = "/tmp/ftun-cli-result.XXXXXX";
  char output[80];
  static const char expected[] = "prefix:ftun: reload committed\n";
  int descriptor = mkstemp(path);
  int alias;
  int flags;
  int fdflags;
  CHECK(descriptor >= 0 && unlink(path) == 0);
  CHECK(write(descriptor, "prefix:", 7u) == 7);
  alias = dup(descriptor);
  flags = fcntl(descriptor, F_GETFL);
  fdflags = fcntl(descriptor, F_GETFD);
  CHECK(alias >= 0 && flags >= 0 && fdflags >= 0);
  CHECK(ftun_cli_result_sink_create(descriptor, &sink) == FTUN_OK);
  CHECK(ftun_cli_result_reserve(sink, &ticket) == FTUN_OK);
  CHECK(ftun_cli_result_publish(ticket, FTUN_CLI_RESULT_RELOAD_COMMITTED,
                                 FTUN_OK, 0u) == FTUN_OK);
  CHECK(ftun_cli_result_sink_stop_until(&sink, UINT64_MAX) == FTUN_OK);
  CHECK(fcntl(descriptor, F_GETFL) == flags &&
        fcntl(alias, F_GETFL) == flags &&
        fcntl(descriptor, F_GETFD) == fdflags);
  CHECK(lseek(alias, 0, SEEK_CUR) == (off_t)sizeof(expected) - 1);
  CHECK(lseek(descriptor, 0, SEEK_SET) == 0);
  CHECK(read(descriptor, output, sizeof(output)) == (ssize_t)sizeof(expected)-1);
  CHECK(memcmp(output, expected, sizeof(expected) - 1u) == 0);
  CHECK(close(alias) == 0 && close(descriptor) == 0);
  CHECK(ftun_cli_result_sink_create(descriptor, &sink) == FTUN_E_IO &&
        sink == NULL);
  return 0;
}

static int socket_output(void)
{
  ftun_cli_result_sink_t *sink = NULL;
  ftun_cli_result_ticket_t *ticket = NULL;
  static const char expected[] = "ftun: reload committed\n";
  char output[80];
  int fds[2];
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
  CHECK(ftun_cli_result_sink_create(fds[1], &sink) == FTUN_OK);
  CHECK(close(fds[1]) == 0);
  CHECK(ftun_cli_result_reserve(sink, &ticket) == FTUN_OK);
  CHECK(ftun_cli_result_publish(ticket, FTUN_CLI_RESULT_RELOAD_COMMITTED,
                                 FTUN_OK, 0u) == FTUN_OK);
  CHECK(ftun_cli_result_sink_stop_until(&sink, UINT64_MAX) == FTUN_OK);
  CHECK(read(fds[0], output, sizeof(output)) == (ssize_t)sizeof(expected)-1);
  CHECK(memcmp(output, expected, sizeof(expected) - 1u) == 0);
  CHECK(close(fds[0]) == 0);
  return 0;
}

static int full_sink(void)
{
  ftun_cli_result_sink_t *sink = NULL;
  ftun_cli_result_ticket_t *ticket = NULL;
  int descriptor = open("/dev/full", O_WRONLY);
  CHECK(descriptor >= 0);
  CHECK(ftun_cli_result_sink_create(descriptor, &sink) == FTUN_OK);
  CHECK(close(descriptor) == 0);
  CHECK(ftun_cli_result_reserve(sink, &ticket) == FTUN_OK);
  CHECK(ftun_cli_result_publish(ticket, FTUN_CLI_RESULT_RELOAD_COMMITTED,
                                 FTUN_OK, 0u) == FTUN_OK);
  CHECK(ftun_cli_result_sink_stop_until(&sink, UINT64_MAX) == FTUN_E_IO &&
        sink == NULL);
  return 0;
}

typedef struct { ftun_cli_result_sink_t *sink; int failed; } producer_t;

static void *produce(void *user)
{
  producer_t *producer = (producer_t *)user;
  unsigned int index;
  struct timespec pause = {0, 1000000L};
  for (index = 0u; index < 100u; index++) {
    ftun_cli_result_ticket_t *ticket = NULL;
    ftun_status_t status;
    unsigned int tries = 0u;
    do {
      status = ftun_cli_result_reserve(producer->sink, &ticket);
      if (status == FTUN_E_LIMIT) (void)nanosleep(&pause, NULL);
    } while (status == FTUN_E_LIMIT && ++tries < 1000u);
    if (status != FTUN_OK ||
        ftun_cli_result_publish(ticket, FTUN_CLI_RESULT_RELOAD_REJECTED,
                               FTUN_E_IO, index) != FTUN_OK) {
      producer->failed = 1;
      break;
    }
  }
  return NULL;
}

static int concurrent_results(void)
{
  ftun_cli_result_sink_t *sink = NULL;
  ftun_cli_result_usage_t usage;
  producer_t producers[4];
  pthread_t threads[4];
  char path[] = "/tmp/ftun-cli-concurrent.XXXXXX";
  char bytes[4096];
  size_t lines = 0u;
  size_t index;
  ssize_t got;
  int descriptor = mkstemp(path);
  CHECK(descriptor >= 0 && unlink(path) == 0);
  CHECK(ftun_cli_result_sink_create(descriptor, &sink) == FTUN_OK);
  memset(producers, 0, sizeof(producers));
  for (index = 0u; index < 4u; index++) {
    producers[index].sink = sink;
    CHECK(pthread_create(&threads[index], NULL, produce, &producers[index]) == 0);
  }
  for (index = 0u; index < 4u; index++) {
    CHECK(pthread_join(threads[index], NULL) == 0 && !producers[index].failed);
  }
  CHECK(ftun_cli_result_get_usage(sink, &usage) == FTUN_OK &&
        usage.accepted == 400u && usage.undelivered == 0u &&
        usage.write_failed == 0u);
  CHECK(ftun_cli_result_sink_stop_until(&sink, UINT64_MAX) == FTUN_OK);
  CHECK(lseek(descriptor, 0, SEEK_SET) == 0);
  while ((got = read(descriptor, bytes, sizeof(bytes))) > 0) {
    for (index = 0u; index < (size_t)got; index++) {
      if (bytes[index] == '\n') lines++;
    }
  }
  CHECK(got == 0 && lines == 400u && close(descriptor) == 0);
  return 0;
}

static int partial_write(void)
{
  ftun_cli_result_sink_t *sink = NULL;
  ftun_cli_result_ticket_t *ticket = NULL;
  static const char expected[] = "ftun: reload committed\n";
  char path[] = "/tmp/ftun-cli-partial.XXXXXX";
  char output[80];
  int descriptor = mkstemp(path);
  CHECK(descriptor >= 0 && unlink(path) == 0);
  CHECK(ftun_cli_result_sink_create(descriptor, &sink) == FTUN_OK);
  CHECK(pthread_mutex_lock(&write_fault_mutex) == 0);
  CHECK(fstat(descriptor, &write_fault_identity) == 0);
  write_fault_calls = 0u;
  write_fault_active = 1;
  CHECK(pthread_mutex_unlock(&write_fault_mutex) == 0);
  CHECK(ftun_cli_result_reserve(sink, &ticket) == FTUN_OK);
  CHECK(ftun_cli_result_publish(ticket, FTUN_CLI_RESULT_RELOAD_COMMITTED,
                                 FTUN_OK, 0u) == FTUN_OK);
  CHECK(ftun_cli_result_sink_stop_until(&sink, UINT64_MAX) == FTUN_OK);
  CHECK(pthread_mutex_lock(&write_fault_mutex) == 0);
  CHECK(write_fault_calls == 4u);
  write_fault_active = 0;
  CHECK(pthread_mutex_unlock(&write_fault_mutex) == 0);
  CHECK(lseek(descriptor, 0, SEEK_SET) == 0);
  CHECK(read(descriptor, output, sizeof(output)) == (ssize_t)sizeof(expected)-1);
  CHECK(memcmp(output, expected, sizeof(expected) - 1u) == 0);
  CHECK(close(descriptor) == 0);
  return 0;
}

static int independent_lifetime(void)
{
  ftun_cli_result_sink_t *sink = NULL;
  ftun_cli_result_ticket_t *ticket = NULL;
  ftun_cli_result_usage_t usage;
  ftun_budget_usage_t pending;
  ftun_core_options_t options = {0};
  ftun_core_t *core = NULL;
  struct timespec deadline;
  uint64_t now_ms;
  char path[] = "/tmp/ftun-cli-budget.XXXXXX";
  int descriptor;
  int invalid;
  CHECK(pthread_mutex_lock(&write_fault_mutex) == 0);
  resource_tracking = 1;
  tracked_destroyed = 0u;
  resource_failure = 0;
  CHECK(pthread_mutex_unlock(&write_fault_mutex) == 0);
  descriptor = mkstemp(path);
  CHECK(descriptor >= 0 && unlink(path) == 0);
  invalid = dup(descriptor);
  CHECK(invalid >= 0 && close(invalid) == 0);
  CHECK(ftun_cli_result_sink_create(invalid, &sink) == FTUN_E_IO && sink == NULL);
  CHECK(tracked_destroyed == 1u && tracked_budget == NULL && !resource_failure);
  options.struct_size = sizeof(options);
  options.abi_version = FTUN_ABI_VERSION;
  CHECK(ftun_core_create(&options, &core) == FTUN_OK);
  CHECK(ftun_cli_result_sink_create(descriptor, &sink) == FTUN_OK);
  CHECK(ftun_cli_result_get_usage(sink, &usage) == FTUN_OK);
  CHECK(usage.owned_resources.memory_bytes > 0u &&
        usage.owned_resources.descriptors == 1u &&
        usage.owned_resources.queue_slots == 34u && usage.budget_metadata_bytes > 0u);
  CHECK(pthread_mutex_lock(&write_fault_mutex) == 0);
  CHECK(fstat(descriptor, &write_fault_identity) == 0);
  write_fault_active = 1;
  write_fault_blocked = 1;
  write_fault_entered = 0;
  write_fault_calls = 3u;
  CHECK(pthread_mutex_unlock(&write_fault_mutex) == 0);
  CHECK(ftun_cli_result_reserve(sink, &ticket) == FTUN_OK);
  CHECK(ftun_cli_result_publish(ticket, FTUN_CLI_RESULT_RELOAD_COMMITTED, FTUN_OK, 0u) == FTUN_OK);
  CHECK(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
  deadline.tv_sec += 5;
  CHECK(pthread_mutex_lock(&write_fault_mutex) == 0);
  while (!write_fault_entered) {
    CHECK(pthread_cond_timedwait(&write_fault_condition, &write_fault_mutex, &deadline) == 0);
  }
  CHECK(pthread_mutex_unlock(&write_fault_mutex) == 0);
  CHECK(ftun_core_destroy(&core) == FTUN_OK && core == NULL);
  CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK);
  CHECK(ftun_cli_result_sink_stop_until(&sink, now_ms) == FTUN_E_TIMEOUT && sink == NULL);
  CHECK(pthread_mutex_lock(&write_fault_mutex) == 0);
  CHECK(tracked_budget != NULL && tracked_destroyed == 1u);
  CHECK(ftun_budget_get_usage(tracked_budget, &pending) == FTUN_OK);
  CHECK(pending.used_resources.memory_bytes == usage.owned_resources.memory_bytes &&
        pending.used_resources.descriptors == 1u && pending.used_resources.queue_slots == 34u &&
        pending.metadata_bytes == usage.budget_metadata_bytes);
  write_fault_blocked = 0;
  CHECK(pthread_cond_broadcast(&write_fault_condition) == 0);
  while (tracked_destroyed != 2u) {
    CHECK(pthread_cond_timedwait(&write_fault_condition, &write_fault_mutex, &deadline) == 0);
  }
  CHECK(tracked_budget == NULL && !resource_failure);
  write_fault_active = 0;
  resource_tracking = 0;
  CHECK(pthread_mutex_unlock(&write_fault_mutex) == 0);
  CHECK(close(descriptor) == 0);
  return 0;
}

int main(void)
{
  CHECK(ordered_output() == 0);
  CHECK(bounded_admission() == 0);
  CHECK(broken_sink() == 0);
  CHECK(blocked_sink_timeout() == 0);
  CHECK(terminal_reserve() == 0);
  CHECK(descriptor_semantics() == 0);
  CHECK(socket_output() == 0);
  CHECK(full_sink() == 0);
  CHECK(concurrent_results() == 0);
  CHECK(partial_write() == 0);
  CHECK(independent_lifetime() == 0);
  puts("CLI result contract: 11 scenarios passed");
  return 0;
}
