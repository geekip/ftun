#define _POSIX_C_SOURCE 200809L
#include "proxy/control_resolver.h"
#include "platform/clock.h"
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "control system worker failed %d: %s\n", __LINE__, #x); return 1; } } while (0)

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static bool entered, released;
static pthread_t owner;
static unsigned int callbacks;
static ftun_status_t completed_status;

typedef struct {
  ftun_control_execution_t execution;
  char domain[32];
} input_t;

static uint64_t now_ms(void)
{
  uint64_t now = 0u;
  (void)ftun_monotonic_now(&now);
  return now;
}

static void pause_once(void)
{
  const struct timespec pause = {0, 1000000};
  (void)nanosleep(&pause, NULL);
}

int __real_getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **);
int __wrap_getaddrinfo(const char *node, const char *service,
  const struct addrinfo *hints, struct addrinfo **out)
{
  if (strcmp(node, "blocked.test") != 0 || pthread_equal(pthread_self(), owner)) return EAI_FAIL;
  (void)pthread_mutex_lock(&mutex);
  entered = true;
  (void)pthread_cond_broadcast(&condition);
  while (!released) (void)pthread_cond_wait(&condition, &mutex);
  (void)pthread_mutex_unlock(&mutex);
  return __real_getaddrinfo("127.0.0.1", service, hints, out);
}

static ftun_status_t execute(ftun_bytes_t bytes, uint8_t *out, size_t capacity, size_t *length)
{
  const input_t *input = (const input_t *)bytes.data;
  ftun_control_resolver_plan_t plan = {0};
  ftun_endpoint_t endpoint;
  ftun_status_t status;
  (void)out; (void)capacity;
  *length = 0u;
  if (bytes.length != sizeof(*input)) return FTUN_E_INVALID;
  status = ftun_control_resolve(&input->execution, &plan,
    (ftun_string_t){input->domain, strlen(input->domain)}, 80u, &endpoint);
  return status;
}

static void completed(ftun_operation_t *operation, ftun_error_t error, ftun_bytes_t result, void *user)
{
  (void)operation; (void)result; (void)user;
  callbacks++;
  completed_status = pthread_equal(pthread_self(), owner) ? error.status : FTUN_E_STATE_CORRUPT;
}

static int run(bool cancel)
{
  ftun_budget_t *budget = NULL;
  ftun_worker_t *worker = NULL;
  ftun_worker_job_t job = {0};
  ftun_operation_t *operation = NULL;
  ftun_worker_usage_t usage;
  ftun_budget_usage_t before, after;
  input_t input = {0};
  size_t dispatched;
  uint64_t deadline;
  entered = released = false;
  callbacks = 0u;
  owner = pthread_self();
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 128u, &budget) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &before) == FTUN_OK);
  CHECK(ftun_worker_create(budget, 1u, &worker) == FTUN_OK);
  input.execution.budget = budget;
  input.execution.generation = 9u;
  input.execution.purpose = FTUN_DIAL_PURPOSE_PROBE;
  input.execution.allow_system_resolver = true;
  input.execution.deadline_ms = now_ms() + 100u;
  memcpy(input.domain, "blocked.test", 13u);
  job.execute = execute;
  job.input = (ftun_bytes_t){(const uint8_t *)&input, sizeof(input)};
  CHECK(ftun_worker_submit(worker, &job, completed, NULL, &operation) == FTUN_OK);
  memset(input.domain, 'x', 12u);
  deadline = now_ms() + 2000u;
  for (;;) {
    bool observed;
    (void)pthread_mutex_lock(&mutex);
    observed = entered;
    (void)pthread_mutex_unlock(&mutex);
    if (observed) break;
    CHECK(now_ms() < deadline);
    pause_once();
  }
  if (cancel) {
    CHECK(ftun_worker_stop(worker) == FTUN_OK);
    CHECK(ftun_worker_join_until(worker, now_ms() + 10u) == FTUN_E_TIMEOUT);
    CHECK(ftun_worker_destroy(&worker) == FTUN_E_AGAIN && worker != NULL);
    CHECK(ftun_worker_get_usage(worker, &usage) == FTUN_OK && usage.running == 1u);
    CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK && after.used_resources.memory_bytes != 0u);
  } else {
    while (now_ms() <= input.execution.deadline_ms) pause_once();
  }
  (void)pthread_mutex_lock(&mutex);
  released = true;
  (void)pthread_cond_broadcast(&condition);
  (void)pthread_mutex_unlock(&mutex);
  deadline = now_ms() + 2000u;
  do {
    CHECK(ftun_worker_poll(worker, 8u, &dispatched) == FTUN_OK);
    CHECK(ftun_worker_get_usage(worker, &usage) == FTUN_OK);
    CHECK(now_ms() < deadline);
    if (usage.tasks != 0u) pause_once();
  } while (usage.tasks != 0u);
  CHECK(callbacks == 1u && completed_status == (cancel ? FTUN_E_CANCELLED : FTUN_E_TIMEOUT));
  CHECK(ftun_worker_stop(worker) == FTUN_OK);
  CHECK(ftun_worker_join_until(worker, deadline) == FTUN_OK);
  CHECK(ftun_worker_destroy(&worker) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK && after.used_resources.memory_bytes == before.used_resources.memory_bytes && after.metadata_bytes == before.metadata_bytes);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(void)
{
  CHECK(run(true) == 0);
  CHECK(run(false) == 0);
  puts("control libc resolver: Worker stop deadline, retained producer, owner completion and late timeout passed");
  return 0;
}
