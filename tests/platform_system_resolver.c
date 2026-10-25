#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "core/budget.h"
#include "core/operation.h"
#include "core/worker.h"
#include "platform/system_resolver.h"
#include "util/time.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "system resolver contract failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  int calls;
  ftun_status_t status;
  uint32_t mark;
  char device[FTUN_SOCKET_INTERFACE_BYTES];
} path_state_t;

typedef struct {
  int calls;
  ftun_error_t error;
  char domain[FTUN_SYSTEM_RESOLVER_MAX_DOMAIN_BYTES + 1u];
  size_t domain_length;
  uint8_t addresses[FTUN_SYSTEM_RESOLVER_MAX_IPV4_RESULTS][4];
  size_t address_count;
} completion_state_t;

typedef struct {
  ftun_budget_t *budget;
  ftun_worker_t *worker;
  path_state_t path;
  ftun_system_resolve_request_t request;
} fixture_t;

static pthread_mutex_t gate_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_condition = PTHREAD_COND_INITIALIZER;
static int gate_entered;
static int gate_open;
static int gate_saw_copy;
static int execute_calls;

static void sleep_one_millisecond(void)
{
  struct timespec delay = {0, 1000000L};
  (void)nanosleep(&delay, NULL);
}

static ftun_status_t check_path(void *user,
                                const ftun_socket_policy_t *protection)
{
  path_state_t *state = (path_state_t *)user;
  state->calls++;
  state->mark = protection->mark;
  memset(state->device, 0, sizeof(state->device));
  if (protection->interface_name.length >= sizeof(state->device)) {
    return FTUN_E_INVALID;
  }
  if (protection->interface_name.length != 0u) {
    memcpy(state->device, protection->interface_name.data,
           protection->interface_name.length);
  }
  return state->status;
}

static void resolved(ftun_operation_t *operation, ftun_error_t error,
                     const ftun_system_resolve_result_t *result, void *user)
{
  completion_state_t *state = (completion_state_t *)user;
  size_t index;
  (void)operation;
  state->calls++;
  state->error = error;
  if (result == NULL || result->domain.length >
      FTUN_SYSTEM_RESOLVER_MAX_DOMAIN_BYTES ||
      result->address_count > FTUN_SYSTEM_RESOLVER_MAX_IPV4_RESULTS) {
    state->calls = -100;
    return;
  }
  state->domain_length = result->domain.length;
  if (result->domain.length != 0u) {
    memcpy(state->domain, result->domain.data, result->domain.length);
  }
  state->domain[result->domain.length] = '\0';
  state->address_count = result->address_count;
  for (index = 0u; index < result->address_count; index++) {
    if (result->addresses[index].kind != FTUN_ADDRESS_IPV4 ||
        result->addresses[index].port != 0u ||
        result->addresses[index].domain.length != 0u) {
      state->calls = -100;
      return;
    }
    memcpy(state->addresses[index], result->addresses[index].address, 4u);
  }
}

static ftun_status_t two_addresses(ftun_bytes_t input, uint8_t *result,
                                   size_t capacity, size_t *out_size)
{
  static const uint8_t expected[] = "dual.test";
  static const uint8_t addresses[8] = {1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u};
  if (input.length != sizeof(expected) ||
      memcmp(input.data, expected, sizeof(expected)) != 0 || capacity < 8u) {
    return FTUN_E_STATE_CORRUPT;
  }
  memcpy(result, addresses, sizeof(addresses));
  *out_size = sizeof(addresses);
  return FTUN_OK;
}

static ftun_status_t resolve_failure(ftun_bytes_t input, uint8_t *result,
                                     size_t capacity, size_t *out_size)
{
  (void)input;
  (void)result;
  (void)capacity;
  *out_size = 0u;
  return FTUN_E_RESOLVE;
}

static ftun_status_t malformed_result(ftun_bytes_t input, uint8_t *result,
                                      size_t capacity, size_t *out_size)
{
  (void)input;
  if (capacity < 3u) return FTUN_E_LIMIT;
  result[0] = 1u;
  result[1] = 2u;
  result[2] = 3u;
  *out_size = 3u;
  return FTUN_OK;
}

static ftun_status_t duplicate_result(ftun_bytes_t input, uint8_t *result,
                                      size_t capacity, size_t *out_size)
{
  static const uint8_t addresses[8] = {1u, 2u, 3u, 4u, 1u, 2u, 3u, 4u};
  (void)input;
  if (capacity < sizeof(addresses)) return FTUN_E_LIMIT;
  memcpy(result, addresses, sizeof(addresses));
  *out_size = sizeof(addresses);
  return FTUN_OK;
}

static ftun_status_t gate_execute(ftun_bytes_t input, uint8_t *result,
                                  size_t capacity, size_t *out_size)
{
  static const uint8_t expected[] = "copy.test";
  (void)pthread_mutex_lock(&gate_mutex);
  gate_entered = 1;
  gate_saw_copy = input.length == sizeof(expected) &&
                  memcmp(input.data, expected, sizeof(expected)) == 0;
  (void)pthread_cond_broadcast(&gate_condition);
  while (!gate_open) (void)pthread_cond_wait(&gate_condition, &gate_mutex);
  execute_calls++;
  (void)pthread_mutex_unlock(&gate_mutex);
  if (capacity < 4u) return FTUN_E_LIMIT;
  result[0] = 9u;
  result[1] = 8u;
  result[2] = 7u;
  result[3] = 6u;
  *out_size = 4u;
  return FTUN_OK;
}

static ftun_status_t counted_execute(ftun_bytes_t input, uint8_t *result,
                                     size_t capacity, size_t *out_size)
{
  (void)input;
  (void)pthread_mutex_lock(&gate_mutex);
  execute_calls++;
  (void)pthread_mutex_unlock(&gate_mutex);
  if (capacity < 4u) return FTUN_E_LIMIT;
  memset(result, 10, 4u);
  *out_size = 4u;
  return FTUN_OK;
}

static void reset_gate(void)
{
  (void)pthread_mutex_lock(&gate_mutex);
  gate_entered = 0;
  gate_open = 0;
  gate_saw_copy = 0;
  (void)pthread_mutex_unlock(&gate_mutex);
}

static void open_gate(void)
{
  (void)pthread_mutex_lock(&gate_mutex);
  gate_open = 1;
  (void)pthread_cond_broadcast(&gate_condition);
  (void)pthread_mutex_unlock(&gate_mutex);
}

static int wait_for_gate(void)
{
  size_t attempt;
  for (attempt = 0u; attempt < 5000u; attempt++) {
    int entered;
    (void)pthread_mutex_lock(&gate_mutex);
    entered = gate_entered;
    (void)pthread_mutex_unlock(&gate_mutex);
    if (entered) return 1;
    sleep_one_millisecond();
  }
  return 0;
}

static int wait_for_calls(ftun_worker_t *worker, completion_state_t *state,
                          int calls)
{
  size_t attempt;
  for (attempt = 0u; attempt < 5000u; attempt++) {
    size_t dispatched = 0u;
    if (ftun_worker_poll(worker, 8u, &dispatched) != FTUN_OK) return 0;
    if (state->calls == calls) return 1;
    sleep_one_millisecond();
  }
  return 0;
}

static int wait_for_empty(ftun_worker_t *worker)
{
  size_t attempt;
  for (attempt = 0u; attempt < 5000u; attempt++) {
    ftun_worker_usage_t usage;
    size_t dispatched = 0u;
    if (ftun_worker_poll(worker, 8u, &dispatched) != FTUN_OK ||
        ftun_worker_get_usage(worker, &usage) != FTUN_OK) return 0;
    if (usage.tasks == 0u) return 1;
    sleep_one_millisecond();
  }
  return 0;
}

static int fixture_start(fixture_t *fixture, size_t capacity)
{
  memset(fixture, 0, sizeof(*fixture));
  if (ftun_budget_create(NULL, 65536u, 1024u, &fixture->budget) != FTUN_OK ||
      ftun_worker_create(fixture->budget, capacity, &fixture->worker) != FTUN_OK) {
    return 1;
  }
  fixture->request.worker = fixture->worker;
  fixture->request.budget = fixture->budget;
  fixture->request.domain.data = "dual.test";
  fixture->request.domain.length = 9u;
  fixture->request.protection.mark = 77u;
  fixture->request.protection.interface_name.data = "eth0";
  fixture->request.protection.interface_name.length = 4u;
  fixture->request.check_path = check_path;
  fixture->request.path_user = &fixture->path;
  fixture->request.completion = resolved;
  return 0;
}

static int fixture_stop(fixture_t *fixture)
{
  ftun_budget_usage_t usage;
  if (ftun_worker_stop(fixture->worker) != FTUN_OK ||
      ftun_worker_join(fixture->worker) != FTUN_OK ||
      !wait_for_empty(fixture->worker) ||
      ftun_worker_destroy(&fixture->worker) != FTUN_OK ||
      ftun_budget_get_usage(fixture->budget, &usage) != FTUN_OK ||
      usage.used != 0u || ftun_budget_destroy(&fixture->budget) != FTUN_OK) {
    return 1;
  }
  return 0;
}

static int test_results_and_failures(void)
{
  fixture_t fixture;
  completion_state_t success = {0};
  completion_state_t failure = {0};
  completion_state_t malformed = {0};
  completion_state_t duplicate = {0};
  ftun_operation_t *operation = NULL;
  static const uint8_t first[4] = {1u, 2u, 3u, 4u};
  static const uint8_t second[4] = {5u, 6u, 7u, 8u};
  CHECK(fixture_start(&fixture, 4u) == 0);
  fixture.request.user = &success;
  CHECK(ftun_system_resolve_with_execute(NULL, &fixture.request,
                                         two_addresses, &operation) == FTUN_OK);
  CHECK(operation != NULL && success.calls == 0 && fixture.path.calls == 1);
  CHECK(fixture.path.mark == 77u && strcmp(fixture.path.device, "eth0") == 0);
  CHECK(wait_for_calls(fixture.worker, &success, 1));
  CHECK(success.error.status == FTUN_OK && success.address_count == 2u);
  CHECK(strcmp(success.domain, "dual.test") == 0);
  CHECK(memcmp(success.addresses[0], first, 4u) == 0 &&
        memcmp(success.addresses[1], second, 4u) == 0);

  fixture.request.user = &failure;
  CHECK(ftun_system_resolve_with_execute(NULL, &fixture.request,
                                         resolve_failure, &operation) == FTUN_OK);
  CHECK(wait_for_calls(fixture.worker, &failure, 1));
  CHECK(failure.error.status == FTUN_E_RESOLVE &&
        failure.error.stage == FTUN_SYSTEM_RESOLVER_STAGE_QUERY &&
        failure.address_count == 0u);

  fixture.request.user = &malformed;
  CHECK(ftun_system_resolve_with_execute(NULL, &fixture.request,
                                         malformed_result, &operation) == FTUN_OK);
  CHECK(wait_for_calls(fixture.worker, &malformed, 1));
  CHECK(malformed.error.status == FTUN_E_STATE_CORRUPT &&
        malformed.error.stage == FTUN_SYSTEM_RESOLVER_STAGE_RESULT);

  fixture.request.user = &duplicate;
  CHECK(ftun_system_resolve_with_execute(NULL, &fixture.request,
                                         duplicate_result, &operation) == FTUN_OK);
  CHECK(wait_for_calls(fixture.worker, &duplicate, 1));
  CHECK(duplicate.error.status == FTUN_E_STATE_CORRUPT &&
        duplicate.error.stage == FTUN_SYSTEM_RESOLVER_STAGE_RESULT);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_copy_cancel_capacity(void)
{
  fixture_t fixture;
  completion_state_t cancelled = {0};
  completion_state_t rejected = {0};
  ftun_operation_t *operation = NULL;
  ftun_operation_t *second = (ftun_operation_t *)(uintptr_t)1;
  char domain[] = "copy.test";
  CHECK(fixture_start(&fixture, 1u) == 0);
  fixture.request.domain.data = domain;
  fixture.request.domain.length = 9u;
  fixture.request.user = &cancelled;
  reset_gate();
  CHECK(ftun_system_resolve_with_execute(NULL, &fixture.request,
                                         gate_execute, &operation) == FTUN_OK);
  memcpy(domain, "xxxx.test", 9u);
  CHECK(wait_for_gate());
  fixture.request.user = &rejected;
  CHECK(ftun_system_resolve_with_execute(NULL, &fixture.request,
                                         counted_execute, &second) == FTUN_E_LIMIT);
  CHECK(second == NULL && rejected.calls == 0);
  CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  CHECK(wait_for_calls(fixture.worker, &cancelled, 1));
  CHECK(cancelled.error.status == FTUN_E_CANCELLED &&
        cancelled.error.stage == FTUN_SYSTEM_RESOLVER_STAGE_QUERY &&
        strcmp(cancelled.domain, "copy.test") == 0);
  open_gate();
  CHECK(wait_for_empty(fixture.worker));
  (void)pthread_mutex_lock(&gate_mutex);
  CHECK(gate_saw_copy && execute_calls > 0);
  (void)pthread_mutex_unlock(&gate_mutex);
  CHECK(cancelled.calls == 1);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_deadline_and_budget(void)
{
  fixture_t fixture;
  completion_state_t timed_out = {0};
  completion_state_t limited = {0};
  ftun_budget_t *tiny = NULL;
  ftun_operation_t *operation = NULL;
  uint64_t now = 0u;
  int before;
  CHECK(fixture_start(&fixture, 2u) == 0);
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  (void)pthread_mutex_lock(&gate_mutex);
  before = execute_calls;
  (void)pthread_mutex_unlock(&gate_mutex);
  fixture.request.deadline_ms = now;
  fixture.request.user = &timed_out;
  CHECK(ftun_system_resolve_with_execute(NULL, &fixture.request,
                                         counted_execute, &operation) == FTUN_OK);
  CHECK(wait_for_calls(fixture.worker, &timed_out, 1));
  CHECK(timed_out.error.status == FTUN_E_TIMEOUT &&
        timed_out.error.stage == FTUN_SYSTEM_RESOLVER_STAGE_DEADLINE);
  (void)pthread_mutex_lock(&gate_mutex);
  CHECK(execute_calls == before);
  (void)pthread_mutex_unlock(&gate_mutex);

  CHECK(ftun_budget_create(NULL, 1u, 0u, &tiny) == FTUN_OK);
  fixture.request.deadline_ms = 0u;
  fixture.request.budget = tiny;
  fixture.request.user = &limited;
  operation = (ftun_operation_t *)(uintptr_t)1;
  CHECK(ftun_system_resolve_with_execute(NULL, &fixture.request,
                                         counted_execute, &operation) == FTUN_E_LIMIT);
  CHECK(operation == NULL && limited.calls == 0);
  CHECK(ftun_budget_destroy(&tiny) == FTUN_OK);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_path_and_input_boundaries(void)
{
  fixture_t fixture;
  completion_state_t state = {0};
  ftun_operation_t *operation = (ftun_operation_t *)(uintptr_t)1;
  char embedded[] = {'a', '\0', 'b'};
  char long_label[65];
  char device[FTUN_SOCKET_INTERFACE_BYTES];
  CHECK(fixture_start(&fixture, 1u) == 0);
  fixture.request.user = &state;
  fixture.path.status = FTUN_E_REJECTED;
  CHECK(ftun_system_resolve_with_execute(NULL, &fixture.request,
                                         counted_execute, &operation) ==
        FTUN_E_REJECTED);
  CHECK(operation == NULL && state.calls == 0 && fixture.path.calls == 1);
  fixture.path.status = FTUN_OK;

  fixture.request.check_path = NULL;
  CHECK(ftun_system_resolve_with_execute(NULL, &fixture.request,
                                         counted_execute, &operation) ==
        FTUN_E_INVALID && operation == NULL);
  fixture.request.check_path = check_path;
  fixture.request.domain.data = embedded;
  fixture.request.domain.length = sizeof(embedded);
  CHECK(ftun_system_resolve_with_execute(NULL, &fixture.request,
                                         counted_execute, &operation) ==
        FTUN_E_INVALID);
  memset(long_label, 'a', sizeof(long_label));
  fixture.request.domain.data = long_label;
  fixture.request.domain.length = sizeof(long_label);
  CHECK(ftun_system_resolve_with_execute(NULL, &fixture.request,
                                         counted_execute, &operation) ==
        FTUN_E_INVALID);
  fixture.request.domain.data = "127.0.0.1";
  fixture.request.domain.length = 9u;
  CHECK(ftun_system_resolve_with_execute(NULL, &fixture.request,
                                         counted_execute, &operation) ==
        FTUN_E_INVALID);
  fixture.request.domain.data = "valid.test";
  fixture.request.domain.length = 10u;
  fixture.request.protection.mark = 0u;
  CHECK(ftun_system_resolve_with_execute(NULL, &fixture.request,
                                         counted_execute, &operation) ==
        FTUN_E_INVALID);
  fixture.request.protection.mark = 1u;
  memset(device, 'x', sizeof(device));
  fixture.request.protection.interface_name.data = device;
  fixture.request.protection.interface_name.length = sizeof(device);
  CHECK(ftun_system_resolve_with_execute(NULL, &fixture.request,
                                         counted_execute, &operation) ==
        FTUN_E_INVALID);
  fixture.request.protection.interface_name.data = NULL;
  fixture.request.protection.interface_name.length = 0u;
  CHECK(ftun_system_resolve_with_execute(NULL, &fixture.request,
                                         NULL, &operation) == FTUN_E_INVALID);
  CHECK(ftun_system_resolve_with_execute(NULL, &fixture.request,
                                         counted_execute, NULL) ==
        FTUN_E_INVALID);
  CHECK(state.calls == 0);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_libc_localhost(void)
{
  fixture_t fixture;
  completion_state_t state = {0};
  ftun_operation_t *operation = NULL;
  size_t index;
  int found_loopback = 0;
  CHECK(fixture_start(&fixture, 1u) == 0);
  fixture.request.domain.data = "localhost";
  fixture.request.domain.length = 9u;
  fixture.request.user = &state;
  CHECK(ftun_system_resolve(NULL, &fixture.request, &operation) == FTUN_OK);
  CHECK(operation != NULL && state.calls == 0);
  CHECK(wait_for_calls(fixture.worker, &state, 1));
  CHECK(state.error.status == FTUN_OK && state.address_count != 0u);
  for (index = 0u; index < state.address_count; index++) {
    if (state.addresses[index][0] == 127u) found_loopback = 1;
  }
  CHECK(found_loopback);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

/* TASK-PLATFORM-004 / TEST-PLATFORM-004：Worker、路径门禁和 libc/NSS。 */
int main(void)
{
  CHECK(test_results_and_failures() == 0);
  CHECK(test_copy_cancel_capacity() == 0);
  CHECK(test_deadline_and_budget() == 0);
  CHECK(test_path_and_input_boundaries() == 0);
  CHECK(test_libc_localhost() == 0);
  return 0;
}
