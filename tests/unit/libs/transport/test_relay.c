#include "libs/transport/relay.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "relay contract failed at line %d: %s\n", __LINE__, #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  uint8_t input[64];
  size_t input_length;
  size_t input_offset;
  size_t read_chunk;
  ftun_status_t read_status;
  int eof_when_empty;
  ftun_stream_write_token_t write;
  uint8_t pending[64];
  size_t pending_length;
  size_t accept_limit;
  ftun_status_t write_status;
  ftun_status_t cancel_status;
  ftun_status_t shutdown_status;
  uint8_t output[128];
  size_t output_length;
  int read_calls;
  int write_calls;
  int cancel_calls;
  int shutdown_calls;
  int destroy_calls;
} stream_backend_state_t;

typedef struct {
  ftun_budget_t *budget;
  ftun_operation_queue_t *operations;
  ftun_stream_t *left;
  ftun_stream_t *right;
  ftun_relay_t *relay;
  stream_backend_state_t left_backend;
  stream_backend_state_t right_backend;
} fixture_t;

static ftun_status_t backend_read(void *user, void *buffer, size_t capacity,
                                  size_t *out_length)
{
  stream_backend_state_t *state = (stream_backend_state_t *)user;
  size_t available;
  size_t amount;
  state->read_calls++;
  *out_length = 0u;
  if (state->read_status != FTUN_OK) return state->read_status;
  if (state->input_offset == state->input_length) {
    return state->eof_when_empty ? FTUN_E_EOF : FTUN_E_AGAIN;
  }
  available = state->input_length - state->input_offset;
  amount = available < capacity ? available : capacity;
  if (state->read_chunk != 0u && amount > state->read_chunk) {
    amount = state->read_chunk;
  }
  memcpy(buffer, state->input + state->input_offset, amount);
  state->input_offset += amount;
  *out_length = amount;
  return FTUN_OK;
}

static ftun_status_t backend_write_start(void *user,
                                         ftun_stream_write_token_t write,
                                         const ftun_buffer_slice_t *slice,
                                         size_t *accepted)
{
  stream_backend_state_t *state = (stream_backend_state_t *)user;
  ftun_bytes_t bytes;
  (void)slice;
  state->write_calls++;
  *accepted = 0u;
  if (state->write_status != FTUN_OK) return state->write_status;
  if (state->write.stream != NULL ||
      ftun_stream_write_data(write, &bytes) != FTUN_OK || bytes.length == 0u) {
    return FTUN_E_STATE_CORRUPT;
  }
  state->pending_length = bytes.length;
  if (state->accept_limit != 0u && state->pending_length > state->accept_limit) {
    state->pending_length = state->accept_limit;
  }
  if (state->pending_length > sizeof(state->pending)) return FTUN_E_LIMIT;
  memcpy(state->pending, bytes.data, state->pending_length);
  state->write = write;
  *accepted = state->pending_length;
  return FTUN_OK;
}

static ftun_status_t backend_write_cancel(void *user,
                                          ftun_stream_write_token_t write)
{
  stream_backend_state_t *state = (stream_backend_state_t *)user;
  state->cancel_calls++;
  if (state->write.stream != write.stream || state->write.slot != write.slot ||
      state->write.generation != write.generation) {
    return FTUN_E_STATE_CORRUPT;
  }
  if (state->cancel_status != FTUN_OK) return state->cancel_status;
  memset(&state->write, 0, sizeof(state->write));
  state->pending_length = 0u;
  return FTUN_OK;
}

static ftun_status_t backend_shutdown(void *user)
{
  stream_backend_state_t *state = (stream_backend_state_t *)user;
  state->shutdown_calls++;
  return state->shutdown_status;
}

static void backend_destroy(void *user)
{
  stream_backend_state_t *state = (stream_backend_state_t *)user;
  state->destroy_calls++;
}

static void unused_completion(ftun_operation_t *operation,
                              ftun_error_t error, void *user)
{
  int *calls = (int *)user;
  (void)operation;
  (void)error;
  (*calls)++;
}

static void relay_progress(void *user)
{
  size_t *calls = (size_t *)user;
  (*calls)++;
}

static void pool_wakeup(void *user)
{
  size_t *calls = (size_t *)user;
  (*calls)++;
}

static int create_stream_on_budget(
  fixture_t *fixture, ftun_budget_t *budget, stream_backend_state_t *state,
  ftun_stream_t **out, int *unused_calls)
{
  ftun_stream_options_t options;
  ftun_stream_backend_t backend;
  memset(&options, 0, sizeof(options));
  memset(&backend, 0, sizeof(backend));
  options.budget = budget;
  options.operations = fixture->operations;
  options.max_pending_writes = 2u;
  options.max_pending_bytes = 64u;
  options.completion = unused_completion;
  options.completion_user = unused_calls;
  backend.read = backend_read;
  backend.write_start = backend_write_start;
  backend.write_cancel = backend_write_cancel;
  backend.shutdown_write = backend_shutdown;
  backend.destroy = backend_destroy;
  backend.context = state;
  return ftun_stream_create(&options, &backend, out) == FTUN_OK ? 0 : 1;
}

static int create_stream(fixture_t *fixture, stream_backend_state_t *state,
                         ftun_stream_t **out, int *unused_calls)
{
  return create_stream_on_budget(fixture, fixture->budget, state, out,
                                 unused_calls);
}

static int fixture_start(fixture_t *fixture, size_t high, size_t low,
                         size_t max_work)
{
  ftun_relay_options_t options;
  static int unused_calls;
  memset(fixture, 0, sizeof(*fixture));
  unused_calls = 0;
  fixture->left_backend.accept_limit = SIZE_MAX;
  fixture->right_backend.accept_limit = SIZE_MAX;
  fixture->left_backend.read_chunk = SIZE_MAX;
  fixture->right_backend.read_chunk = SIZE_MAX;
  if (ftun_budget_create(NULL, 32768u, 0u, &fixture->budget) != FTUN_OK) return 1;
  if (ftun_operation_queue_create(fixture->budget, 8u,
                                  &fixture->operations) != FTUN_OK) return 1;
  if (create_stream(fixture, &fixture->left_backend, &fixture->left,
                    &unused_calls) != 0) return 1;
  if (create_stream(fixture, &fixture->right_backend, &fixture->right,
                    &unused_calls) != 0) return 1;
  options.high_water_bytes = high;
  options.low_water_bytes = low;
  options.max_work_per_round = max_work;
  return ftun_relay_start_with_options(NULL, fixture->left, fixture->right,
                                       &options, &fixture->relay) == FTUN_OK
    ? 0 : 1;
}

static int dispatch_all(fixture_t *fixture, size_t expected)
{
  size_t dispatched = 0u;
  if (ftun_operation_dispatch(fixture->operations, SIZE_MAX,
                              &dispatched) != FTUN_OK) return 1;
  return dispatched == expected ? 0 : 1;
}

static int complete_write(stream_backend_state_t *state, ftun_status_t status)
{
  ftun_stream_write_token_t write = state->write;
  ftun_error_t error = {status, 0u, 0};
  if (write.stream == NULL) return 1;
  if (status == FTUN_OK) {
    if (state->output_length > sizeof(state->output) - state->pending_length) {
      return 1;
    }
    memcpy(state->output + state->output_length, state->pending,
           state->pending_length);
    state->output_length += state->pending_length;
  }
  memset(&state->write, 0, sizeof(state->write));
  state->pending_length = 0u;
  return ftun_stream_write_complete(write, error) == FTUN_OK ? 0 : 1;
}

static int fixture_destroy(fixture_t *fixture, int stop_relay)
{
  ftun_budget_usage_t usage;
  if (stop_relay && fixture->relay != NULL &&
      ftun_relay_stop(fixture->relay) != FTUN_OK) return 1;
  if (fixture->relay != NULL &&
      ftun_relay_destroy(&fixture->relay) != FTUN_OK) return 1;
  if (ftun_stream_stop(fixture->left) != FTUN_OK ||
      ftun_stream_stop(fixture->right) != FTUN_OK) return 1;
  if (ftun_stream_destroy(&fixture->left) != FTUN_OK ||
      ftun_stream_destroy(&fixture->right) != FTUN_OK) return 1;
  if (ftun_operation_queue_destroy(&fixture->operations) != FTUN_OK) return 1;
  if (ftun_budget_get_usage(fixture->budget, &usage) != FTUN_OK ||
      usage.used_resources.memory_bytes != 0u) return 1;
  if (ftun_budget_destroy(&fixture->budget) != FTUN_OK) return 1;
  return 0;
}

static int process(fixture_t *fixture, uint32_t left_events,
                   uint32_t right_events, size_t expected_work)
{
  size_t work = SIZE_MAX;
  if (ftun_relay_process(fixture->relay, left_events, right_events,
                         &work) != FTUN_OK) return 1;
  return work == expected_work ? 0 : 1;
}

static int test_backpressure_and_half_close(void)
{
  fixture_t fixture;
  ftun_relay_usage_t usage;
  const uint8_t left_input[8] = {'a','b','c','d','e','f','g','h'};
  size_t index;
  CHECK(fixture_start(&fixture, 8u, 3u, 1u) == 0);
  memcpy(fixture.left_backend.input, left_input, sizeof(left_input));
  fixture.left_backend.input_length = sizeof(left_input);
  fixture.left_backend.read_chunk = 4u;
  fixture.left_backend.eof_when_empty = 1;
  fixture.right_backend.eof_when_empty = 1;
  fixture.right_backend.accept_limit = 2u;
  CHECK(ftun_relay_get_usage(fixture.relay, &usage) == FTUN_OK);
  CHECK(usage.left_interests == FTUN_EVENT_READ &&
        usage.right_interests == FTUN_EVENT_READ);

  CHECK(process(&fixture, FTUN_EVENT_READ, 0u, 1u) == 0);
  CHECK(process(&fixture, 0u, 0u, 1u) == 0);
  CHECK(fixture.right_backend.write.stream != NULL);
  CHECK(process(&fixture, FTUN_EVENT_READ, 0u, 1u) == 0);
  CHECK(ftun_relay_get_usage(fixture.relay, &usage) == FTUN_OK);
  CHECK(usage.left_to_right_buffered == 8u &&
        (usage.left_interests & FTUN_EVENT_READ) == 0u &&
        (usage.right_interests & FTUN_EVENT_WRITE) == 0u);

  for (index = 0u; index < 32u; index++) {
    if (fixture.right_backend.write.stream != NULL) {
      CHECK(complete_write(&fixture.right_backend, FTUN_OK) == 0);
      CHECK(dispatch_all(&fixture, 1u) == 0);
    }
    if (fixture.right_backend.output_length == 4u) {
      CHECK(ftun_relay_get_usage(fixture.relay, &usage) == FTUN_OK);
      CHECK(usage.left_to_right_buffered == 4u &&
            (usage.left_interests & FTUN_EVENT_READ) == 0u);
    }
    if (fixture.right_backend.output_length == 6u) {
      CHECK(ftun_relay_get_usage(fixture.relay, &usage) == FTUN_OK);
      CHECK(usage.left_to_right_buffered == 2u);
      CHECK(usage.left_eof || (usage.left_interests & FTUN_EVENT_READ) != 0u);
    }
    if (fixture.right_backend.output_length == sizeof(left_input)) break;
    CHECK(process(&fixture, 0u, 0u, 1u) == 0);
  }
  CHECK(fixture.right_backend.output_length == sizeof(left_input) &&
        memcmp(fixture.right_backend.output, left_input, sizeof(left_input)) == 0);
  CHECK(fixture.right_backend.shutdown_calls == 0);

  CHECK(ftun_relay_get_usage(fixture.relay, &usage) == FTUN_OK);
  if (!usage.left_eof) CHECK(process(&fixture, FTUN_EVENT_READ, 0u, 1u) == 0);
  fixture.right_backend.shutdown_status = FTUN_E_AGAIN;
  CHECK(process(&fixture, 0u, 0u, 1u) == 0);
  CHECK(fixture.right_backend.shutdown_calls == 1);
  CHECK(ftun_relay_get_usage(fixture.relay, &usage) == FTUN_OK &&
        (usage.right_interests & FTUN_EVENT_WRITE) != 0u &&
        !usage.right_write_shutdown);
  CHECK(process(&fixture, 0u, 0u, 0u) == 0);
  fixture.right_backend.shutdown_status = FTUN_OK;
  CHECK(process(&fixture, 0u, FTUN_EVENT_WRITE, 1u) == 0);
  CHECK(fixture.right_backend.shutdown_calls == 2);

  CHECK(process(&fixture, 0u, FTUN_EVENT_READ, 1u) == 0);
  CHECK(process(&fixture, 0u, 0u, 1u) == 0);
  CHECK(ftun_relay_get_usage(fixture.relay, &usage) == FTUN_OK);
  CHECK(usage.complete && usage.left_eof && usage.right_eof &&
        usage.left_write_shutdown && usage.right_write_shutdown &&
        usage.total_read_bytes == 8u && usage.total_written_bytes == 8u);
  CHECK(ftun_relay_destroy(&fixture.relay) == FTUN_OK && fixture.relay == NULL);
  CHECK(fixture_destroy(&fixture, 0) == 0);
  return 0;
}

static int test_read_hint_survives_backpressure(void)
{
  fixture_t fixture;
  size_t round;
  int reads;
  CHECK(fixture_start(&fixture, 8u, 3u, 1u) == 0);
  memcpy(fixture.left_backend.input, "abcdefghijkl", 12u);
  fixture.left_backend.input_length = 12u;
  fixture.left_backend.read_chunk = 4u;
  fixture.right_backend.accept_limit = 2u;
  /* 只发一次 READ，配额与异步写背压不能丢失尚未读空的状态。 */
  CHECK(process(&fixture, FTUN_EVENT_READ, 0u, 1u) == 0);
  for (round = 0u; round < 64u; round++) {
    size_t work;
    if (fixture.right_backend.write.stream != NULL) {
      CHECK(complete_write(&fixture.right_backend, FTUN_OK) == 0);
      CHECK(dispatch_all(&fixture, 1u) == 0);
    }
    CHECK(ftun_relay_process(fixture.relay, 0u, 0u, &work) == FTUN_OK);
    CHECK(work <= 1u);
  }
  CHECK(fixture.right_backend.output_length == 12u &&
        memcmp(fixture.right_backend.output, "abcdefghijkl", 12u) == 0);
  reads = fixture.left_backend.read_calls;
  /* 已经读到 AGAIN 后，无关 WRITE 或推进不能重新触发空读。 */
  for (round = 0u; round < 8u; round++) {
    CHECK(process(&fixture, 0u, FTUN_EVENT_WRITE, 0u) == 0);
  }
  CHECK(fixture.left_backend.read_calls == reads);
  fixture.left_backend.input[12] = 'm';
  fixture.left_backend.input_length = 13u;
  CHECK(process(&fixture, 0u, 0u, 0u) == 0);
  CHECK(fixture.left_backend.read_calls == reads);
  CHECK(process(&fixture, FTUN_EVENT_READ, 0u, 1u) == 0);
  CHECK(fixture.left_backend.read_calls == reads + 1);
  CHECK(fixture_destroy(&fixture, 1) == 0);
  return 0;
}

static int test_write_interest_and_cancel_retry(void)
{
  fixture_t fixture;
  ftun_relay_usage_t usage;
  CHECK(fixture_start(&fixture, 8u, 3u, 4u) == 0);
  fixture.left_backend.input[0] = 'x';
  fixture.left_backend.input_length = 1u;
  fixture.right_backend.write_status = FTUN_E_AGAIN;
  CHECK(process(&fixture, FTUN_EVENT_READ, 0u, 3u) == 0);
  CHECK(ftun_relay_get_usage(fixture.relay, &usage) == FTUN_OK &&
        usage.left_to_right_buffered == 1u &&
        (usage.right_interests & FTUN_EVENT_WRITE) != 0u);
  CHECK(process(&fixture, 0u, 0u, 0u) == 0);
  fixture.right_backend.write_status = FTUN_OK;
  CHECK(process(&fixture, 0u, FTUN_EVENT_WRITE, 1u) == 0);
  CHECK((fixture.right_backend.write.stream != NULL) &&
        ftun_relay_get_usage(fixture.relay, &usage) == FTUN_OK &&
        (usage.right_interests & FTUN_EVENT_WRITE) == 0u);
  fixture.right_backend.cancel_status = FTUN_E_IO;
  CHECK(ftun_relay_stop(fixture.relay) == FTUN_E_IO);
  CHECK(ftun_relay_destroy(&fixture.relay) == FTUN_E_AGAIN);
  fixture.right_backend.cancel_status = FTUN_OK;
  CHECK(ftun_relay_stop(fixture.relay) == FTUN_OK);
  CHECK(dispatch_all(&fixture, 1u) == 0);
  CHECK(fixture.right_backend.cancel_calls == 2);
  CHECK(fixture_destroy(&fixture, 0) == 0);
  return 0;
}

static int test_lazy_budget_and_error(void)
{
  fixture_t fixture;
  ftun_reservation_t blocker = (ftun_reservation_t){0};
  ftun_budget_usage_t usage;
  ftun_relay_usage_t relay_usage;
  size_t work = SIZE_MAX;
  CHECK(fixture_start(&fixture, 8u, 3u, 2u) == 0);
  fixture.left_backend.input[0] = 'z';
  fixture.left_backend.input_length = 1u;
  CHECK(ftun_budget_get_usage(fixture.budget, &usage) == FTUN_OK &&
        usage.normal_available_resources.memory_bytes > 0u);
  CHECK(ftun_budget_reserve(fixture.budget, usage.normal_available_resources.memory_bytes,
                            &blocker) == FTUN_OK);
  CHECK(ftun_relay_process(fixture.relay, FTUN_EVENT_READ, 0u,
                           &work) == FTUN_E_LIMIT && work == 0u);
  CHECK(ftun_relay_get_usage(fixture.relay, &relay_usage) == FTUN_OK &&
        !relay_usage.stopped && relay_usage.left_to_right_buffered == 0u);
  ftun_reservation_release(&blocker);
  CHECK(process(&fixture, FTUN_EVENT_READ, 0u, 2u) == 0);
  CHECK(fixture.right_backend.write.stream != NULL);
  CHECK(ftun_relay_process(fixture.relay, FTUN_EVENT_ERROR, 0u,
                           &work) == FTUN_E_IO);
  CHECK(dispatch_all(&fixture, 1u) == 0);
  CHECK(ftun_relay_get_usage(fixture.relay, &relay_usage) == FTUN_OK &&
        relay_usage.stopped && relay_usage.terminal_status == FTUN_E_IO);
  CHECK(fixture_destroy(&fixture, 0) == 0);
  return 0;
}

static int test_boundaries_and_default(void)
{
  fixture_t fixture;
  ftun_relay_options_t options = {8u, 3u, 1u};
  ftun_relay_t *relay = (ftun_relay_t *)(uintptr_t)1;
  ftun_relay_usage_t usage;
  size_t work = 99u;
  CHECK(fixture_start(&fixture, 8u, 3u, 2u) == 0);
  CHECK(ftun_relay_start(NULL, fixture.left, fixture.right, &relay) == FTUN_OK);
  CHECK(relay != NULL);
  CHECK(ftun_relay_stop(relay) == FTUN_OK);
  CHECK(ftun_relay_destroy(&relay) == FTUN_OK && relay == NULL);
  CHECK(ftun_relay_start_with_options(NULL, fixture.left, fixture.left,
                                      &options, &relay) == FTUN_E_INVALID &&
        relay == NULL);
  options.low_water_bytes = options.high_water_bytes;
  CHECK(ftun_relay_start_with_options(NULL, fixture.left, fixture.right,
                                      &options, &relay) == FTUN_E_INVALID);
  CHECK(ftun_relay_process(NULL, 0u, 0u, &work) == FTUN_E_INVALID && work == 0u);
  CHECK(ftun_relay_process(fixture.relay, FTUN_EVENT_TIMER, 0u,
                           &work) == FTUN_E_INVALID && work == 0u);
  CHECK(ftun_relay_stop(NULL) == FTUN_E_INVALID);
  CHECK(ftun_relay_get_usage(NULL, &usage) == FTUN_E_INVALID &&
        usage.total_read_bytes == 0u);
  CHECK(ftun_relay_destroy(NULL) == FTUN_E_INVALID);
  CHECK(ftun_relay_destroy(&relay) == FTUN_OK);
  CHECK(fixture_destroy(&fixture, 1) == 0);
  return 0;
}

static int test_related_budget_hierarchy(void)
{
  fixture_t fixture;
  stream_backend_state_t foreign_backend;
  ftun_budget_t *child = NULL;
  ftun_budget_t *foreign_budget = NULL;
  ftun_stream_t *foreign = NULL;
  ftun_relay_t *relay = NULL;
  ftun_relay_options_t options = {8u, 3u, 1u};
  int unused_calls = 0;
  memset(&fixture, 0, sizeof(fixture));
  memset(&foreign_backend, 0, sizeof(foreign_backend));
  fixture.left_backend.accept_limit = SIZE_MAX;
  fixture.right_backend.accept_limit = SIZE_MAX;
  foreign_backend.accept_limit = SIZE_MAX;
  CHECK(ftun_budget_create(NULL, 32768u, 0u, &fixture.budget) == FTUN_OK);
  CHECK(ftun_budget_create(fixture.budget, 32768u, 0u, &child) == FTUN_OK);
  CHECK(ftun_budget_create(NULL, 32768u, 0u, &foreign_budget) == FTUN_OK);
  CHECK(ftun_operation_queue_create(fixture.budget, 8u,
                                    &fixture.operations) == FTUN_OK);
  CHECK(create_stream_on_budget(&fixture, fixture.budget,
    &fixture.left_backend, &fixture.left, &unused_calls) == 0);
  CHECK(create_stream_on_budget(&fixture, child, &fixture.right_backend,
    &fixture.right, &unused_calls) == 0);
  CHECK(create_stream_on_budget(&fixture, foreign_budget, &foreign_backend,
    &foreign, &unused_calls) == 0);
  CHECK(ftun_relay_start_with_options(NULL, fixture.left, fixture.right,
                                      &options, &relay) == FTUN_OK);
  CHECK(ftun_relay_stop(relay) == FTUN_OK);
  CHECK(ftun_relay_destroy(&relay) == FTUN_OK);
  CHECK(ftun_relay_start_with_options(NULL, fixture.left, foreign,
                                      &options, &relay) == FTUN_E_REJECTED);
  CHECK(relay == NULL);
  CHECK(ftun_stream_stop(fixture.left) == FTUN_OK);
  CHECK(ftun_stream_stop(fixture.right) == FTUN_OK);
  CHECK(ftun_stream_stop(foreign) == FTUN_OK);
  CHECK(ftun_stream_destroy(&fixture.left) == FTUN_OK);
  CHECK(ftun_stream_destroy(&fixture.right) == FTUN_OK);
  CHECK(ftun_stream_destroy(&foreign) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&fixture.operations) == FTUN_OK);
  CHECK(ftun_budget_destroy(&child) == FTUN_OK);
  CHECK(ftun_budget_destroy(&fixture.budget) == FTUN_OK);
  CHECK(ftun_budget_destroy(&foreign_budget) == FTUN_OK);
  return 0;
}

static int test_pool_wait_resume_and_cancel(void)
{
  fixture_t fixture;
  const ftun_relay_options_t options = {256u, 128u, 1u};
  ftun_buffer_pool_t *pool = NULL;
  ftun_buffer_t *held = NULL;
  ftun_reservation_t blocker = (ftun_reservation_t){0};
  ftun_budget_usage_t budget_usage;
  ftun_buffer_pool_usage_t pool_usage;
  ftun_relay_usage_t relay_usage;
  size_t callbacks = SIZE_MAX;
  size_t progress_calls = 0u;
  size_t wakeups = 0u;
  size_t work = SIZE_MAX;

  CHECK(fixture_start(&fixture, 8u, 3u, 1u) == 0);
  CHECK(ftun_relay_stop(fixture.relay) == FTUN_OK);
  CHECK(ftun_relay_destroy(&fixture.relay) == FTUN_OK);
  CHECK(ftun_buffer_pool_create_waitable(fixture.budget, 512u, 2u, 2u, 1u,
                                         &pool) == FTUN_OK);
  CHECK(ftun_buffer_pool_set_wakeup(pool, pool_wakeup, &wakeups) == FTUN_OK);
  CHECK(ftun_relay_start_with_pool_options(NULL, fixture.left, fixture.right,
    pool, &options, relay_progress, &progress_calls,
    &fixture.relay) == FTUN_OK);
  CHECK(ftun_buffer_pool_acquire(pool, 256u, &held) == FTUN_OK);
  CHECK(ftun_budget_get_usage(fixture.budget, &budget_usage) == FTUN_OK);
  CHECK(ftun_budget_reserve(fixture.budget, budget_usage.normal_available_resources.memory_bytes,
                            &blocker) == FTUN_OK);
  fixture.left_backend.input[0] = 'x';
  fixture.left_backend.input_length = 1u;

  CHECK(ftun_relay_process(fixture.relay, FTUN_EVENT_READ, 0u,
                           &work) == FTUN_OK && work == 0u);
  CHECK(fixture.left_backend.read_calls == 0);
  CHECK(ftun_relay_get_usage(fixture.relay, &relay_usage) == FTUN_OK);
  CHECK(relay_usage.left_buffer_waiting &&
        (relay_usage.left_interests & FTUN_EVENT_READ) == 0u);
  CHECK(ftun_buffer_pool_get_usage(pool, &pool_usage) == FTUN_OK &&
        pool_usage.waiting == 1u);

  ftun_buffer_release(&held); CHECK(wakeups == 1u);
  CHECK(ftun_buffer_pool_dispatch(pool, SIZE_MAX, &callbacks) == FTUN_OK &&
        callbacks == 1u && progress_calls == 1u);
  CHECK(ftun_relay_get_usage(fixture.relay, &relay_usage) == FTUN_OK &&
        !relay_usage.left_buffer_waiting &&
        (relay_usage.left_interests & FTUN_EVENT_READ) != 0u);
  /* The saved readiness retries the read even without a second FD event. */
  CHECK(ftun_relay_process(fixture.relay, 0u, 0u, &work) == FTUN_OK &&
        work == 1u && fixture.left_backend.read_calls == 1);
  CHECK(ftun_relay_stop(fixture.relay) == FTUN_OK);
  CHECK(ftun_relay_destroy(&fixture.relay) == FTUN_OK);
  ftun_reservation_release(&blocker);

  CHECK(ftun_relay_start_with_pool_options(NULL, fixture.left, fixture.right,
    pool, &options, relay_progress, &progress_calls,
    &fixture.relay) == FTUN_OK);
  CHECK(ftun_buffer_pool_acquire(pool, 256u, &held) == FTUN_OK);
  CHECK(ftun_budget_get_usage(fixture.budget, &budget_usage) == FTUN_OK);
  CHECK(ftun_budget_reserve(fixture.budget, budget_usage.normal_available_resources.memory_bytes,
                            &blocker) == FTUN_OK);
  fixture.left_backend.input[1] = 'y';
  fixture.left_backend.input_length = 2u;
  CHECK(ftun_relay_process(fixture.relay, FTUN_EVENT_READ, 0u,
                           &work) == FTUN_OK && work == 0u);
  CHECK(ftun_relay_get_usage(fixture.relay, &relay_usage) == FTUN_OK &&
        relay_usage.left_buffer_waiting);
  CHECK(ftun_relay_stop(fixture.relay) == FTUN_OK);
  CHECK(ftun_relay_destroy(&fixture.relay) == FTUN_OK);
  CHECK(ftun_buffer_pool_get_usage(pool, &pool_usage) == FTUN_OK &&
        pool_usage.waiting == 0u && pool_usage.cancelled_waiters == 1u &&
        pool_usage.wake_callbacks == 1u);
  ftun_buffer_release(&held);
  CHECK(ftun_buffer_pool_dispatch(pool, SIZE_MAX, &callbacks) == FTUN_OK &&
        callbacks == 0u && progress_calls == 1u);
  ftun_reservation_release(&blocker);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_OK);
  CHECK(fixture_destroy(&fixture, 0) == 0);
  return 0;
}

static int test_mixed_pool_resume(void)
{
  fixture_t fixture;
  const ftun_relay_options_t options = {512u, 256u, 1u};
  ftun_buffer_pool_t *pool = NULL;
  ftun_buffer_t *held[2] = {NULL, NULL};
  ftun_reservation_t blocker = (ftun_reservation_t){0};
  ftun_budget_usage_t budget_usage;
  ftun_buffer_pool_usage_t pool_usage;
  ftun_relay_usage_t relay_usage;
  size_t callbacks, progress_calls = 0u, wakeups = 0u, work;
  CHECK(fixture_start(&fixture, 8u, 3u, 1u) == 0);
  CHECK(ftun_relay_stop(fixture.relay) == FTUN_OK);
  CHECK(ftun_relay_destroy(&fixture.relay) == FTUN_OK);
  CHECK(ftun_buffer_pool_create_waitable(fixture.budget, 1024u, 4u, 2u, 1u, &pool) == FTUN_OK);
  CHECK(ftun_buffer_pool_set_wakeup(pool, pool_wakeup, &wakeups) == FTUN_OK);
  CHECK(ftun_relay_start_with_pool_options(NULL, fixture.left, fixture.right,
    pool, &options, relay_progress, &progress_calls, &fixture.relay) == FTUN_OK);
  CHECK(ftun_buffer_pool_acquire(pool, 256u, &held[0]) == FTUN_OK);
  CHECK(ftun_buffer_pool_acquire(pool, 256u, &held[1]) == FTUN_OK);
  CHECK(ftun_budget_get_usage(fixture.budget, &budget_usage) == FTUN_OK);
  CHECK(ftun_budget_reserve(fixture.budget, budget_usage.normal_available_resources.memory_bytes, &blocker) == FTUN_OK);
  fixture.left_backend.input[0] = 'm';
  fixture.left_backend.input_length = 1u;
  CHECK(ftun_relay_process(fixture.relay, FTUN_EVENT_READ, 0u, &work) == FTUN_OK && work == 0u);
  CHECK(ftun_relay_get_usage(fixture.relay, &relay_usage) == FTUN_OK && relay_usage.left_buffer_waiting);
  ftun_buffer_release(&held[0]); CHECK(wakeups == 0u);
  ftun_buffer_release(&held[1]); CHECK(wakeups == 1u);
  CHECK(ftun_buffer_pool_dispatch(pool, 1u, &callbacks) == FTUN_OK && callbacks == 1u);
  CHECK(progress_calls == 1u);
  /* 两个小块触发恢复；不再提供新的 FD readiness。 */
  CHECK(ftun_relay_process(fixture.relay, 0u, 0u, &work) == FTUN_OK && work == 1u);
  CHECK(fixture.left_backend.read_calls == 1);
  CHECK(ftun_relay_get_usage(fixture.relay, &relay_usage) == FTUN_OK && !relay_usage.left_buffer_waiting);
  CHECK(ftun_buffer_pool_get_usage(pool, &pool_usage) == FTUN_OK &&
        pool_usage.waiting == 0u && pool_usage.pressure_trimmed_buffers == 2u);
  CHECK(ftun_relay_stop(fixture.relay) == FTUN_OK);
  CHECK(ftun_relay_destroy(&fixture.relay) == FTUN_OK);
  CHECK(ftun_buffer_pool_dispatch(pool, 1u, &callbacks) == FTUN_OK && callbacks == 0u);
  ftun_reservation_release(&blocker);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_OK);
  CHECK(fixture_destroy(&fixture, 0) == 0);
  return 0;
}

/* 水位、工作上限与排空 half-close。 */
static void dummy_completed(ftun_operation_t *operation, ftun_error_t error, void *user)
{
  (void)operation;
  (void)error;
  (void)user;
}

/* 全局 Operation 队列满：写入不再每轮空转重试，而是登记等待，回收出额度后恢复。 */
static int test_operation_queue_full_waits(void)
{
  fixture_t fixture;
  ftun_operation_t *dummy[8];
  ftun_operation_token_t token[8];
  ftun_error_t done = {FTUN_OK, 0u, 0};
  size_t index;
  size_t round;
  CHECK(fixture_start(&fixture, 8u, 3u, 8u) == 0);
  for (index = 0u; index < 8u; index++) {
    CHECK(ftun_operation_accept(fixture.operations, dummy_completed, NULL,
                                &dummy[index], &token[index]) == FTUN_OK);
  }
  memcpy(fixture.left_backend.input, "abc", 3u);
  fixture.left_backend.input_length = 3u;
  /* 读取（含读空的那一次，共 2 次工作），随后的写入被 Operation 队列拒绝并登记等待。 */
  CHECK(process(&fixture, FTUN_EVENT_READ, 0u, 2u) == 0);
  CHECK(fixture.right_backend.write_calls == 0);
  for (round = 0u; round < 16u; round++) {
    CHECK(process(&fixture, 0u, FTUN_EVENT_WRITE, 0u) == 0);
  }
  CHECK(fixture.right_backend.write_calls == 0);
  /* 回收一个额度：等待者收到提示，下一轮写入成功。 */
  CHECK(ftun_operation_complete(token[0], done) == FTUN_OK);
  CHECK(dispatch_all(&fixture, 1u) == 0);
  CHECK(process(&fixture, 0u, 0u, 1u) == 0);
  CHECK(fixture.right_backend.write_calls == 1);
  CHECK(complete_write(&fixture.right_backend, FTUN_OK) == 0);
  CHECK(dispatch_all(&fixture, 1u) == 0);
  CHECK(fixture.right_backend.output_length == 3u &&
        memcmp(fixture.right_backend.output, "abc", 3u) == 0);
  for (index = 1u; index < 8u; index++) {
    CHECK(ftun_operation_cancel(dummy[index]) == FTUN_OK);
  }
  CHECK(dispatch_all(&fixture, 7u) == 0);
  CHECK(fixture_destroy(&fixture, 1) == 0);
  /* 等待期间停止 relay：必须撤销等待，队列才能销毁。 */
  CHECK(fixture_start(&fixture, 8u, 3u, 8u) == 0);
  for (index = 0u; index < 8u; index++) {
    CHECK(ftun_operation_accept(fixture.operations, dummy_completed, NULL,
                                &dummy[index], &token[index]) == FTUN_OK);
  }
  memcpy(fixture.left_backend.input, "xyz", 3u);
  fixture.left_backend.input_length = 3u;
  CHECK(process(&fixture, FTUN_EVENT_READ, 0u, 2u) == 0);
  CHECK(ftun_relay_stop(fixture.relay) == FTUN_OK);
  for (index = 0u; index < 8u; index++) {
    CHECK(ftun_operation_cancel(dummy[index]) == FTUN_OK);
  }
  CHECK(dispatch_all(&fixture, 8u) == 0);
  CHECK(fixture_destroy(&fixture, 0) == 0);
  return 0;
}

int main(void)
{
  CHECK(test_backpressure_and_half_close() == 0);
  CHECK(test_read_hint_survives_backpressure() == 0);
  CHECK(test_write_interest_and_cancel_retry() == 0);
  CHECK(test_lazy_budget_and_error() == 0);
  CHECK(test_boundaries_and_default() == 0);
  CHECK(test_related_budget_hierarchy() == 0);
  CHECK(test_pool_wait_resume_and_cancel() == 0);
  CHECK(test_mixed_pool_resume() == 0);
  CHECK(test_operation_queue_full_waits() == 0);
  return 0;
}
