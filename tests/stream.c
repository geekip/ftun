#include "transport/stream.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "stream contract failed at line %d: %s\n", __LINE__, #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  ftun_stream_write_t *write;
  ftun_status_t start_status;
  ftun_status_t cancel_status;
  size_t accept_count;
  int start_calls;
  int cancel_calls;
  int destroy_calls;
  int complete_during_start_was_stale;
  uint8_t first_byte;
  size_t offered;
} backend_state_t;

typedef struct {
  ftun_stream_t *stream;
  int calls;
  int pending_was_zero;
  int in_completion;
  ftun_error_t error;
} completion_state_t;

typedef struct {
  ftun_budget_t *budget;
  ftun_operation_queue_t *operations;
  ftun_buffer_pool_t *pool;
  ftun_stream_t *stream;
  backend_state_t backend;
  completion_state_t completion;
} fixture_t;

static ftun_status_t backend_write_start(void *user,
                                         ftun_stream_write_t *write,
                                         const ftun_buffer_slice_t *slice,
                                         size_t *accepted)
{
  backend_state_t *state = (backend_state_t *)user;
  ftun_bytes_t bytes;
  ftun_error_t success = {FTUN_OK, 1u, 0};
  state->start_calls++;
  if (ftun_buffer_slice_data(slice, &bytes) != FTUN_OK || bytes.length == 0u) {
    return FTUN_E_STATE_CORRUPT;
  }
  state->first_byte = bytes.data[0];
  state->offered = bytes.length;
  if (ftun_stream_write_complete(write, success) == FTUN_E_STALE) {
    state->complete_during_start_was_stale++;
  }
  if (state->start_status != FTUN_OK) return state->start_status;
  *accepted = state->accept_count == SIZE_MAX ? bytes.length : state->accept_count;
  state->write = write;
  return FTUN_OK;
}

static ftun_status_t backend_write_cancel(void *user,
                                          ftun_stream_write_t *write)
{
  backend_state_t *state = (backend_state_t *)user;
  state->cancel_calls++;
  if (state->write != write) return FTUN_E_STATE_CORRUPT;
  if (state->cancel_status != FTUN_OK) return state->cancel_status;
  state->write = NULL;
  return FTUN_OK;
}

static void backend_destroy(void *user)
{
  backend_state_t *state = (backend_state_t *)user;
  state->destroy_calls++;
}

static void write_completed(ftun_operation_t *operation,
                            ftun_error_t error, void *user)
{
  completion_state_t *state = (completion_state_t *)user;
  ftun_stream_usage_t usage;
  (void)operation;
  state->calls++;
  state->error = error;
  if (ftun_stream_get_usage(state->stream, &usage) == FTUN_OK) {
    state->pending_was_zero += usage.pending_writes == 0u &&
                               usage.pending_bytes == 0u;
    state->in_completion += usage.in_completion;
  }
}

static int fixture_start(fixture_t *fixture, size_t max_writes,
                         size_t max_bytes)
{
  ftun_stream_options_t options;
  ftun_stream_backend_t backend;
  memset(fixture, 0, sizeof(*fixture));
  memset(&options, 0, sizeof(options));
  memset(&backend, 0, sizeof(backend));
  fixture->backend.accept_count = SIZE_MAX;
  if (ftun_budget_create(NULL, 16384u, 0u, &fixture->budget) != FTUN_OK) return 1;
  if (ftun_operation_queue_create(fixture->budget, 4u,
                                  &fixture->operations) != FTUN_OK) return 1;
  if (ftun_buffer_pool_create(fixture->budget, 0u, 0u,
                              &fixture->pool) != FTUN_OK) return 1;
  options.budget = fixture->budget;
  options.operations = fixture->operations;
  options.max_pending_writes = max_writes;
  options.max_pending_bytes = max_bytes;
  options.completion = write_completed;
  options.completion_user = &fixture->completion;
  backend.write_start = backend_write_start;
  backend.write_cancel = backend_write_cancel;
  backend.destroy = backend_destroy;
  backend.context = &fixture->backend;
  if (ftun_stream_create(&options, &backend, &fixture->stream) != FTUN_OK) return 1;
  fixture->completion.stream = fixture->stream;
  return 0;
}

static int fixture_stop(fixture_t *fixture)
{
  ftun_budget_usage_t usage;
  if (ftun_stream_stop(fixture->stream) != FTUN_OK) return 1;
  if (ftun_stream_destroy(&fixture->stream) != FTUN_OK) return 1;
  if (fixture->backend.destroy_calls != 1) return 1;
  if (ftun_buffer_pool_destroy(&fixture->pool) != FTUN_OK) return 1;
  if (ftun_operation_queue_destroy(&fixture->operations) != FTUN_OK) return 1;
  if (ftun_budget_get_usage(fixture->budget, &usage) != FTUN_OK ||
      usage.used != 0u) return 1;
  if (ftun_budget_destroy(&fixture->budget) != FTUN_OK) return 1;
  return 0;
}

static int make_slice(fixture_t *fixture, uint8_t seed, size_t offset,
                      size_t length, ftun_buffer_slice_t *out)
{
  ftun_buffer_t *buffer = NULL;
  uint8_t *data = NULL;
  size_t capacity = 0u;
  size_t index;
  if (ftun_buffer_pool_acquire(fixture->pool, offset + length, &buffer) != FTUN_OK) {
    return 1;
  }
  if (ftun_buffer_data(buffer, &data, &capacity) != FTUN_OK ||
      capacity < offset + length) return 1;
  for (index = 0u; index < length; index++) data[offset + index] = seed + (uint8_t)index;
  if (ftun_buffer_slice(buffer, offset, length, out) != FTUN_OK) return 1;
  if (ftun_buffer_release(&buffer) != FTUN_OK) return 1;
  return 0;
}

static int dispatch_one(fixture_t *fixture)
{
  size_t dispatched = 0u;
  if (ftun_operation_dispatch(fixture->operations, 1u,
                              &dispatched) != FTUN_OK) return 1;
  return dispatched == 1u ? 0 : 1;
}

static int complete_backend(fixture_t *fixture, ftun_error_t error)
{
  ftun_stream_write_t *write = fixture->backend.write;
  if (write == NULL) return 1;
  if (ftun_stream_write_complete(write, error) != FTUN_OK) return 1;
  fixture->backend.write = NULL;
  return 0;
}

static int test_partial_and_lifetime(void)
{
  fixture_t fixture;
  ftun_buffer_slice_t slice = {0};
  ftun_operation_t *operation = NULL;
  ftun_stream_write_t *write;
  ftun_stream_usage_t usage;
  ftun_buffer_pool_usage_t pool_usage;
  ftun_bytes_t bytes;
  ftun_error_t success = {FTUN_OK, 9u, 0};
  size_t accepted = 99u;
  CHECK(fixture_start(&fixture, 2u, 5u) == 0);
  CHECK(make_slice(&fixture, 10u, 2u, 8u, &slice) == 0);
  fixture.backend.accept_count = 3u;
  CHECK(ftun_stream_write_ref(fixture.stream, &slice, &accepted,
                              &operation) == FTUN_OK);
  CHECK(operation != NULL && accepted == 3u);
  CHECK(fixture.backend.start_calls == 1 && fixture.backend.offered == 5u &&
        fixture.backend.first_byte == 10u &&
        fixture.backend.complete_during_start_was_stale == 1);
  CHECK(ftun_buffer_slice_release(&slice) == FTUN_OK);
  CHECK(ftun_stream_write_data(fixture.backend.write, &bytes) == FTUN_OK);
  CHECK(bytes.length == 3u && bytes.data[0] == 10u && bytes.data[2] == 12u);
  CHECK(ftun_stream_get_usage(fixture.stream, &usage) == FTUN_OK);
  CHECK(usage.pending_writes == 1u && usage.pending_bytes == 3u &&
        usage.accepting && !usage.in_completion);
  CHECK(ftun_buffer_pool_get_usage(fixture.pool, &pool_usage) == FTUN_OK &&
        pool_usage.active_buffers == 1u);
  write = fixture.backend.write;
  CHECK(complete_backend(&fixture, success) == 0);
  CHECK(fixture.completion.calls == 0);
  CHECK(ftun_stream_write_data(write, &bytes) == FTUN_E_STALE);
  CHECK(ftun_stream_write_complete(write, success) == FTUN_E_STALE);
  CHECK(ftun_buffer_pool_get_usage(fixture.pool, &pool_usage) == FTUN_OK &&
        pool_usage.active_buffers == 1u);
  CHECK(dispatch_one(&fixture) == 0);
  CHECK(fixture.completion.calls == 1 &&
        fixture.completion.error.status == FTUN_OK &&
        fixture.completion.pending_was_zero == 1 &&
        fixture.completion.in_completion == 1);
  CHECK(ftun_buffer_pool_get_usage(fixture.pool, &pool_usage) == FTUN_OK &&
        pool_usage.active_buffers == 0u);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_rejection_and_limits(void)
{
  fixture_t fixture;
  ftun_buffer_slice_t first = {0};
  ftun_buffer_slice_t second = {0};
  ftun_operation_t *operation = (ftun_operation_t *)(uintptr_t)1;
  ftun_reservation_t *blocker = NULL;
  ftun_budget_usage_t before;
  ftun_budget_usage_t after;
  ftun_error_t success = {FTUN_OK, 0u, 0};
  size_t accepted = 99u;
  CHECK(fixture_start(&fixture, 1u, 16u) == 0);
  CHECK(make_slice(&fixture, 20u, 0u, 4u, &first) == 0);
  CHECK(ftun_budget_get_usage(fixture.budget, &before) == FTUN_OK);
  fixture.backend.start_status = FTUN_E_AGAIN;
  CHECK(ftun_stream_write_ref(fixture.stream, &first, &accepted,
                              &operation) == FTUN_E_AGAIN);
  CHECK(accepted == 0u && operation == NULL && fixture.completion.calls == 0);
  CHECK(ftun_budget_get_usage(fixture.budget, &after) == FTUN_OK &&
        after.used == before.used);

  CHECK(after.normal_available > 0u);
  CHECK(ftun_budget_reserve(fixture.budget, after.normal_available,
                            &blocker) == FTUN_OK);
  operation = (ftun_operation_t *)(uintptr_t)1;
  accepted = 99u;
  CHECK(ftun_stream_write_ref(fixture.stream, &first, &accepted,
                              &operation) == FTUN_E_AGAIN);
  CHECK(accepted == 0u && operation == NULL && fixture.backend.start_calls == 2);
  CHECK(ftun_reservation_release(&blocker) == FTUN_OK);

  fixture.backend.start_status = FTUN_OK;
  fixture.backend.accept_count = 0u;
  operation = (ftun_operation_t *)(uintptr_t)1;
  accepted = 99u;
  CHECK(ftun_stream_write_ref(fixture.stream, &first, &accepted,
                              &operation) == FTUN_E_STATE_CORRUPT);
  CHECK(accepted == 0u && operation == NULL && fixture.backend.write == NULL &&
        fixture.backend.cancel_calls == 1 && fixture.completion.calls == 0);
  CHECK(ftun_buffer_slice_release(&first) == FTUN_OK);

  fixture.backend.accept_count = SIZE_MAX;
  CHECK(make_slice(&fixture, 30u, 0u, 4u, &first) == 0);
  CHECK(make_slice(&fixture, 40u, 0u, 4u, &second) == 0);
  CHECK(ftun_stream_write_ref(fixture.stream, &first, &accepted,
                              &operation) == FTUN_OK);
  CHECK(accepted == 4u && operation != NULL);
  operation = (ftun_operation_t *)(uintptr_t)1;
  accepted = 99u;
  CHECK(ftun_stream_write_ref(fixture.stream, &second, &accepted,
                              &operation) == FTUN_E_LIMIT);
  CHECK(accepted == 0u && operation == NULL && fixture.backend.start_calls == 4);
  CHECK(ftun_buffer_slice_release(&first) == FTUN_OK);
  CHECK(ftun_buffer_slice_release(&second) == FTUN_OK);
  CHECK(complete_backend(&fixture, success) == 0);
  CHECK(dispatch_one(&fixture) == 0);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_cancel_and_stop(void)
{
  fixture_t fixture;
  ftun_buffer_slice_t slice = {0};
  ftun_operation_t *operation = NULL;
  ftun_stream_write_t *write;
  ftun_bytes_t bytes;
  ftun_error_t success = {FTUN_OK, 0u, 0};
  size_t accepted = 0u;
  CHECK(fixture_start(&fixture, 2u, 16u) == 0);
  CHECK(make_slice(&fixture, 50u, 0u, 4u, &slice) == 0);
  CHECK(ftun_stream_write_ref(fixture.stream, &slice, &accepted,
                              &operation) == FTUN_OK);
  CHECK(ftun_buffer_slice_release(&slice) == FTUN_OK);
  fixture.backend.cancel_status = FTUN_E_IO;
  CHECK(ftun_operation_cancel(operation) == FTUN_E_IO);
  CHECK(fixture.backend.cancel_calls == 1 && fixture.backend.write != NULL);
  CHECK(ftun_stream_write_data(fixture.backend.write, &bytes) == FTUN_OK &&
        bytes.length == 4u);
  success.status = FTUN_E_AGAIN;
  CHECK(ftun_stream_write_complete(fixture.backend.write, success) == FTUN_E_INVALID);
  success.status = FTUN_OK;
  write = fixture.backend.write;
  fixture.backend.cancel_status = FTUN_OK;
  CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  CHECK(fixture.backend.cancel_calls == 2 && fixture.backend.write == NULL);
  CHECK(ftun_stream_write_data(write, &bytes) == FTUN_E_STALE);
  CHECK(ftun_stream_write_complete(write, success) == FTUN_E_STALE);
  CHECK(dispatch_one(&fixture) == 0);
  CHECK(fixture.completion.error.status == FTUN_E_CANCELLED);

  CHECK(make_slice(&fixture, 55u, 0u, 4u, &slice) == 0);
  CHECK(ftun_stream_write_ref(fixture.stream, &slice, &accepted,
                              &operation) == FTUN_OK);
  CHECK(ftun_buffer_slice_release(&slice) == FTUN_OK);
  write = fixture.backend.write;
  CHECK(complete_backend(&fixture, success) == 0);
  CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  CHECK(fixture.backend.cancel_calls == 2);
  CHECK(ftun_stream_write_complete(write, success) == FTUN_E_STALE);
  CHECK(dispatch_one(&fixture) == 0);
  CHECK(fixture.completion.calls == 2 &&
        fixture.completion.error.status == FTUN_E_CANCELLED);

  memset(&fixture.completion.error, 0, sizeof(fixture.completion.error));
  CHECK(make_slice(&fixture, 60u, 0u, 4u, &slice) == 0);
  CHECK(ftun_stream_write_ref(fixture.stream, &slice, &accepted,
                              &operation) == FTUN_OK);
  CHECK(ftun_buffer_slice_release(&slice) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(fixture.operations) == FTUN_OK);
  CHECK(fixture.backend.cancel_calls == 3 && fixture.backend.write == NULL);
  CHECK(dispatch_one(&fixture) == 0);
  CHECK(fixture.completion.calls == 3 &&
        fixture.completion.error.status == FTUN_E_CANCELLED);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_failure_and_boundaries(void)
{
  fixture_t fixture;
  ftun_buffer_slice_t slice = {0};
  ftun_operation_t *operation = NULL;
  ftun_stream_usage_t usage;
  ftun_error_t failure = {FTUN_E_IO, 7u, 12};
  size_t accepted = 0u;
  CHECK(fixture_start(&fixture, 2u, 16u) == 0);
  CHECK(make_slice(&fixture, 70u, 0u, 4u, &slice) == 0);
  CHECK(ftun_stream_write_ref(fixture.stream, &slice, &accepted,
                              &operation) == FTUN_OK);
  CHECK(ftun_buffer_slice_release(&slice) == FTUN_OK);
  CHECK(ftun_stream_destroy(&fixture.stream) == FTUN_E_AGAIN &&
        fixture.stream != NULL);
  CHECK(complete_backend(&fixture, failure) == 0);
  CHECK(dispatch_one(&fixture) == 0);
  CHECK(fixture.completion.error.status == FTUN_E_IO &&
        fixture.completion.error.stage == 7u &&
        fixture.completion.error.native_code == 12);
  CHECK(ftun_stream_stop(fixture.stream) == FTUN_OK);
  CHECK(ftun_stream_stop(fixture.stream) == FTUN_OK);
  operation = (ftun_operation_t *)(uintptr_t)1;
  accepted = 99u;
  CHECK(make_slice(&fixture, 80u, 0u, 1u, &slice) == 0);
  CHECK(ftun_stream_write_ref(fixture.stream, &slice, &accepted,
                              &operation) == FTUN_E_CANCELLED);
  CHECK(accepted == 0u && operation == NULL);
  CHECK(ftun_buffer_slice_release(&slice) == FTUN_OK);
  CHECK(ftun_stream_get_usage(fixture.stream, &usage) == FTUN_OK &&
        !usage.accepting && usage.pending_writes == 0u);
  CHECK(fixture_stop(&fixture) == 0);

  CHECK(ftun_stream_create(NULL, NULL, &fixture.stream) == FTUN_E_INVALID &&
        fixture.stream == NULL);
  CHECK(ftun_stream_write_ref(NULL, NULL, &accepted, &operation) == FTUN_E_INVALID);
  CHECK(accepted == 0u && operation == NULL);
  CHECK(ftun_stream_write_data(NULL, NULL) == FTUN_E_INVALID);
  CHECK(ftun_stream_write_complete(NULL, failure) == FTUN_E_INVALID);
  CHECK(ftun_stream_stop(NULL) == FTUN_E_INVALID);
  CHECK(ftun_stream_get_usage(NULL, &usage) == FTUN_E_INVALID &&
        usage.pending_writes == 0u);
  CHECK(ftun_stream_destroy(NULL) == FTUN_E_INVALID);
  CHECK(ftun_stream_destroy(&fixture.stream) == FTUN_OK);
  return 0;
}

/* TASK-TRANSPORT-002 / TEST-TRANSPORT-002：引用只在接纳后保留到完成事件。 */
int main(void)
{
  CHECK(test_partial_and_lifetime() == 0);
  CHECK(test_rejection_and_limits() == 0);
  CHECK(test_cancel_and_stop() == 0);
  CHECK(test_failure_and_boundaries() == 0);
  return 0;
}
