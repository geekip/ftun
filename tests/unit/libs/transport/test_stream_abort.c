#include "libs/transport/stream.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "stream abort contract failed at %d: %s\n", __LINE__, #x); \
  return 1; } } while (0)

typedef struct {
  ftun_stream_t *stream;
  ftun_stream_write_token_t tokens[3];
  ftun_status_t failure;
  unsigned int starts;
  unsigned int cancels;
  unsigned int destroyed;
  unsigned int completed;
  unsigned int cancelled;
  unsigned int successful;
  unsigned int guarded;
  bool abort_in_start;
  bool abort_in_completion;
} channel_state_t;

static ftun_status_t write_start(void *user, ftun_stream_write_token_t write,
  const ftun_buffer_slice_t *slice, size_t *accepted)
{
  channel_state_t *state = (channel_state_t *)user;
  if (write.slot >= 3u) return FTUN_E_STATE_CORRUPT;
  state->tokens[write.slot] = write;
  state->starts++;
  if (state->abort_in_start) {
    ftun_stream_t *borrowed = state->stream;
    state->guarded += ftun_stream_abort(state->stream) == FTUN_E_AGAIN;
    state->guarded += ftun_stream_destroy(&borrowed) == FTUN_E_AGAIN &&
                      borrowed == state->stream;
  }
  *accepted = slice->length;
  return FTUN_OK;
}

static ftun_status_t write_cancel(void *user, ftun_stream_write_token_t write)
{
  channel_state_t *state = (channel_state_t *)user;
  ftun_stream_t *borrowed = state->stream;
  ftun_error_t success = {FTUN_OK, 0u, 0};
  ftun_status_t failure = state->failure;
  if (write.slot >= 3u ||
      state->tokens[write.slot].generation != write.generation) {
    return FTUN_E_STATE_CORRUPT;
  }
  state->cancels++;
  state->guarded += ftun_stream_abort(state->stream) == FTUN_E_AGAIN;
  state->guarded += ftun_stream_destroy(&borrowed) == FTUN_E_AGAIN &&
                    borrowed == state->stream;
  state->guarded += ftun_stream_write_complete(write, success) == FTUN_E_AGAIN;
  state->failure = FTUN_OK;
  if (failure != FTUN_OK) return failure;
  memset(&state->tokens[write.slot], 0, sizeof(state->tokens[write.slot]));
  return FTUN_OK;
}

static void destroy(void *user)
{
  channel_state_t *state = (channel_state_t *)user;
  state->destroyed++;
}

static void completed(ftun_operation_t *operation, ftun_error_t error, void *user)
{
  channel_state_t *state = (channel_state_t *)user;
  (void)operation;
  state->completed++;
  state->cancelled += error.status == FTUN_E_CANCELLED;
  state->successful += error.status == FTUN_OK;
  if (state->abort_in_completion) {
    state->guarded += ftun_stream_abort(state->stream) == FTUN_E_AGAIN;
  }
}

static int scenario(ftun_status_t first_failure, bool complete_failed,
  bool abort_in_start, bool abort_in_completion)
{
  ftun_budget_t *budget = NULL;
  ftun_budget_usage_t usage;
  ftun_operation_queue_t *operations = NULL;
  ftun_operation_queue_usage_t queue_usage;
  ftun_buffer_pool_t *pool = NULL;
  ftun_buffer_t *buffer = NULL;
  ftun_buffer_slice_t slice = {0};
  ftun_stream_options_t options = {0};
  ftun_stream_backend_t backend = {0};
  ftun_stream_usage_t stream_usage;
  ftun_stream_t *retained = NULL;
  ftun_operation_t *operation = NULL;
  channel_state_t state = {0}, other = {0};
  ftun_stream_write_token_t late[3];
  ftun_stream_write_token_t survivor = {0};
  ftun_error_t success = {FTUN_OK, 0u, 0};
  ftun_bytes_t bytes;
  size_t accepted, dispatched, capacity, index, pending;
  uint8_t *data = NULL;
  unsigned int expected_cancels;

  CHECK(ftun_budget_create(NULL, 65536u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 8u, &operations) == FTUN_OK);
  CHECK(ftun_buffer_pool_create(budget, 0u, 0u, &pool) == FTUN_OK);
  CHECK(ftun_buffer_pool_acquire(pool, 8u, &buffer) == FTUN_OK);
  CHECK(ftun_buffer_data(buffer, &data, &capacity) == FTUN_OK && capacity >= 8u);
  memcpy(data, "abcdefgh", 8u);
  CHECK(ftun_buffer_slice(buffer, 0u, 8u, &slice) == FTUN_OK);
  ftun_buffer_release(&buffer);
  options.budget = budget;
  options.operations = operations;
  options.max_pending_writes = 3u;
  options.max_pending_bytes = 24u;
  options.completion = completed;
  options.completion_user = &state;
  backend.write_start = write_start;
  backend.write_cancel = write_cancel;
  backend.destroy = destroy;
  backend.context = &state;
  CHECK(ftun_stream_create(&options, &backend, &state.stream) == FTUN_OK);
  options.completion_user = &other;
  backend.context = &other;
  CHECK(ftun_stream_create(&options, &backend, &other.stream) == FTUN_OK);
  state.abort_in_start = abort_in_start;
  state.abort_in_completion = abort_in_completion;
  pending = abort_in_start ? 1u : 3u;
  for (index = 0u; index < pending; index++) {
    CHECK(ftun_stream_write_ref(state.stream, &slice, &accepted, &operation) ==
          FTUN_OK && accepted == 8u && operation != NULL);
  }
  CHECK(ftun_stream_retain(state.stream) == FTUN_OK);
  retained = state.stream;
  CHECK(ftun_stream_write_ref(other.stream, &slice, &accepted, &operation) ==
        FTUN_OK && accepted == 8u && operation != NULL);
  ftun_buffer_slice_release(&slice);
  memcpy(late, state.tokens, sizeof(late));
  state.failure = first_failure;
  CHECK(ftun_stream_abort(state.stream) == first_failure);
  CHECK(state.cancels == pending && state.completed == 0u &&
        other.cancels == 0u && other.completed == 0u);
  CHECK(ftun_stream_get_usage(state.stream, &stream_usage) == FTUN_OK &&
        !stream_usage.accepting && stream_usage.pending_writes == pending);
  CHECK(ftun_stream_destroy(&state.stream) == FTUN_E_AGAIN && state.stream != NULL);
  CHECK(ftun_operation_queue_get_usage(operations, &queue_usage) == FTUN_OK &&
        queue_usage.accepting && queue_usage.inflight == pending + 1u);
  expected_cancels = (unsigned int)pending;
  if (first_failure != FTUN_OK) {
    for (index = 0u; index < 3u; index++) {
      if (state.tokens[index].stream != NULL) survivor = state.tokens[index];
    }
    CHECK(survivor.stream == state.stream);
    CHECK(ftun_stream_write_data(survivor, &bytes) == FTUN_OK &&
          bytes.length == 8u && memcmp(bytes.data, "abcdefgh", 8u) == 0);
    if (complete_failed) {
      CHECK(ftun_stream_write_complete(survivor, success) == FTUN_OK);
      memset(&state.tokens[survivor.slot], 0, sizeof(state.tokens[survivor.slot]));
    } else {
      expected_cancels++;
    }
  }
  /* 尚未派发的成功结果也由撤销改为取消；已经回调的结果不在此窗口。 */
  CHECK(ftun_stream_abort(state.stream) == FTUN_OK);
  CHECK(ftun_stream_abort(state.stream) == FTUN_OK);
  CHECK(state.cancels == expected_cancels && state.completed == 0u);
  for (index = 0u; index < 3u; index++) {
    if (late[index].stream == NULL) continue;
    CHECK(ftun_stream_write_data(late[index], &bytes) == FTUN_E_STALE);
    CHECK(ftun_stream_write_complete(late[index], success) == FTUN_E_STALE);
  }
  CHECK(ftun_operation_dispatch(operations, 8u, &dispatched) == FTUN_OK &&
        dispatched == pending && state.completed == pending &&
        state.cancelled == pending && state.successful == 0u);
  CHECK(state.guarded == expected_cancels * 3u + 2u * (unsigned int)abort_in_start +
        (abort_in_completion ? pending : 0u));
  CHECK(ftun_stream_destroy(&state.stream) == FTUN_E_AGAIN && state.stream != NULL);
  ftun_stream_release(&retained); CHECK(retained == NULL);
  CHECK(ftun_stream_destroy(&state.stream) == FTUN_OK && state.destroyed == 1u);
  /* 共用队列的另一流保持运行，未被单流撤销取消或停止。 */
  CHECK(ftun_stream_get_usage(other.stream, &stream_usage) == FTUN_OK &&
        stream_usage.accepting && stream_usage.pending_writes == 1u);
  for (index = 0u; index < 3u; index++) {
    if (other.tokens[index].stream == NULL) continue;
    CHECK(ftun_stream_write_complete(other.tokens[index], success) == FTUN_OK);
  }
  CHECK(ftun_operation_dispatch(operations, 8u, &dispatched) == FTUN_OK &&
        dispatched == 1u && other.completed == 1u && other.successful == 1u &&
        other.cancelled == 0u);
  CHECK(ftun_stream_abort(other.stream) == FTUN_OK);
  CHECK(ftun_stream_destroy(&other.stream) == FTUN_OK && other.destroyed == 1u);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(void)
{
  CHECK(ftun_stream_abort(NULL) == FTUN_E_INVALID);
  CHECK(scenario(FTUN_OK, false, false, false) == 0);
  CHECK(scenario(FTUN_E_AGAIN, false, false, false) == 0);
  CHECK(scenario(FTUN_E_IO, false, false, false) == 0);
  CHECK(scenario(FTUN_E_IO, true, false, false) == 0);
  CHECK(scenario(FTUN_OK, false, true, false) == 0);
  CHECK(scenario(FTUN_OK, false, false, true) == 0);
  puts("Stream abort contract passed: six scenarios");
  return 0;
}
