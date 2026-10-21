#include "transport/carrier.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "carrier contract failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

#define BACKEND_PENDING 32u
#define TEST_FLOWS 6u

typedef struct {
  ftun_carrier_send_token_t token;
  ftun_carrier_send_kind_t kind;
  uint32_t owner_id;
  uint64_t flow_id;
  size_t offered;
  size_t accepted;
  uint8_t first;
} backend_send_t;

typedef struct {
  backend_send_t pending[BACKEND_PENDING];
  backend_send_t starts[64];
  size_t pending_count;
  size_t start_count;
  size_t stream_accept_limit;
  size_t cancel_failures;
  size_t start_again;
  size_t cancel_calls;
  size_t destroy_calls;
} backend_state_t;

typedef struct {
  size_t calls;
  size_t ok;
  size_t cancelled;
  size_t io;
  size_t other;
} completion_state_t;

typedef struct {
  ftun_budget_t *budget;
  ftun_buffer_pool_t *pool;
  ftun_operation_queue_t *operations[2];
  ftun_carrier_t *carrier;
  ftun_carrier_owner_token_t owners[2];
  ftun_carrier_flow_token_t flows[TEST_FLOWS];
  size_t flow_count;
  backend_state_t backend;
  size_t wakeups[2];
} fixture_t;

static int token_equal(ftun_carrier_send_token_t left,
                       ftun_carrier_send_token_t right)
{
  return left.carrier == right.carrier && left.slot == right.slot &&
    left.generation == right.generation &&
    left.fragment_generation == right.fragment_generation;
}

static ftun_status_t backend_start(void *user,
                                   ftun_carrier_send_token_t token,
                                   ftun_carrier_send_kind_t kind,
                                   uint32_t owner_id, uint64_t flow_id,
                                   size_t offered, size_t *accepted)
{
  backend_state_t *state = (backend_state_t *)user;
  ftun_carrier_send_kind_t view_kind = 0;
  uint32_t view_owner = 0u;
  uint64_t view_flow = 0u;
  ftun_bytes_t bytes;
  backend_send_t send;
  *accepted = 0u;
  if (state->start_again != 0u) {
    state->start_again--;
    return FTUN_E_AGAIN;
  }
  if (state->pending_count >= BACKEND_PENDING ||
      state->start_count >= sizeof(state->starts) / sizeof(state->starts[0]) ||
      ftun_carrier_send_view(token, &view_kind, &view_owner, &view_flow,
                             &bytes) != FTUN_OK ||
      view_kind != kind || view_owner != owner_id || view_flow != flow_id ||
      bytes.length != offered) return FTUN_E_STATE_CORRUPT;
  memset(&send, 0, sizeof(send));
  send.token = token;
  send.kind = kind;
  send.owner_id = owner_id;
  send.flow_id = flow_id;
  send.offered = offered;
  send.accepted = offered;
  if (kind == FTUN_CARRIER_SEND_STREAM &&
      state->stream_accept_limit != 0u &&
      send.accepted > state->stream_accept_limit) {
    send.accepted = state->stream_accept_limit;
  }
  send.first = bytes.length == 0u ? 0u : bytes.data[0];
  state->pending[state->pending_count++] = send;
  state->starts[state->start_count++] = send;
  *accepted = send.accepted;
  return FTUN_OK;
}

static ftun_status_t backend_cancel(void *user,
                                    ftun_carrier_send_token_t token)
{
  backend_state_t *state = (backend_state_t *)user;
  size_t index;
  state->cancel_calls++;
  if (state->cancel_failures != 0u) {
    state->cancel_failures--;
    return FTUN_E_AGAIN;
  }
  for (index = 0u; index < state->pending_count; index++) {
    if (!token_equal(state->pending[index].token, token)) continue;
    state->pending_count--;
    state->pending[index] = state->pending[state->pending_count];
    memset(&state->pending[state->pending_count], 0,
           sizeof(state->pending[state->pending_count]));
    return FTUN_OK;
  }
  return FTUN_E_STATE_CORRUPT;
}

static void backend_destroy(void *user)
{
  backend_state_t *state = (backend_state_t *)user;
  state->destroy_calls++;
}

static void return_ready(void *user)
{
  size_t *wakeups = (size_t *)user;
  (*wakeups)++;
}

static void completed(ftun_operation_t *operation, ftun_error_t error,
                      void *user)
{
  completion_state_t *state = (completion_state_t *)user;
  (void)operation;
  state->calls++;
  if (error.status == FTUN_OK) state->ok++;
  else if (error.status == FTUN_E_CANCELLED) state->cancelled++;
  else if (error.status == FTUN_E_IO) state->io++;
  else state->other++;
}

static int fixture_start(fixture_t *fixture, size_t messages,
                         size_t control_reserve)
{
  ftun_budget_options_t budget_options;
  ftun_carrier_options_t carrier_options;
  ftun_carrier_backend_t backend;
  ftun_carrier_owner_options_t owner_options;
  size_t index;
  memset(fixture, 0, sizeof(*fixture));
  memset(&budget_options, 0, sizeof(budget_options));
  budget_options.limit = (ftun_budget_resources_t){1024u * 1024u, 64u, 256u};
  if (ftun_budget_create_resources(NULL, &budget_options,
                                   &fixture->budget) != FTUN_OK) return 1;
  if (ftun_buffer_pool_create(fixture->budget, 0u, 0u,
                              &fixture->pool) != FTUN_OK) return 1;
  for (index = 0u; index < 2u; index++) {
    if (ftun_operation_queue_create_reserved(fixture->budget, 16u, 4u,
          &fixture->operations[index]) != FTUN_OK) return 1;
  }
  memset(&carrier_options, 0, sizeof(carrier_options));
  carrier_options.budget = fixture->budget;
  carrier_options.max_owners = 2u;
  carrier_options.max_flows = TEST_FLOWS;
  carrier_options.max_pending_messages = messages;
  carrier_options.max_pending_bytes = 256u;
  carrier_options.control_reserve_messages = control_reserve;
  carrier_options.control_reserve_bytes = 16u;
  carrier_options.connection_credit_bytes = 8u;
  carrier_options.control_credit_bytes = 4u;
  carrier_options.max_work_per_round = messages;
  memset(&backend, 0, sizeof(backend));
  backend.send_start = backend_start;
  backend.send_cancel = backend_cancel;
  backend.destroy = backend_destroy;
  backend.context = &fixture->backend;
  if (ftun_carrier_create(&carrier_options, &backend,
                          &fixture->carrier) != FTUN_OK) return 1;
  for (index = 0u; index < 2u; index++) {
    memset(&owner_options, 0, sizeof(owner_options));
    owner_options.owner_id = (uint32_t)(101u + index);
    owner_options.return_operations = fixture->operations[index];
    owner_options.max_pending_messages = messages;
    owner_options.max_pending_bytes = 192u;
    owner_options.return_ready = return_ready;
    owner_options.return_ready_user = &fixture->wakeups[index];
    if (ftun_carrier_owner_open(fixture->carrier, &owner_options,
                                &fixture->owners[index]) != FTUN_OK) return 1;
  }
  return 0;
}

static ftun_status_t open_flow(fixture_t *fixture, size_t owner_index,
                               uint64_t flow_id,
                               ftun_carrier_flow_kind_t kind, size_t credit,
                               ftun_carrier_flow_token_t *out)
{
  ftun_carrier_flow_options_t options;
  memset(&options, 0, sizeof(options));
  options.flow_id = flow_id;
  options.kind = kind;
  options.credit_bytes = credit;
  options.max_pending_messages = 8u;
  options.max_pending_bytes = 128u;
  return ftun_carrier_flow_open(fixture->owners[owner_index], &options, out);
}

static int fixture_add_flow(fixture_t *fixture, size_t owner_index,
                            uint64_t flow_id,
                            ftun_carrier_flow_kind_t kind, size_t credit,
                            ftun_carrier_flow_token_t **out)
{
  ftun_carrier_flow_token_t *flow;
  if (fixture->flow_count >= TEST_FLOWS) return 1;
  flow = &fixture->flows[fixture->flow_count++];
  if (open_flow(fixture, owner_index, flow_id, kind, credit, flow) != FTUN_OK) {
    return 1;
  }
  *out = flow;
  return 0;
}

static int make_slice(fixture_t *fixture, uint8_t seed, size_t length,
                      ftun_buffer_slice_t *out)
{
  ftun_buffer_t *buffer = NULL;
  uint8_t *data = NULL;
  size_t capacity = 0u;
  size_t requested = length == 0u ? 1u : length;
  size_t index;
  memset(out, 0, sizeof(*out));
  if (ftun_buffer_pool_acquire(fixture->pool, requested, &buffer) != FTUN_OK ||
      ftun_buffer_data(buffer, &data, &capacity) != FTUN_OK ||
      capacity < requested) return 1;
  for (index = 0u; index < length; index++) data[index] = seed + (uint8_t)index;
  if (ftun_buffer_slice(buffer, 0u, length, out) != FTUN_OK ||
      ftun_buffer_release(&buffer) != FTUN_OK) return 1;
  return 0;
}

static ftun_status_t send_flow(fixture_t *fixture,
                               ftun_carrier_flow_token_t flow,
                               uint8_t seed, size_t length,
                               completion_state_t *completion,
                               ftun_operation_t **operation)
{
  ftun_buffer_slice_t slice;
  ftun_status_t status;
  if (operation != NULL) *operation = NULL;
  if (make_slice(fixture, seed, length, &slice) != 0) {
    return FTUN_E_STATE_CORRUPT;
  }
  status = ftun_carrier_flow_send(flow, &slice, completed, completion,
                                  operation);
  if (ftun_buffer_slice_release(&slice) != FTUN_OK) {
    return FTUN_E_STATE_CORRUPT;
  }
  return status;
}

static ftun_status_t send_control(fixture_t *fixture, size_t owner_index,
                                  uint8_t seed, size_t length,
                                  completion_state_t *completion,
                                  ftun_operation_t **operation)
{
  ftun_buffer_slice_t slice;
  ftun_status_t status;
  if (operation != NULL) *operation = NULL;
  if (make_slice(fixture, seed, length, &slice) != 0) {
    return FTUN_E_STATE_CORRUPT;
  }
  status = ftun_carrier_owner_send_control(
    fixture->owners[owner_index], &slice, completed, completion, operation);
  if (ftun_buffer_slice_release(&slice) != FTUN_OK) {
    return FTUN_E_STATE_CORRUPT;
  }
  return status;
}

static backend_send_t *find_pending(backend_state_t *backend,
                                    uint64_t flow_id,
                                    ftun_carrier_send_kind_t kind)
{
  size_t index;
  for (index = 0u; index < backend->pending_count; index++) {
    if (backend->pending[index].flow_id == flow_id &&
        backend->pending[index].kind == kind) return &backend->pending[index];
  }
  return NULL;
}

static int complete_token(backend_state_t *backend,
                          ftun_carrier_send_token_t token,
                          ftun_status_t status)
{
  ftun_error_t error = {status, 0u, 0};
  size_t index;
  for (index = 0u; index < backend->pending_count; index++) {
    if (!token_equal(backend->pending[index].token, token)) continue;
    backend->pending_count--;
    backend->pending[index] = backend->pending[backend->pending_count];
    memset(&backend->pending[backend->pending_count], 0,
           sizeof(backend->pending[backend->pending_count]));
    return ftun_carrier_send_complete(token, error) == FTUN_OK ? 0 : 1;
  }
  return 1;
}

static int complete_flow(backend_state_t *backend, uint64_t flow_id,
                         ftun_carrier_send_kind_t kind,
                         ftun_status_t status,
                         ftun_carrier_send_token_t *saved)
{
  backend_send_t *send = find_pending(backend, flow_id, kind);
  if (send == NULL) return 1;
  if (saved != NULL) *saved = send->token;
  return complete_token(backend, send->token, status);
}

static int dispatch_queue(ftun_operation_queue_t *queue, size_t expected)
{
  size_t dispatched = 0u;
  if (ftun_operation_dispatch(queue, SIZE_MAX, &dispatched) != FTUN_OK) {
    return 1;
  }
  return dispatched == expected ? 0 : 1;
}

static int fixture_finish(fixture_t *fixture)
{
  ftun_budget_usage_t usage;
  size_t index;
  size_t ignored;
  if (ftun_carrier_stop(fixture->carrier) != FTUN_OK) return 1;
  for (index = 0u; index < 2u; index++) {
    if (fixture->operations[index] != NULL &&
        ftun_operation_dispatch(fixture->operations[index], SIZE_MAX,
                                &ignored) != FTUN_OK) return 1;
  }
  for (index = 0u; index < fixture->flow_count; index++) {
    if (fixture->flows[index].carrier == NULL) continue;
    if (ftun_carrier_flow_stop(fixture->flows[index]) != FTUN_OK) return 1;
  }
  for (index = 0u; index < fixture->flow_count; index++) {
    if (ftun_carrier_flow_close(&fixture->flows[index]) != FTUN_OK) return 1;
  }
  for (index = 0u; index < 2u; index++) {
    if (fixture->owners[index].carrier != NULL &&
        (ftun_carrier_owner_stop(fixture->owners[index]) != FTUN_OK ||
         ftun_operation_dispatch(fixture->operations[index], SIZE_MAX,
                                 &ignored) != FTUN_OK ||
         ftun_carrier_owner_close(&fixture->owners[index]) != FTUN_OK)) {
      return 1;
    }
  }
  if (ftun_carrier_destroy(&fixture->carrier) != FTUN_OK ||
      fixture->backend.destroy_calls != 1) return 1;
  for (index = 0u; index < 2u; index++) {
    if (ftun_operation_queue_destroy(&fixture->operations[index]) != FTUN_OK) {
      return 1;
    }
  }
  if (ftun_buffer_pool_destroy(&fixture->pool) != FTUN_OK ||
      ftun_budget_get_usage(fixture->budget, &usage) != FTUN_OK ||
      usage.used_resources.memory_bytes != 0u ||
      usage.used_resources.descriptors != 0u ||
      usage.used_resources.queue_slots != 0u ||
      ftun_budget_destroy(&fixture->budget) != FTUN_OK) return 1;
  return 0;
}

static int test_control_reserve(void)
{
  fixture_t fixture;
  ftun_carrier_flow_token_t *flow;
  completion_state_t completion;
  ftun_operation_t *operation;
  ftun_carrier_usage_t usage;
  size_t index;
  memset(&completion, 0, sizeof(completion));
  CHECK(fixture_start(&fixture, 8u, 2u) == 0);
  CHECK(fixture_add_flow(&fixture, 0u, 1u, FTUN_CARRIER_FLOW_STREAM,
                         8u, &flow) == 0);
  for (index = 0u; index < 6u; index++) {
    CHECK(send_flow(&fixture, *flow, (uint8_t)(10u + index), 1u,
                    &completion, &operation) == FTUN_OK && operation != NULL);
  }
  CHECK(send_flow(&fixture, *flow, 30u, 1u, &completion,
                  &operation) == FTUN_E_LIMIT && operation == NULL);
  CHECK(send_control(&fixture, 0u, 40u, 2u, &completion,
                     &operation) == FTUN_OK && operation != NULL);
  CHECK(send_control(&fixture, 0u, 50u, 2u, &completion,
                     &operation) == FTUN_OK && operation != NULL);
  CHECK(send_control(&fixture, 0u, 60u, 2u, &completion,
                     &operation) == FTUN_E_LIMIT && operation == NULL);
  CHECK(ftun_carrier_get_usage(fixture.carrier, &usage) == FTUN_OK &&
        usage.normal_pending_messages == 6u &&
        usage.control_pending_messages == 2u &&
        usage.rejected_messages == 2u);
  CHECK(ftun_carrier_stop(fixture.carrier) == FTUN_OK);
  CHECK(dispatch_queue(fixture.operations[0], 8u) == 0);
  CHECK(completion.calls == 8u && completion.cancelled == 8u);
  CHECK(fixture_finish(&fixture) == 0);
  return 0;
}

static int test_partial_fair_reorder(void)
{
  fixture_t fixture;
  ftun_carrier_flow_token_t *slow;
  ftun_carrier_flow_token_t *fast;
  ftun_carrier_flow_token_t *packet;
  completion_state_t slow_done;
  completion_state_t fast_done;
  completion_state_t packet_done;
  completion_state_t control_done;
  ftun_operation_t *operation;
  ftun_carrier_send_token_t stale;
  ftun_error_t success = {FTUN_OK, 0u, 0};
  ftun_carrier_flow_usage_t flow_usage;
  ftun_carrier_usage_t usage;
  size_t work;
  memset(&slow_done, 0, sizeof(slow_done));
  memset(&fast_done, 0, sizeof(fast_done));
  memset(&packet_done, 0, sizeof(packet_done));
  memset(&control_done, 0, sizeof(control_done));
  CHECK(fixture_start(&fixture, 12u, 2u) == 0);
  fixture.backend.stream_accept_limit = 2u;
  CHECK(fixture_add_flow(&fixture, 0u, 11u, FTUN_CARRIER_FLOW_STREAM,
                         4u, &slow) == 0);
  CHECK(fixture_add_flow(&fixture, 1u, 22u, FTUN_CARRIER_FLOW_STREAM,
                         4u, &fast) == 0);
  CHECK(fixture_add_flow(&fixture, 0u, 33u, FTUN_CARRIER_FLOW_DATAGRAM,
                         8u, &packet) == 0);
  CHECK(send_flow(&fixture, *slow, 10u, 6u, &slow_done,
                  &operation) == FTUN_OK);
  CHECK(send_flow(&fixture, *fast, 20u, 4u, &fast_done,
                  &operation) == FTUN_OK);
  CHECK(send_flow(&fixture, *packet, 30u, 4u, &packet_done,
                  &operation) == FTUN_OK);
  CHECK(send_control(&fixture, 1u, 40u, 2u, &control_done,
                     &operation) == FTUN_OK);
  CHECK(ftun_carrier_process(fixture.carrier, 12u, &work) == FTUN_OK &&
        work == 4u && fixture.backend.pending_count == 4u);
  CHECK(fixture.backend.starts[0].kind == FTUN_CARRIER_SEND_CONTROL &&
        fixture.backend.starts[0].owner_id == 102u);
  CHECK(fixture.backend.starts[1].flow_id == 11u &&
        fixture.backend.starts[1].accepted == 2u &&
        fixture.backend.starts[1].first == 10u);
  CHECK(fixture.backend.starts[2].flow_id == 22u &&
        fixture.backend.starts[2].accepted == 2u &&
        fixture.backend.starts[2].first == 20u);
  CHECK(fixture.backend.starts[3].flow_id == 33u &&
        fixture.backend.starts[3].accepted == 4u);
  CHECK(ftun_carrier_get_usage(fixture.carrier, &usage) == FTUN_OK &&
        usage.connection_inflight_bytes == 8u &&
        usage.control_inflight_bytes == 2u);
  CHECK(complete_flow(&fixture.backend, 33u, FTUN_CARRIER_SEND_DATAGRAM,
                      FTUN_OK, &stale) == 0);
  CHECK(complete_flow(&fixture.backend, 22u, FTUN_CARRIER_SEND_STREAM,
                      FTUN_OK, NULL) == 0);
  CHECK(complete_flow(&fixture.backend, 0u, FTUN_CARRIER_SEND_CONTROL,
                      FTUN_OK, NULL) == 0);
  CHECK(dispatch_queue(fixture.operations[0], 1u) == 0);
  CHECK(dispatch_queue(fixture.operations[1], 1u) == 0);
  CHECK(packet_done.ok == 1u && control_done.ok == 1u &&
        fast_done.calls == 0u && slow_done.calls == 0u);
  CHECK(ftun_carrier_send_complete(stale, success) == FTUN_E_STALE);
  CHECK(ftun_carrier_process(fixture.carrier, 12u, &work) == FTUN_OK &&
        work == 1u);
  CHECK(complete_flow(&fixture.backend, 22u, FTUN_CARRIER_SEND_STREAM,
                      FTUN_OK, NULL) == 0);
  CHECK(dispatch_queue(fixture.operations[1], 1u) == 0 && fast_done.ok == 1u);
  CHECK(ftun_carrier_flow_get_usage(*slow, &flow_usage) == FTUN_OK &&
        flow_usage.inflight_bytes == 2u && flow_usage.pending_messages == 1u);
  CHECK(complete_flow(&fixture.backend, 11u, FTUN_CARRIER_SEND_STREAM,
                      FTUN_OK, NULL) == 0);
  CHECK(ftun_carrier_process(fixture.carrier, 12u, &work) == FTUN_OK &&
        work == 1u);
  CHECK(fixture.backend.starts[fixture.backend.start_count - 1u].first == 12u);
  CHECK(complete_flow(&fixture.backend, 11u, FTUN_CARRIER_SEND_STREAM,
                      FTUN_OK, NULL) == 0);
  CHECK(ftun_carrier_process(fixture.carrier, 12u, &work) == FTUN_OK &&
        work == 1u);
  CHECK(fixture.backend.starts[fixture.backend.start_count - 1u].first == 14u);
  CHECK(complete_flow(&fixture.backend, 11u, FTUN_CARRIER_SEND_STREAM,
                      FTUN_OK, NULL) == 0);
  CHECK(dispatch_queue(fixture.operations[0], 1u) == 0 && slow_done.ok == 1u);
  CHECK(ftun_carrier_get_usage(fixture.carrier, &usage) == FTUN_OK &&
        usage.pending_messages == 0u && usage.pending_bytes == 0u &&
        usage.connection_inflight_bytes == 0u &&
        usage.control_inflight_bytes == 0u &&
        usage.completed_messages == 4u && fixture.wakeups[0] >= 2u &&
        fixture.wakeups[1] >= 2u);
  CHECK(fixture_finish(&fixture) == 0);
  return 0;
}

static int test_owner_stop_retry_and_generation(void)
{
  fixture_t fixture;
  ftun_carrier_flow_token_t *first;
  ftun_carrier_flow_token_t *second;
  ftun_carrier_flow_token_t old;
  ftun_carrier_flow_token_t replacement;
  completion_state_t first_done;
  completion_state_t second_done;
  ftun_operation_t *operation;
  size_t work;
  memset(&first_done, 0, sizeof(first_done));
  memset(&second_done, 0, sizeof(second_done));
  CHECK(fixture_start(&fixture, 10u, 2u) == 0);
  CHECK(fixture_add_flow(&fixture, 0u, 71u, FTUN_CARRIER_FLOW_STREAM,
                         4u, &first) == 0);
  CHECK(fixture_add_flow(&fixture, 1u, 72u, FTUN_CARRIER_FLOW_STREAM,
                         4u, &second) == 0);
  old = *first;
  CHECK(send_flow(&fixture, *first, 1u, 2u, &first_done,
                  &operation) == FTUN_OK);
  CHECK(send_flow(&fixture, *second, 2u, 2u, &second_done,
                  &operation) == FTUN_OK);
  CHECK(ftun_carrier_process(fixture.carrier, 2u, &work) == FTUN_OK &&
        work == 2u);
  fixture.backend.cancel_failures = 1u;
  CHECK(ftun_carrier_owner_stop(fixture.owners[0]) == FTUN_E_AGAIN);
  CHECK(first_done.calls == 0u && fixture.backend.pending_count == 2u);
  CHECK(ftun_carrier_owner_stop(fixture.owners[0]) == FTUN_OK);
  CHECK(dispatch_queue(fixture.operations[0], 1u) == 0 &&
        first_done.cancelled == 1u);
  CHECK(send_flow(&fixture, *first, 3u, 1u, &first_done,
                  &operation) == FTUN_E_CANCELLED && operation == NULL);
  CHECK(complete_flow(&fixture.backend, 72u, FTUN_CARRIER_SEND_STREAM,
                      FTUN_OK, NULL) == 0);
  CHECK(dispatch_queue(fixture.operations[1], 1u) == 0 && second_done.ok == 1u);
  CHECK(ftun_carrier_flow_close(first) == FTUN_OK);
  CHECK(open_flow(&fixture, 0u, 73u, FTUN_CARRIER_FLOW_STREAM, 4u,
                  &replacement) == FTUN_E_CANCELLED);
  CHECK(send_flow(&fixture, old, 4u, 1u, &first_done,
                  &operation) == FTUN_E_STALE);
  CHECK(ftun_carrier_flow_stop(*second) == FTUN_OK &&
        ftun_carrier_flow_close(second) == FTUN_OK);
  CHECK(ftun_carrier_owner_close(&fixture.owners[0]) == FTUN_OK);
  CHECK(ftun_carrier_owner_stop(fixture.owners[1]) == FTUN_OK &&
        ftun_carrier_owner_close(&fixture.owners[1]) == FTUN_OK);
  CHECK(ftun_carrier_stop(fixture.carrier) == FTUN_OK);
  CHECK(fixture_finish(&fixture) == 0);
  return 0;
}

static int test_failure_fanout(void)
{
  fixture_t fixture;
  ftun_carrier_flow_token_t *left;
  ftun_carrier_flow_token_t *right;
  completion_state_t completions;
  ftun_operation_t *operation;
  ftun_carrier_usage_t usage;
  ftun_error_t failure = {FTUN_E_IO, 9u, 77};
  size_t work;
  memset(&completions, 0, sizeof(completions));
  CHECK(fixture_start(&fixture, 10u, 2u) == 0);
  CHECK(fixture_add_flow(&fixture, 0u, 81u, FTUN_CARRIER_FLOW_STREAM,
                         4u, &left) == 0);
  CHECK(fixture_add_flow(&fixture, 1u, 82u, FTUN_CARRIER_FLOW_DATAGRAM,
                         4u, &right) == 0);
  CHECK(send_flow(&fixture, *left, 10u, 4u, &completions,
                  &operation) == FTUN_OK);
  CHECK(send_flow(&fixture, *right, 20u, 4u, &completions,
                  &operation) == FTUN_OK);
  CHECK(send_control(&fixture, 1u, 30u, 2u, &completions,
                     &operation) == FTUN_OK);
  CHECK(ftun_carrier_process(fixture.carrier, 2u, &work) == FTUN_OK &&
        work == 2u && fixture.backend.pending_count == 2u);
  CHECK(ftun_carrier_fail(fixture.carrier, failure) == FTUN_OK &&
        fixture.backend.pending_count == 0u);
  CHECK(dispatch_queue(fixture.operations[0], 1u) == 0);
  CHECK(dispatch_queue(fixture.operations[1], 2u) == 0);
  CHECK(completions.calls == 3u && completions.io == 3u);
  CHECK(ftun_carrier_get_usage(fixture.carrier, &usage) == FTUN_OK &&
        usage.failed && !usage.accepting &&
        usage.terminal_status == FTUN_E_IO && usage.failed_messages == 3u);
  CHECK(ftun_carrier_process(fixture.carrier, 1u, &work) == FTUN_E_IO);
  CHECK(send_flow(&fixture, *left, 40u, 1u, &completions,
                  &operation) == FTUN_E_IO && operation == NULL);
  CHECK(fixture_finish(&fixture) == 0);
  return 0;
}

static int test_budget_and_owner_rejection(void)
{
  ftun_budget_t *left_budget = NULL;
  ftun_budget_t *right_budget = NULL;
  ftun_operation_queue_t *right_queue = NULL;
  fixture_t fixture;
  ftun_carrier_owner_options_t owner_options;
  ftun_carrier_owner_token_t owner;
  ftun_carrier_flow_token_t *flow;
  ftun_buffer_t *foreign_buffer = NULL;
  ftun_buffer_slice_t foreign_slice;
  completion_state_t completion;
  ftun_operation_t *operation;
  ftun_budget_usage_t usage;
  memset(&completion, 0, sizeof(completion));
  memset(&foreign_slice, 0, sizeof(foreign_slice));
  CHECK(fixture_start(&fixture, 8u, 2u) == 0);
  CHECK(fixture_add_flow(&fixture, 0u, 55u, FTUN_CARRIER_FLOW_STREAM,
                         4u, &flow) == 0);
  CHECK(ftun_budget_create(NULL, 65536u, 0u, &right_budget) == FTUN_OK);
  CHECK(ftun_operation_queue_create_reserved(right_budget, 4u, 1u,
                                              &right_queue) == FTUN_OK);
  memset(&owner_options, 0, sizeof(owner_options));
  owner_options.owner_id = 999u;
  owner_options.return_operations = right_queue;
  owner_options.max_pending_messages = 2u;
  owner_options.max_pending_bytes = 8u;
  CHECK(ftun_carrier_owner_open(fixture.carrier, &owner_options,
                                &owner) == FTUN_E_REJECTED &&
        owner.carrier == NULL);
  CHECK(ftun_buffer_acquire(right_budget, 1u, &foreign_buffer) == FTUN_OK &&
        ftun_buffer_slice(foreign_buffer, 0u, 1u, &foreign_slice) == FTUN_OK &&
        ftun_buffer_release(&foreign_buffer) == FTUN_OK);
  CHECK(ftun_carrier_flow_send(*flow, &foreign_slice, completed, &completion,
                               &operation) == FTUN_E_REJECTED &&
        operation == NULL);
  CHECK(ftun_buffer_slice_release(&foreign_slice) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&right_queue) == FTUN_OK &&
        ftun_budget_get_usage(right_budget, &usage) == FTUN_OK &&
        usage.used == 0u && ftun_budget_destroy(&right_budget) == FTUN_OK);
  CHECK(ftun_budget_create(NULL, 64u, 0u, &left_budget) == FTUN_OK);
  CHECK(ftun_budget_get_usage(left_budget, &usage) == FTUN_OK &&
        usage.used == 0u && ftun_budget_destroy(&left_budget) == FTUN_OK);
  CHECK(fixture_finish(&fixture) == 0);
  return 0;
}

static int test_flow_generation_reuse(void)
{
  fixture_t fixture;
  ftun_carrier_flow_token_t *flow;
  ftun_carrier_flow_token_t old;
  ftun_carrier_flow_token_t replacement;
  completion_state_t completion;
  ftun_operation_t *operation;
  memset(&completion, 0, sizeof(completion));
  CHECK(fixture_start(&fixture, 8u, 2u) == 0);
  CHECK(fixture_add_flow(&fixture, 0u, 91u, FTUN_CARRIER_FLOW_STREAM,
                         4u, &flow) == 0);
  old = *flow;
  CHECK(ftun_carrier_flow_stop(*flow) == FTUN_OK &&
        ftun_carrier_flow_close(flow) == FTUN_OK);
  CHECK(open_flow(&fixture, 0u, 92u, FTUN_CARRIER_FLOW_STREAM, 4u,
                  &replacement) == FTUN_OK);
  CHECK(replacement.slot == old.slot &&
        replacement.generation != old.generation);
  CHECK(send_flow(&fixture, old, 1u, 1u, &completion,
                  &operation) == FTUN_E_STALE && operation == NULL);
  fixture.flows[0] = replacement;
  CHECK(send_flow(&fixture, replacement, 2u, 1u, &completion,
                  &operation) == FTUN_OK && operation != NULL);
  CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  CHECK(dispatch_queue(fixture.operations[0], 1u) == 0 &&
        completion.cancelled == 1u);
  CHECK(fixture_finish(&fixture) == 0);
  return 0;
}

static int test_delayed_start_fairness(void)
{
  fixture_t fixture;
  ftun_carrier_flow_token_t *delayed;
  ftun_carrier_flow_token_t *ready;
  completion_state_t completions;
  ftun_operation_t *operation;
  size_t work;
  memset(&completions, 0, sizeof(completions));
  CHECK(fixture_start(&fixture, 8u, 2u) == 0);
  CHECK(fixture_add_flow(&fixture, 0u, 101u, FTUN_CARRIER_FLOW_STREAM,
                         4u, &delayed) == 0);
  CHECK(fixture_add_flow(&fixture, 1u, 102u, FTUN_CARRIER_FLOW_STREAM,
                         4u, &ready) == 0);
  CHECK(send_flow(&fixture, *delayed, 10u, 2u, &completions,
                  &operation) == FTUN_OK);
  CHECK(send_flow(&fixture, *ready, 20u, 2u, &completions,
                  &operation) == FTUN_OK);
  fixture.backend.start_again = 1u;
  CHECK(ftun_carrier_process(fixture.carrier, 8u, &work) == FTUN_OK &&
        work == 2u && fixture.backend.pending_count == 1u &&
        fixture.backend.pending[0].flow_id == 102u);
  CHECK(ftun_carrier_process(fixture.carrier, 8u, &work) == FTUN_OK &&
        work == 1u && fixture.backend.pending_count == 2u);
  CHECK(complete_flow(&fixture.backend, 102u, FTUN_CARRIER_SEND_STREAM,
                      FTUN_OK, NULL) == 0);
  CHECK(complete_flow(&fixture.backend, 101u, FTUN_CARRIER_SEND_STREAM,
                      FTUN_OK, NULL) == 0);
  CHECK(dispatch_queue(fixture.operations[0], 1u) == 0 &&
        dispatch_queue(fixture.operations[1], 1u) == 0 &&
        completions.ok == 2u);
  CHECK(fixture_finish(&fixture) == 0);
  return 0;
}

int main(void)
{
  if (test_control_reserve() != 0) return 1;
  if (test_partial_fair_reorder() != 0) return 1;
  if (test_owner_stop_retry_and_generation() != 0) return 1;
  if (test_failure_fanout() != 0) return 1;
  if (test_budget_and_owner_rejection() != 0) return 1;
  if (test_flow_generation_reuse() != 0) return 1;
  if (test_delayed_start_fairness() != 0) return 1;
  return 0;
}
