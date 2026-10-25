#include "core/context.h"
#include "proxy/outbound/outbound.h"
#include "util/time.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "outbound Path failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

ftun_status_t __wrap_ftun_socket_path_open(void *, ftun_core_t *,
  const ftun_path_open_request_t *, const ftun_path_spec_t *, ftun_operation_t **);

typedef struct {
  ftun_path_open_request_t pending;
  ftun_operation_token_t token;
  ftun_endpoint_t endpoints[8];
  uint64_t generations[8];
  ftun_path_t *path;
  ftun_status_t error;
  unsigned int starts;
  unsigned int calls;
  bool fail_first;
} state_t;

static void child_completed(ftun_operation_t *operation, ftun_error_t error, void *user)
{
  state_t *state = user;
  state->pending.completion(operation, error, NULL, state->pending.user);
}

static ftun_status_t factory(void *user, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *spec,
  ftun_operation_t **out)
{
  state_t *state = user;
  unsigned int index = state->starts++;
  if (index >= 8u) return FTUN_E_LIMIT;
  state->endpoints[index] = request->dial.endpoint;
  state->generations[index] = spec->configuration_generation;
  if (state->fail_first && index == 0u) {
    state->pending = *request;
    return ftun_operation_accept(request->dial.operations, child_completed, state, out, &state->token);
  }
  return __wrap_ftun_socket_path_open(NULL, core, request, spec, out);
}

static void completed(ftun_operation_t *operation, ftun_error_t error,
  ftun_path_t *path, void *user)
{
  state_t *state = user;
  (void)operation;
  state->calls++;
  state->error = error.status;
  state->path = path;
}

static void write_completed(ftun_operation_t *operation, ftun_error_t error, void *user)
{
  (void)operation;
  (void)error;
  (void)user;
}

int main(void)
{
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_path_provider_t *provider = NULL;
  ftun_path_provider_spec_t spec = {0};
  ftun_path_scope_t *scope = NULL, *other = NULL, *overflow = NULL, *held;
  ftun_path_provider_info_t provider_info;
  ftun_path_info_t info;
  ftun_budget_usage_t usage;
  ftun_operation_t *operation = NULL;
  ftun_endpoint_t endpoints[2] = {{0}};
  ftun_target_t target = {0};
  ftun_route_result_t route = {0};
  ftun_outbound_leaf_t leaf = {0};
  ftun_direct_request_t direct = {0};
  ftun_outbound_request_t request = {0};
  ftun_reject_result_t rejected;
  ftun_metadata_t metadata = {0};
  ftun_network_view_t *view = NULL;
  ftun_network_view_spec_t view_spec = {0};
  size_t dispatched;
  uint64_t now;
  state_t state = {0};

  CHECK(ftun_budget_create(NULL, 4194304u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 32u, &operations) == FTUN_OK);
  CHECK(ftun_event_loop_create(core, &loop) == FTUN_OK);
  spec.budget = budget;
  spec.generation = 7u;
  spec.ops.open = factory;
  spec.context = &state;
  spec.max_paths = 2u;
  spec.max_pending = 2u;
  CHECK(ftun_path_provider_create(&spec, &provider) == FTUN_OK);
  CHECK(ftun_path_provider_scope(provider, 7u, &scope) == FTUN_OK);
  CHECK(ftun_path_provider_scope(provider, 7u, &other) == FTUN_OK);
  CHECK(ftun_path_provider_scope(provider, 7u, &overflow) == FTUN_E_LIMIT && overflow == NULL);
  CHECK(ftun_path_scope_release(&other) == FTUN_OK);
  held = scope;
  CHECK(ftun_path_scope_retain(held) == FTUN_OK);
  CHECK(ftun_path_scope_release(&held) == FTUN_OK && held == NULL);
  endpoints[0].kind = FTUN_ADDRESS_IPV4;
  endpoints[0].port = 443u;
  endpoints[0].address[0] = 127u;
  endpoints[0].address[3] = 1u;
  endpoints[1] = endpoints[0];
  endpoints[1].address[3] = 2u;
  target.generation = 7u;
  target.original = endpoints[0];
  target.candidates = endpoints;
  target.candidate_count = 2u;
  target.allowed = endpoints;
  target.allowed_count = 2u;
  route.kind = FTUN_ROUTE_READY;
  route.generation = 7u;
  route.outbound_id = 3u;
  route.allowed = endpoints;
  route.allowed_count = 2u;
  leaf.generation = 7u;
  leaf.id = 3u;
  leaf.kind = FTUN_OUTBOUND_LEAF_DIRECT;
  leaf.supports_tcp = true;
  direct.loop = loop;
  direct.operations = operations;
  direct.budget = budget;
  direct.scope = scope;
  direct.path_completion = completed;
  direct.user = &state;
  direct.stream.budget = budget;
  direct.stream.operations = operations;
  direct.stream.max_pending_writes = 1u;
  direct.stream.max_pending_bytes = 8192u;
  direct.stream.completion = write_completed;
  request.route = &route;
  request.target = &target;
  request.leaf = &leaf;
  request.transport = FTUN_DIAL_TCP;
  request.direct = &direct;
  state.fail_first = true;
  CHECK(ftun_outbound_open(core, &request, &rejected, &operation) == FTUN_OK);
  CHECK(state.starts == 1u && state.calls == 0u);
  endpoints[1].address[3] = 99u;
  CHECK(ftun_path_provider_reload_prepare(provider, 8u) == FTUN_OK);
  CHECK(ftun_path_provider_reload_commit(provider, 8u) == FTUN_OK);
  CHECK(ftun_path_provider_scope(provider, 7u, &other) == FTUN_E_STALE && other == NULL);
  CHECK(ftun_operation_complete(state.token, (ftun_error_t){FTUN_E_IO, 0u, 0}) == FTUN_OK);
  CHECK(ftun_operation_dispatch(operations, 1u, &dispatched) == FTUN_OK && dispatched == 1u);
  CHECK(state.starts == 2u && state.calls == 0u && state.endpoints[1].address[3] == 2u &&
    state.generations[0] == 7u && state.generations[1] == 7u);
  CHECK(ftun_operation_dispatch(operations, 8u, &dispatched) == FTUN_OK && dispatched == 2u);
  CHECK(state.calls == 1u && state.error == FTUN_OK && state.path != NULL);
  CHECK(ftun_path_get_info(state.path, &info) == FTUN_OK && info.configuration_generation == 7u);
  {
    ftun_stream_t *stream = NULL;
    ftun_buffer_t *buffer = NULL;
    ftun_buffer_slice_t slice = {0};
    ftun_operation_t *write = NULL;
    uint8_t *data;
    size_t capacity, accepted, callbacks;
    CHECK(ftun_path_stream(state.path, &stream) == FTUN_OK);
    CHECK(ftun_buffer_acquire(budget, 8u, &buffer) == FTUN_OK);
    CHECK(ftun_buffer_data(buffer, &data, &capacity) == FTUN_OK);
    memcpy(data, "ab\0defgh", 8u);
    CHECK(ftun_buffer_slice(buffer, 0u, 8u, &slice) == FTUN_OK);
    CHECK(ftun_buffer_release(&buffer) == FTUN_OK);
    CHECK(ftun_stream_write_ref(stream, &slice, &accepted, &write) == FTUN_OK && accepted == 8u);
    CHECK(ftun_buffer_slice_release(&slice) == FTUN_OK);
    /* 驱动还有未派发任务，必须保持 Path/后端，不能只取消写后立即释放。 */
    CHECK(ftun_path_revoke(state.path) == FTUN_E_AGAIN);
    CHECK(ftun_path_destroy(&state.path) == FTUN_E_AGAIN && state.path != NULL);
    CHECK(ftun_monotonic_now(&now) == FTUN_OK);
    CHECK(ftun_event_loop_poll(loop, now, 16u, &callbacks) == FTUN_OK && callbacks == 1u);
    CHECK(ftun_operation_dispatch(operations, 8u, &dispatched) == FTUN_OK && dispatched == 1u);
  }
  CHECK(ftun_path_revoke(state.path) == FTUN_OK);
  CHECK(ftun_path_destroy(&state.path) == FTUN_OK);
  CHECK(ftun_path_provider_get_info(provider, &provider_info) == FTUN_OK &&
    provider_info.generation == 8u && provider_info.scopes == 1u && provider_info.paths == 0u);

  /* 结果已进入父操作队列但尚未回调时取消，Path 不得交给调用方或泄漏。 */
  CHECK(ftun_outbound_open(core, &request, &rejected, &operation) == FTUN_OK);
  CHECK(ftun_operation_dispatch(operations, 1u, &dispatched) == FTUN_OK && dispatched == 1u);
  CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  CHECK(ftun_operation_dispatch(operations, 8u, &dispatched) == FTUN_OK && dispatched == 1u);
  CHECK(state.calls == 2u && state.error == FTUN_E_CANCELLED && state.path == NULL);

  /* 旧 scope 只保留配置身份，不能越过已经撤销的 NetworkView。 */
  view_spec.generation = 9u;
  CHECK(ftun_network_view_create(&view_spec, &view) == FTUN_OK);
  CHECK(ftun_network_view_revoke(view) == FTUN_OK);
  direct.network_view = view;
  direct.network_generation = 9u;
  CHECK(ftun_outbound_open(core, &request, &rejected, &operation) == FTUN_E_CANCELLED && operation == NULL);
  CHECK(state.starts == 3u && state.calls == 2u);
  direct.network_view = NULL;
  direct.network_generation = 0u;
  CHECK(ftun_network_view_release(&view) == FTUN_OK);
  target.generation = 8u;
  route.generation = 8u;
  leaf.generation = 8u;
  CHECK(ftun_outbound_open(core, &request, &rejected, &operation) == FTUN_E_STALE && operation == NULL);
  target.generation = route.generation = leaf.generation = 7u;
  leaf.kind = FTUN_OUTBOUND_LEAF_REJECT;
  request.direct = NULL;
  request.metadata = &metadata;
  metadata.generation = 7u;
  metadata.known_fields = FTUN_META_NETWORK;
  metadata.network = 1u;
  CHECK(ftun_outbound_open(core, &request, &rejected, &operation) == FTUN_E_REJECTED && operation == NULL);
  CHECK(state.starts == 3u && state.calls == 2u);
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  CHECK(ftun_path_provider_stop_until(provider, now + 1000u) == FTUN_OK);
  CHECK(ftun_path_provider_destroy(&provider) == FTUN_E_AGAIN && provider != NULL);
  leaf.kind = FTUN_OUTBOUND_LEAF_DIRECT;
  request.direct = &direct;
  request.metadata = NULL;
  CHECK(ftun_outbound_open(core, &request, &rejected, &operation) == FTUN_E_CANCELLED && operation == NULL);
  CHECK(ftun_path_scope_release(&scope) == FTUN_OK);
  CHECK(ftun_path_provider_destroy(&provider) == FTUN_OK);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  puts("outbound Path contract passed");
  return 0;
}
