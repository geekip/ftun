#include "core/context.h"
#include "libs/transport/path.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "owned provider failed at %d: %s\n", __LINE__, #x); \
  return 1; } } while (0)

typedef struct fixture fixture_t;
typedef struct {
  ftun_stream_t *stream;
  ftun_datagram_t *datagram;
  ftun_stream_write_token_t write;
  ftun_datagram_send_token_t send;
  ftun_status_t cancel_status;
  unsigned int destroyed;
  unsigned int completions;
  unsigned int cancelled;
  unsigned int received;
  unsigned char bytes[64];
  size_t length;
  size_t read_offset;
} channel_t;

typedef struct {
  fixture_t *fixture;
  bool used;
  ftun_path_open_request_t request;
  const ftun_path_spec_t *spec;
  ftun_operation_t *operation;
  ftun_operation_token_t token;
  ftun_path_t *result;
  ftun_status_t cancel_status;
} job_t;

typedef struct {
  fixture_t *fixture;
  ftun_path_t *path;
  unsigned int calls;
  ftun_status_t status;
  unsigned int failures;
} completion_t;

struct fixture {
  ftun_budget_t *budget;
  ftun_core_t *core;
  ftun_operation_queue_t *operations;
  ftun_event_loop_t *loop;
  ftun_buffer_pool_t *pool;
  ftun_path_provider_t *provider;
  ftun_network_view_t *views[2];
  job_t jobs[4];
  channel_t channels[12];
  size_t channel_count;
  unsigned int starts;
  int mode;
  bool dispatching;
};

static void user_completed(ftun_operation_t *operation, ftun_error_t error,
  ftun_path_t *path, void *user)
{
  completion_t *completion = (completion_t *)user;
  if (!completion->fixture->dispatching || operation == NULL ||
      (error.status == FTUN_OK) != (path != NULL)) completion->failures++;
  completion->calls++;
  completion->status = error.status;
  completion->path = path;
}

static void job_completed(ftun_operation_t *operation, ftun_error_t error, void *user)
{
  job_t *job = (job_t *)user;
  job->request.completion(operation, error, job->result, job->request.user);
  memset(job, 0, sizeof(*job));
}

static ftun_status_t job_cancel(void *user)
{
  job_t *job = (job_t *)user;
  return job->cancel_status;
}

static ftun_status_t factory_open(void *user, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *spec,
  ftun_operation_t **out)
{
  fixture_t *fixture = (fixture_t *)user;
  job_t *job = NULL;
  ftun_status_t status;
  size_t index;
  (void)core;
  *out = NULL;
  fixture->starts++;
  if (fixture->mode == 1) return FTUN_E_IO;
  if (fixture->mode == 3) return FTUN_OK;
  for (index = 0u; index < 4u; index++) {
    if (!fixture->jobs[index].used) { job = &fixture->jobs[index]; break; }
  }
  if (job == NULL) return FTUN_E_LIMIT;
  memset(job, 0, sizeof(*job));
  job->fixture = fixture;
  job->used = true;
  job->request = *request;
  job->spec = spec;
  status = ftun_operation_accept(request->dial.operations, job_completed, job,
                                  &job->operation, &job->token);
  if (status != FTUN_OK) { memset(job, 0, sizeof(*job)); return status; }
  status = ftun_operation_set_cancel_hook(job->operation, job_cancel, job);
  if (status != FTUN_OK) return status;
  *out = job->operation;
  return fixture->mode == 2 ? FTUN_E_IO : FTUN_OK;
}

static void channel_destroy(void *user)
{
  channel_t *channel = (channel_t *)user;
  channel->destroyed++;
}

static ftun_status_t stream_read(void *user, void *buffer, size_t capacity,
  size_t *length)
{
  channel_t *channel = (channel_t *)user;
  size_t available = channel->length - channel->read_offset;
  if (available == 0u) return FTUN_E_AGAIN;
  *length = available < capacity ? available : capacity;
  memcpy(buffer, channel->bytes + channel->read_offset, *length);
  channel->read_offset += *length;
  return FTUN_OK;
}

static ftun_status_t stream_write(void *user, ftun_stream_write_token_t write,
  const ftun_buffer_slice_t *slice, size_t *accepted)
{
  channel_t *channel = (channel_t *)user;
  channel->write = write;
  *accepted = slice->length < 3u ? slice->length : 3u;
  return FTUN_OK;
}

static ftun_status_t stream_cancel(void *user, ftun_stream_write_token_t write)
{
  channel_t *channel = (channel_t *)user;
  (void)write;
  if (channel->cancel_status != FTUN_OK) return channel->cancel_status;
  memset(&channel->write, 0, sizeof(channel->write));
  return FTUN_OK;
}

static void stream_completed(ftun_operation_t *operation, ftun_error_t error, void *user)
{
  channel_t *channel = (channel_t *)user;
  (void)operation;
  channel->completions++;
  channel->cancelled += error.status == FTUN_E_CANCELLED;
}

static ftun_status_t datagram_send(void *user, ftun_datagram_send_token_t send,
  const ftun_endpoint_t *target, const ftun_packet_t *packet)
{
  channel_t *channel = (channel_t *)user;
  (void)target;
  (void)packet;
  channel->send = send;
  return FTUN_OK;
}

static ftun_status_t datagram_cancel(void *user, ftun_datagram_send_token_t send)
{
  channel_t *channel = (channel_t *)user;
  (void)send;
  if (channel->cancel_status != FTUN_OK) return channel->cancel_status;
  memset(&channel->send, 0, sizeof(channel->send));
  return FTUN_OK;
}

static void datagram_completed(ftun_datagram_t *datagram, ftun_error_t error,
  const ftun_endpoint_t *target, const ftun_packet_t *packet, void *user)
{
  channel_t *channel = (channel_t *)user;
  (void)datagram;
  (void)target;
  (void)packet;
  channel->completions++;
  channel->cancelled += error.status == FTUN_E_CANCELLED;
}

static ftun_status_t datagram_received(ftun_datagram_t *datagram,
  const ftun_endpoint_t *source, const ftun_packet_t *packet, void *user)
{
  channel_t *channel = (channel_t *)user;
  ftun_bytes_t bytes;
  (void)datagram;
  (void)source;
  if (ftun_packet_view(packet, &bytes) != FTUN_OK || bytes.length > 64u) {
    return FTUN_E_STATE_CORRUPT;
  }
  if (bytes.length != 0u) memcpy(channel->bytes, bytes.data, bytes.length);
  channel->length = bytes.length;
  channel->received++;
  return FTUN_OK;
}

static int finish(job_t *job, ftun_status_t error, bool make_result, bool wrong_identity)
{
  fixture_t *fixture = job->fixture;
  ftun_path_spec_t spec = *job->spec;
  ftun_error_t result = {error, 0u, 0};
  CHECK(job->used && fixture->channel_count < 12u);
  if (wrong_identity) spec.path_generation++;
  if (make_result) {
    channel_t *channel = &fixture->channels[fixture->channel_count++];
    if (job->request.dial.transport == FTUN_DIAL_TCP) {
      ftun_stream_options_t options = {0};
      ftun_stream_backend_t backend = {0};
      ftun_stream_t *owner = NULL;
      options.budget = fixture->budget;
      options.operations = fixture->operations;
      options.max_pending_writes = 1u;
      options.max_pending_bytes = 8u;
      options.completion = stream_completed;
      options.completion_user = channel;
      backend.read = stream_read;
      backend.write_start = stream_write;
      backend.write_cancel = stream_cancel;
      backend.destroy = channel_destroy;
      backend.context = channel;
      CHECK(ftun_stream_create(&options, &backend, &owner) == FTUN_OK);
      channel->stream = owner;
      CHECK(ftun_path_adopt_stream(&spec, &owner, &job->result) == FTUN_OK && owner == NULL);
    } else {
      ftun_datagram_options_t options = {0};
      ftun_datagram_backend_t backend = {0};
      ftun_datagram_t *owner = NULL;
      options.budget = fixture->budget;
      options.max_pending_packets = 1u;
      options.max_pending_bytes = 8u;
      options.result = datagram_completed;
      options.receive = datagram_received;
      options.user = channel;
      backend.send_start = datagram_send;
      backend.send_cancel = datagram_cancel;
      backend.destroy = channel_destroy;
      backend.context = channel;
      CHECK(ftun_datagram_create(&options, &backend, &owner) == FTUN_OK);
      channel->datagram = owner;
      CHECK(ftun_path_adopt_datagram(&spec, &owner, &job->result) == FTUN_OK && owner == NULL);
    }
  }
  CHECK(ftun_operation_complete(job->token, result) == FTUN_OK);
  return 0;
}

static int setup(fixture_t *fixture, size_t pending, size_t paths)
{
  ftun_path_provider_spec_t spec = {0};
  ftun_network_view_spec_t view = {0};
  memset(fixture, 0, sizeof(*fixture));
  CHECK(ftun_budget_create(NULL, 4194304u, 0u, &fixture->budget) == FTUN_OK);
  CHECK(ftun_core_context_create(fixture->budget, &fixture->core) == FTUN_OK);
  CHECK(ftun_operation_queue_create(fixture->budget, 16u, &fixture->operations) == FTUN_OK);
  CHECK(ftun_event_loop_create(fixture->core, &fixture->loop) == FTUN_OK);
  CHECK(ftun_buffer_pool_create(fixture->budget, 0u, 0u, &fixture->pool) == FTUN_OK);
  view.generation = 9u;
  CHECK(ftun_network_view_create(&view, &fixture->views[0]) == FTUN_OK);
  CHECK(ftun_network_view_create(&view, &fixture->views[1]) == FTUN_OK);
  spec.budget = fixture->budget;
  spec.generation = 7u;
  spec.ops.open = factory_open;
  spec.context = fixture;
  spec.max_pending = pending;
  spec.max_paths = paths;
  CHECK(ftun_path_provider_create(&spec, &fixture->provider) == FTUN_OK);
  return 0;
}

static void request_init(fixture_t *fixture, completion_t *completion,
  ftun_dial_transport_t transport, unsigned int view, ftun_path_open_request_t *request)
{
  memset(request, 0, sizeof(*request));
  completion->fixture = fixture;
  request->dial.loop = fixture->loop;
  request->dial.operations = fixture->operations;
  request->dial.budget = fixture->budget;
  request->dial.endpoint.kind = FTUN_ADDRESS_IPV4;
  request->dial.endpoint.address[0] = 127u;
  request->dial.endpoint.address[3] = 1u;
  request->dial.endpoint.port = 53u;
  request->dial.allowed = &request->dial.endpoint;
  request->dial.allowed_count = 1u;
  request->dial.network_view = view < 2u ? fixture->views[view] : NULL;
  request->dial.network_generation = view < 2u ? 9u : 0u;
  request->dial.requested_domain = FTUN_DIAL_DOMAIN_AUTO;
  request->dial.purpose = FTUN_DIAL_PURPOSE_BUSINESS;
  request->dial.transport = transport;
  request->completion = user_completed;
  request->user = completion;
}

static int dispatch(fixture_t *fixture, size_t expected)
{
  size_t count = 0u;
  fixture->dispatching = true;
  CHECK(ftun_operation_dispatch(fixture->operations, expected == 0u ? 16u : expected,
        &count) == FTUN_OK && count == expected);
  fixture->dispatching = false;
  return 0;
}

static int slice(fixture_t *fixture, ftun_buffer_slice_t *out)
{
  ftun_buffer_t *buffer = NULL;
  uint8_t *data;
  size_t capacity;
  CHECK(ftun_buffer_pool_acquire(fixture->pool, 8u, &buffer) == FTUN_OK);
  CHECK(ftun_buffer_data(buffer, &data, &capacity) == FTUN_OK && capacity >= 8u);
  memcpy(data, "ab\0defgh", 8u);
  CHECK(ftun_buffer_slice(buffer, 0u, 8u, out) == FTUN_OK);
  CHECK(ftun_buffer_release(&buffer) == FTUN_OK);
  return 0;
}

static int stream_exchange(fixture_t *fixture, ftun_path_t *path, channel_t *channel)
{
  ftun_buffer_slice_t bytes = {0}, remaining;
  ftun_stream_t *stream = NULL;
  ftun_operation_t *operation = NULL;
  ftun_error_t success = {FTUN_OK, 0u, 0};
  unsigned char received[8];
  size_t offset = 0u, accepted, read_length;
  CHECK(ftun_path_stream(path, &stream) == FTUN_OK);
  CHECK(slice(fixture, &bytes) == 0);
  while (offset < 8u) {
    ftun_bytes_t owned;
    remaining = bytes;
    remaining.offset += offset;
    remaining.length -= offset;
    CHECK(ftun_stream_write_ref(stream, &remaining, &accepted, &operation) == FTUN_OK &&
          accepted != 0u && accepted <= 3u);
    CHECK(ftun_stream_write_data(channel->write, &owned) == FTUN_OK && owned.length == accepted);
    {
      size_t refused = 1u;
      ftun_operation_t *extra = operation;
      CHECK(ftun_stream_write_ref(stream, &remaining, &refused, &extra) == FTUN_E_LIMIT &&
            refused == 0u && extra == NULL);
    }
    memcpy(channel->bytes + channel->length, owned.data, owned.length);
    channel->length += owned.length;
    offset += accepted;
    CHECK(ftun_stream_write_complete(channel->write, success) == FTUN_OK);
    CHECK(dispatch(fixture, 1u) == 0);
  }
  CHECK(ftun_buffer_slice_release(&bytes) == FTUN_OK);
  CHECK(ftun_stream_read(stream, received, sizeof(received), &read_length) == FTUN_OK &&
        read_length == 8u && memcmp(received, "ab\0defgh", 8u) == 0);
  CHECK(channel->completions == 3u && channel->cancelled == 0u);
  return 0;
}

static int cleanup(fixture_t *fixture)
{
  ftun_budget_usage_t usage;
  size_t index;
  CHECK(ftun_path_provider_stop_until(fixture->provider, UINT64_MAX) == FTUN_OK);
  CHECK(ftun_path_provider_destroy(&fixture->provider) == FTUN_OK);
  for (index = 0u; index < fixture->channel_count; index++) {
    CHECK(fixture->channels[index].destroyed == 1u);
  }
  CHECK(ftun_network_view_release(&fixture->views[0]) == FTUN_OK);
  CHECK(ftun_network_view_release(&fixture->views[1]) == FTUN_OK);
  CHECK(ftun_buffer_pool_destroy(&fixture->pool) == FTUN_OK);
  CHECK(ftun_event_loop_stop(fixture->loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&fixture->loop) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&fixture->operations) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&fixture->core) == FTUN_OK);
  CHECK(ftun_budget_get_usage(fixture->budget, &usage) == FTUN_OK && usage.used == 0u);
  CHECK(ftun_budget_destroy(&fixture->budget) == FTUN_OK);
  return 0;
}

static int test_stream_reload_and_identity(void)
{
  fixture_t fixture;
  completion_t first = {0}, second = {0};
  ftun_path_open_request_t request;
  ftun_operation_t *operation;
  ftun_path_info_t old_info, new_info;
  ftun_path_provider_info_t provider_info;
  ftun_path_t *retained;
  ftun_network_dial_decision_t decision;
  CHECK(setup(&fixture, 2u, 3u) == 0);
  request_init(&fixture, &first, FTUN_DIAL_TCP, 0u, &request);
  CHECK(ftun_path_provider_open_channel(fixture.provider, fixture.core, 7u,
        &request, &operation) == FTUN_OK && first.calls == 0u);
  CHECK(ftun_path_provider_reload_prepare(fixture.provider, 8u) == FTUN_OK);
  CHECK(ftun_path_provider_reload_commit(fixture.provider, 8u) == FTUN_OK);
  CHECK(finish(&fixture.jobs[0], FTUN_OK, true, false) == 0);
  CHECK(dispatch(&fixture, 1u) == 0 && first.calls == 1u && first.status == FTUN_OK);
  CHECK(ftun_path_get_info(first.path, &old_info) == FTUN_OK &&
        old_info.configuration_generation == 7u && old_info.network_generation == 9u);
  CHECK(stream_exchange(&fixture, first.path, &fixture.channels[0]) == 0);
  CHECK(ftun_path_provider_open_channel(fixture.provider, fixture.core, 7u,
        &request, &operation) == FTUN_E_STALE && operation == NULL);
  request_init(&fixture, &second, FTUN_DIAL_TCP, 1u, &request);
  CHECK(ftun_path_provider_open_channel(fixture.provider, fixture.core, 8u,
        &request, &operation) == FTUN_OK);
  CHECK(finish(&fixture.jobs[0], FTUN_OK, true, false) == 0);
  CHECK(dispatch(&fixture, 1u) == 0);
  CHECK(ftun_path_get_info(second.path, &new_info) == FTUN_OK &&
        new_info.configuration_generation == 8u && new_info.network_generation == 9u &&
        new_info.path_generation > old_info.path_generation &&
        new_info.network_view != old_info.network_view);
  CHECK(ftun_path_retain(first.path) == FTUN_OK);
  retained = first.path;
  CHECK(ftun_path_provider_revoke_network(fixture.provider, fixture.views[0]) == FTUN_OK);
  CHECK(ftun_path_get_info(first.path, &old_info) == FTUN_OK && old_info.revoked);
  CHECK(ftun_path_get_info(second.path, &new_info) == FTUN_OK && !new_info.revoked);
  CHECK(stream_exchange(&fixture, second.path, &fixture.channels[1]) == 0);
  request.dial.network_view = fixture.views[0];
  CHECK(ftun_dial_authorize(&request.dial, &decision) == FTUN_E_CANCELLED);
  CHECK(ftun_path_provider_open_channel(fixture.provider, fixture.core, 8u,
        &request, &operation) == FTUN_E_CANCELLED && operation == NULL);
  CHECK(ftun_network_view_release(&fixture.views[0]) == FTUN_OK);
  CHECK(ftun_path_destroy(&first.path) == FTUN_E_AGAIN);
  CHECK(ftun_path_release(&retained) == FTUN_OK);
  CHECK(ftun_path_destroy(&first.path) == FTUN_OK);
  CHECK(ftun_path_provider_get_info(fixture.provider, &provider_info) == FTUN_OK &&
        provider_info.pending == 0u && provider_info.paths == 1u);
  CHECK(ftun_path_provider_stop_until(fixture.provider, UINT64_MAX) == FTUN_OK);
  CHECK(ftun_path_provider_destroy(&fixture.provider) == FTUN_E_AGAIN);
  CHECK(ftun_path_destroy(&second.path) == FTUN_OK);
  CHECK(first.failures == 0u && second.failures == 0u);
  CHECK(cleanup(&fixture) == 0);
  return 0;
}

static int test_datagram_late_and_revoke(void)
{
  fixture_t fixture;
  completion_t first = {0}, second = {0};
  ftun_path_open_request_t request;
  ftun_operation_t *operation;
  ftun_datagram_t *datagram;
  ftun_buffer_slice_t payload = {0};
  ftun_packet_t packet = {0};
  const ftun_packet_t *pending;
  const ftun_endpoint_t *target;
  ftun_datagram_send_token_t late;
  ftun_error_t success = {FTUN_OK, 0u, 0};
  channel_t *channel;
  CHECK(setup(&fixture, 2u, 3u) == 0);
  request_init(&fixture, &first, FTUN_DIAL_UDP, 0u, &request);
  CHECK(ftun_path_provider_open_channel(fixture.provider, fixture.core, 7u,
        &request, &operation) == FTUN_OK);
  fixture.jobs[0].cancel_status = FTUN_E_AGAIN;
  request_init(&fixture, &second, FTUN_DIAL_UDP, 1u, &request);
  CHECK(ftun_path_provider_open_channel(fixture.provider, fixture.core, 7u,
        &request, &operation) == FTUN_OK);
  CHECK(ftun_path_provider_revoke_network(fixture.provider, fixture.views[0]) == FTUN_E_AGAIN);
  CHECK(finish(&fixture.jobs[0], FTUN_OK, true, false) == 0);
  CHECK(finish(&fixture.jobs[1], FTUN_OK, true, false) == 0);
  CHECK(dispatch(&fixture, 2u) == 0 && first.calls == 1u && first.path == NULL &&
        first.status == FTUN_E_CANCELLED && second.status == FTUN_OK);
  CHECK(fixture.channels[0].destroyed == 1u);
  channel = &fixture.channels[1];
  CHECK(ftun_path_datagram(second.path, &datagram) == FTUN_OK);
  CHECK(slice(&fixture, &payload) == 0);
  CHECK(ftun_packet_init(&packet, &payload, 17u) == FTUN_OK);
  CHECK(ftun_buffer_slice_release(&payload) == FTUN_OK);
  CHECK(ftun_datagram_send(datagram, &request.dial.endpoint, &packet) == FTUN_OK);
  CHECK(ftun_datagram_send(datagram, &request.dial.endpoint, &packet) == FTUN_E_LIMIT);
  CHECK(ftun_datagram_send_view(channel->send, &target, &pending) == FTUN_OK &&
        pending->source_id == 17u);
  CHECK(ftun_datagram_deliver(datagram, target, pending) == FTUN_OK &&
        channel->received == 1u && channel->length == 8u &&
        memcmp(channel->bytes, "ab\0defgh", 8u) == 0);
  CHECK(ftun_datagram_send_complete(channel->send, success) == FTUN_OK);
  CHECK(ftun_datagram_send(datagram, &request.dial.endpoint, &packet) == FTUN_OK);
  late = channel->send;
  channel->cancel_status = FTUN_E_IO;
  CHECK(ftun_path_provider_revoke_network(fixture.provider, fixture.views[1]) == FTUN_E_IO);
  CHECK(ftun_datagram_send(datagram, &request.dial.endpoint, &packet) == FTUN_E_CANCELLED);
  CHECK(ftun_datagram_deliver(datagram, &request.dial.endpoint, &packet) == FTUN_E_CANCELLED);
  channel->cancel_status = FTUN_OK;
  CHECK(ftun_path_provider_revoke_network(fixture.provider, fixture.views[1]) == FTUN_OK);
  CHECK(channel->completions == 2u && channel->cancelled == 1u);
  CHECK(ftun_datagram_send_complete(late, success) == FTUN_E_STALE);
  CHECK(ftun_packet_release(&packet) == FTUN_OK);
  CHECK(ftun_path_destroy(&second.path) == FTUN_OK);
  CHECK(first.failures == 0u && second.failures == 0u);
  CHECK(cleanup(&fixture) == 0);
  return 0;
}

static int test_admission_and_bad_factory(void)
{
  fixture_t fixture;
  completion_t completion = {0};
  ftun_path_open_request_t request;
  ftun_operation_t *operation;
  ftun_operation_token_t late;
  ftun_path_provider_info_t info;
  ftun_budget_usage_t before, after;
  ftun_error_t success = {FTUN_OK, 0u, 0};
  CHECK(setup(&fixture, 1u, 1u) == 0);
  request_init(&fixture, &completion, FTUN_DIAL_TCP, 2u, &request);
  CHECK(ftun_budget_get_usage(fixture.budget, &before) == FTUN_OK);
  fixture.mode = 1;
  CHECK(ftun_path_provider_open_channel(fixture.provider, fixture.core, 7u,
        &request, &operation) == FTUN_E_IO && operation == NULL);
  fixture.mode = 3;
  CHECK(ftun_path_provider_open_channel(fixture.provider, fixture.core, 7u,
        &request, &operation) == FTUN_E_STATE_CORRUPT && operation == NULL);
  CHECK(ftun_budget_get_usage(fixture.budget, &after) == FTUN_OK && after.used == before.used);
  fixture.mode = 2;
  CHECK(ftun_path_provider_open_channel(fixture.provider, fixture.core, 7u,
        &request, &operation) == FTUN_E_STATE_CORRUPT && operation == NULL);
  CHECK(ftun_path_provider_get_info(fixture.provider, &info) == FTUN_OK && info.pending == 1u);
  CHECK(dispatch(&fixture, 1u) == 0 && completion.calls == 0u);
  CHECK(ftun_budget_get_usage(fixture.budget, &after) == FTUN_OK && after.used == before.used);
  fixture.mode = 0;
  CHECK(ftun_path_provider_open_channel(fixture.provider, fixture.core, 7u,
        &request, &operation) == FTUN_OK);
  late = fixture.jobs[0].token;
  CHECK(ftun_path_provider_open_channel(fixture.provider, fixture.core, 7u,
        &request, &operation) == FTUN_E_LIMIT && operation == NULL);
  CHECK(finish(&fixture.jobs[0], FTUN_OK, true, false) == 0);
  CHECK(dispatch(&fixture, 1u) == 0 && completion.path != NULL);
  CHECK(ftun_path_provider_open_channel(fixture.provider, fixture.core, 7u,
        &request, &operation) == FTUN_E_LIMIT && operation == NULL);
  CHECK(ftun_path_revoke(completion.path) == FTUN_OK);
  CHECK(ftun_path_destroy(&completion.path) == FTUN_OK);
  CHECK(ftun_path_provider_open_channel(fixture.provider, fixture.core, 7u,
        &request, &operation) == FTUN_OK);
  CHECK(ftun_operation_complete(late, success) == FTUN_E_STALE);
  CHECK(finish(&fixture.jobs[0], FTUN_OK, true, true) == 0);
  CHECK(dispatch(&fixture, 1u) == 0 && completion.status == FTUN_E_STATE_CORRUPT &&
        completion.path == NULL && completion.calls == 2u && completion.failures == 0u);
  CHECK(ftun_path_provider_get_info(fixture.provider, &info) == FTUN_OK &&
        info.pending == 0u && info.paths == 0u && info.retired == 0u);
  CHECK(cleanup(&fixture) == 0);
  return 0;
}

static int test_stop_late_result(void)
{
  fixture_t fixture;
  completion_t completion = {0};
  ftun_path_open_request_t request;
  ftun_operation_t *operation;
  ftun_path_provider_info_t info;
  CHECK(setup(&fixture, 1u, 2u) == 0);
  request_init(&fixture, &completion, FTUN_DIAL_TCP, 0u, &request);
  CHECK(ftun_path_provider_open_channel(fixture.provider, fixture.core, 7u,
        &request, &operation) == FTUN_OK);
  fixture.jobs[0].cancel_status = FTUN_E_AGAIN;
  CHECK(ftun_path_provider_stop_until(fixture.provider, UINT64_MAX) == FTUN_E_AGAIN);
  CHECK(ftun_path_provider_stop_until(fixture.provider, 1u) == FTUN_E_TIMEOUT);
  CHECK(ftun_path_provider_destroy(&fixture.provider) == FTUN_E_AGAIN);
  CHECK(finish(&fixture.jobs[0], FTUN_OK, true, false) == 0);
  CHECK(dispatch(&fixture, 1u) == 0 && completion.calls == 1u &&
        completion.status == FTUN_E_CANCELLED && completion.path == NULL);
  CHECK(ftun_path_provider_get_info(fixture.provider, &info) == FTUN_OK &&
        !info.accepting && info.pending == 0u && info.paths == 0u);
  CHECK(completion.failures == 0u && cleanup(&fixture) == 0);
  return 0;
}

static int test_stop_pending_stream(void)
{
  fixture_t fixture;
  completion_t completion = {0};
  ftun_path_open_request_t request;
  ftun_operation_t *operation;
  ftun_path_provider_info_t info;
  ftun_buffer_slice_t payload = {0};
  ftun_stream_t *stream;
  ftun_stream_write_token_t late;
  ftun_error_t success = {FTUN_OK, 0u, 0};
  ftun_endpoint_t different;
  size_t accepted;
  CHECK(setup(&fixture, 1u, 2u) == 0);
  request_init(&fixture, &completion, FTUN_DIAL_TCP, 0u, &request);
  different = request.dial.endpoint;
  different.port++;
  request.dial.allowed = &different;
  CHECK(ftun_path_provider_open_channel(fixture.provider, fixture.core, 7u,
        &request, &operation) == FTUN_E_REJECTED && operation == NULL &&
        fixture.starts == 0u);
  request.dial.allowed = &request.dial.endpoint;
  CHECK(ftun_path_provider_open_channel(fixture.provider, fixture.core, 7u,
        &request, &operation) == FTUN_OK);
  CHECK(finish(&fixture.jobs[0], FTUN_OK, true, false) == 0);
  CHECK(dispatch(&fixture, 1u) == 0 && completion.status == FTUN_OK);
  CHECK(ftun_path_stream(completion.path, &stream) == FTUN_OK);
  CHECK(slice(&fixture, &payload) == 0);
  CHECK(ftun_stream_write_ref(stream, &payload, &accepted, &operation) == FTUN_OK &&
        accepted == 3u);
  CHECK(ftun_buffer_slice_release(&payload) == FTUN_OK);
  late = fixture.channels[0].write;
  fixture.channels[0].cancel_status = FTUN_E_AGAIN;
  CHECK(ftun_path_provider_stop_until(fixture.provider, 1u) == FTUN_E_TIMEOUT);
  CHECK(ftun_path_destroy(&completion.path) == FTUN_E_AGAIN);
  CHECK(ftun_path_provider_destroy(&fixture.provider) == FTUN_E_AGAIN);
  CHECK(ftun_path_provider_get_info(fixture.provider, &info) == FTUN_OK &&
        !info.accepting && !info.stopped && info.paths == 1u);
  fixture.channels[0].cancel_status = FTUN_OK;
  CHECK(ftun_path_provider_stop_until(fixture.provider, UINT64_MAX) == FTUN_E_AGAIN);
  CHECK(ftun_stream_write_complete(late, success) == FTUN_E_STALE);
  CHECK(dispatch(&fixture, 1u) == 0 && fixture.channels[0].cancelled == 1u);
  CHECK(ftun_path_provider_stop_until(fixture.provider, UINT64_MAX) == FTUN_OK);
  CHECK(ftun_path_destroy(&completion.path) == FTUN_OK);
  CHECK(completion.failures == 0u && cleanup(&fixture) == 0);
  return 0;
}

int main(void)
{
  CHECK(test_stream_reload_and_identity() == 0);
  CHECK(test_datagram_late_and_revoke() == 0);
  CHECK(test_admission_and_bad_factory() == 0);
  CHECK(test_stop_late_result() == 0);
  CHECK(test_stop_pending_stream() == 0);
  puts("Owned Provider contract passed: five asynchronous consumer scenarios");
  return 0;
}
