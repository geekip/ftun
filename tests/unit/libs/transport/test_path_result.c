#include "libs/transport/path.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "path result contract failed at %d: %s\n", __LINE__, #x); \
  return 1; } } while (0)
#define RECORD(state, x) do { if (!(x)) { \
  fprintf(stderr, "path callback contract failed at %d: %s\n", __LINE__, #x); \
  (state)->failures++; } } while (0)

typedef struct {
  ftun_path_t *path;
  ftun_stream_t *stream;
  ftun_datagram_t *datagram;
  ftun_path_spec_t spec;
  ftun_stream_write_token_t write;
  ftun_datagram_send_token_t send;
  ftun_status_t cancel_status;
  unsigned int failures;
  unsigned int cancels;
  unsigned int completions;
  unsigned int cancellations;
  unsigned int destroyed;
  unsigned int progress;
  unsigned int received;
  size_t received_length;
  size_t read_offset;
  bool probe_adoption;
  bool probe_revoke;
} channel_t;

typedef struct {
  ftun_budget_t *budget;
  ftun_budget_t *foreign;
  ftun_budget_t *tiny;
  ftun_operation_queue_t *operations;
  ftun_buffer_pool_t *pool;
  ftun_buffer_slice_t bytes;
  ftun_buffer_slice_t empty;
  ftun_network_view_t *old_view;
  ftun_network_view_t *new_view;
} fixture_t;

static ftun_channel_t *data_channel(ftun_path_t *path)
{
  ftun_channel_t *channel = NULL;
  if (ftun_path_channel(path, &channel) != FTUN_OK) return NULL;
  return channel;
}

static void probe_adoption(channel_t *state)
{
  ftun_path_t *out = (ftun_path_t *)(uintptr_t)1;
  if (!state->probe_adoption) return;
  if (state->stream != NULL) {
    ftun_stream_t *borrowed = state->stream;
    RECORD(state, ftun_path_adopt_stream(&state->spec, &borrowed, &out) ==
           FTUN_E_AGAIN && borrowed == state->stream && out == NULL);
  } else {
    ftun_datagram_t *borrowed = state->datagram;
    RECORD(state, ftun_path_adopt_datagram(&state->spec, &borrowed, &out) ==
           FTUN_E_AGAIN && borrowed == state->datagram && out == NULL);
  }
}

static void probe_revoke(channel_t *state)
{
  ftun_path_t *borrowed = state->path;
  ftun_path_info_t info;
  if (!state->probe_revoke || state->path == NULL) return;
  RECORD(state, ftun_path_revoke(state->path) == FTUN_E_AGAIN);
  RECORD(state, ftun_path_destroy(&borrowed) == FTUN_E_AGAIN &&
         borrowed == state->path);
  RECORD(state, ftun_path_get_info(state->path, &info) == FTUN_OK && info.revoked);
}

static ftun_status_t stream_read(void *user, void *buffer, size_t capacity,
  size_t *length)
{
  channel_t *state = (channel_t *)user;
  static const char data[] = "abcdefgh";
  size_t available = 8u - state->read_offset;
  probe_adoption(state);
  if (available == 0u) return FTUN_E_AGAIN;
  *length = capacity < available ? capacity : available;
  memcpy(buffer, data + state->read_offset, *length);
  state->read_offset += *length;
  return FTUN_OK;
}

static ftun_status_t stream_write(void *user, ftun_stream_write_token_t write,
  const ftun_buffer_slice_t *slice, size_t *accepted)
{
  channel_t *state = (channel_t *)user;
  probe_adoption(state);
  state->write = write;
  *accepted = slice->length < 3u ? slice->length : 3u;
  return FTUN_OK;
}

static ftun_status_t stream_cancel(void *user, ftun_stream_write_token_t write)
{
  channel_t *state = (channel_t *)user;
  state->cancels++;
  RECORD(state, write.stream == state->write.stream &&
         write.generation == state->write.generation);
  probe_revoke(state);
  if (state->cancel_status != FTUN_OK) return state->cancel_status;
  memset(&state->write, 0, sizeof(state->write));
  return FTUN_OK;
}

static void channel_destroy(void *user)
{
  channel_t *state = (channel_t *)user;
  state->destroyed++;
  probe_revoke(state);
  RECORD(state, ftun_path_retain(state->path) == FTUN_E_AGAIN);
  if (state->stream != NULL) {
    ftun_stream_t *borrowed = state->stream;
    RECORD(state, ftun_stream_retain(borrowed) == FTUN_E_AGAIN);
    RECORD(state, ftun_stream_destroy(&borrowed) == FTUN_E_AGAIN &&
           borrowed == state->stream);
  } else {
    ftun_datagram_t *borrowed = state->datagram;
    RECORD(state, ftun_datagram_destroy(&borrowed) == FTUN_E_AGAIN &&
           borrowed == state->datagram);
  }
}

static void stream_completed(ftun_operation_t *operation,
  ftun_error_t error, void *user)
{
  channel_t *state = (channel_t *)user;
  (void)operation;
  state->completions++;
  state->cancellations += error.status == FTUN_E_CANCELLED;
  probe_adoption(state);
  probe_revoke(state);
}

static void stream_progress(void *user)
{
  channel_t *state = (channel_t *)user;
  state->progress++;
  probe_adoption(state);
  probe_revoke(state);
}

static ftun_status_t datagram_send(void *user, ftun_datagram_send_token_t send,
  const ftun_endpoint_t *target, const ftun_packet_t *packet)
{
  channel_t *state = (channel_t *)user;
  (void)target;
  (void)packet;
  state->send = send;
  probe_adoption(state);
  return FTUN_OK;
}

static ftun_status_t datagram_cancel(void *user, ftun_datagram_send_token_t send)
{
  channel_t *state = (channel_t *)user;
  state->cancels++;
  RECORD(state, send.channel == state->send.channel &&
         send.generation == state->send.generation);
  probe_revoke(state);
  if (state->cancel_status != FTUN_OK) return state->cancel_status;
  memset(&state->send, 0, sizeof(state->send));
  return FTUN_OK;
}

static void datagram_completed(ftun_datagram_t *channel, ftun_error_t error,
  const ftun_endpoint_t *target, const ftun_packet_t *packet, void *user)
{
  channel_t *state = (channel_t *)user;
  ftun_bytes_t bytes;
  RECORD(state, channel == state->datagram && target->port == 53u);
  RECORD(state, ftun_packet_view(packet, &bytes) == FTUN_OK);
  state->completions++;
  state->cancellations += error.status == FTUN_E_CANCELLED;
  probe_adoption(state);
  probe_revoke(state);
}

static ftun_status_t datagram_receive(ftun_datagram_t *channel,
  const ftun_endpoint_t *source, const ftun_packet_t *packet, void *user)
{
  channel_t *state = (channel_t *)user;
  ftun_bytes_t bytes;
  RECORD(state, channel == state->datagram && source->port == 53u);
  RECORD(state, ftun_packet_view(packet, &bytes) == FTUN_OK);
  state->received++;
  state->received_length = bytes.length;
  RECORD(state, bytes.length == 0u ||
         (bytes.length == 8u && memcmp(bytes.data, "abcdefgh", 8u) == 0));
  probe_adoption(state);
  probe_revoke(state);
  return FTUN_OK;
}

static int setup(fixture_t *fixture)
{
  ftun_buffer_t *buffer = NULL;
  ftun_network_view_spec_t spec = {0};
  size_t capacity;
  uint8_t *data;
  memset(fixture, 0, sizeof(*fixture));
  CHECK(ftun_budget_create(NULL, 1048576u, 0u, &fixture->budget) == FTUN_OK);
  CHECK(ftun_budget_create(NULL, 65536u, 0u, &fixture->foreign) == FTUN_OK);
  CHECK(ftun_budget_create(fixture->budget, 64u, 0u, &fixture->tiny) == FTUN_OK);
  CHECK(ftun_operation_queue_create(fixture->budget, 8u,
        &fixture->operations) == FTUN_OK);
  CHECK(ftun_buffer_pool_create(fixture->budget, 0u, 0u, &fixture->pool) == FTUN_OK);
  CHECK(ftun_buffer_pool_acquire(fixture->pool, 8u, &buffer) == FTUN_OK);
  CHECK(ftun_buffer_data(buffer, &data, &capacity) == FTUN_OK && capacity >= 8u);
  memcpy(data, "abcdefgh", 8u);
  CHECK(ftun_buffer_slice(buffer, 0u, 8u, &fixture->bytes) == FTUN_OK);
  CHECK(ftun_buffer_slice(buffer, 0u, 0u, &fixture->empty) == FTUN_OK);
  ftun_buffer_release(&buffer);
  spec.generation = 9u;
  CHECK(ftun_network_view_create(&spec, &fixture->old_view) == FTUN_OK);
  CHECK(ftun_network_view_create(&spec, &fixture->new_view) == FTUN_OK);
  CHECK(fixture->old_view != fixture->new_view);
  return 0;
}

static int cleanup(fixture_t *fixture)
{
  ftun_budget_usage_t usage;
  ftun_network_view_release(&fixture->old_view);
  ftun_network_view_release(&fixture->new_view);
  ftun_buffer_slice_release(&fixture->bytes);
  ftun_buffer_slice_release(&fixture->empty);
  CHECK(ftun_buffer_pool_destroy(&fixture->pool) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&fixture->operations) == FTUN_OK);
  CHECK(ftun_budget_destroy(&fixture->tiny) == FTUN_OK);
  CHECK(ftun_budget_destroy(&fixture->foreign) == FTUN_OK);
  CHECK(ftun_budget_get_usage(fixture->budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u);
  CHECK(ftun_budget_destroy(&fixture->budget) == FTUN_OK);
  return 0;
}

static int create(fixture_t *fixture, channel_t *state, bool datagram)
{
  memset(state, 0, sizeof(*state));
  state->spec.budget = fixture->budget;
  state->spec.configuration_generation = 7u;
  state->spec.path_generation = datagram ? 42u : 41u;
  state->spec.network_view = datagram ? fixture->new_view : fixture->old_view;
  state->spec.endpoint.kind = FTUN_ADDRESS_IPV4;
  state->spec.endpoint.address[0] = 127u;
  state->spec.endpoint.address[3] = 1u;
  state->spec.endpoint.port = 53u;
  state->spec.domain = FTUN_DIAL_DOMAIN_UNDERLAY;
  state->spec.purpose = FTUN_DIAL_PURPOSE_DNS;
  if (datagram) {
    ftun_datagram_options_t options = {0};
    ftun_datagram_backend_t backend = {0};
    options.budget = fixture->budget;
    options.max_pending_packets = 1u;
    options.max_pending_bytes = 8u;
    options.result = datagram_completed;
    options.receive = datagram_receive;
    options.user = state;
    backend.send_start = datagram_send;
    backend.send_cancel = datagram_cancel;
    backend.destroy = channel_destroy;
    backend.context = state;
    CHECK(ftun_datagram_create(&options, &backend, &state->datagram) == FTUN_OK);
  } else {
    ftun_stream_options_t options = {0};
    ftun_stream_backend_t backend = {0};
    options.budget = fixture->budget;
    options.operations = fixture->operations;
    options.max_pending_writes = 1u;
    options.max_pending_bytes = 8u;
    options.completion = stream_completed;
    options.completion_user = state;
    options.progress = stream_progress;
    options.progress_user = state;
    backend.read = stream_read;
    backend.write_start = stream_write;
    backend.write_cancel = stream_cancel;
    backend.destroy = channel_destroy;
    backend.context = state;
    CHECK(ftun_stream_create(&options, &backend, &state->stream) == FTUN_OK);
  }
  return 0;
}

static int adoption_failures(fixture_t *fixture, channel_t *state)
{
  ftun_path_t *out;
  ftun_path_spec_t spec;
  ftun_status_t expected[] = {FTUN_E_INVALID, FTUN_E_REJECTED, FTUN_E_LIMIT,
                             FTUN_E_UNSUPPORTED};
  size_t index;
  for (index = 0u; index < 4u; index++) {
    spec = state->spec;
    if (index == 0u) spec.configuration_generation = 0u;
    if (index == 1u) spec.budget = fixture->foreign;
    if (index == 2u) spec.budget = fixture->tiny;
    if (index == 3u) {
      spec.network_view = NULL;
      spec.domain = FTUN_DIAL_DOMAIN_OVERLAY;
    }
    out = (ftun_path_t *)(uintptr_t)1;
    if (state->stream != NULL) {
      ftun_stream_t *original = state->stream;
      CHECK(ftun_path_adopt_stream(&spec, &original, &out) == expected[index]);
      CHECK(original == state->stream && out == NULL);
    } else {
      ftun_datagram_t *original = state->datagram;
      CHECK(ftun_path_adopt_datagram(&spec, &original, &out) == expected[index]);
      CHECK(original == state->datagram && out == NULL);
    }
    CHECK(state->destroyed == 0u && state->completions == 0u);
  }
  return 0;
}

static int stream_case(void)
{
  fixture_t fixture;
  channel_t state;
  ftun_stream_t *owner, *retained;
  ftun_datagram_t *wrong = (ftun_datagram_t *)(uintptr_t)1;
  ftun_path_t *alias, *out;
  ftun_path_info_t info;
  ftun_network_view_info_t view_info;
  ftun_operation_t *operation = NULL;
  ftun_stream_write_token_t late;
  ftun_bytes_t bytes;
  size_t length, accepted, count;
  char read_buffer[8];
  char domain[] = "node.example";
  CHECK(setup(&fixture) == 0 && create(&fixture, &state, false) == 0);
  CHECK(adoption_failures(&fixture, &state) == 0);
  state.probe_adoption = true;
  CHECK(ftun_stream_read(state.stream, read_buffer, 2u, &length) == FTUN_OK &&
        length == 2u && memcmp(read_buffer, "ab", 2u) == 0);
  CHECK(state.failures == 0u);
  CHECK(ftun_stream_retain(state.stream) == FTUN_OK);
  retained = state.stream;
  owner = state.stream;
  CHECK(ftun_path_adopt_stream(&state.spec, &owner, &out) == FTUN_E_AGAIN &&
        owner == state.stream && out == NULL);
  ftun_stream_release(&retained);
  state.spec.endpoint.kind = FTUN_ADDRESS_DOMAIN;
  state.spec.endpoint.domain = (ftun_string_t){domain, sizeof(domain) - 1u};
  CHECK(ftun_path_adopt_stream(&state.spec, &owner, &state.path) == FTUN_OK &&
        owner == NULL && state.path != NULL);
  memset(domain, 'x', sizeof(domain) - 1u);
  CHECK(ftun_path_get_info(state.path, &info) == FTUN_OK &&
        info.configuration_generation == 7u && info.path_generation == 41u &&
        info.network_generation == 9u && info.network_view == fixture.old_view &&
        info.network_view != fixture.new_view && info.references == 1u &&
        info.endpoint.domain.length == 12u &&
        memcmp(info.endpoint.domain.data, "node.example", 12u) == 0);
  ftun_network_view_release(&fixture.old_view);
  CHECK(ftun_network_view_get_info(info.network_view, &view_info) == FTUN_OK &&
        view_info.generation == 9u);
  CHECK(ftun_path_stream(state.path, &owner) == FTUN_OK && owner == state.stream);
  CHECK(ftun_path_datagram(state.path, &wrong) == FTUN_E_UNSUPPORTED && wrong == NULL);
  CHECK(ftun_channel_send(data_channel(state.path), &state.spec.endpoint, NULL) == FTUN_E_UNSUPPORTED);
  {
    ftun_channel_usage_t usage;
    CHECK(ftun_channel_get_usage(data_channel(state.path), &usage) == FTUN_OK &&
      usage.transport == FTUN_DIAL_TCP && usage.accepting && usage.pending_items == 0u);
  }
  CHECK(ftun_path_retain(state.path) == FTUN_OK);
  alias = state.path;
  CHECK(ftun_path_destroy(&state.path) == FTUN_E_AGAIN);
  CHECK(ftun_channel_read(data_channel(state.path), read_buffer, sizeof(read_buffer), &length) ==
        FTUN_OK && length == 6u && memcmp(read_buffer, "cdefgh", 6u) == 0);
  CHECK(ftun_channel_write_ref(data_channel(state.path), &fixture.bytes, &accepted, &operation) ==
        FTUN_OK && accepted == 3u && operation != NULL);
  late = state.write;
  CHECK(ftun_channel_write_ref(data_channel(state.path), &fixture.bytes, &accepted, &operation) ==
        FTUN_E_LIMIT && accepted == 0u && operation == NULL);
  state.cancel_status = FTUN_E_AGAIN;
  state.probe_revoke = true;
  CHECK(ftun_path_revoke(state.path) == FTUN_E_AGAIN && state.cancels == 1u);
  CHECK(ftun_path_get_info(state.path, &info) == FTUN_OK && info.revoked);
  CHECK(ftun_channel_read(data_channel(state.path), read_buffer, sizeof(read_buffer), &length) ==
        FTUN_E_CANCELLED && length == 0u);
  CHECK(ftun_channel_write_ref(data_channel(state.path), &fixture.bytes, &accepted, &operation) ==
        FTUN_E_CANCELLED && accepted == 0u && operation == NULL);
  CHECK(ftun_stream_write_data(late, &bytes) == FTUN_OK && bytes.length == 3u &&
        memcmp(bytes.data, "abc", 3u) == 0);
  CHECK(ftun_path_destroy(&state.path) == FTUN_E_AGAIN);
  ftun_path_release(&alias); CHECK(alias == NULL);
  state.cancel_status = FTUN_OK;
  CHECK(ftun_path_revoke(state.path) == FTUN_OK && state.cancels == 2u);
  CHECK(ftun_path_revoke(state.path) == FTUN_OK && state.cancels == 2u);
  CHECK(state.completions == 0u);
  CHECK(ftun_path_destroy(&state.path) == FTUN_E_AGAIN);
  CHECK(ftun_operation_dispatch(fixture.operations, 8u, &count) == FTUN_OK &&
        count == 1u && state.completions == 1u && state.cancellations == 1u &&
        state.progress == 1u && state.failures == 0u);
  CHECK(ftun_stream_write_data(late, &bytes) == FTUN_E_STALE);
  CHECK(ftun_stream_retain(owner) == FTUN_OK);
  retained = owner;
  CHECK(ftun_path_destroy(&state.path) == FTUN_E_AGAIN);
  ftun_stream_release(&retained);
  CHECK(ftun_path_destroy(&state.path) == FTUN_OK && state.path == NULL &&
        state.destroyed == 1u && state.failures == 0u);
  CHECK(cleanup(&fixture) == 0);
  return 0;
}

static int datagram_case(bool revoke_from_receive)
{
  fixture_t fixture;
  channel_t state;
  ftun_datagram_t *owner;
  ftun_stream_t *wrong = (ftun_stream_t *)(uintptr_t)1;
  ftun_packet_t empty = {0}, packet = {0};
  ftun_error_t success = {FTUN_OK, 0u, 0};
  ftun_path_info_t info;
  const ftun_endpoint_t *target;
  const ftun_packet_t *pending;
  ftun_bytes_t bytes;
  ftun_datagram_send_token_t late;
  CHECK(setup(&fixture) == 0 && create(&fixture, &state, true) == 0);
  CHECK(adoption_failures(&fixture, &state) == 0);
  owner = state.datagram;
  CHECK(ftun_path_adopt_datagram(&state.spec, &owner, &state.path) == FTUN_OK &&
        owner == NULL && state.path != NULL);
  CHECK(ftun_path_get_info(state.path, &info) == FTUN_OK &&
        info.configuration_generation == 7u && info.path_generation == 42u &&
        info.network_generation == 9u && info.network_view == fixture.new_view &&
        info.network_view != fixture.old_view);
  ftun_network_view_release(&fixture.new_view);
  CHECK(ftun_path_datagram(state.path, &owner) == FTUN_OK && owner == state.datagram);
  CHECK(ftun_path_stream(state.path, &wrong) == FTUN_E_UNSUPPORTED && wrong == NULL);
  {
    uint8_t byte;
    size_t length = 9u;
    ftun_channel_usage_t usage;
    CHECK(ftun_channel_read(data_channel(state.path), &byte, 1u, &length) == FTUN_E_UNSUPPORTED && length == 0u);
    CHECK(ftun_channel_get_usage(data_channel(state.path), &usage) == FTUN_OK &&
      usage.transport == FTUN_DIAL_UDP && usage.accepting && usage.pending_items == 0u);
  }
  state.probe_adoption = true;
  CHECK(ftun_packet_init(&empty, &fixture.empty, 1u) == FTUN_OK);
  CHECK(ftun_packet_init(&packet, &fixture.bytes, 2u) == FTUN_OK);
  CHECK(ftun_channel_send(data_channel(state.path), &state.spec.endpoint, &empty) == FTUN_OK);
  CHECK(ftun_datagram_send_view(state.send, &target, &pending) == FTUN_OK &&
        target->port == 53u && pending->source_id == 1u);
  CHECK(ftun_packet_view(pending, &bytes) == FTUN_OK && bytes.length == 0u);
  CHECK(ftun_datagram_send_complete(state.send, success) == FTUN_OK);
  CHECK(state.completions == 1u && state.failures == 0u);
  CHECK(ftun_channel_deliver(data_channel(state.path), &state.spec.endpoint, &empty) == FTUN_OK &&
        state.received == 1u && state.received_length == 0u);
  CHECK(ftun_channel_send(data_channel(state.path), &state.spec.endpoint, &packet) == FTUN_OK);
  late = state.send;
  CHECK(ftun_channel_send(data_channel(state.path), &state.spec.endpoint, &empty) == FTUN_E_LIMIT);
  CHECK(ftun_datagram_send_view(late, &target, &pending) == FTUN_OK &&
        pending->source_id == 2u);
  CHECK(ftun_packet_view(pending, &bytes) == FTUN_OK && bytes.length == 8u &&
        memcmp(bytes.data, "abcdefgh", 8u) == 0);
  state.probe_revoke = revoke_from_receive;
  CHECK(ftun_channel_deliver(data_channel(state.path), &state.spec.endpoint, &packet) == FTUN_OK &&
        state.received == 2u && state.received_length == 8u);
  CHECK(state.cancels == 0u && state.failures == 0u);
  state.probe_revoke = true;
  state.cancel_status = FTUN_E_IO;
  CHECK(ftun_path_revoke(state.path) == FTUN_E_IO && state.cancels == 1u);
  CHECK(ftun_datagram_send_view(late, &target, &pending) == FTUN_OK);
  CHECK(ftun_path_destroy(&state.path) == FTUN_E_AGAIN);
  CHECK(ftun_channel_deliver(data_channel(state.path), &state.spec.endpoint, &packet) ==
        FTUN_E_CANCELLED && state.received == 2u);
  CHECK(ftun_channel_send(data_channel(state.path), &state.spec.endpoint, &packet) == FTUN_E_CANCELLED);
  state.cancel_status = FTUN_OK;
  CHECK(ftun_path_revoke(state.path) == FTUN_OK && state.cancels == 2u &&
        state.completions == 2u && state.cancellations == 1u && state.failures == 0u);
  CHECK(ftun_path_revoke(state.path) == FTUN_OK && state.cancels == 2u);
  CHECK(ftun_datagram_send_complete(late, success) == FTUN_E_STALE);
  CHECK(ftun_path_destroy(&state.path) == FTUN_OK && state.path == NULL &&
        state.destroyed == 1u && state.failures == 0u);
  ftun_packet_release(&empty);
  ftun_packet_release(&packet);
  CHECK(cleanup(&fixture) == 0);
  return 0;
}

static int no_view_case(bool datagram)
{
  fixture_t fixture;
  channel_t state;
  ftun_path_info_t info;
  ftun_path_t *alias;
  CHECK(setup(&fixture) == 0 && create(&fixture, &state, datagram) == 0);
  state.spec.network_view = NULL;
  if (datagram) {
    ftun_datagram_t *owner = state.datagram;
    CHECK(ftun_path_adopt_datagram(&state.spec, &owner, &state.path) == FTUN_OK &&
          owner == NULL);
  } else {
    ftun_stream_t *owner = state.stream;
    CHECK(ftun_path_adopt_stream(&state.spec, &owner, &state.path) == FTUN_OK &&
          owner == NULL);
  }
  CHECK(ftun_path_get_info(state.path, &info) == FTUN_OK &&
        info.network_view == NULL && info.network_generation == 0u &&
        info.configuration_generation == 7u && info.domain == FTUN_DIAL_DOMAIN_UNDERLAY);
  alias = state.path;

  CHECK(ftun_path_retain(state.path) == FTUN_OK);
  ftun_path_release(&alias); CHECK(alias == NULL);
  CHECK(ftun_path_destroy(&state.path) == FTUN_E_AGAIN);
  CHECK(ftun_path_revoke(state.path) == FTUN_OK);
  CHECK(ftun_path_destroy(&state.path) == FTUN_OK && state.path == NULL &&
        state.destroyed == 1u && state.failures == 0u);
  CHECK(ftun_path_destroy(&state.path) == FTUN_OK);
  CHECK(cleanup(&fixture) == 0);
  return 0;
}

int main(void)
{
  CHECK(stream_case() == 0);
  CHECK(datagram_case(false) == 0);
  CHECK(datagram_case(true) == 0);
  CHECK(no_view_case(false) == 0);
  CHECK(no_view_case(true) == 0);
  puts("Owned path result contract passed: five lifecycle scenarios");
  return 0;
}
