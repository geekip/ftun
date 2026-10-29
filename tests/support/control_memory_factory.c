#include "libs/transport/socket_path.h"
#include "libs/resolver/resolver.h"
#include "frs_fixture.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  ftun_reservation_t reservation;
  ftun_event_loop_t *loop;
  ftun_budget_t *budget;
  ftun_datagram_t *datagram;
  ftun_path_t *path;
  ftun_path_completion_fn completion;
  void *user;
  ftun_path_notify_fn notify;
  void *notify_user;
  ftun_stream_write_token_t write;
  bool pending;
  bool stopped;
  size_t request_length, response_length, offset;
  char request[4096];
  uint8_t response[8192];
} memory_t;

static void flush(void *user)
{
  memory_t *state = user;
  ftun_path_t *held = state->path;
  ftun_stream_write_token_t write = state->write;
  if (ftun_path_retain(held) != FTUN_OK) abort();
  state->pending = false;
  memset(&state->write, 0, sizeof(state->write));
  (void)ftun_stream_write_complete(write,
    (ftun_error_t){state->stopped ? FTUN_E_CANCELLED : FTUN_OK, 0u, 0});
  if (state->notify != NULL) {
    state->notify(state->path, FTUN_PATH_READABLE | FTUN_PATH_WRITABLE,
      (ftun_error_t){FTUN_OK, 0u, 0}, state->notify_user);
  }
  ftun_path_release(&held);
}

static ftun_status_t stop(void *user)
{
  memory_t *state = user;
  state->stopped = true;
  return state->pending ? FTUN_E_AGAIN : FTUN_OK;
}

static ftun_status_t read_bytes(void *user, void *buffer, size_t capacity, size_t *length)
{
  memory_t *state = user;
  *length = 0u;
  if (state->stopped) return FTUN_E_CANCELLED;
  if (state->response_length == 0u) return FTUN_E_AGAIN;
  if (state->offset == state->response_length) return FTUN_E_EOF;
  if (capacity > 5u) capacity = 5u;
  if (capacity > state->response_length - state->offset) capacity = state->response_length - state->offset;
  memcpy(buffer, state->response + state->offset, capacity);
  state->offset += capacity;
  *length = capacity;
  return FTUN_OK;
}

static ftun_status_t write_bytes(void *user, ftun_stream_write_token_t write,
  const ftun_buffer_slice_t *slice, size_t *accepted)
{
  memory_t *state = user;
  ftun_bytes_t bytes;
  ftun_status_t status;
  *accepted = 0u;
  if (state->pending) return FTUN_E_AGAIN;
  status = ftun_buffer_slice_data(slice, &bytes);
  if (status != FTUN_OK) return status;
  if (bytes.length > 3u) bytes.length = 3u;
  if (bytes.length >= sizeof(state->request) - state->request_length) return FTUN_E_LIMIT;
  status = ftun_event_defer(state->loop, flush, state);
  if (status != FTUN_OK) return status;
  memcpy(state->request + state->request_length, bytes.data, bytes.length);
  state->request_length += bytes.length;
  state->request[state->request_length] = '\0';
  if (strstr(state->request, "\r\n\r\n") != NULL) {
    uint8_t *body = NULL;
    size_t length = 0u;
    int header;
    if (ftun_test_frs_fixture(&body, &length) == 0) abort();
    header = snprintf((char *)state->response, sizeof(state->response),
      "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\nETag: \"memory-frs\"\r\n\r\n", length);
    if (header <= 0 || (size_t)header + length > sizeof(state->response)) abort();
    memcpy(state->response + header, body, length);
    state->response_length = (size_t)header + length;
    free(body);
  }
  state->write = write;
  state->pending = true;
  *accepted = bytes.length;
  return FTUN_OK;
}

static ftun_status_t cancel(void *user, ftun_stream_write_token_t write)
{
  memory_t *state = user;
  (void)write;
  return state->pending ? FTUN_E_AGAIN : FTUN_OK;
}

static ftun_status_t shutdown_write(void *user)
{
  (void)user;
  return FTUN_OK;
}

static ftun_status_t send_packet(void *user, ftun_datagram_send_token_t token,
  const ftun_endpoint_t *target, const ftun_packet_t *packet)
{
  memory_t *state = user;
  ftun_bytes_t query;
  ftun_buffer_t *buffer = NULL;
  ftun_packet_t response = {0};
  uint8_t *bytes;
  size_t capacity;
  bool negative;
  const uint8_t record[] = {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 7};
  ftun_status_t status = ftun_packet_view(packet, &query);
  if (status != FTUN_OK) return status;
  if (query.length < 17u || query.length > 512u || query.data[4] != 0u ||
      query.data[5] != 1u || target->port != 53u) return FTUN_E_PROTOCOL;
  negative = query.length == 30u && memcmp(query.data + 12u, "\7missing\4test\0", 14u) == 0;
  if (!negative && !((query.length == 28u && memcmp(query.data + 12u, "\5rules\4test\0", 12u) == 0) ||
        (query.length == 29u && memcmp(query.data + 12u, "\6health\4test\0", 13u) == 0))) return FTUN_E_REJECTED;
  status = ftun_buffer_acquire(state->budget, query.length + sizeof(record), &buffer);
  if (status == FTUN_OK) status = ftun_buffer_data(buffer, &bytes, &capacity);
  if (status == FTUN_OK) {
    memcpy(bytes, query.data, query.length);
    bytes[2] = 0x81u;
    bytes[3] = negative ? 0x83u : 0x80u;
    bytes[6] = 0u;
    bytes[7] = (uint8_t)(negative ? 0u : 1u);
    memcpy(bytes + query.length, record, sizeof(record));
    status = ftun_buffer_slice(buffer, 0u, query.length + (negative ? 0u : sizeof(record)), &response.payload);
  }
  if (status == FTUN_OK) status = ftun_datagram_deliver(state->datagram, target, &response);
  ftun_packet_release(&response);
  ftun_buffer_release(&buffer);
  if (status != FTUN_OK) return status;
  if (negative) fprintf(stderr, "control memory dns negative\n");
  return ftun_datagram_send_complete(token, (ftun_error_t){FTUN_OK, 0u, 0});
}

static ftun_status_t cancel_packet(void *user, ftun_datagram_send_token_t token)
{
  (void)user;
  (void)token;
  return FTUN_OK;
}

static void destroy(void *user)
{
  memory_t *state = user;
  ftun_reservation_t reservation = state->reservation;
  free(state);
  ftun_reservation_release(&reservation);
}

static void opened(ftun_operation_t *operation, ftun_error_t error, void *user)
{
  memory_t *state = user;
  state->completion(operation, error, state->path, state->user);
}

ftun_status_t __wrap_ftun_socket_path_open(void *context, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *spec,
  ftun_operation_t **out)
{
  memory_t *state;
  ftun_stream_t *stream = NULL;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_stream_backend_t backend = {0};
  ftun_stream_options_t options = request->stream;
  ftun_path_spec_t adopted = *spec;
  ftun_operation_token_t token;
  ftun_status_t status;
  (void)context; (void)core;
  *out = NULL;
  if ((request->dial.transport != FTUN_DIAL_TCP && request->dial.transport != FTUN_DIAL_UDP) ||
      (request->dial.purpose != FTUN_DIAL_PURPOSE_FRS_UPDATE &&
       request->dial.purpose != FTUN_DIAL_PURPOSE_PROBE)) return FTUN_E_REJECTED;
  fprintf(stderr, "control memory purpose=%u generation=%" PRIu64 " transport=%u\n",
    (unsigned)request->dial.purpose, spec->configuration_generation, (unsigned)request->dial.transport);
  status = ftun_budget_reserve(request->dial.budget, sizeof(*state), &reservation);
  if (status != FTUN_OK) return status;
  state = calloc(1u, sizeof(*state));
  if (state == NULL) { ftun_reservation_release(&reservation); return FTUN_E_LIMIT; }
  state->reservation = reservation;
  state->budget = request->dial.budget;
  state->loop = request->dial.loop;
  state->completion = request->completion;
  state->user = request->user;
  state->notify = request->notify;
  state->notify_user = request->notify_user;
  backend.context = state;
  backend.read = read_bytes;
  backend.write_start = write_bytes;
  backend.write_cancel = cancel;
  backend.shutdown_write = shutdown_write;
  backend.destroy = destroy;
  options.budget = request->dial.budget;
  options.operations = request->dial.operations;
  adopted.driver.stop = stop;
  adopted.driver.resume = shutdown_write;
  adopted.driver.context = state;
  if (request->dial.transport == FTUN_DIAL_UDP) {
    ftun_datagram_backend_t datagram_backend = {send_packet, cancel_packet, destroy, state};
    ftun_datagram_options_t datagram_options = request->datagram;
    ftun_datagram_t *datagram = NULL;
    datagram_options.budget = state->budget;
    status = ftun_datagram_create(&datagram_options, &datagram_backend, &datagram);
    if (status != FTUN_OK) { destroy(state); return status; }
    state->datagram = datagram;
    status = ftun_path_adopt_datagram(&adopted, &datagram, &state->path);
    if (status != FTUN_OK) {
      (void)ftun_datagram_stop(datagram);
      (void)ftun_datagram_destroy(&datagram);
      return status;
    }
  } else {
    status = ftun_stream_create(&options, &backend, &stream);
    if (status != FTUN_OK) { destroy(state); return status; }
    status = ftun_path_adopt_stream(&adopted, &stream, &state->path);
    if (status != FTUN_OK) {
      (void)ftun_stream_abort(stream);
      (void)ftun_stream_destroy(&stream);
      return status;
    }
  }
  status = ftun_operation_accept(request->dial.operations, opened, state, out, &token);
  if (status != FTUN_OK) {
    ftun_path_t *path = state->path;
    (void)ftun_path_revoke(path);
    (void)ftun_path_destroy(&path);
    return status;
  }
  return ftun_operation_complete(token, (ftun_error_t){FTUN_OK, 0u, 0});
}

ftun_status_t __real_ftun_resolver_provider_start(ftun_resolver_provider_t *,
  ftun_core_t *, const ftun_resolver_provider_request_t *, ftun_operation_t **);
ftun_status_t __wrap_ftun_resolver_provider_start(ftun_resolver_provider_t *provider,
  ftun_core_t *core, const ftun_resolver_provider_request_t *request, ftun_operation_t **out)
{
  fprintf(stderr, "control resolver purpose=%u generation=%" PRIu64 " source=%u\n",
    (unsigned)request->purpose, request->generation, (unsigned)request->source);
  return __real_ftun_resolver_provider_start(provider, core, request, out);
}
