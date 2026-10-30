#include <unistd.h>
#include "proxy/inbound/adapter.h"
#include "platform/clock.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "inbound adapter contract failed at %d: %s\n", __LINE__, #x); \
  return 1; } } while (0)

typedef struct {
  ftun_budget_t *budget;
  ftun_buffer_pool_t *pool;
  ftun_operation_queue_t *operations;
  ftun_stream_t *stream;
  ftun_inbound_adapter_t *adapter;
  ftun_stream_write_token_t token;
  const uint8_t *input;
  size_t length, offset, read_size, write_size, output_length;
  uint8_t output[2048];
  unsigned int reads, wakes, cancellations;
  ftun_status_t cancel_error;
  ftun_status_t write_error;
} fixture_t;

static ftun_status_t read_bytes(void *user, void *buffer, size_t capacity,
  size_t *length)
{
  fixture_t *f = user;
  size_t n = f->length - f->offset;
  *length = 0u;
  f->reads++;
  if (n == 0u) return FTUN_E_AGAIN;
  if (n > capacity) n = capacity;
  if (n > f->read_size) n = f->read_size;
  memcpy(buffer, f->input + f->offset, n);
  f->offset += n;
  *length = n;
  return FTUN_OK;
}

static ftun_status_t write_bytes(void *user, ftun_stream_write_token_t token,
  const ftun_buffer_slice_t *slice, size_t *accepted)
{
  fixture_t *f = user;
  *accepted = 0u;
  if (f->write_error != FTUN_OK) return f->write_error;
  if (f->token.stream != NULL) return FTUN_E_AGAIN;
  *accepted = slice->length < f->write_size ? slice->length : f->write_size;
  f->token = token;
  return FTUN_OK;
}

static ftun_status_t cancel_write(void *user, ftun_stream_write_token_t token)
{
  fixture_t *f = user;
  f->cancellations++;
  if (f->token.stream != token.stream || f->token.generation != token.generation)
    return FTUN_E_STATE_CORRUPT;
  if (f->cancel_error != FTUN_OK) return f->cancel_error;
  memset(&f->token, 0, sizeof(f->token));
  return FTUN_OK;
}

static void wake(void *user)
{
  fixture_t *f = user;
  f->wakes++;
}

static void backend_destroy(void *user)
{
  (void)user;
}

static void fallback_completed(ftun_operation_t *operation, ftun_error_t error, void *user)
{
  (void)operation;
  (void)error;
  (void)user;
}

static int setup_with_pool(fixture_t *f, ftun_inbound_kind_t kind, const void *input,
  size_t length, bool auth, size_t fragment, bool pooled)
{
  ftun_stream_options_t options = {0};
  ftun_stream_backend_t backend = {0};
  ftun_inbound_spec_t spec = {0};
  ftun_inbound_user_t credentials = {{(const uint8_t *)"u", 1u},
                                    {(const uint8_t *)"p", 1u}};
  uint64_t now;
  memset(f, 0, sizeof(*f));
  f->input = input;
  f->length = length;
  f->read_size = fragment;
  f->write_size = 1u;
  CHECK(ftun_budget_create(NULL, 262144u, 0u, &f->budget) == FTUN_OK);
  CHECK(ftun_operation_queue_create(f->budget, 8u, &f->operations) == FTUN_OK);
  options.completion = fallback_completed;
  options.budget = f->budget;
  options.operations = f->operations;
  options.max_pending_writes = 1u;
  options.max_pending_bytes = 2048u;
  backend.destroy = backend_destroy;
  backend.context = f;
  backend.read = read_bytes;
  backend.write_start = write_bytes;
  backend.write_cancel = cancel_write;
  CHECK(ftun_stream_create(&options, &backend, &f->stream) == FTUN_OK);
  spec.budget = f->budget;
  spec.kind = kind;
  spec.tcp = true;
  spec.udp = true;
  spec.users = auth ? &credentials : NULL;
  spec.user_count = auth ? 1u : 0u;
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  if (pooled) {
    CHECK(ftun_buffer_pool_create(f->budget, 4096u, 16u, &f->pool) == FTUN_OK);
    CHECK(ftun_inbound_adapter_create_with_pool(f->stream, &spec, f->pool,
      now + 10000u, 5000u, wake, f, &f->adapter) == FTUN_OK);
  } else CHECK(ftun_inbound_adapter_create(f->stream, &spec, now + 10000u,
    5000u, wake, f, &f->adapter) == FTUN_OK);
  return 0;
}

static int setup(fixture_t *f, ftun_inbound_kind_t kind, const void *input,
  size_t length, bool auth, size_t fragment)
{
  return setup_with_pool(f, kind, input, length, auth, fragment, false);
}

static int complete(fixture_t *f)
{
  ftun_bytes_t bytes;
  size_t dispatched;
  unsigned int wakes = f->wakes;
  if (f->token.stream != NULL) {
    CHECK(ftun_stream_write_data(f->token, &bytes) == FTUN_OK);
    CHECK(bytes.length <= sizeof(f->output) - f->output_length);
    memcpy(f->output + f->output_length, bytes.data, bytes.length);
    f->output_length += bytes.length;
    CHECK(ftun_stream_write_complete(f->token, (ftun_error_t){FTUN_OK, 0u, 0}) == FTUN_OK);
    memset(&f->token, 0, sizeof(f->token));
    CHECK(f->wakes == wakes);
  }
  CHECK(ftun_operation_dispatch(f->operations, 8u, &dispatched) == FTUN_OK);
  return 0;
}

static int cleanup(fixture_t *f)
{
  ftun_budget_usage_t usage;
  size_t dispatched;
  CHECK(ftun_inbound_adapter_stop(f->adapter) == FTUN_OK);
  CHECK(ftun_operation_dispatch(f->operations, 8u, &dispatched) == FTUN_OK);
  CHECK(ftun_inbound_adapter_destroy(&f->adapter) == FTUN_OK);
  CHECK(ftun_stream_abort(f->stream) == FTUN_OK);
  CHECK(ftun_stream_destroy(&f->stream) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(f->operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&f->operations) == FTUN_OK);
  CHECK(ftun_buffer_pool_destroy(&f->pool) == FTUN_OK);
  CHECK(ftun_budget_get_usage(f->budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u);
  CHECK(ftun_budget_destroy(&f->budget) == FTUN_OK);
  return 0;
}

static int until_event(fixture_t *f, ftun_inbound_event_t *event, ftun_status_t expected)
{
  size_t i;
  for (i = 0u; i < 4096u; i++) {
    ftun_status_t status = ftun_inbound_adapter_drive(f->adapter,
      f->offset != f->length, event);
    if (event->kind != FTUN_INBOUND_EVENT_NONE || (status != FTUN_OK && status != FTUN_E_AGAIN)) {
      CHECK(status == expected);
      return 0;
    }
    CHECK(complete(f) == 0);
  }
  fprintf(stderr, "inbound adapter did not produce an event\n");
  return 1;
}

static int drain(fixture_t *f)
{
  ftun_inbound_adapter_info_t info;
  ftun_inbound_event_t event;
  size_t i;
  for (i = 0u; i < 4096u; i++) {
    ftun_status_t status = ftun_inbound_adapter_drive(f->adapter, false, &event);
    CHECK(status == FTUN_OK || status == FTUN_E_AGAIN || status == FTUN_E_EOF);
    CHECK(event.kind == FTUN_INBOUND_EVENT_NONE && event.preread.owner == NULL);
    CHECK(complete(f) == 0);
    CHECK(ftun_inbound_adapter_get_info(f->adapter, &info) == FTUN_OK);
    if (!info.reply_pending) return 0;
  }
  CHECK(false);
  return 1;
}

static int socks(bool auth, size_t fragment, bool mixed, bool pooled)
{
  const uint8_t plain[] = {5,1,0, 5,1,0,1,127,0,0,1,0,80, 0,255,7,0,9};
  const uint8_t authenticated[] = {5,1,2, 1,1,'u',1,'p', 5,1,0,1,127,0,0,1,0,80, 0,255,7,0,9};
  fixture_t f;
  ftun_inbound_event_t event, next;
  ftun_inbound_adapter_info_t info;
  ftun_bytes_t bytes;
  ftun_endpoint_t bound = {0};
  const uint8_t *input = auth ? authenticated : plain;
  size_t length = auth ? sizeof(authenticated) : sizeof(plain);
  CHECK(setup_with_pool(&f, mixed ? FTUN_INBOUND_MIXED : FTUN_INBOUND_SOCKS5,
    input, length, auth, fragment, pooled) == 0);
  CHECK(until_event(&f, &event, FTUN_OK) == 0);
  CHECK(event.kind == FTUN_INBOUND_EVENT_CONNECT && event.target.port == 80u);
  CHECK(ftun_inbound_adapter_get_info(f.adapter, &info) == FTUN_OK &&
    info.waiting_downstream && info.deadline_ms == 0u);
  if (fragment >= length) {
    CHECK(ftun_buffer_slice_data(&event.preread, &bytes) == FTUN_OK &&
      bytes.length == 5u && memcmp(bytes.data, plain + sizeof(plain) - 5u, 5u) == 0);
    CHECK(f.reads == 1u);
  }
  CHECK(ftun_inbound_adapter_drive(f.adapter, true, &next) == FTUN_E_AGAIN &&
    next.kind == FTUN_INBOUND_EVENT_NONE);
  bound.kind = FTUN_ADDRESS_IPV4;
  bound.port = 1234u;
  CHECK(ftun_inbound_adapter_finish(f.adapter, FTUN_OK, &bound) == FTUN_OK);
  CHECK(ftun_inbound_adapter_finish(f.adapter, FTUN_OK, &bound) == FTUN_E_STALE);
  CHECK(drain(&f) == 0);
  CHECK(f.output_length == (auth ? 14u : 12u) && f.output[1] == (auth ? 2u : 0u));
  CHECK(f.output[f.output_length - 9u] == 0u);
  if (pooled) {
    ftun_buffer_pool_usage_t usage;
    CHECK(ftun_buffer_pool_get_usage(f.pool, &usage) == FTUN_OK && usage.cache_hits != 0u);
  }
  CHECK(ftun_inbound_adapter_stop(f.adapter) == FTUN_OK);
  CHECK(ftun_inbound_adapter_destroy(&f.adapter) == FTUN_OK);
  if (event.preread.owner != NULL) {
    if (pooled) CHECK(ftun_buffer_pool_destroy(&f.pool) == FTUN_E_AGAIN && f.pool != NULL);
    CHECK(ftun_buffer_slice_data(&event.preread, &bytes) == FTUN_OK && bytes.length <= 5u);
    ftun_buffer_slice_release(&event.preread);
  }
  /* 已拥有的预读在 adapter 销毁后仍有效。 */
  CHECK(ftun_stream_abort(f.stream) == FTUN_OK);
  CHECK(ftun_stream_destroy(&f.stream) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(f.operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&f.operations) == FTUN_OK);
  CHECK(ftun_buffer_pool_destroy(&f.pool) == FTUN_OK);
  CHECK(ftun_budget_destroy(&f.budget) == FTUN_OK);
  return 0;
}

static int rejection(const uint8_t *input, size_t length, bool auth,
  uint8_t expected, size_t reply_length)
{
  fixture_t f;
  ftun_inbound_event_t event;
  CHECK(setup(&f, FTUN_INBOUND_SOCKS5, input, length, auth, 1u) == 0);
  CHECK(until_event(&f, &event, FTUN_E_EOF) == 0);
  CHECK(event.kind == FTUN_INBOUND_EVENT_NONE && f.output_length == reply_length);
  CHECK(f.output[reply_length == 12u ? 3u : reply_length - 1u] == expected);
  CHECK(cleanup(&f) == 0);
  return 0;
}

static int http(const char *input, size_t length, const char *preread,
  size_t preread_length, bool forward, bool auth, ftun_status_t result)
{
  fixture_t f;
  ftun_inbound_event_t event;
  ftun_bytes_t bytes;
  CHECK(setup(&f, FTUN_INBOUND_MIXED, input, length, auth, 512u) == 0);
  if (auth) {
    CHECK(until_event(&f, &event, FTUN_E_EOF) == 0);
    CHECK(f.output_length > 12u && memcmp(f.output, "HTTP/1.1 407", 12u) == 0);
  } else {
    CHECK(until_event(&f, &event, FTUN_OK) == 0);
    CHECK(event.kind == FTUN_INBOUND_EVENT_CONNECT && event.target.port == 80u);
    CHECK(ftun_buffer_slice_data(&event.preread, &bytes) == FTUN_OK &&
      bytes.length == preread_length && memcmp(bytes.data, preread, preread_length) == 0);
    CHECK(ftun_inbound_adapter_finish(f.adapter, result, NULL) == (forward ? result : FTUN_OK));
    CHECK(drain(&f) == 0);
    if (forward) CHECK(f.output_length == 0u);
    else CHECK(f.output_length > 12u && memcmp(f.output,
      result == FTUN_OK ? "HTTP/1.1 200" :
      result == FTUN_E_REJECTED ? "HTTP/1.1 403" : "HTTP/1.1 502", 12u) == 0);
    ftun_buffer_slice_release(&event.preread);
  }
  CHECK(cleanup(&f) == 0);
  return 0;
}

static int cancel_pending(ftun_status_t failure)
{
  const uint8_t input[] = {5,1,0};
  fixture_t f;
  ftun_inbound_event_t event;
  size_t dispatched;
  unsigned int reads;
  CHECK(setup(&f, FTUN_INBOUND_SOCKS5, input, sizeof(input), false, 512u) == 0);
  CHECK(ftun_inbound_adapter_drive(f.adapter, true, &event) == FTUN_OK);
  CHECK(ftun_inbound_adapter_drive(f.adapter, true, &event) == FTUN_E_AGAIN);
  reads = f.reads;
  CHECK(ftun_inbound_adapter_drive(f.adapter, true, &event) == FTUN_E_AGAIN && f.reads == reads);
  f.cancel_error = failure;
  CHECK(ftun_inbound_adapter_stop(f.adapter) == failure);
  CHECK(ftun_inbound_adapter_destroy(&f.adapter) == FTUN_E_AGAIN && f.adapter != NULL);
  CHECK(ftun_inbound_adapter_drive(f.adapter, true, &event) == FTUN_E_CANCELLED);
  f.cancel_error = FTUN_OK;
  CHECK(ftun_inbound_adapter_stop(f.adapter) == FTUN_OK);
  CHECK(ftun_operation_dispatch(f.operations, 8u, &dispatched) == FTUN_OK && dispatched == 1u);
  CHECK(cleanup(&f) == 0);
  return 0;
}

static int reply_progress_without_extra_round(void)
{
  fixture_t f;
  const uint8_t input[] = {5, 1, 0};
  ftun_inbound_event_t event;
  ftun_status_t status;
  ftun_inbound_adapter_info_t info;
  CHECK(setup(&f, FTUN_INBOUND_SOCKS5, input, sizeof(input), false, 512u) == 0);
  status = ftun_inbound_adapter_drive(f.adapter, true, &event);
  CHECK(status == FTUN_OK || status == FTUN_E_AGAIN);
  CHECK(event.kind == FTUN_INBOUND_EVENT_NONE && f.reads == 1u);
  CHECK(f.token.stream != NULL && f.output_length == 0u);
  CHECK(ftun_inbound_adapter_get_info(f.adapter, &info) == FTUN_OK &&
        info.reply_pending && info.write_pending);
  CHECK(complete(&f) == 0);
  CHECK(ftun_inbound_adapter_get_info(f.adapter, &info) == FTUN_OK &&
        info.reply_pending && !info.write_pending);
  CHECK(drain(&f) == 0 && f.output_length == 2u &&
        memcmp(f.output, "\x05\x00", 2u) == 0);
  CHECK(cleanup(&f) == 0);
  CHECK(setup(&f, FTUN_INBOUND_SOCKS5, input, sizeof(input), false, 512u) == 0);
  f.write_error = FTUN_E_AGAIN;
  status = ftun_inbound_adapter_drive(f.adapter, true, &event);
  CHECK(status == FTUN_OK || status == FTUN_E_AGAIN);
  CHECK(f.token.stream == NULL && f.output_length == 0u);
  CHECK(ftun_inbound_adapter_get_info(f.adapter, &info) == FTUN_OK &&
        info.reply_pending && !info.write_pending);
  f.write_error = FTUN_OK;
  CHECK(ftun_inbound_adapter_drive(f.adapter, false, &event) == FTUN_E_AGAIN);
  CHECK(ftun_inbound_adapter_get_info(f.adapter, &info) == FTUN_OK &&
        info.reply_pending && info.write_pending);
  CHECK(cleanup(&f) == 0);
  return 0;
}

static int admission_and_deadline(void)
{
  fixture_t f;
  const uint8_t input[] = {5,1,0};
  ftun_inbound_spec_t spec = {0};
  ftun_inbound_adapter_t *other = NULL;
  ftun_budget_t *foreign = NULL, *small = NULL;
  ftun_buffer_pool_t *pool = NULL;
  ftun_budget_usage_t usage;
  ftun_inbound_event_t event;
  CHECK(setup(&f, FTUN_INBOUND_SOCKS5, input, sizeof(input), false, 512u) == 0);
  spec.kind = FTUN_INBOUND_MIXED;
  spec.tcp = true;
  CHECK(ftun_budget_create(NULL, 65536u, 0u, &foreign) == FTUN_OK);
  spec.budget = foreign;
  CHECK(ftun_inbound_adapter_create(f.stream, &spec, 1u, 1u, NULL, NULL, &other) ==
    FTUN_E_REJECTED && other == NULL);
  CHECK(ftun_buffer_pool_create(foreign, 4096u, 16u, &pool) == FTUN_OK);
  spec.budget = f.budget;
  CHECK(ftun_inbound_adapter_create_with_pool(f.stream, &spec, pool,
    1u, 1u, NULL, NULL, &other) == FTUN_E_REJECTED && other == NULL);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_OK);
  CHECK(ftun_budget_destroy(&foreign) == FTUN_OK);
  CHECK(ftun_budget_create(f.budget, 4096u, 0u, &small) == FTUN_OK);
  spec.budget = small;
  CHECK(ftun_inbound_adapter_create(f.stream, &spec, 1u, 1u, NULL, NULL, &other) ==
    FTUN_E_LIMIT && other == NULL);
  CHECK(ftun_budget_get_usage(small, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u);
  CHECK(ftun_budget_destroy(&small) == FTUN_OK);
  spec.budget = f.budget;
  CHECK(ftun_inbound_adapter_create(f.stream, &spec, 1u, 1u, NULL, NULL, &other) == FTUN_OK);
  CHECK(ftun_inbound_adapter_drive(other, true, &event) == FTUN_E_TIMEOUT && f.reads == 0u);
  CHECK(ftun_inbound_adapter_stop(other) == FTUN_OK);
  CHECK(ftun_inbound_adapter_destroy(&other) == FTUN_OK);
  CHECK(cleanup(&f) == 0);
  return 0;
}

static int udp_associate(bool mixed)
{
  fixture_t f;
  const uint8_t input[] = {5,1,0, 5,3,0,1,0,0,0,0,0,0};
  uint8_t packet[] = {0,0,0,1,127,0,0,1,0,53,0,255};
  ftun_inbound_event_t event;
  ftun_socks5_udp_datagram_t datagram;
  ftun_endpoint_t bound = {0};
  CHECK(setup(&f, mixed ? FTUN_INBOUND_MIXED : FTUN_INBOUND_SOCKS5,
    input, sizeof(input), false, 512u) == 0);
  CHECK(until_event(&f, &event, FTUN_OK) == 0 && event.kind == FTUN_INBOUND_EVENT_ASSOCIATE);
  CHECK(event.preread.owner == NULL);
  bound.kind = FTUN_ADDRESS_IPV4;
  bound.port = 1234u;
  CHECK(ftun_inbound_adapter_finish(f.adapter, FTUN_OK, &bound) == FTUN_OK);
  CHECK(drain(&f) == 0);
  CHECK(ftun_inbound_adapter_udp(f.adapter, (ftun_bytes_t){packet, sizeof(packet)},
    &datagram) == FTUN_OK && datagram.payload.length == 2u && datagram.payload.data[1] == 255u);
  packet[2] = 1u;
  CHECK(ftun_inbound_adapter_udp(f.adapter, (ftun_bytes_t){packet, sizeof(packet)},
    &datagram) == FTUN_E_UNSUPPORTED);
  CHECK(cleanup(&f) == 0);
  return 0;
}

int main(void)
{
  const uint8_t bad_auth[] = {5,1,2, 1,1,'u',1,'x'};
  const uint8_t no_method[] = {5,1,1};
  const uint8_t bind[] = {5,1,0,5,2,0,1,127,0,0,1,0,80};
  const char connect[] = "CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n\0\xffxyz";
  const char forward[] = "POST http://example.com/x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabcTAIL";
  const char rewritten[] = "POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabcTAIL";
  CHECK(socks(false, 512u, false, false) == 0);
  CHECK(socks(true, 512u, false, false) == 0);
  CHECK(socks(true, 1u, false, false) == 0);
  CHECK(socks(true, 512u, true, false) == 0);
  CHECK(socks(false, 512u, false, true) == 0);
  CHECK(socks(true, 512u, false, true) == 0);
  CHECK(socks(true, 1u, false, true) == 0);
  CHECK(socks(true, 512u, true, true) == 0);
  CHECK(rejection(bad_auth, sizeof(bad_auth), true, 1u, 4u) == 0);
  CHECK(rejection(no_method, sizeof(no_method), false, 255u, 2u) == 0);
  CHECK(rejection(bind, sizeof(bind), false, 7u, 12u) == 0);
  CHECK(http(connect, sizeof(connect)-1u, "\0\xffxyz", 5u, false, false, FTUN_OK) == 0);
  CHECK(http(connect, sizeof(connect)-1u, "\0\xffxyz", 5u, false, false, FTUN_E_REJECTED) == 0);
  CHECK(http(connect, sizeof(connect)-1u, "\0\xffxyz", 5u, false, false, FTUN_E_IO) == 0);
  CHECK(http(connect, sizeof(connect)-1u, NULL, 0u, false, true, FTUN_OK) == 0);
  CHECK(http(forward, sizeof(forward)-1u, rewritten, sizeof(rewritten)-1u, true, false, FTUN_OK) == 0);
  CHECK(admission_and_deadline() == 0);
  CHECK(reply_progress_without_extra_round() == 0);
  CHECK(udp_associate(false) == 0);
  CHECK(udp_associate(true) == 0);
  CHECK(cancel_pending(FTUN_OK) == 0);
  CHECK(cancel_pending(FTUN_E_AGAIN) == 0);
  CHECK(cancel_pending(FTUN_E_IO) == 0);
  puts("inbound adapter contract passed");
  return 0;
}
