/* 真实 DNS server 与非 socket 通道，验证异步接纳后的取消和停止拥有权。 */
#define _GNU_SOURCE 1
#include "util/time.h"
static uint64_t fanout_now_ms;
static ftun_status_t fanout_monotonic_now(uint64_t *out)
{
  if (fanout_now_ms == 0u) return ftun_monotonic_now(out);
  *out = fanout_now_ms;
  return FTUN_OK;
}
#define ftun_monotonic_now fanout_monotonic_now
#include "dns/service.c"
#undef ftun_monotonic_now
#include "memory_path_factory.c"
#include "core/context.h"
#include "event/libev_adapter.h"

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "DNS path lifecycle failed: %s:%d: %s\n", __FILE__, __LINE__, #x); \
  return 1; } } while (0)

typedef struct {
  ftun_budget_t *budget;
  ftun_operation_queue_t *operations;
  ftun_core_t *core;
  ftun_event_loop_t *loop;
  ftun_config_t *config;
  ftun_dns_runtime_t *dns;
  ftun_budget_usage_t baseline;
  size_t calls;
  ftun_status_t status;
  size_t path_opens;
} fixture_t;

static ftun_status_t fixture_path_open(void *user, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *spec,
  ftun_operation_t **out)
{
  fixture_t *f = user;
  f->path_opens++;
  return __wrap_ftun_socket_path_open(NULL, core, request, spec, out);
}

static int fixture_open_capacity(fixture_t *f, bool tcp, size_t capacity,
                                  size_t memory_bytes)
{
  char json[512];
  int length;
  ftun_dns_runtime_network_t network = {0};
  memset(f, 0, sizeof(*f));
  CHECK(ftun_budget_create(NULL, memory_bytes, 1024u, &f->budget) == FTUN_OK);
  CHECK(ftun_operation_queue_create(f->budget, capacity, &f->operations) == FTUN_OK);
  CHECK(ftun_core_context_create(f->budget, &f->core) == FTUN_OK);
  CHECK(ftun_event_loop_create_with_capacity(f->core, 128u, &f->loop) == FTUN_OK);
  CHECK(ftun_libev_attach(f->loop) == FTUN_OK);
  CHECK(ftun_budget_get_usage(f->budget, &f->baseline) == FTUN_OK);
  length = snprintf(json, sizeof(json),
    "{\"dns\":{\"enable\":true,\"cache\":false,\"default-server\":\"real\","
    "\"servers\":[{\"name\":\"real\",\"type\":\"%s\","
    "\"address\":[\"192.0.2.53:53\"],\"outbound\":\"DIRECT\"}]}}", tcp ? "tcp" : "udp");
  CHECK(length > 0 && (size_t)length < sizeof(json));
  CHECK(ftun_config_parse((ftun_bytes_t){(const uint8_t *)json, (size_t)length}, &f->config) == FTUN_OK);
  network.generation = 1u;
  network.path.open = fixture_path_open;
  network.context = f;
  CHECK(ftun_dns_runtime_prepare(f->core, f->budget, f->operations, f->loop,
    f->config, NULL, &network, &f->dns) == FTUN_OK);
  CHECK(ftun_dns_runtime_activate(f->dns) == FTUN_OK);
  return 0;
}

static int fixture_open(fixture_t *f, bool tcp)
{
  return fixture_open_capacity(f, tcp, 64u, 8u * 1024u * 1024u);
}

static void query_done(ftun_operation_t *operation, ftun_error_t error,
  ftun_bytes_t response, void *user)
{
  fixture_t *f = user;
  (void)operation; (void)response;
  f->calls++;
  f->status = error.status;
}

static int query_begin(fixture_t *f, ftun_operation_t **operation)
{
  static const uint8_t wire[] = {
    0u, 100u, 1u, 0u, 0u, 1u, 0u, 0u, 0u, 0u, 0u, 0u,
    1u, 'a', 7u, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0u, 0u, 1u, 0u, 1u
  };
  ftun_dns_query_t query = {0};
  query.id = 100u;
  query.flags = 0x100u;
  query.resolution_mode = 1u;
  query.question.name = (ftun_dns_name_t){wire + 12u, 11u};
  query.question.type = 1u;
  query.question.class_code = 1u;
  query.wire = (ftun_bytes_t){wire, sizeof(wire)};
  query.deadline_ms = ftun_dns_runtime_now(NULL) + 3000u;
  query.completion = query_done;
  query.completion_user = f;
  CHECK(ftun_dns_exchange(f->core, f->dns->servers[0], &query, operation) == FTUN_OK);
  CHECK(f->dns->request_count == 1u && f->dns->request_head->opening != NULL);
  return 0;
}

static int progress(fixture_t *f)
{
  size_t work;
  CHECK(ftun_event_loop_run_once(f->loop, false, 64u, &work) == FTUN_OK);
  CHECK(ftun_operation_dispatch(f->operations, 64u, &work) == FTUN_OK);
  return 0;
}

static int fixture_close(fixture_t *f, size_t calls, ftun_status_t expected)
{
  ftun_status_t status = FTUN_E_AGAIN;
  ftun_budget_usage_t usage;
  ftun_event_loop_usage_t events;
  size_t tries;
  for (tries = 0u; tries < 64u && status == FTUN_E_AGAIN; tries++) {
    CHECK(progress(f) == 0);
    status = ftun_dns_runtime_destroy(&f->dns);
  }
  CHECK(status == FTUN_OK && f->dns == NULL);
  CHECK(progress(f) == 0);
  CHECK(f->calls == calls && f->status == expected);
  CHECK(ftun_config_destroy(&f->config) == FTUN_OK);
  CHECK(ftun_budget_get_usage(f->budget, &usage) == FTUN_OK);
  CHECK(usage.used == f->baseline.used &&
        usage.metadata_bytes == f->baseline.metadata_bytes &&
        usage.used_resources.descriptors == f->baseline.used_resources.descriptors &&
        usage.used_resources.queue_slots == f->baseline.used_resources.queue_slots);
  CHECK(ftun_event_loop_get_usage(f->loop, &events) == FTUN_OK && events.source_count == 0u);
  CHECK(ftun_event_loop_stop(f->loop) == FTUN_OK);
  CHECK(ftun_libev_detach(f->loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&f->loop) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&f->core) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(f->operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&f->operations) == FTUN_OK);
  CHECK(ftun_budget_destroy(&f->budget) == FTUN_OK);
  return 0;
}

static int pending_case(bool tcp, bool writing, bool cancel)
{
  fixture_t f;
  ftun_operation_t *operation = NULL;
  ftun_dns_runtime_transport_request_t *request;
  size_t work;
  CHECK(fixture_open(&f, tcp) == 0);
  CHECK(query_begin(&f, &operation) == 0);
  request = f.dns->request_head;
  if (writing) {
    CHECK(ftun_operation_dispatch(f.operations, 64u, &work) == FTUN_OK);
    CHECK(ftun_dns_runtime_run_once(f.dns, 1u, &work) == FTUN_OK);
    CHECK(request->write_pending && request->opening == NULL);
  }
  if (cancel) CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  else CHECK(ftun_dns_runtime_stop_until(f.dns,
    ftun_dns_runtime_now(NULL) + 1000u) == FTUN_E_AGAIN);
  CHECK(f.dns->request_count == 1u && f.dns->request_head == request && request->closing);
  CHECK(fixture_close(&f, 1u, FTUN_E_CANCELLED) == 0);
  return 0;
}

typedef struct {
  size_t *total;
  size_t calls;
  uint16_t id;
  ftun_status_t status;
  bool valid;
} fanout_query_t;

static void fanout_done(ftun_operation_t *operation, ftun_error_t error,
  ftun_bytes_t response, void *user)
{
  fanout_query_t *query = user;
  (void)operation;
  query->calls++;
  (*query->total)++;
  query->status = error.status;
  query->valid = error.status == FTUN_OK && response.length >= 12u &&
    response.data[0] == (uint8_t)(query->id >> 8u) &&
    response.data[1] == (uint8_t)query->id;
}

static int fanout_begin(fixture_t *f, fanout_query_t *state, bool cold,
                         ftun_operation_t **out)
{
  uint8_t wire[] = {
    0u, 0u, 1u, 0u, 0u, 1u, 0u, 0u, 0u, 0u, 0u, 0u,
    1u, 'a', 7u, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0u, 0u, 1u, 0u, 1u
  };
  ftun_dns_query_t query = {0};
  wire[0] = (uint8_t)(state->id >> 8u);
  wire[1] = (uint8_t)state->id;
  if (cold) wire[13] = 'b';
  query.id = state->id;
  query.flags = 0x100u;
  query.resolution_mode = 1u;
  query.question.name = (ftun_dns_name_t){wire + 12u, 11u};
  query.question.type = 1u;
  query.question.class_code = 1u;
  query.wire = (ftun_bytes_t){wire, sizeof(wire)};
  query.deadline_ms = ftun_dns_runtime_now(NULL) + (cold ? 300000u : 30000u);
  query.completion = fanout_done;
  query.completion_user = state;
  CHECK(ftun_dns_exchange(f->core, f->dns->servers[0], &query, out) == FTUN_OK);
  return 0;
}

static int fanout_case(bool tcp, bool truncated, size_t quota)
{
  enum { HOT = 1000 };
  fixture_t f;
  fanout_query_t queries[HOT + 1u] = {{0}};
  ftun_operation_t *operations[HOT + 1u] = {NULL};
  size_t total = 0u, round, index, work, committed_round = 0u;
  size_t max_callbacks = 0u, cold_round = SIZE_MAX;
  bool committed = false, cold_progress = false;
  CHECK(fixture_open_capacity(&f, tcp, 2048u,
    128u * 1024u * 1024u) == 0);
  for (index = 0u; index <= HOT; index++) {
    queries[index].id = (uint16_t)((index + 1u) * 2u + (truncated ? 1u : 0u));
    queries[index].total = &total;
    if (index < HOT) CHECK(fanout_begin(&f, &queries[index], false, &operations[index]) == 0);
  }
  queries[HOT].id = (uint16_t)((HOT + 1u) * 2u);
  CHECK(f.dns->request_count == 1u && f.dns->waiter_count == HOT);
  for (round = 0u; round < 8192u && total != HOT + 1u; round++) {
    size_t before = total;
    ftun_dns_runtime_transport_request_t *candidate = NULL, *request;
    CHECK(ftun_dns_runtime_run_once(f.dns, quota, &work) == FTUN_OK && work <= quota);
    CHECK(progress(&f) == 0);
    if (total - before > max_callbacks) max_callbacks = total - before;
    if (queries[HOT].calls != 0u && cold_round == SIZE_MAX) cold_round = round;
    if (queries[HOT].calls != 0u) cold_progress = true;
    CHECK(total - before <= quota);
    for (request = f.dns->request_head; request != NULL; request = request->next) {
      if (request->query[13] == 'b' && request->state != FTUN_DNS_RUNTIME_REQUEST_CONNECT) {
        cold_progress = true;
      }
      if (candidate == NULL && request->closing && request->waiter_head != NULL && request->query[13] == 'a' &&
          (!truncated || (request->transport == FTUN_DNS_TRANSPORT_TCP &&
           request->fallback_parent != NULL && request->fallback_parent->waiter_head == NULL))) {
        candidate = request;
      }
    }
    if (!committed && candidate != NULL) {
      committed = true;
      committed_round = round;
      CHECK(fanout_begin(&f, &queries[HOT], true, &operations[HOT]) == 0);
      CHECK(ftun_dns_runtime_quiesce(f.dns) == FTUN_OK);
      /* 响应已提交后再跨越期限，不得把排队交付改为超时。 */
      fanout_now_ms = ftun_dns_runtime_now(NULL) + 60000u;
    }
    if (committed && round - committed_round >= 16u) CHECK(cold_progress);
  }
  CHECK(committed && total == HOT + 1u && queries[HOT].calls == 1u);
  CHECK(f.path_opens == (truncated ? 3u : 2u));
  for (index = 0u; index <= HOT; index++) CHECK(queries[index].calls == 1u && queries[index].valid);
  fanout_now_ms = 0u;
  CHECK(fixture_close(&f, 0u, FTUN_OK) == 0);
  printf("DNS fanout: tcp=%u truncated=%u quota=%zu queries=%u rounds=%zu max_callbacks=%zu cold_round=%zu paths=%zu\n",
    tcp ? 1u : 0u, truncated ? 1u : 0u, quota, HOT + 1u,
    round, max_callbacks, cold_round, f.path_opens);
  return 0;
}

typedef struct {
  fixture_t *fixture;
  void **cancel_other;
  size_t calls;
  ftun_status_t expected;
  bool reenter;
  bool payload;
  bool valid;
} direct_waiter_t;

static bool expired_in_callback(fixture_t *f)
{
  static const uint8_t wire[] = {
    0u, 2u, 1u, 0u, 0u, 1u, 0u, 0u, 0u, 0u, 0u, 0u,
    1u, 'a', 7u, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0u, 0u, 1u, 0u, 1u
  };
  ftun_dns_query_t query = {0};
  ftun_operation_t *rejected = NULL;
  ftun_status_t status;
  uint64_t previous = fanout_now_ms;
  query.id = 2u;
  query.flags = 0x100u;
  query.resolution_mode = 1u;
  query.question.name = (ftun_dns_name_t){wire + 12u, 11u};
  query.question.type = 1u;
  query.question.class_code = 1u;
  query.wire = (ftun_bytes_t){wire, sizeof(wire)};
  query.deadline_ms = ftun_dns_runtime_now(NULL) + 1000u;
  query.completion = query_done;
  query.completion_user = f;
  fanout_now_ms = query.deadline_ms + 60000u;
  status = ftun_dns_exchange(f->core, f->dns->servers[0], &query, &rejected);
  fanout_now_ms = previous;
  return status == FTUN_E_TIMEOUT && rejected == NULL;
}

static void direct_done(void *user, ftun_status_t status,
  ftun_dns_transport_t transport, const ftun_endpoint_t *source,
  ftun_bytes_t response)
{
  direct_waiter_t *state = user;
  fixture_t *f = state->fixture;
  size_t work = SIZE_MAX;
  (void)transport; (void)source;
  state->calls++;
  state->valid = status == state->expected && (state->payload
    ? response.length == 12u && response.data[11] == 0xa5u : response.length == 0u);
  if (state->reenter) {
    state->valid = state->valid &&
      ftun_dns_runtime_run_once(f->dns, 1u, &work) == FTUN_E_AGAIN && work == 0u &&
      ftun_dns_runtime_stop_until(f->dns, ftun_dns_runtime_now(NULL) + 1000u) == FTUN_E_AGAIN &&
      ftun_dns_runtime_destroy(&f->dns) == FTUN_E_AGAIN && f->dns != NULL;
    if (state->cancel_other != NULL) {
      state->valid = state->valid &&
        ftun_dns_runtime_transport_cancel(f->dns, state->cancel_other) == FTUN_OK &&
        *state->cancel_other == NULL;
    }
    if (state->payload) state->valid = state->valid &&
      response.data[11] == 0xa5u && expired_in_callback(f);
  }
}

static int direct_begin(fixture_t *f, ftun_dns_runtime_transport_request_t *request,
  direct_waiter_t *state, uint16_t id, void **out)
{
  uint8_t wire[2] = {(uint8_t)(id >> 8u), (uint8_t)id};
  ftun_dns_runtime_transport_waiter_t *waiter = NULL;
  state->fixture = f;
  CHECK(ftun_dns_runtime_waiter_create(f->dns, request,
    (ftun_bytes_t){wire, sizeof(wire)}, ftun_dns_runtime_now(NULL) + 30000u,
    direct_done, state, &waiter) == FTUN_OK);
  *out = waiter;
  return 0;
}

static int fanout_stop_case(void)
{
  enum { EXTRA = 1023 };
  fixture_t f;
  direct_waiter_t states[EXTRA] = {{0}};
  void *handles[EXTRA] = {NULL};
  ftun_operation_t *operation = NULL;
  ftun_dns_runtime_transport_request_t *request;
  ftun_status_t status = FTUN_E_AGAIN;
  size_t index, round, total = 0u;
  uint64_t deadline;
  CHECK(fixture_open(&f, false) == 0);
  CHECK(query_begin(&f, &operation) == 0);
  request = f.dns->request_head;
  for (index = 0u; index < EXTRA; index++) {
    states[index].expected = FTUN_E_CANCELLED;
    CHECK(direct_begin(&f, request, &states[index], (uint16_t)(index + 1u), &handles[index]) == 0);
  }
  states[0].reenter = true;
  states[0].cancel_other = &handles[EXTRA - 1u];
  CHECK(ftun_dns_runtime_stop_until(f.dns, 1u) == FTUN_E_TIMEOUT);
  CHECK(f.dns->waiter_count == EXTRA + 1u && states[0].calls == 0u);
  deadline = ftun_dns_runtime_now(NULL) + 10000u;
  for (round = 0u; round < 256u && status == FTUN_E_AGAIN; round++) {
    size_t before = total + f.calls;
    status = ftun_dns_runtime_stop_until(f.dns, deadline);
    CHECK(status == FTUN_OK || status == FTUN_E_AGAIN);
    CHECK(progress(&f) == 0);
    total = 0u;
    for (index = 0u; index < EXTRA; index++) total += states[index].calls;
    CHECK(total + f.calls - before <= 32u);
  }
  CHECK(status == FTUN_OK && total == EXTRA - 1u && handles[EXTRA - 1u] == NULL);
  for (index = 0u; index < EXTRA - 1u; index++) CHECK(states[index].calls == 1u && states[index].valid);
  CHECK(states[EXTRA - 1u].calls == 0u);
  CHECK(fixture_close(&f, 1u, FTUN_E_CANCELLED) == 0);
  return 0;
}

static int callback_lifetime_case(void)
{
  fixture_t f;
  direct_waiter_t states[2] = {{0}};
  void *handles[2] = {NULL};
  ftun_operation_t *operation = NULL;
  ftun_dns_runtime_transport_request_t *request;
  size_t work, index;
  CHECK(fixture_open(&f, false) == 0);
  CHECK(query_begin(&f, &operation) == 0);
  request = f.dns->request_head;
  for (index = 0u; index < 2u; index++) {
    states[index].expected = FTUN_OK;
    states[index].payload = true;
    CHECK(direct_begin(&f, request, &states[index], (uint16_t)(index + 1u), &handles[index]) == 0);
  }
  CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  CHECK(progress(&f) == 0);
  CHECK(request->opening == NULL && request->path != NULL && !request->write_pending);
  request->response_length = 12u;
  request->buffer[11] = 0xa5u;
  ftun_dns_runtime_request_finish(request, FTUN_OK);
  ftun_dns_runtime_request_ready_enqueue(request);
  states[0].reenter = true;
  states[0].cancel_other = &handles[1];
  CHECK(ftun_dns_runtime_run_once(f.dns, 1u, &work) == FTUN_OK && work == 1u);
  CHECK(states[0].calls == 1u && states[0].valid && states[1].calls == 0u && handles[1] == NULL);
  CHECK(fixture_close(&f, 1u, FTUN_E_CANCELLED) == 0);
  return 0;
}

static int fallback_stop_case(void)
{
  enum { QUERIES = 65 };
  fixture_t f;
  fanout_query_t queries[QUERIES] = {{0}};
  ftun_operation_t *operations[QUERIES] = {NULL};
  ftun_dns_runtime_transport_request_t *request;
  ftun_status_t status = FTUN_E_AGAIN;
  size_t index, round, work, total = 0u;
  bool fallback = false;
  uint64_t deadline;
  CHECK(fixture_open_capacity(&f, false, 128u, 16u * 1024u * 1024u) == 0);
  for (index = 0u; index < QUERIES; index++) {
    queries[index].id = (uint16_t)(index * 2u + 1u);
    queries[index].total = &total;
    CHECK(fanout_begin(&f, &queries[index], false, &operations[index]) == 0);
  }
  for (round = 0u; round < 128u && !fallback; round++) {
    CHECK(ftun_dns_runtime_run_once(f.dns, 1u, &work) == FTUN_OK);
    CHECK(progress(&f) == 0);
    for (request = f.dns->request_head; request != NULL; request = request->next) {
      if (request->fallback_parent != NULL) fallback = true;
    }
  }
  CHECK(fallback && f.path_opens == 2u && total == 0u);
  deadline = ftun_dns_runtime_now(NULL) + 10000u;
  for (round = 0u; round < 128u && status == FTUN_E_AGAIN; round++) {
    size_t before = total;
    status = ftun_dns_runtime_stop_until(f.dns, deadline);
    CHECK(status == FTUN_OK || status == FTUN_E_AGAIN);
    CHECK(progress(&f) == 0 && total - before <= 32u);
  }
  CHECK(status == FTUN_OK && total == QUERIES);
  for (index = 0u; index < QUERIES; index++) {
    CHECK(queries[index].calls == 1u && queries[index].status == FTUN_E_CANCELLED);
  }
  CHECK(fixture_close(&f, 0u, FTUN_OK) == 0);
  return 0;
}

int main(void)
{
  size_t tcp, writing, cancel;
  for (tcp = 0u; tcp < 2u; tcp++) {
    for (writing = 0u; writing < 2u; writing++) {
      for (cancel = 0u; cancel < 2u; cancel++) {
        CHECK(pending_case(tcp != 0u, writing != 0u, cancel != 0u) == 0);
      }
    }
  }
  CHECK(fanout_case(false, false, 8u) == 0);
  CHECK(fanout_case(true, false, 8u) == 0);
  CHECK(fanout_case(false, true, 1u) == 0);
  CHECK(fanout_case(false, false, 1u) == 0);
  CHECK(fanout_stop_case() == 0);
  CHECK(callback_lifetime_case() == 0);
  CHECK(fallback_stop_case() == 0);
  puts("DNS Path lifecycle: 8 lifecycle, 4 fanout, bounded stop, callback and fallback stop cases passed");
  return 0;
}
