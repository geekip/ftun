#include "core/budget.h"
#include "core/operation.h"
#include "proxy/runtime_state.h"
#include "dns/server.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "dns server contract failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  ftun_dns_transport_completion_fn completion;
  void *completion_user;
  ftun_endpoint_t upstream;
  ftun_dns_transport_t protocol;
  uint32_t outbound;
  uint64_t policy_fingerprint;
  uint64_t server_fingerprint;
  uint64_t deadline;
  unsigned int submits;
  unsigned int selects;
  uint32_t next_leaf;
  uint32_t submitted_leaf;
  ftun_status_t select_status;
  unsigned int cancels;
  int pending;
  ftun_status_t cancel_status;
  const uint8_t *cancel_response;
  size_t cancel_response_length;
} transport_t;

typedef struct {
  unsigned int calls;
  ftun_status_t status;
  uint32_t stage;
  uint8_t response[64];
  size_t response_length;
} completion_t;

static uint64_t fake_now(void *user)
{
  return *(uint64_t *)user;
}

static ftun_status_t transport_select(void *user, uint32_t root,
  ftun_dns_transport_binding_t *out)
{
  transport_t *transport = (transport_t *)user;
  memset(out, 0, sizeof(*out));
  transport->selects++;
  if (transport->select_status != FTUN_OK) return transport->select_status;
  out->scope = user;
  out->root_id = root;
  out->leaf_id = transport->next_leaf;
  return FTUN_OK;
}

static ftun_status_t transport_submit(
  void *user, const ftun_dns_transport_binding_t *binding,
  uint64_t policy_fingerprint,
  uint64_t server_fingerprint, const ftun_endpoint_t *upstream,
  ftun_dns_transport_t protocol, ftun_bytes_t query, uint64_t deadline,
  ftun_dns_transport_completion_fn completion, void *completion_user,
  void **out_request)
{
  transport_t *transport = (transport_t *)user;
  if (out_request != NULL) *out_request = NULL;
  if (transport == NULL || upstream == NULL || query.data == NULL ||
      query.length < 12u || completion == NULL || out_request == NULL ||
      transport->pending) return FTUN_E_INVALID;
  transport->completion = completion;
  transport->completion_user = completion_user;
  transport->upstream = *upstream;
  transport->protocol = protocol;
  transport->outbound = binding->root_id;
  transport->submitted_leaf = binding->leaf_id;
  transport->policy_fingerprint = policy_fingerprint;
  transport->server_fingerprint = server_fingerprint;
  transport->deadline = deadline;
  transport->submits++;
  transport->pending = 1;
  *out_request = transport;
  return FTUN_OK;
}

static ftun_status_t transport_cancel(void *user, void **request)
{
  transport_t *transport = (transport_t *)user;
  if (transport == NULL || request == NULL || *request != transport ||
      !transport->pending) return FTUN_E_INVALID;
  transport->cancels++;
  if (transport->cancel_response != NULL) {
    ftun_dns_transport_completion_fn callback = transport->completion;
    void *callback_user = transport->completion_user;
    ftun_dns_transport_t protocol = transport->protocol;
    ftun_endpoint_t upstream = transport->upstream;
    transport->pending = 0;
    transport->completion = NULL;
    transport->completion_user = NULL;
    callback(callback_user, FTUN_OK, protocol, &upstream,
      (ftun_bytes_t){transport->cancel_response,
                     transport->cancel_response_length});
    /* 原请求直到 cancel 返回前才清空，不能覆盖回调中新建的 fallback。 */
    *request = NULL;
    return transport->cancel_status;
  }
  if (transport->cancel_status != FTUN_OK) return transport->cancel_status;
  transport->pending = 0;
  transport->completion = NULL;
  transport->completion_user = NULL;
  *request = NULL;
  return FTUN_OK;
}

static int transport_deliver(transport_t *transport, ftun_status_t status,
                             const uint8_t *wire, size_t length)
{
  ftun_dns_transport_completion_fn completion;
  void *user;
  if (!transport->pending || transport->completion == NULL) return 0;
  completion = transport->completion;
  user = transport->completion_user;
  transport->pending = 0;
  transport->completion = NULL;
  transport->completion_user = NULL;
  completion(user, status, transport->protocol, &transport->upstream,
             (ftun_bytes_t){wire, length});
  return 1;
}

static void completed(ftun_operation_t *operation, ftun_error_t error,
                      ftun_bytes_t response, void *user)
{
  completion_t *completion = (completion_t *)user;
  (void)operation;
  completion->calls++;
  completion->status = error.status;
  completion->stage = error.stage;
  completion->response_length = response.length;
  if (response.length <= sizeof(completion->response) && response.data != NULL) {
    memcpy(completion->response, response.data, response.length);
  }
}

static void query_init(ftun_dns_query_t *query, completion_t *completion,
                       uint8_t wire[29], uint64_t deadline)
{
  static const uint8_t question[] = {
    7u,'e','x','a','m','p','l','e',3u,'c','o','m',0u,0u,1u,0u,1u
  };
  memset(wire, 0, 29u);
  wire[0] = 0x12u; wire[1] = 0x34u;
  wire[2] = 0x01u; wire[5] = 1u;
  memcpy(wire + 12u, question, sizeof(question));
  memset(query, 0, sizeof(*query));
  query->id = 0x1234u;
  query->flags = 0x0100u;
  query->question.name.data = wire + 12u;
  query->question.name.length = 13u;
  query->question.type = 1u;
  query->question.class_code = 1u;
  query->wire.data = wire;
  query->wire.length = 29u;
  query->deadline_ms = deadline;
  query->policy_fingerprint = 77u;
  query->resolution_mode = 1u;
  query->completion = completed;
  query->completion_user = completion;
}

static void response_init(uint8_t wire[45], uint16_t flags, uint16_t id)
{
  static const uint8_t question[] = {
    7u,'e','x','a','m','p','l','e',3u,'c','o','m',0u,0u,1u,0u,1u
  };
  memset(wire, 0, 45u);
  wire[0] = (uint8_t)(id >> 8u); wire[1] = (uint8_t)id;
  wire[2] = (uint8_t)(flags >> 8u); wire[3] = (uint8_t)flags;
  wire[5] = 1u;
  memcpy(wire + 12u, question, sizeof(question));
  if ((flags & 0x0200u) == 0u) {
    wire[7] = 1u;
    wire[29] = 0xc0u; wire[30] = 0x0cu;
    wire[31] = 0u; wire[32] = 1u;
    wire[33] = 0u; wire[34] = 1u;
    wire[38] = 10u;
    wire[39] = 0u; wire[40] = 4u;
    wire[41] = 203u; wire[42] = 0u; wire[43] = 113u; wire[44] = 9u;
  }
}

static int dispatch_one(ftun_operation_queue_t *operations)
{
  size_t dispatched = 0u;
  return ftun_operation_dispatch(operations, 8u, &dispatched) == FTUN_OK &&
         dispatched == 1u;
}

static int test_cancel_delivery(ftun_status_t cancel_status, int stop,
                                 int truncated)
{
  ftun_budget_t *budget = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_core_t *core = NULL;
  ftun_dns_server_t *server = NULL;
  ftun_dns_server_options_t options;
  ftun_dns_server_info_t info;
  ftun_dns_query_t query;
  ftun_operation_t *operation = NULL;
  transport_t transport;
  completion_t completion;
  uint8_t request[29];
  uint8_t response[45];
  uint8_t expected[45];
  uint64_t now = 1000u;
  ftun_status_t cancelled;
  memset(&options, 0, sizeof(options));
  memset(&transport, 0, sizeof(transport));
  memset(&completion, 0, sizeof(completion));
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 4u, &operations) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 1u, &core) == FTUN_OK);
  options.budget = budget;
  options.operations = operations;
  options.upstream.kind = FTUN_ADDRESS_IPV4;
  options.upstream.address[0] = 192u;
  options.upstream.address[2] = 2u;
  options.upstream.address[3] = 53u;
  options.upstream.port = 53u;
  options.outbound_id = 42u;
  options.fingerprint = 99u;
  options.transport = FTUN_DNS_TRANSPORT_UDP;
  options.tcp_fallback = true;
  options.max_response_bytes = 512u;
  options.query_transport.select = transport_select;
  options.query_transport.submit = transport_submit;
  options.query_transport.cancel = transport_cancel;
  options.query_transport.context = &transport;
  options.now = fake_now;
  options.now_user = &now;
  CHECK(ftun_dns_server_create(&options, &server) == FTUN_OK);
  query_init(&query, &completion, request, 5000u);
  transport.next_leaf = 11u;
  CHECK(ftun_dns_exchange(core, server, &query, &operation) == FTUN_OK);
  CHECK(transport.selects == 1u && transport.submitted_leaf == 11u);
  transport.next_leaf = 22u;
  response_init(response, truncated ? 0x8380u : 0x8180u, query.id);
  memcpy(expected, response, sizeof(expected));
  transport.cancel_status = cancel_status;
  transport.cancel_response = response;
  transport.cancel_response_length = truncated ? 29u : sizeof(response);
  cancelled = stop ? ftun_operation_queue_stop(operations)
                   : ftun_operation_cancel(operation);
  CHECK(cancelled == (truncated && cancel_status == FTUN_OK
                       ? FTUN_E_AGAIN : cancel_status));
  CHECK(completion.calls == 0u);
  CHECK(ftun_dns_server_get_info(server, &info) == FTUN_OK && info.inflight == 1u);
  /* transport 的借用响应已经失效，owner callback 必须使用自己保留的副本。 */
  memset(response, 0xe5, sizeof(response));
  if (truncated) {
    CHECK(transport.pending && transport.submits == 2u &&
          transport.protocol == FTUN_DNS_TRANSPORT_TCP &&
          transport.deadline == 5000u && transport.selects == 1u &&
          transport.submitted_leaf == 11u);
    transport.cancel_response = NULL;
    transport.cancel_status = FTUN_OK;
    if (stop) {
      CHECK(ftun_operation_queue_stop(operations) == FTUN_OK);
      CHECK(!transport.pending);
    } else {
      response_init(response, 0x8180u, query.id);
      memcpy(expected, response, sizeof(expected));
      CHECK(transport_deliver(&transport, FTUN_OK, response, sizeof(response)));
      memset(response, 0xe5, sizeof(response));
    }
  }
  CHECK(dispatch_one(operations) && completion.calls == 1u);
  CHECK(completion.status == (truncated ? (stop ? FTUN_E_CANCELLED : FTUN_OK)
    : (cancel_status == FTUN_OK ? FTUN_E_CANCELLED : FTUN_OK)));
  if (completion.status == FTUN_OK) {
    CHECK(completion.response_length == sizeof(expected) &&
          memcmp(completion.response, expected, sizeof(expected)) == 0);
  } else {
    CHECK(completion.response_length == 0u);
  }
  CHECK(ftun_dns_server_get_info(server, &info) == FTUN_OK && info.inflight == 0u);
  CHECK(ftun_dns_server_destroy(&server) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int test_cache_binding(void)
{
  ftun_budget_t *budget = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_core_t *core = NULL;
  ftun_dns_server_t *server = NULL;
  ftun_dns_cache_t *cache = NULL;
  ftun_dns_cache_options_t cache_options;
  ftun_dns_server_options_t options;
  ftun_dns_query_t query;
  ftun_operation_t *operation = NULL;
  ftun_dns_answer_t *answer = NULL;
  transport_t transport;
  completion_t completion;
  uint8_t request[29];
  uint8_t response[45];
  uint64_t now = 1000u;
  memset(&options, 0, sizeof(options));
  memset(&cache_options, 0, sizeof(cache_options));
  memset(&transport, 0, sizeof(transport));
  memset(&completion, 0, sizeof(completion));
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 4u, &operations) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 1u, &core) == FTUN_OK);
  cache_options.budget = budget;
  cache_options.max_entries = 8u;
  cache_options.now = fake_now;
  cache_options.now_user = &now;
  CHECK(ftun_dns_cache_create(&cache_options, &cache) == FTUN_OK);
  options.budget = budget;
  options.operations = operations;
  options.upstream.kind = FTUN_ADDRESS_IPV4;
  options.upstream.address[0] = 192u;
  options.upstream.address[2] = 2u;
  options.upstream.address[3] = 53u;
  options.upstream.port = 53u;
  options.outbound_id = 42u;
  options.fingerprint = 99u;
  options.transport = FTUN_DNS_TRANSPORT_UDP;
  options.tcp_fallback = true;
  options.max_response_bytes = 512u;
  options.query_transport.select = transport_select;
  options.query_transport.submit = transport_submit;
  options.query_transport.cancel = transport_cancel;
  options.query_transport.context = &transport;
  options.now = fake_now;
  options.now_user = &now;
  options.cache = cache;
  CHECK(ftun_dns_server_create(&options, &server) == FTUN_OK);
  query_init(&query, &completion, request, 5000u);
  query.outbound_id = 42u;
  query.server_fingerprint = 99u;
  query.upstream = options.upstream;
  transport.next_leaf = 11u;
  CHECK(ftun_dns_exchange(core, server, &query, &operation) == FTUN_OK);
  response_init(response, 0x8180u, query.id);
  CHECK(transport_deliver(&transport, FTUN_OK, response, sizeof(response)));
  CHECK(dispatch_one(operations) && completion.calls == 1u && completion.status == FTUN_OK);
  CHECK(transport.selects == 1u && transport.submits == 1u);
  memset(&completion, 0, sizeof(completion));
  transport.select_status = FTUN_E_IO;
  transport.next_leaf = 22u;
  CHECK(ftun_dns_exchange(core, server, &query, &operation) == FTUN_OK);
  CHECK(dispatch_one(operations) && completion.calls == 1u && completion.status == FTUN_OK);
  CHECK(transport.selects == 1u && transport.submits == 1u && !transport.pending);
  CHECK(ftun_dns_cache_lookup(cache, &query, &answer) == FTUN_OK);
  CHECK(ftun_dns_answer_release(&answer) == FTUN_OK);
  query.outbound_id = 11u;
  CHECK(ftun_dns_cache_lookup(cache, &query, &answer) == FTUN_E_EOF && answer == NULL);
  query.outbound_id = 42u;
  {
    ftun_budget_usage_t before;
    ftun_budget_usage_t after;
    size_t count;
    size_t index;
    memset(&completion, 0, sizeof(completion));
    for (index = 0u; index < 4u; index++) {
      CHECK(ftun_dns_exchange(core, server, &query, &operation) == FTUN_OK && operation != NULL);
    }
    CHECK(ftun_budget_get_usage(budget, &before) == FTUN_OK);
    CHECK(ftun_dns_exchange(core, server, &query, &operation) == FTUN_E_LIMIT && operation == NULL);
    CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK &&
          before.used == after.used && before.metadata_bytes == after.metadata_bytes);
    CHECK(completion.calls == 0u && transport.selects == 1u && transport.submits == 1u);
    CHECK(ftun_operation_dispatch(operations, 4u, &count) == FTUN_OK && count == 4u);
    CHECK(completion.calls == 4u && completion.status == FTUN_OK);
    CHECK(ftun_operation_queue_stop(operations) == FTUN_OK);
    CHECK(ftun_budget_get_usage(budget, &before) == FTUN_OK);
    CHECK(ftun_dns_exchange(core, server, &query, &operation) == FTUN_E_CANCELLED && operation == NULL);
    CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK &&
          before.used == after.used && before.metadata_bytes == after.metadata_bytes);
    CHECK(completion.calls == 4u && transport.selects == 1u && transport.submits == 1u);
  }
  CHECK(ftun_dns_server_destroy(&server) == FTUN_OK);
  CHECK(ftun_dns_cache_destroy(&cache) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(void)
{
  ftun_budget_t *budget = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_core_t *core = NULL;
  ftun_dns_server_t *server = NULL;
  ftun_dns_server_options_t options;
  ftun_dns_server_info_t info;
  ftun_dns_query_t query;
  ftun_operation_t *operation = NULL;
  transport_t transport;
  completion_t completion;
  uint8_t request[29];
  uint8_t response[45];
  uint64_t now = 1000u;
  memset(&options, 0, sizeof(options));
  memset(&transport, 0, sizeof(transport));
  memset(&completion, 0, sizeof(completion));
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 4u, &operations) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 1u, &core) == FTUN_OK);
  options.budget = budget;
  options.operations = operations;
  options.upstream.kind = FTUN_ADDRESS_IPV4;
  options.upstream.address[0] = 192u;
  options.upstream.address[1] = 0u;
  options.upstream.address[2] = 2u;
  options.upstream.address[3] = 53u;
  options.upstream.port = 53u;
  options.outbound_id = 42u;
  options.fingerprint = 99u;
  options.transport = FTUN_DNS_TRANSPORT_UDP;
  options.tcp_fallback = true;
  options.max_response_bytes = 512u;
  options.query_transport.select = transport_select;
  options.query_transport.submit = transport_submit;
  options.query_transport.cancel = transport_cancel;
  options.query_transport.context = &transport;
  options.now = fake_now;
  options.now_user = &now;
  CHECK(ftun_dns_server_create(&options, &server) == FTUN_OK);

  query_init(&query, &completion, request, 5000u);
  transport.next_leaf = 11u;
  CHECK(ftun_dns_exchange(core, server, &query, &operation) == FTUN_OK &&
        operation != NULL && transport.pending &&
        transport.outbound == 42u && transport.deadline == 5000u &&
        transport.policy_fingerprint == 77u &&
        transport.server_fingerprint == 99u &&
        transport.protocol == FTUN_DNS_TRANSPORT_UDP);
  CHECK(transport.selects == 1u && transport.submitted_leaf == 11u);
  transport.next_leaf = 22u;
  response_init(response, 0x8380u, query.id);
  CHECK(transport_deliver(&transport, FTUN_OK, response, 29u));
  CHECK(transport.pending && transport.submits == 2u &&
        transport.protocol == FTUN_DNS_TRANSPORT_TCP &&
        transport.outbound == 42u && transport.deadline == 5000u &&
        transport.selects == 1u && transport.submitted_leaf == 11u);
  response_init(response, 0x8180u, query.id);
  CHECK(transport_deliver(&transport, FTUN_OK, response, sizeof(response)));
  CHECK(dispatch_one(operations) && completion.calls == 1u &&
        completion.status == FTUN_OK && completion.response_length == 45u);
  CHECK(ftun_dns_server_get_info(server, &info) == FTUN_OK &&
        info.inflight == 0u && info.outbound_id == 42u);

  memset(&completion, 0, sizeof(completion));
  query_init(&query, &completion, request, 5000u);
  CHECK(ftun_dns_exchange(core, server, &query, &operation) == FTUN_OK);
  response_init(response, 0x8180u, 0x9999u);
  CHECK(transport_deliver(&transport, FTUN_OK, response, sizeof(response)));
  CHECK(dispatch_one(operations) && completion.status == FTUN_E_PROTOCOL);

  memset(&completion, 0, sizeof(completion));
  query_init(&query, &completion, request, 5000u);
  CHECK(ftun_dns_exchange(core, server, &query, &operation) == FTUN_OK);
  CHECK(ftun_operation_cancel(operation) == FTUN_OK &&
        transport.cancels == 1u && !transport.pending);
  CHECK(dispatch_one(operations) && completion.status == FTUN_E_CANCELLED);

  query_init(&query, &completion, request, 5000u);
  query.resolution_mode = 2u;
  CHECK(ftun_dns_exchange(core, server, &query, &operation) == FTUN_E_INVALID &&
        operation == NULL);
  query_init(&query, &completion, request, now);
  CHECK(ftun_dns_exchange(core, server, &query, &operation) == FTUN_E_TIMEOUT &&
        operation == NULL);

  {
    unsigned int submits = transport.submits;
    unsigned int selects = transport.selects;
    memset(&completion, 0, sizeof(completion));
    query_init(&query, &completion, request, 5000u);
    transport.select_status = FTUN_E_STALE;
    CHECK(ftun_dns_exchange(core, server, &query, &operation) == FTUN_OK &&
          operation != NULL && completion.calls == 0u);
    CHECK(transport.selects == selects + 1u && transport.submits == submits);
    CHECK(dispatch_one(operations) && completion.calls == 1u &&
          completion.status == FTUN_E_STALE);
    transport.select_status = FTUN_OK;
    memset(&completion, 0, sizeof(completion));
    CHECK(ftun_dns_exchange(core, server, &query, &operation) == FTUN_OK);
    CHECK(transport.submitted_leaf == 22u);
    now = query.deadline_ms;
    response_init(response, 0x8380u, query.id);
    submits = transport.submits;
    CHECK(transport_deliver(&transport, FTUN_OK, response, 29u));
    CHECK(transport.submits == submits && !transport.pending);
    CHECK(dispatch_one(operations) && completion.calls == 1u &&
          completion.status == FTUN_E_TIMEOUT);
  }

  CHECK(ftun_dns_server_destroy(&server) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  {
    const ftun_status_t results[] = {FTUN_OK, FTUN_E_IO, FTUN_E_AGAIN};
    int stop;
    int truncated;
    size_t index;
    for (stop = 0; stop <= 1; stop++) {
      for (truncated = 0; truncated <= 1; truncated++) {
        for (index = 0u; index < sizeof(results) / sizeof(results[0]); index++) {
          CHECK(test_cancel_delivery(results[index], stop, truncated) == 0);
        }
      }
    }
  }
  CHECK(test_cache_binding() == 0);
  puts("dns-server: cancel delivery windows=12; binding, cache and deadline passed");
  return 0;
}
