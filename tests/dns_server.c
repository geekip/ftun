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
  unsigned int cancels;
  int pending;
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

static ftun_status_t transport_submit(
  void *user, uint32_t outbound, uint64_t policy_fingerprint,
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
  transport->outbound = outbound;
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
  transport->pending = 0;
  transport->completion = NULL;
  transport->completion_user = NULL;
  transport->cancels++;
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
  options.query_transport.submit = transport_submit;
  options.query_transport.cancel = transport_cancel;
  options.query_transport.context = &transport;
  options.now = fake_now;
  options.now_user = &now;
  CHECK(ftun_dns_server_create(&options, &server) == FTUN_OK);

  query_init(&query, &completion, request, 5000u);
  CHECK(ftun_dns_exchange(core, server, &query, &operation) == FTUN_OK &&
        operation != NULL && transport.pending &&
        transport.outbound == 42u && transport.deadline == 5000u &&
        transport.policy_fingerprint == 77u &&
        transport.server_fingerprint == 99u &&
        transport.protocol == FTUN_DNS_TRANSPORT_UDP);
  response_init(response, 0x8380u, query.id);
  CHECK(transport_deliver(&transport, FTUN_OK, response, 29u));
  CHECK(transport.pending && transport.submits == 2u &&
        transport.protocol == FTUN_DNS_TRANSPORT_TCP &&
        transport.outbound == 42u && transport.deadline == 5000u);
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

  CHECK(ftun_dns_server_destroy(&server) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}
