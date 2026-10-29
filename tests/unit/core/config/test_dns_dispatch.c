#include "app/composition/bridges.h"
#include "app/config/compile.h"
#include "app/config/model.h"
#include "app/config/parser.h"
#include "core/limits.h"
#include "core/operation.h"
#include "proxy/outbound_id.h"
#include "app/composition/dns_dispatch.h"
#include "proxy/fakeip/pool.h"
#include "proxy/dns/runtime_adapter.h"
#include "proxy/runtime_state.h"
#include "dns/dispatcher.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "dns dispatch contract failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  ftun_dns_transport_completion_fn completion;
  void *user;
  ftun_endpoint_t upstream;
  ftun_dns_transport_t protocol;
  uint32_t outbound;
  unsigned int submits;
  unsigned int selects;
  int pending;
} transport_t;

typedef struct {
  unsigned int calls;
  ftun_status_t status;
  uint8_t response[64];
  size_t length;
} completion_t;

static ftun_status_t transport_select(void *user, uint32_t root,
  ftun_dns_transport_binding_t *out)
{
  transport_t *transport = (transport_t *)user;
  transport->selects++;
  memset(out, 0, sizeof(*out));
  out->scope = user;
  out->root_id = root;
  out->leaf_id = root;
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
  (void)policy_fingerprint;
  (void)server_fingerprint;
  (void)query;
  (void)deadline;
  if (transport->pending) return FTUN_E_LIMIT;
  transport->completion = completion;
  transport->user = completion_user;
  transport->upstream = *upstream;
  transport->protocol = protocol;
  transport->outbound = binding->root_id;
  transport->submits++;
  transport->pending = 1;
  *out_request = transport;
  return FTUN_OK;
}

static ftun_status_t transport_cancel(void *user, void **request)
{
  transport_t *transport = (transport_t *)user;
  if (request == NULL || *request != transport || !transport->pending) {
    return FTUN_E_INVALID;
  }
  transport->pending = 0;
  *request = NULL;
  return FTUN_OK;
}

static void completed(ftun_operation_t *operation, ftun_error_t error,
                      ftun_bytes_t response, void *user)
{
  completion_t *completion = (completion_t *)user;
  (void)operation;
  completion->calls++;
  completion->status = error.status;
  completion->length = response.length;
  if (response.data != NULL && response.length <= sizeof(completion->response)) {
    memcpy(completion->response, response.data, response.length);
  }
}

static ftun_config_t *make_config(void)
{
  static const char text[] =
    "{\"dns\":{\"enable\":false},"
    "\"outbounds\":[{\"name\":\"proxy\",\"type\":\"socks5\","
    "\"server\":\"192.0.2.1:1080\"}],"
    "\"rules\":[\"IP-CIDR,10.0.0.0/8,DIRECT\","
    "\"DOMAIN,a.example,proxy\",\"MATCH,REJECT\"]}";
  ftun_config_t *config = NULL;
  ftun_feature_plan_t *plan = NULL;
  ftun_bytes_t bytes = {(const uint8_t *)text, sizeof(text) - 1u};
  if (ftun_config_parse(bytes, &config) != FTUN_OK) return NULL;
  if (ftun_config_compile(config, &plan) != FTUN_OK) {
    (void)ftun_config_destroy(&config);
    return NULL;
  }
  ftun_config_bind_plan(config, plan);
  return config;
}

static void query_init(ftun_dns_query_t *query, completion_t *completion,
                       uint8_t wire[27], uint16_t type)
{
  static const uint8_t name[] = {1u,'a',7u,'e','x','a','m','p','l','e',0u};
  memset(wire, 0, 27u);
  wire[0] = 0x12u; wire[1] = 0x34u;
  wire[2] = 0x01u; wire[5] = 1u;
  memcpy(wire + 12u, name, sizeof(name));
  wire[23] = (uint8_t)(type >> 8u); wire[24] = (uint8_t)type;
  wire[25] = 0u; wire[26] = 1u;
  memset(query, 0, sizeof(*query));
  query->id = 0x1234u;
  query->flags = 0x0100u;
  query->question.name.data = wire + 12u;
  query->question.name.length = sizeof(name);
  query->question.type = type;
  query->question.class_code = 1u;
  query->wire = (ftun_bytes_t){wire, 27u};
  query->deadline_ms = UINT64_MAX;
  query->resolution_mode = 1u;
  query->completion = completed;
  query->completion_user = completion;
}

static ftun_status_t select_server(uint32_t outbound, size_t *out, void *user)
{
  uint32_t *seen = (uint32_t *)user;
  *seen = outbound;
  if (outbound == FTUN_OUTBOUND_ID_NAMED_BASE) {
    *out = 1u;
    return FTUN_OK;
  }
  if (outbound == FTUN_OUTBOUND_ID_DIRECT) {
    *out = 0u;
    return FTUN_OK;
  }
  return FTUN_E_REJECTED;
}

static int dispatch_one(ftun_operation_queue_t *operations)
{
  size_t count = 0u;
  return ftun_operation_dispatch(operations, 8u, &count) == FTUN_OK &&
         count == 1u;
}

int main(void)
{
  ftun_budget_t *budget = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_core_t *core = NULL;
  ftun_config_t *config = NULL;
  ftun_runtime_t *candidate = NULL;
  ftun_fakeip_service_t *fakeip = NULL;
  ftun_dns_server_t *servers[2] = {NULL, NULL};
  ftun_dns_server_t *server_views[2];
  ftun_dns_dispatcher_t *dispatcher = NULL;
  ftun_fakeip_service_options_t fake_options;
  ftun_dns_server_options_t server_options;
  ftun_dns_dispatcher_options_t dispatcher_options;
  ftun_proxy_dns_runtime_adapter_t dns_adapter;
  ftun_dns_query_t query;
  ftun_metadata_t metadata;
  ftun_operation_t *operation = NULL;
  completion_t completion;
  transport_t transport;
  uint8_t wire[27];
  uint32_t selected_outbound = UINT32_MAX;
  size_t index;
  memset(&fake_options, 0, sizeof(fake_options));
  memset(&server_options, 0, sizeof(server_options));
  memset(&dispatcher_options, 0, sizeof(dispatcher_options));
  memset(&dns_adapter, 0, sizeof(dns_adapter));
  memset(&transport, 0, sizeof(transport));
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 8u, &operations) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 1u, &core) == FTUN_OK);
  config = make_config();
  CHECK(config != NULL);
  CHECK(ftun_runtime_prepare(core, config, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  fake_options.budget = budget;
  fake_options.first_address = UINT32_C(0xc6120001);
  fake_options.end_address_exclusive = UINT32_C(0xc6120010);
  fake_options.max_entries = 8u;
  CHECK(ftun_fakeip_service_create(&fake_options, &fakeip) == FTUN_OK);
  server_options.budget = budget;
  server_options.operations = operations;
  server_options.upstream.kind = FTUN_ADDRESS_IPV4;
  server_options.upstream.address[0] = 192u;
  server_options.upstream.address[1] = 0u;
  server_options.upstream.address[2] = 2u;
  server_options.upstream.address[3] = 53u;
  server_options.upstream.port = 53u;
  server_options.transport = FTUN_DNS_TRANSPORT_UDP;
  server_options.tcp_fallback = true;
  server_options.max_response_bytes = 512u;
  server_options.query_transport.select = transport_select;
  server_options.query_transport.submit = transport_submit;
  server_options.query_transport.cancel = transport_cancel;
  server_options.query_transport.context = &transport;
  for (index = 0u; index < 2u; index++) {
    server_options.outbound_id = (uint32_t)(10u + index);
    server_options.fingerprint = (uint64_t)(20u + index);
    server_options.fakeip = index == 0u;
    CHECK(ftun_dns_server_create(&server_options, &servers[index]) == FTUN_OK);
    server_views[index] = servers[index];
  }
  dispatcher_options.budget = budget;
  CHECK(ftun_runtime_active_config(core, &dispatcher_options.config_scope) == FTUN_OK);
  dispatcher_options.operations = operations;
  dispatcher_options.servers = server_views;
  dispatcher_options.server_count = 2u;
  dispatcher_options.select_server = select_server;
  dispatcher_options.select_user = &selected_outbound;
  CHECK(ftun_dns_dispatcher_create(&dispatcher_options, &dispatcher) == FTUN_OK);
  dns_adapter.core = core;
  ftun_app_dns_bridge_init(&dns_adapter);
  dns_adapter.fakeip_slot = &fakeip;

  memset(&completion, 0, sizeof(completion));
  query_init(&query, &completion, wire, 1u);
  query.entry = FTUN_DNS_ENTRY_FIXED;
  query.fixed_server = 0u;
  CHECK(ftun_proxy_dns_dispatch(&dns_adapter, core, dispatcher, &query,
        &operation) == FTUN_OK &&
        operation != NULL && !transport.pending);
  CHECK(dispatch_one(operations) && completion.status == FTUN_OK &&
        completion.length == 43u && completion.response[7] == 1u &&
        completion.response[39] == 198u && completion.response[40] == 18u &&
        completion.response[41] == 0u && completion.response[42] == 1u);

  memset(&completion, 0, sizeof(completion));
  query_init(&query, &completion, wire, 28u);
  query.entry = FTUN_DNS_ENTRY_FIXED;
  CHECK(ftun_proxy_dns_dispatch(&dns_adapter, core, dispatcher, &query,
        &operation) == FTUN_OK);
  CHECK(dispatch_one(operations) && completion.length == 27u &&
        completion.response[7] == 0u && transport.selects == 0u);

  memset(&completion, 0, sizeof(completion));
  query_init(&query, &completion, wire, 1u);
  query.entry = FTUN_DNS_ENTRY_FIXED;
  query.real_only = true;
  CHECK(ftun_proxy_dns_dispatch(&dns_adapter, core, dispatcher, &query,
        &operation) == FTUN_OK &&
        transport.pending && transport.outbound == 10u);
  CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  CHECK(dispatch_one(operations) && completion.status == FTUN_E_CANCELLED);

  memset(&metadata, 0, sizeof(metadata));
  metadata.generation = 1u;
  metadata.known_fields = FTUN_META_DOMAIN | FTUN_META_PORT | FTUN_META_NETWORK;
  metadata.network = 2u;
  metadata.domain = (ftun_string_t){"a.example", 9u};
  metadata.domain_source = FTUN_DOMAIN_EXPLICIT;
  metadata.original_target.kind = FTUN_ADDRESS_DOMAIN;
  metadata.original_target.domain = metadata.domain;
  metadata.original_target.port = 53u;
  memset(&completion, 0, sizeof(completion));
  query_init(&query, &completion, wire, 1u);
  query.entry = FTUN_DNS_ENTRY_POLICY;
  query.metadata = &metadata;
  CHECK(ftun_proxy_dns_dispatch(&dns_adapter, core, dispatcher, &query,
        &operation) == FTUN_OK &&
        selected_outbound == FTUN_OUTBOUND_ID_NAMED_BASE &&
        transport.pending && transport.outbound == 11u);
  CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  CHECK(dispatch_one(operations) && completion.status == FTUN_E_CANCELLED);
  query.real_only = true;
  CHECK(ftun_proxy_dns_dispatch(&dns_adapter, core, dispatcher, &query,
        &operation) == FTUN_E_INVALID);

  {
    unsigned int selects = transport.selects;
    unsigned int submits = transport.submits;
    ftun_config_t *replacement;
    query.real_only = false;
    wire[13] = (uint8_t)'b';
    metadata.domain = (ftun_string_t){"b.example", 9u};
    memset(&completion, 0, sizeof(completion));
    CHECK(ftun_proxy_dns_dispatch(&dns_adapter, core, dispatcher, &query,
                                   &operation) == FTUN_OK);
    CHECK(dispatch_one(operations) && completion.status == FTUN_OK &&
          (completion.response[3] & 15u) == 5u);
    CHECK(transport.selects == selects && transport.submits == submits);
    config = (ftun_config_t *)dispatcher_options.config_scope;
    CHECK(ftun_config_retain(config) == FTUN_OK);
    replacement = make_config();
    CHECK(replacement != NULL);
    CHECK(ftun_runtime_prepare(core, replacement, &candidate) == FTUN_OK);
    CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK);
    CHECK(ftun_config_destroy(&replacement) == FTUN_OK);
    wire[13] = (uint8_t)'a';
    metadata.domain = (ftun_string_t){"a.example", 9u};
    metadata.generation = 2u;
    selected_outbound = UINT32_MAX;
    memset(&completion, 0, sizeof(completion));
    CHECK(ftun_proxy_dns_dispatch(&dns_adapter, core, dispatcher, &query,
                                   &operation) == FTUN_E_STALE);
    CHECK(operation == NULL && completion.calls == 0u &&
          selected_outbound == UINT32_MAX && transport.selects == selects &&
          transport.submits == submits);
  }

  CHECK(ftun_dns_dispatcher_destroy(&dispatcher) == FTUN_OK);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(ftun_dns_server_destroy(&servers[1]) == FTUN_OK);
  CHECK(ftun_dns_server_destroy(&servers[0]) == FTUN_OK);
  CHECK(ftun_fakeip_service_destroy(&fakeip) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}
