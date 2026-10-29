#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#include "app/composition/bridges.h"

#include "app/config/compile.h"
#include "app/config/model.h"
#include "app/config/parser.h"
#include "core/limits.h"
#include "core/operation.h"
#include "proxy/runtime_state.h"
#include "core/worker.h"
#include "dns/dispatcher.h"
#include "app/composition/dns_dispatch.h"
#include "proxy/fakeip/pool.h"
#include "proxy/dns/runtime_adapter.h"
#include "proxy/route/router.h"

#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "v0.3 integration failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  unsigned int calls;
  ftun_status_t status;
  ftun_fakeip_store_operation_t kind;
} store_completion_t;

typedef struct {
  ftun_dns_transport_completion_fn completion;
  void *user;
  ftun_endpoint_t source;
  ftun_dns_transport_t protocol;
  uint32_t outbound;
  int pending;
} transport_t;

typedef struct {
  unsigned int calls;
  ftun_status_t status;
  uint8_t response[64];
  size_t length;
} dns_completion_t;

static void store_completed(ftun_operation_t *operation, ftun_error_t error,
                            ftun_fakeip_store_operation_t kind,
                            uint64_t sequence, uint32_t reserved_end,
                            void *user)
{
  store_completion_t *completion = (store_completion_t *)user;
  (void)operation;
  (void)sequence;
  (void)reserved_end;
  completion->calls++;
  completion->status = error.status;
  completion->kind = kind;
}

static int poll_worker(ftun_worker_t *worker, store_completion_t *completion,
                       unsigned int expected)
{
  unsigned int attempt;
  for (attempt = 0u; attempt < 100000u && completion->calls < expected;
       attempt++) {
    size_t callbacks = 0u;
    if (ftun_worker_poll(worker, 8u, &callbacks) != FTUN_OK) return 0;
    if (callbacks == 0u) sched_yield();
  }
  return completion->calls == expected;
}

static ftun_status_t transport_select(void *user, uint32_t root,
  ftun_dns_transport_binding_t *out)
{
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
  transport->source = *upstream;
  transport->protocol = protocol;
  transport->outbound = binding->root_id;
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

static void transport_deliver(transport_t *transport, ftun_bytes_t response)
{
  ftun_dns_transport_completion_fn completion = transport->completion;
  void *user = transport->user;
  transport->pending = 0;
  transport->completion = NULL;
  completion(user, FTUN_OK, transport->protocol, &transport->source, response);
}

static void dns_completed(ftun_operation_t *operation, ftun_error_t error,
                          ftun_bytes_t response, void *user)
{
  dns_completion_t *completion = (dns_completion_t *)user;
  (void)operation;
  completion->calls++;
  completion->status = error.status;
  completion->length = response.length;
  if (response.data != NULL && response.length <= sizeof(completion->response)) {
    memcpy(completion->response, response.data, response.length);
  }
}

static int dispatch_one(ftun_operation_queue_t *operations)
{
  size_t count = 0u;
  return ftun_operation_dispatch(operations, 8u, &count) == FTUN_OK &&
         count == 1u;
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

static void dns_query(ftun_dns_query_t *query, dns_completion_t *completion,
                      uint8_t wire[27], ftun_dns_entry_t entry)
{
  static const uint8_t name[] = {1u,'a',7u,'e','x','a','m','p','l','e',0u};
  memset(wire, 0, 27u);
  wire[0] = 0x44u; wire[1] = 0x55u;
  wire[2] = 0x01u; wire[5] = 1u;
  memcpy(wire + 12u, name, sizeof(name));
  wire[23] = 0u; wire[24] = 1u; wire[25] = 0u; wire[26] = 1u;
  memset(query, 0, sizeof(*query));
  query->id = 0x4455u;
  query->flags = 0x0100u;
  query->question.name = (ftun_dns_name_t){wire + 12u, sizeof(name)};
  query->question.type = 1u;
  query->question.class_code = 1u;
  query->wire = (ftun_bytes_t){wire, 27u};
  query->deadline_ms = UINT64_MAX;
  query->resolution_mode = 1u;
  query->completion = dns_completed;
  query->completion_user = completion;
  query->entry = entry;
}

static void dns_response(uint8_t wire[43])
{
  ftun_dns_query_t ignored;
  dns_completion_t completion;
  uint8_t request[27];
  dns_query(&ignored, &completion, request, FTUN_DNS_ENTRY_FIXED);
  memset(wire, 0, 43u);
  memcpy(wire, request, 27u);
  wire[2] = 0x81u; wire[3] = 0x80u; wire[7] = 1u;
  wire[27] = 0xc0u; wire[28] = 0x0cu;
  wire[29] = 0u; wire[30] = 1u;
  wire[31] = 0u; wire[32] = 1u;
  wire[36] = 30u;
  wire[37] = 0u; wire[38] = 4u;
  wire[39] = 203u; wire[40] = 0u; wire[41] = 113u; wire[42] = 8u;
}

static ftun_status_t select_server(uint32_t outbound, size_t *out, void *user)
{
  uint32_t *selected = (uint32_t *)user;
  *selected = outbound;
  if (outbound == FTUN_OUTBOUND_ID_NAMED_BASE) {
    *out = 1u;
    return FTUN_OK;
  }
  *out = 0u;
  return FTUN_OK;
}

static int remove_store(const char *directory)
{
  const char *names[] = {"identity", "reservations", "mappings", "lock"};
  char path[256];
  size_t index;
  for (index = 0u; index < sizeof(names) / sizeof(names[0]); index++) {
    int length = snprintf(path, sizeof(path), "%s/%s", directory, names[index]);
    if (length <= 0 || (size_t)length >= sizeof(path) || unlink(path) != 0) return 0;
  }
  return rmdir(directory) == 0;
}

int main(void)
{
  char directory[] = "/tmp/ftun-v03.XXXXXX";
  char mapping_path[256];
  ftun_budget_t *budget = NULL;
  ftun_worker_t *worker = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_core_t *core = NULL;
  ftun_config_t *config = NULL;
  ftun_runtime_t *candidate = NULL;
  ftun_runtime_t *runtime = NULL;
  ftun_fakeip_store_t *store = NULL;
  ftun_fakeip_snapshot_t *snapshot = NULL;
  ftun_fakeip_service_t *fakeip = NULL;
  ftun_fakeip_handle_t *handle = NULL;
  ftun_dns_server_t *servers[2] = {NULL, NULL};
  ftun_dns_server_t *views[2];
  ftun_dns_dispatcher_t *dispatcher = NULL;
  ftun_operation_t *operation = NULL;
  ftun_fakeip_store_identity_t identity;
  ftun_fakeip_store_options_t store_options;
  ftun_fakeip_service_options_t fake_options;
  ftun_dns_server_options_t server_options;
  ftun_dns_dispatcher_options_t dispatcher_options;
  ftun_proxy_dns_runtime_adapter_t dns_adapter;
  ftun_metadata_t metadata;
  ftun_endpoint_t candidates[2];
  ftun_route_result_t route;
  ftun_dns_query_t query;
  store_completion_t store_completion;
  dns_completion_t dns_completion;
  transport_t transport;
  uint8_t request[27];
  uint8_t response[43];
  uint32_t address;
  uint32_t selected_outbound = UINT32_MAX;
  ftun_string_t domain;
  size_t callbacks;
  int descriptor;
  uint8_t byte;
  memset(&identity, 0, sizeof(identity));
  memset(&store_options, 0, sizeof(store_options));
  memset(&fake_options, 0, sizeof(fake_options));
  memset(&server_options, 0, sizeof(server_options));
  memset(&dispatcher_options, 0, sizeof(dispatcher_options));
  memset(&dns_adapter, 0, sizeof(dns_adapter));
  memset(&store_completion, 0, sizeof(store_completion));
  memset(&dns_completion, 0, sizeof(dns_completion));
  memset(&transport, 0, sizeof(transport));
  CHECK(mkdtemp(directory) != NULL && rmdir(directory) == 0);
  identity.uuid[0] = 0x33u;
  identity.first_address = UINT32_C(0xc6120001);
  identity.end_address_exclusive = UINT32_C(0xc6120010);
  CHECK(ftun_fakeip_store_initialize(directory, &identity) == FTUN_OK);
  CHECK(ftun_budget_create(NULL, 4u * 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_worker_create(budget, 4u, &worker) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 8u, &operations) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 1u, &core) == FTUN_OK);
  config = make_config();
  CHECK(config != NULL);
  CHECK(ftun_runtime_prepare(core, config, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK);
  dns_adapter.core = core;
  ftun_app_dns_bridge_init(&dns_adapter);
  dns_adapter.fakeip_slot = &fakeip;
  CHECK(ftun_config_destroy(&config) == FTUN_OK);

  dns_query(&query, &dns_completion, request, FTUN_DNS_ENTRY_FIXED);
  CHECK(ftun_proxy_dns_dispatch(&dns_adapter, core, dispatcher, &query,
        &operation) == FTUN_E_AGAIN);
  store_options.directory = directory;
  store_options.budget = budget;
  store_options.worker = worker;
  store_options.completion = store_completed;
  store_options.user = &store_completion;
  CHECK(ftun_fakeip_store_open(&store_options, &store) == FTUN_OK);
  CHECK(ftun_fakeip_snapshot_load(store, 8u, &snapshot) == FTUN_OK);
  fake_options.budget = budget;
  fake_options.store = store;
  fake_options.snapshot = snapshot;
  fake_options.max_entries = 8u;
  CHECK(ftun_fakeip_service_create(&fake_options, &fakeip) == FTUN_OK);
  CHECK(ftun_fakeip_service_acquire(fakeip,
    (ftun_string_t){"a.example", 9u}, &handle) == FTUN_E_AGAIN);
  CHECK(ftun_fakeip_store_reserve(store, identity.first_address + 4u,
                                  &operation) == FTUN_OK);
  CHECK(poll_worker(worker, &store_completion, 1u) &&
        store_completion.status == FTUN_OK);
  CHECK(ftun_fakeip_service_acquire(fakeip,
    (ftun_string_t){"a.example", 9u}, &handle) == FTUN_OK);
  CHECK(ftun_fakeip_handle_get(handle, &address, &domain) == FTUN_OK &&
        address == identity.first_address);
  CHECK(ftun_fakeip_handle_release(&handle) == FTUN_OK);
  CHECK(ftun_fakeip_snapshot_destroy(&snapshot) == FTUN_OK);
  CHECK(ftun_fakeip_service_snapshot(fakeip, &snapshot) == FTUN_OK);
  CHECK(ftun_fakeip_snapshot_save(store, snapshot, &operation) == FTUN_OK);
  CHECK(ftun_fakeip_snapshot_destroy(&snapshot) == FTUN_OK);
  CHECK(poll_worker(worker, &store_completion, 2u) &&
        store_completion.kind == FTUN_FAKEIP_STORE_SNAPSHOT &&
        store_completion.status == FTUN_OK);

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
  server_options.fakeip = true;
  server_options.outbound_id = 10u;
  server_options.fingerprint = 100u;
  CHECK(ftun_dns_server_create(&server_options, &servers[0]) == FTUN_OK);
  server_options.fakeip = false;
  server_options.outbound_id = 11u;
  server_options.fingerprint = 101u;
  CHECK(ftun_dns_server_create(&server_options, &servers[1]) == FTUN_OK);
  views[0] = servers[0]; views[1] = servers[1];
  dispatcher_options.budget = budget;
  CHECK(ftun_runtime_active_config(core, &dispatcher_options.config_scope) == FTUN_OK);
  dispatcher_options.operations = operations;
  dispatcher_options.servers = views;
  dispatcher_options.server_count = 2u;
  dispatcher_options.select_server = select_server;
  dispatcher_options.select_user = &selected_outbound;
  CHECK(ftun_dns_dispatcher_create(&dispatcher_options, &dispatcher) == FTUN_OK);

  memset(&dns_completion, 0, sizeof(dns_completion));
  dns_query(&query, &dns_completion, request, FTUN_DNS_ENTRY_FIXED);
  query.fixed_server = 0u;
  CHECK(ftun_proxy_dns_dispatch(&dns_adapter, core, dispatcher, &query,
        &operation) == FTUN_OK);
  CHECK(dispatch_one(operations) && dns_completion.status == FTUN_OK &&
        dns_completion.response[39] == 198u &&
        dns_completion.response[40] == 18u);

  memset(&metadata, 0, sizeof(metadata));
  metadata.generation = 1u;
  metadata.known_fields = FTUN_META_DOMAIN;
  metadata.domain = (ftun_string_t){"a.example", 9u};
  metadata.domain_source = FTUN_DOMAIN_EXPLICIT;
  metadata.original_target.kind = FTUN_ADDRESS_DOMAIN;
  metadata.original_target.domain = metadata.domain;
  CHECK(ftun_runtime_active_acquire(core, &runtime) == FTUN_OK);
  CHECK(ftun_route_evaluate(runtime, &metadata, 0u, &route) == FTUN_OK &&
        route.kind == FTUN_ROUTE_NEED_RESOLVE && route.resume_rule == 0u);
  memset(candidates, 0, sizeof(candidates));
  candidates[0].kind = FTUN_ADDRESS_IPV4;
  candidates[0].address[0] = 10u; candidates[0].address[3] = 1u;
  candidates[1].kind = FTUN_ADDRESS_IPV4;
  candidates[1].address[0] = 192u; candidates[1].address[2] = 2u;
  candidates[1].address[3] = 1u;
  metadata.resolved = candidates;
  metadata.resolved_count = 2u;
  CHECK(ftun_route_evaluate(runtime, &metadata, route.resume_rule, &route) ==
        FTUN_OK && route.kind == FTUN_ROUTE_READY &&
        route.allowed_count == 1u && route.allowed[0].address[0] == 10u);
  CHECK(ftun_runtime_release(&runtime) == FTUN_OK);

  metadata.resolved = NULL;
  metadata.resolved_count = 0u;
  memset(&dns_completion, 0, sizeof(dns_completion));
  dns_query(&query, &dns_completion, request, FTUN_DNS_ENTRY_POLICY);
  query.metadata = &metadata;
  CHECK(ftun_proxy_dns_dispatch(&dns_adapter, core, dispatcher, &query,
        &operation) == FTUN_OK &&
        transport.pending && selected_outbound == FTUN_OUTBOUND_ID_NAMED_BASE &&
        transport.outbound == 11u);
  dns_response(response);
  transport_deliver(&transport, (ftun_bytes_t){response, sizeof(response)});
  CHECK(dispatch_one(operations) && dns_completion.status == FTUN_OK &&
        dns_completion.response[42] == 8u);

  CHECK(ftun_dns_dispatcher_destroy(&dispatcher) == FTUN_OK);
  CHECK(ftun_dns_server_destroy(&servers[1]) == FTUN_OK);
  CHECK(ftun_dns_server_destroy(&servers[0]) == FTUN_OK);
  CHECK(ftun_fakeip_service_destroy(&fakeip) == FTUN_OK);
  CHECK(ftun_fakeip_store_destroy(&store) == FTUN_OK);

  CHECK(ftun_fakeip_store_open(&store_options, &store) == FTUN_OK);
  CHECK(ftun_fakeip_snapshot_load(store, 8u, &snapshot) == FTUN_OK);
  fake_options.store = store;
  fake_options.snapshot = snapshot;
  CHECK(ftun_fakeip_service_create(&fake_options, &fakeip) == FTUN_OK);
  CHECK(ftun_fakeip_service_acquire(fakeip,
    (ftun_string_t){"a.example", 9u}, &handle) == FTUN_OK);
  CHECK(ftun_fakeip_handle_get(handle, &address, &domain) == FTUN_OK &&
        address == identity.first_address);
  CHECK(ftun_fakeip_handle_release(&handle) == FTUN_OK);
  CHECK(ftun_fakeip_service_acquire(fakeip,
    (ftun_string_t){"new.example", 11u}, &handle) == FTUN_E_AGAIN);
  CHECK(ftun_fakeip_store_reserve(store, identity.first_address + 6u,
                                  &operation) == FTUN_OK);
  CHECK(poll_worker(worker, &store_completion, 3u));
  CHECK(ftun_fakeip_service_acquire(fakeip,
    (ftun_string_t){"new.example", 11u}, &handle) == FTUN_OK);
  CHECK(ftun_fakeip_handle_get(handle, &address, &domain) == FTUN_OK &&
        address == identity.first_address + 4u);
  CHECK(ftun_fakeip_handle_release(&handle) == FTUN_OK);
  CHECK(ftun_fakeip_snapshot_destroy(&snapshot) == FTUN_OK);
  CHECK(ftun_fakeip_service_destroy(&fakeip) == FTUN_OK);
  CHECK(ftun_fakeip_store_destroy(&store) == FTUN_OK);

  CHECK(snprintf(mapping_path, sizeof(mapping_path), "%s/mappings", directory) > 0);
  descriptor = open(mapping_path, O_RDWR | O_CLOEXEC);
  CHECK(descriptor >= 0 && lseek(descriptor, -1, SEEK_END) >= 0 &&
        read(descriptor, &byte, 1u) == 1 && lseek(descriptor, -1, SEEK_END) >= 0);
  byte ^= 0x5au;
  CHECK(write(descriptor, &byte, 1u) == 1 && fsync(descriptor) == 0 &&
        close(descriptor) == 0);
  CHECK(ftun_fakeip_store_open(&store_options, &store) ==
        FTUN_E_STATE_CORRUPT && store == NULL);

  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_worker_stop(worker) == FTUN_OK);
  CHECK(ftun_worker_join(worker) == FTUN_OK);
  CHECK(ftun_worker_poll(worker, 8u, &callbacks) == FTUN_OK);
  CHECK(ftun_worker_destroy(&worker) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(remove_store(directory));
  return 0;
}
