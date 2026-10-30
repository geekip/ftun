/* 新增测试协议只实现通用出口；宿主配置不依赖app或Proxy布局。 */
#include "dns/service_internal.h"
#include "core/context.h"
#include "core/event/backend.h"
#include "support/memory_path_factory.c"

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "DNS egress failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

struct ftun_config {
  ftun_config_document_t document;
  uint64_t marker;
  ftun_config_dns_t dns;
};
static ftun_dns_config_binding_t binding(const ftun_config_t *config)
{
  (void)config;
  return (ftun_dns_config_binding_t){0};
}
static const void *section(const ftun_config_t *config, uint32_t id)
{
  static const ftun_dns_config_binding_ops_t bindings = {binding};
  if (id == FTUN_CONFIG_SECTION_DNS) return &config->dns;
  if (id == FTUN_CONFIG_SECTION_DNS_BINDING) return &bindings;
  return NULL;
}
typedef struct { size_t references, streams, datagrams; bool stream_only; } fake_t;
static ftun_status_t query(const void *context, uint32_t id, uint64_t generation,
  ftun_egress_info_t *out)
{
  const fake_t *fake = context;
  if (generation != 7u) return FTUN_E_STALE;
  if (id != 42u) return FTUN_E_REJECTED;
  *out = (ftun_egress_info_t){0};
  out->id = id;
  out->configuration_generation = generation;
  out->capabilities = FTUN_EGRESS_CAP_STREAM |
    (fake->stream_only ? 0u : FTUN_EGRESS_CAP_DATAGRAM);
  out->state = FTUN_EGRESS_STATE_AVAILABLE;
  out->provider_kind = "test-tunnel";
  return FTUN_OK;
}
static ftun_status_t resolve(const void *context, const ftun_config_t *config,
  ftun_string_t name, ftun_egress_info_t *out)
{
  (void)config;
  if (name.length != 11u || memcmp(name.data, "test-tunnel", 11u) != 0) return FTUN_E_REJECTED;
  return query(context, 42u, 7u, out);
}
static ftun_status_t validate(const void *context, uint32_t root, uint32_t leaf,
  uint64_t generation)
{
  ftun_egress_info_t info;
  return root == leaf ? query(context, leaf, generation, &info) : FTUN_E_REJECTED;
}
static void retain(void *context) { ((fake_t *)context)->references++; }
static void release(void *context) { ((fake_t *)context)->references--; }
static ftun_status_t open_path(void *context, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *spec,
  ftun_operation_t **out)
{
  fake_t *fake = context;
  ftun_path_open_request_t physical = *request;
  ftun_egress_info_t info;
  ftun_status_t status = query(fake, request->egress, spec->configuration_generation, &info);
  if (status != FTUN_OK) return status;
  if (spec->endpoint.port != 53u || request->dial.endpoint.port != 53u) return FTUN_E_REJECTED;
  if (request->dial.transport == FTUN_DIAL_TCP) fake->streams++;
  else fake->datagrams++;
  physical.egress = FTUN_EGRESS_DIRECT;
  return __wrap_ftun_socket_path_open(NULL, core, &physical, spec, out);
}
static void done(ftun_operation_t *operation, ftun_error_t error,
  ftun_bytes_t response, void *context)
{
  ftun_status_t *result = context;
  (void)operation;
  *result = error.status == FTUN_OK && response.length != 27u ? FTUN_E_PROTOCOL : error.status;
}
static int run(bool tcp, bool fallback, bool stream_only)
{
  static const ftun_config_document_ops_t ops = {NULL, NULL, section};
  ftun_config_t config = {0};
  ftun_config_dns_server_t server = {0};
  char *address = "192.0.2.53:53";
  fake_t fake = {0};
  ftun_egress_provider_t provider = {resolve, query, open_path, &fake, retain, release, validate};
  ftun_dns_runtime_network_t network = {.generation = 7u,
    .path = {.open = open_path}, .egress = &provider};
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_operation_t *operation = NULL;
  ftun_dns_runtime_t *dns = NULL;
  ftun_dns_query_t request = {0};
  uint8_t wire[] = {0u, 100u, 1u, 0u, 0u, 1u, 0u, 0u, 0u, 0u, 0u, 0u,
    1u, 'a', 7u, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0u, 0u, 1u, 0u, 1u};
  ftun_status_t result = FTUN_E_AGAIN, status;
  size_t work, round;
  CHECK(ftun_budget_create(NULL, 8u * 1024u * 1024u, 1024u, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 64u, &operations) == FTUN_OK);
  CHECK(ftun_event_loop_create_with_capacity(core, 128u, &loop) == FTUN_OK);
  CHECK(ftun_event_backend_attach(loop) == FTUN_OK);
  config.document.reference_count = 1u;
  config.document.ops = &ops;
  config.marker = UINT64_C(0x1122334455667788);
  config.dns.enable = true;
  config.dns.default_server = "real";
  config.dns.servers = &server;
  config.dns.server_count = 1u;
  server.name = "real";
  server.type = tcp ? "tcp" : "udp";
  server.addresses = (ftun_config_string_list_t){&address, 1u};
  server.outbound = "test-tunnel";
  fake.stream_only = stream_only;
  status = ftun_dns_runtime_prepare(core, budget, operations, loop, &config, NULL, &network, &dns);
  CHECK(status == (stream_only && !tcp ? FTUN_E_UNSUPPORTED : FTUN_OK));
  if (status == FTUN_OK) {
    CHECK(fake.references == 1u);
    CHECK(ftun_dns_runtime_activate(dns) == FTUN_OK);
    wire[1] = (uint8_t)(wire[1] + (fallback ? 1u : 0u));
    request.id = wire[1];
    request.flags = 0x100u;
    request.resolution_mode = 1u;
    request.question.name = (ftun_dns_name_t){wire + 12u, 11u};
    request.question.type = request.question.class_code = 1u;
    request.wire = (ftun_bytes_t){wire, sizeof(wire)};
    request.deadline_ms = ftun_dns_runtime_now(NULL) + 3000u;
    request.completion = done;
    request.completion_user = &result;
    CHECK(ftun_dns_exchange(core, dns->servers[0], &request, &operation) == FTUN_OK);
    for (round = 0u; round < 4096u && result == FTUN_E_AGAIN; round++) {
      CHECK(ftun_event_loop_run_once(loop, false, 64u, &work) == FTUN_OK);
      CHECK(ftun_operation_dispatch(operations, 64u, &work) == FTUN_OK);
      CHECK(ftun_dns_runtime_run_once(dns, 64u, &work) == FTUN_OK);
    }
    CHECK(result == FTUN_OK);
    CHECK(fake.datagrams == (tcp ? 0u : 1u) && fake.streams == (tcp || fallback ? 1u : 0u));
  }
  CHECK(ftun_dns_runtime_destroy(&dns) == FTUN_OK);
  CHECK(fake.references == 0u && config.document.reference_count == 1u);
  CHECK(config.marker == UINT64_C(0x1122334455667788));
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_backend_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}
int main(void)
{
  CHECK(run(false, false, false) == 0);
  CHECK(run(true, false, false) == 0);
  CHECK(run(false, true, false) == 0);
  CHECK(run(false, false, true) == 0);
  CHECK(run(true, false, true) == 0);
  return 0;
}
