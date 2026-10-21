#include "core/budget.h"
#include "proxy/runtime_state.h"
#include "proxy/inbound/inbound.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "inbound contract failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

#define TEST_INVALID_SOCKET ((ftun_native_socket_t)UINTPTR_MAX)

typedef struct {
  ftun_status_t listener_open_status;
  ftun_status_t listener_close_status;
  ftun_status_t packet_open_status;
  ftun_status_t packet_close_status;
  ftun_status_t stream_ingress_status;
  ftun_status_t packet_ingress_status;
  ftun_native_socket_t listener;
  char inbound_name[FTUN_INBOUND_NAME_BYTES];
  char tun_name[FTUN_PACKET_PORT_NAME_BYTES];
  ftun_endpoint_t listen;
  uint32_t mtu;
  int corrupt_listener;
  int corrupt_packet;
  int listener_open_calls;
  int listener_close_calls;
  int packet_open_calls;
  int packet_close_calls;
  int stream_ingress_calls;
  int packet_ingress_calls;
  ftun_inbound_kind_t ingress_kind;
} backend_state_t;

typedef struct {
  ftun_budget_t *budget;
  ftun_core_t *core;
  backend_state_t state;
  ftun_inbound_backend_t backend;
} fixture_t;

static ftun_status_t listener_open(void *user,
                                   const ftun_inbound_spec_t *spec,
                                   ftun_native_socket_t *out)
{
  backend_state_t *state = (backend_state_t *)user;
  if (out != NULL) *out = TEST_INVALID_SOCKET;
  state->listener_open_calls++;
  if (state->listener_open_status != FTUN_OK) {
    return state->listener_open_status;
  }
  memcpy(state->inbound_name, spec->name.data, spec->name.length);
  state->inbound_name[spec->name.length] = '\0';
  state->listen = spec->listen;
  if (!state->corrupt_listener) {
    state->listener = 101u;
    *out = state->listener;
  }
  return FTUN_OK;
}

static ftun_status_t listener_close(void *user, ftun_native_socket_t *listener)
{
  backend_state_t *state = (backend_state_t *)user;
  state->listener_close_calls++;
  if (listener == NULL || *listener != state->listener) return FTUN_E_INVALID;
  *listener = TEST_INVALID_SOCKET;
  state->listener = TEST_INVALID_SOCKET;
  return state->listener_close_status;
}

static ftun_status_t packet_open(void *user, ftun_core_t *core,
                                 const ftun_tun_spec_t *spec,
                                 ftun_packet_port_t **out)
{
  backend_state_t *state = (backend_state_t *)user;
  (void)core;
  if (out != NULL) *out = NULL;
  state->packet_open_calls++;
  if (state->packet_open_status != FTUN_OK) return state->packet_open_status;
  memcpy(state->tun_name, spec->name.data, spec->name.length);
  state->tun_name[spec->name.length] = '\0';
  state->mtu = spec->mtu;
  if (!state->corrupt_packet) {
    *out = (ftun_packet_port_t *)(uintptr_t)201u;
  }
  return FTUN_OK;
}

static ftun_status_t packet_close(void *user, ftun_packet_port_t **port)
{
  backend_state_t *state = (backend_state_t *)user;
  state->packet_close_calls++;
  if (port == NULL || *port != (ftun_packet_port_t *)(uintptr_t)201u) {
    return FTUN_E_INVALID;
  }
  *port = NULL;
  return state->packet_close_status;
}

static ftun_status_t stream_ingress(void *user, ftun_core_t *core,
                                    ftun_inbound_kind_t kind,
                                    ftun_stream_t *stream)
{
  backend_state_t *state = (backend_state_t *)user;
  (void)core;
  if (stream != (ftun_stream_t *)(uintptr_t)301u) return FTUN_E_INVALID;
  state->stream_ingress_calls++;
  state->ingress_kind = kind;
  return state->stream_ingress_status;
}

static ftun_status_t packet_ingress(void *user, ftun_core_t *core,
                                    ftun_packet_port_t *port,
                                    ftun_packet_t *packet)
{
  backend_state_t *state = (backend_state_t *)user;
  (void)core;
  if (port != (ftun_packet_port_t *)(uintptr_t)201u ||
      packet != (ftun_packet_t *)(uintptr_t)302u) return FTUN_E_INVALID;
  state->packet_ingress_calls++;
  return state->packet_ingress_status;
}

static int fixture_start(fixture_t *fixture)
{
  memset(fixture, 0, sizeof(*fixture));
  if (ftun_budget_create(NULL, 65536u, 0u, &fixture->budget) != FTUN_OK) {
    return 1;
  }
  if (ftun_runtime_manager_create(fixture->budget, 1u,
                                  &fixture->core) != FTUN_OK) return 1;
  fixture->state.listener = TEST_INVALID_SOCKET;
  fixture->backend.kind_mask = FTUN_INBOUND_KIND_MASK_MIXED |
                               FTUN_INBOUND_KIND_MASK_SOCKS5 |
                               FTUN_INBOUND_KIND_MASK_TUN;
  fixture->backend.listener_open = listener_open;
  fixture->backend.listener_close = listener_close;
  fixture->backend.packet_open = packet_open;
  fixture->backend.packet_close = packet_close;
  fixture->backend.stream_ingress = stream_ingress;
  fixture->backend.packet_ingress = packet_ingress;
  fixture->backend.context = &fixture->state;
  return 0;
}

static int fixture_stop(fixture_t *fixture)
{
  ftun_budget_usage_t usage;
  if (ftun_runtime_manager_destroy(&fixture->core) != FTUN_OK) return 1;
  if (ftun_budget_get_usage(fixture->budget, &usage) != FTUN_OK ||
      usage.used != 0u) return 1;
  return ftun_budget_destroy(&fixture->budget) == FTUN_OK ? 0 : 1;
}

static ftun_endpoint_t listen_endpoint(uint16_t port)
{
  ftun_endpoint_t endpoint;
  memset(&endpoint, 0, sizeof(endpoint));
  endpoint.kind = FTUN_ADDRESS_IPV4;
  endpoint.address[0] = 127u;
  endpoint.address[3] = 1u;
  endpoint.port = port;
  return endpoint;
}

static void fill_listener_spec(ftun_inbound_spec_t *spec,
                               fixture_t *fixture, ftun_inbound_kind_t kind,
                               char *name)
{
  memset(spec, 0, sizeof(*spec));
  spec->budget = fixture->budget;
  spec->kind = kind;
  spec->generation = 9u;
  spec->id = 12u;
  spec->name.data = name;
  spec->name.length = strlen(name);
  spec->tcp = true;
  spec->udp = true;
  spec->listen = listen_endpoint(1080u);
}

static void fill_tun_spec(ftun_inbound_spec_t *spec, fixture_t *fixture,
                          char *name, char *device)
{
  memset(spec, 0, sizeof(*spec));
  spec->budget = fixture->budget;
  spec->kind = FTUN_INBOUND_TUN;
  spec->generation = 10u;
  spec->id = 13u;
  spec->name.data = name;
  spec->name.length = strlen(name);
  spec->tcp = true;
  spec->udp = true;
  spec->tun.name.data = device;
  spec->tun.name.length = strlen(device);
  spec->tun.mtu = 1500u;
}

static void fill_adapter_metadata(ftun_metadata_t *metadata, uint8_t network)
{
  static const char domain[] = "client.example";
  memset(metadata, 0, sizeof(*metadata));
  metadata->known_fields = FTUN_META_SOURCE | FTUN_META_PORT |
                           FTUN_META_NETWORK | FTUN_META_DOMAIN;
  metadata->network = network;
  metadata->source = listen_endpoint(40000u);
  metadata->original_target.kind = FTUN_ADDRESS_DOMAIN;
  metadata->original_target.domain.data = domain;
  metadata->original_target.domain.length = sizeof(domain) - 1u;
  metadata->original_target.port = 443u;
  metadata->domain = metadata->original_target.domain;
  metadata->domain_source = FTUN_DOMAIN_EXPLICIT;
}

static int test_listener_identity_and_policy(void)
{
  fixture_t fixture;
  ftun_inbound_spec_t spec;
  ftun_inbound_t *inbound = NULL;
  ftun_inbound_info_t info;
  ftun_inbound_policy_t policy;
  ftun_metadata_t adapter;
  ftun_metadata_t bound;
  char name[] = "mixed-main";
  CHECK(fixture_start(&fixture) == 0);
  fill_listener_spec(&spec, &fixture, FTUN_INBOUND_MIXED, name);
  spec.fixed_outbound_id = 77u;
  CHECK(ftun_inbound_prepare_with_backend(fixture.core, &spec,
        &fixture.backend, &inbound) == FTUN_OK && inbound != NULL);
  CHECK(fixture.state.listener_open_calls == 1 &&
        fixture.state.packet_open_calls == 0 &&
        strcmp(fixture.state.inbound_name, "mixed-main") == 0 &&
        fixture.state.listen.port == 1080u);
  memset(name, 'x', strlen(name));
  spec.listen.port = 9999u;
  CHECK(ftun_inbound_get_info(inbound, &info) == FTUN_OK &&
        info.kind == FTUN_INBOUND_MIXED &&
        info.resource_kind == FTUN_INBOUND_RESOURCE_LISTENER &&
        info.generation == 9u && info.id == 12u &&
        strcmp(info.name, "mixed-main") == 0 && info.tcp && info.udp &&
        info.accepting);
  CHECK(ftun_inbound_get_policy(inbound, &policy) == FTUN_OK &&
        policy.generation == 9u && policy.inbound_id == 12u &&
        policy.forced && policy.fixed_outbound_id == 77u);
  fill_adapter_metadata(&adapter, 1u);
  CHECK(ftun_inbound_bind_metadata(inbound, &adapter, &bound) == FTUN_OK &&
        bound.generation == 9u && bound.inbound_id == 12u &&
        bound.network == 1u && bound.domain.data == adapter.domain.data);
  CHECK(ftun_inbound_stream_ingress(
        inbound, (ftun_stream_t *)(uintptr_t)301u) == FTUN_OK &&
        fixture.state.stream_ingress_calls == 1 &&
        fixture.state.ingress_kind == FTUN_INBOUND_MIXED);
  CHECK(ftun_inbound_packet_ingress(
        inbound, (ftun_packet_t *)(uintptr_t)302u) == FTUN_E_UNSUPPORTED &&
        fixture.state.packet_ingress_calls == 0);
  adapter.generation = 3u;
  CHECK(ftun_inbound_bind_metadata(inbound, &adapter, &bound) ==
        FTUN_E_INVALID && bound.generation == 0u);
  CHECK(ftun_inbound_close(&inbound) == FTUN_OK && inbound == NULL &&
        fixture.state.listener_close_calls == 1);
  CHECK(ftun_inbound_close(&inbound) == FTUN_OK);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_listener_transport_and_close_error(void)
{
  fixture_t fixture;
  ftun_inbound_spec_t spec;
  ftun_inbound_t *inbound = NULL;
  ftun_metadata_t adapter;
  ftun_metadata_t bound;
  char name[] = "socks";
  CHECK(fixture_start(&fixture) == 0);
  fill_listener_spec(&spec, &fixture, FTUN_INBOUND_SOCKS5, name);
  spec.udp = false;
  CHECK(ftun_inbound_prepare_with_backend(fixture.core, &spec,
        &fixture.backend, &inbound) == FTUN_OK);
  fill_adapter_metadata(&adapter, 2u);
  CHECK(ftun_inbound_bind_metadata(inbound, &adapter, &bound) ==
        FTUN_E_UNSUPPORTED);
  fill_adapter_metadata(&adapter, 1u);
  CHECK(ftun_inbound_bind_metadata(inbound, &adapter, &bound) == FTUN_OK);
  fixture.state.listener_close_status = FTUN_E_IO;
  CHECK(ftun_inbound_close(&inbound) == FTUN_E_IO && inbound == NULL);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_tun_packet_resource(void)
{
  fixture_t fixture;
  ftun_inbound_spec_t spec;
  ftun_inbound_t *inbound = NULL;
  ftun_inbound_info_t info;
  char name[] = "tun-main";
  char device[] = "ftun0";
  CHECK(fixture_start(&fixture) == 0);
  fill_tun_spec(&spec, &fixture, name, device);
  CHECK(ftun_inbound_prepare_with_backend(fixture.core, &spec,
        &fixture.backend, &inbound) == FTUN_OK && inbound != NULL);
  CHECK(fixture.state.packet_open_calls == 1 &&
        fixture.state.listener_open_calls == 0 &&
        strcmp(fixture.state.tun_name, "ftun0") == 0 &&
        fixture.state.mtu == 1500u);
  memset(name, 'x', strlen(name));
  memset(device, 'y', strlen(device));
  CHECK(ftun_inbound_get_info(inbound, &info) == FTUN_OK &&
        info.kind == FTUN_INBOUND_TUN &&
        info.resource_kind == FTUN_INBOUND_RESOURCE_PACKET_PORT &&
        strcmp(info.name, "tun-main") == 0);
  CHECK(ftun_inbound_packet_ingress(
        inbound, (ftun_packet_t *)(uintptr_t)302u) == FTUN_OK &&
        fixture.state.packet_ingress_calls == 1);
  CHECK(ftun_inbound_stream_ingress(
        inbound, (ftun_stream_t *)(uintptr_t)301u) == FTUN_E_UNSUPPORTED &&
        fixture.state.stream_ingress_calls == 0);
  CHECK(ftun_inbound_close(&inbound) == FTUN_OK &&
        fixture.state.packet_close_calls == 1);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

static int test_failures_and_boundaries(void)
{
  fixture_t fixture;
  ftun_inbound_spec_t spec;
  ftun_inbound_t *inbound = (ftun_inbound_t *)(uintptr_t)1u;
  ftun_inbound_backend_t invalid;
  ftun_budget_t *tiny = NULL;
  char name[] = "boundary";
  CHECK(fixture_start(&fixture) == 0);
  fill_listener_spec(&spec, &fixture, FTUN_INBOUND_MIXED, name);
  fixture.state.listener_open_status = FTUN_E_REJECTED;
  CHECK(ftun_inbound_prepare_with_backend(fixture.core, &spec,
        &fixture.backend, &inbound) == FTUN_E_REJECTED && inbound == NULL);
  fixture.state.listener_open_status = FTUN_OK;
  fixture.state.corrupt_listener = 1;
  CHECK(ftun_inbound_prepare_with_backend(fixture.core, &spec,
        &fixture.backend, &inbound) == FTUN_E_STATE_CORRUPT && inbound == NULL);
  fixture.state.corrupt_listener = 0;
  CHECK(ftun_inbound_prepare(fixture.core, &spec, &inbound) ==
        FTUN_E_UNSUPPORTED && inbound == NULL);
  fixture.backend.kind_mask = FTUN_INBOUND_KIND_MASK_SOCKS5;
  CHECK(ftun_inbound_prepare_with_backend(fixture.core, &spec,
        &fixture.backend, &inbound) == FTUN_E_UNSUPPORTED && inbound == NULL);
  fixture.backend.kind_mask = FTUN_INBOUND_KIND_MASK_MIXED |
                              FTUN_INBOUND_KIND_MASK_SOCKS5 |
                              FTUN_INBOUND_KIND_MASK_TUN;
  invalid = fixture.backend;
  invalid.packet_ingress = NULL;
  CHECK(ftun_inbound_prepare_with_backend(fixture.core, &spec,
        &invalid, &inbound) == FTUN_E_INVALID && inbound == NULL);
  CHECK(ftun_inbound_prepare_with_backend(NULL, &spec, &fixture.backend,
        &inbound) == FTUN_E_INVALID && inbound == NULL);
  CHECK(ftun_inbound_prepare_with_backend(fixture.core, NULL,
        &fixture.backend, &inbound) == FTUN_E_INVALID && inbound == NULL);
  CHECK(ftun_inbound_prepare_with_backend(fixture.core, &spec,
        &fixture.backend, NULL) == FTUN_E_INVALID);
  spec.tcp = false;
  CHECK(ftun_inbound_prepare_with_backend(fixture.core, &spec,
        &fixture.backend, &inbound) == FTUN_E_INVALID);
  spec.tcp = true;
  spec.listen.port = 0u;
  CHECK(ftun_inbound_prepare_with_backend(fixture.core, &spec,
        &fixture.backend, &inbound) == FTUN_E_INVALID);
  spec.listen.port = 1080u;
  spec.generation = 0u;
  CHECK(ftun_inbound_prepare_with_backend(fixture.core, &spec,
        &fixture.backend, &inbound) == FTUN_E_INVALID);
  spec.generation = 9u;
  CHECK(ftun_budget_create(NULL, 1u, 0u, &tiny) == FTUN_OK);
  spec.budget = tiny;
  CHECK(ftun_inbound_prepare_with_backend(fixture.core, &spec,
        &fixture.backend, &inbound) == FTUN_E_LIMIT && inbound == NULL);
  CHECK(ftun_budget_destroy(&tiny) == FTUN_OK);
  CHECK(ftun_inbound_get_info(NULL, &(ftun_inbound_info_t){0}) ==
        FTUN_E_INVALID);
  CHECK(ftun_inbound_get_policy(NULL, &(ftun_inbound_policy_t){0}) ==
        FTUN_E_INVALID);
  CHECK(ftun_inbound_close(NULL) == FTUN_E_INVALID);
  CHECK(fixture.state.listener_close_calls == 0 &&
        fixture.state.packet_close_calls == 0);
  CHECK(fixture_stop(&fixture) == 0);
  return 0;
}

/* TASK-INBOUND-001 / TEST-INBOUND-001：资源工厂、能力和策略身份。 */
int main(void)
{
  CHECK(test_listener_identity_and_policy() == 0);
  CHECK(test_listener_transport_and_close_error() == 0);
  CHECK(test_tun_packet_resource() == 0);
  CHECK(test_failures_and_boundaries() == 0);
  return 0;
}
