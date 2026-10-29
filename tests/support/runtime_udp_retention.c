#define _POSIX_C_SOURCE 200809L
#include "libs/tun/service.h"
#include "proxy/runtime.h"
#include "proxy/netstack/ingress.h"
#include "proxy/dns/resolver_adapter.h"
#include "libs/transport/socket_path.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "platform/clock.h"

#define REQUIRE(value) do { if (!(value)) { \
  fprintf(stderr, "UDP retention failed at %d: %s\n", __LINE__, #value); \
  abort(); } } while (0)

static ftun_tun_ingress_spec_t ingress;
static ftun_bootstrap_request_t pending;
static ftun_operation_token_t pending_token;
static ftun_datagram_t *channel;
static ftun_packet_t packet;
static unsigned int destroyed, path_opens, completions;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
typedef struct { int step; bool done, result; } command_t;
#if defined(FTUN_TEST_TUN_UDP_RECOVERY)
static ftun_tun_lease_t lease;
static unsigned int binds, cancels;
static ftun_status_t cancel_delayed(void *user)
{ (void)user; cancels++; return FTUN_E_AGAIN; }
ftun_status_t __real_ftun_l3_provider_acquire(const ftun_l3_provider_t *,
  uint64_t, const ftun_tun_consumer_spec_t *, ftun_tun_lease_t *);
ftun_status_t __wrap_ftun_l3_provider_acquire(const ftun_l3_provider_t *provider,
  uint64_t generation, const ftun_tun_consumer_spec_t *spec, ftun_tun_lease_t *out)
{
  ftun_status_t status = __real_ftun_l3_provider_acquire(provider, generation, spec, out);
  if (status == FTUN_OK) lease = *out;
  return status;
}
#endif

ftun_status_t __real_ftun_tun_ingress_bind(const ftun_tun_ingress_spec_t *,
  ftun_tun_ingress_context_t **);

ftun_status_t __wrap_ftun_tun_ingress_bind(const ftun_tun_ingress_spec_t *spec,
  ftun_tun_ingress_context_t **out)
{
  ingress = *spec;
#if defined(FTUN_TEST_TUN_UDP_RECOVERY)
  binds++;
#endif
  return __real_ftun_tun_ingress_bind(spec, out);
}

static void resolved(ftun_operation_t *operation, ftun_error_t error, void *user)
{
  ftun_system_resolve_result_t result = {0};
  ftun_endpoint_t address = {0};
  (void)user;
  result.address_count = 1u;
  result.addresses = &address;
  address.kind = FTUN_ADDRESS_IPV4;
  address.address[0] = 127u;
  address.address[3] = 1u;
  completions++;
  pending.completion(operation, error, &result, pending.user);
}

ftun_status_t __wrap_ftun_proxy_dns_resolve_with_provider(ftun_core_t *core,
  ftun_resolver_scope_t *scope, bool dns_enabled, ftun_string_t server,
  const ftun_bootstrap_request_t *query, ftun_dial_purpose_t purpose,
  ftun_operation_t **out)
{
  (void)core; (void)scope; (void)dns_enabled; (void)server;
  REQUIRE(purpose == FTUN_DIAL_PURPOSE_BUSINESS);
  REQUIRE(query->domain.length == 12u &&
    memcmp(query->domain.data, "late.example", 12u) == 0);
  pending = *query;
  {
    ftun_status_t status = ftun_operation_accept(query->operations, resolved, NULL, out, &pending_token);
#if defined(FTUN_TEST_TUN_UDP_RECOVERY)
    if (status == FTUN_OK) REQUIRE(ftun_operation_set_cancel_hook(*out, cancel_delayed, NULL) == FTUN_OK);
#endif
    return status;
  }
}

ftun_status_t __wrap_ftun_socket_path_open(void *context, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *spec,
  ftun_operation_t **out)
{
  (void)context; (void)core; (void)request; (void)spec;
  path_opens++;
  *out = NULL;
  return FTUN_E_LIMIT;
}

static ftun_status_t send_unexpected(void *user, ftun_datagram_send_token_t token,
  const ftun_endpoint_t *target, const ftun_packet_t *data)
{ (void)user; (void)token; (void)target; (void)data; abort(); }

static ftun_status_t cancel_unexpected(void *user, ftun_datagram_send_token_t token)
{ (void)user; (void)token; abort(); }

static void destroy_channel(void *user)
{ (void)user; destroyed++; }

static void owner_command(ftun_operation_t *operation, ftun_error_t error, void *user)
{
  command_t *command = user;
  ftun_datagram_usage_t usage;
  (void)operation;
  REQUIRE(error.status == FTUN_OK);
  command->result = true;
  if (command->step == 0) {
    ftun_buffer_t *buffer = NULL;
    ftun_buffer_slice_t slice = {0};
    ftun_datagram_options_t options = {0};
    ftun_datagram_backend_t backend = {
      send_unexpected, cancel_unexpected, destroy_channel, NULL};
    ftun_metadata_t metadata = {0};
    options.budget = ingress.budget;
    options.max_pending_packets = 1u;
    options.max_pending_bytes = 128u;
    REQUIRE(ftun_datagram_create(&options, &backend, &channel) == FTUN_OK);
    REQUIRE(ftun_buffer_acquire(ingress.budget, 1u, &buffer) == FTUN_OK);
    REQUIRE(ftun_buffer_slice(buffer, 0u, 0u, &slice) == FTUN_OK);
    REQUIRE(ftun_packet_init(&packet, &slice, ingress.inbound_id) == FTUN_OK);
    REQUIRE(ftun_buffer_slice_release(&slice) == FTUN_OK);
    REQUIRE(ftun_buffer_release(&buffer) == FTUN_OK);
    metadata.generation = ingress.generation;
    metadata.inbound_id = ingress.inbound_id;
    metadata.network = 2u;
    metadata.known_fields = FTUN_META_SOURCE | FTUN_META_PORT |
      FTUN_META_NETWORK | FTUN_META_DOMAIN;
    metadata.source.kind = FTUN_ADDRESS_IPV4;
    metadata.source.address[0] = 10u;
    metadata.source.address[3] = 2u;
    metadata.source.port = 12345u;
    metadata.original_target.port = 9u;
    metadata.domain = (ftun_string_t){"late.example", 12u};
    /* 真实 TUN 回调校验 IPv4 目标；带域名元数据触发实际异步路由。 */
    metadata.original_target.kind = FTUN_ADDRESS_IPV4;
    metadata.original_target.domain = (ftun_string_t){0};
    metadata.original_target.address[0] = 10u;
    metadata.original_target.address[3] = 3u;
    metadata.original_is_fake = true;
    metadata.domain_source = FTUN_DOMAIN_FAKEIP;
    REQUIRE(ingress.datagram_receive(ingress.user, &metadata, channel,
      &metadata.original_target, &packet) == FTUN_OK);
    REQUIRE(pending_token.queue != NULL);
#if !defined(FTUN_TEST_TUN_UDP_RECOVERY)
    REQUIRE(ftun_datagram_stop(channel) == FTUN_OK);
    REQUIRE(ftun_datagram_destroy(&channel) == FTUN_E_AGAIN && destroyed == 0u);
    REQUIRE(ftun_operation_complete(pending_token, (ftun_error_t){FTUN_OK, 0u, 0}) == FTUN_OK);
#endif
#if defined(FTUN_TEST_TUN_UDP_RECOVERY)
  } else if (command->step == 1) {
    REQUIRE(ftun_tun_service_rebuild(lease.service) == FTUN_OK && binds == 1u);
  } else if (command->step == 2) {
    command->result = cancels != 0u;
    REQUIRE(binds == 1u && completions == 0u);
    REQUIRE(ftun_datagram_get_usage(channel, &usage) == FTUN_OK && usage.reference_count == 2u);
    if (command->result) REQUIRE(ftun_operation_complete(pending_token,
      (ftun_error_t){FTUN_OK, 0u, 0}) == FTUN_OK);
#endif
  } else {
#if defined(FTUN_TEST_TUN_UDP_RECOVERY)
    if (binds != 2u) { command->result = false; goto done; }
    REQUIRE(ftun_datagram_get_usage(channel, &usage) == FTUN_OK && usage.accepting);
    REQUIRE(ftun_datagram_stop(channel) == FTUN_OK);
#endif
    REQUIRE(completions == 1u && path_opens == 0u);
    REQUIRE(ftun_datagram_get_usage(channel, &usage) == FTUN_OK &&
      usage.reference_count == 1u && !usage.accepting);
    REQUIRE(ftun_datagram_destroy(&channel) == FTUN_OK && destroyed == 1u);
    REQUIRE(ftun_packet_release(&packet) == FTUN_OK);
  }
#if defined(FTUN_TEST_TUN_UDP_RECOVERY)
done:
#endif
  (void)pthread_mutex_lock(&mutex);
  command->done = true;
  (void)pthread_cond_signal(&condition);
  (void)pthread_mutex_unlock(&mutex);
}

int ftun_test_tun_admission(ftun_core_t *core)
{
  int step;
#if defined(FTUN_TEST_TUN_UDP_RECOVERY)
  const int steps = 4;
#else
  const int steps = 2;
#endif
  for (step = 0; step < steps; step++) {
    uint64_t started = 0u, now = 0u;
    bool ready = false;
    REQUIRE(ftun_monotonic_now(&started) == FTUN_OK);
    while (!ready) {
      command_t command = {step, false, false};
      ftun_operation_t *operation = NULL;
      struct timespec until;
      const struct timespec pause = {0, 1000000};
      REQUIRE(clock_gettime(CLOCK_REALTIME, &until) == 0);
      until.tv_sec += 5;
      REQUIRE(ftun_core_post(core, owner_command, &command, &operation) == FTUN_OK);
      (void)pthread_mutex_lock(&mutex);
      while (!command.done) REQUIRE(pthread_cond_timedwait(&condition, &mutex, &until) == 0);
      ready = command.result;
      (void)pthread_mutex_unlock(&mutex);
      REQUIRE(ftun_monotonic_now(&now) == FTUN_OK && now - started < 5000u);
      if (!ready) (void)nanosleep(&pause, NULL);
    }
  }
  puts("UDP pending retains ingress; stopped input or rebuild prevents late success from opening a path");
  return 0;
}
