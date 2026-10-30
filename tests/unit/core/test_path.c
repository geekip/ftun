#define _POSIX_C_SOURCE 200809L
#include <sys/types.h>
#include "core/context.h"
#include "libs/transport/path.h"

#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "path contract failed at %d: %s\n", __LINE__, #x); \
  return 1; } } while (0)

typedef struct {
  unsigned int calls;
  unsigned int starts;
  ftun_error_t error;
  ftun_dial_result_t result;
} completion_state_t;

static void completed(ftun_operation_t *operation, ftun_error_t error,
  const ftun_dial_result_t *result, void *user)
{
  completion_state_t *state = (completion_state_t *)user;
  (void)operation;
  state->calls++;
  state->error = error;
  if (result != NULL) state->result = *result;
}

static ftun_status_t start(void *user, ftun_core_t *core,
  const ftun_dial_request_t *request, ftun_operation_t **out)
{
  completion_state_t *state = (completion_state_t *)user;
  state->starts++;
  return ftun_dial_start(core, request, out);
}

static int dispatched(ftun_operation_queue_t *operations,
  completion_state_t *state, ftun_status_t expected)
{
  size_t count = 0u;
  unsigned int previous = state->calls;
  CHECK(ftun_operation_dispatch(operations, 8u, &count) == FTUN_OK);
  CHECK(count == 1u && state->calls == previous + 1u);
  CHECK(state->error.status == expected);
  return 0;
}

static int exchange(completion_state_t *state, int server,
  uint64_t network_generation)
{
  const unsigned char payload[] = {0u, 1u, 0xffu, 3u};
  unsigned char received[sizeof(payload) + 1u];
  struct sockaddr_in client;
  socklen_t length = sizeof(client);
  struct pollfd ready;
  int fd = (int)state->result.socket;
  CHECK(state->result.domain == FTUN_DIAL_DOMAIN_UNDERLAY &&
        state->result.network_generation == network_generation);
  CHECK(send(fd, payload, sizeof(payload), 0) == (ssize_t)sizeof(payload));
  ready.fd = server;
  ready.events = POLLIN;
  ready.revents = 0;
  CHECK(poll(&ready, 1u, 1000) == 1 && (ready.revents & POLLIN) != 0);
  CHECK(recvfrom(server, received, sizeof(received), MSG_DONTWAIT,
        (struct sockaddr *)&client, &length) == (ssize_t)sizeof(payload));
  CHECK(memcmp(received, payload, sizeof(payload)) == 0);
  CHECK(sendto(server, received, sizeof(payload), 0,
        (const struct sockaddr *)&client, length) == (ssize_t)sizeof(payload));
  ready.fd = fd;
  ready.revents = 0;
  CHECK(poll(&ready, 1u, 1000) == 1 && (ready.revents & POLLIN) != 0);
  CHECK(recv(fd, received, sizeof(received), MSG_DONTWAIT) ==
        (ssize_t)sizeof(payload));
  CHECK(memcmp(received, payload, sizeof(payload)) == 0);
  CHECK(close(fd) == 0);
  state->result.socket = FTUN_INVALID_SOCKET;
  return 0;
}

static int rejected(ftun_path_provider_t *provider, ftun_core_t *core,
  uint64_t configuration_generation, const ftun_dial_request_t *request,
  completion_state_t *state, ftun_status_t expected)
{
  ftun_operation_t *operation = (ftun_operation_t *)(uintptr_t)1;
  ftun_budget_usage_t before, after;
  unsigned int previous = state->calls;
  size_t count = 0u;
  CHECK(ftun_budget_get_usage(request->budget, &before) == FTUN_OK);
  CHECK(ftun_path_provider_open_datagram(provider, core,
        configuration_generation, request, &operation) == expected);
  CHECK(operation == NULL);
  CHECK(ftun_operation_dispatch(request->operations, 8u, &count) == FTUN_OK);
  CHECK(count == 0u && state->calls == previous);
  CHECK(ftun_budget_get_usage(request->budget, &after) == FTUN_OK);
  CHECK(before.used_resources.memory_bytes == after.used_resources.memory_bytes);
  return 0;
}

int main(void)
{
  ftun_budget_t *budget = NULL;
  ftun_budget_usage_t usage;
  ftun_core_t *core = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_path_provider_t *provider = NULL;
  ftun_path_provider_spec_t spec = {0};
  ftun_network_view_spec_t view_spec = {0};
  ftun_network_prefix_t protected_prefix = {{FTUN_IP_V4, {127u, 0u, 0u, 0u}}, 8u};
  ftun_network_view_t *open_view = NULL, *closed_view = NULL;
  ftun_dial_request_t request = {0};
  ftun_operation_t *operation = NULL;
  completion_state_t state = {0};
  ftun_endpoint_t allowed;
  struct sockaddr_in address;
  socklen_t length = sizeof(address);
  unsigned int starts;
  int server;

  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  server = socket(AF_INET, SOCK_DGRAM, 0);
  CHECK(server >= 0);
  CHECK(bind(server, (const struct sockaddr *)&address, sizeof(address)) == 0);
  CHECK(getsockname(server, (struct sockaddr *)&address, &length) == 0);
  CHECK(ftun_budget_create(NULL, 4u * 1024u * 1024u, 64u, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 8u, &operations) == FTUN_OK);
  CHECK(ftun_event_loop_create(core, &loop) == FTUN_OK);
  spec.budget = budget;
  spec.generation = 7u;
  spec.ops.start = start;
  spec.context = &state;
  CHECK(ftun_path_provider_create(&spec, &provider) == FTUN_OK);
  request.loop = loop;
  request.operations = operations;
  request.budget = budget;
  request.endpoint.kind = FTUN_ADDRESS_IPV4;
  request.endpoint.address[0] = 127u;
  request.endpoint.address[3] = 1u;
  request.endpoint.port = ntohs(address.sin_port);
  allowed = request.endpoint;
  request.allowed = &allowed;
  request.allowed_count = 1u;
  request.transport = FTUN_DIAL_UDP;
  request.purpose = FTUN_DIAL_PURPOSE_BUSINESS;
  request.requested_domain = FTUN_DIAL_DOMAIN_AUTO;
  request.completion = completed;
  request.user = &state;

  /* 不存在 View 的默认 Underlay 不需要伪造与配置相等的网络代次。 */
  CHECK(ftun_path_provider_open_datagram(provider, core, 7u,
        &request, &operation) == FTUN_OK && operation != NULL);
  CHECK(dispatched(operations, &state, FTUN_OK) == 0);
  CHECK(exchange(&state, server, 0u) == 0);
  starts = state.starts;
  CHECK(rejected(provider, core, 0u, &request, &state, FTUN_E_INVALID) == 0);
  CHECK(rejected(provider, core, 6u, &request, &state, FTUN_E_STALE) == 0);
  CHECK(state.starts == starts);
  request.network_generation = 7u;
  CHECK(rejected(provider, core, 7u, &request, &state,
        FTUN_E_UNSUPPORTED) == 0);
  request.network_generation = 0u;
  request.requested_domain = FTUN_DIAL_DOMAIN_OVERLAY;
  CHECK(rejected(provider, core, 7u, &request, &state,
        FTUN_E_UNSUPPORTED) == 0);
  request.requested_domain = FTUN_DIAL_DOMAIN_UNDERLAY;

  view_spec.generation = 9u;
  CHECK(ftun_network_view_create(&view_spec, &open_view) == FTUN_OK);
  view_spec.protected_prefixes = &protected_prefix;
  view_spec.protected_prefix_count = 1u;
  CHECK(ftun_network_view_create(&view_spec, &closed_view) == FTUN_OK);
  CHECK(open_view != closed_view);
  request.network_view = open_view;
  request.network_generation = 9u;
  CHECK(ftun_path_provider_open_datagram(provider, core, 7u,
        &request, &operation) == FTUN_OK);
  CHECK(dispatched(operations, &state, FTUN_OK) == 0);
  CHECK(exchange(&state, server, 9u) == 0);

  /* 数值相同但身份不同的 View 必须使用各自的授权；拒绝不能放宽 allowed。 */
  request.network_view = closed_view;
  CHECK(rejected(provider, core, 7u, &request, &state, FTUN_E_REJECTED) == 0);
  request.network_view = open_view;
  request.network_generation = 8u;
  CHECK(rejected(provider, core, 7u, &request, &state, FTUN_E_STALE) == 0);
  request.network_generation = 9u;
  allowed.address[3] = 2u;
  CHECK(rejected(provider, core, 7u, &request, &state, FTUN_E_REJECTED) == 0);
  allowed = request.endpoint;

  /* reload 在完成派发前提交；旧请求仍返回原网络授权，新配置单独准入。 */
  CHECK(ftun_path_provider_open_datagram(provider, core, 7u,
        &request, &operation) == FTUN_OK);
  CHECK(ftun_path_provider_reload_prepare(provider, 8u) == FTUN_OK);
  CHECK(ftun_path_provider_reload_commit(provider, 8u) == FTUN_OK);
  CHECK(dispatched(operations, &state, FTUN_OK) == 0);
  CHECK(exchange(&state, server, 9u) == 0);
  CHECK(rejected(provider, core, 7u, &request, &state, FTUN_E_STALE) == 0);
  CHECK(ftun_path_provider_open_datagram(provider, core, 8u,
        &request, &operation) == FTUN_OK);
  CHECK(ftun_operation_cancel(operation) == FTUN_OK);
  CHECK(dispatched(operations, &state, FTUN_E_CANCELLED) == 0);
  CHECK(state.result.socket == FTUN_INVALID_SOCKET);

  CHECK(ftun_path_provider_stop_until(provider, UINT64_MAX) == FTUN_OK);
  CHECK(rejected(provider, core, 8u, &request, &state, FTUN_E_CANCELLED) == 0);
  CHECK(ftun_path_provider_destroy(&provider) == FTUN_OK);
  ftun_network_view_release(&open_view);
  ftun_network_view_release(&closed_view);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(close(server) == 0);
  puts("Path configuration and network generation contract passed");
  return 0;
}
