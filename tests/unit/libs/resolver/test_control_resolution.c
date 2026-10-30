#include "libs/resolver/control_channel.h"
#include "platform/clock.h"
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "control resolution failed %d: %s\n", __LINE__, #x); return 1; } } while (0)

typedef struct {
  ftun_operation_token_t token;
  ftun_system_resolve_completion_fn completion;
  void *user;
  char domain[254];
  unsigned int starts, cancelled, callbacks;
  bool hold, reject, in_start;
} fixture_t;

static ftun_status_t cancel(void *user)
{
  fixture_t *state = user;
  state->cancelled++;
  return FTUN_E_AGAIN;
}

static void completed(ftun_operation_t *operation, ftun_error_t error, void *user)
{
  fixture_t *state = user;
  ftun_endpoint_t endpoints[2] = {{0}};
  ftun_system_resolve_result_t result = {0};
  if (state->in_start) error.status = FTUN_E_STATE_CORRUPT;
  endpoints[0].kind = endpoints[1].kind = FTUN_ADDRESS_IPV4;
  endpoints[0].address[0] = 192u; endpoints[0].address[3] = 1u;
  endpoints[1].address[0] = 192u; endpoints[1].address[3] = 2u;
  result.domain = (ftun_string_t){state->domain, strlen(state->domain)};
  result.addresses = endpoints;
  result.address_count = 2u;
  state->callbacks++;
  state->completion(operation, error, error.status == FTUN_OK ? &result : NULL, state->user);
}

static ftun_status_t start(void *context, ftun_core_t *core,
  const ftun_resolver_provider_request_t *request, ftun_operation_t **out)
{
  fixture_t *state = context;
  ftun_status_t status;
  *out = NULL;
  (void)core;
  state->starts++;
  if (state->reject) return FTUN_E_LIMIT;
  state->completion = request->system.completion;
  state->user = request->system.user;
  memcpy(state->domain, request->system.domain.data, request->system.domain.length);
  state->domain[request->system.domain.length] = '\0';
  state->in_start = true;
  status = ftun_operation_accept(request->operations, completed, state, out, &state->token);
  if (status == FTUN_OK) status = ftun_operation_set_cancel_hook(*out, cancel, state);
  if (status == FTUN_OK && !state->hold) status = ftun_operation_complete(state->token, (ftun_error_t){FTUN_OK, 0u, 0});
  state->in_start = false;
  return status;
}

static int run(bool hold, bool reject)
{
  ftun_budget_t *budget = NULL;
  ftun_control_channel_t *channel = NULL;
  ftun_resolver_provider_ops_t ops = {0};
  ftun_resolver_provider_request_t request = {0};
  ftun_endpoint_t result;
  ftun_budget_usage_t before, after;
  fixture_t state = {0};
  uint64_t now;
  state.hold = hold;
  state.reject = reject;
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 128u, &budget) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &before) == FTUN_OK);
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  CHECK(ftun_control_channel_create(budget, 7u, now + 20u, &channel) == FTUN_OK);
  ops.start = start;
  request.system.domain = (ftun_string_t){"control.test", 12u};
  request.source = FTUN_RESOLVER_SYSTEM;
  request.generation = 8u;
  request.purpose = FTUN_DIAL_PURPOSE_PROBE;
  request.requested_domain = FTUN_DIAL_DOMAIN_UNDERLAY;
  CHECK(ftun_control_channel_resolve(channel, &ops, &state, &request, &result) == FTUN_E_STALE);
  CHECK(state.starts == 0u);
  request.generation = 7u;
  CHECK(ftun_control_channel_resolve(channel, &ops, &state, &request, &result) ==
    (reject ? FTUN_E_LIMIT : hold ? FTUN_E_TIMEOUT : FTUN_OK));
  CHECK(state.starts == 1u);
  if (hold) {
    CHECK(result.kind == 0u && state.callbacks == 0u);
    CHECK(ftun_control_channel_close(&channel) == FTUN_E_AGAIN && channel != NULL);
    CHECK(state.cancelled != 0u);
    CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK && after.used_resources.memory_bytes != 0u);
    memset(&result, 0xa5, sizeof(result));
    CHECK(ftun_operation_complete(state.token, (ftun_error_t){FTUN_OK, 0u, 0}) == FTUN_OK);
    CHECK(ftun_control_channel_close(&channel) == FTUN_OK);
    CHECK(((unsigned char *)&result)[0] == 0xa5u && state.callbacks == 1u);
  } else {
    CHECK(state.callbacks == (reject ? 0u : 1u));
    if (!reject) CHECK(result.kind == FTUN_ADDRESS_IPV4 && result.address[3] == 1u);
    CHECK(ftun_control_channel_close(&channel) == FTUN_OK);
  }
  CHECK(channel == NULL);
  CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK && after.used_resources.memory_bytes == before.used_resources.memory_bytes && after.metadata_bytes == before.metadata_bytes);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(void)
{
  CHECK(run(false, false) == 0);
  CHECK(run(true, false) == 0);
  CHECK(run(false, true) == 0);
  puts("control Resolver owner completion, generation, rejection and late cancellation passed");
  return 0;
}
