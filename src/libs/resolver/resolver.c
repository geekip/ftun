#include "libs/resolver/resolver.h"
#include "platform/clock.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

typedef struct ftun_resolver_pending {
  struct ftun_resolver_pending *next;
  struct ftun_resolver_pending *previous;
  ftun_resolver_provider_t *provider;
  ftun_reservation_t reservation;
  ftun_operation_t *operation;
  ftun_system_resolve_completion_fn completion;
  void *user;
  bool completing;
  bool cancelled;
  bool suppress;
} ftun_resolver_pending_t;

struct ftun_resolver_scope {
  ftun_resolver_provider_t *provider;
  ftun_reservation_t reservation;
  uint64_t generation;
  size_t references;
};

struct ftun_resolver_provider {
  ftun_budget_t *budget;
  ftun_reservation_t reservation;
  ftun_resolver_provider_ops_t ops;
  void *context;
  uint64_t generation;
  uint64_t pending_generation;
  ftun_resolver_pending_t *pending;
  size_t pending_count;
  size_t scope_count;
  size_t max_pending;
  size_t max_scopes;
  bool visiting;
  bool accepting;
  bool stopped;
  bool reload_prepared;
  bool reload_pending;
  bool quiesced;
};

static int ftun_resolver_provider_ops_valid(
  const ftun_resolver_provider_ops_t *ops)
{
  return ops != NULL && ops->start != NULL;
}

static int ftun_resolver_provider_request_valid(
  const ftun_resolver_provider_request_t *request)
{
  size_t index;
  if (request == NULL || request->source < FTUN_RESOLVER_SYSTEM ||
      request->source > FTUN_RESOLVER_NAMED ||
      request->server_count > FTUN_RESOLVER_MAX_SERVERS) return 0;
  if (request->source != FTUN_RESOLVER_SYSTEM &&
      (request->loop == NULL || request->operations == NULL)) return 0;
  if (request->source == FTUN_RESOLVER_NAMED) {
    if (request->resolver_name.data == NULL || request->resolver_name.length == 0u ||
        request->resolver_name.length > 255u ||
        memchr(request->resolver_name.data, '\0', request->resolver_name.length) != NULL) return 0;
  } else if (request->resolver_name.length != 0u) return 0;
  if (request->source != FTUN_RESOLVER_BOOTSTRAP && request->server_count != 0u) return 0;
  if (request->server_count != 0u && request->servers == NULL) return 0;
  for (index = 0u; index < request->server_count; index++) {
    if (request->servers[index].kind != FTUN_ADDRESS_IPV4 ||
        request->servers[index].port == 0u) return 0;
  }
  if (request->network_view == NULL && request->network_generation != 0u) return 0;
  return request->system.budget != NULL &&
    request->system.domain.data != NULL &&
    request->system.domain.length != 0u &&
    request->system.domain.length <= FTUN_SYSTEM_RESOLVER_MAX_DOMAIN_BYTES &&
    memchr(request->system.domain.data, '\0', request->system.domain.length) == NULL &&
    request->system.deadline_ms != 0u &&
    request->system.completion != NULL && request->generation != 0u &&
    request->purpose >= FTUN_DIAL_PURPOSE_BUSINESS &&
    request->purpose <= FTUN_DIAL_PURPOSE_RELAY &&
    request->requested_domain >= FTUN_DIAL_DOMAIN_AUTO &&
    request->requested_domain <= FTUN_DIAL_DOMAIN_OVERLAY;
}

ftun_status_t ftun_resolver_provider_create(
  const ftun_resolver_provider_spec_t *spec,
  ftun_resolver_provider_t **out)
{
  ftun_resolver_provider_t *provider;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (spec == NULL || spec->budget == NULL || spec->generation == 0u ||
      !ftun_resolver_provider_ops_valid(&spec->ops) || out == NULL) {
    return FTUN_E_INVALID;
  }
  status = ftun_budget_reserve(spec->budget, sizeof(*provider), &reservation);
  if (status != FTUN_OK) return status;
  provider = (ftun_resolver_provider_t *)calloc(1u, sizeof(*provider));
  if (provider == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  provider->budget = spec->budget;
  provider->reservation = reservation;
  provider->ops = spec->ops;
  provider->context = spec->context;
  provider->generation = spec->generation;
  provider->max_pending = spec->max_pending == 0u ? 4096u : spec->max_pending;
  provider->max_scopes = spec->max_scopes == 0u ? 4096u : spec->max_scopes;
  provider->accepting = true;
  *out = provider;
  return FTUN_OK;
}

static void ftun_resolver_pending_release(ftun_resolver_pending_t *pending)
{
  ftun_resolver_provider_t *provider = pending->provider;
  ftun_reservation_t reservation = pending->reservation;
  if (pending->previous != NULL) pending->previous->next = pending->next;
  else provider->pending = pending->next;
  if (pending->next != NULL) pending->next->previous = pending->previous;
  provider->pending_count--;
  free(pending);
  ftun_reservation_release(&reservation);
}

static void ftun_resolver_pending_completed(ftun_operation_t *operation,
  ftun_error_t error, const ftun_system_resolve_result_t *result, void *user)
{
  ftun_resolver_pending_t *pending = user;
  size_t index;
  pending->completing = true;
  pending->operation = NULL;
  if (pending->cancelled) error.status = FTUN_E_CANCELLED;
  if (error.status == FTUN_OK) {
    if (result == NULL || result->domain.data == NULL || result->domain.length == 0u ||
        result->domain.length > FTUN_SYSTEM_RESOLVER_MAX_DOMAIN_BYTES ||
        result->addresses == NULL || result->address_count == 0u ||
        result->address_count > FTUN_SYSTEM_RESOLVER_MAX_IPV4_RESULTS) {
      error.status = FTUN_E_STATE_CORRUPT;
    } else {
      for (index = 0u; index < result->address_count; index++) {
        if (result->addresses[index].kind != FTUN_ADDRESS_IPV4) {
          error.status = FTUN_E_UNSUPPORTED;
          break;
        }
      }
    }
  }
  if (!pending->suppress) pending->completion(operation, error,
    error.status == FTUN_OK ? result : NULL, pending->user);
  ftun_resolver_pending_release(pending);
}

static ftun_status_t ftun_resolver_provider_start_internal(
  ftun_resolver_provider_t *provider, ftun_core_t *core,
  const ftun_resolver_provider_request_t *request, bool pinned,
  ftun_operation_t **out)
{
  ftun_resolver_pending_t *pending;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_resolver_provider_request_t delegated;
  bool same_root = false;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (provider == NULL || core == NULL || out == NULL ||
      !ftun_resolver_provider_request_valid(request)) return FTUN_E_INVALID;
  if (!pinned && request->generation != provider->generation) return FTUN_E_STALE;
  if (!provider->accepting || provider->stopped) return FTUN_E_CANCELLED;
  if (provider->visiting) return FTUN_E_AGAIN;
  if (provider->pending_count >= provider->max_pending) return FTUN_E_LIMIT;
  status = ftun_budget_same_root(provider->budget, request->system.budget, &same_root);
  if (status != FTUN_OK) return status;
  if (!same_root) return FTUN_E_REJECTED;
  if (request->network_view != NULL) {
    ftun_network_view_info_t info;
    status = ftun_network_view_get_info(request->network_view, &info);
    if (status != FTUN_OK) return status;
    if (info.revoked) return FTUN_E_CANCELLED;
    if (request->network_generation != info.generation) return FTUN_E_STALE;
  }
  status = ftun_budget_reserve(request->system.budget, sizeof(*pending), &reservation);
  if (status != FTUN_OK) return status;
  pending = calloc(1u, sizeof(*pending));
  if (pending == NULL) { ftun_reservation_release(&reservation); return FTUN_E_LIMIT; }
  pending->provider = provider;
  pending->reservation = reservation;
  pending->completion = request->system.completion;
  pending->user = request->system.user;
  pending->next = provider->pending;
  if (pending->next != NULL) pending->next->previous = pending;
  provider->pending = pending;
  provider->pending_count++;
  delegated = *request;
  delegated.system.completion = ftun_resolver_pending_completed;
  delegated.system.user = pending;
  status = provider->ops.start(provider->context, core, &delegated, &pending->operation);
  if (status != FTUN_OK || pending->operation == NULL) {
    if (pending->operation != NULL) {
      /* 错误接纳仍有后台引用时保留状态，禁止回调未接纳的调用方。 */
      pending->suppress = true;
      pending->cancelled = true;
      (void)ftun_operation_cancel(pending->operation);
      return FTUN_E_STATE_CORRUPT;
    }
    ftun_resolver_pending_release(pending);
    return status == FTUN_OK ? FTUN_E_STATE_CORRUPT : status;
  }
  *out = pending->operation;
  return FTUN_OK;
}

ftun_status_t ftun_resolver_provider_start(ftun_resolver_provider_t *provider,
  ftun_core_t *core, const ftun_resolver_provider_request_t *request,
  ftun_operation_t **out)
{
  return ftun_resolver_provider_start_internal(provider, core, request, false, out);
}

ftun_status_t ftun_resolver_provider_scope(ftun_resolver_provider_t *provider,
  uint64_t generation, ftun_resolver_scope_t **out)
{
  ftun_resolver_scope_t *scope;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (provider == NULL || generation == 0u || out == NULL) return FTUN_E_INVALID;
  if (!provider->accepting || provider->stopped) return FTUN_E_CANCELLED;
  if (provider->visiting) return FTUN_E_AGAIN;
  if (generation != provider->generation) return FTUN_E_STALE;
  if (provider->scope_count >= provider->max_scopes) return FTUN_E_LIMIT;
  status = ftun_budget_reserve(provider->budget, sizeof(*scope), &reservation);
  if (status != FTUN_OK) return status;
  scope = calloc(1u, sizeof(*scope));
  if (scope == NULL) { ftun_reservation_release(&reservation); return FTUN_E_LIMIT; }
  scope->provider = provider;
  scope->reservation = reservation;
  scope->generation = generation;
  scope->references = 1u;
  provider->scope_count++;
  *out = scope;
  return FTUN_OK;
}

ftun_status_t ftun_resolver_scope_retain(ftun_resolver_scope_t *scope)
{
  if (scope == NULL) return FTUN_E_INVALID;
  if (scope->references == SIZE_MAX) return FTUN_E_LIMIT;
  scope->references++;
  return FTUN_OK;
}

void ftun_resolver_scope_release(ftun_resolver_scope_t **scope)
{
  ftun_resolver_scope_t *owned;
  assert(scope != NULL);
  owned = *scope;
  if (owned == NULL) return;
  assert(owned->references != 0u);
  *scope = NULL;
  if (--owned->references != 0u) return;
  assert(owned->provider->scope_count != 0u);
  owned->provider->scope_count--;
  ftun_reservation_release(&owned->reservation);
  free(owned);
}

ftun_status_t ftun_resolver_scope_generation(const ftun_resolver_scope_t *scope,
  uint64_t *out)
{
  if (out != NULL) *out = 0u;
  if (scope == NULL || out == NULL) return FTUN_E_INVALID;
  *out = scope->generation;
  return FTUN_OK;
}

ftun_status_t ftun_resolver_scope_start(ftun_resolver_scope_t *scope,
  ftun_core_t *core, const ftun_resolver_provider_request_t *request,
  ftun_operation_t **out)
{
  if (out != NULL) *out = NULL;
  if (scope == NULL || request == NULL) return FTUN_E_INVALID;
  if (request->generation != scope->generation) return FTUN_E_STALE;
  return ftun_resolver_provider_start_internal(scope->provider, core, request, true, out);
}

ftun_status_t ftun_resolver_provider_reload_prepare(
  ftun_resolver_provider_t *provider, uint64_t generation)
{
  ftun_status_t status = FTUN_OK;
  if (provider == NULL || generation == 0u || provider->stopped ||
      provider->reload_pending) return FTUN_E_INVALID;
  if (!provider->accepting) return FTUN_E_CANCELLED;
  if (generation <= provider->generation) return FTUN_E_STALE;
  /* 后端可在返回错误前持有部分资源；abort 必须仍能到达该代。 */
  provider->pending_generation = generation;
  provider->reload_pending = true;
  if (provider->ops.reload_prepare != NULL) {
    status = provider->ops.reload_prepare(provider->context, generation);
  }
  if (status == FTUN_OK) provider->reload_prepared = true;
  return status;
}

ftun_status_t ftun_resolver_provider_reload_commit(
  ftun_resolver_provider_t *provider, uint64_t generation)
{
  if (provider == NULL || !provider->reload_prepared ||
      generation != provider->pending_generation) return FTUN_E_INVALID;
  if (provider->ops.reload_commit != NULL) {
    provider->ops.reload_commit(provider->context, generation);
  }
  provider->generation = generation;
  provider->pending_generation = 0u;
  provider->reload_prepared = false;
  provider->reload_pending = false;
  return FTUN_OK;
}

ftun_status_t ftun_resolver_provider_reload_abort(
  ftun_resolver_provider_t *provider)
{
  if (provider == NULL) return FTUN_E_INVALID;
  if (!provider->reload_pending) return FTUN_OK;
  if (provider->ops.reload_abort != NULL) {
    provider->ops.reload_abort(provider->context,
                               provider->pending_generation);
  }
  provider->pending_generation = 0u;
  provider->reload_prepared = false;
  provider->reload_pending = false;
  return FTUN_OK;
}

ftun_status_t ftun_resolver_provider_quiesce(
  ftun_resolver_provider_t *provider)
{
  ftun_status_t status;
  if (provider == NULL) return FTUN_E_INVALID;
  provider->accepting = false;
  if (provider->quiesced) return FTUN_OK;
  status = provider->ops.quiesce == NULL ? FTUN_OK :
    provider->ops.quiesce(provider->context);
  if (status == FTUN_OK) provider->quiesced = true;
  return status;
}

ftun_status_t ftun_resolver_provider_stop_until(
  ftun_resolver_provider_t *provider, uint64_t deadline_ms)
{
  ftun_status_t status;
  if (provider == NULL || deadline_ms == 0u) return FTUN_E_INVALID;
  if (provider->stopped) return FTUN_OK;
  status = ftun_resolver_provider_quiesce(provider);
  if (status != FTUN_OK) return status;
  {
    ftun_resolver_pending_t *pending;
    ftun_status_t first = FTUN_OK;
    uint64_t now;
    if (provider->visiting) return FTUN_E_AGAIN;
    provider->visiting = true;
    for (pending = provider->pending; pending != NULL; pending = pending->next) {
      pending->cancelled = true;
      if (pending->completing || pending->operation == NULL) continue;
      status = ftun_operation_cancel(pending->operation);
      if (status != FTUN_OK && status != FTUN_E_STALE && first == FTUN_OK) first = status;
    }
    provider->visiting = false;
    if (provider->ops.stop_until != NULL) {
      status = provider->ops.stop_until(provider->context, deadline_ms);
      if (first == FTUN_OK) first = status;
    }
    if (first != FTUN_OK && first != FTUN_E_AGAIN) return first;
    if (provider->pending_count != 0u) {
      status = ftun_monotonic_now(&now);
      if (status != FTUN_OK) return status;
      return now >= deadline_ms ? FTUN_E_TIMEOUT : FTUN_E_AGAIN;
    }
    if (first != FTUN_OK) return first;
  }
  provider->stopped = true;
  return FTUN_OK;
}

ftun_status_t ftun_resolver_provider_get_info(
  const ftun_resolver_provider_t *provider,
  ftun_resolver_provider_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (provider == NULL || out == NULL) return FTUN_E_INVALID;
  out->generation = provider->generation;
  out->pending_generation = provider->pending_generation;
  out->accepting = provider->accepting;
  out->stopped = provider->stopped;
  out->reload_prepared = provider->reload_prepared;
  out->pending = provider->pending_count;
  out->scopes = provider->scope_count;
  return FTUN_OK;
}

ftun_status_t ftun_resolver_provider_destroy(
  ftun_resolver_provider_t **provider)
{
  ftun_resolver_provider_t *owned;
  ftun_reservation_t reservation;
  if (provider == NULL) return FTUN_E_INVALID;
  owned = *provider;
  if (owned == NULL) return FTUN_OK;
  if (!owned->stopped || owned->reload_pending || owned->pending_count != 0u ||
      owned->scope_count != 0u || owned->visiting) return FTUN_E_AGAIN;
  reservation = owned->reservation;
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *provider = NULL;
  ftun_reservation_release(&reservation);
  return FTUN_OK;
}
