#include "network/resolver.h"

#include <stdlib.h>
#include <string.h>

struct ftun_resolver_provider {
  ftun_budget_t *budget;
  ftun_reservation_t *reservation;
  ftun_resolver_provider_ops_t ops;
  void *context;
  uint64_t generation;
  uint64_t pending_generation;
  bool accepting;
  bool stopped;
  bool reload_prepared;
};

static int ftun_resolver_provider_ops_valid(
  const ftun_resolver_provider_ops_t *ops)
{
  return ops != NULL && ops->start != NULL;
}

static int ftun_resolver_provider_request_valid(
  const ftun_resolver_provider_request_t *request)
{
  return request != NULL && request->system.budget != NULL &&
    request->system.domain.data != NULL &&
    request->system.domain.length != 0u &&
    request->system.domain.length <= FTUN_SYSTEM_RESOLVER_MAX_DOMAIN_BYTES &&
    memchr(request->system.domain.data, '\0',
           request->system.domain.length) == NULL &&
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
  ftun_reservation_t *reservation = NULL;
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
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  provider->budget = spec->budget;
  provider->reservation = reservation;
  provider->ops = spec->ops;
  provider->context = spec->context;
  provider->generation = spec->generation;
  provider->accepting = true;
  *out = provider;
  return FTUN_OK;
}

ftun_status_t ftun_resolver_provider_start(
  ftun_resolver_provider_t *provider, ftun_core_t *core,
  const ftun_resolver_provider_request_t *request,
  ftun_operation_t **out)
{
  bool same_root = false;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (provider == NULL || core == NULL || out == NULL ||
      !ftun_resolver_provider_request_valid(request)) return FTUN_E_INVALID;
  if (request->generation != provider->generation) return FTUN_E_STALE;
  if (!provider->accepting || provider->stopped) return FTUN_E_CANCELLED;
  status = ftun_budget_same_root(provider->budget, request->system.budget,
                                 &same_root);
  if (status != FTUN_OK) return status;
  if (!same_root) return FTUN_E_REJECTED;
  status = provider->ops.start(provider->context, core, request, out);
  if (status == FTUN_OK && *out == NULL) return FTUN_E_STATE_CORRUPT;
  if (status != FTUN_OK) *out = NULL;
  return status;
}

ftun_status_t ftun_resolver_provider_reload_prepare(
  ftun_resolver_provider_t *provider, uint64_t generation)
{
  ftun_status_t status = FTUN_OK;
  if (provider == NULL || generation == 0u || provider->stopped ||
      provider->reload_prepared) return FTUN_E_INVALID;
  if (!provider->accepting) return FTUN_E_CANCELLED;
  if (generation <= provider->generation) return FTUN_E_STALE;
  if (provider->ops.reload_prepare != NULL) {
    status = provider->ops.reload_prepare(provider->context, generation);
  }
  if (status == FTUN_OK) {
    provider->pending_generation = generation;
    provider->reload_prepared = true;
  }
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
  return FTUN_OK;
}

ftun_status_t ftun_resolver_provider_reload_abort(
  ftun_resolver_provider_t *provider)
{
  if (provider == NULL) return FTUN_E_INVALID;
  if (!provider->reload_prepared) return FTUN_OK;
  if (provider->ops.reload_abort != NULL) {
    provider->ops.reload_abort(provider->context,
                               provider->pending_generation);
  }
  provider->pending_generation = 0u;
  provider->reload_prepared = false;
  return FTUN_OK;
}

ftun_status_t ftun_resolver_provider_quiesce(
  ftun_resolver_provider_t *provider)
{
  if (provider == NULL) return FTUN_E_INVALID;
  if (!provider->accepting) return FTUN_OK;
  provider->accepting = false;
  return provider->ops.quiesce == NULL ? FTUN_OK :
    provider->ops.quiesce(provider->context);
}

ftun_status_t ftun_resolver_provider_stop_until(
  ftun_resolver_provider_t *provider, uint64_t deadline_ms)
{
  ftun_status_t status;
  if (provider == NULL || deadline_ms == 0u) return FTUN_E_INVALID;
  if (provider->stopped) return FTUN_OK;
  status = ftun_resolver_provider_quiesce(provider);
  if (status != FTUN_OK) return status;
  if (provider->ops.stop_until != NULL) {
    status = provider->ops.stop_until(provider->context, deadline_ms);
    if (status != FTUN_OK) return status;
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
  return FTUN_OK;
}

ftun_status_t ftun_resolver_provider_destroy(
  ftun_resolver_provider_t **provider)
{
  ftun_resolver_provider_t *owned;
  ftun_reservation_t *reservation;
  if (provider == NULL) return FTUN_E_INVALID;
  owned = *provider;
  if (owned == NULL) return FTUN_OK;
  if (!owned->stopped || owned->reload_prepared) return FTUN_E_AGAIN;
  reservation = owned->reservation;
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *provider = NULL;
  return ftun_reservation_release(&reservation);
}
