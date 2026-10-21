#include "transport/path.h"

#include <stdlib.h>
#include <string.h>

struct ftun_path_provider {
  ftun_budget_t *budget;
  ftun_reservation_t *reservation;
  ftun_path_provider_ops_t ops;
  void *context;
  uint64_t generation;
  uint64_t pending_generation;
  bool accepting;
  bool stopped;
  bool reload_prepared;
};

ftun_status_t ftun_path_provider_create(
  const ftun_path_provider_spec_t *spec, ftun_path_provider_t **out)
{
  ftun_path_provider_t *provider;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (spec == NULL || spec->budget == NULL || spec->generation == 0u ||
      spec->ops.start == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_budget_reserve(spec->budget, sizeof(*provider), &reservation);
  if (status != FTUN_OK) return status;
  provider = (ftun_path_provider_t *)calloc(1u, sizeof(*provider));
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

static ftun_status_t ftun_path_provider_open(
  ftun_path_provider_t *provider, ftun_core_t *core,
  const ftun_dial_request_t *request, ftun_dial_transport_t transport,
  ftun_operation_t **out)
{
  bool same_root = false;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (provider == NULL || core == NULL || request == NULL || out == NULL ||
      request->budget == NULL || request->operations == NULL ||
      request->loop == NULL || request->completion == NULL ||
      request->transport != transport || request->network_generation == 0u ||
      request->purpose < FTUN_DIAL_PURPOSE_BUSINESS ||
      request->purpose > FTUN_DIAL_PURPOSE_RELAY ||
      request->requested_domain < FTUN_DIAL_DOMAIN_AUTO ||
      request->requested_domain > FTUN_DIAL_DOMAIN_OVERLAY) {
    return FTUN_E_INVALID;
  }
  if (request->network_generation != provider->generation) {
    return FTUN_E_STALE;
  }
  if (!provider->accepting || provider->stopped) return FTUN_E_CANCELLED;
  status = ftun_budget_same_root(provider->budget, request->budget,
                                 &same_root);
  if (status != FTUN_OK) return status;
  if (!same_root) return FTUN_E_REJECTED;
  status = provider->ops.start(provider->context, core, request, out);
  if (status == FTUN_OK && *out == NULL) return FTUN_E_STATE_CORRUPT;
  if (status != FTUN_OK) *out = NULL;
  return status;
}

ftun_status_t ftun_path_provider_open_stream(
  ftun_path_provider_t *provider, ftun_core_t *core,
  const ftun_dial_request_t *request, ftun_operation_t **out)
{
  return ftun_path_provider_open(provider, core, request, FTUN_DIAL_TCP, out);
}

ftun_status_t ftun_path_provider_open_datagram(
  ftun_path_provider_t *provider, ftun_core_t *core,
  const ftun_dial_request_t *request, ftun_operation_t **out)
{
  return ftun_path_provider_open(provider, core, request, FTUN_DIAL_UDP, out);
}

ftun_status_t ftun_path_provider_reload_prepare(
  ftun_path_provider_t *provider, uint64_t generation)
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

ftun_status_t ftun_path_provider_reload_commit(
  ftun_path_provider_t *provider, uint64_t generation)
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

ftun_status_t ftun_path_provider_reload_abort(ftun_path_provider_t *provider)
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

ftun_status_t ftun_path_provider_quiesce(ftun_path_provider_t *provider)
{
  if (provider == NULL) return FTUN_E_INVALID;
  if (!provider->accepting) return FTUN_OK;
  provider->accepting = false;
  return provider->ops.quiesce == NULL ? FTUN_OK :
    provider->ops.quiesce(provider->context);
}

ftun_status_t ftun_path_provider_stop_until(
  ftun_path_provider_t *provider, uint64_t deadline_ms)
{
  ftun_status_t status;
  if (provider == NULL || deadline_ms == 0u) return FTUN_E_INVALID;
  if (provider->stopped) return FTUN_OK;
  status = ftun_path_provider_quiesce(provider);
  if (status != FTUN_OK) return status;
  if (provider->ops.stop_until != NULL) {
    status = provider->ops.stop_until(provider->context, deadline_ms);
    if (status != FTUN_OK) return status;
  }
  provider->stopped = true;
  return FTUN_OK;
}

ftun_status_t ftun_path_provider_get_info(
  const ftun_path_provider_t *provider, ftun_path_provider_info_t *out)
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

ftun_status_t ftun_path_provider_destroy(ftun_path_provider_t **provider)
{
  ftun_path_provider_t *owned;
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
