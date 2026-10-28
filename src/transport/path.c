#include "transport/path.h"
#include "util/time.h"

#include <stdlib.h>
#include <string.h>

typedef struct ftun_path_open ftun_path_open_t;

struct ftun_path_provider {
  ftun_budget_t *budget;
  ftun_reservation_t *reservation;
  ftun_path_provider_ops_t ops;
  ftun_buffer_pool_t *receive_pool;
  void *context;
  uint64_t generation;
  uint64_t pending_generation;
  uint64_t next_path_generation;
  size_t max_pending;
  size_t max_paths;
  size_t pending_count;
  size_t path_count;
  size_t retired_count;
  size_t scope_count;
  ftun_path_open_t *opens;
  ftun_path_t *paths;
  ftun_path_t *cleanup_path;
  bool accepting;
  bool stopped;
  bool reload_prepared;
  bool reload_pending;
  bool quiesced;
  bool visiting;
};

struct ftun_path_scope {
  ftun_path_provider_t *provider;
  ftun_reservation_t *reservation;
  uint64_t generation;
  size_t references;
};

struct ftun_path_open {
  ftun_path_provider_t *provider;
  ftun_path_open_t *previous;
  ftun_path_open_t *next;
  ftun_reservation_t *reservation;
  ftun_operation_t *operation;
  ftun_path_spec_t result_spec;
  ftun_path_completion_fn completion;
  void *user;
  ftun_dial_transport_t transport;
  bool completing;
  bool revoked;
  bool suppress;
};

struct ftun_path {
  ftun_budget_t *budget;
  ftun_reservation_t *reservation;
  ftun_path_info_t info;
  ftun_network_view_t *network_view;
  ftun_stream_t *stream;
  ftun_datagram_t *datagram;
  ftun_path_driver_t driver;
  char domain[FTUN_DATAGRAM_DOMAIN_BYTES];
  ftun_path_provider_t *provider;
  ftun_path_t *previous;
  ftun_path_t *next;
  bool retired;
  bool busy;
};

static void ftun_path_untrack(ftun_path_t *path)
{
  ftun_path_provider_t *provider = path->provider;
  if (provider == NULL) return;
  if (path->previous != NULL) path->previous->next = path->next;
  else provider->paths = path->next;
  if (path->next != NULL) path->next->previous = path->previous;
  provider->path_count--;
  if (path->retired) provider->retired_count--;
  path->provider = NULL;
}

static ftun_status_t ftun_path_spec_valid(const ftun_path_spec_t *spec)
{
  size_t index;
  if (spec == NULL || spec->budget == NULL ||
      spec->configuration_generation == 0u || spec->path_generation == 0u ||
      spec->endpoint.port == 0u ||
      spec->purpose < FTUN_DIAL_PURPOSE_BUSINESS ||
      spec->purpose > FTUN_DIAL_PURPOSE_RELAY ||
      (spec->domain != FTUN_DIAL_DOMAIN_UNDERLAY &&
       spec->domain != FTUN_DIAL_DOMAIN_OVERLAY)) return FTUN_E_INVALID;
  if (spec->domain == FTUN_DIAL_DOMAIN_OVERLAY && spec->network_view == NULL) {
    return FTUN_E_UNSUPPORTED;
  }
  if (spec->endpoint.kind == FTUN_ADDRESS_IPV4) return FTUN_OK;
  if (spec->endpoint.kind == FTUN_ADDRESS_IPV6_RESERVED) {
    return FTUN_E_UNSUPPORTED;
  }
  if (spec->endpoint.kind != FTUN_ADDRESS_DOMAIN ||
      spec->endpoint.domain.data == NULL || spec->endpoint.domain.length == 0u ||
      spec->endpoint.domain.length >= FTUN_DATAGRAM_DOMAIN_BYTES) {
    return FTUN_E_INVALID;
  }
  for (index = 0u; index < spec->endpoint.domain.length; index++) {
    if (spec->endpoint.domain.data[index] == '\0') return FTUN_E_INVALID;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_path_allocate(const ftun_path_spec_t *spec,
  ftun_budget_t *channel_budget, ftun_path_t **out)
{
  ftun_path_t *path;
  ftun_reservation_t *reservation = NULL;
  ftun_network_view_info_t view_info;
  ftun_status_t status;
  bool same_root = false;
  if (out != NULL) *out = NULL;
  if (out == NULL || channel_budget == NULL) return FTUN_E_INVALID;
  status = ftun_path_spec_valid(spec);
  if (status != FTUN_OK) return status;
  status = ftun_budget_same_root(spec->budget, channel_budget, &same_root);
  if (status != FTUN_OK) return status;
  if (!same_root) return FTUN_E_REJECTED;
  memset(&view_info, 0, sizeof(view_info));
  if (spec->network_view != NULL) {
    status = ftun_network_view_get_info(spec->network_view, &view_info);
    if (status != FTUN_OK) return status;
  }
  status = ftun_budget_reserve(spec->budget, sizeof(*path), &reservation);
  if (status != FTUN_OK) return status;
  path = (ftun_path_t *)calloc(1u, sizeof(*path));
  if (path == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  if (spec->network_view != NULL) {
    status = ftun_network_view_retain(spec->network_view);
    if (status != FTUN_OK) {
      free(path);
      (void)ftun_reservation_release(&reservation);
      return status;
    }
  }
  path->reservation = reservation;
  path->budget = spec->budget;
  path->network_view = spec->network_view;
  path->info.network_view = spec->network_view;
  path->info.network_generation = view_info.generation;
  path->info.configuration_generation = spec->configuration_generation;
  path->info.path_generation = spec->path_generation;
  path->info.endpoint = spec->endpoint;
  path->info.endpoint.domain.data = NULL;
  path->info.endpoint.domain.length = 0u;
  if (spec->endpoint.kind == FTUN_ADDRESS_DOMAIN) {
    memcpy(path->domain, spec->endpoint.domain.data, spec->endpoint.domain.length);
    path->info.endpoint.domain.data = path->domain;
    path->info.endpoint.domain.length = spec->endpoint.domain.length;
  }
  path->info.purpose = spec->purpose;
  path->info.domain = spec->domain;
  path->info.references = 1u;
  path->driver = spec->driver;
  *out = path;
  return FTUN_OK;
}

ftun_status_t ftun_path_adopt_stream(const ftun_path_spec_t *spec,
  ftun_stream_t **channel, ftun_path_t **out)
{
  ftun_stream_usage_t usage;
  ftun_budget_t *budget = NULL;
  ftun_path_t *path = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (channel == NULL || *channel == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_stream_get_usage(*channel, &usage);
  if (status != FTUN_OK) return status;
  if (!usage.accepting || usage.write_shutdown || usage.pending_writes != 0u ||
      usage.in_completion || usage.in_backend || usage.reference_count != 1u) {
    return FTUN_E_AGAIN;
  }
  status = ftun_stream_budget(*channel, &budget);
  if (status != FTUN_OK) return status;
  status = ftun_path_allocate(spec, budget, &path);
  if (status != FTUN_OK) return status;
  path->stream = *channel;
  path->info.transport = FTUN_DIAL_TCP;
  *channel = NULL;
  *out = path;
  return FTUN_OK;
}

ftun_status_t ftun_path_adopt_datagram(const ftun_path_spec_t *spec,
  ftun_datagram_t **channel, ftun_path_t **out)
{
  ftun_datagram_usage_t usage;
  ftun_budget_t *budget = NULL;
  ftun_path_t *path = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (channel == NULL || *channel == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_datagram_get_usage(*channel, &usage);
  if (status != FTUN_OK) return status;
  if (!usage.accepting || usage.pending_packets != 0u || usage.in_callback ||
      usage.in_backend) {
    return FTUN_E_AGAIN;
  }
  status = ftun_datagram_budget(*channel, &budget);
  if (status != FTUN_OK) return status;
  status = ftun_path_allocate(spec, budget, &path);
  if (status != FTUN_OK) return status;
  path->datagram = *channel;
  path->info.transport = FTUN_DIAL_UDP;
  *channel = NULL;
  *out = path;
  return FTUN_OK;
}

ftun_status_t ftun_path_retain(ftun_path_t *path)
{
  if (path == NULL) return FTUN_E_INVALID;
  if (path->busy) return FTUN_E_AGAIN;
  if (path->info.references == SIZE_MAX) return FTUN_E_LIMIT;
  path->info.references++;
  return FTUN_OK;
}

ftun_status_t ftun_path_release(ftun_path_t **path)
{
  if (path == NULL) return FTUN_E_INVALID;
  if (*path == NULL) return FTUN_OK;
  if ((*path)->info.references <= 1u) return FTUN_E_STATE_CORRUPT;
  (*path)->info.references--;
  *path = NULL;
  return FTUN_OK;
}

ftun_status_t ftun_path_get_info(const ftun_path_t *path, ftun_path_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (path == NULL || out == NULL) return FTUN_E_INVALID;
  *out = path->info;
  return FTUN_OK;
}

ftun_status_t ftun_path_stream(ftun_path_t *path, ftun_stream_t **out)
{
  if (out != NULL) *out = NULL;
  if (path == NULL || out == NULL) return FTUN_E_INVALID;
  if (path->stream == NULL) return FTUN_E_UNSUPPORTED;
  *out = path->stream;
  return FTUN_OK;
}

ftun_status_t ftun_path_datagram(ftun_path_t *path, ftun_datagram_t **out)
{
  if (out != NULL) *out = NULL;
  if (path == NULL || out == NULL) return FTUN_E_INVALID;
  if (path->datagram == NULL) return FTUN_E_UNSUPPORTED;
  *out = path->datagram;
  return FTUN_OK;
}

ftun_status_t ftun_path_revoke(ftun_path_t *path)
{
  ftun_status_t status;
  ftun_status_t driver_status;
  if (path == NULL) return FTUN_E_INVALID;
  path->info.revoked = true;
  if (path->busy) return FTUN_E_AGAIN;
  path->busy = true;
  driver_status = path->driver.stop == NULL ? FTUN_OK :
    path->driver.stop(path->driver.context);
  status = path->stream != NULL ? ftun_stream_abort(path->stream) :
    ftun_datagram_stop(path->datagram);
  path->busy = false;
  return driver_status != FTUN_OK ? driver_status : status;
}

ftun_status_t ftun_path_resume(ftun_path_t *path)
{
  ftun_status_t status;
  if (path == NULL) return FTUN_E_INVALID;
  if (path->info.revoked) return FTUN_E_CANCELLED;
  if (path->busy) return FTUN_E_AGAIN;
  if (path->driver.resume == NULL) return FTUN_E_UNSUPPORTED;
  path->busy = true;
  status = path->driver.resume(path->driver.context);
  path->busy = false;
  return status;
}

ftun_status_t ftun_path_destroy(ftun_path_t **path)
{
  ftun_path_t *owned;
  ftun_status_t status;
  if (path == NULL) return FTUN_E_INVALID;
  owned = *path;
  if (owned == NULL) return FTUN_OK;
  if (!owned->info.revoked || owned->info.references != 1u || owned->busy) {
    return FTUN_E_AGAIN;
  }
  if (owned->provider != NULL && owned->provider->visiting &&
      owned->provider->cleanup_path != owned) return FTUN_E_AGAIN;
  owned->busy = true;
  status = owned->driver.stop == NULL ? FTUN_OK :
    owned->driver.stop(owned->driver.context);
  if (status != FTUN_OK) {
    owned->busy = false;
    return status;
  }
  status = owned->stream != NULL ? ftun_stream_destroy(&owned->stream) :
    ftun_datagram_destroy(&owned->datagram);
  owned->busy = false;
  if (status != FTUN_OK) return status;
  status = ftun_network_view_release(&owned->network_view);
  if (status != FTUN_OK) return status;
  status = ftun_reservation_release(&owned->reservation);
  if (status != FTUN_OK) return status;
  ftun_path_untrack(owned);
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *path = NULL;
  return FTUN_OK;
}

ftun_status_t ftun_path_provider_create(
  const ftun_path_provider_spec_t *spec, ftun_path_provider_t **out)
{
  ftun_path_provider_t *provider;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (spec == NULL || spec->budget == NULL || spec->generation == 0u ||
      (spec->ops.start == NULL && spec->ops.open == NULL) || out == NULL) {
    return FTUN_E_INVALID;
  }
  if (spec->max_pending != 0u && spec->max_paths != 0u &&
      spec->max_pending > spec->max_paths) return FTUN_E_INVALID;
  if (spec->receive_pool != NULL) {
    ftun_budget_t *pool_budget = NULL;
    bool same_root = false;
    status = ftun_buffer_pool_budget(spec->receive_pool, &pool_budget);
    if (status == FTUN_OK) status = ftun_budget_same_root(
      spec->budget, pool_budget, &same_root);
    if (status != FTUN_OK) return status;
    if (!same_root) return FTUN_E_REJECTED;
  }
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
  provider->receive_pool = spec->receive_pool;
  provider->context = spec->context;
  provider->generation = spec->generation;
  provider->max_paths = spec->max_paths == 0u ? 4096u : spec->max_paths;
  provider->max_pending = spec->max_pending == 0u ? 64u : spec->max_pending;
  if (provider->max_pending > provider->max_paths) {
    provider->max_pending = provider->max_paths;
  }
  provider->accepting = true;
  *out = provider;
  return FTUN_OK;
}

static ftun_status_t ftun_path_provider_open(
  ftun_path_provider_t *provider, ftun_core_t *core,
  uint64_t configuration_generation,
  const ftun_dial_request_t *request, ftun_dial_transport_t transport,
  ftun_operation_t **out)
{
  bool same_root = false;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (provider == NULL || core == NULL || request == NULL || out == NULL ||
      request->budget == NULL || request->operations == NULL ||
      request->loop == NULL || request->completion == NULL ||
      request->transport != transport || configuration_generation == 0u ||
      request->purpose < FTUN_DIAL_PURPOSE_BUSINESS ||
      request->purpose > FTUN_DIAL_PURPOSE_RELAY ||
      request->requested_domain < FTUN_DIAL_DOMAIN_AUTO ||
      request->requested_domain > FTUN_DIAL_DOMAIN_OVERLAY) {
    return FTUN_E_INVALID;
  }
  if (configuration_generation != provider->generation) {
    return FTUN_E_STALE;
  }
  if (!provider->accepting || provider->stopped) return FTUN_E_CANCELLED;
  if (provider->ops.start == NULL) return FTUN_E_UNSUPPORTED;
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
  uint64_t configuration_generation,
  const ftun_dial_request_t *request, ftun_operation_t **out)
{
  return ftun_path_provider_open(provider, core, configuration_generation,
                                  request, FTUN_DIAL_TCP, out);
}

ftun_status_t ftun_path_provider_open_datagram(
  ftun_path_provider_t *provider, ftun_core_t *core,
  uint64_t configuration_generation,
  const ftun_dial_request_t *request, ftun_operation_t **out)
{
  return ftun_path_provider_open(provider, core, configuration_generation,
                                  request, FTUN_DIAL_UDP, out);
}

static void ftun_path_open_release(ftun_path_open_t *open)
{
  ftun_path_provider_t *provider = open->provider;
  if (open->previous != NULL) open->previous->next = open->next;
  else provider->opens = open->next;
  if (open->next != NULL) open->next->previous = open->previous;
  provider->pending_count--;
  (void)ftun_network_view_release(&open->result_spec.network_view);
  (void)ftun_reservation_release(&open->reservation);
  free(open);
}

static bool ftun_path_view_revoked(const ftun_network_view_t *view)
{
  ftun_network_view_info_t info;
  return view != NULL &&
    (ftun_network_view_get_info(view, &info) != FTUN_OK || info.revoked);
}

static ftun_status_t ftun_path_result_check(const ftun_path_open_t *open,
  ftun_path_t *path)
{
  const ftun_path_spec_t *spec = &open->result_spec;
  const ftun_path_info_t *info;
  bool same_root = false;
  ftun_status_t status;
  if (path == NULL || path->provider != NULL) return FTUN_E_STATE_CORRUPT;
  info = &path->info;
  status = ftun_budget_same_root(spec->budget, path->budget, &same_root);
  if (status != FTUN_OK) return status;
  if (!same_root || info->configuration_generation != spec->configuration_generation ||
      info->path_generation != spec->path_generation ||
      info->network_view != spec->network_view || info->transport != open->transport ||
      info->purpose != spec->purpose || info->domain != spec->domain ||
      info->endpoint.kind != spec->endpoint.kind ||
      info->endpoint.port != spec->endpoint.port ||
      memcmp(info->endpoint.address, spec->endpoint.address, 4u) != 0 ||
      info->references != 1u || info->revoked) return FTUN_E_STATE_CORRUPT;
  return FTUN_OK;
}

static void ftun_path_open_completed(ftun_operation_t *operation,
  ftun_error_t error, ftun_path_t *path, void *user)
{
  ftun_path_open_t *open = (ftun_path_open_t *)user;
  ftun_path_provider_t *provider = open->provider;
  open->completing = true;
  open->operation = NULL;
  if (error.status == FTUN_OK) {
    error.status = ftun_path_result_check(open, path);
  }
  if (open->revoked || !provider->accepting ||
      ftun_path_view_revoked(open->result_spec.network_view)) {
    error.status = FTUN_E_CANCELLED;
  }
  /* 非空结果无论成功/失败均转交拥有权。已经属于其他持有者的对象不再接管。 */
  if (path != NULL && path->provider == NULL) {
    path->provider = provider;
    path->next = provider->paths;
    if (provider->paths != NULL) provider->paths->previous = path;
    provider->paths = path;
    provider->path_count++;
    if (error.status != FTUN_OK || open->suppress) {
      path->retired = true;
      provider->retired_count++;
    }
  } else if (path != NULL) {
    error.status = FTUN_E_STATE_CORRUPT;
    path = NULL;
  }
  if (error.status != FTUN_OK || open->suppress) {
    (void)ftun_path_provider_collect(provider);
    path = NULL;
  }
  if (!open->suppress) open->completion(operation, error, path, open->user);
  ftun_path_open_release(open);
}

static ftun_status_t ftun_path_provider_open_channel_internal(ftun_path_provider_t *provider,
  ftun_core_t *core, uint64_t configuration_generation, bool pinned,
  const ftun_path_open_request_t *request, ftun_operation_t **out)
{
  ftun_path_open_request_t delegated;
  ftun_network_dial_decision_t decision;
  ftun_path_open_t *open;
  ftun_reservation_t *reservation = NULL;
  ftun_budget_t *queue_budget = NULL;
  ftun_status_t status;
  bool same_root = false;
  if (out != NULL) *out = NULL;
  if (provider == NULL || core == NULL || request == NULL || out == NULL ||
      configuration_generation == 0u || request->completion == NULL ||
      request->dial.completion != NULL || request->dial.user != NULL) {
    return FTUN_E_INVALID;
  }
  if (!pinned && configuration_generation != provider->generation) return FTUN_E_STALE;
  if (!provider->accepting || provider->stopped) return FTUN_E_CANCELLED;
  if (provider->visiting) return FTUN_E_AGAIN;
  if (provider->ops.open == NULL) return FTUN_E_UNSUPPORTED;
  status = ftun_dial_authorize(&request->dial, &decision);
  if (status != FTUN_OK) return status;
  status = ftun_budget_same_root(provider->budget, request->dial.budget, &same_root);
  if (status != FTUN_OK) return status;
  if (!same_root) return FTUN_E_REJECTED;
  status = ftun_operation_queue_budget(request->dial.operations, &queue_budget);
  if (status != FTUN_OK) return status;
  status = ftun_budget_same_root(provider->budget, queue_budget, &same_root);
  if (status != FTUN_OK) return status;
  if (!same_root) return FTUN_E_REJECTED;
  if (provider->pending_count >= provider->max_pending ||
      provider->path_count >= provider->max_paths - provider->pending_count ||
      provider->next_path_generation == UINT64_MAX) return FTUN_E_LIMIT;
  status = ftun_budget_reserve(request->dial.budget, sizeof(*open), &reservation);
  if (status != FTUN_OK) return status;
  open = (ftun_path_open_t *)calloc(1u, sizeof(*open));
  if (open == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  open->result_spec.network_view = (ftun_network_view_t *)request->dial.network_view;
  if (open->result_spec.network_view != NULL) {
    status = ftun_network_view_retain(open->result_spec.network_view);
    if (status != FTUN_OK) {
      free(open);
      (void)ftun_reservation_release(&reservation);
      return status;
    }
  }
  open->provider = provider;
  open->reservation = reservation;
  open->result_spec.budget = request->dial.budget;
  open->result_spec.receive_pool = provider->receive_pool;
  open->result_spec.configuration_generation = configuration_generation;
  open->result_spec.path_generation = ++provider->next_path_generation;
  open->result_spec.endpoint = request->dial.endpoint;
  open->result_spec.endpoint.domain.data = NULL;
  open->result_spec.endpoint.domain.length = 0u;
  open->result_spec.purpose = request->dial.purpose;
  open->result_spec.domain = decision.domain;
  open->transport = request->dial.transport;
  open->completion = request->completion;
  open->user = request->user;
  open->next = provider->opens;
  if (provider->opens != NULL) provider->opens->previous = open;
  provider->opens = open;
  provider->pending_count++;
  delegated = *request;
  delegated.completion = ftun_path_open_completed;
  delegated.user = open;
  status = provider->ops.open(provider->context, core, &delegated,
                              &open->result_spec, &open->operation);
  if (status != FTUN_OK || open->operation == NULL) {
    if (open->operation != NULL) {
      /* 违反零接纳错误契约的工厂仍不能使已接纳 callback 悬空。 */
      open->suppress = true;
      open->revoked = true;
      (void)ftun_operation_cancel(open->operation);
      return FTUN_E_STATE_CORRUPT;
    }
    ftun_path_open_release(open);
    return status == FTUN_OK ? FTUN_E_STATE_CORRUPT : status;
  }
  *out = open->operation;
  return FTUN_OK;
}

ftun_status_t ftun_path_provider_open_channel(ftun_path_provider_t *provider,
  ftun_core_t *core, uint64_t configuration_generation,
  const ftun_path_open_request_t *request, ftun_operation_t **out)
{
  return ftun_path_provider_open_channel_internal(provider, core,
    configuration_generation, false, request, out);
}

ftun_status_t ftun_path_provider_scope(ftun_path_provider_t *provider,
  uint64_t configuration_generation, ftun_path_scope_t **out)
{
  ftun_path_scope_t *scope;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (provider == NULL || out == NULL || configuration_generation == 0u) return FTUN_E_INVALID;
  if (!provider->accepting || provider->stopped) return FTUN_E_CANCELLED;
  if (provider->visiting) return FTUN_E_AGAIN;
  if (provider->generation != configuration_generation) return FTUN_E_STALE;
  if (provider->scope_count >= provider->max_paths) return FTUN_E_LIMIT;
  status = ftun_budget_reserve(provider->budget, sizeof(*scope), &reservation);
  if (status != FTUN_OK) return status;
  scope = (ftun_path_scope_t *)calloc(1u, sizeof(*scope));
  if (scope == NULL) { (void)ftun_reservation_release(&reservation); return FTUN_E_LIMIT; }
  scope->provider = provider;
  scope->reservation = reservation;
  scope->generation = configuration_generation;
  scope->references = 1u;
  provider->scope_count++;
  *out = scope;
  return FTUN_OK;
}

ftun_status_t ftun_path_scope_retain(ftun_path_scope_t *scope)
{
  if (scope == NULL) return FTUN_E_INVALID;
  if (scope->references == SIZE_MAX) return FTUN_E_LIMIT;
  scope->references++;
  return FTUN_OK;
}

ftun_status_t ftun_path_scope_release(ftun_path_scope_t **scope)
{
  ftun_path_scope_t *owned;
  ftun_status_t status;
  if (scope == NULL) return FTUN_E_INVALID;
  owned = *scope;
  if (owned == NULL) return FTUN_OK;
  if (owned->references > 1u) { owned->references--; *scope = NULL; return FTUN_OK; }
  status = ftun_reservation_release(&owned->reservation);
  if (status != FTUN_OK) return status;
  owned->provider->scope_count--;
  free(owned);
  *scope = NULL;
  return FTUN_OK;
}

ftun_status_t ftun_path_scope_generation(const ftun_path_scope_t *scope, uint64_t *out)
{
  if (out != NULL) *out = 0u;
  if (scope == NULL || out == NULL) return FTUN_E_INVALID;
  *out = scope->generation;
  return FTUN_OK;
}

ftun_status_t ftun_path_scope_open(ftun_path_scope_t *scope, ftun_core_t *core,
  const ftun_path_open_request_t *request, ftun_operation_t **out)
{
  if (out != NULL) *out = NULL;
  if (scope == NULL) return FTUN_E_INVALID;
  return ftun_path_provider_open_channel_internal(scope->provider, core,
    scope->generation, true, request, out);
}

ftun_status_t ftun_path_local_endpoint(ftun_path_t *path, ftun_endpoint_t *out)
{
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (path == NULL || out == NULL) return FTUN_E_INVALID;
  if (path->busy) return FTUN_E_AGAIN;
  if (path->info.revoked) return FTUN_E_CANCELLED;
  if (path->driver.local_endpoint == NULL) return FTUN_E_UNSUPPORTED;
  path->busy = true;
  status = path->driver.local_endpoint(path->driver.context, out);
  path->busy = false;
  return status;
}

ftun_status_t ftun_path_send_progress(ftun_path_t *path, uint64_t *acked,
  uint32_t *queued)
{
  ftun_status_t status;
  if (path == NULL || acked == NULL || queued == NULL) return FTUN_E_INVALID;
  if (path->busy) return FTUN_E_AGAIN;
  if (path->info.revoked) return FTUN_E_CANCELLED;
  if (path->driver.send_progress == NULL) return FTUN_E_UNSUPPORTED;
  path->busy = true;
  status = path->driver.send_progress(path->driver.context, acked, queued);
  path->busy = false;
  return status;
}

static ftun_status_t ftun_path_provider_sweep(ftun_path_provider_t *provider,
  const ftun_network_view_t *view, bool all)
{
  ftun_path_open_t *open;
  ftun_path_t *path;
  ftun_status_t first = FTUN_OK;
  if (provider->visiting) return FTUN_E_AGAIN;
  provider->visiting = true;
  for (open = provider->opens; open != NULL; open = open->next) {
    ftun_status_t status;
    if (!all && (view == NULL || open->result_spec.network_view != view)) continue;
    open->revoked = true;
    if (open->completing || open->operation == NULL) continue;
    status = ftun_operation_cancel(open->operation);
    if (status != FTUN_OK && status != FTUN_E_STALE && first == FTUN_OK) first = status;
  }
  path = provider->paths;
  while (path != NULL) {
    ftun_path_t *next = path->next;
    ftun_status_t status = FTUN_OK;
    if (all || path->retired || (view != NULL && path->network_view == view)) {
      status = ftun_path_revoke(path);
      if (status == FTUN_OK && path->retired) {
        provider->cleanup_path = path;
        status = ftun_path_destroy(&path);
        provider->cleanup_path = NULL;
      }
    }
    if (first == FTUN_OK && status != FTUN_OK) first = status;
    path = next;
  }
  provider->visiting = false;
  return first;
}

ftun_status_t ftun_path_provider_collect(ftun_path_provider_t *provider)
{
  if (provider == NULL) return FTUN_E_INVALID;
  return ftun_path_provider_sweep(provider, NULL, false);
}

ftun_status_t ftun_path_provider_revoke_network(ftun_path_provider_t *provider,
  ftun_network_view_t *view)
{
  ftun_status_t status;
  if (provider == NULL || view == NULL) return FTUN_E_INVALID;
  status = ftun_network_view_revoke(view);
  if (status != FTUN_OK) return status;
  return ftun_path_provider_sweep(provider, view, false);
}

ftun_status_t ftun_path_provider_reload_prepare(
  ftun_path_provider_t *provider, uint64_t generation)
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
  provider->reload_pending = false;
  return FTUN_OK;
}

ftun_status_t ftun_path_provider_reload_abort(ftun_path_provider_t *provider)
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

ftun_status_t ftun_path_provider_quiesce(ftun_path_provider_t *provider)
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

ftun_status_t ftun_path_provider_stop_until(
  ftun_path_provider_t *provider, uint64_t deadline_ms)
{
  ftun_status_t status;
  ftun_status_t first;
  ftun_path_t *path;
  uint64_t now;
  if (provider == NULL || deadline_ms == 0u) return FTUN_E_INVALID;
  if (provider->visiting) return FTUN_E_AGAIN;
  if (provider->stopped) return FTUN_OK;
  status = ftun_path_provider_quiesce(provider);
  if (status != FTUN_OK) return status;
  first = ftun_path_provider_sweep(provider, NULL, true);
  if (provider->ops.stop_until != NULL) {
    status = provider->ops.stop_until(provider->context, deadline_ms);
    if (status != FTUN_OK && first == FTUN_OK) first = status;
  }
  if (first != FTUN_OK) {
    if (first == FTUN_E_AGAIN &&
        (provider->pending_count != 0u || provider->path_count != 0u)) {
      status = ftun_monotonic_now(&now);
      if (status != FTUN_OK) return status;
      if (now >= deadline_ms) return FTUN_E_TIMEOUT;
    }
    return first;
  }
  status = provider->pending_count != 0u || provider->retired_count != 0u
    ? FTUN_E_AGAIN : FTUN_OK;
  for (path = provider->paths; path != NULL; path = path->next) {
    if (path->stream != NULL) {
      ftun_stream_usage_t usage;
      first = ftun_stream_get_usage(path->stream, &usage);
      if (first != FTUN_OK) return first;
      if (usage.pending_writes != 0u || usage.in_completion || usage.in_backend) {
        status = FTUN_E_AGAIN;
      }
    } else if (path->datagram != NULL) {
      ftun_datagram_usage_t usage;
      first = ftun_datagram_get_usage(path->datagram, &usage);
      if (first != FTUN_OK) return first;
      if (usage.pending_packets != 0u || usage.in_callback || usage.in_backend) {
        status = FTUN_E_AGAIN;
      }
    }
    if (path->busy) status = FTUN_E_AGAIN;
  }
  if (status != FTUN_OK) {
    first = ftun_monotonic_now(&now);
    if (first != FTUN_OK) return first;
    return now >= deadline_ms ? FTUN_E_TIMEOUT : status;
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
  out->pending = provider->pending_count;
  out->paths = provider->path_count;
  out->retired = provider->retired_count;
  out->scopes = provider->scope_count;
  return FTUN_OK;
}

ftun_status_t ftun_path_provider_destroy(ftun_path_provider_t **provider)
{
  ftun_path_provider_t *owned;
  ftun_reservation_t *reservation;
  if (provider == NULL) return FTUN_E_INVALID;
  owned = *provider;
  if (owned == NULL) return FTUN_OK;
  if (!owned->stopped || owned->reload_pending || owned->visiting ||
      owned->pending_count != 0u || owned->path_count != 0u ||
      owned->scope_count != 0u) return FTUN_E_AGAIN;
  reservation = owned->reservation;
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *provider = NULL;
  return ftun_reservation_release(&reservation);
}
