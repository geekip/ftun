#include "proxy/session.h"

#include "core/budget.h"
#include "core/operation.h"
#include "proxy/runtime_state.h"
#include "transport/stream.h"

#include <stdlib.h>
#include <string.h>

struct ftun_session {
  ftun_runtime_t *runtime;
  ftun_stream_t *inbound;
  ftun_operation_t *pending_operation;
  ftun_reservation_t *reservation;
  ftun_metadata_t metadata;
  ftun_route_result_t route;
  ftun_endpoint_t *resolved;
  ftun_endpoint_t *allowed;
  size_t endpoint_capacity;
  size_t accounted_bytes;
  ftun_session_state_t state;
  ftun_error_t terminal_error;
  int route_pinned;
};

static int ftun_session_size_add(size_t *total, size_t value)
{
  if (*total > SIZE_MAX - value) return 0;
  *total += value;
  return 1;
}

static int ftun_session_size_array(size_t *total, size_t count,
                                   size_t item_size)
{
  if (item_size != 0u && count > SIZE_MAX / item_size) return 0;
  return ftun_session_size_add(total, count * item_size);
}

static ftun_status_t ftun_session_string_validate(ftun_string_t value,
                                                  size_t maximum,
                                                  int allow_empty)
{
  if (value.length == 0u) return allow_empty ? FTUN_OK : FTUN_E_INVALID;
  if (value.data == NULL || value.length > maximum ||
      memchr(value.data, '\0', value.length) != NULL) return FTUN_E_INVALID;
  return FTUN_OK;
}

static ftun_status_t ftun_session_endpoint_validate(
  const ftun_endpoint_t *endpoint, int allow_none)
{
  if (endpoint == NULL) return FTUN_E_INVALID;
  if (endpoint->kind == FTUN_ADDRESS_NONE) {
    return allow_none && endpoint->port == 0u && endpoint->domain.length == 0u
      ? FTUN_OK : FTUN_E_INVALID;
  }
  if (endpoint->kind == FTUN_ADDRESS_IPV6_RESERVED) return FTUN_E_UNSUPPORTED;
  if (endpoint->kind == FTUN_ADDRESS_IPV4) {
    return endpoint->domain.length == 0u ? FTUN_OK : FTUN_E_INVALID;
  }
  if (endpoint->kind != FTUN_ADDRESS_DOMAIN) return FTUN_E_INVALID;
  return ftun_session_string_validate(endpoint->domain, 253u, 0);
}

static int ftun_session_add_string_size(size_t *total, ftun_string_t value)
{
  return value.length == 0u ||
         (ftun_session_size_add(total, value.length) &&
          ftun_session_size_add(total, 1u));
}

static ftun_status_t ftun_session_layout(const ftun_metadata_t *metadata,
                                         size_t *capacity,
                                         size_t *accounted_bytes)
{
  const uint32_t known = FTUN_META_SOURCE | FTUN_META_PORT |
                         FTUN_META_NETWORK | FTUN_META_DOMAIN;
  size_t total = sizeof(ftun_session_t);
  size_t slots;
  size_t index;
  ftun_status_t status;
  if (metadata == NULL || capacity == NULL || accounted_bytes == NULL ||
      (metadata->known_fields & ~known) != 0u) return FTUN_E_INVALID;
  if ((metadata->known_fields & FTUN_META_NETWORK) != 0u) {
    if (metadata->network != 1u && metadata->network != 2u) {
      return FTUN_E_INVALID;
    }
  } else if (metadata->network != 0u) {
    return FTUN_E_INVALID;
  }
  if ((metadata->known_fields & FTUN_META_PORT) == 0u ||
      metadata->original_target.port == 0u) return FTUN_E_INVALID;
  status = ftun_session_endpoint_validate(&metadata->original_target, 0);
  if (status != FTUN_OK) return status;
  if ((metadata->known_fields & FTUN_META_SOURCE) != 0u) {
    status = ftun_session_endpoint_validate(&metadata->source, 0);
    if (status != FTUN_OK) return status;
  } else if (metadata->source.kind != FTUN_ADDRESS_NONE) {
    return FTUN_E_INVALID;
  }
  if ((metadata->known_fields & FTUN_META_DOMAIN) != 0u) {
    status = ftun_session_string_validate(metadata->domain, 253u, 0);
    if (status != FTUN_OK) return status;
  } else if (metadata->domain.length != 0u) {
    return FTUN_E_INVALID;
  }
  if (metadata->resolved_count != 0u && metadata->resolved == NULL) {
    return FTUN_E_INVALID;
  }
  if (metadata->resolved_count > FTUN_SESSION_MAX_RESOLVED_IPV4) {
    return FTUN_E_LIMIT;
  }
  for (index = 0u; index < metadata->resolved_count; index++) {
    status = ftun_session_endpoint_validate(&metadata->resolved[index], 0);
    if (status != FTUN_OK) return status;
    if (metadata->resolved[index].kind != FTUN_ADDRESS_IPV4 ||
        metadata->resolved[index].port == 0u) return FTUN_E_INVALID;
  }
  slots = metadata->resolved_count;
  if (slots == 0u) {
    slots = metadata->original_target.kind == FTUN_ADDRESS_DOMAIN ||
            metadata->original_is_fake
      ? FTUN_SESSION_MAX_RESOLVED_IPV4 : 1u;
  }
  if (!ftun_session_size_array(&total, slots, sizeof(ftun_endpoint_t)) ||
      !ftun_session_size_array(&total, slots, sizeof(ftun_endpoint_t)) ||
      !ftun_session_add_string_size(&total, metadata->source.domain) ||
      !ftun_session_add_string_size(&total, metadata->original_target.domain) ||
      !ftun_session_add_string_size(&total, metadata->domain)) {
    return FTUN_E_LIMIT;
  }
  for (index = 0u; index < metadata->resolved_count; index++) {
    if (!ftun_session_add_string_size(&total,
                                      metadata->resolved[index].domain)) {
      return FTUN_E_LIMIT;
    }
  }
  *capacity = slots;
  *accounted_bytes = total;
  return FTUN_OK;
}

static void ftun_session_copy_string(ftun_string_t source,
                                     ftun_string_t *destination,
                                     char **cursor)
{
  memset(destination, 0, sizeof(*destination));
  if (source.length == 0u) return;
  memcpy(*cursor, source.data, source.length);
  (*cursor)[source.length] = '\0';
  destination->data = *cursor;
  destination->length = source.length;
  *cursor += source.length + 1u;
}

static void ftun_session_copy_endpoint(const ftun_endpoint_t *source,
                                       ftun_endpoint_t *destination,
                                       char **cursor)
{
  *destination = *source;
  if (source->kind == FTUN_ADDRESS_DOMAIN) {
    ftun_session_copy_string(source->domain, &destination->domain, cursor);
  } else {
    memset(&destination->domain, 0, sizeof(destination->domain));
  }
}

static int ftun_session_endpoint_equal(const ftun_endpoint_t *left,
                                       const ftun_endpoint_t *right)
{
  if (left->kind != right->kind || left->port != right->port) return 0;
  if (left->kind == FTUN_ADDRESS_IPV4) {
    return memcmp(left->address, right->address, 4u) == 0;
  }
  if (left->kind == FTUN_ADDRESS_DOMAIN) {
    return left->domain.length == right->domain.length &&
           memcmp(left->domain.data, right->domain.data,
                  left->domain.length) == 0;
  }
  return left->kind == FTUN_ADDRESS_NONE;
}

static const ftun_endpoint_t *ftun_session_allowed_source(
  const ftun_session_t *session, const ftun_endpoint_t *candidate)
{
  size_t index;
  if (session->metadata.resolved_count == 0u) {
    return ftun_session_endpoint_equal(candidate,
      &session->metadata.original_target) ? &session->metadata.original_target : NULL;
  }
  for (index = 0u; index < session->metadata.resolved_count; index++) {
    if (ftun_session_endpoint_equal(candidate,
                                    &session->metadata.resolved[index])) {
      return &session->metadata.resolved[index];
    }
  }
  return NULL;
}

static int ftun_session_transition_allowed(ftun_session_state_t current,
                                           ftun_session_state_t next)
{
  switch (current) {
    case FTUN_SESSION_ACCEPTED:
      return next == FTUN_SESSION_HANDSHAKING || next == FTUN_SESSION_ROUTING;
    case FTUN_SESSION_HANDSHAKING:
      return next == FTUN_SESSION_ROUTING;
    case FTUN_SESSION_ROUTING:
      return next == FTUN_SESSION_RESOLVING || next == FTUN_SESSION_CONNECTING;
    case FTUN_SESSION_RESOLVING:
      return next == FTUN_SESSION_ROUTING;
    case FTUN_SESSION_CONNECTING:
      return next == FTUN_SESSION_REPLYING || next == FTUN_SESSION_RELAYING;
    case FTUN_SESSION_REPLYING:
      return next == FTUN_SESSION_RELAYING;
    case FTUN_SESSION_RELAYING:
      return next == FTUN_SESSION_DRAINING;
    case FTUN_SESSION_DRAINING:
    case FTUN_SESSION_CLOSING:
    case FTUN_SESSION_CLOSED:
    default:
      return 0;
  }
}

static ftun_status_t ftun_session_close(ftun_session_t *session,
                                        ftun_error_t result,
                                        int preserve_result)
{
  ftun_status_t status;
  if (!preserve_result) session->terminal_error = result;
  session->state = FTUN_SESSION_CLOSING;
  status = ftun_stream_stop(session->inbound);
  if (status != FTUN_OK) return status;
  if (session->pending_operation != NULL) {
    status = ftun_operation_cancel(session->pending_operation);
    if (status == FTUN_E_STALE) return FTUN_OK;
    return status;
  }
  session->state = FTUN_SESSION_CLOSED;
  return FTUN_OK;
}

/* ftun_session_submit 实现 TASK-CORE-002（0.2.0）的 owner-loop 生命周期。 */
ftun_status_t ftun_session_submit(ftun_core_t *core,
                                  const ftun_metadata_t *metadata,
                                  ftun_stream_t *inbound,
                                  ftun_session_t **out)
{
  ftun_session_t *session;
  ftun_runtime_t *runtime = NULL;
  ftun_budget_t *manager_budget = NULL;
  ftun_budget_t *stream_budget = NULL;
  ftun_reservation_t *reservation = NULL;
  ftun_runtime_info_t runtime_info;
  bool same_budget_root = false;
  ftun_status_t status;
  size_t capacity = 0u;
  size_t accounted_bytes = 0u;
  size_t index;
  char *cursor;
  if (out != NULL) *out = NULL;
  if (core == NULL || metadata == NULL || inbound == NULL || out == NULL) {
    return FTUN_E_INVALID;
  }
  status = ftun_session_layout(metadata, &capacity, &accounted_bytes);
  if (status != FTUN_OK) return status;
  status = ftun_core_context_budget(core, &manager_budget);
  if (status == FTUN_OK) status = ftun_stream_budget(inbound, &stream_budget);
  if (status == FTUN_OK) {
    status = ftun_budget_same_root(manager_budget, stream_budget,
                                   &same_budget_root);
  }
  if (status != FTUN_OK) return status;
  if (!same_budget_root) return FTUN_E_REJECTED;
  status = ftun_runtime_active_acquire(core, &runtime);
  if (status != FTUN_OK) return status;
  status = ftun_runtime_get_info(runtime, &runtime_info);
  if (status != FTUN_OK || (metadata->generation != 0u &&
      metadata->generation != runtime_info.generation)) {
    (void)ftun_runtime_release(&runtime);
    return status != FTUN_OK ? status : FTUN_E_STALE;
  }
  status = ftun_budget_reserve(manager_budget, accounted_bytes, &reservation);
  if (status != FTUN_OK) {
    (void)ftun_runtime_release(&runtime);
    return status;
  }
  session = (ftun_session_t *)calloc(1u, accounted_bytes);
  if (session == NULL) {
    (void)ftun_reservation_release(&reservation);
    (void)ftun_runtime_release(&runtime);
    return FTUN_E_LIMIT;
  }
  status = ftun_stream_retain(inbound);
  if (status != FTUN_OK) {
    free(session);
    (void)ftun_reservation_release(&reservation);
    (void)ftun_runtime_release(&runtime);
    return status;
  }
  session->runtime = runtime;
  session->inbound = inbound;
  session->reservation = reservation;
  session->endpoint_capacity = capacity;
  session->accounted_bytes = accounted_bytes;
  session->state = FTUN_SESSION_ACCEPTED;
  session->resolved = (ftun_endpoint_t *)(session + 1u);
  session->allowed = session->resolved + capacity;
  cursor = (char *)(session->allowed + capacity);
  session->metadata = *metadata;
  session->metadata.generation = runtime_info.generation;
  ftun_session_copy_endpoint(&metadata->source, &session->metadata.source,
                             &cursor);
  ftun_session_copy_endpoint(&metadata->original_target,
                             &session->metadata.original_target, &cursor);
  ftun_session_copy_string(metadata->domain, &session->metadata.domain,
                           &cursor);
  for (index = 0u; index < metadata->resolved_count; index++) {
    ftun_session_copy_endpoint(&metadata->resolved[index],
                               &session->resolved[index], &cursor);
  }
  session->metadata.resolved = metadata->resolved_count == 0u
    ? NULL : session->resolved;
  *out = session;
  return FTUN_OK;
}

ftun_status_t ftun_session_transition(ftun_session_t *session,
                                      ftun_session_state_t next,
                                      ftun_operation_t *operation)
{
  if (session == NULL) return FTUN_E_INVALID;
  if (session->pending_operation != NULL) return FTUN_E_AGAIN;
  if (!ftun_session_transition_allowed(session->state, next)) {
    return FTUN_E_STALE;
  }
  if (next == FTUN_SESSION_CONNECTING && !session->route_pinned) {
    return FTUN_E_AGAIN;
  }
  session->state = next;
  session->pending_operation = operation;
  return FTUN_OK;
}

ftun_status_t ftun_session_pin_route(ftun_session_t *session,
                                     const ftun_route_result_t *route)
{
  size_t index;
  if (session == NULL || route == NULL) return FTUN_E_INVALID;
  if (session->state != FTUN_SESSION_ROUTING || session->route_pinned) {
    return FTUN_E_STALE;
  }
  if (route->kind != FTUN_ROUTE_READY ||
      route->generation != session->metadata.generation ||
      (route->allowed_count != 0u && route->allowed == NULL)) {
    return route->generation != session->metadata.generation
      ? FTUN_E_STALE : FTUN_E_INVALID;
  }
  if (route->allowed_count > session->endpoint_capacity) return FTUN_E_REJECTED;
  for (index = 0u; index < route->allowed_count; index++) {
    const ftun_endpoint_t *source;
    ftun_status_t status = ftun_session_endpoint_validate(
      &route->allowed[index], 0);
    if (status != FTUN_OK) return status;
    source = ftun_session_allowed_source(session, &route->allowed[index]);
    if (source == NULL) return FTUN_E_REJECTED;
    session->allowed[index] = *source;
  }
  session->route = *route;
  session->route.allowed = route->allowed_count == 0u ? NULL : session->allowed;
  session->route_pinned = 1;
  return FTUN_OK;
}

ftun_status_t ftun_session_operation_complete(ftun_session_t *session,
                                               ftun_operation_t *operation,
                                               ftun_error_t result)
{
  ftun_error_t terminal;
  ftun_status_t status;
  if (session == NULL || operation == NULL) return FTUN_E_INVALID;
  if (session->pending_operation != operation) return FTUN_E_STALE;
  session->pending_operation = NULL;
  if (session->state == FTUN_SESSION_CLOSING) {
    session->state = FTUN_SESSION_CLOSED;
    return FTUN_OK;
  }
  if (result.status == FTUN_E_AGAIN) {
    memset(&terminal, 0, sizeof(terminal));
    terminal.status = FTUN_E_STATE_CORRUPT;
    status = ftun_session_close(session, terminal, 0);
    return status == FTUN_OK ? FTUN_E_STATE_CORRUPT : status;
  }
  if (result.status == FTUN_OK) return FTUN_OK;
  terminal = result;
  return ftun_session_close(session, terminal, 0);
}

ftun_status_t ftun_session_store_resolved(
  ftun_session_t *session, ftun_operation_t *operation,
  const ftun_endpoint_t *addresses, size_t address_count)
{
  size_t index;
  size_t previous;
  if (session == NULL || operation == NULL || addresses == NULL ||
      address_count == 0u) return FTUN_E_INVALID;
  if (session->state != FTUN_SESSION_RESOLVING ||
      session->pending_operation != operation ||
      session->metadata.resolved_count != 0u) return FTUN_E_STALE;
  if (address_count > session->endpoint_capacity ||
      address_count > FTUN_SESSION_MAX_RESOLVED_IPV4) return FTUN_E_LIMIT;
  for (index = 0u; index < address_count; index++) {
    if (addresses[index].kind != FTUN_ADDRESS_IPV4 ||
        addresses[index].port != 0u ||
        addresses[index].domain.length != 0u) {
      return addresses[index].kind == FTUN_ADDRESS_IPV6_RESERVED
        ? FTUN_E_UNSUPPORTED : FTUN_E_STATE_CORRUPT;
    }
    for (previous = 0u; previous < index; previous++) {
      if (memcmp(addresses[index].address,
                 addresses[previous].address, 4u) == 0) {
        return FTUN_E_STATE_CORRUPT;
      }
    }
  }
  for (index = 0u; index < address_count; index++) {
    session->resolved[index] = addresses[index];
    session->resolved[index].port = session->metadata.original_target.port;
  }
  session->metadata.resolved = session->resolved;
  session->metadata.resolved_count = address_count;
  return FTUN_OK;
}

ftun_status_t ftun_session_finish(ftun_session_t *session,
                                  ftun_error_t result)
{
  if (session == NULL || result.status == FTUN_E_AGAIN) return FTUN_E_INVALID;
  if (session->state == FTUN_SESSION_CLOSED) return FTUN_E_STALE;
  if (session->state == FTUN_SESSION_CLOSING) {
    return ftun_session_close(session, session->terminal_error, 1);
  }
  if (result.status == FTUN_OK && session->state != FTUN_SESSION_DRAINING) {
    return FTUN_E_STALE;
  }
  return ftun_session_close(session, result, 0);
}

ftun_status_t ftun_session_cancel(ftun_session_t *session)
{
  ftun_error_t result;
  memset(&result, 0, sizeof(result));
  result.status = FTUN_E_CANCELLED;
  return ftun_session_finish(session, result);
}

ftun_status_t ftun_session_get_info(const ftun_session_t *session,
                                    ftun_session_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (session == NULL || out == NULL) return FTUN_E_INVALID;
  out->state = session->state;
  out->runtime_generation = session->metadata.generation;
  out->outbound_id = session->route.outbound_id;
  out->allowed_count = session->route.allowed_count;
  out->accounted_bytes = session->accounted_bytes;
  out->terminal_error = session->terminal_error;
  out->route_pinned = session->route_pinned != 0;
  out->has_pending_operation = session->pending_operation != NULL;
  return FTUN_OK;
}

ftun_status_t ftun_session_get_metadata(const ftun_session_t *session,
                                        const ftun_metadata_t **out)
{
  if (out != NULL) *out = NULL;
  if (session == NULL || out == NULL) return FTUN_E_INVALID;
  *out = &session->metadata;
  return FTUN_OK;
}

ftun_status_t ftun_session_get_route(const ftun_session_t *session,
                                     const ftun_route_result_t **out)
{
  if (out != NULL) *out = NULL;
  if (session == NULL || out == NULL) return FTUN_E_INVALID;
  if (!session->route_pinned) return FTUN_E_AGAIN;
  *out = &session->route;
  return FTUN_OK;
}

ftun_status_t ftun_session_get_runtime(const ftun_session_t *session,
                                       const ftun_runtime_t **out)
{
  if (out != NULL) *out = NULL;
  if (session == NULL || out == NULL) return FTUN_E_INVALID;
  *out = session->runtime;
  return FTUN_OK;
}

ftun_status_t ftun_session_destroy(ftun_session_t **session)
{
  ftun_session_t *owned;
  ftun_reservation_t *reservation;
  ftun_status_t status;
  if (session == NULL) return FTUN_E_INVALID;
  owned = *session;
  if (owned == NULL) return FTUN_OK;
  if (owned->state != FTUN_SESSION_CLOSED ||
      owned->pending_operation != NULL) return FTUN_E_AGAIN;
  status = ftun_stream_release(&owned->inbound);
  if (status != FTUN_OK) return status;
  status = ftun_runtime_release(&owned->runtime);
  if (status != FTUN_OK) return status;
  reservation = owned->reservation;
  owned->reservation = NULL;
  status = ftun_reservation_release(&reservation);
  if (status != FTUN_OK) return status;
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *session = NULL;
  return FTUN_OK;
}
