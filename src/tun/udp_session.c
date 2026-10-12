#include "udp_session.h"

#include "core/runtime.h"

#include <stdlib.h>
#include <string.h>

#define FTUN_UDP_FLOW_DOMAIN_BYTES 254u
#define FTUN_UDP_FLOW_BUCKETS 512u
#define FTUN_UDP_FLOW_REAP_QUOTA 32u

typedef struct ftun_udp_flow ftun_udp_flow_t;

struct ftun_udp_flow {
  ftun_udp_flow_table_t *table;
  ftun_udp_flow_t *next;
  ftun_udp_flow_t *hash_next;
  ftun_reservation_t *reservation;
  ftun_runtime_t *runtime;
  ftun_datagram_t *inbound;
  ftun_datagram_t *outbound;
  ftun_metadata_t metadata;
  ftun_endpoint_t resolved[FTUN_UDP_FLOW_MAX_RESOLVED_IPV4];
  ftun_endpoint_t remote;
  char domain[FTUN_UDP_FLOW_DOMAIN_BYTES];
  uint64_t expires_at;
  uint32_t outbound_id;
  uint32_t route_outbound_id;
  ftun_status_t failure_status;
  bool route_pinned;
  bool failed;
};

struct ftun_udp_flow_table {
  ftun_core_t *core;
  ftun_budget_t *budget;
  ftun_reservation_t *reservation;
  ftun_udp_flow_backend_t backend;
  ftun_udp_flow_t *flows;
  ftun_udp_flow_t *buckets[FTUN_UDP_FLOW_BUCKETS];
  ftun_udp_flow_t *reap_cursor;
  size_t capacity;
  size_t active;
  size_t created;
  size_t expired;
  size_t failed;
  size_t rejected_sources;
  uint64_t idle_timeout_ms;
  uint64_t now_ms;
  bool accepting;
};

static ftun_udp_flow_table_t *ftun_udp_flow_active;

static void ftun_udp_flow_increment(size_t *value)
{
  if (*value != SIZE_MAX) (*value)++;
}

static int ftun_udp_endpoint_equal(const ftun_endpoint_t *left,
                                   const ftun_endpoint_t *right)
{
  if (left == NULL || right == NULL || left->kind != right->kind ||
      left->port != right->port) return 0;
  if (left->kind == FTUN_ADDRESS_IPV4) {
    return memcmp(left->address, right->address, 4u) == 0;
  }
  return left->kind == FTUN_ADDRESS_DOMAIN &&
         left->domain.data != NULL && right->domain.data != NULL &&
         left->domain.length == right->domain.length &&
         memcmp(left->domain.data, right->domain.data,
                left->domain.length) == 0;
}

static ftun_status_t ftun_udp_metadata_validate(
  const ftun_metadata_t *metadata)
{
  const uint32_t required = FTUN_META_SOURCE | FTUN_META_PORT |
                            FTUN_META_NETWORK;
  const uint32_t known = required | FTUN_META_DOMAIN;
  size_t index;
  if (metadata == NULL || metadata->generation == 0u ||
      metadata->inbound_id == 0u ||
      (metadata->known_fields & required) != required ||
      (metadata->known_fields & ~known) != 0u || metadata->network != 2u ||
      metadata->source.kind != FTUN_ADDRESS_IPV4 ||
      metadata->source.port == 0u || metadata->source.domain.length != 0u ||
      metadata->original_target.port == 0u ||
      (metadata->original_target.kind != FTUN_ADDRESS_IPV4 &&
       metadata->original_target.kind != FTUN_ADDRESS_DOMAIN) ||
      metadata->resolved_count > FTUN_UDP_FLOW_MAX_RESOLVED_IPV4 ||
      (metadata->resolved_count != 0u && metadata->resolved == NULL)) {
    return FTUN_E_INVALID;
  }
  if (metadata->original_target.kind == FTUN_ADDRESS_IPV4 &&
      metadata->original_target.domain.length != 0u) return FTUN_E_INVALID;
  if (metadata->original_target.kind == FTUN_ADDRESS_DOMAIN &&
      (metadata->original_target.domain.data == NULL ||
       metadata->original_target.domain.length == 0u ||
       metadata->original_target.domain.length >= FTUN_UDP_FLOW_DOMAIN_BYTES)) {
    return FTUN_E_INVALID;
  }
  if ((metadata->known_fields & FTUN_META_DOMAIN) != 0u) {
    if (metadata->domain.data == NULL || metadata->domain.length == 0u ||
        metadata->domain.length >= FTUN_UDP_FLOW_DOMAIN_BYTES ||
        memchr(metadata->domain.data, '\0', metadata->domain.length) != NULL) {
      return FTUN_E_INVALID;
    }
  } else if (metadata->domain.length != 0u ||
             metadata->domain_source != FTUN_DOMAIN_NONE) {
    return FTUN_E_INVALID;
  }
  if (metadata->original_is_fake) {
    if ((metadata->known_fields & FTUN_META_DOMAIN) == 0u ||
        metadata->domain_source != FTUN_DOMAIN_FAKEIP) return FTUN_E_INVALID;
  } else if (metadata->domain_source == FTUN_DOMAIN_FAKEIP) {
    return FTUN_E_INVALID;
  }
  for (index = 0u; index < metadata->resolved_count; index++) {
    size_t previous;
    const ftun_endpoint_t *endpoint = &metadata->resolved[index];
    if (endpoint->kind != FTUN_ADDRESS_IPV4 ||
        endpoint->port != metadata->original_target.port ||
        endpoint->domain.length != 0u) return FTUN_E_INVALID;
    for (previous = 0u; previous < index; previous++) {
      if (ftun_udp_endpoint_equal(endpoint, &metadata->resolved[previous])) {
        return FTUN_E_INVALID;
      }
    }
  }
  return FTUN_OK;
}

static bool ftun_udp_remote_allowed(const ftun_metadata_t *metadata,
                                    const ftun_endpoint_t *remote)
{
  size_t index;
  if (remote == NULL || remote->port != metadata->original_target.port) {
    return false;
  }
  if (remote->kind == FTUN_ADDRESS_DOMAIN) {
    ftun_string_t expected = metadata->original_is_fake
      ? metadata->domain : metadata->original_target.domain;
    return remote->domain.data != NULL && expected.data != NULL &&
      remote->domain.length == expected.length &&
      memcmp(remote->domain.data, expected.data, expected.length) == 0;
  }
  if (remote->kind != FTUN_ADDRESS_IPV4 || remote->domain.length != 0u) {
    return false;
  }
  if (!metadata->original_is_fake &&
      metadata->original_target.kind == FTUN_ADDRESS_IPV4) {
    return ftun_udp_endpoint_equal(remote, &metadata->original_target);
  }
  for (index = 0u; index < metadata->resolved_count; index++) {
    if (ftun_udp_endpoint_equal(remote, &metadata->resolved[index])) {
      return true;
    }
  }
  return false;
}

static uint64_t ftun_udp_expiry(const ftun_udp_flow_table_t *table)
{
  if (table->now_ms > UINT64_MAX - table->idle_timeout_ms) return UINT64_MAX;
  return table->now_ms + table->idle_timeout_ms;
}

static bool ftun_udp_flow_key_equal(const ftun_udp_flow_t *flow,
                                    const ftun_metadata_t *metadata,
                                    const ftun_route_result_t *route)
{
  if (flow->metadata.generation != metadata->generation ||
      flow->metadata.inbound_id != metadata->inbound_id ||
      flow->metadata.network != metadata->network ||
      flow->metadata.original_is_fake != metadata->original_is_fake ||
      !ftun_udp_endpoint_equal(&flow->metadata.source, &metadata->source) ||
      !ftun_udp_endpoint_equal(&flow->metadata.original_target,
                               &metadata->original_target) ||
      flow->route_pinned != (route != NULL) ||
      (route != NULL && flow->route_outbound_id != route->outbound_id)) {
    return false;
  }
  if (!metadata->original_is_fake) return true;
  return flow->metadata.domain.length == metadata->domain.length &&
         memcmp(flow->metadata.domain.data, metadata->domain.data,
                metadata->domain.length) == 0;
}

static uint64_t ftun_udp_hash_bytes(uint64_t hash, const void *data,
                                    size_t length)
{
  const uint8_t *bytes = (const uint8_t *)data;
  size_t index;
  for (index = 0u; index < length; index++) {
    hash ^= bytes[index];
    hash *= UINT64_C(1099511628211);
  }
  return hash;
}

static size_t ftun_udp_flow_hash(const ftun_metadata_t *metadata)
{
  uint64_t hash = UINT64_C(1469598103934665603);
  hash = ftun_udp_hash_bytes(hash, &metadata->generation,
                             sizeof(metadata->generation));
  hash = ftun_udp_hash_bytes(hash, &metadata->inbound_id,
                             sizeof(metadata->inbound_id));
  hash = ftun_udp_hash_bytes(hash, &metadata->network,
                             sizeof(metadata->network));
  hash = ftun_udp_hash_bytes(hash, &metadata->original_is_fake,
                             sizeof(metadata->original_is_fake));
  hash = ftun_udp_hash_bytes(hash, metadata->source.address, 4u);
  hash = ftun_udp_hash_bytes(hash, &metadata->source.port,
                             sizeof(metadata->source.port));
  hash = ftun_udp_hash_bytes(hash, &metadata->original_target.kind,
                             sizeof(metadata->original_target.kind));
  hash = ftun_udp_hash_bytes(hash, &metadata->original_target.port,
                             sizeof(metadata->original_target.port));
  if (metadata->original_target.kind == FTUN_ADDRESS_IPV4) {
    hash = ftun_udp_hash_bytes(hash, metadata->original_target.address, 4u);
  } else {
    hash = ftun_udp_hash_bytes(hash, metadata->original_target.domain.data,
                               metadata->original_target.domain.length);
  }
  if (metadata->original_is_fake) {
    hash = ftun_udp_hash_bytes(hash, metadata->domain.data,
                               metadata->domain.length);
  }
  return (size_t)(hash % FTUN_UDP_FLOW_BUCKETS);
}

static ftun_udp_flow_t *ftun_udp_flow_find(ftun_udp_flow_table_t *table,
                                           const ftun_metadata_t *metadata,
                                           const ftun_route_result_t *route)
{
  ftun_udp_flow_t *flow;
  size_t bucket = ftun_udp_flow_hash(metadata);
  for (flow = table->buckets[bucket]; flow != NULL; flow = flow->hash_next) {
    if (ftun_udp_flow_key_equal(flow, metadata, route)) return flow;
  }
  return NULL;
}

static void ftun_udp_flow_unlink(ftun_udp_flow_t *flow)
{
  ftun_udp_flow_t **cursor;
  ftun_udp_flow_table_t *table = flow->table;
  size_t bucket = ftun_udp_flow_hash(&flow->metadata);
  for (cursor = &table->buckets[bucket]; *cursor != NULL;
       cursor = &(*cursor)->hash_next) {
    if (*cursor == flow) {
      *cursor = flow->hash_next;
      flow->hash_next = NULL;
      break;
    }
  }
  if (table->reap_cursor == flow) table->reap_cursor = flow->next;
  for (cursor = &table->flows; *cursor != NULL; cursor = &(*cursor)->next) {
    if (*cursor == flow) {
      *cursor = flow->next;
      flow->next = NULL;
      if (table->active != 0u) table->active--;
      return;
    }
  }
}

static ftun_status_t ftun_udp_flow_dispose(ftun_udp_flow_t *flow)
{
  ftun_datagram_t *outbound = flow->outbound;
  ftun_reservation_t *reservation;
  ftun_status_t status;
  if (outbound != NULL) {
    status = ftun_datagram_stop(outbound);
    if (status != FTUN_OK) return status;
    status = ftun_datagram_destroy(&outbound);
    if (status != FTUN_OK) return status;
    flow->outbound = NULL;
  }
  status = ftun_runtime_release(&flow->runtime);
  if (status != FTUN_OK) return status;
  ftun_udp_flow_unlink(flow);
  reservation = flow->reservation;
  flow->reservation = NULL;
  memset(flow, 0, sizeof(*flow));
  free(flow);
  return ftun_reservation_release(&reservation);
}

static void ftun_udp_flow_result(ftun_datagram_t *channel,
                                 ftun_error_t error,
                                 const ftun_endpoint_t *target,
                                 const ftun_packet_t *packet, void *user)
{
  ftun_udp_flow_t *flow = (ftun_udp_flow_t *)user;
  (void)packet;
  if (flow == NULL || channel != flow->outbound ||
      !ftun_udp_endpoint_equal(target, &flow->remote)) {
    if (flow != NULL) {
      flow->failed = true;
      flow->failure_status = FTUN_E_STATE_CORRUPT;
    }
    return;
  }
  if (error.status != FTUN_OK) {
    flow->failed = true;
    flow->failure_status = error.status;
  }
}

static ftun_status_t ftun_udp_flow_receive(
  ftun_datagram_t *channel, const ftun_endpoint_t *source,
  const ftun_packet_t *packet, void *user)
{
  ftun_udp_flow_t *flow = (ftun_udp_flow_t *)user;
  ftun_status_t status;
  if (flow == NULL || channel != flow->outbound || packet == NULL) {
    return FTUN_E_INVALID;
  }
  if (!ftun_udp_endpoint_equal(source, &flow->remote) &&
      !(flow->remote.kind == FTUN_ADDRESS_DOMAIN &&
        source != NULL && source->kind == FTUN_ADDRESS_IPV4 &&
        source->port == flow->remote.port)) {
    ftun_udp_flow_increment(&flow->table->rejected_sources);
    return FTUN_E_REJECTED;
  }
  status = flow->table->backend.reply != NULL
    ? flow->table->backend.reply(flow->table->backend.user, flow->inbound,
                                 &flow->metadata, source, packet)
    : ftun_datagram_send(flow->inbound, &flow->metadata.source,
                         (ftun_packet_t *)packet);
  if (status != FTUN_OK) {
    flow->failed = true;
    flow->failure_status = status;
    return status;
  }
  flow->expires_at = ftun_udp_expiry(flow->table);
  return FTUN_OK;
}

static void ftun_udp_flow_copy_metadata(ftun_udp_flow_t *flow,
                                        const ftun_metadata_t *metadata)
{
  size_t index;
  flow->metadata = *metadata;
  if (metadata->original_target.kind == FTUN_ADDRESS_DOMAIN) {
    memcpy(flow->domain, metadata->original_target.domain.data,
           metadata->original_target.domain.length);
    flow->domain[metadata->original_target.domain.length] = '\0';
    flow->metadata.original_target.domain.data = flow->domain;
  }
  if (metadata->domain.length != 0u) {
    if (metadata->original_target.kind != FTUN_ADDRESS_DOMAIN) {
      memcpy(flow->domain, metadata->domain.data, metadata->domain.length);
      flow->domain[metadata->domain.length] = '\0';
    }
    flow->metadata.domain.data = flow->domain;
  } else {
    flow->metadata.domain.data = NULL;
  }
  for (index = 0u; index < metadata->resolved_count; index++) {
    flow->resolved[index] = metadata->resolved[index];
    flow->resolved[index].domain.data = NULL;
    flow->resolved[index].domain.length = 0u;
  }
  flow->metadata.resolved = metadata->resolved_count == 0u
    ? NULL : flow->resolved;
}

static ftun_status_t ftun_udp_flow_create(
  ftun_udp_flow_table_t *table, ftun_datagram_t *inbound,
  const ftun_metadata_t *metadata, const ftun_route_result_t *route,
  ftun_udp_flow_t **out)
{
  ftun_udp_flow_t *flow;
  ftun_runtime_t *runtime = NULL;
  ftun_reservation_t *reservation = NULL;
  ftun_runtime_info_t runtime_info;
  ftun_budget_t *channel_budget = NULL;
  ftun_datagram_t *outbound = NULL;
  ftun_endpoint_t remote;
  uint32_t outbound_id = 0u;
  ftun_status_t status;
  *out = NULL;
  status = ftun_runtime_active_acquire(table->core, &runtime);
  if (status != FTUN_OK) return status;
  status = ftun_runtime_get_info(runtime, &runtime_info);
  if (status != FTUN_OK || runtime_info.generation != metadata->generation) {
    (void)ftun_runtime_release(&runtime);
    return status != FTUN_OK ? status : FTUN_E_STALE;
  }
  status = ftun_budget_reserve(table->budget, sizeof(*flow), &reservation);
  if (status != FTUN_OK) {
    (void)ftun_runtime_release(&runtime);
    return status;
  }
  flow = (ftun_udp_flow_t *)calloc(1u, sizeof(*flow));
  if (flow == NULL) {
    (void)ftun_reservation_release(&reservation);
    (void)ftun_runtime_release(&runtime);
    return FTUN_E_LIMIT;
  }
  flow->table = table;
  flow->reservation = reservation;
  flow->runtime = runtime;
  flow->inbound = inbound;
  flow->route_pinned = route != NULL;
  flow->route_outbound_id = route == NULL ? 0u : route->outbound_id;
  ftun_udp_flow_copy_metadata(flow, metadata);
  memset(&remote, 0, sizeof(remote));
  status = table->backend.open(table->backend.user, table->core, runtime,
                               &flow->metadata, route, ftun_udp_flow_result,
                               ftun_udp_flow_receive, flow, &outbound_id,
                               &remote, &outbound);
  if (status == FTUN_OK && (outbound == NULL ||
      !ftun_udp_remote_allowed(&flow->metadata, &remote))) {
    status = FTUN_E_STATE_CORRUPT;
  }
  if (status == FTUN_OK) {
    status = ftun_datagram_budget(outbound, &channel_budget);
    if (status == FTUN_OK && channel_budget != table->budget) {
      status = FTUN_E_REJECTED;
    }
  }
  if (status != FTUN_OK) {
    if (outbound != NULL) {
      (void)ftun_datagram_stop(outbound);
      (void)ftun_datagram_destroy(&outbound);
    }
    (void)ftun_runtime_release(&runtime);
    free(flow);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  flow->outbound = outbound;
  flow->outbound_id = outbound_id;
  flow->remote = remote;
  flow->expires_at = ftun_udp_expiry(table);
  flow->next = table->flows;
  table->flows = flow;
  {
    size_t bucket = ftun_udp_flow_hash(&flow->metadata);
    flow->hash_next = table->buckets[bucket];
    table->buckets[bucket] = flow;
  }
  table->active++;
  ftun_udp_flow_increment(&table->created);
  *out = flow;
  return FTUN_OK;
}

static ftun_status_t ftun_udp_flow_reap(ftun_udp_flow_table_t *table,
                                        bool all)
{
  ftun_udp_flow_t *flow = all || table->reap_cursor == NULL
    ? table->flows : table->reap_cursor;
  size_t inspected = 0u;
  while (flow != NULL && (all || inspected < FTUN_UDP_FLOW_REAP_QUOTA)) {
    ftun_udp_flow_t *next = flow->next;
    inspected++;
    table->reap_cursor = next;
    if (all || flow->failed || table->now_ms >= flow->expires_at) {
      bool expired = !flow->failed && table->now_ms >= flow->expires_at;
      bool failed = flow->failed;
      ftun_status_t status = ftun_udp_flow_dispose(flow);
      if (status != FTUN_OK) return status;
      if (expired) ftun_udp_flow_increment(&table->expired);
      if (failed) ftun_udp_flow_increment(&table->failed);
    }
    flow = next;
  }
  if (all) table->reap_cursor = NULL;
  return FTUN_OK;
}

/* TASK-TUN-003 / TEST-TUN-003，目标 0.2.0：有界四元组 UDP flow。 */
ftun_status_t ftun_udp_flow_table_create(
  const ftun_udp_flow_table_spec_t *spec, ftun_udp_flow_table_t **out)
{
  ftun_udp_flow_table_t *table;
  ftun_budget_t *core_budget = NULL;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (spec == NULL || out == NULL || spec->core == NULL ||
      spec->budget == NULL || spec->capacity == 0u ||
      spec->idle_timeout_ms == 0u || spec->backend.open == NULL ||
      ftun_udp_flow_active != NULL) return FTUN_E_INVALID;
  status = ftun_runtime_manager_budget(spec->core, &core_budget);
  if (status != FTUN_OK) return status;
  if (core_budget != spec->budget) return FTUN_E_REJECTED;
  status = ftun_budget_reserve(spec->budget, sizeof(*table), &reservation);
  if (status != FTUN_OK) return status;
  table = (ftun_udp_flow_table_t *)calloc(1u, sizeof(*table));
  if (table == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  table->core = spec->core;
  table->budget = spec->budget;
  table->reservation = reservation;
  table->backend = spec->backend;
  table->capacity = spec->capacity;
  table->idle_timeout_ms = spec->idle_timeout_ms;
  table->now_ms = spec->now_ms;
  table->accepting = true;
  ftun_udp_flow_active = table;
  *out = table;
  return FTUN_OK;
}

ftun_status_t ftun_udp_flow_input_routed(ftun_udp_flow_table_t *table,
                                         ftun_datagram_t *inbound,
                                         const ftun_metadata_t *metadata,
                                         const ftun_route_result_t *route,
                                         ftun_packet_t *packet)
{
  ftun_udp_flow_t *flow;
  ftun_budget_t *inbound_budget = NULL;
  ftun_status_t status;
  ftun_status_t cleanup;
  if (table == NULL || inbound == NULL || packet == NULL ||
      table != ftun_udp_flow_active) return FTUN_E_INVALID;
  status = ftun_udp_metadata_validate(metadata);
  if (status != FTUN_OK) return status;
  /* 旧入口没有预先完成的路由，因此仍需要具体目标。Engine 专用的路由
   * 入口可以为 SOCKS5 UDP 叶子保留域名，且不得擅自附带 IPv4 候选。 */
  if (route == NULL && metadata->resolved_count == 0u &&
      (metadata->original_target.kind == FTUN_ADDRESS_DOMAIN ||
       metadata->original_is_fake)) return FTUN_E_INVALID;
  if (route != NULL && (route->kind != FTUN_ROUTE_READY ||
      route->generation != metadata->generation ||
      (route->allowed_count != 0u && route->allowed == NULL))) {
    return FTUN_E_INVALID;
  }
  if (!table->accepting) return FTUN_E_CANCELLED;
  status = ftun_datagram_budget(inbound, &inbound_budget);
  if (status != FTUN_OK) return status;
  if (inbound_budget != table->budget) return FTUN_E_REJECTED;
  flow = ftun_udp_flow_find(table, metadata, route);
  if (flow != NULL && flow->inbound != inbound) return FTUN_E_REJECTED;
  if (flow == NULL) {
    if (table->active >= table->capacity) return FTUN_E_LIMIT;
    status = ftun_udp_flow_create(table, inbound, metadata, route, &flow);
    if (status != FTUN_OK) return status;
  }
  status = ftun_datagram_send(flow->outbound, &flow->remote, packet);
  if (status == FTUN_OK && !flow->failed) {
    flow->expires_at = ftun_udp_expiry(table);
    return FTUN_OK;
  }
  if (status == FTUN_OK) status = flow->failure_status;
  flow->failed = true;
  flow->failure_status = status;
  cleanup = ftun_udp_flow_dispose(flow);
  ftun_udp_flow_increment(&table->failed);
  return cleanup == FTUN_OK ? status : cleanup;
}

ftun_status_t ftun_udp_flow_input_on(ftun_udp_flow_table_t *table,
                                     ftun_datagram_t *inbound,
                                     const ftun_metadata_t *metadata,
                                     ftun_packet_t *packet)
{
  return ftun_udp_flow_input_routed(table, inbound, metadata, NULL, packet);
}

ftun_status_t ftun_udp_flow_input(ftun_core_t *core,
                                  const ftun_metadata_t *metadata,
                                  ftun_packet_t *packet)
{
  ftun_udp_flow_table_t *table = ftun_udp_flow_active;
  ftun_datagram_t *inbound = NULL;
  ftun_status_t status;
  if (core == NULL || metadata == NULL || packet == NULL) return FTUN_E_INVALID;
  if (table == NULL || table->core != core) return FTUN_E_STALE;
  if (table->backend.inbound == NULL) return FTUN_E_UNSUPPORTED;
  status = table->backend.inbound(table->backend.user, metadata, &inbound);
  if (status != FTUN_OK) return status;
  if (inbound == NULL) return FTUN_E_STATE_CORRUPT;
  return ftun_udp_flow_input_on(table, inbound, metadata, packet);
}

ftun_status_t ftun_udp_flow_tick(ftun_udp_flow_table_t *table,
                                 uint64_t now_ms)
{
  if (table == NULL || table != ftun_udp_flow_active ||
      now_ms < table->now_ms) return FTUN_E_INVALID;
  table->now_ms = now_ms;
  return ftun_udp_flow_reap(table, false);
}

ftun_status_t ftun_udp_flow_fail_outbound(ftun_udp_flow_table_t *table,
                                          ftun_datagram_t *outbound,
                                          ftun_status_t failure)
{
  ftun_udp_flow_t *flow;
  ftun_status_t status;
  if (table == NULL || outbound == NULL || failure == FTUN_OK ||
      table != ftun_udp_flow_active) return FTUN_E_INVALID;
  for (flow = table->flows; flow != NULL; flow = flow->next) {
    if (flow->outbound == outbound) break;
  }
  if (flow == NULL) return FTUN_E_STALE;
  flow->failed = true;
  flow->failure_status = failure;
  status = ftun_udp_flow_dispose(flow);
  if (status == FTUN_OK) ftun_udp_flow_increment(&table->failed);
  return status;
}

ftun_status_t ftun_udp_flow_close_inbound(ftun_udp_flow_table_t *table,
                                          ftun_datagram_t *inbound)
{
  ftun_udp_flow_t *flow;
  if (table == NULL || inbound == NULL || table != ftun_udp_flow_active) {
    return FTUN_E_INVALID;
  }
  flow = table->flows;
  while (flow != NULL) {
    ftun_udp_flow_t *next = flow->next;
    if (flow->inbound == inbound) {
      ftun_status_t status = ftun_udp_flow_dispose(flow);
      if (status != FTUN_OK) return status;
    }
    flow = next;
  }
  return FTUN_OK;
}

ftun_status_t ftun_udp_flow_get_usage(const ftun_udp_flow_table_t *table,
                                      ftun_udp_flow_usage_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (table == NULL || out == NULL || table != ftun_udp_flow_active) {
    return FTUN_E_INVALID;
  }
  out->capacity = table->capacity;
  out->active = table->active;
  out->created = table->created;
  out->expired = table->expired;
  out->failed = table->failed;
  out->rejected_sources = table->rejected_sources;
  out->now_ms = table->now_ms;
  out->accepting = table->accepting;
  return FTUN_OK;
}

ftun_status_t ftun_udp_flow_table_destroy(ftun_udp_flow_table_t **table)
{
  ftun_udp_flow_table_t *owned;
  ftun_reservation_t *reservation;
  ftun_status_t status;
  if (table == NULL) return FTUN_E_INVALID;
  owned = *table;
  if (owned == NULL) return FTUN_OK;
  if (owned != ftun_udp_flow_active) return FTUN_E_STALE;
  owned->accepting = false;
  status = ftun_udp_flow_reap(owned, true);
  if (status != FTUN_OK) return status;
  reservation = owned->reservation;
  owned->reservation = NULL;
  ftun_udp_flow_active = NULL;
  *table = NULL;
  memset(owned, 0, sizeof(*owned));
  free(owned);
  return ftun_reservation_release(&reservation);
}
