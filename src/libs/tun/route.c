#include "libs/tun/internal.h"

#include <assert.h>
#include <string.h>

uint32_t ftun_tun_service_ipv4_value(const uint8_t address[4])
{
  return ((uint32_t)address[0] << 24u) | ((uint32_t)address[1] << 16u) |
         ((uint32_t)address[2] << 8u) | (uint32_t)address[3];
}

static int ftun_tun_service_route_valid(const ftun_tun_route_t *route)
{
  uint32_t address;
  uint32_t mask;
  if (route == NULL) return 0;
  if (route->kind == FTUN_TUN_ROUTE_DEFAULT) {
    return route->prefix_length == 0u && route->network[0] == 0u &&
           route->network[1] == 0u && route->network[2] == 0u &&
           route->network[3] == 0u;
  }
  if (route->kind != FTUN_TUN_ROUTE_IPV4_PREFIX ||
      route->prefix_length > 32u) return 0;
  address = ftun_tun_service_ipv4_value(route->network);
  mask = route->prefix_length == 0u
    ? 0u : UINT32_MAX << (32u - route->prefix_length);
  return (address & mask) == address;
}

static int ftun_tun_service_route_equal(const ftun_tun_route_t *left,
                                        const ftun_tun_route_t *right)
{
  if (left->kind != right->kind || left->priority != right->priority) return 0;
  if (left->kind == FTUN_TUN_ROUTE_DEFAULT) return 1;
  return left->prefix_length == right->prefix_length &&
         memcmp(left->network, right->network, 4u) == 0;
}

ftun_status_t ftun_tun_service_acquire(
  ftun_tun_service_t *service, const ftun_tun_consumer_t *consumer,
  ftun_tun_lease_t *out)
{
  ftun_tun_consumer_spec_t spec;
  if (consumer == NULL) {
    if (out != NULL) memset(out, 0, sizeof(*out));
    return FTUN_E_INVALID;
  }
  if (service != NULL && service->consumer_capacity == 1u &&
      service->active_leases != 0u) {
    if (out != NULL) memset(out, 0, sizeof(*out));
    return FTUN_E_AGAIN;
  }
  memset(&spec, 0, sizeof(spec));
  spec.consumer = *consumer;
  spec.route.kind = FTUN_TUN_ROUTE_DEFAULT;
  spec.route.priority = UINT16_MAX;
  return ftun_tun_service_acquire_routed(service, &spec, out);
}

ftun_status_t ftun_tun_service_acquire_routed(
  ftun_tun_service_t *service, const ftun_tun_consumer_spec_t *spec,
  ftun_tun_lease_t *out)
{
  ftun_tun_service_consumer_t *available = NULL;
  uint32_t inner_mtu;
  size_t index;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (service == NULL || spec == NULL || spec->consumer.packet == NULL ||
      out == NULL || !ftun_tun_service_route_valid(&spec->route) ||
      !ftun_tun_service_path_valid(service, &spec->route, &spec->path,
                                   &inner_mtu)) {
    return FTUN_E_INVALID;
  }
  if (service->callback_depth != 0u) return FTUN_E_AGAIN;
  if (!service->accepting) return FTUN_E_CANCELLED;
  for (index = 0u; index < service->consumer_capacity; index++) {
    ftun_tun_service_consumer_t *consumer = &service->consumers[index];
    if (consumer->lease.service == service) {
      if (ftun_tun_service_route_equal(&consumer->route, &spec->route)) {
        return FTUN_E_REJECTED;
      }
    } else if (available == NULL) {
      available = consumer;
    }
  }
  if (available == NULL) return FTUN_E_LIMIT;
  if (service->next_lease_generation == UINT64_MAX) return FTUN_E_LIMIT;
  service->next_lease_generation++;
  available->consumer = spec->consumer;
  available->route = spec->route;
  available->path = spec->path;
  available->path_generation = 1u;
  available->inner_mtu = inner_mtu;
  available->feedback_tokens = spec->path.carrier_mtu == 0u
    ? 0u : FTUN_TUN_FEEDBACK_BURST;
  available->packets_received = 0u;
  available->packets_written = 0u;
  available->packets_dropped = 0u;
  available->malformed_packets = 0u;
  available->oversized_packets = 0u;
  available->fragments_rejected = 0u;
  available->sources_rejected = 0u;
  available->feedback_sent = 0u;
  available->feedback_suppressed = 0u;
  available->feedback_progress = 0u;
  available->lease.service = service;
  available->lease.generation = service->next_lease_generation;
  service->active_leases++;
  status = ftun_tun_service_interests(service);
  if (status != FTUN_OK) {
    service->active_leases--;
    memset(&available->consumer, 0, sizeof(available->consumer));
    memset(&available->route, 0, sizeof(available->route));
    memset(&available->path, 0, sizeof(available->path));
    memset(&available->lease, 0, sizeof(available->lease));
    available->path_generation = 0u;
    available->inner_mtu = 0u;
    available->feedback_tokens = 0u;
    return status;
  }
  *out = available->lease;
  return FTUN_OK;
}

ftun_status_t ftun_tun_service_update_consumer(
  ftun_tun_lease_t lease, uint64_t expected_path_generation,
  const ftun_tun_route_t *route, const ftun_tun_path_t *path)
{
  ftun_tun_service_t *service = lease.service;
  ftun_tun_service_consumer_t *consumer =
    ftun_tun_service_lease_consumer(service, lease);
  ftun_tun_route_t next_route;
  ftun_tun_path_t next_path;
  uint32_t inner_mtu;
  uint32_t interests = FTUN_EVENT_ERROR | FTUN_EVENT_READ;
  size_t index;
  ftun_status_t status;
  if (consumer == NULL) return FTUN_E_STALE;
  if (service->callback_depth != 0u) return FTUN_E_AGAIN;
  if (expected_path_generation != consumer->path_generation) return FTUN_E_STALE;
  if (!ftun_tun_service_route_valid(route) ||
      !ftun_tun_service_path_valid(service, route, path, &inner_mtu)) {
    return FTUN_E_INVALID;
  }
  if (!service->accepting) return FTUN_E_CANCELLED;
  if (ftun_tun_service_route_equal(&consumer->route, route) &&
      ftun_tun_service_path_equal(&consumer->path, path)) return FTUN_OK;
  if (consumer->path_generation == UINT64_MAX) return FTUN_E_LIMIT;
  for (index = 0u; index < service->consumer_capacity; index++) {
    ftun_tun_service_consumer_t *other = &service->consumers[index];
    if (other != consumer && other->lease.service == service &&
        ftun_tun_service_route_equal(&other->route, route)) return FTUN_E_REJECTED;
  }
  if (service->queued_outputs < consumer->output_count) return FTUN_E_STATE_CORRUPT;
  if (service->queued_outputs != consumer->output_count) interests |= FTUN_EVENT_WRITE;
  /* watcher 拒绝发生在清队列及发布之前，失败时原路由仍完整可用。 */
  status = ftun_event_io_update(service->source, interests);
  if (status != FTUN_OK) return status;
  next_route = *route;
  next_path = *path;
  ftun_tun_service_consumer_clear(service, consumer);
  consumer->route = next_route;
  consumer->path = next_path;
  consumer->inner_mtu = inner_mtu;
  consumer->path_generation++;
  consumer->feedback_tokens = path->carrier_mtu == 0u
    ? 0u : FTUN_TUN_FEEDBACK_BURST;
  consumer->feedback_progress = 0u;
  if (consumer->consumer.event != NULL) {
    service->callback_depth++;
    consumer->consumer.event(consumer->consumer.user, lease,
                              FTUN_TUN_SERVICE_PATH_UPDATED, FTUN_OK);
    service->callback_depth--;
  }
  return FTUN_OK;
}

ftun_status_t ftun_tun_service_release(ftun_tun_lease_t *lease)
{
  ftun_tun_service_t *service;
  ftun_tun_service_consumer_t *consumer;
  if (lease == NULL) return FTUN_E_INVALID;
  if (lease->service == NULL) return FTUN_OK;
  service = lease->service;
  consumer = ftun_tun_service_lease_consumer(service, *lease);
  if (consumer == NULL) return FTUN_E_STALE;
  ftun_tun_service_consumer_clear(service, consumer);
  memset(&consumer->consumer, 0, sizeof(consumer->consumer));
  memset(&consumer->route, 0, sizeof(consumer->route));
  memset(&consumer->path, 0, sizeof(consumer->path));
  memset(&consumer->lease, 0, sizeof(consumer->lease));
  consumer->path_generation = 0u;
  consumer->inner_mtu = 0u;
  consumer->feedback_tokens = 0u;
  consumer->feedback_progress = 0u;
  memset(lease, 0, sizeof(*lease));
  assert(service->active_leases != 0u);
  service->active_leases--;
  return service->source != NULL ? ftun_tun_service_interests(service) : FTUN_OK;
}

ftun_tun_service_consumer_t *ftun_tun_service_route(
  ftun_tun_service_t *service, ftun_bytes_t packet)
{
  ftun_tun_service_consumer_t *prefix_match = NULL;
  ftun_tun_service_consumer_t *default_match = NULL;
  uint32_t destination = 0u;
  bool ipv4 = false;
  size_t index;
  if (packet.length >= 20u && (packet.data[0] >> 4u) == 4u) {
    size_t header_length = (size_t)(packet.data[0] & 0x0fu) * 4u;
    size_t total_length = ((size_t)packet.data[2] << 8u) | packet.data[3];
    if (header_length >= 20u && header_length <= packet.length &&
        total_length >= header_length && total_length <= packet.length) {
      destination = ftun_tun_service_ipv4_value(packet.data + 16u);
      ipv4 = true;
    }
  }
  for (index = 0u; index < service->consumer_capacity; index++) {
    ftun_tun_service_consumer_t *consumer = &service->consumers[index];
    if (consumer->lease.service != service) continue;
    if (consumer->route.kind == FTUN_TUN_ROUTE_DEFAULT) {
      if (default_match == NULL ||
          consumer->route.priority < default_match->route.priority) {
        default_match = consumer;
      }
    } else if (ipv4) {
      uint32_t network = ftun_tun_service_ipv4_value(consumer->route.network);
      uint32_t mask = consumer->route.prefix_length == 0u
        ? 0u : UINT32_MAX << (32u - consumer->route.prefix_length);
      if ((destination & mask) != network) continue;
      if (prefix_match == NULL ||
          consumer->route.prefix_length > prefix_match->route.prefix_length ||
          (consumer->route.prefix_length == prefix_match->route.prefix_length &&
           consumer->route.priority < prefix_match->route.priority)) {
        prefix_match = consumer;
      }
    }
  }
  return prefix_match != NULL ? prefix_match : default_match;
}
