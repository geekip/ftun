#include "libs/tun/internal.h"

#include <string.h>

static uint16_t ftun_tun_service_checksum(const uint8_t *data, size_t length)
{
  uint32_t sum = 0u;
  while (length >= 2u) {
    sum += ((uint32_t)data[0] << 8u) | data[1];
    data += 2u;
    length -= 2u;
  }
  if (length != 0u) sum += (uint32_t)data[0] << 8u;
  while ((sum >> 16u) != 0u) sum = (sum & UINT16_MAX) + (sum >> 16u);
  return (uint16_t)~sum;
}

static int ftun_tun_service_ip_parse(ftun_bytes_t packet,
                                       ftun_tun_ip_t *out)
{
  size_t header_length;
  size_t total_length;
  uint16_t fragment;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (packet.data != NULL && out != NULL && packet.length >= 40u && (packet.data[0] >> 4u) == 6u) {
    size_t cursor = 40u;
    uint8_t protocol = packet.data[6];
    if (40u + ((size_t)packet.data[4] << 8u) + packet.data[5] != packet.length) return 0;
    while (protocol == 0u || protocol == 43u || protocol == 60u || protocol == 44u || protocol == 51u) {
      size_t length;
      if (cursor + 8u > packet.length) return 0;
      if (protocol == 44u) { length = 8u; out->fragmented = true; }
      else length = protocol == 51u ? ((size_t)packet.data[cursor + 1u] + 2u) * 4u :
        ((size_t)packet.data[cursor + 1u] + 1u) * 8u;
      if (length > packet.length - cursor) return 0;
      protocol = packet.data[cursor];
      cursor += length;
    }
    out->header_length = cursor;
    out->protocol = protocol;
    out->dont_fragment = true;
    out->source.family = out->destination.family = FTUN_IP_V6;
    memcpy(out->source.bytes, packet.data + 8u, 16u);
    memcpy(out->destination.bytes, packet.data + 24u, 16u);
    return 1;
  }
  if (packet.data == NULL || out == NULL || packet.length < 20u ||
      packet.length > UINT16_MAX || (packet.data[0] >> 4u) != 4u) return 0;
  header_length = (size_t)(packet.data[0] & 0x0fu) * 4u;
  total_length = ((size_t)packet.data[2] << 8u) | packet.data[3];
  fragment = (uint16_t)(((uint16_t)packet.data[6] << 8u) | packet.data[7]);
  if (header_length < 20u || header_length > 60u ||
      header_length > packet.length || total_length != packet.length ||
      total_length < header_length || (fragment & UINT16_C(0x8000)) != 0u ||
      ftun_tun_service_checksum(packet.data, header_length) != 0u) return 0;
  out->header_length = header_length;
  out->fragment = fragment;
  out->protocol = packet.data[9];
  out->source.family = out->destination.family = FTUN_IP_V4;
  memcpy(out->source.bytes, packet.data + 12u, 4u);
  memcpy(out->destination.bytes, packet.data + 16u, 4u);
  out->dont_fragment = (fragment & UINT16_C(0x4000)) != 0u;
  out->fragmented = (fragment & UINT16_C(0x3fff)) != 0u;
  if (out->dont_fragment && out->fragmented) return 0;
  return 1;
}

int ftun_tun_service_path_valid(
  const ftun_tun_service_t *service, const ftun_tun_route_t *route,
  const ftun_tun_path_t *path, uint32_t *inner_mtu)
{
  uint32_t effective;
  uint16_t allowed = FTUN_TUN_PATH_ALLOW_IPV4_FRAGMENTS |
    FTUN_TUN_PATH_VALIDATE_OUTPUT_SOURCE;
  if (inner_mtu != NULL) *inner_mtu = 0u;
  if (service == NULL || route == NULL || path == NULL || inner_mtu == NULL ||
      (path->flags & (uint16_t)~allowed) != 0u) return 0;
  if (path->carrier_mtu == 0u) {
    if (path->headroom != 0u || path->flags != 0u) return 0;
    *inner_mtu = service->mtu;
    return 1;
  }
  if (path->carrier_mtu > UINT16_MAX ||
      path->carrier_mtu <= (uint32_t)path->headroom) return 0;
  effective = path->carrier_mtu - (uint32_t)path->headroom;
  if (effective > service->mtu) effective = service->mtu;
  if (effective < (route->kind == FTUN_TUN_ROUTE_PREFIX && route->prefix.address.family == FTUN_IP_V6 ? 1280u : FTUN_TUN_IPV4_MIN_MTU)) return 0;
  if ((path->flags & FTUN_TUN_PATH_VALIDATE_OUTPUT_SOURCE) != 0u &&
      (route->kind != FTUN_TUN_ROUTE_PREFIX ||
       route->prefix.prefix == 0u)) return 0;
  *inner_mtu = effective;
  return 1;
}

int ftun_tun_service_path_equal(const ftun_tun_path_t *left,
                                const ftun_tun_path_t *right)
{
  return left->carrier_mtu == right->carrier_mtu &&
         left->headroom == right->headroom && left->flags == right->flags;
}

static int ftun_tun_service_prefix_contains(const ftun_tun_route_t *route, const ftun_ip_t *address)
{
  return route->kind == FTUN_TUN_ROUTE_PREFIX && ftun_cidr_contains(&route->prefix, address);
}

static int ftun_tun_service_unicast(const uint8_t address[4])
{
  uint32_t value = ftun_tun_service_ipv4_value(address);
  return value != 0u && value != UINT32_MAX && address[0] != 127u &&
         address[0] < 224u;
}

static int ftun_tun_service_icmp_error(const ftun_tun_ip_t *ipv4,
                                       ftun_bytes_t packet)
{
  uint8_t type;
  if (ipv4->protocol != 1u || ipv4->header_length >= packet.length) return 0;
  type = packet.data[ipv4->header_length];
  return type == 3u || type == 4u || type == 5u || type == 11u || type == 12u;
}

static int ftun_tun_service_send_feedback6(ftun_tun_service_t *service,
  ftun_tun_service_consumer_t *consumer, ftun_bytes_t packet, const ftun_tun_ip_t *ip)
{
  uint8_t response[1280] = {0};
  size_t quote, length;
  uint32_t sum = 0u;
  uint16_t checksum;
  static const uint8_t zero[16] = {0};
  (void)service;
  if (ip->source.bytes[0] == 0xffu || ip->destination.bytes[0] == 0xffu ||
      memcmp(ip->source.bytes, zero, 16u) == 0 ||
      (ip->protocol == 58u && ip->header_length < packet.length && packet.data[ip->header_length] < 128u) ||
      consumer->feedback_tokens == 0u || consumer->inner_mtu < 1280u) return 0;
  quote = packet.length < 1232u ? packet.length : 1232u;
  length = 48u + quote;
  response[0] = 0x60u;
  response[4] = (uint8_t)((length - 40u) >> 8u);
  response[5] = (uint8_t)(length - 40u);
  response[6] = 58u;
  response[7] = 64u;
  memcpy(response + 8u, ip->destination.bytes, 16u);
  memcpy(response + 24u, ip->source.bytes, 16u);
  response[40] = 2u;
  response[44] = (uint8_t)(consumer->inner_mtu >> 24u);
  response[45] = (uint8_t)(consumer->inner_mtu >> 16u);
  response[46] = (uint8_t)(consumer->inner_mtu >> 8u);
  response[47] = (uint8_t)consumer->inner_mtu;
  memcpy(response + 48u, packet.data, quote);
  for (size_t i = 8u; i < 40u; i += 2u) sum += ((uint32_t)response[i] << 8u) | response[i + 1u];
  sum += (uint32_t)(length - 40u) + 58u;
  sum += (uint16_t)~ftun_tun_service_checksum(response + 40u, length - 40u);
  while (sum >> 16u) sum = (sum & UINT16_MAX) + (sum >> 16u);
  checksum = (uint16_t)~sum;
  response[42] = (uint8_t)(checksum >> 8u);
  response[43] = (uint8_t)checksum;
  consumer->feedback_tokens--;
  return ftun_tun_service_write(consumer->lease, (ftun_bytes_t){response, length}) == FTUN_OK;
}

static int ftun_tun_service_send_feedback(
  ftun_tun_service_t *service, ftun_tun_service_consumer_t *consumer,
  ftun_bytes_t packet, const ftun_tun_ip_t *ipv4)
{
  if (ipv4->source.family == FTUN_IP_V6) return ftun_tun_service_send_feedback6(service, consumer, packet, ipv4);
  uint8_t response[96];
  size_t quote_length;
  size_t response_length;
  uint16_t checksum;
  ftun_status_t status;
  if (!ipv4->dont_fragment || ipv4->fragmented ||
      !ftun_tun_service_unicast(ipv4->source.bytes) ||
      !ftun_tun_service_unicast(ipv4->destination.bytes) ||
      ftun_tun_service_icmp_error(ipv4, packet)) return 0;
  quote_length = ipv4->header_length + 8u;
  if (quote_length > packet.length) quote_length = packet.length;
  response_length = 28u + quote_length;
  if (response_length > consumer->inner_mtu ||
      consumer->feedback_tokens == 0u) return 0;
  consumer->feedback_tokens--;
  memset(response, 0, response_length);
  response[0] = 0x45u;
  response[2] = (uint8_t)(response_length >> 8u);
  response[3] = (uint8_t)response_length;
  response[8] = 64u;
  response[9] = 1u;
  memcpy(response + 12u, ipv4->destination.bytes, 4u);
  memcpy(response + 16u, ipv4->source.bytes, 4u);
  checksum = ftun_tun_service_checksum(response, 20u);
  response[10] = (uint8_t)(checksum >> 8u);
  response[11] = (uint8_t)checksum;
  response[20] = 3u;
  response[21] = 4u;
  response[26] = (uint8_t)(consumer->inner_mtu >> 8u);
  response[27] = (uint8_t)consumer->inner_mtu;
  memcpy(response + 28u, packet.data, quote_length);
  checksum = ftun_tun_service_checksum(response + 20u, response_length - 20u);
  response[22] = (uint8_t)(checksum >> 8u);
  response[23] = (uint8_t)checksum;
  status = ftun_tun_service_write(
    consumer->lease, (ftun_bytes_t){response, response_length});
  (void)service;
  return status == FTUN_OK;
}

static void ftun_tun_service_report_packet_error(
  ftun_tun_service_t *service, ftun_tun_service_consumer_t *consumer,
  ftun_tun_packet_direction_t direction,
  ftun_tun_packet_error_reason_t reason, ftun_bytes_t packet,
  const ftun_tun_ip_t *ipv4)
{
  ftun_tun_packet_error_t error;
  ftun_tun_lease_t lease = consumer->lease;
  ftun_tun_service_packet_error_fn callback = consumer->consumer.packet_error;
  void *user = consumer->consumer.user;
  memset(&error, 0, sizeof(error));
  error.direction = direction;
  error.reason = reason;
  error.packet_length = packet.length;
  error.inner_mtu = consumer->inner_mtu;
  error.headroom = consumer->path.headroom;
  if (ipv4 != NULL) {
    error.source = ipv4->source;
    error.destination = ipv4->destination;
    error.dont_fragment = ipv4->dont_fragment;
    error.fragmented = ipv4->fragmented;
  }
  ftun_tun_service_drop(service, consumer);
  ftun_tun_service_increment(&service->packet_errors);
  if (reason == FTUN_TUN_PACKET_MALFORMED) {
    ftun_tun_service_increment(&consumer->malformed_packets);
  } else if (reason == FTUN_TUN_PACKET_TOO_BIG) {
    ftun_tun_service_increment(&consumer->oversized_packets);
    if (direction == FTUN_TUN_PACKET_FROM_DEVICE && ipv4 != NULL) {
      error.feedback_sent = ftun_tun_service_send_feedback(
        service, consumer, packet, ipv4) != 0;
      if (error.feedback_sent) {
        ftun_tun_service_increment(&consumer->feedback_sent);
        ftun_tun_service_increment(&service->feedback_sent);
      } else {
        ftun_tun_service_increment(&consumer->feedback_suppressed);
        ftun_tun_service_increment(&service->feedback_suppressed);
      }
    }
  } else if (reason == FTUN_TUN_PACKET_FRAGMENT_UNSUPPORTED) {
    ftun_tun_service_increment(&consumer->fragments_rejected);
  } else if (reason == FTUN_TUN_PACKET_SOURCE_REJECTED) {
    ftun_tun_service_increment(&consumer->sources_rejected);
  }
  if (callback != NULL && ftun_tun_service_lease_consumer(service, lease) != NULL) {
    service->callback_depth++;
    callback(user, lease, &error);
    service->callback_depth--;
  }
}

ftun_status_t ftun_tun_service_check_packet(
  ftun_tun_service_t *service, ftun_tun_service_consumer_t *consumer,
  ftun_tun_packet_direction_t direction, ftun_bytes_t packet, bool *drop)
{
  ftun_tun_ip_t ipv4;
  ftun_tun_packet_error_reason_t reason;
  if (drop != NULL) *drop = false;
  if (service == NULL || consumer == NULL || drop == NULL) return FTUN_E_INVALID;
  if (consumer->path.carrier_mtu == 0u) return FTUN_OK;
  if (!ftun_tun_service_ip_parse(packet, &ipv4)) {
    reason = FTUN_TUN_PACKET_MALFORMED;
  } else if (packet.length > consumer->inner_mtu) {
    reason = FTUN_TUN_PACKET_TOO_BIG;
  } else if (ipv4.source.family == FTUN_IP_V4 && ipv4.fragmented &&
             (consumer->path.flags &
              FTUN_TUN_PATH_ALLOW_IPV4_FRAGMENTS) == 0u) {
    reason = FTUN_TUN_PACKET_FRAGMENT_UNSUPPORTED;
  } else if (direction == FTUN_TUN_PACKET_TO_DEVICE &&
             (consumer->path.flags &
              FTUN_TUN_PATH_VALIDATE_OUTPUT_SOURCE) != 0u &&
             !ftun_tun_service_prefix_contains(&consumer->route,
                                               &ipv4.source)) {
    reason = FTUN_TUN_PACKET_SOURCE_REJECTED;
  } else {
    return FTUN_OK;
  }
  ftun_tun_service_report_packet_error(
    service, consumer, direction, reason, packet,
    reason == FTUN_TUN_PACKET_MALFORMED ? NULL : &ipv4);
  *drop = true;
  if (direction == FTUN_TUN_PACKET_FROM_DEVICE) return FTUN_OK;
  if (reason == FTUN_TUN_PACKET_MALFORMED) return FTUN_E_PROTOCOL;
  if (reason == FTUN_TUN_PACKET_TOO_BIG) return FTUN_E_LIMIT;
  if (reason == FTUN_TUN_PACKET_FRAGMENT_UNSUPPORTED) {
    return FTUN_E_UNSUPPORTED;
  }
  return FTUN_E_REJECTED;
}

void ftun_tun_service_packet_progress(
  ftun_tun_service_consumer_t *consumer)
{
  if (consumer->path.carrier_mtu == 0u ||
      consumer->feedback_tokens >= FTUN_TUN_FEEDBACK_BURST) return;
  consumer->feedback_progress++;
  if (consumer->feedback_progress >= FTUN_TUN_FEEDBACK_PROGRESS) {
    consumer->feedback_progress = 0u;
    consumer->feedback_tokens++;
  }
}

ftun_status_t ftun_tun_service_update_path(
  ftun_tun_lease_t lease, const ftun_tun_path_t *path)
{
  ftun_tun_service_t *service = lease.service;
  ftun_tun_service_consumer_t *consumer =
    ftun_tun_service_lease_consumer(service, lease);
  if (consumer == NULL) return FTUN_E_STALE;
  return ftun_tun_service_update_consumer(
    lease, consumer->path_generation, &consumer->route, path);
}
