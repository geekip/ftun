#ifndef FTUN_UTIL_ENDPOINT_H
#define FTUN_UTIL_ENDPOINT_H
#include "util/types.h"
#include "util/ip.h"
#include <string.h>

static inline bool ftun_endpoint_is_ip(const ftun_endpoint_t *endpoint)
{
  return endpoint->kind == FTUN_ADDRESS_IPV4 || endpoint->kind == FTUN_ADDRESS_IPV6;
}
static inline size_t ftun_endpoint_address_bytes(const ftun_endpoint_t *endpoint)
{
  return endpoint->kind == FTUN_ADDRESS_IPV6 ? 16u : 4u;
}
static inline bool ftun_endpoint_equal(const ftun_endpoint_t *left, const ftun_endpoint_t *right)
{
  if (left->kind != right->kind || left->port != right->port) return false;
  if (ftun_endpoint_is_ip(left)) return memcmp(left->address, right->address,
    ftun_endpoint_address_bytes(left)) == 0;
  return left->kind == FTUN_ADDRESS_DOMAIN && left->domain.length == right->domain.length &&
    memcmp(left->domain.data, right->domain.data, left->domain.length) == 0;
}
static inline void ftun_endpoint_set_ip(ftun_endpoint_t *out, const ftun_ip_t *ip, uint16_t port)
{
  memset(out, 0, sizeof(*out));
  out->kind = ip->family == FTUN_IP_V6 ? FTUN_ADDRESS_IPV6 : FTUN_ADDRESS_IPV4;
  memcpy(out->address, ip->bytes, ip->family == FTUN_IP_V6 ? 16u : 4u);
  out->port = port;
}
static inline ftun_ip_t ftun_endpoint_ip(const ftun_endpoint_t *endpoint)
{
  ftun_ip_t result = {0};
  result.family = endpoint->kind == FTUN_ADDRESS_IPV6 ? FTUN_IP_V6 : FTUN_IP_V4;
  memcpy(result.bytes, endpoint->address, ftun_endpoint_address_bytes(endpoint));
  return result;
}
#endif
