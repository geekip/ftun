#include "target.h"

#include <string.h>

static ftun_status_t ftun_target_domain_validate(ftun_string_t domain)
{
  if (domain.data == NULL || domain.length == 0u || domain.length > 253u ||
      memchr(domain.data, '\0', domain.length) != NULL) return FTUN_E_INVALID;
  return FTUN_OK;
}

static ftun_status_t ftun_target_endpoint_validate(
  const ftun_endpoint_t *endpoint)
{
  if (endpoint == NULL || endpoint->port == 0u) return FTUN_E_INVALID;
  if (endpoint->kind == FTUN_ADDRESS_IPV6_RESERVED) return FTUN_E_UNSUPPORTED;
  if (endpoint->kind == FTUN_ADDRESS_IPV4) {
    return endpoint->domain.length == 0u ? FTUN_OK : FTUN_E_INVALID;
  }
  if (endpoint->kind != FTUN_ADDRESS_DOMAIN) return FTUN_E_INVALID;
  return ftun_target_domain_validate(endpoint->domain);
}

static int ftun_target_string_equal(ftun_string_t left, ftun_string_t right)
{
  return left.length == right.length && left.data != NULL && right.data != NULL &&
         memcmp(left.data, right.data, left.length) == 0;
}

static int ftun_target_endpoint_equal(const ftun_endpoint_t *left,
                                      const ftun_endpoint_t *right)
{
  if (left->kind != right->kind || left->port != right->port) return 0;
  if (left->kind == FTUN_ADDRESS_IPV4) {
    return memcmp(left->address, right->address, 4u) == 0;
  }
  if (left->kind == FTUN_ADDRESS_DOMAIN) {
    return ftun_target_string_equal(left->domain, right->domain);
  }
  return 0;
}

static int ftun_target_contains(const ftun_endpoint_t *items, size_t count,
                                const ftun_endpoint_t *endpoint)
{
  size_t index;
  for (index = 0u; index < count; index++) {
    if (ftun_target_endpoint_equal(&items[index], endpoint)) return 1;
  }
  return 0;
}

static int ftun_target_valid(const ftun_target_t *target)
{
  return target != NULL && target->generation != 0u &&
         ftun_target_endpoint_validate(&target->original) == FTUN_OK &&
         (target->candidate_count == 0u || target->candidates != NULL) &&
         (target->allowed_count == 0u || target->allowed != NULL) &&
         target->allowed_count <= target->candidate_count;
}

/* TASK-ROUTE-003 / TEST-ROUTE-003，目标 0.2.0：身份、候选和拨号地址分离。 */
ftun_status_t ftun_target_from_metadata(const ftun_metadata_t *metadata,
                                        ftun_target_t *out)
{
  const uint32_t known = FTUN_META_SOURCE | FTUN_META_PORT |
                         FTUN_META_NETWORK | FTUN_META_DOMAIN;
  ftun_status_t status;
  size_t index;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (metadata == NULL || out == NULL || metadata->generation == 0u ||
      (metadata->known_fields & ~known) != 0u ||
      (metadata->known_fields & FTUN_META_PORT) == 0u) return FTUN_E_INVALID;
  status = ftun_target_endpoint_validate(&metadata->original_target);
  if (status != FTUN_OK) return status;
  if (metadata->resolved_count != 0u && metadata->resolved == NULL) {
    return FTUN_E_INVALID;
  }
  for (index = 0u; index < metadata->resolved_count; index++) {
    status = ftun_target_endpoint_validate(&metadata->resolved[index]);
    if (status != FTUN_OK) return status;
    if (metadata->resolved[index].kind != FTUN_ADDRESS_IPV4 ||
        metadata->resolved[index].port != metadata->original_target.port) {
      return FTUN_E_INVALID;
    }
  }
  if ((metadata->known_fields & FTUN_META_DOMAIN) != 0u) {
    status = ftun_target_domain_validate(metadata->domain);
    if (status != FTUN_OK || metadata->domain_source == FTUN_DOMAIN_NONE) {
      return FTUN_E_INVALID;
    }
  } else if (metadata->domain.length != 0u ||
             metadata->domain_source != FTUN_DOMAIN_NONE) {
    return FTUN_E_INVALID;
  }
  if (metadata->original_target.kind == FTUN_ADDRESS_DOMAIN) {
    if (metadata->original_is_fake) return FTUN_E_INVALID;
    if ((metadata->known_fields & FTUN_META_DOMAIN) != 0u &&
        !ftun_target_string_equal(metadata->original_target.domain,
                                  metadata->domain)) return FTUN_E_INVALID;
  }
  if (metadata->original_is_fake &&
      (metadata->original_target.kind != FTUN_ADDRESS_IPV4 ||
       (metadata->known_fields & FTUN_META_DOMAIN) == 0u ||
       metadata->domain_source != FTUN_DOMAIN_FAKEIP)) return FTUN_E_INVALID;

  out->generation = metadata->generation;
  out->original = metadata->original_target;
  out->original_is_fake = metadata->original_is_fake;
  if ((metadata->known_fields & FTUN_META_DOMAIN) != 0u) {
    out->identity = metadata->domain;
    out->identity_source = metadata->domain_source;
  } else if (metadata->original_target.kind == FTUN_ADDRESS_DOMAIN) {
    out->identity = metadata->original_target.domain;
    out->identity_source = FTUN_DOMAIN_EXPLICIT;
  }
  if (metadata->original_target.kind == FTUN_ADDRESS_IPV4 &&
      !metadata->original_is_fake) {
    /* 原始真实 IP 不因嗅探或额外解析结果被替换。 */
    out->candidates = &metadata->original_target;
    out->candidate_count = 1u;
  } else {
    out->candidates = metadata->resolved;
    out->candidate_count = metadata->resolved_count;
  }
  out->allowed = out->candidates;
  out->allowed_count = out->candidate_count;
  return FTUN_OK;
}

ftun_status_t ftun_target_apply_route(ftun_target_t *target,
                                      const ftun_route_result_t *route)
{
  size_t index;
  size_t previous;
  if (!ftun_target_valid(target) || route == NULL ||
      (route->allowed_count != 0u && route->allowed == NULL)) {
    return FTUN_E_INVALID;
  }
  if (route->generation != target->generation) return FTUN_E_STALE;
  if (route->kind != FTUN_ROUTE_READY) return FTUN_E_INVALID;
  if (route->allowed_count > target->allowed_count) return FTUN_E_REJECTED;
  for (index = 0u; index < route->allowed_count; index++) {
    ftun_status_t status = ftun_target_endpoint_validate(&route->allowed[index]);
    if (status != FTUN_OK) return status;
    if (!ftun_target_contains(target->allowed, target->allowed_count,
                              &route->allowed[index])) return FTUN_E_REJECTED;
    for (previous = 0u; previous < index; previous++) {
      if (ftun_target_endpoint_equal(&route->allowed[previous],
                                     &route->allowed[index])) {
        return FTUN_E_INVALID;
      }
    }
  }
  target->allowed = route->allowed_count == 0u ? NULL : route->allowed;
  target->allowed_count = route->allowed_count;
  if (target->dial_selected &&
      !ftun_target_contains(target->allowed, target->allowed_count,
                            &target->dial)) {
    memset(&target->dial, 0, sizeof(target->dial));
    target->dial_selected = false;
  }
  return FTUN_OK;
}

ftun_status_t ftun_target_select_dial(ftun_target_t *target,
                                      const ftun_endpoint_t *endpoint)
{
  ftun_status_t status;
  if (!ftun_target_valid(target) || endpoint == NULL) return FTUN_E_INVALID;
  status = ftun_target_endpoint_validate(endpoint);
  if (status != FTUN_OK) return status;
  if (!ftun_target_contains(target->allowed, target->allowed_count, endpoint)) {
    return FTUN_E_REJECTED;
  }
  target->dial = *endpoint;
  target->dial_selected = true;
  return FTUN_OK;
}

ftun_status_t ftun_target_select_remote_domain(ftun_target_t *target)
{
  if (!ftun_target_valid(target)) return FTUN_E_INVALID;
  if (target->candidate_count != 0u) return FTUN_E_REJECTED;
  if (ftun_target_domain_validate(target->identity) != FTUN_OK) {
    return FTUN_E_REJECTED;
  }
  memset(&target->dial, 0, sizeof(target->dial));
  target->dial.kind = FTUN_ADDRESS_DOMAIN;
  target->dial.domain = target->identity;
  target->dial.port = target->original.port;
  target->dial_selected = true;
  return FTUN_OK;
}
