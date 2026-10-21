#include "network/view.h"

#include <stdlib.h>
#include <string.h>

#define FTUN_NETWORK_VIEW_MAGIC UINT32_C(0x46544e56)
#define FTUN_NETWORK_PURPOSE_ALL \
  ((UINT32_C(1) << (uint32_t)FTUN_DIAL_PURPOSE_RELAY) - UINT32_C(1))

struct ftun_network_view {
  uint32_t magic;
  size_t references;
  uint64_t generation;
  size_t protected_prefix_count;
  size_t overlay_route_count;
  size_t underlay_exception_count;
  ftun_network_prefix_t protected_prefixes[FTUN_NETWORK_VIEW_MAX_PREFIXES];
  ftun_network_route_t overlay_routes[FTUN_NETWORK_VIEW_MAX_ROUTES];
  ftun_network_underlay_exception_t
    underlay_exceptions[FTUN_NETWORK_VIEW_MAX_EXCEPTIONS];
};

static int ftun_network_purpose_valid(ftun_dial_purpose_t purpose)
{
  return purpose >= FTUN_DIAL_PURPOSE_BUSINESS &&
         purpose <= FTUN_DIAL_PURPOSE_RELAY;
}

static int ftun_network_domain_valid(ftun_dial_domain_t domain)
{
  return domain >= FTUN_DIAL_DOMAIN_AUTO &&
         domain <= FTUN_DIAL_DOMAIN_OVERLAY;
}

static uint32_t ftun_network_ipv4(const uint8_t address[4])
{
  return ((uint32_t)address[0] << 24u) |
         ((uint32_t)address[1] << 16u) |
         ((uint32_t)address[2] << 8u) | (uint32_t)address[3];
}

static uint32_t ftun_network_mask(uint8_t prefix_length)
{
  return prefix_length == 0u ? 0u :
    UINT32_MAX << (32u - (uint32_t)prefix_length);
}

static int ftun_network_prefix_valid(const ftun_network_prefix_t *prefix)
{
  uint32_t value;
  uint32_t mask;
  if (prefix == NULL || prefix->prefix_length > 32u) return 0;
  value = ftun_network_ipv4(prefix->network);
  mask = ftun_network_mask(prefix->prefix_length);
  return (value & ~mask) == 0u;
}

static int ftun_network_prefix_equal(const ftun_network_prefix_t *left,
                                     const ftun_network_prefix_t *right)
{
  return left->prefix_length == right->prefix_length &&
         memcmp(left->network, right->network, 4u) == 0;
}

static int ftun_network_prefix_contains(const ftun_network_prefix_t *prefix,
                                        const uint8_t address[4])
{
  uint32_t mask = ftun_network_mask(prefix->prefix_length);
  return (ftun_network_ipv4(prefix->network) & mask) ==
         (ftun_network_ipv4(address) & mask);
}

static int ftun_network_prefix_contains_prefix(
  const ftun_network_prefix_t *outer, const ftun_network_prefix_t *inner)
{
  return outer->prefix_length <= inner->prefix_length &&
         ftun_network_prefix_contains(outer, inner->network);
}

static int ftun_network_endpoint_valid(const ftun_endpoint_t *endpoint)
{
  return endpoint != NULL && endpoint->kind == FTUN_ADDRESS_IPV4 &&
         endpoint->port != 0u && endpoint->domain.length == 0u;
}

static int ftun_network_endpoint_equal(const ftun_endpoint_t *left,
                                       const ftun_endpoint_t *right)
{
  return left->kind == FTUN_ADDRESS_IPV4 &&
         right->kind == FTUN_ADDRESS_IPV4 && left->port == right->port &&
         memcmp(left->address, right->address, 4u) == 0;
}

static int ftun_network_mask_valid(uint32_t mask)
{
  return mask != 0u && (mask & ~FTUN_NETWORK_PURPOSE_ALL) == 0u;
}

static int ftun_network_forced_underlay(ftun_dial_purpose_t purpose)
{
  return purpose == FTUN_DIAL_PURPOSE_BOOTSTRAP ||
         purpose == FTUN_DIAL_PURPOSE_PROBE ||
         purpose == FTUN_DIAL_PURPOSE_FRS_UPDATE ||
         purpose == FTUN_DIAL_PURPOSE_MESH_CONTROL ||
         purpose == FTUN_DIAL_PURPOSE_STUN ||
         purpose == FTUN_DIAL_PURPOSE_RELAY;
}

static int ftun_network_spec_valid(const ftun_network_view_spec_t *spec)
{
  size_t index;
  size_t previous;
  if (spec == NULL || spec->generation == 0u ||
      spec->protected_prefix_count > FTUN_NETWORK_VIEW_MAX_PREFIXES ||
      spec->overlay_route_count > FTUN_NETWORK_VIEW_MAX_ROUTES ||
      spec->underlay_exception_count > FTUN_NETWORK_VIEW_MAX_EXCEPTIONS ||
      (spec->protected_prefix_count != 0u &&
       spec->protected_prefixes == NULL) ||
      (spec->overlay_route_count != 0u && spec->overlay_routes == NULL) ||
      (spec->underlay_exception_count != 0u &&
       spec->underlay_exceptions == NULL)) return 0;
  for (index = 0u; index < spec->protected_prefix_count; index++) {
    if (!ftun_network_prefix_valid(&spec->protected_prefixes[index])) return 0;
    for (previous = 0u; previous < index; previous++) {
      if (ftun_network_prefix_equal(&spec->protected_prefixes[index],
                                    &spec->protected_prefixes[previous])) {
        return 0;
      }
    }
  }
  for (index = 0u; index < spec->overlay_route_count; index++) {
    bool protected_route = false;
    if (!ftun_network_prefix_valid(&spec->overlay_routes[index].prefix) ||
        !ftun_network_mask_valid(spec->overlay_routes[index].purpose_mask)) {
      return 0;
    }
    for (previous = 0u; previous < spec->protected_prefix_count; previous++) {
      if (ftun_network_prefix_contains_prefix(
            &spec->protected_prefixes[previous],
            &spec->overlay_routes[index].prefix)) protected_route = true;
    }
    if (!protected_route) return 0;
    for (previous = 0u; previous < index; previous++) {
      if (ftun_network_prefix_equal(&spec->overlay_routes[index].prefix,
                                    &spec->overlay_routes[previous].prefix)) {
        return 0;
      }
    }
  }
  for (index = 0u; index < spec->underlay_exception_count; index++) {
    const ftun_network_underlay_exception_t *item =
      &spec->underlay_exceptions[index];
    if (!ftun_network_endpoint_valid(&item->endpoint) ||
        !ftun_network_mask_valid(item->purpose_mask)) return 0;
    for (previous = 0u; previous < index; previous++) {
      if (ftun_network_endpoint_equal(&item->endpoint,
            &spec->underlay_exceptions[previous].endpoint)) return 0;
    }
  }
  return 1;
}

ftun_status_t ftun_network_view_create(const ftun_network_view_spec_t *spec,
                                       ftun_network_view_t **out)
{
  ftun_network_view_t *view;
  if (out != NULL) *out = NULL;
  if (out == NULL || !ftun_network_spec_valid(spec)) return FTUN_E_INVALID;
  view = (ftun_network_view_t *)calloc(1u, sizeof(*view));
  if (view == NULL) return FTUN_E_LIMIT;
  view->magic = FTUN_NETWORK_VIEW_MAGIC;
  view->references = 1u;
  view->generation = spec->generation;
  view->protected_prefix_count = spec->protected_prefix_count;
  view->overlay_route_count = spec->overlay_route_count;
  view->underlay_exception_count = spec->underlay_exception_count;
  if (spec->protected_prefix_count != 0u) {
    memcpy(view->protected_prefixes, spec->protected_prefixes,
      spec->protected_prefix_count * sizeof(spec->protected_prefixes[0]));
  }
  if (spec->overlay_route_count != 0u) {
    memcpy(view->overlay_routes, spec->overlay_routes,
      spec->overlay_route_count * sizeof(spec->overlay_routes[0]));
  }
  if (spec->underlay_exception_count != 0u) {
    memcpy(view->underlay_exceptions, spec->underlay_exceptions,
      spec->underlay_exception_count * sizeof(spec->underlay_exceptions[0]));
    for (size_t index = 0u; index < spec->underlay_exception_count; index++) {
      view->underlay_exceptions[index].endpoint.domain.data = NULL;
      view->underlay_exceptions[index].endpoint.domain.length = 0u;
    }
  }
  *out = view;
  return FTUN_OK;
}

ftun_status_t ftun_network_view_retain(ftun_network_view_t *view)
{
  if (view == NULL || view->magic != FTUN_NETWORK_VIEW_MAGIC ||
      view->references == SIZE_MAX) return FTUN_E_INVALID;
  view->references++;
  return FTUN_OK;
}

ftun_status_t ftun_network_view_release(ftun_network_view_t **view)
{
  ftun_network_view_t *owned;
  if (view == NULL) return FTUN_E_INVALID;
  owned = *view;
  if (owned == NULL) return FTUN_OK;
  if (owned->magic != FTUN_NETWORK_VIEW_MAGIC || owned->references == 0u) {
    return FTUN_E_INVALID;
  }
  *view = NULL;
  owned->references--;
  if (owned->references == 0u) {
    owned->magic = 0u;
    memset(owned, 0, sizeof(*owned));
    free(owned);
  }
  return FTUN_OK;
}

ftun_status_t ftun_network_view_get_info(const ftun_network_view_t *view,
                                         ftun_network_view_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (view == NULL || view->magic != FTUN_NETWORK_VIEW_MAGIC || out == NULL) {
    return FTUN_E_INVALID;
  }
  out->generation = view->generation;
  out->protected_prefix_count = view->protected_prefix_count;
  out->overlay_route_count = view->overlay_route_count;
  out->underlay_exception_count = view->underlay_exception_count;
  return FTUN_OK;
}

ftun_status_t ftun_network_view_get_protected(
  const ftun_network_view_t *view, size_t index, ftun_network_prefix_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (view == NULL || view->magic != FTUN_NETWORK_VIEW_MAGIC || out == NULL ||
      index >= view->protected_prefix_count) return FTUN_E_INVALID;
  *out = view->protected_prefixes[index];
  return FTUN_OK;
}

ftun_status_t ftun_network_view_get_route(
  const ftun_network_view_t *view, size_t index, ftun_network_route_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (view == NULL || view->magic != FTUN_NETWORK_VIEW_MAGIC || out == NULL ||
      index >= view->overlay_route_count) return FTUN_E_INVALID;
  *out = view->overlay_routes[index];
  return FTUN_OK;
}

ftun_status_t ftun_network_view_select_dial(
  const ftun_network_view_t *view, const ftun_endpoint_t *endpoint,
  ftun_dial_purpose_t purpose, ftun_dial_domain_t requested,
  ftun_network_dial_decision_t *out)
{
  const ftun_network_route_t *route = NULL;
  uint32_t purpose_bit;
  uint8_t protected_length = 0u;
  bool protected_target = false;
  size_t index;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (view == NULL || view->magic != FTUN_NETWORK_VIEW_MAGIC ||
      !ftun_network_endpoint_valid(endpoint) ||
      !ftun_network_purpose_valid(purpose) ||
      !ftun_network_domain_valid(requested) || out == NULL) {
    return FTUN_E_INVALID;
  }
  purpose_bit = FTUN_DIAL_PURPOSE_BIT(purpose);
  out->generation = view->generation;
  for (index = 0u; index < view->underlay_exception_count; index++) {
    const ftun_network_underlay_exception_t *item =
      &view->underlay_exceptions[index];
    if ((item->purpose_mask & purpose_bit) != 0u &&
        ftun_network_endpoint_equal(&item->endpoint, endpoint)) {
      if (requested == FTUN_DIAL_DOMAIN_OVERLAY) return FTUN_E_REJECTED;
      out->domain = FTUN_DIAL_DOMAIN_UNDERLAY;
      out->purpose_exception = true;
      return FTUN_OK;
    }
  }
  for (index = 0u; index < view->protected_prefix_count; index++) {
    const ftun_network_prefix_t *prefix = &view->protected_prefixes[index];
    if ((!protected_target || prefix->prefix_length > protected_length) &&
        ftun_network_prefix_contains(prefix, endpoint->address)) {
      protected_target = true;
      protected_length = prefix->prefix_length;
    }
  }
  out->protected_target = protected_target;
  out->matched_prefix_length = protected_length;
  if (ftun_network_forced_underlay(purpose)) {
    if (protected_target) return FTUN_E_REJECTED;
    if (requested == FTUN_DIAL_DOMAIN_OVERLAY) return FTUN_E_REJECTED;
    out->domain = FTUN_DIAL_DOMAIN_UNDERLAY;
    return FTUN_OK;
  }
  if (!protected_target) {
    if (requested == FTUN_DIAL_DOMAIN_OVERLAY) return FTUN_E_REJECTED;
    out->domain = FTUN_DIAL_DOMAIN_UNDERLAY;
    return FTUN_OK;
  }
  if (requested == FTUN_DIAL_DOMAIN_UNDERLAY) return FTUN_E_REJECTED;
  for (index = 0u; index < view->overlay_route_count; index++) {
    const ftun_network_route_t *candidate = &view->overlay_routes[index];
    if ((candidate->purpose_mask & purpose_bit) != 0u &&
        ftun_network_prefix_contains(&candidate->prefix, endpoint->address) &&
        (route == NULL || candidate->prefix.prefix_length >
                          route->prefix.prefix_length)) route = candidate;
  }
  if (route == NULL) return FTUN_E_REJECTED;
  out->domain = FTUN_DIAL_DOMAIN_OVERLAY;
  out->matched_prefix_length = route->prefix.prefix_length;
  return FTUN_OK;
}
