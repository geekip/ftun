#include "libs/transport/view.h"
#include "util/endpoint.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define FTUN_NETWORK_VIEW_MAGIC UINT32_C(0x46544e56)
#define FTUN_NETWORK_PURPOSE_ALL \
  ((UINT32_C(1) << (uint32_t)FTUN_DIAL_PURPOSE_RELAY) - UINT32_C(1))

struct ftun_network_view {
  uint32_t magic;
  size_t references;
  uint64_t generation;
  bool revoked;
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

static int ftun_network_prefix_valid(const ftun_network_prefix_t *prefix)
{
  size_t bits, i;
  if (prefix == NULL || (prefix->address.family != FTUN_IP_V4 &&
      prefix->address.family != FTUN_IP_V6)) return 0;
  bits = prefix->address.family == FTUN_IP_V6 ? 128u : 32u;
  if (prefix->prefix > bits) return 0;
  for (i = prefix->prefix; i < bits; i++) {
    if ((prefix->address.bytes[i / 8u] & (1u << (7u - i % 8u))) != 0u) return 0;
  }
  return 1;
}
static int ftun_network_prefix_equal(const ftun_network_prefix_t *left,
  const ftun_network_prefix_t *right)
{
  return left->prefix == right->prefix && ftun_ip_equal(&left->address, &right->address);
}
static int ftun_network_prefix_contains_prefix(const ftun_network_prefix_t *outer,
  const ftun_network_prefix_t *inner)
{
  return outer->prefix <= inner->prefix && ftun_cidr_contains(outer, &inner->address);
}

static int ftun_network_endpoint_valid(const ftun_endpoint_t *endpoint)
{
  return endpoint != NULL && ftun_endpoint_is_ip(endpoint) &&
         endpoint->port != 0u && endpoint->domain.length == 0u;
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
      if (ftun_endpoint_equal(&item->endpoint,
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

void ftun_network_view_release(ftun_network_view_t **view)
{
  ftun_network_view_t *owned;
  assert(view != NULL);
  owned = *view;
  if (owned == NULL) return;
  assert(owned->magic == FTUN_NETWORK_VIEW_MAGIC && owned->references != 0u);
  *view = NULL;
  if (--owned->references == 0u) free(owned);
}

ftun_status_t ftun_network_view_get_info(const ftun_network_view_t *view,
                                         ftun_network_view_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (view == NULL || view->magic != FTUN_NETWORK_VIEW_MAGIC || out == NULL) {
    return FTUN_E_INVALID;
  }
  out->generation = view->generation;
  out->revoked = __atomic_load_n(&view->revoked, __ATOMIC_ACQUIRE);
  out->protected_prefix_count = view->protected_prefix_count;
  out->overlay_route_count = view->overlay_route_count;
  out->underlay_exception_count = view->underlay_exception_count;
  return FTUN_OK;
}

ftun_status_t ftun_network_view_revoke(ftun_network_view_t *view)
{
  if (view == NULL || view->magic != FTUN_NETWORK_VIEW_MAGIC) return FTUN_E_INVALID;
  __atomic_store_n(&view->revoked, true, __ATOMIC_RELEASE);
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
  ftun_ip_t target = ftun_endpoint_ip(endpoint);
  purpose_bit = FTUN_DIAL_PURPOSE_BIT(purpose);
  if (__atomic_load_n(&view->revoked, __ATOMIC_ACQUIRE)) return FTUN_E_CANCELLED;
  out->generation = view->generation;
  for (index = 0u; index < view->underlay_exception_count; index++) {
    const ftun_network_underlay_exception_t *item =
      &view->underlay_exceptions[index];
    if ((item->purpose_mask & purpose_bit) != 0u &&
        ftun_endpoint_equal(&item->endpoint, endpoint)) {
      if (requested == FTUN_DIAL_DOMAIN_OVERLAY) return FTUN_E_REJECTED;
      out->domain = FTUN_DIAL_DOMAIN_UNDERLAY;
      out->purpose_exception = true;
      return FTUN_OK;
    }
  }
  for (index = 0u; index < view->protected_prefix_count; index++) {
    const ftun_network_prefix_t *prefix = &view->protected_prefixes[index];
    if ((!protected_target || prefix->prefix > protected_length) &&
        ftun_cidr_contains(prefix, &target)) {
      protected_target = true;
      protected_length = prefix->prefix;
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
        ftun_cidr_contains(&candidate->prefix, &target) &&
        (route == NULL || candidate->prefix.prefix >
                          route->prefix.prefix)) route = candidate;
  }
  if (route == NULL) return FTUN_E_REJECTED;
  out->domain = FTUN_DIAL_DOMAIN_OVERLAY;
  out->matched_prefix_length = route->prefix.prefix;
  return FTUN_OK;
}
