#include "libs/transport/view.h"

#include <stdio.h>
#include <string.h>

#define CHECK(expression) do { \
  if (!(expression)) { \
    fprintf(stderr, "check failed: %s:%d: %s\n", \
            __FILE__, __LINE__, #expression); \
    return 1; \
  } \
} while (0)

static ftun_endpoint_t endpoint(uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                                uint16_t port)
{
  ftun_endpoint_t value;
  memset(&value, 0, sizeof(value));
  value.kind = FTUN_ADDRESS_IPV4;
  value.address[0] = a;
  value.address[1] = b;
  value.address[2] = c;
  value.address[3] = d;
  value.port = port;
  return value;
}

static int test_selection_and_revocation(void)
{
  ftun_network_prefix_t protected_prefixes[2] = {
    {{10u, 0u, 0u, 0u}, 8u},
    {{172u, 16u, 0u, 0u}, 12u}
  };
  ftun_network_route_t routes[2] = {
    {{{10u, 0u, 0u, 0u}, 8u},
      FTUN_DIAL_PURPOSE_BIT(FTUN_DIAL_PURPOSE_PROXY)},
    {{{10u, 2u, 0u, 0u}, 16u},
      FTUN_DIAL_PURPOSE_BIT(FTUN_DIAL_PURPOSE_PROXY) |
      FTUN_DIAL_PURPOSE_BIT(FTUN_DIAL_PURPOSE_BUSINESS)}
  };
  ftun_network_underlay_exception_t exception;
  ftun_network_view_spec_t spec;
  ftun_network_view_t *view = NULL;
  ftun_network_view_t *revoked = NULL;
  ftun_network_dial_decision_t decision;
  ftun_network_view_info_t info;
  ftun_endpoint_t proxy = endpoint(10u, 2u, 3u, 4u, 1080u);
  ftun_endpoint_t control = endpoint(10u, 9u, 8u, 7u, 443u);
  ftun_endpoint_t unreachable = endpoint(172u, 16u, 1u, 2u, 80u);
  ftun_endpoint_t public_target = endpoint(192u, 0u, 2u, 2u, 443u);

  memset(&exception, 0, sizeof(exception));
  exception.endpoint = control;
  exception.purpose_mask =
    FTUN_DIAL_PURPOSE_BIT(FTUN_DIAL_PURPOSE_MESH_CONTROL) |
    FTUN_DIAL_PURPOSE_BIT(FTUN_DIAL_PURPOSE_STUN) |
    FTUN_DIAL_PURPOSE_BIT(FTUN_DIAL_PURPOSE_RELAY);
  memset(&spec, 0, sizeof(spec));
  spec.generation = 9u;
  spec.protected_prefixes = protected_prefixes;
  spec.protected_prefix_count = 2u;
  spec.overlay_routes = routes;
  spec.overlay_route_count = 2u;
  spec.underlay_exceptions = &exception;
  spec.underlay_exception_count = 1u;
  CHECK(ftun_network_view_create(&spec, &view) == FTUN_OK && view != NULL);
  CHECK(ftun_network_view_get_info(view, &info) == FTUN_OK &&
        info.generation == 9u && info.protected_prefix_count == 2u &&
        info.overlay_route_count == 2u && info.underlay_exception_count == 1u);

  CHECK(ftun_network_view_select_dial(view, &proxy,
          FTUN_DIAL_PURPOSE_PROXY, FTUN_DIAL_DOMAIN_AUTO, &decision) ==
        FTUN_OK && decision.domain == FTUN_DIAL_DOMAIN_OVERLAY &&
        decision.protected_target && decision.matched_prefix_length == 16u);
  CHECK(ftun_network_view_select_dial(view, &proxy,
          FTUN_DIAL_PURPOSE_BUSINESS, FTUN_DIAL_DOMAIN_AUTO, &decision) ==
        FTUN_OK && decision.domain == FTUN_DIAL_DOMAIN_OVERLAY);
  CHECK(ftun_network_view_select_dial(view, &control,
          FTUN_DIAL_PURPOSE_MESH_CONTROL, FTUN_DIAL_DOMAIN_AUTO, &decision) ==
        FTUN_OK && decision.domain == FTUN_DIAL_DOMAIN_UNDERLAY &&
        decision.purpose_exception);
  CHECK(ftun_network_view_select_dial(view, &control,
          FTUN_DIAL_PURPOSE_BUSINESS, FTUN_DIAL_DOMAIN_UNDERLAY, &decision) ==
        FTUN_E_REJECTED);
  CHECK(ftun_network_view_select_dial(view, &proxy,
          FTUN_DIAL_PURPOSE_BOOTSTRAP, FTUN_DIAL_DOMAIN_AUTO, &decision) ==
        FTUN_E_REJECTED);
  CHECK(ftun_network_view_select_dial(view, &unreachable,
          FTUN_DIAL_PURPOSE_PROXY, FTUN_DIAL_DOMAIN_AUTO, &decision) ==
        FTUN_E_REJECTED);
  CHECK(ftun_network_view_select_dial(view, &public_target,
          FTUN_DIAL_PURPOSE_PROXY, FTUN_DIAL_DOMAIN_AUTO, &decision) ==
        FTUN_OK && decision.domain == FTUN_DIAL_DOMAIN_UNDERLAY &&
        !decision.protected_target);
  CHECK(ftun_network_view_select_dial(view, &public_target,
          FTUN_DIAL_PURPOSE_PROXY, FTUN_DIAL_DOMAIN_OVERLAY, &decision) ==
        FTUN_E_REJECTED);

  /* 撤销只清空可达 route，protected identity 继续失败关闭。 */
  spec.generation = 10u;
  spec.overlay_routes = NULL;
  spec.overlay_route_count = 0u;
  CHECK(ftun_network_view_create(&spec, &revoked) == FTUN_OK);
  CHECK(ftun_network_view_select_dial(revoked, &proxy,
          FTUN_DIAL_PURPOSE_PROXY, FTUN_DIAL_DOMAIN_AUTO, &decision) ==
        FTUN_E_REJECTED);
  ftun_network_view_release(&revoked); CHECK(revoked == NULL);
  ftun_network_view_release(&view); CHECK(view == NULL);
  return 0;
}

static int test_invalid_specs(void)
{
  ftun_network_prefix_t protected_prefix = {{10u, 1u, 0u, 1u}, 16u};
  ftun_network_route_t route = {
    {{192u, 0u, 2u, 0u}, 24u},
    FTUN_DIAL_PURPOSE_BIT(FTUN_DIAL_PURPOSE_PROXY)
  };
  ftun_network_view_spec_t spec;
  ftun_network_view_t *view = (ftun_network_view_t *)(uintptr_t)1u;
  memset(&spec, 0, sizeof(spec));
  spec.generation = 1u;
  spec.protected_prefixes = &protected_prefix;
  spec.protected_prefix_count = 1u;
  CHECK(ftun_network_view_create(&spec, &view) == FTUN_E_INVALID &&
        view == NULL);
  protected_prefix.network[3] = 0u;
  spec.overlay_routes = &route;
  spec.overlay_route_count = 1u;
  CHECK(ftun_network_view_create(&spec, &view) == FTUN_E_INVALID &&
        view == NULL);
  route.prefix.network[0] = 10u;
  route.prefix.network[1] = 1u;
  CHECK(ftun_network_view_create(&spec, &view) == FTUN_OK);
  CHECK(ftun_network_view_retain(view) == FTUN_OK);
  {
    ftun_network_view_t *second = view;
    ftun_network_view_release(&second); CHECK(second == NULL);
  }
  ftun_network_view_release(&view); CHECK(view == NULL);
  return 0;
}

static int test_default_prefix(void)
{
  ftun_network_prefix_t protected_prefix = {{0u, 0u, 0u, 0u}, 0u};
  ftun_network_route_t route = {
    {{0u, 0u, 0u, 0u}, 0u},
    FTUN_DIAL_PURPOSE_BIT(FTUN_DIAL_PURPOSE_PROXY)
  };
  ftun_network_view_spec_t spec;
  ftun_network_view_t *view = NULL;
  ftun_network_dial_decision_t decision;
  ftun_endpoint_t target = endpoint(203u, 0u, 113u, 9u, 443u);
  memset(&spec, 0, sizeof(spec));
  spec.generation = 11u;
  spec.protected_prefixes = &protected_prefix;
  spec.protected_prefix_count = 1u;
  spec.overlay_routes = &route;
  spec.overlay_route_count = 1u;
  CHECK(ftun_network_view_create(&spec, &view) == FTUN_OK);
  CHECK(ftun_network_view_select_dial(view, &target,
          FTUN_DIAL_PURPOSE_PROXY, FTUN_DIAL_DOMAIN_AUTO, &decision) ==
        FTUN_OK && decision.domain == FTUN_DIAL_DOMAIN_OVERLAY &&
        decision.protected_target && decision.matched_prefix_length == 0u);
  CHECK(ftun_network_view_select_dial(view, &target,
          FTUN_DIAL_PURPOSE_PROXY, FTUN_DIAL_DOMAIN_UNDERLAY, &decision) ==
        FTUN_E_REJECTED);
  CHECK(ftun_network_view_select_dial(view, &target,
          FTUN_DIAL_PURPOSE_BOOTSTRAP, FTUN_DIAL_DOMAIN_AUTO, &decision) ==
        FTUN_E_REJECTED);
  ftun_network_view_release(&view);

  protected_prefix.network[0] = 1u;
  CHECK(ftun_network_view_create(&spec, &view) == FTUN_E_INVALID &&
        view == NULL);
  return 0;
}

int main(void)
{
  CHECK(test_selection_and_revocation() == 0);
  CHECK(test_invalid_specs() == 0);
  CHECK(test_default_prefix() == 0);
  return 0;
}
