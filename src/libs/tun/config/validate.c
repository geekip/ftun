#include "libs/tun/config/validate.h"
#include "platform/route.h"
#include "platform/tun.h"
#include "core/config/syntax.h"
#include <string.h>

ftun_status_t ftun_config_validate_tun_device(
  const ftun_config_tun_t *tun,
  ftun_diagnostic_t *out)
{
  ftun_config_cidr_t tun_range;
  const char *base = "/tun";
  const char *route_error;
  if (tun == NULL || !tun->present) return FTUN_OK;
  if (!ftun_path_valid(tun->interface_name) ||
      strlen(tun->interface_name) > 15u) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, base,
                                  "TUN interface name is invalid");
  }
  if (tun->auto_route && !ftun_platform_tun_auto_route_supported()) {
    return ftun_config_diagnostic(out, FTUN_E_UNSUPPORTED, "/tun/auto-route",
      "TUN auto-route is unavailable on this platform; use manual routes");
  }
  route_error = ftun_platform_route_config_error(
    (ftun_route_settings_t){tun->route_table, tun->rule_priority});
  if (route_error != NULL) return ftun_config_diagnostic(out, FTUN_E_INVALID, base, route_error);
  if (tun->mtu == 0u ||
      (tun->strict_route && !tun->auto_route)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, base,
                                  "TUN options are invalid");
  }
  if ((!ftun_cidr(tun->ipv4_address, 0, &tun_range) || tun_range.address.family != FTUN_IP_V4)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, base,
                                  "TUN IPv4 address is invalid");
  }

  if (tun->ipv6_address != NULL &&
      (!ftun_cidr(tun->ipv6_address, 0, &tun_range) || tun_range.address.family != FTUN_IP_V6 || tun->mtu < 1280u)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/tun/ipv6/address", "TUN IPv6 requires a valid address and MTU >= 1280");
  }
  return FTUN_OK;
}
