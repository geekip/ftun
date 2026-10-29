#include "libs/tun/config/validate.h"
#include "core/config/syntax.h"
#include <string.h>

ftun_status_t ftun_config_validate_tun_device(
  const ftun_config_tun_t *tun,
  ftun_diagnostic_t *out)
{
  ftun_config_cidr_t tun_range;
  const char *base = "/tun";
  if (tun == NULL || !tun->present) return FTUN_OK;
  if (!ftun_path_valid(tun->interface_name) ||
      strlen(tun->interface_name) > 15u) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, base,
                                  "TUN interface name is invalid");
  }
  if (tun->route_table < 256u ||
      tun->route_table > FTUN_CONFIG_ROUTE_TABLE_MAXIMUM ||
      tun->rule_priority == 0u ||
      tun->rule_priority > FTUN_CONFIG_RULE_PRIORITY_MAXIMUM) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, base,
      "TUN route-table must be 256..4294967280 and rule-priority 1..32000");
  }
  if (tun->mtu == 0u ||
      (tun->strict_route && !tun->auto_route)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, base,
                                  "TUN options are invalid");
  }
  if (!ftun_cidr(tun->ipv4_address, 0, &tun_range)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, base,
                                  "TUN IPv4 address is invalid");
  }

  return FTUN_OK;
}
