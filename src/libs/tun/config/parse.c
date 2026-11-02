#include "platform/route.h"
#include "libs/tun/config/parse.h"
#include "core/config/fields.h"
#include <stdlib.h>

ftun_status_t ftun_config_parse_tun_device(const cJSON *item,
                                           ftun_config_t *config, ftun_config_tun_t *tun)
{
  static const char *const fields[] = {
    "interface", "mtu", "ipv4", "auto-route", "strict-route",
    "route-table", "rule-priority", "ipv6"
  };
  static const char *const ipv4_fields[] = {"address"};
  const cJSON *ipv4;
  ftun_status_t status;
  status = ftun_config_check_fields(config, item, fields, 8u);
  if (status == FTUN_OK) {
    status = ftun_config_replace_string(config, &tun->interface_name,
      item, "interface", 1);
  }
  if (status == FTUN_OK) {
    status = ftun_config_optional_uint(config, item, "mtu", 1u, UINT32_MAX,
                                &tun->mtu);
  }
  ipv4 = cJSON_GetObjectItemCaseSensitive(item, "ipv4");
  if (status == FTUN_OK && ipv4 == NULL) status = ftun_config_parse_failure(
    config, item, "ipv4", FTUN_E_INVALID, "required IPv4 object is missing");
  if (status == FTUN_OK) status = ftun_config_check_fields(config, ipv4, ipv4_fields, 1u);
  if (status == FTUN_OK) {
    status = ftun_config_replace_string(config, &tun->ipv4_address,
      ipv4, "address", 1);
  }
  const cJSON *ipv6 = cJSON_GetObjectItemCaseSensitive(item, "ipv6");
  if (status == FTUN_OK && ipv6 != NULL) {
    status = ftun_config_check_fields(config, ipv6, ipv4_fields, 1u);
    if (status == FTUN_OK) status = ftun_config_replace_string(config, &tun->ipv6_address,
      ipv6, "address", 1);
  }
  if (status == FTUN_OK) {
    status = ftun_config_optional_bool(config, item, "auto-route",
                                &tun->auto_route);
  }
  if (status == FTUN_OK) {
    status = ftun_config_optional_bool(config, item, "strict-route",
                                &tun->strict_route);
  }
  if (status == FTUN_OK) {
    status = ftun_config_optional_uint(config, item, "route-table", 1u, UINT32_MAX,
                                &tun->route_table);
  }
  if (status == FTUN_OK) {
    status = ftun_config_optional_uint(config, item, "rule-priority", 1u, UINT32_MAX,
                                &tun->rule_priority);
  }
  if (status == FTUN_OK) tun->present = true;
  return status;
}


void ftun_config_clear_tun(ftun_config_tun_t *tun)
{
  free(tun->interface_name);
  free(tun->ipv4_address);
  free(tun->ipv6_address);
}

void ftun_config_defaults_tun(ftun_config_tun_t *tun)
{
  tun->mtu = 1500u;
  {
    ftun_route_settings_t settings = ftun_platform_route_defaults();
    tun->route_table = settings.routing_domain;
    tun->rule_priority = settings.precedence;
  }
}
