#include "platform/iface.h"
#include "platform/route.h"
#include "platform/tun.h"
bool ftun_platform_tun_auto_route_supported(void) { return false; }

/* 非Linux发行档不提供路由接管及原生网络变化订阅；不交付伪句柄。 */
ftun_status_t ftun_iface_subscribe(ftun_handle_t *descriptor)
{
  *descriptor = -1;
  return FTUN_E_UNSUPPORTED;
}
ftun_status_t ftun_iface_receive(ftun_handle_t descriptor, void *data, size_t capacity, size_t *received)
{
  (void)descriptor; (void)data; (void)capacity;
  *received = 0u;
  return FTUN_E_UNSUPPORTED;
}
size_t ftun_netmon_parse(const uint8_t *data, size_t length, ftun_network_change_t *change)
{
  (void)data; (void)length; (void)change;
  return 0u;
}
ftun_route_settings_t ftun_platform_route_defaults(void)
{
  return (ftun_route_settings_t){18004u, 11000u};
}

const char *ftun_platform_route_config_error(ftun_route_settings_t settings)
{
  if (settings.routing_domain < 256u || settings.routing_domain > UINT32_C(0xfffffff0) ||
      settings.precedence == 0u || settings.precedence > 32000u) {
    return "TUN route-table must be 256..4294967280 and rule-priority 1..32000";
  }
  return NULL;
}
