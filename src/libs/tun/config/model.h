#ifndef FTUN_LIBS_TUN_CONFIG_MODEL_H
#define FTUN_LIBS_TUN_CONFIG_MODEL_H
#include "core/config/document.h"
enum {
  FTUN_CONFIG_SECTION_TUN = 12u
};

/* 系统保留表号：unspec/default/main/local 和内核规则优先级上限之外的值。 */

typedef struct {
  bool present;
  char *interface_name;
  uint32_t mtu;
  char *ipv4_address;
  bool auto_route;
  bool strict_route;
  /* 策略路由表号与规则优先级：同机多实例时必须各不相同。 */
  uint32_t route_table;
  uint32_t rule_priority;
} ftun_config_tun_t;

static inline const ftun_config_tun_t *ftun_config_tun(const ftun_config_t *config)
{
  return ftun_config_document_section(config, FTUN_CONFIG_SECTION_TUN);
}

#endif
