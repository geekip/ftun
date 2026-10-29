#ifndef FTUN_LIBS_TUN_CONFIG_PARSE_H
#define FTUN_LIBS_TUN_CONFIG_PARSE_H
#include "libs/tun/config/model.h"
/* 同步借用 JSON，只修改构造中的 tun 段；部分失败由宿主最终析构。
 * 无设备或路由 I/O；clear 仅用于最终 payload 析构。 */
ftun_status_t ftun_config_parse_tun_device(const cJSON *item, ftun_config_t *owner,
  ftun_config_tun_t *tun);
void ftun_config_defaults_tun(ftun_config_tun_t *tun);
void ftun_config_clear_tun(ftun_config_tun_t *tun);
#endif
