#ifndef FTUN_LIBS_TUN_CONFIG_VALIDATE_H
#define FTUN_LIBS_TUN_CONFIG_VALIDATE_H
#include "core/config/error.h"
#include "libs/tun/config/model.h"
/* 只校验设备段的局部语义，不访问设备、路由或宿主配置。 */
ftun_status_t ftun_config_validate_tun_device(
  const ftun_config_tun_t *tun,
  ftun_config_error_t *out);
#endif
