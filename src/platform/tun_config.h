#ifndef FTUN_PLATFORM_TUN_CONFIG_H
#define FTUN_PLATFORM_TUN_CONFIG_H
#include "util/types.h"
#include "util/ip.h"
/* 手动路由平台只安装本次创建网卡的地址；状态保留到逐项撤销成功。 */
size_t ftun_platform_tun_config_size(void);
ftun_status_t ftun_platform_tun_configure(void *state, const void *io,
  ftun_string_t name, uint32_t mtu, const ftun_cidr_t *addresses, size_t count);
ftun_status_t ftun_platform_tun_unconfigure(void *state, const void *io);
#endif
