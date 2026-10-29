#ifndef FTUN_LIBS_TUN_INTERFACE_BACKEND_H
#define FTUN_LIBS_TUN_INTERFACE_BACKEND_H
#include "libs/tun/interface.h"

/* 同步 context 为 NULL 时使用系统路由后端，否则借用 linux_route_io；
 * async.context 同理，非 NULL 时借用 linux_route_async_io。 */
extern const ftun_interface_ops_t ftun_interface_default_ops;
#endif
