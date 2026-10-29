#ifndef FTUN_PROXY_MODULE_H
#define FTUN_PROXY_MODULE_H

#include "core/lifecycle.h"

/* 静态描述符只注册一次；热路径直接持有已解析的 ProxyRuntime 句柄。 */
extern const ftun_core_service_descriptor_t ftun_proxy_service;

#endif
