#ifndef FTUN_APP_COMPOSITION_BRIDGES_H
#define FTUN_APP_COMPOSITION_BRIDGES_H
#include "proxy/dns/runtime_adapter.h"
/* Composition 在发布 bindings 之前装配，表为静态常量；adapter 仍由调用方拥有。 */
void ftun_app_dns_bridge_init(ftun_proxy_dns_runtime_adapter_t *adapter);
#endif
