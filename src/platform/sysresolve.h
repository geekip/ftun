#ifndef FTUN_PLATFORM_SYSRESOLVE_H
#define FTUN_PLATFORM_SYSRESOLVE_H
#include "util/types.h"
#include "util/ip.h"
/* 仅供隔离worker调用；family为FTUN_IP_NONE/V4/V6，保留有序去重结果。 */
ftun_status_t ftun_sysresolve(const char *domain, uint8_t family, ftun_ip_t *addresses,
  size_t maximum, size_t *out_count);
ftun_status_t ftun_sysresolve_first(const char *domain, uint8_t family,
  uint16_t port, ftun_endpoint_t *out);
ftun_status_t ftun_system_nameserver(ftun_endpoint_t *out);
#endif
