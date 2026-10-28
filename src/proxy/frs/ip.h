#ifndef FTUN_PROXY_FRS_IP_H
#define FTUN_PROXY_FRS_IP_H

#include "proxy/frs/frs.h"

/* IPv4 合并区间查询。 */

ftun_status_t ftun_frs_ip_contains(const ftun_frs_set_t *set,
                                   const uint8_t ipv4[4], bool *out);

#endif
