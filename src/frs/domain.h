#ifndef FTUN_FRS_DOMAIN_H
#define FTUN_FRS_DOMAIN_H

#include "frs/frs.h"

/* TASK-FRS-003 / TEST-FRS-003：域名 radix 与关键词查询，目标 0.4.0。 */

/* domain 必须已是无尾点、ASCII 小写的规范域名。 */
ftun_status_t ftun_frs_domain_contains(const ftun_frs_set_t *set,
                                       ftun_string_t domain, bool *out);

#endif
