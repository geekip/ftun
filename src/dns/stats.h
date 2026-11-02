#ifndef FTUN_DNS_STATS_H
#define FTUN_DNS_STATS_H
#include "util/types.h"
/* owner累计：queries包含尚未结束的查询，终态按原始错误计数。 */
typedef struct {
  uint64_t queries, success;
  uint64_t failures[FTUN_E_STATE_CORRUPT + 1u];
} ftun_dns_query_stats_t;
typedef struct {
  ftun_dns_query_stats_t queries;
  uint64_t cache_hits, cache_misses, cache_evictions, cache_expirations;
} ftun_dns_lifetime_stats_t;
#endif
