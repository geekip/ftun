#ifndef FTUN_DNS_CACHE_H
#define FTUN_DNS_CACHE_H
#include "core/budget.h"
#include "dns/wire.h"

typedef uint64_t (*ftun_dns_cache_now_fn)(void *user);

typedef struct {
  ftun_budget_t *budget;
  size_t max_entries;
  ftun_dns_cache_now_fn now;
  void *now_user;
} ftun_dns_cache_options_t;

typedef enum {
  FTUN_DNS_CACHE_POSITIVE = 1,
  FTUN_DNS_CACHE_NEGATIVE,
  FTUN_DNS_CACHE_FAILURE
} ftun_dns_cache_kind_t;

typedef struct {
  size_t capacity;
  size_t entries;
  size_t positive;
  size_t negative;
  size_t failures;
} ftun_dns_cache_usage_t;

struct ftun_dns_answer {
  uint8_t *wire;
  size_t wire_length;
  ftun_dns_cache_kind_t kind;
  ftun_status_t failure;
  ftun_reservation_t *reservation;
  void *owned_block;
};

ftun_status_t ftun_dns_cache_create(const ftun_dns_cache_options_t *options,
                                    ftun_dns_cache_t **out);
/* wire 必须是已验证、与 query 完整匹配的响应。TTL=0 的回答不缓存。 */
ftun_status_t ftun_dns_cache_store(ftun_dns_cache_t *cache,
                                   const ftun_dns_query_t *query,
                                   ftun_bytes_t wire);
/* 网络失败只做短时抑制，绝不序列化成 NXDOMAIN/NODATA。 */
ftun_status_t ftun_dns_cache_store_failure(ftun_dns_cache_t *cache,
                                           const ftun_dns_query_t *query,
                                           ftun_status_t failure,
                                           uint64_t suppress_ms);
/* 策略隔离的响应缓存。
 * 需求 REQ-DNSWIRE-001；任务 TASK-DNS-006；目标 0.3.0；验收 TEST-DNS-006。
 * 实现路径：键包括问题、标志、解析策略和实际出口身份；正确递减 TTL；NXDOMAIN/NODATA 与短期失败抑制分开。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * lookup 返回拥有型 answer，并按当前单调时刻重写 ID 与递减普通 RR TTL。
 */
ftun_status_t ftun_dns_cache_lookup(ftun_dns_cache_t *cache, const ftun_dns_query_t *query, ftun_dns_answer_t **out);
ftun_status_t ftun_dns_answer_release(ftun_dns_answer_t **answer);
ftun_status_t ftun_dns_cache_get_usage(const ftun_dns_cache_t *cache,
                                       ftun_dns_cache_usage_t *out);
ftun_status_t ftun_dns_cache_destroy(ftun_dns_cache_t **cache);
#endif
