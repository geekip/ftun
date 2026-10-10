#include "cache.h"
#include <string.h>

/* 策略隔离的响应缓存。
 * 需求 REQ-DNSWIRE-001；任务 TASK-DNS-006；目标 0.3.0；验收 TEST-DNS-006。
 * 实现路径：键包括问题、标志、解析策略和实际出口身份；正确递减 TTL；NXDOMAIN/NODATA 与短期失败抑制分开。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_dns_cache_lookup(ftun_dns_cache_t *cache, const ftun_dns_query_t *query, ftun_dns_answer_t **out)
{
  if (out != NULL) *out = NULL;
  (void)cache;
  (void)query;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
