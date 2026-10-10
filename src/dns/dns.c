#include "dns.h"
#include <string.h>

/* 固定与策略 DNS 入口。
 * 需求 REQ-DNS-001；任务 TASK-DNS-001；目标 0.3.0；验收 TEST-DNS-001。
 * 实现路径：固定入口不选业务 server；策略入口按已知信息复用 matcher；REAL 内部请求不得递归进入策略入口。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_dns_dispatch(ftun_core_t *core, const ftun_dns_query_t *query, ftun_operation_t **out)
{
  if (out != NULL) *out = NULL;
  (void)core;
  (void)query;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
