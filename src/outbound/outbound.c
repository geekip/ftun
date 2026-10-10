#include "outbound.h"
#include <string.h>

/* 出站分派。
 * 需求 REQ-OUT-001；任务 TASK-OUTBOUND-001；目标 0.2.0；验收 TEST-OUTBOUND-001。
 * 实现路径：接收已经固定的具体出口与允许目标；能力不匹配明确失败；不得在 adapter 内重新路由或静默 DIRECT。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_outbound_open(ftun_core_t *core, const ftun_route_result_t *route, ftun_operation_t **out)
{
  if (out != NULL) *out = NULL;
  (void)core;
  (void)route;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
