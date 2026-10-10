#include "resolver.h"
#include <string.h>

/* 按用途选择解析器。
 * 需求 REQ-DNS-001；任务 TASK-DNS-005；目标 0.2.0；验收 TEST-DNS-005。
 * 实现路径：IP 规则前 default-server REAL/Bootstrap；DNS 关闭统一系统；结果在同一 Session 复用，出口确定不二次解析。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_resolve_real(ftun_core_t *core, const ftun_resolve_request_t *request, ftun_operation_t **out)
{
  if (out != NULL) *out = NULL;
  (void)core;
  (void)request;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
