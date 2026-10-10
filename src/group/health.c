#include "health.h"
#include <string.h>

/* 共享健康探测。
 * 需求 REQ-GROUP-001；任务 TASK-GROUP-003；目标 0.4.0；验收 TEST-GROUP-003。
 * 实现路径：通过真实节点路径探测 HTTP/HTTPS，独立总 deadline；jitter/退避/并发限制；无消费者停周期任务，不能证明 UDP 可达。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_health_probe(ftun_core_t *core, const ftun_probe_request_t *request, ftun_operation_t **out)
{
  if (out != NULL) *out = NULL;
  (void)core;
  (void)request;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
