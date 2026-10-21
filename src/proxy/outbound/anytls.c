#include "anytls.h"
#include <string.h>

/* AnyTLS 出站扩展。
 * 需求 REQ-FUTURE-001；任务 TASK-OUTBOUND-005；目标 1.1.0；验收 TEST-OUTBOUND-005。
 * 实现路径：后续实现 TLS、协议认证、padding、空闲会话复用与 UoT；容量和上下文隔离，不能直接嵌入 Go runtime。
 * 调用边界：不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_anytls_connect(ftun_core_t *core, const ftun_proxy_spec_t *proxy, const ftun_route_result_t *route, ftun_operation_t **out)
{
  if (out != NULL) *out = NULL;
  (void)core;
  (void)proxy;
  (void)route;
  (void)out;
  return FTUN_E_UNSUPPORTED;
}
