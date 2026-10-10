#include "inbound.h"
#include <string.h>

/* 统一入站工厂。
 * 需求 REQ-IN-001；任务 TASK-INBOUND-001；目标 0.2.0；验收 TEST-INBOUND-001。
 * 实现路径：准备监听或 PacketPort；检查实际能力与资源；按类型绑定 adapter ops，协议层不得直接选择代理。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_inbound_prepare(ftun_core_t *core, const ftun_inbound_spec_t *spec, ftun_inbound_t **out)
{
  if (out != NULL) *out = NULL;
  (void)core;
  (void)spec;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
