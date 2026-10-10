#include "mixed.h"
#include <string.h>

/* HTTP 与 SOCKS 混合入口。
 * 需求 REQ-IN-001；任务 TASK-INBOUND-002；目标 0.4.0；验收 TEST-INBOUND-002。
 * 实现路径：有界首字节识别后调用共享协议解析；HTTP 每个请求验证目标和重新选路；认证与预读字节移交 Session。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_mixed_accept(ftun_core_t *core, ftun_stream_t *client, const ftun_inbound_spec_t *spec)
{
  (void)core;
  (void)client;
  (void)spec;
  return FTUN_E_NOT_IMPLEMENTED;
}
