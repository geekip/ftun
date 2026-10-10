#include "relay.h"
#include <string.h>

/* 双向背压中继。
 * 需求 REQ-PERF-001；任务 TASK-TRANSPORT-004；目标 0.2.0；验收 TEST-TRANSPORT-004。
 * 实现路径：按需缓冲，高低水位贯穿所有 adapter；先排空再 half-close；只在待写时监听 WRITE，每轮限定工作量。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_relay_start(ftun_core_t *core, ftun_stream_t *left, ftun_stream_t *right, ftun_session_t **out)
{
  if (out != NULL) *out = NULL;
  (void)core;
  (void)left;
  (void)right;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
