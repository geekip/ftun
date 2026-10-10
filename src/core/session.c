#include "session.h"
#include <string.h>

/* 统一业务会话。
 * 需求 REQ-CORE-001；任务 TASK-CORE-002；目标 0.2.0；验收 TEST-CORE-002。
 * 实现路径：接纳时保留 Runtime 和传输；恢复身份、嗅探、规则挂起、出站建立；成功后 relay；取消后等待回调清零。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_session_submit(ftun_core_t *core, const ftun_metadata_t *metadata, ftun_stream_t *inbound, ftun_session_t **out)
{
  if (out != NULL) *out = NULL;
  (void)core;
  (void)metadata;
  (void)inbound;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
