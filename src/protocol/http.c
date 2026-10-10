#include "http.h"
#include <string.h>

/* HTTP 代理报文。
 * 需求 REQ-IN-001；任务 TASK-PROTOCOL-002；目标 0.4.0；验收 TEST-PROTOCOL-002。
 * 实现路径：约束 request-target/Host、长度及头字段；拒绝冲突长度，流式处理 body；连接复用不得固定首个请求目标。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_http_decode(ftun_bytes_t input, ftun_protocol_result_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  (void)input;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
