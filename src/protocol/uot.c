#include "uot.h"
#include <string.h>

/* UoT 数据报扩展。
 * 需求 REQ-FUTURE-001；任务 TASK-PROTOCOL-004；目标 1.1.0；验收 TEST-PROTOCOL-004。
 * 实现路径：保留逻辑 UDP 边界，地址编码按协议独立定义；不把物理 TCP 误当业务 NETWORK=TCP。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_uot_decode(ftun_bytes_t input, ftun_protocol_result_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  (void)input;
  (void)out;
  return FTUN_E_UNSUPPORTED;
}
