#include "socket_protect.h"
#include <string.h>

/* 物理出口保护。
 * 需求 REQ-GUARD-001；任务 TASK-PLATFORM-003；目标 0.2.0；验收 TEST-PLATFORM-003。
 * 实现路径：在 bind/connect/send 前设置必需 mark/出口约束；DIRECT、DNS、探测、relay 同样保护；必需项失败不得忽略。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_linux_socket_protect(ftun_native_socket_t socket, const ftun_socket_policy_t *policy)
{
  (void)socket;
  (void)policy;
  return FTUN_E_NOT_IMPLEMENTED;
}
