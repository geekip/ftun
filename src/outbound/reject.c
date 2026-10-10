#include "reject.h"
#include <string.h>

/* 策略拒绝。
 * 需求 REQ-OUT-001；任务 TASK-OUTBOUND-003；目标 0.2.0；验收 TEST-OUTBOUND-003。
 * 实现路径：将策略拒绝交入站映射到协议错误；DNS REFUSED、UDP 丢包、TCP 拒绝分开处理；不建立物理 socket。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_reject_request(const ftun_metadata_t *metadata)
{
  (void)metadata;
  return FTUN_E_NOT_IMPLEMENTED;
}
