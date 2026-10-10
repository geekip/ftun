#include "logger.h"
#include <string.h>

/* 有界日志。
 * 需求 REQ-OBS-001；任务 TASK-UTIL-001；目标 0.5.0；验收 TEST-UTIL-001。
 * 实现路径：先判断级别再格式化；脱敏、限流和有界队列；慢磁盘不阻塞 loop，丢弃计数保留。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_log_emit(ftun_core_t *core, const ftun_diagnostic_t *diagnostic)
{
  (void)core;
  (void)diagnostic;
  return FTUN_E_NOT_IMPLEMENTED;
}
