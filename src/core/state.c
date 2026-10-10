#include "state.h"
#include <string.h>

/* Group 与 Health 状态恢复。
 * 需求 REQ-STATE-001；任务 TASK-CORE-003；目标 0.5.0；验收 TEST-CORE-003。
 * 实现路径：按配置身份、成员合法性和样本有效期恢复；不得覆盖明确修改的 default；可丢弃缓存不得影响 FakeIP 预留身份。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_state_restore(ftun_core_t *core, const ftun_config_t *config)
{
  (void)core;
  (void)config;
  return FTUN_E_NOT_IMPLEMENTED;
}
