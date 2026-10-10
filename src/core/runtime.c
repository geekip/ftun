#include "runtime.h"
#include <string.h>

/* 编译结果的准备与快照生命周期。
 * 需求 REQ-CONF-001；任务 TASK-CORE-001；目标 0.2.0；验收 TEST-CORE-001。
 * 实现路径：引用配置计划，检查 active/candidate/retained 总预算；准备必需对象；由 loop 提交，旧代按引用回收。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_runtime_prepare(ftun_core_t *core, const ftun_config_t *config, ftun_runtime_t **out)
{
  if (out != NULL) *out = NULL;
  (void)core;
  (void)config;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
