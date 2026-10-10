#include "config.h"
#include <string.h>

/* 配置加载协调。
 * 需求 REQ-CONF-001；任务 TASK-CONFIG-001；目标 0.2.0；验收 TEST-CONFIG-001。
 * 实现路径：有界读取后依次调用 parser/validate/compile；路径相对配置目录；失败不替换 active Runtime。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_config_load(ftun_core_t *core, const char *path, ftun_config_t **out)
{
  if (out != NULL) *out = NULL;
  (void)core;
  (void)path;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
