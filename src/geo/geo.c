#include "geo.h"
#include <string.h>

/* 只读 Geo 文件入口。
 * 需求 REQ-GEO-001；任务 TASK-GEO-001；目标 0.4.0；验收 TEST-GEO-001。
 * 实现路径：验证版本、长度、校验与所有索引范围，之后 mmap/read；视图不可变并由 Runtime 引用，不能原地更新文件。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_geo_open(ftun_core_t *core, const char *path, ftun_geo_view_t **out)
{
  if (out != NULL) *out = NULL;
  (void)core;
  (void)path;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
