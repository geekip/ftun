#include "update.h"
#include <string.h>

/* Geo 下载更新事务。
 * 需求 REQ-GEO-001；任务 TASK-GEO-004；目标 0.4.0；验收 TEST-GEO-004。
 * 实现路径：通过指定下载出口和解析上下文写临时产物；验证并试加载成功再替换；失败保留旧视图和文件。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_geo_update(ftun_core_t *core, const ftun_geo_update_request_t *request, ftun_operation_t **out)
{
  if (out != NULL) *out = NULL;
  (void)core;
  (void)request;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
