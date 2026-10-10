#include "format.h"
#include <string.h>

/* 二进制格式验证。
 * 需求 REQ-GEO-001；任务 TASK-GEO-005；目标 0.4.0；验收 TEST-GEO-005。
 * 实现路径：逐字段读固定端序；检查 offset+size 溢出、section 重叠、索引循环、哈希桶完整性；校验成功才给查询器。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_geo_format_validate(ftun_bytes_t file, ftun_geo_layout_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  (void)file;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
