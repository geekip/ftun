#include "geoip.h"
#include <string.h>

/* IPv4 集合成员查询。
 * 需求 REQ-GEO-001；任务 TASK-GEO-002；目标 0.4.0；验收 TEST-GEO-002。
 * 实现路径：压缩前缀 Trie 判断集合成员；规则序号优先于最长前缀，不能以 LPM 重排业务规则。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_geoip_contains(const ftun_geo_view_t *view, uint32_t set_id, const uint8_t ipv4[4], bool *out)
{
  if (out != NULL) *out = false;
  (void)view;
  (void)set_id;
  (void)ipv4;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
