#include "rule.h"
#include <string.h>

/* 共享 matcher。
 * 需求 REQ-ROUTE-001；任务 TASK-ROUTE-002；目标 0.3.0；验收 TEST-ROUTE-002。
 * 实现路径：纯函数匹配已知元数据；域名与 GeoSite 不解析 DNS；FakeIP 不作为真实 IP；DNS 未知业务端口/网络不匹配。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_rule_match(const ftun_rule_t *rule, const ftun_metadata_t *metadata, ftun_match_result_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  (void)rule;
  (void)metadata;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
