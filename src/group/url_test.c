#include "url_test.h"
#include <string.h>

/* 稳定自动选择。
 * 需求 REQ-GROUP-001；任务 TASK-GROUP-002；目标 0.4.0；验收 TEST-GROUP-002。
 * 实现路径：只比较新鲜成功样本，加容差和最短保持时间；全失败标记 degraded 并保留上次或 default，不按请求切 DIRECT。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_url_test_choose(const ftun_group_spec_t *group, const ftun_health_snapshot_t *health, ftun_group_choice_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  (void)group;
  (void)health;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
