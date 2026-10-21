#include "group.h"
#include "proxy/runtime_state.h"
#include <string.h>

/* 不可变组路径展开。
 * 需求 REQ-GROUP-001；任务 TASK-ROUTE-004；目标 0.4.0；验收 TEST-ROUTE-004。
 * 实现路径：沿选中路径展开到叶子，有限深度并校验 generation；DNS 外到内继承，DIRECT/REJECT 内置行为优先。
 * 调用边界：不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 输出借用不可变 Runtime 内的 DNS 名称，不跨越 Runtime 引用期。
 */
ftun_status_t ftun_group_expand(const ftun_runtime_t *runtime, uint32_t group_id, ftun_group_choice_t *out)
{
  ftun_runtime_info_t info;
  uint32_t current = group_id;
  bool degraded = false;
  ftun_string_t inherited_dns;
  size_t depth;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (runtime == NULL || out == NULL) return FTUN_E_INVALID;
  if (ftun_runtime_get_info(runtime, &info) != FTUN_OK ||
      info.generation == 0u || info.state == FTUN_RUNTIME_CANDIDATE) {
    return FTUN_E_INVALID;
  }
  memset(&inherited_dns, 0, sizeof(inherited_dns));
  for (depth = 0u; depth < 32u; depth++) {
    uint32_t selected = 0u;
    bool is_group = false;
    bool current_degraded = false;
    ftun_string_t current_dns;
    ftun_status_t status = ftun_runtime_group_selected(
      runtime, current, &selected, &is_group, &current_degraded,
      &current_dns);
    if (status != FTUN_OK) return status;
    if (inherited_dns.length == 0u && current_dns.length != 0u) {
      inherited_dns = current_dns;
    }
    degraded = degraded || current_degraded;
    if (!is_group) {
      out->generation = info.generation;
      out->leaf_id = current;
      out->degraded = degraded;
      out->dns_server = inherited_dns;
      return FTUN_OK;
    }
    current = selected;
  }
  return FTUN_E_STATE_CORRUPT;
}
