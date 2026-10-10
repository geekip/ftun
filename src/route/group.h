#ifndef FTUN_ROUTE_GROUP_H
#define FTUN_ROUTE_GROUP_H
#include "internal/contracts.h"
/* 不可变组路径展开。
 * 需求 REQ-GROUP-001；任务 TASK-ROUTE-004；目标 0.4.0；验收 TEST-ROUTE-004。
 * 实现路径：沿选中路径展开到叶子，有限深度并校验 generation；DNS 外到内继承，DIRECT/REJECT 内置行为优先。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_group_expand(const ftun_runtime_t *runtime, uint32_t group_id, ftun_group_choice_t *out);
#endif
