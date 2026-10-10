#ifndef FTUN_ROUTE_ROUTER_H
#define FTUN_ROUTE_ROUTER_H
#include "internal/contracts.h"
/* 保序路由解释器。
 * 需求 REQ-ROUTE-001；任务 TASK-ROUTE-001；目标 0.3.0；验收 TEST-ROUTE-001。
 * 实现路径：按序求值；缺真实 IP 返回 NEED_RESOLVE 和同代游标；恢复原条规则，选中结果携带允许地址集合。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_route_evaluate(const ftun_runtime_t *runtime, const ftun_metadata_t *metadata, size_t resume_rule, ftun_route_result_t *out);
#endif
