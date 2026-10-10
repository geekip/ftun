#ifndef FTUN_CORE_BUDGET_H
#define FTUN_CORE_BUDGET_H
#include "internal/contracts.h"
/* 统一资源准入。
 * 需求 REQ-PERF-001；任务 TASK-CORE-004；目标 0.2.0；验收 TEST-CORE-004。
 * 实现路径：在分配前同时预留全局和模块额度；保留清理及终结通知空间；任何失败回滚本次额度，不能用计账量冒充 RSS。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_budget_reserve(ftun_budget_t *budget, size_t bytes, ftun_reservation_t **out);
#endif
