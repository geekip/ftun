#ifndef FTUN_PLATFORM_LINUX_ROUTE_H
#define FTUN_PLATFORM_LINUX_ROUTE_H
#include "internal/contracts.h"
/* Linux 路由资源事务。
 * 需求 REQ-GUARD-001；任务 TASK-PLATFORM-002；目标 0.2.0；验收 TEST-PLATFORM-002。
 * 实现路径：记录实例所有权；保护与 TUN 路由按序准备；冲突拒绝、失败反序撤销；本机/LAN 分别验收，退出不改他人规则。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_linux_route_prepare(const ftun_route_policy_t *policy, ftun_route_transaction_t **out);
#endif
