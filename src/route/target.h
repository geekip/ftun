#ifndef FTUN_ROUTE_TARGET_H
#define FTUN_ROUTE_TARGET_H
#include "internal/contracts.h"
/* 目标与候选约束。
 * 需求 REQ-ROUTE-001；任务 TASK-ROUTE-003；目标 0.2.0；验收 TEST-ROUTE-003。
 * 实现路径：区分原始真实地址、域名、FakeIP、真实候选和实际拨号地址；任何重试只能缩小已选允许集合。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_target_from_metadata(const ftun_metadata_t *metadata, ftun_target_t *out);
#endif
