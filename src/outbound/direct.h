#ifndef FTUN_OUTBOUND_DIRECT_H
#define FTUN_OUTBOUND_DIRECT_H
#include "internal/contracts.h"
/* 直连出口。
 * 需求 REQ-OUT-001；任务 TASK-OUTBOUND-002；目标 0.2.0；验收 TEST-OUTBOUND-002。
 * 实现路径：使用受保护 Dialer；域名仅在缺少本次真实结果时解析；TCP 候选重试不越过允许集合，不重放已发送业务。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_direct_open(ftun_core_t *core, const ftun_endpoint_t *target, ftun_operation_t **out);
#endif
