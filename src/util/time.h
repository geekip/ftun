#ifndef FTUN_UTIL_TIME_H
#define FTUN_UTIL_TIME_H
#include "internal/contracts.h"
/* 返回绝对单调时刻，单位为毫秒。
 * 需求 REQ-CORE-001；任务 TASK-UTIL-004；目标 0.2.0；验收 TEST-UTIL-004。
 * 实现路径：平台时钟转换检查溢出；阶段 timeout 共享总 deadline；不能用墙钟变化延长重试。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * out 不能为空；失败时清零。该同步查询不转移所有权，也不触发回调。
 */
ftun_status_t ftun_monotonic_now(uint64_t *out);
#endif
