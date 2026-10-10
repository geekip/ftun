#ifndef FTUN_CORE_OPERATION_H
#define FTUN_CORE_OPERATION_H
#include "internal/contracts.h"
/* 异步接纳与取消。
 * 需求 REQ-CORE-001；任务 TASK-CORE-005；目标 0.2.0；验收 TEST-CORE-005。
 * 实现路径：未接纳零回调；已接纳必须延迟终结一次；取消与完成在 owner loop 仲裁，取消后上下文仍活到回调结束。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_operation_cancel(ftun_operation_t *operation);
#endif
