#ifndef FTUN_CORE_WORKER_H
#define FTUN_CORE_WORKER_H
#include "internal/contracts.h"
/* 有界文件任务。
 * 需求 REQ-CORE-001；任务 TASK-CORE-006；目标 0.2.0；验收 TEST-CORE-006。
 * 实现路径：复制独立输入，预留结果和 completion；后台不得访问 Session；超时不等于中断 fsync，迟到结果只清理。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_worker_submit(ftun_core_t *core, const ftun_worker_job_t *job, ftun_operation_t **out);
#endif
