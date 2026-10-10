#ifndef FTUN_EVENT_EVENT_H
#define FTUN_EVENT_EVENT_H
#include "internal/contracts.h"
/* 可移植事件接口。
 * 需求 REQ-CORE-001；任务 TASK-EVENT-001；目标 0.2.0；验收 TEST-EVENT-001。
 * 实现路径：封装 I/O/timer/wakeup，不向公共 API 暴露 watcher；只唤醒有工作对象，停止时排空终结队列。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_event_loop_create(ftun_core_t *core, ftun_event_loop_t **out);
#endif
