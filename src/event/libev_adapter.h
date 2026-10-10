#ifndef FTUN_EVENT_LIBEV_ADAPTER_H
#define FTUN_EVENT_LIBEV_ADAPTER_H
#include "internal/contracts.h"
/* 完整上游 libev 适配。
 * 需求 REQ-DEP-001；任务 TASK-EVENT-002；目标 0.2.0；验收 TEST-EVENT-002。
 * 实现路径：固定完整上游来源与版本，按目标裁剪后端；Linux epoll 首验；跨线程唤醒审核线程配置；macOS/Windows 后续分别验证。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_libev_attach(ftun_event_loop_t *loop);
#endif
