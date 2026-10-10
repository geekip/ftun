#ifndef FTUN_TRANSPORT_DIALER_H
#define FTUN_TRANSPORT_DIALER_H
#include "internal/contracts.h"
/* 唯一物理拨号入口。
 * 需求 REQ-GUARD-001；任务 TASK-TRANSPORT-001；目标 0.2.0；验收 TEST-TRANSPORT-001。
 * 实现路径：先 resource admission 和 socket protection，再异步建连；记录 purpose；业务流量不按目的地址全局豁免规则。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_dial_start(ftun_core_t *core, const ftun_dial_request_t *request, ftun_operation_t **out);
#endif
