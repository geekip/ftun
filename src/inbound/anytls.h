#ifndef FTUN_INBOUND_ANYTLS_H
#define FTUN_INBOUND_ANYTLS_H
#include "internal/contracts.h"
/* AnyTLS 入站扩展边界。
 * 需求 REQ-FUTURE-001；任务 TASK-INBOUND-004；目标 1.1.0；验收 TEST-INBOUND-004。
 * 实现路径：后续连接 TLS 与协议 adapter；分别表达协议就绪与目标确认；当前没有实现或可用能力。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_anytls_accept(ftun_core_t *core, ftun_stream_t *client, const ftun_inbound_spec_t *spec);
#endif
