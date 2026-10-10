#ifndef FTUN_OUTBOUND_SOCKS5_H
#define FTUN_OUTBOUND_SOCKS5_H
#include "internal/contracts.h"
/* SOCKS5 出站。
 * 需求 REQ-OUT-001；任务 TASK-OUTBOUND-004；目标 0.2.0；验收 TEST-OUTBOUND-004。
 * 实现路径：节点域名先基础解析，物理连接受保护；真实候选已有则发送 IP，否则允许 DOMAIN；UDP 持有控制 TCP 并核验 relay 来源。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_socks5_connect(ftun_core_t *core, const ftun_proxy_spec_t *proxy, const ftun_route_result_t *route, ftun_operation_t **out);
#endif
