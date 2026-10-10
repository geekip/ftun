#ifndef FTUN_DNS_SERVER_H
#define FTUN_DNS_SERVER_H
#include "internal/contracts.h"
/* 真实 DNS 传输。
 * 需求 REQ-DNS-001；任务 TASK-DNS-002；目标 0.3.0；验收 TEST-DNS-002。
 * 实现路径：server.outbound 仅决定查询通道；内部 REAL 绕过 FakeIP；固定一次事务出口，校验响应，使用绝对 deadline。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_dns_exchange(ftun_core_t *core, const ftun_dns_server_t *server, const ftun_dns_query_t *query, ftun_operation_t **out);
#endif
