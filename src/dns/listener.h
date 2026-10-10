#ifndef FTUN_DNS_LISTENER_H
#define FTUN_DNS_LISTENER_H
#include "internal/contracts.h"
/* UDP 和 TCP DNS 接入。
 * 需求 REQ-DNSWIRE-001；任务 TASK-DNS-003；目标 0.3.0；验收 TEST-DNS-003。
 * 实现路径：UDP 超长合法截断并设置 TC；TCP 两字节分帧和有界在途；将请求交 Dispatcher，停用时关闭接纳。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_dns_listen(ftun_core_t *core, const ftun_dns_listener_spec_t *spec, ftun_dns_listener_t **out);
#endif
