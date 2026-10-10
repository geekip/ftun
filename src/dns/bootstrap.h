#ifndef FTUN_DNS_BOOTSTRAP_H
#define FTUN_DNS_BOOTSTRAP_H
#include "internal/contracts.h"
/* 基础真实解析。
 * 需求 REQ-DNS-001；任务 TASK-DNS-004；目标 0.2.0；验收 TEST-DNS-004。
 * 实现路径：显式 IP 上游 DIRECT；省略则平台 SystemResolver；用于节点和上游地址破环，不做 FakeIP，不暗中换来源。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_bootstrap_resolve(ftun_core_t *core, ftun_string_t domain, ftun_operation_t **out);
#endif
