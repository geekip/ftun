#ifndef FTUN_DNS_FAKEIP_H
#define FTUN_DNS_FAKEIP_H
#include "internal/contracts.h"
/* 全局 FakeIP 身份服务。
 * 需求 REQ-FAKE-001；任务 TASK-DNS-007；目标 0.3.0；验收 TEST-DNS-007。
 * 实现路径：规范域名双索引；先 durable reserve 后发布；条目满拒绝新域名；引用保护旧身份，禁止跨域回收。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_fakeip_acquire(ftun_core_t *core, ftun_string_t domain, ftun_fakeip_handle_t **out);
#endif
