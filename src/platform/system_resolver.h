#ifndef FTUN_PLATFORM_SYSTEM_RESOLVER_H
#define FTUN_PLATFORM_SYSTEM_RESOLVER_H
#include "internal/contracts.h"
/* 系统解析适配。
 * 需求 REQ-DNS-001；任务 TASK-PLATFORM-004；目标 0.2.0；验收 TEST-PLATFORM-004。
 * 实现路径：遵循系统配置、非阻塞交付结果；验证 libc 或本地解析服务实际网络路径，不能假定隐藏 socket 自动带 mark。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_system_resolve(ftun_core_t *core, ftun_string_t domain, ftun_operation_t **out);
#endif
