#ifndef FTUN_CONFIG_COMPILE_H
#define FTUN_CONFIG_COMPILE_H
#include "internal/contracts.h"
/* 返回进程编译时静态能力。指针在进程生命期内有效，调用者不得修改或释放。
 * BUILTIN 仅表示源码已编入，不表示对应运行功能已实现。 */
const ftun_build_capabilities_t *ftun_build_capabilities(void);
/* required 只能包含 FTUN_BUILD_MODULE_ALL 中的位。能力缺失返回 UNSUPPORTED；
 * 未知位返回 INVALID。out 可为 NULL，其中 message 为静态借用视图。 */
ftun_status_t ftun_build_require_modules(uint32_t required, ftun_diagnostic_t *out);
/* 依赖闭包与资源计划。
 * 需求 REQ-CONF-001；任务 TASK-CONFIG-004；目标 0.2.0；验收 TEST-CONFIG-004。
 * 实现路径：从监听、路由、DNS、探测及历史引用求闭包；区分 compiled/prepare/lazy/active/retained；不重排 rules。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_config_compile(const ftun_config_t *config, ftun_feature_plan_t **out);
#endif
