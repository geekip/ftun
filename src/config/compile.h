#ifndef FTUN_CONFIG_COMPILE_H
#define FTUN_CONFIG_COMPILE_H
#include "internal/contracts.h"
/* 依赖闭包与资源计划。
 * 需求 REQ-CONF-001；任务 TASK-CONFIG-004；目标 0.2.0；验收 TEST-CONFIG-004。
 * 实现路径：从监听、路由、DNS、探测及历史引用求闭包；区分 compiled/prepare/lazy/active/retained；不重排 rules。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_config_compile(const ftun_config_t *config, ftun_feature_plan_t **out);
#endif
