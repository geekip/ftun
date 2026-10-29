#ifndef FTUN_APP_CONFIG_COMPILE_H
#define FTUN_APP_CONFIG_COMPILE_H
#include "util/types.h"
#include "app/config/plan.h"
/* 返回进程编译时静态能力。指针在进程生命期内有效，调用者不得修改或释放。
 * BUILTIN 仅表示源码已编入，不表示对应运行功能已实现。 */
const ftun_build_capabilities_t *ftun_build_capabilities(void);
/* 从规范化配置计算运行时根模块；只描述配置需求，不检查当前构建能力。 */
uint32_t ftun_config_required_modules(const ftun_config_t *config);
/* required 只能包含 FTUN_BUILD_MODULE_ALL 中的位。能力缺失返回 UNSUPPORTED；
 * 未知位返回 INVALID。out 可为 NULL，其中 message 为静态借用视图。 */
ftun_status_t ftun_build_require_modules(uint32_t required, ftun_diagnostic_t *out);

/* 依赖闭包与资源计划。
 * 实现路径：从监听、路由、DNS、探测及历史引用求闭包；区分 compiled/prepare/lazy/active/retained；不重排 rules。
 * 调用边界：不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；返回计划独立拥有索引数组，不转移配置所有权。
 */
/* 发布计划及其模块需求借用；只在未发布的配置构造阶段调用。 */
void ftun_config_bind_plan(ftun_config_t *config, ftun_feature_plan_t *plan);

ftun_status_t ftun_config_compile(const ftun_config_t *config, ftun_feature_plan_t **out);
/* 空计划销毁幂等；成功后清空调用者句柄。 */
ftun_status_t ftun_feature_plan_destroy(ftun_feature_plan_t **plan);
#endif
