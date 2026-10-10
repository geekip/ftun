#include "compile.h"
#include <string.h>

static const char *const ftun_builtin_module_names[] = {
  "core",
#if defined(FTUN_HAVE_MODULE_DNS)
  "dns",
#endif
#if defined(FTUN_HAVE_MODULE_TUN)
  "tun",
#endif
};

static const ftun_build_capabilities_t ftun_capabilities = {
  FTUN_BUILD_MODULE_CORE
#if defined(FTUN_HAVE_MODULE_DNS)
    | FTUN_BUILD_MODULE_DNS
#endif
#if defined(FTUN_HAVE_MODULE_TUN)
    | FTUN_BUILD_MODULE_TUN
#endif
  ,
  ftun_builtin_module_names,
  sizeof(ftun_builtin_module_names) / sizeof(ftun_builtin_module_names[0])
};

static void ftun_build_diagnostic(ftun_diagnostic_t *out, ftun_status_t status,
                                  const char *message)
{
  if (out == NULL) return;
  memset(out, 0, sizeof(*out));
  out->error.status = status;
  out->message.data = message;
  out->message.length = strlen(message);
}

const ftun_build_capabilities_t *ftun_build_capabilities(void)
{
  return &ftun_capabilities;
}

ftun_status_t ftun_build_require_modules(uint32_t required, ftun_diagnostic_t *out)
{
  uint32_t missing;
  if ((required & ~(uint32_t)FTUN_BUILD_MODULE_ALL) != 0u) {
    ftun_build_diagnostic(out, FTUN_E_INVALID, "unknown build module");
    return FTUN_E_INVALID;
  }
  missing = required & ~ftun_capabilities.builtins;
  if (missing != 0u) {
    ftun_build_diagnostic(out, FTUN_E_UNSUPPORTED, "required build module is not built in");
    return FTUN_E_UNSUPPORTED;
  }
  if (out != NULL) memset(out, 0, sizeof(*out));
  return FTUN_OK;
}

/* 依赖闭包与资源计划。
 * 需求 REQ-CONF-001；任务 TASK-CONFIG-004；目标 0.2.0；验收 TEST-CONFIG-004。
 * 实现路径：从监听、路由、DNS、探测及历史引用求闭包；区分 compiled/prepare/lazy/active/retained；不重排 rules。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_config_compile(const ftun_config_t *config, ftun_feature_plan_t **out)
{
  if (out != NULL) *out = NULL;
  (void)config;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
