#include "validate.h"
#include <string.h>

/* 无副作用语义校验。
 * 需求 REQ-CONF-001；任务 TASK-CONFIG-003；目标 0.2.0；验收 TEST-CONFIG-003。
 * 实现路径：验证名称、端口冲突、能力、引用和组环；校验不 bind、不解析网络、不创建闲置节点资源。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_config_validate(const ftun_config_t *config, ftun_diagnostic_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  (void)config;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
