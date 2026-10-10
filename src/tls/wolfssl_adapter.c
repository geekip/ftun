#include "wolfssl_adapter.h"
#include <string.h>

/* 首个 TLS 验证候选。
 * 需求 REQ-DEP-001；任务 TASK-TLS-002；目标 0.4.0；验收 TEST-TLS-002。
 * 实现路径：后续审核精确版本、许可、裁剪和互操作后接入；当前未包含 wolfSSL 代码或报告 backend 可用。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_wolfssl_prepare(const ftun_tls_options_t *options, ftun_tls_context_t **out)
{
  if (out != NULL) *out = NULL;
  (void)options;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
