#include "tls.h"
#include <string.h>

/* TLS 抽象。
 * 需求 REQ-DEP-001；任务 TASK-TLS-001；目标 0.4.0；验收 TEST-TLS-001。
 * 实现路径：非阻塞 WANT_READ/WRITE、证书与主机名验证、SNI/CA、取消和内部缓冲预算；HTTPS 即使无 AnyTLS 也需要客户端。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_tls_client_open(ftun_core_t *core, const ftun_tls_options_t *options, ftun_stream_t *transport, ftun_stream_t **out)
{
  if (out != NULL) *out = NULL;
  (void)core;
  (void)options;
  (void)transport;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
