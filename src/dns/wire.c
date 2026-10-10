#include "wire.h"
#include <string.h>

/* DNS 有界报文解析。
 * 需求 REQ-DNSWIRE-001；任务 TASK-DNS-008；目标 0.2.0；验收 TEST-DNS-008。
 * 实现路径：检查标签/压缩指针循环/消息边界；保留未知普通 RR，OPT 不作 TTL；关联 ID、问题及上游端点。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_dns_message_parse(ftun_bytes_t wire, ftun_dns_message_t **out)
{
  if (out != NULL) *out = NULL;
  (void)wire;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
