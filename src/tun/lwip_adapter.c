#include "lwip_adapter.h"
#include <string.h>

/* lwIP raw API 移植。
 * 需求 REQ-CORE-001；任务 TASK-TUN-002；目标 0.2.0；验收 TEST-TUN-002。
 * 实现路径：NO_SYS 单 loop，补计时和分配器；pbuf 引用转交，tcp_recved 随下游消费；无复制 tcp_write 缓冲保留至 ACK 或终止。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_lwip_input(ftun_lwip_t *stack, ftun_packet_t *packet)
{
  (void)stack;
  (void)packet;
  return FTUN_E_NOT_IMPLEMENTED;
}
