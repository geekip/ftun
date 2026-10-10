#include "datagram.h"
#include <string.h>

/* 整包发送接口。
 * 需求 REQ-UDP-001；任务 TASK-TRANSPORT-003；目标 0.2.0；验收 TEST-TRANSPORT-003。
 * 实现路径：成功仅表示整包发送或入有界队列，不证明远端收到；AGAIN 完全未接纳；保留空 payload、报文边界和回包来源。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_datagram_send(ftun_datagram_t *channel, const ftun_endpoint_t *target, ftun_packet_t *packet)
{
  (void)channel;
  (void)target;
  (void)packet;
  return FTUN_E_NOT_IMPLEMENTED;
}
