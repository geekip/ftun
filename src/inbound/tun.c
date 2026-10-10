#include "tun.h"
#include <string.h>

/* TUN 到协议栈入口。
 * 需求 REQ-IN-001；任务 TASK-INBOUND-005；目标 0.2.0；验收 TEST-INBOUND-005。
 * 实现路径：保留来源、设备身份及完整 IP 包；仅支持 IPv4 TCP/UDP；将包交 lwIP，生成统一 Stream/Datagram。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_tun_ingress(ftun_core_t *core, ftun_packet_port_t *port, ftun_packet_t *packet)
{
  (void)core;
  (void)port;
  (void)packet;
  return FTUN_E_NOT_IMPLEMENTED;
}
