#ifndef FTUN_TUN_UDP_SESSION_H
#define FTUN_TUN_UDP_SESSION_H
#include "internal/contracts.h"
/* TUN UDP flow。
 * 需求 REQ-UDP-001；任务 TASK-TUN-003；目标 0.2.0；验收 TEST-TUN-003。
 * 实现路径：按入站/源/目标建立有界表并固定 Runtime；FakeIP 回包恢复客户端原目标；idle 回收且不向另一地址重放同一包。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_udp_flow_input(ftun_core_t *core, const ftun_metadata_t *metadata, ftun_packet_t *packet);
#endif
