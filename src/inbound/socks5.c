#include "socks5.h"
#include <string.h>

/* SOCKS5 入站。
 * 需求 REQ-IN-001；任务 TASK-INBOUND-003；目标 0.4.0；验收 TEST-INBOUND-003。
 * 实现路径：增量协商认证和 CONNECT/UDP ASSOCIATE；出站成功后才回复成功；拒绝 BIND，FRAG 非零整包丢弃。
 * 编译边界：UDP 使用核心 Datagram/flow，不依赖可选 TUN/lwIP 接入。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_socks5_accept(ftun_core_t *core, ftun_stream_t *client, const ftun_inbound_spec_t *spec)
{
  (void)core;
  (void)client;
  (void)spec;
  return FTUN_E_NOT_IMPLEMENTED;
}
