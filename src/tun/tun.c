#include "tun.h"
#include <string.h>

/* 平台无关包端口。
 * 需求 REQ-PLAT-001；任务 TASK-TUN-001；目标 0.2.0；验收 TEST-TUN-001。
 * 实现路径：委托平台设备或宿主回调读取整包；控制 MTU/队列/关闭；不负责平台路由和业务出口。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_packet_port_open(ftun_core_t *core, const ftun_tun_spec_t *spec, ftun_packet_port_t **out)
{
  if (out != NULL) *out = NULL;
  (void)core;
  (void)spec;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
