#include "tun.h"
#include <string.h>

/* Linux TUN 设备。
 * 需求 REQ-PLAT-001；任务 TASK-PLATFORM-001；目标 0.2.0；验收 TEST-PLATFORM-001。
 * 实现路径：显式权限检查和非阻塞设备接入；处理 MTU、整包边界和关闭；初版不宣称支持未实现的 offload。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_linux_tun_open(const ftun_tun_spec_t *spec, ftun_packet_port_t **out)
{
  if (out != NULL) *out = NULL;
  (void)spec;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
