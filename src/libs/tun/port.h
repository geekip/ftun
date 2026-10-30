#ifndef FTUN_LIBS_TUN_PORT_H
#define FTUN_LIBS_TUN_PORT_H
#include "libs/tun/device.h"
#include "platform/tun.h"


typedef struct {
  char name[FTUN_PACKET_PORT_NAME_BYTES];
  uint32_t mtu;
  ftun_handle_t descriptor;
  uint32_t flags;
} ftun_tun_port_info_t;

/* 平台 TUN 设备。
 * 实现路径：显式权限检查和非阻塞设备接入；处理 MTU、整包边界和关闭；初版不宣称支持未实现的 offload。
 * 调用边界：不访问配置 AST，不跨线程修改 Session。
 * spec 仅在调用期间借用；成功后 port 独占设备，必须由 close 终结。
 * port 只由 owner loop 使用；每次 read/write 对应一个无 PI 的三层包。
 */
ftun_status_t ftun_tun_port_open(const ftun_tun_spec_t *spec, ftun_packet_port_t **out);
/* 测试与受控宿主注入；操作表会复制，context 必须比 port 长寿。 */
ftun_status_t ftun_tun_port_open_with_io(const ftun_tun_spec_t *spec,
                                          const ftun_platform_tun_io_t *io,
                                          ftun_packet_port_t **out);
ftun_status_t ftun_tun_port_get_info(const ftun_packet_port_t *port,
                                      ftun_tun_port_info_t *out);
/* capacity 至少为配置 MTU，避免 Linux TUN 截断并丢弃包尾。 */
ftun_status_t ftun_tun_port_read(ftun_packet_port_t *port, void *buffer,
                                  size_t capacity, size_t *out_length);
ftun_status_t ftun_tun_port_write(ftun_packet_port_t *port, const void *packet,
                                   size_t length);
/* close 即使底层报告错误也消费句柄；Linux close 不可安全重试。 */
ftun_status_t ftun_tun_port_close(ftun_packet_port_t **port);
/* 对象、环区和设备/控制句柄按平台需求先准入，关闭完成后归还。 */
ftun_status_t ftun_tun_port_open_with_budget(ftun_budget_t *budget,
  const ftun_tun_spec_t *spec, ftun_packet_port_t **out);
ftun_status_t ftun_tun_port_open_with_io_and_budget(ftun_budget_t *budget,
  const ftun_tun_spec_t *spec, const ftun_platform_tun_io_t *io,
  ftun_packet_port_t **out);
#endif
