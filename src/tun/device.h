#ifndef FTUN_TUN_TUN_H
#define FTUN_TUN_TUN_H
#include "internal/contracts.h"

#define FTUN_PACKET_PORT_NAME_BYTES 16u

struct ftun_tun_spec {
  ftun_string_t name;
  uint32_t mtu;
};

typedef struct {
  char name[FTUN_PACKET_PORT_NAME_BYTES];
  uint32_t mtu;
  ftun_native_socket_t native_socket;
} ftun_packet_port_info_t;

/* 平台无关包端口。
 * 实现路径：委托平台设备或宿主回调读取整包；控制 MTU/队列/关闭；不负责平台路由和业务出口。
 * 调用边界：不访问配置 AST，不跨线程修改 Session。
 * spec 仅在打开期间借用；成功 port 独占平台设备并由 owner loop 使用。
 * 端口不增加无界用户态队列；EAGAIN 交由 Event readiness 驱动重试。
 */
ftun_status_t ftun_packet_port_open(ftun_core_t *core, const ftun_tun_spec_t *spec, ftun_packet_port_t **out);
ftun_status_t ftun_packet_port_get_info(const ftun_packet_port_t *port,
                                        ftun_packet_port_info_t *out);
ftun_status_t ftun_packet_port_read(ftun_packet_port_t *port, void *buffer,
                                    size_t capacity, size_t *out_length);
ftun_status_t ftun_packet_port_write(ftun_packet_port_t *port,
                                     const void *packet, size_t length);
ftun_status_t ftun_packet_port_close(ftun_packet_port_t **port);
ftun_status_t ftun_packet_port_open_with_budget(ftun_core_t *core,
  ftun_budget_t *budget, const ftun_tun_spec_t *spec, ftun_packet_port_t **out);
#endif
