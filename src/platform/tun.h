#ifndef FTUN_PLATFORM_TUN_H
#define FTUN_PLATFORM_TUN_H
#include "util/types.h"
#define FTUN_PACKET_PORT_NAME_BYTES 16u

struct ftun_tun_spec {
  ftun_string_t name;
  uint32_t mtu;
};

/* HANDLE 等待与无写就绪通知的设备由服务分别接入。 */
#define FTUN_PACKET_PORT_WAITABLE 1u
#define FTUN_PACKET_PORT_WRITE_TIMER 2u
typedef struct {
  char name[FTUN_PACKET_PORT_NAME_BYTES];
  uint32_t mtu;
  ftun_native_socket_t native_socket;
  uint32_t flags;
} ftun_packet_port_info_t;

/* 私有设备状态放在调用方已准入且对齐的 storage 中，平台不分配对象。
 * 操作表仅用于平台测试/受控宿主，调用方只传递其借用指针。 */
typedef struct ftun_platform_tun ftun_platform_tun_t;
typedef struct ftun_platform_tun_io ftun_platform_tun_io_t;
size_t ftun_platform_tun_allocation_size(void);
/* DLL 环形区与原生句柄在 open 前准入；不包含调用方的对象存储。 */
void ftun_platform_tun_resources(size_t *external_bytes, size_t *handles, size_t *temporary_handles);
bool ftun_platform_tun_auto_route_supported(void);
const ftun_platform_tun_io_t *ftun_platform_tun_default_io(void);
bool ftun_platform_tun_spec_valid(const ftun_tun_spec_t *spec, const ftun_platform_tun_io_t *io);
ftun_status_t ftun_platform_tun_open(const ftun_tun_spec_t *spec,
  const ftun_platform_tun_io_t *io, ftun_platform_tun_t *port);
void ftun_platform_tun_get_info(const ftun_platform_tun_t *port, ftun_packet_port_info_t *out);
ftun_status_t ftun_platform_tun_read(ftun_platform_tun_t *port,
  void *buffer, size_t capacity, size_t *length);
ftun_status_t ftun_platform_tun_write(ftun_platform_tun_t *port, const void *packet, size_t length);
ftun_status_t ftun_platform_tun_close(ftun_platform_tun_t *port);

#endif
