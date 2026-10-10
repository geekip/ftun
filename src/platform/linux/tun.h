#ifndef FTUN_PLATFORM_LINUX_TUN_H
#define FTUN_PLATFORM_LINUX_TUN_H
#include "tun/tun.h"

#define FTUN_LINUX_TUN_NAME_BYTES FTUN_PACKET_PORT_NAME_BYTES
#define FTUN_LINUX_TUN_MIN_MTU 68u
#define FTUN_LINUX_TUN_MAX_MTU 65535u

typedef struct {
  int (*open_device)(void *context, const char *path, int flags, int *error_code);
  int (*open_control)(void *context, int domain, int type, int protocol,
                      int *error_code);
  int (*ioctl_call)(void *context, int descriptor, unsigned long request,
                    void *argument, int *error_code);
  ptrdiff_t (*read_call)(void *context, int descriptor, void *buffer,
                         size_t capacity, int *error_code);
  ptrdiff_t (*write_call)(void *context, int descriptor, const void *packet,
                          size_t length, int *error_code);
  int (*close_call)(void *context, int descriptor, int *error_code);
  void *context;
} ftun_linux_tun_io_t;

typedef struct {
  char name[FTUN_LINUX_TUN_NAME_BYTES];
  uint32_t mtu;
  int descriptor;
} ftun_linux_tun_info_t;

/* Linux TUN 设备。
 * 需求 REQ-PLAT-001；任务 TASK-PLATFORM-001；目标 0.2.0；验收 TEST-PLATFORM-001。
 * 实现路径：显式权限检查和非阻塞设备接入；处理 MTU、整包边界和关闭；初版不宣称支持未实现的 offload。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * spec 仅在调用期间借用；成功后 port 独占 fd，必须由 close 终结。
 * port 只由 owner loop 使用；每次 read/write 对应一个无 PI 的三层包。
 */
ftun_status_t ftun_linux_tun_open(const ftun_tun_spec_t *spec, ftun_packet_port_t **out);
/* 测试与受控宿主注入；操作表会复制，context 必须比 port 长寿。 */
ftun_status_t ftun_linux_tun_open_with_io(const ftun_tun_spec_t *spec,
                                          const ftun_linux_tun_io_t *io,
                                          ftun_packet_port_t **out);
ftun_status_t ftun_linux_tun_get_info(const ftun_packet_port_t *port,
                                      ftun_linux_tun_info_t *out);
/* capacity 至少为配置 MTU，避免 Linux TUN 截断并丢弃包尾。 */
ftun_status_t ftun_linux_tun_read(ftun_packet_port_t *port, void *buffer,
                                  size_t capacity, size_t *out_length);
ftun_status_t ftun_linux_tun_write(ftun_packet_port_t *port, const void *packet,
                                   size_t length);
/* close 即使底层报告错误也消费句柄；Linux close 不可安全重试。 */
ftun_status_t ftun_linux_tun_close(ftun_packet_port_t **port);
#endif
