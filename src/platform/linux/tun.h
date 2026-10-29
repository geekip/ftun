#ifndef FTUN_PLATFORM_LINUX_TUN_H
#define FTUN_PLATFORM_LINUX_TUN_H
#include "platform/tun.h"
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
  int descriptor;
  uint32_t mtu;
  char name[FTUN_LINUX_TUN_NAME_BYTES];
  ftun_linux_tun_io_t io;
} ftun_platform_tun_t;
/* 设备存储由调用方准入并拥有；open 失败不交付 FD，不做堆分配。 */
const ftun_linux_tun_io_t *ftun_platform_tun_default_io(void);
bool ftun_platform_tun_spec_valid(const ftun_tun_spec_t *spec, const ftun_linux_tun_io_t *io);
ftun_status_t ftun_platform_tun_open(const ftun_tun_spec_t *spec,
  const ftun_linux_tun_io_t *io, ftun_platform_tun_t *port);
ftun_status_t ftun_platform_tun_read(ftun_platform_tun_t *port,
  void *buffer, size_t capacity, size_t *length);
ftun_status_t ftun_platform_tun_write(ftun_platform_tun_t *port, const void *packet, size_t length);
ftun_status_t ftun_platform_tun_close(ftun_platform_tun_t *port);
#endif
