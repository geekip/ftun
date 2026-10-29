#ifndef FTUN_PLATFORM_LINUX_TUN_H
#define FTUN_PLATFORM_LINUX_TUN_H
#include "platform/tun.h"
#define FTUN_LINUX_TUN_NAME_BYTES FTUN_PACKET_PORT_NAME_BYTES
#define FTUN_LINUX_TUN_MIN_MTU 68u
#define FTUN_LINUX_TUN_MAX_MTU 65535u
struct ftun_platform_tun_io {
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
};
struct ftun_platform_tun {
  int descriptor;
  uint32_t mtu;
  char name[FTUN_LINUX_TUN_NAME_BYTES];
  ftun_platform_tun_io_t io;
};
#endif
