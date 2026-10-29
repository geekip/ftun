#ifndef FTUN_PLATFORM_TUN_H
#define FTUN_PLATFORM_TUN_H
#include "util/types.h"
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

#endif
