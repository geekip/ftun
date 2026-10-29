#define _GNU_SOURCE 1
#include "libs/tun/linux/device.h"
#include "platform/linux/uapi.h"
#include "libs/tun/device.h"
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "packet port contract failed: %s\n", #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  int ioctl_calls;
  int closes;
  int read_error;
  int write_error;
  uint8_t packet[128];
  size_t packet_length;
} port_mock_t;

static int mock_open_device(void *context, const char *path, int flags,
                            int *error_code)
{
  (void)context;
  (void)error_code;
  return strcmp(path, "/dev/net/tun") == 0 &&
         (flags & (O_RDWR | O_NONBLOCK | O_CLOEXEC)) ==
         (O_RDWR | O_NONBLOCK | O_CLOEXEC) ? 31 : -1;
}

static int mock_open_control(void *context, int domain, int type, int protocol,
                             int *error_code)
{
  (void)context;
  (void)protocol;
  (void)error_code;
  return domain == AF_INET && (type & SOCK_DGRAM) != 0 ? 32 : -1;
}

static int mock_ioctl(void *context, int descriptor, unsigned long request,
                      void *argument, int *error_code)
{
  port_mock_t *mock = (port_mock_t *)context;
  struct ifreq *interface_request = (struct ifreq *)argument;
  (void)descriptor;
  (void)error_code;
  mock->ioctl_calls++;
  if (request == FTUN_TUNSETIFF) return 0;
  if (request == SIOCSIFMTU) return interface_request->ifr_mtu == 128 ? 0 : -1;
  if (request == SIOCGIFFLAGS) {
    interface_request->ifr_flags = 0;
    return 0;
  }
  if (request == SIOCSIFFLAGS) {
    return (interface_request->ifr_flags & IFF_UP) != 0 ? 0 : -1;
  }
  return -1;
}

static ptrdiff_t mock_read(void *context, int descriptor, void *buffer,
                           size_t capacity, int *error_code)
{
  port_mock_t *mock = (port_mock_t *)context;
  (void)descriptor;
  if (mock->read_error != 0) {
    *error_code = mock->read_error;
    return -1;
  }
  if (mock->packet_length > capacity) return -1;
  memcpy(buffer, mock->packet, mock->packet_length);
  return (ptrdiff_t)mock->packet_length;
}

static ptrdiff_t mock_write(void *context, int descriptor, const void *packet,
                            size_t length, int *error_code)
{
  port_mock_t *mock = (port_mock_t *)context;
  (void)descriptor;
  if (mock->write_error != 0) {
    *error_code = mock->write_error;
    return -1;
  }
  memcpy(mock->packet, packet, length);
  mock->packet_length = length;
  return (ptrdiff_t)length;
}

static int mock_close(void *context, int descriptor, int *error_code)
{
  port_mock_t *mock = (port_mock_t *)context;
  (void)descriptor;
  (void)error_code;
  mock->closes++;
  return 0;
}

static int real_smoke(void)
{
  ftun_tun_spec_t spec;
  ftun_packet_port_t *port = NULL;
  ftun_packet_port_info_t info;
  spec.name.data = "ftun-port0";
  spec.name.length = strlen(spec.name.data);
  spec.mtu = 1400u;
  CHECK(ftun_packet_port_open(NULL, &spec, &port) == FTUN_OK && port != NULL);
  CHECK(ftun_packet_port_get_info(port, &info) == FTUN_OK);
  CHECK(strcmp(info.name, "ftun-port0") == 0 && info.mtu == 1400u &&
        info.native_socket != 0u);
  CHECK(ftun_packet_port_close(&port) == FTUN_OK && port == NULL);
  return 0;
}

/* 平台委托、MTU、整包和关闭。 */
int main(int argc, char **argv)
{
  port_mock_t mock;
  ftun_linux_tun_io_t io;
  ftun_tun_spec_t spec;
  ftun_packet_port_t *port = NULL;
  ftun_packet_port_info_t info;
  uint8_t packet[128];
  size_t length = 99u;

  if (argc == 2 && strcmp(argv[1], "--real") == 0) return real_smoke();
  CHECK(argc == 1);
  memset(&mock, 0, sizeof(mock));
  io.open_device = mock_open_device;
  io.open_control = mock_open_control;
  io.ioctl_call = mock_ioctl;
  io.read_call = mock_read;
  io.write_call = mock_write;
  io.close_call = mock_close;
  io.context = &mock;
  spec.name.data = "ftun0";
  spec.name.length = strlen(spec.name.data);
  spec.mtu = 128u;
  CHECK(ftun_linux_tun_open_with_io(&spec, &io, &port) == FTUN_OK && port != NULL);
  CHECK(mock.ioctl_calls == 4 && mock.closes == 1);
  CHECK(ftun_packet_port_get_info(port, &info) == FTUN_OK);
  CHECK(strcmp(info.name, "ftun0") == 0 && info.mtu == 128u &&
        info.native_socket == 31u);
  memset(mock.packet, 0x45, 20u);
  mock.packet_length = 20u;
  CHECK(ftun_packet_port_read(port, packet, sizeof(packet), &length) == FTUN_OK &&
        length == 20u && packet[0] == 0x45u);
  CHECK(ftun_packet_port_read(port, packet, sizeof(packet) - 1u, &length) ==
        FTUN_E_LIMIT && length == 0u);
  mock.read_error = EAGAIN;
  CHECK(ftun_packet_port_read(port, packet, sizeof(packet), &length) ==
        FTUN_E_AGAIN && length == 0u);
  mock.read_error = 0;
  memset(packet, 0x5a, 32u);
  CHECK(ftun_packet_port_write(port, packet, 32u) == FTUN_OK &&
        mock.packet_length == 32u && mock.packet[0] == 0x5au);
  mock.write_error = EAGAIN;
  CHECK(ftun_packet_port_write(port, packet, 32u) == FTUN_E_AGAIN);
  CHECK(ftun_packet_port_close(&port) == FTUN_OK && port == NULL);
  CHECK(mock.closes == 2);
  CHECK(ftun_packet_port_close(&port) == FTUN_OK);

  memset(&info, 0x7f, sizeof(info));
  CHECK(ftun_packet_port_get_info(NULL, &info) == FTUN_E_INVALID);
  CHECK(info.name[0] == '\0' && info.mtu == 0u && info.native_socket == 0u);
  CHECK(ftun_packet_port_read(NULL, packet, sizeof(packet), &length) ==
        FTUN_E_INVALID && length == 0u);
  CHECK(ftun_packet_port_write(NULL, packet, 1u) == FTUN_E_INVALID);
  CHECK(ftun_packet_port_close(NULL) == FTUN_E_INVALID);
  spec.mtu = 1u;
  CHECK(ftun_packet_port_open(NULL, &spec, &port) == FTUN_E_INVALID && port == NULL);
  CHECK(ftun_packet_port_open(NULL, &spec, NULL) == FTUN_E_INVALID);
  return 0;
}
