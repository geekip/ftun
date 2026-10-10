#define _GNU_SOURCE 1
#include "tun.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define FTUN_LINUX_TUN_MAGIC UINT32_C(0x4654544e)
#define FTUN_LINUX_TUN_PATH "/dev/net/tun"

#if IFNAMSIZ != FTUN_LINUX_TUN_NAME_BYTES
#error "FTUN Linux TUN name size must match IFNAMSIZ"
#endif

struct ftun_packet_port {
  uint32_t magic;
  int descriptor;
  uint32_t mtu;
  char name[FTUN_LINUX_TUN_NAME_BYTES];
  ftun_linux_tun_io_t io;
};

static int ftun_system_open_device(void *context, const char *path, int flags,
                                   int *error_code)
{
  int result;
  (void)context;
  result = open(path, flags);
  if (result < 0 && error_code != NULL) *error_code = errno;
  return result;
}

static int ftun_system_open_control(void *context, int domain, int type,
                                    int protocol, int *error_code)
{
  int result;
  (void)context;
  result = socket(domain, type, protocol);
  if (result < 0 && error_code != NULL) *error_code = errno;
  return result;
}

static int ftun_system_ioctl(void *context, int descriptor,
                             unsigned long request, void *argument,
                             int *error_code)
{
  int result;
  (void)context;
  result = ioctl(descriptor, request, argument);
  if (result < 0 && error_code != NULL) *error_code = errno;
  return result;
}

static ptrdiff_t ftun_system_read(void *context, int descriptor, void *buffer,
                                  size_t capacity, int *error_code)
{
  ssize_t result;
  (void)context;
  result = read(descriptor, buffer, capacity);
  if (result < 0 && error_code != NULL) *error_code = errno;
  return (ptrdiff_t)result;
}

static ptrdiff_t ftun_system_write(void *context, int descriptor,
                                   const void *packet, size_t length,
                                   int *error_code)
{
  ssize_t result;
  (void)context;
  result = write(descriptor, packet, length);
  if (result < 0 && error_code != NULL) *error_code = errno;
  return (ptrdiff_t)result;
}

static int ftun_system_close(void *context, int descriptor, int *error_code)
{
  int result;
  (void)context;
  result = close(descriptor);
  if (result < 0 && error_code != NULL) *error_code = errno;
  return result;
}

static const ftun_linux_tun_io_t ftun_system_io = {
  ftun_system_open_device,
  ftun_system_open_control,
  ftun_system_ioctl,
  ftun_system_read,
  ftun_system_write,
  ftun_system_close,
  NULL
};

static ftun_status_t ftun_linux_error_status(int error_code)
{
  if (error_code == EACCES || error_code == EPERM) return FTUN_E_REJECTED;
  if (error_code == EAGAIN || error_code == EWOULDBLOCK) return FTUN_E_AGAIN;
  if (error_code == ENOMEM || error_code == ENOBUFS || error_code == EMFILE ||
      error_code == ENFILE) return FTUN_E_LIMIT;
  if (error_code == ENOSYS || error_code == ENOTTY || error_code == ENOENT ||
      error_code == EOPNOTSUPP || error_code == ENODEV) {
    return FTUN_E_UNSUPPORTED;
  }
  return FTUN_E_IO;
}

static int ftun_linux_tun_io_valid(const ftun_linux_tun_io_t *io)
{
  return io != NULL && io->open_device != NULL && io->open_control != NULL &&
         io->ioctl_call != NULL && io->read_call != NULL &&
         io->write_call != NULL && io->close_call != NULL;
}

static int ftun_linux_tun_name_valid(ftun_string_t name)
{
  size_t index;
  if (name.data == NULL || name.length == 0u ||
      name.length >= FTUN_LINUX_TUN_NAME_BYTES) return 0;
  if ((name.length == 1u && name.data[0] == '.') ||
      (name.length == 2u && name.data[0] == '.' && name.data[1] == '.')) return 0;
  for (index = 0u; index < name.length; index++) {
    unsigned char value = (unsigned char)name.data[index];
    if (value <= (unsigned char)' ' || value == (unsigned char)'/' ||
        value == (unsigned char)':') return 0;
  }
  return 1;
}

static int ftun_linux_open_device(const ftun_linux_tun_io_t *io,
                                  const char *path, int flags,
                                  int *error_code)
{
  int result;
  do {
    *error_code = 0;
    result = io->open_device(io->context, path, flags, error_code);
  } while (result < 0 && *error_code == EINTR);
  return result;
}

static int ftun_linux_open_control(const ftun_linux_tun_io_t *io,
                                   int *error_code)
{
  int result;
  do {
    *error_code = 0;
    result = io->open_control(io->context, AF_INET,
                              SOCK_DGRAM | SOCK_CLOEXEC, 0, error_code);
  } while (result < 0 && *error_code == EINTR);
  return result;
}

static int ftun_linux_ioctl(const ftun_linux_tun_io_t *io, int descriptor,
                            unsigned long request, void *argument,
                            int *error_code)
{
  int result;
  do {
    *error_code = 0;
    result = io->ioctl_call(io->context, descriptor, request, argument,
                            error_code);
  } while (result < 0 && *error_code == EINTR);
  return result;
}

static void ftun_linux_close_ignored(const ftun_linux_tun_io_t *io,
                                     int descriptor)
{
  int ignored = 0;
  if (descriptor >= 0) (void)io->close_call(io->context, descriptor, &ignored);
}

static void ftun_linux_ifreq_name(struct ifreq *request, const char *name)
{
  memset(request, 0, sizeof(*request));
  memcpy(request->ifr_name, name, strlen(name) + 1u);
}

/* TASK-PLATFORM-001 / TEST-PLATFORM-001，目标 0.2.0：独占非阻塞 TUN 及失败回滚。 */
ftun_status_t ftun_linux_tun_open_with_io(const ftun_tun_spec_t *spec,
                                          const ftun_linux_tun_io_t *io,
                                          ftun_packet_port_t **out)
{
  ftun_packet_port_t *port;
  struct ifreq request;
  int error_code = 0;
  int control = -1;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (spec == NULL || out == NULL || !ftun_linux_tun_io_valid(io) ||
      !ftun_linux_tun_name_valid(spec->name) ||
      spec->mtu < FTUN_LINUX_TUN_MIN_MTU ||
      spec->mtu > FTUN_LINUX_TUN_MAX_MTU) return FTUN_E_INVALID;
  port = (ftun_packet_port_t *)calloc(1u, sizeof(*port));
  if (port == NULL) return FTUN_E_LIMIT;
  port->io = *io;
  port->descriptor = ftun_linux_open_device(
    &port->io, FTUN_LINUX_TUN_PATH, O_RDWR | O_NONBLOCK | O_CLOEXEC,
    &error_code);
  if (port->descriptor < 0) {
    status = ftun_linux_error_status(error_code);
    free(port);
    return status;
  }
  memcpy(port->name, spec->name.data, spec->name.length);
  port->name[spec->name.length] = '\0';
  ftun_linux_ifreq_name(&request, port->name);
  request.ifr_flags = (short)(IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL);
  if (ftun_linux_ioctl(&port->io, port->descriptor, TUNSETIFF, &request,
                       &error_code) < 0) {
    status = ftun_linux_error_status(error_code);
    ftun_linux_close_ignored(&port->io, port->descriptor);
    free(port);
    return status;
  }
  request.ifr_name[IFNAMSIZ - 1u] = '\0';
  memcpy(port->name, request.ifr_name, sizeof(port->name));
  port->name[sizeof(port->name) - 1u] = '\0';
  control = ftun_linux_open_control(&port->io, &error_code);
  if (control < 0) {
    status = ftun_linux_error_status(error_code);
    ftun_linux_close_ignored(&port->io, port->descriptor);
    free(port);
    return status;
  }
  ftun_linux_ifreq_name(&request, port->name);
  request.ifr_mtu = (int)spec->mtu;
  if (ftun_linux_ioctl(&port->io, control, SIOCSIFMTU, &request,
                       &error_code) < 0) {
    status = ftun_linux_error_status(error_code);
    ftun_linux_close_ignored(&port->io, control);
    ftun_linux_close_ignored(&port->io, port->descriptor);
    free(port);
    return status;
  }
  ftun_linux_ifreq_name(&request, port->name);
  if (ftun_linux_ioctl(&port->io, control, SIOCGIFFLAGS, &request,
                       &error_code) < 0) {
    status = ftun_linux_error_status(error_code);
    ftun_linux_close_ignored(&port->io, control);
    ftun_linux_close_ignored(&port->io, port->descriptor);
    free(port);
    return status;
  }
  request.ifr_flags = (short)(request.ifr_flags | (short)IFF_UP);
  if (ftun_linux_ioctl(&port->io, control, SIOCSIFFLAGS, &request,
                       &error_code) < 0) {
    status = ftun_linux_error_status(error_code);
    ftun_linux_close_ignored(&port->io, control);
    ftun_linux_close_ignored(&port->io, port->descriptor);
    free(port);
    return status;
  }
  if (port->io.close_call(port->io.context, control, &error_code) < 0) {
    status = ftun_linux_error_status(error_code);
    ftun_linux_close_ignored(&port->io, port->descriptor);
    free(port);
    return status;
  }
  port->magic = FTUN_LINUX_TUN_MAGIC;
  port->mtu = spec->mtu;
  *out = port;
  return FTUN_OK;
}

ftun_status_t ftun_linux_tun_open(const ftun_tun_spec_t *spec,
                                  ftun_packet_port_t **out)
{
  return ftun_linux_tun_open_with_io(spec, &ftun_system_io, out);
}

ftun_status_t ftun_linux_tun_get_info(const ftun_packet_port_t *port,
                                      ftun_linux_tun_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (port == NULL || port->magic != FTUN_LINUX_TUN_MAGIC || out == NULL) {
    return FTUN_E_INVALID;
  }
  memcpy(out->name, port->name, sizeof(out->name));
  out->mtu = port->mtu;
  out->descriptor = port->descriptor;
  return FTUN_OK;
}

ftun_status_t ftun_linux_tun_read(ftun_packet_port_t *port, void *buffer,
                                  size_t capacity, size_t *out_length)
{
  ptrdiff_t result;
  int error_code;
  if (out_length != NULL) *out_length = 0u;
  if (port == NULL || port->magic != FTUN_LINUX_TUN_MAGIC || buffer == NULL ||
      out_length == NULL) return FTUN_E_INVALID;
  if (capacity < (size_t)port->mtu) return FTUN_E_LIMIT;
  if (capacity > (size_t)PTRDIFF_MAX) return FTUN_E_LIMIT;
  do {
    error_code = 0;
    result = port->io.read_call(port->io.context, port->descriptor, buffer,
                                capacity, &error_code);
  } while (result < 0 && error_code == EINTR);
  if (result < 0) return ftun_linux_error_status(error_code);
  if (result == 0) return FTUN_E_EOF;
  if ((size_t)result > capacity || (size_t)result > (size_t)port->mtu) {
    return FTUN_E_PROTOCOL;
  }
  *out_length = (size_t)result;
  return FTUN_OK;
}

ftun_status_t ftun_linux_tun_write(ftun_packet_port_t *port,
                                   const void *packet, size_t length)
{
  ptrdiff_t result;
  int error_code;
  if (port == NULL || port->magic != FTUN_LINUX_TUN_MAGIC || packet == NULL ||
      length == 0u) return FTUN_E_INVALID;
  if (length > (size_t)port->mtu) return FTUN_E_LIMIT;
  do {
    error_code = 0;
    result = port->io.write_call(port->io.context, port->descriptor, packet,
                                 length, &error_code);
  } while (result < 0 && error_code == EINTR);
  if (result < 0) return ftun_linux_error_status(error_code);
  if ((size_t)result != length) return FTUN_E_IO;
  return FTUN_OK;
}

ftun_status_t ftun_linux_tun_close(ftun_packet_port_t **port)
{
  ftun_packet_port_t *owned;
  int error_code = 0;
  int result;
  if (port == NULL) return FTUN_E_INVALID;
  owned = *port;
  if (owned == NULL) return FTUN_OK;
  if (owned->magic != FTUN_LINUX_TUN_MAGIC || owned->io.close_call == NULL) {
    return FTUN_E_INVALID;
  }
  result = owned->io.close_call(owned->io.context, owned->descriptor,
                                &error_code);
  owned->magic = 0u;
  owned->descriptor = -1;
  memset(&owned->io, 0, sizeof(owned->io));
  free(owned);
  *port = NULL;
  return result < 0 ? ftun_linux_error_status(error_code) : FTUN_OK;
}
