#define _GNU_SOURCE 1
#include "platform/linux/tun.h"
#include "platform/linux/uapi.h"
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#define FTUN_LINUX_TUN_PATH "/dev/net/tun"
#if IFNAMSIZ != FTUN_LINUX_TUN_NAME_BYTES
#error "FTUN Linux TUN name size must match IFNAMSIZ"
#endif
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

static const ftun_platform_tun_io_t ftun_system_io = {
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

static int ftun_tun_port_io_valid(const ftun_platform_tun_io_t *io)
{
  return io != NULL && io->open_device != NULL && io->open_control != NULL &&
         io->ioctl_call != NULL && io->read_call != NULL &&
         io->write_call != NULL && io->close_call != NULL;
}

static int ftun_tun_port_name_valid(ftun_string_t name)
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

static int ftun_linux_open_device(const ftun_platform_tun_io_t *io,
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

static int ftun_linux_open_control(const ftun_platform_tun_io_t *io,
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

static int ftun_linux_ioctl(const ftun_platform_tun_io_t *io, int descriptor,
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

static void ftun_linux_close_ignored(const ftun_platform_tun_io_t *io,
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

const ftun_platform_tun_io_t *ftun_platform_tun_default_io(void) { return &ftun_system_io; }
bool ftun_platform_tun_spec_valid(const ftun_tun_spec_t *spec, const ftun_platform_tun_io_t *io)
{
  return spec != NULL && ftun_tun_port_io_valid(io) && ftun_tun_port_name_valid(spec->name) &&
    spec->mtu >= FTUN_LINUX_TUN_MIN_MTU && spec->mtu <= FTUN_LINUX_TUN_MAX_MTU;
}
ftun_status_t ftun_platform_tun_open(const ftun_tun_spec_t *spec,
  const ftun_platform_tun_io_t *io, ftun_platform_tun_t *port)
{
  struct ifreq request;
  int error_code = 0, control;
  ftun_status_t status;
  port->io = *io;
  port->descriptor = ftun_linux_open_device(
    &port->io, FTUN_LINUX_TUN_PATH, O_RDWR | O_NONBLOCK | O_CLOEXEC,
    &error_code);
  if (port->descriptor < 0) {
    status = ftun_linux_error_status(error_code);
    return status;
  }
  memcpy(port->name, spec->name.data, spec->name.length);
  port->name[spec->name.length] = '\0';
  ftun_linux_ifreq_name(&request, port->name);
  request.ifr_flags = (short)(FTUN_IFF_TUN | FTUN_IFF_NO_PI |
                              FTUN_IFF_TUN_EXCL);
  if (ftun_linux_ioctl(&port->io, port->descriptor, FTUN_TUNSETIFF, &request,
                       &error_code) < 0) {
    status = ftun_linux_error_status(error_code);
    ftun_linux_close_ignored(&port->io, port->descriptor);
    return status;
  }
  request.ifr_name[IFNAMSIZ - 1u] = '\0';
  memcpy(port->name, request.ifr_name, sizeof(port->name));
  port->name[sizeof(port->name) - 1u] = '\0';
  control = ftun_linux_open_control(&port->io, &error_code);
  if (control < 0) {
    status = ftun_linux_error_status(error_code);
    ftun_linux_close_ignored(&port->io, port->descriptor);
    return status;
  }
  ftun_linux_ifreq_name(&request, port->name);
  request.ifr_mtu = (int)spec->mtu;
  if (ftun_linux_ioctl(&port->io, control, SIOCSIFMTU, &request,
                       &error_code) < 0) {
    status = ftun_linux_error_status(error_code);
    ftun_linux_close_ignored(&port->io, control);
    ftun_linux_close_ignored(&port->io, port->descriptor);
    return status;
  }
  ftun_linux_ifreq_name(&request, port->name);
  if (ftun_linux_ioctl(&port->io, control, SIOCGIFFLAGS, &request,
                       &error_code) < 0) {
    status = ftun_linux_error_status(error_code);
    ftun_linux_close_ignored(&port->io, control);
    ftun_linux_close_ignored(&port->io, port->descriptor);
    return status;
  }
  request.ifr_flags = (short)(request.ifr_flags | (short)IFF_UP);
  if (ftun_linux_ioctl(&port->io, control, SIOCSIFFLAGS, &request,
                       &error_code) < 0) {
    status = ftun_linux_error_status(error_code);
    ftun_linux_close_ignored(&port->io, control);
    ftun_linux_close_ignored(&port->io, port->descriptor);
    return status;
  }
  if (port->io.close_call(port->io.context, control, &error_code) < 0) {
    status = ftun_linux_error_status(error_code);
    ftun_linux_close_ignored(&port->io, port->descriptor);
    return status;
  }
  port->mtu = spec->mtu;
  return FTUN_OK;
}
ftun_status_t ftun_platform_tun_read(ftun_platform_tun_t *port, void *buffer,
                                  size_t capacity, size_t *out_length)
{
  ptrdiff_t result;
  int error_code;
  if (out_length != NULL) *out_length = 0u;
  if (buffer == NULL ||
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

ftun_status_t ftun_platform_tun_write(ftun_platform_tun_t *port,
                                   const void *packet, size_t length)
{
  ptrdiff_t result;
  int error_code;
  if (packet == NULL ||
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

ftun_status_t ftun_platform_tun_close(ftun_platform_tun_t *port)
{
  int error_code = 0;
  int result = port->io.close_call(port->io.context, port->descriptor, &error_code);
  port->descriptor = -1;
  memset(&port->io, 0, sizeof(port->io));
  return result < 0 ? ftun_linux_error_status(error_code) : FTUN_OK;
}

size_t ftun_platform_tun_allocation_size(void)
{
  return sizeof(ftun_platform_tun_t);
}

void ftun_platform_tun_get_info(const ftun_platform_tun_t *port, ftun_packet_port_info_t *out)
{
  memcpy(out->name, port->name, sizeof(out->name));
  out->mtu = port->mtu;
  out->native_socket = (ftun_native_socket_t)(unsigned int)port->descriptor;
}
