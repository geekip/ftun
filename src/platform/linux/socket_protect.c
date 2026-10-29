#define _GNU_SOURCE 1
#include "platform/linux/socket_protect.h"
#include <limits.h>
#include <stdint.h>
#include <string.h>

#ifdef __linux__
#include <errno.h>
#include <net/if.h>
#include <sys/socket.h>

#if IFNAMSIZ != FTUN_LINUX_SOCKET_DEVICE_BYTES
#error "FTUN Linux socket device size must match IFNAMSIZ"
#endif
#endif

static int ftun_socket_device_valid(ftun_string_t name)
{
  size_t index;
  if (name.length == 0u) return 1;
  if (name.data == NULL || name.length >= FTUN_LINUX_SOCKET_DEVICE_BYTES) return 0;
  if ((name.length == 1u && name.data[0] == '.') ||
      (name.length == 2u && name.data[0] == '.' && name.data[1] == '.')) return 0;
  for (index = 0u; index < name.length; index++) {
    unsigned char value = (unsigned char)name.data[index];
    if (value <= (unsigned char)' ' || value == (unsigned char)'/' ||
        value == (unsigned char)':') return 0;
  }
  return 1;
}

static int ftun_socket_io_valid(const ftun_linux_socket_io_t *io)
{
  return io != NULL && io->get_mark != NULL && io->set_mark != NULL &&
         io->get_device != NULL && io->set_device != NULL;
}

static ftun_status_t ftun_socket_rollback(const ftun_linux_socket_io_t *io,
                                          int descriptor, bool mark_changed,
                                          uint32_t old_mark,
                                          bool device_changed,
                                          const char *old_device)
{
  ftun_status_t result = FTUN_OK;
  if (mark_changed && io->set_mark(io->context, descriptor, old_mark) != FTUN_OK) {
    result = FTUN_E_STATE_CORRUPT;
  }
  if (device_changed &&
      io->set_device(io->context, descriptor, old_device) != FTUN_OK) {
    result = FTUN_E_STATE_CORRUPT;
  }
  return result;
}

/* 物理 socket 保护。 */
ftun_status_t ftun_linux_socket_protect_with_io(
  ftun_native_socket_t socket, const ftun_socket_policy_t *policy,
  const ftun_linux_socket_io_t *io)
{
  char old_device[FTUN_LINUX_SOCKET_DEVICE_BYTES];
  char requested_device[FTUN_LINUX_SOCKET_DEVICE_BYTES];
  char verify_device[FTUN_LINUX_SOCKET_DEVICE_BYTES];
  uint32_t old_mark = 0u;
  uint32_t verify_mark = 0u;
  int descriptor;
  bool device_changed = false;
  bool mark_changed = false;
  ftun_status_t status;
  if (socket > (ftun_native_socket_t)INT_MAX || policy == NULL ||
      policy->mark == 0u || !ftun_socket_device_valid(policy->interface_name) ||
      !ftun_socket_io_valid(io)) return FTUN_E_INVALID;
  descriptor = (int)socket;
  memset(old_device, 0, sizeof(old_device));
  memset(requested_device, 0, sizeof(requested_device));
  if (policy->interface_name.length != 0u) {
    memcpy(requested_device, policy->interface_name.data,
           policy->interface_name.length);
  }
  status = io->get_device(io->context, descriptor, old_device);
  if (status != FTUN_OK) return status;
  old_device[sizeof(old_device) - 1u] = '\0';
  status = io->get_mark(io->context, descriptor, &old_mark);
  if (status != FTUN_OK) return status;
  if (requested_device[0] != '\0' && old_device[0] != '\0' &&
      strcmp(requested_device, old_device) != 0) return FTUN_E_REJECTED;
  if (old_mark != 0u && old_mark != policy->mark) return FTUN_E_REJECTED;

  if (requested_device[0] != '\0' && old_device[0] == '\0') {
    status = io->set_device(io->context, descriptor, requested_device);
    if (status != FTUN_OK) return status;
    device_changed = true;
  }
  if (old_mark == 0u) {
    status = io->set_mark(io->context, descriptor, policy->mark);
    if (status != FTUN_OK) {
      if (ftun_socket_rollback(io, descriptor, false, old_mark,
                               device_changed, old_device) != FTUN_OK) {
        return FTUN_E_STATE_CORRUPT;
      }
      return status;
    }
    mark_changed = true;
  }
  memset(verify_device, 0, sizeof(verify_device));
  status = io->get_device(io->context, descriptor, verify_device);
  if (status == FTUN_OK) status = io->get_mark(io->context, descriptor, &verify_mark);
  if (status == FTUN_OK &&
      ((requested_device[0] != '\0' &&
        strcmp(requested_device, verify_device) != 0) ||
       verify_mark != policy->mark)) status = FTUN_E_STATE_CORRUPT;
  if (status != FTUN_OK) {
    if (ftun_socket_rollback(io, descriptor, mark_changed, old_mark,
                             device_changed, old_device) != FTUN_OK) {
      return FTUN_E_STATE_CORRUPT;
    }
    return status;
  }
  return FTUN_OK;
}

#ifdef __linux__
static ftun_status_t ftun_socket_errno(int error_code)
{
  if (error_code == EACCES || error_code == EPERM) return FTUN_E_REJECTED;
  if (error_code == ENOMEM || error_code == ENOBUFS || error_code == EMFILE ||
      error_code == ENFILE) return FTUN_E_LIMIT;
  if (error_code == ENOPROTOOPT || error_code == EOPNOTSUPP ||
      error_code == ENOSYS || error_code == ENODEV) return FTUN_E_UNSUPPORTED;
  if (error_code == EBADF || error_code == ENOTSOCK || error_code == EINVAL) {
    return FTUN_E_INVALID;
  }
  return FTUN_E_IO;
}

static ftun_status_t ftun_system_get_mark(void *context, int descriptor,
                                          uint32_t *out)
{
  socklen_t length = (socklen_t)sizeof(*out);
  (void)context;
  *out = 0u;
  if (getsockopt(descriptor, SOL_SOCKET, SO_MARK, out, &length) < 0) {
    return ftun_socket_errno(errno);
  }
  return length == (socklen_t)sizeof(*out) ? FTUN_OK : FTUN_E_IO;
}

static ftun_status_t ftun_system_set_mark(void *context, int descriptor,
                                          uint32_t mark)
{
  (void)context;
  if (setsockopt(descriptor, SOL_SOCKET, SO_MARK, &mark,
                 (socklen_t)sizeof(mark)) < 0) return ftun_socket_errno(errno);
  return FTUN_OK;
}

static ftun_status_t ftun_system_get_device(
  void *context, int descriptor, char out[FTUN_LINUX_SOCKET_DEVICE_BYTES])
{
  socklen_t length = (socklen_t)FTUN_LINUX_SOCKET_DEVICE_BYTES;
  (void)context;
  memset(out, 0, FTUN_LINUX_SOCKET_DEVICE_BYTES);
  if (getsockopt(descriptor, SOL_SOCKET, SO_BINDTODEVICE, out, &length) < 0) {
    return ftun_socket_errno(errno);
  }
  if (length > (socklen_t)FTUN_LINUX_SOCKET_DEVICE_BYTES) return FTUN_E_IO;
  out[FTUN_LINUX_SOCKET_DEVICE_BYTES - 1u] = '\0';
  return FTUN_OK;
}

static ftun_status_t ftun_system_set_device(void *context, int descriptor,
                                            const char *interface_name)
{
  socklen_t length;
  (void)context;
  length = interface_name[0] == '\0' ? 0u :
           (socklen_t)(strlen(interface_name) + 1u);
  if (setsockopt(descriptor, SOL_SOCKET, SO_BINDTODEVICE, interface_name,
                 length) < 0) return ftun_socket_errno(errno);
  return FTUN_OK;
}

static const ftun_linux_socket_io_t ftun_system_socket_io = {
  ftun_system_get_mark,
  ftun_system_set_mark,
  ftun_system_get_device,
  ftun_system_set_device,
  NULL
};
#endif

ftun_status_t ftun_linux_socket_protect(ftun_native_socket_t socket,
                                        const ftun_socket_policy_t *policy)
{
#ifdef __linux__
  return ftun_linux_socket_protect_with_io(socket, policy,
                                           &ftun_system_socket_io);
#else
  (void)socket;
  (void)policy;
  return FTUN_E_UNSUPPORTED;
#endif
}
