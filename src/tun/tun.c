#include "tun.h"
#include "platform/linux/tun.h"
#include <stdint.h>
#include <string.h>

/* TASK-TUN-001 / TEST-TUN-001，目标 0.2.0：平台无关整包端口。 */
ftun_status_t ftun_packet_port_open(ftun_core_t *core,
                                    const ftun_tun_spec_t *spec,
                                    ftun_packet_port_t **out)
{
  (void)core;
  return ftun_linux_tun_open(spec, out);
}

ftun_status_t ftun_packet_port_get_info(const ftun_packet_port_t *port,
                                        ftun_packet_port_info_t *out)
{
  ftun_linux_tun_info_t linux_info;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (out == NULL) return FTUN_E_INVALID;
  status = ftun_linux_tun_get_info(port, &linux_info);
  if (status != FTUN_OK) return status;
  memcpy(out->name, linux_info.name, sizeof(out->name));
  out->mtu = linux_info.mtu;
  out->native_socket = (ftun_native_socket_t)(unsigned int)linux_info.descriptor;
  return FTUN_OK;
}

ftun_status_t ftun_packet_port_read(ftun_packet_port_t *port, void *buffer,
                                    size_t capacity, size_t *out_length)
{
  return ftun_linux_tun_read(port, buffer, capacity, out_length);
}

ftun_status_t ftun_packet_port_write(ftun_packet_port_t *port,
                                     const void *packet, size_t length)
{
  return ftun_linux_tun_write(port, packet, length);
}

ftun_status_t ftun_packet_port_close(ftun_packet_port_t **port)
{
  return ftun_linux_tun_close(port);
}
