#include "libs/tun/linux/device.h"
#include "core/limits.h"
#include <stdlib.h>
#include <string.h>
#define FTUN_LINUX_TUN_MAGIC UINT32_C(0x4654544e)
struct ftun_packet_port {
  uint32_t magic;
  ftun_platform_tun_t device;
  ftun_reservation_t reservation;
};
ftun_status_t ftun_linux_tun_open_with_io_and_budget(ftun_budget_t *budget,
  const ftun_tun_spec_t *spec, const ftun_linux_tun_io_t *io, ftun_packet_port_t **out)
{
  ftun_packet_port_t *port;
  ftun_reservation_t reservation = (ftun_reservation_t){0}, control = (ftun_reservation_t){0};
  ftun_status_t status = FTUN_OK;
  if (out != NULL) *out = NULL;
  if (out == NULL || !ftun_platform_tun_spec_valid(spec, io)) return FTUN_E_INVALID;
  if (budget != NULL) {
    status = ftun_budget_reserve_resources(budget,
      (ftun_budget_resources_t){sizeof(*port), 1u, 0u}, &reservation);
    if (status == FTUN_OK) status = ftun_budget_reserve_resources(budget,
      (ftun_budget_resources_t){0u, 1u, 0u}, &control);
  }
  if (status != FTUN_OK) { (void)ftun_reservation_release(&reservation); return status; }
  port = calloc(1u, sizeof(*port));
  if (port == NULL) status = FTUN_E_LIMIT;
  else status = ftun_platform_tun_open(spec, io, &port->device);
  (void)ftun_reservation_release(&control);
  if (status != FTUN_OK) {
    free(port);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  port->magic = FTUN_LINUX_TUN_MAGIC;
  port->reservation = reservation;
  *out = port;
  return FTUN_OK;
}
ftun_status_t ftun_linux_tun_open_with_io(const ftun_tun_spec_t *spec,
  const ftun_linux_tun_io_t *io, ftun_packet_port_t **out)
{
  return ftun_linux_tun_open_with_io_and_budget(NULL, spec, io, out);
}
ftun_status_t ftun_linux_tun_open_with_budget(ftun_budget_t *budget,
  const ftun_tun_spec_t *spec, ftun_packet_port_t **out)
{
  return ftun_linux_tun_open_with_io_and_budget(budget, spec, ftun_platform_tun_default_io(), out);
}
ftun_status_t ftun_linux_tun_open(const ftun_tun_spec_t *spec, ftun_packet_port_t **out)
{
  return ftun_linux_tun_open_with_budget(NULL, spec, out);
}
ftun_status_t ftun_linux_tun_get_info(const ftun_packet_port_t *port, ftun_linux_tun_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (port == NULL || port->magic != FTUN_LINUX_TUN_MAGIC || out == NULL) return FTUN_E_INVALID;
  memcpy(out->name, port->device.name, sizeof(out->name));
  out->mtu = port->device.mtu;
  out->descriptor = port->device.descriptor;
  return FTUN_OK;
}
ftun_status_t ftun_linux_tun_read(ftun_packet_port_t *port,
  void *buffer, size_t capacity, size_t *out_length)
{
  if (out_length != NULL) *out_length = 0u;
  if (port == NULL || port->magic != FTUN_LINUX_TUN_MAGIC) return FTUN_E_INVALID;
  return ftun_platform_tun_read(&port->device, buffer, capacity, out_length);
}
ftun_status_t ftun_linux_tun_write(ftun_packet_port_t *port, const void *packet, size_t length)
{
  if (port == NULL || port->magic != FTUN_LINUX_TUN_MAGIC) return FTUN_E_INVALID;
  return ftun_platform_tun_write(&port->device, packet, length);
}
ftun_status_t ftun_linux_tun_close(ftun_packet_port_t **port)
{
  ftun_packet_port_t *owned;
  ftun_reservation_t reservation;
  ftun_status_t status;
  if (port == NULL) return FTUN_E_INVALID;
  owned = *port;
  if (owned == NULL) return FTUN_OK;
  if (owned->magic != FTUN_LINUX_TUN_MAGIC) return FTUN_E_INVALID;
  status = ftun_platform_tun_close(&owned->device);
  owned->magic = 0u;
  reservation = owned->reservation;
  free(owned);
  (void)ftun_reservation_release(&reservation);
  *port = NULL;
  return status;
}
