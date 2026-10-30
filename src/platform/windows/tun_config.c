#include "platform/windows/tun_config.h"
#include "platform/windows/tun.h"
#include <string.h>

typedef struct {
  MIB_UNICASTIPADDRESS_ROW rows[2];
  size_t count;
} address_state_t;
static const ftun_windows_tun_config_io_t system_io = {
  InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry,
  ConvertInterfaceAliasToLuid, GetIpInterfaceEntry, SetIpInterfaceEntry,
  CreateUnicastIpAddressEntry, DeleteUnicastIpAddressEntry
};
size_t ftun_platform_tun_config_size(void) { return sizeof(address_state_t); }
ftun_status_t ftun_platform_tun_configure(void *storage, const void *operations,
  ftun_string_t name, uint32_t mtu, const ftun_cidr_t *addresses, size_t count)
{
  address_state_t *state = storage;
  const ftun_windows_tun_config_io_t *io = operations == NULL ? &system_io : operations;
  WCHAR alias[FTUN_PACKET_PORT_NAME_BYTES] = {0};
  NET_LUID luid;
  DWORD error;
  if (state->count != 0u || count == 0u || count > 2u || name.length >= ARRAYSIZE(alias) ||
      mtu < 68u || mtu > 65535u) return FTUN_E_INVALID;
  for (size_t i = 0u; i < count; i++) {
    if (!ftun_cidr_valid(&addresses[i], false) ||
        (addresses[i].address.family == FTUN_IP_V6 && mtu < 1280u)) return FTUN_E_INVALID;
  }
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name.data,
      (int)name.length, alias, ARRAYSIZE(alias) - 1u) == 0) return FTUN_E_INVALID;
  error = io->alias_to_luid(alias, &luid);
  if (error != NO_ERROR) return ftun_windows_tun_error(error);
  for (size_t i = 0u; i < count; i++) {
    MIB_IPINTERFACE_ROW iface;
    MIB_UNICASTIPADDRESS_ROW *row = &state->rows[state->count];
    ADDRESS_FAMILY family = addresses[i].address.family == FTUN_IP_V4 ? AF_INET : AF_INET6;
    io->initialize_interface(&iface);
    iface.InterfaceLuid = luid;
    iface.Family = family;
    error = io->get_interface(&iface);
    if (error != NO_ERROR) return ftun_windows_tun_error(error);
    if (family == AF_INET) iface.SitePrefixLength = 0u;
    iface.NlMtu = mtu;
    iface.DadTransmits = 0u;
    iface.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
    error = io->set_interface(&iface);
    if (error != NO_ERROR) return ftun_windows_tun_error(error);
    io->initialize_address(row);
    row->InterfaceLuid = luid;
    row->Address.si_family = family;
    if (family == AF_INET) memcpy(&row->Address.Ipv4.sin_addr, addresses[i].address.bytes, 4u);
    else memcpy(&row->Address.Ipv6.sin6_addr, addresses[i].address.bytes, 16u);
    row->OnLinkPrefixLength = addresses[i].prefix;
    row->DadState = IpDadStatePreferred;
    row->PrefixOrigin = IpPrefixOriginManual;
    row->SuffixOrigin = IpSuffixOriginManual;
    error = io->create_address(row);
    if (error != NO_ERROR) return ftun_windows_tun_error(error);
    state->count++;
  }
  return FTUN_OK;
}
ftun_status_t ftun_platform_tun_unconfigure(void *storage, const void *operations)
{
  address_state_t *state = storage;
  const ftun_windows_tun_config_io_t *io = operations == NULL ? &system_io : operations;
  while (state->count != 0u) {
    DWORD error = io->delete_address(&state->rows[state->count - 1u]);
    if (error != NO_ERROR && error != ERROR_NOT_FOUND && error != ERROR_FILE_NOT_FOUND) {
      return ftun_windows_tun_error(error);
    }
    state->count--;
  }
  return FTUN_OK;
}
