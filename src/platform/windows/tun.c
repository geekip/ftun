#include "platform/windows/tun.h"
#include <string.h>
#include <wchar.h>
#define FTUN_WINTUN_RING_CAPACITY (1024u * 1024u)

static const ftun_platform_tun_io_t system_io = {0};
ftun_status_t ftun_windows_tun_error(DWORD error)
{
  if (error == ERROR_ACCESS_DENIED || error == ERROR_PRIVILEGE_NOT_HELD) return FTUN_E_REJECTED;
  if (error == ERROR_NO_MORE_ITEMS || error == ERROR_BUFFER_OVERFLOW) return FTUN_E_AGAIN;
  if (error == ERROR_NOT_ENOUGH_MEMORY || error == ERROR_OUTOFMEMORY ||
      error == ERROR_NO_SYSTEM_RESOURCES || error == ERROR_TOO_MANY_OPEN_FILES) return FTUN_E_LIMIT;
  if (error == ERROR_MOD_NOT_FOUND || error == ERROR_PROC_NOT_FOUND ||
      error == ERROR_NOT_SUPPORTED || error == ERROR_BAD_EXE_FORMAT) return FTUN_E_UNSUPPORTED;
  return FTUN_E_IO;
}

ftun_status_t ftun_windows_tun_load(ftun_platform_tun_io_t *io, HMODULE *module)
{
  WCHAR path[32768], *slash;
  DWORD length = GetModuleFileNameW(NULL, path, ARRAYSIZE(path));
  *module = NULL;
  if (length == 0u || length >= ARRAYSIZE(path)) return FTUN_E_IO;
  slash = wcsrchr(path, L'\\');
  if (slash == NULL || (size_t)(slash - path) + 12u > ARRAYSIZE(path)) return FTUN_E_LIMIT;
  wcscpy(slash + 1, L"wintun.dll");
  *module = LoadLibraryExW(path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (*module == NULL) return ftun_windows_tun_error(GetLastError());
#define LOAD(field, type, name) do { \
  io->field = (type *)(void *)GetProcAddress(*module, name); \
  if (io->field == NULL) { FreeLibrary(*module); *module = NULL; return FTUN_E_UNSUPPORTED; } \
} while (0)
  LOAD(create_adapter, WINTUN_CREATE_ADAPTER_FUNC, "WintunCreateAdapter");
  LOAD(close_adapter, WINTUN_CLOSE_ADAPTER_FUNC, "WintunCloseAdapter");
  LOAD(get_adapter_luid, WINTUN_GET_ADAPTER_LUID_FUNC, "WintunGetAdapterLUID");
  LOAD(start_session, WINTUN_START_SESSION_FUNC, "WintunStartSession");
  LOAD(end_session, WINTUN_END_SESSION_FUNC, "WintunEndSession");
  LOAD(get_read_wait_event, WINTUN_GET_READ_WAIT_EVENT_FUNC, "WintunGetReadWaitEvent");
  LOAD(receive_packet, WINTUN_RECEIVE_PACKET_FUNC, "WintunReceivePacket");
  LOAD(release_receive_packet, WINTUN_RELEASE_RECEIVE_PACKET_FUNC, "WintunReleaseReceivePacket");
  LOAD(allocate_send_packet, WINTUN_ALLOCATE_SEND_PACKET_FUNC, "WintunAllocateSendPacket");
  LOAD(send_packet, WINTUN_SEND_PACKET_FUNC, "WintunSendPacket");
#undef LOAD
  io->alias_to_luid = ConvertInterfaceAliasToLuid;
  io->luid_to_alias = ConvertInterfaceLuidToAlias;
  return FTUN_OK;
}

const ftun_platform_tun_io_t *ftun_platform_tun_default_io(void) { return &system_io; }
size_t ftun_platform_tun_allocation_size(void) { return sizeof(ftun_platform_tun_t); }
void ftun_platform_tun_resources(size_t *bytes, size_t *handles, size_t *temporary)
{
  SYSTEM_INFO info;
  size_t ring_bytes = FTUN_WINTUN_RING_CAPACITY + 65548u;
  GetSystemInfo(&info);
  /* 0.14.1 的两块环区，按页向上取整；另预留适配器及 DLL 的控制元数据。 */
  *bytes = 2u * ((ring_bytes + info.dwPageSize - 1u) / info.dwPageSize * info.dwPageSize) + 65536u;
  *handles = 14u; /* session 设备与双事件、适配器的设备信息与软件设备。 */
  *temporary = 0u; /* 其中 8 个控制句柄额度持有到关闭，覆盖删除适配器。 */
}
bool ftun_platform_tun_spec_valid(const ftun_tun_spec_t *spec, const ftun_platform_tun_io_t *io)
{
  WCHAR name[FTUN_PACKET_PORT_NAME_BYTES];
  if (spec == NULL || io == NULL || spec->name.data == NULL || spec->name.length == 0u ||
      spec->name.length >= FTUN_PACKET_PORT_NAME_BYTES || spec->mtu < 68u || spec->mtu > 65535u ||
      memchr(spec->name.data, '\0', spec->name.length) != NULL) return false;
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, spec->name.data,
      (int)spec->name.length, name, ARRAYSIZE(name) - 1u) == 0) return false;
  return io == &system_io || (io->create_adapter && io->close_adapter && io->get_adapter_luid &&
    io->start_session && io->end_session && io->get_read_wait_event && io->receive_packet &&
    io->release_receive_packet && io->allocate_send_packet && io->send_packet &&
    io->alias_to_luid && io->luid_to_alias);
}
ftun_status_t ftun_platform_tun_open(const ftun_tun_spec_t *spec,
  const ftun_platform_tun_io_t *io, ftun_platform_tun_t *port)
{
  WCHAR name[FTUN_PACKET_PORT_NAME_BYTES] = {0}, actual[IF_MAX_STRING_SIZE + 1u];
  NET_LUID luid;
  ftun_status_t status;
  memset(port, 0, sizeof(*port));
  port->io = *io;
  if (io == &system_io) {
    status = ftun_windows_tun_load(&port->io, &port->module);
    if (status != FTUN_OK) return status;
  }
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, spec->name.data,
    (int)spec->name.length, name, ARRAYSIZE(name) - 1u);
  /* 不接管同名已有网卡；只关闭本次创建且独占的适配器。 */
  DWORD error = port->io.alias_to_luid(name, &luid);
  if (error == NO_ERROR) { status = FTUN_E_REJECTED; goto fail; }
  if (error != ERROR_INVALID_PARAMETER && error != ERROR_NOT_FOUND) {
    status = ftun_windows_tun_error(error); goto fail;
  }
  port->adapter = port->io.create_adapter(name, L"FTUN", NULL);
  if (port->adapter == NULL) { status = ftun_windows_tun_error(GetLastError()); goto fail; }
  port->io.get_adapter_luid(port->adapter, &luid);
  if (port->io.luid_to_alias(&luid, actual, ARRAYSIZE(actual)) != NO_ERROR || wcscmp(name, actual) != 0) {
    status = FTUN_E_REJECTED;
    goto fail;
  }
  port->session = port->io.start_session(port->adapter, FTUN_WINTUN_RING_CAPACITY);
  if (port->session == NULL) { status = ftun_windows_tun_error(GetLastError()); goto fail; }
  port->read_event = port->io.get_read_wait_event(port->session);
  if (port->read_event == NULL || port->read_event == INVALID_HANDLE_VALUE) {
    status = FTUN_E_IO; goto fail;
  }
  memcpy(port->name, spec->name.data, spec->name.length);
  port->mtu = spec->mtu;
  return FTUN_OK;
fail:
  (void)ftun_platform_tun_close(port);
  return status;
}
void ftun_platform_tun_get_info(const ftun_platform_tun_t *port, ftun_packet_port_info_t *out)
{
  memset(out, 0, sizeof(*out));
  memcpy(out->name, port->name, sizeof(out->name));
  out->mtu = port->mtu;
  out->native_socket = (ftun_native_socket_t)(uintptr_t)port->read_event;
  out->flags = FTUN_PACKET_PORT_WAITABLE | FTUN_PACKET_PORT_WRITE_TIMER;
}
ftun_status_t ftun_platform_tun_read(ftun_platform_tun_t *port,
  void *buffer, size_t capacity, size_t *length)
{
  DWORD size;
  BYTE *packet;
  if (length != NULL) *length = 0u;
  if (buffer == NULL || length == NULL || capacity < port->mtu) return FTUN_E_INVALID;
  packet = port->io.receive_packet(port->session, &size);
  if (packet == NULL) return ftun_windows_tun_error(GetLastError());
  if (size > capacity) {
    port->io.release_receive_packet(port->session, packet);
    return FTUN_E_LIMIT;
  }
  memcpy(buffer, packet, size);
  port->io.release_receive_packet(port->session, packet);
  *length = size;
  return FTUN_OK;
}
ftun_status_t ftun_platform_tun_write(ftun_platform_tun_t *port, const void *packet, size_t length)
{
  BYTE *target;
  if (packet == NULL || length == 0u || length > port->mtu) return FTUN_E_INVALID;
  target = port->io.allocate_send_packet(port->session, (DWORD)length);
  if (target == NULL) return ftun_windows_tun_error(GetLastError());
  memcpy(target, packet, length);
  port->io.send_packet(port->session, target);
  return FTUN_OK;
}
ftun_status_t ftun_platform_tun_close(ftun_platform_tun_t *port)
{
  if (port->session != NULL) port->io.end_session(port->session);
  if (port->adapter != NULL) port->io.close_adapter(port->adapter);
  if (port->module != NULL) FreeLibrary(port->module);
  memset(port, 0, sizeof(*port));
  return FTUN_OK;
}
