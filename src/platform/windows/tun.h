#ifndef FTUN_PLATFORM_WINDOWS_TUN_H
#define FTUN_PLATFORM_WINDOWS_TUN_H
#include "platform/tun.h"
#include <winsock2.h>
#include <windows.h>
#include <netioapi.h>
#include <wintun.h>

/* 沿用平台操作表注入；生产只从程序目录加载官方 DLL。 */
struct ftun_platform_tun_io {
  WINTUN_CREATE_ADAPTER_FUNC *create_adapter;
  WINTUN_CLOSE_ADAPTER_FUNC *close_adapter;
  WINTUN_GET_ADAPTER_LUID_FUNC *get_adapter_luid;
  WINTUN_START_SESSION_FUNC *start_session;
  WINTUN_END_SESSION_FUNC *end_session;
  WINTUN_GET_READ_WAIT_EVENT_FUNC *get_read_wait_event;
  WINTUN_RECEIVE_PACKET_FUNC *receive_packet;
  WINTUN_RELEASE_RECEIVE_PACKET_FUNC *release_receive_packet;
  WINTUN_ALLOCATE_SEND_PACKET_FUNC *allocate_send_packet;
  WINTUN_SEND_PACKET_FUNC *send_packet;
  NETIO_STATUS (WINAPI *alias_to_luid)(PCWSTR, PNET_LUID);
  NETIO_STATUS (WINAPI *luid_to_alias)(const NET_LUID *, PWSTR, SIZE_T);
};
struct ftun_platform_tun {
  ftun_platform_tun_io_t io;
  HMODULE module;
  WINTUN_ADAPTER_HANDLE adapter;
  WINTUN_SESSION_HANDLE session;
  HANDLE read_event;
  uint32_t mtu;
  char name[FTUN_PACKET_PORT_NAME_BYTES];
};
ftun_status_t ftun_windows_tun_error(DWORD error);
/* 仅解析导出，不创建网卡。调用方拥有 module，测试可验证真实 DLL 装载。 */
ftun_status_t ftun_windows_tun_load(ftun_platform_tun_io_t *io, HMODULE *module);
#endif
