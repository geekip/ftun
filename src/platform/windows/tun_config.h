#ifndef FTUN_PLATFORM_WINDOWS_TUN_CONFIG_H
#define FTUN_PLATFORM_WINDOWS_TUN_CONFIG_H
#include "platform/tun_config.h"
#include <winsock2.h>
#include <windows.h>
#include <netioapi.h>
/* 与整包端口相同，仅平台测试可注入实际使用的系统调用。 */
typedef struct {
  void (WINAPI *initialize_interface)(PMIB_IPINTERFACE_ROW);
  void (WINAPI *initialize_address)(PMIB_UNICASTIPADDRESS_ROW);
  NETIO_STATUS (WINAPI *alias_to_luid)(PCWSTR, PNET_LUID);
  NETIO_STATUS (WINAPI *get_interface)(PMIB_IPINTERFACE_ROW);
  NETIO_STATUS (WINAPI *set_interface)(PMIB_IPINTERFACE_ROW);
  NETIO_STATUS (WINAPI *create_address)(const MIB_UNICASTIPADDRESS_ROW *);
  NETIO_STATUS (WINAPI *delete_address)(const MIB_UNICASTIPADDRESS_ROW *);
} ftun_windows_tun_config_io_t;
#endif
