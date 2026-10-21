#ifndef FTUN_TUN_OWNER_H
#define FTUN_TUN_OWNER_H

#include "core/service.h"
#include "platform/linux/route.h"
#include "tun/service.h"

/* Composition 为物理 TUN service 提供每实例发布槽和共享 owner loop。
 * device/route 操作只用于确定性测试或受控宿主；NULL 选择 Linux 实现。 */
typedef struct {
  ftun_l3_provider_t *provider;
  ftun_event_loop_t *loop;
  const ftun_tun_device_ops_t *device_ops;
  const ftun_linux_route_io_t *route_io;
  uint32_t protection_mark;
} ftun_tun_owner_binding_t;

extern const ftun_core_service_descriptor_t ftun_tun_owner_service;

#endif
