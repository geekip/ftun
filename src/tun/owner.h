#ifndef FTUN_TUN_OWNER_H
#define FTUN_TUN_OWNER_H

#include "core/service.h"
#include "network/interface.h"
#include "tun/service.h"

/* Composition 为物理 TUN service 提供每实例发布槽和共享 owner loop。
 * device 操作为 NULL 选择系统设备；网络状态后端由 Composition 显式装配。 */
typedef struct {
  ftun_l3_provider_t *provider;
  ftun_event_loop_t *loop;
  const ftun_tun_device_ops_t *device_ops;
  const ftun_interface_ops_t *network;
  uint32_t protection_mark;
} ftun_tun_owner_binding_t;

extern const ftun_core_service_descriptor_t ftun_tun_owner_service;

typedef struct {
  ftun_status_t update_status;
  ftun_status_t rollback_status;
  uint64_t network_generation;
  uint64_t device_generation;
  bool committed;
  bool ready;
  bool pending;
  bool rebuild;
} ftun_tun_network_update_result_t;

/* 非阻塞内部事务：OK 表示接纳，结果保存在 owner 中，参数仅在调用期间
 * 借用。单个待处理事务由 run_once 推进，query 按值复制最新结果；拒绝
 * 不覆盖已有结果。deadline_ms 为包含失败补偿的单调绝对总期限。 */
ftun_status_t ftun_tun_owner_start_network_update(
  void *implementation, uint64_t expected_network_generation,
  const ftun_interface_spec_t *network, uint64_t deadline_ms);
ftun_status_t ftun_tun_owner_query_network_update(
  void *implementation, ftun_tun_network_update_result_t *out);
/* 同一事务槽执行设备重建，结果同样由 query_network_update 获取。
 * 原 lease 保留；新端口和网络就绪前不发布 REBUILT 或接纳收发。 */
ftun_status_t ftun_tun_owner_start_rebuild(
  void *implementation, uint64_t expected_device_generation,
  uint64_t expected_network_generation, uint64_t deadline_ms);

/* 内部 owner-loop 地址/路由事务。implementation 为本 descriptor 的实例；
 * 固定设备名、MTU 与 socket mark，只允许更新 IPv4 地址/前缀及 strict_route。
 * 失败恢复旧计划，回滚失败则保留对象并停 I/O，后续显式重试或停止清理。
 * 公开 reload 仍按原始配置比较并返回 RESTART_REQUIRED，不调用本入口。
 * 异步后端使用 5 秒总期限；接纳后返回 AGAIN 且 out.pending 为 true，
 * 应由 run_once/query 继续，不能重复提交。显式期限调用优先使用 start。 */
ftun_status_t ftun_tun_owner_update_network(
  void *implementation, uint64_t expected_network_generation,
  const ftun_interface_spec_t *network, ftun_tun_network_update_result_t *out);

#endif
