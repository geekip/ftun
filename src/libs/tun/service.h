#ifndef FTUN_LIBS_TUN_SERVICE_H
#define FTUN_LIBS_TUN_SERVICE_H

#include "core/limits.h"
#include "core/event/loop.h"
#include "libs/tun/device.h"
#include "libs/buffer/buffer.h"

typedef struct ftun_tun_service ftun_tun_service_t;

/* Composition 发布的 L3 Provider 是借用型代次句柄；物理 service 保持唯一
 * owner。consumer 只能凭当前 provider generation 获取独立 lease。 */
typedef struct ftun_l3_provider {
  ftun_tun_service_t *service;
  ftun_budget_t *budget;
  uint64_t generation;
  uint64_t pending_generation;
  bool reload_prepared;
} ftun_l3_provider_t;

typedef struct {
  ftun_tun_service_t *service;
  uint64_t generation;
} ftun_tun_lease_t;

typedef enum {
  FTUN_TUN_SERVICE_REBUILT = 1,
  FTUN_TUN_SERVICE_QUIESCED,
  FTUN_TUN_SERVICE_FAILED,
  FTUN_TUN_SERVICE_PATH_UPDATED,
  FTUN_TUN_SERVICE_NETWORK_UPDATED,
  FTUN_TUN_SERVICE_NETWORK_CHANGING
} ftun_tun_service_event_t;

typedef enum {
  FTUN_TUN_PACKET_FROM_DEVICE = 1,
  FTUN_TUN_PACKET_TO_DEVICE
} ftun_tun_packet_direction_t;

typedef enum {
  FTUN_TUN_PACKET_MALFORMED = 1,
  FTUN_TUN_PACKET_TOO_BIG,
  FTUN_TUN_PACKET_FRAGMENT_UNSUPPORTED,
  FTUN_TUN_PACKET_SOURCE_REJECTED
} ftun_tun_packet_error_reason_t;

typedef struct {
  ftun_tun_packet_direction_t direction;
  ftun_tun_packet_error_reason_t reason;
  size_t packet_length;
  uint32_t inner_mtu;
  uint16_t headroom;
  uint8_t source[4];
  uint8_t destination[4];
  bool dont_fragment;
  bool fragmented;
  bool feedback_sent;
} ftun_tun_packet_error_t;

typedef ftun_status_t (*ftun_tun_service_packet_fn)(
  void *user, ftun_tun_lease_t lease, ftun_bytes_t packet);
typedef void (*ftun_tun_service_event_fn)(
  void *user, ftun_tun_lease_t lease, ftun_tun_service_event_t event,
  ftun_status_t status);
typedef void (*ftun_tun_service_packet_error_fn)(
  void *user, ftun_tun_lease_t lease,
  const ftun_tun_packet_error_t *error);

typedef struct {
  ftun_tun_service_packet_fn packet;
  ftun_tun_service_event_fn event;
  /* error 仅在同步回调期间借用；回调可以释放 lease。 */
  ftun_tun_service_packet_error_fn packet_error;
  void *user;
} ftun_tun_consumer_t;

#define FTUN_TUN_PATH_ALLOW_IPV4_FRAGMENTS UINT16_C(0x0001)
#define FTUN_TUN_PATH_VALIDATE_OUTPUT_SOURCE UINT16_C(0x0002)

typedef struct {
  /* 零 carrier_mtu 保持原消费者行为；显式路径按 carrier_mtu-headroom
   * 得到最大 inner packet，并且不改变共享物理 TUN 的 MTU。 */
  uint32_t carrier_mtu;
  uint16_t headroom;
  uint16_t flags;
} ftun_tun_path_t;

typedef enum {
  FTUN_TUN_ROUTE_DEFAULT = 1,
  FTUN_TUN_ROUTE_IPV4_PREFIX
} ftun_tun_route_kind_t;

typedef struct {
  ftun_tun_route_kind_t kind;
  uint8_t network[4];
  uint8_t prefix_length;
  /* 数值越小优先级越高；最长前缀始终先于 priority。 */
  uint16_t priority;
} ftun_tun_route_t;

typedef struct {
  ftun_tun_consumer_t consumer;
  ftun_tun_route_t route;
  ftun_tun_path_t path;
} ftun_tun_consumer_spec_t;

typedef struct {
  ftun_status_t (*open)(void *user, ftun_core_t *core,
                        const ftun_tun_spec_t *spec,
                        ftun_packet_port_t **out);
  ftun_status_t (*get_info)(void *user, const ftun_packet_port_t *port,
                            ftun_packet_port_info_t *out);
  ftun_status_t (*read)(void *user, ftun_packet_port_t *port, void *buffer,
                        size_t capacity, size_t *out_length);
  ftun_status_t (*write)(void *user, ftun_packet_port_t *port,
                         const void *packet, size_t length);
  /* 消费非空 port；即使底层 close 报错，也不得留下半关闭句柄。 */
  ftun_status_t (*close)(void *user, ftun_packet_port_t **port);
  void *user;
} ftun_tun_device_ops_t;

typedef struct {
  /* 初次打开及重开后、启用 watcher 前恢复；关闭设备前撤销。
   * 失败保留 context 内部分状态，withdraw 可重试且支持空状态。 */
  ftun_status_t (*restore)(void *context);
  ftun_status_t (*withdraw)(void *context);
  void *context;
  /* 可选 owner 驱动入口：接纳后返回 AGAIN，由 owner loop 推进；不在
   * service 内等待网络 ACK。为空保留同步生命周期后端的行为。 */
  ftun_status_t (*change)(void *context, bool rebuild,
    uint64_t device_generation, uint64_t network_generation);
} ftun_tun_network_lifecycle_t;

typedef struct {
  ftun_core_t *core;
  ftun_budget_t *budget;
  ftun_event_loop_t *loop;
  ftun_buffer_pool_t *buffers;
  ftun_tun_spec_t device;
  ftun_tun_network_lifecycle_t network;
  /* 零值保持 C10-014 的单消费者行为。其余容量均按消费者独立计算。 */
  size_t consumer_capacity;
  size_t input_capacity;
  size_t consumer_quota;
  size_t output_capacity;
  size_t read_quota;
  size_t write_quota;
} ftun_tun_service_spec_t;

typedef struct {
  ftun_packet_port_info_t device;
  uint64_t device_generation;
  uint64_t network_generation;
  uint64_t lease_generation;
  size_t active_leases;
  size_t blocked_consumers;
  size_t queued_inputs;
  size_t queued_input_bytes;
  size_t queued_packets;
  size_t queued_bytes;
  size_t packets_read;
  size_t packets_written;
  size_t packets_dropped;
  size_t packet_errors;
  size_t feedback_sent;
  size_t feedback_suppressed;
  bool accepting;
  bool ready;
  bool device_lost;
} ftun_tun_service_usage_t;

typedef struct {
  ftun_packet_port_info_t device;
  uint64_t generation;
  uint64_t pending_generation;
  uint64_t device_generation;
  uint64_t network_generation;
  size_t active_leases;
  bool accepting;
  bool reload_prepared;
} ftun_l3_provider_info_t;

typedef struct {
  ftun_tun_route_t route;
  ftun_tun_path_t path;
  uint64_t path_generation;
  uint32_t inner_mtu;
  size_t queued_inputs;
  size_t queued_input_bytes;
  size_t queued_outputs;
  size_t queued_output_bytes;
  size_t packets_received;
  size_t packets_written;
  size_t packets_dropped;
  size_t malformed_packets;
  size_t oversized_packets;
  size_t fragments_rejected;
  size_t sources_rejected;
  size_t feedback_sent;
  size_t feedback_suppressed;
  bool blocked;
} ftun_tun_consumer_usage_t;

/* 物理 TUN 的唯一 owner。service 独占设备、watcher 和写队列；consumer 只持有
 * generation lease，并在 owner loop 内同步借用完整包。回调可以写包、释放
 * lease；释放后报文借用仍持续到回调返回。回调内 acquire、更新映射、run、
 * rebuild、quiesce 和 destroy 返回 AGAIN，调用者须在回调返回后重试。 */
ftun_status_t ftun_tun_service_create(
  const ftun_tun_service_spec_t *spec, ftun_tun_service_t **out);
/* 操作表会复制，user 必须比 service 长寿。失败后的非空 out 表示撤销尚未
 * 完成，调用者必须保留并重试 destroy，不得当作可用 service 发布。 */
ftun_status_t ftun_tun_service_create_with_ops(
  const ftun_tun_service_spec_t *spec, const ftun_tun_device_ops_t *ops,
  ftun_tun_service_t **out);
ftun_status_t ftun_l3_provider_bind(ftun_tun_service_t *service,
                                    uint64_t generation,
                                    ftun_l3_provider_t *out);
ftun_status_t ftun_l3_provider_acquire(
  const ftun_l3_provider_t *provider, uint64_t generation,
  const ftun_tun_consumer_spec_t *consumer, ftun_tun_lease_t *out);
ftun_status_t ftun_l3_provider_reload_prepare(
  ftun_l3_provider_t *provider, uint64_t generation);
ftun_status_t ftun_l3_provider_reload_commit(
  ftun_l3_provider_t *provider, uint64_t generation);
ftun_status_t ftun_l3_provider_reload_abort(ftun_l3_provider_t *provider);
ftun_status_t ftun_l3_provider_get_info(
  const ftun_l3_provider_t *provider, ftun_l3_provider_info_t *out);
ftun_status_t ftun_l3_provider_quiesce(ftun_l3_provider_t *provider);
ftun_status_t ftun_tun_service_acquire(
  ftun_tun_service_t *service, const ftun_tun_consumer_t *consumer,
  ftun_tun_lease_t *out);
/* routed acquire 用于共享设备。相同 kind/network/prefix/priority 冲突；
 * IPv4 先最长前缀匹配，再选较小 priority，最后才使用 DEFAULT。 */
ftun_status_t ftun_tun_service_acquire_routed(
  ftun_tun_service_t *service, const ftun_tun_consumer_spec_t *consumer,
  ftun_tun_lease_t *out);
ftun_status_t ftun_tun_service_release(ftun_tun_lease_t *lease);
ftun_status_t ftun_tun_service_write(
  ftun_tun_lease_t lease, ftun_bytes_t packet);
/* 在 owner loop 内更新消费者路径。成功时物理设备与 lease 均保持，旧路径的
 * 该消费者输入/输出队列被丢弃，path generation 递增并发出 PATH_UPDATED。 */
ftun_status_t ftun_tun_service_update_path(
  ftun_tun_lease_t lease, const ftun_tun_path_t *path);
/* 原子更新 route/path，expected_path_generation 必须匹配当前代次。
 * 无效参数、旧代、冲突或 watcher 拒绝均保留原映射和队列；成功丢弃本
 * consumer 的旧队列并递增路径代次。其他 consumer 与物理设备不变。
 * 相同配置不递增；generation 耗尽拒绝复用，内部计账损坏则停止接纳。 */
ftun_status_t ftun_tun_service_update_consumer(
  ftun_tun_lease_t lease, uint64_t expected_path_generation,
  const ftun_tun_route_t *route, const ftun_tun_path_t *path);
/* packet 回调返回 AGAIN 后暂停该消费者；resume 只接受当前代租约。 */
ftun_status_t ftun_tun_service_resume(ftun_tun_lease_t lease);
/* Event adapter 和确定性测试共用的 readiness 入口；不执行业务回调。 */
ftun_status_t ftun_tun_service_notify(
  ftun_tun_service_t *service, uint32_t events);
ftun_status_t ftun_tun_service_run(
  ftun_tun_service_t *service, size_t *out_work);
/* 重建先停收发、丢弃旧设备全部排队包，撤销网络状态再关闭旧设备；新设备
 * 与网络状态均恢复后才报告成功。失败保留可重试对象且不接纳 I/O；成功后
 * 原 lease 继续有效。quiesce 后不可再重建。 */
ftun_status_t ftun_tun_service_rebuild(ftun_tun_service_t *service);
/* 内部网络事务重新应用：固定设备和 lease，先停 I/O 并丢弃旧队列，再
 * withdraw/restore，全部成功才恢复 watcher 并递增 network generation。
 * 失败保留设备及撤销未完成的网络句柄，拒绝 I/O；拥有者可恢复旧计划后
 * 重试。它不改变配置代次，不提供公开配置热更新。回调期间返回 AGAIN。 */
ftun_status_t ftun_tun_service_refresh_network(
  ftun_tun_service_t *service, uint64_t expected_network_generation);
/* owner 的异步网络事务独占 I/O 发布权。pause 不调用平台网络回调，先
 * 撤销 watcher、丢弃旧队列并通知消费者。finish(OK) 只在网络已就绪后
 * 恢复 watcher/递增代次；其他结果保持停收发。回调内不可重入。 */
ftun_status_t ftun_tun_service_network_pause(
  ftun_tun_service_t *service, uint64_t expected_network_generation);
ftun_status_t ftun_tun_service_network_finish(
  ftun_tun_service_t *service, ftun_status_t result);
/* 重建暂停允许设备已缺席；reopen 只在网络已撤销后替换物理端口，
 * 不安装网络、不发布 watcher。网络就绪后仍由 network_finish 发布。 */
ftun_status_t ftun_tun_service_rebuild_pause(
  ftun_tun_service_t *service, uint64_t expected_device_generation,
  uint64_t expected_network_generation);
ftun_status_t ftun_tun_service_reopen_paused(ftun_tun_service_t *service);
ftun_status_t ftun_tun_service_quiesce(ftun_tun_service_t *service);
/* 永久停止 I/O 与 consumer 接纳，但不调用网络撤销回调。拥有者须继续
 * 驱动自己的异步网络事务；网络责任未清空前 destroy 仍不可完成。 */
ftun_status_t ftun_tun_service_quiesce_io(ftun_tun_service_t *service);
ftun_status_t ftun_tun_service_get_usage(
  const ftun_tun_service_t *service, ftun_tun_service_usage_t *out);
ftun_status_t ftun_tun_service_get_consumer_usage(
  ftun_tun_lease_t lease, ftun_tun_consumer_usage_t *out);
ftun_status_t ftun_tun_service_destroy(ftun_tun_service_t **service);

#endif
