#ifndef FTUN_TUN_SERVICE_H
#define FTUN_TUN_SERVICE_H

#include "core/budget.h"
#include "event/event.h"
#include "tun/device.h"
#include "util/buffer.h"

typedef struct ftun_tun_service ftun_tun_service_t;

/* Composition 发布的 L3 Provider 是借用型代次句柄；物理 service 保持唯一
 * owner。consumer 只能凭当前 provider generation 获取独立 lease。 */
typedef struct {
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
  FTUN_TUN_SERVICE_PATH_UPDATED
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
  ftun_core_t *core;
  ftun_budget_t *budget;
  ftun_event_loop_t *loop;
  ftun_buffer_pool_t *buffers;
  ftun_tun_spec_t device;
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
} ftun_tun_service_usage_t;

typedef struct {
  ftun_packet_port_info_t device;
  uint64_t generation;
  uint64_t pending_generation;
  uint64_t device_generation;
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
 * generation lease，并在 owner loop 内同步借用完整包。 */
ftun_status_t ftun_tun_service_create(
  const ftun_tun_service_spec_t *spec, ftun_tun_service_t **out);
/* 测试与受控宿主注入；操作表会复制，user 必须比 service 长寿。 */
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
/* packet 回调返回 AGAIN 后暂停该消费者；resume 只接受当前代租约。 */
ftun_status_t ftun_tun_service_resume(ftun_tun_lease_t lease);
/* Event adapter 和确定性测试共用的 readiness 入口；不执行业务回调。 */
ftun_status_t ftun_tun_service_notify(
  ftun_tun_service_t *service, uint32_t events);
ftun_status_t ftun_tun_service_run(
  ftun_tun_service_t *service, size_t *out_work);
/* 重建会先取消旧 watcher、丢弃旧设备待发包并消费旧 fd；成功后原 lease 继续有效。 */
ftun_status_t ftun_tun_service_rebuild(ftun_tun_service_t *service);
ftun_status_t ftun_tun_service_quiesce(ftun_tun_service_t *service);
ftun_status_t ftun_tun_service_get_usage(
  const ftun_tun_service_t *service, ftun_tun_service_usage_t *out);
ftun_status_t ftun_tun_service_get_consumer_usage(
  ftun_tun_lease_t lease, ftun_tun_consumer_usage_t *out);
ftun_status_t ftun_tun_service_destroy(ftun_tun_service_t **service);

#endif
