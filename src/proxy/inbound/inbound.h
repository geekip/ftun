#ifndef FTUN_PROXY_INBOUND_INBOUND_H
#define FTUN_PROXY_INBOUND_INBOUND_H

#include "core/budget.h"
#include "tun/device.h"

#define FTUN_INBOUND_NAME_BYTES 64u

#define FTUN_INBOUND_KIND_MASK_MIXED (1u << 0)
#define FTUN_INBOUND_KIND_MASK_SOCKS5 (1u << 1)
#define FTUN_INBOUND_KIND_MASK_TUN (1u << 2)

typedef enum {
  FTUN_INBOUND_MIXED = 1,
  FTUN_INBOUND_SOCKS5,
  FTUN_INBOUND_TUN
} ftun_inbound_kind_t;

typedef enum {
  FTUN_INBOUND_RESOURCE_LISTENER = 1,
  FTUN_INBOUND_RESOURCE_PACKET_PORT
} ftun_inbound_resource_kind_t;

typedef struct {
  ftun_bytes_t username;
  ftun_bytes_t password;
} ftun_inbound_user_t;

struct ftun_inbound_spec {
  ftun_budget_t *budget;
  ftun_inbound_kind_t kind;
  uint64_t generation;
  uint32_t id;
  ftun_string_t name;
  uint32_t fixed_outbound_id;
  bool tcp;
  bool udp;
  ftun_endpoint_t listen;
  const ftun_inbound_user_t *users; /* prepare 期间同步借用。 */
  size_t user_count;
  ftun_tun_spec_t tun;
};

typedef struct {
  ftun_inbound_kind_t kind;
  ftun_inbound_resource_kind_t resource_kind;
  uint64_t generation;
  uint32_t id;
  char name[FTUN_INBOUND_NAME_BYTES];
  uint32_t fixed_outbound_id;
  bool tcp;
  bool udp;
  bool accepting;
} ftun_inbound_info_t;

typedef struct {
  uint64_t generation;
  uint32_t inbound_id;
  uint32_t fixed_outbound_id;
  bool forced;
} ftun_inbound_policy_t;

typedef struct {
  uint32_t kind_mask;
  ftun_status_t (*listener_open)(void *context,
                                 const ftun_inbound_spec_t *spec,
                                 ftun_native_socket_t *out);
  /* close 无论返回值都消费 listener，避免不可安全重试的 fd close。 */
  ftun_status_t (*listener_close)(void *context,
                                  ftun_native_socket_t *listener);
  ftun_status_t (*packet_open)(void *context, ftun_core_t *core,
                               const ftun_tun_spec_t *spec,
                               ftun_packet_port_t **out);
  /* 与 PacketPort close 一致：返回错误也消费句柄。 */
  ftun_status_t (*packet_close)(void *context, ftun_packet_port_t **port);
  ftun_status_t (*stream_ingress)(void *context, ftun_core_t *core,
                                  ftun_inbound_kind_t kind,
                                  ftun_stream_t *stream);
  ftun_status_t (*packet_ingress)(void *context, ftun_core_t *core,
                                  ftun_packet_port_t *port,
                                  ftun_packet_t *packet);
  void *context;
} ftun_inbound_backend_t;

/* 统一入站工厂。
 * 需求 REQ-IN-001；任务 TASK-INBOUND-001；目标 0.2.0；验收 TEST-INBOUND-001。
 * 在资源打开前检查构建/adapter/传输能力并复制身份；socket 类型只准备
 * listener，TUN 类型只准备 PacketPort。工厂保存固定出口策略但 adapter
 * 只能提交 Metadata，不接收或选择代理名称/叶子。
 */
ftun_status_t ftun_inbound_prepare(ftun_core_t *core,
                                   const ftun_inbound_spec_t *spec,
                                   ftun_inbound_t **out);
ftun_status_t ftun_inbound_prepare_with_backend(
  ftun_core_t *core, const ftun_inbound_spec_t *spec,
  const ftun_inbound_backend_t *backend, ftun_inbound_t **out);

ftun_status_t ftun_inbound_get_info(const ftun_inbound_t *inbound,
                                    ftun_inbound_info_t *out);
ftun_status_t ftun_inbound_get_policy(const ftun_inbound_t *inbound,
                                      ftun_inbound_policy_t *out);
/* adapter 提供协议事实；工厂固定 generation/inbound_id 并检查传输能力。
 * 输出同步借用 adapter Metadata 的字符串/数组，Session submit 再深拷贝。 */
ftun_status_t ftun_inbound_bind_metadata(const ftun_inbound_t *inbound,
                                         const ftun_metadata_t *adapter,
                                         ftun_metadata_t *out);
/* 只允许与准备资源匹配的 adapter 入口；工厂传递协议流/完整包，不传递
 * fixed_outbound_id，出口策略由统一协调层读取 policy 后处理。 */
ftun_status_t ftun_inbound_stream_ingress(ftun_inbound_t *inbound,
                                          ftun_stream_t *stream);
ftun_status_t ftun_inbound_packet_ingress(ftun_inbound_t *inbound,
                                          ftun_packet_t *packet);
/* 关闭后总是消费 inbound；底层 close 错误原样返回但不保留失效句柄。 */
ftun_status_t ftun_inbound_close(ftun_inbound_t **inbound);

#endif
