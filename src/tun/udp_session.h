#ifndef FTUN_TUN_UDP_SESSION_H
#define FTUN_TUN_UDP_SESSION_H

#include "core/budget.h"
#include "transport/datagram.h"

#define FTUN_UDP_FLOW_MAX_RESOLVED_IPV4 16u

typedef struct ftun_udp_flow_table ftun_udp_flow_table_t;

typedef ftun_status_t (*ftun_udp_flow_open_fn)(
  void *user, ftun_core_t *core, const ftun_runtime_t *runtime,
  const ftun_metadata_t *metadata, ftun_datagram_result_fn result,
  ftun_datagram_receive_fn receive, void *callback_user,
  uint32_t *outbound_id, ftun_endpoint_t *remote, ftun_datagram_t **out);
typedef ftun_status_t (*ftun_udp_flow_inbound_fn)(
  void *user, const ftun_metadata_t *metadata, ftun_datagram_t **out);

typedef struct {
  ftun_udp_flow_open_fn open;
  ftun_udp_flow_inbound_fn inbound;
  void *user;
} ftun_udp_flow_backend_t;

typedef struct {
  ftun_core_t *core;
  ftun_budget_t *budget;
  size_t capacity;
  uint64_t idle_timeout_ms;
  uint64_t now_ms;
  ftun_udp_flow_backend_t backend;
} ftun_udp_flow_table_spec_t;

typedef struct {
  size_t capacity;
  size_t active;
  size_t created;
  size_t expired;
  size_t failed;
  size_t rejected_sources;
  uint64_t now_ms;
  bool accepting;
} ftun_udp_flow_usage_t;

/* TUN UDP flow。
 * 需求 REQ-UDP-001；任务 TASK-TUN-003；目标 0.2.0；验收 TEST-TUN-003。
 * 实现路径：按入站/源/目标建立有界表并固定 Runtime；FakeIP 回包恢复客户端原目标；idle 回收且不向另一地址重放同一包。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 新 flow 在首包同步复制 Metadata、保留 active Runtime 并固定一个真实 remote
 * 和出站 Datagram。每个输入包只调用一次固定 channel；失败不换地址重放。
 * inbound Datagram 由 TUN ingress 拥有，flow 只借用且要求整个 flow 生命周期稳定。
 */
ftun_status_t ftun_udp_flow_table_create(
  const ftun_udp_flow_table_spec_t *spec, ftun_udp_flow_table_t **out);
ftun_status_t ftun_udp_flow_input(ftun_core_t *core,
                                  const ftun_metadata_t *metadata,
                                  ftun_packet_t *packet);
ftun_status_t ftun_udp_flow_input_on(ftun_udp_flow_table_t *table,
                                     ftun_datagram_t *inbound,
                                     const ftun_metadata_t *metadata,
                                     ftun_packet_t *packet);
ftun_status_t ftun_udp_flow_tick(ftun_udp_flow_table_t *table,
                                 uint64_t now_ms);
ftun_status_t ftun_udp_flow_get_usage(const ftun_udp_flow_table_t *table,
                                      ftun_udp_flow_usage_t *out);
ftun_status_t ftun_udp_flow_table_destroy(ftun_udp_flow_table_t **table);
#endif
