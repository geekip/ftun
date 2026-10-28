#ifndef FTUN_TUN_UDP_SESSION_H
#define FTUN_TUN_UDP_SESSION_H

#include "core/budget.h"
#include "network/resolver.h"
#include "transport/datagram.h"
#include "transport/path.h"

#define FTUN_UDP_FLOW_MAX_RESOLVED_IPV4 16u

typedef struct ftun_udp_flow_table ftun_udp_flow_table_t;

/* 首包异步解析前取得的授权。调用期间借用；创建 flow 时保留 Runtime，
 * backend 保留自己需要的 scope，不借用此结构跨异步回调。 */
typedef struct {
  ftun_runtime_t *runtime;
  ftun_path_scope_t *path;
  ftun_resolver_scope_t *resolver;
} ftun_udp_flow_admission_t;

typedef ftun_status_t (*ftun_udp_flow_open_fn)(
  void *user, ftun_core_t *core, const ftun_runtime_t *runtime,
  const ftun_metadata_t *metadata, const ftun_route_result_t *route,
  const ftun_udp_flow_admission_t *admission,
  ftun_datagram_result_fn result,
  ftun_datagram_receive_fn receive, void *callback_user,
  uint32_t *outbound_id, ftun_endpoint_t *remote, ftun_datagram_t **out);
typedef ftun_status_t (*ftun_udp_flow_inbound_fn)(
  void *user, const ftun_metadata_t *metadata, ftun_datagram_t **out);
typedef ftun_status_t (*ftun_udp_flow_reply_fn)(
  void *user, ftun_datagram_t *inbound, const ftun_metadata_t *metadata,
  const ftun_endpoint_t *source, const ftun_packet_t *packet);

typedef struct {
  ftun_udp_flow_open_fn open;
  ftun_udp_flow_inbound_fn inbound;
  ftun_udp_flow_reply_fn reply;
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
  size_t reused;
  size_t rejected_sources;
  uint64_t now_ms;
  bool accepting;
} ftun_udp_flow_usage_t;

/* TUN UDP flow。
 * 实现路径：按入站/源/目标建立有界表并固定 Runtime；FakeIP 回包恢复客户端原目标；idle 回收且不向另一地址重放同一包。
 * 调用边界：不访问配置 AST，不跨线程修改 Session。进程仅允许一个活跃
 * table，创建/输入/回收/销毁均由同一 owner loop 串行调用；无并发创建契约。
 * table 绑定创建时 Core 与其预算树，Core 和预算必须活到 table 销毁；
 * 重复创建返回 INVALID 且 out=NULL，其他 Core 的 input 返回 STALE。
 * 销毁因 flow 回收失败而保留非空句柄时，单例仍被占用，须原 owner 重试。
 * 新 flow 在首包同步复制 Metadata、保留 active Runtime 并固定一个真实 remote
 * 和出站 Datagram。每个输入包只调用一次固定 channel；失败不换地址重放。
 * inbound Datagram 由入口拥有，flow 持有额外引用，静默后归还。
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
/* 已由共享异步 Router 决定路由的 Engine 路径。 */
ftun_status_t ftun_udp_flow_input_routed(ftun_udp_flow_table_t *table,
                                         ftun_datagram_t *inbound,
                                         const ftun_metadata_t *metadata,
                                         const ftun_route_result_t *route,
                                         const ftun_udp_flow_admission_t *admission,
                                         ftun_packet_t *packet);
/* 仅查找并复用已经固定路由的完整键；miss 返回 OK 且 found=false，调用方
 * 再执行首包路由。命中时不得依据当前组选择或规则重新选择出口。 */
ftun_status_t ftun_udp_flow_input_existing(ftun_udp_flow_table_t *table,
                                           ftun_datagram_t *inbound,
                                           const ftun_metadata_t *metadata,
                                           ftun_packet_t *packet,
                                           bool *found);
/* Owner loop 使用已经取得的单调时钟样本推进表时钟，不触发回收。 */
ftun_status_t ftun_udp_flow_set_now(ftun_udp_flow_table_t *table,
                                    uint64_t now_ms);
ftun_status_t ftun_udp_flow_tick(ftun_udp_flow_table_t *table,
                                 uint64_t now_ms);
ftun_status_t ftun_udp_flow_next_deadline(
  const ftun_udp_flow_table_t *table, uint64_t *out_deadline_ms,
  bool *out_present);
/* 只标记并回收拥有该 outbound 的 flow；单个已连接 UDP socket 的网络或
 * 协议错误不得逃逸到 owner loop。 */
ftun_status_t ftun_udp_flow_fail_outbound(ftun_udp_flow_table_t *table,
                                          ftun_datagram_t *outbound,
                                          ftun_status_t failure);
ftun_status_t ftun_udp_flow_close_inbound(ftun_udp_flow_table_t *table,
                                          ftun_datagram_t *inbound);
/* 有界扫描并回收已停止入站的 flow；取消失败保留，其他入站不受影响。 */
ftun_status_t ftun_udp_flow_reap_stopped(ftun_udp_flow_table_t *table,
  size_t quota, size_t *out_work);
ftun_status_t ftun_udp_flow_get_usage(const ftun_udp_flow_table_t *table,
                                      ftun_udp_flow_usage_t *out);
ftun_status_t ftun_udp_flow_table_destroy(ftun_udp_flow_table_t **table);
#endif
