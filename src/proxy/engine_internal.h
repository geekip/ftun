#ifndef FTUN_PROXY_ENGINE_INTERNAL_H
#define FTUN_PROXY_ENGINE_INTERNAL_H

#include "platform/file.h"
#include "core/limits.h"
#include "proxy/diagnostics.h"
#include "proxy/runtime.h"
#include "proxy/fakeip/store.h"
#include "proxy/dns/runtime_adapter.h"
#include "proxy/slot_pool.h"
#include "proxy/http_route.h"
#include "proxy/egress.h"

#include "proxy/runtime_state.h"
#include "proxy/session.h"
#include "core/worker.h"
#include "core/recovery.h"
#include "proxy/config/transport.h"
#include "platform/socket.h"
#include "proxy/config/plan.h"
#include "proxy/dns/resolver_adapter.h"
#include "core/event/loop.h"
#include "proxy/inbound/adapter.h"
#include "proxy/udp/session.h"
#if defined(FTUN_HAVE_MODULE_TUN)
#include "proxy/netstack/ingress.h"
#include "libs/tun/service.h"
#endif
#include "proxy/outbound/outbound.h"
#include "proxy/route/group.h"
#include "proxy/route/router.h"
#include "proxy/route/rule.h"
#include "proxy/route/target.h"
#include "proxy/outbound/group/health.h"
#include "proxy/sniff/sniff.h"
#include "platform/socket.h"
#if defined(FTUN_HAVE_MODULE_FRS)
#include "proxy/frs/frs.h"
#include "core/io/file.h"
#endif
#if defined(FTUN_HAVE_MODULE_FAKEIP)
#include "proxy/fakeip/pool.h"
#include "proxy/fakeip/store.h"
#include "proxy/fakeip/snapshot.h"
#endif
#include "libs/transport/relay.h"
#include "libs/transport/stream.h"
#include "libs/buffer/buffer.h"
#include "core/log/log.h"
#include "core/log/event_log.h"
#include "core/context.h"
#include "platform/clock.h"
#include "platform/socket.h"

#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FTUN_PROXY_RUNTIME_MAX_LISTENERS 32u
#define FTUN_PROXY_RUNTIME_DATAGRAM_CAPACITY 32u
#define FTUN_PROXY_RUNTIME_PREREAD_BYTES 65536u
#define FTUN_PROXY_RUNTIME_ACCEPT_QUOTA 16u
#define FTUN_PROXY_RUNTIME_DATAGRAM_QUOTA 32u
#define FTUN_PROXY_RUNTIME_RELAY_POOL_BYTES (2u * 1024u * 1024u)
#define FTUN_PROXY_RUNTIME_RELAY_POOL_BUFFERS 32u
#define FTUN_PROXY_RUNTIME_RELAY_WAKE_QUOTA 32u
#define FTUN_PROXY_RUNTIME_EVENT_QUOTA 64u
#define FTUN_PROXY_RUNTIME_FLOW_QUOTA 64u
#define FTUN_PROXY_RUNTIME_QUARANTINE_QUOTA 8u
#define FTUN_PROXY_RUNTIME_IDLE_SCAN_MS UINT64_C(1000)
#define FTUN_PROXY_RUNTIME_IDLE_QUOTA 64u
#define FTUN_PROXY_RUNTIME_QUARANTINE_RETRY_MS UINT64_C(100)
#define FTUN_PROXY_RUNTIME_UDP_QUOTA 64u
#define FTUN_PROXY_RUNTIME_WORKER_QUOTA 16u
#define FTUN_PROXY_RUNTIME_MAINTENANCE_QUOTA 8u
#define FTUN_PROXY_RUNTIME_FAKEIP_QUOTA 2u
#define FTUN_PROXY_RUNTIME_HEALTH_QUOTA 8u
#define FTUN_PROXY_RUNTIME_IO_SOURCE_QUOTA 16u
/* 内部等待 Worker 的期限，不是网络超时；网络超时来自 base.timeouts。 */
#define FTUN_PROXY_RUNTIME_WORKER_WAIT_MS UINT64_C(10000)
/* 监听恢复退避（候选值）：起点较短以免 accept 资源不足时停太久。 */
#define FTUN_PROXY_RUNTIME_LISTENER_RETRY_INITIAL_MS UINT64_C(100)
#define FTUN_PROXY_RUNTIME_LISTENER_RETRY_MAXIMUM_MS UINT64_C(30000)
#define FTUN_PROXY_RUNTIME_LISTENER_RETRY_STABLE_MS UINT64_C(60000)
/* A0 实体的 kind 位：1 监听，2 DNS 上游（dns 模块），4 UDP 出口。 */
#define FTUN_PROXY_RUNTIME_UDP_RECOVERY_KIND UINT32_C(4)
#define FTUN_PROXY_RUNTIME_FAKEIP_RESERVE_BATCH UINT32_C(4096)
#define FTUN_PROXY_RUNTIME_FAKEIP_RESERVE_LOW_WATER UINT32_C(512)
#define FTUN_PROXY_RUNTIME_HTTP_ETAG_BYTES (64u * 1024u)
#define FTUN_PROXY_RUNTIME_HTTP_WORK_MAGIC UINT32_C(0x46544846)
#define FTUN_PROXY_RUNTIME_FRS_PUBLISH_MAGIC UINT32_C(0x46525042)
/* 其他来源（如 reload）持有代次预留时，FRS 发布短暂延后再试。 */
#define FTUN_PROXY_RUNTIME_FRS_GENERATION_RETRY_MS UINT64_C(1000)
#define FTUN_PROXY_RUNTIME_FRS_RETRY_INITIAL_MS UINT64_C(1000)
#define FTUN_PROXY_RUNTIME_FRS_RETRY_MAXIMUM_MS UINT64_C(30000)

typedef struct {
  uint32_t magic;
  uint32_t mark;
  uintptr_t budget;
  ftun_tls_context_t **tls_context;
  const ftun_egress_provider_t *egress;
  ftun_egress_id_t egress_id;
  uint64_t generation;
  ftun_dial_purpose_t purpose;
  ftun_control_resolver_plan_t resolver;
  ftun_control_path_binding_t path;
  bool allow_system_resolver;
  uint64_t maximum_bytes;
  uint64_t deadline_ms;
  uint8_t validate_frs;
  uintptr_t runtime_snapshot;
  uint32_t url_length;
  uint32_t etag_length;
} ftun_proxy_runtime_http_work_t;

typedef struct {
  uint32_t status;
  uint32_t etag_length;
  uint64_t body_length;
  uintptr_t prepared_runtime;
  uintptr_t cleanup_view;
  uint8_t tls_verified;
  uint8_t reserved[7];
} ftun_proxy_runtime_http_result_t;

#if defined(FTUN_HAVE_MODULE_FRS)
typedef struct {
  uint32_t magic;
  uint32_t path_length;
  uintptr_t budget;
  uint64_t body_length;
} ftun_proxy_runtime_frs_publish_work_t;

typedef struct {
  int32_t status;
  uint32_t reached;
} ftun_proxy_runtime_frs_publish_result_t;
#endif

typedef enum {
  FTUN_PROXY_RELOAD_OWNER_NONE = 0,
  FTUN_PROXY_RELOAD_OWNER_HOST,
  FTUN_PROXY_RELOAD_OWNER_FRS
} ftun_proxy_reload_owner_t;

typedef struct ftun_proxy_runtime_listener ftun_proxy_runtime_listener_t;
typedef struct ftun_proxy_runtime_flow ftun_proxy_runtime_flow_t;
typedef struct ftun_proxy_runtime_health_slot ftun_proxy_runtime_health_slot_t;
typedef struct ftun_proxy_runtime_udp_pending ftun_proxy_runtime_udp_pending_t;

/* SOCKS5 UDP association 的出口退避：每个出口一个 A0 恢复实体（首次失败时登记）。
 * A0 到期只表示“可以再试一次”，不发起任何动作；新的 association 请求自然成为尝试。 */
typedef struct {
  struct ftun_proxy_runtime *engine;
  ftun_recovery_id_t id;
  uint32_t outbound_id;
  bool active;
} ftun_proxy_runtime_udp_backoff_t;

typedef struct {
  size_t outbound_index;
  size_t slot_start;
  size_t slot_count;
  uint32_t group_id;
  uint64_t interval_ms;
  uint64_t timeout_ms;
  uint64_t selected_since_ms;
  bool lazy;
  bool consumed;
} ftun_proxy_runtime_health_group_t;

struct ftun_proxy_runtime_health_slot {
  struct ftun_proxy_runtime *engine;
  ftun_operation_t *operation;
  ftun_health_schedule_t schedule;
  ftun_health_sample_t sample;
  size_t group_index;
  uint32_t member_id;
  uint64_t generation;
  uint64_t started_ms;
};

#if defined(FTUN_HAVE_MODULE_FRS)
typedef struct {
  ftun_file_stage_t reached;
} ftun_proxy_runtime_file_publish_t;

static inline ftun_status_t ftun_proxy_runtime_file_stage(ftun_file_stage_t stage,
                                            void *user)
{
  ftun_proxy_runtime_file_publish_t *publish =
    (ftun_proxy_runtime_file_publish_t *)user;
  if (publish == NULL) return FTUN_E_INVALID;
  publish->reached = stage;
  return FTUN_OK;
}
#endif

typedef struct ftun_proxy_runtime_udp_slot {
  ftun_proxy_slot_token_t slot_token;
  struct ftun_proxy_runtime *engine;
  ftun_budget_t *budget;
  ftun_reservation_t admission;
  struct ftun_proxy_runtime_udp_slot *ready_previous;
  struct ftun_proxy_runtime_udp_slot *ready_next;
  ftun_datagram_t *channel;
  ftun_socks5_connection_t *proxy_connection;
  ftun_operation_t *open_operation;
  ftun_path_scope_t *path_scope;
  ftun_resolver_scope_t *resolver_scope;
  ftun_path_t *path;
  ftun_channel_t *remote_channel;
  ftun_datagram_send_token_t sending;
  bool cancelling_send;
  bool resume_pending;
  ftun_status_t failure;
  ftun_datagram_send_token_t pending[FTUN_PROXY_RUNTIME_DATAGRAM_CAPACITY];
  ftun_endpoint_t remote;
  ftun_endpoint_t proxy_server;
  ftun_endpoint_t proxy_resolved[FTUN_SESSION_MAX_RESOLVED];
  ftun_endpoint_t target_candidates[FTUN_SESSION_MAX_RESOLVED];
  ftun_endpoint_t target_allowed[FTUN_SESSION_MAX_RESOLVED];
  ftun_target_t socks_target;
  char proxy_domain[254];
  char target_domain[254];
  uint8_t proxy_username[FTUN_SOCKS5_MAX_CREDENTIAL_BYTES];
  uint8_t proxy_password[FTUN_SOCKS5_MAX_CREDENTIAL_BYTES];
  size_t proxy_resolved_count;
  size_t proxy_username_length;
  size_t proxy_password_length;
  size_t pending_count;
  ftun_status_t open_status;
  uint32_t outbound_id;
  bool socks5;
  bool ready;
  bool destroying;
  bool ready_queued;
  bool active;
} ftun_proxy_runtime_udp_slot_t;

struct ftun_proxy_runtime_udp_pending {
  ftun_proxy_slot_token_t slot_token;
  struct ftun_proxy_runtime *engine;
  ftun_operation_t *operation;
  ftun_runtime_t *runtime;
  ftun_resolver_scope_t *resolver_scope;
  ftun_path_scope_t *path_scope;
  ftun_datagram_t *inbound;
  ftun_packet_t packet;
  ftun_metadata_t metadata;
  ftun_endpoint_t resolved[FTUN_UDP_FLOW_MAX_RESOLVED];
  ftun_route_result_t route;
  char domain[254];
  size_t resume_rule;
  bool preserve_route;
  bool cancelled;
  bool tun;
  bool active;
};

typedef struct {
  ftun_proxy_runtime_flow_t *flow;
  ftun_handle_t descriptor;
  ftun_stream_write_token_t pending;
  bool write_shutdown;
} ftun_proxy_runtime_socket_stream_t;

/* 写进展扫描状态：上次看到的累计确认字节数，以及“有积压且确认不前进”的起点。 */
typedef struct {
  uint64_t acked;
  uint64_t stalled_since_ms;
} ftun_proxy_runtime_progress_t;

typedef enum {
  FTUN_PROXY_RUNTIME_FLOW_HANDSHAKE = 1,
  FTUN_PROXY_RUNTIME_FLOW_CONNECTING,
  FTUN_PROXY_RUNTIME_FLOW_RELAY,
  FTUN_PROXY_RUNTIME_FLOW_UDP_ASSOCIATE,
  FTUN_PROXY_RUNTIME_FLOW_CLOSING,
  /* 收尾失败：继续占用自己的槽位，由定期清理重试（对象级故障）。 */
  FTUN_PROXY_RUNTIME_FLOW_QUARANTINED
} ftun_proxy_runtime_flow_state_t;

typedef enum {
  FTUN_PROXY_RUNTIME_FLOW_PENDING = 0,
  FTUN_PROXY_RUNTIME_FLOW_TCP,
  FTUN_PROXY_RUNTIME_FLOW_ASSOCIATION
} ftun_proxy_runtime_flow_class_t;

struct ftun_proxy_runtime_listener {
  struct ftun_proxy_runtime *engine;
  ftun_handle_t descriptor;
  ftun_handle_t udp_descriptor;
  ftun_event_source_t *source;
  ftun_event_source_t *udp_source;
  uint32_t events;
  uint32_t udp_events;
  char *name;
  ftun_config_inbound_kind_t kind;
  uint32_t inbound_id;
  /* 恢复：地址与是否带 UDP 在打开时记下；waiting 表示 socket 已关闭、等待重新
   * bind；paused 表示 socket 仍在、accept 因资源不足暂停读取。 */
  ftun_endpoint_t address;
  bool udp;
  /* 来自 inbounds[].tcp-idle；0 表示继承 base.timeouts.tcp-idle。创建时记下，reload 不改。 */
  uint32_t tcp_idle_ms;
  bool waiting;
  bool paused;
  ftun_socket_bind_issue_t bind_issue;
  ftun_recovery_id_t recovery;
};

struct ftun_proxy_runtime_flow {
  ftun_proxy_slot_token_t slot_token;
  ftun_proxy_runtime_flow_t *ready_next;
  ftun_proxy_runtime_flow_t *association_client_next;
  ftun_proxy_runtime_flow_t *association_channel_next;
  struct ftun_proxy_runtime *engine;
  ftun_budget_t *budget;
  ftun_reservation_t admission;
  ftun_proxy_runtime_listener_t *listener;
  ftun_proxy_runtime_socket_stream_t client_socket;
  ftun_proxy_runtime_socket_stream_t remote_socket;
  ftun_proxy_runtime_progress_t client_progress;
  ftun_proxy_runtime_progress_t remote_progress;
  ftun_stream_t *client;
  ftun_stream_t *remote;
  ftun_path_t *remote_path;
  ftun_path_scope_t *path_scope;
  ftun_resolver_scope_t *resolver_scope;
  ftun_session_t *session;
  ftun_relay_t *relay;
  ftun_operation_t *open_operation;
  ftun_runtime_t *udp_runtime;
  ftun_event_source_t *client_source;
  ftun_event_source_t *remote_source;
  ftun_event_source_t *deadline_source;
  ftun_socks5_connection_t *proxy_connection;
  ftun_inbound_adapter_t *protocol;
  uint64_t protocol_deadline_ms;
  ftun_proxy_runtime_flow_state_t state;
  ftun_proxy_runtime_flow_class_t flow_class;
  uint8_t *preread;
  ftun_reservation_t preread_reservation;
  size_t preread_capacity;
  size_t preread_offset;
  size_t preread_length;
  ftun_buffer_slice_t preread_slice;
  ftun_operation_t *preread_operation;
  ftun_status_t preread_status;
  ftun_status_t accept_failure;
  ftun_metadata_t pending_metadata;
  ftun_endpoint_t proxy_resolved[FTUN_SESSION_MAX_RESOLVED];
  char sniff_domain[FTUN_SNIFF_DOMAIN_BYTES];
  size_t proxy_resolved_count;
  uint64_t sniff_deadline_ms;
  uint64_t handshake_deadline_ms;
  /* 最近一次转发活动的时刻（任一方向的事件或搬运），空闲回收按它判定。 */
  uint64_t last_activity_ms;
  uint64_t udp_generation;
  uint32_t proxy_leaf_id;
  uint32_t udp_inbound_id;
  uint16_t proxy_port;
  uint32_t left_events;
  uint32_t client_events;
  uint32_t remote_events;
  uint32_t path_events;
  ftun_datagram_t *udp_channel;
  ftun_endpoint_t tcp_peer;
  ftun_endpoint_t udp_request;
  ftun_endpoint_t udp_client;
  bool tun;
  bool udp_client_pinned;
  bool association_client_indexed;
  bool association_channel_indexed;
  bool ready_queued;
  bool driving;
  bool reschedule;
  bool active;
};

/* base.timeouts 在 Proxy 内用到的部分；reload 先暂存，提交时一并生效。 */
typedef struct {
  ftun_socket_liveness_t liveness;
  uint32_t handshake_ms;
  uint32_t connect_ms;
  uint32_t reply_ms;
  uint32_t tcp_idle_ms;
  uint32_t write_progress_ms;
} ftun_proxy_runtime_timeouts_t;

static inline void ftun_proxy_runtime_timeouts_from(const ftun_config_t *config,
  ftun_proxy_runtime_timeouts_t *out)
{
  out->liveness = ftun_config_socket_liveness(config);
  /* TCP_USER_TIMEOUT 会按队首数据的入队时间计时，误关慢速但有进展的连接；
   * 转发连接改由应用层扫描确认进展，这里不设置。 */
  out->liveness.user_timeout_ms = 0u;
  out->write_progress_ms = ftun_config_base(config)->timeouts.write_progress_ms;
  out->handshake_ms = ftun_config_base(config)->timeouts.handshake_ms;
  out->connect_ms = ftun_config_base(config)->timeouts.connect_ms;
  out->reply_ms = ftun_config_base(config)->timeouts.reply_ms;
  out->tcp_idle_ms = ftun_config_base(config)->timeouts.tcp_idle_ms;
}

struct ftun_proxy_runtime {
  ftun_core_t *core;
  ftun_budget_t *budget;
  ftun_reservation_t reservation;
  ftun_operation_queue_t *operations;
  ftun_resolver_provider_t *resolver_provider;
  ftun_path_provider_t *path_provider;
  ftun_control_path_binding_t control_path;
  const ftun_egress_provider_t *egress, *pending_egress;
  const ftun_egress_provider_t *const *egress_slot;
  const ftun_l3_provider_t *l3_provider;
  ftun_event_loop_t *loop;
  ftun_event_source_t *deadline_source;
  /* 解析工作对延迟敏感。健康探测、FRS 更新与持久化使用独立有界队列，
   * 避免维护任务占用唯一的系统解析执行槽。 */
  ftun_worker_t *worker;
  ftun_worker_t *maintenance_worker;
  ftun_tls_context_t *http_tls_context;
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  ftun_worker_t *fakeip_worker;
#endif
  ftun_buffer_pool_t *relay_pool;
  ftun_proxy_dns_runtime_adapter_t *dns_adapter;
  ftun_fakeip_service_t **fakeip_slot;
  ftun_proxy_runtime_health_group_t *health_groups;
  ftun_proxy_runtime_health_group_t *pending_health_groups;
  ftun_proxy_runtime_health_slot_t *health_slots;
  ftun_proxy_runtime_health_slot_t *pending_health_slots;
  ftun_reservation_t health_reservation;
  ftun_reservation_t pending_health_reservation;
  size_t health_group_count;
  size_t pending_health_group_count;
  size_t health_slot_count;
  size_t pending_health_slot_count;
  size_t health_cursor;
  uint64_t health_deadline_ms;
  uint64_t health_deadline_generation;
  size_t health_scan_work;
  bool health_deadline_valid;
  bool health_deadline_present;
  bool pending_health_reuse;
  ftun_proxy_runtime_listener_t listeners[FTUN_PROXY_RUNTIME_MAX_LISTENERS];
  uint32_t pending_listener_ids[FTUN_PROXY_RUNTIME_MAX_LISTENERS];
  ftun_proxy_slot_pool_t *flow_pool;
  size_t flow_capacity;
  /* 收尾失败而被隔离的流；每轮最多重试 QUARANTINE_QUOTA 个，间隔 RETRY_MS。 */
  ftun_recovery_scheduler_t *recovery;
  size_t quarantined_flows;
  size_t quarantine_cursor;
  uint64_t quarantine_due_ms;
  uint64_t round_ms;
  uint64_t idle_next_ms;
  size_t idle_cursor;
  size_t object_faults;
  size_t tcp_capacity;
  size_t association_capacity;
  size_t active_tcp_flows;
  size_t active_associations;
  ftun_proxy_runtime_flow_t *ready_flow_head;
  ftun_proxy_runtime_flow_t *ready_flow_tail;
  ftun_proxy_runtime_flow_t **association_clients;
  ftun_proxy_runtime_flow_t **association_channels;
  size_t association_bucket_count;
  ftun_udp_flow_table_t *udp_flows;
  ftun_proxy_slot_pool_t *udp_pool;
  ftun_proxy_slot_pool_t *udp_pending_pool;
  size_t udp_capacity;
  size_t tun_flow_count;
  size_t tun_pending_count;
  ftun_proxy_runtime_udp_backoff_t *udp_backoff;
  size_t udp_backoff_capacity;
  ftun_proxy_runtime_udp_slot_t *ready_udp_head;
  ftun_proxy_runtime_udp_slot_t *ready_udp_tail;
  size_t listener_count;
  size_t listener_cursor;
  uint64_t generation;
  uint64_t now_ms;
  uint64_t deadline_ms;
  uint32_t socket_mark;
  /* 来自 base.timeouts；reload 提交时刷新。 */
  ftun_socket_liveness_t liveness;
  uint32_t handshake_ms;
  uint32_t connect_ms;
  uint32_t reply_ms;
  uint32_t tcp_idle_ms;
  uint32_t write_progress_ms;
  ftun_proxy_runtime_timeouts_t pending_timeouts;
  uint16_t next_dns_query_id;
  /* 规则因引用未就绪的 FRS 集合而拒绝连接的日志，每个 NOT_READY 期间只记一次。 */
  bool frs_not_ready_logged;
#if defined(FTUN_HAVE_MODULE_FRS)
  /* 启动时本地规则文件缺失：FRS 规则 NOT_READY，后台下载按退避重试（1s→30s）。 */
  bool frs_not_ready;
  uint64_t frs_retry_ms;
  ftun_operation_t *frs_operation;
  ftun_runtime_t *frs_candidate;
  char *frs_etag;
  char *frs_candidate_etag;
  ftun_reservation_t frs_etag_reservation;
  ftun_reservation_t frs_candidate_etag_reservation;
  ftun_reservation_t frs_group_records_reservation;
  ftun_runtime_group_record_t *frs_group_records;
  size_t frs_group_record_capacity;
  uint64_t frs_due_ms;
  uint64_t frs_interval_ms;
  uint64_t frs_operation_generation;
  /* 本次 FRS 发布在 Core 上下文预留的代次；零表示未持有预留。 */
  uint64_t frs_reserved_generation;
  uint64_t pending_frs_interval_ms;
  bool frs_enabled;
  bool pending_frs_enabled;

#endif
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  ftun_fakeip_store_t *fakeip_store;
  ftun_fakeip_service_t *fakeip;
  char *fakeip_directory;
  ftun_reservation_t fakeip_directory_reservation;
  ftun_operation_t *fakeip_reserve_operation;
  ftun_status_t fakeip_store_status;
  size_t fakeip_store_completions;
  bool fakeip_reserve_warning;
#endif
#if defined(FTUN_HAVE_MODULE_TUN)
  ftun_proxy_runtime_listener_t tun_listener;
  ftun_tun_lease_t tun_lease;
  ftun_tun_ingress_context_t *tun_ingress;
  ftun_packet_port_info_t tun_info;
  ftun_tun_ingress_spec_t tun_spec;
  size_t tun_flow_cursor;
  size_t tun_pending_cursor;
  uint64_t tun_reset_due_ms;
  bool tun_resetting;
  bool tun_provider_ready;
  uint32_t pending_tun_inbound_id;
  bool has_tun;
  bool tun_auto_route;
#endif
  bool accepting;
  bool deadline_ready;
  bool reload_prepared;
  bool reload_pending;
  /* 准备状态的持有者（宿主 reload / FRS 更新）。各方只撤销或提交自己持有的
   * 准备，另一方持有时 prepare 返回 AGAIN。 */
  ftun_proxy_reload_owner_t reload_owner;
  bool cleanup_only;
  bool stopped;
};


ftun_status_t ftun_proxy_runtime_accept(ftun_proxy_runtime_t *engine,
                                         ftun_proxy_runtime_listener_t *listener);
ftun_status_t ftun_proxy_runtime_accept_pause(
  ftun_proxy_runtime_t *engine, ftun_proxy_runtime_listener_t *listener);
size_t ftun_proxy_runtime_association_channel_bucket(
  const ftun_proxy_runtime_t *engine, const ftun_datagram_t *channel);
size_t ftun_proxy_runtime_association_client_bucket(
  const ftun_proxy_runtime_t *engine,
  const ftun_proxy_runtime_listener_t *listener, const ftun_endpoint_t *client);
void ftun_proxy_runtime_association_destroy(void *user);
ftun_proxy_runtime_flow_t *ftun_proxy_runtime_association_find(
  ftun_proxy_runtime_t *engine, ftun_proxy_runtime_listener_t *listener,
  const ftun_endpoint_t *client);
ftun_proxy_runtime_flow_t *ftun_proxy_runtime_association_find_channel(
  ftun_proxy_runtime_t *engine, ftun_datagram_t *channel);
void ftun_proxy_runtime_association_index_channel(ftun_proxy_runtime_flow_t *flow);
void ftun_proxy_runtime_association_index_client(ftun_proxy_runtime_flow_t *flow);
ftun_status_t ftun_proxy_runtime_association_receive(
  ftun_datagram_t *channel, const ftun_endpoint_t *source,
  const ftun_packet_t *packet, void *user);
void ftun_proxy_runtime_association_result(
  ftun_datagram_t *channel, ftun_error_t error,
  const ftun_endpoint_t *target, const ftun_packet_t *packet, void *user);
ftun_status_t ftun_proxy_runtime_association_send_cancel(
  void *user, ftun_datagram_send_token_t send);
ftun_status_t ftun_proxy_runtime_association_send_start(
  void *user, ftun_datagram_send_token_t send,
  const ftun_endpoint_t *target,
  const ftun_packet_t *packet);
ftun_status_t ftun_proxy_runtime_association_start(
  ftun_proxy_runtime_flow_t *flow, const ftun_endpoint_t *requested);
void ftun_proxy_runtime_association_unlink(ftun_proxy_runtime_flow_t *flow);
void ftun_proxy_runtime_background_log(ftun_proxy_runtime_t *engine,
                                       ftun_status_t status,
                                       ftun_diagnostic_kind_t kind, const char *message);
ftun_status_t ftun_proxy_runtime_build_inbound_spec(
  ftun_proxy_runtime_flow_t *flow, const ftun_config_inbound_t *config,
  ftun_inbound_spec_t *spec, ftun_inbound_user_t **out_users,
  ftun_reservation_t *out_reservation);
ftun_status_t ftun_proxy_runtime_copy_etag(ftun_budget_t *budget,
  const uint8_t *value, size_t length, char **out,
  ftun_reservation_t *out_reservation);
ftun_status_t ftun_proxy_runtime_copy_preread(ftun_proxy_runtime_flow_t *flow,
                                               ftun_bytes_t bytes);
void ftun_proxy_runtime_deadline_consider(uint64_t candidate,
                                           uint64_t *deadline,
                                           bool *present);
void ftun_proxy_runtime_deadline_ready(ftun_event_source_t *source,
                                       uint32_t events, void *user);
ftun_status_t ftun_proxy_runtime_deadline_run(
  ftun_proxy_runtime_t *engine, uint64_t now_ms, size_t *out_work,
  uint64_t *out_lateness, bool *out_quota_exhausted);
ftun_status_t ftun_proxy_runtime_deadline_schedule(ftun_proxy_runtime_t *engine);
void ftun_proxy_runtime_direct_path_completed(ftun_operation_t *operation,
  ftun_error_t error, ftun_path_t *path, void *user);
void ftun_proxy_runtime_downstream_failed(ftun_proxy_runtime_flow_t *flow,
  ftun_status_t failure);
int ftun_proxy_runtime_duration_ms(const char *value, uint64_t *out);
int ftun_proxy_runtime_endpoint_equal(const ftun_endpoint_t *left,
                                      const ftun_endpoint_t *right);
ftun_status_t ftun_proxy_runtime_fakeip_prepare(ftun_proxy_runtime_t *engine,
                                                 const ftun_config_t *config);
ftun_status_t ftun_proxy_runtime_fakeip_range(const char *text,
                                               uint32_t *first,
                                               uint32_t *end);
ftun_status_t ftun_proxy_runtime_fakeip_reserve_runtime(
  ftun_proxy_runtime_t *engine);
void ftun_proxy_runtime_fakeip_store_completed(
  ftun_operation_t *operation, ftun_error_t error,
  ftun_fakeip_store_operation_t kind, uint64_t sequence,
  uint32_t reserved_end, void *user);
ftun_proxy_runtime_flow_t *ftun_proxy_runtime_flow_at(
  ftun_proxy_runtime_t *engine, size_t index);
ftun_status_t ftun_proxy_runtime_flow_classify(
  ftun_proxy_runtime_flow_t *flow, ftun_proxy_runtime_flow_class_t flow_class);
void ftun_proxy_runtime_flow_client_ready(ftun_event_source_t *source,
                                          uint32_t events, void *user);
void ftun_proxy_runtime_flow_close(ftun_proxy_runtime_flow_t *flow,
                                   ftun_status_t reason);
ftun_status_t ftun_proxy_runtime_flow_create(ftun_proxy_runtime_t *engine,
                                              ftun_proxy_runtime_listener_t *listener,
                                              ftun_handle_t descriptor,
                                              const ftun_endpoint_t *peer);
ftun_status_t ftun_proxy_runtime_flow_deadline_arm(
  ftun_proxy_runtime_flow_t *flow, uint64_t deadline_ms);
void ftun_proxy_runtime_flow_deadline_ready(ftun_event_source_t *source,
                                             uint32_t events, void *user);
ftun_status_t ftun_proxy_runtime_flow_drain(ftun_proxy_runtime_t *engine,
                                             size_t quota,
                                             size_t *out_work);
ftun_status_t ftun_proxy_runtime_flow_drive(ftun_proxy_runtime_flow_t *flow,
                                             uint32_t client_events,
                                             uint32_t remote_events);
ftun_status_t ftun_proxy_runtime_flow_finalize(ftun_proxy_runtime_flow_t *flow);
uint32_t ftun_proxy_runtime_flow_idle_ms(const ftun_proxy_runtime_t *engine,
                                                const ftun_proxy_runtime_flow_t *flow);
ftun_status_t ftun_proxy_runtime_flow_interests(
  ftun_proxy_runtime_flow_t *flow, uint32_t *client, uint32_t *remote);
void ftun_proxy_runtime_flow_remote_ready(ftun_event_source_t *source,
                                          uint32_t events, void *user);
void ftun_proxy_runtime_flow_schedule(ftun_proxy_runtime_flow_t *flow);
ftun_status_t ftun_proxy_runtime_flow_settle(ftun_proxy_runtime_flow_t *flow);
ftun_status_t ftun_proxy_runtime_flow_slot_acquire(
  ftun_proxy_runtime_t *engine, ftun_proxy_runtime_flow_t **out);
ftun_status_t ftun_proxy_runtime_flow_slot_release(
  ftun_proxy_runtime_flow_t **flow);
void ftun_proxy_runtime_flow_unclassify(ftun_proxy_runtime_flow_t *flow);
ftun_status_t ftun_proxy_runtime_flow_update_sources(ftun_proxy_runtime_flow_t *flow);
ftun_status_t ftun_proxy_runtime_flush_preread(ftun_proxy_runtime_flow_t *flow);
void ftun_proxy_runtime_frs_completed(ftun_operation_t *operation,
                                      ftun_error_t error,
                                      ftun_bytes_t result, void *user);
void ftun_proxy_runtime_frs_publish_completed(ftun_operation_t *operation,
                                               ftun_error_t error,
                                               ftun_bytes_t result,
                                               void *user);
ftun_status_t ftun_proxy_runtime_frs_publish_execute(
  ftun_bytes_t input, uint8_t *result, size_t result_capacity,
  size_t *out_result_size);
ftun_status_t ftun_proxy_runtime_frs_publish_submit(
  ftun_proxy_runtime_t *engine, const char *path, ftun_bytes_t body,
  ftun_worker_completion_fn completion, ftun_operation_t **out);
void ftun_proxy_runtime_frs_release_generation(ftun_proxy_runtime_t *engine);
ftun_status_t ftun_proxy_runtime_frs_schedule(ftun_proxy_runtime_t *engine);
void ftun_proxy_runtime_frs_schedule_next(ftun_proxy_runtime_t *engine,
                                           uint64_t now_ms);
void ftun_proxy_runtime_health_completed(ftun_operation_t *operation,
                                         ftun_error_t error,
                                         ftun_bytes_t result, void *user);
int ftun_proxy_runtime_health_config_equal(const ftun_config_t *left,
                                           const ftun_config_t *right);
void ftun_proxy_runtime_health_consume(ftun_proxy_runtime_t *engine,
                                       uint32_t group_id);
void ftun_proxy_runtime_health_deadline_refresh(ftun_proxy_runtime_t *engine);
ftun_status_t ftun_proxy_runtime_health_prepare(
  ftun_proxy_runtime_t *engine, const ftun_config_t *config, uint64_t generation,
  ftun_proxy_runtime_health_group_t **out_groups, size_t *out_group_count,
  ftun_proxy_runtime_health_slot_t **out_slots, size_t *out_slot_count,
  ftun_reservation_t *out_reservation);
ftun_status_t ftun_proxy_runtime_health_publish(
  ftun_proxy_runtime_health_slot_t *completed, uint64_t now_ms);
ftun_status_t ftun_proxy_runtime_health_release(
  ftun_proxy_runtime_health_group_t **groups,
  ftun_proxy_runtime_health_slot_t **slots,
  size_t slot_count, ftun_reservation_t *reservation);
ftun_status_t ftun_proxy_runtime_health_run(ftun_proxy_runtime_t *engine,
                                             size_t quota,
                                             size_t *out_work);
ftun_status_t ftun_proxy_runtime_http_execute(
  ftun_bytes_t input, uint8_t *result, size_t result_capacity,
  size_t *out_result_size);
ftun_status_t ftun_proxy_runtime_http_input_cleanup(ftun_bytes_t input);
ftun_status_t ftun_proxy_runtime_http_result_cleanup(ftun_bytes_t result);
ftun_status_t ftun_proxy_runtime_http_submit(
  ftun_proxy_runtime_t *engine, const ftun_http_fetch_spec_t *spec,
  bool validate_frs, ftun_runtime_t *runtime_snapshot,
  ftun_worker_completion_fn completion, void *user,
  ftun_operation_t **out);
bool ftun_proxy_runtime_idle_possible(const ftun_proxy_runtime_t *engine);
bool ftun_proxy_runtime_write_stalled(ftun_proxy_runtime_progress_t *progress,
  ftun_status_t status, uint64_t acked, uint32_t queued, uint64_t now_ms,
  uint32_t limit_ms);
size_t ftun_proxy_runtime_idle_scan(ftun_proxy_runtime_t *engine, uint64_t now_ms);
const ftun_config_inbound_t *ftun_proxy_runtime_inbound_by_id(
  const ftun_config_t *config, uint32_t inbound_id);
const ftun_config_inbound_t *ftun_proxy_runtime_inbound_config(
  const ftun_config_t *config, const ftun_proxy_runtime_listener_t *listener);
ftun_status_t ftun_proxy_runtime_leaf(
  ftun_proxy_runtime_t *engine, const ftun_runtime_t *runtime,
  const ftun_config_t *config,
  uint32_t requested, uint64_t generation, ftun_outbound_leaf_t *leaf,
  const ftun_config_outbound_t **out_config);
ftun_status_t ftun_proxy_runtime_listener_bind(
  ftun_proxy_runtime_listener_t *listener);
ftun_status_t ftun_proxy_runtime_listener_close(
  ftun_proxy_runtime_listener_t *listener);
ftun_status_t ftun_proxy_runtime_listener_endpoint(
  ftun_proxy_runtime_listener_t *listener, const ftun_config_inbound_t *config,
  uint32_t inbound_id);
ftun_status_t ftun_proxy_runtime_listener_fail(
  ftun_proxy_runtime_t *engine, ftun_proxy_runtime_listener_t *listener,
  ftun_recovery_fault_t fault);
void ftun_proxy_runtime_listener_ready(ftun_event_source_t *source,
                                       uint32_t events, void *user);
ftun_status_t ftun_proxy_runtime_listener_recover(
  void *user, ftun_recovery_id_t id);
ftun_status_t ftun_proxy_runtime_listener_start(
  ftun_proxy_runtime_t *engine, ftun_proxy_runtime_listener_t *listener);
ftun_status_t ftun_proxy_runtime_listener_udp(ftun_proxy_runtime_t *engine,
                                               ftun_proxy_runtime_listener_t *listener);
void ftun_proxy_runtime_listener_udp_ready(ftun_event_source_t *source,
                                           uint32_t events, void *user);
ftun_status_t ftun_proxy_runtime_next_deadline(ftun_proxy_runtime_t *engine,
                                                uint64_t *out_deadline,
                                                bool *out_present);
void ftun_proxy_runtime_note_denied(ftun_proxy_runtime_t *engine,
                                           const ftun_route_result_t *route);
ftun_status_t ftun_proxy_runtime_object_admit(
  ftun_proxy_runtime_t *engine, ftun_budget_resources_t minimum,
  ftun_budget_t **out_budget, ftun_reservation_t *out_admission);
ftun_status_t ftun_proxy_runtime_object_release(
  ftun_budget_t **budget, ftun_reservation_t *admission);
ftun_status_t ftun_proxy_runtime_operation_complete(ftun_proxy_runtime_flow_t *flow,
  ftun_operation_t *operation, ftun_error_t error);
/* SOCKS5 上游：IP 字面量或 域名:端口；域名指向 text，调用方保证其存活。 */
ftun_status_t ftun_proxy_runtime_parse_server_endpoint(
  const char *text, ftun_endpoint_t *out);
/* 引导 DNS：IP 字面量，端口缺省 53。 */
ftun_status_t ftun_proxy_runtime_parse_bootstrap_endpoint(
  const char *text, ftun_endpoint_t *out);
ftun_status_t ftun_proxy_runtime_parse_ip_endpoint(
  const char *text, ftun_endpoint_t *out);
void ftun_proxy_runtime_path_notify(ftun_path_t *path, uint32_t events,
  ftun_error_t error, void *user);
ftun_status_t ftun_proxy_runtime_prepare_inbound_ids(
  ftun_proxy_runtime_t *engine, const ftun_config_t *config);
ftun_status_t ftun_proxy_runtime_preread_ensure(ftun_proxy_runtime_flow_t *flow,
                                                size_t required);
ftun_status_t ftun_proxy_runtime_preread_release(ftun_proxy_runtime_flow_t *flow);
void ftun_proxy_runtime_preread_written(ftun_operation_t *operation,
  ftun_error_t error, void *user);
ftun_status_t ftun_proxy_runtime_protocol_drive(ftun_proxy_runtime_flow_t *flow,
  bool readable);
ftun_status_t ftun_proxy_runtime_protocol_finish(
  ftun_proxy_runtime_flow_t *flow, ftun_status_t downstream,
  const ftun_endpoint_t *bound);
bool ftun_proxy_runtime_protocol_pending(ftun_proxy_runtime_flow_t *flow);
ftun_status_t ftun_proxy_runtime_protocol_update(ftun_proxy_runtime_flow_t *flow);
void ftun_proxy_runtime_proxy_resolved(
  ftun_operation_t *operation, ftun_error_t error,
  const ftun_system_resolve_result_t *result, void *user);
ftun_status_t ftun_proxy_runtime_quarantine_run(
  ftun_proxy_runtime_t *engine, uint64_t now_ms, size_t *out_work);
ftun_status_t ftun_proxy_runtime_relay_path_ready(ftun_proxy_runtime_flow_t *flow);
void ftun_proxy_runtime_relay_progress(void *user);
ftun_status_t ftun_proxy_runtime_relay_ready(ftun_proxy_runtime_flow_t *flow,
                                              ftun_handle_t descriptor);
ftun_status_t ftun_proxy_runtime_reload_abort_owned(
  ftun_proxy_runtime_t *engine, ftun_proxy_reload_owner_t owner);
ftun_status_t ftun_proxy_runtime_reload_commit_owned(
  ftun_proxy_runtime_t *engine, uint64_t generation,
  ftun_proxy_reload_owner_t owner);
ftun_status_t ftun_proxy_runtime_reload_prepare_owned(
  ftun_proxy_runtime_t *engine, const ftun_config_t *config, uint64_t generation,
  const void *plan, ftun_proxy_reload_owner_t owner);
ftun_status_t ftun_proxy_runtime_replace_etag(ftun_proxy_runtime_t *engine,
                                               const uint8_t *value,
                                               size_t length);
ftun_status_t ftun_proxy_runtime_resolve_async(
  ftun_proxy_runtime_t *engine, ftun_budget_t *budget,
  const ftun_config_t *config, ftun_resolver_scope_t *scope,
  ftun_string_t domain, bool bootstrap_only,
  ftun_system_resolve_completion_fn completion, void *user,
  ftun_operation_t **out);
void ftun_proxy_runtime_resolve_completed(
  ftun_operation_t *operation, ftun_error_t error,
  const ftun_system_resolve_result_t *result, void *user);
ftun_status_t ftun_proxy_runtime_resolve_session(
  ftun_proxy_runtime_flow_t *flow, ftun_string_t server);
ftun_status_t ftun_proxy_runtime_restore_fakeip(ftun_proxy_runtime_flow_t *flow,
                                                ftun_metadata_t *metadata);
ftun_status_t ftun_proxy_runtime_restore_fakeip_to(
  ftun_proxy_runtime_t *engine, ftun_metadata_t *metadata,
  char *domain_storage, size_t domain_capacity);
ftun_status_t ftun_proxy_runtime_route_open(ftun_proxy_runtime_flow_t *flow);
ftun_status_t ftun_proxy_runtime_runtime_for_flow(
  ftun_proxy_runtime_flow_t *flow, ftun_runtime_t **out_runtime,
  const ftun_config_t **out_config);
ftun_status_t ftun_proxy_runtime_session_start(
  ftun_proxy_runtime_flow_t *flow, const ftun_endpoint_t *requested_target);
ftun_status_t ftun_proxy_runtime_session_start_metadata(
  ftun_proxy_runtime_flow_t *flow, const ftun_metadata_t *input);
void ftun_proxy_runtime_socks_completed(
  ftun_operation_t *operation, ftun_error_t error,
  ftun_socks5_connection_t *connection, void *user);
ftun_status_t ftun_proxy_runtime_start_real_resolution(
  ftun_proxy_runtime_flow_t *flow, ftun_resolve_request_t *request);
ftun_status_t ftun_proxy_runtime_stream_complete_pending(
  ftun_proxy_runtime_socket_stream_t *socket_stream);
void ftun_proxy_runtime_stream_completed(ftun_operation_t *operation,
                                         ftun_error_t error, void *user);
ftun_status_t ftun_proxy_runtime_stream_create(
  ftun_proxy_runtime_flow_t *flow, ftun_proxy_runtime_socket_stream_t *socket_stream,
  ftun_handle_t descriptor, ftun_stream_t **out);
void ftun_proxy_runtime_stream_destroy(void *user);
void ftun_proxy_runtime_stream_progress(void *user);
ftun_status_t ftun_proxy_runtime_stream_read(void *user, void *buffer,
                                              size_t capacity,
                                              size_t *out_length);
ftun_status_t ftun_proxy_runtime_stream_shutdown(void *user);
ftun_status_t ftun_proxy_runtime_stream_write_cancel(
  void *user, ftun_stream_write_token_t write);
ftun_status_t ftun_proxy_runtime_stream_write_start(
  void *user, ftun_stream_write_token_t write,
  const ftun_buffer_slice_t *slice,
  size_t *accepted);
int ftun_proxy_runtime_string_equal(const char *left, const char *right);
int ftun_proxy_runtime_string_list_equal(
  const ftun_config_string_list_t *left,
  const ftun_config_string_list_t *right);
ftun_status_t ftun_proxy_runtime_system_resolver_path(
  void *user, const ftun_socket_policy_t *protection);
#if defined(FTUN_HAVE_MODULE_TUN)
ftun_status_t ftun_proxy_runtime_tun_accept(
  void *user, const ftun_metadata_t *metadata, ftun_stream_t *stream);
ftun_status_t ftun_proxy_runtime_tun_activate(
  ftun_proxy_runtime_t *engine);
ftun_status_t ftun_proxy_runtime_tun_begin(ftun_proxy_runtime_flow_t *flow,
                                           const ftun_metadata_t *metadata);
ftun_status_t ftun_proxy_runtime_tun_datagram(
  void *user, const ftun_metadata_t *metadata, ftun_datagram_t *channel,
  const ftun_endpoint_t *source, const ftun_packet_t *packet);
void ftun_proxy_runtime_tun_event(void *user, ftun_tun_lease_t lease,
  ftun_tun_service_event_t event, ftun_status_t status);
ftun_status_t ftun_proxy_runtime_tun_output(
  void *user, ftun_bytes_t packet);
ftun_status_t ftun_proxy_runtime_tun_packet(
  void *user, ftun_tun_lease_t lease, ftun_bytes_t packet);
ftun_status_t ftun_proxy_runtime_tun_prepare(
  ftun_proxy_runtime_t *engine, const ftun_config_inbound_t *inbound,
  uint32_t inbound_id);
ftun_status_t ftun_proxy_runtime_tun_reset(ftun_proxy_runtime_t *engine,
  uint64_t now_ms, size_t *out_work);
ftun_status_t ftun_proxy_runtime_tun_sniff(ftun_proxy_runtime_flow_t *flow,
                                            bool readable);
void ftun_proxy_runtime_tun_stream_completed(ftun_operation_t *operation,
                                              ftun_error_t error, void *user);
void ftun_proxy_runtime_tun_stream_event(
  void *user, ftun_stream_t *stream, ftun_tun_stream_event_t event,
  ftun_status_t status);
#endif
ftun_proxy_runtime_udp_slot_t *ftun_proxy_runtime_udp_at(
  ftun_proxy_runtime_t *engine, size_t index);
bool ftun_proxy_runtime_udp_backoff_allowed(ftun_proxy_runtime_t *engine,
                                            uint32_t outbound_id);
ftun_status_t ftun_proxy_runtime_udp_backoff_attempt(void *user,
                                                           ftun_recovery_id_t id);
ftun_proxy_runtime_udp_backoff_t *ftun_proxy_runtime_udp_backoff_entry(
  ftun_proxy_runtime_t *engine, uint32_t outbound_id, bool create);
void ftun_proxy_runtime_udp_backoff_failed(ftun_proxy_runtime_t *engine,
                                           uint32_t outbound_id);
void ftun_proxy_runtime_udp_backoff_succeeded(ftun_proxy_runtime_t *engine,
                                              uint32_t outbound_id);
ftun_status_t ftun_proxy_runtime_udp_cleanup(ftun_proxy_runtime_udp_slot_t *slot);
void ftun_proxy_runtime_udp_destroy(void *user);
void ftun_proxy_runtime_udp_direct_completed(ftun_operation_t *operation,
  ftun_error_t error, ftun_path_t *path, void *user);
ftun_status_t ftun_proxy_runtime_udp_drain(ftun_proxy_runtime_t *engine,
  size_t quota, size_t *out_work);
void ftun_proxy_runtime_udp_finish_pending(ftun_proxy_runtime_udp_slot_t *slot,
  ftun_status_t status);
ftun_status_t ftun_proxy_runtime_udp_finish_route(
  ftun_proxy_runtime_udp_pending_t *pending, bool after_resolution);
void ftun_proxy_runtime_udp_handshake_written(ftun_operation_t *operation,
  ftun_error_t error, void *user);
ftun_status_t ftun_proxy_runtime_udp_open(
  void *user, ftun_core_t *core, const ftun_runtime_t *runtime,
  const ftun_metadata_t *metadata, const ftun_route_result_t *prepared_route,
  const ftun_udp_flow_admission_t *admission,
  ftun_datagram_result_fn result,
  ftun_datagram_receive_fn receive, void *callback_user,
  uint32_t *outbound_id, ftun_endpoint_t *remote, ftun_datagram_t **out);
void ftun_proxy_runtime_udp_path_notify(ftun_path_t *path, uint32_t events,
  ftun_error_t error, void *user);
ftun_proxy_runtime_udp_pending_t *ftun_proxy_runtime_udp_pending_at(
  ftun_proxy_runtime_t *engine, size_t index);
void ftun_proxy_runtime_udp_pending_cancel_all(ftun_proxy_runtime_t *engine);
void ftun_proxy_runtime_udp_pending_cancel_inbound(
  ftun_proxy_runtime_t *engine, ftun_datagram_t *inbound);
void ftun_proxy_runtime_udp_pending_release(
  ftun_proxy_runtime_udp_pending_t *pending);
void ftun_proxy_runtime_udp_proxy_resolved(
  ftun_operation_t *operation, ftun_error_t error,
  const ftun_system_resolve_result_t *result, void *user);
ftun_status_t ftun_proxy_runtime_udp_queue_send(
  ftun_proxy_runtime_udp_slot_t *slot, ftun_datagram_send_token_t send);
ftun_status_t ftun_proxy_runtime_udp_received(ftun_datagram_t *channel,
  const ftun_endpoint_t *source, const ftun_packet_t *packet, void *user);
ftun_status_t ftun_proxy_runtime_udp_reply(
  void *user, ftun_datagram_t *inbound, const ftun_metadata_t *metadata,
  const ftun_endpoint_t *source, const ftun_packet_t *packet);
void ftun_proxy_runtime_udp_resolved(
  ftun_operation_t *operation, ftun_error_t error,
  const ftun_system_resolve_result_t *result, void *user);
ftun_status_t ftun_proxy_runtime_udp_route_datagram(
  ftun_proxy_runtime_t *engine, ftun_datagram_t *inbound,
  const ftun_metadata_t *metadata, const ftun_packet_t *packet,
  ftun_runtime_t *runtime, bool tun);
ftun_status_t ftun_proxy_runtime_udp_route_own(
  ftun_route_result_t *route);
void ftun_proxy_runtime_udp_schedule(ftun_proxy_runtime_udp_slot_t *slot);
ftun_status_t ftun_proxy_runtime_udp_send_cancel(void *user,
  ftun_datagram_send_token_t send);
ftun_status_t ftun_proxy_runtime_udp_send_packet(ftun_proxy_runtime_udp_slot_t *slot,
  ftun_datagram_send_token_t send, const ftun_endpoint_t *target, const ftun_packet_t *packet);
ftun_status_t ftun_proxy_runtime_udp_send_start(void *user,
  ftun_datagram_send_token_t send, const ftun_endpoint_t *target, const ftun_packet_t *packet);
void ftun_proxy_runtime_udp_sent(ftun_datagram_t *channel, ftun_error_t error,
  const ftun_endpoint_t *target, const ftun_packet_t *packet, void *user);
ftun_status_t ftun_proxy_runtime_udp_slot_reset(ftun_proxy_runtime_udp_slot_t *slot);
void ftun_proxy_runtime_udp_socks_completed(ftun_operation_t *operation,
  ftun_error_t error, ftun_socks5_connection_t *connection, void *user);
ftun_status_t ftun_proxy_runtime_udp_socks_prepare(
  ftun_proxy_runtime_udp_slot_t *slot, const ftun_target_t *target,
  const ftun_config_outbound_t *config, const ftun_endpoint_t *server);
ftun_status_t ftun_proxy_runtime_udp_socks_start(
  ftun_proxy_runtime_udp_slot_t *slot);
void ftun_proxy_runtime_udp_unschedule(ftun_proxy_runtime_udp_slot_t *slot);
ftun_status_t ftun_proxy_runtime_wait_worker(ftun_proxy_runtime_t *engine,
                                              ftun_worker_t *worker,
                                              size_t expected);
/* 已交付回调的终态优先于等待截止时间；回调交付后取消句柄失效。 */
ftun_status_t ftun_proxy_runtime_wait_worker_until(ftun_proxy_runtime_t *engine,
                                                    ftun_worker_t *worker,
                                                    size_t expected,
                                                    uint64_t deadline_ms);
ftun_status_t ftun_proxy_runtime_worker_stop_until(ftun_worker_t *worker,
                                                    uint64_t deadline_ms);
void ftun_proxy_runtime_worker_wakeup(void *user);
bool ftun_proxy_runtime_zero_ip(const ftun_endpoint_t *endpoint);

#endif
