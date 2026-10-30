#ifndef FTUN_DNS_SERVICE_INTERNAL_H
#define FTUN_DNS_SERVICE_INTERNAL_H

#include "core/limits.h"
#include "dns/service.h"
#include "core/recovery.h"
#include "dns/upstream_set.h"

#if defined(FTUN_HAVE_MODULE_DNS)

#include "dns/dispatcher.h"
#include "libs/resolver/basic.h"
#include "dns/cache.h"
#include "dns/listener.h"
#include "dns/server.h"
#include "libs/resolver/dnswire.h"
#include "core/config/document.h"
#include "libs/transport/egress.h"
#include "libs/transport/datagram.h"
#include "platform/socket.h"
#include "platform/socket.h"
#include "libs/buffer/buffer.h"
#include "platform/clock.h"

#include "platform/socket.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FTUN_DNS_RUNTIME_MAX_SERVERS 32u
#define FTUN_DNS_RUNTIME_MAX_LISTENERS 16u
#define FTUN_DNS_RUNTIME_QUARANTINE_RETRY_MS UINT64_C(100)
/* 监听恢复退避（候选值）。 */
#define FTUN_DNS_RUNTIME_LISTENER_RETRY_INITIAL_MS UINT64_C(100)
#define FTUN_DNS_RUNTIME_LISTENER_RETRY_MAXIMUM_MS UINT64_C(30000)
#define FTUN_DNS_RUNTIME_LISTENER_RETRY_STABLE_MS UINT64_C(60000)
#define FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS 64u
typedef char ftun_dns_tcp_mask_fits[
  (FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS <= 64u) ? 1 : -1];
#define FTUN_DNS_RUNTIME_MAX_PENDING 256u
#define FTUN_DNS_RUNTIME_MAX_PENDING_PER_LISTENER 64u
#define FTUN_DNS_RUNTIME_MAX_WAITERS 1024u
#define FTUN_DNS_RUNTIME_REQUEST_BUCKETS 512u
#define FTUN_DNS_RUNTIME_LANE_COUNT 4u
#define FTUN_DNS_RUNTIME_STOP_QUOTA 32u
#define FTUN_DNS_RUNTIME_TIMEOUT_MS UINT64_C(5000)
#define FTUN_DNS_RUNTIME_ACCEPT_BACKOFF_MIN_MS UINT64_C(50)
#define FTUN_DNS_RUNTIME_ACCEPT_BACKOFF_MAX_MS UINT64_C(1000)
#define FTUN_DNS_RUNTIME_TRANSPORT_BUFFER_BYTES \
  (FTUN_DNS_MAX_MESSAGE_BYTES + 263u)


/* DNS 内部出口编号只在本 service 的配置快照中使用；不依赖 Proxy 私有 ID。 */
enum {
  FTUN_DNS_OUTBOUND_DIRECT = FTUN_EGRESS_DIRECT
};

struct ftun_dns_runtime_plan {
  ftun_reservation_t reservation;
  ftun_config_t *config;
  ftun_endpoint_t servers[FTUN_DNS_RUNTIME_MAX_SERVERS];
  /* 每个服务器的全部上游地址（配置顺序即优先级）；servers[i] 是其中第一个。 */
  ftun_endpoint_t addresses[FTUN_DNS_RUNTIME_MAX_SERVERS][FTUN_UPSTREAM_SET_MAX];
  uint8_t address_count[FTUN_DNS_RUNTIME_MAX_SERVERS];
  size_t server_count;
};

typedef enum {
  FTUN_DNS_RUNTIME_REQUEST_CONNECT = 1,
  FTUN_DNS_RUNTIME_REQUEST_DNS_SEND,
  FTUN_DNS_RUNTIME_REQUEST_DNS_RECV_UDP,
  FTUN_DNS_RUNTIME_REQUEST_DNS_RECV_PREFIX,
  FTUN_DNS_RUNTIME_REQUEST_DNS_RECV_BODY
} ftun_dns_runtime_request_state_t;

typedef struct ftun_dns_runtime_transport_waiter
  ftun_dns_runtime_transport_waiter_t;

typedef struct ftun_dns_runtime_transport_request {
  struct ftun_dns_runtime_transport_request *previous;
  struct ftun_dns_runtime_transport_request *next;
  struct ftun_dns_runtime_transport_request *hash_previous;
  struct ftun_dns_runtime_transport_request *hash_next;
  struct ftun_dns_runtime_transport_request *ready_previous;
  struct ftun_dns_runtime_transport_request *ready_next;
  struct ftun_dns_runtime *dns;
  struct ftun_dns_runtime_transport_request *fallback_parent;
  size_t fallback_children;
  ftun_path_t *path;
  ftun_channel_t *stream;
  ftun_channel_t *datagram;
  ftun_operation_t *opening;
  ftun_operation_t *writing;
  ftun_packet_t received;
  ftun_endpoint_t peer;
  ftun_status_t io_status;
  ftun_status_t completion_status;
  size_t completion_depth;
  uint64_t completed_ms;
  size_t writing_bytes;
  ftun_reservation_t reservation;
  ftun_dns_runtime_transport_waiter_t *waiter_head;
  ftun_dns_runtime_transport_waiter_t *waiter_tail;
  ftun_endpoint_t upstream;
  uint64_t deadline_ms;
  uint8_t *query;
  uint8_t *buffer;
  size_t query_length;
  size_t buffer_length;
  size_t buffer_offset;
  size_t receive_needed;
  size_t response_length;
  uint64_t identity_hash;
  uint64_t policy_fingerprint;
  uint64_t server_fingerprint;
  uint32_t outbound_id;
  ftun_egress_id_t egress_id;
  ftun_dns_transport_t transport;
  ftun_dns_runtime_request_state_t state;
  bool write_pending;
  bool received_present;
  bool closing;
  bool ready;
  bool indexed;
  bool ready_queued;
} ftun_dns_runtime_transport_request_t;

struct ftun_dns_runtime_transport_waiter {
  ftun_dns_runtime_transport_waiter_t *previous;
  ftun_dns_runtime_transport_waiter_t *next;
  ftun_dns_runtime_transport_request_t *request;
  ftun_reservation_t reservation;
  ftun_dns_transport_completion_fn completion;
  void *completion_user;
  uint64_t deadline_ms;
  size_t heap_index;
  uint16_t query_id;
};

typedef struct ftun_dns_runtime_listener_slot {
  struct ftun_dns_runtime *dns;
  ftun_handle_t descriptor;
  ftun_handle_t tcp_descriptor;
  ftun_event_source_t *source;
  ftun_event_source_t *tcp_source;
  ftun_dns_listener_t *protocol;
  size_t fixed_server;
  uint64_t accept_after_ms;
  uint64_t accept_backoff_ms;
  uint32_t events;
  uint32_t tcp_events;
  size_t pending_count;
  bool policy;
  /* 地址暂不可用或监听出错：socket 已关闭，等待恢复调度器重新 bind。 */
  bool waiting;
  ftun_recovery_id_t recovery;
} ftun_dns_runtime_listener_slot_t;

typedef struct {
  struct ftun_dns_runtime *dns;
  ftun_handle_t descriptor;
  ftun_event_source_t *source;
  ftun_dns_connection_t *protocol;
  uint64_t peer_id;
  struct ftun_dns_runtime_response *response_head;
  struct ftun_dns_runtime_response *response_tail;
  ftun_reservation_t input_reservation;
  uint8_t *input;
  size_t input_offset;
  size_t input_length;
  uint8_t prefix[2];
  size_t prefix_length;
  size_t response_count;
  uint32_t events;
  bool active;
  bool peer_eof;
  bool transport_failed;
  /* 非零表示收尾/更新失败后被隔离：继续占用槽位，到点重新排入就绪。 */
  uint64_t quarantine_retry_ms;
} ftun_dns_runtime_tcp_t;

typedef struct ftun_dns_runtime_response {
  struct ftun_dns_runtime_response *next;
  ftun_reservation_t reservation;
  size_t offset;
  size_t length;
  uint8_t data[1];
} ftun_dns_runtime_response_t;

typedef enum {
  FTUN_DNS_RUNTIME_PENDING_SOCKET = 1,
  FTUN_DNS_RUNTIME_PENDING_TUN
} ftun_dns_runtime_pending_kind_t;

typedef struct {
  uint64_t id;
  ftun_dns_runtime_pending_kind_t kind;
  ftun_handle_t descriptor;
  ftun_endpoint_t peer;
  ftun_datagram_t *inbound;
  ftun_endpoint_t client;
  size_t listener_index;
  bool active;
} ftun_dns_runtime_pending_t;

struct ftun_dns_runtime {
  const ftun_egress_provider_t *egress;
  ftun_core_t *core;
  ftun_budget_t *budget;
  ftun_reservation_t listener_reservation;
  ftun_operation_queue_t *operations;
  ftun_event_loop_t *loop;
  ftun_config_t *config;
  ftun_path_provider_t *paths;
  uint64_t generation;
  ftun_dns_runtime_adapter_t adapter;
  ftun_dns_server_t *servers[FTUN_DNS_RUNTIME_MAX_SERVERS];
  ftun_upstream_set_t *upstream_sets[FTUN_DNS_RUNTIME_MAX_SERVERS];
  ftun_dns_runtime_listener_slot_t listeners[FTUN_DNS_RUNTIME_MAX_LISTENERS];
  ftun_dns_runtime_pending_t pending[FTUN_DNS_RUNTIME_MAX_PENDING];
  ftun_dns_runtime_tcp_t tcp[FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS];
  ftun_dns_dispatcher_t *dispatcher;
  ftun_dns_cache_t *cache;
  ftun_dns_listener_t *hijack;
  ftun_dns_runtime_transport_request_t *request_head;
  ftun_dns_runtime_transport_request_t *request_tail;
  ftun_dns_runtime_transport_request_t *ready_request_head;
  ftun_dns_runtime_transport_request_t *ready_request_tail;
  ftun_dns_runtime_transport_request_t *delivering_request;
  ftun_dns_runtime_transport_request_t *request_buckets[
    FTUN_DNS_RUNTIME_REQUEST_BUCKETS];
  ftun_dns_runtime_transport_waiter_t *waiter_heap[
    FTUN_DNS_RUNTIME_MAX_WAITERS];
  size_t request_count;
  size_t waiter_count;
  size_t pending_count;
  size_t server_count;
  size_t listener_count;
  size_t default_server;
  size_t listener_cursor;
  size_t tcp_cursor;
  size_t pending_cursor;
  size_t lane_cursor;
  uint64_t next_peer_id;
  uint64_t delivery_now_ms;
  uint64_t tcp_ready_mask;
  ftun_recovery_scheduler_t *recovery;
  size_t quarantined_tcp;
  size_t object_faults;
  uint32_t socket_mark;
  ftun_socket_liveness_t liveness;
  ftun_status_t pending_status;
  bool accepting;
  bool active;
  bool sources_prepared;
  bool cleanup_only;
  bool listener_tcp_turn;
  bool dispatching;
  bool deadline_served;
  bool delivering;
};


ftun_status_t ftun_dns_runtime_binding_validate(
  ftun_dns_runtime_t *dns, const ftun_dns_transport_binding_t *binding);
ftun_status_t ftun_dns_runtime_bootstrap_endpoint(
  ftun_budget_t *budget, const ftun_config_t *config, ftun_endpoint_t *out);

uint64_t ftun_dns_runtime_hash_bytes(uint64_t hash, const void *data,
                                           size_t length);
ftun_status_t ftun_dns_runtime_idle(const ftun_dns_runtime_t *dns);
ftun_status_t ftun_dns_runtime_listener_bind(
  ftun_dns_runtime_listener_slot_t *slot, const char *listen);
void ftun_dns_runtime_listener_ready(ftun_event_source_t *source,
                                            uint32_t events, void *user);
int ftun_dns_runtime_listener_reusable(
  const ftun_dns_runtime_t *dns, const char *listen, size_t *out_index);
ftun_status_t ftun_dns_runtime_listener_sources_start(
  ftun_dns_runtime_t *dns);
void ftun_dns_runtime_listener_tcp_ready(ftun_event_source_t *source,
                                                uint32_t events, void *user);
ftun_status_t ftun_dns_runtime_listener_udp_one(
  ftun_dns_runtime_t *dns, ftun_dns_runtime_listener_slot_t *slot,
  size_t listener_index, bool *out_work);
ftun_status_t ftun_dns_runtime_named_index(ftun_string_t name,
                                                  size_t *out, void *user);
ftun_status_t ftun_dns_runtime_now(void *user, uint64_t *out);
ftun_status_t ftun_dns_runtime_outbound_id(
  ftun_dns_runtime_t *dns, const char *name, uint32_t required, uint32_t *out);
void ftun_dns_runtime_packet_done(ftun_datagram_t *channel,
  ftun_error_t error, const ftun_endpoint_t *target,
  const ftun_packet_t *packet, void *user);
ftun_status_t ftun_dns_runtime_packet_receive(ftun_datagram_t *channel,
  const ftun_endpoint_t *source, const ftun_packet_t *packet, void *user);
ftun_status_t ftun_dns_runtime_parse_endpoint(const char *text,
                                                     ftun_endpoint_t *out);
void ftun_dns_runtime_path_notify(ftun_path_t *path, uint32_t events,
  ftun_error_t error, void *user);
void ftun_dns_runtime_path_opened(ftun_operation_t *operation,
  ftun_error_t error, ftun_path_t *path, void *user);
ftun_dns_runtime_pending_t *ftun_dns_runtime_pending(
  ftun_dns_runtime_t *dns, uint64_t id);
void ftun_dns_runtime_pending_clear(ftun_dns_runtime_t *dns,
                                          ftun_dns_runtime_pending_t *pending);
ftun_dns_runtime_pending_t *ftun_dns_runtime_pending_new(
  ftun_dns_runtime_t *dns, size_t listener_index);
ftun_status_t ftun_dns_runtime_prepare_internal(
  ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations, ftun_event_loop_t *loop,
  const ftun_config_t *config, const ftun_dns_runtime_adapter_t *adapter,
  const ftun_dns_runtime_network_t *network, bool bind_sockets,
  const ftun_dns_runtime_plan_t *plan, ftun_dns_runtime_t **out);
ftun_status_t ftun_dns_runtime_protocol_create(
  ftun_dns_runtime_t *dns, bool policy, size_t fixed_server,
  uint32_t inbound_id, ftun_dns_listener_t **out);
void ftun_dns_runtime_record(ftun_dns_runtime_t *dns,
                                   ftun_status_t status);
ftun_status_t ftun_dns_runtime_recovery_create(ftun_dns_runtime_t *dns,
  const ftun_config_t *config);
ftun_status_t ftun_dns_runtime_recovery_open(ftun_dns_runtime_t *dns);
void ftun_dns_runtime_reply(ftun_dns_transport_t transport,
                                  uint64_t peer_id, ftun_error_t error,
                                  ftun_bytes_t response, void *user);
void ftun_dns_runtime_request_complete_one(
  ftun_dns_runtime_transport_request_t *request);
ftun_status_t ftun_dns_runtime_request_connected(
  ftun_dns_runtime_transport_request_t *request, bool *connected);
ftun_status_t ftun_dns_runtime_request_dns_send(
  ftun_dns_runtime_transport_request_t *request);
ftun_status_t ftun_dns_runtime_request_drive(
  ftun_dns_runtime_transport_request_t *request);
ftun_status_t ftun_dns_runtime_request_drive_connected(
  ftun_dns_runtime_transport_request_t *request);
void ftun_dns_runtime_request_finish(
  ftun_dns_runtime_transport_request_t *request, ftun_status_t status);
uint64_t ftun_dns_runtime_request_hash(
  uint32_t outbound_id, uint64_t policy_fingerprint,
  uint64_t server_fingerprint, const ftun_endpoint_t *upstream,
  ftun_dns_transport_t transport, ftun_egress_id_t egress_id,
  ftun_bytes_t query);
void ftun_dns_runtime_request_index_insert(
  ftun_dns_runtime_transport_request_t *request);
void ftun_dns_runtime_request_index_remove(
  ftun_dns_runtime_transport_request_t *request);
int ftun_dns_runtime_request_matches(
  const ftun_dns_runtime_transport_request_t *request,
  uint32_t outbound_id, uint64_t policy_fingerprint,
  uint64_t server_fingerprint, const ftun_endpoint_t *upstream,
  ftun_dns_transport_t transport, ftun_egress_id_t egress_id, ftun_bytes_t query);
ftun_status_t ftun_dns_runtime_request_open(ftun_dns_runtime_transport_request_t *request);
ftun_status_t ftun_dns_runtime_request_path_close(ftun_path_t **path);
void ftun_dns_runtime_request_ready_enqueue(
  ftun_dns_runtime_transport_request_t *request);
void ftun_dns_runtime_request_ready_remove(
  ftun_dns_runtime_transport_request_t *request);
ftun_status_t ftun_dns_runtime_request_receive(
  ftun_dns_runtime_transport_request_t *request, size_t needed);
void ftun_dns_runtime_request_release(
  ftun_dns_runtime_transport_request_t *request);
ftun_status_t ftun_dns_runtime_request_send(
  ftun_dns_runtime_transport_request_t *request);
void ftun_dns_runtime_request_unlink(
  ftun_dns_runtime_transport_request_t *request);
ftun_status_t ftun_dns_runtime_resolve_upstream(
  ftun_budget_t *budget, const ftun_config_t *config, const char *text, uint32_t socket_mark,
  ftun_endpoint_t *out);
ftun_status_t ftun_dns_runtime_response_now(void *user, uint64_t *out);
ftun_status_t ftun_dns_runtime_run_slice(ftun_dns_runtime_t *dns,
                                                size_t quota, size_t *out_work);
ftun_status_t ftun_dns_runtime_select(uint32_t outbound_id,
                                             size_t *out, void *user);
ftun_status_t ftun_dns_runtime_slot_close(
  ftun_dns_runtime_listener_slot_t *slot);
ftun_status_t ftun_dns_runtime_slot_fail(
  ftun_dns_runtime_t *dns, ftun_dns_runtime_listener_slot_t *slot);
ftun_status_t ftun_dns_runtime_slot_recover(void *user,
                                                   ftun_recovery_id_t id);
ftun_status_t ftun_dns_runtime_slot_sources_start(
  ftun_dns_runtime_t *dns, ftun_dns_runtime_listener_slot_t *slot);
ftun_status_t ftun_dns_runtime_socket_duplicate(ftun_handle_t descriptor,
                                                       ftun_handle_t *out);
ftun_status_t ftun_dns_runtime_socket_open(const char *text,
                                                  ftun_dial_transport_t type, ftun_handle_t *out,
                                                  ftun_socket_bind_issue_t *error_code);
ftun_status_t ftun_dns_runtime_step_deadline(ftun_dns_runtime_t *dns,
                                                   uint64_t now_ms,
                                                   bool *out_work);
ftun_status_t ftun_dns_runtime_step_listener(ftun_dns_runtime_t *dns,
                                                   uint64_t now_ms,
                                                   bool *out_work);
ftun_status_t ftun_dns_runtime_step_request(ftun_dns_runtime_t *dns,
                                                  bool *out_work);
ftun_status_t ftun_dns_runtime_step_tcp(ftun_dns_runtime_t *dns,
                                              bool *out_work);
ftun_status_t ftun_dns_runtime_stop_slice(ftun_dns_runtime_t *dns,
                                                 uint64_t deadline_ms);
ftun_status_t ftun_dns_runtime_tcp_accept(
  ftun_dns_runtime_t *dns, ftun_dns_runtime_listener_slot_t *listener,
  size_t quota, size_t *out_accepted);
ftun_status_t ftun_dns_runtime_tcp_close(
  ftun_dns_runtime_tcp_t *connection);
ftun_status_t ftun_dns_runtime_tcp_disconnect(
  ftun_dns_runtime_tcp_t *connection);
ftun_status_t ftun_dns_runtime_tcp_drive(
  ftun_dns_runtime_t *dns, ftun_dns_runtime_tcp_t *connection);
ftun_dns_runtime_tcp_t *ftun_dns_runtime_tcp_find(
  ftun_dns_runtime_t *dns, uint64_t peer_id);
size_t ftun_dns_runtime_tcp_next_ready(const ftun_dns_runtime_t *dns);
void ftun_dns_runtime_tcp_ready(ftun_event_source_t *source,
                                       uint32_t events, void *user);
void ftun_dns_runtime_tcp_set_ready(ftun_dns_runtime_tcp_t *connection,
                                            bool ready);
ftun_status_t ftun_dns_runtime_tcp_source_update(
  ftun_dns_runtime_tcp_t *connection);
ftun_status_t ftun_dns_runtime_transport_cancel(void *user,
                                                       void **request_ptr);
ftun_status_t ftun_dns_runtime_transport_select(void *user,
  uint32_t root, ftun_dns_transport_binding_t *out);
ftun_status_t ftun_dns_runtime_transport_submit(
  void *user, const ftun_dns_transport_binding_t *binding,
  uint64_t policy_fingerprint,
  uint64_t server_fingerprint, const ftun_endpoint_t *upstream,
  ftun_dns_transport_t transport, ftun_bytes_t query, uint64_t deadline_ms,
  ftun_dns_transport_completion_fn completion, void *completion_user,
  void **out_request);
int ftun_dns_runtime_waiter_before(
  const ftun_dns_runtime_transport_waiter_t *left,
  const ftun_dns_runtime_transport_waiter_t *right);
ftun_status_t ftun_dns_runtime_waiter_create(
  ftun_dns_runtime_t *dns, ftun_dns_runtime_transport_request_t *request,
  ftun_bytes_t query, uint64_t deadline_ms,
  ftun_dns_transport_completion_fn completion, void *completion_user,
  ftun_dns_runtime_transport_waiter_t **out);
void ftun_dns_runtime_waiter_finish(
  ftun_dns_runtime_transport_waiter_t *waiter, ftun_status_t status,
  ftun_bytes_t response);
void ftun_dns_runtime_waiter_heap_push(
  ftun_dns_runtime_t *dns, ftun_dns_runtime_transport_waiter_t *waiter);
void ftun_dns_runtime_waiter_heap_remove(
  ftun_dns_runtime_t *dns, ftun_dns_runtime_transport_waiter_t *waiter);
void ftun_dns_runtime_waiter_heap_swap(ftun_dns_runtime_t *dns,
                                             size_t left, size_t right);
void ftun_dns_runtime_waiter_release(
  ftun_dns_runtime_transport_waiter_t *waiter);
void ftun_dns_runtime_waiter_unlink(
  ftun_dns_runtime_transport_waiter_t *waiter);
void ftun_dns_runtime_write_done(ftun_operation_t *operation,
  ftun_error_t error, void *user);

#endif

#endif
