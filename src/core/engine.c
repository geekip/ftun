#define _GNU_SOURCE 1

#include "core/engine.h"
#include "core/engine_dns.h"
#include "core/http_fetch.h"

#include "core/runtime.h"
#include "core/session.h"
#include "core/worker.h"
#include "config/compile.h"
#include "dns/dns.h"
#include "dns/resolver.h"
#include "event/event.h"
#include "event/libev_adapter.h"
#include "inbound/mixed.h"
#include "inbound/socks5.h"
#include "tun/udp_session.h"
#if defined(FTUN_HAVE_MODULE_TUN)
#include "inbound/tun.h"
#include "platform/linux/route.h"
#include "tun/tun.h"
#endif
#include "outbound/outbound.h"
#include "route/group.h"
#include "route/router.h"
#include "route/rule.h"
#include "route/target.h"
#include "group/health.h"
#include "sniff/sniff.h"
#if defined(FTUN_HAVE_MODULE_FRS)
#include "frs/frs.h"
#include "platform/file.h"
#endif
#if defined(FTUN_HAVE_MODULE_FAKEIP)
#include "dns/fakeip.h"
#include "state/fakeip_store.h"
#include "state/snapshot.h"
#endif
#include "transport/relay.h"
#include "transport/stream.h"
#include "util/buffer.h"
#include "util/logger.h"
#include "util/time.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define FTUN_ENGINE_MAX_LISTENERS 32u
#define FTUN_ENGINE_MAX_TCP_FLOWS 256u
#define FTUN_ENGINE_MAX_UDP_FLOWS 256u
#define FTUN_ENGINE_REPLY_BYTES 1024u
#define FTUN_ENGINE_PREREAD_BYTES 65536u
#define FTUN_ENGINE_ACCEPT_QUOTA 16u
#define FTUN_ENGINE_DATAGRAM_QUOTA 32u
#define FTUN_ENGINE_TUN_QUOTA 64u
#define FTUN_ENGINE_TUN_OUTPUT_CAPACITY 256u
#define FTUN_ENGINE_ASSOCIATION_BUCKETS 512u
#define FTUN_ENGINE_RELAY_POOL_BYTES (2u * 1024u * 1024u)
#define FTUN_ENGINE_RELAY_POOL_BUFFERS 32u
#define FTUN_ENGINE_SOCKET_MARK UINT32_C(0x4654)
#define FTUN_ENGINE_CONNECT_TIMEOUT_MS UINT64_C(10000)
#define FTUN_ENGINE_HANDSHAKE_TIMEOUT_MS UINT64_C(10000)
#define FTUN_ENGINE_REPLY_TIMEOUT_MS UINT64_C(5000)
#define FTUN_ENGINE_ACCEPT_BACKOFF_MIN_MS UINT64_C(50)
#define FTUN_ENGINE_ACCEPT_BACKOFF_MAX_MS UINT64_C(1000)
#define FTUN_ENGINE_UDP_RECONNECT_BACKOFF_MIN_MS UINT64_C(100)
#define FTUN_ENGINE_UDP_RECONNECT_BACKOFF_MAX_MS UINT64_C(5000)
#define FTUN_ENGINE_FAKEIP_RESERVE_BATCH UINT32_C(4096)
#define FTUN_ENGINE_FAKEIP_RESERVE_LOW_WATER UINT32_C(512)
#define FTUN_ENGINE_HTTP_ETAG_BYTES (64u * 1024u)
#define FTUN_ENGINE_HTTP_WORK_MAGIC UINT32_C(0x46544846)
#define FTUN_ENGINE_FRS_PUBLISH_MAGIC UINT32_C(0x46525042)

typedef struct {
  uint32_t magic;
  uint32_t mark;
  ftun_control_resolver_plan_t resolver;
  uint64_t maximum_bytes;
  uint64_t deadline_ms;
  uint16_t proxy_port;
  uint8_t proxy_address[4];
  char proxy_domain[FTUN_CONTROL_ENDPOINT_TEXT_BYTES];
  uint8_t use_proxy;
  uint8_t validate_frs;
  uintptr_t runtime_snapshot;
  uint32_t url_length;
  uint32_t username_length;
  uint32_t password_length;
  uint32_t etag_length;
} ftun_engine_http_work_t;

typedef struct {
  uint32_t status;
  uint32_t etag_length;
  uint64_t body_length;
  uintptr_t prepared_runtime;
  uint8_t tls_verified;
  uint8_t reserved[7];
} ftun_engine_http_result_t;

#if defined(FTUN_HAVE_MODULE_FRS)
typedef struct {
  uint32_t magic;
  uint32_t path_length;
  uint64_t body_length;
} ftun_engine_frs_publish_work_t;

typedef struct {
  int32_t status;
  uint32_t reached;
} ftun_engine_frs_publish_result_t;
#endif

typedef struct ftun_engine_listener ftun_engine_listener_t;
typedef struct ftun_engine_flow ftun_engine_flow_t;
typedef struct ftun_engine_health_slot ftun_engine_health_slot_t;
typedef struct ftun_engine_udp_pending ftun_engine_udp_pending_t;

typedef struct {
  uint32_t outbound_id;
  uint32_t failures;
  uint64_t retry_after_ms;
  bool active;
} ftun_engine_udp_backoff_t;

#if defined(FTUN_HAVE_MODULE_TUN)
typedef struct {
  ftun_buffer_t *buffer;
  size_t length;
} ftun_engine_tun_output_t;
#endif

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
} ftun_engine_health_group_t;

struct ftun_engine_health_slot {
  struct ftun_engine *engine;
  ftun_operation_t *operation;
  ftun_health_schedule_t schedule;
  ftun_health_sample_t sample;
  size_t group_index;
  uint32_t member_id;
  uint64_t generation;
  uint64_t started_ms;
};

static void ftun_engine_health_consume(ftun_engine_t *engine,
                                       uint32_t group_id);
static void ftun_engine_flow_close(ftun_engine_flow_t *flow,
                                   ftun_status_t reason);
static void ftun_engine_background_log(ftun_engine_t *engine,
                                       ftun_status_t status,
                                       const char *message);
#if defined(FTUN_HAVE_MODULE_FRS)
typedef struct {
  ftun_file_stage_t reached;
} ftun_engine_file_publish_t;

static ftun_status_t ftun_engine_file_stage(ftun_file_stage_t stage,
                                            void *user)
{
  ftun_engine_file_publish_t *publish =
    (ftun_engine_file_publish_t *)user;
  if (publish == NULL) return FTUN_E_INVALID;
  publish->reached = stage;
  return FTUN_OK;
}
#endif

typedef struct ftun_engine_udp_slot {
  struct ftun_engine *engine;
  struct ftun_engine_udp_slot *ready_previous;
  struct ftun_engine_udp_slot *ready_next;
  ftun_datagram_t *channel;
  ftun_socks5_connection_t *proxy_connection;
  ftun_operation_t *open_operation;
  ftun_event_source_t *source;
  ftun_event_source_t *control_source;
  ftun_datagram_send_t *pending[32];
  ftun_endpoint_t remote;
  ftun_endpoint_t proxy_server;
  ftun_endpoint_t proxy_resolved[FTUN_SESSION_MAX_RESOLVED_IPV4];
  ftun_endpoint_t target_candidates[FTUN_SESSION_MAX_RESOLVED_IPV4];
  ftun_endpoint_t target_allowed[FTUN_SESSION_MAX_RESOLVED_IPV4];
  ftun_target_t socks_target;
  char proxy_domain[254];
  char target_domain[254];
  uint8_t proxy_username[FTUN_SOCKS5_MAX_CREDENTIAL_BYTES];
  uint8_t proxy_password[FTUN_SOCKS5_MAX_CREDENTIAL_BYTES];
  size_t proxy_resolved_count;
  size_t proxy_username_length;
  size_t proxy_password_length;
  int descriptor;
  size_t pending_count;
  ftun_status_t open_status;
  uint32_t outbound_id;
  bool socks5;
  bool ready;
  bool destroying;
  bool ready_queued;
  bool active;
  uint32_t events;
  uint32_t control_events;
} ftun_engine_udp_slot_t;

struct ftun_engine_udp_pending {
  struct ftun_engine *engine;
  ftun_operation_t *operation;
  ftun_runtime_t *runtime;
  ftun_datagram_t *inbound;
  ftun_packet_t packet;
  ftun_metadata_t metadata;
  ftun_endpoint_t resolved[FTUN_UDP_FLOW_MAX_RESOLVED_IPV4];
  ftun_route_result_t route;
  char domain[254];
  size_t resume_rule;
  bool preserve_route;
  bool active;
};

typedef struct {
  ftun_engine_flow_t *flow;
  int descriptor;
  ftun_stream_write_t *pending;
  bool write_shutdown;
} ftun_engine_socket_stream_t;

typedef enum {
  FTUN_ENGINE_FLOW_HANDSHAKE = 1,
  FTUN_ENGINE_FLOW_CONNECTING,
  FTUN_ENGINE_FLOW_RELAY,
  FTUN_ENGINE_FLOW_UDP_ASSOCIATE,
  FTUN_ENGINE_FLOW_CLOSING
} ftun_engine_flow_state_t;

struct ftun_engine_listener {
  struct ftun_engine *engine;
  int descriptor;
  int udp_descriptor;
  ftun_event_source_t *source;
  ftun_event_source_t *udp_source;
  ftun_event_source_t *accept_timer;
  uint32_t events;
  uint32_t udp_events;
  char *name;
  ftun_config_inbound_kind_t kind;
  uint32_t inbound_id;
  uint64_t accept_backoff_ms;
};

struct ftun_engine_flow {
  ftun_engine_flow_t *ready_next;
  ftun_engine_flow_t *association_client_next;
  ftun_engine_flow_t *association_channel_next;
  struct ftun_engine *engine;
  ftun_engine_listener_t *listener;
  ftun_engine_socket_stream_t client_socket;
  ftun_engine_socket_stream_t remote_socket;
  ftun_stream_t *client;
  ftun_stream_t *remote;
  ftun_session_t *session;
  ftun_relay_t *relay;
  ftun_operation_t *open_operation;
  ftun_event_source_t *client_source;
  ftun_event_source_t *remote_source;
  ftun_event_source_t *deadline_source;
  ftun_socks5_connection_t *proxy_connection;
  ftun_socks5_server_t *socks5;
  ftun_mixed_connection_t *mixed;
  ftun_engine_flow_state_t state;
  uint8_t reply[FTUN_ENGINE_REPLY_BYTES];
  size_t reply_offset;
  size_t reply_length;
  uint8_t *preread;
  ftun_reservation_t *preread_reservation;
  size_t preread_capacity;
  size_t preread_offset;
  size_t preread_length;
  ftun_metadata_t pending_metadata;
  ftun_endpoint_t proxy_resolved[FTUN_SESSION_MAX_RESOLVED_IPV4];
  char sniff_domain[FTUN_SNIFF_DOMAIN_BYTES];
  size_t proxy_resolved_count;
  uint64_t sniff_deadline_ms;
  uint64_t handshake_deadline_ms;
  uint32_t proxy_leaf_id;
  uint16_t proxy_port;
  uint32_t left_events;
  uint32_t client_events;
  uint32_t remote_events;
  ftun_datagram_t *udp_channel;
  ftun_endpoint_t tcp_peer;
  ftun_endpoint_t udp_request;
  ftun_endpoint_t udp_client;
  bool mixed_http;
  bool http_connect;
  bool tun;
  bool udp_client_pinned;
  bool association_client_indexed;
  bool association_channel_indexed;
  bool close_after_reply;
  bool ready_queued;
  bool driving;
  bool reschedule;
  bool active;
};

struct ftun_engine {
  ftun_core_t *core;
  ftun_budget_t *budget;
  ftun_reservation_t *reservation;
  ftun_operation_queue_t *operations;
  ftun_event_loop_t *loop;
  /* 解析工作对延迟敏感。健康探测、FRS 更新与持久化使用独立有界队列，
   * 避免维护任务占用唯一的系统解析执行槽。 */
  ftun_worker_t *worker;
  ftun_worker_t *maintenance_worker;
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  ftun_worker_t *fakeip_worker;
#endif
  ftun_buffer_pool_t *relay_pool;
  ftun_engine_dns_t *dns;
  ftun_engine_dns_t *pending_dns;
  ftun_engine_health_group_t *health_groups;
  ftun_engine_health_group_t *pending_health_groups;
  ftun_engine_health_slot_t *health_slots;
  ftun_engine_health_slot_t *pending_health_slots;
  ftun_reservation_t *health_reservation;
  ftun_reservation_t *pending_health_reservation;
  size_t health_group_count;
  size_t pending_health_group_count;
  size_t health_slot_count;
  size_t pending_health_slot_count;
  bool pending_health_reuse;
  ftun_engine_listener_t listeners[FTUN_ENGINE_MAX_LISTENERS];
  uint32_t pending_listener_ids[FTUN_ENGINE_MAX_LISTENERS];
  ftun_engine_flow_t flows[FTUN_ENGINE_MAX_TCP_FLOWS];
  ftun_engine_flow_t *ready_flow_head;
  ftun_engine_flow_t *ready_flow_tail;
  ftun_engine_flow_t *association_clients[FTUN_ENGINE_ASSOCIATION_BUCKETS];
  ftun_engine_flow_t *association_channels[FTUN_ENGINE_ASSOCIATION_BUCKETS];
  ftun_udp_flow_table_t *udp_flows;
  ftun_engine_udp_slot_t udp[FTUN_ENGINE_MAX_UDP_FLOWS];
  ftun_engine_udp_backoff_t udp_backoff[FTUN_ENGINE_MAX_UDP_FLOWS];
  ftun_engine_udp_slot_t *ready_udp_head;
  ftun_engine_udp_slot_t *ready_udp_tail;
  ftun_engine_udp_pending_t udp_pending[FTUN_ENGINE_MAX_UDP_FLOWS];
  size_t listener_count;
  uint64_t generation;
  uint64_t now_ms;
  uint32_t socket_mark;
  uint16_t next_dns_query_id;
#if defined(FTUN_HAVE_MODULE_FRS)
  ftun_operation_t *frs_operation;
  ftun_runtime_t *frs_candidate;
  char *frs_etag;
  char *frs_candidate_etag;
  uint64_t frs_due_ms;
  uint64_t frs_interval_ms;
  uint64_t frs_operation_generation;
  uint64_t pending_frs_interval_ms;
  bool frs_enabled;
  bool pending_frs_enabled;
#endif
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  ftun_fakeip_store_t *fakeip_store;
  ftun_fakeip_service_t *fakeip;
  char *fakeip_directory;
  ftun_operation_t *fakeip_reserve_operation;
  ftun_status_t fakeip_store_status;
  size_t fakeip_store_completions;
  bool fakeip_reserve_warning;
#endif
#if defined(FTUN_HAVE_MODULE_TUN)
  ftun_engine_listener_t tun_listener;
  ftun_packet_port_t *tun_port;
  ftun_tun_ingress_context_t *tun_ingress;
  ftun_route_transaction_t *routes;
  ftun_packet_port_info_t tun_info;
  ftun_event_source_t *tun_source;
  ftun_engine_tun_output_t tun_output[FTUN_ENGINE_TUN_OUTPUT_CAPACITY];
  size_t tun_output_head;
  size_t tun_output_count;
  uint32_t tun_events;
  uint32_t pending_tun_inbound_id;
  bool has_tun;
#endif
  bool accepting;
  bool reload_prepared;
  bool stopped;
};

static ftun_status_t ftun_engine_errno_status(int error_code)
{
  if (error_code == EAGAIN || error_code == EWOULDBLOCK ||
      error_code == EINTR) return FTUN_E_AGAIN;
  if (error_code == ENOMEM || error_code == ENOBUFS ||
      error_code == EMFILE || error_code == ENFILE) return FTUN_E_LIMIT;
  if (error_code == ECONNRESET || error_code == EPIPE ||
      error_code == ECONNREFUSED || error_code == EHOSTUNREACH ||
      error_code == ENETUNREACH) return FTUN_E_REJECTED;
  if (error_code == EBADF || error_code == EINVAL ||
      error_code == ENOTSOCK) return FTUN_E_INVALID;
  return FTUN_E_IO;
}

static void ftun_engine_listener_ready(ftun_event_source_t *source,
                                       uint32_t events, void *user)
{
  ftun_engine_listener_t *listener = (ftun_engine_listener_t *)user;
  if (listener != NULL && listener->source == source) {
    listener->events |= events;
  }
}

static void ftun_engine_worker_wakeup(void *user)
{
  (void)ftun_event_loop_wakeup((ftun_event_loop_t *)user);
}

static void ftun_engine_listener_udp_ready(ftun_event_source_t *source,
                                           uint32_t events, void *user)
{
  ftun_engine_listener_t *listener = (ftun_engine_listener_t *)user;
  if (listener != NULL && listener->udp_source == source) {
    listener->udp_events |= events;
  }
}

static void ftun_engine_flow_schedule(ftun_engine_flow_t *flow)
{
  ftun_engine_t *engine;
  if (flow == NULL || !flow->active) return;
  if (flow->driving) {
    flow->reschedule = true;
    return;
  }
  if (flow->ready_queued) return;
  engine = flow->engine;
  if (engine == NULL) return;
  flow->ready_next = NULL;
  if (engine->ready_flow_tail != NULL) {
    engine->ready_flow_tail->ready_next = flow;
  } else {
    engine->ready_flow_head = flow;
  }
  engine->ready_flow_tail = flow;
  flow->ready_queued = true;
}

static void ftun_engine_listener_accept_resume(ftun_event_source_t *source,
                                                uint32_t events, void *user)
{
  ftun_engine_listener_t *listener = (ftun_engine_listener_t *)user;
  ftun_status_t status;
  if (listener == NULL || listener->accept_timer != source ||
      (events & FTUN_EVENT_TIMER) == 0u) return;
  status = ftun_event_source_cancel(&listener->accept_timer);
  if (status == FTUN_OK && listener->source != NULL) {
    status = ftun_event_io_update(listener->source,
      FTUN_EVENT_READ | FTUN_EVENT_ERROR);
  }
  if (status != FTUN_OK) listener->events |= FTUN_EVENT_ERROR;
}

static void ftun_engine_flow_client_ready(ftun_event_source_t *source,
                                          uint32_t events, void *user)
{
  ftun_engine_flow_t *flow = (ftun_engine_flow_t *)user;
  if (flow != NULL && flow->active && flow->client_source == source) {
    flow->client_events |= events;
    ftun_engine_flow_schedule(flow);
  }
}

static void ftun_engine_flow_remote_ready(ftun_event_source_t *source,
                                          uint32_t events, void *user)
{
  ftun_engine_flow_t *flow = (ftun_engine_flow_t *)user;
  if (flow != NULL && flow->active && flow->remote_source == source) {
    flow->remote_events |= events;
    ftun_engine_flow_schedule(flow);
  }
}

static void ftun_engine_udp_unschedule(ftun_engine_udp_slot_t *slot)
{
  ftun_engine_t *engine;
  if (slot == NULL || !slot->ready_queued || slot->engine == NULL) return;
  engine = slot->engine;
  if (slot->ready_previous != NULL) {
    slot->ready_previous->ready_next = slot->ready_next;
  } else {
    engine->ready_udp_head = slot->ready_next;
  }
  if (slot->ready_next != NULL) {
    slot->ready_next->ready_previous = slot->ready_previous;
  } else {
    engine->ready_udp_tail = slot->ready_previous;
  }
  slot->ready_previous = NULL;
  slot->ready_next = NULL;
  slot->ready_queued = false;
}

static void ftun_engine_udp_schedule(ftun_engine_udp_slot_t *slot)
{
  ftun_engine_t *engine;
  if (slot == NULL || !slot->active || slot->ready_queued ||
      slot->engine == NULL) return;
  engine = slot->engine;
  slot->ready_previous = engine->ready_udp_tail;
  slot->ready_next = NULL;
  if (engine->ready_udp_tail != NULL) {
    engine->ready_udp_tail->ready_next = slot;
  } else {
    engine->ready_udp_head = slot;
  }
  engine->ready_udp_tail = slot;
  slot->ready_queued = true;
}

static void ftun_engine_udp_ready(ftun_event_source_t *source,
                                  uint32_t events, void *user)
{
  ftun_engine_udp_slot_t *slot = (ftun_engine_udp_slot_t *)user;
  if (slot != NULL && slot->active && slot->source == source) {
    slot->events |= events;
    ftun_engine_udp_schedule(slot);
  }
}

static void ftun_engine_udp_control_ready(ftun_event_source_t *source,
                                          uint32_t events, void *user)
{
  ftun_engine_udp_slot_t *slot = (ftun_engine_udp_slot_t *)user;
  if (slot != NULL && slot->active && slot->control_source == source) {
    slot->control_events |= events;
    ftun_engine_udp_schedule(slot);
  }
}

static ftun_status_t ftun_engine_udp_update_source(
  ftun_engine_udp_slot_t *slot)
{
  uint32_t interests = FTUN_EVENT_READ | FTUN_EVENT_ERROR;
  if (slot == NULL || slot->source == NULL) return FTUN_E_INVALID;
  if (slot->ready && slot->pending_count != 0u) {
    interests |= FTUN_EVENT_WRITE;
  }
  return ftun_event_io_update(slot->source, interests);
}

#if defined(FTUN_HAVE_MODULE_TUN)
static void ftun_engine_tun_ready(ftun_event_source_t *source,
                                  uint32_t events, void *user)
{
  ftun_engine_t *engine = (ftun_engine_t *)user;
  if (engine != NULL && engine->tun_source == source) {
    engine->tun_events |= events;
  }
}
#endif

static ftun_status_t ftun_engine_flow_interests(
  ftun_engine_flow_t *flow, uint32_t *client, uint32_t *remote)
{
  ftun_relay_usage_t usage;
  ftun_status_t status;
  if (flow == NULL || client == NULL || remote == NULL) return FTUN_E_INVALID;
  *client = FTUN_EVENT_ERROR;
  *remote = FTUN_EVENT_ERROR;
  if (flow->reply_length != 0u) {
    *client |= FTUN_EVENT_WRITE;
  } else if (flow->state == FTUN_ENGINE_FLOW_HANDSHAKE ||
             flow->state == FTUN_ENGINE_FLOW_UDP_ASSOCIATE) {
    *client |= FTUN_EVENT_READ;
  }
  if (flow->state != FTUN_ENGINE_FLOW_RELAY || flow->relay == NULL) {
    return FTUN_OK;
  }
  status = ftun_relay_get_usage(flow->relay, &usage);
  if (status != FTUN_OK) return status;
  if (flow->preread_length != 0u) {
    *remote |= FTUN_EVENT_WRITE;
    return FTUN_OK;
  }
  if (!flow->tun) *client |= usage.left_interests;
  *remote |= usage.right_interests;
  return FTUN_OK;
}

static ftun_status_t ftun_engine_flow_update_sources(ftun_engine_flow_t *flow)
{
  uint32_t client;
  uint32_t remote;
  ftun_status_t status = ftun_engine_flow_interests(flow, &client, &remote);
  if (status != FTUN_OK) return status;
  if (flow->client_source != NULL) {
    status = ftun_event_io_update(flow->client_source, client);
  }
  if (status == FTUN_OK && flow->remote_source != NULL) {
    status = ftun_event_io_update(flow->remote_source, remote);
  }
  return status;
}

static int ftun_engine_duration_ms(const char *value, uint64_t *out)
{
  size_t length;
  size_t digits;
  size_t index;
  uint64_t result = 0u;
  uint64_t multiplier;
  if (value == NULL) return 0;
  length = strlen(value);
  if (length < 2u || value[0] < '1' || value[0] > '9') return 0;
  if (length >= 3u && value[length - 2u] == 'm' &&
      value[length - 1u] == 's') {
    digits = length - 2u;
    multiplier = 1u;
  } else {
    digits = length - 1u;
    if (value[length - 1u] == 's') multiplier = UINT64_C(1000);
    else if (value[length - 1u] == 'm') multiplier = UINT64_C(60000);
    else if (value[length - 1u] == 'h') multiplier = UINT64_C(3600000);
    else return 0;
  }
  for (index = 0u; index < digits; index++) {
    uint64_t digit;
    if (value[index] < '0' || value[index] > '9') return 0;
    digit = (uint64_t)(value[index] - '0');
    if (result > (UINT64_MAX - digit) / 10u) return 0;
    result = result * 10u + digit;
  }
  if (result == 0u || result > UINT64_MAX / multiplier) return 0;
  *out = result * multiplier;
  return 1;
}

static ftun_status_t ftun_engine_http_execute(
  ftun_bytes_t input, uint8_t *result, size_t result_capacity,
  size_t *out_result_size)
{
  const ftun_engine_http_work_t *header;
  const char *url;
  const char *username;
  const char *password;
  const char *etag;
  ftun_http_fetch_spec_t spec;
  ftun_http_fetch_result_t fetched;
  ftun_engine_http_result_t output;
  ftun_budget_t *budget = NULL;
#if defined(FTUN_HAVE_MODULE_FRS)
  ftun_runtime_t *prepared = NULL;
  ftun_frs_view_t *view = NULL;
#endif
  size_t expected;
  size_t maximum;
  size_t total;
  size_t copied_body;
  size_t budget_limit;
  ftun_status_t status;
  if (out_result_size != NULL) *out_result_size = 0u;
  if (input.data == NULL || input.length < sizeof(*header) || result == NULL ||
      out_result_size == NULL) return FTUN_E_INVALID;
  header = (const ftun_engine_http_work_t *)input.data;
  if (header->magic != FTUN_ENGINE_HTTP_WORK_MAGIC ||
      header->maximum_bytes == 0u || header->maximum_bytes > SIZE_MAX ||
      header->url_length == 0u) return FTUN_E_INVALID;
  maximum = (size_t)header->maximum_bytes;
  expected = sizeof(*header);
  if (header->url_length > SIZE_MAX - expected) return FTUN_E_LIMIT;
  expected += header->url_length;
  if (header->username_length > SIZE_MAX - expected) return FTUN_E_LIMIT;
  expected += header->username_length;
  if (header->password_length > SIZE_MAX - expected) return FTUN_E_LIMIT;
  expected += header->password_length;
  if (header->etag_length > SIZE_MAX - expected) return FTUN_E_LIMIT;
  expected += header->etag_length;
  if (expected != input.length || header->etag_length >
      FTUN_ENGINE_HTTP_ETAG_BYTES ||
      (header->use_proxy != 0u && header->proxy_port == 0u) ||
      (header->validate_frs != 0u && header->runtime_snapshot == 0u)) {
    return FTUN_E_INVALID;
  }
  if (maximum > (SIZE_MAX - 2u * 1024u * 1024u) / 2u) {
    return FTUN_E_LIMIT;
  }
  budget_limit = maximum * 2u + 2u * 1024u * 1024u;
  status = ftun_budget_create(NULL, budget_limit, 0u, &budget);
  if (status != FTUN_OK) return status;
  url = (const char *)input.data + sizeof(*header);
  username = url + header->url_length;
  password = username + header->username_length;
  etag = password + header->password_length;
  memset(&spec, 0, sizeof(spec));
  spec.budget = budget;
  spec.url.data = url;
  spec.url.length = header->url_length;
  spec.maximum_bytes = maximum;
  spec.deadline_ms = header->deadline_ms;
  spec.socket_mark = header->mark;
  spec.resolver = header->resolver;
  spec.use_proxy = header->use_proxy != 0u;
  if (spec.use_proxy) {
    spec.proxy.kind = header->proxy_domain[0] == '\0'
      ? FTUN_ADDRESS_IPV4 : FTUN_ADDRESS_DOMAIN;
    spec.proxy.port = header->proxy_port;
    memcpy(spec.proxy.address, header->proxy_address, 4u);
    memcpy(spec.proxy_domain, header->proxy_domain,
           sizeof(spec.proxy_domain));
    if (spec.proxy.kind == FTUN_ADDRESS_DOMAIN) {
      spec.proxy.domain.data = spec.proxy_domain;
      spec.proxy.domain.length = strlen(spec.proxy_domain);
    }
  }
  spec.proxy_username.data = username;
  spec.proxy_username.length = header->username_length;
  spec.proxy_password.data = password;
  spec.proxy_password.length = header->password_length;
  spec.if_none_match.data = etag;
  spec.if_none_match.length = header->etag_length;
  memset(&fetched, 0, sizeof(fetched));
  status = ftun_http_fetch(&spec, &fetched);
#if defined(FTUN_HAVE_MODULE_FRS)
  if (status == FTUN_OK && header->validate_frs != 0u &&
      fetched.status == 200u) {
    const ftun_config_t *config = NULL;
    status = ftun_frs_open_bytes(
      (ftun_bytes_t){fetched.data, fetched.length}, &view);
    if (status == FTUN_OK) {
      status = ftun_runtime_config(
        (ftun_runtime_t *)header->runtime_snapshot, &config);
    }
    if (status == FTUN_OK) {
      status = ftun_runtime_prepare_detached_frs(config, view, &prepared);
      if (status == FTUN_OK) view = NULL;
    }
  }
#else
  if (status == FTUN_OK && header->validate_frs != 0u) {
    status = FTUN_E_UNSUPPORTED;
  }
#endif
  if (status == FTUN_OK) {
    size_t etag_length = fetched.etag == NULL ? 0u : strlen(fetched.etag);
    copied_body = header->validate_frs != 0u ? 0u : fetched.length;
    if (etag_length > FTUN_ENGINE_HTTP_ETAG_BYTES ||
        fetched.length > maximum ||
        etag_length > SIZE_MAX - sizeof(output) ||
        copied_body > SIZE_MAX - sizeof(output) - etag_length) {
      status = FTUN_E_LIMIT;
    } else {
      total = sizeof(output) + etag_length + copied_body;
      if (total > result_capacity) status = FTUN_E_LIMIT;
      else {
        memset(&output, 0, sizeof(output));
        output.status = fetched.status;
        output.etag_length = (uint32_t)etag_length;
        output.body_length = fetched.length;
#if defined(FTUN_HAVE_MODULE_FRS)
        output.prepared_runtime = (uintptr_t)prepared;
#endif
        output.tls_verified = fetched.tls_verified ? 1u : 0u;
        memcpy(result, &output, sizeof(output));
        if (etag_length != 0u) {
          memcpy(result + sizeof(output), fetched.etag, etag_length);
        }
        if (copied_body != 0u) {
          memcpy(result + sizeof(output) + etag_length,
                 fetched.data, copied_body);
        }
        *out_result_size = total;
#if defined(FTUN_HAVE_MODULE_FRS)
        prepared = NULL;
#endif
      }
    }
  }
#if defined(FTUN_HAVE_MODULE_FRS)
  (void)ftun_runtime_prepared_release(&prepared);
  (void)ftun_frs_view_release(&view);
#endif
  ftun_http_fetch_release(&fetched);
  if (ftun_budget_destroy(&budget) != FTUN_OK && status == FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
  }
  return status;
}

static void ftun_engine_http_input_cleanup(ftun_bytes_t input)
{
  ftun_engine_http_work_t header;
  ftun_runtime_t *runtime;
  if (input.data == NULL || input.length < sizeof(header)) return;
  memcpy(&header, input.data, sizeof(header));
  if (header.magic != FTUN_ENGINE_HTTP_WORK_MAGIC ||
      header.runtime_snapshot == 0u) return;
  runtime = (ftun_runtime_t *)header.runtime_snapshot;
  (void)ftun_runtime_release(&runtime);
}

static void ftun_engine_http_result_cleanup(ftun_bytes_t result)
{
#if defined(FTUN_HAVE_MODULE_FRS)
  ftun_engine_http_result_t output;
  ftun_runtime_t *prepared;
  if (result.data == NULL || result.length < sizeof(output)) return;
  memcpy(&output, result.data, sizeof(output));
  prepared = (ftun_runtime_t *)output.prepared_runtime;
  (void)ftun_runtime_prepared_release(&prepared);
#else
  (void)result;
#endif
}

static ftun_status_t ftun_engine_http_submit(
  ftun_engine_t *engine, const ftun_http_fetch_spec_t *spec,
  bool validate_frs, ftun_runtime_t *runtime_snapshot,
  ftun_worker_completion_fn completion, void *user,
  ftun_operation_t **out)
{
  ftun_engine_http_work_t *header;
  ftun_worker_job_t job;
  uint8_t *input;
  size_t input_length;
  size_t result_capacity;
  size_t username_length;
  size_t password_length;
  size_t etag_length;
  size_t accounted_extra;
  size_t runtime_accounted = 0u;
  ftun_reservation_t *input_reservation = NULL;
  ftun_status_t release_status;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (engine == NULL || spec == NULL || completion == NULL || out == NULL ||
      spec->url.data == NULL || spec->url.length == 0u ||
      spec->url.length > UINT32_MAX || spec->maximum_bytes == 0u) {
    return FTUN_E_INVALID;
  }
  if (validate_frs != (runtime_snapshot != NULL)) return FTUN_E_INVALID;
  username_length = spec->proxy_username.length;
  password_length = spec->proxy_password.length;
  etag_length = spec->if_none_match.length;
  if (username_length > UINT32_MAX || password_length > UINT32_MAX ||
      etag_length > FTUN_ENGINE_HTTP_ETAG_BYTES ||
      spec->maximum_bytes > SIZE_MAX - sizeof(ftun_engine_http_result_t) -
                            FTUN_ENGINE_HTTP_ETAG_BYTES) return FTUN_E_LIMIT;
  input_length = sizeof(*header);
  if (spec->url.length > SIZE_MAX - input_length) return FTUN_E_LIMIT;
  input_length += spec->url.length;
  if (username_length > SIZE_MAX - input_length) return FTUN_E_LIMIT;
  input_length += username_length;
  if (password_length > SIZE_MAX - input_length) return FTUN_E_LIMIT;
  input_length += password_length;
  if (etag_length > SIZE_MAX - input_length) return FTUN_E_LIMIT;
  input_length += etag_length;
  result_capacity = sizeof(ftun_engine_http_result_t) +
                    FTUN_ENGINE_HTTP_ETAG_BYTES +
                    (validate_frs ? 0u : spec->maximum_bytes);
  if (spec->maximum_bytes > (SIZE_MAX - 2u * 1024u * 1024u) / 6u) {
    return FTUN_E_LIMIT;
  }
  accounted_extra = spec->maximum_bytes * (validate_frs ? 6u : 2u) +
                    2u * 1024u * 1024u;
  if (validate_frs) {
    const ftun_config_t *config = NULL;
    status = ftun_runtime_config(runtime_snapshot, &config);
    if (status == FTUN_OK) {
      status = ftun_runtime_accounted_bytes(config, &runtime_accounted);
    }
    if (status != FTUN_OK || runtime_accounted > SIZE_MAX - accounted_extra) {
      return status == FTUN_OK ? FTUN_E_LIMIT : status;
    }
    accounted_extra += runtime_accounted;
  }
  status = ftun_budget_reserve(engine->budget, input_length,
                               &input_reservation);
  if (status != FTUN_OK) return status;
  input = (uint8_t *)calloc(1u, input_length);
  if (input == NULL) {
    (void)ftun_reservation_release(&input_reservation);
    return FTUN_E_LIMIT;
  }
  header = (ftun_engine_http_work_t *)input;
  header->magic = FTUN_ENGINE_HTTP_WORK_MAGIC;
  header->mark = spec->socket_mark;
  header->resolver = spec->resolver;
  header->maximum_bytes = spec->maximum_bytes;
  header->deadline_ms = spec->deadline_ms;
  header->use_proxy = spec->use_proxy ? 1u : 0u;
  header->validate_frs = validate_frs ? 1u : 0u;
  header->runtime_snapshot = (uintptr_t)runtime_snapshot;
  header->proxy_port = spec->proxy.port;
  memcpy(header->proxy_address, spec->proxy.address, 4u);
  memcpy(header->proxy_domain, spec->proxy_domain,
         sizeof(header->proxy_domain));
  header->url_length = (uint32_t)spec->url.length;
  header->username_length = (uint32_t)username_length;
  header->password_length = (uint32_t)password_length;
  header->etag_length = (uint32_t)etag_length;
  memcpy(input + sizeof(*header), spec->url.data, spec->url.length);
  if (username_length != 0u) {
    memcpy(input + sizeof(*header) + spec->url.length,
           spec->proxy_username.data, username_length);
  }
  if (password_length != 0u) {
    memcpy(input + sizeof(*header) + spec->url.length + username_length,
           spec->proxy_password.data, password_length);
  }
  if (etag_length != 0u) {
    memcpy(input + sizeof(*header) + spec->url.length + username_length +
           password_length, spec->if_none_match.data, etag_length);
  }
  memset(&job, 0, sizeof(job));
  job.execute = ftun_engine_http_execute;
  job.input.data = input;
  job.input.length = input_length;
  job.result_capacity = result_capacity;
  job.accounted_extra = accounted_extra;
  job.input_cleanup = ftun_engine_http_input_cleanup;
  job.result_cleanup = ftun_engine_http_result_cleanup;
  job.deadline_ms = spec->deadline_ms;
  if (runtime_snapshot != NULL) {
    status = ftun_runtime_retain(runtime_snapshot);
    if (status != FTUN_OK) {
      free(input);
      (void)ftun_reservation_release(&input_reservation);
      return status;
    }
  }
  status = ftun_worker_submit(engine->maintenance_worker, &job, completion,
                              user, out);
  if (status != FTUN_OK && runtime_snapshot != NULL) {
    (void)ftun_runtime_release(&runtime_snapshot);
  }
  free(input);
  release_status = ftun_reservation_release(&input_reservation);
  if (status != FTUN_OK && release_status != FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
  }
  return status;
}

static int ftun_engine_nonblocking(int descriptor)
{
  int flags = fcntl(descriptor, F_GETFL, 0);
  return flags >= 0 &&
         fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0;
}

static ftun_status_t ftun_engine_parse_ipv4_endpoint(
  const char *text, ftun_endpoint_t *out)
{
  const char *colon;
  char address[INET_ADDRSTRLEN];
  char *tail = NULL;
  unsigned long port;
  size_t length;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (text == NULL || out == NULL || (colon = strrchr(text, ':')) == NULL) {
    return FTUN_E_INVALID;
  }
  length = (size_t)(colon - text);
  if (length == 0u || length >= sizeof(address) || colon[1] == '\0') {
    return FTUN_E_INVALID;
  }
  memcpy(address, text, length);
  address[length] = '\0';
  errno = 0;
  port = strtoul(colon + 1u, &tail, 10);
  if (errno != 0 || tail == colon + 1u || *tail != '\0' ||
      port == 0u || port > UINT16_MAX ||
      inet_pton(AF_INET, address, out->address) != 1) return FTUN_E_INVALID;
  out->kind = FTUN_ADDRESS_IPV4;
  out->port = (uint16_t)port;
  return FTUN_OK;
}

#if defined(FTUN_HAVE_MODULE_FAKEIP)
static ftun_status_t ftun_engine_fakeip_range(const char *text,
                                               uint32_t *first,
                                               uint32_t *end)
{
  const char *slash;
  char address_text[INET_ADDRSTRLEN];
  struct in_addr address;
  char *tail = NULL;
  unsigned long prefix;
  uint32_t host;
  uint32_t mask;
  uint32_t network;
  uint32_t broadcast;
  size_t length;
  if (first != NULL) *first = 0u;
  if (end != NULL) *end = 0u;
  if (text == NULL || first == NULL || end == NULL ||
      (slash = strchr(text, '/')) == NULL) return FTUN_E_INVALID;
  length = (size_t)(slash - text);
  if (length == 0u || length >= sizeof(address_text)) return FTUN_E_INVALID;
  memcpy(address_text, text, length);
  address_text[length] = '\0';
  errno = 0;
  prefix = strtoul(slash + 1u, &tail, 10);
  if (errno != 0 || tail == slash + 1u || *tail != '\0' || prefix > 32u ||
      inet_pton(AF_INET, address_text, &address) != 1) return FTUN_E_INVALID;
  host = ntohl(address.s_addr);
  mask = prefix == 0u ? 0u : UINT32_MAX << (32u - (unsigned int)prefix);
  network = host & mask;
  broadcast = network | ~mask;
  if (host != network || network == UINT32_MAX || network + 1u >= broadcast) {
    return FTUN_E_INVALID;
  }
  *first = network + 1u;
  *end = broadcast;
  return FTUN_OK;
}

static void ftun_engine_fakeip_store_completed(
  ftun_operation_t *operation, ftun_error_t error,
  ftun_fakeip_store_operation_t kind, uint64_t sequence,
  uint32_t reserved_end, void *user)
{
  ftun_engine_t *engine = (ftun_engine_t *)user;
  (void)operation;
  (void)sequence;
  (void)reserved_end;
  if (engine == NULL) return;
  if (kind == FTUN_FAKEIP_STORE_RESERVATION &&
      engine->fakeip_reserve_operation == operation) {
    engine->fakeip_reserve_operation = NULL;
  }
  engine->fakeip_store_status = error.status;
  if (engine->fakeip_store_completions != SIZE_MAX) {
    engine->fakeip_store_completions++;
  }
  if (kind == FTUN_FAKEIP_STORE_RESERVATION && error.status != FTUN_OK) {
    engine->fakeip_reserve_warning = true;
    ftun_engine_background_log(engine, error.status,
      "persistent FakeIP reservation failed; existing mappings remain readable");
  } else if (kind == FTUN_FAKEIP_STORE_RESERVATION) {
    engine->fakeip_reserve_warning = false;
  }
}

static ftun_status_t ftun_engine_wait_worker(ftun_engine_t *engine,
                                              ftun_worker_t *worker,
                                              size_t expected)
{
  uint64_t begin;
  ftun_status_t status = ftun_monotonic_now(&begin);
  if (status != FTUN_OK) return status;
  if (worker == NULL) return FTUN_E_INVALID;
  while (engine->fakeip_store_completions < expected) {
    uint64_t now;
    size_t callbacks = 0u;
    status = ftun_worker_poll(worker, 64u, &callbacks);
    if (status != FTUN_OK) return status;
    status = ftun_monotonic_now(&now);
    if (status != FTUN_OK) return status;
    if (now - begin >= FTUN_ENGINE_CONNECT_TIMEOUT_MS) return FTUN_E_TIMEOUT;
    if (callbacks == 0u) sched_yield();
  }
  return engine->fakeip_store_status;
}

static ftun_status_t ftun_engine_fakeip_prepare(ftun_engine_t *engine,
                                                 const ftun_config_t *config)
{
  ftun_fakeip_service_options_t service_options;
  ftun_fakeip_store_options_t store_options;
  ftun_fakeip_snapshot_t *snapshot = NULL;
  ftun_fakeip_store_info_t store_info;
  ftun_operation_t *operation = NULL;
  uint32_t first;
  uint32_t end;
  uint32_t reserve_end;
  size_t maximum;
  size_t path_length;
  size_t expected;
  ftun_status_t status;
  if ((config->plan->prepare & FTUN_PLAN_FAKE_IP) == 0u) return FTUN_OK;
  status = ftun_engine_fakeip_range(config->dns.fake_ip.range, &first, &end);
  if (status != FTUN_OK) return status;
  maximum = (size_t)((uint64_t)end - (uint64_t)first);
  if (maximum == 0u) return FTUN_E_INVALID;
  memset(&service_options, 0, sizeof(service_options));
  service_options.budget = engine->budget;
  service_options.max_entries = maximum;
  if (config->dns.fake_ip.persist) {
    if (config->base.cache_file == NULL) return FTUN_E_INVALID;
    path_length = strlen(config->base.cache_file);
    if (path_length > SIZE_MAX - sizeof(".fakeip")) return FTUN_E_LIMIT;
    engine->fakeip_directory = (char *)malloc(path_length + sizeof(".fakeip"));
    if (engine->fakeip_directory == NULL) return FTUN_E_LIMIT;
    memcpy(engine->fakeip_directory, config->base.cache_file, path_length);
    memcpy(engine->fakeip_directory + path_length, ".fakeip",
           sizeof(".fakeip"));
    memset(&store_options, 0, sizeof(store_options));
    store_options.directory = engine->fakeip_directory;
    store_options.budget = engine->budget;
    store_options.worker = engine->fakeip_worker;
    store_options.completion = ftun_engine_fakeip_store_completed;
    store_options.user = engine;
    status = ftun_fakeip_store_open(&store_options, &engine->fakeip_store);
    if (status == FTUN_OK) {
      status = ftun_fakeip_snapshot_load(engine->fakeip_store, maximum,
                                         &snapshot);
    }
    if (status == FTUN_OK) {
      status = ftun_fakeip_store_get_info(engine->fakeip_store, &store_info);
    }
    if (status == FTUN_OK &&
        (store_info.identity.first_address != first ||
         store_info.identity.end_address_exclusive != end)) {
      status = FTUN_E_STATE_CORRUPT;
    }
    service_options.store = engine->fakeip_store;
    service_options.snapshot = snapshot;
  } else {
    service_options.first_address = first;
    service_options.end_address_exclusive = end;
  }
  if (status == FTUN_OK) {
    status = ftun_fakeip_service_create(&service_options, &engine->fakeip);
  }
  (void)ftun_fakeip_snapshot_destroy(&snapshot);
  if (status != FTUN_OK) return status;
  if (engine->fakeip_store == NULL || store_info.reserved_end >= end) {
    return FTUN_OK;
  }
  reserve_end = store_info.reserved_end;
  if (reserve_end < first) return FTUN_E_STATE_CORRUPT;
  if ((uint64_t)reserve_end + FTUN_ENGINE_FAKEIP_RESERVE_BATCH <
      (uint64_t)end) {
    reserve_end += FTUN_ENGINE_FAKEIP_RESERVE_BATCH;
  }
  else reserve_end = end;
  expected = engine->fakeip_store_completions + 1u;
  engine->fakeip_store_status = FTUN_E_AGAIN;
  status = ftun_fakeip_store_reserve(engine->fakeip_store, reserve_end,
                                     &operation);
  if (status == FTUN_OK) engine->fakeip_reserve_operation = operation;
  if (status == FTUN_OK) status = ftun_engine_wait_worker(
    engine, engine->fakeip_worker, expected);
  return status;
}

static ftun_status_t ftun_engine_fakeip_reserve_runtime(
  ftun_engine_t *engine)
{
  ftun_fakeip_service_info_t service;
  ftun_fakeip_store_info_t store;
  ftun_operation_t *operation = NULL;
  uint32_t reserve_end;
  ftun_status_t status;
  if (engine == NULL || engine->fakeip_store == NULL ||
      engine->fakeip == NULL || engine->fakeip_reserve_operation != NULL) {
    return FTUN_OK;
  }
  status = ftun_fakeip_store_get_info(engine->fakeip_store, &store);
  if (status != FTUN_OK) return status;
  if (store.pending || store.halted) return FTUN_OK;
  status = ftun_fakeip_service_get_info(engine->fakeip, &service);
  if (status != FTUN_OK) return status;
  if (service.next_address > store.reserved_end ||
      store.reserved_end > service.end_address_exclusive) {
    return FTUN_E_STATE_CORRUPT;
  }
  if (store.reserved_end >= service.end_address_exclusive ||
      store.reserved_end - service.next_address >
        FTUN_ENGINE_FAKEIP_RESERVE_LOW_WATER) {
    return FTUN_OK;
  }
  reserve_end = store.reserved_end;
  if ((uint64_t)reserve_end + FTUN_ENGINE_FAKEIP_RESERVE_BATCH <
      (uint64_t)service.end_address_exclusive) {
    reserve_end += FTUN_ENGINE_FAKEIP_RESERVE_BATCH;
  } else {
    reserve_end = service.end_address_exclusive;
  }
  engine->fakeip_store_status = FTUN_E_AGAIN;
  status = ftun_fakeip_store_reserve(engine->fakeip_store, reserve_end,
                                     &operation);
  if (status == FTUN_OK) {
    engine->fakeip_reserve_operation = operation;
    engine->fakeip_reserve_warning = false;
    return FTUN_OK;
  }
  if (status != FTUN_E_AGAIN && !engine->fakeip_reserve_warning) {
    engine->fakeip_reserve_warning = true;
    ftun_engine_background_log(engine, status,
      "persistent FakeIP reservation could not be scheduled; "
      "existing mappings remain readable");
  }
  return FTUN_OK;
}
#endif

static ftun_status_t ftun_engine_listener_open(
  ftun_engine_listener_t *listener, const ftun_config_inbound_t *config,
  uint32_t inbound_id)
{
  ftun_endpoint_t endpoint;
  struct sockaddr_in address;
  int one = 1;
  int descriptor;
  int udp_descriptor = -1;
  ftun_status_t status = ftun_engine_parse_ipv4_endpoint(config->listen,
                                                          &endpoint);
  if (status != FTUN_OK) return status;
  descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
  if (descriptor < 0) return ftun_engine_errno_status(errno);
  (void)setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_port = htons(endpoint.port);
  memcpy(&address.sin_addr.s_addr, endpoint.address, 4u);
  if (bind(descriptor, (const struct sockaddr *)&address,
           (socklen_t)sizeof(address)) != 0 || listen(descriptor, 128) != 0 ||
      !ftun_engine_nonblocking(descriptor)) {
    int error_code = errno;
    (void)close(descriptor);
    return ftun_engine_errno_status(error_code);
  }
  if (config->udp) {
    udp_descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
    if (udp_descriptor < 0) {
      int error_code = errno;
      (void)close(descriptor);
      return ftun_engine_errno_status(error_code);
    }
    (void)setsockopt(udp_descriptor, SOL_SOCKET, SO_REUSEADDR, &one,
                     sizeof(one));
    if (bind(udp_descriptor, (const struct sockaddr *)&address,
             (socklen_t)sizeof(address)) != 0 ||
        !ftun_engine_nonblocking(udp_descriptor)) {
      int error_code = errno;
      (void)close(udp_descriptor);
      (void)close(descriptor);
      return ftun_engine_errno_status(error_code);
    }
  }
  listener->name = strdup(config->name);
  if (listener->name == NULL) {
    if (udp_descriptor >= 0) (void)close(udp_descriptor);
    (void)close(descriptor);
    return FTUN_E_LIMIT;
  }
  listener->descriptor = descriptor;
  listener->udp_descriptor = udp_descriptor;
  listener->kind = config->kind;
  listener->inbound_id = inbound_id;
  return FTUN_OK;
}

static ftun_status_t ftun_engine_stream_read(void *user, void *buffer,
                                              size_t capacity,
                                              size_t *out_length)
{
  ftun_engine_socket_stream_t *socket_stream =
    (ftun_engine_socket_stream_t *)user;
  ssize_t length;
  if (out_length != NULL) *out_length = 0u;
  if (socket_stream == NULL || socket_stream->descriptor < 0 ||
      buffer == NULL || capacity == 0u || out_length == NULL) {
    return FTUN_E_INVALID;
  }
  do {
    length = recv(socket_stream->descriptor, buffer, capacity, 0);
  } while (length < 0 && errno == EINTR);
  if (length > 0) {
    *out_length = (size_t)length;
    return FTUN_OK;
  }
  if (length == 0) return FTUN_E_EOF;
  return ftun_engine_errno_status(errno);
}

static ftun_status_t ftun_engine_stream_write_start(
  void *user, ftun_stream_write_t *write, const ftun_buffer_slice_t *slice,
  size_t *accepted)
{
  ftun_engine_socket_stream_t *socket_stream =
    (ftun_engine_socket_stream_t *)user;
  ftun_bytes_t bytes;
  ssize_t length;
  if (accepted != NULL) *accepted = 0u;
  if (socket_stream == NULL || socket_stream->descriptor < 0 ||
      socket_stream->pending != NULL ||
      write == NULL || slice == NULL || accepted == NULL ||
      ftun_buffer_slice_data(slice, &bytes) != FTUN_OK ||
      bytes.length == 0u) return FTUN_E_INVALID;
  do {
    length = send(socket_stream->descriptor, bytes.data, bytes.length,
                  MSG_NOSIGNAL);
  } while (length < 0 && errno == EINTR);
  if (length < 0) return ftun_engine_errno_status(errno);
  if (length == 0) return FTUN_E_IO;
  socket_stream->pending = write;
  *accepted = (size_t)length;
  ftun_engine_flow_schedule(socket_stream->flow);
  return FTUN_OK;
}

static ftun_status_t ftun_engine_stream_write_cancel(
  void *user, ftun_stream_write_t *write)
{
  ftun_engine_socket_stream_t *socket_stream =
    (ftun_engine_socket_stream_t *)user;
  if (socket_stream == NULL || socket_stream->pending != write) {
    return FTUN_E_STALE;
  }
  socket_stream->pending = NULL;
  return FTUN_OK;
}

static ftun_status_t ftun_engine_stream_shutdown(void *user)
{
  ftun_engine_socket_stream_t *socket_stream =
    (ftun_engine_socket_stream_t *)user;
  if (socket_stream == NULL || socket_stream->descriptor < 0) {
    return FTUN_E_INVALID;
  }
  if (socket_stream->write_shutdown) return FTUN_OK;
  if (shutdown(socket_stream->descriptor, SHUT_WR) != 0 &&
      errno != ENOTCONN) return ftun_engine_errno_status(errno);
  socket_stream->write_shutdown = true;
  return FTUN_OK;
}

static void ftun_engine_stream_destroy(void *user)
{
  ftun_engine_socket_stream_t *socket_stream =
    (ftun_engine_socket_stream_t *)user;
  if (socket_stream == NULL) return;
  if (socket_stream->descriptor >= 0) {
    (void)close(socket_stream->descriptor);
  }
  socket_stream->descriptor = -1;
  socket_stream->pending = NULL;
}

static ftun_status_t ftun_engine_stream_complete_pending(
  ftun_engine_socket_stream_t *socket_stream)
{
  ftun_stream_write_t *pending;
  ftun_error_t result;
  if (socket_stream == NULL || socket_stream->pending == NULL) return FTUN_OK;
  pending = socket_stream->pending;
  socket_stream->pending = NULL;
  memset(&result, 0, sizeof(result));
  result.status = FTUN_OK;
  return ftun_stream_write_complete(pending, result);
}

static void ftun_engine_stream_completed(ftun_operation_t *operation,
                                         ftun_error_t error, void *user)
{
  ftun_engine_flow_t *flow = (ftun_engine_flow_t *)user;
  (void)operation;
  if (flow != NULL && error.status != FTUN_OK &&
      error.status != FTUN_E_CANCELLED) ftun_engine_flow_close(flow,
                                                               error.status);
}

static void ftun_engine_stream_progress(void *user)
{
  ftun_engine_flow_schedule((ftun_engine_flow_t *)user);
}

static ftun_status_t ftun_engine_stream_create(
  ftun_engine_flow_t *flow, ftun_engine_socket_stream_t *socket_stream,
  int descriptor, ftun_stream_t **out)
{
  ftun_stream_options_t options;
  ftun_stream_backend_t backend;
  socket_stream->flow = flow;
  socket_stream->descriptor = descriptor;
  socket_stream->write_shutdown = false;
  memset(&options, 0, sizeof(options));
  options.budget = flow->engine->budget;
  options.operations = flow->engine->operations;
  options.max_pending_writes = 16u;
  options.max_pending_bytes = 256u * 1024u;
  options.completion = ftun_engine_stream_completed;
  options.completion_user = flow;
  options.progress = ftun_engine_stream_progress;
  options.progress_user = flow;
  memset(&backend, 0, sizeof(backend));
  backend.read = ftun_engine_stream_read;
  backend.write_start = ftun_engine_stream_write_start;
  backend.write_cancel = ftun_engine_stream_write_cancel;
  backend.shutdown_write = ftun_engine_stream_shutdown;
  backend.destroy = ftun_engine_stream_destroy;
  backend.context = socket_stream;
  return ftun_stream_create(&options, &backend, out);
}

static const ftun_config_inbound_t *ftun_engine_inbound_config(
  const ftun_config_t *config, const ftun_engine_listener_t *listener)
{
  size_t index;
  for (index = 0u; index < config->inbound_count; index++) {
    if (config->inbounds[index].name != NULL &&
        strcmp(config->inbounds[index].name, listener->name) == 0) {
      return &config->inbounds[index];
    }
  }
  return NULL;
}

static const ftun_config_inbound_t *ftun_engine_inbound_by_id(
  const ftun_config_t *config, uint32_t inbound_id)
{
  if (config == NULL || inbound_id == 0u ||
      (size_t)inbound_id > config->inbound_count) return NULL;
  return &config->inbounds[inbound_id - 1u];
}

static ftun_status_t ftun_engine_build_inbound_spec(
  ftun_engine_flow_t *flow, const ftun_config_inbound_t *config,
  ftun_inbound_spec_t *spec, ftun_inbound_user_t **out_users)
{
  ftun_inbound_user_t *users = NULL;
  size_t index;
  if (out_users != NULL) *out_users = NULL;
  if (flow == NULL || config == NULL || spec == NULL || out_users == NULL) {
    return FTUN_E_INVALID;
  }
  if (config->user_count != 0u) {
    users = (ftun_inbound_user_t *)calloc(config->user_count, sizeof(*users));
    if (users == NULL) return FTUN_E_LIMIT;
    for (index = 0u; index < config->user_count; index++) {
      users[index].username.data = (const uint8_t *)config->users[index].name;
      users[index].username.length = strlen(config->users[index].name);
      users[index].password.data =
        (const uint8_t *)config->users[index].password;
      users[index].password.length = strlen(config->users[index].password);
    }
  }
  memset(spec, 0, sizeof(*spec));
  spec->budget = flow->engine->budget;
  spec->kind = config->kind == FTUN_CONFIG_INBOUND_MIXED
    ? FTUN_INBOUND_MIXED : FTUN_INBOUND_SOCKS5;
  spec->generation = flow->engine->generation;
  spec->id = flow->listener->inbound_id;
  spec->name.data = config->name;
  spec->name.length = strlen(config->name);
  spec->tcp = true;
  spec->udp = config->udp;
  spec->users = users;
  spec->user_count = config->user_count;
  *out_users = users;
  return FTUN_OK;
}

static void ftun_engine_flow_deadline_ready(ftun_event_source_t *source,
                                             uint32_t events, void *user)
{
  ftun_engine_flow_t *flow = (ftun_engine_flow_t *)user;
  if (flow == NULL || !flow->active || flow->deadline_source != source ||
      (events & FTUN_EVENT_TIMER) == 0u) return;
  ftun_engine_flow_close(flow, FTUN_E_TIMEOUT);
}

static ftun_status_t ftun_engine_flow_deadline_arm(
  ftun_engine_flow_t *flow, uint64_t deadline_ms)
{
  ftun_status_t status;
  if (flow == NULL || !flow->active || deadline_ms == 0u) {
    return FTUN_E_INVALID;
  }
  status = ftun_event_source_cancel(&flow->deadline_source);
  if (status != FTUN_OK) return status;
  return ftun_event_timer_start(flow->engine->loop, deadline_ms,
    ftun_engine_flow_deadline_ready, flow, &flow->deadline_source);
}

static ftun_status_t ftun_engine_queue_reply(ftun_engine_flow_t *flow,
                                              ftun_bytes_t wire,
                                              bool close_after)
{
  bool first_reply;
  uint64_t now;
  uint64_t deadline;
  ftun_status_t status;
  if (flow == NULL || (wire.length != 0u && wire.data == NULL) ||
      wire.length > sizeof(flow->reply) - flow->reply_length) {
    return FTUN_E_LIMIT;
  }
  first_reply = flow->reply_length == 0u && wire.length != 0u;
  if (wire.length != 0u) {
    memcpy(flow->reply + flow->reply_length, wire.data, wire.length);
    flow->reply_length += wire.length;
  }
  flow->close_after_reply = flow->close_after_reply || close_after;
  if (first_reply) {
    status = ftun_monotonic_now(&now);
    if (status != FTUN_OK || now > UINT64_MAX - FTUN_ENGINE_REPLY_TIMEOUT_MS) {
      return status == FTUN_OK ? FTUN_E_LIMIT : status;
    }
    deadline = now + FTUN_ENGINE_REPLY_TIMEOUT_MS;
    if (flow->state == FTUN_ENGINE_FLOW_HANDSHAKE &&
        flow->handshake_deadline_ms < deadline) {
      deadline = flow->handshake_deadline_ms;
    }
    status = ftun_engine_flow_deadline_arm(flow, deadline);
    if (status != FTUN_OK) return status;
  }
  /* Replies can be produced by DNS/dial worker completions while the flow has
   * no subscribed WRITE interest.  Queue the owner-side drive so interests
   * are refreshed without relying on the removed full flow-table scan. */
  if (wire.length != 0u) ftun_engine_flow_schedule(flow);
  return FTUN_OK;
}

static ftun_status_t ftun_engine_flush_reply(ftun_engine_flow_t *flow)
{
  while (flow->reply_offset < flow->reply_length) {
    ssize_t length = send(flow->client_socket.descriptor,
      flow->reply + flow->reply_offset,
      flow->reply_length - flow->reply_offset, MSG_NOSIGNAL);
    if (length > 0) flow->reply_offset += (size_t)length;
    else if (length < 0 && errno == EINTR) continue;
    else if (length < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      return FTUN_E_AGAIN;
    } else {
      return length == 0 ? FTUN_E_IO : ftun_engine_errno_status(errno);
    }
  }
  flow->reply_offset = 0u;
  flow->reply_length = 0u;
  if (flow->close_after_reply) {
    flow->state = FTUN_ENGINE_FLOW_CLOSING;
    return FTUN_E_EOF;
  }
  if (flow->state == FTUN_ENGINE_FLOW_HANDSHAKE) {
    return ftun_engine_flow_deadline_arm(flow,
                                         flow->handshake_deadline_ms);
  }
  (void)ftun_event_source_cancel(&flow->deadline_source);
  return FTUN_OK;
}

static ftun_status_t ftun_engine_preread_release(ftun_engine_flow_t *flow)
{
  if (flow == NULL) return FTUN_E_INVALID;
  free(flow->preread);
  flow->preread = NULL;
  flow->preread_capacity = 0u;
  flow->preread_offset = 0u;
  flow->preread_length = 0u;
  return ftun_reservation_release(&flow->preread_reservation);
}

static ftun_status_t ftun_engine_preread_ensure(ftun_engine_flow_t *flow,
                                                size_t required)
{
  ftun_reservation_t *reservation = NULL;
  uint8_t *storage;
  size_t capacity;
  ftun_status_t status;
  if (flow == NULL || required > FTUN_ENGINE_PREREAD_BYTES) {
    return FTUN_E_LIMIT;
  }
  if (required > flow->preread_capacity) {
    capacity = flow->preread_capacity == 0u ? 4096u : flow->preread_capacity;
    while (capacity < required && capacity < FTUN_ENGINE_PREREAD_BYTES) {
      capacity = capacity > FTUN_ENGINE_PREREAD_BYTES / 2u
        ? FTUN_ENGINE_PREREAD_BYTES : capacity * 2u;
    }
    status = ftun_budget_reserve(flow->engine->budget, capacity,
                                 &reservation);
    if (status != FTUN_OK) return status;
    storage = (uint8_t *)malloc(capacity);
    if (storage == NULL) {
      (void)ftun_reservation_release(&reservation);
      return FTUN_E_LIMIT;
    }
    if (flow->preread_length != 0u) {
      memcpy(storage, flow->preread, flow->preread_length);
    }
    free(flow->preread);
    if (ftun_reservation_release(&flow->preread_reservation) != FTUN_OK) {
      free(storage);
      (void)ftun_reservation_release(&reservation);
      return FTUN_E_STATE_CORRUPT;
    }
    flow->preread = storage;
    flow->preread_reservation = reservation;
    flow->preread_capacity = capacity;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_engine_copy_preread(ftun_engine_flow_t *flow,
                                               ftun_bytes_t bytes)
{
  size_t source_offset = 0u;
  bool aliases_preread = false;
  ftun_status_t status;
  if (flow == NULL || (bytes.length != 0u && bytes.data == NULL) ||
      bytes.length > FTUN_ENGINE_PREREAD_BYTES) return FTUN_E_LIMIT;
  if (flow->preread != NULL && bytes.data != NULL) {
    uintptr_t source = (uintptr_t)bytes.data;
    uintptr_t begin = (uintptr_t)flow->preread;
    if (source >= begin && source - begin <= flow->preread_capacity) {
      source_offset = (size_t)(source - begin);
      aliases_preread = bytes.length <=
        flow->preread_capacity - source_offset;
    }
  }
  status = ftun_engine_preread_ensure(flow, bytes.length);
  if (status != FTUN_OK) return status;
  if (aliases_preread) bytes.data = flow->preread + source_offset;
  if (bytes.length != 0u) memmove(flow->preread, bytes.data, bytes.length);
  flow->preread_offset = 0u;
  flow->preread_length = bytes.length;
  return FTUN_OK;
}

static ftun_status_t ftun_engine_flush_preread(ftun_engine_flow_t *flow)
{
  while (flow->preread_offset < flow->preread_length) {
    ssize_t length = send(flow->remote_socket.descriptor,
      flow->preread + flow->preread_offset,
      flow->preread_length - flow->preread_offset, MSG_NOSIGNAL);
    if (length > 0) flow->preread_offset += (size_t)length;
    else if (length < 0 && errno == EINTR) continue;
    else if (length < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      return FTUN_E_AGAIN;
    } else {
      return length == 0 ? FTUN_E_IO : ftun_engine_errno_status(errno);
    }
  }
  flow->preread_offset = 0u;
  flow->preread_length = 0u;
  if (ftun_engine_preread_release(flow) != FTUN_OK) {
    return FTUN_E_STATE_CORRUPT;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_engine_runtime_for_flow(
  ftun_engine_flow_t *flow, ftun_runtime_t **out_runtime,
  const ftun_config_t **out_config)
{
  ftun_runtime_t *runtime = NULL;
  ftun_runtime_info_t info;
  ftun_status_t status;
  if (out_runtime != NULL) *out_runtime = NULL;
  if (out_config != NULL) *out_config = NULL;
  if (flow == NULL || out_runtime == NULL || out_config == NULL) {
    return FTUN_E_INVALID;
  }
  status = ftun_runtime_active_acquire(flow->engine->core, &runtime);
  if (status == FTUN_OK) status = ftun_runtime_get_info(runtime, &info);
  if (status == FTUN_OK && info.generation != flow->engine->generation) {
    status = FTUN_E_STALE;
  }
  if (status == FTUN_OK) status = ftun_runtime_config(runtime, out_config);
  if (status != FTUN_OK) {
    (void)ftun_runtime_release(&runtime);
    return status;
  }
  *out_runtime = runtime;
  return FTUN_OK;
}

static ftun_status_t ftun_engine_leaf(
  ftun_engine_t *engine, const ftun_runtime_t *runtime,
  const ftun_config_t *config,
  uint32_t requested, uint64_t generation, ftun_outbound_leaf_t *leaf,
  const ftun_config_outbound_t **out_config)
{
  ftun_group_choice_t choice;
  uint32_t id = requested;
  size_t index;
  ftun_status_t status;
  if (out_config != NULL) *out_config = NULL;
  memset(leaf, 0, sizeof(*leaf));
  if (requested >= FTUN_OUTBOUND_ID_NAMED_BASE) {
    index = (size_t)(requested - FTUN_OUTBOUND_ID_NAMED_BASE);
    if (index >= config->outbound_count) return FTUN_E_INVALID;
    if (config->outbounds[index].kind != FTUN_CONFIG_OUTBOUND_SOCKS5) {
      if (config->outbounds[index].kind == FTUN_CONFIG_OUTBOUND_URL_TEST) {
        ftun_engine_health_consume(engine, requested);
      }
      status = ftun_group_expand(runtime, requested, &choice);
      if (status != FTUN_OK) return status;
      id = choice.leaf_id;
    }
  }
  leaf->generation = generation;
  leaf->id = id;
  leaf->supports_tcp = true;
  leaf->supports_udp = true;
  if (id == FTUN_OUTBOUND_ID_DIRECT) {
    leaf->kind = FTUN_OUTBOUND_LEAF_DIRECT;
  } else if (id == FTUN_OUTBOUND_ID_REJECT) {
    leaf->kind = FTUN_OUTBOUND_LEAF_REJECT;
  } else {
    index = (size_t)(id - FTUN_OUTBOUND_ID_NAMED_BASE);
    if (index >= config->outbound_count ||
        config->outbounds[index].kind != FTUN_CONFIG_OUTBOUND_SOCKS5) {
      return FTUN_E_STATE_CORRUPT;
    }
    leaf->kind = FTUN_OUTBOUND_LEAF_SOCKS5;
    leaf->supports_udp = config->outbounds[index].udp;
    if (out_config != NULL) *out_config = &config->outbounds[index];
  }
  return FTUN_OK;
}

static ftun_status_t ftun_engine_session_start_metadata(
  ftun_engine_flow_t *flow, const ftun_metadata_t *input);
static ftun_status_t ftun_engine_route_open(ftun_engine_flow_t *flow);
static ftun_status_t ftun_engine_start_real_resolution(
  ftun_engine_flow_t *flow, ftun_resolve_request_t *request);
static ftun_status_t ftun_engine_resolve_async(
  ftun_engine_t *engine, const ftun_config_t *config,
  ftun_string_t domain, bool bootstrap_only,
  ftun_system_resolve_completion_fn completion, void *user,
  ftun_operation_t **out);

#if defined(FTUN_HAVE_MODULE_FAKEIP)
static ftun_status_t ftun_engine_restore_fakeip_to(
  ftun_engine_t *engine, ftun_metadata_t *metadata,
  char *domain_storage, size_t domain_capacity)
{
  ftun_fakeip_handle_t *handle = NULL;
  ftun_fakeip_service_info_t info;
  ftun_string_t domain;
  uint32_t address;
  uint32_t value;
  ftun_status_t status;
  if (engine == NULL || metadata == NULL || domain_storage == NULL ||
      domain_capacity == 0u || engine->fakeip == NULL ||
      metadata->original_target.kind != FTUN_ADDRESS_IPV4) return FTUN_OK;
  value = ((uint32_t)metadata->original_target.address[0] << 24u) |
          ((uint32_t)metadata->original_target.address[1] << 16u) |
          ((uint32_t)metadata->original_target.address[2] << 8u) |
          (uint32_t)metadata->original_target.address[3];
  status = ftun_fakeip_service_get_info(engine->fakeip, &info);
  if (status != FTUN_OK) return status;
  if (value < info.first_address || value >= info.end_address_exclusive) {
    return FTUN_OK;
  }
  status = ftun_fakeip_reverse(engine->fakeip, value, &handle);
  if (status == FTUN_E_EOF) return FTUN_E_REJECTED;
  if (status != FTUN_OK) return status;
  status = ftun_fakeip_handle_get(handle, &address, &domain);
  if (status == FTUN_OK && (address != value ||
      domain.length >= domain_capacity)) {
    status = FTUN_E_STATE_CORRUPT;
  }
  if (status == FTUN_OK) {
    memcpy(domain_storage, domain.data, domain.length);
    domain_storage[domain.length] = '\0';
    metadata->known_fields |= FTUN_META_DOMAIN;
    metadata->domain.data = domain_storage;
    metadata->domain.length = domain.length;
    metadata->domain_source = FTUN_DOMAIN_FAKEIP;
    metadata->original_is_fake = true;
  }
  if (ftun_fakeip_handle_release(&handle) != FTUN_OK && status == FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
  }
  return status;
}

#else
static ftun_status_t ftun_engine_restore_fakeip_to(
  ftun_engine_t *engine, ftun_metadata_t *metadata,
  char *domain_storage, size_t domain_capacity)
{
  (void)engine;
  (void)metadata;
  (void)domain_storage;
  (void)domain_capacity;
  return FTUN_OK;
}

#endif

#if defined(FTUN_HAVE_MODULE_TUN)
static ftun_status_t ftun_engine_restore_fakeip(ftun_engine_flow_t *flow,
                                                ftun_metadata_t *metadata)
{
  if (flow == NULL) return FTUN_E_INVALID;
  return ftun_engine_restore_fakeip_to(flow->engine, metadata,
    flow->sniff_domain, sizeof(flow->sniff_domain));
}
#endif

static ftun_status_t ftun_engine_session_start(
  ftun_engine_flow_t *flow, const ftun_endpoint_t *requested_target)
{
  ftun_metadata_t metadata;
  if (flow == NULL || requested_target == NULL) return FTUN_E_INVALID;
  memset(&metadata, 0, sizeof(metadata));
  metadata.known_fields = FTUN_META_PORT | FTUN_META_NETWORK;
  metadata.network = 1u;
  metadata.original_target = *requested_target;
  if (requested_target->kind == FTUN_ADDRESS_DOMAIN) {
    metadata.known_fields |= FTUN_META_DOMAIN;
    metadata.domain = requested_target->domain;
    metadata.domain_source = FTUN_DOMAIN_EXPLICIT;
  }
  return ftun_engine_session_start_metadata(flow, &metadata);
}

static void ftun_engine_flow_close(ftun_engine_flow_t *flow,
                                   ftun_status_t reason)
{
  ftun_error_t error;
  if (flow == NULL || !flow->active) return;
  /* A protocol-level failure reply owns the close sequence.  Keep the flow
   * alive until that bounded reply is drained; hard transport failures and
   * timeouts still tear it down immediately. */
  if (flow->close_after_reply && flow->reply_length != 0u &&
      reason != FTUN_E_IO && reason != FTUN_E_EOF &&
      reason != FTUN_E_TIMEOUT && reason != FTUN_E_CANCELLED) {
    ftun_engine_flow_schedule(flow);
    return;
  }
  flow->state = FTUN_ENGINE_FLOW_CLOSING;
#if defined(FTUN_HAVE_MODULE_TUN)
  if (flow->tun && flow->client != NULL && flow->engine->tun_ingress != NULL) {
    (void)ftun_tun_ingress_abort_stream(flow->engine->tun_ingress,
                                        flow->client);
  }
#endif
  if (flow->relay != NULL) (void)ftun_relay_stop(flow->relay);
  if (flow->session != NULL) {
    memset(&error, 0, sizeof(error));
    error.status = reason == FTUN_OK ? FTUN_E_CANCELLED : reason;
    (void)ftun_session_finish(flow->session, error);
  } else if (flow->open_operation != NULL) {
    (void)ftun_operation_cancel(flow->open_operation);
  }
  ftun_engine_flow_schedule(flow);
}

static ftun_status_t ftun_engine_protocol_finish(
  ftun_engine_flow_t *flow, ftun_status_t downstream,
  const ftun_endpoint_t *bound)
{
  ftun_status_t status;
  if (flow->tun) {
    (void)downstream;
    (void)bound;
    return FTUN_OK;
  }
  if (flow->listener->kind == FTUN_CONFIG_INBOUND_SOCKS5) {
    ftun_socks5_server_event_t event;
    status = ftun_socks5_server_finish_request(flow->socks5, downstream,
                                                bound, &event);
    if (status != FTUN_OK) return status;
    return ftun_engine_queue_reply(flow, event.wire,
                                   downstream != FTUN_OK);
  }
  if (flow->mixed_http) {
    if (flow->http_connect) {
      ftun_mixed_event_t event;
      status = ftun_mixed_http_finish(flow->mixed, downstream, &event);
      if (status != FTUN_OK) return status;
      return ftun_engine_queue_reply(flow, event.wire,
                                     downstream != FTUN_OK);
    }
    return downstream;
  } else if (flow->mixed != NULL) {
    {
      ftun_mixed_event_t event;
      status = ftun_mixed_socks5_finish_request(flow->mixed, downstream,
                                                 bound, &event);
      if (status != FTUN_OK) return status;
      return ftun_engine_queue_reply(flow, event.socks5.wire,
                                     downstream != FTUN_OK);
    }
  }
  return FTUN_E_STATE_CORRUPT;
}

static ftun_status_t ftun_engine_relay_ready(ftun_engine_flow_t *flow,
                                              int descriptor)
{
  ftun_endpoint_t bound;
  struct sockaddr_in address;
  socklen_t length = (socklen_t)sizeof(address);
  ftun_status_t status;
  memset(&bound, 0, sizeof(bound));
  bound.kind = FTUN_ADDRESS_IPV4;
  if (getsockname(descriptor, (struct sockaddr *)&address, &length) == 0 &&
      length >= (socklen_t)sizeof(address) && address.sin_family == AF_INET) {
    memcpy(bound.address, &address.sin_addr.s_addr, 4u);
    bound.port = ntohs(address.sin_port);
  }
  status = ftun_engine_stream_create(flow, &flow->remote_socket, descriptor,
                                     &flow->remote);
  if (status != FTUN_OK) {
    (void)close(descriptor);
    return status;
  }
  status = ftun_relay_start_with_pool(flow->engine->core, flow->client,
                                      flow->remote, flow->engine->relay_pool,
                                      &flow->relay);
  if (status == FTUN_OK && flow->session != NULL) {
    status = ftun_session_transition(flow->session,
                                     FTUN_SESSION_RELAYING, NULL);
  }
  if (status == FTUN_OK) status = ftun_engine_protocol_finish(flow, FTUN_OK,
                                                               &bound);
  if (status != FTUN_OK) return status;
  flow->state = FTUN_ENGINE_FLOW_RELAY;
  {
    uint32_t client_interests;
    uint32_t remote_interests;
    status = ftun_engine_flow_interests(flow, &client_interests,
                                        &remote_interests);
    if (status == FTUN_OK) {
      status = ftun_event_io_start(flow->engine->loop,
        (ftun_native_socket_t)(unsigned int)descriptor, remote_interests,
        ftun_engine_flow_remote_ready, flow, &flow->remote_source);
    }
    if (status == FTUN_OK && flow->client_source != NULL) {
      status = ftun_event_io_update(flow->client_source, client_interests);
    }
  }
  if (status == FTUN_OK) ftun_engine_flow_schedule(flow);
  return status;
}

static void ftun_engine_direct_completed(ftun_operation_t *operation,
                                         ftun_error_t error,
                                         const ftun_dial_result_t *result,
                                         void *user)
{
  ftun_engine_flow_t *flow = (ftun_engine_flow_t *)user;
  ftun_status_t status;
  if (flow == NULL || !flow->active || flow->session == NULL) return;
  flow->open_operation = NULL;
  status = ftun_session_operation_complete(flow->session, operation, error);
  if (status == FTUN_OK && error.status == FTUN_OK && result != NULL &&
      result->socket != FTUN_INVALID_SOCKET) {
    status = ftun_engine_relay_ready(flow, (int)result->socket);
  } else if (status == FTUN_OK) {
    status = error.status == FTUN_OK ? FTUN_E_STATE_CORRUPT : error.status;
  }
  if (status != FTUN_OK) {
    (void)ftun_engine_protocol_finish(flow, status, NULL);
    ftun_engine_flow_close(flow, status);
  }
}

static void ftun_engine_socks_completed(
  ftun_operation_t *operation, ftun_error_t error,
  ftun_socks5_connection_t *connection, void *user)
{
  ftun_engine_flow_t *flow = (ftun_engine_flow_t *)user;
  ftun_native_socket_t socket = FTUN_INVALID_SOCKET;
  ftun_status_t status;
  if (flow == NULL || !flow->active || flow->session == NULL) {
    (void)ftun_socks5_connection_close(&connection);
    return;
  }
  flow->open_operation = NULL;
  flow->proxy_connection = connection;
  status = ftun_session_operation_complete(flow->session, operation, error);
  if (status == FTUN_OK && error.status == FTUN_OK && connection != NULL) {
    status = ftun_socks5_connection_take_tcp(&flow->proxy_connection, &socket);
  } else if (status == FTUN_OK) {
    status = error.status == FTUN_OK ? FTUN_E_STATE_CORRUPT : error.status;
  }
  if (status == FTUN_OK) status = ftun_engine_relay_ready(flow, (int)socket);
  if (status != FTUN_OK) {
    (void)ftun_socks5_connection_close(&flow->proxy_connection);
    (void)ftun_engine_protocol_finish(flow, status, NULL);
    ftun_engine_flow_close(flow, status);
  }
}

static ftun_status_t ftun_engine_system_resolver_path(
  void *user, const ftun_socket_policy_t *protection)
{
  ftun_engine_t *engine = (ftun_engine_t *)user;
  if (engine == NULL || protection == NULL ||
      (protection->mark == 0u &&
       protection->interface_name.length != 0u)) {
    return FTUN_E_INVALID;
  }
#if defined(FTUN_HAVE_MODULE_TUN)
  /* libc/NSS 隐藏 socket 无法继承 SO_MARK；本机捕获启用时拒绝可能回环的
   * SystemResolver。显式 Bootstrap 和命名 DNS 均使用受保护 socket。 */
  if (engine->routes != NULL) return FTUN_E_REJECTED;
#endif
  return FTUN_OK;
}

static void ftun_engine_resolve_completed(
  ftun_operation_t *operation, ftun_error_t error,
  const ftun_system_resolve_result_t *result, void *user)
{
  ftun_engine_flow_t *flow = (ftun_engine_flow_t *)user;
  ftun_status_t status = FTUN_OK;
  if (flow == NULL || !flow->active || flow->session == NULL) return;
  flow->open_operation = NULL;
  if (error.status == FTUN_OK) {
    if (result == NULL) {
      error.status = FTUN_E_STATE_CORRUPT;
    } else {
      status = ftun_session_store_resolved(flow->session, operation,
        result->addresses, result->address_count);
      if (status != FTUN_OK) error.status = status;
    }
  }
  status = ftun_session_operation_complete(flow->session, operation, error);
  if (status == FTUN_OK && error.status == FTUN_OK &&
      flow->state != FTUN_ENGINE_FLOW_CLOSING) {
    status = ftun_session_transition(flow->session, FTUN_SESSION_ROUTING,
                                     NULL);
    if (status == FTUN_OK) status = ftun_engine_route_open(flow);
  }
  if (status != FTUN_OK || error.status != FTUN_OK) {
    ftun_status_t failure = status != FTUN_OK ? status : error.status;
    (void)ftun_engine_protocol_finish(flow, failure, NULL);
    ftun_engine_flow_close(flow, failure);
  }
}

static void ftun_engine_proxy_resolved(
  ftun_operation_t *operation, ftun_error_t error,
  const ftun_system_resolve_result_t *result, void *user)
{
  ftun_engine_flow_t *flow = (ftun_engine_flow_t *)user;
  ftun_status_t status = FTUN_OK;
  size_t index;
  if (flow == NULL || !flow->active || flow->session == NULL ||
      flow->open_operation != operation) return;
  flow->open_operation = NULL;
  if (error.status == FTUN_OK && (result == NULL ||
      result->address_count == 0u ||
      result->address_count > FTUN_SESSION_MAX_RESOLVED_IPV4)) {
    error.status = FTUN_E_STATE_CORRUPT;
  }
  for (index = 0u; error.status == FTUN_OK &&
       index < result->address_count; index++) {
    if (result->addresses[index].kind != FTUN_ADDRESS_IPV4) {
      error.status = FTUN_E_UNSUPPORTED;
      break;
    }
    flow->proxy_resolved[index] = result->addresses[index];
    flow->proxy_resolved[index].port = flow->proxy_port;
    flow->proxy_resolved[index].domain.data = NULL;
    flow->proxy_resolved[index].domain.length = 0u;
  }
  if (error.status == FTUN_OK) {
    flow->proxy_resolved_count = result->address_count;
  }
  status = ftun_session_operation_complete(flow->session, operation, error);
  if (status == FTUN_OK && error.status == FTUN_OK &&
      flow->state != FTUN_ENGINE_FLOW_CLOSING) {
    status = ftun_session_transition(flow->session, FTUN_SESSION_ROUTING,
                                     NULL);
    if (status == FTUN_OK) status = ftun_engine_route_open(flow);
  }
  if (status != FTUN_OK || error.status != FTUN_OK) {
    ftun_status_t failure = status != FTUN_OK ? status : error.status;
    (void)ftun_engine_protocol_finish(flow, failure, NULL);
    ftun_engine_flow_close(flow, failure);
  }
}

static ftun_status_t ftun_engine_start_real_resolution(
  ftun_engine_flow_t *flow, ftun_resolve_request_t *request)
{
  ftun_operation_t *operation = NULL;
  ftun_status_t status;
  if (flow == NULL || request == NULL || flow->session == NULL) {
    return FTUN_E_INVALID;
  }
  request->query.check_system_path = ftun_engine_system_resolver_path;
  request->query.system_path_user = flow->engine;
  request->query.completion = ftun_engine_resolve_completed;
  request->query.user = flow;
  status = ftun_resolve_real(flow->engine->core, request, &operation);
  if (status != FTUN_OK) return status;
  status = ftun_session_transition(flow->session, FTUN_SESSION_RESOLVING,
                                   operation);
  if (status != FTUN_OK) {
    (void)ftun_operation_cancel(operation);
    return status;
  }
  flow->open_operation = operation;
  flow->state = FTUN_ENGINE_FLOW_CONNECTING;
  return FTUN_OK;
}

static ftun_status_t ftun_engine_resolve_session(
  ftun_engine_flow_t *flow, ftun_string_t server)
{
  ftun_resolve_request_t request;
  ftun_bootstrap_request_t *query = &request.query;
  ftun_endpoint_t bootstrap[FTUN_BOOTSTRAP_MAX_SERVERS];
  const ftun_runtime_t *session_runtime = NULL;
  const ftun_config_t *config = NULL;
  const ftun_metadata_t *stored = NULL;
  size_t index;
  ftun_status_t status;
  if (flow == NULL || flow->session == NULL ||
      (server.length != 0u && server.data == NULL)) return FTUN_E_INVALID;
  memset(&request, 0, sizeof(request));
  status = ftun_session_get_runtime(flow->session, &session_runtime);
  if (status == FTUN_OK) status = ftun_runtime_config(session_runtime,
                                                      &config);
  if (status == FTUN_OK) status = ftun_session_get_metadata(flow->session,
                                                            &stored);
  if (status != FTUN_OK) return status;
  request.session = flow->session;
  request.dns_enabled = config->dns.enable;
  request.default_server = server;
  query->loop = flow->engine->loop;
  query->operations = flow->engine->operations;
  query->worker = flow->engine->worker;
  query->budget = flow->engine->budget;
  query->domain = stored->domain;
  query->protection.mark = flow->engine->socket_mark;
  status = ftun_monotonic_now(&query->deadline_ms);
  if (status == FTUN_OK && query->deadline_ms <=
      UINT64_MAX - FTUN_ENGINE_CONNECT_TIMEOUT_MS) {
    query->deadline_ms += FTUN_ENGINE_CONNECT_TIMEOUT_MS;
  } else if (status == FTUN_OK) {
    status = FTUN_E_LIMIT;
  }
  flow->engine->next_dns_query_id++;
  if (flow->engine->next_dns_query_id == 0u) {
    flow->engine->next_dns_query_id++;
  }
  query->query_id = flow->engine->next_dns_query_id;
  for (index = 0u; status == FTUN_OK &&
       index < config->dns.bootstrap.count; index++) {
    const char *text = config->dns.bootstrap.items[index];
    const char *colon = strrchr(text, ':');
    char endpoint[INET_ADDRSTRLEN + 7u];
    if (colon == NULL) {
      int length = snprintf(endpoint, sizeof(endpoint), "%s:53", text);
      if (length <= 0 || (size_t)length >= sizeof(endpoint)) {
        status = FTUN_E_LIMIT;
      } else {
        status = ftun_engine_parse_ipv4_endpoint(endpoint,
                                                  &bootstrap[index]);
      }
    } else {
      status = ftun_engine_parse_ipv4_endpoint(text, &bootstrap[index]);
    }
  }
  if (status == FTUN_OK) {
    query->servers = bootstrap;
    query->server_count = config->dns.bootstrap.count;
  }
  return status == FTUN_OK
    ? ftun_engine_start_real_resolution(flow, &request) : status;
}

static ftun_status_t ftun_engine_session_start_metadata(
  ftun_engine_flow_t *flow, const ftun_metadata_t *input)
{
  ftun_runtime_t *runtime = NULL;
  const ftun_config_t *config = NULL;
  const ftun_config_inbound_t *inbound;
  ftun_runtime_info_t runtime_info;
  ftun_metadata_t metadata;
  ftun_status_t status;
  if (flow == NULL || input == NULL) return FTUN_E_INVALID;
  metadata = *input;
  status = ftun_engine_runtime_for_flow(flow, &runtime, &config);
  if (status == FTUN_OK) status = ftun_runtime_get_info(runtime,
                                                        &runtime_info);
  inbound = status == FTUN_OK
    ? ftun_engine_inbound_config(config, flow->listener) : NULL;
  if (status == FTUN_OK && inbound == NULL) status = FTUN_E_STALE;
  if (status == FTUN_OK) {
    metadata.generation = runtime_info.generation;
    metadata.inbound_id = flow->listener->inbound_id;
    status = ftun_session_submit(flow->engine->core, &metadata, flow->client,
                                 &flow->session);
  }
  (void)ftun_runtime_release(&runtime);
  if (status != FTUN_OK) return status;
  status = ftun_session_transition(flow->session, FTUN_SESSION_ROUTING, NULL);
  if (status != FTUN_OK) return status;
  return ftun_engine_route_open(flow);
}

static ftun_status_t ftun_engine_route_open(ftun_engine_flow_t *flow)
{
  const ftun_runtime_t *session_runtime = NULL;
  const ftun_metadata_t *metadata = NULL;
  const ftun_config_t *config = NULL;
  const ftun_config_inbound_t *inbound;
  const ftun_config_outbound_t *proxy_config = NULL;
  ftun_runtime_info_t runtime_info;
  ftun_route_result_t route;
  ftun_target_t target;
  ftun_outbound_leaf_t leaf;
  ftun_outbound_request_t request;
  ftun_direct_request_t direct;
  ftun_socks5_proxy_t proxy;
  ftun_socks5_connect_request_t socks;
  ftun_endpoint_t proxy_server;
  ftun_reject_result_t reject;
  uint32_t forced = 0u;
  bool has_forced = false;
  bool resume_proxy;
  ftun_status_t status;
  if (flow == NULL || flow->session == NULL) return FTUN_E_INVALID;
  status = ftun_session_get_runtime(flow->session, &session_runtime);
  if (status == FTUN_OK) status = ftun_runtime_get_info(session_runtime,
                                                        &runtime_info);
  if (status == FTUN_OK) status = ftun_runtime_config(session_runtime,
                                                      &config);
  if (status == FTUN_OK) status = ftun_session_get_metadata(flow->session,
                                                            &metadata);
  inbound = status == FTUN_OK
    ? ftun_engine_inbound_config(config, flow->listener) : NULL;
  if (status == FTUN_OK && inbound == NULL) status = FTUN_E_STALE;
  resume_proxy = flow->proxy_leaf_id != 0u &&
                 flow->proxy_resolved_count != 0u;
  if (status == FTUN_OK && !resume_proxy && inbound->outbound != NULL &&
      inbound->outbound[0] != '\0') {
    has_forced = true;
    status = ftun_runtime_resolve_outbound_name(session_runtime,
      (ftun_string_t){inbound->outbound, strlen(inbound->outbound)}, &forced);
  }
  memset(&route, 0, sizeof(route));
  if (status == FTUN_OK && resume_proxy) {
    const ftun_route_result_t *stored_route = NULL;
    status = ftun_session_get_route(flow->session, &stored_route);
    if (status == FTUN_OK) {
      route = *stored_route;
      if (stored_route->allowed_count != 0u) {
        memcpy(route.allowed_storage, stored_route->allowed,
          stored_route->allowed_count * sizeof(route.allowed_storage[0]));
        route.allowed = route.allowed_storage;
      }
    }
  } else if (status == FTUN_OK && has_forced) {
    route.kind = forced == FTUN_OUTBOUND_ID_REJECT
      ? FTUN_ROUTE_DENY : FTUN_ROUTE_READY;
    route.generation = runtime_info.generation;
    route.outbound_id = forced;
    if (metadata->original_target.kind == FTUN_ADDRESS_IPV4 &&
        !metadata->original_is_fake) {
      route.allowed = &metadata->original_target;
      route.allowed_count = 1u;
    } else {
      route.allowed = metadata->resolved;
      route.allowed_count = metadata->resolved_count;
    }
  } else if (status == FTUN_OK) {
    status = ftun_route_evaluate(session_runtime, metadata, 0u, &route);
  }
  if (status == FTUN_OK && route.kind == FTUN_ROUTE_NEED_RESOLVE) {
    ftun_string_t server = {NULL, 0u};
    if (config->dns.default_server != NULL &&
        config->dns.default_server[0] != '\0') {
      server.data = config->dns.default_server;
      server.length = strlen(config->dns.default_server);
    }
    return ftun_engine_resolve_session(flow, server);
  }
  if (status == FTUN_OK && route.kind == FTUN_ROUTE_DENY) {
    status = FTUN_E_REJECTED;
  }
  if (status == FTUN_OK) {
    status = ftun_engine_leaf(flow->engine, session_runtime, config,
                              flow->proxy_leaf_id != 0u
                                ? flow->proxy_leaf_id : route.outbound_id,
                              route.generation, &leaf, &proxy_config);
  }
  if (status == FTUN_OK && !resume_proxy &&
      leaf.kind == FTUN_OUTBOUND_LEAF_DIRECT &&
      route.allowed_count == 0u &&
      (metadata->known_fields & FTUN_META_DOMAIN) != 0u) {
    /* DIRECT cannot delegate a domain to a remote peer.  Resolve it through
     * Bootstrap (or SystemResolver when DNS is disabled) before pinning the
     * route; a selected proxy may keep an unresolved SOCKS domain. */
    return ftun_engine_resolve_session(flow, (ftun_string_t){NULL, 0u});
  }
  if (status == FTUN_OK && !resume_proxy) {
    route.outbound_id = leaf.id;
    status = ftun_session_pin_route(flow->session, &route);
  }
  if (status == FTUN_OK) {
    status = ftun_target_from_metadata(metadata, &target);
  }
  if (status == FTUN_OK) {
    const ftun_route_result_t *stored_route = NULL;
    status = ftun_session_get_route(flow->session, &stored_route);
    if (status == FTUN_OK) status = ftun_target_apply_route(&target,
                                                            stored_route);
  }
  if (status != FTUN_OK) return status;
  {
    const ftun_route_result_t *stored_route = NULL;
    (void)ftun_session_get_route(flow->session, &stored_route);
    memset(&request, 0, sizeof(request));
    request.route = stored_route;
    request.target = &target;
    request.leaf = &leaf;
    request.transport = FTUN_DIAL_TCP;
  }
  if (leaf.kind == FTUN_OUTBOUND_LEAF_DIRECT) {
    memset(&direct, 0, sizeof(direct));
    direct.loop = flow->engine->loop;
    direct.operations = flow->engine->operations;
    direct.budget = flow->engine->budget;
    direct.protection.mark = flow->engine->socket_mark;
    direct.deadline_ms = 0u;
    status = ftun_monotonic_now(&direct.deadline_ms);
    if (status == FTUN_OK && direct.deadline_ms <=
        UINT64_MAX - FTUN_ENGINE_CONNECT_TIMEOUT_MS) {
      direct.deadline_ms += FTUN_ENGINE_CONNECT_TIMEOUT_MS;
    } else if (status == FTUN_OK) {
      status = FTUN_E_LIMIT;
    }
    direct.transport = FTUN_DIAL_TCP;
    direct.completion = ftun_engine_direct_completed;
    direct.user = flow;
    request.direct = &direct;
  } else if (leaf.kind == FTUN_OUTBOUND_LEAF_SOCKS5) {
    status = ftun_engine_parse_ipv4_endpoint(proxy_config->server,
                                              &proxy_server);
    if (status != FTUN_OK) {
      const char *colon = strrchr(proxy_config->server, ':');
      if (colon != NULL && colon != proxy_config->server) {
        size_t domain_length = (size_t)(colon - proxy_config->server);
        char *tail = NULL;
        unsigned long port = strtoul(colon + 1u, &tail, 10);
        if (domain_length <= 253u && tail != colon + 1u && *tail == '\0' &&
            port != 0u && port <= UINT16_MAX) {
          memset(&proxy_server, 0, sizeof(proxy_server));
          proxy_server.kind = FTUN_ADDRESS_DOMAIN;
          proxy_server.domain.data = proxy_config->server;
          proxy_server.domain.length = domain_length;
          proxy_server.port = (uint16_t)port;
          status = FTUN_OK;
        }
      }
    }
    if (status == FTUN_OK && proxy_server.kind == FTUN_ADDRESS_DOMAIN &&
        flow->proxy_resolved_count == 0u) {
      ftun_operation_t *operation = NULL;
      flow->proxy_leaf_id = leaf.id;
      flow->proxy_port = proxy_server.port;
      status = ftun_engine_resolve_async(flow->engine, config,
        proxy_server.domain, true, ftun_engine_proxy_resolved, flow,
        &operation);
      if (status == FTUN_OK) {
        status = ftun_session_transition(flow->session,
          FTUN_SESSION_RESOLVING, operation);
      }
      if (status != FTUN_OK && operation != NULL) {
        (void)ftun_operation_cancel(operation);
      }
      if (status == FTUN_OK) {
        flow->open_operation = operation;
        flow->state = FTUN_ENGINE_FLOW_CONNECTING;
      }
      return status;
    }
    if (status == FTUN_OK) {
      memset(&proxy, 0, sizeof(proxy));
      proxy.server = proxy_server;
      if (proxy_server.kind == FTUN_ADDRESS_DOMAIN) {
        proxy.resolved = flow->proxy_resolved;
        proxy.resolved_count = flow->proxy_resolved_count;
      }
      if (proxy_config->username != NULL) {
        proxy.username.data = (const uint8_t *)proxy_config->username;
        proxy.username.length = strlen(proxy_config->username);
      }
      if (proxy_config->password != NULL) {
        proxy.password.data = (const uint8_t *)proxy_config->password;
        proxy.password.length = strlen(proxy_config->password);
      }
      proxy.udp_enabled = proxy_config->udp;
      memset(&socks, 0, sizeof(socks));
      socks.loop = flow->engine->loop;
      socks.operations = flow->engine->operations;
      socks.budget = flow->engine->budget;
      socks.proxy = &proxy;
      socks.target = &target;
      socks.protection.mark = flow->engine->socket_mark;
      status = ftun_monotonic_now(&socks.deadline_ms);
      if (status == FTUN_OK && socks.deadline_ms <=
          UINT64_MAX - FTUN_ENGINE_CONNECT_TIMEOUT_MS) {
        socks.deadline_ms += FTUN_ENGINE_CONNECT_TIMEOUT_MS;
      } else if (status == FTUN_OK) {
        status = FTUN_E_LIMIT;
      }
      socks.transport = FTUN_DIAL_TCP;
      socks.completion = ftun_engine_socks_completed;
      socks.user = flow;
      request.socks5 = &socks;
    }
  } else {
    status = FTUN_E_REJECTED;
  }
  if (status == FTUN_OK) {
    status = ftun_outbound_open(flow->engine->core, &request, &reject,
                                &flow->open_operation);
  }
  if (status == FTUN_OK) {
    flow->proxy_leaf_id = 0u;
    flow->proxy_port = 0u;
    flow->proxy_resolved_count = 0u;
  }
  if (status == FTUN_OK) {
    status = ftun_session_transition(flow->session,
      FTUN_SESSION_CONNECTING, flow->open_operation);
  }
  if (status == FTUN_OK) flow->state = FTUN_ENGINE_FLOW_CONNECTING;
  return status;
}

static int ftun_engine_endpoint_equal(const ftun_endpoint_t *left,
                                      const ftun_endpoint_t *right)
{
  if (left == NULL || right == NULL || left->kind != right->kind ||
      left->port != right->port) return 0;
  if (left->kind == FTUN_ADDRESS_IPV4) {
    return memcmp(left->address, right->address, 4u) == 0;
  }
  return left->kind == FTUN_ADDRESS_DOMAIN && left->domain.data != NULL &&
    right->domain.data != NULL && left->domain.length == right->domain.length &&
    memcmp(left->domain.data, right->domain.data, left->domain.length) == 0;
}

#if defined(FTUN_HAVE_MODULE_TUN)
static void ftun_engine_tun_stream_completed(ftun_operation_t *operation,
                                              ftun_error_t error, void *user)
{
  (void)operation;
  (void)error;
  (void)user;
}

static ftun_status_t ftun_engine_tun_begin(ftun_engine_flow_t *flow,
                                           const ftun_metadata_t *metadata)
{
  ftun_runtime_t *runtime = NULL;
  const ftun_config_t *config = NULL;
  const ftun_config_inbound_t *inbound;
  uint64_t now;
  ftun_status_t status;
  flow->pending_metadata = *metadata;
  status = ftun_engine_restore_fakeip(flow, &flow->pending_metadata);
  if (status != FTUN_OK) return status;
  status = ftun_engine_runtime_for_flow(flow, &runtime, &config);
  inbound = status == FTUN_OK
    ? ftun_engine_inbound_config(config, flow->listener) : NULL;
  if (status == FTUN_OK && inbound == NULL) status = FTUN_E_STALE;
  if (status == FTUN_OK && config->sniff.enable &&
      (flow->pending_metadata.known_fields & FTUN_META_DOMAIN) == 0u) {
    status = ftun_monotonic_now(&now);
    if (status == FTUN_OK) {
      flow->sniff_deadline_ms = now > UINT64_MAX - 200u
        ? UINT64_MAX : now + 200u;
      flow->state = FTUN_ENGINE_FLOW_HANDSHAKE;
    }
  } else if (status == FTUN_OK) {
    status = ftun_engine_session_start_metadata(flow,
                                                &flow->pending_metadata);
  }
  (void)ftun_runtime_release(&runtime);
  return status;
}

static ftun_status_t ftun_engine_tun_sniff(ftun_engine_flow_t *flow,
                                            bool readable)
{
  ftun_runtime_t *runtime = NULL;
  const ftun_config_t *config = NULL;
  ftun_sniff_result_t result;
  ftun_bytes_t bytes;
  uint64_t now;
  bool enabled;
  ftun_status_t status;
  if (readable && flow->preread_length < FTUN_ENGINE_PREREAD_BYTES) {
    size_t received = 0u;
    if (flow->preread_length == flow->preread_capacity) {
      size_t wanted = flow->preread_capacity == 0u
        ? 4096u : flow->preread_capacity * 2u;
      if (wanted > FTUN_ENGINE_PREREAD_BYTES) {
        wanted = FTUN_ENGINE_PREREAD_BYTES;
      }
      status = ftun_engine_preread_ensure(flow, wanted);
      if (status != FTUN_OK) return status;
    }
    status = ftun_stream_read(flow->client,
      flow->preread + flow->preread_length,
      flow->preread_capacity - flow->preread_length, &received);
    if (status == FTUN_OK) flow->preread_length += received;
    else if (status != FTUN_E_AGAIN && status != FTUN_E_EOF) return status;
  }
  status = ftun_monotonic_now(&now);
  if (status != FTUN_OK) return status;
  status = ftun_engine_runtime_for_flow(flow, &runtime, &config);
  if (status != FTUN_OK) return status;
  enabled = flow->preread_length != 0u &&
    ((flow->preread[0] == 22u && config->sniff.tls_sni) ||
     (flow->preread[0] != 22u && config->sniff.http_host));
  memset(&result, 0, sizeof(result));
  bytes.data = flow->preread;
  bytes.length = flow->preread_length;
  status = enabled ? ftun_sniff_domain(&flow->pending_metadata, bytes, &result)
                   : FTUN_OK;
  (void)ftun_runtime_release(&runtime);
  if (status != FTUN_OK) return status;
  if (enabled && result.need_more &&
      flow->preread_length < FTUN_ENGINE_PREREAD_BYTES &&
      now < flow->sniff_deadline_ms) return FTUN_E_AGAIN;
  if (result.found) {
    if (result.domain.length >= sizeof(flow->sniff_domain)) return FTUN_E_LIMIT;
    memcpy(flow->sniff_domain, result.domain.data, result.domain.length);
    flow->sniff_domain[result.domain.length] = '\0';
    flow->pending_metadata.known_fields |= FTUN_META_DOMAIN;
    flow->pending_metadata.domain.data = flow->sniff_domain;
    flow->pending_metadata.domain.length = result.domain.length;
    flow->pending_metadata.domain_source = FTUN_DOMAIN_SNIFF;
  }
  flow->preread_offset = 0u;
  return ftun_engine_session_start_metadata(flow, &flow->pending_metadata);
}

static ftun_status_t ftun_engine_tun_accept(
  void *user, const ftun_metadata_t *metadata, ftun_stream_t *stream)
{
  ftun_engine_t *engine = (ftun_engine_t *)user;
  ftun_engine_flow_t *flow = NULL;
  int dns_pair[2] = {-1, -1};
  bool dns_hijack;
  ftun_status_t status;
  size_t index;
  if (engine == NULL || metadata == NULL || stream == NULL) {
    return FTUN_E_INVALID;
  }
  for (index = 0u; index < FTUN_ENGINE_MAX_TCP_FLOWS; index++) {
    if (!engine->flows[index].active) {
      flow = &engine->flows[index];
      break;
    }
  }
  if (flow == NULL) return FTUN_E_LIMIT;
  memset(flow, 0, sizeof(*flow));
  flow->engine = engine;
  flow->listener = &engine->tun_listener;
  flow->client_socket.descriptor = -1;
  flow->remote_socket.descriptor = -1;
  flow->client = stream;
  flow->tun = true;
  flow->active = true;
  flow->state = FTUN_ENGINE_FLOW_CONNECTING;
  dns_hijack = metadata->original_target.port == 53u &&
    ftun_engine_dns_has_hijack(engine->dns);
  if (dns_hijack) {
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                   dns_pair) != 0) {
      status = ftun_engine_errno_status(errno);
    } else {
      status = ftun_engine_dns_hijack_tcp(engine->dns, dns_pair[1]);
      if (status == FTUN_OK) {
        dns_pair[1] = -1;
        status = ftun_engine_relay_ready(flow, dns_pair[0]);
        if (status == FTUN_OK) dns_pair[0] = -1;
      }
    }
  } else {
    status = ftun_engine_tun_begin(flow, metadata);
  }
  if (status != FTUN_OK) {
    ftun_error_t error;
    if (flow->session != NULL) {
      memset(&error, 0, sizeof(error));
      error.status = status;
      (void)ftun_session_finish(flow->session, error);
      (void)ftun_session_destroy(&flow->session);
    }
    if (ftun_engine_preread_release(flow) != FTUN_OK) {
      status = FTUN_E_STATE_CORRUPT;
    }
    memset(flow, 0, sizeof(*flow));
    flow->client_socket.descriptor = -1;
    flow->remote_socket.descriptor = -1;
  }
  if (dns_pair[0] >= 0) (void)close(dns_pair[0]);
  if (dns_pair[1] >= 0) (void)close(dns_pair[1]);
  return status;
}

static void ftun_engine_tun_stream_event(
  void *user, ftun_stream_t *stream, ftun_tun_stream_event_t event,
  ftun_status_t status)
{
  ftun_engine_t *engine = (ftun_engine_t *)user;
  size_t index;
  if (engine == NULL || stream == NULL) return;
  for (index = 0u; index < FTUN_ENGINE_MAX_TCP_FLOWS; index++) {
    ftun_engine_flow_t *flow = &engine->flows[index];
    if (!flow->active || !flow->tun || flow->client != stream) continue;
    if (event == FTUN_TUN_STREAM_READABLE ||
        event == FTUN_TUN_STREAM_PEER_FIN) {
      flow->left_events |= FTUN_EVENT_READ;
    } else if (event == FTUN_TUN_STREAM_WRITABLE) {
      flow->left_events |= FTUN_EVENT_WRITE;
    } else if (event == FTUN_TUN_STREAM_CLOSED && status != FTUN_OK &&
               status != FTUN_E_EOF) {
      ftun_engine_flow_close(flow, status);
    }
    ftun_engine_flow_schedule(flow);
    return;
  }
}

static ftun_status_t ftun_engine_tun_output(
  void *user, ftun_packet_port_t *port, ftun_bytes_t packet)
{
  ftun_engine_t *engine = (ftun_engine_t *)user;
  ftun_engine_tun_output_t *queued;
  ftun_buffer_t *buffer = NULL;
  uint8_t *data = NULL;
  size_t capacity = 0u;
  size_t index;
  ftun_status_t status;
  if (engine == NULL || port != engine->tun_port) {
    return FTUN_E_STATE_CORRUPT;
  }
  if (packet.data == NULL || packet.length == 0u ||
      packet.length > engine->tun_info.mtu) return FTUN_E_INVALID;
  if (engine->tun_output_count == 0u) {
    status = ftun_packet_port_write(port, packet.data, packet.length);
    if (status != FTUN_E_AGAIN) return status;
  }
  if (engine->tun_output_count >= FTUN_ENGINE_TUN_OUTPUT_CAPACITY) {
    return FTUN_E_LIMIT;
  }
  status = ftun_buffer_pool_acquire(engine->relay_pool, packet.length,
                                    &buffer);
  if (status == FTUN_OK) status = ftun_buffer_data(buffer, &data, &capacity);
  if (status != FTUN_OK || capacity < packet.length) {
    (void)ftun_buffer_release(&buffer);
    return status == FTUN_OK ? FTUN_E_STATE_CORRUPT : status;
  }
  memcpy(data, packet.data, packet.length);
  index = (engine->tun_output_head + engine->tun_output_count) %
          FTUN_ENGINE_TUN_OUTPUT_CAPACITY;
  queued = &engine->tun_output[index];
  queued->buffer = buffer;
  queued->length = packet.length;
  engine->tun_output_count++;
  return FTUN_OK;
}

static ftun_status_t ftun_engine_tun_output_flush(ftun_engine_t *engine)
{
  size_t flushed = 0u;
  while (engine->tun_output_count != 0u &&
         flushed < FTUN_ENGINE_TUN_QUOTA) {
    ftun_engine_tun_output_t *queued =
      &engine->tun_output[engine->tun_output_head];
    uint8_t *data = NULL;
    size_t capacity = 0u;
    ftun_status_t status = ftun_buffer_data(queued->buffer, &data, &capacity);
    if (status != FTUN_OK || queued->length > capacity) {
      return status == FTUN_OK ? FTUN_E_STATE_CORRUPT : status;
    }
    status = ftun_packet_port_write(engine->tun_port, data, queued->length);
    if (status == FTUN_E_AGAIN) return FTUN_OK;
    if (status != FTUN_OK) return status;
    status = ftun_buffer_release(&queued->buffer);
    if (status != FTUN_OK) return status;
    queued->length = 0u;
    engine->tun_output_head = (engine->tun_output_head + 1u) %
                              FTUN_ENGINE_TUN_OUTPUT_CAPACITY;
    engine->tun_output_count--;
    flushed++;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_engine_tun_output_clear(ftun_engine_t *engine)
{
  ftun_status_t result = FTUN_OK;
  while (engine->tun_output_count != 0u) {
    ftun_engine_tun_output_t *queued =
      &engine->tun_output[engine->tun_output_head];
    ftun_status_t status = ftun_buffer_release(&queued->buffer);
    if (status != FTUN_OK && result == FTUN_OK) result = status;
    queued->length = 0u;
    engine->tun_output_head = (engine->tun_output_head + 1u) %
                              FTUN_ENGINE_TUN_OUTPUT_CAPACITY;
    engine->tun_output_count--;
  }
  engine->tun_output_head = 0u;
  return result;
}
#endif

static ftun_status_t ftun_engine_udp_send_wire(
  ftun_engine_udp_slot_t *slot,
  const ftun_endpoint_t *target, const ftun_packet_t *packet)
{
  ftun_bytes_t payload;
  uint8_t wire[UINT16_MAX + 263u];
  const uint8_t *data;
  size_t data_length;
  size_t written = 0u;
  ssize_t length;
  ftun_status_t status;
  if (slot == NULL || !slot->active || slot->destroying ||
      !ftun_engine_endpoint_equal(target, &slot->remote) ||
      ftun_packet_view(packet, &payload) != FTUN_OK) return FTUN_E_INVALID;
  if (!slot->ready) return FTUN_E_AGAIN;
  if (slot->descriptor < 0) return FTUN_E_STATE_CORRUPT;
  data = payload.data;
  data_length = payload.length;
  if (slot->socks5) {
    status = ftun_socks5_connection_encode_udp(slot->proxy_connection,
      payload, wire, sizeof(wire), &written);
    if (status != FTUN_OK) return status;
    data = wire;
    data_length = written;
  }
  do {
    length = send(slot->descriptor, data, data_length, MSG_NOSIGNAL);
  } while (length < 0 && errno == EINTR);
  if (length < 0) return ftun_engine_errno_status(errno);
  if ((size_t)length != data_length) return FTUN_E_IO;
  return FTUN_OK;
}

static ftun_status_t ftun_engine_udp_queue_send(
  ftun_engine_udp_slot_t *slot, ftun_datagram_send_t *send)
{
  ftun_status_t status = FTUN_OK;
  if (slot->pending_count >= sizeof(slot->pending) /
                             sizeof(slot->pending[0])) return FTUN_E_LIMIT;
  slot->pending[slot->pending_count++] = send;
  if (slot->ready && slot->source != NULL) {
    status = ftun_engine_udp_update_source(slot);
    if (status != FTUN_OK) {
      slot->pending[--slot->pending_count] = NULL;
    }
  }
  return status;
}

static ftun_status_t ftun_engine_udp_send_start(
  void *user, ftun_datagram_send_t *datagram_send,
  const ftun_endpoint_t *target, const ftun_packet_t *packet)
{
  ftun_engine_udp_slot_t *slot = (ftun_engine_udp_slot_t *)user;
  ftun_error_t result;
  ftun_status_t status;
  if (slot == NULL || !slot->active || slot->destroying ||
      datagram_send == NULL) return FTUN_E_INVALID;
  if (!slot->ready) {
    if (slot->open_operation == NULL) {
      return slot->open_status == FTUN_OK ? FTUN_E_STATE_CORRUPT
                                          : slot->open_status;
    }
    return ftun_engine_udp_queue_send(slot, datagram_send);
  }
  /* Preserve FIFO order once a packet is blocked.  Returning OK transfers
   * backend ownership to this queue until a writable event retries it. */
  if (slot->pending_count != 0u) {
    return ftun_engine_udp_queue_send(slot, datagram_send);
  }
  status = ftun_engine_udp_send_wire(slot, target, packet);
  if (status == FTUN_E_AGAIN) {
    return ftun_engine_udp_queue_send(slot, datagram_send);
  }
  if (status != FTUN_OK) return status;
  memset(&result, 0, sizeof(result));
  result.status = FTUN_OK;
  return ftun_datagram_send_complete(datagram_send, result);
}

static ftun_status_t ftun_engine_udp_send_cancel(
  void *user, ftun_datagram_send_t *send)
{
  ftun_engine_udp_slot_t *slot = (ftun_engine_udp_slot_t *)user;
  size_t index;
  if (slot == NULL || send == NULL) return FTUN_E_INVALID;
  for (index = 0u; index < slot->pending_count; index++) {
    if (slot->pending[index] == send) {
      size_t remaining = slot->pending_count - index - 1u;
      if (remaining != 0u) {
        memmove(&slot->pending[index], &slot->pending[index + 1u],
                remaining * sizeof(slot->pending[0]));
      }
      slot->pending_count--;
      slot->pending[slot->pending_count] = NULL;
      return slot->ready && slot->source != NULL
        ? ftun_engine_udp_update_source(slot) : FTUN_OK;
    }
  }
  return slot->ready ? FTUN_OK : FTUN_E_STALE;
}

static void ftun_engine_udp_slot_reset(ftun_engine_udp_slot_t *slot)
{
  ftun_engine_udp_unschedule(slot);
  memset(slot, 0, sizeof(*slot));
  slot->descriptor = -1;
}

static ftun_engine_udp_backoff_t *ftun_engine_udp_backoff_entry(
  ftun_engine_t *engine, uint32_t outbound_id, bool create)
{
  ftun_engine_udp_backoff_t *free_entry = NULL;
  size_t index;
  for (index = 0u; index < FTUN_ENGINE_MAX_UDP_FLOWS; index++) {
    ftun_engine_udp_backoff_t *entry = &engine->udp_backoff[index];
    if (entry->active && entry->outbound_id == outbound_id) return entry;
    if (!entry->active && free_entry == NULL) free_entry = entry;
  }
  if (!create || free_entry == NULL) return NULL;
  memset(free_entry, 0, sizeof(*free_entry));
  free_entry->active = true;
  free_entry->outbound_id = outbound_id;
  return free_entry;
}

static bool ftun_engine_udp_backoff_allowed(ftun_engine_t *engine,
                                            uint32_t outbound_id)
{
  ftun_engine_udp_backoff_t *entry =
    ftun_engine_udp_backoff_entry(engine, outbound_id, false);
  uint64_t now_ms;
  if (entry == NULL || entry->failures == 0u) return true;
  if (ftun_monotonic_now(&now_ms) != FTUN_OK) return false;
  return now_ms >= entry->retry_after_ms;
}

static void ftun_engine_udp_backoff_failed(ftun_engine_t *engine,
                                           uint32_t outbound_id)
{
  ftun_engine_udp_backoff_t *entry =
    ftun_engine_udp_backoff_entry(engine, outbound_id, true);
  uint64_t delay = FTUN_ENGINE_UDP_RECONNECT_BACKOFF_MIN_MS;
  uint64_t now_ms;
  uint32_t shift;
  if (entry == NULL || ftun_monotonic_now(&now_ms) != FTUN_OK) return;
  if (entry->failures != UINT32_MAX) entry->failures++;
  shift = entry->failures > 1u ? entry->failures - 1u : 0u;
  while (shift-- != 0u &&
         delay < FTUN_ENGINE_UDP_RECONNECT_BACKOFF_MAX_MS) {
    delay = delay > FTUN_ENGINE_UDP_RECONNECT_BACKOFF_MAX_MS / 2u
      ? FTUN_ENGINE_UDP_RECONNECT_BACKOFF_MAX_MS : delay * 2u;
  }
  if (delay > FTUN_ENGINE_UDP_RECONNECT_BACKOFF_MAX_MS) {
    delay = FTUN_ENGINE_UDP_RECONNECT_BACKOFF_MAX_MS;
  }
  entry->retry_after_ms = now_ms > UINT64_MAX - delay
    ? UINT64_MAX : now_ms + delay;
}

static void ftun_engine_udp_backoff_succeeded(ftun_engine_t *engine,
                                              uint32_t outbound_id)
{
  ftun_engine_udp_backoff_t *entry =
    ftun_engine_udp_backoff_entry(engine, outbound_id, false);
  if (entry != NULL) memset(entry, 0, sizeof(*entry));
}

static ftun_status_t ftun_engine_udp_watch(ftun_engine_udp_slot_t *slot)
{
  if (slot == NULL || slot->engine == NULL || slot->descriptor < 0 ||
      slot->source != NULL) return FTUN_E_INVALID;
  return ftun_event_io_start(slot->engine->loop,
    (ftun_native_socket_t)(unsigned int)slot->descriptor,
    FTUN_EVENT_READ | FTUN_EVENT_ERROR, ftun_engine_udp_ready, slot,
    &slot->source);
}

static void ftun_engine_udp_destroy(void *user)
{
  ftun_engine_udp_slot_t *slot = (ftun_engine_udp_slot_t *)user;
  if (slot == NULL) return;
  slot->channel = NULL;
  slot->destroying = true;
  if (slot->open_operation != NULL) {
    (void)ftun_operation_cancel(slot->open_operation);
    return;
  }
  (void)ftun_event_source_cancel(&slot->source);
  (void)ftun_event_source_cancel(&slot->control_source);
  if (slot->socks5) {
    (void)ftun_socks5_connection_close(&slot->proxy_connection);
  } else if (slot->descriptor >= 0) {
    (void)close(slot->descriptor);
  }
  ftun_engine_udp_slot_reset(slot);
}

static void ftun_engine_udp_finish_pending(ftun_engine_udp_slot_t *slot,
                                            ftun_status_t status)
{
  while (slot->pending_count != 0u) {
    ftun_datagram_send_t *send = slot->pending[0];
    const ftun_endpoint_t *target = NULL;
    const ftun_packet_t *packet = NULL;
    ftun_error_t error;
    if (status == FTUN_OK) {
      status = ftun_datagram_send_view(send, &target, &packet);
      if (status == FTUN_OK) {
        status = ftun_engine_udp_send_wire(slot, target, packet);
      }
      if (status == FTUN_E_AGAIN) {
        (void)ftun_engine_udp_update_source(slot);
        return;
      }
    }
    {
      size_t remaining = --slot->pending_count;
      if (remaining != 0u) {
        memmove(&slot->pending[0], &slot->pending[1],
                remaining * sizeof(slot->pending[0]));
      }
      slot->pending[remaining] = NULL;
    }
    memset(&error, 0, sizeof(error));
    error.status = status;
    (void)ftun_datagram_send_complete(send, error);
  }
  if (slot->ready && slot->source != NULL) {
    (void)ftun_engine_udp_update_source(slot);
  }
}

static void ftun_engine_udp_socks_completed(
  ftun_operation_t *operation, ftun_error_t error,
  ftun_socks5_connection_t *connection, void *user);

static void ftun_engine_udp_direct_completed(
  ftun_operation_t *operation, ftun_error_t error,
  const ftun_dial_result_t *result, void *user)
{
  ftun_engine_udp_slot_t *slot = (ftun_engine_udp_slot_t *)user;
  ftun_native_socket_t socket = result == NULL
    ? FTUN_INVALID_SOCKET : result->socket;
  ftun_status_t status = error.status;
  if (slot == NULL || !slot->active || slot->open_operation != operation) {
    if (socket != FTUN_INVALID_SOCKET && socket <= (ftun_native_socket_t)INT_MAX) {
      (void)close((int)socket);
    }
    return;
  }
  slot->open_operation = NULL;
  if (slot->destroying) {
    if (socket != FTUN_INVALID_SOCKET && socket <= (ftun_native_socket_t)INT_MAX) {
      (void)close((int)socket);
    }
    ftun_engine_udp_slot_reset(slot);
    return;
  }
  if (status == FTUN_OK && (result == NULL ||
      socket == FTUN_INVALID_SOCKET || socket > (ftun_native_socket_t)INT_MAX)) {
    status = FTUN_E_STATE_CORRUPT;
  }
  if (status == FTUN_OK) {
    slot->descriptor = (int)socket;
    status = ftun_engine_udp_watch(slot);
    if (status == FTUN_OK) slot->ready = true;
  } else if (socket != FTUN_INVALID_SOCKET &&
             socket <= (ftun_native_socket_t)INT_MAX) {
    (void)close((int)socket);
  }
  slot->open_status = status;
  ftun_engine_udp_finish_pending(slot, status);
}

static ftun_status_t ftun_engine_udp_socks_start(
  ftun_engine_udp_slot_t *slot)
{
  ftun_socks5_proxy_t proxy;
  ftun_socks5_connect_request_t socks;
  ftun_status_t status;
  if (slot == NULL || slot->engine == NULL || !slot->active ||
      slot->open_operation != NULL) return FTUN_E_INVALID;
  memset(&proxy, 0, sizeof(proxy));
  proxy.server = slot->proxy_server;
  if (proxy.server.kind == FTUN_ADDRESS_DOMAIN) {
    proxy.resolved = slot->proxy_resolved;
    proxy.resolved_count = slot->proxy_resolved_count;
  }
  proxy.username.data = slot->proxy_username_length == 0u
    ? NULL : slot->proxy_username;
  proxy.username.length = slot->proxy_username_length;
  proxy.password.data = slot->proxy_password_length == 0u
    ? NULL : slot->proxy_password;
  proxy.password.length = slot->proxy_password_length;
  proxy.udp_enabled = true;
  memset(&socks, 0, sizeof(socks));
  socks.loop = slot->engine->loop;
  socks.operations = slot->engine->operations;
  socks.budget = slot->engine->budget;
  socks.proxy = &proxy;
  socks.target = &slot->socks_target;
  socks.protection.mark = slot->engine->socket_mark;
  status = ftun_monotonic_now(&socks.deadline_ms);
  if (status == FTUN_OK && socks.deadline_ms <=
      UINT64_MAX - FTUN_ENGINE_CONNECT_TIMEOUT_MS) {
    socks.deadline_ms += FTUN_ENGINE_CONNECT_TIMEOUT_MS;
  } else if (status == FTUN_OK) {
    status = FTUN_E_LIMIT;
  }
  socks.transport = FTUN_DIAL_UDP;
  socks.completion = ftun_engine_udp_socks_completed;
  socks.user = slot;
  if (status == FTUN_OK) {
    status = ftun_socks5_connect(slot->engine->core, &socks,
                                 &slot->open_operation);
  }
  return status;
}

static void ftun_engine_udp_proxy_resolved(
  ftun_operation_t *operation, ftun_error_t error,
  const ftun_system_resolve_result_t *result, void *user)
{
  ftun_engine_udp_slot_t *slot = (ftun_engine_udp_slot_t *)user;
  ftun_status_t status = error.status;
  size_t index;
  if (slot == NULL || !slot->active || slot->open_operation != operation) {
    return;
  }
  slot->open_operation = NULL;
  if (slot->destroying) {
    ftun_engine_udp_slot_reset(slot);
    return;
  }
  if (status == FTUN_OK && (result == NULL || result->address_count == 0u ||
      result->address_count > FTUN_SESSION_MAX_RESOLVED_IPV4)) {
    status = FTUN_E_STATE_CORRUPT;
  }
  for (index = 0u; status == FTUN_OK && index < result->address_count;
       index++) {
    if (result->addresses[index].kind != FTUN_ADDRESS_IPV4) {
      status = FTUN_E_UNSUPPORTED;
      break;
    }
    slot->proxy_resolved[index] = result->addresses[index];
    slot->proxy_resolved[index].port = slot->proxy_server.port;
    slot->proxy_resolved[index].domain.data = NULL;
    slot->proxy_resolved[index].domain.length = 0u;
  }
  if (status == FTUN_OK) {
    slot->proxy_resolved_count = result->address_count;
    status = ftun_engine_udp_socks_start(slot);
  }
  if (status != FTUN_OK) {
    ftun_engine_udp_backoff_failed(slot->engine, slot->outbound_id);
    slot->open_status = status;
    ftun_engine_udp_finish_pending(slot, status);
  }
}

static void ftun_engine_udp_socks_completed(
  ftun_operation_t *operation, ftun_error_t error,
  ftun_socks5_connection_t *connection, void *user)
{
  ftun_engine_udp_slot_t *slot = (ftun_engine_udp_slot_t *)user;
  ftun_socks5_connection_info_t info;
  ftun_status_t status = error.status;
  if (slot == NULL || !slot->active || slot->open_operation != operation) {
    (void)ftun_socks5_connection_close(&connection);
    return;
  }
  slot->open_operation = NULL;
  if (slot->destroying) {
    (void)ftun_socks5_connection_close(&connection);
    ftun_engine_udp_slot_reset(slot);
    return;
  }
  if (status == FTUN_OK && connection == NULL) status = FTUN_E_STATE_CORRUPT;
  if (status == FTUN_OK) {
    status = ftun_socks5_connection_get_info(connection, &info);
  }
  if (status == FTUN_OK && (info.transport != FTUN_DIAL_UDP ||
      info.data_socket == FTUN_INVALID_SOCKET ||
      info.data_socket > (ftun_native_socket_t)INT_MAX)) {
    status = FTUN_E_STATE_CORRUPT;
  }
  if (status == FTUN_OK) {
    slot->proxy_connection = connection;
    slot->descriptor = (int)info.data_socket;
    status = ftun_engine_udp_watch(slot);
    if (status == FTUN_OK && (info.control_socket == FTUN_INVALID_SOCKET ||
        info.control_socket > (ftun_native_socket_t)INT_MAX ||
        info.control_socket == info.data_socket)) {
      status = FTUN_E_STATE_CORRUPT;
    }
    if (status == FTUN_OK) {
      status = ftun_event_io_start(slot->engine->loop, info.control_socket,
        FTUN_EVENT_READ | FTUN_EVENT_ERROR, ftun_engine_udp_control_ready,
        slot, &slot->control_source);
    }
    if (status == FTUN_OK) {
      slot->ready = true;
    }
  } else {
    (void)ftun_event_source_cancel(&slot->source);
    (void)ftun_event_source_cancel(&slot->control_source);
    if (slot->proxy_connection == connection) {
      (void)ftun_socks5_connection_close(&slot->proxy_connection);
    } else {
      (void)ftun_socks5_connection_close(&connection);
    }
  }
  slot->open_status = status;
  if (status != FTUN_OK) {
    ftun_engine_udp_backoff_failed(slot->engine, slot->outbound_id);
  }
  ftun_engine_udp_finish_pending(slot, status);
}

static ftun_status_t ftun_engine_udp_socks_prepare(
  ftun_engine_udp_slot_t *slot, const ftun_target_t *target,
  const ftun_config_outbound_t *config, const ftun_endpoint_t *server)
{
  size_t length;
  if (slot == NULL || target == NULL || config == NULL || server == NULL ||
      target->candidate_count > FTUN_SESSION_MAX_RESOLVED_IPV4 ||
      target->allowed_count > FTUN_SESSION_MAX_RESOLVED_IPV4 ||
      (target->candidate_count != 0u && target->candidates == NULL) ||
      (target->allowed_count != 0u && target->allowed == NULL)) {
    return FTUN_E_INVALID;
  }
  slot->socks_target = *target;
  if (target->candidate_count != 0u) {
    memcpy(slot->target_candidates, target->candidates,
      target->candidate_count * sizeof(slot->target_candidates[0]));
    slot->socks_target.candidates = slot->target_candidates;
  }
  if (target->allowed_count != 0u) {
    memcpy(slot->target_allowed, target->allowed,
      target->allowed_count * sizeof(slot->target_allowed[0]));
    slot->socks_target.allowed = slot->target_allowed;
  }
  if (target->identity.length != 0u) {
    if (target->identity.data == NULL ||
        target->identity.length >= sizeof(slot->target_domain)) {
      return FTUN_E_LIMIT;
    }
    memcpy(slot->target_domain, target->identity.data,
           target->identity.length);
    slot->target_domain[target->identity.length] = '\0';
    slot->socks_target.identity.data = slot->target_domain;
    if (slot->socks_target.original.kind == FTUN_ADDRESS_DOMAIN) {
      slot->socks_target.original.domain.data = slot->target_domain;
    }
  }
  slot->proxy_server = *server;
  if (server->kind == FTUN_ADDRESS_DOMAIN) {
    if (server->domain.data == NULL || server->domain.length == 0u ||
        server->domain.length >= sizeof(slot->proxy_domain)) {
      return FTUN_E_INVALID;
    }
    memcpy(slot->proxy_domain, server->domain.data, server->domain.length);
    slot->proxy_domain[server->domain.length] = '\0';
    slot->proxy_server.domain.data = slot->proxy_domain;
  }
  if (config->username != NULL) {
    size_t password_length;
    length = strlen(config->username);
    password_length = config->password == NULL
      ? 0u : strlen(config->password);
    if (length > sizeof(slot->proxy_username) || password_length == 0u ||
        password_length > sizeof(slot->proxy_password)) return FTUN_E_INVALID;
    memcpy(slot->proxy_username, config->username, length);
    memcpy(slot->proxy_password, config->password, password_length);
    slot->proxy_username_length = length;
    slot->proxy_password_length = password_length;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_engine_udp_open(
  void *user, ftun_core_t *core, const ftun_runtime_t *runtime,
  const ftun_metadata_t *metadata, const ftun_route_result_t *prepared_route,
  ftun_datagram_result_fn result,
  ftun_datagram_receive_fn receive, void *callback_user,
  uint32_t *outbound_id, ftun_endpoint_t *remote, ftun_datagram_t **out)
{
  ftun_engine_t *engine = (ftun_engine_t *)user;
  const ftun_config_t *config = NULL;
  const ftun_config_inbound_t *inbound;
  const ftun_config_outbound_t *proxy_config = NULL;
  ftun_route_result_t route;
  ftun_target_t target;
  ftun_outbound_leaf_t leaf;
  ftun_outbound_request_t request;
  ftun_direct_request_t direct;
  ftun_endpoint_t proxy_server;
  ftun_reject_result_t reject;
  ftun_engine_udp_slot_t *slot = NULL;
  ftun_datagram_options_t options;
  ftun_datagram_backend_t backend;
  ftun_status_t status;
  uint32_t forced = 0u;
  bool has_forced = false;
  size_t index;
  if (out != NULL) *out = NULL;
  if (engine == NULL || core != engine->core || runtime == NULL ||
      metadata == NULL || result == NULL || receive == NULL ||
      outbound_id == NULL || remote == NULL || out == NULL) {
    return FTUN_E_INVALID;
  }
  for (index = 0u; index < FTUN_ENGINE_MAX_UDP_FLOWS; index++) {
    if (!engine->udp[index].active) {
      slot = &engine->udp[index];
      break;
    }
  }
  if (slot == NULL) return FTUN_E_LIMIT;
  status = ftun_runtime_config(runtime, &config);
  inbound = status == FTUN_OK
    ? ftun_engine_inbound_by_id(config, metadata->inbound_id) : NULL;
  if (status == FTUN_OK && inbound == NULL) status = FTUN_E_STALE;
  if (status == FTUN_OK && inbound->outbound != NULL &&
      inbound->outbound[0] != '\0') {
    has_forced = true;
    status = ftun_runtime_resolve_outbound_name(runtime,
      (ftun_string_t){inbound->outbound, strlen(inbound->outbound)}, &forced);
  }
  memset(&route, 0, sizeof(route));
  if (status == FTUN_OK && prepared_route != NULL) {
    route = *prepared_route;
    if (prepared_route->allowed_count != 0u) {
      if (prepared_route->allowed_count > FTUN_ROUTE_MAX_CANDIDATES) {
        status = FTUN_E_LIMIT;
      } else {
        memcpy(route.allowed_storage, prepared_route->allowed,
          prepared_route->allowed_count * sizeof(route.allowed_storage[0]));
        route.allowed = route.allowed_storage;
      }
    }
  } else if (status == FTUN_OK && has_forced) {
    route.kind = forced == FTUN_OUTBOUND_ID_REJECT
      ? FTUN_ROUTE_DENY : FTUN_ROUTE_READY;
    route.generation = metadata->generation;
    route.outbound_id = forced;
    if (metadata->original_target.kind == FTUN_ADDRESS_IPV4 &&
        !metadata->original_is_fake) {
      route.allowed = &metadata->original_target;
      route.allowed_count = 1u;
    } else {
      route.allowed = metadata->resolved;
      route.allowed_count = metadata->resolved_count;
    }
  } else if (status == FTUN_OK) {
    status = ftun_route_evaluate(runtime, metadata, 0u, &route);
  }
  if (status == FTUN_OK && route.kind == FTUN_ROUTE_DENY) {
    status = FTUN_E_REJECTED;
  } else if (status == FTUN_OK && route.kind != FTUN_ROUTE_READY) {
    status = FTUN_E_RESOLVE;
  }
  if (status == FTUN_OK) {
    status = ftun_engine_leaf(engine, runtime, config, route.outbound_id,
                              route.generation, &leaf, &proxy_config);
  }
  if (status == FTUN_OK && (leaf.kind == FTUN_OUTBOUND_LEAF_REJECT ||
      (leaf.kind == FTUN_OUTBOUND_LEAF_SOCKS5 && !leaf.supports_udp))) {
    status = FTUN_E_REJECTED;
  } else if (status == FTUN_OK && leaf.kind != FTUN_OUTBOUND_LEAF_DIRECT &&
             leaf.kind != FTUN_OUTBOUND_LEAF_SOCKS5) {
    status = FTUN_E_UNSUPPORTED;
  }
  if (status == FTUN_OK && leaf.kind == FTUN_OUTBOUND_LEAF_SOCKS5 &&
      !ftun_engine_udp_backoff_allowed(engine, leaf.id)) {
    status = FTUN_E_AGAIN;
  }
  if (status == FTUN_OK) {
    route.outbound_id = leaf.id;
    status = ftun_target_from_metadata(metadata, &target);
  }
  if (status == FTUN_OK) status = ftun_target_apply_route(&target, &route);
  if (status == FTUN_OK && target.allowed_count == 0u &&
      leaf.kind == FTUN_OUTBOUND_LEAF_DIRECT) {
    status = FTUN_E_REJECTED;
  }
  if (status != FTUN_OK) return status;

  ftun_engine_udp_slot_reset(slot);
  slot->engine = engine;
  if (target.allowed_count != 0u) {
    slot->remote = target.allowed[0];
  } else {
    slot->remote.kind = FTUN_ADDRESS_DOMAIN;
    slot->remote.domain = target.identity;
    slot->remote.port = target.original.port;
  }
  slot->socks5 = leaf.kind == FTUN_OUTBOUND_LEAF_SOCKS5;
  slot->outbound_id = leaf.id;
  slot->open_status = FTUN_E_AGAIN;
  slot->active = true;
  memset(&options, 0, sizeof(options));
  options.budget = engine->budget;
  options.max_pending_packets = 32u;
  options.max_pending_bytes = 256u * 1024u;
  options.result = result;
  options.receive = receive;
  options.user = callback_user;
  memset(&backend, 0, sizeof(backend));
  backend.send_start = ftun_engine_udp_send_start;
  backend.send_cancel = ftun_engine_udp_send_cancel;
  backend.destroy = ftun_engine_udp_destroy;
  backend.context = slot;
  status = ftun_datagram_create(&options, &backend, &slot->channel);
  if (status != FTUN_OK) {
    ftun_engine_udp_slot_reset(slot);
    return status;
  }

  memset(&direct, 0, sizeof(direct));
  memset(&request, 0, sizeof(request));
  request.route = &route;
  request.target = &target;
  request.leaf = &leaf;
  request.transport = FTUN_DIAL_UDP;
  if (leaf.kind == FTUN_OUTBOUND_LEAF_DIRECT) {
    direct.loop = engine->loop;
    direct.operations = engine->operations;
    direct.budget = engine->budget;
    direct.protection.mark = engine->socket_mark;
    status = ftun_monotonic_now(&direct.deadline_ms);
    if (status == FTUN_OK && direct.deadline_ms <=
        UINT64_MAX - FTUN_ENGINE_CONNECT_TIMEOUT_MS) {
      direct.deadline_ms += FTUN_ENGINE_CONNECT_TIMEOUT_MS;
    } else if (status == FTUN_OK) {
      status = FTUN_E_LIMIT;
    }
    direct.transport = FTUN_DIAL_UDP;
    direct.completion = ftun_engine_udp_direct_completed;
    direct.user = slot;
    request.direct = &direct;
    if (status == FTUN_OK) {
      status = ftun_outbound_open(core, &request, &reject,
                                  &slot->open_operation);
    }
  } else {
    status = ftun_engine_parse_ipv4_endpoint(proxy_config->server,
                                              &proxy_server);
    if (status != FTUN_OK) {
      const char *colon = strrchr(proxy_config->server, ':');
      if (colon != NULL && colon != proxy_config->server) {
        size_t domain_length = (size_t)(colon - proxy_config->server);
        char *tail = NULL;
        unsigned long port = strtoul(colon + 1u, &tail, 10);
        if (domain_length <= 253u && tail != colon + 1u && *tail == '\0' &&
            port != 0u && port <= UINT16_MAX) {
          memset(&proxy_server, 0, sizeof(proxy_server));
          proxy_server.kind = FTUN_ADDRESS_DOMAIN;
          proxy_server.domain.data = proxy_config->server;
          proxy_server.domain.length = domain_length;
          proxy_server.port = (uint16_t)port;
          status = FTUN_OK;
        }
      }
    }
    if (status == FTUN_OK) {
      status = ftun_engine_udp_socks_prepare(slot, &target, proxy_config,
                                             &proxy_server);
    }
    if (status == FTUN_OK && proxy_server.kind == FTUN_ADDRESS_DOMAIN) {
      status = ftun_engine_resolve_async(engine, config,
        slot->proxy_server.domain, true, ftun_engine_udp_proxy_resolved, slot,
        &slot->open_operation);
    } else if (status == FTUN_OK) {
      status = ftun_engine_udp_socks_start(slot);
    }
  }
  if (status != FTUN_OK) {
    (void)ftun_datagram_stop(slot->channel);
    (void)ftun_datagram_destroy(&slot->channel);
    return status;
  }
  *outbound_id = leaf.id;
  *remote = slot->remote;
  *out = slot->channel;
  return FTUN_OK;
}

static void ftun_engine_udp_pending_release(
  ftun_engine_udp_pending_t *pending)
{
  if (pending == NULL) return;
  (void)ftun_packet_release(&pending->packet);
  (void)ftun_runtime_release(&pending->runtime);
  memset(pending, 0, sizeof(*pending));
}

static void ftun_engine_udp_pending_cancel_inbound(
  ftun_engine_t *engine, ftun_datagram_t *inbound)
{
  size_t index;
  if (engine == NULL || inbound == NULL) return;
  for (index = 0u; index < FTUN_ENGINE_MAX_UDP_FLOWS; index++) {
    ftun_engine_udp_pending_t *pending = &engine->udp_pending[index];
    if (pending->active && pending->inbound == inbound &&
        pending->operation != NULL) {
      (void)ftun_operation_cancel(pending->operation);
    }
  }
}

static void ftun_engine_udp_pending_cancel_all(ftun_engine_t *engine)
{
  size_t index;
  if (engine == NULL) return;
  for (index = 0u; index < FTUN_ENGINE_MAX_UDP_FLOWS; index++) {
    ftun_engine_udp_pending_t *pending = &engine->udp_pending[index];
    if (pending->active && pending->operation != NULL) {
      (void)ftun_operation_cancel(pending->operation);
    }
  }
}

static ftun_status_t ftun_engine_udp_route_own(
  ftun_route_result_t *route)
{
  if (route == NULL || route->allowed_count > FTUN_ROUTE_MAX_CANDIDATES ||
      (route->allowed_count != 0u && route->allowed == NULL)) {
    return FTUN_E_INVALID;
  }
  if (route->allowed_count != 0u && route->allowed != route->allowed_storage) {
    memcpy(route->allowed_storage, route->allowed,
      route->allowed_count * sizeof(route->allowed_storage[0]));
    route->allowed = route->allowed_storage;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_engine_resolve_async(
  ftun_engine_t *engine, const ftun_config_t *config,
  ftun_string_t domain, bool bootstrap_only,
  ftun_system_resolve_completion_fn completion, void *user,
  ftun_operation_t **out)
{
  ftun_bootstrap_request_t query;
  ftun_system_resolve_request_t system;
  ftun_endpoint_t bootstrap[FTUN_BOOTSTRAP_MAX_SERVERS];
  ftun_string_t server = {NULL, 0u};
  size_t index;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (engine == NULL || config == NULL || domain.data == NULL ||
      domain.length == 0u || completion == NULL || out == NULL) {
    return FTUN_E_INVALID;
  }
  memset(&query, 0, sizeof(query));
  query.loop = engine->loop;
  query.operations = engine->operations;
  query.worker = engine->worker;
  query.budget = engine->budget;
  query.domain = domain;
  query.protection.mark = engine->socket_mark;
  query.check_system_path = ftun_engine_system_resolver_path;
  query.system_path_user = engine;
  query.completion = completion;
  query.user = user;
  status = ftun_monotonic_now(&query.deadline_ms);
  if (status == FTUN_OK && query.deadline_ms <=
      UINT64_MAX - FTUN_ENGINE_CONNECT_TIMEOUT_MS) {
    query.deadline_ms += FTUN_ENGINE_CONNECT_TIMEOUT_MS;
  } else if (status == FTUN_OK) {
    status = FTUN_E_LIMIT;
  }
  engine->next_dns_query_id++;
  if (engine->next_dns_query_id == 0u) engine->next_dns_query_id++;
  query.query_id = engine->next_dns_query_id;
  for (index = 0u; status == FTUN_OK &&
       index < config->dns.bootstrap.count; index++) {
    const char *text = config->dns.bootstrap.items[index];
    const char *colon = strrchr(text, ':');
    char endpoint[INET_ADDRSTRLEN + 7u];
    if (colon == NULL) {
      int length = snprintf(endpoint, sizeof(endpoint), "%s:53", text);
      if (length <= 0 || (size_t)length >= sizeof(endpoint)) {
        status = FTUN_E_LIMIT;
      } else {
        status = ftun_engine_parse_ipv4_endpoint(endpoint, &bootstrap[index]);
      }
    } else {
      status = ftun_engine_parse_ipv4_endpoint(text, &bootstrap[index]);
    }
  }
  if (status != FTUN_OK) return status;
  query.servers = bootstrap;
  query.server_count = config->dns.bootstrap.count;
  if (!config->dns.enable) {
    memset(&system, 0, sizeof(system));
    system.worker = engine->worker;
    system.budget = engine->budget;
    system.domain = domain;
    system.protection = query.protection;
    system.deadline_ms = query.deadline_ms;
    system.check_path = query.check_system_path;
    system.path_user = query.system_path_user;
    system.completion = completion;
    system.user = user;
    return ftun_system_resolve(engine->core, &system, out);
  }
  if (!bootstrap_only && config->dns.default_server != NULL &&
      config->dns.default_server[0] != '\0') {
    server.data = config->dns.default_server;
    server.length = strlen(config->dns.default_server);
    return ftun_dns_resolve_named(engine->core, server, &query, out);
  }
  return ftun_bootstrap_resolve(engine->core, &query, out);
}

static ftun_status_t ftun_engine_udp_finish_route(
  ftun_engine_udp_pending_t *pending, bool after_resolution)
{
  const ftun_config_t *config = NULL;
  const ftun_config_inbound_t *inbound;
  const ftun_config_outbound_t *proxy_config = NULL;
  ftun_outbound_leaf_t leaf;
  ftun_status_t status;
  uint32_t forced = 0u;
  bool has_forced = false;
  status = ftun_runtime_config(pending->runtime, &config);
  inbound = status == FTUN_OK
    ? ftun_engine_inbound_by_id(config, pending->metadata.inbound_id) : NULL;
  if (status == FTUN_OK && inbound == NULL) status = FTUN_E_STALE;
  if (status == FTUN_OK && !after_resolution &&
      inbound->outbound != NULL && inbound->outbound[0] != '\0') {
    has_forced = true;
    status = ftun_runtime_resolve_outbound_name(pending->runtime,
      (ftun_string_t){inbound->outbound, strlen(inbound->outbound)}, &forced);
  }
  if (status == FTUN_OK && after_resolution && pending->preserve_route) {
    size_t index;
    pending->route.allowed_count = pending->metadata.resolved_count;
    for (index = 0u; index < pending->route.allowed_count; index++) {
      pending->route.allowed_storage[index] = pending->resolved[index];
    }
    pending->route.allowed = pending->route.allowed_count == 0u
      ? NULL : pending->route.allowed_storage;
  } else if (status == FTUN_OK && has_forced) {
    memset(&pending->route, 0, sizeof(pending->route));
    pending->route.kind = forced == FTUN_OUTBOUND_ID_REJECT
      ? FTUN_ROUTE_DENY : FTUN_ROUTE_READY;
    pending->route.generation = pending->metadata.generation;
    pending->route.outbound_id = forced;
    if (pending->metadata.original_target.kind == FTUN_ADDRESS_IPV4 &&
        !pending->metadata.original_is_fake) {
      pending->route.allowed = &pending->metadata.original_target;
      pending->route.allowed_count = 1u;
    } else {
      pending->route.allowed = pending->metadata.resolved;
      pending->route.allowed_count = pending->metadata.resolved_count;
    }
  } else if (status == FTUN_OK) {
    status = ftun_route_evaluate(pending->runtime, &pending->metadata,
      after_resolution ? pending->resume_rule : 0u, &pending->route);
  }
  if (status == FTUN_OK && pending->route.kind == FTUN_ROUTE_NEED_RESOLVE) {
    pending->resume_rule = pending->route.resume_rule;
    return FTUN_E_RESOLVE;
  }
  if (status == FTUN_OK && pending->route.kind == FTUN_ROUTE_DENY) {
    status = FTUN_E_REJECTED;
  } else if (status == FTUN_OK && pending->route.kind != FTUN_ROUTE_READY) {
    status = FTUN_E_STATE_CORRUPT;
  }
  if (status == FTUN_OK) status = ftun_engine_udp_route_own(&pending->route);
  if (status == FTUN_OK) {
    status = ftun_engine_leaf(pending->engine, pending->runtime, config,
      pending->route.outbound_id, pending->route.generation, &leaf,
      &proxy_config);
  }
  (void)proxy_config;
  if (status == FTUN_OK && (leaf.kind == FTUN_OUTBOUND_LEAF_REJECT ||
      (leaf.kind == FTUN_OUTBOUND_LEAF_SOCKS5 && !leaf.supports_udp))) {
    status = FTUN_E_REJECTED;
  }
  if (status == FTUN_OK) pending->route.outbound_id = leaf.id;
  if (status == FTUN_OK && leaf.kind == FTUN_OUTBOUND_LEAF_DIRECT &&
      pending->route.allowed_count == 0u) {
    if (after_resolution) return FTUN_E_RESOLVE;
    pending->preserve_route = true;
    return FTUN_E_RESOLVE;
  }
  if (status == FTUN_OK) {
    status = ftun_udp_flow_input_routed(pending->engine->udp_flows,
      pending->inbound, &pending->metadata, &pending->route,
      &pending->packet);
  }
  return status;
}

static void ftun_engine_udp_resolved(
  ftun_operation_t *operation, ftun_error_t error,
  const ftun_system_resolve_result_t *result, void *user)
{
  ftun_engine_udp_pending_t *pending =
    (ftun_engine_udp_pending_t *)user;
  ftun_status_t status = error.status;
  size_t index;
  if (pending == NULL || !pending->active ||
      pending->operation != operation) return;
  pending->operation = NULL;
  if (status == FTUN_OK && (result == NULL || result->address_count == 0u ||
      result->address_count > FTUN_UDP_FLOW_MAX_RESOLVED_IPV4)) {
    status = FTUN_E_STATE_CORRUPT;
  }
  for (index = 0u; status == FTUN_OK && index < result->address_count;
       index++) {
    if (result->addresses[index].kind != FTUN_ADDRESS_IPV4) {
      status = FTUN_E_UNSUPPORTED;
      break;
    }
    pending->resolved[index] = result->addresses[index];
    pending->resolved[index].port = pending->metadata.original_target.port;
    pending->resolved[index].domain.data = NULL;
    pending->resolved[index].domain.length = 0u;
  }
  if (status == FTUN_OK) {
    pending->metadata.resolved = pending->resolved;
    pending->metadata.resolved_count = result->address_count;
    status = ftun_engine_udp_finish_route(pending, true);
  }
  ftun_engine_udp_pending_release(pending);
}

static ftun_status_t ftun_engine_udp_route_datagram(
  ftun_engine_t *engine, ftun_datagram_t *inbound,
  const ftun_metadata_t *metadata, const ftun_packet_t *packet)
{
  ftun_engine_udp_pending_t *pending = NULL;
  ftun_metadata_t restored;
  ftun_runtime_info_t info;
  const ftun_config_t *config = NULL;
  char restored_domain[254];
  bool found = false;
  ftun_status_t status;
  size_t index;
  if (engine == NULL || inbound == NULL || metadata == NULL || packet == NULL) {
    return FTUN_E_INVALID;
  }
  restored = *metadata;
  if ((metadata->known_fields & FTUN_META_DOMAIN) != 0u) {
    if (metadata->domain.data == NULL || metadata->domain.length == 0u ||
        metadata->domain.length >= sizeof(restored_domain)) {
      return FTUN_E_INVALID;
    }
    memcpy(restored_domain, metadata->domain.data, metadata->domain.length);
    restored_domain[metadata->domain.length] = '\0';
    restored.domain.data = restored_domain;
    if (metadata->original_target.kind == FTUN_ADDRESS_DOMAIN) {
      restored.original_target.domain.data = restored_domain;
    }
  }
  status = ftun_engine_restore_fakeip_to(engine, &restored,
    restored_domain, sizeof(restored_domain));
  if (status != FTUN_OK) return status;
  status = ftun_udp_flow_input_existing(engine->udp_flows, inbound, &restored,
    (ftun_packet_t *)packet, &found);
  if (status != FTUN_OK || found) return status;

  for (index = 0u; index < FTUN_ENGINE_MAX_UDP_FLOWS; index++) {
    if (!engine->udp_pending[index].active) {
      pending = &engine->udp_pending[index];
      break;
    }
  }
  if (pending == NULL) return FTUN_E_LIMIT;
  memset(pending, 0, sizeof(*pending));
  pending->engine = engine;
  pending->inbound = inbound;
  pending->metadata = restored;
  if ((restored.known_fields & FTUN_META_DOMAIN) != 0u) {
    if (restored.domain.data == NULL || restored.domain.length == 0u ||
        restored.domain.length >= sizeof(pending->domain)) {
      return FTUN_E_INVALID;
    }
    memcpy(pending->domain, restored.domain.data, restored.domain.length);
    pending->domain[restored.domain.length] = '\0';
    pending->metadata.domain.data = pending->domain;
    if (restored.original_target.kind == FTUN_ADDRESS_DOMAIN) {
      pending->metadata.original_target.domain.data = pending->domain;
    }
  }
  if (metadata->resolved_count != 0u) {
    if (metadata->resolved == NULL ||
        metadata->resolved_count > FTUN_UDP_FLOW_MAX_RESOLVED_IPV4) {
      return FTUN_E_INVALID;
    }
    memcpy(pending->resolved, metadata->resolved,
      metadata->resolved_count * sizeof(pending->resolved[0]));
    pending->metadata.resolved = pending->resolved;
  }
  pending->active = true;
  status = ftun_runtime_active_acquire(engine->core, &pending->runtime);
  if (status == FTUN_OK) status = ftun_runtime_get_info(pending->runtime,
                                                        &info);
  if (status == FTUN_OK && info.generation != pending->metadata.generation) {
    status = FTUN_E_STALE;
  }
  if (status == FTUN_OK) status = ftun_runtime_config(pending->runtime,
                                                       &config);
  if (status == FTUN_OK) status = ftun_packet_clone(packet, &pending->packet);
  if (status == FTUN_OK) status = ftun_engine_udp_finish_route(pending, false);
  if (status == FTUN_E_RESOLVE) {
    ftun_string_t domain = pending->metadata.domain;
    if (domain.length == 0u &&
        pending->metadata.original_target.kind == FTUN_ADDRESS_DOMAIN) {
      domain = pending->metadata.original_target.domain;
    }
    status = ftun_engine_resolve_async(engine, config, domain, false,
      ftun_engine_udp_resolved, pending, &pending->operation);
    if (status == FTUN_OK) return FTUN_OK;
  }
  ftun_engine_udp_pending_release(pending);
  return status;
}

#if defined(FTUN_HAVE_MODULE_TUN)
static ftun_status_t ftun_engine_tun_datagram(
  void *user, const ftun_metadata_t *metadata, ftun_datagram_t *channel,
  const ftun_endpoint_t *source, const ftun_packet_t *packet)
{
  ftun_engine_t *engine = (ftun_engine_t *)user;
  ftun_status_t status;
  if (engine == NULL || metadata == NULL || source == NULL ||
      !ftun_engine_endpoint_equal(source, &metadata->original_target)) {
    return FTUN_E_STATE_CORRUPT;
  }
  if (metadata->original_target.port == 53u &&
      ftun_engine_dns_has_hijack(engine->dns)) {
    return ftun_engine_dns_hijack_udp(engine->dns, channel,
                                      &metadata->source, packet);
  }
  status = ftun_engine_udp_route_datagram(engine, channel, metadata, packet);
  if (status == FTUN_E_PROTOCOL || status == FTUN_E_REJECTED ||
      status == FTUN_E_RESOLVE || status == FTUN_E_LIMIT ||
      status == FTUN_E_AGAIN || status == FTUN_E_STALE) return FTUN_OK;
  return status;
}

static ftun_status_t ftun_engine_packet_from_bytes(
  ftun_engine_t *engine, const uint8_t *bytes, size_t length)
{
  ftun_buffer_t *buffer = NULL;
  ftun_buffer_slice_t slice;
  ftun_packet_t packet;
  uint8_t *storage = NULL;
  size_t capacity = 0u;
  ftun_status_t status;
  memset(&slice, 0, sizeof(slice));
  memset(&packet, 0, sizeof(packet));
  status = ftun_buffer_pool_acquire(engine->relay_pool,
                                    length == 0u ? 1u : length, &buffer);
  if (status == FTUN_OK) status = ftun_buffer_data(buffer, &storage, &capacity);
  if (status == FTUN_OK && capacity < length) status = FTUN_E_STATE_CORRUPT;
  if (status == FTUN_OK) memcpy(storage, bytes, length);
  if (status == FTUN_OK) status = ftun_buffer_slice(buffer, 0u, length, &slice);
  if (status == FTUN_OK) {
    status = ftun_packet_init(&packet, &slice, engine->tun_listener.inbound_id);
  }
  (void)ftun_buffer_slice_release(&slice);
  (void)ftun_buffer_release(&buffer);
  if (status == FTUN_OK) {
    status = ftun_tun_ingress(engine->core, engine->tun_port, &packet);
  }
  if (ftun_packet_release(&packet) != FTUN_OK && status == FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
  }
  return status;
}

static ftun_status_t ftun_engine_tun_read(ftun_engine_t *engine)
{
  uint8_t packet[65535];
  size_t received;
  for (received = 0u; received < FTUN_ENGINE_TUN_QUOTA; received++) {
    size_t length = 0u;
    ftun_status_t status = ftun_packet_port_read(engine->tun_port, packet,
                                                 sizeof(packet), &length);
    if (status == FTUN_E_AGAIN) return FTUN_OK;
    if (status != FTUN_OK) return status;
    status = ftun_engine_packet_from_bytes(engine, packet, length);
    if (status != FTUN_OK && status != FTUN_E_PROTOCOL) return status;
  }
  return FTUN_OK;
}
#endif

static ftun_status_t ftun_engine_udp_receive(ftun_engine_udp_slot_t *slot)
{
  uint8_t payload[65535];
  ftun_buffer_t *buffer = NULL;
  ftun_buffer_slice_t slice;
  ftun_packet_t packet;
  uint8_t *storage = NULL;
  size_t capacity = 0u;
  ssize_t length;
  ftun_status_t status;
  ftun_bytes_t data;
  memset(&slice, 0, sizeof(slice));
  memset(&packet, 0, sizeof(packet));
  do {
    length = recv(slot->descriptor, payload, sizeof(payload), 0);
  } while (length < 0 && errno == EINTR);
  if (length < 0) return ftun_engine_errno_status(errno);
  data.data = payload;
  data.length = (size_t)length;
  if (slot->socks5) {
    ftun_socks5_connection_info_t info;
    ftun_socks5_udp_datagram_t datagram;
    size_t consumed = 0u;
    status = ftun_socks5_connection_get_info(slot->proxy_connection, &info);
    if (status == FTUN_OK) {
      status = ftun_socks5_connection_decode_udp(slot->proxy_connection,
        &info.relay, data, &datagram, &consumed);
    }
    if (status != FTUN_OK) return status;
    if (consumed != (size_t)length ||
        (!ftun_engine_endpoint_equal(&datagram.endpoint, &slot->remote) &&
         !(slot->remote.kind == FTUN_ADDRESS_DOMAIN &&
           datagram.endpoint.kind == FTUN_ADDRESS_IPV4 &&
           datagram.endpoint.port == slot->remote.port))) {
      return FTUN_E_REJECTED;
    }
    data = datagram.payload;
  }
  status = ftun_buffer_pool_acquire(slot->engine->relay_pool,
    data.length == 0u ? 1u : data.length, &buffer);
  if (status == FTUN_OK) status = ftun_buffer_data(buffer, &storage, &capacity);
  if (status == FTUN_OK && capacity < data.length) {
    status = FTUN_E_STATE_CORRUPT;
  }
  if (status == FTUN_OK && data.length != 0u) {
    memcpy(storage, data.data, data.length);
  }
  if (status == FTUN_OK) {
    status = ftun_buffer_slice(buffer, 0u, data.length, &slice);
  }
  if (status == FTUN_OK) status = ftun_packet_init(&packet, &slice, 0u);
  (void)ftun_buffer_slice_release(&slice);
  (void)ftun_buffer_release(&buffer);
  if (status == FTUN_OK) {
    status = ftun_datagram_deliver(slot->channel, &slot->remote, &packet);
  }
  if (status == FTUN_OK && slot->socks5) {
    /* A completed SOCKS handshake alone is not recovery: a flapping proxy can
     * accept UDP ASSOCIATE and immediately drop its control connection.  Only
     * a valid relayed response proves the association useful and resets the
     * consecutive-failure backoff. */
    ftun_engine_udp_backoff_succeeded(slot->engine, slot->outbound_id);
  }
  if (ftun_packet_release(&packet) != FTUN_OK && status == FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
  }
  return status;
}

static ftun_status_t ftun_engine_association_send_start(
  void *user, ftun_datagram_send_t *send, const ftun_endpoint_t *target,
  const ftun_packet_t *packet)
{
  (void)user;
  (void)send;
  (void)target;
  (void)packet;
  return FTUN_E_STATE_CORRUPT;
}

static ftun_status_t ftun_engine_association_send_cancel(
  void *user, ftun_datagram_send_t *send)
{
  (void)user;
  (void)send;
  return FTUN_E_STALE;
}

static void ftun_engine_association_destroy(void *user)
{
  (void)user;
}

static void ftun_engine_association_result(
  ftun_datagram_t *channel, ftun_error_t error,
  const ftun_endpoint_t *target, const ftun_packet_t *packet, void *user)
{
  (void)channel;
  (void)error;
  (void)target;
  (void)packet;
  (void)user;
}

static ftun_status_t ftun_engine_association_receive(
  ftun_datagram_t *channel, const ftun_endpoint_t *source,
  const ftun_packet_t *packet, void *user)
{
  (void)channel;
  (void)source;
  (void)packet;
  (void)user;
  return FTUN_E_STATE_CORRUPT;
}

static size_t ftun_engine_association_client_bucket(
  const ftun_engine_listener_t *listener, const ftun_endpoint_t *client)
{
  uint32_t hash = UINT32_C(2166136261);
  size_t index;
  hash = (hash ^ listener->inbound_id) * UINT32_C(16777619);
  for (index = 0u; index < 4u; index++) {
    hash = (hash ^ client->address[index]) * UINT32_C(16777619);
  }
  hash = (hash ^ client->port) * UINT32_C(16777619);
  return (size_t)(hash % FTUN_ENGINE_ASSOCIATION_BUCKETS);
}

static size_t ftun_engine_association_channel_bucket(
  const ftun_datagram_t *channel)
{
  uintptr_t value = (uintptr_t)channel;
  value ^= value >> 17u;
  value *= (uintptr_t)UINT32_C(0xed5ad4bb);
  value ^= value >> 11u;
  return (size_t)(value % FTUN_ENGINE_ASSOCIATION_BUCKETS);
}

static void ftun_engine_association_index_client(ftun_engine_flow_t *flow)
{
  size_t bucket;
  if (flow == NULL || flow->association_client_indexed ||
      !flow->udp_client_pinned || flow->listener == NULL) return;
  bucket = ftun_engine_association_client_bucket(flow->listener,
                                                  &flow->udp_client);
  flow->association_client_next = flow->engine->association_clients[bucket];
  flow->engine->association_clients[bucket] = flow;
  flow->association_client_indexed = true;
}

static void ftun_engine_association_index_channel(ftun_engine_flow_t *flow)
{
  size_t bucket;
  if (flow == NULL || flow->association_channel_indexed ||
      flow->udp_channel == NULL) return;
  bucket = ftun_engine_association_channel_bucket(flow->udp_channel);
  flow->association_channel_next = flow->engine->association_channels[bucket];
  flow->engine->association_channels[bucket] = flow;
  flow->association_channel_indexed = true;
}

static void ftun_engine_association_unlink(ftun_engine_flow_t *flow)
{
  ftun_engine_flow_t **cursor;
  size_t bucket;
  if (flow == NULL || flow->engine == NULL) return;
  if (flow->association_client_indexed && flow->listener != NULL) {
    bucket = ftun_engine_association_client_bucket(flow->listener,
                                                    &flow->udp_client);
    for (cursor = &flow->engine->association_clients[bucket];
         *cursor != NULL; cursor = &(*cursor)->association_client_next) {
      if (*cursor == flow) {
        *cursor = flow->association_client_next;
        break;
      }
    }
  }
  if (flow->association_channel_indexed && flow->udp_channel != NULL) {
    bucket = ftun_engine_association_channel_bucket(flow->udp_channel);
    for (cursor = &flow->engine->association_channels[bucket];
         *cursor != NULL; cursor = &(*cursor)->association_channel_next) {
      if (*cursor == flow) {
        *cursor = flow->association_channel_next;
        break;
      }
    }
  }
  flow->association_client_next = NULL;
  flow->association_channel_next = NULL;
  flow->association_client_indexed = false;
  flow->association_channel_indexed = false;
}

static ftun_engine_flow_t *ftun_engine_association_find_channel(
  ftun_engine_t *engine, ftun_datagram_t *channel)
{
  ftun_engine_flow_t *flow;
  size_t bucket = ftun_engine_association_channel_bucket(channel);
  for (flow = engine->association_channels[bucket]; flow != NULL;
       flow = flow->association_channel_next) {
    if (flow->active && flow->udp_channel == channel) return flow;
  }
  return NULL;
}

static ftun_status_t ftun_engine_udp_reply(
  void *user, ftun_datagram_t *inbound, const ftun_metadata_t *metadata,
  const ftun_endpoint_t *source, const ftun_packet_t *packet)
{
  ftun_engine_t *engine = (ftun_engine_t *)user;
  ftun_engine_flow_t *association = NULL;
  ftun_bytes_t payload;
  struct sockaddr_in client;
  uint8_t wire[UINT16_MAX + 263u];
  size_t written = 0u;
  ssize_t sent;
  ftun_status_t status;
  if (engine == NULL || inbound == NULL || metadata == NULL ||
      source == NULL || packet == NULL) return FTUN_E_INVALID;
  association = ftun_engine_association_find_channel(engine, inbound);
  if (association == NULL) {
    return ftun_datagram_send(inbound, &metadata->source,
                              (ftun_packet_t *)packet);
  }
  if (!association->udp_client_pinned ||
      association->listener == NULL ||
      association->listener->udp_descriptor < 0) return FTUN_E_STALE;
  status = ftun_packet_view(packet, &payload);
  if (status == FTUN_OK) {
    status = ftun_socks5_encode_udp_datagram(source, payload, wire,
                                             sizeof(wire), &written);
  }
  if (status != FTUN_OK) return status;
  memset(&client, 0, sizeof(client));
  client.sin_family = AF_INET;
  client.sin_port = htons(association->udp_client.port);
  memcpy(&client.sin_addr.s_addr, association->udp_client.address, 4u);
  do {
    sent = sendto(association->listener->udp_descriptor, wire, written,
                  MSG_NOSIGNAL, (const struct sockaddr *)&client,
                  (socklen_t)sizeof(client));
  } while (sent < 0 && errno == EINTR);
  if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return FTUN_OK;
  if (sent < 0) return ftun_engine_errno_status(errno);
  return (size_t)sent == written ? FTUN_OK : FTUN_E_IO;
}

static ftun_status_t ftun_engine_association_start(
  ftun_engine_flow_t *flow, const ftun_endpoint_t *requested)
{
  ftun_datagram_options_t options;
  ftun_datagram_backend_t backend;
  struct sockaddr_in bound_address;
  socklen_t bound_length = (socklen_t)sizeof(bound_address);
  ftun_endpoint_t bound;
  ftun_status_t status;
  if (flow == NULL || requested == NULL || flow->listener == NULL ||
      flow->listener->udp_descriptor < 0 ||
      requested->kind != FTUN_ADDRESS_IPV4) return FTUN_E_UNSUPPORTED;
  memset(&options, 0, sizeof(options));
  options.budget = flow->engine->budget;
  options.max_pending_packets = 1u;
  options.max_pending_bytes = 1u;
  options.result = ftun_engine_association_result;
  options.receive = ftun_engine_association_receive;
  options.user = flow;
  memset(&backend, 0, sizeof(backend));
  backend.send_start = ftun_engine_association_send_start;
  backend.send_cancel = ftun_engine_association_send_cancel;
  backend.destroy = ftun_engine_association_destroy;
  backend.context = flow;
  status = ftun_datagram_create(&options, &backend, &flow->udp_channel);
  if (status != FTUN_OK) return status;
  memset(&bound_address, 0, sizeof(bound_address));
  if (getsockname(flow->listener->udp_descriptor,
                  (struct sockaddr *)&bound_address, &bound_length) != 0 ||
      bound_length < (socklen_t)sizeof(bound_address) ||
      bound_address.sin_family != AF_INET) {
    status = FTUN_E_IO;
  }
  if (status == FTUN_OK && bound_address.sin_addr.s_addr == htonl(INADDR_ANY)) {
    bound_length = (socklen_t)sizeof(bound_address);
    if (getsockname(flow->client_socket.descriptor,
                    (struct sockaddr *)&bound_address, &bound_length) != 0 ||
        bound_length < (socklen_t)sizeof(bound_address) ||
        bound_address.sin_family != AF_INET) status = FTUN_E_IO;
  }
  memset(&bound, 0, sizeof(bound));
  if (status == FTUN_OK) {
    bound.kind = FTUN_ADDRESS_IPV4;
    bound.port = ntohs(bound_address.sin_port);
    memcpy(bound.address, &bound_address.sin_addr.s_addr, 4u);
    flow->udp_request = *requested;
    flow->state = FTUN_ENGINE_FLOW_UDP_ASSOCIATE;
    if (flow->listener->kind == FTUN_CONFIG_INBOUND_SOCKS5) {
      ftun_socks5_server_event_t event;
      status = ftun_socks5_server_finish_request(flow->socks5, FTUN_OK,
                                                  &bound, &event);
      if (status == FTUN_OK) {
        status = ftun_engine_queue_reply(flow, event.wire, false);
      }
    } else {
      ftun_mixed_event_t event;
      status = ftun_mixed_socks5_finish_request(flow->mixed, FTUN_OK,
                                                 &bound, &event);
      if (status == FTUN_OK) {
        status = ftun_engine_queue_reply(flow, event.socks5.wire, false);
      }
    }
  }
  if (status != FTUN_OK) {
    if (flow->udp_channel != NULL) {
      (void)ftun_datagram_stop(flow->udp_channel);
      (void)ftun_datagram_destroy(&flow->udp_channel);
    }
  } else {
    ftun_engine_association_index_channel(flow);
  }
  return status;
}

static bool ftun_engine_zero_ipv4(const ftun_endpoint_t *endpoint)
{
  static const uint8_t zero[4] = {0u, 0u, 0u, 0u};
  return endpoint != NULL && endpoint->kind == FTUN_ADDRESS_IPV4 &&
         memcmp(endpoint->address, zero, sizeof(zero)) == 0;
}

static ftun_engine_flow_t *ftun_engine_association_find(
  ftun_engine_t *engine, ftun_engine_listener_t *listener,
  const ftun_endpoint_t *client)
{
  ftun_engine_flow_t *flow;
  size_t bucket = ftun_engine_association_client_bucket(listener, client);
  size_t index;
  for (flow = engine->association_clients[bucket]; flow != NULL;
       flow = flow->association_client_next) {
    if (flow->active && flow->listener == listener &&
        flow->state == FTUN_ENGINE_FLOW_UDP_ASSOCIATE &&
        ftun_engine_endpoint_equal(&flow->udp_client, client)) return flow;
  }
  for (index = 0u; index < FTUN_ENGINE_MAX_TCP_FLOWS; index++) {
    flow = &engine->flows[index];
    if (!flow->active || flow->listener != listener ||
        flow->state != FTUN_ENGINE_FLOW_UDP_ASSOCIATE ||
        flow->udp_client_pinned ||
        flow->tcp_peer.kind != FTUN_ADDRESS_IPV4 ||
        memcmp(flow->tcp_peer.address, client->address, 4u) != 0) {
      continue;
    }
    if (!ftun_engine_zero_ipv4(&flow->udp_request) &&
        memcmp(flow->udp_request.address, client->address, 4u) != 0) continue;
    if (flow->udp_request.port != 0u &&
        flow->udp_request.port != client->port) continue;
    flow->udp_client = *client;
    flow->udp_client_pinned = true;
    ftun_engine_association_index_client(flow);
    return flow;
  }
  return NULL;
}

static ftun_status_t ftun_engine_listener_udp(ftun_engine_t *engine,
                                               ftun_engine_listener_t *listener)
{
  uint8_t wire[65535];
  size_t received;
  for (received = 0u; received < FTUN_ENGINE_DATAGRAM_QUOTA; received++) {
    struct sockaddr_in peer;
    socklen_t peer_length = (socklen_t)sizeof(peer);
    ftun_engine_flow_t *flow;
    ftun_socks5_udp_datagram_t datagram;
    ftun_endpoint_t client;
    ftun_metadata_t metadata;
    ftun_buffer_t *buffer = NULL;
    ftun_buffer_slice_t slice;
    ftun_packet_t packet;
    uint8_t *storage = NULL;
    size_t capacity = 0u;
    ssize_t length;
    ftun_status_t status;
    memset(&peer, 0, sizeof(peer));
    do {
      length = recvfrom(listener->udp_descriptor, wire, sizeof(wire), 0,
                        (struct sockaddr *)&peer, &peer_length);
    } while (length < 0 && errno == EINTR);
    if (length < 0) {
      return errno == EAGAIN || errno == EWOULDBLOCK
        ? FTUN_OK : ftun_engine_errno_status(errno);
    }
    if (peer_length < (socklen_t)sizeof(peer) || peer.sin_family != AF_INET ||
        peer.sin_port == 0) continue;
    memset(&client, 0, sizeof(client));
    client.kind = FTUN_ADDRESS_IPV4;
    client.port = ntohs(peer.sin_port);
    memcpy(client.address, &peer.sin_addr.s_addr, 4u);
    flow = ftun_engine_association_find(engine, listener, &client);
    if (flow == NULL) continue;
    memset(&datagram, 0, sizeof(datagram));
    status = listener->kind == FTUN_CONFIG_INBOUND_SOCKS5
      ? ftun_socks5_server_udp(flow->socks5,
          (ftun_bytes_t){wire, (size_t)length}, &datagram)
      : ftun_mixed_socks5_udp(flow->mixed,
          (ftun_bytes_t){wire, (size_t)length}, &datagram);
    if (status != FTUN_OK) continue;
    memset(&metadata, 0, sizeof(metadata));
    metadata.generation = engine->generation;
    metadata.known_fields = FTUN_META_SOURCE | FTUN_META_PORT |
                            FTUN_META_NETWORK;
    metadata.inbound_id = listener->inbound_id;
    metadata.network = 2u;
    metadata.source = client;
    metadata.original_target = datagram.endpoint;
    if (datagram.endpoint.kind == FTUN_ADDRESS_DOMAIN) {
      metadata.known_fields |= FTUN_META_DOMAIN;
      metadata.domain = datagram.endpoint.domain;
      metadata.domain_source = FTUN_DOMAIN_EXPLICIT;
    }
    memset(&slice, 0, sizeof(slice));
    memset(&packet, 0, sizeof(packet));
    if (status == FTUN_OK) {
      status = ftun_buffer_pool_acquire(engine->relay_pool,
        datagram.payload.length == 0u ? 1u : datagram.payload.length, &buffer);
    }
    if (status == FTUN_OK) {
      status = ftun_buffer_data(buffer, &storage, &capacity);
    }
    if (status == FTUN_OK && capacity < datagram.payload.length) {
      status = FTUN_E_STATE_CORRUPT;
    }
    if (status == FTUN_OK && datagram.payload.length != 0u) {
      memcpy(storage, datagram.payload.data, datagram.payload.length);
    }
    if (status == FTUN_OK) {
      status = ftun_buffer_slice(buffer, 0u, datagram.payload.length, &slice);
    }
    if (status == FTUN_OK) {
      status = ftun_packet_init(&packet, &slice, listener->inbound_id);
    }
    (void)ftun_buffer_slice_release(&slice);
    (void)ftun_buffer_release(&buffer);
    if (status == FTUN_OK) {
      status = ftun_engine_udp_route_datagram(engine, flow->udp_channel,
                                              &metadata, &packet);
    }
    (void)ftun_packet_release(&packet);
    /* Client/protocol/routing failures drop this datagram, not the daemon. */
    (void)status;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_engine_handle_socks_event(
  ftun_engine_flow_t *flow, const ftun_socks5_server_event_t *event)
{
  ftun_status_t status;
  if (event->kind == FTUN_SOCKS5_SERVER_METHOD_REPLY ||
      event->kind == FTUN_SOCKS5_SERVER_AUTH_REPLY) {
    return ftun_engine_queue_reply(flow, event->wire, false);
  }
  if (event->kind == FTUN_SOCKS5_SERVER_COMMAND_REPLY) {
    return ftun_engine_queue_reply(flow, event->wire, true);
  }
  if (event->kind != FTUN_SOCKS5_SERVER_REQUEST) {
    return FTUN_E_STATE_CORRUPT;
  }
  if (event->command == FTUN_SOCKS5_COMMAND_UDP_ASSOCIATE) {
    return ftun_engine_association_start(flow, &event->target);
  }
  if (event->command != FTUN_SOCKS5_COMMAND_CONNECT) {
    ftun_socks5_server_event_t reply;
    status = ftun_socks5_server_finish_request(flow->socks5,
      FTUN_E_UNSUPPORTED, NULL, &reply);
    if (status == FTUN_OK) status = ftun_engine_queue_reply(flow, reply.wire,
                                                            true);
    return status;
  }
  status = ftun_engine_copy_preread(flow, event->preread);
  if (status == FTUN_OK) status = ftun_engine_session_start(flow,
                                                            &event->target);
  return status;
}

static ftun_status_t ftun_engine_handle_mixed_event(
  ftun_engine_flow_t *flow, const ftun_mixed_event_t *event)
{
  ftun_status_t status;
  if (event->kind == FTUN_MIXED_EVENT_HTTP_REPLY) {
    return ftun_engine_queue_reply(flow, event->wire, true);
  }
  if (event->kind == FTUN_MIXED_EVENT_SOCKS5) {
    const ftun_socks5_server_event_t *socks = &event->socks5;
    if (socks->kind == FTUN_SOCKS5_SERVER_METHOD_REPLY ||
        socks->kind == FTUN_SOCKS5_SERVER_AUTH_REPLY) {
      return ftun_engine_queue_reply(flow, socks->wire, false);
    }
    if (socks->kind == FTUN_SOCKS5_SERVER_COMMAND_REPLY) {
      return ftun_engine_queue_reply(flow, socks->wire, true);
    }
    if (socks->kind == FTUN_SOCKS5_SERVER_REQUEST &&
        socks->command == FTUN_SOCKS5_COMMAND_UDP_ASSOCIATE) {
      return ftun_engine_association_start(flow, &socks->target);
    }
    if (socks->kind != FTUN_SOCKS5_SERVER_REQUEST ||
        socks->command != FTUN_SOCKS5_COMMAND_CONNECT) {
      ftun_mixed_event_t reply;
      status = ftun_mixed_socks5_finish_request(flow->mixed,
        FTUN_E_UNSUPPORTED, NULL, &reply);
      if (status == FTUN_OK) status = ftun_engine_queue_reply(
        flow, reply.socks5.wire, true);
      return status;
    }
    flow->http_connect = false;
    flow->mixed_http = false;
    status = ftun_engine_copy_preread(flow, socks->preread);
    if (status == FTUN_OK) status = ftun_engine_session_start(flow,
                                                              &socks->target);
    return status;
  }
  if (event->kind != FTUN_MIXED_EVENT_HTTP_REQUEST) {
    return FTUN_E_STATE_CORRUPT;
  }
  flow->http_connect = event->http.kind == FTUN_HTTP_PROXY_CONNECT;
  flow->mixed_http = true;
  status = flow->http_connect ? FTUN_OK :
    ftun_engine_copy_preread(flow, event->wire);
  if (status == FTUN_OK) status = ftun_engine_session_start(flow,
                                                            &event->http.target);
  return status;
}

static ftun_status_t ftun_engine_flow_handshake(ftun_engine_flow_t *flow)
{
  uint8_t input[2048];
  ftun_bytes_t bytes;
  ssize_t length;
  size_t consumed = 0u;
  ftun_status_t status;
  if (flow->reply_length != 0u) return FTUN_E_AGAIN;
  do {
    length = recv(flow->client_socket.descriptor, input, sizeof(input), 0);
  } while (length < 0 && errno == EINTR);
  if (length < 0) return ftun_engine_errno_status(errno);
  if (length == 0) return FTUN_E_EOF;
  bytes.data = input;
  bytes.length = (size_t)length;
  if (flow->listener->kind == FTUN_CONFIG_INBOUND_SOCKS5) {
    ftun_socks5_server_event_t event;
    status = ftun_socks5_server_feed(flow->socks5, bytes, &consumed, &event);
    if (status == FTUN_OK) status = ftun_engine_handle_socks_event(flow,
                                                                   &event);
  } else {
    ftun_mixed_event_t event;
    status = ftun_mixed_connection_feed(flow->mixed, bytes, &consumed,
                                         &event);
    if (status == FTUN_OK) status = ftun_engine_handle_mixed_event(flow,
                                                                   &event);
  }
  return status;
}

static ftun_status_t ftun_engine_flow_create(ftun_engine_t *engine,
                                              ftun_engine_listener_t *listener,
                                              int descriptor,
                                              const struct sockaddr_in *peer)
{
  ftun_engine_flow_t *flow = NULL;
  ftun_runtime_t *runtime = NULL;
  const ftun_config_t *config = NULL;
  const ftun_config_inbound_t *inbound;
  ftun_inbound_spec_t spec;
  ftun_inbound_user_t *users = NULL;
  ftun_status_t status;
  uint64_t now;
  size_t index;
  for (index = 0u; index < FTUN_ENGINE_MAX_TCP_FLOWS; index++) {
    if (!engine->flows[index].active) {
      flow = &engine->flows[index];
      break;
    }
  }
  if (flow == NULL) {
    (void)close(descriptor);
    return FTUN_E_LIMIT;
  }
  memset(flow, 0, sizeof(*flow));
  flow->engine = engine;
  flow->listener = listener;
  flow->client_socket.descriptor = -1;
  flow->remote_socket.descriptor = -1;
  flow->active = true;
  flow->state = FTUN_ENGINE_FLOW_HANDSHAKE;
  status = ftun_monotonic_now(&now);
  if (status != FTUN_OK ||
      now > UINT64_MAX - FTUN_ENGINE_HANDSHAKE_TIMEOUT_MS) {
    status = status == FTUN_OK ? FTUN_E_LIMIT : status;
    goto fail;
  }
  flow->handshake_deadline_ms = now + FTUN_ENGINE_HANDSHAKE_TIMEOUT_MS;
  if (peer != NULL && peer->sin_family == AF_INET) {
    flow->tcp_peer.kind = FTUN_ADDRESS_IPV4;
    flow->tcp_peer.port = ntohs(peer->sin_port);
    memcpy(flow->tcp_peer.address, &peer->sin_addr.s_addr, 4u);
  }
  status = ftun_engine_stream_create(flow, &flow->client_socket, descriptor,
                                     &flow->client);
  if (status != FTUN_OK) goto fail;
  status = ftun_engine_runtime_for_flow(flow, &runtime, &config);
  if (status != FTUN_OK) goto fail;
  inbound = ftun_engine_inbound_config(config, listener);
  if (inbound == NULL) {
    status = FTUN_E_STALE;
    goto fail;
  }
  status = ftun_engine_build_inbound_spec(flow, inbound, &spec, &users);
  if (status == FTUN_OK && listener->kind == FTUN_CONFIG_INBOUND_SOCKS5) {
    status = ftun_socks5_server_create(&spec, &flow->socks5);
  } else if (status == FTUN_OK) {
    status = ftun_mixed_connection_create(&spec, &flow->mixed);
  }
  free(users);
  users = NULL;
  (void)ftun_runtime_release(&runtime);
  if (status == FTUN_OK) {
    status = ftun_event_io_start(engine->loop,
      (ftun_native_socket_t)(unsigned int)descriptor,
      FTUN_EVENT_READ | FTUN_EVENT_ERROR,
      ftun_engine_flow_client_ready, flow, &flow->client_source);
  }
  if (status == FTUN_OK) {
    status = ftun_engine_flow_deadline_arm(flow,
                                           flow->handshake_deadline_ms);
  }
  if (status != FTUN_OK) goto fail;
  return FTUN_OK;

fail:
  free(users);
  (void)ftun_runtime_release(&runtime);
  (void)ftun_event_source_cancel(&flow->client_source);
  (void)ftun_event_source_cancel(&flow->remote_source);
  (void)ftun_event_source_cancel(&flow->deadline_source);
  if (flow->client != NULL) {
    (void)ftun_stream_stop(flow->client);
    (void)ftun_stream_destroy(&flow->client);
  } else if (descriptor >= 0) {
    (void)close(descriptor);
  }
  if (ftun_engine_preread_release(flow) != FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
  }
  memset(flow, 0, sizeof(*flow));
  flow->client_socket.descriptor = -1;
  flow->remote_socket.descriptor = -1;
  return status;
}

static ftun_status_t ftun_engine_accept_pause(
  ftun_engine_t *engine, ftun_engine_listener_t *listener)
{
  uint64_t now;
  uint64_t delay;
  uint64_t deadline;
  ftun_status_t status;
  if (engine == NULL || listener == NULL || listener->source == NULL) {
    return FTUN_E_INVALID;
  }
  if (listener->accept_timer != NULL) return FTUN_OK;
  delay = listener->accept_backoff_ms == 0u
    ? FTUN_ENGINE_ACCEPT_BACKOFF_MIN_MS : listener->accept_backoff_ms;
  if (delay > FTUN_ENGINE_ACCEPT_BACKOFF_MAX_MS) {
    delay = FTUN_ENGINE_ACCEPT_BACKOFF_MAX_MS;
  }
  status = ftun_monotonic_now(&now);
  if (status != FTUN_OK || now > UINT64_MAX - delay) {
    return status == FTUN_OK ? FTUN_E_LIMIT : status;
  }
  deadline = now + delay;
  status = ftun_event_io_update(listener->source, FTUN_EVENT_ERROR);
  if (status != FTUN_OK) return status;
  status = ftun_event_timer_start(engine->loop, deadline,
    ftun_engine_listener_accept_resume, listener, &listener->accept_timer);
  if (status != FTUN_OK) {
    (void)ftun_event_io_update(listener->source,
      FTUN_EVENT_READ | FTUN_EVENT_ERROR);
    return status;
  }
  listener->accept_backoff_ms = delay >= FTUN_ENGINE_ACCEPT_BACKOFF_MAX_MS / 2u
    ? FTUN_ENGINE_ACCEPT_BACKOFF_MAX_MS : delay * 2u;
  return FTUN_OK;
}

static ftun_status_t ftun_engine_accept(ftun_engine_t *engine,
                                         ftun_engine_listener_t *listener)
{
  size_t accepted;
  for (accepted = 0u; accepted < FTUN_ENGINE_ACCEPT_QUOTA; accepted++) {
    struct sockaddr_in peer;
    socklen_t peer_length = (socklen_t)sizeof(peer);
    int descriptor = accept4(listener->descriptor,
                             (struct sockaddr *)&peer, &peer_length,
                             SOCK_CLOEXEC | SOCK_NONBLOCK);
    ftun_status_t status;
    if (descriptor < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) return FTUN_OK;
      if (errno == ECONNABORTED || errno == EPROTO || errno == ENETDOWN ||
          errno == EHOSTDOWN || errno == ENONET || errno == EHOSTUNREACH ||
          errno == ENETUNREACH || errno == EOPNOTSUPP) {
        return FTUN_OK;
      }
      if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS ||
          errno == ENOMEM) {
        return ftun_engine_accept_pause(engine, listener);
      }
      return ftun_engine_errno_status(errno);
    }
    listener->accept_backoff_ms = 0u;
    {
      ftun_runtime_t *runtime = NULL;
      const ftun_config_t *config = NULL;
      bool permitted = false;
      status = ftun_runtime_active_acquire(engine->core, &runtime);
      if (status == FTUN_OK) status = ftun_runtime_config(runtime, &config);
      if (status == FTUN_OK && peer_length >= (socklen_t)sizeof(peer) &&
          peer.sin_family == AF_INET) {
        const uint8_t *address = (const uint8_t *)&peer.sin_addr.s_addr;
        permitted = config->base.allow_lan || address[0] == 127u;
      }
      (void)ftun_runtime_release(&runtime);
      if (status != FTUN_OK || !permitted) {
        (void)close(descriptor);
        if (status != FTUN_OK) return status;
        continue;
      }
    }
    status = ftun_engine_flow_create(engine, listener, descriptor, &peer);
    if (status != FTUN_OK) {
      if (status == FTUN_E_LIMIT) return FTUN_OK;
      return status;
    }
  }
  return FTUN_OK;
}

static ftun_status_t ftun_engine_flow_finalize(ftun_engine_flow_t *flow)
{
  ftun_session_info_t info;
  ftun_error_t result;
  ftun_status_t status = FTUN_OK;
  if (flow->open_operation != NULL) return FTUN_E_AGAIN;
  status = ftun_event_source_cancel(&flow->deadline_source);
  if (status == FTUN_OK) {
    status = ftun_event_source_cancel(&flow->client_source);
  }
  if (status == FTUN_OK) {
    status = ftun_event_source_cancel(&flow->remote_source);
  }
  if (status != FTUN_OK) return status;
  if (flow->proxy_connection != NULL) {
    status = ftun_socks5_connection_close(&flow->proxy_connection);
    if (status != FTUN_OK) return status;
  }
  if (flow->relay != NULL) {
    ftun_status_t current = ftun_relay_destroy(&flow->relay);
    if (current != FTUN_OK && current != FTUN_E_AGAIN) return current;
    if (current == FTUN_E_AGAIN) return current;
  }
  if (flow->session != NULL) {
    status = ftun_session_get_info(flow->session, &info);
    if (status != FTUN_OK) return status;
    if (info.state == FTUN_SESSION_RELAYING) {
      status = ftun_session_transition(flow->session,
                                       FTUN_SESSION_DRAINING, NULL);
      if (status == FTUN_OK) {
        memset(&result, 0, sizeof(result));
        result.status = FTUN_OK;
        status = ftun_session_finish(flow->session, result);
      }
    } else if (info.state != FTUN_SESSION_CLOSED) {
      status = ftun_session_cancel(flow->session);
    }
    if (status != FTUN_OK && status != FTUN_E_STALE) return status;
    status = ftun_session_get_info(flow->session, &info);
    if (status != FTUN_OK || info.state != FTUN_SESSION_CLOSED) {
      return status == FTUN_OK ? FTUN_E_AGAIN : status;
    }
    status = ftun_session_destroy(&flow->session);
    if (status != FTUN_OK) return status;
  }
  if (flow->udp_channel != NULL) {
    ftun_engine_association_unlink(flow);
    ftun_engine_udp_pending_cancel_inbound(flow->engine, flow->udp_channel);
    if (flow->engine->udp_flows != NULL) {
      status = ftun_udp_flow_close_inbound(flow->engine->udp_flows,
                                           flow->udp_channel);
      if (status != FTUN_OK) return status;
    }
    status = ftun_datagram_stop(flow->udp_channel);
    if (status != FTUN_OK) return status;
    status = ftun_datagram_destroy(&flow->udp_channel);
    if (status != FTUN_OK) return status;
  }
  (void)ftun_socks5_server_destroy(&flow->socks5);
  (void)ftun_mixed_connection_destroy(&flow->mixed);
  if (flow->client != NULL) {
    (void)ftun_stream_stop(flow->client);
    status = ftun_stream_destroy(&flow->client);
    if (status != FTUN_OK) return status;
  }
  if (flow->remote != NULL) {
    (void)ftun_stream_stop(flow->remote);
    status = ftun_stream_destroy(&flow->remote);
    if (status != FTUN_OK) return status;
  }
  status = ftun_engine_preread_release(flow);
  if (status != FTUN_OK) return status;
  memset(flow, 0, sizeof(*flow));
  flow->client_socket.descriptor = -1;
  flow->remote_socket.descriptor = -1;
  return FTUN_OK;
}

static ftun_status_t ftun_engine_flow_drive(ftun_engine_flow_t *flow,
                                             uint32_t client_events,
                                             uint32_t remote_events)
{
  ftun_status_t status = FTUN_OK;
  if (!flow->active) return FTUN_OK;
  status = ftun_engine_stream_complete_pending(&flow->client_socket);
  if (status == FTUN_OK) {
    status = ftun_engine_stream_complete_pending(&flow->remote_socket);
  }
  if (status != FTUN_OK) ftun_engine_flow_close(flow, status);
#if defined(FTUN_HAVE_MODULE_TUN)
  if (flow->tun && flow->state == FTUN_ENGINE_FLOW_HANDSHAKE) {
    bool readable = (flow->left_events & FTUN_EVENT_READ) != 0u;
    flow->left_events = 0u;
    status = ftun_engine_tun_sniff(flow, readable);
    if (status != FTUN_OK && status != FTUN_E_AGAIN) {
      ftun_engine_flow_close(flow, status);
    }
  }
#endif
  if (flow->reply_length != 0u &&
      (client_events & (FTUN_EVENT_WRITE | FTUN_EVENT_ERROR)) != 0u) {
    status = ftun_engine_flush_reply(flow);
    if (status != FTUN_OK && status != FTUN_E_AGAIN &&
        status != FTUN_E_EOF) ftun_engine_flow_close(flow, status);
  }
  if (flow->state == FTUN_ENGINE_FLOW_HANDSHAKE &&
      flow->reply_length == 0u &&
      (client_events & FTUN_EVENT_READ) != 0u) {
    status = ftun_engine_flow_handshake(flow);
    if (status != FTUN_OK && status != FTUN_E_AGAIN) {
      ftun_engine_flow_close(flow, status);
    }
  }
  if (flow->state != FTUN_ENGINE_FLOW_HANDSHAKE &&
      flow->reply_length == 0u && flow->deadline_source != NULL) {
    status = ftun_event_source_cancel(&flow->deadline_source);
    if (status != FTUN_OK) ftun_engine_flow_close(flow, status);
  }
  if (flow->state == FTUN_ENGINE_FLOW_UDP_ASSOCIATE) {
    if ((client_events & FTUN_EVENT_READ) != 0u) {
      uint8_t discard[256];
      ssize_t length;
      do {
        length = recv(flow->client_socket.descriptor, discard,
                      sizeof(discard), 0);
      } while (length < 0 && errno == EINTR);
      if (length == 0 || (length < 0 && errno != EAGAIN &&
                          errno != EWOULDBLOCK)) {
        ftun_engine_flow_close(flow, length == 0 ? FTUN_E_EOF
                                                 : ftun_engine_errno_status(errno));
      }
    }
  }
  if (flow->state == FTUN_ENGINE_FLOW_RELAY && flow->relay != NULL) {
    ftun_relay_usage_t usage;
    uint32_t left = 0u;
    uint32_t right = 0u;
    size_t work = 0u;
    left = client_events;
#if defined(FTUN_HAVE_MODULE_TUN)
    if (flow->tun) {
      bool readable = false;
      bool writable = false;
      left |= flow->left_events;
      flow->left_events = 0u;
      status = ftun_relay_get_usage(flow->relay, &usage);
      if (status == FTUN_OK) {
        status = ftun_tun_ingress_stream_ready(flow->engine->tun_ingress,
          flow->client, &readable, &writable);
      }
      if (status != FTUN_OK && status != FTUN_E_STALE) {
        ftun_engine_flow_close(flow, status);
      } else if (status == FTUN_OK) {
        if (readable && (usage.left_interests & FTUN_EVENT_READ) != 0u) {
          left |= FTUN_EVENT_READ;
        }
        if (writable && (usage.left_interests & FTUN_EVENT_WRITE) != 0u) {
          left |= FTUN_EVENT_WRITE;
        }
      }
    }
#endif
    right = remote_events;
    if (flow->preread_length != 0u) {
      status = ftun_engine_flush_preread(flow);
      if (status != FTUN_OK && status != FTUN_E_AGAIN) {
        ftun_engine_flow_close(flow, status);
      }
    }
    if (flow->preread_length == 0u && flow->state == FTUN_ENGINE_FLOW_RELAY) {
      status = ftun_relay_process(flow->relay, left, right, &work);
      if (status != FTUN_OK) ftun_engine_flow_close(flow, status);
    }
    if (flow->relay != NULL &&
        ftun_relay_get_usage(flow->relay, &usage) == FTUN_OK &&
        usage.complete) flow->state = FTUN_ENGINE_FLOW_CLOSING;
  }
  if ((client_events & FTUN_EVENT_ERROR) != 0u ||
      (remote_events & FTUN_EVENT_ERROR) != 0u) {
    ftun_engine_flow_close(flow, FTUN_E_IO);
  }
  if (flow->state == FTUN_ENGINE_FLOW_CLOSING) {
    status = ftun_engine_flow_finalize(flow);
    if (status == FTUN_E_AGAIN) return FTUN_OK;
    return status;
  }
  status = ftun_engine_flow_update_sources(flow);
  if (status != FTUN_OK) {
    ftun_engine_flow_close(flow, status);
    status = ftun_engine_flow_finalize(flow);
    return status == FTUN_E_AGAIN ? FTUN_OK : status;
  }
  return status;
}

static ftun_status_t ftun_engine_flow_drain(ftun_engine_t *engine,
                                             size_t quota,
                                             size_t *out_work)
{
  ftun_engine_flow_t *last;
  size_t work = 0u;
  if (out_work != NULL) *out_work = 0u;
  if (engine == NULL || quota == 0u || out_work == NULL) {
    return FTUN_E_INVALID;
  }
  /* Preserve the old owner-loop lifecycle boundary: a flow which becomes
   * runnable while this batch is being driven is deferred to the next
   * batch.  Without this boundary a synchronously rescheduled TUN flow can
   * be driven repeatedly and finalized before the packet/ACK cycle which
   * caused the reschedule has returned through the event loop. */
  last = engine->ready_flow_tail;
  while (engine->ready_flow_head != NULL && work < quota) {
    ftun_engine_flow_t *flow = engine->ready_flow_head;
    bool batch_complete = flow == last;
    uint32_t client_events;
    uint32_t remote_events;
    ftun_status_t status;
    engine->ready_flow_head = flow->ready_next;
    if (engine->ready_flow_head == NULL) engine->ready_flow_tail = NULL;
    flow->ready_next = NULL;
    flow->ready_queued = false;
    if (!flow->active) continue;
    client_events = flow->client_events;
    remote_events = flow->remote_events;
    flow->client_events = 0u;
    flow->remote_events = 0u;
    flow->driving = true;
    flow->reschedule = false;
    status = ftun_engine_flow_drive(flow, client_events, remote_events);
    work++;
    if (flow->active) {
      bool reschedule = flow->reschedule;
      flow->driving = false;
      flow->reschedule = false;
      if (reschedule) ftun_engine_flow_schedule(flow);
    }
    if (status != FTUN_OK) return status;
    if (batch_complete) break;
  }
  *out_work = work;
  return FTUN_OK;
}

#if defined(FTUN_HAVE_MODULE_TUN)
static ftun_status_t ftun_engine_parse_cidr(const char *text,
                                             uint8_t address[4],
                                             uint8_t *prefix)
{
  const char *slash;
  char ip[INET_ADDRSTRLEN];
  char *tail = NULL;
  unsigned long value;
  size_t length;
  if (text == NULL || address == NULL || prefix == NULL ||
      (slash = strchr(text, '/')) == NULL) return FTUN_E_INVALID;
  length = (size_t)(slash - text);
  if (length == 0u || length >= sizeof(ip)) return FTUN_E_INVALID;
  memcpy(ip, text, length);
  ip[length] = '\0';
  errno = 0;
  value = strtoul(slash + 1u, &tail, 10);
  if (errno != 0 || tail == slash + 1u || *tail != '\0' || value > 32u ||
      inet_pton(AF_INET, ip, address) != 1) return FTUN_E_INVALID;
  *prefix = (uint8_t)value;
  return FTUN_OK;
}

static ftun_status_t ftun_engine_tun_prepare(
  ftun_engine_t *engine, const ftun_config_inbound_t *inbound,
  uint32_t inbound_id)
{
  ftun_tun_spec_t tun;
  ftun_tun_ingress_spec_t ingress;
  ftun_route_policy_t route;
  uint8_t prefix = 0u;
  ftun_status_t status;
  engine->tun_listener.descriptor = -1;
  engine->tun_listener.name = strdup(inbound->name);
  if (engine->tun_listener.name == NULL) return FTUN_E_LIMIT;
  engine->tun_listener.kind = FTUN_CONFIG_INBOUND_TUN;
  engine->tun_listener.inbound_id = inbound_id;
  memset(&tun, 0, sizeof(tun));
  tun.name.data = inbound->interface_name;
  tun.name.length = strlen(inbound->interface_name);
  tun.mtu = inbound->mtu;
  status = ftun_packet_port_open(engine->core, &tun, &engine->tun_port);
  if (status == FTUN_OK) {
    status = ftun_packet_port_get_info(engine->tun_port, &engine->tun_info);
  }
  if (status != FTUN_OK) return status;
  if (inbound->auto_route) {
    memset(&route, 0, sizeof(route));
    route.tun_interface = tun.name;
    status = ftun_engine_parse_cidr(inbound->ipv4_address,
                                    route.tun_ipv4, &prefix);
    route.tun_prefix_length = prefix;
    route.route_table = 51820u;
    route.rule_priority = 11000u;
    route.protection_mark = engine->socket_mark;
    route.protection_mark_mask = UINT32_MAX;
    route.manage_local = true;
    route.strict_route = inbound->strict_route;
    if (status == FTUN_OK) {
      status = ftun_linux_route_prepare(&route, &engine->routes);
    }
    if (status != FTUN_OK) return status;
  }
  status = ftun_monotonic_now(&engine->now_ms);
  if (status != FTUN_OK) return status;
  memset(&ingress, 0, sizeof(ingress));
  ingress.core = engine->core;
  ingress.port = engine->tun_port;
  ingress.budget = engine->budget;
  ingress.operations = engine->operations;
  ingress.generation = engine->generation;
  ingress.now_ms = engine->now_ms;
  ingress.inbound_id = inbound_id;
  ingress.mtu = inbound->mtu;
  ingress.max_pending_stream_writes = 32u;
  ingress.max_pending_stream_bytes = 256u * 1024u;
  ingress.max_pending_datagrams = 32u;
  ingress.max_pending_datagram_bytes = 256u * 1024u;
  ingress.tcp = inbound->tcp;
  ingress.udp = inbound->udp;
  ingress.stream_write_completion = ftun_engine_tun_stream_completed;
  ingress.stream_accept = ftun_engine_tun_accept;
  ingress.stream_event = ftun_engine_tun_stream_event;
  ingress.datagram_receive = ftun_engine_tun_datagram;
  ingress.output = ftun_engine_tun_output;
  ingress.user = engine;
  status = ftun_tun_ingress_bind(&ingress, &engine->tun_ingress);
  if (status == FTUN_OK) engine->has_tun = true;
  return status;
}
#endif

static ftun_status_t ftun_engine_config_outbound_id(
  const ftun_config_t *config, const char *name, uint32_t *out)
{
  size_t index;
  if (config == NULL || name == NULL || out == NULL) return FTUN_E_INVALID;
  if (strcmp(name, "DIRECT") == 0) {
    *out = FTUN_OUTBOUND_ID_DIRECT;
    return FTUN_OK;
  }
  if (strcmp(name, "REJECT") == 0) {
    *out = FTUN_OUTBOUND_ID_REJECT;
    return FTUN_OK;
  }
  for (index = 0u; index < config->outbound_count; index++) {
    if (strcmp(name, config->outbounds[index].name) == 0) {
      if (index > UINT32_MAX - FTUN_OUTBOUND_ID_NAMED_BASE) {
        return FTUN_E_LIMIT;
      }
      *out = (uint32_t)index + FTUN_OUTBOUND_ID_NAMED_BASE;
      return FTUN_OK;
    }
  }
  return FTUN_E_REJECTED;
}

static int ftun_engine_string_equal(const char *left, const char *right)
{
  if (left == NULL || right == NULL) return left == right;
  return strcmp(left, right) == 0;
}

static int ftun_engine_string_list_equal(
  const ftun_config_string_list_t *left,
  const ftun_config_string_list_t *right)
{
  size_t index;
  if (left->count != right->count) return 0;
  for (index = 0u; index < left->count; index++) {
    if (!ftun_engine_string_equal(left->items[index], right->items[index])) {
      return 0;
    }
  }
  return 1;
}

static int ftun_engine_health_config_equal(const ftun_config_t *left,
                                           const ftun_config_t *right)
{
  size_t index;
  if (left == NULL || right == NULL || left->outbound_count !=
      right->outbound_count || left->plan == NULL || right->plan == NULL) {
    return 0;
  }
  for (index = 0u; index < left->outbound_count; index++) {
    const ftun_config_outbound_t *a = &left->outbounds[index];
    const ftun_config_outbound_t *b = &right->outbounds[index];
    if (a->kind != b->kind || a->udp != b->udp ||
        a->tolerance_ms != b->tolerance_ms || a->lazy != b->lazy ||
        a->expected_status != b->expected_status ||
        !ftun_engine_string_equal(a->name, b->name) ||
        !ftun_engine_string_equal(a->dns_server, b->dns_server) ||
        !ftun_engine_string_equal(a->server, b->server) ||
        !ftun_engine_string_equal(a->username, b->username) ||
        !ftun_engine_string_equal(a->password, b->password) ||
        !ftun_engine_string_list_equal(&a->members, &b->members) ||
        !ftun_engine_string_equal(a->default_member, b->default_member) ||
        !ftun_engine_string_equal(a->url, b->url) ||
        !ftun_engine_string_equal(a->interval, b->interval) ||
        !ftun_engine_string_equal(a->timeout, b->timeout) ||
        ((left->plan->outbound_states[index] & FTUN_PLAN_ITEM_REACHABLE) !=
         (right->plan->outbound_states[index] & FTUN_PLAN_ITEM_REACHABLE))) {
      return 0;
    }
  }
  return 1;
}

static ftun_status_t ftun_engine_prepare_inbound_ids(
  ftun_engine_t *engine, const ftun_config_t *config)
{
  size_t listener;
  if (engine == NULL || config == NULL) return FTUN_E_INVALID;
  memset(engine->pending_listener_ids, 0,
         sizeof(engine->pending_listener_ids));
#if defined(FTUN_HAVE_MODULE_TUN)
  engine->pending_tun_inbound_id = 0u;
#endif
  for (listener = 0u; listener < engine->listener_count; listener++) {
    size_t index;
    for (index = 0u; index < config->inbound_count; index++) {
      if (strcmp(engine->listeners[listener].name,
                 config->inbounds[index].name) == 0) break;
    }
    if (index == config->inbound_count || index >= UINT32_MAX) {
      return FTUN_E_RESTART_REQUIRED;
    }
    engine->pending_listener_ids[listener] = (uint32_t)index + 1u;
  }
#if defined(FTUN_HAVE_MODULE_TUN)
  if (engine->has_tun) {
    size_t index;
    for (index = 0u; index < config->inbound_count; index++) {
      if (strcmp(engine->tun_listener.name, config->inbounds[index].name) == 0) {
        break;
      }
    }
    if (index == config->inbound_count || index >= UINT32_MAX) {
      return FTUN_E_RESTART_REQUIRED;
    }
    engine->pending_tun_inbound_id = (uint32_t)index + 1u;
  }
#endif
  return FTUN_OK;
}

static ftun_status_t ftun_engine_health_prepare(
  ftun_engine_t *engine, const ftun_config_t *config, uint64_t generation,
  ftun_engine_health_group_t **out_groups, size_t *out_group_count,
  ftun_engine_health_slot_t **out_slots, size_t *out_slot_count,
  ftun_reservation_t **out_reservation)
{
  ftun_engine_health_group_t *groups = NULL;
  ftun_engine_health_slot_t *slots = NULL;
  ftun_reservation_t *reservation = NULL;
  size_t group_count = 0u;
  size_t slot_count = 0u;
  size_t group_cursor = 0u;
  size_t slot_cursor = 0u;
  size_t bytes;
  size_t index;
  uint64_t now_ms;
  ftun_status_t status;
  if (out_groups != NULL) *out_groups = NULL;
  if (out_group_count != NULL) *out_group_count = 0u;
  if (out_slots != NULL) *out_slots = NULL;
  if (out_slot_count != NULL) *out_slot_count = 0u;
  if (out_reservation != NULL) *out_reservation = NULL;
  if (engine == NULL || config == NULL || generation == 0u ||
      out_groups == NULL || out_group_count == NULL || out_slots == NULL ||
      out_slot_count == NULL || out_reservation == NULL) {
    return FTUN_E_INVALID;
  }
  for (index = 0u; index < config->outbound_count; index++) {
    const ftun_config_outbound_t *item = &config->outbounds[index];
    if (item->kind != FTUN_CONFIG_OUTBOUND_URL_TEST ||
        (config->plan->outbound_states[index] &
         FTUN_PLAN_ITEM_REACHABLE) == 0u) continue;
    if (group_count == SIZE_MAX || item->members.count > SIZE_MAX - slot_count) {
      return FTUN_E_LIMIT;
    }
    group_count++;
    slot_count += item->members.count;
  }
  if (group_count == 0u) return FTUN_OK;
  if (group_count > SIZE_MAX / sizeof(*groups) ||
      slot_count > SIZE_MAX / sizeof(*slots) ||
      group_count * sizeof(*groups) >
        SIZE_MAX - slot_count * sizeof(*slots)) return FTUN_E_LIMIT;
  bytes = group_count * sizeof(*groups) + slot_count * sizeof(*slots);
  status = ftun_budget_reserve(engine->budget, bytes, &reservation);
  if (status != FTUN_OK) return status;
  groups = (ftun_engine_health_group_t *)calloc(group_count, sizeof(*groups));
  slots = (ftun_engine_health_slot_t *)calloc(slot_count, sizeof(*slots));
  if (groups == NULL || slots == NULL) {
    free(groups);
    free(slots);
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  status = ftun_monotonic_now(&now_ms);
  for (index = 0u; status == FTUN_OK && index < config->outbound_count;
       index++) {
    const ftun_config_outbound_t *item = &config->outbounds[index];
    ftun_engine_health_group_t *group;
    size_t member;
    if (item->kind != FTUN_CONFIG_OUTBOUND_URL_TEST ||
        (config->plan->outbound_states[index] &
         FTUN_PLAN_ITEM_REACHABLE) == 0u) continue;
    group = &groups[group_cursor];
    group->outbound_index = index;
    group->slot_start = slot_cursor;
    group->slot_count = item->members.count;
    group->group_id = (uint32_t)index + FTUN_OUTBOUND_ID_NAMED_BASE;
    group->lazy = item->lazy;
    group->consumed = !item->lazy;
    group->selected_since_ms = now_ms;
    if (!ftun_engine_duration_ms(item->interval, &group->interval_ms) ||
        !ftun_engine_duration_ms(item->timeout, &group->timeout_ms)) {
      status = FTUN_E_INVALID;
      break;
    }
    for (member = 0u; member < item->members.count; member++, slot_cursor++) {
      ftun_engine_health_slot_t *slot = &slots[slot_cursor];
      slot->engine = engine;
      slot->group_index = group_cursor;
      slot->generation = generation;
      slot->schedule.consumers = group->consumed ? 1u : 0u;
      slot->schedule.next_due_ms = group->consumed ? now_ms : 0u;
      status = ftun_engine_config_outbound_id(config,
        item->members.items[member], &slot->member_id);
      if (status != FTUN_OK) break;
      slot->sample.member_id = slot->member_id;
      slot->sample.tcp_only = true;
    }
    group_cursor++;
  }
  if (status != FTUN_OK) {
    free(groups);
    free(slots);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  *out_groups = groups;
  *out_group_count = group_count;
  *out_slots = slots;
  *out_slot_count = slot_count;
  *out_reservation = reservation;
  return FTUN_OK;
}

static ftun_status_t ftun_engine_health_release(
  ftun_engine_health_group_t **groups,
  ftun_engine_health_slot_t **slots,
  size_t slot_count, ftun_reservation_t **reservation)
{
  size_t index;
  if (groups == NULL || slots == NULL || reservation == NULL) {
    return FTUN_E_INVALID;
  }
  if (*slots != NULL) {
    for (index = 0u; index < slot_count; index++) {
      if ((*slots)[index].operation != NULL) return FTUN_E_AGAIN;
    }
  }
  free(*groups);
  free(*slots);
  *groups = NULL;
  *slots = NULL;
  return ftun_reservation_release(reservation);
}

static void ftun_engine_health_consume(ftun_engine_t *engine,
                                       uint32_t group_id)
{
  size_t index;
  uint64_t now_ms;
  if (engine == NULL || ftun_monotonic_now(&now_ms) != FTUN_OK) return;
  for (index = 0u; index < engine->health_group_count; index++) {
    ftun_engine_health_group_t *group = &engine->health_groups[index];
    size_t member;
    if (group->group_id != group_id || group->consumed) continue;
    group->consumed = true;
    for (member = 0u; member < group->slot_count; member++) {
      ftun_engine_health_slot_t *slot =
        &engine->health_slots[group->slot_start + member];
      slot->schedule.consumers = 1u;
      slot->schedule.next_due_ms = now_ms;
    }
    return;
  }
}

static ftun_status_t ftun_engine_health_publish(
  ftun_engine_health_slot_t *completed, uint64_t now_ms)
{
  ftun_engine_t *engine = completed->engine;
  ftun_engine_health_group_t *group;
  ftun_runtime_t *runtime = NULL;
  const ftun_config_t *config = NULL;
  const ftun_config_outbound_t *item;
  ftun_health_sample_t *samples = NULL;
  uint32_t *members = NULL;
  ftun_health_snapshot_t snapshot;
  ftun_group_spec_t spec;
  ftun_group_choice_t choice;
  ftun_health_sample_t selected_sample;
  ftun_string_t dns_server;
  uint32_t previous = 0u;
  bool is_group = false;
  bool degraded = false;
  size_t index;
  ftun_status_t status;
  if (completed->group_index >= engine->health_group_count) {
    return FTUN_E_STATE_CORRUPT;
  }
  group = &engine->health_groups[completed->group_index];
  status = ftun_runtime_active_acquire(engine->core, &runtime);
  if (status == FTUN_OK) status = ftun_runtime_config(runtime, &config);
  if (status == FTUN_OK && (completed->generation != engine->generation ||
      group->outbound_index >= config->outbound_count)) status = FTUN_E_STALE;
  if (status != FTUN_OK) goto done;
  item = &config->outbounds[group->outbound_index];
  members = (uint32_t *)calloc(group->slot_count, sizeof(*members));
  samples = (ftun_health_sample_t *)calloc(group->slot_count,
                                            sizeof(*samples));
  if (members == NULL || samples == NULL) {
    status = FTUN_E_LIMIT;
    goto done;
  }
  for (index = 0u; index < group->slot_count; index++) {
    ftun_engine_health_slot_t *slot =
      &engine->health_slots[group->slot_start + index];
    members[index] = slot->member_id;
    samples[index] = slot->sample;
  }
  status = ftun_runtime_group_selected(runtime, group->group_id, &previous,
                                        &is_group, &degraded, &dns_server);
  (void)degraded;
  (void)dns_server;
  if (status == FTUN_OK && !is_group) status = FTUN_E_STATE_CORRUPT;
  memset(&snapshot, 0, sizeof(snapshot));
  snapshot.generation = engine->generation;
  snapshot.samples = samples;
  snapshot.sample_count = group->slot_count;
  memset(&spec, 0, sizeof(spec));
  spec.generation = engine->generation;
  spec.group_id = group->group_id;
  spec.members = members;
  spec.member_count = group->slot_count;
  spec.previous_member_id = previous;
  spec.previous_since_ms = group->selected_since_ms;
  spec.now_ms = now_ms;
  spec.sample_max_age_ms = group->interval_ms > UINT64_MAX / 2u
    ? UINT64_MAX : group->interval_ms * 2u;
  spec.minimum_hold_ms = group->interval_ms;
  spec.tolerance_ms = item->tolerance_ms;
  status = ftun_engine_config_outbound_id(config, item->default_member,
                                           &spec.default_member_id);
  if (status == FTUN_OK) status = ftun_url_test_choose(&spec, &snapshot,
                                                       &choice);
  memset(&selected_sample, 0, sizeof(selected_sample));
  if (status == FTUN_OK) {
    selected_sample.member_id = choice.leaf_id;
    selected_sample.tcp_only = true;
    for (index = 0u; index < group->slot_count; index++) {
      if (samples[index].member_id == choice.leaf_id) {
        selected_sample = samples[index];
        break;
      }
    }
    status = ftun_runtime_group_publish_health(engine->core,
      group->group_id, &choice, &selected_sample);
    if (status == FTUN_OK && choice.leaf_id != previous) {
      group->selected_since_ms = now_ms;
    }
  }
done:
  free(samples);
  free(members);
  (void)ftun_runtime_release(&runtime);
  return status;
}

static void ftun_engine_health_completed(ftun_operation_t *operation,
                                         ftun_error_t error,
                                         ftun_bytes_t result, void *user)
{
  ftun_engine_health_slot_t *slot =
    (ftun_engine_health_slot_t *)user;
  ftun_engine_t *engine;
  ftun_engine_health_group_t *group;
  const ftun_engine_http_result_t *response = NULL;
  const ftun_config_t *config = NULL;
  ftun_runtime_t *runtime = NULL;
  uint64_t now_ms = 0u;
  uint64_t maximum_backoff;
  bool success = false;
  ftun_status_t status = error.status;
  if (slot == NULL || slot->operation != operation || slot->engine == NULL) {
    return;
  }
  engine = slot->engine;
  slot->operation = NULL;
  if (slot->group_index >= engine->health_group_count || engine->stopped ||
      slot->generation != engine->generation) return;
  group = &engine->health_groups[slot->group_index];
  (void)ftun_monotonic_now(&now_ms);
  if (status == FTUN_OK && result.data != NULL &&
      result.length >= sizeof(*response)) {
    response = (const ftun_engine_http_result_t *)result.data;
    if (response->etag_length <= FTUN_ENGINE_HTTP_ETAG_BYTES &&
        response->body_length <= SIZE_MAX &&
        response->etag_length <= result.length - sizeof(*response) &&
        (size_t)response->body_length == result.length - sizeof(*response) -
                                         response->etag_length) {
      status = ftun_runtime_active_acquire(engine->core, &runtime);
      if (status == FTUN_OK) status = ftun_runtime_config(runtime, &config);
      if (status == FTUN_OK && group->outbound_index < config->outbound_count) {
        const ftun_config_outbound_t *item =
          &config->outbounds[group->outbound_index];
        success = response->status == item->expected_status &&
          (item->url == NULL || strncmp(item->url, "https://", 8u) != 0 ||
           response->tls_verified != 0u);
      }
    } else {
      status = FTUN_E_PROTOCOL;
    }
  }
  (void)ftun_runtime_release(&runtime);
  memset(&slot->sample, 0, sizeof(slot->sample));
  slot->sample.member_id = slot->member_id;
  slot->sample.tcp_only = true;
  slot->sample.success = status == FTUN_OK && success;
  slot->sample.observed_ms = now_ms;
  if (now_ms >= slot->started_ms) {
    uint64_t latency = now_ms - slot->started_ms;
    slot->sample.latency_ms = latency > UINT32_MAX
      ? UINT32_MAX : (uint32_t)latency;
  }
  maximum_backoff = group->interval_ms > UINT64_MAX / 16u
    ? UINT64_MAX : group->interval_ms * 16u;
  (void)ftun_health_schedule(&slot->schedule, now_ms, group->interval_ms,
                              maximum_backoff,
                              slot->member_id ^ (uint32_t)now_ms,
                              slot->sample.success);
  status = ftun_engine_health_publish(slot, now_ms);
  if (status != FTUN_OK && status != FTUN_E_STALE) {
#if defined(FTUN_HAVE_MODULE_FRS)
    ftun_engine_background_log(engine, status,
                               "URL-Test result publish failed");
#endif
  }
}

static ftun_status_t ftun_engine_health_run(ftun_engine_t *engine)
{
  ftun_runtime_t *runtime = NULL;
  const ftun_config_t *config = NULL;
  size_t index;
  ftun_status_t status;
  if (engine == NULL || engine->health_slot_count == 0u) return FTUN_OK;
  status = ftun_runtime_active_acquire(engine->core, &runtime);
  if (status == FTUN_OK) status = ftun_runtime_config(runtime, &config);
  for (index = 0u; status == FTUN_OK && index < engine->health_slot_count;
       index++) {
    ftun_engine_health_slot_t *slot = &engine->health_slots[index];
    ftun_engine_health_group_t *group =
      &engine->health_groups[slot->group_index];
    const ftun_config_outbound_t *item;
    ftun_http_fetch_spec_t spec;
    if (!group->consumed || slot->operation != NULL ||
        engine->now_ms < slot->schedule.next_due_ms) continue;
    if (group->outbound_index >= config->outbound_count ||
        index - group->slot_start >= group->slot_count) {
      status = FTUN_E_STATE_CORRUPT;
      break;
    }
    item = &config->outbounds[group->outbound_index];
    memset(&spec, 0, sizeof(spec));
    spec.budget = engine->budget;
    spec.url.data = item->url;
    spec.url.length = strlen(item->url);
    spec.maximum_bytes = 64u * 1024u;
    spec.socket_mark = engine->socket_mark;
    if (group->timeout_ms > UINT64_MAX - engine->now_ms) {
      status = FTUN_E_LIMIT;
      break;
    }
    spec.deadline_ms = engine->now_ms + group->timeout_ms;
    status = ftun_http_fetch_resolver(config, runtime,
      (ftun_string_t){NULL, 0u}, &spec);
    if (status == FTUN_OK) {
      status = ftun_http_fetch_route(config, runtime,
        item->members.items[index - group->slot_start], &spec);
    }
    if (status == FTUN_OK) {
      slot->started_ms = engine->now_ms;
      slot->generation = engine->generation;
      status = ftun_engine_http_submit(engine, &spec, false, NULL,
        ftun_engine_health_completed, slot, &slot->operation);
    }
    if (status != FTUN_OK) {
      uint64_t maximum_backoff = group->interval_ms > UINT64_MAX / 16u
        ? UINT64_MAX : group->interval_ms * 16u;
      (void)ftun_health_schedule(&slot->schedule, engine->now_ms,
        group->interval_ms, maximum_backoff,
        slot->member_id ^ (uint32_t)engine->now_ms, false);
      status = FTUN_OK;
    }
  }
  (void)ftun_runtime_release(&runtime);
  return status;
}

static void ftun_engine_background_log(ftun_engine_t *engine,
                                       ftun_status_t status,
                                       const char *message)
{
  ftun_diagnostic_t diagnostic;
  if (engine == NULL || message == NULL) return;
  memset(&diagnostic, 0, sizeof(diagnostic));
  diagnostic.error.status = status;
  diagnostic.error.stage = FTUN_STAGE_CONTROL;
  diagnostic.message.data = message;
  diagnostic.message.length = strlen(message);
  (void)ftun_log_emit(engine->core, &diagnostic);
}

#if defined(FTUN_HAVE_MODULE_FRS)
static ftun_status_t ftun_engine_replace_etag(ftun_engine_t *engine,
                                               const uint8_t *value,
                                               size_t length)
{
  char *copy = NULL;
  if (engine == NULL || (length != 0u && value == NULL)) {
    return FTUN_E_INVALID;
  }
  if (length != 0u) {
    copy = (char *)malloc(length + 1u);
    if (copy == NULL) return FTUN_E_LIMIT;
    memcpy(copy, value, length);
    copy[length] = '\0';
  }
  free(engine->frs_etag);
  engine->frs_etag = copy;
  return FTUN_OK;
}

static ftun_status_t ftun_engine_frs_publish_execute(
  ftun_bytes_t input, uint8_t *result, size_t result_capacity,
  size_t *out_result_size)
{
  const ftun_engine_frs_publish_work_t *work;
  ftun_engine_frs_publish_result_t output;
  ftun_engine_file_publish_t publish;
  const char *path;
  const uint8_t *body;
  size_t expected;
  ftun_status_t status;
  if (out_result_size != NULL) *out_result_size = 0u;
  if (input.data == NULL || input.length < sizeof(*work) || result == NULL ||
      result_capacity < sizeof(output) || out_result_size == NULL) {
    return FTUN_E_INVALID;
  }
  work = (const ftun_engine_frs_publish_work_t *)input.data;
  if (work->magic != FTUN_ENGINE_FRS_PUBLISH_MAGIC ||
      work->path_length == 0u || work->body_length > SIZE_MAX) {
    return FTUN_E_INVALID;
  }
  expected = sizeof(*work);
  if ((size_t)work->path_length > SIZE_MAX - expected - 1u) {
    return FTUN_E_LIMIT;
  }
  expected += (size_t)work->path_length + 1u;
  if ((size_t)work->body_length > SIZE_MAX - expected) return FTUN_E_LIMIT;
  expected += (size_t)work->body_length;
  if (expected != input.length) return FTUN_E_INVALID;
  path = (const char *)input.data + sizeof(*work);
  if (path[work->path_length] != '\0' ||
      memchr(path, '\0', work->path_length) != NULL) {
    return FTUN_E_INVALID;
  }
  body = input.data + sizeof(*work) + work->path_length + 1u;
  memset(&publish, 0, sizeof(publish));
  status = ftun_file_write_atomic_with_hook(path,
    (ftun_bytes_t){body, (size_t)work->body_length}, 0644u,
    ftun_engine_file_stage, &publish);
  output.status = (int32_t)status;
  output.reached = (uint32_t)publish.reached;
  memcpy(result, &output, sizeof(output));
  *out_result_size = sizeof(output);
  /* 发布失败作为数据返回 owner。这里返回成功以保留已到达阶段，使
   * “替换成功、同步失败”表现为耐久性警告，而不是误判为没有替换。 */
  return FTUN_OK;
}

static ftun_status_t ftun_engine_frs_publish_submit(
  ftun_engine_t *engine, const char *path, ftun_bytes_t body,
  ftun_worker_completion_fn completion, ftun_operation_t **out)
{
  ftun_engine_frs_publish_work_t *work;
  ftun_worker_job_t job;
  uint8_t *input;
  size_t path_length;
  size_t input_length;
  ftun_reservation_t *input_reservation = NULL;
  ftun_status_t release_status;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (engine == NULL || path == NULL || path[0] == '\0' ||
      (body.length != 0u && body.data == NULL) || completion == NULL ||
      out == NULL) return FTUN_E_INVALID;
  path_length = strlen(path);
  if (path_length > UINT32_MAX || body.length > UINT64_MAX ||
      path_length > SIZE_MAX - sizeof(*work) - 1u ||
      body.length > SIZE_MAX - sizeof(*work) - path_length - 1u) {
    return FTUN_E_LIMIT;
  }
  input_length = sizeof(*work) + path_length + 1u + body.length;
  status = ftun_budget_reserve(engine->budget, input_length,
                               &input_reservation);
  if (status != FTUN_OK) return status;
  input = (uint8_t *)malloc(input_length);
  if (input == NULL) {
    (void)ftun_reservation_release(&input_reservation);
    return FTUN_E_LIMIT;
  }
  work = (ftun_engine_frs_publish_work_t *)input;
  memset(work, 0, sizeof(*work));
  work->magic = FTUN_ENGINE_FRS_PUBLISH_MAGIC;
  work->path_length = (uint32_t)path_length;
  work->body_length = body.length;
  memcpy(input + sizeof(*work), path, path_length + 1u);
  if (body.length != 0u) {
    memcpy(input + sizeof(*work) + path_length + 1u, body.data, body.length);
  }
  memset(&job, 0, sizeof(job));
  job.execute = ftun_engine_frs_publish_execute;
  job.input.data = input;
  job.input.length = input_length;
  job.result_capacity = sizeof(ftun_engine_frs_publish_result_t);
  status = ftun_worker_submit(engine->maintenance_worker, &job, completion,
                              engine, out);
  free(input);
  release_status = ftun_reservation_release(&input_reservation);
  if (status != FTUN_OK && release_status != FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
  }
  return status;
}

static void ftun_engine_frs_schedule_next(ftun_engine_t *engine,
                                           uint64_t now_ms)
{
  if (now_ms != 0u && engine->frs_interval_ms <= UINT64_MAX - now_ms) {
    engine->frs_due_ms = now_ms + engine->frs_interval_ms;
  } else {
    engine->frs_due_ms = UINT64_MAX;
  }
}

static void ftun_engine_frs_publish_completed(ftun_operation_t *operation,
                                               ftun_error_t error,
                                               ftun_bytes_t result,
                                               void *user)
{
  ftun_engine_t *engine = (ftun_engine_t *)user;
  const ftun_engine_frs_publish_result_t *published = NULL;
  ftun_runtime_t *active = NULL;
  ftun_runtime_info_t info;
  uint64_t now_ms = 0u;
  ftun_status_t status = error.status;
  ftun_status_t durability_status = FTUN_OK;
  if (engine == NULL || engine->frs_operation != operation) return;
  engine->frs_operation = NULL;
  (void)ftun_monotonic_now(&now_ms);
  if (!engine->frs_enabled || engine->stopped ||
      engine->frs_candidate == NULL) {
    status = FTUN_E_CANCELLED;
  }
  if (status == FTUN_OK) {
    if (result.data == NULL || result.length != sizeof(*published)) {
      status = FTUN_E_PROTOCOL;
    } else {
      published = (const ftun_engine_frs_publish_result_t *)result.data;
      status = (ftun_status_t)published->status;
      if (status != FTUN_OK &&
          published->reached >= (uint32_t)FTUN_FILE_STAGE_RENAMED) {
        durability_status = status;
        status = FTUN_OK;
      }
    }
  }
  if (status == FTUN_OK) {
    status = ftun_runtime_active_acquire(engine->core, &active);
  }
  if (status == FTUN_OK) status = ftun_runtime_get_info(active, &info);
  if (status == FTUN_OK && (info.generation != engine->generation ||
      info.generation != engine->frs_operation_generation)) {
    status = FTUN_E_STALE;
  }
  (void)ftun_runtime_release(&active);
  if (status == FTUN_OK) {
    status = ftun_runtime_can_commit(engine->core, engine->frs_candidate);
  }
  if (status == FTUN_OK) {
    status = ftun_runtime_commit(engine->core, &engine->frs_candidate);
  }
  if (status == FTUN_OK) {
    status = ftun_engine_reload_commit(
      engine, engine->frs_operation_generation + 1u);
  }
  if (status == FTUN_OK) {
    size_t length = engine->frs_candidate_etag == NULL ? 0u :
      strlen(engine->frs_candidate_etag);
    status = ftun_engine_replace_etag(engine,
      (const uint8_t *)engine->frs_candidate_etag, length);
  }
  if (engine->frs_candidate != NULL) {
    (void)ftun_runtime_abort(engine->core, &engine->frs_candidate);
  }
  if (engine->reload_prepared) (void)ftun_engine_reload_abort(engine);
  free(engine->frs_candidate_etag);
  engine->frs_candidate_etag = NULL;
  ftun_engine_frs_schedule_next(engine, now_ms);
  if (status != FTUN_OK && status != FTUN_E_STALE &&
      status != FTUN_E_CANCELLED) {
    ftun_engine_background_log(engine, status, "FRS update failed");
  } else if (status == FTUN_OK && durability_status != FTUN_OK) {
    ftun_engine_background_log(engine, durability_status,
      "FRS update applied but directory durability is uncertain");
  }
}

static void ftun_engine_frs_completed(ftun_operation_t *operation,
                                      ftun_error_t error,
                                      ftun_bytes_t result, void *user)
{
  ftun_engine_t *engine = (ftun_engine_t *)user;
  ftun_engine_http_result_t *response = NULL;
  const uint8_t *etag = NULL;
  const uint8_t *body = NULL;
  ftun_runtime_t *baseline = NULL;
  ftun_runtime_t *candidate = NULL;
  ftun_runtime_t *prepared = NULL;
  const ftun_config_t *config = NULL;
  ftun_runtime_info_t info;
  ftun_runtime_group_record_t *records = NULL;
  char *candidate_etag = NULL;
  size_t record_count = 0u;
  size_t index;
  uint64_t now_ms = 0u;
  ftun_status_t status = error.status;
  bool unchanged = false;
  bool publish_scheduled = false;
  if (engine == NULL || engine->frs_operation != operation) return;
  engine->frs_operation = NULL;
  (void)ftun_monotonic_now(&now_ms);
  if (!engine->frs_enabled || engine->stopped ||
      engine->frs_operation_generation != engine->generation) {
    return;
  }
  if (status == FTUN_OK) {
    if (result.data == NULL || result.length < sizeof(*response)) {
      status = FTUN_E_PROTOCOL;
    } else {
      response = (ftun_engine_http_result_t *)(uintptr_t)result.data;
      if (response->etag_length > FTUN_ENGINE_HTTP_ETAG_BYTES ||
          response->body_length > SIZE_MAX ||
          response->etag_length > result.length - sizeof(*response) ||
          result.length != sizeof(*response) + response->etag_length ||
          (response->status == 200u && response->prepared_runtime == 0u) ||
          (response->status != 200u && response->prepared_runtime != 0u)) {
        status = FTUN_E_PROTOCOL;
      } else {
        ftun_bytes_t prepared_bytes;
        etag = result.data + sizeof(*response);
        if (response->prepared_runtime != 0u) {
          prepared = (ftun_runtime_t *)response->prepared_runtime;
          status = ftun_runtime_prepared_frs_bytes(prepared,
                                                    &prepared_bytes);
          if (status == FTUN_OK &&
              prepared_bytes.length != (size_t)response->body_length) {
            status = FTUN_E_PROTOCOL;
          }
          if (status == FTUN_OK) {
            body = prepared_bytes.data;
            response->prepared_runtime = 0u;
          } else {
            prepared = NULL;
          }
        } else if (response->body_length != 0u) {
          status = FTUN_E_PROTOCOL;
        }
      }
    }
  }
  if (status == FTUN_OK) {
    status = ftun_runtime_active_acquire(engine->core, &baseline);
  }
  if (status == FTUN_OK) status = ftun_runtime_get_info(baseline, &info);
  if (status == FTUN_OK && (info.generation != engine->generation ||
      info.generation != engine->frs_operation_generation)) {
    status = FTUN_E_STALE;
  }
  if (status == FTUN_OK) status = ftun_runtime_config(baseline, &config);
  if (status == FTUN_OK && response->status == 304u) {
    if (engine->frs_etag == NULL) status = FTUN_E_PROTOCOL;
    else unchanged = true;
  } else if (status == FTUN_OK && response->status != 200u) {
    status = FTUN_E_PROTOCOL;
  }
  if (status == FTUN_OK && !unchanged) {
    ftun_frs_view_t *old_view = NULL;
    ftun_bytes_t old_bytes;
    if (ftun_runtime_frs_view(baseline, &old_view) == FTUN_OK &&
        ftun_frs_view_bytes(old_view, &old_bytes) == FTUN_OK &&
        old_bytes.length == (size_t)response->body_length &&
        memcmp(old_bytes.data, body, old_bytes.length) == 0) {
      unchanged = true;
    }
  }
  if (status == FTUN_OK && !unchanged) {
    status = ftun_runtime_attach_prepared(engine->core, &prepared,
                                          &candidate);
  }
  if (status == FTUN_OK && !unchanged) {
    ftun_status_t records_status = ftun_runtime_group_records(
      engine->core, NULL, 0u, &record_count);
    if (records_status != FTUN_OK && records_status != FTUN_E_LIMIT) {
      status = records_status;
    }
    if (status == FTUN_OK && record_count != 0u) {
      records = (ftun_runtime_group_record_t *)calloc(
        record_count, sizeof(*records));
      if (records == NULL) status = FTUN_E_LIMIT;
      else status = ftun_runtime_group_records(engine->core, records,
                                                record_count, &record_count);
    }
    for (index = 0u; status == FTUN_OK && index < record_count; index++) {
      status = ftun_runtime_candidate_group_restore(engine->core,
                                                     &records[index], true);
    }
  }
  if (status == FTUN_OK && !unchanged) {
    status = ftun_engine_reload_prepare(engine, config, info.generation + 1u);
  }
  if (status == FTUN_OK && !unchanged) {
    status = ftun_runtime_can_commit(engine->core, candidate);
  }
  if (status == FTUN_OK && !unchanged) {
    if (response->etag_length != 0u) {
      candidate_etag = (char *)malloc(response->etag_length + 1u);
      if (candidate_etag == NULL) status = FTUN_E_LIMIT;
      else {
        memcpy(candidate_etag, etag, response->etag_length);
        candidate_etag[response->etag_length] = '\0';
      }
    }
  }
  if (status == FTUN_OK && !unchanged) {
    status = ftun_engine_frs_publish_submit(engine, config->frs.path,
      (ftun_bytes_t){body, (size_t)response->body_length},
      ftun_engine_frs_publish_completed, &engine->frs_operation);
    if (status == FTUN_OK) {
      engine->frs_candidate = candidate;
      candidate = NULL;
      engine->frs_candidate_etag = candidate_etag;
      candidate_etag = NULL;
      publish_scheduled = true;
    }
  }
  if (status == FTUN_OK && unchanged) {
    status = ftun_engine_replace_etag(engine, etag,
                                      response->etag_length);
  }
  if (candidate != NULL) (void)ftun_runtime_abort(engine->core, &candidate);
  if (!publish_scheduled && engine->reload_prepared) {
    (void)ftun_engine_reload_abort(engine);
  }
  free(candidate_etag);
  free(records);
  (void)ftun_runtime_prepared_release(&prepared);
  (void)ftun_runtime_release(&baseline);
  if (publish_scheduled) return;
  ftun_engine_frs_schedule_next(engine, now_ms);
  if (status != FTUN_OK && status != FTUN_E_STALE &&
      status != FTUN_E_CANCELLED) {
    ftun_engine_background_log(engine, status, "FRS update failed");
  }
}

static ftun_status_t ftun_engine_frs_schedule(ftun_engine_t *engine)
{
  ftun_runtime_t *runtime = NULL;
  const ftun_config_t *config = NULL;
  ftun_runtime_info_t info;
  ftun_budget_usage_t usage;
  ftun_http_fetch_spec_t spec;
  size_t runtime_accounted = 0u;
  size_t fixed_update_bytes;
  ftun_status_t status;
  if (engine == NULL || !engine->frs_enabled ||
      engine->frs_operation != NULL) return FTUN_OK;
  status = ftun_runtime_active_acquire(engine->core, &runtime);
  if (status == FTUN_OK) status = ftun_runtime_get_info(runtime, &info);
  if (status == FTUN_OK && info.generation != engine->generation) {
    status = FTUN_E_STALE;
  }
  if (status == FTUN_OK) status = ftun_runtime_config(runtime, &config);
  if (status == FTUN_OK) status = ftun_budget_get_usage(engine->budget, &usage);
  if (status == FTUN_OK) {
    status = ftun_runtime_accounted_bytes(config, &runtime_accounted);
  }
  if (runtime_accounted > (SIZE_MAX - 2u * 1024u * 1024u) / 2u) {
    status = FTUN_E_LIMIT;
  }
  fixed_update_bytes = status == FTUN_OK
    ? 2u * 1024u * 1024u + runtime_accounted * 2u : 0u;
  if (status == FTUN_OK &&
      (usage.normal_available <= fixed_update_bytes ||
       usage.normal_available - fixed_update_bytes <=
         FTUN_FRS_HEADER_BYTES * 9u)) status = FTUN_E_LIMIT;
  memset(&spec, 0, sizeof(spec));
  if (status == FTUN_OK) {
    spec.budget = engine->budget;
    spec.url.data = config->frs.url;
    spec.url.length = strlen(config->frs.url);
    /* 更新任务在下载前同时为 HTTP 临时空间、FRS 校验、脱离态候选与
     * owner 接管期的新旧对象重叠预留额度。上限只由当前用户预算推导，
     * 不引入固定 FRS 文件大小限制。 */
    spec.maximum_bytes =
      (usage.normal_available - fixed_update_bytes) / 9u;
    spec.socket_mark = engine->socket_mark;
    if (engine->now_ms > UINT64_MAX - UINT64_C(30000)) status = FTUN_E_LIMIT;
    else spec.deadline_ms = engine->now_ms + UINT64_C(30000);
    if (engine->frs_etag != NULL) {
      spec.if_none_match.data = engine->frs_etag;
      spec.if_none_match.length = strlen(engine->frs_etag);
    }
  }
  if (status == FTUN_OK) {
    ftun_string_t resolver = {NULL, 0u};
    if (config->frs.dns_server != NULL &&
        config->frs.dns_server[0] != '\0') {
      resolver.data = config->frs.dns_server;
      resolver.length = strlen(config->frs.dns_server);
    }
    status = ftun_http_fetch_resolver(config, runtime, resolver, &spec);
  }
  if (status == FTUN_OK) {
    status = ftun_http_fetch_route(config, runtime,
      config->frs.update_outbound, &spec);
  }
  if (status == FTUN_OK) {
    engine->frs_operation_generation = engine->generation;
    status = ftun_engine_http_submit(engine, &spec, true, runtime,
      ftun_engine_frs_completed, engine, &engine->frs_operation);
  }
  (void)ftun_runtime_release(&runtime);
  return status;
}
#endif

ftun_status_t ftun_engine_prepare(ftun_core_t *core, ftun_budget_t *budget,
                                  ftun_operation_queue_t *operations,
                                  const ftun_config_t *config,
                                  uint64_t generation,
                                  ftun_engine_t **out)
{
  ftun_engine_t *engine;
  ftun_reservation_t *reservation = NULL;
  ftun_udp_flow_table_spec_t flow_spec;
  bool udp_required = false;
  bool tun_required = false;
  size_t index;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core == NULL || budget == NULL || operations == NULL || config == NULL ||
      generation == 0u || out == NULL) return FTUN_E_INVALID;
  if (config->inbound_count > FTUN_ENGINE_MAX_LISTENERS) return FTUN_E_LIMIT;
  status = ftun_budget_reserve(budget, sizeof(*engine), &reservation);
  if (status != FTUN_OK) return status;
  engine = (ftun_engine_t *)calloc(1u, sizeof(*engine));
  if (engine == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  engine->core = core;
  engine->budget = budget;
  engine->reservation = reservation;
  engine->operations = operations;
  engine->generation = generation;
#if defined(FTUN_HAVE_MODULE_FRS)
  if (config->frs.active && config->frs.auto_update &&
      config->frs.url != NULL && config->frs.url[0] != '\0') {
    if (!ftun_engine_duration_ms(config->frs.update_interval,
                                 &engine->frs_interval_ms) ||
        ftun_monotonic_now(&engine->now_ms) != FTUN_OK ||
        engine->frs_interval_ms > UINT64_MAX - engine->now_ms) {
      status = FTUN_E_INVALID;
      goto fail;
    }
    engine->frs_due_ms = engine->now_ms + engine->frs_interval_ms;
    engine->frs_enabled = true;
  }
#endif
  for (index = 0u; index < FTUN_ENGINE_MAX_LISTENERS; index++) {
    engine->listeners[index].descriptor = -1;
    engine->listeners[index].udp_descriptor = -1;
  }
  for (index = 0u; index < FTUN_ENGINE_MAX_TCP_FLOWS; index++) {
    engine->flows[index].client_socket.descriptor = -1;
    engine->flows[index].remote_socket.descriptor = -1;
  }
  for (index = 0u; index < FTUN_ENGINE_MAX_UDP_FLOWS; index++) {
    engine->udp[index].descriptor = -1;
  }
  for (index = 0u; index < config->inbound_count; index++) {
    if (config->inbounds[index].udp) udp_required = true;
    if (config->inbounds[index].kind == FTUN_CONFIG_INBOUND_TUN) {
      tun_required = true;
    }
  }
  engine->socket_mark = tun_required ? FTUN_ENGINE_SOCKET_MARK : 0u;
  status = ftun_engine_health_prepare(engine, config, generation,
    &engine->health_groups, &engine->health_group_count,
    &engine->health_slots, &engine->health_slot_count,
    &engine->health_reservation);
  if (status == FTUN_OK) {
    status = ftun_worker_create(budget, 64u, &engine->worker);
  }
  if (status == FTUN_OK) {
    status = ftun_worker_create(budget, 16u, &engine->maintenance_worker);
  }
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  if (status == FTUN_OK &&
      (config->plan->prepare & FTUN_PLAN_FAKE_IP) != 0u &&
      config->dns.fake_ip.persist) {
    status = ftun_worker_create(budget, 2u, &engine->fakeip_worker);
  }
#endif
  if (status == FTUN_OK) {
    status = ftun_buffer_pool_create(budget, FTUN_ENGINE_RELAY_POOL_BYTES,
      FTUN_ENGINE_RELAY_POOL_BUFFERS, &engine->relay_pool);
  }
  if (status == FTUN_OK) status = ftun_event_loop_create(core, &engine->loop);
  if (status == FTUN_OK) status = ftun_libev_attach(engine->loop);
  if (status == FTUN_OK) {
    status = ftun_worker_set_wakeup(engine->worker,
      ftun_engine_worker_wakeup, engine->loop);
  }
  if (status == FTUN_OK) {
    status = ftun_worker_set_wakeup(engine->maintenance_worker,
      ftun_engine_worker_wakeup, engine->loop);
  }
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  if (status == FTUN_OK && engine->fakeip_worker != NULL) {
    status = ftun_worker_set_wakeup(engine->fakeip_worker,
      ftun_engine_worker_wakeup, engine->loop);
  }
#endif
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  if (status == FTUN_OK) status = ftun_engine_fakeip_prepare(engine, config);
#endif
  if (status == FTUN_OK) {
    status = ftun_engine_dns_prepare(core, budget, operations, engine->worker,
                                     config,
#if defined(FTUN_HAVE_MODULE_FAKEIP)
                                     engine->fakeip,
#else
                                     NULL,
#endif
                                     engine->socket_mark,
                                     &engine->dns);
  }
  if (status == FTUN_OK && udp_required) {
    status = ftun_monotonic_now(&engine->now_ms);
    memset(&flow_spec, 0, sizeof(flow_spec));
    flow_spec.core = core;
    flow_spec.budget = budget;
    flow_spec.capacity = FTUN_ENGINE_MAX_UDP_FLOWS;
    flow_spec.idle_timeout_ms = UINT64_C(120000);
    flow_spec.now_ms = engine->now_ms;
    flow_spec.backend.open = ftun_engine_udp_open;
    flow_spec.backend.reply = ftun_engine_udp_reply;
    flow_spec.backend.user = engine;
    if (status == FTUN_OK) {
      status = ftun_udp_flow_table_create(&flow_spec, &engine->udp_flows);
    }
  }
  if (status != FTUN_OK) goto fail;
  for (index = 0u; index < config->inbound_count; index++) {
    const ftun_config_inbound_t *inbound = &config->inbounds[index];
    ftun_engine_listener_t *listener;
    if (inbound->kind == FTUN_CONFIG_INBOUND_TUN) {
      #if defined(FTUN_HAVE_MODULE_TUN)
      status = ftun_engine_tun_prepare(engine, inbound,
                                        (uint32_t)index + 1u);
      if (status == FTUN_OK && engine->tun_info.native_socket <=
          (ftun_native_socket_t)INT_MAX) {
        status = ftun_event_io_start(engine->loop,
          engine->tun_info.native_socket,
          FTUN_EVENT_READ | FTUN_EVENT_ERROR, ftun_engine_tun_ready, engine,
          &engine->tun_source);
      }
      if (status != FTUN_OK) goto fail;
      continue;
      #else
      status = FTUN_E_UNSUPPORTED;
      goto fail;
      #endif
    }
    listener = &engine->listeners[engine->listener_count];
    listener->engine = engine;
    status = ftun_engine_listener_open(listener, inbound,
                                        (uint32_t)index + 1u);
    if (status != FTUN_OK) goto fail;
    engine->listener_count++;
    status = ftun_event_io_start(engine->loop,
      (ftun_native_socket_t)(unsigned int)listener->descriptor,
      FTUN_EVENT_READ | FTUN_EVENT_ERROR, ftun_engine_listener_ready,
      listener, &listener->source);
    if (status == FTUN_OK && listener->udp_descriptor >= 0) {
      status = ftun_event_io_start(engine->loop,
        (ftun_native_socket_t)(unsigned int)listener->udp_descriptor,
        FTUN_EVENT_READ | FTUN_EVENT_ERROR,
        ftun_engine_listener_udp_ready, listener, &listener->udp_source);
    }
    if (status != FTUN_OK) goto fail;
  }
  *out = engine;
  return FTUN_OK;

fail:
  (void)ftun_engine_destroy(&engine);
  return status;
}

ftun_status_t ftun_engine_activate(ftun_engine_t *engine)
{
  ftun_status_t status;
  if (engine == NULL || engine->stopped) return FTUN_E_INVALID;
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  status = ftun_runtime_manager_set_fakeip(engine->core, engine->fakeip);
  if (status != FTUN_OK) return status;
#else
  status = FTUN_OK;
#endif
  if (status == FTUN_OK) status = ftun_engine_dns_activate(engine->dns);
  if (status == FTUN_OK) engine->accepting = true;
  return status;
}

ftun_status_t ftun_engine_reload_prepare_planned(
  ftun_engine_t *engine, const ftun_config_t *config, uint64_t generation,
  const ftun_engine_dns_plan_t *dns_plan)
{
  ftun_runtime_t *active_runtime = NULL;
  const ftun_config_t *active_config = NULL;
  ftun_status_t status;
  if (engine == NULL || config == NULL || generation == 0u ||
      engine->stopped || engine->reload_prepared) {
    return FTUN_E_INVALID;
  }
  if (generation <= engine->generation) return FTUN_E_STALE;
  status = ftun_engine_prepare_inbound_ids(engine, config);
  if (status != FTUN_OK) return status;
  status = ftun_runtime_active_acquire(engine->core, &active_runtime);
  if (status == FTUN_OK) {
    status = ftun_runtime_config(active_runtime, &active_config);
  }
  if (status == FTUN_OK) {
    engine->pending_health_reuse =
      ftun_engine_health_config_equal(active_config, config) != 0;
  }
  (void)ftun_runtime_release(&active_runtime);
  if (status != FTUN_OK) return status;
  if (!engine->pending_health_reuse) {
    size_t index;
    for (index = 0u; index < engine->health_slot_count; index++) {
      if (engine->health_slots[index].operation != NULL) return FTUN_E_AGAIN;
    }
    status = ftun_engine_health_prepare(engine, config, generation,
      &engine->pending_health_groups, &engine->pending_health_group_count,
      &engine->pending_health_slots, &engine->pending_health_slot_count,
      &engine->pending_health_reservation);
    if (status != FTUN_OK) return status;
  }
#if defined(FTUN_HAVE_MODULE_FRS)
  engine->pending_frs_enabled = config->frs.active &&
    config->frs.auto_update && config->frs.url != NULL &&
    config->frs.url[0] != '\0';
  engine->pending_frs_interval_ms = 0u;
  if (engine->pending_frs_enabled && !ftun_engine_duration_ms(
        config->frs.update_interval, &engine->pending_frs_interval_ms)) {
    engine->pending_frs_enabled = false;
    if (!engine->pending_health_reuse) {
      (void)ftun_engine_health_release(&engine->pending_health_groups,
        &engine->pending_health_slots, engine->pending_health_slot_count,
        &engine->pending_health_reservation);
    }
    engine->pending_health_group_count = 0u;
    engine->pending_health_slot_count = 0u;
    return FTUN_E_INVALID;
  }
#endif
  status = ftun_engine_dns_prepare_reload_planned(engine->dns, engine->core,
    engine->budget, engine->operations, engine->worker, config,
#if defined(FTUN_HAVE_MODULE_FAKEIP)
    engine->fakeip,
#else
    NULL,
#endif
    engine->socket_mark, dns_plan,
    &engine->pending_dns);
  if (status == FTUN_OK) engine->reload_prepared = true;
  else {
    if (!engine->pending_health_reuse) {
      (void)ftun_engine_health_release(&engine->pending_health_groups,
        &engine->pending_health_slots, engine->pending_health_slot_count,
        &engine->pending_health_reservation);
    }
    engine->pending_health_group_count = 0u;
    engine->pending_health_slot_count = 0u;
    engine->pending_health_reuse = false;
  }
  return status;
}

ftun_status_t ftun_engine_reload_prepare(ftun_engine_t *engine,
                                         const ftun_config_t *config,
                                         uint64_t generation)
{
  return ftun_engine_reload_prepare_planned(engine, config, generation, NULL);
}

ftun_status_t ftun_engine_reload_commit(ftun_engine_t *engine,
                                        uint64_t generation)
{
  ftun_status_t status;
  if (engine == NULL || generation == 0u || engine->stopped ||
      !engine->reload_prepared || generation <= engine->generation) {
    return FTUN_E_INVALID;
  }
  status = ftun_engine_dns_commit_reload(&engine->dns,
                                         &engine->pending_dns);
  if (status != FTUN_OK) return status;
  if (engine->pending_health_reuse) {
    size_t index;
    for (index = 0u; index < engine->health_slot_count; index++) {
      engine->health_slots[index].generation = generation;
    }
  } else {
    status = ftun_engine_health_release(&engine->health_groups,
      &engine->health_slots, engine->health_slot_count,
      &engine->health_reservation);
    if (status != FTUN_OK) return status;
    engine->health_groups = engine->pending_health_groups;
    engine->health_group_count = engine->pending_health_group_count;
    engine->health_slots = engine->pending_health_slots;
    engine->health_slot_count = engine->pending_health_slot_count;
    engine->health_reservation = engine->pending_health_reservation;
    engine->pending_health_groups = NULL;
    engine->pending_health_group_count = 0u;
    engine->pending_health_slots = NULL;
    engine->pending_health_slot_count = 0u;
    engine->pending_health_reservation = NULL;
  }
  {
    size_t index;
    for (index = 0u; index < engine->listener_count; index++) {
      engine->listeners[index].inbound_id =
        engine->pending_listener_ids[index];
      engine->pending_listener_ids[index] = 0u;
    }
  }
#if defined(FTUN_HAVE_MODULE_TUN)
  if (engine->tun_ingress != NULL) {
    status = ftun_tun_ingress_set_identity(engine->tun_ingress, generation,
      engine->pending_tun_inbound_id);
    if (status != FTUN_OK) return status;
    engine->tun_listener.inbound_id = engine->pending_tun_inbound_id;
    engine->pending_tun_inbound_id = 0u;
  }
#endif
  engine->generation = generation;
  engine->reload_prepared = false;
  engine->pending_health_reuse = false;
#if defined(FTUN_HAVE_MODULE_FRS)
  engine->frs_enabled = engine->pending_frs_enabled;
  engine->frs_interval_ms = engine->pending_frs_interval_ms;
  engine->pending_frs_enabled = false;
  engine->pending_frs_interval_ms = 0u;
  free(engine->frs_etag);
  engine->frs_etag = NULL;
  if (engine->frs_enabled &&
      ftun_monotonic_now(&engine->now_ms) == FTUN_OK &&
      engine->frs_interval_ms <= UINT64_MAX - engine->now_ms) {
    engine->frs_due_ms = engine->now_ms + engine->frs_interval_ms;
  } else {
    engine->frs_due_ms = UINT64_MAX;
  }
#endif
  return FTUN_OK;
}

ftun_status_t ftun_engine_reload_abort(ftun_engine_t *engine)
{
  ftun_status_t status;
  if (engine == NULL) return FTUN_E_INVALID;
  status = ftun_engine_dns_destroy(&engine->pending_dns);
  if (status == FTUN_OK && !engine->pending_health_reuse) {
    status = ftun_engine_health_release(&engine->pending_health_groups,
      &engine->pending_health_slots, engine->pending_health_slot_count,
      &engine->pending_health_reservation);
    engine->pending_health_group_count = 0u;
    engine->pending_health_slot_count = 0u;
  }
  if (status == FTUN_OK) {
    engine->reload_prepared = false;
    engine->pending_health_reuse = false;
    memset(engine->pending_listener_ids, 0,
           sizeof(engine->pending_listener_ids));
#if defined(FTUN_HAVE_MODULE_TUN)
    engine->pending_tun_inbound_id = 0u;
#endif
#if defined(FTUN_HAVE_MODULE_FRS)
    engine->pending_frs_enabled = false;
    engine->pending_frs_interval_ms = 0u;
#endif
  }
  return status;
}

static ftun_status_t ftun_engine_udp_drain(ftun_engine_t *engine,
                                            size_t quota)
{
  size_t work = 0u;
  if (engine == NULL || quota == 0u) return FTUN_E_INVALID;
  while (engine->ready_udp_head != NULL && work < quota) {
    ftun_engine_udp_slot_t *slot = engine->ready_udp_head;
    uint32_t events;
    uint32_t control_events;
    ftun_status_t status = FTUN_OK;
    ftun_engine_udp_unschedule(slot);
    if (!slot->active) continue;
    events = slot->events;
    control_events = slot->control_events;
    slot->events = 0u;
    slot->control_events = 0u;
    if (control_events != 0u) {
      uint8_t byte;
      ssize_t received;
      int socket_error = 0;
      socklen_t socket_error_length = (socklen_t)sizeof(socket_error);
      /* The connection object owns the descriptor; retrieve it rather than
       * duplicating socket ownership in the slot. */
      {
        ftun_socks5_connection_info_t info;
        status = ftun_socks5_connection_get_info(slot->proxy_connection,
                                                  &info);
        if (status == FTUN_OK) {
          if ((control_events & FTUN_EVENT_ERROR) != 0u &&
              getsockopt((int)info.control_socket, SOL_SOCKET, SO_ERROR,
                         &socket_error, &socket_error_length) != 0) {
            socket_error = errno;
          }
          do {
            received = recv((int)info.control_socket, &byte, sizeof(byte),
                            MSG_PEEK | MSG_DONTWAIT);
          } while (received < 0 && errno == EINTR);
          if (received == 0) status = FTUN_E_EOF;
          else if (received > 0) status = FTUN_E_PROTOCOL;
          else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            status = socket_error == 0 ? FTUN_OK
              : ftun_engine_errno_status(socket_error);
          } else status = ftun_engine_errno_status(errno);
        }
      }
      if (status != FTUN_OK) {
        ftun_engine_udp_backoff_failed(engine, slot->outbound_id);
        ftun_status_t cleanup = ftun_udp_flow_fail_outbound(
          engine->udp_flows, slot->channel, status);
        if (cleanup != FTUN_OK && cleanup != FTUN_E_STALE) return cleanup;
        work++;
        continue;
      }
    }
    if ((events & FTUN_EVENT_WRITE) != 0u) {
      ftun_engine_udp_finish_pending(slot, FTUN_OK);
    }
    if (slot->active &&
        (events & (FTUN_EVENT_READ | FTUN_EVENT_ERROR)) != 0u) {
      status = ftun_engine_udp_receive(slot);
      if (status == FTUN_E_PROTOCOL || status == FTUN_E_REJECTED ||
          status == FTUN_E_LIMIT || status == FTUN_E_AGAIN) {
        status = FTUN_OK;
      } else if (status != FTUN_OK) {
        if (slot->socks5) {
          ftun_engine_udp_backoff_failed(engine, slot->outbound_id);
        }
        ftun_status_t cleanup = ftun_udp_flow_fail_outbound(
          engine->udp_flows, slot->channel, status);
        if (cleanup != FTUN_OK && cleanup != FTUN_E_STALE) return cleanup;
        status = FTUN_OK;
      }
    }
    if (status != FTUN_OK) return status;
    work++;
  }
  return FTUN_OK;
}

ftun_status_t ftun_engine_run_once(ftun_engine_t *engine)
{
  size_t index;
  size_t callbacks = 0u;
  size_t flow_work = 0u;
  bool immediate_work = false;
  ftun_status_t status;
  if (engine == NULL || engine->stopped) return FTUN_E_INVALID;
  status = ftun_engine_dns_run_once(engine->dns);
  if (status != FTUN_OK) return status;
  status = ftun_engine_flow_drain(engine, 1024u, &flow_work);
  if (status != FTUN_OK) return status;
  immediate_work = flow_work != 0u || engine->ready_flow_head != NULL;
#if defined(FTUN_HAVE_MODULE_TUN)
  if (engine->tun_source != NULL) {
    uint32_t interests = FTUN_EVENT_READ | FTUN_EVENT_ERROR;
    if (engine->tun_output_count != 0u) interests |= FTUN_EVENT_WRITE;
    status = ftun_event_io_update(engine->tun_source, interests);
    if (status != FTUN_OK) return status;
  }
#endif
  status = ftun_event_loop_run_once(engine->loop, !immediate_work, 1024u,
                                    &callbacks);
  if (status != FTUN_OK) return status;
  for (index = 0u; index < engine->listener_count; index++) {
    ftun_engine_listener_t *listener = &engine->listeners[index];
    uint32_t events = listener->events;
    uint32_t udp_events = listener->udp_events;
    listener->events = 0u;
    listener->udp_events = 0u;
    if (engine->accepting && (events & FTUN_EVENT_READ) != 0u) {
      status = ftun_engine_accept(engine, listener);
      if (status != FTUN_OK) return status;
    }
    if ((events & FTUN_EVENT_ERROR) != 0u) return FTUN_E_IO;
    if (engine->accepting && (udp_events & FTUN_EVENT_READ) != 0u) {
      status = ftun_engine_listener_udp(engine, listener);
      if (status != FTUN_OK) return status;
    }
    if ((udp_events & FTUN_EVENT_ERROR) != 0u) return FTUN_E_IO;
  }
#if defined(FTUN_HAVE_MODULE_TUN)
  {
    uint32_t tun_events = engine->tun_events;
    engine->tun_events = 0u;
    if (engine->has_tun && (tun_events & FTUN_EVENT_WRITE) != 0u) {
      status = ftun_engine_tun_output_flush(engine);
      if (status != FTUN_OK) return status;
    }
    if (engine->has_tun && (tun_events & FTUN_EVENT_READ) != 0u) {
      status = ftun_engine_tun_read(engine);
      if (status != FTUN_OK) return status;
    }
    if (engine->has_tun && (tun_events & FTUN_EVENT_ERROR) != 0u) {
      return FTUN_E_IO;
    }
  }
#endif
  /* FD 与 TUN callbacks only enqueue runnable flows.  Draining the queue
   * avoids a full-table pass and also completes synchronous socket writes
   * before the owner can block again. */
  status = ftun_engine_flow_drain(engine, 1024u, &flow_work);
  if (status != FTUN_OK) return status;
  status = ftun_engine_udp_drain(engine, 1024u);
  if (status != FTUN_OK) return status;
  if (engine->udp_flows != NULL ||
#if defined(FTUN_HAVE_MODULE_TUN)
      engine->has_tun ||
#else
      false ||
#endif
#if defined(FTUN_HAVE_MODULE_FRS)
      engine->frs_enabled ||
#else
      false ||
#endif
      engine->health_slot_count != 0u
      ) {
    status = ftun_monotonic_now(&engine->now_ms);
    if (status != FTUN_OK) return status;
  }
#if defined(FTUN_HAVE_MODULE_TUN)
  if (engine->has_tun) {
    status = ftun_tun_ingress_tick(engine->tun_ingress, engine->now_ms);
    if (status != FTUN_OK) return status;
  }
#endif
  if (engine->udp_flows != NULL) {
    status = ftun_udp_flow_tick(engine->udp_flows, engine->now_ms);
    if (status != FTUN_OK) return status;
  }
#if defined(FTUN_HAVE_MODULE_FRS)
  if (engine->frs_enabled && engine->frs_operation == NULL &&
      engine->now_ms >= engine->frs_due_ms) {
    status = ftun_engine_frs_schedule(engine);
    if (status != FTUN_OK) {
      if (engine->frs_interval_ms <= UINT64_MAX - engine->now_ms) {
        engine->frs_due_ms = engine->now_ms + engine->frs_interval_ms;
      } else {
        engine->frs_due_ms = UINT64_MAX;
      }
      ftun_engine_background_log(engine, status,
                                 "FRS update could not be scheduled");
    }
  }
#endif
  if (engine->health_slot_count != 0u) {
    status = ftun_engine_health_run(engine);
    if (status != FTUN_OK) return status;
  }
  if (engine->worker != NULL) {
    status = ftun_worker_poll(engine->worker, 64u, &callbacks);
  }
  if (status == FTUN_OK && engine->maintenance_worker != NULL) {
    status = ftun_worker_poll(engine->maintenance_worker, 16u, &callbacks);
  }
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  if (status == FTUN_OK && engine->fakeip_worker != NULL) {
    status = ftun_worker_poll(engine->fakeip_worker, 2u, &callbacks);
  }
  if (status == FTUN_OK) {
    status = ftun_engine_fakeip_reserve_runtime(engine);
  }
#endif
  return status;
}

ftun_status_t ftun_engine_wakeup(ftun_engine_t *engine)
{
  if (engine == NULL || engine->loop == NULL || engine->stopped) {
    return FTUN_E_INVALID;
  }
  return ftun_event_loop_wakeup(engine->loop);
}

ftun_status_t ftun_engine_stop(ftun_engine_t *engine)
{
  size_t index;
  ftun_status_t result = FTUN_OK;
  if (engine == NULL) return FTUN_E_INVALID;
  if (engine->stopped) return FTUN_OK;
  engine->accepting = false;
  ftun_engine_udp_pending_cancel_all(engine);
  for (index = 0u; index < engine->health_slot_count; index++) {
    if (engine->health_slots[index].operation != NULL) {
      (void)ftun_operation_cancel(engine->health_slots[index].operation);
    }
  }
#if defined(FTUN_HAVE_MODULE_FRS)
  engine->frs_enabled = false;
  if (engine->frs_operation != NULL) {
    (void)ftun_operation_cancel(engine->frs_operation);
  }
#endif
  (void)ftun_engine_dns_stop(engine->dns);
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  if (engine->fakeip_store != NULL && engine->fakeip != NULL) {
    ftun_fakeip_snapshot_t *snapshot = NULL;
    ftun_operation_t *operation = NULL;
    size_t expected;
    ftun_status_t status = FTUN_OK;
    if (engine->fakeip_reserve_operation != NULL) {
      expected = engine->fakeip_store_completions + 1u;
      status = ftun_engine_wait_worker(engine, engine->fakeip_worker,
                                       expected);
    }
    expected = engine->fakeip_store_completions + 1u;
    if (status == FTUN_OK) {
      status = ftun_fakeip_service_snapshot(engine->fakeip, &snapshot);
    }
    if (status == FTUN_OK) {
      engine->fakeip_store_status = FTUN_E_AGAIN;
      status = ftun_fakeip_snapshot_save(engine->fakeip_store, snapshot,
                                         &operation);
    }
    (void)ftun_fakeip_snapshot_destroy(&snapshot);
    if (status == FTUN_OK) status = ftun_engine_wait_worker(
      engine, engine->fakeip_worker, expected);
    if (status != FTUN_OK) result = status;
  }
  (void)ftun_runtime_manager_set_fakeip(engine->core, NULL);
#endif
  for (index = 0u; index < engine->listener_count; index++) {
    (void)ftun_event_source_cancel(&engine->listeners[index].source);
    (void)ftun_event_source_cancel(&engine->listeners[index].udp_source);
    (void)ftun_event_source_cancel(&engine->listeners[index].accept_timer);
    if (engine->listeners[index].descriptor >= 0) {
      (void)close(engine->listeners[index].descriptor);
      engine->listeners[index].descriptor = -1;
    }
    if (engine->listeners[index].udp_descriptor >= 0) {
      (void)close(engine->listeners[index].udp_descriptor);
      engine->listeners[index].udp_descriptor = -1;
    }
  }
  for (index = 0u; index < FTUN_ENGINE_MAX_TCP_FLOWS; index++) {
    if (engine->flows[index].active) {
      (void)ftun_event_source_cancel(&engine->flows[index].client_source);
      (void)ftun_event_source_cancel(&engine->flows[index].remote_source);
      (void)ftun_event_source_cancel(&engine->flows[index].deadline_source);
      ftun_engine_flow_close(&engine->flows[index], FTUN_E_CANCELLED);
      engine->flows[index].ready_queued = false;
      engine->flows[index].ready_next = NULL;
    }
  }
  engine->ready_flow_head = NULL;
  engine->ready_flow_tail = NULL;
  for (index = 0u; index < FTUN_ENGINE_MAX_UDP_FLOWS; index++) {
    (void)ftun_event_source_cancel(&engine->udp[index].source);
    (void)ftun_event_source_cancel(&engine->udp[index].control_source);
  }
#if defined(FTUN_HAVE_MODULE_TUN)
  (void)ftun_event_source_cancel(&engine->tun_source);
  if (engine->tun_ingress != NULL) {
    (void)ftun_tun_ingress_close(&engine->tun_ingress);
  }
  if (ftun_engine_tun_output_clear(engine) != FTUN_OK &&
      result == FTUN_OK) result = FTUN_E_STATE_CORRUPT;
#endif
  (void)ftun_event_loop_stop(engine->loop);
  engine->stopped = true;
  return result;
}

ftun_status_t ftun_engine_destroy(ftun_engine_t **engine)
{
  ftun_engine_t *owned;
  ftun_reservation_t *reservation;
  size_t index;
  ftun_status_t result = FTUN_OK;
  if (engine == NULL) return FTUN_E_INVALID;
  owned = *engine;
  if (owned == NULL) return FTUN_OK;
  (void)ftun_engine_stop(owned);
  /* Drain every worker callback while the DNS/flow/health owners they refer
   * to are still alive.  Destroying those owners first can turn a clean stop
   * with an in-flight probe or resolver into a retry-only partial teardown. */
  if (owned->worker != NULL) {
    size_t callbacks = 0u;
    (void)ftun_worker_stop(owned->worker);
    if (ftun_worker_join(owned->worker) != FTUN_OK) return FTUN_E_AGAIN;
    if (ftun_worker_poll(owned->worker, SIZE_MAX, &callbacks) != FTUN_OK) {
      return FTUN_E_AGAIN;
    }
  }
  if (owned->maintenance_worker != NULL) {
    size_t callbacks = 0u;
    (void)ftun_worker_stop(owned->maintenance_worker);
    if (ftun_worker_join(owned->maintenance_worker) != FTUN_OK) {
      return FTUN_E_AGAIN;
    }
    if (ftun_worker_poll(owned->maintenance_worker, SIZE_MAX,
                         &callbacks) != FTUN_OK) {
      return FTUN_E_AGAIN;
    }
  }
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  if (owned->fakeip_worker != NULL) {
    size_t callbacks = 0u;
    (void)ftun_worker_stop(owned->fakeip_worker);
    if (ftun_worker_join(owned->fakeip_worker) != FTUN_OK) {
      return FTUN_E_AGAIN;
    }
    if (ftun_worker_poll(owned->fakeip_worker, SIZE_MAX,
                         &callbacks) != FTUN_OK) {
      return FTUN_E_AGAIN;
    }
  }
#endif
  for (index = 0u; index < FTUN_ENGINE_MAX_TCP_FLOWS; index++) {
    ftun_engine_flow_t *flow = &owned->flows[index];
    if (!flow->active) continue;
    if (flow->open_operation != NULL) {
      (void)ftun_operation_cancel(flow->open_operation);
      result = FTUN_E_AGAIN;
      continue;
    }
    if (ftun_engine_flow_finalize(flow) != FTUN_OK) result = FTUN_E_AGAIN;
  }
  if (result != FTUN_OK) return result;
  if (owned->udp_flows != NULL &&
      ftun_udp_flow_table_destroy(&owned->udp_flows) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
#if defined(FTUN_HAVE_MODULE_TUN)
  if (owned->tun_ingress != NULL &&
      ftun_tun_ingress_close(&owned->tun_ingress) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
  if (owned->routes != NULL &&
      ftun_linux_route_release(&owned->routes) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
  if (owned->tun_port != NULL &&
      ftun_packet_port_close(&owned->tun_port) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
  free(owned->tun_listener.name);
  owned->tun_listener.name = NULL;
#endif
  if (ftun_engine_dns_destroy(&owned->dns) != FTUN_OK) return FTUN_E_AGAIN;
  if (ftun_engine_dns_destroy(&owned->pending_dns) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  if (owned->fakeip != NULL &&
      ftun_fakeip_service_destroy(&owned->fakeip) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
  if (owned->fakeip_store != NULL &&
      ftun_fakeip_store_destroy(&owned->fakeip_store) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
  free(owned->fakeip_directory);
  owned->fakeip_directory = NULL;
#endif
  for (index = 0u; index < owned->listener_count; index++) {
    free(owned->listeners[index].name);
    owned->listeners[index].name = NULL;
  }
  if (owned->loop != NULL) {
    (void)ftun_libev_detach(owned->loop);
    if (ftun_event_loop_destroy(&owned->loop) != FTUN_OK) return FTUN_E_AGAIN;
  }
  if (owned->worker != NULL) {
    if (ftun_worker_destroy(&owned->worker) != FTUN_OK) return FTUN_E_AGAIN;
  }
  if (owned->maintenance_worker != NULL) {
    if (ftun_worker_destroy(&owned->maintenance_worker) != FTUN_OK) {
      return FTUN_E_AGAIN;
    }
  }
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  if (owned->fakeip_worker != NULL &&
      ftun_worker_destroy(&owned->fakeip_worker) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
#endif
  if (owned->relay_pool != NULL &&
      ftun_buffer_pool_destroy(&owned->relay_pool) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
  if (ftun_engine_health_release(&owned->health_groups,
      &owned->health_slots, owned->health_slot_count,
      &owned->health_reservation) != FTUN_OK) return FTUN_E_AGAIN;
  if (ftun_engine_health_release(&owned->pending_health_groups,
      &owned->pending_health_slots, owned->pending_health_slot_count,
      &owned->pending_health_reservation) != FTUN_OK) return FTUN_E_AGAIN;
#if defined(FTUN_HAVE_MODULE_FRS)
  free(owned->frs_etag);
  owned->frs_etag = NULL;
#endif
  reservation = owned->reservation;
  owned->reservation = NULL;
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *engine = NULL;
  if (ftun_reservation_release(&reservation) != FTUN_OK) {
    return FTUN_E_STATE_CORRUPT;
  }
  return FTUN_OK;
}
