#ifndef FTUN_LIBS_RESOLVER_BASIC_H
#define FTUN_LIBS_RESOLVER_BASIC_H

#include "libs/resolver/dnswire.h"
#include "libs/resolver/system.h"
#include "libs/transport/dialer.h"

#define FTUN_BOOTSTRAP_MAX_SERVERS 16u
#define FTUN_BOOTSTRAP_MAX_RESPONSE_BYTES 4096u

#define FTUN_BOOTSTRAP_STAGE_ADMISSION 1u
#define FTUN_BOOTSTRAP_STAGE_DIAL 2u
#define FTUN_BOOTSTRAP_STAGE_SEND 3u
#define FTUN_BOOTSTRAP_STAGE_RECEIVE 4u
#define FTUN_BOOTSTRAP_STAGE_RESPONSE 5u
#define FTUN_BOOTSTRAP_STAGE_TIMEOUT 6u

typedef struct {
  ftun_event_loop_t *loop;
  ftun_operation_queue_t *operations;
  ftun_worker_t *worker;
  ftun_budget_t *budget;
  ftun_string_t domain;
  const ftun_endpoint_t *servers;
  size_t server_count;
  const ftun_network_view_t *network_view;
  uint64_t network_generation;
  ftun_socket_policy_t protection;
  uint64_t deadline_ms;
  uint16_t query_id;
  uint16_t query_type;
  bool ipv6; /* 供Provider组合A/AAAA；单次Bootstrap使用query_type。 */
  ftun_system_resolver_path_check_fn check_system_path;
  void *system_path_user;
  ftun_system_resolve_completion_fn completion;
  void *user;
} ftun_bootstrap_request_t;

typedef struct {
  /* UDP send 必须整包接纳；OK 时 out_sent 必须等于 length。 */
  ftun_status_t (*send_datagram)(void *context, ftun_native_socket_t socket,
                                 const void *data, size_t length,
                                 size_t *out_sent);
  /* OK 返回一个完整数据报及物理来源；截断必须返回 LIMIT。 */
  ftun_status_t (*receive_datagram)(void *context,
                                    ftun_native_socket_t socket,
                                    void *data, size_t capacity,
                                    size_t *out_received,
                                    ftun_endpoint_t *out_source);
  void *context;
} ftun_bootstrap_io_t;

/* 基础真实解析。
 * servers 非空时只按复制后的 IP 列表经 purpose=BOOTSTRAP 的受保护
 * UDP Dialer 顺序尝试，校验来源、ID 和完整 Question，绝不回退系统 DNS。
 * servers 为空时原样委托 SystemResolver，并要求其路径保护门禁。
 * 成功结果是有序去重 IP，同步借给 completion。接纳后 Operation
 * 恰好一次终结；取消消费当前 child/source/socket，失败可重试。
 * 当前最小 Bootstrap 不实现 TC 后 TCP fallback，收到 TC 明确 unsupported。
 */
ftun_status_t ftun_bootstrap_resolve(
  ftun_core_t *core, const ftun_bootstrap_request_t *request,
  ftun_operation_t **out);

/* 测试与受控宿主注入；操作表按值复制。仅用于显式 servers 分支。 */
ftun_status_t ftun_bootstrap_resolve_with_io(
  ftun_core_t *core, const ftun_bootstrap_request_t *request,
  const ftun_dial_io_t *dial_io, const ftun_bootstrap_io_t *io,
  ftun_operation_t **out);

#endif
