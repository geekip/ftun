#ifndef FTUN_PLATFORM_LINUX_ROUTE_H
#define FTUN_PLATFORM_LINUX_ROUTE_H
#include "internal/contracts.h"
#include "network/view.h"

#define FTUN_LINUX_ROUTE_NAME_BYTES 16u
#define FTUN_LINUX_ROUTE_MAX_RESOURCES 7u
#define FTUN_LINUX_ROUTE_PLAN_MAX_RESOURCES 128u
#define FTUN_LINUX_ROUTE_PROTOCOL 186u

typedef enum {
  FTUN_LINUX_ROUTE_ADDRESS = 1,
  FTUN_LINUX_ROUTE_MARK_RULE,
  FTUN_LINUX_ROUTE_DEFAULT,
  FTUN_LINUX_ROUTE_CAPTURE_RULE,
  FTUN_LINUX_ROUTE_BLOCK_IPV6,
  FTUN_LINUX_ROUTE_PROTECT_RULE,
  FTUN_LINUX_ROUTE_OVERLAY,
  FTUN_LINUX_ROUTE_UNREACHABLE
} ftun_linux_route_resource_kind_t;

typedef struct {
  ftun_linux_route_resource_kind_t kind;
  int family;
  char interface_name[FTUN_LINUX_ROUTE_NAME_BYTES];
  uint8_t address[16];
  uint8_t prefix_length;
  uint32_t table;
  uint32_t priority;
  uint32_t mark;
  uint32_t mark_mask;
  uint32_t metric;
  uint8_t protocol;
} ftun_linux_route_resource_t;

typedef struct {
  ftun_linux_route_resource_t resources[FTUN_LINUX_ROUTE_PLAN_MAX_RESOURCES];
  size_t resource_count;
} ftun_linux_route_plan_t;

typedef struct {
  ftun_status_t (*apply)(void *context,
                         const ftun_linux_route_resource_t *resource);
  ftun_status_t (*remove)(void *context,
                          const ftun_linux_route_resource_t *resource);
  void *context;
} ftun_linux_route_io_t;

struct ftun_route_policy {
  ftun_string_t tun_interface;
  uint8_t tun_ipv4[4];
  uint8_t tun_prefix_length;
  uint32_t route_table;
  uint32_t rule_priority;
  /* 0 保持旧布局：capture 从 rule_priority+1 开始。NetworkView 可预留
   * 中间优先级给目标前缀 guard，但 Underlay mark rule 必须仍最先匹配。 */
  uint32_t capture_priority_offset;
  uint32_t protection_mark;
  uint32_t protection_mark_mask;
  bool manage_local;
  ftun_string_t lan_interface;
  bool strict_route;
};

typedef struct {
  size_t resource_count;
  size_t active_count;
  bool strict_route;
} ftun_linux_route_info_t;

typedef enum {
  FTUN_LINUX_ROUTE_ASYNC_APPLYING = 1,
  FTUN_LINUX_ROUTE_ASYNC_READY,
  FTUN_LINUX_ROUTE_ASYNC_COMPENSATING,
  FTUN_LINUX_ROUTE_ASYNC_RELEASING,
  FTUN_LINUX_ROUTE_ASYNC_FAILED,
  FTUN_LINUX_ROUTE_ASYNC_CLEANUP_FAILED,
  FTUN_LINUX_ROUTE_ASYNC_RELEASED
} ftun_linux_route_async_state_t;

typedef enum {
  FTUN_LINUX_ROUTE_REQUEST_QUERY = 1,
  FTUN_LINUX_ROUTE_REQUEST_ADD,
  FTUN_LINUX_ROUTE_REQUEST_REMOVE
} ftun_linux_route_request_kind_t;

typedef struct {
  uint32_t sequence;
  ftun_linux_route_request_kind_t kind;
  ftun_linux_route_resource_t resource;
} ftun_linux_route_request_t;

typedef struct {
  uint32_t sequence;
  ftun_status_t status;
  bool present;
} ftun_linux_route_reply_t;

typedef struct {
  /* submit/receive 均不得阻塞；AGAIN 表示等待下一次 readiness。 */
  ftun_status_t (*submit)(void *context,
                          const ftun_linux_route_request_t *request);
  ftun_status_t (*receive)(void *context, ftun_linux_route_reply_t *reply);
  void *context;
} ftun_linux_route_async_io_t;

typedef struct {
  size_t resource_count;
  size_t active_count;
  ftun_linux_route_async_state_t state;
  ftun_status_t result;
  ftun_status_t cleanup_result;
  uint32_t pending_sequence;
  size_t stale_replies;
  size_t timeouts;
  size_t cleanup_failures;
  bool runnable;
} ftun_linux_route_async_info_t;

/* 动态路由事务使用非阻塞 rtnetlink，并把 fd/timer 挂到 owner loop。
 * total_deadline_ms 是绝对单调毫秒；step_timeout_ms 限制单个 ACK/dump。
 * 每个资源先核验不存在再 CREATE|EXCL。ACK 超时必须 dump reconcile，
 * 无法确认的资源按可能已创建保留所有权并进入可重试清理状态。 */
ftun_status_t ftun_linux_route_async_start(
  const ftun_route_policy_t *policy, ftun_event_loop_t *loop,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  ftun_linux_route_async_t **out);
/* 测试与受控宿主注入；io/context 借用至 destroy，initial_sequence 不能为 0。 */
ftun_status_t ftun_linux_route_async_start_with_io(
  const ftun_route_policy_t *policy, const ftun_linux_route_async_io_t *io,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  uint32_t initial_sequence, ftun_linux_route_async_t **out);
/* NetworkView 使用的通用有界资源计划。guard plan 只含持久拒绝兜底，
 * overlay plan 只含当前可达路径；调用方必须先提交 guard 再发布路径。 */
ftun_status_t ftun_linux_route_async_start_plan(
  const ftun_linux_route_plan_t *plan, ftun_event_loop_t *loop,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  ftun_linux_route_async_t **out);
ftun_status_t ftun_linux_route_async_start_plan_with_io(
  const ftun_linux_route_plan_t *plan, const ftun_linux_route_async_io_t *io,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  uint32_t initial_sequence, ftun_linux_route_async_t **out);
ftun_status_t ftun_linux_route_guard_plan(
  const ftun_network_view_t *view, uint32_t table, uint32_t first_priority,
  ftun_linux_route_plan_t *out);
ftun_status_t ftun_linux_route_overlay_plan(
  const ftun_network_view_t *view, ftun_string_t tun_interface,
  uint32_t table, uint32_t metric, ftun_linux_route_plan_t *out);
/* 单轮最多处理 max_work 个提交或回复；不会等待 I/O。 */
ftun_status_t ftun_linux_route_async_run(ftun_linux_route_async_t *operation,
                                         uint64_t now_ms, size_t max_work,
                                         size_t *out_work);
ftun_status_t ftun_linux_route_async_next_deadline(
  const ftun_linux_route_async_t *operation, uint64_t *out_deadline,
  bool *out_present);
ftun_status_t ftun_linux_route_async_get_info(
  const ftun_linux_route_async_t *operation,
  ftun_linux_route_async_info_t *out);
/* APPLYING 时请求 release 会取消安装并反序清理；清理失败后可用新期限重试。 */
ftun_status_t ftun_linux_route_async_release(
  ftun_linux_route_async_t *operation, uint64_t now_ms,
  uint64_t total_deadline_ms);
/* 只有无活动/不确定资源的终态可销毁；其余返回 AGAIN 并保留句柄。 */
ftun_status_t ftun_linux_route_async_destroy(
  ftun_linux_route_async_t **operation);

/* Linux 路由资源事务。
 * 需求 REQ-GUARD-001；任务 TASK-PLATFORM-002；目标 0.2.0；验收 TEST-PLATFORM-002。
 * 实现路径：记录实例所有权；保护与 TUN 路由按序准备；冲突拒绝、失败反序撤销；本机/LAN 分别验收，退出不改他人规则。
 * 调用边界：不访问配置 AST，不跨线程修改 Session。
 * policy 仅在调用期间借用，成功 transaction 拥有已安装资源记录。
 * 本机范围使用 iif lo，LAN 范围必须显式提供接口；strict-route 只阻断同一范围 IPv6。
 * 冲突返回 rejected；普通失败完成逆序回滚并清空输出。
 * 若回滚本身失败则返回 state-corrupt 并交付 transaction，调用者必须重试 release。
 */
ftun_status_t ftun_linux_route_prepare(const ftun_route_policy_t *policy, ftun_route_transaction_t **out);
/* 测试与受控宿主注入；操作表会复制，context 必须比 transaction 长寿。 */
ftun_status_t ftun_linux_route_prepare_with_io(const ftun_route_policy_t *policy,
                                               const ftun_linux_route_io_t *io,
                                               ftun_route_transaction_t **out);
ftun_status_t ftun_linux_route_get_info(const ftun_route_transaction_t *transaction,
                                        ftun_linux_route_info_t *out);
/* 逆序删除仍活动的自有资源；部分失败保留句柄和失败项供重试。 */
ftun_status_t ftun_linux_route_release(ftun_route_transaction_t **transaction);
#endif
