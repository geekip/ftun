#ifndef FTUN_PLATFORM_ROUTE_H
#define FTUN_PLATFORM_ROUTE_H
#include "util/types.h"
#include "util/ip.h"
#include "platform/poller.h"

/* OS 资源/计划的布局只由平台实现和原生夹具可见。 */
typedef struct ftun_route_plan ftun_route_plan_t;
typedef struct ftun_route_io ftun_route_io_t;
typedef struct ftun_route_async_io ftun_route_async_io_t;
typedef struct ftun_platform_route_transaction ftun_platform_route_transaction_t;
typedef struct ftun_platform_route_async ftun_platform_route_async_t;

/* 宿主串行注册 readiness/期限，取消成功后不得再交付该借用。
 * 只传通用就绪位，不向平台传入 Core/Event 对象。 */
typedef void (*ftun_route_notify_fn)(void *user, uint32_t events);
#define FTUN_ROUTE_TIMER 8u
typedef struct {
  ftun_status_t (*watch)(void *context, ftun_native_socket_t socket,
    uint32_t events, ftun_route_notify_fn notify, void *user);
  ftun_status_t (*update)(void *context, uint32_t events);
  ftun_status_t (*unwatch)(void *context);
  ftun_status_t (*timer)(void *context, uint64_t deadline_ms,
    ftun_route_notify_fn notify, void *user);
  ftun_status_t (*untimer)(void *context);
  void *context;
} ftun_route_events_t;

/* 兼容已有配置的选项由当前平台确定，业务不解释原生表号/规则范围。 */
typedef struct {
  uint32_t routing_domain;
  uint32_t precedence;
} ftun_route_settings_t;
ftun_route_settings_t ftun_platform_route_defaults(void);
/* 返回静态诊断文本；NULL 表示合法，不分配或执行 I/O。 */
const char *ftun_platform_route_config_error(ftun_route_settings_t settings);

struct ftun_route_policy {
  ftun_string_t tun_interface;
  uint8_t tun_ipv4[4];
  uint8_t tun_prefix_length;
  uint32_t routing_domain;
  uint32_t precedence;
  /* 0 保持旧布局：capture 从 precedence+1 开始。NetworkView 可预留
   * 中间优先级给目标前缀 guard，但 Underlay mark rule 必须仍最先匹配。 */
  uint32_t capture_offset;
  uint32_t bypass_tag;
  uint32_t bypass_mask;
  bool manage_local;
  ftun_string_t lan_interface;
  bool strict_route;
};

typedef struct {
  size_t resource_count;
  size_t active_count;
  bool strict_route;
} ftun_route_info_t;

typedef enum {
  FTUN_ROUTE_ASYNC_APPLYING = 1,
  FTUN_ROUTE_ASYNC_READY,
  FTUN_ROUTE_ASYNC_COMPENSATING,
  FTUN_ROUTE_ASYNC_RELEASING,
  FTUN_ROUTE_ASYNC_FAILED,
  FTUN_ROUTE_ASYNC_CLEANUP_FAILED,
  FTUN_ROUTE_ASYNC_RELEASED
} ftun_route_async_state_t;

typedef struct {
  size_t resource_count;
  size_t active_count;
  ftun_route_async_state_t state;
  ftun_status_t result;
  ftun_status_t cleanup_result;
  uint32_t pending_sequence;
  size_t stale_replies;
  size_t timeouts;
  size_t cleanup_failures;
  bool runnable;
  /* 对账修复：repairing 为真时 state 暂为 APPLYING，但失败不会撤销已有资源。 */
  bool repairing;
  ftun_status_t repair_result;
  size_t repair_runs;
  size_t repairs;
  size_t repair_failures;
  size_t strays_removed;
} ftun_route_async_info_t;


ftun_status_t ftun_platform_route_async_start(
  const ftun_route_policy_t *policy, const ftun_route_events_t *events,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  ftun_platform_route_async_t **out);
ftun_status_t ftun_platform_route_async_start_with_io(
  const ftun_route_policy_t *policy, const ftun_route_async_io_t *io,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  uint32_t initial_sequence, ftun_platform_route_async_t **out);
ftun_status_t ftun_platform_route_async_start_plan(
  const ftun_route_plan_t *plan, const ftun_route_events_t *events,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  ftun_platform_route_async_t **out);
ftun_status_t ftun_platform_route_async_start_plan_with_io(
  const ftun_route_plan_t *plan, const ftun_route_async_io_t *io,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  uint32_t initial_sequence, ftun_platform_route_async_t **out);
ftun_status_t ftun_platform_route_async_adopt(
  ftun_platform_route_transaction_t **source, const ftun_route_events_t *events,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  ftun_platform_route_async_t **out);
ftun_status_t ftun_platform_route_async_adopt_with_io(
  ftun_platform_route_transaction_t **source, const ftun_route_async_io_t *io,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  uint32_t initial_sequence, ftun_platform_route_async_t **out);
ftun_status_t ftun_platform_route_guard_plan(
  const ftun_cidr_t *prefixes, size_t prefix_count, uint32_t table, uint32_t first_priority,
  ftun_route_plan_t *out);
ftun_status_t ftun_platform_route_overlay_plan(
  const ftun_cidr_t *prefixes, size_t prefix_count, ftun_string_t tun_interface,
  uint32_t table, uint32_t metric, ftun_route_plan_t *out);
ftun_status_t ftun_platform_route_async_repair(
  ftun_platform_route_async_t *operation, uint64_t now_ms,
  uint64_t total_deadline_ms);
ftun_status_t ftun_platform_route_async_run(ftun_platform_route_async_t *operation,
                                         uint64_t now_ms, size_t max_work,
                                         size_t *out_work);
ftun_status_t ftun_platform_route_async_next_deadline(
  const ftun_platform_route_async_t *operation, uint64_t *out_deadline,
  bool *out_present);
ftun_status_t ftun_platform_route_async_get_info(
  const ftun_platform_route_async_t *operation,
  ftun_route_async_info_t *out);
ftun_status_t ftun_platform_route_async_release(
  ftun_platform_route_async_t *operation, uint64_t now_ms,
  uint64_t total_deadline_ms);
ftun_status_t ftun_platform_route_async_destroy(
  ftun_platform_route_async_t **operation);
ftun_status_t ftun_platform_route_prepare(const ftun_route_policy_t *policy, ftun_platform_route_transaction_t **out);
ftun_status_t ftun_platform_route_prepare_with_io(const ftun_route_policy_t *policy,
                                               const ftun_route_io_t *io,
                                               ftun_platform_route_transaction_t **out);
ftun_status_t ftun_platform_route_get_info(const ftun_platform_route_transaction_t *transaction,
                                        ftun_route_info_t *out);
ftun_status_t ftun_platform_route_release(ftun_platform_route_transaction_t **transaction);
bool ftun_platform_route_prepare_valid(const ftun_route_policy_t *policy,
  const ftun_route_io_t *io, bool system);
size_t ftun_platform_route_transaction_allocation_size(void);
size_t ftun_platform_route_async_allocation_size(void);
size_t ftun_platform_route_plan_allocation_size(void);
#endif
