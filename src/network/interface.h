#ifndef FTUN_NETWORK_INTERFACE_H
#define FTUN_NETWORK_INTERFACE_H
#include "internal/contracts.h"

/* 设备网络状态与平台路由对象分离。输入只在 restore 调用期间借用；失败
 * 可返回部分事务，必须保留并重复 withdraw，成功撤销才清空句柄。 */
typedef struct {
  ftun_string_t name;
  uint8_t ipv4_address[4];
  uint8_t prefix_length;
  uint32_t protection_mark;
  bool strict_route;
  ftun_budget_t *budget;
} ftun_interface_spec_t;

typedef struct {
  ftun_budget_t *budget;
  ftun_event_loop_t *loop;
  uint64_t now_ms;
  uint64_t step_timeout_ms;
  uint64_t deadline_ms;
} ftun_interface_async_options_t;

typedef enum {
  FTUN_INTERFACE_INSTALLING = 1,
  FTUN_INTERFACE_READY,
  FTUN_INTERFACE_REMOVING,
  FTUN_INTERFACE_FAILED,
  FTUN_INTERFACE_RETAINED,
  FTUN_INTERFACE_RELEASED
} ftun_interface_state_t;

typedef struct {
  ftun_interface_state_t state;
  ftun_status_t result;
  ftun_status_t cleanup_result;
  size_t active_count;
  uint64_t next_deadline_ms;
  bool has_deadline;
  bool runnable;
} ftun_interface_async_info_t;

/* owner-loop 非阻塞事务：start/adopt 成功交付拥有句柄，spec/options 仅同步
 * 借用。adopt 成功消费原同步 state，失败不改变它；不会再次安装已有资源。
 * run 受 quota 约束；withdraw 接纳取消/撤销，不代表已完成。只有 FAILED 或
 * RELEASED 且无残留资源时 destroy 才成功；其余保留句柄供新期限重试。
 * context 借用到 destroy，预算与 loop 必须覆盖对象寿命。 */
typedef struct {
  ftun_status_t (*start)(void *context, const ftun_interface_spec_t *spec,
    const ftun_interface_async_options_t *options, void **state);
  ftun_status_t (*adopt)(void *context, void **source,
    const ftun_interface_async_options_t *options, void **state);
  ftun_status_t (*withdraw)(void *context, void *state, uint64_t now_ms,
    uint64_t deadline_ms);
  ftun_status_t (*run)(void *context, void *state, uint64_t now_ms,
    size_t quota, size_t *out_work);
  ftun_status_t (*query)(void *context, const void *state,
    ftun_interface_async_info_t *out);
  ftun_status_t (*destroy)(void *context, void **state);
  void *context;
} ftun_interface_async_ops_t;

typedef struct {
  ftun_status_t (*restore)(void *context, const ftun_interface_spec_t *spec, void **state);
  ftun_status_t (*withdraw)(void *context, void **state);
  void *context;
  ftun_interface_async_ops_t async;
} ftun_interface_ops_t;
#endif
