#ifndef FTUN_APP_CONTROL_H
#define FTUN_APP_CONTROL_H

#include "ftun/ftun.h"
#include "core/lifecycle.h"
#include "core/log/event_log.h"
#include "app/config/config.h"
#include <stdbool.h>

#define FTUN_APP_CONTROL_PATH_CAPACITY 4097u

typedef enum {
  FTUN_APP_COMMAND_RELOAD = 1,
  FTUN_APP_COMMAND_SELECT,
  FTUN_APP_COMMAND_STOP
} ftun_app_command_kind_t;

#define FTUN_APP_CONTROL_RELOAD UINT32_C(1)
#define FTUN_APP_CONTROL_SELECT UINT32_C(2)
#define FTUN_APP_CONTROL_STOP UINT32_C(4)

typedef struct {
  bool present;
  uint64_t generation;
} ftun_app_generation_guard_t;

typedef struct {
  ftun_app_command_kind_t kind;
  ftun_app_generation_guard_t expected;
  const char *first;
  const char *second;
} ftun_app_command_t;

typedef enum {
  FTUN_APP_COMMAND_REQUESTED = 1,
  FTUN_APP_COMMAND_COMPLETED,
  FTUN_APP_COMMAND_FAILED,
  FTUN_APP_COMMAND_CANCELLED
} ftun_app_command_phase_t;

typedef struct {
  ftun_app_command_kind_t kind;
  ftun_app_command_phase_t phase;
  ftun_error_t error;
  uint64_t generation;
} ftun_app_command_result_t;

typedef void (*ftun_app_command_completion_fn)(ftun_operation_t *operation,
  ftun_app_command_result_t result, void *user);

/* 所有字段均由调用方拥有，没有 Runtime/配置借用。query 可跨线程；
 * Core 销毁仍须由宿主保证没有并发 API 使用。路径与代次在同一锁内复制。 */
typedef struct {
  ftun_core_info_t core;
  uint32_t build_modules;
  uint32_t commands;
  size_t queued_commands;
  bool reload_pending;
  bool stop_requested;
  /* 服务级故障计数（按 ftun_fault_scope_t 范围累计）、暂停次数及当前是否
   * 处于暂停新业务的状态。 */
  uint64_t service_faults[FTUN_FAULT_SCOPE_COUNT];
  uint64_t service_pauses;
  bool service_paused;
  ftun_event_log_usage_t events;
  bool logger_present;
  ftun_logger_usage_t logger;
  ftun_log_totals_t log_totals;
  /* runtime_stopped 表示业务模块/Worker/Operation 已停止；Core 仍须等
   * 日志排空和句柄回收后才进入 STOPPED。run_result 仅在 run_returned 时有效。 */
  bool runtime_stopped;
  bool run_returned;
  ftun_status_t run_result;
  ftun_config_trace_t config_trace;
  uint64_t config_trace_generation;
  char config_path[FTUN_APP_CONTROL_PATH_CAPACITY];
} ftun_app_control_snapshot_t;

/* 上一次 run 是否因 owner 失去响应由看门狗终止。 */
bool ftun_app_control_watchdog_fired(ftun_core_t *core);

ftun_status_t ftun_app_control_query(ftun_core_t *core,
  ftun_app_control_snapshot_t *out);

/* reload/select 接纳前复制有界字符串及 guard。同步拒绝清空 out、零回调；
 * 成功后 user 有效至 owner 终结回调，operation 仅借用至回调返回。
 * guard 在接纳和 owner 执行时检查；公开 C 接口不默认增加 guard。
 * 超时停止后 run 的回调截止与后台清理规则沿用公开宿主契约。 */
ftun_status_t ftun_app_control_submit(ftun_core_t *core,
  const ftun_app_command_t *command, ftun_app_command_completion_fn completion,
  void *user, ftun_operation_t **out);

/* stop 使用独立控制门，不依赖队列空位。成功只表示请求已登记；
 * REQUESTED 不等于运行进程已停止，只有已处于 STOPPED 才报告 COMPLETED。 */
ftun_status_t ftun_app_control_stop(ftun_core_t *core, uint64_t deadline_ms,
  ftun_app_generation_guard_t expected, ftun_app_command_result_t *out);

#endif
