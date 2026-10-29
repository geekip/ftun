#ifndef FTUN_APP_RUNTIME_INTERNAL_H
#define FTUN_APP_RUNTIME_INTERNAL_H

#include "platform/file.h"
#include "app/control/diagnostics.h"
#include "core/core.h"
#include "app/cleanup.h"
#include "app/control.h"
#include "app/runtime_support.h"
#include "app/control/watchdog.h"

#include "app/config/config.h"
#include "app/config/compile.h"
#include "app/config/model.h"
#include "app/config/parser.h"
#include "core/limits.h"
#include "core/operation.h"
#include "core/worker.h"
#include "core/recovery.h"
#include "core/log/log.h"
#include "core/log/event_log.h"
#include "core/context.h"
#include "platform/clock.h"

#include <stddef.h>
#include "platform/thread.h"
#include <stdlib.h>
#include <string.h>

#define FTUN_CORE_MAINTAIN_QUOTA 16u
/* 看门狗判定失去响应后留给停止的期限与宽限，之和为最终期限。 */
#define FTUN_CORE_WATCHDOG_STOP_MS 10000u
#define FTUN_CORE_WATCHDOG_GRACE_MS 5000u
#define FTUN_CORE_SERVICE_RETRY_INITIAL_MS UINT64_C(1000)
#define FTUN_CORE_SERVICE_RETRY_MAXIMUM_MS UINT64_C(30000)
#define FTUN_CORE_SERVICE_RETRY_STABLE_MS UINT64_C(60000)

#define FTUN_CORE_DEFAULT_MEMORY (64u * 1024u * 1024u)
#define FTUN_CORE_DEFAULT_OPERATIONS 1024u
#define FTUN_CORE_MIN_OPERATIONS 4u
#define FTUN_CORE_MAX_OPERATIONS 4096u
#define FTUN_CORE_DEFAULT_RETAINED 4u
#define FTUN_CORE_DEFAULT_DESCRIPTORS 4096u
#define FTUN_CORE_DEFAULT_QUEUE_SLOTS 4096u
#define FTUN_CORE_MIN_MEMORY (1024u * 1024u)
#define FTUN_CORE_MIN_DESCRIPTORS 16u
#define FTUN_CORE_MIN_QUEUE_SLOTS 64u
#define FTUN_CORE_CONTROL_STRING 4096u
#define FTUN_CORE_RELOAD_WORK_MAGIC UINT32_C(0x4654524c)
#define FTUN_CORE_OPERATION_DISPATCH_QUOTA 32u
#define FTUN_CORE_STATE_WORKER_CAPACITY 4u

typedef enum {
  FTUN_CONTROL_POST = 1,
  FTUN_CONTROL_RELOAD,
  FTUN_CONTROL_SELECT
} ftun_control_kind_t;

typedef struct {
  char *value;
  ftun_reservation_t reservation;
} ftun_core_owned_path_t;

typedef struct ftun_control_task {
  ftun_core_t *core;
  ftun_operation_t *operation;
  ftun_operation_token_t completion_token;
  ftun_completion_fn completion;
  ftun_app_command_completion_fn command_completion;
  ftun_app_generation_guard_t expected;
  uint64_t result_generation;
  void *completion_user;
  char *first;
  char *second;
  ftun_control_kind_t kind;
  ftun_operation_t *prepare_operation;
  ftun_reservation_t reservation;
  ftun_mutex_t mutex;
  int cancelled;
  int ring_consumed;
  int callback_complete;
  int async_started;
  int async_complete;
  int control_priority;
  bool reload_event_recorded; /* 只由 owner 的完成/取消派发使用。 */
  void *reload_transaction;
} ftun_control_task_t;

typedef struct {
  uint32_t magic;
  uint32_t socket_mark;
  bool allow_system_resolver;
  uint64_t base_generation;
  uint64_t maximum_bytes;
  uintptr_t service_descriptor;
  uintptr_t owner;
  uintptr_t log_ledger;
  uintptr_t plan_budget;
  uint32_t path_length;
} ftun_core_reload_work_t;

typedef struct {
  uint64_t base_generation;
  uintptr_t owner;
  ftun_status_t status;
  uintptr_t config;
  uintptr_t attachment;
  ftun_core_service_plan_t service_plan;
  uintptr_t logger;
  ftun_core_owned_path_t source_path;
  bool publish_required;
  ftun_config_trace_t config_trace;
} ftun_core_reload_result_t;

typedef struct {
  ftun_config_t *config;
  ftun_app_runtime_candidate_t *candidate;
  ftun_core_service_plan_t service_plan;
  ftun_logger_t *next_logger;
  ftun_core_owned_path_t next_path;
  ftun_reservation_t reservation;
  uint64_t next_generation;
  bool replace_logger;
  bool service_prepared;
  bool generation_reserved; /* next_generation 已在 Core 上下文预留。 */
} ftun_core_reload_transaction_t;

typedef struct {
  ftun_mutex_t mutex;
  ftun_condition_t condition;
  ftun_budget_t *root_budget;
  ftun_budget_t *budget;
  ftun_budget_t *data_budget;
  ftun_reservation_t reservation;
  size_t bootstrap_bytes;
  ftun_operation_queue_t *operations;
  ftun_logger_t *logger;
  ftun_logger_t *retired_logger;
  const ftun_core_service_descriptor_t *service_descriptor;
  ftun_core_service_t service;
  ftun_core_t *core;
  ftun_worker_t *reload_worker;
  ftun_worker_t *state_worker;
  ftun_core_reload_result_t retired_result;
  ftun_core_reload_transaction_t *retired_transaction;
  const ftun_app_runtime_support_t *support;
  ftun_config_t *active_config;
  ftun_config_t *startup_config;
  ftun_app_runtime_candidate_t *startup_candidate;
  ftun_logger_t *startup_logger;
  ftun_event_log_t *events;
  ftun_log_ledger_t *log_ledger;
  bool lifecycle_started;
  bool runtime_stopped;
  bool run_returned;
  ftun_status_t run_result;
  ftun_config_trace_t config_trace;
  uint64_t config_trace_generation;
  ftun_control_task_t **tasks;
  ftun_core_owned_path_t config_path;
  ftun_core_owned_path_t startup_path;
  size_t task_capacity;
  size_t task_head;
  size_t task_tail;
  size_t task_count;
  size_t normal_task_count;
  size_t task_control_reserve;
  uint64_t owner_rounds;
  uint64_t owner_max_busy_ms;
  uint64_t owner_max_deadline_lateness_ms;
  uint64_t stop_deadline_ms;
  size_t owner_max_work;
  uint64_t owner_quota_exhaustions;
  /* 服务级故障：按范围累计的计数、当前是否暂停新业务、暂停次数。
   * recovery 只在服务支持 maintain_once 时存在，单实体表示“服务可运行”。 */
  uint64_t service_faults[FTUN_FAULT_SCOPE_COUNT];
  uint64_t service_pauses;
  uint64_t reload_correlation;
  bool service_paused;
  /* 心跳看门狗：线程只通过原子量和 watchdog_wake 与 owner 通信。 */
  ftun_watchdog_t *watchdog;
  size_t watchdog_slot;
  bool watchdog_fired;
  ftun_recovery_scheduler_t *recovery;
  ftun_recovery_id_t recovery_id;
  ftun_core_state_t state;
  int owner_valid;
  int stop_requested;
  int reload_pending;
  bool callbacks_enabled;
  bool service_stopped;
  bool state_save_done;
  bool state_save_submitted;
  bool retired_busy;
  ftun_status_t first_error;
  ftun_status_t cleanup_error;
} ftun_core_control_t;


ftun_app_cleanup_t ftun_core_cleanup(ftun_core_control_t *control);
ftun_status_t ftun_core_control(ftun_core_t *core, ftun_core_control_t **out);
uint64_t ftun_core_generation_now(const ftun_core_control_t *control);
ftun_status_t ftun_core_generation_settle(ftun_core_t *core, uint64_t next);
void ftun_core_event(ftun_core_control_t *control, ftun_lifecycle_kind_t kind,
  uint64_t generation, ftun_status_t status);
void ftun_core_config_trace(ftun_core_control_t *control,
  const ftun_config_trace_t *trace, uint64_t generation);
ftun_status_t ftun_core_owned_path_copy(ftun_budget_t *budget,
  const char *value, ftun_core_owned_path_t *out);
ftun_status_t ftun_core_owned_path_destroy(ftun_core_owned_path_t *path);
ftun_status_t ftun_core_prepare_parent(const char *path);
ftun_status_t ftun_core_logger_create(const ftun_config_t *config,
  ftun_log_ledger_t *ledger, ftun_logger_t **out);
ftun_status_t ftun_core_logger_reap(ftun_core_control_t *control,
  uint64_t deadline_ms);
ftun_status_t ftun_core_logger_retire(ftun_core_control_t *control,
  ftun_logger_t **logger);
int ftun_control_task_cancelled(ftun_control_task_t *task);
void ftun_control_task_destroy(ftun_control_task_t *task);
void ftun_control_task_consumed(ftun_control_task_t *task);
void ftun_core_log_status(ftun_core_t *core, ftun_status_t status,
  uint32_t stage, ftun_diagnostic_kind_t kind, const char *message);
ftun_status_t ftun_core_transaction(ftun_core_t *core,
  ftun_core_control_t *control, const char *path, uint32_t *out_stage);
void ftun_core_reload_event(ftun_control_task_t *task,
  ftun_core_control_t *control, ftun_status_t status);
ftun_status_t ftun_core_reload_result_release(
  ftun_core_reload_result_t *result, uint64_t deadline);
ftun_status_t ftun_core_reload_transaction_cleanup(ftun_core_t *core,
  ftun_core_control_t *control,
  ftun_core_reload_transaction_t **transaction, uint64_t deadline);
ftun_status_t ftun_core_reload_prepare_transaction(ftun_core_t *core,
  ftun_core_control_t *control, ftun_core_reload_result_t *prepared,
  ftun_core_reload_transaction_t **out, uint32_t *out_stage);
ftun_status_t ftun_core_reload_commit_transaction(ftun_core_t *core,
  ftun_core_control_t *control, ftun_core_reload_transaction_t *transaction);
ftun_status_t ftun_core_state_schedule(ftun_core_t *core,
  ftun_core_control_t *control, const char *path, uint64_t deadline_ms);
ftun_status_t ftun_core_reload_reap(ftun_core_control_t *control,
  uint64_t deadline_ms);
ftun_status_t ftun_core_reload_schedule(ftun_core_control_t *control,
  ftun_control_task_t *task);
void ftun_core_reload_wakeup(void *user);
ftun_status_t ftun_core_cleanup_step(void *context, bool may_wait,
  bool *complete, bool *progress);

#endif
