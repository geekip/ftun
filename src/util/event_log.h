#ifndef FTUN_UTIL_EVENT_LOG_H
#define FTUN_UTIL_EVENT_LOG_H

#include "core/budget.h"
#include "util/logger.h"

#define FTUN_EVENT_LOG_EARLY_CAPACITY 16u
#define FTUN_DIAGNOSTIC_MESSAGE_CAPACITY 192u

/* 固定生产类别，不从配置、路径或任意输入生成限频键。 */
typedef enum {
  FTUN_DIAGNOSTIC_STATE_SAVE = 1,
  FTUN_DIAGNOSTIC_CONTROL,
  FTUN_DIAGNOSTIC_RELOAD_PUBLISH,
  FTUN_DIAGNOSTIC_RELOAD_WORKER,
  FTUN_DIAGNOSTIC_STATE_WORKER,
  FTUN_DIAGNOSTIC_SERVICE_RUN,
  FTUN_DIAGNOSTIC_STARTUP_PUBLISH,
  FTUN_DIAGNOSTIC_STATE_DISCARD,
  FTUN_DIAGNOSTIC_FAKEIP_RESERVE,
  FTUN_DIAGNOSTIC_FAKEIP_SCHEDULE,
  FTUN_DIAGNOSTIC_UDP_RELEASE,
  FTUN_DIAGNOSTIC_HEALTH_PUBLISH,
  FTUN_DIAGNOSTIC_FRS_UPDATE,
  FTUN_DIAGNOSTIC_FRS_PUBLISH,
  FTUN_DIAGNOSTIC_FRS_SCHEDULE,
  FTUN_DIAGNOSTIC_COUNT
} ftun_diagnostic_kind_t;

/* 仅用于既有固定诊断文本；不接纳配置内容和借用字符串。 */
typedef struct {
  ftun_diagnostic_kind_t kind;
  uint64_t generation;
  ftun_error_t error;
  char message[FTUN_DIAGNOSTIC_MESSAGE_CAPACITY];
} ftun_diagnostic_event_t;

typedef enum {
  FTUN_LIFECYCLE_STARTING = 1,
  FTUN_LIFECYCLE_CONFIG_READ,
  FTUN_LIFECYCLE_CONFIG_PARSED,
  FTUN_LIFECYCLE_CONFIG_VALIDATED,
  FTUN_LIFECYCLE_CONFIG_COMPILED,
  FTUN_LIFECYCLE_CONFIG_FAILED,
  FTUN_LIFECYCLE_MODULE_SELECTED,
  FTUN_LIFECYCLE_MODULE_DISABLED,
  FTUN_LIFECYCLE_MODULE_PREPARING,
  FTUN_LIFECYCLE_MODULE_PREPARED,
  FTUN_LIFECYCLE_MODULE_ACTIVE,
  FTUN_LIFECYCLE_MODULE_QUIESCED,
  FTUN_LIFECYCLE_MODULE_DRAINED,
  FTUN_LIFECYCLE_MODULE_STOPPED,
  FTUN_LIFECYCLE_MODULE_FAILED,
  FTUN_LIFECYCLE_ROLLBACK,
  FTUN_LIFECYCLE_RUNNING,
  FTUN_LIFECYCLE_RELOAD_REQUESTED,
  FTUN_LIFECYCLE_RELOAD_COMMITTED,
  FTUN_LIFECYCLE_RELOAD_REJECTED,
  FTUN_LIFECYCLE_STOPPING,
  FTUN_LIFECYCLE_STOPPED, /* runtime.stopped：诊断自身排空另由 Core/ledger 表示。 */
  FTUN_LIFECYCLE_STOP_FAILED,
  FTUN_LIFECYCLE_RELOAD_CANCELLED,
  FTUN_LIFECYCLE_COUNT
} ftun_lifecycle_kind_t;

typedef enum {
  FTUN_LIFECYCLE_REASON_NONE = 0,
  FTUN_LIFECYCLE_REASON_REQUIRED,
  FTUN_LIFECYCLE_REASON_DEPENDENCY,
  FTUN_LIFECYCLE_REASON_OPTIONAL,
  FTUN_LIFECYCLE_REASON_NOT_SELECTED,
  FTUN_LIFECYCLE_REASON_NOT_BUILT,
  FTUN_LIFECYCLE_REASON_NOT_REGISTERED,
  FTUN_LIFECYCLE_REASON_CONFIG_READ,
  FTUN_LIFECYCLE_REASON_CONFIG_PARSE,
  FTUN_LIFECYCLE_REASON_CONFIG_PATHS,
  FTUN_LIFECYCLE_REASON_CONFIG_VALIDATE,
  FTUN_LIFECYCLE_REASON_CONFIG_COMPILE,
  FTUN_LIFECYCLE_REASON_LOG_DRAINING,
  FTUN_LIFECYCLE_REASON_ADMISSION,
  FTUN_LIFECYCLE_REASON_RUN,
  FTUN_LIFECYCLE_REASON_QUIESCE,
  FTUN_LIFECYCLE_REASON_DRAIN,
  FTUN_LIFECYCLE_REASON_DESTROY,
  FTUN_LIFECYCLE_REASON_RELOAD_PREPARE,
  FTUN_LIFECYCLE_REASON_RELOAD_COMMIT,
  FTUN_LIFECYCLE_REASON_RELOAD_ABORT,
  FTUN_LIFECYCLE_REASON_COUNT
} ftun_lifecycle_reason_t;

/* 只接纳枚举与数值，不采集配置内容、凭据、URL 或借用字符串。
 * module 为一个 FTUN_BUILD_MODULE 位，零表示 App；generation 属于事件。 */
typedef struct {
  ftun_lifecycle_kind_t kind;
  uint32_t module;
  uint64_t generation;
  ftun_status_t status;
  ftun_lifecycle_reason_t reason;
} ftun_lifecycle_event_t;

typedef struct ftun_event_log ftun_event_log_t;

typedef struct {
  uint64_t recorded;
  uint64_t forwarded;
  uint64_t early_dropped;
  uint64_t suppressed;
  uint64_t filtered_without_sink;
  uint64_t unavailable;
  size_t buffered;
  bool configured;
  bool closed;
  bool has_last;
  bool has_error;
  ftun_lifecycle_event_t last;
  ftun_lifecycle_event_t last_error;
  uint64_t diagnostics;
  uint64_t diagnostic_suppressed;
  bool has_diagnostic;
  ftun_diagnostic_event_t last_diagnostic;
} ftun_event_log_usage_t;

ftun_status_t ftun_event_log_create(ftun_budget_t *budget, ftun_event_log_t **out);
/* 除 destroy 外可并发。logger 只在调用期间借用，不被保存；调用方须与
 * sink 的退休同步。forwarded 仅表示交给 logger，真实过滤/丢弃/IO 见其 usage。 */
ftun_status_t ftun_event_log_record(ftun_event_log_t *log,
  ftun_logger_t *logger, const ftun_lifecycle_event_t *event, uint64_t now_ms);
/* 每类别/代次/错误/消息一秒前四条保持原格式，重复项汇总；调用期间
 * 复制消息。与生命周期事件共享有界早期 FIFO、切换与停止边界。 */
ftun_status_t ftun_event_log_diagnostic(ftun_event_log_t *log,
  ftun_logger_t *logger, const ftun_diagnostic_event_t *event, uint64_t now_ms);
ftun_status_t ftun_diagnostic_emit(ftun_core_t *core,
  const ftun_diagnostic_event_t *event);
/* message 必须是生产者的固定诊断，不可传配置/凭据；长度小于固定上限。
 * generation 由调用方捕获，接口不读 owner 的可变状态。 */
ftun_status_t ftun_diagnostic_report(ftun_core_t *core, ftun_diagnostic_kind_t kind,
  uint64_t generation, ftun_error_t error, const char *message);
/* 配置确定后按 FIFO 输出早期事件；silent 使用 NULL logger，其他情形
 * 必须提供有效 logger。不得借补齐事件绕过 logger 的既有级别过滤。 */
ftun_status_t ftun_event_log_publish(ftun_event_log_t *log,
  ftun_logger_t *logger, bool silent);
/* 调用方串行切换发布槽：先向旧 sink 汇总，再更改过滤状态。
 * 不保存新旧 logger；即使旧 sink 拒绝汇总，新过滤状态仍生效。
 * 未 publish 或已 finish 返回 STALE，状态不变。 */
ftun_status_t ftun_event_log_reconfigure(ftun_event_log_t *log,
  ftun_logger_t *old_logger, bool silent);
/* 每种事件/模块/代次/状态一秒最多四条重复错误，后续错误计数；
 * 同类同模块的新窗口、状态/代次/原因变化、切换 sink 或 finish 输出汇总，
 * 不登记周期 timer，不在空闲时刷屏。 */
ftun_status_t ftun_event_log_finish(ftun_event_log_t *log, ftun_logger_t *logger);
/* 先汇总，后记录一次 terminal，再关闭接纳；重试不重复 terminal。
 * 未配置 sink 时保存 terminal 值，并把未输出事件计入 early_dropped。 */
ftun_status_t ftun_event_log_finish_with(ftun_event_log_t *log,
  ftun_logger_t *logger, const ftun_lifecycle_event_t *terminal);
ftun_status_t ftun_event_log_get_usage(ftun_event_log_t *log,
  ftun_event_log_usage_t *out);
/* 重试启动前显式重置阶段；仅初始空状态或 finish 后允许，总计数保留。
 * 活动阶段返回 AGAIN，不能无声丢弃尚未汇总的错误。 */
ftun_status_t ftun_event_log_begin(ftun_event_log_t *log);
/* 唯一拥有者先撤销发布槽及所有借用，才可销毁。 */
ftun_status_t ftun_event_log_destroy(ftun_event_log_t **log);

/* Core 入口同时借用记录器与 sink；没有记录器时返回 AGAIN。
 * 事件的代次由调用方提供，不跨线程读取 owner 的可变 generation。 */
ftun_status_t ftun_lifecycle_emit(ftun_core_t *core,
  const ftun_lifecycle_event_t *event);

#endif
