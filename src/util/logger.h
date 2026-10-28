#ifndef FTUN_UTIL_LOGGER_H
#define FTUN_UTIL_LOGGER_H
#include "internal/contracts.h"

/* 
 * ftun_log_emit 不把秘密或慢 writer 带入 owner-loop 热路径。 */

typedef enum {
  FTUN_LOG_SILENT = 0,
  FTUN_LOG_ERROR,
  FTUN_LOG_WARN,
  FTUN_LOG_INFO,
  FTUN_LOG_DEBUG,
  FTUN_LOG_TRACE
} ftun_log_level_t;

typedef ftun_status_t (*ftun_log_writer_fn)(void *user, ftun_bytes_t line);

typedef struct ftun_log_ledger ftun_log_ledger_t;

/* 跨当前/候选/退休 sink 的累计记录结果；queued 包含正在 writer 中的记录。
 * written 表示 writer 返回 OK，不承诺 fsync 或持久化。容量含构造中的实例。 */
typedef struct {
  uint64_t created;
  uint64_t destroyed;
  uint64_t emitted;
  uint64_t written;
  uint64_t filtered;
  uint64_t dropped;
  uint64_t rejected;
  uint64_t io_errors;
  uint64_t close_errors;
  uint64_t redacted;
  uint64_t oversized;
  uint64_t truncated;
  size_t instances;
  size_t capacity;
  size_t queued;
} ftun_log_totals_t;

ftun_status_t ftun_log_ledger_create(ftun_budget_t *budget, ftun_log_ledger_t **out);
ftun_status_t ftun_log_ledger_get_usage(ftun_log_ledger_t *ledger, ftun_log_totals_t *out);
/* 唯一拥有者须终止 create/query 并发；仍有关联 logger 时返回 AGAIN。 */
ftun_status_t ftun_log_ledger_destroy(ftun_log_ledger_t **ledger);

typedef struct {
  ftun_log_level_t level;
  const char *path;
  size_t queue_capacity;
  size_t line_capacity;
  ftun_log_writer_fn writer;
  void *writer_user;
  /* 可选借用。拥有者须保持至本实例 destroy 成功；ledger 可并发计数，
   * 不借 Core/Runtime。关联实例在创建前从 ledger 的 Budget 预留对象、
   * 两个缓冲数组、文件 FD 和全部队列槽，直到 destroy 成功才归还；
   * 新旧实例重叠计量，线程栈/allocator/内核缓冲不包含在逻辑字节中。
   * App 在所有 Worker 和候选/退休 logger 之后销毁 ledger。 */
  ftun_log_ledger_t *ledger;
  /* 为每行加上 ts（UTC 毫秒）、seq（进程内单调序号）、boot（进程标识）及
   * 非零的 id 前缀。底层单元测试不开启，产品路径开启。 */
  bool stamp;
  /* 文件轮转（仅 path 方式有效，自定义 writer 时必须为 0）。写入会让当前文件超过
   * max_size 字节时，先把 path.(n-1) 依次改名为 path.n 再新建 path；max_files 是保留
   * 的文件总数（含当前文件，≥1；为 1 时超限直接截断重写）。max_size 为 0 不轮转。 */
  uint64_t max_size;
  size_t max_files;
} ftun_logger_options_t;

/* 进程标识：第一次调用时随机生成，此后不变。不是安全用途的标识。 */
uint64_t ftun_log_boot_id(void);
/* 进程内单调递增的关联 ID，从 1 开始；线程安全。 */
uint64_t ftun_correlation_next(void);

typedef struct {
  size_t capacity;
  size_t queued;
  uint64_t emitted;
  uint64_t filtered;
  uint64_t dropped;
  uint64_t io_errors;
  uint64_t redacted;
  uint64_t oversized;
  uint64_t truncated;
  /* 文件轮转次数、外部请求的重新打开次数、轮转/重新打开失败次数。 */
  uint64_t rotations;
  uint64_t reopens;
  uint64_t rotate_errors;
  bool accepting;
  bool stopping;
  bool exited;
  bool joined;
} ftun_logger_usage_t;

ftun_status_t ftun_log_level_parse(const char *name, ftun_log_level_t *out);
ftun_status_t ftun_logger_create(const ftun_logger_options_t *options,
                                 ftun_logger_t **out);
/* write/usage/stop 可并发；直接句柄的调用者须保证实例存活。每个字段
 * 最多检查 4096 字节，超长字段使整条诊断脱敏，不读取未检查的前缀。
 * 成功只表示日志已过滤或已接纳；队列满时丢弃新项并返回 OK。 */
ftun_status_t ftun_logger_write(ftun_logger_t *logger, ftun_log_level_t level,
                                const ftun_diagnostic_t *diagnostic);
/* 请求重新打开日志文件（配合外部 logrotate：它改走了旧文件之后，下一次写入落在新建
 * 的文件上）。可从任意线程调用，不阻塞；由写入线程执行。自定义 writer 返回 UNSUPPORTED。 */
ftun_status_t ftun_logger_reopen(ftun_logger_t *logger);
ftun_status_t ftun_logger_flush(ftun_logger_t *logger);
ftun_status_t ftun_logger_flush_until(ftun_logger_t *logger,
                                      uint64_t deadline_ms);
ftun_status_t ftun_logger_stop(ftun_logger_t *logger);
/* join/destroy 由唯一拥有者串行调用；destroy 前先撤销发布槽并终止所有
 * 直接句柄借用。writer_user 必须存活至 join/destroy 成功。 */
ftun_status_t ftun_logger_join_until(ftun_logger_t *logger,
                                     uint64_t deadline_ms);
ftun_status_t ftun_logger_get_usage(ftun_logger_t *logger,
                                    ftun_logger_usage_t *out);
ftun_status_t ftun_logger_destroy(ftun_logger_t **logger);
/* 到期时保留 logger 及 writer 仍可能访问的全部内存，调用方稍后重试。 */
ftun_status_t ftun_logger_destroy_until(ftun_logger_t **logger,
                                        uint64_t deadline_ms);
/* Core 便利入口：对当前发布的 logger 请求重新打开日志文件（线程安全）。 */
ftun_status_t ftun_log_reopen(ftun_core_t *core);
/* Core 便利入口；保留 diagnostic 内已捕获的 stage/native_code。 */
ftun_status_t ftun_log_emit(ftun_core_t *core, const ftun_diagnostic_t *diagnostic);
#endif
