#ifndef FTUN_UTIL_LOGGER_H
#define FTUN_UTIL_LOGGER_H
#include "internal/contracts.h"

/* REQ-OBS-001 / TASK-UTIL-001 / TEST-UTIL-001，目标 0.5.0：
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

typedef struct {
  ftun_log_level_t level;
  const char *path;
  size_t queue_capacity;
  size_t line_capacity;
  ftun_log_writer_fn writer;
  void *writer_user;
} ftun_logger_options_t;

typedef struct {
  size_t capacity;
  size_t queued;
  uint64_t emitted;
  uint64_t filtered;
  uint64_t dropped;
  uint64_t io_errors;
  bool accepting;
  bool stopping;
  bool exited;
  bool joined;
} ftun_logger_usage_t;

ftun_status_t ftun_log_level_parse(const char *name, ftun_log_level_t *out);
ftun_status_t ftun_logger_create(const ftun_logger_options_t *options,
                                 ftun_logger_t **out);
/* 成功只表示日志已过滤或已接纳；队列满时丢弃新项并返回 OK。 */
ftun_status_t ftun_logger_write(ftun_logger_t *logger, ftun_log_level_t level,
                                const ftun_diagnostic_t *diagnostic);
ftun_status_t ftun_logger_flush(ftun_logger_t *logger);
ftun_status_t ftun_logger_flush_until(ftun_logger_t *logger,
                                      uint64_t deadline_ms);
ftun_status_t ftun_logger_stop(ftun_logger_t *logger);
ftun_status_t ftun_logger_join_until(ftun_logger_t *logger,
                                     uint64_t deadline_ms);
ftun_status_t ftun_logger_get_usage(ftun_logger_t *logger,
                                    ftun_logger_usage_t *out);
ftun_status_t ftun_logger_destroy(ftun_logger_t **logger);
/* 到期时保留 logger 及 writer 仍可能访问的全部内存，调用方稍后重试。 */
ftun_status_t ftun_logger_destroy_until(ftun_logger_t **logger,
                                        uint64_t deadline_ms);
/* Core 便利入口；保留 diagnostic 内已捕获的 stage/native_code。 */
ftun_status_t ftun_log_emit(ftun_core_t *core, const ftun_diagnostic_t *diagnostic);
#endif
