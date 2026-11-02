#ifndef FTUN_APP_CLI_BACKGROUND_H
#define FTUN_APP_CLI_BACKGROUND_H
#include "app/cli/result.h"
#include "platform/process.h"

/* fork两端同一二进制的固定拥有型报告，无指针、无外部序列化输入。 */
typedef struct {
  ftun_error_t error;
  uint32_t module, pid;
  char reasons[FTUN_CLI_READY_REASONS_CAPACITY];
  char file_error[FTUN_APP_CONTROL_PATH_CAPACITY];
  char log_file[FTUN_APP_CONTROL_PATH_CAPACITY];
} ftun_cli_background_report_t;

/* CLI栈拥有；只借用null FD至finish成功join，先于Core/FD预算销毁。
 * guard线程仅操作自己条件变量、标准流和原生信号，不取Core锁。 */
typedef struct {
  ftun_thread_t thread;
  ftun_mutex_t mutex;
  ftun_condition_t condition;
  ftun_process_alarm_t alarm;
  ftun_handle_t null_descriptor;
  uint64_t deadline_ms;
  ftun_status_t result;
  bool quit;
} ftun_cli_background_guard_t;
ftun_status_t ftun_cli_background_guard_start(ftun_cli_background_guard_t *guard,
  uint64_t deadline_ms, ftun_handle_t null_descriptor);
ftun_status_t ftun_cli_background_guard_finish(ftun_cli_background_guard_t *guard);

uint32_t ftun_cli_background_timeout(void);
/* parent仅在收到完整报告及最终提交状态后确认ready；均共享绝对期限。 */
int ftun_cli_background_wait(ftun_handle_t channel, uint64_t deadline_ms);
ftun_status_t ftun_cli_background_report(ftun_handle_t channel, uint64_t deadline_ms,
  const ftun_cli_background_report_t *report);
ftun_status_t ftun_cli_background_commit(ftun_handle_t channel, uint64_t deadline_ms, ftun_status_t status);
#endif
