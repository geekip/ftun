#define _POSIX_C_SOURCE 200809L

#include "platform/file.h"
#include "app/cli/internal.h"
#include "app/cli/result.h"
#include "app/control.h"

#include "app/config/config.h"
#include "app/config/parser.h"
#include "core/log/log.h"
#include "platform/clock.h"

#include "platform/process.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define FTUN_CLI_SIGNALS (FTUN_SIGNAL_HANGUP | FTUN_SIGNAL_INTERRUPT | FTUN_SIGNAL_TERMINATE | FTUN_SIGNAL_USER1)
#define FTUN_CLI_STOP_TIMEOUT_MS UINT64_C(10000)
/* 退出码：0 正常停止，1 配置或启动失败，2 用法错误（见 dispatch），
 * 3 运行时致命错误，4 看门狗触发。 */
#define FTUN_CLI_EXIT_FATAL 3
#define FTUN_CLI_EXIT_WATCHDOG 4

typedef struct {
  ftun_core_t *core;
  const char *config_path;
  ftun_mutex_t mutex;
  ftun_cli_result_sink_t *results;
  uint64_t stop_deadline_ms;
  int done;
} ftun_cli_signal_context_t;

static void ftun_cli_reload_done(ftun_operation_t *operation,
                                 ftun_app_command_result_t result, void *user)
{
  ftun_cli_result_ticket_t *ticket = (ftun_cli_result_ticket_t *)user;
  ftun_error_t error = result.error;
  (void)operation;
  if (error.status == FTUN_OK) {
    (void)ftun_cli_result_publish(ticket, FTUN_CLI_RESULT_RELOAD_COMMITTED,
                                  FTUN_OK, 0u);
  } else {
    (void)ftun_cli_result_publish(ticket, FTUN_CLI_RESULT_RELOAD_REJECTED,
                                  error.status, error.stage);
  }
}

static void *ftun_cli_signal_waiter(void *user)
{
  ftun_cli_signal_context_t *context = (ftun_cli_signal_context_t *)user;
  for (;;) {
    uint32_t signal_number = 0u;
    int done;
    if (ftun_signal_wait(FTUN_CLI_SIGNALS, &signal_number) != FTUN_OK) continue;
    ftun_mutex_lock(&context->mutex);
    done = context->done;
    ftun_mutex_unlock(&context->mutex);
    if (done) break;
    if (signal_number == FTUN_SIGNAL_USER1) {
      /* 外部 logrotate 改走了日志文件：重新打开，之后的日志写进新文件。 */
      (void)ftun_log_reopen(context->core);
    } else if (signal_number == FTUN_SIGNAL_HANGUP) {
      ftun_operation_t *operation = NULL;
      ftun_cli_result_ticket_t *ticket = NULL;
      ftun_status_t status = ftun_cli_result_reserve(context->results, &ticket);
      if (status != FTUN_OK) {
        (void)ftun_cli_result_report_admission_rejected(context->results,
                                                        status);
        continue;
      }
      {
        ftun_app_command_t command;
        memset(&command, 0, sizeof(command));
        command.kind = FTUN_APP_COMMAND_RELOAD;
        command.first = context->config_path;
        status = ftun_app_control_submit(context->core, &command,
          ftun_cli_reload_done, ticket, &operation);
      }
      if (status != FTUN_OK) {
        (void)ftun_cli_result_publish(ticket,
          FTUN_CLI_RESULT_RELOAD_REQUEST_REJECTED, status, 0u);
      }
    } else {
      uint64_t now_ms = 0u;
      ftun_status_t status = ftun_monotonic_now(&now_ms);
      ftun_cli_result_ticket_t *ticket = NULL;
      (void)ftun_cli_result_reserve_terminal(context->results,
        FTUN_CLI_RESULT_STOP_FAILED, &ticket);
      if (status == FTUN_OK &&
          now_ms > UINT64_MAX - FTUN_CLI_STOP_TIMEOUT_MS) {
        status = FTUN_E_LIMIT;
      }
      if (status == FTUN_OK) {
        context->stop_deadline_ms = now_ms + FTUN_CLI_STOP_TIMEOUT_MS;
        ftun_app_command_result_t result;
        ftun_app_generation_guard_t expected = {false, 0u};
        status = ftun_app_control_stop(context->core, context->stop_deadline_ms,
          expected, &result);
      }
      if (ticket != NULL) {
        if (status != FTUN_OK && status != FTUN_E_STALE) {
          (void)ftun_cli_result_publish(ticket, FTUN_CLI_RESULT_STOP_FAILED,
                                        status, 0u);
        } else {
          (void)ftun_cli_result_abandon(ticket);
        }
      }
      break;
    }
  }
  return NULL;
}

int ftun_cli_run(const char *path)
{
  ftun_cli_signal_context_t context;
  ftun_cli_checked_config_t checked = {0};
  ftun_core_t *core = NULL;
  ftun_thread_t signal_thread;
  ftun_signal_mask_t previous;
  ftun_status_t status;
  int thread_started = 0;
  int mutex_started = 0;
  int signals_blocked = 0;
  int exit_code = 1;
  status = ftun_cli_check_config(path, 1, &checked);
  if (status != FTUN_OK) {
    (void)ftun_cli_checked_config_destroy(&checked);
    if (status == FTUN_E_INVALID) {
      fputs("ftun: run: invalid configuration or no service root\n", stderr);
      return 1;
    }
    return ftun_cli_error("run preflight", status);
  }
  status = ftun_cli_core_create(checked.config, &core);
  {
    ftun_status_t cleanup_status = ftun_cli_checked_config_destroy(&checked);
    if (status == FTUN_OK) status = cleanup_status;
  }
  if (status != FTUN_OK) (void)ftun_core_destroy(&core);
  if (status != FTUN_OK) return ftun_cli_error("create", status);
  memset(&context, 0, sizeof(context));
  context.core = core;
  context.config_path = path;
  if (ftun_mutex_init(&context.mutex) != FTUN_OK) {
    status = FTUN_E_IO;
    goto done;
  }
  mutex_started = 1;
  if (ftun_signals_block(FTUN_CLI_SIGNALS, &previous) != FTUN_OK) {
    status = FTUN_E_IO;
    goto done;
  }
  signals_blocked = 1;
  status = ftun_cli_result_sink_create(ftun_file_standard_error(), &context.results);
  if (status != FTUN_OK) goto done;
  if (ftun_thread_create(&signal_thread, ftun_cli_signal_waiter,
                         &context) != FTUN_OK) {
    status = FTUN_E_IO;
    goto done;
  }
  thread_started = 1;
  status = ftun_core_run(core, path);
  ftun_mutex_lock(&context.mutex);
  context.done = 1;
  ftun_mutex_unlock(&context.mutex);
  (void)ftun_thread_signal(&signal_thread, FTUN_SIGNAL_TERMINATE);
  (void)ftun_thread_join(&signal_thread);
  thread_started = 0;
  /* 看门狗触发后即使 owner 随后正常停止，也要让服务管理器重启进程。 */
  if (ftun_app_control_watchdog_fired(core)) exit_code = FTUN_CLI_EXIT_WATCHDOG;
  else if (status == FTUN_OK) exit_code = 0;
  else if (status == FTUN_E_STATE_CORRUPT) exit_code = FTUN_CLI_EXIT_FATAL;

done:
  if (thread_started) {
    ftun_mutex_lock(&context.mutex);
    context.done = 1;
    ftun_mutex_unlock(&context.mutex);
    (void)ftun_thread_signal(&signal_thread, FTUN_SIGNAL_TERMINATE);
    (void)ftun_thread_join(&signal_thread);
  }
  if (ftun_core_destroy(&core) != FTUN_OK && status == FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
    exit_code = FTUN_CLI_EXIT_FATAL;
  }
  if (status != FTUN_OK && context.results != NULL) {
    ftun_cli_result_ticket_t *ticket = NULL;
    if (ftun_cli_result_reserve_terminal(context.results,
          FTUN_CLI_RESULT_RUN_FAILED, &ticket) == FTUN_OK) {
      (void)ftun_cli_result_publish(ticket, FTUN_CLI_RESULT_RUN_FAILED,
                                    status, 0u);
    }
  }
  if (context.results != NULL) {
    uint64_t deadline = context.stop_deadline_ms;
    if (deadline == 0u) {
      uint64_t now_ms = 0u;
      if (ftun_monotonic_now(&now_ms) == FTUN_OK &&
          now_ms <= UINT64_MAX - FTUN_CLI_STOP_TIMEOUT_MS) {
        deadline = now_ms + FTUN_CLI_STOP_TIMEOUT_MS;
      }
    }
    (void)ftun_cli_result_sink_stop_until(&context.results, deadline);
  } else if (status != FTUN_OK) {
    (void)ftun_cli_error("run", status);
  }
  if (signals_blocked) (void)ftun_signals_restore(&previous);
  if (mutex_started) ftun_mutex_destroy(&context.mutex);
  return exit_code;
}
