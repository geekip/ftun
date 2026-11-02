#include "app/cli/background.h"
#include "app/cli/internal.h"
#include "app/cli/render.h"
#include "platform/process.h"
#include "platform/file.h"
#include "platform/clock.h"

uint32_t ftun_cli_background_timeout(void) { return 60000u; }

ftun_status_t ftun_cli_background_report(ftun_handle_t channel, uint64_t deadline_ms,
  const ftun_cli_background_report_t *report)
{
  return ftun_process_pipe_write(channel, report, sizeof(*report), deadline_ms);
}
ftun_status_t ftun_cli_background_commit(ftun_handle_t channel, uint64_t deadline_ms, ftun_status_t status)
{
  return ftun_process_pipe_write(channel, &status, sizeof(status), deadline_ms);
}

int ftun_cli_background_wait(ftun_handle_t channel, uint64_t deadline_ms)
{
  ftun_cli_background_report_t report = {0};
  ftun_cli_result_sink_t *results = NULL;
  ftun_cli_result_ticket_t *ticket = NULL;
  ftun_status_t commit = FTUN_E_AGAIN;
  ftun_status_t status = ftun_process_pipe_read(channel, &report, sizeof(report), deadline_ms);
  uint64_t now;
  int result;
  if (status == FTUN_OK) status = ftun_process_pipe_read(channel, &commit, sizeof(commit), deadline_ms);
  if (status != FTUN_OK) {
    (void)ftun_cli_failure("background startup", "failed", ftun_status_name(status), false);
    return FTUN_EXIT_FAIL;
  }
  if (commit != FTUN_OK) {
    (void)ftun_cli_failure("background standard streams", "failed", ftun_status_name(commit), false);
    return FTUN_EXIT_FAIL;
  }
  result = report.error.status == FTUN_OK ? FTUN_EXIT_OK : FTUN_EXIT_FAIL;
  status = ftun_cli_result_sink_create(ftun_file_standard_error(), &results);
  if (status == FTUN_OK) status = report.error.status == FTUN_OK ? ftun_cli_result_reserve(results, &ticket) :
    ftun_cli_result_reserve_terminal(results, FTUN_CLI_RESULT_RUN_FAILED, &ticket);
  if (status == FTUN_OK) {
    if (report.error.status == FTUN_OK) {
      (void)ftun_cli_result_publish_background_ready(ticket, report.pid, report.log_file, report.reasons);
    } else {
      (void)ftun_cli_result_publish_run_failure(ticket, report.error.status, report.error.stage,
        report.module, report.file_error);
    }
  }
  if (results != NULL) {
    now = 0u;
    (void)ftun_monotonic_now(&now);
    (void)ftun_cli_result_sink_stop_until(&results, now + 2000u);
  }
  return result;
}

static void *ftun_cli_background_guard_wait(void *user)
{
  ftun_cli_background_guard_t *guard = user;
  ftun_status_t waited = FTUN_OK;
  bool expired;
  int native_error;
  ftun_mutex_lock(&guard->mutex);
  while (!guard->quit && waited == FTUN_OK) {
    waited = ftun_condition_wait_until(&guard->condition, &guard->mutex, guard->deadline_ms);
  }
  expired = !guard->quit;
  if (expired) guard->result = waited;
  ftun_mutex_unlock(&guard->mutex);
  if (expired) {
    /* 释放调用方捕获管道的引用；即使owner卡死，父进程仍能按期限返回。 */
    (void)ftun_process_stdio_null(guard->null_descriptor);
    (void)ftun_process_signal(ftun_process_id(), FTUN_SIGNAL_TERMINATE, &native_error);
    /* 与既有看门狗一样保留线程退出路径，内核alarm独立保障线程失去进展。 */
    waited = FTUN_OK;
    ftun_mutex_lock(&guard->mutex);
    while (!guard->quit && waited == FTUN_OK) {
      waited = ftun_condition_wait_until(&guard->condition, &guard->mutex, guard->deadline_ms + 10000u);
    }
    expired = !guard->quit;
    ftun_mutex_unlock(&guard->mutex);
    if (expired) ftun_process_exit(FTUN_EXIT_FAIL);
  }
  return NULL;
}

ftun_status_t ftun_cli_background_guard_start(ftun_cli_background_guard_t *guard,
  uint64_t deadline_ms, ftun_handle_t null_descriptor)
{
  uint64_t now;
  ftun_status_t status = ftun_monotonic_now(&now);
  if (status != FTUN_OK) return status;
  if (now >= deadline_ms) return FTUN_E_TIMEOUT;
  guard->deadline_ms = deadline_ms;
  guard->null_descriptor = null_descriptor;
  guard->result = FTUN_OK;
  guard->quit = false;
  if (ftun_mutex_init(&guard->mutex) != FTUN_OK) return FTUN_E_IO;
  if (ftun_condition_init(&guard->condition) != FTUN_OK) {
    ftun_mutex_destroy(&guard->mutex);
    return FTUN_E_IO;
  }
  status = ftun_process_alarm_start(&guard->alarm, deadline_ms - now + 10000u);
  if (status != FTUN_OK) goto failed;
  status = ftun_thread_create(&guard->thread, ftun_cli_background_guard_wait, guard);
  if (status == FTUN_OK) return FTUN_OK;
  ftun_process_alarm_destroy(&guard->alarm);
failed:
  ftun_condition_destroy(&guard->condition);
  ftun_mutex_destroy(&guard->mutex);
  return status;
}

ftun_status_t ftun_cli_background_guard_finish(ftun_cli_background_guard_t *guard)
{
  ftun_status_t result;
  ftun_mutex_lock(&guard->mutex);
  guard->quit = true;
  result = guard->result;
  ftun_condition_broadcast(&guard->condition);
  ftun_mutex_unlock(&guard->mutex);
  if (ftun_thread_join(&guard->thread) != FTUN_OK) {
    /* 不能让仍借用CLI栈/FD的线程晚于宿主返回。 */
    ftun_process_exit(FTUN_EXIT_FATAL);
    return FTUN_E_STATE_CORRUPT;
  }
  ftun_process_alarm_destroy(&guard->alarm);
  ftun_condition_destroy(&guard->condition);
  ftun_mutex_destroy(&guard->mutex);
  return result;
}
