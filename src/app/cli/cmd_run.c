#define _POSIX_C_SOURCE 200809L

#include "platform/file.h"
#include "platform/pidfile.h"
#include "app/cli/internal.h"
#include "app/cli/result.h"
#include "app/cli/background.h"
#include "core/context.h"
#include "app/cli/render.h"
#include "core/io/file.h"
#include "app/control.h"
#include "app/control/server.h"
#include "app/control/status.h"

#include "app/config/config.h"
#include "app/config/parser.h"
#include "core/log/log.h"
#include "platform/clock.h"

#include "platform/process.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FTUN_CLI_SIGNALS (FTUN_SIGNAL_HANGUP | FTUN_SIGNAL_INTERRUPT | FTUN_SIGNAL_TERMINATE | FTUN_SIGNAL_USER1)
#define FTUN_CLI_STOP_TIMEOUT_MS UINT64_C(10000)

typedef struct {
  ftun_core_t *core;
  const char *config_path;
  ftun_mutex_t mutex;
  ftun_cli_result_sink_t *results;
  ftun_cli_result_ticket_t *ready_ticket;
  ftun_handle_t background_channel, null_descriptor;
  uint64_t background_deadline;
  bool background_guard;
  ftun_cli_background_guard_t startup_guard;
  ftun_reservation_t background_pipe_budget, null_budget;
  uint64_t stop_deadline_ms;
  int done;
} ftun_cli_signal_context_t;

static ftun_status_t ftun_cli_background_ready(ftun_cli_signal_context_t *context,
  const ftun_ctl_status_t *snapshot, const char *reasons)
{
  ftun_status_t status;
  ftun_cli_background_report_t report = {0};
  uint64_t now;
  status = ftun_monotonic_now(&now);
  if (status == FTUN_OK && now >= context->background_deadline) status = FTUN_E_TIMEOUT;
  if (status != FTUN_OK) return status;
  report.pid = ftun_process_id();
  memcpy(report.reasons, reasons, sizeof(report.reasons));
  if (snapshot->host.logger_present) memcpy(report.log_file, snapshot->log_file, sizeof(report.log_file));
  status = ftun_cli_background_report(context->background_channel, context->background_deadline, &report);
  if (status == FTUN_OK) {
    /* 先交付ready报告，再重定向；父进程还需最后提交字，失败不会误报成功。 */
    ftun_status_t redirected = ftun_process_stdio_null(context->null_descriptor);
    if (redirected == FTUN_OK) {
      redirected = ftun_cli_background_guard_finish(&context->startup_guard);
      context->background_guard = false;
    }
    status = ftun_cli_background_commit(context->background_channel, context->background_deadline, redirected);
    if (status == FTUN_OK) status = redirected;
  }
  (void)ftun_file_close(context->background_channel);
  context->background_channel = -1;
  ftun_reservation_release(&context->background_pipe_budget);
  /* 失败路径仍由guard借用null FD，交给run返回后的join一起回收。 */
  if (!context->background_guard) {
    (void)ftun_file_close(context->null_descriptor);
    context->null_descriptor = -1;
    ftun_reservation_release(&context->null_budget);
  }
  return status;
}

static ftun_status_t ftun_cli_ready_report(ftun_core_t *core,
  ftun_cli_signal_context_t *context, const ftun_ctl_status_t *snapshot)
{
  char reasons[FTUN_CLI_READY_REASONS_CAPACITY] = "";
  size_t used = 0u, index;
  ftun_status_t status;
  for (index = 0u; index < snapshot->service_count; index++) {
    const ftun_ctl_service_status_t *service = &snapshot->services[index];
    int count;
    if (service->status.state == FTUN_SERVICE_FAILED) return FTUN_E_STATE_CORRUPT;
    if (service->status.state == FTUN_SERVICE_ACTIVE || service->status.state == FTUN_SERVICE_DISABLED) continue;
    count = snprintf(reasons + used, sizeof(reasons) - used, "%s%s %s (%s)", used == 0u ? "" : "; ",
      service->name, ftun_service_state_name(service->status.state), ftun_status_name(service->status.reason));
    if (count < 0 || (size_t)count >= sizeof(reasons) - used) return FTUN_E_LIMIT;
    used += (size_t)count;
  }
  if (used != 0u) {
    static const ftun_log_event_t degraded = {FTUN_LOG_APP, FTUN_LOG_WARN, "app.degraded", "degraded"};
    FTUN_CORE_LOG(core, &degraded, .generation = snapshot->host.core.generation,
      .fields = (ftun_log_field_t[]){{.key = "reason", .kind = FTUN_LOG_TEXT, .value.text = {reasons, used}}}, .field_count = 1u);
  }
  if (context->background_channel >= 0) return ftun_cli_background_ready(context, snapshot, reasons);
  status = ftun_cli_result_publish_ready(context->ready_ticket, reasons);
  /* 断开的输出仍消费ticket并记账，不终止已可工作的业务。 */
  if (status == FTUN_OK || status == FTUN_E_IO) {
    context->ready_ticket = NULL;
    return FTUN_OK;
  }
  return status;
}

static ftun_status_t ftun_cli_ready(ftun_core_t *core, void *user)
{
  ftun_ctl_status_t *snapshot;
  ftun_budget_t *budget;
  ftun_reservation_t reservation = {0};
  ftun_status_t status = ftun_core_context_budget(core, &budget);
  if (status == FTUN_OK) status = ftun_budget_reserve(budget, sizeof(*snapshot), &reservation);
  if (status != FTUN_OK) return status;
  /* 完整业务快照只在就绪交接期间存在，不把大缓冲留在主线程栈上。 */
  snapshot = malloc(sizeof(*snapshot));
  if (snapshot == NULL) { ftun_reservation_release(&reservation); return FTUN_E_LIMIT; }
  status = ftun_ctl_status_fill(core, snapshot);
  if (status == FTUN_OK) status = ftun_cli_ready_report(core, user, snapshot);
  free(snapshot);
  ftun_reservation_release(&reservation);
  return status;
}

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
    (void)ftun_cli_result_publish_file(ticket, FTUN_CLI_RESULT_RELOAD_REJECTED,
      error.status, error.stage, result.file_error);
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
        command.source_signal = signal_number;
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
        static const ftun_log_event_t requested = {FTUN_LOG_CTL, FTUN_LOG_INFO, "ctl.stop-requested", "stop requested"};
        FTUN_CORE_LOG(context->core, &requested, .fields = (ftun_log_field_t[]){
          {.key = "source", .kind = FTUN_LOG_TEXT, .value.text = {"signal", 6u}},
          {.key = "signal", .kind = FTUN_LOG_TEXT, .value.text = signal_number == FTUN_SIGNAL_TERMINATE
            ? (ftun_string_t){"SIGTERM", 7u} : (ftun_string_t){"SIGINT", 6u}}}, .field_count = 2u);
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

static ftun_status_t ftun_cli_default_config(const char *path)
{
  static const char contents[] =
    "{\n"
    "  \"dns\": { \"enable\": false },\n"
    "  \"inbounds\": [\n"
    "    { \"name\": \"local\", \"type\": \"socks5\", \"listen\": \"127.0.0.1:1080\" }\n"
    "  ],\n"
    "  \"rules\": [\"MATCH,DIRECT\"]\n"
    "}\n";
  ftun_file_info_t info;
  ftun_string_t parent;
  char directory[4096];
  char message[4192];
  ftun_status_t status = ftun_file_inspect_path(path, &info);
  if (status == FTUN_OK) return FTUN_OK;
  if (status != FTUN_E_EOF) return status;
  status = ftun_platform_file_parent(path, &parent);
  if (status != FTUN_OK) return status;
  memcpy(directory, parent.data, parent.length);
  directory[parent.length] = '\0';
  status = ftun_directory_ensure(directory, 0700u);
  if (status == FTUN_OK) status = ftun_file_create_atomic_budget(NULL, path,
    (ftun_bytes_t){(const uint8_t *)contents, sizeof(contents) - 1u}, 0600u);
  if (status != FTUN_OK) return status;
  (void)snprintf(message, sizeof(message), "ftun: created default configuration: %s\n", path);
  return ftun_cli_output(2, message) == FTUN_EXIT_OK ? FTUN_OK : FTUN_E_IO;
}

int ftun_cli_run(const char *path, const char *pidfile_path, bool no_color, unsigned int verbosity, bool background)
{
  ftun_cli_signal_context_t context;
  ftun_cli_checked_config_t checked = {0};
  ftun_core_t *core = NULL;
  ftun_ctl_server_t *server = NULL;
  ftun_pidfile_t pidfile = FTUN_PIDFILE_INVALID;
  char resolved_path[4096];
  char instance_path[4096];
  char socket_path[4096];
  uint32_t holder = 0u;
  uint32_t failure_module = 0u, failure_stage = FTUN_STAGE_NONE;
  char file_error[FTUN_APP_CONTROL_PATH_CAPACITY] = "";
  ftun_thread_t signal_thread;
  ftun_signal_mask_t previous;
  ftun_status_t status;
  int thread_started = 0;
  int mutex_started = 0;
  int signals_blocked = 0;
  bool background_parent = false, background_child = false;
  int exit_code = 1;
  if (background) {
    status = ftun_process_standard_ensure();
    if (status != FTUN_OK) return ftun_cli_failure("background startup", "failed", ftun_status_name(status), false);
  }
  status = ftun_cli_config_path(path, resolved_path, sizeof(resolved_path));
  if (status == FTUN_OK && path == NULL) status = ftun_cli_default_config(resolved_path);
  if (status != FTUN_OK) return ftun_cli_error("default configuration", status);
  path = resolved_path;
  status = ftun_cli_check_config(path, 1, &checked);
  if (status != FTUN_OK) {
    (void)ftun_cli_checked_config_destroy(&checked);
    return ftun_cli_config_error("run", &checked.error, false);
  }
  status = ftun_pidfile_path(pidfile_path, instance_path, sizeof(instance_path));
  if (status == FTUN_OK) {
    status = ftun_pidfile_socket_path(instance_path, socket_path, sizeof(socket_path));
  }
  if (status == FTUN_OK && pidfile_path == NULL) {
    ftun_string_t parent;
    status = ftun_platform_file_parent(instance_path, &parent);
    if (status == FTUN_OK) {
      char directory[4096];
      memcpy(directory, parent.data, parent.length);
      directory[parent.length] = '\0';
      status = ftun_directory_ensure(directory, 0700u);
    }
  }
  if (status == FTUN_OK) status = ftun_pidfile_acquire(instance_path, &pidfile, &holder);
  if (status != FTUN_OK) {
    (void)ftun_cli_checked_config_destroy(&checked);
    if (status == FTUN_E_AGAIN) {
      char identity[32] = "unknown";
      if (holder > 1u) (void)snprintf(identity, sizeof(identity), "%u", holder);
      fprintf(stderr, "ftun: run: another instance is running (pid %s, pidfile %s); use -p FILE to run another instance\n",
        identity, instance_path);
      return FTUN_EXIT_FAIL;
    }
    return ftun_cli_error("run pidfile", status);
  }
  status = ftun_cli_core_create(checked.config, &core);
  if (status == FTUN_OK) status = ftun_app_control_set_no_color(core, no_color);
  if (status == FTUN_OK) status = ftun_app_control_set_verbosity(core, verbosity);
  if (status == FTUN_OK) status = ftun_app_control_set_background(core, background);
  {
    ftun_status_t cleanup_status = ftun_cli_checked_config_destroy(&checked);
    if (status == FTUN_OK) status = cleanup_status;
  }
  if (status != FTUN_OK) (void)ftun_core_destroy(&core);
  if (status != FTUN_OK) {
    (void)ftun_pidfile_release(&pidfile);
    return ftun_cli_error("create", status);
  }
  memset(&context, 0, sizeof(context));
  context.background_channel = -1;
  context.null_descriptor = -1;
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
  status = ftun_ctl_server_create(core, socket_path, &server);
  if (status == FTUN_E_UNSUPPORTED) {
    fputs("ftun: local control is not supported on this platform\n", stderr);
    status = FTUN_OK;
  }
  if (status == FTUN_OK && server != NULL) status = ftun_app_control_bind_server(core, server);
  if (status != FTUN_OK) {
    (void)snprintf(file_error, sizeof(file_error), "%s", socket_path);
  }
  if (status == FTUN_OK && background) {
    ftun_budget_t *budget = NULL;
    bool child = false;
    uint32_t child_pid = 0u;
    uint64_t now;
    status = ftun_core_context_budget(core, &budget);
    if (status == FTUN_OK) status = ftun_budget_reserve_resources(budget,
      (ftun_budget_resources_t){0u, 2u, 0u}, &context.background_pipe_budget);
    if (status == FTUN_OK) status = ftun_monotonic_now(&now);
    if (status == FTUN_OK) context.background_deadline = now + ftun_cli_background_timeout();
    if (status == FTUN_OK) status = ftun_process_background_fork(&context.background_channel, &child, &child_pid);
    if (status == FTUN_OK && !child) {
      background_parent = true;
      exit_code = ftun_cli_background_wait(context.background_channel, context.background_deadline);
      (void)ftun_file_close(context.background_channel);
      context.background_channel = -1;
      ftun_reservation_release(&context.background_pipe_budget);
      goto done;
    }
    if (status == FTUN_OK) background_child = true;
    if (status == FTUN_OK) status = ftun_thread_block_sigpipe();
    if (status == FTUN_OK) status = ftun_process_background_session();
    if (status == FTUN_OK) status = ftun_budget_reserve_resources(budget,
      (ftun_budget_resources_t){0u, 1u, 0u}, &context.null_budget);
    if (status == FTUN_OK) status = ftun_process_null_open(&context.null_descriptor);
    if (status == FTUN_OK) status = ftun_cli_background_guard_start(&context.startup_guard,
      context.background_deadline, context.null_descriptor);
    if (status == FTUN_OK) context.background_guard = true;
    if (status == FTUN_OK) {
      status = ftun_pidfile_rewrite(&pidfile);
      if (status != FTUN_OK) (void)snprintf(file_error, sizeof(file_error), "%s", instance_path);
    }
  }
  {
    /* 端点失败也走相同的有界结果通道；成功路径的端点准备早于任何线程。 */
    ftun_status_t reporting = background_child && context.null_descriptor < 0 ? FTUN_OK : ftun_cli_result_sink_create(context.background_channel >= 0 && context.null_descriptor >= 0 ?
      context.null_descriptor : ftun_file_standard_error(), &context.results);
    if (status == FTUN_OK) status = reporting;
  }
  if (status == FTUN_OK && !background) status = ftun_cli_result_reserve(context.results, &context.ready_ticket);
  if (status == FTUN_OK) status = ftun_app_control_set_ready(core, ftun_cli_ready, &context);
  if (status != FTUN_OK) goto done;
  if (ftun_thread_create(&signal_thread, ftun_cli_signal_waiter,
                         &context) != FTUN_OK) {
    status = FTUN_E_IO;
    goto done;
  }
  thread_started = 1;
  status = ftun_core_run(core, path);
  if (status == FTUN_OK && background && context.background_channel >= 0) status = FTUN_E_CANCELLED;
  ftun_mutex_lock(&context.mutex);
  context.done = 1;
  ftun_mutex_unlock(&context.mutex);
  (void)ftun_thread_signal(&signal_thread, FTUN_SIGNAL_TERMINATE);
  (void)ftun_thread_join(&signal_thread);
  thread_started = 0;
  /* 看门狗触发后即使 owner 随后正常停止，也要让服务管理器重启进程。 */
  if (ftun_app_control_watchdog_fired(core)) exit_code = FTUN_EXIT_WATCHDOG;
  else if (status == FTUN_OK) exit_code = 0;
  else if (status == FTUN_E_STATE_CORRUPT) exit_code = FTUN_EXIT_FATAL;

done:
  if (thread_started) {
    ftun_mutex_lock(&context.mutex);
    context.done = 1;
    ftun_mutex_unlock(&context.mutex);
    (void)ftun_thread_signal(&signal_thread, FTUN_SIGNAL_TERMINATE);
    (void)ftun_thread_join(&signal_thread);
  }
  if (status != FTUN_OK && core != NULL) {
    ftun_app_control_snapshot_t snapshot;
    if (ftun_app_control_query(core, &snapshot) == FTUN_OK) {
      if (file_error[0] == '\0') memcpy(file_error, snapshot.file_error, sizeof(file_error));
      if (snapshot.startup_error.status != FTUN_OK) {
        failure_stage = snapshot.startup_error.stage;
        if (snapshot.events.has_error && snapshot.events.first_error.kind == FTUN_LIFECYCLE_MODULE_FAILED &&
            snapshot.events.first_error.status == snapshot.startup_error.status) {
          failure_module = snapshot.events.first_error.module;
        }
      }
    }
  }
  if (context.background_channel >= 0) {
    ftun_cli_background_report_t report = {0};
    if (status == FTUN_OK) status = FTUN_E_CANCELLED;
    report.error = (ftun_error_t){status, failure_stage, 0};
    report.module = failure_module;
    report.pid = ftun_process_id();
    memcpy(report.file_error, file_error, sizeof(report.file_error));
    if (ftun_cli_background_report(context.background_channel, context.background_deadline, &report) == FTUN_OK) {
      (void)ftun_cli_background_commit(context.background_channel, context.background_deadline, FTUN_OK);
    }
    (void)ftun_file_close(context.background_channel);
    context.background_channel = -1;
  }
  ftun_reservation_release(&context.background_pipe_budget);
  if (context.background_guard) {
    (void)ftun_cli_background_guard_finish(&context.startup_guard);
    context.background_guard = false;
  }
  if (context.null_descriptor >= 0) {
    (void)ftun_file_close(context.null_descriptor);
    context.null_descriptor = -1;
  }
  ftun_reservation_release(&context.null_budget);
  if (background_parent && server != NULL) {
    ftun_status_t discarded = ftun_ctl_server_discard(&server);
    if (discarded != FTUN_OK) { status = discarded; exit_code = FTUN_EXIT_FAIL; }
    if (server == NULL) (void)ftun_app_control_bind_server(core, NULL);
  }
  if (server != NULL) {
    ftun_status_t finished = ftun_ctl_server_finish(server, status);
    ftun_status_t destroyed = ftun_ctl_server_destroy(&server);
    if (server == NULL) (void)ftun_app_control_bind_server(core, NULL);
    if (status == FTUN_OK && (finished != FTUN_OK || destroyed != FTUN_OK)) {
      status = finished != FTUN_OK ? finished : destroyed;
      exit_code = status == FTUN_E_STATE_CORRUPT ? FTUN_EXIT_FATAL : FTUN_EXIT_FAIL;
    }
  }
  if (ftun_core_destroy(&core) != FTUN_OK && status == FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
    exit_code = FTUN_EXIT_FATAL;
  }
  if (status != FTUN_OK && context.results != NULL) {
    ftun_cli_result_ticket_t *ticket = NULL;
    if (ftun_cli_result_reserve_terminal(context.results,
          FTUN_CLI_RESULT_RUN_FAILED, &ticket) == FTUN_OK) {
      (void)ftun_cli_result_publish_run_failure(ticket, status, failure_stage, failure_module, file_error);
    }
  }
  if (context.ready_ticket != NULL) {
    (void)ftun_cli_result_abandon(context.ready_ticket);
    context.ready_ticket = NULL;
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
  } else if (status != FTUN_OK && !background_child) {
    (void)ftun_cli_error("run", status);
  }
  if (signals_blocked) (void)ftun_signals_restore(&previous);
  if (mutex_started) ftun_mutex_destroy(&context.mutex);
  /* 清理失败且 Core 仍存活时，让内核在进程退出时关闭锁，避免提前开放实例入口。 */
  if (core == NULL) {
    ftun_status_t released = background_parent ? ftun_pidfile_discard(&pidfile) : ftun_pidfile_release(&pidfile);
    if (released != FTUN_OK) {
      (void)ftun_cli_error("pidfile cleanup", released);
      if (exit_code == FTUN_EXIT_OK) exit_code = FTUN_EXIT_FAIL;
    }
  }
  return exit_code;
}
