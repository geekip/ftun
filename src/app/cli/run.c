#define _POSIX_C_SOURCE 200809L

#include "app/cli/internal.h"

#include "config/config.h"
#include "config/parser.h"
#include "util/time.h"

#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define FTUN_CLI_STOP_TIMEOUT_MS UINT64_C(10000)

typedef struct {
  ftun_core_t *core;
  const char *config_path;
  pthread_mutex_t mutex;
  int done;
} ftun_cli_signal_context_t;

static void ftun_cli_reload_done(ftun_operation_t *operation,
                                 ftun_error_t error, void *user)
{
  (void)operation;
  (void)user;
  if (error.status == FTUN_OK) {
    fputs("ftun: reload committed\n", stderr);
  } else {
    fprintf(stderr, "ftun: reload rejected at stage %u: %s\n",
            error.stage, ftun_status_name(error.status));
  }
}

static void *ftun_cli_signal_waiter(void *user)
{
  ftun_cli_signal_context_t *context = (ftun_cli_signal_context_t *)user;
  sigset_t signals;
  (void)sigemptyset(&signals);
  (void)sigaddset(&signals, SIGHUP);
  (void)sigaddset(&signals, SIGINT);
  (void)sigaddset(&signals, SIGTERM);
  for (;;) {
    int signal_number = 0;
    int done;
    if (sigwait(&signals, &signal_number) != 0) continue;
    (void)pthread_mutex_lock(&context->mutex);
    done = context->done;
    (void)pthread_mutex_unlock(&context->mutex);
    if (done) break;
    if (signal_number == SIGHUP) {
      ftun_operation_t *operation = NULL;
      ftun_status_t status = ftun_core_reload(
        context->core, context->config_path, ftun_cli_reload_done,
        context, &operation);
      if (status != FTUN_OK) {
        fprintf(stderr, "ftun: reload request rejected: %s\n",
                ftun_status_name(status));
      }
    } else {
      uint64_t now_ms = 0u;
      ftun_status_t status = ftun_monotonic_now(&now_ms);
      if (status == FTUN_OK &&
          now_ms > UINT64_MAX - FTUN_CLI_STOP_TIMEOUT_MS) {
        status = FTUN_E_LIMIT;
      }
      if (status == FTUN_OK) {
        status = ftun_core_stop(context->core,
          now_ms + FTUN_CLI_STOP_TIMEOUT_MS);
      }
      if (status != FTUN_OK && status != FTUN_E_STALE) {
        fprintf(stderr, "ftun: stop request failed: %s\n",
                ftun_status_name(status));
      }
      break;
    }
  }
  return NULL;
}

int ftun_cli_run(const char *path)
{
  ftun_cli_signal_context_t context;
  ftun_config_t *checked = NULL;
  ftun_core_t *core = NULL;
  pthread_t signal_thread;
  sigset_t signals;
  sigset_t previous;
  ftun_status_t status;
  int thread_started = 0;
  int mutex_started = 0;
  int signals_blocked = 0;
  int exit_code = 1;
  status = ftun_cli_check_config(path, 1, &checked);
  if (status != FTUN_OK) {
    if (status == FTUN_E_INVALID) {
      fputs("ftun: run: invalid configuration or no service root\n", stderr);
      return 1;
    }
    return ftun_cli_error("run preflight", status);
  }
  ftun_cli_warn_deprecated_config(checked);
  status = ftun_cli_core_create(checked, &core);
  (void)ftun_config_destroy(&checked);
  if (status != FTUN_OK) return ftun_cli_error("create", status);
  memset(&context, 0, sizeof(context));
  context.core = core;
  context.config_path = path;
  if (pthread_mutex_init(&context.mutex, NULL) != 0) {
    status = FTUN_E_IO;
    goto done;
  }
  mutex_started = 1;
  (void)sigemptyset(&signals);
  (void)sigaddset(&signals, SIGHUP);
  (void)sigaddset(&signals, SIGINT);
  (void)sigaddset(&signals, SIGTERM);
  if (pthread_sigmask(SIG_BLOCK, &signals, &previous) != 0) {
    status = FTUN_E_IO;
    goto done;
  }
  signals_blocked = 1;
  if (pthread_create(&signal_thread, NULL, ftun_cli_signal_waiter,
                     &context) != 0) {
    status = FTUN_E_IO;
    goto done;
  }
  thread_started = 1;
  status = ftun_core_run(core, path);
  (void)pthread_mutex_lock(&context.mutex);
  context.done = 1;
  (void)pthread_mutex_unlock(&context.mutex);
  (void)pthread_kill(signal_thread, SIGTERM);
  (void)pthread_join(signal_thread, NULL);
  thread_started = 0;
  if (status == FTUN_OK) exit_code = 0;

done:
  if (thread_started) {
    (void)pthread_mutex_lock(&context.mutex);
    context.done = 1;
    (void)pthread_mutex_unlock(&context.mutex);
    (void)pthread_kill(signal_thread, SIGTERM);
    (void)pthread_join(signal_thread, NULL);
  }
  if (signals_blocked) (void)pthread_sigmask(SIG_SETMASK, &previous, NULL);
  if (mutex_started) (void)pthread_mutex_destroy(&context.mutex);
  if (ftun_core_destroy(&core) != FTUN_OK && status == FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
    exit_code = 1;
  }
  if (status != FTUN_OK) (void)ftun_cli_error("run", status);
  return exit_code;
}
