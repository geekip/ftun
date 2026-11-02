#define _POSIX_C_SOURCE 200809L
#include <sys/types.h>
#include <unistd.h>
#include "app/runtime_internal.h"
#include "app/cli/background.h"
#include "platform/process.h"
#include "platform/pidfile.h"
#include "platform/atomic.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static bool in_child;
static unsigned int threads;
static ftun_atomic_size_t guard_null = {SIZE_MAX};
static ftun_atomic_bool_t guard_borrow;
static bool fault(const char *name)
{
  const char *selected = getenv("FTUN_TEST_BACKGROUND_FAULT");
  return selected != NULL && strcmp(selected, name) == 0;
}
pid_t __real_fork(void);
pid_t __wrap_fork(void)
{
  pid_t pid;
  if (threads != 0u || fault("fork")) { errno = EAGAIN; return -1; }
  pid = __real_fork();
  if (pid == 0) in_child = true;
  return pid;
}
ftun_status_t __real_ftun_thread_create(ftun_thread_t *thread, void *(*function)(void *), void *user);
ftun_status_t __wrap_ftun_thread_create(ftun_thread_t *thread, void *(*function)(void *), void *user)
{
  threads++;
  return __real_ftun_thread_create(thread, function, user);
}
uint32_t __real_ftun_cli_background_timeout(void);
uint32_t __wrap_ftun_cli_background_timeout(void)
{
  return fault("timeout") || fault("stuck") ? 250u : __real_ftun_cli_background_timeout();
}
ftun_status_t __real_ftun_core_transaction(ftun_core_t *core, ftun_core_control_t *control,
  const char *path, uint32_t *stage);
ftun_status_t __wrap_ftun_core_transaction(ftun_core_t *core, ftun_core_control_t *control,
  const char *path, uint32_t *stage)
{
  if (fault("delayed")) ftun_thread_pause(350u);
  if (fault("timeout") || fault("real-timeout") || fault("stuck")) {
    for (;;) {
      ftun_app_control_snapshot_t snapshot;
      if (ftun_app_control_query(core, &snapshot) != FTUN_OK) return FTUN_E_STATE_CORRUPT;
      if (!fault("stuck") && snapshot.stop_requested) return FTUN_E_TIMEOUT;
      ftun_thread_pause(1u);
    }
  }
  return __real_ftun_core_transaction(core, control, path, stage);
}
ftun_status_t __real_ftun_process_background_session(void);
ftun_status_t __wrap_ftun_process_background_session(void)
{ return fault("setsid") ? FTUN_E_IO : __real_ftun_process_background_session(); }
ftun_status_t __real_ftun_pidfile_rewrite(ftun_pidfile_t *pidfile);
ftun_status_t __wrap_ftun_pidfile_rewrite(ftun_pidfile_t *pidfile)
{ return in_child && fault("pidfile") ? FTUN_E_IO : __real_ftun_pidfile_rewrite(pidfile); }
ftun_status_t __real_ftun_process_null_open(ftun_handle_t *out);
ftun_status_t __wrap_ftun_process_null_open(ftun_handle_t *out)
{
  ftun_status_t status = fault("null") ? FTUN_E_IO : __real_ftun_process_null_open(out);
  if (status == FTUN_OK) ftun_atomic_store(&guard_null, (size_t)*out);
  return status;
}
ftun_status_t __real_ftun_cli_background_guard_start(ftun_cli_background_guard_t *guard,
  uint64_t deadline_ms, ftun_handle_t null_descriptor);
ftun_status_t __wrap_ftun_cli_background_guard_start(ftun_cli_background_guard_t *guard,
  uint64_t deadline_ms, ftun_handle_t null_descriptor)
{
  ftun_status_t status = __real_ftun_cli_background_guard_start(guard, deadline_ms, null_descriptor);
  if (status == FTUN_OK) ftun_atomic_store(&guard_borrow, true);
  return status;
}
ftun_status_t __real_ftun_cli_background_guard_finish(ftun_cli_background_guard_t *guard);
ftun_status_t __wrap_ftun_cli_background_guard_finish(ftun_cli_background_guard_t *guard)
{
  ftun_status_t status = __real_ftun_cli_background_guard_finish(guard);
  ftun_atomic_store(&guard_borrow, false);
  return status;
}
ftun_status_t __real_ftun_file_close(ftun_handle_t descriptor);
ftun_status_t __wrap_ftun_file_close(ftun_handle_t descriptor)
{
  if (in_child && descriptor >= 0 && (size_t)descriptor == ftun_atomic_load(&guard_null)) {
    if (ftun_atomic_load(&guard_borrow)) abort();
    ftun_atomic_store(&guard_null, SIZE_MAX);
  }
  return __real_ftun_file_close(descriptor);
}
ftun_status_t __real_ftun_process_stdio_null(ftun_handle_t descriptor);
ftun_status_t __wrap_ftun_process_stdio_null(ftun_handle_t descriptor)
{ return fault("redirect") ? FTUN_E_IO : __real_ftun_process_stdio_null(descriptor); }
ftun_status_t __real_ftun_cli_background_report(ftun_handle_t channel, uint64_t deadline,
  const ftun_cli_background_report_t *report);
ftun_status_t __wrap_ftun_cli_background_report(ftun_handle_t channel, uint64_t deadline,
  const ftun_cli_background_report_t *report)
{
  if (fault("short")) {
    ftun_status_t status = ftun_process_pipe_write(channel, report, 8u, deadline);
    return status == FTUN_OK ? FTUN_E_IO : status;
  }
  if (fault("pipe")) return FTUN_E_IO;
  return __real_ftun_cli_background_report(channel, deadline, report);
}
