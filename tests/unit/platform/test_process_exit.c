#define _POSIX_C_SOURCE 200809L
#include "platform/process.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "process exit failed at %d: %s\n", __LINE__, #x); abort(); } } while (0)
static pid_t exit_during_read;
ssize_t __real_read(int descriptor, void *data, size_t length);
ssize_t __wrap_read(int descriptor, void *data, size_t length)
{
  if (exit_during_read != 0) {
    int status;
    CHECK(kill(exit_during_read, SIGKILL) == 0);
    CHECK(waitpid(exit_during_read, &status, 0) == exit_during_read && WIFSIGNALED(status));
    exit_during_read = 0;
    /* 真实/proc FD已经打开，进程在本次read之前消失，内核应返回ESRCH。 */
    CHECK(__real_read(descriptor, data, length) == -1 && errno == ESRCH);
    errno = ESRCH;
    return -1;
  }
  return __real_read(descriptor, data, length);
}

static pid_t child(void)
{
  pid_t pid = fork();
  CHECK(pid >= 0);
  if (pid == 0) { for (;;) pause(); }
  return pid;
}

int main(void)
{
  bool exited = true;
  pid_t pid;
  int status;
  siginfo_t info;
  CHECK(ftun_process_exited((uint32_t)getpid(), &exited) == FTUN_OK && !exited);
  pid = child();
  CHECK(ftun_process_exited((uint32_t)pid, &exited) == FTUN_OK && !exited);
  CHECK(kill(pid, SIGKILL) == 0);
  /* WNOWAIT保留真正的僵尸，kill(pid,0)仍成功，但进程已经退出。 */
  CHECK(waitid(P_PID, (id_t)pid, &info, WEXITED | WNOWAIT) == 0 && info.si_pid == pid);
  CHECK(kill(pid, 0) == 0);
  CHECK(ftun_process_exited((uint32_t)pid, &exited) == FTUN_OK && exited);
  CHECK(waitpid(pid, &status, 0) == pid);
  CHECK(ftun_process_exited((uint32_t)pid, &exited) == FTUN_OK && exited);
  pid = child();
  exit_during_read = pid;
  CHECK(ftun_process_exited((uint32_t)pid, &exited) == FTUN_OK && exited);
  puts("process exit: live, zombie, missing and exit between open/read passed");
  return 0;
}
