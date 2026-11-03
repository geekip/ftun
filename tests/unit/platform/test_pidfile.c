#define _POSIX_C_SOURCE 200809L
#include "platform/pidfile.h"
#include "platform/process.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "PID file contract failed at %d: %s (errno %d)\n", __LINE__, #x, errno); \
  return 1; \
} } while (0)

static bool fail_write;
static const char *probe_path, *replace_path, *moved_path;
static bool probe_shared, transient_probe;
static ftun_platform_file_lock_t replacement = FTUN_FILE_INVALID;
int __real_flock(int descriptor, int operation);
int __wrap_flock(int descriptor, int operation)
{
  int result = __real_flock(descriptor, operation);
  if (probe_path != NULL && result == 0) {
    int other = open(probe_path, O_RDONLY);
    probe_shared = other >= 0 && __real_flock(other, LOCK_SH | LOCK_NB) == 0;
    if (other >= 0) (void)close(other);
  }
  return result;
}
ftun_status_t __real_ftun_platform_file_lock_acquire(const char *, ftun_platform_file_lock_t *);
ftun_status_t __wrap_ftun_platform_file_lock_acquire(const char *path, ftun_platform_file_lock_t *out)
{
  if (transient_probe) { transient_probe = false; return FTUN_E_AGAIN; }
  ftun_status_t status = __real_ftun_platform_file_lock_acquire(path, out);
  if (status == FTUN_OK && replace_path != NULL) {
    const char *target = replace_path;
    replace_path = NULL;
    if (rename(target, moved_path) != 0 ||
        __real_ftun_platform_file_lock_acquire(target, &replacement) != FTUN_OK) abort();
  }
  return status;
}
ssize_t __real_write(int descriptor, const void *data, size_t length);
ssize_t __wrap_write(int descriptor, const void *data, size_t length)
{
  if (fail_write) { errno = ENOSPC; return -1; }
  return __real_write(descriptor, data, length);
}

static int write_text(const char *path, const char *text)
{
  int descriptor = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
  size_t length = strlen(text);
  CHECK(descriptor >= 0);
  CHECK(write(descriptor, text, length) == (ssize_t)length);
  CHECK(close(descriptor) == 0);
  return 0;
}

static int test_path_rules(const char *directory)
{
  char path[4096], socket_path[4096], expected[4096];
  char maximum[sizeof(((struct sockaddr_un *)0)->sun_path) + 4u];
  int status;
  pid_t child;
  CHECK(setenv("HOME", directory, 1) == 0);
  CHECK(ftun_pidfile_path("~/custom.pid", path, sizeof(path)) == FTUN_OK);
  CHECK(snprintf(expected, sizeof(expected), "%s/custom.pid", directory) > 0);
  CHECK(strcmp(path, expected) == 0);
  CHECK(ftun_pidfile_path("relative.pid", path, sizeof(path)) == FTUN_OK && strcmp(path, "relative.pid") == 0);
  CHECK(ftun_pidfile_path("", path, sizeof(path)) == FTUN_E_INVALID);
  CHECK(ftun_pidfile_path("relative.pid", path, 4u) == FTUN_E_LIMIT);
  CHECK(ftun_pidfile_socket_path("instance.pid", socket_path, sizeof(socket_path)) == FTUN_OK);
  CHECK(strcmp(socket_path, "instance.sock") == 0);
  CHECK(ftun_pidfile_socket_path("instance", socket_path, sizeof(socket_path)) == FTUN_OK);
  CHECK(strcmp(socket_path, "instance.sock") == 0);
  memset(maximum, 'x', sizeof(maximum));
  memcpy(maximum + sizeof(maximum) - 5u, ".pid", 5u);
  CHECK(ftun_pidfile_socket_path(maximum, socket_path, sizeof(socket_path)) == FTUN_E_LIMIT);
  maximum[sizeof(maximum) - 7u] = '\0';
  CHECK(ftun_pidfile_socket_path(maximum, socket_path, sizeof(socket_path)) == FTUN_E_LIMIT);
  maximum[sizeof(maximum) - 10u] = '\0';
  CHECK(ftun_pidfile_socket_path(maximum, socket_path, sizeof(socket_path)) == FTUN_OK);
  child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    if (geteuid() == 0 && setuid(65534u) != 0) _exit(10);
    if (ftun_pidfile_path(NULL, path, sizeof(path)) != FTUN_OK) _exit(11);
    (void)snprintf(expected, sizeof(expected), "%s/.ftun/ftun.pid", directory);
    if (strcmp(path, expected) != 0) _exit(12);
    if (unsetenv("HOME") != 0 || ftun_pidfile_path(NULL, path, sizeof(path)) != FTUN_E_IO) _exit(13);
    _exit(0);
  }
  CHECK(waitpid(child, &status, 0) == child && status == 0);
  if (geteuid() == 0) {
    CHECK(ftun_pidfile_path(NULL, path, sizeof(path)) == FTUN_OK);
    CHECK(strcmp(path, "/run/ftun/ftun.pid") == 0);
  }
  CHECK(unsetenv("HOME") == 0);
  CHECK(ftun_pidfile_path("~/instance.pid", path, sizeof(path)) == FTUN_E_IO);
  return 0;
}

static int test_fork_inheritance(const char *path)
{
  ftun_pidfile_t owned = FTUN_PIDFILE_INVALID, contender = FTUN_PIDFILE_INVALID;
  uint32_t pid;
  int to_child[2], to_parent[2], status;
  char byte;
  pid_t child;
  CHECK(pipe(to_child) == 0 && pipe(to_parent) == 0);
  CHECK(ftun_pidfile_acquire(path, &owned, &pid) == FTUN_OK);
  child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    (void)close(to_child[1]); (void)close(to_parent[0]);
    if (read(to_child[0], &byte, 1u) != 1 || ftun_pidfile_rewrite(&owned) != FTUN_OK) _exit(20);
    if (write(to_parent[1], "r", 1u) != 1 || read(to_child[0], &byte, 1u) != 1) _exit(21);
    if (ftun_pidfile_release(&owned) != FTUN_OK) _exit(22);
    _exit(0);
  }
  CHECK(close(to_child[0]) == 0 && close(to_parent[1]) == 0);
  CHECK(ftun_pidfile_discard(&owned) == FTUN_OK);
  CHECK(write(to_child[1], "r", 1u) == 1 && read(to_parent[0], &byte, 1u) == 1);
  CHECK(ftun_pidfile_probe(path, &pid) == FTUN_OK && pid == (uint32_t)child);
  CHECK(ftun_pidfile_acquire(path, &contender, &pid) == FTUN_E_AGAIN && pid == (uint32_t)child);
  CHECK(write(to_child[1], "q", 1u) == 1);
  CHECK(waitpid(child, &status, 0) == child && status == 0);
  CHECK(ftun_pidfile_probe(path, &pid) == FTUN_E_EOF);
  CHECK(close(to_child[1]) == 0 && close(to_parent[0]) == 0);
  return 0;
}

static int test_probe_start(const char *path)
{
  pid_t children[3];
  CHECK(write_text(path, "1234\n") == 0);
  for (size_t i = 0u; i < 3u; i++) {
    children[i] = fork();
    CHECK(children[i] >= 0);
    if (children[i] == 0) {
      for (size_t n = 0u; n < 1000u; n++) {
        uint32_t holder;
        (void)ftun_pidfile_probe(path, &holder);
      }
      _exit(0);
    }
  }
  for (size_t n = 0u; n < 100u; n++) {
    ftun_pidfile_t instance = FTUN_PIDFILE_INVALID;
    uint32_t holder;
    CHECK(ftun_pidfile_acquire(path, &instance, &holder) == FTUN_OK);
    CHECK(ftun_pidfile_release(&instance) == FTUN_OK);
  }
  for (size_t i = 0u; i < 3u; i++) {
    int status;
    CHECK(waitpid(children[i], &status, 0) == children[i] && status == 0);
  }
  return 0;
}

int main(void)
{
  char directory[] = "/tmp/ftun-pidfile.XXXXXX";
  char path[256], previous[256];
  ftun_pidfile_t owned = FTUN_PIDFILE_INVALID, contender = FTUN_PIDFILE_INVALID;
  ftun_platform_file_lock_t raw;
  uint32_t pid;
  struct stat info;
  CHECK(mkdtemp(directory) != NULL);
  CHECK(snprintf(path, sizeof(path), "%s/instance.pid", directory) > 0);
  CHECK(snprintf(previous, sizeof(previous), "%s/previous", directory) > 0);
  CHECK(ftun_pidfile_probe(path, &pid) == FTUN_E_EOF && pid == 0u);
  CHECK(write_text(path, "2147483647\n") == 0);
  probe_path = path;
  CHECK(ftun_pidfile_probe(path, &pid) == FTUN_E_EOF && pid == 0u);
  probe_path = NULL;
  CHECK(probe_shared);
  transient_probe = true;
  CHECK(ftun_pidfile_acquire(path, &owned, &pid) == FTUN_OK);
  CHECK(stat(path, &info) == 0 && (info.st_mode & 0777u) == 0600u);
  CHECK(ftun_pidfile_probe(path, &pid) == FTUN_OK && pid == ftun_process_id());
  CHECK(ftun_pidfile_acquire(path, &contender, &pid) == FTUN_E_AGAIN && pid == ftun_process_id());
  CHECK(!ftun_platform_file_is_open(&contender.file));
  CHECK(ftun_pidfile_release(&owned) == FTUN_OK && access(path, F_OK) != 0);
  CHECK(ftun_pidfile_release(&owned) == FTUN_OK);
  CHECK(test_fork_inheritance(path) == 0);
  CHECK(test_probe_start(path) == 0);
  /* 旧锁刚释放且路径被替换，拿到已移走inode的锁不能成为第二个实例。 */
  replace_path = path;
  moved_path = previous;
  CHECK(ftun_pidfile_acquire(path, &owned, &pid) == FTUN_E_AGAIN);
  CHECK(!ftun_platform_file_is_open(&owned.file));
  CHECK(ftun_platform_file_lock_release(&replacement) == FTUN_OK);
  CHECK(unlink(path) == 0 && unlink(previous) == 0);
  CHECK(ftun_pidfile_acquire(path, &owned, &pid) == FTUN_OK);
  CHECK(rename(path, previous) == 0 && write_text(path, "1234\n") == 0);
  CHECK(ftun_pidfile_release(&owned) == FTUN_OK);
  CHECK(access(path, F_OK) == 0 && access(previous, F_OK) == 0);
  CHECK(unlink(path) == 0 && symlink(previous, path) == 0);
  CHECK(ftun_pidfile_acquire(path, &owned, &pid) != FTUN_OK && !ftun_platform_file_is_open(&owned.file));
  CHECK(unlink(path) == 0 && unlink(previous) == 0);
  CHECK(write_text(path, "1234 extra\n") == 0);
  CHECK(ftun_platform_file_lock_acquire(path, &raw) == FTUN_OK);
  CHECK(ftun_pidfile_probe(path, &pid) == FTUN_E_INVALID && pid == 0u);
  CHECK(ftun_platform_file_lock_release(&raw) == FTUN_OK && unlink(path) == 0);
  fail_write = true;
  CHECK(ftun_pidfile_acquire(path, &owned, &pid) == FTUN_E_LIMIT && !ftun_platform_file_is_open(&owned.file));
  fail_write = false;
  CHECK(access(path, F_OK) != 0);
  CHECK(mkfifo(path, 0600u) == 0);
  CHECK(ftun_pidfile_acquire(path, &owned, &pid) == FTUN_E_INVALID);
  CHECK(access(path, F_OK) == 0 && !ftun_platform_file_is_open(&owned.file));
  CHECK(ftun_pidfile_probe(path, &pid) == FTUN_E_INVALID);
  CHECK(unlink(path) == 0);
  CHECK(test_path_rules(directory) == 0);
  CHECK(rmdir(directory) == 0);
  return 0;
}
