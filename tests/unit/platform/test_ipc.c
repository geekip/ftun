#define _GNU_SOURCE 1
#include "platform/ipc.h"
#include "platform/socket.h"
#include "platform/clock.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "IPC failed at %d: %s\n", __LINE__, #x); abort(); } } while (0)

static int connect_path(const char *path)
{
  struct sockaddr_un address = {0};
  int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
  CHECK(descriptor >= 0);
  address.sun_family = AF_UNIX;
  CHECK(strlen(path) < sizeof(address.sun_path));
  memcpy(address.sun_path, path, strlen(path) + 1u);
  CHECK(connect(descriptor, (struct sockaddr *)&address, sizeof(address)) == 0);
  return descriptor;
}

static void peer(ftun_ipc_listener_t *listener, bool expected)
{
  ftun_handle_t accepted;
  ftun_socket_accept_disposition_t disposition;
  bool allowed;
  uint64_t user_id;
  CHECK(ftun_socket_accept(listener->socket, &accepted, NULL, &disposition) == FTUN_OK);
  CHECK((fcntl((int)accepted, F_GETFD) & FD_CLOEXEC) != 0 &&
    (fcntl((int)accepted, F_GETFL) & O_NONBLOCK) != 0);
  CHECK(ftun_ipc_peer_allowed(accepted, &allowed, &user_id) == FTUN_OK && allowed == expected);
  CHECK(allowed == (user_id == 0u || user_id == (uint64_t)geteuid()));
  CHECK(ftun_socket_close((ftun_native_socket_t)accepted) == FTUN_OK);
}

int main(void)
{
  char directory[] = "/tmp/ftun-ipc-XXXXXX", path[128], moved[128], long_path[256];
  ftun_ipc_listener_t listener = FTUN_IPC_LISTENER_INVALID;
  struct stat info;
  FILE *file;
  int client;
  bool allowed = true;
  uint64_t now;
  ftun_handle_t connected;
  CHECK(mkdtemp(directory) != NULL);
  CHECK(snprintf(path, sizeof(path), "%s/control.sock", directory) > 0);
  CHECK(snprintf(moved, sizeof(moved), "%s/old.sock", directory) > 0);
  CHECK(ftun_ipc_listen(path, &listener) == FTUN_OK);
  CHECK(stat(path, &info) == 0 && S_ISSOCK(info.st_mode) && (info.st_mode & 0777) == 0600);
  CHECK((fcntl((int)listener.socket, F_GETFD) & FD_CLOEXEC) != 0 &&
    (fcntl((int)listener.socket, F_GETFL) & O_NONBLOCK) != 0);
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  CHECK(ftun_ipc_connect(path, now, &connected) == FTUN_E_TIMEOUT && connected == -1);
  CHECK(ftun_ipc_connect(path, now + 1000u, &connected) == FTUN_OK);
  client = (int)connected;
  CHECK((fcntl(client, F_GETFD) & FD_CLOEXEC) != 0 &&
    (fcntl(client, F_GETFL) & O_NONBLOCK) != 0);
  peer(&listener, true);
  CHECK(close(client) == 0);
  uint64_t user_id;
  CHECK(ftun_ipc_peer_allowed(-1, &allowed, &user_id) == FTUN_E_IO && !allowed && user_id == UINT64_MAX);
  if (geteuid() == 0u) {
    int status;
    pid_t child;
    /* 放开测试端点的路径权限，单独验证系统凭据，而非依赖文件权限拒绝。 */
    CHECK(chmod(directory, 0777) == 0 && chmod(path, 0666) == 0);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
      CHECK(close((int)listener.socket) == 0);
      CHECK(setgid(65534u) == 0 && setuid(65534u) == 0);
      client = connect_path(path);
      CHECK(close(client) == 0);
      _exit(0);
    }
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    peer(&listener, false);
    CHECK(chmod(directory, 0700) == 0);
  }
  /* 模拟异常退出：残留socket文件在已持对应PID锁的下一实例中可重新绑定。 */
  CHECK(close((int)listener.socket) == 0);
  listener = (ftun_ipc_listener_t)FTUN_IPC_LISTENER_INVALID;
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  CHECK(ftun_ipc_connect(path, now + 1000u, &connected) == FTUN_E_EOF && connected == -1);
  CHECK(ftun_ipc_listen(path, &listener) == FTUN_OK);
  CHECK(stat(path, &info) == 0 && (info.st_mode & 0777) == 0600);
  CHECK(rename(path, moved) == 0);
  file = fopen(path, "w");
  CHECK(file != NULL && fputs("external", file) >= 0 && fclose(file) == 0);
  CHECK(ftun_ipc_listener_close(&listener) == FTUN_OK && listener.socket == -1);
  CHECK(stat(path, &info) == 0 && S_ISREG(info.st_mode));
  CHECK(ftun_ipc_listen(path, &listener) == FTUN_E_REJECTED && listener.socket == -1);
  CHECK(stat(path, &info) == 0 && S_ISREG(info.st_mode));
  CHECK(unlink(path) == 0 && unlink(moved) == 0);
  CHECK(symlink("missing", path) == 0);
  CHECK(ftun_ipc_listen(path, &listener) == FTUN_E_REJECTED);
  CHECK(lstat(path, &info) == 0 && S_ISLNK(info.st_mode));
  CHECK(unlink(path) == 0);
  memset(long_path, 'x', sizeof(long_path) - 1u);
  long_path[sizeof(long_path) - 1u] = '\0';
  CHECK(ftun_ipc_listen(long_path, &listener) == FTUN_E_LIMIT && listener.socket == -1);
  CHECK(ftun_ipc_listen(path, &listener) == FTUN_OK);
  CHECK(ftun_ipc_listener_close(&listener) == FTUN_OK && access(path, F_OK) != 0);
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  CHECK(ftun_ipc_connect(path, now + 1000u, &connected) == FTUN_E_EOF && connected == -1);
  CHECK(ftun_ipc_listener_close(&listener) == FTUN_OK);
  CHECK(rmdir(directory) == 0);
  puts("IPC: native credentials, permissions, nonblocking handles, stale sockets and owned cleanup passed");
  return 0;
}
