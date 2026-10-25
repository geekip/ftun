#define _POSIX_C_SOURCE 200809L

#include "ftun/ftun.h"
#include "util/time.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expression) do { \
  if (!(expression)) { \
    fprintf(stderr, "service runtime failed at line %d: %s\n", \
            __LINE__, #expression); \
    return 1; \
  } \
} while (0)

typedef struct {
  atomic_uint post_callbacks;
  atomic_uint reload_callbacks;
  atomic_uint reload_cancelled;
  atomic_uint wrong_owner;
  pthread_t owner;
} callback_context_t;

typedef struct {
  ftun_core_t *core;
  const char *path;
  atomic_int result;
  callback_context_t *callbacks;
} run_context_t;

static int write_text(const char *path, const char *text)
{
  FILE *file = fopen(path, "wb");
  size_t length = strlen(text);
  int ok;
  if (file == NULL) return 0;
  ok = fwrite(text, 1u, length, file) == length && fflush(file) == 0;
  if (fclose(file) != 0) ok = 0;
  return ok;
}

static uint16_t reserve_port(void)
{
  size_t attempt;
  /* DNS listener 同时绑定 UDP/TCP，不能只选 UDP 空闲端口。 */
  for (attempt = 0u; attempt < 64u; attempt++) {
    struct sockaddr_in address;
    socklen_t length = sizeof(address);
    int udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int tcp = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int error;
    if (udp < 0 || tcp < 0) {
      if (udp >= 0) (void)close(udp);
      if (tcp >= 0) (void)close(tcp);
      return 0u;
    }
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(udp, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        getsockname(udp, (struct sockaddr *)&address, &length) != 0) {
      (void)close(tcp);
      (void)close(udp);
      return 0u;
    }
    if (bind(tcp, (const struct sockaddr *)&address, sizeof(address)) == 0) {
      uint16_t port = ntohs(address.sin_port);
      (void)close(tcp);
      (void)close(udp);
      return port;
    }
    error = errno;
    (void)close(tcp);
    (void)close(udp);
    if (error != EADDRINUSE) return 0u;
  }
  return 0u;
}

static void *run_core(void *user)
{
  run_context_t *context = (run_context_t *)user;
  context->callbacks->owner = pthread_self();
  atomic_store_explicit(&context->result,
    ftun_core_run(context->core, context->path), memory_order_release);
  return NULL;
}

static int wait_running(ftun_core_t *core)
{
  size_t attempt;
  for (attempt = 0u; attempt < 500u; attempt++) {
    ftun_core_info_t info;
    struct timespec pause = {0, 10 * 1000 * 1000};
    if (ftun_core_get_info(core, &info) == FTUN_OK &&
        info.state == FTUN_CORE_RUNNING && info.generation == 1u) return 1;
    (void)nanosleep(&pause, NULL);
  }
  return 0;
}

static void post_done(ftun_operation_t *operation, ftun_error_t error,
                      void *user)
{
  callback_context_t *context = (callback_context_t *)user;
  (void)operation;
  if (error.status == FTUN_OK && error.stage == FTUN_STAGE_CONTROL) {
    (void)atomic_fetch_add_explicit(&context->post_callbacks, 1u,
                                    memory_order_relaxed);
  }
}

static void reload_done(ftun_operation_t *operation, ftun_error_t error,
                        void *user)
{
  callback_context_t *context = (callback_context_t *)user;
  (void)operation;
  if (error.status == FTUN_E_CANCELLED) {
    (void)atomic_fetch_add_explicit(&context->reload_cancelled, 1u,
                                    memory_order_relaxed);
  }
  if (!pthread_equal(pthread_self(), context->owner)) {
    (void)atomic_fetch_add_explicit(&context->wrong_owner, 1u,
                                    memory_order_relaxed);
  }
  (void)atomic_fetch_add_explicit(&context->reload_callbacks, 1u,
                                  memory_order_relaxed);
}

static int wait_post(callback_context_t *context)
{
  size_t attempt;
  for (attempt = 0u; attempt < 500u; attempt++) {
    struct timespec pause = {0, 10 * 1000 * 1000};
    if (atomic_load_explicit(&context->post_callbacks,
                             memory_order_relaxed) == 1u) return 1;
    (void)nanosleep(&pause, NULL);
  }
  return 0;
}

int main(void)
{
  char directory[] = "/tmp/ftun-service-runtime-XXXXXX";
  char config_path[256];
  char fifo_path[256];
  char config[1024];
  ftun_core_options_t options;
  ftun_core_t *core = NULL;
  ftun_operation_t *operation = NULL;
  ftun_core_info_t info;
  callback_context_t callbacks;
  run_context_t run;
  pthread_t thread;
  uint64_t now_ms = 0u;
  uint16_t port = reserve_port();
  uint16_t upstream_port = reserve_port();
  int writer;
  size_t attempt;

  CHECK(port != 0u && upstream_port != 0u && port != upstream_port &&
        mkdtemp(directory) != NULL);
  CHECK(snprintf(config_path, sizeof(config_path), "%s/config.json",
                 directory) > 0);
  CHECK(snprintf(fifo_path, sizeof(fifo_path), "%s/reload.fifo",
                 directory) > 0);
  CHECK(snprintf(config, sizeof(config),
    "{\"base\":{\"state-cache\":false},\"log\":{\"level\":\"silent\"},"
    "\"dns\":{\"enable\":true,\"cache\":false,"
    "\"fake-ip\":{\"enable\":false},\"default-server\":\"direct\","
    "\"listeners\":[{\"listen\":\"127.0.0.1:%u\","
    "\"server\":\"direct\"}],\"servers\":[{\"name\":\"direct\","
    "\"type\":\"udp\",\"address\":[\"127.0.0.1:%u\"],"
    "\"outbound\":\"DIRECT\"}]}}", (unsigned int)port,
    (unsigned int)upstream_port) > 0);
  CHECK(write_text(config_path, config) && mkfifo(fifo_path, 0600) == 0);
  memset(&options, 0, sizeof(options));
  options.struct_size = sizeof(options);
  options.abi_version = FTUN_ABI_VERSION;
  options.owned_memory_limit = 16u * 1024u * 1024u;
  options.operation_capacity = 16u;
  CHECK(ftun_core_create(&options, &core) == FTUN_OK && core != NULL);
  atomic_init(&callbacks.post_callbacks, 0u);
  atomic_init(&callbacks.reload_callbacks, 0u);
  atomic_init(&callbacks.reload_cancelled, 0u);
  atomic_init(&callbacks.wrong_owner, 0u);
  run.core = core;
  run.path = config_path;
  atomic_init(&run.result, FTUN_E_STATE_CORRUPT);
  run.callbacks = &callbacks;
  CHECK(pthread_create(&thread, NULL, run_core, &run) == 0);
  if (!wait_running(core)) {
    fprintf(stderr, "run status while waiting for RUNNING: %d\n",
      atomic_load_explicit(&run.result, memory_order_acquire));
    CHECK(0 && "core did not enter RUNNING");
  }
  CHECK(ftun_core_reload(core, fifo_path, reload_done, &callbacks,
                         &operation) == FTUN_OK && operation != NULL);
  {
    struct timespec pause = {0, 50 * 1000 * 1000};
    (void)nanosleep(&pause, NULL);
  }
  CHECK(ftun_core_post(core, post_done, &callbacks, &operation) == FTUN_OK);
  CHECK(wait_post(&callbacks));
  CHECK(ftun_monotonic_now(&now_ms) == FTUN_OK);
  CHECK(ftun_core_stop(core, now_ms + 100u) == FTUN_OK);
  CHECK(pthread_join(thread, NULL) == 0 &&
        atomic_load_explicit(&run.result, memory_order_acquire) == FTUN_E_TIMEOUT);
  /* 已接纳 reload 在 run 返回前由 owner 取消终结；迟到 Worker 仅清理。 */
  CHECK(atomic_load_explicit(&callbacks.reload_callbacks,
                             memory_order_relaxed) == 1u);
  CHECK(atomic_load_explicit(&callbacks.reload_cancelled,
                             memory_order_relaxed) == 1u);
  CHECK(atomic_load_explicit(&callbacks.wrong_owner,
                             memory_order_relaxed) == 0u);
  CHECK(ftun_core_get_info(core, &info) == FTUN_OK &&
        info.state == FTUN_CORE_STOPPING && info.generation == 1u);
  CHECK(ftun_core_destroy(&core) == FTUN_E_AGAIN && core != NULL);
  writer = open(fifo_path, O_WRONLY | O_CLOEXEC);
  CHECK(writer >= 0 && close(writer) == 0);
  for (attempt = 0u; attempt < 500u && core != NULL; attempt++) {
    struct timespec pause = {0, 10 * 1000 * 1000};
    ftun_status_t status = ftun_core_destroy(&core);
    if (status == FTUN_OK) break;
    CHECK(status == FTUN_E_AGAIN);
    (void)nanosleep(&pause, NULL);
  }
  CHECK(core == NULL);
  CHECK(atomic_load_explicit(&callbacks.reload_callbacks,
                             memory_order_relaxed) == 1u);
  CHECK(unlink(fifo_path) == 0 && unlink(config_path) == 0 &&
        rmdir(directory) == 0);
  return 0;
}
