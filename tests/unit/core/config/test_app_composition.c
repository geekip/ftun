#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <sys/types.h>
#include <netinet/in.h>
#include "ftun/ftun.h"
#include "app/config/compile.h"
#include "core/limits.h"
#include "platform/clock.h"
#if defined(FTUN_TEST_TUN)
#include "libs/tun/device.h"
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#if defined(FTUN_TEST_EVENT_CLEANUP)
int ftun_test_event_cleanup_verify(bool active);
#endif
#if defined(FTUN_TEST_TUN_ADMISSION)
int ftun_test_tun_admission(ftun_core_t *core);
#endif
#if defined(FTUN_TEST_TUN_RECOVERY)
bool ftun_test_tun_fail_open(void);
int ftun_test_tun_quiesce(ftun_core_t *core);
#endif
#if defined(FTUN_TEST_TUN_ASYNC)
bool ftun_test_tun_fail_open(void);
int ftun_test_tun_async_verify(void);
#endif
#if defined(FTUN_TEST_CONTROL_POLICY)
int ftun_test_control_policy_verify(void);
#endif

#define CHECK(value) do { if (!(value)) { \
  fprintf(stderr, "App composition failed at %d: %s\n", __LINE__, #value); \
  return 1; } } while (0)

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned int callbacks;
static ftun_status_t completed_status;
static ftun_status_t run_status;
static bool run_finished;
static ftun_core_t *core;
static char config_path[256];

static uint64_t now_ms(void)
{
  uint64_t now = 0u;
  if (ftun_monotonic_now(&now) != FTUN_OK) abort();
  return now;
}

static void pause_once(void)
{
  struct timespec duration = {0, 1000000};
  (void)nanosleep(&duration, NULL);
}

#if defined(FTUN_TEST_TUN)
/* 只替换设备边界，App/default/ModulePlan/TUN owner/service 均为生产实现。
 * 默认 auto-route=false；路由测试注入无宿主副作用的后端。真实 socketpair
 * 提供 Event 可观察 FD。 */
typedef struct {
  int sockets[2];
  uint32_t mtu;
  ftun_reservation_t reservation;
} test_port_t;
static unsigned int opens, closes;

ftun_status_t __wrap_ftun_packet_port_open_with_budget(ftun_core_t *owner,
  ftun_budget_t *budget, const ftun_tun_spec_t *spec, ftun_packet_port_t **out)
{
  test_port_t *port;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_status_t status;
  (void)owner;
  *out = NULL;
#if defined(FTUN_TEST_TUN_RECOVERY) || defined(FTUN_TEST_TUN_ASYNC)
  if (ftun_test_tun_fail_open()) return FTUN_E_IO;
#endif
  if (spec->name.length != 9u || memcmp(spec->name.data, "ftun-app0", 9u)) {
    return FTUN_E_INVALID;
  }
  if (budget != NULL) {
    status = ftun_budget_reserve_resources(budget,
      (ftun_budget_resources_t){sizeof(*port), 2u, 0u}, &reservation);
    if (status != FTUN_OK) return status;
  }
  port = calloc(1u, sizeof(*port));
  if (port == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  port->reservation = reservation;
  if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0,
                 port->sockets) != 0) {
    free(port);
    ftun_reservation_release(&reservation);
    return FTUN_E_IO;
  }
  port->mtu = spec->mtu;
  opens++;
  *out = (ftun_packet_port_t *)port;
  return FTUN_OK;
}

ftun_status_t __wrap_ftun_packet_port_open(ftun_core_t *owner,
  const ftun_tun_spec_t *spec, ftun_packet_port_t **out)
{
  return __wrap_ftun_packet_port_open_with_budget(owner, NULL, spec, out);
}

ftun_status_t __wrap_ftun_packet_port_get_info(const ftun_packet_port_t *raw,
  ftun_packet_port_info_t *info)
{
  const test_port_t *port = (const test_port_t *)raw;
  memset(info, 0, sizeof(*info));
  memcpy(info->name, "ftun-app0", 10u);
  info->mtu = port->mtu;
  info->native_socket = (ftun_native_socket_t)(unsigned int)port->sockets[0];
  return FTUN_OK;
}

ftun_status_t __wrap_ftun_packet_port_read(ftun_packet_port_t *raw,
  void *data, size_t capacity, size_t *length)
{
  test_port_t *port = (test_port_t *)raw;
  ssize_t count = recv(port->sockets[0], data, capacity, 0);
  *length = count > 0 ? (size_t)count : 0u;
  if (count < 0) return errno == EAGAIN ? FTUN_E_AGAIN : FTUN_E_IO;
  return FTUN_OK;
}

ftun_status_t __wrap_ftun_packet_port_write(ftun_packet_port_t *raw,
  const void *data, size_t length)
{
  test_port_t *port = (test_port_t *)raw;
  return send(port->sockets[0], data, length, 0) == (ssize_t)length
    ? FTUN_OK : FTUN_E_IO;
}

ftun_status_t __wrap_ftun_packet_port_close(ftun_packet_port_t **raw)
{
  test_port_t *port = (test_port_t *)*raw;
  if (port == NULL) return FTUN_OK;
  (void)close(port->sockets[0]);
  (void)close(port->sockets[1]);
  ftun_reservation_release(&port->reservation);
  free(port);
  *raw = NULL;
  closes++;
  return FTUN_OK;
}
#endif

static void completed(ftun_operation_t *operation, ftun_error_t result, void *user)
{
  (void)operation;
  (void)user;
  (void)pthread_mutex_lock(&mutex);
  callbacks++;
  completed_status = result.status;
  (void)pthread_mutex_unlock(&mutex);
}

static int wait_completion(unsigned int expected, ftun_status_t status)
{
  uint64_t expires = now_ms() + 5000u;
  for (;;) {
    unsigned int count;
    ftun_status_t result;
    (void)pthread_mutex_lock(&mutex);
    count = callbacks;
    result = completed_status;
    (void)pthread_mutex_unlock(&mutex);
    if (count == expected) {
      if (result != status) fprintf(stderr, "completion got %s expected %s\n",
        ftun_status_name(result), ftun_status_name(status));
      CHECK(result == status);
      return 0;
    }
    CHECK(count < expected && now_ms() < expires);
    pause_once();
  }
}

static void *run(void *unused)
{
  ftun_status_t status;
  (void)unused;
  status = ftun_core_run(core, config_path);
  (void)pthread_mutex_lock(&mutex);
  run_status = status;
  run_finished = true;
  (void)pthread_mutex_unlock(&mutex);
  return NULL;
}

static int make_config(const char *path, uint32_t modules, unsigned int port,
  unsigned int mtu)
{
  FILE *file = fopen(path, "w");
  CHECK(file != NULL);
  CHECK(fputs("{\"base\":{\"state-cache\":false},\"log\":{\"level\":\"silent\"},", file) >= 0);
  if (modules & FTUN_BUILD_MODULE_DNS) {
    CHECK(fputs("\"dns\":{\"enable\":true,\"servers\":[{\"name\":\"d\","
      "\"type\":\"udp\",\"address\":[\"127.0.0.1:9\"],\"outbound\":\"DIRECT\"}],"
      "\"default-server\":\"d\"}", file) >= 0);
  } else CHECK(fputs("\"dns\":{\"enable\":false}", file) >= 0);
  if (modules & FTUN_BUILD_MODULE_PROXY) {
    CHECK(fprintf(file, ",\"inbounds\":[{\"name\":\"p\",\"type\":\"mixed\","
      "\"listen\":\"127.0.0.1:%u\"}", port) > 0);
    if (modules & FTUN_BUILD_MODULE_TUN) {
      CHECK(fputs(",{\"name\":\"t\",\"type\":\"tun\",\"tcp\":true,"
        "\"udp\":true,\"dns-hijack\":false}", file) >= 0);
    }
    CHECK(fputs("],\"rules\":[\"MATCH,DIRECT\"]", file) >= 0);
  }
  if (modules & FTUN_BUILD_MODULE_TUN) {
    CHECK(fprintf(file, ",\"tun\":{\"interface\":\"ftun-app0\",\"mtu\":%u,"
      "\"ipv4\":{\"address\":\"10.89.0.1/30\"},\"auto-route\":%s}", mtu,
#if defined(FTUN_TEST_TUN_ASYNC)
      "true"
#elif defined(FTUN_TEST_CONTROL_POLICY)
      getenv("FTUN_TEST_CONTROL_AUTO_ROUTE")
#else
      "false"
#endif
      ) > 0);
  }
  CHECK(fputs("}\n", file) >= 0 && fclose(file) == 0);
  return 0;
}

static int submit_reload(const char *path)
{
  ftun_operation_t *operation = NULL;
  uint64_t expires = now_ms() + 5000u;
  ftun_status_t status;
  do {
    status = ftun_core_reload(core, path, completed, NULL, &operation);
    if (status != FTUN_E_AGAIN) break;
    CHECK(operation == NULL && now_ms() < expires);
    pause_once();
  } while (1);
  CHECK(status == FTUN_OK && operation != NULL);
  return 0;
}

int main(void)
{
  const ftun_build_capabilities_t *capabilities = ftun_build_capabilities();
  uint32_t modules = capabilities->builtins & (FTUN_BUILD_MODULE_DNS |
    FTUN_BUILD_MODULE_PROXY | FTUN_BUILD_MODULE_TUN);
  uint32_t changed;
  char directory[] = "/tmp/ftun-composition-XXXXXX";
  char reload_path[256], changed_path[256], device_path[256];
  struct sockaddr_in address;
  socklen_t length = sizeof(address);
  ftun_core_options_t options;
  ftun_core_info_t info;
  ftun_operation_t *operation = NULL;
  pthread_t thread;
  uint64_t expires;
  unsigned int port, expected = 3u;
  int descriptor = socket(AF_INET, SOCK_STREAM, 0);
  /* 当前公开配置只有 Proxy TUN inbound 会激活 TUN 根；纯 provider 构建
   * 不虚构新的使用入口，仍验证其默认 App 生命周期与能力拒绝。 */
  if (!(modules & FTUN_BUILD_MODULE_PROXY)) modules &= ~(uint32_t)FTUN_BUILD_MODULE_TUN;
  CHECK(descriptor >= 0 && mkdtemp(directory) != NULL);
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  CHECK(bind(descriptor, (struct sockaddr *)&address, length) == 0);
  CHECK(getsockname(descriptor, (struct sockaddr *)&address, &length) == 0);
  port = ntohs(address.sin_port);
  CHECK(close(descriptor) == 0);
  CHECK(snprintf(config_path, sizeof(config_path), "%s/start.json", directory) > 0);
  CHECK(snprintf(reload_path, sizeof(reload_path), "%s/reload.json", directory) > 0);
  CHECK(snprintf(changed_path, sizeof(changed_path), "%s/changed.json", directory) > 0);
  CHECK(snprintf(device_path, sizeof(device_path), "%s/device.json", directory) > 0);
  changed = (modules & FTUN_BUILD_MODULE_TUN) ? modules & ~(uint32_t)FTUN_BUILD_MODULE_TUN :
    (modules & FTUN_BUILD_MODULE_DNS) ? modules & ~(uint32_t)FTUN_BUILD_MODULE_DNS :
    (modules & FTUN_BUILD_MODULE_PROXY) ? modules & ~(uint32_t)FTUN_BUILD_MODULE_PROXY : FTUN_BUILD_MODULE_DNS;
  CHECK(make_config(config_path, modules, port, 1420u) == 0);
  CHECK(make_config(reload_path, modules, port, 1420u) == 0);
  CHECK(make_config(changed_path, changed, port, 1420u) == 0);
  CHECK(make_config(device_path, modules, port, 1421u) == 0);
  memset(&options, 0, sizeof(options));
  options.struct_size = sizeof(options);
  options.abi_version = FTUN_ABI_VERSION;
  CHECK(ftun_core_create(&options, &core) == FTUN_OK);
  if (modules == 0u) {
    /* 零物理服务一直不支持 run；拒绝后恢复 CREATED 并可重试、销毁。 */
    CHECK(ftun_core_run(core, config_path) == FTUN_E_UNSUPPORTED);
    CHECK(ftun_core_get_info(core, &info) == FTUN_OK &&
      info.state == FTUN_CORE_CREATED && info.generation == 0u);
    CHECK(ftun_core_run(core, config_path) == FTUN_E_UNSUPPORTED);
    CHECK(callbacks == 0u);
    CHECK(ftun_core_destroy(&core) == FTUN_OK && core == NULL);
    goto cleaned;
  }
  CHECK(pthread_create(&thread, NULL, run, NULL) == 0);
  expires = now_ms() + 5000u;
  do {
    bool finished;
    (void)pthread_mutex_lock(&mutex);
    finished = run_finished;
    if (finished) fprintf(stderr, "run returned before startup: %s\n",
      ftun_status_name(run_status));
    (void)pthread_mutex_unlock(&mutex);
    CHECK(!finished);
    CHECK(ftun_core_get_info(core, &info) == FTUN_OK && now_ms() < expires);
    if (info.state == FTUN_CORE_RUNNING) break;
    if (info.state != FTUN_CORE_CREATED && info.state != FTUN_CORE_STARTING) {
      fprintf(stderr, "startup state=%u port=%u\n", (unsigned)info.state, port);
    }
    CHECK(info.state == FTUN_CORE_CREATED || info.state == FTUN_CORE_STARTING);
    pause_once();
  } while (1);
#if defined(FTUN_TEST_TUN_ADMISSION)
#if defined(FTUN_TEST_TUN_RECOVERY) || defined(FTUN_TEST_TUN_ASYNC)
  {
    int unrelated = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval timeout = {2, 0};
    const uint8_t greeting[] = {5u, 1u, 0u};
    const uint8_t connect_request[] = {5u, 1u, 0u, 1u, 127u, 0u, 0u, 1u, 0u, 9u};
    uint8_t response[10];
    CHECK(unrelated >= 0);
    CHECK(setsockopt(unrelated, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    address.sin_port = htons((uint16_t)port);
    CHECK(connect(unrelated, (struct sockaddr *)&address, sizeof(address)) == 0);
    CHECK(send(unrelated, greeting, sizeof(greeting), 0) == (ssize_t)sizeof(greeting));
    CHECK(recv(unrelated, response, 2u, MSG_WAITALL) == 2 && response[0] == 5u && response[1] == 0u);
    CHECK(ftun_test_tun_admission(core) == 0);
    /* TUN 恢复不得关闭无关 socket；原 SOCKS 会话仍能接收命令并回复。 */
    CHECK(send(unrelated, connect_request, sizeof(connect_request), 0) == (ssize_t)sizeof(connect_request));
    CHECK(recv(unrelated, response, sizeof(response), MSG_WAITALL) == (ssize_t)sizeof(response) && response[0] == 5u);
    CHECK(close(unrelated) == 0);
  }
#else
  CHECK(ftun_test_tun_admission(core) == 0);
#endif
#endif
  CHECK(ftun_core_post(core, completed, NULL, &operation) == FTUN_OK);
  CHECK(wait_completion(1u, FTUN_OK) == 0);
  CHECK(submit_reload(reload_path) == 0 && wait_completion(2u, FTUN_OK) == 0);
  CHECK(ftun_core_get_info(core, &info) == FTUN_OK && info.generation == 2u);
  CHECK(submit_reload(changed_path) == 0);
  CHECK(wait_completion(3u, modules ? FTUN_E_RESTART_REQUIRED : FTUN_E_UNSUPPORTED) == 0);
  if (modules & FTUN_BUILD_MODULE_TUN) {
    CHECK(submit_reload(device_path) == 0 && wait_completion(4u, FTUN_E_RESTART_REQUIRED) == 0);
    expected = 4u;
  }
  CHECK(ftun_core_get_info(core, &info) == FTUN_OK && info.generation == 2u);
#if defined(FTUN_TEST_TUN_RECOVERY)
  CHECK(ftun_test_tun_quiesce(core) == 0);
#endif
  CHECK(ftun_core_stop(core, now_ms() + 1000u) == FTUN_OK);
  CHECK(pthread_join(thread, NULL) == 0 && run_status == FTUN_OK);
  CHECK(callbacks == expected);
  CHECK(ftun_core_destroy(&core) == FTUN_OK && core == NULL);
cleaned:
#if defined(FTUN_TEST_TUN_ASYNC)
  CHECK(ftun_test_tun_async_verify() == 0);
#endif
#if defined(FTUN_TEST_CONTROL_POLICY)
  CHECK(ftun_test_control_policy_verify() == 0);
#endif
#if defined(FTUN_TEST_EVENT_CLEANUP)
  CHECK(ftun_test_event_cleanup_verify(modules != 0u) == 0);
#endif
#if defined(FTUN_TEST_TUN)
#if defined(FTUN_TEST_TUN_RECOVERY) || defined(FTUN_TEST_TUN_UDP_RECOVERY) || defined(FTUN_TEST_TUN_ASYNC)
  CHECK(opens == 2u);
#else
  CHECK(opens == ((modules & FTUN_BUILD_MODULE_TUN) ? 1u : 0u));
#endif
  CHECK(closes == opens);
#endif
  CHECK(unlink(config_path) == 0 && unlink(reload_path) == 0);
  CHECK(unlink(changed_path) == 0 && unlink(device_path) == 0);
  CHECK(rmdir(directory) == 0);
  printf("App default composition: modules=%u; %s passed\n", modules,
    modules ? "post/reload/rejection/stop" : "empty-service rejection/retry/destroy");
  return 0;
}
