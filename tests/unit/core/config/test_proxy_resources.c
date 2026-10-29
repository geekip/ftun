#define _GNU_SOURCE 1
#include <netinet/in.h>
#include "app/config/model.h"
#include "dns/module.h"
#include "app/composition/bridges.h"
#include "app/config/compile.h"
#include "core/context.h"
#include "core/event/backend.h"
#include "proxy/runtime.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "proxy resources failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

static unsigned int fail_socket;
static bool fail_cancel;
int __real_socket(int domain, int type, int protocol);
int __wrap_socket(int domain, int type, int protocol)
{
  if (fail_socket != 0u && --fail_socket == 0u) {
    errno = EMFILE;
    return -1;
  }
  return __real_socket(domain, type, protocol);
}
/* accept4 故障注入：按脚本返回 errno；脚本用尽后返回 EAGAIN。夹具没有发布
 * 活动配置，不放行真实 accept，避免把"缺少运行配置"混入本场景。 */
static const int *accept_script;
static size_t accept_script_length;
static size_t accept_calls;
static bool accept_injecting;
int __real_accept4(int descriptor, struct sockaddr *address,
                   socklen_t *length, int flags);
int __wrap_accept4(int descriptor, struct sockaddr *address,
                   socklen_t *length, int flags)
{
  if (!accept_injecting) return __real_accept4(descriptor, address, length, flags);
  accept_calls++;
  errno = accept_calls <= accept_script_length
    ? accept_script[accept_calls - 1u] : EAGAIN;
  return -1;
}
ftun_status_t __real_ftun_event_source_backend_data(ftun_event_source_t *, void **);
ftun_status_t __wrap_ftun_event_source_backend_data(ftun_event_source_t *source, void **out)
{
  if (fail_cancel) { *out = NULL; return FTUN_E_IO; }
  return __real_ftun_event_source_backend_data(source, out);
}

static size_t fd_count(void)
{
  DIR *directory = opendir("/proc/self/fd");
  struct dirent *entry;
  size_t count = 0u;
  if (directory == NULL) return SIZE_MAX;
  while ((entry = readdir(directory)) != NULL) if (entry->d_name[0] != '.') count++;
  (void)closedir(directory);
  return count;
}

static int endpoint(char *text, size_t capacity)
{
  struct sockaddr_in address = {0};
  socklen_t length = sizeof(address);
  int descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
  CHECK(descriptor >= 0);
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  CHECK(bind(descriptor, (struct sockaddr *)&address, length) == 0);
  CHECK(getsockname(descriptor, (struct sockaddr *)&address, &length) == 0);
  CHECK(snprintf(text, capacity, "127.0.0.1:%u", ntohs(address.sin_port)) > 0);
  CHECK(close(descriptor) == 0);
  return 0;
}

static ftun_status_t resolve_unused(void *context, ftun_core_t *core,
  const ftun_resolver_provider_request_t *request, ftun_operation_t **out)
{
  (void)context; (void)core; (void)request;
  *out = NULL;
  return FTUN_E_UNSUPPORTED;
}

static ftun_status_t dial_unused(void *context, ftun_core_t *core,
  const ftun_dial_request_t *request, ftun_operation_t **out)
{
  (void)context; (void)core; (void)request;
  *out = NULL;
  return FTUN_E_UNSUPPORTED;
}

static int equal_usage(ftun_budget_t *budget, const ftun_budget_usage_t *expected)
{
  ftun_budget_usage_t usage;
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
  CHECK(usage.used_resources.memory_bytes == expected->used_resources.memory_bytes);
  CHECK(usage.used_resources.descriptors == expected->used_resources.descriptors);
  CHECK(usage.used_resources.queue_slots == expected->used_resources.queue_slots);
  CHECK(usage.child_count == expected->child_count);
  return 0;
}

/* 使用真实 libev/listener/Worker；仅解析和出站工厂不接纳业务。 */
static int admission(unsigned int listener_count, bool udp)
{
  ftun_budget_options_t limits = {0};
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_proxy_runtime_t *runtime = NULL;
  ftun_proxy_bindings_t bindings = {0};
  ftun_proxy_dns_runtime_adapter_t dns = {0};
  ftun_dns_service_slot_t dns_slot = {0};
  ftun_fakeip_service_t *fakeip = NULL;
  ftun_config_t config = {0};
  ftun_config_bind_sections(&config);
  ftun_feature_plan_t plan = {0};
  ftun_config_inbound_t inbound[2] = {{0}};
  ftun_budget_usage_t base, running, usage;
  ftun_reservation_t pressure = (ftun_reservation_t){0};
  size_t baseline = fd_count(), descriptors = listener_count * (udp ? 2u : 1u);
  size_t short_name_bytes = 0u, index;
  char endpoints[2][32];
  limits.limit = (ftun_budget_resources_t){16u * 1024u * 1024u,
    2u + descriptors, 256u + 8u + 64u + 16u + 2u + descriptors};
  CHECK(ftun_budget_create_resources(NULL, &limits, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 8u, &operations) == FTUN_OK);
  CHECK(ftun_event_loop_create_with_capacity(core, 16u, &loop) == FTUN_OK);
  CHECK(ftun_event_backend_attach(loop) == FTUN_OK);
  CHECK(fd_count() == baseline + 2u);
  bindings.loop = loop;
  bindings.resolver.start = resolve_unused;
  bindings.path.start = dial_unused;
  bindings.fakeip_slot = &fakeip;
  dns.core = core;
  ftun_app_dns_bridge_init(&dns);
  dns.slot = &dns_slot;
  bindings.dns = &dns;
  ftun_config_bind_plan(&config, &plan);
  ftun_config_timeouts_default(&config);
  config.base.proxy.capacity.tcp_flows = 1u;
  config.base.proxy.capacity.udp_flows = 1u;
  config.base.proxy.capacity.udp_associations = 1u;
  config.inbounds = inbound;
  config.inbound_count = listener_count;
  for (index = 0u; index < listener_count; index++) {
    CHECK(endpoint(endpoints[index], sizeof(endpoints[index])) == 0);
    inbound[index].kind = FTUN_CONFIG_INBOUND_SOCKS5;
    inbound[index].name = index == 0u ? "a" : "b";
    inbound[index].listen = endpoints[index];
    inbound[index].udp = udp;
  }
  CHECK(ftun_budget_get_usage(budget, &base) == FTUN_OK);
  CHECK(ftun_budget_reserve(budget, base.normal_available_resources.memory_bytes, &pressure) == FTUN_OK);
  CHECK(ftun_proxy_runtime_prepare(core, budget, operations, &bindings,
    &config, 1u, &runtime) == FTUN_E_LIMIT && runtime == NULL);
  ftun_reservation_release(&pressure);
  CHECK(equal_usage(budget, &base) == 0 && fd_count() == baseline + 2u);

  if (descriptors != 0u) {
    CHECK(ftun_budget_reserve_resources(budget,
      (ftun_budget_resources_t){0u, 1u, 0u}, &pressure) == FTUN_OK);
    CHECK(ftun_proxy_runtime_prepare(core, budget, operations, &bindings,
      &config, 1u, &runtime) == FTUN_E_LIMIT && runtime == NULL);
    ftun_reservation_release(&pressure);
    CHECK(equal_usage(budget, &base) == 0 && fd_count() == baseline + 2u);

    CHECK(ftun_budget_reserve_resources(budget,
      (ftun_budget_resources_t){0u, 0u, 1u}, &pressure) == FTUN_OK);
    CHECK(ftun_proxy_runtime_prepare(core, budget, operations, &bindings,
      &config, 1u, &runtime) == FTUN_E_LIMIT);
    CHECK(ftun_proxy_runtime_destroy(&runtime) == FTUN_OK);
    ftun_reservation_release(&pressure);
    CHECK(equal_usage(budget, &base) == 0 && fd_count() == baseline + 2u);

    fail_socket = (unsigned int)descriptors;
    CHECK(ftun_proxy_runtime_prepare(core, budget, operations, &bindings,
      &config, 1u, &runtime) == FTUN_E_LIMIT && fail_socket == 0u);
    CHECK(ftun_proxy_runtime_destroy(&runtime) == FTUN_OK);
    CHECK(equal_usage(budget, &base) == 0 && fd_count() == baseline + 2u);
  }
  for (index = 0u; index < 2u; index++) {
    CHECK(ftun_proxy_runtime_prepare(core, budget, operations, &bindings,
      &config, 1u, &runtime) == FTUN_OK);
    CHECK(ftun_budget_get_usage(budget, &running) == FTUN_OK);
    CHECK(running.used_resources.descriptors == 2u + descriptors);
    CHECK(fd_count() == baseline + running.used_resources.descriptors);
    CHECK(running.used_resources.queue_slots == limits.limit.queue_slots);
    if (index == 0u) short_name_bytes = running.used_resources.memory_bytes;
    else CHECK(running.used_resources.memory_bytes == short_name_bytes + (listener_count ? strlen("long-listener-name") - 1u : 0u));
    if (descriptors != 0u) {
      fail_cancel = true;
      CHECK(ftun_proxy_runtime_destroy(&runtime) != FTUN_OK && runtime != NULL);
      CHECK(equal_usage(budget, &running) == 0);
      CHECK(fd_count() == baseline + 2u + descriptors);
      fail_cancel = false;
    }
    CHECK(ftun_proxy_runtime_destroy(&runtime) == FTUN_OK && runtime == NULL);
    CHECK(equal_usage(budget, &base) == 0 && fd_count() == baseline + 2u);
    inbound[0].name = "long-listener-name";
  }
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_backend_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u &&
    usage.used_resources.descriptors == 0u && usage.used_resources.queue_slots == 0u &&
    usage.child_count == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK && fd_count() == baseline);
  return 0;
}

static int run_round(ftun_proxy_runtime_t *runtime, ftun_status_t *out)
{
  ftun_proxy_runtime_run_usage_t usage;
  *out = ftun_proxy_runtime_run_once(runtime, false, &usage);
  return 0;
}

/* 单个待接纳连接的错误、资源不足及未知错误都不能让数据面失败；未知错误
 * 必须退避而不是热循环。监听句柄无效仍按故障上报，留给故障域契约处理。 */
static int accept_errors(void)
{
  static const int per_connection[] = {EPERM, ETIMEDOUT, ENOPROTOOPT,
    ECONNRESET, ECONNABORTED};
  static const int unknown[] = {EIO};
  static const int invalid[] = {EBADF};
  const struct timespec pause = {0, 150 * 1000 * 1000};
  ftun_budget_options_t limits = {0};
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_proxy_runtime_t *runtime = NULL;
  ftun_proxy_bindings_t bindings = {0};
  ftun_proxy_dns_runtime_adapter_t dns = {0};
  ftun_dns_service_slot_t dns_slot = {0};
  ftun_fakeip_service_t *fakeip = NULL;
  ftun_config_t config = {0};
  ftun_config_bind_sections(&config);
  ftun_feature_plan_t plan = {0};
  ftun_config_inbound_t inbound = {0};
  ftun_status_t status = FTUN_OK;
  struct sockaddr_in address = {0};
  unsigned int port = 0u;
  char listen[32];
  size_t round;
  int client;
  /* 与产品派生容量一致保留余量：监听退避需要额外的计时事件源。 */
  limits.limit = (ftun_budget_resources_t){16u * 1024u * 1024u, 16u, 4096u};
  CHECK(ftun_budget_create_resources(NULL, &limits, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 8u, &operations) == FTUN_OK);
  CHECK(ftun_event_loop_create_with_capacity(core, 64u, &loop) == FTUN_OK);
  CHECK(ftun_event_backend_attach(loop) == FTUN_OK);
  bindings.loop = loop;
  bindings.resolver.start = resolve_unused;
  bindings.path.start = dial_unused;
  bindings.fakeip_slot = &fakeip;
  dns.core = core;
  ftun_app_dns_bridge_init(&dns);
  dns.slot = &dns_slot;
  bindings.dns = &dns;
  ftun_config_bind_plan(&config, &plan);
  ftun_config_timeouts_default(&config);
  config.base.proxy.capacity.tcp_flows = 1u;
  config.base.proxy.capacity.udp_flows = 1u;
  config.base.proxy.capacity.udp_associations = 1u;
  config.inbounds = &inbound;
  config.inbound_count = 1u;
  CHECK(endpoint(listen, sizeof(listen)) == 0);
  CHECK(sscanf(listen, "127.0.0.1:%u", &port) == 1);
  inbound.kind = FTUN_CONFIG_INBOUND_SOCKS5;
  inbound.name = "a";
  inbound.listen = listen;
  CHECK(ftun_proxy_runtime_prepare(core, budget, operations, &bindings,
    &config, 1u, &runtime) == FTUN_OK);
  CHECK(ftun_proxy_runtime_activate(runtime) == FTUN_OK);
  client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
  CHECK(client >= 0);
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons((uint16_t)port);
  CHECK(connect(client, (struct sockaddr *)&address, sizeof(address)) == 0);

  accept_injecting = true;
  accept_script = per_connection;
  accept_script_length = sizeof(per_connection) / sizeof(per_connection[0]);
  accept_calls = 0u;
  for (round = 0u; round < 64u && accept_calls <= accept_script_length; round++) {
    CHECK(run_round(runtime, &status) == 0 && status == FTUN_OK);
  }
  CHECK(accept_calls > accept_script_length);

  accept_script = unknown;
  accept_script_length = 1u;
  accept_calls = 0u;
  for (round = 0u; round < 64u && accept_calls == 0u; round++) {
    CHECK(run_round(runtime, &status) == 0 && status == FTUN_OK);
  }
  CHECK(accept_calls == 1u);
  for (round = 0u; round < 16u; round++) {
    CHECK(run_round(runtime, &status) == 0 && status == FTUN_OK);
  }
  CHECK(accept_calls == 1u);
  CHECK(nanosleep(&pause, NULL) == 0);
  for (round = 0u; round < 64u && accept_calls == 1u; round++) {
    CHECK(run_round(runtime, &status) == 0 && status == FTUN_OK);
  }
  CHECK(accept_calls > 1u);

  accept_script = invalid;
  accept_script_length = 1u;
  accept_calls = 0u;
  for (round = 0u; round < 64u && accept_calls == 0u; round++) {
    CHECK(run_round(runtime, &status) == 0);
    if (status != FTUN_OK) break;
  }
  /* 监听句柄本身失效只影响这个监听：关闭并等待恢复，服务不报错。 */
  CHECK(accept_calls == 1u && status == FTUN_OK);
  CHECK(ftun_proxy_runtime_listeners_waiting(runtime) == 1u);
  accept_script_length = 0u;
  accept_calls = 0u;
  for (round = 0u; round < 400u && ftun_proxy_runtime_listeners_waiting(runtime) != 0u; round++) {
    const struct timespec tick = {0, 5 * 1000 * 1000};
    CHECK(nanosleep(&tick, NULL) == 0);
    CHECK(run_round(runtime, &status) == 0 && status == FTUN_OK);
  }
  CHECK(ftun_proxy_runtime_listeners_waiting(runtime) == 0u);
  {
    /* 重新 bind 之后新连接又能进入。 */
    int again = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    CHECK(again >= 0);
    CHECK(connect(again, (struct sockaddr *)&address, sizeof(address)) == 0);
    CHECK(close(again) == 0);
  }

  CHECK(close(client) == 0);
  CHECK(ftun_proxy_runtime_destroy(&runtime) == FTUN_OK && runtime == NULL);
  accept_injecting = false;
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_backend_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

/* 启动时监听地址：尚未就绪（EADDRNOTAVAIL）进入等待恢复，不让启动失败；
 * 地址被占用（EADDRINUSE）仍然让启动失败。 */
static int startup_listener(const char *listen_text, bool expect_prepare_ok)
{
  ftun_budget_options_t limits = {0};
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_proxy_runtime_t *runtime = NULL;
  ftun_proxy_bindings_t bindings = {0};
  ftun_proxy_dns_runtime_adapter_t dns = {0};
  ftun_dns_service_slot_t dns_slot = {0};
  ftun_fakeip_service_t *fakeip = NULL;
  ftun_config_t config = {0};
  ftun_config_bind_sections(&config);
  ftun_feature_plan_t plan = {0};
  ftun_config_inbound_t inbound = {0};
  ftun_status_t status;
  size_t round;
  limits.limit = (ftun_budget_resources_t){16u * 1024u * 1024u, 16u, 4096u};
  CHECK(ftun_budget_create_resources(NULL, &limits, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 8u, &operations) == FTUN_OK);
  CHECK(ftun_event_loop_create_with_capacity(core, 64u, &loop) == FTUN_OK);
  CHECK(ftun_event_backend_attach(loop) == FTUN_OK);
  bindings.loop = loop;
  bindings.resolver.start = resolve_unused;
  bindings.path.start = dial_unused;
  bindings.fakeip_slot = &fakeip;
  dns.core = core;
  ftun_app_dns_bridge_init(&dns);
  dns.slot = &dns_slot;
  bindings.dns = &dns;
  ftun_config_bind_plan(&config, &plan);
  ftun_config_timeouts_default(&config);
  config.base.proxy.capacity.tcp_flows = 1u;
  config.base.proxy.capacity.udp_flows = 1u;
  config.base.proxy.capacity.udp_associations = 1u;
  config.inbounds = &inbound;
  config.inbound_count = 1u;
  inbound.kind = FTUN_CONFIG_INBOUND_SOCKS5;
  inbound.name = "a";
  inbound.listen = (char *)listen_text;
  status = ftun_proxy_runtime_prepare(core, budget, operations, &bindings,
    &config, 1u, &runtime);
  if (!expect_prepare_ok) {
    CHECK(status != FTUN_OK);
    /* 失败的 prepare 可能留下只供清理的实例，由调用方回收。 */
    if (runtime != NULL) CHECK(ftun_proxy_runtime_destroy(&runtime) == FTUN_OK);
  } else {
    CHECK(status == FTUN_OK && ftun_proxy_runtime_activate(runtime) == FTUN_OK);
    CHECK(ftun_proxy_runtime_listeners_waiting(runtime) == 1u);
    for (round = 0u; round < 8u; round++) {
      const struct timespec tick = {0, 20 * 1000 * 1000};
      CHECK(nanosleep(&tick, NULL) == 0);
      CHECK(run_round(runtime, &status) == 0 && status == FTUN_OK);
    }
    /* 地址一直没有出现：继续等待，不报错也不空转。 */
    CHECK(ftun_proxy_runtime_listeners_waiting(runtime) == 1u);
    CHECK(ftun_proxy_runtime_destroy(&runtime) == FTUN_OK && runtime == NULL);
  }
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_backend_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int startup_listeners(void)
{
  char busy[32];
  struct sockaddr_in address = {0};
  socklen_t length = sizeof(address);
  int occupied;
  /* 192.0.2.0/24 是文档保留网段，本机没有这个地址。 */
  CHECK(startup_listener("192.0.2.77:9", true) == 0);
  occupied = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
  CHECK(occupied >= 0);
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  CHECK(bind(occupied, (struct sockaddr *)&address, length) == 0);
  CHECK(listen(occupied, 1) == 0);
  CHECK(getsockname(occupied, (struct sockaddr *)&address, &length) == 0);
  CHECK(snprintf(busy, sizeof(busy), "127.0.0.1:%u", ntohs(address.sin_port)) > 0);
  CHECK(startup_listener(busy, false) == 0);
  CHECK(close(occupied) == 0);
  return 0;
}

int main(void)
{
  CHECK(accept_errors() == 0);
  CHECK(startup_listeners() == 0);
  CHECK(admission(0u, false) == 0);
  CHECK(admission(1u, false) == 0);
  CHECK(admission(1u, true) == 0);
  CHECK(admission(2u, false) == 0);
  puts("Proxy resources: exact owned FD/queue limits, listener names, pressure recovery and retained cleanup passed");
  return 0;
}
