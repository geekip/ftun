#define _GNU_SOURCE 1
#include "config/compile.h"
#include "core/context.h"
#include "event/libev_adapter.h"
#include "proxy/runtime.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
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
  ftun_feature_plan_t plan = {0};
  ftun_config_inbound_t inbound[2] = {{0}};
  ftun_budget_usage_t base, running, usage;
  ftun_reservation_t *pressure = NULL;
  size_t baseline = fd_count(), descriptors = listener_count * (udp ? 2u : 1u);
  size_t short_name_bytes = 0u, index;
  char endpoints[2][32];
  limits.limit = (ftun_budget_resources_t){16u * 1024u * 1024u,
    2u + descriptors, 256u + 8u + 64u + 16u + 2u + descriptors};
  CHECK(ftun_budget_create_resources(NULL, &limits, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 8u, &operations) == FTUN_OK);
  CHECK(ftun_event_loop_create_with_capacity(core, 16u, &loop) == FTUN_OK);
  CHECK(ftun_libev_attach(loop) == FTUN_OK);
  CHECK(fd_count() == baseline + 2u);
  bindings.loop = loop;
  bindings.resolver.start = resolve_unused;
  bindings.path.start = dial_unused;
  bindings.fakeip_slot = &fakeip;
  dns.core = core;
  dns.slot = &dns_slot;
  bindings.dns = &dns;
  config.plan = &plan;
  config.base.capacity.tcp_flows = 1u;
  config.base.capacity.udp_flows = 1u;
  config.base.capacity.udp_associations = 1u;
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
  CHECK(ftun_budget_reserve(budget, base.normal_available, &pressure) == FTUN_OK);
  CHECK(ftun_proxy_runtime_prepare(core, budget, operations, &bindings,
    &config, 1u, &runtime) == FTUN_E_LIMIT && runtime == NULL);
  CHECK(ftun_reservation_release(&pressure) == FTUN_OK);
  CHECK(equal_usage(budget, &base) == 0 && fd_count() == baseline + 2u);

  if (descriptors != 0u) {
    CHECK(ftun_budget_reserve_resources(budget,
      (ftun_budget_resources_t){0u, 1u, 0u}, &pressure) == FTUN_OK);
    CHECK(ftun_proxy_runtime_prepare(core, budget, operations, &bindings,
      &config, 1u, &runtime) == FTUN_E_LIMIT && runtime == NULL);
    CHECK(ftun_reservation_release(&pressure) == FTUN_OK);
    CHECK(equal_usage(budget, &base) == 0 && fd_count() == baseline + 2u);

    CHECK(ftun_budget_reserve_resources(budget,
      (ftun_budget_resources_t){0u, 0u, 1u}, &pressure) == FTUN_OK);
    CHECK(ftun_proxy_runtime_prepare(core, budget, operations, &bindings,
      &config, 1u, &runtime) == FTUN_E_LIMIT);
    CHECK(ftun_proxy_runtime_destroy(&runtime) == FTUN_OK);
    CHECK(ftun_reservation_release(&pressure) == FTUN_OK);
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
    if (index == 0u) short_name_bytes = running.used;
    else CHECK(running.used == short_name_bytes + (listener_count ? strlen("long-listener-name") - 1u : 0u));
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
  CHECK(ftun_libev_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == 0u &&
    usage.used_resources.descriptors == 0u && usage.used_resources.queue_slots == 0u &&
    usage.child_count == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK && fd_count() == baseline);
  return 0;
}

int main(void)
{
  CHECK(admission(0u, false) == 0);
  CHECK(admission(1u, false) == 0);
  CHECK(admission(1u, true) == 0);
  CHECK(admission(2u, false) == 0);
  puts("Proxy resources: exact owned FD/queue limits, listener names, pressure recovery and retained cleanup passed");
  return 0;
}
