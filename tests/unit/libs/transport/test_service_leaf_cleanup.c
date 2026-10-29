#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#include <netinet/in.h>
#include "app/config/model.h"
#include "app/composition/bridges.h"

#include "libs/transport/socket_path.h"
#include "app/config/parser.h"
#include "app/config/compile.h"
#include "core/limits.h"
#include "core/context.h"
#include "core/operation.h"
#include "core/lifecycle.h"
#include "core/worker.h"
#include "dns/module.h"
#include "dns/dispatcher.h"
#include "core/event/loop.h"
#include "proxy/runtime.h"
#include "proxy/module.h"
#include "proxy/slot_pool.h"
#include "platform/clock.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expression) do { \
  if (!(expression)) { \
    fprintf(stderr, "leaf cleanup contract failed: %s:%d: %s\n", \
            __FILE__, __LINE__, #expression); \
    return 1; \
  } \
} while (0)

typedef struct {
  size_t io_starts;
  size_t io_fail_at;
  size_t cancels;
  ftun_status_t cancel_status;
} backend_t;

typedef struct {
  ftun_budget_t *budget;
  ftun_operation_queue_t *operations;
  ftun_core_t *core;
  ftun_event_loop_t *loop;
  ftun_budget_usage_t baseline;
  backend_t backend;
} fixture_t;

static bool pool_fail;
static bool worker_wakeup_fail;
static bool socket_tracking;
static size_t socket_calls;
static size_t socket_fail_at;
static int tracked_socket = -1;
static size_t tracked_closes;
static ftun_status_t dispatcher_destroy_status;
static size_t dispatcher_releases;

ftun_status_t __real_ftun_proxy_slot_pool_create(
  ftun_budget_t *, size_t, size_t, size_t, size_t, ftun_proxy_slot_pool_t **);
ftun_status_t __wrap_ftun_proxy_slot_pool_create(
  ftun_budget_t *budget, size_t object_size, size_t capacity,
  size_t slab_size, size_t retained, ftun_proxy_slot_pool_t **out)
{
  if (pool_fail) {
    *out = NULL;
    return FTUN_E_IO;
  }
  return __real_ftun_proxy_slot_pool_create(budget, object_size, capacity,
                                            slab_size, retained, out);
}

ftun_status_t __real_ftun_worker_set_wakeup(ftun_worker_t *,
  ftun_worker_wakeup_fn, void *);
ftun_status_t __wrap_ftun_worker_set_wakeup(ftun_worker_t *worker,
  ftun_worker_wakeup_fn wakeup, void *user)
{
  if (worker_wakeup_fail && wakeup != NULL) return FTUN_E_IO;
  return __real_ftun_worker_set_wakeup(worker, wakeup, user);
}

ftun_status_t __real_ftun_dns_dispatcher_destroy(ftun_dns_dispatcher_t **);
ftun_status_t __wrap_ftun_dns_dispatcher_destroy(ftun_dns_dispatcher_t **dispatcher)
{
  bool owned = dispatcher != NULL && *dispatcher != NULL;
  ftun_status_t status;
  if (owned && dispatcher_destroy_status != FTUN_OK) {
    return dispatcher_destroy_status;
  }
  status = __real_ftun_dns_dispatcher_destroy(dispatcher);
  if (owned && *dispatcher == NULL) dispatcher_releases++;
  return status;
}

int __real_socket(int, int, int);
int __wrap_socket(int domain, int type, int protocol)
{
  int descriptor;
  if (socket_tracking) {
    socket_calls++;
    if (socket_calls == socket_fail_at) {
      errno = EIO;
      return -1;
    }
  }
  descriptor = __real_socket(domain, type, protocol);
  if (socket_tracking && descriptor >= 0 && tracked_socket < 0) {
    tracked_socket = descriptor;
  }
  return descriptor;
}

int __real_close(int);
int __wrap_close(int descriptor)
{
  if (socket_tracking && descriptor == tracked_socket) tracked_closes++;
  return __real_close(descriptor);
}

static ftun_status_t backend_io(void *context, ftun_event_source_t *source,
                                ftun_native_socket_t socket, uint32_t interests)
{
  backend_t *backend = (backend_t *)context;
  (void)source; (void)socket; (void)interests;
  backend->io_starts++;
  return backend->io_starts == backend->io_fail_at ? FTUN_E_IO : FTUN_OK;
}

static ftun_status_t backend_update(void *context, ftun_event_source_t *source,
                                    uint32_t interests)
{
  (void)context; (void)source; (void)interests;
  return FTUN_OK;
}

static ftun_status_t backend_timer(void *context, ftun_event_source_t *source,
                                   uint64_t deadline_ms)
{
  (void)context; (void)source; (void)deadline_ms;
  return FTUN_OK;
}

static ftun_status_t backend_cancel(void *context, ftun_event_source_t *source)
{
  backend_t *backend = (backend_t *)context;
  (void)source;
  backend->cancels++;
  return backend->cancel_status;
}

static void backend_void(void *context) { (void)context; }
static ftun_status_t backend_run(void *context, bool block)
{
  (void)context; (void)block;
  return FTUN_OK;
}

static const ftun_event_backend_ops_t backend_ops = {
  backend_io, backend_update, backend_timer, backend_cancel,
  backend_void, backend_run, backend_void, backend_void, false
};

static int fixture_open(fixture_t *fixture)
{
  memset(fixture, 0, sizeof(*fixture));
  CHECK(ftun_budget_create(NULL, 64u * 1024u * 1024u, 1024u,
                            &fixture->budget) == FTUN_OK);
  CHECK(ftun_operation_queue_create(fixture->budget, 512u,
                                     &fixture->operations) == FTUN_OK);
  CHECK(ftun_core_context_create(fixture->budget, &fixture->core) == FTUN_OK);
  CHECK(ftun_event_loop_create_with_capacity(fixture->core, 128u,
                                              &fixture->loop) == FTUN_OK);
  CHECK(ftun_event_loop_attach_backend(fixture->loop, &backend_ops,
                                        &fixture->backend) == FTUN_OK);
  CHECK(ftun_budget_get_usage(fixture->budget, &fixture->baseline) == FTUN_OK);
  return 0;
}

static int fixture_close(fixture_t *fixture)
{
  ftun_budget_usage_t usage;
  ftun_event_loop_usage_t events;
  CHECK(ftun_budget_get_usage(fixture->budget, &usage) == FTUN_OK);
  CHECK(usage.used == fixture->baseline.used &&
        usage.used_resources.descriptors == fixture->baseline.used_resources.descriptors &&
        usage.used_resources.queue_slots == fixture->baseline.used_resources.queue_slots);
  CHECK(ftun_event_loop_get_usage(fixture->loop, &events) == FTUN_OK &&
        events.source_count == 0u && events.ready_count == 0u);
  CHECK(ftun_event_loop_stop(fixture->loop) == FTUN_OK);
  CHECK(ftun_event_loop_detach_backend(fixture->loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&fixture->loop) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&fixture->core) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(fixture->operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&fixture->operations) == FTUN_OK);
  CHECK(ftun_budget_destroy(&fixture->budget) == FTUN_OK);
  return 0;
}

static uint16_t reserve_port(void)
{
  struct sockaddr_in address;
  socklen_t length = (socklen_t)sizeof(address);
  int descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (descriptor < 0) return 0u;
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(descriptor, (const struct sockaddr *)&address, length) != 0 ||
      getsockname(descriptor, (struct sockaddr *)&address, &length) != 0) {
    (void)close(descriptor);
    return 0u;
  }
  (void)close(descriptor);
  return ntohs(address.sin_port);
}

static ftun_config_t *make_config(uint16_t port)
{
  char json[1024];
  ftun_config_t *config = NULL;
  int length;
  if (port == 0u) {
    length = snprintf(json, sizeof(json), "{}");
  } else {
    length = snprintf(json, sizeof(json),
      "{\"dns\":{\"enable\":true,\"cache\":true,"
      "\"default-server\":\"real\",\"listeners\":[{"
      "\"listen\":\"127.0.0.1:%u\",\"server\":\"real\"}],"
      "\"servers\":[{\"name\":\"real\",\"type\":\"udp\","
      "\"address\":[\"192.0.2.53:53\"],\"outbound\":\"DIRECT\"}]}}",
      (unsigned int)port);
  }
  if (length <= 0 || (size_t)length >= sizeof(json)) return NULL;
  if (ftun_config_parse((ftun_bytes_t){(const uint8_t *)json, (size_t)length},
                          &config) != FTUN_OK) return NULL;
  if (ftun_config_compile(config, &config->plan) != FTUN_OK) {
    (void)ftun_config_destroy(&config);
    return NULL;
  }
  return config;
}

typedef struct { ftun_status_t status; size_t stops; } provider_t;
static ftun_status_t provider_stop(void *context, uint64_t deadline_ms)
{
  provider_t *provider = (provider_t *)context;
  if (deadline_ms == 0u || deadline_ms == UINT64_MAX) return FTUN_E_INVALID;
  provider->stops++;
  return provider->status;
}
static ftun_status_t resolver_start(void *context, ftun_core_t *core,
  const ftun_resolver_provider_request_t *request, ftun_operation_t **out)
{
  (void)context; (void)core; (void)request; (void)out;
  return FTUN_E_UNSUPPORTED;
}
static ftun_status_t path_start(void *context, ftun_core_t *core,
  const ftun_dial_request_t *request, ftun_operation_t **out)
{
  (void)context; (void)core; (void)request; (void)out;
  return FTUN_E_UNSUPPORTED;
}

static int proxy_prepare_failure(bool after_path)
{
  fixture_t fixture;
  ftun_core_service_t service = {0};
  ftun_proxy_bindings_t bindings = {0};
  ftun_dns_service_slot_t slot = {0};
  ftun_proxy_dns_runtime_adapter_t adapter = {0};
  ftun_fakeip_service_t *fakeip = NULL;
  ftun_config_t *config = make_config(0u);
  ftun_core_service_binding_t erased = {&bindings, sizeof(bindings)};
  provider_t provider = {FTUN_E_IO, 0u};
  ftun_budget_usage_t usage;
  void *retained;
  uint64_t now = 0u;
  size_t provider_count = after_path ? 2u : 1u;
  size_t attempt;
  ftun_status_t status = FTUN_E_AGAIN;
  CHECK(config != NULL && fixture_open(&fixture) == 0);
  bindings.loop = fixture.loop;
  bindings.resolver.start = resolver_start;
  bindings.resolver.stop_until = provider_stop;
  bindings.resolver_context = &provider;
  bindings.path.start = path_start;
  bindings.path.stop_until = provider_stop;
  bindings.path_context = &provider;
  adapter.core = fixture.core;
  ftun_app_dns_bridge_init(&adapter);
  adapter.slot = &slot;
  adapter.fakeip_slot = &fakeip;
  bindings.dns = &adapter;
  bindings.fakeip_slot = &fakeip;
  pool_fail = !after_path;
  worker_wakeup_fail = after_path;
  CHECK(ftun_core_service_prepare(&service, &ftun_proxy_service, fixture.core,
    fixture.budget, fixture.operations, &erased, config, 1u) == FTUN_E_IO);
  pool_fail = false;
  worker_wakeup_fail = false;
  CHECK(service.implementation != NULL && service.cleanup_only &&
        service.first_error == FTUN_E_IO && provider.stops == provider_count);
  retained = service.implementation;
  CHECK(ftun_core_service_activate(&service) == FTUN_E_STALE);
  CHECK(ftun_proxy_runtime_activate((ftun_proxy_runtime_t *)retained) == FTUN_E_INVALID);
  CHECK(ftun_core_service_prepare(&service, &ftun_proxy_service, fixture.core,
    fixture.budget, fixture.operations, &erased, config, 1u) == FTUN_E_AGAIN);
  CHECK(service.implementation == retained);
  CHECK(ftun_budget_get_usage(fixture.budget, &usage) == FTUN_OK &&
        usage.used > fixture.baseline.used);
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  provider.status = FTUN_E_AGAIN;
  CHECK(ftun_core_service_destroy_until(&service, now) == FTUN_E_AGAIN &&
        service.implementation == retained && service.cleanup_error == FTUN_E_AGAIN);
  provider.status = FTUN_OK;
  /* 后置故障点已创建真实 worker；非阻塞清理须允许线程异步退出。 */
  for (attempt = 0u; attempt < 1000u && service.implementation != NULL; attempt++) {
    struct timespec pause = {0, 1000000L};
    CHECK(ftun_monotonic_now(&now) == FTUN_OK);
    status = ftun_core_service_destroy_until(&service, now);
    CHECK(status == FTUN_OK || status == FTUN_E_AGAIN || status == FTUN_E_TIMEOUT);
    if (status != FTUN_OK) {
      CHECK(service.implementation == retained);
      (void)nanosleep(&pause, NULL);
    }
  }
  CHECK(status == FTUN_OK && service.implementation == NULL &&
        service.first_error == FTUN_E_IO);
  CHECK(provider.stops == provider_count * 3u);
  CHECK(ftun_core_service_destroy_until(&service, now) == FTUN_OK &&
        provider.stops == provider_count * 3u);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(fixture_close(&fixture) == 0);
  return 0;
}

static int proxy_watcher_failure(void)
{
  fixture_t fixture;
  ftun_core_service_t service = {0};
  ftun_proxy_bindings_t bindings = {0};
  ftun_dns_service_slot_t slot = {0};
  ftun_proxy_dns_runtime_adapter_t adapter = {0};
  ftun_fakeip_service_t *fakeip = NULL;
  ftun_config_t *config = NULL;
  ftun_core_service_binding_t erased = {&bindings, sizeof(bindings)};
  provider_t provider = {FTUN_OK, 0u};
  ftun_event_loop_usage_t events;
  ftun_status_t status = FTUN_E_AGAIN;
  uint16_t port = reserve_port();
  uint64_t now = 0u;
  char json[256];
  int length = snprintf(json, sizeof(json),
    "{\"inbounds\":[{\"name\":\"socks\",\"type\":\"socks5\","
    "\"listen\":\"127.0.0.1:%u\",\"udp\":true}]}", (unsigned int)port);
  size_t attempt;
  CHECK(port != 0u && length > 0 && (size_t)length < sizeof(json));
  CHECK(ftun_config_parse((ftun_bytes_t){(const uint8_t *)json, (size_t)length},
                          &config) == FTUN_OK);
  CHECK(ftun_config_compile(config, &config->plan) == FTUN_OK);
  CHECK(fixture_open(&fixture) == 0);
  bindings.loop = fixture.loop;
  bindings.resolver.start = resolver_start;
  bindings.resolver.stop_until = provider_stop;
  bindings.resolver_context = &provider;
  bindings.path.start = path_start;
  bindings.path.stop_until = provider_stop;
  bindings.path_context = &provider;
  adapter.core = fixture.core;
  ftun_app_dns_bridge_init(&adapter);
  adapter.slot = &slot;
  adapter.fakeip_slot = &fakeip;
  bindings.dns = &adapter;
  bindings.fakeip_slot = &fakeip;
  fixture.backend.io_fail_at = 2u;
  fixture.backend.cancel_status = FTUN_E_IO;
  CHECK(ftun_core_service_prepare(&service, &ftun_proxy_service, fixture.core,
    fixture.budget, fixture.operations, &erased, config, 1u) == FTUN_E_IO);
  CHECK(service.implementation != NULL && service.cleanup_only && provider.stops == 0u);
  CHECK(ftun_event_loop_get_usage(fixture.loop, &events) == FTUN_OK && events.source_count == 1u);
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  CHECK(ftun_core_service_destroy_until(&service, now) == FTUN_E_IO &&
        service.implementation != NULL && provider.stops == 0u);
  fixture.backend.cancel_status = FTUN_OK;
  /* 真 worker 异步退出；每次 destroy 只给当前时刻，不能借重试延长阻塞。 */
  for (attempt = 0u; attempt < 1000u && service.implementation != NULL; attempt++) {
    struct timespec pause = {0, 1000000L};
    CHECK(ftun_monotonic_now(&now) == FTUN_OK);
    status = ftun_core_service_destroy_until(&service, now);
    CHECK(status == FTUN_OK || status == FTUN_E_AGAIN || status == FTUN_E_TIMEOUT);
    if (status != FTUN_OK) {
      CHECK(service.implementation != NULL);
      (void)nanosleep(&pause, NULL);
    }
  }
  CHECK(status == FTUN_OK && service.implementation == NULL && provider.stops == 2u);
  CHECK(ftun_core_service_destroy_until(&service, now) == FTUN_OK && provider.stops == 2u);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(fixture_close(&fixture) == 0);
  return 0;
}

static int dns_early_retain_failure(void)
{
  fixture_t fixture;
  ftun_dns_runtime_t *runtime = NULL;
  uint16_t port = reserve_port();
  ftun_config_t *config = make_config(port);
  int stdin_flags = fcntl(STDIN_FILENO, F_GETFD);
  CHECK(port != 0u && config != NULL && fixture_open(&fixture) == 0);
  config->document.reference_count = SIZE_MAX;
  CHECK(ftun_dns_runtime_prepare(fixture.core, fixture.budget,
    fixture.operations, fixture.loop, config, NULL,
    &(ftun_dns_runtime_network_t){.generation = 1u, .socket_mark = 0u,
      .path = {.open = ftun_socket_path_open}}, &runtime) == FTUN_E_LIMIT);
  CHECK(runtime == NULL && config->document.reference_count == SIZE_MAX);
  CHECK(fcntl(STDIN_FILENO, F_GETFD) == stdin_flags);
  config->document.reference_count = 1u;
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(fixture_close(&fixture) == 0);
  return 0;
}

static int dns_prepare_failure(bool hold_cleanup)
{
  fixture_t fixture;
  ftun_core_service_t service = {0};
  ftun_dns_service_slot_t slot = {0};
  ftun_dns_service_binding_t bindings = {0};
  ftun_core_service_binding_t erased = {&bindings, sizeof(bindings)};
  uint16_t port = reserve_port();
  ftun_config_t *config = make_config(port);
  size_t released = dispatcher_releases;
  void *retained;
  CHECK(port != 0u && config != NULL && fixture_open(&fixture) == 0);
  bindings.loop = fixture.loop;
  bindings.slot = &slot;
  bindings.path.open = ftun_socket_path_open;
  socket_calls = 0u;
  socket_fail_at = 2u;
  tracked_socket = -1;
  tracked_closes = 0u;
  socket_tracking = true;
  dispatcher_destroy_status = hold_cleanup ? FTUN_E_AGAIN : FTUN_OK;
  CHECK(ftun_core_service_prepare(&service, &ftun_dns_core_service, fixture.core,
    fixture.budget, fixture.operations, &erased, config, 1u) == FTUN_E_IO);
  CHECK(socket_calls == 2u && tracked_socket >= 0 && tracked_closes == 1u);
  CHECK(fcntl(tracked_socket, F_GETFD) == -1 && errno == EBADF);
  CHECK(service.first_error == FTUN_E_IO && !slot.accepting && slot.active == NULL);
  if (hold_cleanup) {
    CHECK(service.implementation != NULL && service.cleanup_only &&
          config->document.reference_count == 2u && dispatcher_releases == released);
    retained = service.implementation;
    CHECK(ftun_core_service_activate(&service) == FTUN_E_STALE);
    CHECK(ftun_core_service_destroy_until(&service, 1u) == FTUN_E_AGAIN &&
          service.implementation == retained && config->document.reference_count == 2u);
    CHECK(ftun_config_destroy(&config) == FTUN_OK && config == NULL);
    dispatcher_destroy_status = FTUN_OK;
    CHECK(ftun_core_service_destroy_until(&service, 1u) == FTUN_OK &&
          service.implementation == NULL);
  } else {
    CHECK(service.implementation == NULL && config->document.reference_count == 1u);
    CHECK(ftun_config_destroy(&config) == FTUN_OK);
  }
  CHECK(dispatcher_releases == released + 1u && tracked_closes == 1u);
  CHECK(ftun_core_service_destroy_until(&service, 1u) == FTUN_OK &&
        dispatcher_releases == released + 1u);
  socket_tracking = false;
  CHECK(fixture_close(&fixture) == 0);
  return 0;
}

static int dns_reload_failure(void)
{
  fixture_t fixture;
  ftun_core_service_t service = {0};
  ftun_dns_service_slot_t slot = {0};
  ftun_dns_service_binding_t bindings = {0};
  ftun_core_service_binding_t erased = {&bindings, sizeof(bindings)};
  ftun_event_loop_usage_t usage;
  uint16_t port = reserve_port();
  ftun_config_t *config = make_config(port);
  ftun_config_t *candidate = make_config(port);
  size_t released = dispatcher_releases;
  CHECK(port != 0u && config != NULL && candidate != NULL && fixture_open(&fixture) == 0);
  bindings.loop = fixture.loop;
  bindings.slot = &slot;
  bindings.path.open = ftun_socket_path_open;
  CHECK(ftun_core_service_prepare(&service, &ftun_dns_core_service, fixture.core,
    fixture.budget, fixture.operations, &erased, config, 1u) == FTUN_OK);
  CHECK(ftun_core_service_activate(&service) == FTUN_OK && slot.accepting);
  CHECK(fixture.backend.io_starts == 2u);
  fixture.backend.io_fail_at = 4u;
  fixture.backend.cancel_status = FTUN_E_IO;
  CHECK(ftun_core_service_reload_prepare(&service, candidate, 2u) == FTUN_E_IO);
  CHECK(service.reload_pending && !service.reload_ready && candidate->document.reference_count == 2u);
  CHECK(ftun_event_loop_get_usage(fixture.loop, &usage) == FTUN_OK && usage.source_count == 3u);
  CHECK(ftun_core_service_reload_prepare(&service, candidate, 2u) == FTUN_E_AGAIN);
  CHECK(ftun_core_service_reload_abort(&service) == FTUN_E_IO && candidate->document.reference_count == 2u);
  CHECK(ftun_core_service_destroy_until(&service, 1u) == FTUN_E_IO &&
        service.implementation != NULL && dispatcher_releases == released);
  fixture.backend.cancel_status = FTUN_OK;
  CHECK(ftun_core_service_reload_abort(&service) == FTUN_OK && candidate->document.reference_count == 1u);
  CHECK(dispatcher_releases == released + 1u);
  CHECK(ftun_core_service_destroy_until(&service, 1u) == FTUN_OK &&
        service.implementation == NULL && config->document.reference_count == 1u);
  CHECK(dispatcher_releases == released + 2u);
  CHECK(ftun_core_service_destroy_until(&service, 1u) == FTUN_OK &&
        dispatcher_releases == released + 2u);
  CHECK(ftun_config_destroy(&candidate) == FTUN_OK);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(fixture_close(&fixture) == 0);
  return 0;
}

int main(void)
{
  CHECK(proxy_prepare_failure(false) == 0);
  CHECK(proxy_prepare_failure(true) == 0);
  CHECK(proxy_watcher_failure() == 0);
  CHECK(dns_early_retain_failure() == 0);
  CHECK(dns_prepare_failure(false) == 0);
  CHECK(dns_prepare_failure(true) == 0);
  CHECK(dns_reload_failure() == 0);
  puts("leaf cleanup: 6 real Proxy/DNS ownership scenarios passed");
  return 0;
}
