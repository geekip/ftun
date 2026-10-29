#define _POSIX_C_SOURCE 200809L
#include "app/config/model.h"
#include "libs/tun/service.h"
#include "proxy/runtime.h"
#include "proxy/session.h"
#include "proxy/netstack/ingress.h"
#include "proxy/dns/runtime_adapter.h"
#include "libs/transport/relay.h"
#include "libs/transport/socket_path.h"
#include "platform/clock.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define REQUIRE(value) do { if (!(value)) { \
  fprintf(stderr, "TUN admission failed at %d: %s\n", __LINE__, #value); \
  abort(); } } while (0)

enum { PATH_FAILED, MEMORY_EXHAUSTED, SESSION_PENDING, DNS_STREAM_FAILED, DNS_RELAY_FAILED };
#define ADMISSION_FAILED (-1)
enum { START, HELD, RELEASE, DRAINED, FAILED_REBUILD, REBUILD, PATH_CHANGE, NETWORK_CHANGE, GATED, QUIESCE, COMMITTED };
typedef struct { int mode, step; bool done, result; } command_t;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static ftun_tun_ingress_spec_t ingress;
static ftun_proxy_runtime_t *runtime;
static ftun_budget_t *budget;
static ftun_session_t *pending_session;
static ftun_operation_t *pending_operation;
static ftun_stream_t *incoming, *held_remote;
static void (*remote_progress)(void *user);
static void *remote_user;
static size_t baseline_descriptors;
static unsigned int destroyed, cancels, completed, left_closes;
static unsigned int path_opens;
static int mode, pair_left = -1, guard = -1;
static bool armed, allow_cancel;
#if defined(FTUN_TEST_TUN_RECOVERY)
static ftun_tun_lease_t tun_lease;
static ftun_tun_consumer_t tun_consumer;
static unsigned int binds;
static bool fail_open;

ftun_status_t __real_ftun_proxy_runtime_reload_commit(ftun_proxy_runtime_t *, uint64_t);
ftun_status_t __wrap_ftun_proxy_runtime_reload_commit(ftun_proxy_runtime_t *engine, uint64_t generation)
{
  ftun_tun_path_t path = {1250u, 0u, 0u};
  REQUIRE(generation == 2u);
  REQUIRE(ftun_tun_service_update_path(tun_lease, &path) == FTUN_OK);
  return __real_ftun_proxy_runtime_reload_commit(engine, generation);
}

bool ftun_test_tun_fail_open(void)
{
  bool result = fail_open;
  fail_open = false;
  return result;
}

ftun_status_t __real_ftun_l3_provider_acquire(const ftun_l3_provider_t *,
  uint64_t, const ftun_tun_consumer_spec_t *, ftun_tun_lease_t *);
ftun_status_t __wrap_ftun_l3_provider_acquire(const ftun_l3_provider_t *provider,
  uint64_t generation, const ftun_tun_consumer_spec_t *spec, ftun_tun_lease_t *out)
{
  ftun_status_t status = __real_ftun_l3_provider_acquire(provider, generation, spec, out);
  if (status == FTUN_OK) { tun_lease = *out; tun_consumer = spec->consumer; }
  return status;
}
#endif

ftun_status_t __real_ftun_proxy_runtime_prepare(ftun_core_t *, ftun_budget_t *,
  ftun_operation_queue_t *, const ftun_proxy_bindings_t *, const ftun_config_t *,
  uint64_t, ftun_proxy_runtime_t **);
ftun_status_t __real_ftun_tun_ingress_bind(const ftun_tun_ingress_spec_t *,
  ftun_tun_ingress_context_t **);
ftun_status_t __real_ftun_stream_create(const ftun_stream_options_t *,
  const ftun_stream_backend_t *, ftun_stream_t **);
ftun_status_t __real_ftun_session_transition(ftun_session_t *,
  ftun_session_state_t, ftun_operation_t *);
ftun_status_t __real_ftun_relay_start_with_pool_options(ftun_core_t *,
  ftun_stream_t *, ftun_stream_t *, ftun_buffer_pool_t *,
  const ftun_relay_options_t *, ftun_relay_progress_fn, void *, ftun_relay_t **);
int __real_socketpair(int, int, int, int[2]);
int __real_close(int);

ftun_status_t __wrap_ftun_proxy_runtime_prepare(ftun_core_t *core,
  ftun_budget_t *owner_budget, ftun_operation_queue_t *operations,
  const ftun_proxy_bindings_t *bindings, const ftun_config_t *config,
  uint64_t generation, ftun_proxy_runtime_t **out)
{
  ftun_status_t status = __real_ftun_proxy_runtime_prepare(core, owner_budget,
    operations, bindings, config, generation, out);
  if (status == FTUN_OK) { runtime = *out; budget = owner_budget; }
  return status;
}

ftun_status_t __wrap_ftun_tun_ingress_bind(const ftun_tun_ingress_spec_t *spec,
  ftun_tun_ingress_context_t **out)
{
  ingress = *spec;
#if defined(FTUN_TEST_TUN_RECOVERY)
  binds++;
#endif
  return __real_ftun_tun_ingress_bind(spec, out);
}

ftun_status_t __wrap_ftun_socket_path_open(void *context, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *spec,
  ftun_operation_t **out)
{
  (void)context; (void)core; (void)request; (void)spec;
  path_opens++;
  *out = NULL;
  return FTUN_E_LIMIT;
}

bool __wrap_ftun_proxy_dns_has_hijack(const ftun_proxy_dns_runtime_adapter_t *adapter)
{ (void)adapter; return mode >= DNS_STREAM_FAILED; }

ftun_status_t __wrap_ftun_proxy_dns_hijack_tcp(
  const ftun_proxy_dns_runtime_adapter_t *adapter, int descriptor)
{
  (void)adapter;
  REQUIRE(armed && mode >= DNS_STREAM_FAILED);
  REQUIRE(__real_close(descriptor) == 0);
  return FTUN_OK;
}

int __wrap_socketpair(int domain, int type, int protocol, int descriptors[2])
{
  int result = __real_socketpair(domain, type, protocol, descriptors);
  if (result == 0 && armed && mode >= DNS_STREAM_FAILED) pair_left = descriptors[0];
  return result;
}

int __wrap_close(int descriptor)
{
  int result = __real_close(descriptor);
  if (descriptor == pair_left) {
    left_closes++;
    if (mode == DNS_STREAM_FAILED && left_closes == 1u) {
      /* 精确复用已释放的 FD，二次关闭会误伤独立资源。 */
      guard = open("/dev/null", O_RDONLY | O_CLOEXEC);
      REQUIRE(guard == descriptor);
    }
  }
  return result;
}

ftun_status_t __wrap_ftun_stream_create(const ftun_stream_options_t *options,
  const ftun_stream_backend_t *backend, ftun_stream_t **out)
{
  ftun_status_t status;
  if (armed && mode == DNS_STREAM_FAILED) { *out = NULL; return FTUN_E_LIMIT; }
  status = __real_ftun_stream_create(options, backend, out);
  if (armed && mode == DNS_RELAY_FAILED && status == FTUN_OK) {
    held_remote = *out;
    REQUIRE(ftun_stream_retain(held_remote) == FTUN_OK);
    remote_progress = options->progress;
    remote_user = options->progress_user;
  }
  return status;
}

ftun_status_t __wrap_ftun_relay_start_with_pool_options(ftun_core_t *core,
  ftun_stream_t *left, ftun_stream_t *right, ftun_buffer_pool_t *pool,
  const ftun_relay_options_t *options, ftun_relay_progress_fn progress,
  void *user, ftun_relay_t **out)
{
  if (armed && mode == DNS_RELAY_FAILED) { *out = NULL; return FTUN_E_IO; }
  return __real_ftun_relay_start_with_pool_options(core, left, right, pool,
    options, progress, user, out);
}

static ftun_status_t pending_cancel(void *user)
{
  (void)user;
  cancels++;
  return allow_cancel ? FTUN_OK : FTUN_E_AGAIN;
}

static void pending_completed(ftun_operation_t *operation, ftun_error_t error, void *user)
{
  (void)user;
  REQUIRE(error.status == FTUN_E_CANCELLED && completed == 0u);
  REQUIRE(ftun_session_operation_complete(pending_session, operation, error) == FTUN_OK);
  pending_operation = NULL;
  completed++;
  ingress.stream_event(ingress.user, incoming, FTUN_TUN_STREAM_WRITABLE, FTUN_OK);
}

ftun_status_t __wrap_ftun_session_transition(ftun_session_t *session,
  ftun_session_state_t next, ftun_operation_t *operation)
{
  ftun_status_t status = __real_ftun_session_transition(session, next, operation);
  if (armed && mode == SESSION_PENDING && next == FTUN_SESSION_ROUTING && status == FTUN_OK) {
    ftun_operation_token_t token;
    pending_session = session;
    REQUIRE(ftun_operation_accept(ingress.operations, pending_completed, NULL,
      &pending_operation, &token) == FTUN_OK);
    REQUIRE(ftun_operation_set_cancel_hook(pending_operation, pending_cancel, NULL) == FTUN_OK);
    REQUIRE(__real_ftun_session_transition(session, FTUN_SESSION_RESOLVING,
      pending_operation) == FTUN_OK);
    return FTUN_E_IO;
  }
  return status;
}

static void incoming_destroy(void *user)
{ (void)user; destroyed++; }
static void unused_completion(ftun_operation_t *operation, ftun_error_t error, void *user)
{ (void)operation; (void)error; (void)user; abort(); }
static ftun_status_t read_empty(void *user, void *data, size_t capacity, size_t *length)
{ (void)user; (void)data; (void)capacity; *length = 0u; return FTUN_E_AGAIN; }
static ftun_status_t write_rejected(void *user, ftun_stream_write_token_t token,
  const ftun_buffer_slice_t *slice, size_t *accepted)
{ (void)user; (void)token; (void)slice; *accepted = 0u; return FTUN_E_AGAIN; }
static ftun_status_t write_cancelled(void *user, ftun_stream_write_token_t token)
{ (void)user; (void)token; return FTUN_OK; }

static void owner_command(ftun_operation_t *operation, ftun_error_t error, void *user)
{
  command_t *command = user;
  ftun_proxy_runtime_capacity_info_t capacity;
  ftun_budget_usage_t usage;
  (void)operation;
  REQUIRE(error.status == FTUN_OK);
  REQUIRE(ftun_proxy_runtime_get_capacity_info(runtime, &capacity) == FTUN_OK);
  REQUIRE(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
  command->result = true;
#if defined(FTUN_TEST_TUN_RECOVERY)
  if (command->step >= FAILED_REBUILD) {
    ftun_tun_service_usage_t service;
    ftun_tun_consumer_usage_t consumer;
    uint8_t bytes[20] = {0x45u};
    if (command->step == COMMITTED) {
      command->result = binds == 3u;
      if (command->result) REQUIRE(ingress.generation == 2u && ingress.mtu == 1250u);
      goto done;
    }
    if (command->step == FAILED_REBUILD) {
      fail_open = true;
      REQUIRE(ftun_tun_service_rebuild(tun_lease.service) == FTUN_E_IO);
      REQUIRE(ftun_tun_service_get_usage(tun_lease.service, &service) == FTUN_OK && !service.accepting);
    } else if (command->step == REBUILD) {
      REQUIRE(ftun_tun_service_rebuild(tun_lease.service) == FTUN_OK);
    } else if (command->step == PATH_CHANGE) {
      ftun_tun_path_t path = {1300u, 0u, 0u};
      REQUIRE(ftun_tun_service_update_path(tun_lease, &path) == FTUN_OK);
    } else if (command->step == NETWORK_CHANGE) {
      REQUIRE(ftun_tun_service_get_usage(tun_lease.service, &service) == FTUN_OK);
      REQUIRE(ftun_tun_service_refresh_network(tun_lease.service, service.network_generation) == FTUN_OK);
    } else if (command->step == QUIESCE) {
      REQUIRE(ftun_tun_service_quiesce(tun_lease.service) == FTUN_OK);
    }
    REQUIRE(ingress.output(ingress.user, (ftun_bytes_t){bytes, sizeof(bytes)}) == FTUN_E_CANCELLED);
    REQUIRE(tun_consumer.packet(tun_consumer.user, tun_lease,
      (ftun_bytes_t){bytes, sizeof(bytes)}) == FTUN_OK);
    REQUIRE(ftun_tun_service_get_consumer_usage(tun_lease, &consumer) == FTUN_OK &&
      consumer.queued_inputs == 0u && consumer.queued_outputs == 0u);
    if (command->step != QUIESCE) REQUIRE(binds == 1u && destroyed == 0u);
  } else
#endif
  if (command->step == START) {
    ftun_stream_options_t options = {0};
    ftun_stream_backend_t backend = {0};
    ftun_metadata_t metadata = {0};
    ftun_status_t accepted;
    ftun_reservation_t pressure = (ftun_reservation_t){0};
    REQUIRE(capacity.tcp_active == 0u);
    mode = command->mode;
    destroyed = cancels = completed = left_closes = 0u;
    path_opens = 0u;
    allow_cancel = false;
    pair_left = guard = -1;
    baseline_descriptors = usage.used_resources.descriptors;
    options.budget = ingress.budget;
    options.operations = ingress.operations;
    options.max_pending_writes = 1u;
    options.max_pending_bytes = 1024u;
    options.completion = unused_completion;
    backend.read = read_empty;
    backend.write_start = write_rejected;
    backend.write_cancel = write_cancelled;
    backend.destroy = incoming_destroy;
    REQUIRE(ftun_stream_create(&options, &backend, &incoming) == FTUN_OK);
    metadata.known_fields = FTUN_META_PORT | FTUN_META_NETWORK;
    metadata.network = 1u;
    metadata.generation = ingress.generation;
    metadata.inbound_id = ingress.inbound_id;
    metadata.original_target.kind = FTUN_ADDRESS_IPV4;
    metadata.original_target.address[0] = 127u;
    metadata.original_target.address[3] = 1u;
    metadata.original_target.port = mode >= DNS_STREAM_FAILED ? 53u : 9u;
    if (mode == ADMISSION_FAILED || mode == MEMORY_EXHAUSTED) {
      REQUIRE(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
      if (mode == ADMISSION_FAILED) {
        /* 接纳本身需要推进槽；不要依赖已删除的虚拟内存保底。 */
        REQUIRE(ftun_budget_reserve_resources(budget,
          (ftun_budget_resources_t){0u, 0u, usage.normal_available_resources.queue_slots},
          &pressure) == FTUN_OK);
      } else {
        /* 前一场景保留slab，借用Stream接纳后创建scope/Session时才申请内存。 */
        REQUIRE(ftun_budget_reserve(budget, usage.normal_available, &pressure) == FTUN_OK);
      }
    }
    armed = true;
    accepted = ingress.stream_accept(ingress.user, &metadata, incoming);
    armed = false;
    if (mode == DNS_STREAM_FAILED) {
      REQUIRE(left_closes == 1u && fcntl(guard, F_GETFD) >= 0);
    }
    if (mode == ADMISSION_FAILED) {
      ftun_stream_usage_t stream_usage;
      REQUIRE(ftun_reservation_release(&pressure) == FTUN_OK);
      REQUIRE(accepted == FTUN_E_LIMIT && destroyed == 0u);
      REQUIRE(ftun_stream_get_usage(incoming, &stream_usage) == FTUN_OK &&
        stream_usage.reference_count == 1u);
      REQUIRE(ftun_stream_stop(incoming) == FTUN_OK);
      REQUIRE(ftun_stream_destroy(&incoming) == FTUN_OK);
    } else REQUIRE(accepted == FTUN_OK && destroyed == 0u);
    if (mode == MEMORY_EXHAUSTED) {
      REQUIRE(path_opens == 0u);
      REQUIRE(ftun_proxy_runtime_get_capacity_info(runtime, &capacity) == FTUN_OK &&
        capacity.tcp_active == 1u);
      REQUIRE(ftun_reservation_release(&pressure) == FTUN_OK);
    }
    REQUIRE(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
    REQUIRE(usage.used_resources.descriptors == baseline_descriptors +
      (mode >= DNS_STREAM_FAILED ? 2u : 0u));
  } else if (command->step == HELD) {
    REQUIRE(capacity.tcp_active == 1u);
    command->result = mode == SESSION_PENDING ? cancels != 0u : destroyed == 1u;
    if (mode == SESSION_PENDING) REQUIRE(destroyed == 0u && completed == 0u);
    else REQUIRE(held_remote != NULL && left_closes == 0u);
  } else if (command->step == RELEASE) {
    if (mode == SESSION_PENDING) {
      allow_cancel = true;
      REQUIRE(ftun_operation_cancel(pending_operation) == FTUN_OK);
    } else {
      REQUIRE(ftun_stream_release(&held_remote) == FTUN_OK);
      REQUIRE(remote_progress != NULL);
      remote_progress(remote_user);
    }
  } else {
    command->result = capacity.tcp_active == 0u;
#if defined(FTUN_TEST_TUN_RECOVERY)
    if (mode == SESSION_PENDING && command->result) {
      command->result = binds == 2u;
      if (command->result) REQUIRE(ingress.mtu == 1300u);
    }
#endif
    if (command->result) {
      REQUIRE(destroyed == 1u && usage.used_resources.descriptors == baseline_descriptors);
      if (mode == SESSION_PENDING) REQUIRE(completed == 1u && pending_operation == NULL);
      if (mode >= DNS_STREAM_FAILED) REQUIRE(left_closes == 1u);
      pair_left = -1;
      if (guard >= 0) { REQUIRE(__real_close(guard) == 0); guard = -1; }
      incoming = NULL;
    }
  }
#if defined(FTUN_TEST_TUN_RECOVERY)
done:
#endif
  (void)pthread_mutex_lock(&mutex);
  command->done = true;
  (void)pthread_cond_signal(&condition);
  (void)pthread_mutex_unlock(&mutex);
}

static bool submit(ftun_core_t *core, int current_mode, int step)
{
  command_t command = {current_mode, step, false, false};
  ftun_operation_t *operation = NULL;
  struct timespec until;
  REQUIRE(clock_gettime(CLOCK_REALTIME, &until) == 0);
  until.tv_sec += 5;
  REQUIRE(ftun_core_post(core, owner_command, &command, &operation) == FTUN_OK);
  (void)pthread_mutex_lock(&mutex);
  while (!command.done) REQUIRE(pthread_cond_timedwait(&condition, &mutex, &until) == 0);
  (void)pthread_mutex_unlock(&mutex);
  return command.result;
}

static void wait_step(ftun_core_t *core, int current_mode, int step)
{
  uint64_t start = 0u, now = 0u;
  const struct timespec pause = {0, 1000000};
  REQUIRE(ftun_monotonic_now(&start) == FTUN_OK);
  while (!submit(core, current_mode, step)) {
    REQUIRE(ftun_monotonic_now(&now) == FTUN_OK && now - start < 5000u);
    (void)nanosleep(&pause, NULL);
  }
}

int ftun_test_tun_admission(ftun_core_t *core)
{
  int current_mode;
  for (current_mode = ADMISSION_FAILED; current_mode <= DNS_RELAY_FAILED; current_mode++) {
    REQUIRE(submit(core, current_mode, START));
    if (current_mode == SESSION_PENDING || current_mode == DNS_RELAY_FAILED) {
      wait_step(core, current_mode, HELD);
#if defined(FTUN_TEST_TUN_RECOVERY)
      if (current_mode == SESSION_PENDING) {
        REQUIRE(submit(core, current_mode, FAILED_REBUILD));
        REQUIRE(submit(core, current_mode, GATED));
        REQUIRE(submit(core, current_mode, REBUILD));
        REQUIRE(submit(core, current_mode, PATH_CHANGE));
        REQUIRE(submit(core, current_mode, NETWORK_CHANGE));
        REQUIRE(submit(core, current_mode, GATED));
      }
#endif
      REQUIRE(submit(core, current_mode, RELEASE));
    }
    wait_step(core, current_mode, DRAINED);
  }
  puts("TUN admission: quota rejection, downstream failure, retained Session/Stream, unique FD close and accounting passed");
  return 0;
}

#if defined(FTUN_TEST_TUN_RECOVERY)
int ftun_test_tun_quiesce(ftun_core_t *core)
{
  wait_step(core, 0, COMMITTED);
  REQUIRE(submit(core, 0, QUIESCE));
  puts("TUN failure/rebuild/network/path/quiesce gate and retained Session drain passed");
  return 0;
}
#endif
