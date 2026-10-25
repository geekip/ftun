/* 在真实内部接纳路径上检查窄内存预算与临时副本寿命。 */
#include "proxy/runtime.c"
#include "config/parser.h"
#include "event/libev_adapter.h"
#include "proxy/inbound/socks5.h"
#include <time.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "proxy owned memory failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

static size_t fail_malloc_bytes, fail_calloc_bytes;
static ftun_budget_t *http_job_budget;
static size_t http_job_calls;
static bool http_job_failed;
static bool health_reject_submit;
static size_t health_submit_calls;
ftun_status_t __real_ftun_worker_submit(ftun_worker_t *worker,
  const ftun_worker_job_t *job, ftun_worker_completion_fn callback,
  void *user, ftun_operation_t **out);
ftun_status_t __wrap_ftun_worker_submit(ftun_worker_t *worker,
  const ftun_worker_job_t *job, ftun_worker_completion_fn callback,
  void *user, ftun_operation_t **out)
{
  ftun_budget_usage_t usage;
  const ftun_proxy_runtime_http_work_t *header;
  if (health_reject_submit) {
    health_submit_calls++;
    *out = NULL;
    return FTUN_E_LIMIT;
  }
  if (http_job_budget == NULL) {
    return __real_ftun_worker_submit(worker, job, callback, user, out);
  }
  http_job_calls++;
  header = (const ftun_proxy_runtime_http_work_t *)job->input.data;
  if (job->input.length < sizeof(*header) ||
      header->magic != FTUN_PROXY_RUNTIME_HTTP_WORK_MAGIC ||
      header->budget != (uintptr_t)http_job_budget || job->accounted_extra != 0u ||
      job->input_cleanup == NULL || job->result_cleanup == NULL ||
      ftun_budget_get_usage(http_job_budget, &usage) != FTUN_OK ||
      usage.used != job->input.length) http_job_failed = true;
  *out = NULL;
  return FTUN_E_LIMIT;
}
void *__real_malloc(size_t size);
void *__real_calloc(size_t count, size_t size);
void *__wrap_malloc(size_t size)
{
  if (fail_malloc_bytes != 0u && size == fail_malloc_bytes) {
    fail_malloc_bytes = 0u;
    return NULL;
  }
  return __real_malloc(size);
}
void *__wrap_calloc(size_t count, size_t size)
{
  if (fail_calloc_bytes != 0u && size != 0u && count == fail_calloc_bytes / size &&
      count * size == fail_calloc_bytes) {
    fail_calloc_bytes = 0u;
    return NULL;
  }
  return __real_calloc(count, size);
}

static int memory(ftun_budget_t *budget, size_t expected)
{
  ftun_budget_usage_t usage;
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == expected);
  return 0;
}

static void http_unused(ftun_operation_t *operation, ftun_error_t error,
  ftun_bytes_t result, void *user)
{
  (void)operation; (void)error; (void)result; (void)user;
  abort();
}

static int http_input(void)
{
  const char url[] = "http://127.0.0.1/probe";
  ftun_proxy_runtime_t engine = {0};
  ftun_http_fetch_spec_t spec = {0};
  ftun_operation_t *operation = NULL;
  ftun_reservation_t *hold = NULL;
  ftun_budget_usage_t usage;
  CHECK(ftun_budget_create(NULL, 512u * 1024u, 0u, &engine.budget) == FTUN_OK);
  spec.budget = engine.budget;
  spec.url = (ftun_string_t){url, sizeof(url) - 1u};
  spec.maximum_bytes = 4096u;
  spec.deadline_ms = UINT64_MAX;
  http_job_budget = engine.budget;
  http_job_calls = 0u;
  http_job_failed = false;
  CHECK(ftun_proxy_runtime_http_submit(&engine, &spec, false, NULL,
    http_unused, NULL, &operation) == FTUN_E_LIMIT);
  CHECK(operation == NULL && http_job_calls == 1u && !http_job_failed &&
    memory(engine.budget, 0u) == 0);
  fail_calloc_bytes = sizeof(ftun_proxy_runtime_http_work_t) + spec.url.length;
  CHECK(ftun_proxy_runtime_http_submit(&engine, &spec, false, NULL,
    http_unused, NULL, &operation) == FTUN_E_LIMIT);
  CHECK(fail_calloc_bytes == 0u && http_job_calls == 1u && memory(engine.budget, 0u) == 0);
  CHECK(ftun_budget_get_usage(engine.budget, &usage) == FTUN_OK);
  CHECK(ftun_budget_reserve(engine.budget, usage.normal_available, &hold) == FTUN_OK);
  CHECK(ftun_proxy_runtime_http_submit(&engine, &spec, false, NULL,
    http_unused, NULL, &operation) == FTUN_E_LIMIT);
  CHECK(http_job_calls == 1u && ftun_reservation_release(&hold) == FTUN_OK);
  http_job_budget = NULL;
  CHECK(ftun_budget_destroy(&engine.budget) == FTUN_OK);
  return 0;
}

static int users(void)
{
  ftun_budget_t *budget = NULL;
  ftun_reservation_t *hold = NULL, *reservation = NULL;
  ftun_proxy_runtime_flow_t flow = {0};
  ftun_proxy_runtime_t engine = {0};
  ftun_proxy_runtime_listener_t listener = {0};
  ftun_config_inbound_t config = {0};
  ftun_config_user_t credentials[2] = {{"alice", "one"}, {"bob", "two"}};
  ftun_inbound_user_t *copy = NULL;
  ftun_inbound_spec_t spec;
  ftun_socks5_server_t *server = NULL;
  ftun_budget_usage_t usage;
  CHECK(ftun_budget_create(NULL, 65536u, 0u, &budget) == FTUN_OK);
  flow.engine = &engine;
  flow.listener = &listener;
  flow.budget = budget;
  engine.generation = 1u;
  listener.inbound_id = 1u;
  config.kind = FTUN_CONFIG_INBOUND_SOCKS5;
  config.name = "auth";
  config.users = credentials;
  config.user_count = 2u;
  CHECK(ftun_budget_reserve(budget, 65536u, &hold) == FTUN_OK);
  CHECK(ftun_proxy_runtime_build_inbound_spec(&flow, &config, &spec, &copy,
    &reservation) == FTUN_E_LIMIT && copy == NULL && reservation == NULL);
  CHECK(ftun_reservation_release(&hold) == FTUN_OK);
  fail_calloc_bytes = 2u * sizeof(*copy);
  CHECK(ftun_proxy_runtime_build_inbound_spec(&flow, &config, &spec, &copy,
    &reservation) == FTUN_E_LIMIT && copy == NULL && reservation == NULL);
  CHECK(fail_calloc_bytes == 0u && memory(budget, 0u) == 0);
  CHECK(ftun_proxy_runtime_build_inbound_spec(&flow, &config, &spec, &copy,
    &reservation) == FTUN_OK);
  CHECK(memory(budget, 2u * sizeof(*copy)) == 0);
  CHECK(ftun_socks5_server_create(&spec, &server) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used > 2u * sizeof(*copy));
  free(copy);
  CHECK(ftun_reservation_release(&reservation) == FTUN_OK);
  CHECK(memory(budget, usage.used - 2u * sizeof(*copy)) == 0);
  CHECK(ftun_socks5_server_destroy(&server) == FTUN_OK && memory(budget, 0u) == 0);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int health_scratch(void)
{
  const char text[] = "{\"base\":{\"state-cache\":false},\"dns\":{\"enable\":false},"
    "\"outbounds\":[{\"name\":\"A\",\"type\":\"socks5\",\"server\":\"127.0.0.1:9\"},"
    "{\"name\":\"G\",\"type\":\"url-test\",\"outbounds\":[\"A\"],\"default\":\"A\","
    "\"url\":\"http://127.0.0.1:9/\"}],\"rules\":[\"MATCH,G\"]}";
  ftun_proxy_runtime_t engine = {0};
  ftun_config_t *config = NULL;
  ftun_runtime_t *candidate = NULL;
  ftun_reservation_t *hold = NULL;
  ftun_budget_usage_t usage;
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &engine.budget) == FTUN_OK);
  CHECK(ftun_core_context_create(engine.budget, &engine.core) == FTUN_OK);
  CHECK(ftun_runtime_manager_attach(engine.core, 2u, 1024u * 1024u) == FTUN_OK);
  CHECK(ftun_config_parse((ftun_bytes_t){(const uint8_t *)text, strlen(text)}, &config) == FTUN_OK);
  CHECK(ftun_config_compile(config, &config->plan) == FTUN_OK);
  CHECK(ftun_runtime_prepare(engine.core, config, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_commit(engine.core, &candidate) == FTUN_OK);
  engine.generation = 1u;
  CHECK(ftun_proxy_runtime_health_prepare(&engine, config, 1u,
    &engine.health_groups, &engine.health_group_count, &engine.health_slots,
    &engine.health_slot_count, &engine.health_reservation) == FTUN_OK);
  CHECK(engine.health_slot_count == 1u && engine.health_group_count == 1u);
  CHECK(ftun_budget_get_usage(engine.budget, &usage) == FTUN_OK);
  CHECK(ftun_budget_reserve(engine.budget, usage.normal_available, &hold) == FTUN_OK);
  CHECK(ftun_proxy_runtime_health_publish(engine.health_slots, 100u) == FTUN_E_LIMIT);
  CHECK(ftun_reservation_release(&hold) == FTUN_OK && memory(engine.budget, usage.used) == 0);
  fail_calloc_bytes = sizeof(uint32_t);
  CHECK(ftun_proxy_runtime_health_publish(engine.health_slots, 100u) == FTUN_E_LIMIT);
  CHECK(fail_calloc_bytes == 0u && memory(engine.budget, usage.used) == 0);
  fail_calloc_bytes = sizeof(ftun_health_sample_t);
  CHECK(ftun_proxy_runtime_health_publish(engine.health_slots, 100u) == FTUN_E_LIMIT);
  CHECK(fail_calloc_bytes == 0u && memory(engine.budget, usage.used) == 0);
  CHECK(ftun_proxy_runtime_health_publish(engine.health_slots, 100u) == FTUN_OK);
  CHECK(memory(engine.budget, usage.used) == 0);
  {
    ftun_proxy_runtime_health_slot_t *slot = engine.health_slots;
    ftun_proxy_runtime_health_group_t *group = engine.health_groups;
    uint64_t deadline;
    bool present;
    size_t work;
    ftun_error_t error = {0};
    group->consumed = false;
    slot->schedule.consumers = 0u;
    CHECK(ftun_proxy_runtime_next_deadline(&engine, &deadline, &present) == FTUN_OK && !present);
    CHECK(ftun_proxy_runtime_health_run(&engine, 8u, &work) == FTUN_OK && work == 0u);
    CHECK(engine.health_scan_work == 1u);
    ftun_proxy_runtime_health_consume(&engine, group->group_id);
    CHECK(ftun_proxy_runtime_next_deadline(&engine, &deadline, &present) == FTUN_OK &&
      present && deadline == slot->schedule.next_due_ms);
    engine.now_ms = deadline - 1u;
    work = engine.health_scan_work;
    CHECK(ftun_proxy_runtime_health_run(&engine, 8u, &health_submit_calls) == FTUN_OK &&
      health_submit_calls == 0u && engine.health_scan_work == work);
    engine.now_ms = deadline;
    health_reject_submit = true;
    CHECK(ftun_proxy_runtime_health_run(&engine, 8u, &work) == FTUN_OK &&
      work == 1u && health_submit_calls == 1u && slot->operation == NULL);
    health_reject_submit = false;
    CHECK(ftun_proxy_runtime_next_deadline(&engine, &deadline, &present) == FTUN_OK &&
      present && deadline > engine.now_ms && deadline == slot->schedule.next_due_ms);
    /* 完成入口仅用身份匹配该指针；本夹具不解引用伪操作。 */
    slot->operation = (ftun_operation_t *)&engine;
    engine.health_deadline_valid = false;
    CHECK(ftun_proxy_runtime_next_deadline(&engine, &deadline, &present) == FTUN_OK && !present);
    error.status = FTUN_E_TIMEOUT;
    ftun_proxy_runtime_health_completed(slot->operation, error,
      (ftun_bytes_t){NULL, 0u}, slot);
    CHECK(slot->operation == NULL);
    CHECK(ftun_proxy_runtime_next_deadline(&engine, &deadline, &present) == FTUN_OK &&
      present && deadline == slot->schedule.next_due_ms);
    engine.generation++;
    slot->schedule.next_due_ms = 1u;
    CHECK(ftun_proxy_runtime_next_deadline(&engine, &deadline, &present) == FTUN_OK &&
      present && deadline == 1u);
    CHECK(memory(engine.budget, usage.used) == 0);
  }
  CHECK(ftun_proxy_runtime_health_release(&engine.health_groups, &engine.health_slots,
    engine.health_slot_count, &engine.health_reservation) == FTUN_OK);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&engine.core) == FTUN_OK);
  CHECK(memory(engine.budget, 0u) == 0 && ftun_budget_destroy(&engine.budget) == FTUN_OK);
  return 0;
}

static int health_deadline_scaling(void)
{
  const size_t counts[] = {0u, 16u, 256u, 1000u, 4096u};
  size_t index;
  for (index = 0u; index < sizeof(counts) / sizeof(counts[0]); index++) {
    ftun_proxy_runtime_t engine = {0};
    ftun_proxy_runtime_health_group_t group = {0};
    uint64_t deadline;
    bool present;
    size_t repeat, work;
    engine.health_slot_count = counts[index];
    engine.health_group_count = 1u;
    engine.health_groups = &group;
    if (counts[index] != 0u) {
      engine.health_slots = calloc(counts[index], sizeof(*engine.health_slots));
      CHECK(engine.health_slots != NULL);
    }
    CHECK(ftun_proxy_runtime_next_deadline(&engine, &deadline, &present) == FTUN_OK && !present);
    CHECK(engine.health_scan_work == counts[index]);
    for (repeat = 0u; repeat < 100u; repeat++) {
      CHECK(ftun_proxy_runtime_next_deadline(&engine, &deadline, &present) == FTUN_OK && !present);
      CHECK(ftun_proxy_runtime_health_run(&engine, 8u, &work) == FTUN_OK && work == 0u);
    }
    CHECK(engine.health_scan_work == counts[index]);
    printf("Health dormant deadlines: slots=%zu, first_visits=%zu, repeat_visits=0\n",
      counts[index], engine.health_scan_work);
    if (counts[index] >= 2u) {
      group.slot_count = counts[index];
      group.group_id = 1u;
      ftun_proxy_runtime_health_consume(&engine, 1u);
      for (repeat = 0u; repeat < counts[index]; repeat++) {
        engine.health_slots[repeat].schedule.next_due_ms = 1000u;
      }
      engine.health_slots[0].schedule.next_due_ms = 10u;
      engine.health_slots[0].operation = (ftun_operation_t *)&engine;
      engine.health_slots[counts[index] - 1u].schedule.next_due_ms = 20u;
      CHECK(ftun_proxy_runtime_next_deadline(&engine, &deadline, &present) == FTUN_OK &&
        present && deadline == 20u);
    }
    free(engine.health_slots);
  }
  return 0;
}

static int flow_admission(void)
{
  const char text[] = "{\"base\":{\"state-cache\":false},\"dns\":{\"enable\":false},"
    "\"inbounds\":[{\"name\":\"auth\",\"type\":\"socks5\",\"listen\":\"127.0.0.1:1080\","
    "\"users\":{\"alice\":\"one\"}}],\"rules\":[\"MATCH,DIRECT\"]}";
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_config_t *config = NULL;
  ftun_runtime_t *candidate = NULL;
  ftun_proxy_runtime_t engine = {0};
  ftun_proxy_runtime_listener_t listener = {0};
  ftun_proxy_runtime_flow_t *flow = NULL;
  ftun_reservation_t *hold = NULL;
  ftun_budget_usage_t baseline, usage;
  int pair[2];
  size_t iteration;
  CHECK(ftun_budget_create(NULL, 2u * 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_runtime_manager_attach(core, 2u, 1024u * 1024u) == FTUN_OK);
  CHECK(ftun_config_parse((ftun_bytes_t){(const uint8_t *)text, strlen(text)}, &config) == FTUN_OK);
  CHECK(ftun_config_compile(config, &config->plan) == FTUN_OK);
  CHECK(ftun_runtime_prepare(core, config, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK);
  engine.core = core;
  engine.budget = budget;
  engine.generation = 1u;
  engine.flow_capacity = engine.tcp_capacity = 2u;
  listener.engine = &engine;
  listener.name = "auth";
  listener.inbound_id = 1u;
  listener.kind = FTUN_CONFIG_INBOUND_SOCKS5;
  CHECK(ftun_operation_queue_create(budget, 16u, &engine.operations) == FTUN_OK);
  CHECK(ftun_event_loop_create_with_capacity(core, 16u, &engine.loop) == FTUN_OK);
  CHECK(ftun_libev_attach(engine.loop) == FTUN_OK);
  CHECK(ftun_proxy_slot_pool_create(budget, sizeof(*flow), 2u, 2u, 1u, &engine.flow_pool) == FTUN_OK);
  /* slab先分配且保留，之后的限制只作用于新增Flow的实际子对象。 */
  CHECK(ftun_proxy_runtime_flow_slot_acquire(&engine, &flow) == FTUN_OK);
  flow->engine = &engine;
  CHECK(ftun_proxy_runtime_flow_slot_release(&flow) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &baseline) == FTUN_OK);
  for (iteration = 0u; iteration < 3u; iteration++) {
    size_t available = iteration == 0u ? 1u : 12u * 1024u;
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
    CHECK(ftun_budget_reserve(budget, baseline.normal_available - available, &hold) == FTUN_OK);
    if (iteration == 0u) {
      CHECK(ftun_proxy_runtime_flow_create(&engine, &listener, pair[0], NULL) == FTUN_E_LIMIT);
      CHECK(fcntl(pair[0], F_GETFD) < 0 && errno == EBADF);
    } else {
      CHECK(ftun_proxy_runtime_flow_create(&engine, &listener, pair[0], NULL) == FTUN_OK);
      flow = ftun_proxy_runtime_flow_at(&engine, 0u);
      if (flow == NULL) flow = ftun_proxy_runtime_flow_at(&engine, 1u);
      CHECK(flow != NULL && flow->active && flow->protocol != NULL);
      CHECK(ftun_budget_get_usage(flow->budget, &usage) == FTUN_OK &&
        usage.used_resources.queue_slots == 1u);
      CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used <= baseline.used +
        baseline.normal_available);
      CHECK(ftun_proxy_runtime_flow_finalize(flow) == FTUN_OK);
      CHECK(fcntl(pair[0], F_GETFD) < 0 && errno == EBADF);
    }
    CHECK(close(pair[1]) == 0);
    CHECK(ftun_reservation_release(&hold) == FTUN_OK && memory(budget, baseline.used) == 0);
    CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK &&
      usage.child_count == baseline.child_count &&
      usage.used_resources.descriptors == baseline.used_resources.descriptors &&
      usage.used_resources.queue_slots == baseline.used_resources.queue_slots);
  }
  CHECK(ftun_proxy_slot_pool_destroy(&engine.flow_pool) == FTUN_OK);
  CHECK(ftun_event_loop_stop(engine.loop) == FTUN_OK);
  CHECK(ftun_libev_detach(engine.loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&engine.loop) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&engine.operations) == FTUN_OK);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(memory(budget, 0u) == 0 && ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

#if defined(FTUN_HAVE_MODULE_FRS)
static size_t publish_callbacks;
static ftun_proxy_runtime_frs_publish_result_t publish_result;

static void publish_completed(ftun_operation_t *operation, ftun_error_t error,
  ftun_bytes_t result, void *user)
{
  (void)operation; (void)user;
  if (error.status != FTUN_OK || result.length != sizeof(publish_result)) abort();
  memcpy(&publish_result, result.data, sizeof(publish_result));
  publish_callbacks++;
}

static int publish_budget(void)
{
  char path[] = "/tmp/ftun-proxy-publish-XXXXXX", contents[3];
  const uint8_t body[] = "new";
  ftun_budget_options_t options = {{512u * 1024u, 2u, 32u}, {0}, {0}};
  ftun_budget_resources_t descriptor = {0u, 1u, 0u};
  ftun_proxy_runtime_t engine = {0};
  ftun_reservation_t *hold = NULL;
  ftun_budget_usage_t before, after;
  ftun_operation_t *operation = NULL;
  size_t round;
  int file = mkstemp(path);
  CHECK(file >= 0 && write(file, "old", 3u) == 3 && close(file) == 0);
  CHECK(ftun_budget_create_resources(NULL, &options, &engine.budget) == FTUN_OK);
  CHECK(ftun_worker_create(engine.budget, 1u, &engine.maintenance_worker) == FTUN_OK);
  CHECK(ftun_budget_get_usage(engine.budget, &before) == FTUN_OK);
  for (round = 0u; round < 2u; round++) {
    uint64_t now, deadline;
    if (round == 0u) CHECK(ftun_budget_reserve_resources(engine.budget, descriptor, &hold) == FTUN_OK);
    publish_callbacks = 0u;
    CHECK(ftun_proxy_runtime_frs_publish_submit(&engine, path,
      (ftun_bytes_t){body, sizeof(body) - 1u}, publish_completed, &operation) == FTUN_OK);
    CHECK(operation != NULL && ftun_monotonic_now(&now) == FTUN_OK);
    deadline = now + 2000u;
    while (publish_callbacks == 0u) {
      size_t callbacks;
      struct timespec pause = {0, 1000000};
      CHECK(ftun_worker_poll(engine.maintenance_worker, 1u, &callbacks) == FTUN_OK);
      CHECK(ftun_monotonic_now(&now) == FTUN_OK && now < deadline);
      if (publish_callbacks == 0u) (void)nanosleep(&pause, NULL);
    }
    CHECK(publish_callbacks == 1u && publish_result.status ==
      (round == 0u ? FTUN_E_LIMIT : FTUN_OK));
    CHECK(publish_result.reached == (round == 0u ? 0u : FTUN_FILE_STAGE_DIRECTORY_SYNCED));
    CHECK(ftun_reservation_release(&hold) == FTUN_OK);
    CHECK(ftun_budget_get_usage(engine.budget, &after) == FTUN_OK &&
      after.used == before.used && after.metadata_bytes == before.metadata_bytes &&
      after.used_resources.descriptors == before.used_resources.descriptors &&
      after.used_resources.queue_slots == before.used_resources.queue_slots);
    file = open(path, O_RDONLY);
    CHECK(file >= 0 && read(file, contents, sizeof(contents)) == (ssize_t)sizeof(contents) && close(file) == 0);
    CHECK(memcmp(contents, round == 0u ? "old" : "new", sizeof(contents)) == 0);
  }
  CHECK(ftun_worker_stop(engine.maintenance_worker) == FTUN_OK);
  CHECK(ftun_worker_join(engine.maintenance_worker) == FTUN_OK);
  CHECK(ftun_worker_destroy(&engine.maintenance_worker) == FTUN_OK);
  CHECK(ftun_budget_destroy(&engine.budget) == FTUN_OK && unlink(path) == 0);
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

static int publish_ownership(void)
{
  const char text[] = "{\"base\":{\"state-cache\":false},\"dns\":{\"enable\":false},\"rules\":[\"MATCH,DIRECT\"]}";
  ftun_proxy_runtime_t engine = {0};
  ftun_config_t *config = NULL;
  ftun_runtime_t *candidate = NULL;
  ftun_resolver_provider_spec_t resolver = {0};
  ftun_path_provider_spec_t path = {0};
  ftun_proxy_runtime_frs_publish_result_t published = {0};
  ftun_budget_usage_t baseline;
  size_t round;
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &engine.budget) == FTUN_OK);
  CHECK(ftun_core_context_create(engine.budget, &engine.core) == FTUN_OK);
  CHECK(ftun_runtime_manager_attach(engine.core, 2u, 1024u * 1024u) == FTUN_OK);
  CHECK(ftun_config_parse((ftun_bytes_t){(const uint8_t *)text, strlen(text)}, &config) == FTUN_OK);
  CHECK(ftun_config_compile(config, &config->plan) == FTUN_OK);
  CHECK(ftun_runtime_prepare(engine.core, config, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_commit(engine.core, &candidate) == FTUN_OK);
  engine.generation = 1u;
  resolver.budget = engine.budget;
  resolver.generation = 1u;
  resolver.ops.start = resolve_unused;
  CHECK(ftun_resolver_provider_create(&resolver, &engine.resolver_provider) == FTUN_OK);
  path.budget = engine.budget;
  path.generation = 1u;
  path.ops.start = dial_unused;
  path.max_pending = path.max_paths = 1u;
  CHECK(ftun_path_provider_create(&path, &engine.path_provider) == FTUN_OK);
  CHECK(ftun_budget_get_usage(engine.budget, &baseline) == FTUN_OK);
  CHECK(ftun_proxy_runtime_replace_etag(&engine, (const uint8_t *)"old", 3u) == FTUN_OK);
  for (round = 0u; round < 2u; round++) {
    CHECK(ftun_runtime_prepare(engine.core, config, &engine.frs_candidate) == FTUN_OK);
    CHECK(ftun_proxy_runtime_reload_prepare(&engine, config, 2u) == FTUN_OK);
    engine.frs_enabled = true;
    engine.frs_operation_generation = 1u;
    CHECK(ftun_proxy_runtime_copy_etag(engine.budget, (const uint8_t *)"candidate", 9u,
      &engine.frs_candidate_etag, &engine.frs_candidate_etag_reservation) == FTUN_OK);
    CHECK(ftun_budget_reserve(engine.budget, sizeof(*engine.frs_group_records),
      &engine.frs_group_records_reservation) == FTUN_OK);
    engine.frs_group_records = calloc(1u, sizeof(*engine.frs_group_records));
    CHECK(engine.frs_group_records != NULL);
    engine.frs_group_record_capacity = 1u;
    /* 直接驱动生产完成函数，真实Snapshot和Provider执行失败回滚/成功提交。 */
    published.status = FTUN_OK;
    published.reached = FTUN_FILE_STAGE_RENAMED;
    ftun_proxy_runtime_frs_publish_completed(NULL,
      (ftun_error_t){round == 0u ? FTUN_E_IO : FTUN_OK, 0u, 0},
      (ftun_bytes_t){(const uint8_t *)&published, sizeof(published)}, &engine);
    CHECK(engine.frs_candidate == NULL && engine.frs_candidate_etag == NULL &&
      engine.frs_candidate_etag_reservation == NULL && engine.frs_group_records == NULL &&
      engine.frs_group_records_reservation == NULL && !engine.reload_pending);
    CHECK(engine.generation == (round == 0u ? 1u : 2u));
    CHECK(strcmp(engine.frs_etag, round == 0u ? "old" : "candidate") == 0);
    CHECK(memory(engine.budget, baseline.used + (round == 0u ? 4u : 10u)) == 0);
  }
  CHECK(ftun_proxy_runtime_replace_etag(&engine, NULL, 0u) == FTUN_OK);
  CHECK(ftun_resolver_provider_stop_until(engine.resolver_provider, UINT64_MAX) == FTUN_OK);
  CHECK(ftun_path_provider_stop_until(engine.path_provider, UINT64_MAX) == FTUN_OK);
  CHECK(ftun_resolver_provider_destroy(&engine.resolver_provider) == FTUN_OK);
  CHECK(ftun_path_provider_destroy(&engine.path_provider) == FTUN_OK);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&engine.core) == FTUN_OK);
  CHECK(memory(engine.budget, 0u) == 0 && ftun_budget_destroy(&engine.budget) == FTUN_OK);
  return 0;
}

static int etags(void)
{
  ftun_proxy_runtime_t engine = {0};
  ftun_reservation_t *hold = NULL;
  ftun_budget_usage_t usage;
  const uint8_t old[] = "old", next[] = "new-etag";
  CHECK(ftun_budget_create(NULL, 1024u, 0u, &engine.budget) == FTUN_OK);
  CHECK(ftun_proxy_runtime_replace_etag(&engine, old, sizeof(old) - 1u) == FTUN_OK);
  CHECK(memory(engine.budget, sizeof(old)) == 0);
  CHECK(ftun_budget_get_usage(engine.budget, &usage) == FTUN_OK);
  CHECK(ftun_budget_reserve(engine.budget, usage.normal_available, &hold) == FTUN_OK);
  CHECK(ftun_proxy_runtime_replace_etag(&engine, next, sizeof(next) - 1u) == FTUN_E_LIMIT);
  CHECK(strcmp(engine.frs_etag, "old") == 0);
  CHECK(ftun_reservation_release(&hold) == FTUN_OK);
  fail_malloc_bytes = sizeof(next);
  CHECK(ftun_proxy_runtime_replace_etag(&engine, next, sizeof(next) - 1u) == FTUN_E_LIMIT);
  CHECK(fail_malloc_bytes == 0u && strcmp(engine.frs_etag, "old") == 0 && memory(engine.budget, sizeof(old)) == 0);
  CHECK(ftun_proxy_runtime_copy_etag(engine.budget, next, sizeof(next) - 1u,
    &engine.frs_candidate_etag, &engine.frs_candidate_etag_reservation) == FTUN_OK);
  CHECK(memory(engine.budget, sizeof(old) + sizeof(next)) == 0);
  free(engine.frs_candidate_etag);
  engine.frs_candidate_etag = NULL;
  CHECK(ftun_reservation_release(&engine.frs_candidate_etag_reservation) == FTUN_OK);
  CHECK(ftun_proxy_runtime_replace_etag(&engine, next, sizeof(next) - 1u) == FTUN_OK);
  CHECK(strcmp(engine.frs_etag, "new-etag") == 0 && memory(engine.budget, sizeof(next)) == 0);
  CHECK(ftun_proxy_runtime_replace_etag(&engine, NULL, 0u) == FTUN_OK && engine.frs_etag == NULL);
  CHECK(memory(engine.budget, 0u) == 0 && ftun_budget_destroy(&engine.budget) == FTUN_OK);
  return 0;
}
#endif

#if defined(FTUN_HAVE_MODULE_FAKEIP)
static int fakeip_path(void)
{
  ftun_budget_t *budget = NULL;
  ftun_proxy_runtime_t *engine = calloc(1u, sizeof(*engine));
  ftun_config_t config = {0};
  ftun_feature_plan_t plan = {0};
  ftun_reservation_t *hold = NULL;
  const size_t bytes = sizeof("cache.fakeip");
  CHECK(engine != NULL);
  CHECK(ftun_budget_create(NULL, 1024u, 0u, &budget) == FTUN_OK);
  engine->budget = budget;
  config.plan = &plan;
  plan.prepare = FTUN_PLAN_FAKE_IP;
  config.dns.fake_ip.range = "198.18.0.0/24";
  config.dns.fake_ip.persist = true;
  config.base.cache_file = "cache";
  CHECK(ftun_budget_reserve(budget, 1024u, &hold) == FTUN_OK);
  CHECK(ftun_proxy_runtime_fakeip_prepare(engine, &config) == FTUN_E_LIMIT);
  CHECK(engine->fakeip_directory == NULL && engine->fakeip_directory_reservation == NULL);
  CHECK(ftun_reservation_release(&hold) == FTUN_OK);
  fail_malloc_bytes = bytes;
  CHECK(ftun_proxy_runtime_fakeip_prepare(engine, &config) == FTUN_E_LIMIT);
  CHECK(fail_malloc_bytes == 0u && memory(budget, 0u) == 0);
  /* 缺少Worker使后续store拒绝，已拥有的名字必须保留至Engine销毁。 */
  CHECK(ftun_proxy_runtime_fakeip_prepare(engine, &config) == FTUN_E_INVALID);
  CHECK(engine->fakeip_directory != NULL && strcmp(engine->fakeip_directory, "cache.fakeip") == 0);
  CHECK(memory(budget, bytes) == 0);
  engine->stopped = true;
  CHECK(ftun_proxy_runtime_destroy(&engine) == FTUN_OK && engine == NULL);
  CHECK(memory(budget, 0u) == 0 && ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}
#endif

static void pending_backend_destroy(void *user)
{
  ftun_proxy_runtime_udp_slot_t *slot = user;
  slot->active = false;
}

static int pending_tokens(void)
{
  ftun_proxy_runtime_udp_slot_t slot = {0};
  ftun_budget_options_t limits = {{65536u, 0u, 32u}, {0}, {0}};
  ftun_budget_t *budget = NULL;
  ftun_budget_usage_t baseline, usage;
  ftun_buffer_pool_t *pool = NULL;
  ftun_buffer_t *buffer = NULL;
  ftun_buffer_slice_t slice = {0};
  ftun_packet_t packet = {0};
  ftun_datagram_options_t options = {0};
  ftun_datagram_backend_t backend = {0};
  size_t index;
  CHECK(ftun_budget_create_resources(NULL, &limits, &budget) == FTUN_OK);
  CHECK(ftun_buffer_pool_create(budget, 0u, 0u, &pool) == FTUN_OK);
  CHECK(ftun_buffer_pool_acquire(pool, 1u, &buffer) == FTUN_OK);
  CHECK(ftun_buffer_slice(buffer, 0u, 1u, &slice) == FTUN_OK);
  CHECK(ftun_packet_init(&packet, &slice, 1u) == FTUN_OK);
  CHECK(ftun_buffer_slice_release(&slice) == FTUN_OK);
  CHECK(ftun_buffer_release(&buffer) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &baseline) == FTUN_OK);
  slot.active = slot.ready = true;
  slot.remote.kind = FTUN_ADDRESS_IPV4;
  slot.remote.address[0] = 127u;
  slot.remote.address[3] = 1u;
  slot.remote.port = 1234u;
  options.budget = budget;
  options.max_pending_packets = FTUN_PROXY_RUNTIME_DATAGRAM_CAPACITY;
  options.max_pending_bytes = 32u;
  backend.send_start = ftun_proxy_runtime_udp_send_start;
  backend.send_cancel = ftun_proxy_runtime_udp_send_cancel;
  backend.destroy = pending_backend_destroy;
  backend.context = &slot;
  CHECK(ftun_datagram_create(&options, &backend, &slot.channel) == FTUN_OK);
  /* 下游尚不可发送，真实 Proxy backend 保存同一 Datagram 的 token。
   * 无 Engine/物理网络，仅验证接纳与取消队列，不声称完成网络交付。 */
  for (index = 0u; index < 32u; index++) {
    CHECK(ftun_datagram_send(slot.channel, &slot.remote, &packet) == FTUN_OK);
    CHECK(slot.pending_count == index + 1u);
    CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK &&
      usage.used_resources.queue_slots == 32u);
  }
  CHECK(ftun_datagram_send(slot.channel, &slot.remote, &packet) == FTUN_E_LIMIT);
  CHECK(ftun_datagram_stop(slot.channel) == FTUN_OK && slot.pending_count == 0u);
  CHECK(ftun_datagram_destroy(&slot.channel) == FTUN_OK && !slot.active);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK &&
    usage.used == baseline.used && usage.used_resources.queue_slots == 0u);
  CHECK(ftun_packet_release(&packet) == FTUN_OK);
  CHECK(ftun_buffer_pool_destroy(&pool) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static void pool_work_unexpected(void *user)
{
  size_t *calls = user;
  (*calls)++;
}

static int blocked_pool_work(void)
{
  ftun_proxy_runtime_t engine = {0};
  ftun_buffer_wait_token_t token = {0};
  ftun_reservation_t *hold = NULL;
  ftun_budget_usage_t budget_usage;
  ftun_buffer_pool_usage_t before, after;
  ftun_proxy_runtime_run_usage_t usage;
  size_t calls = 0u;
  ftun_proxy_runtime_health_group_t health_group = {0};
  ftun_proxy_runtime_health_slot_t health_slot = {0};
  engine.health_groups = &health_group;
  engine.health_group_count = 1u;
  engine.health_slots = &health_slot;
  engine.health_slot_count = 1u;
  CHECK(ftun_budget_create(NULL, 128u * 1024u, 0u, &engine.budget) == FTUN_OK);
  CHECK(ftun_event_loop_create_with_budget(NULL, engine.budget, 4u, &engine.loop) == FTUN_OK);
  CHECK(ftun_libev_attach(engine.loop) == FTUN_OK);
  CHECK(ftun_buffer_pool_create_waitable(engine.budget, 0u, 0u, 4u, 4u, &engine.relay_pool) == FTUN_OK);
  CHECK(ftun_proxy_slot_pool_create(engine.budget, sizeof(ftun_proxy_runtime_flow_t), 1u, 1u, 0u, &engine.flow_pool) == FTUN_OK);
  CHECK(ftun_proxy_slot_pool_create(engine.budget, sizeof(ftun_proxy_runtime_udp_slot_t), 1u, 1u, 0u, &engine.udp_pool) == FTUN_OK);
  CHECK(ftun_proxy_slot_pool_create(engine.budget, sizeof(ftun_proxy_runtime_udp_pending_t), 1u, 1u, 0u, &engine.udp_pending_pool) == FTUN_OK);
  CHECK(ftun_budget_get_usage(engine.budget, &budget_usage) == FTUN_OK);
  CHECK(ftun_budget_reserve(engine.budget, budget_usage.normal_available, &hold) == FTUN_OK);
  CHECK(ftun_buffer_pool_wait(engine.relay_pool, 65536u, pool_work_unexpected, &calls, &token) == FTUN_OK);
  CHECK(ftun_buffer_pool_get_usage(engine.relay_pool, &before) == FTUN_OK);
  CHECK(ftun_proxy_runtime_run_once(&engine, false, &usage) == FTUN_OK && calls == 0u);
  CHECK(ftun_buffer_pool_get_usage(engine.relay_pool, &after) == FTUN_OK && after.waiting == 1u);
  CHECK(after.selection_steps > before.selection_steps && after.availability_probes > before.availability_probes);
  CHECK(usage.work >= after.selection_steps - before.selection_steps + after.availability_probes - before.availability_probes);
  CHECK(engine.health_scan_work == 1u &&
    usage.work >= 1u + after.selection_steps - before.selection_steps + after.availability_probes - before.availability_probes);
  CHECK(ftun_buffer_pool_wait_cancel(&token) == FTUN_OK);
  CHECK(ftun_reservation_release(&hold) == FTUN_OK);
  CHECK(ftun_proxy_slot_pool_destroy(&engine.flow_pool) == FTUN_OK);
  CHECK(ftun_proxy_slot_pool_destroy(&engine.udp_pool) == FTUN_OK);
  CHECK(ftun_proxy_slot_pool_destroy(&engine.udp_pending_pool) == FTUN_OK);
  CHECK(ftun_buffer_pool_destroy(&engine.relay_pool) == FTUN_OK);
  CHECK(ftun_event_loop_stop(engine.loop) == FTUN_OK);
  CHECK(ftun_libev_detach(engine.loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&engine.loop) == FTUN_OK);
  CHECK(memory(engine.budget, 0u) == 0 && ftun_budget_destroy(&engine.budget) == FTUN_OK);
  return 0;
}

int main(void)
{
  CHECK(health_deadline_scaling() == 0);
  CHECK(blocked_pool_work() == 0);
  CHECK(pending_tokens() == 0);
  CHECK(users() == 0);
  CHECK(http_input() == 0);
  CHECK(health_scratch() == 0);
  CHECK(flow_admission() == 0);
#if defined(FTUN_HAVE_MODULE_FRS)
  CHECK(etags() == 0);
  CHECK(publish_budget() == 0);
  CHECK(publish_ownership() == 0);
#endif
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  CHECK(fakeip_path() == 0);
#endif
  puts("Proxy owned memory: constrained Flow admission, temporary credentials, failure recovery and ETag coexistence passed");
  return 0;
}
