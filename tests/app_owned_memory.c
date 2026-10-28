/* 直接检查真实宿主内部拥有链的准入、转移和失败保留。 */
#include "app/runtime.c"
#include <stdio.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "app owned memory failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

static size_t fail_malloc_size, fail_calloc_size;
static size_t watch_calloc_size, watched_used, submit_used;
static ftun_budget_t *watch_budget;
static bool hold_plan, accept_commit, reject_submit, watch_failed;

void *__real_malloc(size_t size);
void *__real_calloc(size_t count, size_t size);
void *__wrap_malloc(size_t size)
{
  if (size == fail_malloc_size && size != 0u) {
    fail_malloc_size = 0u;
    return NULL;
  }
  return __real_malloc(size);
}
void *__wrap_calloc(size_t count, size_t size)
{
  if (size != 0u && count <= SIZE_MAX / size) {
    size_t bytes = count * size;
    if (bytes == watch_calloc_size && bytes != 0u) {
      ftun_budget_usage_t usage;
      watch_failed = ftun_budget_get_usage(watch_budget, &usage) != FTUN_OK;
      watched_used = watch_failed ? 0u : usage.used;
      watch_calloc_size = 0u;
    }
    if (bytes == fail_calloc_size && bytes != 0u) {
      fail_calloc_size = 0u;
      return NULL;
    }
  }
  return __real_calloc(count, size);
}

ftun_status_t __real_ftun_core_service_plan_destroy(ftun_core_service_plan_t *plan);
ftun_status_t __wrap_ftun_core_service_plan_destroy(ftun_core_service_plan_t *plan)
{
  return hold_plan ? FTUN_E_AGAIN : __real_ftun_core_service_plan_destroy(plan);
}
ftun_status_t __real_ftun_core_service_reload_commit(ftun_core_service_t *service,
  uint64_t generation);
ftun_status_t __wrap_ftun_core_service_reload_commit(ftun_core_service_t *service,
  uint64_t generation)
{
  return accept_commit ? FTUN_OK : __real_ftun_core_service_reload_commit(service, generation);
}
ftun_status_t __real_ftun_worker_submit(ftun_worker_t *worker,
  const ftun_worker_job_t *job, ftun_completion_fn completion, void *user,
  ftun_operation_t **out);
ftun_status_t __wrap_ftun_worker_submit(ftun_worker_t *worker,
  const ftun_worker_job_t *job, ftun_completion_fn completion, void *user,
  ftun_operation_t **out)
{
  if (reject_submit) {
    ftun_budget_usage_t usage;
    watch_failed = ftun_budget_get_usage(watch_budget, &usage) != FTUN_OK;
    submit_used = watch_failed ? 0u : usage.used;
    *out = NULL;
    return FTUN_E_LIMIT;
  }
  return __real_ftun_worker_submit(worker, job, completion, user, out);
}

static int memory(ftun_budget_t *budget, size_t expected)
{
  ftun_budget_usage_t usage;
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == expected);
  CHECK(usage.used_resources.descriptors == 0u && usage.used_resources.queue_slots == 0u);
  return 0;
}

static int paths(void)
{
  ftun_budget_t *budget = NULL, *child = NULL;
  ftun_core_owned_path_t first = {0}, second = {0};
  ftun_core_reload_result_t result = {0};
  char text[127];
  memset(text, 'a', sizeof(text));
  text[sizeof(text) - 1u] = '\0';
  CHECK(ftun_budget_create(NULL, 4096u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_budget_create(budget, sizeof(text) - 1u, 0u, &child) == FTUN_OK);
  CHECK(ftun_core_owned_path_copy(child, text, &first) == FTUN_E_LIMIT);
  CHECK(first.value == NULL && first.reservation == NULL && memory(budget, 0u) == 0);
  CHECK(ftun_budget_destroy(&child) == FTUN_OK);
  fail_malloc_size = sizeof(text);
  CHECK(ftun_core_owned_path_copy(budget, text, &first) == FTUN_E_LIMIT);
  CHECK(fail_malloc_size == 0u && memory(budget, 0u) == 0);
  CHECK(ftun_core_owned_path_copy(budget, text, &first) == FTUN_OK);
  CHECK(ftun_core_owned_path_copy(budget, text, &first) == FTUN_E_AGAIN);
  CHECK(ftun_core_owned_path_copy(budget, text, &second) == FTUN_OK);
  CHECK(first.value != second.value && strcmp(first.value, second.value) == 0);
  CHECK(memory(budget, 2u * sizeof(text)) == 0);
  result.source_path = first;
  memset(&first, 0, sizeof(first));
  hold_plan = true;
  CHECK(ftun_core_reload_result_release(&result, 1u) == FTUN_E_AGAIN);
  CHECK(result.source_path.value != NULL && memory(budget, 2u * sizeof(text)) == 0);
  hold_plan = false;
  CHECK(ftun_core_reload_result_release(&result, 1u) == FTUN_OK);
  CHECK(result.source_path.value == NULL && memory(budget, sizeof(text)) == 0);
  CHECK(ftun_core_owned_path_destroy(&second) == FTUN_OK && memory(budget, 0u) == 0);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int transactions(void)
{
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_core_control_t control = {0};
  ftun_core_reload_result_t result = {0};
  ftun_core_reload_transaction_t *transaction = NULL;
  ftun_reservation_t *hold = NULL;
  ftun_budget_usage_t usage;
  size_t baseline;
  const char text[] = "/prepared.json";
  char *original;
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  control.core = core;
  control.budget = budget;
  CHECK(pthread_mutex_init(&control.mutex, NULL) == 0);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
  baseline = usage.used;
  CHECK(ftun_core_owned_path_copy(budget, text, &result.source_path) == FTUN_OK);
  original = result.source_path.value;
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
  CHECK(ftun_budget_reserve(budget, usage.normal_available, &hold) == FTUN_OK);
  CHECK(ftun_core_reload_prepare_transaction(core, &control, &result, &transaction, NULL) == FTUN_E_LIMIT);
  CHECK(transaction == NULL && result.source_path.value == original);
  CHECK(ftun_reservation_release(&hold) == FTUN_OK);
  fail_calloc_size = sizeof(*transaction);
  CHECK(ftun_core_reload_prepare_transaction(core, &control, &result, &transaction, NULL) == FTUN_E_LIMIT);
  CHECK(transaction == NULL && fail_calloc_size == 0u && result.source_path.value == original);
  CHECK(memory(budget, baseline + sizeof(text)) == 0);
  /* 无配置的结果在准入后失败；叶清理暂拒绝时外层事务仍须持有路径和额度。 */
  hold_plan = true;
  CHECK(ftun_core_reload_prepare_transaction(core, &control, &result, &transaction, NULL) == FTUN_E_STATE_CORRUPT);
  CHECK(transaction == NULL && control.retired_transaction != NULL && result.source_path.value == NULL);
  CHECK(memory(budget, baseline + sizeof(text) + sizeof(*transaction)) == 0);
  hold_plan = false;
  CHECK(ftun_core_reload_transaction_cleanup(core, &control, &control.retired_transaction, 1u) == FTUN_OK);
  CHECK(memory(budget, baseline) == 0);

  /* 提交只交换拥有权：旧路径随事务退休，新路径保留至宿主销毁。 */
  CHECK(ftun_core_owned_path_copy(budget, "/old.json", &control.config_path) == FTUN_OK);
  transaction = calloc(1u, sizeof(*transaction));
  CHECK(transaction != NULL);
  CHECK(ftun_budget_reserve(budget, sizeof(*transaction), &transaction->reservation) == FTUN_OK);
  CHECK(ftun_core_owned_path_copy(budget, text, &transaction->next_path) == FTUN_OK);
  transaction->service_prepared = true;
  /* 代次只经 Core 上下文预留与发布。 */
  CHECK(ftun_core_context_generation_reserve(core, core, &transaction->next_generation) == FTUN_OK);
  transaction->generation_reserved = true;
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
  accept_commit = true;
  CHECK(ftun_core_reload_commit_transaction(core, &control, transaction) == FTUN_OK);
  accept_commit = false;
  {
    uint64_t generation = 0u, reserved = 99u;
    CHECK(ftun_core_context_generation(core, &generation) == FTUN_OK &&
          ftun_core_context_generation_reserved(core, &reserved) == FTUN_OK);
    CHECK(memory(budget, usage.used) == 0 &&
          generation == transaction->next_generation && reserved == 0u &&
          !transaction->generation_reserved);
  }
  CHECK(strcmp(control.config_path.value, text) == 0 && strcmp(transaction->next_path.value, "/old.json") == 0);
  CHECK(ftun_core_reload_transaction_cleanup(core, &control, &transaction, 1u) == FTUN_OK);
  CHECK(memory(budget, baseline + sizeof(text)) == 0);
  CHECK(ftun_core_owned_path_destroy(&control.config_path) == FTUN_OK);
  CHECK(pthread_mutex_destroy(&control.mutex) == 0);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK && memory(budget, 0u) == 0);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int reload_input(void)
{
  ftun_core_control_t control = {0};
  ftun_control_task_t task = {0};
  ftun_budget_usage_t usage;
  const char path[] = "/input-budget.json";
  size_t bytes = sizeof(ftun_core_reload_work_t) + sizeof(path);
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &control.budget) == FTUN_OK);
  CHECK(pthread_mutex_init(&control.mutex, NULL) == 0);
  CHECK(pthread_mutex_init(&task.mutex, NULL) == 0);
  task.first = (char *)path;
  watch_budget = control.budget;
  watch_calloc_size = fail_calloc_size = bytes;
  CHECK(ftun_core_reload_schedule(&control, &task) == FTUN_E_LIMIT);
  CHECK(watch_calloc_size == 0u && fail_calloc_size == 0u && !watch_failed && watched_used == bytes);
  CHECK(memory(control.budget, 0u) == 0);
  CHECK(ftun_budget_get_usage(control.budget, &usage) == FTUN_OK);
  reject_submit = true;
  CHECK(ftun_core_reload_schedule(&control, &task) == FTUN_E_LIMIT);
  reject_submit = false;
  CHECK(!watch_failed && submit_used == bytes);
  CHECK(memory(control.budget, 0u) == 0);
  CHECK(ftun_core_reload_reap(&control, 1u) == FTUN_OK && !control.retired_busy);
  CHECK(memory(control.budget, 0u) == 0);
  CHECK(pthread_mutex_destroy(&task.mutex) == 0);
  CHECK(pthread_mutex_destroy(&control.mutex) == 0);
  CHECK(ftun_budget_destroy(&control.budget) == FTUN_OK);
  return 0;
}

int main(void)
{
  CHECK(paths() == 0);
  CHECK(transactions() == 0);
  CHECK(reload_input() == 0);
  return 0;
}
