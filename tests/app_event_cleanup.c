#include "core/module_plan.h"
#include "core/operation.h"
#include "event/event.h"
#include "event/libev_adapter.h"

#include <stdio.h>
#include <stdlib.h>

#define REQUIRE(value) do { if (!(value)) { \
  fprintf(stderr, "Event cleanup failed at %d: %s\n", __LINE__, #value); \
  abort(); } } while (0)

static ftun_event_loop_t *loop;
static ftun_event_source_t *chain_source, *cancel_source;
static ftun_operation_token_t token;
static unsigned int deferred, tasks, late, completed, rounds, previous;
static bool enabled, seeded, cancel_scheduled;

ftun_status_t __real_ftun_libev_attach(ftun_event_loop_t *events);
ftun_status_t __real_ftun_core_module_runtime_prepare(
  const ftun_core_module_catalog_t *catalog, ftun_core_t *core,
  ftun_budget_t *budget, ftun_operation_queue_t *operations,
  const ftun_config_t *config, uint64_t generation,
  ftun_core_module_runtime_t **out, ftun_diagnostic_t *diagnostic);
ftun_status_t __real_ftun_core_module_runtime_drain_until(
  ftun_core_module_runtime_t *runtime, uint64_t deadline_ms);

ftun_status_t __wrap_ftun_libev_attach(ftun_event_loop_t *events)
{
  loop = events;
  return __real_ftun_libev_attach(events);
}

static void deferred_chain(void *user)
{
  (void)user;
  deferred++;
  if (deferred < 64u) REQUIRE(ftun_event_defer(loop, deferred_chain, NULL) == FTUN_OK);
}

static void task_chain(ftun_event_source_t *source, uint32_t events, void *user)
{
  (void)user;
  REQUIRE(source == chain_source && events == FTUN_EVENT_TASK);
  tasks++;
  if (tasks < 64u) REQUIRE(ftun_event_task_ready(source) == FTUN_OK);
  else REQUIRE(ftun_event_source_cancel(&chain_source) == FTUN_OK);
}

static void late_deferred(void *user)
{
  (void)user;
  late++;
}

static void operation_completed(ftun_operation_t *operation, ftun_error_t error,
  void *user)
{
  (void)operation;
  (void)user;
  REQUIRE(error.status == FTUN_E_CANCELLED && completed == 0u);
  completed++;
  /* Operation 派发在服务 drain 之后，回调仍须能排入最后一个清理通知。 */
  REQUIRE(ftun_event_defer(loop, late_deferred, NULL) == FTUN_OK);
}

static void cancel_task(ftun_event_source_t *source, uint32_t events, void *user)
{
  (void)user;
  REQUIRE(source == cancel_source && events == FTUN_EVENT_TASK);
  REQUIRE(ftun_event_source_cancel(&cancel_source) == FTUN_OK);
  REQUIRE(ftun_operation_complete(token,
    (ftun_error_t){FTUN_E_CANCELLED, 0u, 0}) == FTUN_OK);
}

static ftun_status_t cancel_operation(void *user)
{
  (void)user;
  /* 等已有事件排空后再排入取消任务，独立验证 Operation 静默屏障。 */
  if (deferred < 64u || tasks < 64u) return FTUN_E_AGAIN;
  if (!cancel_scheduled) {
    REQUIRE(ftun_event_task_start(loop, cancel_task, NULL, &cancel_source) == FTUN_OK);
    REQUIRE(ftun_event_task_ready(cancel_source) == FTUN_OK);
    cancel_scheduled = true;
  }
  return FTUN_E_AGAIN;
}

ftun_status_t __wrap_ftun_core_module_runtime_prepare(
  const ftun_core_module_catalog_t *catalog, ftun_core_t *core,
  ftun_budget_t *budget, ftun_operation_queue_t *operations,
  const ftun_config_t *config, uint64_t generation,
  ftun_core_module_runtime_t **out, ftun_diagnostic_t *diagnostic)
{
  ftun_operation_t *operation = NULL;
  ftun_core_module_info_t info;
  ftun_status_t status = __real_ftun_core_module_runtime_prepare(
    catalog, core, budget, operations, config, generation, out, diagnostic);
  if (status == FTUN_OK) {
    REQUIRE(ftun_core_module_runtime_get_info(*out, &info) == FTUN_OK);
    /* 无物理服务的配置在 activate 拒绝；不为该拒绝路径注入假生产者。 */
    if (info.service_count == 0u) return status;
    enabled = true;
    REQUIRE(ftun_operation_accept(operations, operation_completed, NULL,
      &operation, &token) == FTUN_OK);
    REQUIRE(ftun_operation_set_cancel_hook(operation, cancel_operation, NULL) == FTUN_OK);
  }
  return status;
}

ftun_status_t __wrap_ftun_core_module_runtime_drain_until(
  ftun_core_module_runtime_t *runtime, uint64_t deadline_ms)
{
  ftun_status_t status = __real_ftun_core_module_runtime_drain_until(runtime, deadline_ms);
  unsigned int total = deferred + tasks + late;
  if (!enabled) return status;
  REQUIRE(total - previous <= 32u);
  previous = total;
  if (status != FTUN_OK) return status;
  rounds++;
  if (!seeded) {
    seeded = true;
    REQUIRE(ftun_event_defer(loop, deferred_chain, NULL) == FTUN_OK);
    REQUIRE(ftun_event_task_start(loop, task_chain, NULL, &chain_source) == FTUN_OK);
    REQUIRE(ftun_event_task_ready(chain_source) == FTUN_OK);
    return FTUN_E_AGAIN;
  }
  /* 后续模块已完成 drain，Event 和 Operation 清理仍须继续推进。 */
  return FTUN_OK;
}

int ftun_test_event_cleanup_verify(bool active)
{
  if (!active) return seeded || completed || deferred || tasks || late ? 1 : 0;
  REQUIRE(seeded && rounds >= 5u && deferred == 64u && tasks == 64u);
  REQUIRE(late == 1u && completed == 1u && cancel_scheduled);
  REQUIRE(chain_source == NULL && cancel_source == NULL);
  puts("App event cleanup: bounded deferred/task drain and late operation cleanup passed");
  return 0;
}
