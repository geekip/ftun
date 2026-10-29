#include "core/core.h"

#include <stdio.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "Core resource contract failed at %d: %s\n", __LINE__, #x); \
  return 1; \
} } while (0)

static int context_case(void)
{
  ftun_budget_t *budget = NULL;
  ftun_budget_t *alternate = NULL;
  ftun_reservation_t hold = (ftun_reservation_t){0};
  ftun_core_t *core = NULL;
  ftun_core_t *second = NULL;
  ftun_budget_usage_t empty, first, both, usage;
  int extension;
  CHECK(ftun_budget_create(NULL, 65536u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_budget_create(NULL, 65536u, 0u, &alternate) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &empty) == FTUN_OK);
  CHECK(ftun_budget_reserve(budget, empty.normal_available_resources.memory_bytes, &hold) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_E_LIMIT && core == NULL);
  ftun_reservation_release(&hold);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &first) == FTUN_OK && first.used_resources.memory_bytes > 0u);
  CHECK(ftun_core_context_create(budget, &second) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &both) == FTUN_OK && both.used_resources.memory_bytes == 2u * first.used_resources.memory_bytes);
  CHECK(ftun_core_context_bind(core, &extension) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_E_AGAIN && core != NULL);
  CHECK(ftun_core_context_bind(core, NULL) == FTUN_OK);
  CHECK(ftun_core_context_set_budget(core, alternate) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == both.used_resources.memory_bytes);
  CHECK(ftun_budget_get_usage(alternate, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u);
  CHECK(ftun_core_context_destroy(&second) == FTUN_OK && second == NULL);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == first.used_resources.memory_bytes);
  CHECK(ftun_budget_destroy(&budget) == FTUN_E_AGAIN && budget != NULL);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK && core == NULL);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u &&
        usage.metadata_bytes == empty.metadata_bytes);
  CHECK(ftun_budget_destroy(&alternate) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

/* 运行配置代次唯一由 Core 上下文预留与发布，预留带持有者。 */
static int generation_case(void)
{
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  int host = 0, other = 0;
  uint64_t value = 99u;
  uint64_t next = 0u;
  uint64_t second = 0u;
  CHECK(ftun_budget_create(NULL, 65536u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_core_context_is_valid(core) && !ftun_core_context_is_valid(NULL));
  CHECK(ftun_core_context_generation(core, &value) == FTUN_OK && value == 0u);
  CHECK(ftun_core_context_generation_reserved(core, &value) == FTUN_OK && value == 0u);
  CHECK(ftun_core_context_generation_held(core, &host, &value) == FTUN_E_STALE && value == 0u);
  /* 未预留不能发布；持有者必须非空。 */
  CHECK(ftun_core_context_generation_publish(core, &host, 1u) == FTUN_E_STALE);
  CHECK(ftun_core_context_generation_reserve(core, NULL, &next) == FTUN_E_INVALID && next == 0u);
  CHECK(ftun_core_context_generation_reserve(core, &host, &next) == FTUN_OK && next == 1u);
  /* 预留期间其他来源得到 AGAIN，且不能发布、释放或查询为己有。 */
  CHECK(ftun_core_context_generation_reserve(core, &other, &second) == FTUN_E_AGAIN && second == 0u);
  CHECK(ftun_core_context_generation_publish(core, &other, next) == FTUN_E_STALE);
  CHECK(ftun_core_context_generation_release(core, &other, next) == FTUN_E_STALE);
  CHECK(ftun_core_context_generation_held(core, &other, &value) == FTUN_E_STALE && value == 0u);
  CHECK(ftun_core_context_generation_held(core, &host, &value) == FTUN_OK && value == 1u);
  CHECK(ftun_core_context_generation(core, &value) == FTUN_OK && value == 0u);
  /* 释放后可重新预留同一代次；错误代次的发布/释放返回 STALE。 */
  CHECK(ftun_core_context_generation_release(core, &host, 2u) == FTUN_E_STALE);
  CHECK(ftun_core_context_generation_release(core, &host, next) == FTUN_OK);
  CHECK(ftun_core_context_generation_release(core, &host, next) == FTUN_E_STALE);
  CHECK(ftun_core_context_generation_reserve(core, &other, &next) == FTUN_OK && next == 1u);
  CHECK(ftun_core_context_generation_publish(core, &other, 2u) == FTUN_E_STALE);
  CHECK(ftun_core_context_generation_publish(core, &other, next) == FTUN_OK);
  CHECK(ftun_core_context_generation(core, &value) == FTUN_OK && value == 1u);
  CHECK(ftun_core_context_generation_reserved(core, &value) == FTUN_OK && value == 0u);
  CHECK(ftun_core_context_generation_publish(core, &other, next) == FTUN_E_STALE);
  CHECK(ftun_core_context_generation_reserve(core, &host, &next) == FTUN_OK && next == 2u);
  CHECK(ftun_core_context_generation_publish(core, &host, next) == FTUN_OK);
  CHECK(ftun_core_context_generation(core, &value) == FTUN_OK && value == 2u);
  CHECK(ftun_core_context_generation_reserve(NULL, &host, &next) == FTUN_E_INVALID && next == 0u);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int app_case(void)
{
  ftun_core_options_t options = {0};
  ftun_core_t *core = NULL;
  ftun_budget_t *control = NULL;
  ftun_budget_t *root = NULL;
  ftun_budget_t *control_child = NULL;
  ftun_budget_t *root_child = NULL;
  ftun_budget_usage_t baseline, live, usage;
  ftun_reservation_t hold = (ftun_reservation_t){0};
  ftun_core_info_t info;
  options.struct_size = sizeof(options);
  options.abi_version = FTUN_ABI_VERSION;
  options.owned_memory_limit = 1024u * 1024u;
  options.owned_descriptor_limit = 16u;
  options.owned_queue_limit = 64u;
  /* 在 context/control/tasks 已构造后因 Operation 槽不足失败，完整回滚。 */
  options.operation_capacity = 4096u;
  CHECK(ftun_core_create(&options, &core) == FTUN_E_LIMIT && core == NULL);
  options.operation_capacity = 4u;
  CHECK(ftun_core_create(&options, &core) == FTUN_OK);
  CHECK(ftun_core_context_budget(core, &control) == FTUN_OK);
  CHECK(ftun_budget_get_usage(control, &baseline) == FTUN_OK);
  /* task 指针环和 Operation 存储是两份内存，但同一容量只计一组槽。 */
  CHECK(baseline.used_resources.memory_bytes > 0u && baseline.used_resources.queue_slots >= 4u);
  CHECK(ftun_budget_reserve(control, 1u, &hold) == FTUN_OK);
  CHECK(ftun_core_destroy(&core) == FTUN_E_AGAIN && core != NULL);
  CHECK(ftun_core_context_budget(core, &root) == FTUN_OK && root != control);
  CHECK(ftun_budget_get_usage(control, &live) == FTUN_OK && live.used_resources.memory_bytes > 1u);
  CHECK(live.used_resources.memory_bytes < baseline.used_resources.memory_bytes && live.used_resources.queue_slots == 0u &&
        live.used_resources.descriptors == 0u);
  CHECK(ftun_core_get_info(core, &info) == FTUN_OK && info.state == FTUN_CORE_STOPPED);
  CHECK(ftun_core_destroy(&core) == FTUN_E_AGAIN && core != NULL);
  CHECK(ftun_budget_get_usage(control, &usage) == FTUN_OK && usage.used_resources.memory_bytes == live.used_resources.memory_bytes);
  CHECK(ftun_budget_create(control, 1024u, 0u, &control_child) == FTUN_OK);
  CHECK(ftun_budget_create(root, 1024u, 0u, &root_child) == FTUN_OK);
  ftun_reservation_release(&hold);
  CHECK(ftun_core_destroy(&core) == FTUN_E_AGAIN && core != NULL);
  CHECK(ftun_budget_destroy(&control_child) == FTUN_OK);
  CHECK(ftun_core_destroy(&core) == FTUN_E_AGAIN && core != NULL);
  CHECK(ftun_budget_get_usage(control, &usage) == FTUN_OK && usage.used_resources.memory_bytes == live.used_resources.memory_bytes - 1u);
  CHECK(ftun_budget_destroy(&root_child) == FTUN_OK);
  CHECK(ftun_budget_reserve_resources(root,
    (ftun_budget_resources_t){0u, 1u, 1u}, &hold) == FTUN_OK);
  CHECK(ftun_core_destroy(&core) == FTUN_E_AGAIN && core != NULL);
  CHECK(ftun_core_get_info(core, &info) == FTUN_OK && info.state == FTUN_CORE_STOPPED);
  ftun_reservation_release(&hold);
  CHECK(ftun_core_destroy(&core) == FTUN_OK && core == NULL);
  CHECK(ftun_core_destroy(&core) == FTUN_OK);
  return 0;
}

int main(void)
{
  CHECK(context_case() == 0);
  CHECK(generation_case() == 0);
  CHECK(app_case() == 0);
  return 0;
}
