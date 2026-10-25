#include "config/compile.h"
#include "config/model.h"
#include "config/parser.h"
#include "core/budget.h"
#include "proxy/runtime_state.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "runtime contract failed: %s\n", #x); \
    return 1; \
  } \
} while (0)

static ftun_config_t *make_config(const char *text)
{
  ftun_bytes_t bytes;
  ftun_config_t *config = NULL;
  ftun_feature_plan_t *plan = NULL;
  bytes.data = (const uint8_t *)text;
  bytes.length = strlen(text);
  if (ftun_config_parse(bytes, &config) != FTUN_OK || config == NULL) return NULL;
  if (ftun_config_compile(config, &plan) != FTUN_OK || plan == NULL) {
    (void)ftun_config_destroy(&config);
    return NULL;
  }
  config->plan = plan;
  return config;
}

static int check_budget(ftun_budget_t *budget, size_t used)
{
  ftun_budget_usage_t usage;
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
  CHECK(usage.used == used);
  return 0;
}

/* TASK-CORE-001 / TEST-CORE-001：候选峰值、提交、旧代引用和回收。 */
int main(void)
{
  static const char first_text[] =
    "{\"dns\":{\"enable\":false},\"inbounds\":[{\"name\":\"one\","
    "\"type\":\"mixed\",\"listen\":\"127.0.0.1:1001\"}]}";
  static const char second_text[] =
    "{\"dns\":{\"enable\":false},\"inbounds\":[{\"name\":\"two\","
    "\"type\":\"socks5\",\"listen\":\"127.0.0.1:1002\"}],"
    "\"rules\":[\"MATCH,REJECT\"]}";
  static const char third_text[] =
    "{\"dns\":{\"enable\":false},\"inbounds\":[{\"name\":\"three\","
    "\"type\":\"mixed\",\"listen\":\"127.0.0.1:1003\"}],"
    "\"rules\":[\"MATCH,DIRECT\"]}";
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_runtime_t *candidate = NULL;
  ftun_runtime_t *duplicate = (ftun_runtime_t *)(uintptr_t)1;
  ftun_runtime_t *old = NULL;
  ftun_runtime_t *active = NULL;
  ftun_config_t *first = NULL;
  ftun_config_t *second = NULL;
  ftun_config_t *third = NULL;
  ftun_config_t *uncompiled = NULL;
  ftun_runtime_info_t runtime_info;
  ftun_runtime_manager_info_t manager_info;
  size_t first_bytes;
  size_t second_bytes;
  size_t manager_bytes;
  ftun_budget_usage_t usage;
  ftun_reservation_t *hold = NULL;

  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_attach(NULL, 1u, SIZE_MAX) == FTUN_E_INVALID);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used > 0u);
  CHECK(ftun_budget_reserve(budget, usage.normal_available, &hold) == FTUN_OK);
  CHECK(ftun_runtime_manager_attach(core, 2u, 4096u) == FTUN_E_LIMIT);
  CHECK(ftun_reservation_release(&hold) == FTUN_OK);
  CHECK(ftun_runtime_manager_attach(core, 2u, 4096u) == FTUN_OK);
  CHECK(ftun_runtime_manager_attach(core, 3u, 8192u) == FTUN_E_STALE);
  CHECK(ftun_runtime_manager_get_info(core, &manager_info) == FTUN_OK &&
        manager_info.retained_limit == 2u &&
        manager_info.retained_bytes_limit == 4096u);
  CHECK(ftun_runtime_manager_clear(core) == FTUN_OK);
  CHECK(ftun_core_context_bind(core, &manager_info) == FTUN_OK);
  CHECK(ftun_runtime_manager_attach(core, 1u, SIZE_MAX) == FTUN_E_STALE);
  {
    void *extension = NULL;
    CHECK(ftun_core_context_extension(core, &extension) == FTUN_OK &&
          extension == &manager_info);
  }
  CHECK(ftun_core_context_bind(core, NULL) == FTUN_OK);
  CHECK(ftun_runtime_manager_attach(core, 1u, SIZE_MAX) == FTUN_OK);
  CHECK(ftun_runtime_manager_clear(core) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 1u, &core) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used > 0u);
  manager_bytes = usage.used;
  CHECK(ftun_runtime_manager_get_info(core, &manager_info) == FTUN_OK);
  CHECK(manager_info.generation == 0u && !manager_info.has_active &&
        !manager_info.has_candidate && manager_info.retained_limit == 1u &&
        manager_info.retained_bytes == 0u &&
        manager_info.retained_bytes_limit == SIZE_MAX);
  CHECK(ftun_runtime_active_acquire(core, &duplicate) == FTUN_E_AGAIN &&
        duplicate == NULL);

  first = make_config(first_text);
  second = make_config(second_text);
  CHECK(first != NULL && second != NULL);
  CHECK(first->reference_count == 1u && second->reference_count == 1u);
  CHECK(ftun_runtime_prepare(core, first, &candidate) == FTUN_OK && candidate != NULL);
  CHECK(first->reference_count == 2u);
  CHECK(ftun_runtime_get_info(candidate, &runtime_info) == FTUN_OK);
  CHECK(runtime_info.state == FTUN_RUNTIME_CANDIDATE && runtime_info.generation == 0u &&
        runtime_info.reference_count == 1u && runtime_info.accounted_bytes > 0u &&
        runtime_info.prepared_item_count > 0u);
  first_bytes = runtime_info.accounted_bytes;
  CHECK(check_budget(budget, manager_bytes + first_bytes) == 0);
  CHECK(ftun_runtime_prepare(core, second, &duplicate) == FTUN_E_AGAIN &&
        duplicate == NULL);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_E_AGAIN && core != NULL);
  CHECK(ftun_runtime_abort(core, &candidate) == FTUN_OK && candidate == NULL);
  CHECK(first->reference_count == 1u);
  CHECK(check_budget(budget, manager_bytes) == 0);
  CHECK(ftun_runtime_abort(core, &candidate) == FTUN_OK);

  CHECK(ftun_runtime_prepare(core, first, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK && candidate == NULL);
  CHECK(ftun_runtime_manager_get_info(core, &manager_info) == FTUN_OK);
  CHECK(manager_info.generation == 1u && manager_info.has_active &&
        !manager_info.has_candidate && manager_info.retained_count == 0u);
  CHECK(ftun_config_destroy(&first) == FTUN_OK && first == NULL);
  CHECK(ftun_runtime_active_acquire(core, &old) == FTUN_OK && old != NULL);
  CHECK(ftun_runtime_get_info(old, &runtime_info) == FTUN_OK);
  CHECK(runtime_info.state == FTUN_RUNTIME_ACTIVE && runtime_info.generation == 1u &&
        runtime_info.reference_count == 2u);

  CHECK(ftun_runtime_prepare(core, second, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_get_info(candidate, &runtime_info) == FTUN_OK);
  second_bytes = runtime_info.accounted_bytes;
  CHECK(check_budget(budget, manager_bytes + first_bytes + second_bytes) == 0);
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK && candidate == NULL);
  CHECK(ftun_config_destroy(&second) == FTUN_OK && second == NULL);
  CHECK(ftun_runtime_manager_get_info(core, &manager_info) == FTUN_OK);
  CHECK(manager_info.generation == 2u && manager_info.retained_count == 1u);
  CHECK(ftun_runtime_get_info(old, &runtime_info) == FTUN_OK);
  CHECK(runtime_info.state == FTUN_RUNTIME_RETAINED && runtime_info.generation == 1u &&
        runtime_info.reference_count == 2u);
  CHECK(ftun_runtime_release(&old) == FTUN_OK && old == NULL);
  CHECK(ftun_runtime_manager_get_info(core, &manager_info) == FTUN_OK &&
        manager_info.retained_count == 0u &&
        manager_info.retained_bytes == 0u);
  CHECK(check_budget(budget, manager_bytes + second_bytes) == 0);

  /* stage 只固定候选代次，abort 后 active 与 manager generation 不变。 */
  third = make_config(third_text);
  CHECK(third != NULL);
  CHECK(ftun_runtime_prepare(core, third, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_stage_commit(core, candidate, 3u) == FTUN_OK);
  CHECK(ftun_runtime_get_info(candidate, &runtime_info) == FTUN_OK &&
        runtime_info.state == FTUN_RUNTIME_CANDIDATE &&
        runtime_info.generation == 3u);
  CHECK(ftun_runtime_manager_get_info(core, &manager_info) == FTUN_OK &&
        manager_info.generation == 2u && manager_info.has_candidate);
  CHECK(ftun_runtime_abort(core, &candidate) == FTUN_OK && candidate == NULL);
  CHECK(ftun_config_destroy(&third) == FTUN_OK);

  CHECK(ftun_runtime_active_acquire(core, &active) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_E_AGAIN && core != NULL);
  CHECK(ftun_runtime_release(&active) == FTUN_OK && active == NULL);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK && core == NULL);
  CHECK(check_budget(budget, 0u) == 0);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK && budget == NULL);

  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 0u, &core) == FTUN_OK);
  first = make_config(first_text);
  second = make_config(second_text);
  CHECK(first != NULL && second != NULL);
  CHECK(ftun_runtime_prepare(core, first, &candidate) == FTUN_OK);
  active = candidate;
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK);
  CHECK(ftun_config_destroy(&first) == FTUN_OK);
  CHECK(ftun_runtime_active_acquire(core, &old) == FTUN_OK);
  CHECK(ftun_runtime_prepare(core, second, &candidate) == FTUN_E_LIMIT &&
        candidate == NULL);
  CHECK(ftun_runtime_manager_get_info(core, &manager_info) == FTUN_OK);
  CHECK(manager_info.generation == 1u && !manager_info.has_candidate &&
        manager_info.retained_count == 0u);
  CHECK(ftun_runtime_release(&old) == FTUN_OK);
  CHECK(ftun_runtime_prepare(core, second, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_stage_commit(core, candidate, 2u) == FTUN_OK);
  old = (ftun_runtime_t *)(uintptr_t)1;
  CHECK(ftun_runtime_active_acquire(core, &old) == FTUN_E_LIMIT && old == NULL);
  CHECK(ftun_runtime_retain(active) == FTUN_E_LIMIT);
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK && candidate == NULL);
  CHECK(ftun_config_destroy(&second) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(check_budget(budget, 0u) == 0);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);

  /* retained 的字节额度独立于数量额度；拒绝不得改变 active。 */
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create_limits(budget, 4u, 1u, &core) == FTUN_OK);
  first = make_config(first_text);
  second = make_config(second_text);
  CHECK(first != NULL && second != NULL);
  CHECK(ftun_runtime_prepare(core, first, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK);
  CHECK(ftun_config_destroy(&first) == FTUN_OK);
  CHECK(ftun_runtime_active_acquire(core, &old) == FTUN_OK);
  CHECK(ftun_runtime_prepare(core, second, &candidate) == FTUN_E_LIMIT &&
        candidate == NULL);
  CHECK(ftun_runtime_manager_get_info(core, &manager_info) == FTUN_OK &&
        manager_info.generation == 1u && manager_info.retained_count == 0u &&
        manager_info.retained_bytes_limit == 1u);
  CHECK(ftun_runtime_release(&old) == FTUN_OK);
  CHECK(ftun_runtime_prepare(core, second, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK);
  CHECK(ftun_config_destroy(&second) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);

  /* retained 已满时，提交不得改动 active、candidate 或 generation。 */
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 1u, &core) == FTUN_OK);
  first = make_config(first_text);
  second = make_config(second_text);
  third = make_config(third_text);
  CHECK(first != NULL && second != NULL && third != NULL);
  CHECK(ftun_runtime_prepare(core, first, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK);
  CHECK(ftun_config_destroy(&first) == FTUN_OK);
  CHECK(ftun_runtime_active_acquire(core, &old) == FTUN_OK);
  CHECK(ftun_runtime_prepare(core, second, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK);
  CHECK(ftun_config_destroy(&second) == FTUN_OK);
  CHECK(ftun_runtime_active_acquire(core, &active) == FTUN_OK);
  CHECK(ftun_runtime_prepare(core, third, &candidate) == FTUN_E_LIMIT &&
        candidate == NULL);
  CHECK(ftun_runtime_manager_get_info(core, &manager_info) == FTUN_OK);
  CHECK(manager_info.generation == 2u && manager_info.has_active &&
        !manager_info.has_candidate && manager_info.retained_count == 1u);
  CHECK(ftun_runtime_get_info(active, &runtime_info) == FTUN_OK);
  CHECK(runtime_info.state == FTUN_RUNTIME_ACTIVE && runtime_info.generation == 2u);
  CHECK(ftun_runtime_release(&old) == FTUN_OK && old == NULL);
  CHECK(ftun_runtime_prepare(core, third, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK && candidate == NULL);
  CHECK(ftun_config_destroy(&third) == FTUN_OK);
  CHECK(ftun_runtime_manager_get_info(core, &manager_info) == FTUN_OK);
  CHECK(manager_info.generation == 3u && !manager_info.has_candidate &&
        manager_info.retained_count == 1u);
  CHECK(ftun_runtime_get_info(active, &runtime_info) == FTUN_OK);
  CHECK(runtime_info.state == FTUN_RUNTIME_RETAINED && runtime_info.generation == 2u);
  CHECK(ftun_runtime_release(&active) == FTUN_OK && active == NULL);
  CHECK(ftun_runtime_manager_get_info(core, &manager_info) == FTUN_OK &&
        manager_info.retained_count == 0u);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(check_budget(budget, 0u) == 0);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);

  CHECK(ftun_budget_create(NULL, 1u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 1u, &core) == FTUN_E_LIMIT && core == NULL);
  CHECK(check_budget(budget, 0u) == 0);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 1u, &core) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
  manager_bytes = usage.used;
  CHECK(ftun_budget_reserve(budget, usage.normal_available, &hold) == FTUN_OK);
  first = make_config(first_text);
  CHECK(first != NULL);
  candidate = (ftun_runtime_t *)(uintptr_t)1;
  CHECK(ftun_runtime_prepare(core, first, &candidate) == FTUN_E_LIMIT &&
        candidate == NULL && first->reference_count == 1u);
  CHECK(check_budget(budget, 1024u * 1024u) == 0);
  CHECK(ftun_reservation_release(&hold) == FTUN_OK);
  CHECK(check_budget(budget, manager_bytes) == 0);
  CHECK(ftun_config_destroy(&first) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(check_budget(budget, 0u) == 0);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);

  CHECK(ftun_budget_create(NULL, 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 1u, &core) == FTUN_OK);
  {
    ftun_bytes_t bytes;
    bytes.data = (const uint8_t *)"{\"dns\":{\"enable\":false}}";
    bytes.length = strlen((const char *)bytes.data);
    CHECK(ftun_config_parse(bytes, &uncompiled) == FTUN_OK && uncompiled != NULL);
  }
  CHECK(ftun_runtime_prepare(core, uncompiled, &candidate) == FTUN_E_INVALID &&
        candidate == NULL);
  CHECK(ftun_config_destroy(&uncompiled) == FTUN_OK);
  CHECK(ftun_runtime_prepare(NULL, NULL, &candidate) == FTUN_E_INVALID &&
        candidate == NULL);
  CHECK(ftun_runtime_prepare(core, NULL, NULL) == FTUN_E_INVALID);
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_E_INVALID);
  CHECK(ftun_runtime_abort(core, NULL) == FTUN_E_INVALID);
  CHECK(ftun_runtime_release(NULL) == FTUN_E_INVALID);
  CHECK(ftun_runtime_get_info(NULL, &runtime_info) == FTUN_E_INVALID);
  CHECK(runtime_info.state == 0 && runtime_info.accounted_bytes == 0u);
  CHECK(ftun_runtime_manager_get_info(NULL, &manager_info) == FTUN_E_INVALID);
  CHECK(manager_info.generation == 0u && !manager_info.has_active);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(NULL, 0u, &core) == FTUN_E_INVALID && core == NULL);
  CHECK(ftun_runtime_manager_create(NULL, 0u, NULL) == FTUN_E_INVALID);
  CHECK(ftun_runtime_manager_destroy(NULL) == FTUN_E_INVALID);
  return 0;
}
