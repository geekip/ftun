#include "core/module_plan.h"

#include "config/compile.h"
#include "util/time.h"
#include "util/event_log.h"

#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>

typedef enum {
  FTUN_MODULE_SELECTED = 1,
  FTUN_MODULE_PREPARED,
  FTUN_MODULE_ACTIVE,
  FTUN_MODULE_QUIESCED,
  FTUN_MODULE_DRAINED,
  FTUN_MODULE_DESTROYED
} ftun_core_module_phase_t;

typedef struct {
  const ftun_core_module_descriptor_t *descriptor;
  ftun_core_service_t service;
  ftun_core_module_phase_t phase;
  bool reload_pending;
} ftun_core_module_entry_t;

typedef struct {
  const ftun_core_module_descriptor_t *descriptor;
  ftun_core_service_plan_t service_plan;
} ftun_core_module_reload_entry_t;

typedef struct {
  uint32_t required;
  uint32_t selected;
  uint32_t skipped_optional;
  size_t order[FTUN_CORE_MODULE_LIMIT];
  size_t count;
  size_t service_count;
} ftun_core_module_selection_t;

struct ftun_core_module_reload_plan {
  ftun_reservation_t *reservation;
  const ftun_core_module_catalog_t *catalog;
  ftun_core_module_reload_entry_t entries[FTUN_CORE_MODULE_LIMIT];
  uint32_t required_modules;
  uint32_t selected_modules;
  uint32_t skipped_optional;
  size_t entry_count;
  ftun_status_t first_error;
  ftun_status_t cleanup_error;
  bool cleanup_only;
};

struct ftun_core_module_runtime {
  ftun_core_t *core;
  ftun_reservation_t *reservation;
  uint64_t generation;
  uint32_t built_modules;
  const ftun_core_module_catalog_t *catalog;
  ftun_core_module_entry_t entries[FTUN_CORE_MODULE_LIMIT];
  uint32_t required_modules;
  uint32_t selected_modules;
  uint32_t skipped_optional;
  uint32_t pending_required_modules;
  uint32_t pending_selected_modules;
  uint32_t pending_skipped_optional;
  size_t entry_count;
  size_t service_count;
  size_t service_entries[FTUN_CORE_MODULE_LIMIT];
  size_t block_cursor;
  atomic_bool wake_pending;
  bool activated;
  bool reload_prepared;
  bool rolled_back;
  bool cleanup_only;
  ftun_status_t first_error;
  ftun_status_t cleanup_error;
};

static void ftun_core_module_event(ftun_core_module_runtime_t *runtime,
  uint32_t module, ftun_lifecycle_kind_t kind, ftun_status_t status,
  ftun_lifecycle_reason_t reason)
{
  ftun_lifecycle_event_t item = {0};
  item.kind = kind;
  item.module = module;
  item.generation = runtime->generation;
  item.status = status;
  item.reason = reason;
  (void)ftun_lifecycle_emit(runtime->core, &item);
}

/* 清理的小片期限和 AGAIN 表示继续推进，不冒充模块终态失败。 */
static void ftun_core_module_failure(ftun_core_module_runtime_t *runtime,
  ftun_core_module_entry_t *entry, ftun_status_t status, ftun_lifecycle_reason_t reason)
{
  if (status != FTUN_OK && status != FTUN_E_AGAIN && status != FTUN_E_TIMEOUT) {
    ftun_core_module_event(runtime, entry->descriptor->capability,
      FTUN_LIFECYCLE_MODULE_FAILED, status, reason);
  }
}

static void ftun_core_module_phase(ftun_core_module_runtime_t *runtime,
  ftun_core_module_entry_t *entry, ftun_core_module_phase_t phase)
{
  static const ftun_lifecycle_kind_t kinds[] = {0, FTUN_LIFECYCLE_MODULE_SELECTED,
    FTUN_LIFECYCLE_MODULE_PREPARED, FTUN_LIFECYCLE_MODULE_ACTIVE,
    FTUN_LIFECYCLE_MODULE_QUIESCED, FTUN_LIFECYCLE_MODULE_DRAINED,
    FTUN_LIFECYCLE_MODULE_STOPPED};
  if (entry->phase == phase) return;
  entry->phase = phase;
  ftun_core_module_event(runtime, entry->descriptor->capability,
    kinds[phase], FTUN_OK, FTUN_LIFECYCLE_REASON_NONE);
}

static void ftun_core_module_selection_events(ftun_core_module_runtime_t *runtime)
{
  uint32_t remaining = FTUN_BUILD_MODULE_ALL;
  while (remaining != 0u) {
    uint32_t module = remaining & (~remaining + 1u);
    ftun_lifecycle_reason_t reason;
    ftun_lifecycle_kind_t kind = FTUN_LIFECYCLE_MODULE_DISABLED;
    size_t index;
    if ((runtime->selected_modules & module) != 0u) {
      kind = FTUN_LIFECYCLE_MODULE_SELECTED;
      reason = (runtime->required_modules & module) != 0u ? FTUN_LIFECYCLE_REASON_REQUIRED :
        ((runtime->catalog->optional_modules & module) != 0u ?
          FTUN_LIFECYCLE_REASON_OPTIONAL : FTUN_LIFECYCLE_REASON_DEPENDENCY);
    } else if ((runtime->built_modules & module) == 0u) reason = FTUN_LIFECYCLE_REASON_NOT_BUILT;
    else {
      reason = FTUN_LIFECYCLE_REASON_NOT_REGISTERED;
      for (index = 0u; index < runtime->catalog->module_count; index++) {
        if (runtime->catalog->modules[index].capability == module) {
          reason = FTUN_LIFECYCLE_REASON_NOT_SELECTED;
          break;
        }
      }
    }
    ftun_core_module_event(runtime, module, kind, FTUN_OK, reason);
    remaining &= ~module;
  }
}

static void ftun_core_module_record(ftun_status_t *first,
                                     ftun_status_t status)
{
  if (*first == FTUN_OK && status != FTUN_OK) *first = status;
}

static ftun_status_t ftun_core_module_runtime_rollback(
  ftun_core_module_runtime_t *runtime, uint64_t deadline_ms);

static ftun_status_t ftun_core_module_diagnostic(
  ftun_diagnostic_t *out, ftun_status_t status, const char *message)
{
  if (out != NULL) {
    memset(out, 0, sizeof(*out));
    out->error.status = status;
    out->path.data = "/";
    out->path.length = 1u;
    out->message.data = message;
    out->message.length = strlen(message);
  }
  return status;
}

static int ftun_core_module_capability_valid(uint32_t capability)
{
  return capability != 0u && (capability & (capability - 1u)) == 0u &&
    (capability & ~(uint32_t)FTUN_BUILD_MODULE_ALL) == 0u;
}

static int ftun_core_module_find(const ftun_core_module_catalog_t *catalog,
                                 uint32_t capability, size_t *out)
{
  size_t index;
  if (catalog == NULL) return 0;
  for (index = 0u; index < catalog->module_count; index++) {
    if (catalog->modules[index].capability == capability) {
      if (out != NULL) *out = index;
      return 1;
    }
  }
  return 0;
}

static int ftun_core_module_catalog_visit(
  const ftun_core_module_catalog_t *catalog, size_t index, uint8_t *states)
{
  uint32_t dependencies;
  if (states[index] == 2u) return 1;
  if (states[index] == 1u) return 0;
  states[index] = 1u;
  dependencies = catalog->modules[index].dependencies;
  while (dependencies != 0u) {
    uint32_t dependency = dependencies & (~dependencies + 1u);
    size_t dependency_index;
    if (!ftun_core_module_find(catalog, dependency, &dependency_index) ||
        !ftun_core_module_catalog_visit(catalog, dependency_index, states)) {
      return 0;
    }
    dependencies &= ~dependency;
  }
  states[index] = 2u;
  return 1;
}

bool ftun_core_module_catalog_valid(
  const ftun_core_module_catalog_t *catalog)
{
  uint8_t states[FTUN_CORE_MODULE_LIMIT];
  size_t left;
  size_t right;
  if (catalog == NULL || catalog->modules == NULL ||
      catalog->module_count == 0u ||
      catalog->module_count > FTUN_CORE_MODULE_LIMIT ||
      (catalog->optional_modules & ~(uint32_t)FTUN_BUILD_MODULE_ALL) != 0u) {
    return false;
  }
  memset(states, 0, sizeof(states));
  for (left = 0u; left < catalog->module_count; left++) {
    const ftun_core_module_descriptor_t *module = &catalog->modules[left];
    if (module->name == NULL || module->name[0] == '\0' ||
        !ftun_core_module_capability_valid(module->capability) ||
        (module->dependencies & ~(uint32_t)FTUN_BUILD_MODULE_ALL) != 0u ||
        (module->dependencies & module->capability) != 0u ||
        ((module->binding.value == NULL) != (module->binding.size == 0u)) ||
        (module->service != NULL &&
         !ftun_core_service_descriptor_valid(module->service))) return false;
    for (right = left + 1u; right < catalog->module_count; right++) {
      if (catalog->modules[right].capability == module->capability ||
          strcmp(catalog->modules[right].name, module->name) == 0) return false;
    }
  }
  for (left = 0u; left < catalog->module_count; left++) {
    if (!ftun_core_module_catalog_visit(catalog, left, states)) return false;
  }
  return true;
}

static ftun_status_t ftun_core_module_select_one(
  const ftun_core_module_catalog_t *catalog, uint32_t built,
  uint32_t capability, uint32_t *selected, uint32_t *visiting)
{
  const ftun_core_module_descriptor_t *module;
  uint32_t dependencies;
  size_t index;
  ftun_status_t status = FTUN_OK;
  if ((*selected & capability) != 0u) return FTUN_OK;
  if ((built & capability) == 0u ||
      !ftun_core_module_find(catalog, capability, &index)) {
    return FTUN_E_UNSUPPORTED;
  }
  if ((*visiting & capability) != 0u) return FTUN_E_STATE_CORRUPT;
  *visiting |= capability;
  module = &catalog->modules[index];
  dependencies = module->dependencies;
  while (status == FTUN_OK && dependencies != 0u) {
    uint32_t dependency = dependencies & (~dependencies + 1u);
    status = ftun_core_module_select_one(catalog, built, dependency,
                                         selected, visiting);
    dependencies &= ~dependency;
  }
  *visiting &= ~capability;
  if (status == FTUN_OK) *selected |= capability;
  return status;
}

static ftun_status_t ftun_core_module_order(
  const ftun_core_module_catalog_t *catalog, uint32_t selected,
  ftun_core_module_selection_t *out)
{
  uint32_t visited = 0u;
  while (visited != selected) {
    const ftun_core_module_descriptor_t *best = NULL;
    size_t best_index = 0u;
    size_t index;
    for (index = 0u; index < catalog->module_count; index++) {
      const ftun_core_module_descriptor_t *candidate =
        &catalog->modules[index];
      if ((selected & candidate->capability) == 0u ||
          (visited & candidate->capability) != 0u ||
          (candidate->dependencies & selected & ~visited) != 0u) continue;
      if (best == NULL || candidate->startup_order < best->startup_order ||
          (candidate->startup_order == best->startup_order &&
           candidate->capability < best->capability)) {
        best = candidate;
        best_index = index;
      }
    }
    if (best == NULL) return FTUN_E_STATE_CORRUPT;
    if (out->count >= FTUN_CORE_MODULE_LIMIT) return FTUN_E_LIMIT;
    out->order[out->count++] = best_index;
    if (best->service != NULL) out->service_count++;
    visited |= best->capability;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_core_module_compile(
  const ftun_core_module_catalog_t *catalog, const ftun_config_t *config,
  ftun_core_module_selection_t *out, ftun_diagnostic_t *diagnostic)
{
  uint32_t required;
  uint32_t visiting = 0u;
  uint32_t optional;
  ftun_status_t status = FTUN_OK;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (!ftun_core_module_catalog_valid(catalog) || config == NULL ||
      config->plan == NULL || out == NULL) {
    return ftun_core_module_diagnostic(diagnostic, FTUN_E_INVALID,
                                       "invalid module catalog or plan");
  }
  required = config->plan->required_modules;
  if ((required & ~(uint32_t)FTUN_BUILD_MODULE_ALL) != 0u) {
    return ftun_core_module_diagnostic(diagnostic, FTUN_E_INVALID,
                                       "unknown required module");
  }
  while (status == FTUN_OK && required != 0u) {
    uint32_t capability = required & (~required + 1u);
    status = ftun_core_module_select_one(catalog, config->plan->built_modules,
                                         capability, &out->selected,
                                         &visiting);
    required &= ~capability;
  }
  if (status != FTUN_OK) {
    return ftun_core_module_diagnostic(diagnostic, FTUN_E_UNSUPPORTED,
                                       "required module is unavailable");
  }
  optional = catalog->optional_modules;
  while (optional != 0u) {
    uint32_t capability = optional & (~optional + 1u);
    uint32_t candidate = out->selected;
    visiting = 0u;
    status = ftun_core_module_select_one(catalog,
      config->plan->built_modules, capability, &candidate, &visiting);
    if (status == FTUN_OK) out->selected = candidate;
    else if (status == FTUN_E_UNSUPPORTED) out->skipped_optional |= capability;
    else return ftun_core_module_diagnostic(diagnostic, status,
                                             "invalid optional dependency");
    optional &= ~capability;
  }
  out->required = config->plan->required_modules;
  status = ftun_core_module_order(catalog, out->selected, out);
  if (status != FTUN_OK) {
    return ftun_core_module_diagnostic(diagnostic, status,
                                       "module dependency ordering failed");
  }
  if (diagnostic != NULL) memset(diagnostic, 0, sizeof(*diagnostic));
  return FTUN_OK;
}

ftun_status_t ftun_core_module_reload_plan_prepare(
  const ftun_core_module_catalog_t *catalog, ftun_budget_t *budget, const ftun_config_t *config,
  uint32_t socket_mark, ftun_core_module_reload_plan_t **out,
  ftun_diagnostic_t *diagnostic)
{
  ftun_core_module_reload_plan_t *plan;
  ftun_reservation_t *reservation = NULL;
  ftun_core_module_selection_t selection;
  ftun_status_t status;
  size_t index;
  if (out == NULL || budget == NULL) return FTUN_E_INVALID;
  if (*out != NULL) return FTUN_E_AGAIN;
  status = ftun_core_module_compile(catalog, config, &selection, diagnostic);
  if (status != FTUN_OK) return status;
  status = ftun_budget_reserve(budget, sizeof(*plan), &reservation);
  if (status != FTUN_OK) return status;
  plan = (ftun_core_module_reload_plan_t *)calloc(1u, sizeof(*plan));
  if (plan == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  plan->reservation = reservation;
  plan->catalog = catalog;
  plan->required_modules = selection.required;
  plan->selected_modules = selection.selected;
  plan->skipped_optional = selection.skipped_optional;
  plan->entry_count = selection.count;
  for (index = 0u; index < selection.count; index++) {
    const ftun_core_module_descriptor_t *module =
      &catalog->modules[selection.order[index]];
    plan->entries[index].descriptor = module;
    if (module->service == NULL) continue;
    status = ftun_core_service_plan_prepare(module->service, budget, config,
      socket_mark, &plan->entries[index].service_plan);
    if (status != FTUN_OK) {
      plan->first_error = status;
      plan->cleanup_only = true;
      (void)ftun_core_module_reload_plan_destroy(&plan);
      *out = plan;
      return status;
    }
  }
  *out = plan;
  return FTUN_OK;
}

ftun_status_t ftun_core_module_reload_plan_destroy(
  ftun_core_module_reload_plan_t **plan)
{
  ftun_core_module_reload_plan_t *owned;
  size_t index;
  if (plan == NULL) return FTUN_E_INVALID;
  owned = *plan;
  if (owned == NULL) return FTUN_OK;
  owned->cleanup_only = true;
  for (index = owned->entry_count; index != 0u; index--) {
    ftun_core_module_reload_entry_t *entry = &owned->entries[index - 1u];
    ftun_status_t status;
    if (entry->descriptor == NULL || entry->descriptor->service == NULL) {
      continue;
    }
    status = ftun_core_service_plan_destroy(&entry->service_plan);
    if (status != FTUN_OK) {
      ftun_core_module_record(&owned->cleanup_error, status);
      return status;
    }
  }
  {
    ftun_status_t status = ftun_reservation_release(&owned->reservation);
    if (status != FTUN_OK) {
      ftun_core_module_record(&owned->cleanup_error, status);
      return status;
    }
  }
  free(owned);
  *plan = NULL;
  return FTUN_OK;
}

ftun_status_t ftun_core_module_reload_plan_get_errors(
  const ftun_core_module_reload_plan_t *plan,
  ftun_status_t *first_error, ftun_status_t *cleanup_error)
{
  if (plan == NULL || first_error == NULL || cleanup_error == NULL) {
    return FTUN_E_INVALID;
  }
  *first_error = plan->first_error;
  *cleanup_error = plan->cleanup_error;
  return FTUN_OK;
}

ftun_status_t ftun_core_module_runtime_prepare(
  const ftun_core_module_catalog_t *catalog, ftun_core_t *core,
  ftun_budget_t *budget, ftun_operation_queue_t *operations,
  const ftun_config_t *config, uint64_t generation,
  ftun_core_module_runtime_t **out, ftun_diagnostic_t *diagnostic)
{
  ftun_core_module_runtime_t *runtime;
  ftun_reservation_t *reservation = NULL;
  ftun_core_module_selection_t selection;
  ftun_status_t status;
  size_t index;
  size_t service_index = 0u;
  if (core == NULL || budget == NULL || operations == NULL || out == NULL ||
      generation == 0u) return FTUN_E_INVALID;
  if (*out != NULL) return FTUN_E_AGAIN;
  status = ftun_core_module_compile(catalog, config, &selection, diagnostic);
  if (status != FTUN_OK) return status;
  status = ftun_budget_reserve(budget, sizeof(*runtime), &reservation);
  if (status != FTUN_OK) return status;
  runtime = (ftun_core_module_runtime_t *)calloc(1u, sizeof(*runtime));
  if (runtime == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  runtime->reservation = reservation;
  atomic_init(&runtime->wake_pending, false);
  runtime->core = core;
  runtime->generation = generation;
  runtime->built_modules = config->plan->built_modules;
  runtime->catalog = catalog;
  runtime->required_modules = selection.required;
  runtime->selected_modules = selection.selected;
  runtime->skipped_optional = selection.skipped_optional;
  runtime->entry_count = selection.count;
  runtime->service_count = selection.service_count;
  ftun_core_module_selection_events(runtime);
  /* 完整描述符先就位，失败清理可以安全遍历尚未进入 prepare 的条目。 */
  for (index = 0u; index < selection.count; index++) {
    ftun_core_module_entry_t *entry = &runtime->entries[index];
    entry->descriptor = &catalog->modules[selection.order[index]];
    entry->phase = FTUN_MODULE_SELECTED;
    if (entry->descriptor->service != NULL) {
      runtime->service_entries[service_index++] = index;
    }
  }
  for (index = 0u; index < selection.count; index++) {
    ftun_core_module_entry_t *entry = &runtime->entries[index];
    ftun_core_module_event(runtime, entry->descriptor->capability,
      FTUN_LIFECYCLE_MODULE_PREPARING, FTUN_OK, FTUN_LIFECYCLE_REASON_NONE);
    if (entry->descriptor->service == NULL) {
      ftun_core_module_phase(runtime, entry, FTUN_MODULE_PREPARED);
      continue;
    }
    status = ftun_core_service_prepare(&entry->service,
      entry->descriptor->service, core, budget, operations,
      &entry->descriptor->binding, config, generation);
    if (status != FTUN_OK) {
      uint64_t now_ms = 0u;
      ftun_status_t cleanup = ftun_monotonic_now(&now_ms);
      ftun_core_module_event(runtime, entry->descriptor->capability,
        FTUN_LIFECYCLE_MODULE_FAILED, status, FTUN_LIFECYCLE_REASON_NONE);
      ftun_core_module_event(runtime, 0u, FTUN_LIFECYCLE_ROLLBACK, status,
        FTUN_LIFECYCLE_REASON_NONE);
      runtime->first_error = status;
      runtime->cleanup_only = true;
      if (cleanup == FTUN_OK) {
        cleanup = ftun_core_module_runtime_destroy_until(&runtime,
          now_ms == 0u ? 1u : now_ms);
      }
      if (runtime != NULL) {
        ftun_core_module_record(&runtime->cleanup_error, cleanup);
      }
      *out = runtime;
      return status;
    }
    ftun_core_module_phase(runtime, entry, FTUN_MODULE_PREPARED);
  }
  *out = runtime;
  return FTUN_OK;
}

static ftun_status_t ftun_core_module_runtime_rollback(
  ftun_core_module_runtime_t *runtime, uint64_t deadline_ms)
{
  ftun_status_t result;
  size_t index;
  result = ftun_core_module_runtime_drain_until(runtime, deadline_ms);
  if (result != FTUN_OK) return result;
  result = ftun_core_module_runtime_reload_abort(runtime);
  if (result != FTUN_OK) return result;
  for (index = runtime->entry_count; index != 0u; index--) {
    ftun_core_module_entry_t *entry = &runtime->entries[index - 1u];
    ftun_status_t status;
    if (entry->descriptor->service == NULL) {
      ftun_core_module_phase(runtime, entry, FTUN_MODULE_DESTROYED);
      continue;
    }
    if (entry->service.implementation == NULL) {
      ftun_core_module_phase(runtime, entry, FTUN_MODULE_DESTROYED);
      continue;
    }
    status = ftun_core_service_destroy_until(&entry->service, deadline_ms);
    ftun_core_module_failure(runtime, entry, status, FTUN_LIFECYCLE_REASON_DESTROY);
    if (status != FTUN_OK) {
      ftun_core_module_record(&runtime->cleanup_error, status);
      return status;
    }
    ftun_core_module_phase(runtime, entry, FTUN_MODULE_DESTROYED);
  }
  runtime->rolled_back = true;
  runtime->activated = false;
  return FTUN_OK;
}

ftun_status_t ftun_core_module_runtime_activate(
  ftun_core_module_runtime_t *runtime, uint64_t rollback_deadline_ms)
{
  ftun_status_t status = FTUN_OK;
  size_t index;
  if (runtime == NULL || rollback_deadline_ms == 0u) return FTUN_E_INVALID;
  if (runtime->activated || runtime->rolled_back || runtime->cleanup_only) {
    return FTUN_E_STALE;
  }
  if (runtime->service_count == 0u) return FTUN_E_UNSUPPORTED;
  for (index = 0u; index < runtime->entry_count; index++) {
    ftun_core_module_entry_t *entry = &runtime->entries[index];
    /* activate 失败也可能已启动部分生产者，必须参加 quiesce/drain。 */
    entry->phase = FTUN_MODULE_ACTIVE;
    if (entry->descriptor->service != NULL) {
      status = ftun_core_service_activate(&entry->service);
      if (status != FTUN_OK) {
        ftun_core_module_event(runtime, entry->descriptor->capability,
          FTUN_LIFECYCLE_MODULE_FAILED, status, FTUN_LIFECYCLE_REASON_NONE);
        break;
      }
    }
    ftun_core_module_event(runtime, entry->descriptor->capability,
      FTUN_LIFECYCLE_MODULE_ACTIVE, FTUN_OK, FTUN_LIFECYCLE_REASON_NONE);
  }
  if (status != FTUN_OK) {
    uint64_t now_ms = 0u;
    ftun_status_t rollback = ftun_monotonic_now(&now_ms);
    ftun_core_module_event(runtime, 0u, FTUN_LIFECYCLE_ROLLBACK, status,
      FTUN_LIFECYCLE_REASON_NONE);
    ftun_core_module_record(&runtime->first_error, status);
    runtime->cleanup_only = true;
    if (rollback == FTUN_OK) {
      if (now_ms == 0u) now_ms = 1u;
      if (rollback_deadline_ms < now_ms) now_ms = rollback_deadline_ms;
      rollback = ftun_core_module_runtime_rollback(runtime, now_ms);
    }
    ftun_core_module_record(&runtime->cleanup_error, rollback);
    return status;
  }
  runtime->activated = true;
  return FTUN_OK;
}

static int ftun_core_module_service_sets_equal(
  const ftun_core_module_runtime_t *runtime,
  const ftun_core_module_reload_plan_t *plan)
{
  size_t index;
  for (index = 0u; index < runtime->entry_count; index++) {
    const ftun_core_module_descriptor_t *module =
      runtime->entries[index].descriptor;
    if (module->service != NULL &&
        (plan->selected_modules & module->capability) == 0u) return 0;
  }
  for (index = 0u; index < plan->entry_count; index++) {
    const ftun_core_module_descriptor_t *module =
      plan->entries[index].descriptor;
    if (module->service != NULL &&
        (runtime->selected_modules & module->capability) == 0u) return 0;
  }
  return 1;
}

static int ftun_core_module_catalogs_compatible(
  const ftun_core_module_catalog_t *left,
  const ftun_core_module_catalog_t *right)
{
  size_t index;
  if (!ftun_core_module_catalog_valid(left) ||
      !ftun_core_module_catalog_valid(right) ||
      left->module_count != right->module_count ||
      left->optional_modules != right->optional_modules) return 0;
  for (index = 0u; index < left->module_count; index++) {
    const ftun_core_module_descriptor_t *a = &left->modules[index];
    const ftun_core_module_descriptor_t *b;
    size_t other;
    if (!ftun_core_module_find(right, a->capability, &other)) return 0;
    b = &right->modules[other];
    if (strcmp(a->name, b->name) != 0 ||
        a->dependencies != b->dependencies ||
        a->startup_order != b->startup_order ||
        a->service != b->service) return 0;
  }
  return 1;
}

static ftun_core_module_reload_entry_t *ftun_core_module_reload_find(
  const ftun_core_module_reload_plan_t *plan, uint32_t capability)
{
  size_t index;
  for (index = 0u; index < plan->entry_count; index++) {
    if (plan->entries[index].descriptor->capability == capability) {
      return (ftun_core_module_reload_entry_t *)&plan->entries[index];
    }
  }
  return NULL;
}

static size_t ftun_core_module_reload_pending(
  const ftun_core_module_runtime_t *runtime)
{
  size_t count = 0u;
  size_t index;
  for (index = 0u; index < runtime->entry_count; index++) {
    if (runtime->entries[index].reload_pending) count++;
  }
  return count;
}

ftun_status_t ftun_core_module_runtime_reload_prepare_planned(
  ftun_core_module_runtime_t *runtime, const ftun_config_t *config,
  uint64_t generation, const ftun_core_module_reload_plan_t *plan)
{
  ftun_status_t status = FTUN_OK;
  size_t index;
  if (runtime == NULL || config == NULL || generation == 0u || plan == NULL ||
      !ftun_core_module_catalogs_compatible(
        plan->catalog, runtime->catalog)) return FTUN_E_INVALID;
  if (!runtime->activated || runtime->cleanup_only || plan->cleanup_only ||
      runtime->reload_prepared || ftun_core_module_reload_pending(runtime) != 0u) {
    return FTUN_E_STALE;
  }
  if (!ftun_core_module_service_sets_equal(runtime, plan)) {
    return FTUN_E_RESTART_REQUIRED;
  }
  for (index = 0u; index < runtime->entry_count; index++) {
    ftun_core_module_entry_t *entry = &runtime->entries[index];
    ftun_core_module_reload_entry_t *prepared;
    if (entry->descriptor->service == NULL) continue;
    prepared = ftun_core_module_reload_find(plan,
      entry->descriptor->capability);
    if (prepared == NULL) {
      status = FTUN_E_STATE_CORRUPT;
      break;
    }
    entry->reload_pending = true;
    status = ftun_core_service_reload_prepare_planned(&entry->service,
      config, generation, &prepared->service_plan);
    ftun_core_module_failure(runtime, entry, status, FTUN_LIFECYCLE_REASON_RELOAD_PREPARE);
    if (status != FTUN_OK) break;
  }
  if (status != FTUN_OK) {
    ftun_core_module_record(&runtime->first_error, status);
    (void)ftun_core_module_runtime_reload_abort(runtime);
    return status;
  }
  runtime->pending_required_modules = plan->required_modules;
  runtime->pending_selected_modules = plan->selected_modules;
  runtime->pending_skipped_optional = plan->skipped_optional;
  runtime->reload_prepared = true;
  return FTUN_OK;
}

ftun_status_t ftun_core_module_runtime_reload_prepare(
  ftun_core_module_runtime_t *runtime, const ftun_config_t *config,
  uint64_t generation)
{
  ftun_core_module_selection_t selection;
  ftun_status_t status;
  size_t index;
  if (runtime == NULL || config == NULL || generation == 0u) {
    return FTUN_E_INVALID;
  }
  if (!runtime->activated || runtime->cleanup_only || runtime->reload_prepared ||
      ftun_core_module_reload_pending(runtime) != 0u) return FTUN_E_STALE;
  status = ftun_core_module_compile(runtime->catalog, config, &selection,
                                    NULL);
  if (status != FTUN_OK) return status;
  for (index = 0u; index < runtime->entry_count; index++) {
    const ftun_core_module_descriptor_t *module =
      runtime->entries[index].descriptor;
    if (module->service != NULL &&
        (selection.selected & module->capability) == 0u) {
      return FTUN_E_RESTART_REQUIRED;
    }
  }
  for (index = 0u; index < selection.count; index++) {
    const ftun_core_module_descriptor_t *module =
      &runtime->catalog->modules[selection.order[index]];
    if (module->service != NULL &&
        (runtime->selected_modules & module->capability) == 0u) {
      return FTUN_E_RESTART_REQUIRED;
    }
  }
  for (index = 0u; index < runtime->entry_count; index++) {
    ftun_core_module_entry_t *entry = &runtime->entries[index];
    if (entry->descriptor->service == NULL) continue;
    entry->reload_pending = true;
    status = ftun_core_service_reload_prepare(&entry->service, config,
                                              generation);
    ftun_core_module_failure(runtime, entry, status, FTUN_LIFECYCLE_REASON_RELOAD_PREPARE);
    if (status != FTUN_OK) break;
  }
  if (status != FTUN_OK) {
    ftun_core_module_record(&runtime->first_error, status);
    (void)ftun_core_module_runtime_reload_abort(runtime);
    return status;
  }
  runtime->pending_required_modules = selection.required;
  runtime->pending_selected_modules = selection.selected;
  runtime->pending_skipped_optional = selection.skipped_optional;
  runtime->reload_prepared = true;
  return FTUN_OK;
}

ftun_status_t ftun_core_module_runtime_reload_commit(
  ftun_core_module_runtime_t *runtime, uint64_t generation)
{
  ftun_status_t status = FTUN_OK;
  size_t index;
  if (runtime == NULL || generation == 0u) return FTUN_E_INVALID;
  if (!runtime->reload_prepared || runtime->cleanup_only) return FTUN_E_STALE;
  for (index = 0u; index < runtime->entry_count; index++) {
    ftun_core_module_entry_t *entry = &runtime->entries[index];
    if (entry->descriptor->service == NULL) continue;
    status = ftun_core_service_reload_commit(&entry->service, generation);
    ftun_core_module_failure(runtime, entry, status, FTUN_LIFECYCLE_REASON_RELOAD_COMMIT);
    if (status != FTUN_OK) {
      ftun_core_module_record(&runtime->first_error, status);
      runtime->cleanup_only = true;
      return status;
    }
    entry->reload_pending = false;
  }
  runtime->required_modules = runtime->pending_required_modules;
  runtime->selected_modules = runtime->pending_selected_modules;
  runtime->skipped_optional = runtime->pending_skipped_optional;
  runtime->generation = generation;
  ftun_core_module_selection_events(runtime);
  runtime->pending_required_modules = 0u;
  runtime->pending_selected_modules = 0u;
  runtime->pending_skipped_optional = 0u;
  runtime->reload_prepared = false;
  return FTUN_OK;
}

ftun_status_t ftun_core_module_runtime_reload_abort(
  ftun_core_module_runtime_t *runtime)
{
  size_t index;
  if (runtime == NULL) return FTUN_E_INVALID;
  for (index = runtime->entry_count; index != 0u; index--) {
    ftun_core_module_entry_t *entry = &runtime->entries[index - 1u];
    ftun_status_t status;
    if (!entry->reload_pending) continue;
    status = ftun_core_service_reload_abort(&entry->service);
    ftun_core_module_failure(runtime, entry, status, FTUN_LIFECYCLE_REASON_RELOAD_ABORT);
    if (status != FTUN_OK) {
      ftun_core_module_record(&runtime->cleanup_error, status);
      return status;
    }
    entry->reload_pending = false;
  }
  runtime->pending_required_modules = 0u;
  runtime->pending_selected_modules = 0u;
  runtime->pending_skipped_optional = 0u;
  runtime->reload_prepared = false;
  return FTUN_OK;
}

static void ftun_core_module_usage_add(ftun_core_service_run_usage_t *target,
                                       const ftun_core_service_run_usage_t *add)
{
  size_t index;
  target->work = add->work > SIZE_MAX - target->work
    ? SIZE_MAX : target->work + add->work;
  target->busy_ms = add->busy_ms > UINT64_MAX - target->busy_ms
    ? UINT64_MAX : target->busy_ms + add->busy_ms;
  if (add->deadline_lateness_ms > target->deadline_lateness_ms) {
    target->deadline_lateness_ms = add->deadline_lateness_ms;
  }
  target->quota_exhausted = target->quota_exhausted || add->quota_exhausted;
  target->fatal = target->fatal || add->fatal;
  for (index = 0u; index < FTUN_FAULT_SCOPE_COUNT; index++) {
    target->faults[index] += add->faults[index];
  }
}

ftun_status_t ftun_core_module_runtime_run_once(
  ftun_core_module_runtime_t *runtime, bool may_block,
  ftun_core_service_run_usage_t *out_usage)
{
  size_t active_services = 0u;
  size_t index;
  ftun_status_t status = FTUN_OK;
  ftun_status_t first_fault = FTUN_OK;
  if (out_usage != NULL) memset(out_usage, 0, sizeof(*out_usage));
  if (runtime == NULL || out_usage == NULL || !runtime->activated ||
      runtime->rolled_back || runtime->cleanup_only) return FTUN_E_INVALID;
  for (index = 0u; index < runtime->service_count; index++) {
    if (runtime->entries[runtime->service_entries[index]].phase ==
        FTUN_MODULE_ACTIVE) active_services++;
  }
  if (active_services == 0u) return FTUN_E_UNSUPPORTED;
  if (active_services == 1u) {
    for (index = 0u; index < runtime->service_count; index++) {
      ftun_core_module_entry_t *entry =
        &runtime->entries[runtime->service_entries[index]];
      if (entry->phase == FTUN_MODULE_ACTIVE) {
        if (atomic_exchange_explicit(&runtime->wake_pending, false,
              memory_order_acq_rel)) may_block = false;
        status = ftun_core_service_run_once(&entry->service, may_block, out_usage);
        if (status != FTUN_OK) ftun_core_module_event(runtime, entry->descriptor->capability,
          FTUN_LIFECYCLE_MODULE_FAILED, status, FTUN_LIFECYCLE_REASON_RUN);
        return status;
      }
    }
  }
  /* 非致命故障只记录第一个，其余服务本轮照常运行；致命故障立即返回。 */
  for (index = 0u; index < runtime->service_count; index++) {
    ftun_core_service_run_usage_t usage;
    ftun_core_module_entry_t *entry =
      &runtime->entries[runtime->service_entries[index]];
    if (entry->phase != FTUN_MODULE_ACTIVE) continue;
    status = ftun_core_service_run_once(&entry->service, false, &usage);
    if (status != FTUN_OK) ftun_core_module_event(runtime, entry->descriptor->capability,
      FTUN_LIFECYCLE_MODULE_FAILED, status, FTUN_LIFECYCLE_REASON_RUN);
    ftun_core_module_usage_add(out_usage, &usage);
    if (ftun_core_service_run_fatal(status, &usage)) {
      return status == FTUN_OK ? FTUN_E_STATE_CORRUPT : status;
    }
    if (status != FTUN_OK && first_fault == FTUN_OK) first_fault = status;
  }
  status = FTUN_OK;
  /* 共享 Event 的非阻塞轮询可能消费跨线程唤醒；本轮须先返回宿主，
   * 让控制请求被观察。检查之后到达的唤醒由后续唯一阻塞等待接收。 */
  if (atomic_exchange_explicit(&runtime->wake_pending, false,
        memory_order_acq_rel)) may_block = false;
  if (first_fault == FTUN_OK && may_block && out_usage->work == 0u &&
      !out_usage->quota_exhausted) {
    size_t target = runtime->block_cursor++ % active_services;
    size_t ordinal = 0u;
    for (index = 0u; index < runtime->service_count; index++) {
      ftun_core_service_run_usage_t usage;
      ftun_core_module_entry_t *entry =
        &runtime->entries[runtime->service_entries[index]];
      if (entry->phase != FTUN_MODULE_ACTIVE) continue;
      if (ordinal++ != target) continue;
      status = ftun_core_service_run_once(&entry->service, true, &usage);
      if (status != FTUN_OK) ftun_core_module_event(runtime, entry->descriptor->capability,
        FTUN_LIFECYCLE_MODULE_FAILED, status, FTUN_LIFECYCLE_REASON_RUN);
      ftun_core_module_usage_add(out_usage, &usage);
      if (ftun_core_service_run_fatal(status, &usage)) {
        return status == FTUN_OK ? FTUN_E_STATE_CORRUPT : status;
      }
      if (status != FTUN_OK) first_fault = status;
      break;
    }
  }
  return first_fault;
}

ftun_status_t ftun_core_module_runtime_wakeup(
  ftun_core_module_runtime_t *runtime)
{
  ftun_status_t result = FTUN_OK;
  size_t index;
  if (runtime == NULL) return FTUN_E_INVALID;
  atomic_store_explicit(&runtime->wake_pending, true, memory_order_release);
  for (index = 0u; index < runtime->entry_count; index++) {
    ftun_core_module_entry_t *entry = &runtime->entries[index];
    ftun_status_t status;
    if (entry->descriptor->service == NULL ||
        entry->service.implementation == NULL) continue;
    status = ftun_core_service_wakeup(&entry->service);
    if (status != FTUN_OK && result == FTUN_OK) result = status;
  }
  return result;
}

void ftun_core_module_runtime_network_changed(
  ftun_core_module_runtime_t *runtime, const ftun_network_change_t *change,
  uint64_t now_ms)
{
  size_t index;
  if (runtime == NULL || change == NULL || runtime->rolled_back ||
      runtime->cleanup_only) return;
  for (index = 0u; index < runtime->entry_count; index++) {
    ftun_core_module_entry_t *entry = &runtime->entries[index];
    if (entry->descriptor->service == NULL ||
        entry->service.implementation == NULL) continue;
    ftun_core_service_network_changed(&entry->service, change, now_ms);
  }
}

ftun_status_t ftun_core_module_runtime_quiesce(
  ftun_core_module_runtime_t *runtime)
{
  ftun_status_t result = FTUN_OK;
  size_t index;
  if (runtime == NULL) return FTUN_E_INVALID;
  if (runtime->rolled_back) return FTUN_OK;
  runtime->cleanup_only = true;
  for (index = runtime->entry_count; index != 0u; index--) {
    ftun_core_module_entry_t *entry = &runtime->entries[index - 1u];
    ftun_status_t status;
    if (entry->phase == FTUN_MODULE_ACTIVE &&
        entry->descriptor->service == NULL) {
      ftun_core_module_phase(runtime, entry, FTUN_MODULE_QUIESCED);
      continue;
    }
    if (entry->phase != FTUN_MODULE_ACTIVE ||
        entry->descriptor->service == NULL) continue;
    status = ftun_core_service_quiesce(&entry->service);
    ftun_core_module_failure(runtime, entry, status, FTUN_LIFECYCLE_REASON_QUIESCE);
    if (status == FTUN_OK) ftun_core_module_phase(runtime, entry, FTUN_MODULE_QUIESCED);
    else if (result == FTUN_OK) result = status;
  }
  ftun_core_module_record(&runtime->cleanup_error, result);
  return result;
}

ftun_status_t ftun_core_module_runtime_drain_until(
  ftun_core_module_runtime_t *runtime, uint64_t deadline_ms)
{
  ftun_status_t status;
  size_t index;
  if (runtime == NULL || deadline_ms == 0u) return FTUN_E_INVALID;
  if (runtime->rolled_back) return FTUN_OK;
  status = ftun_core_module_runtime_quiesce(runtime);
  if (status != FTUN_OK) return status;
  for (index = runtime->entry_count; index != 0u; index--) {
    ftun_core_module_entry_t *entry = &runtime->entries[index - 1u];
    if (entry->phase == FTUN_MODULE_DRAINED ||
        entry->phase == FTUN_MODULE_DESTROYED ||
        entry->phase == FTUN_MODULE_SELECTED ||
        entry->phase == FTUN_MODULE_PREPARED) continue;
    if (entry->descriptor->service == NULL) {
      ftun_core_module_phase(runtime, entry, FTUN_MODULE_DRAINED);
      continue;
    }
    status = ftun_core_service_drain_until(&entry->service, deadline_ms);
    ftun_core_module_failure(runtime, entry, status, FTUN_LIFECYCLE_REASON_DRAIN);
    if (status != FTUN_OK) {
      ftun_core_module_record(&runtime->cleanup_error, status);
      return status;
    }
    ftun_core_module_phase(runtime, entry, FTUN_MODULE_DRAINED);
  }
  return FTUN_OK;
}

ftun_status_t ftun_core_module_runtime_stop_until(
  ftun_core_module_runtime_t *runtime, uint64_t deadline_ms)
{
  return ftun_core_module_runtime_drain_until(runtime, deadline_ms);
}

ftun_status_t ftun_core_module_runtime_destroy_until(
  ftun_core_module_runtime_t **runtime, uint64_t deadline_ms)
{
  ftun_core_module_runtime_t *owned;
  ftun_reservation_t *reservation;
  ftun_status_t status;
  size_t index;
  if (runtime == NULL || deadline_ms == 0u) return FTUN_E_INVALID;
  owned = *runtime;
  if (owned == NULL) return FTUN_OK;
  if (!owned->rolled_back) {
    status = ftun_core_module_runtime_drain_until(owned, deadline_ms);
    if (status != FTUN_OK) return status;
  }
  status = ftun_core_module_runtime_reload_abort(owned);
  if (status != FTUN_OK) return status;
  for (index = owned->entry_count; index != 0u; index--) {
    ftun_core_module_entry_t *entry = &owned->entries[index - 1u];
    if (entry->descriptor->service == NULL) {
      ftun_core_module_phase(owned, entry, FTUN_MODULE_DESTROYED);
      continue;
    }
    if (entry->service.implementation == NULL) {
      ftun_core_module_phase(owned, entry, FTUN_MODULE_DESTROYED);
      continue;
    }
    status = ftun_core_service_destroy_until(&entry->service, deadline_ms);
    ftun_core_module_failure(owned, entry, status, FTUN_LIFECYCLE_REASON_DESTROY);
    if (status != FTUN_OK) {
      ftun_core_module_record(&owned->cleanup_error, status);
      return status;
    }
    ftun_core_module_phase(owned, entry, FTUN_MODULE_DESTROYED);
  }
  reservation = owned->reservation;
  free(owned);
  *runtime = NULL;
  return ftun_reservation_release(&reservation);
}

ftun_status_t ftun_core_module_runtime_get_info(
  const ftun_core_module_runtime_t *runtime, ftun_core_module_info_t *out)
{
  size_t index;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (runtime == NULL || out == NULL) return FTUN_E_INVALID;
  out->required_modules = runtime->required_modules;
  out->selected_modules = runtime->selected_modules;
  out->skipped_optional = runtime->skipped_optional;
  out->module_count = runtime->entry_count;
  out->service_count = runtime->service_count;
  out->reload_prepared = runtime->reload_prepared;
  out->rolled_back = runtime->rolled_back;
  out->cleanup_only = runtime->cleanup_only;
  out->reload_pending_count = ftun_core_module_reload_pending(runtime);
  out->first_error = runtime->first_error;
  out->cleanup_error = runtime->cleanup_error;
  for (index = 0u; index < runtime->entry_count; index++) {
    switch (runtime->entries[index].phase) {
      case FTUN_MODULE_PREPARED: out->prepared_count++; break;
      case FTUN_MODULE_ACTIVE: out->active_count++; break;
      case FTUN_MODULE_QUIESCED: out->quiesced_count++; break;
      case FTUN_MODULE_DRAINED: out->drained_count++; break;
      default: break;
    }
  }
  return FTUN_OK;
}
