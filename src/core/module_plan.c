#include "core/module_plan.h"

#include "config/compile.h"

#include <stdlib.h>
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
  const ftun_core_module_catalog_t *catalog;
  ftun_core_module_reload_entry_t entries[FTUN_CORE_MODULE_LIMIT];
  uint32_t required_modules;
  uint32_t selected_modules;
  uint32_t skipped_optional;
  size_t entry_count;
};

struct ftun_core_module_runtime {
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
  bool activated;
  bool reload_prepared;
  bool rolled_back;
};

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
  const ftun_core_module_catalog_t *catalog, const ftun_config_t *config,
  uint32_t socket_mark, ftun_core_module_reload_plan_t **out,
  ftun_diagnostic_t *diagnostic)
{
  ftun_core_module_reload_plan_t *plan;
  ftun_core_module_selection_t selection;
  ftun_status_t status;
  size_t index;
  if (out != NULL) *out = NULL;
  if (out == NULL) return FTUN_E_INVALID;
  status = ftun_core_module_compile(catalog, config, &selection, diagnostic);
  if (status != FTUN_OK) return status;
  plan = (ftun_core_module_reload_plan_t *)calloc(1u, sizeof(*plan));
  if (plan == NULL) return FTUN_E_LIMIT;
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
    status = ftun_core_service_plan_prepare(module->service, config,
      socket_mark, &plan->entries[index].service_plan);
    if (status != FTUN_OK) {
      (void)ftun_core_module_reload_plan_destroy(&plan);
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
  for (index = owned->entry_count; index != 0u; index--) {
    ftun_core_module_reload_entry_t *entry = &owned->entries[index - 1u];
    ftun_status_t status;
    if (entry->descriptor == NULL || entry->descriptor->service == NULL) {
      continue;
    }
    status = ftun_core_service_plan_destroy(&entry->service_plan);
    if (status != FTUN_OK) return status;
  }
  free(owned);
  *plan = NULL;
  return FTUN_OK;
}

ftun_status_t ftun_core_module_runtime_prepare(
  const ftun_core_module_catalog_t *catalog, ftun_core_t *core,
  ftun_budget_t *budget, ftun_operation_queue_t *operations,
  const ftun_config_t *config, uint64_t generation,
  ftun_core_module_runtime_t **out, ftun_diagnostic_t *diagnostic)
{
  ftun_core_module_runtime_t *runtime;
  ftun_core_module_selection_t selection;
  ftun_status_t status;
  size_t index;
  size_t service_index = 0u;
  if (out != NULL) *out = NULL;
  if (core == NULL || budget == NULL || operations == NULL || out == NULL ||
      generation == 0u) return FTUN_E_INVALID;
  status = ftun_core_module_compile(catalog, config, &selection, diagnostic);
  if (status != FTUN_OK) return status;
  runtime = (ftun_core_module_runtime_t *)calloc(1u, sizeof(*runtime));
  if (runtime == NULL) return FTUN_E_LIMIT;
  runtime->catalog = catalog;
  runtime->required_modules = selection.required;
  runtime->selected_modules = selection.selected;
  runtime->skipped_optional = selection.skipped_optional;
  runtime->entry_count = selection.count;
  runtime->service_count = selection.service_count;
  for (index = 0u; index < selection.count; index++) {
    ftun_core_module_entry_t *entry = &runtime->entries[index];
    entry->descriptor = &catalog->modules[selection.order[index]];
    entry->phase = FTUN_MODULE_SELECTED;
    if (entry->descriptor->service == NULL) {
      entry->phase = FTUN_MODULE_PREPARED;
      continue;
    }
    runtime->service_entries[service_index++] = index;
    status = ftun_core_service_prepare(&entry->service,
      entry->descriptor->service, core, budget, operations,
      &entry->descriptor->binding, config, generation);
    if (status != FTUN_OK) {
      size_t rollback;
      for (rollback = index; rollback != 0u; rollback--) {
        ftun_core_module_entry_t *prepared =
          &runtime->entries[rollback - 1u];
        if (prepared->service.implementation != NULL) {
          (void)ftun_core_service_destroy(&prepared->service);
        }
        prepared->phase = FTUN_MODULE_DESTROYED;
      }
      free(runtime);
      return status;
    }
    entry->phase = FTUN_MODULE_PREPARED;
  }
  *out = runtime;
  return FTUN_OK;
}

static ftun_status_t ftun_core_module_runtime_rollback(
  ftun_core_module_runtime_t *runtime, uint64_t deadline_ms)
{
  ftun_status_t result = FTUN_OK;
  size_t index;
  for (index = runtime->entry_count; index != 0u; index--) {
    ftun_core_module_entry_t *entry = &runtime->entries[index - 1u];
    ftun_status_t status;
    if (entry->descriptor->service == NULL ||
        entry->phase != FTUN_MODULE_ACTIVE) continue;
    status = ftun_core_service_quiesce(&entry->service);
    if (status == FTUN_OK) entry->phase = FTUN_MODULE_QUIESCED;
    else if (result == FTUN_OK) result = status;
  }
  for (index = runtime->entry_count; index != 0u; index--) {
    ftun_core_module_entry_t *entry = &runtime->entries[index - 1u];
    ftun_status_t status;
    if (entry->descriptor->service == NULL ||
        entry->service.implementation == NULL) continue;
    status = ftun_core_service_drain_until(&entry->service, deadline_ms);
    if (status == FTUN_OK) entry->phase = FTUN_MODULE_DRAINED;
    else if (result == FTUN_OK) result = status;
  }
  if (result != FTUN_OK) return result;
  for (index = runtime->entry_count; index != 0u; index--) {
    ftun_core_module_entry_t *entry = &runtime->entries[index - 1u];
    ftun_status_t status;
    if (entry->descriptor->service == NULL) {
      entry->phase = FTUN_MODULE_DESTROYED;
      continue;
    }
    if (entry->service.implementation == NULL) continue;
    status = ftun_core_service_destroy_until(&entry->service, deadline_ms);
    if (status != FTUN_OK) return status;
    entry->phase = FTUN_MODULE_DESTROYED;
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
  if (runtime->activated || runtime->rolled_back) return FTUN_E_STALE;
  if (runtime->service_count == 0u) return FTUN_E_UNSUPPORTED;
  for (index = 0u; index < runtime->entry_count; index++) {
    ftun_core_module_entry_t *entry = &runtime->entries[index];
    if (entry->descriptor->service != NULL) {
      status = ftun_core_service_activate(&entry->service);
      if (status != FTUN_OK) break;
    }
    entry->phase = FTUN_MODULE_ACTIVE;
  }
  if (status != FTUN_OK) {
    ftun_status_t rollback = ftun_core_module_runtime_rollback(
      runtime, rollback_deadline_ms);
    return rollback == FTUN_OK ? status : rollback;
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

ftun_status_t ftun_core_module_runtime_reload_prepare_planned(
  ftun_core_module_runtime_t *runtime, const ftun_config_t *config,
  uint64_t generation, const ftun_core_module_reload_plan_t *plan)
{
  ftun_status_t status = FTUN_OK;
  size_t index;
  if (runtime == NULL || config == NULL || generation == 0u || plan == NULL ||
      !ftun_core_module_catalogs_compatible(
        plan->catalog, runtime->catalog)) return FTUN_E_INVALID;
  if (!runtime->activated || runtime->reload_prepared) return FTUN_E_STALE;
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
    status = ftun_core_service_reload_prepare_planned(&entry->service,
      config, generation, &prepared->service_plan);
    if (status != FTUN_OK) break;
  }
  if (status != FTUN_OK) {
    while (index != 0u) {
      index--;
      if (runtime->entries[index].descriptor->service != NULL) {
        (void)ftun_core_service_reload_abort(
          &runtime->entries[index].service);
      }
    }
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
  if (!runtime->activated || runtime->reload_prepared) return FTUN_E_STALE;
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
    status = ftun_core_service_reload_prepare(&entry->service, config,
                                              generation);
    if (status != FTUN_OK) break;
  }
  if (status != FTUN_OK) {
    while (index != 0u) {
      index--;
      if (runtime->entries[index].descriptor->service != NULL) {
        (void)ftun_core_service_reload_abort(
          &runtime->entries[index].service);
      }
    }
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
  if (!runtime->reload_prepared) return FTUN_E_STALE;
  for (index = 0u; index < runtime->entry_count; index++) {
    ftun_core_module_entry_t *entry = &runtime->entries[index];
    if (entry->descriptor->service == NULL) continue;
    status = ftun_core_service_reload_commit(&entry->service, generation);
    if (status != FTUN_OK) return status;
  }
  runtime->required_modules = runtime->pending_required_modules;
  runtime->selected_modules = runtime->pending_selected_modules;
  runtime->skipped_optional = runtime->pending_skipped_optional;
  runtime->pending_required_modules = 0u;
  runtime->pending_selected_modules = 0u;
  runtime->pending_skipped_optional = 0u;
  runtime->reload_prepared = false;
  return FTUN_OK;
}

ftun_status_t ftun_core_module_runtime_reload_abort(
  ftun_core_module_runtime_t *runtime)
{
  ftun_status_t result = FTUN_OK;
  size_t index;
  if (runtime == NULL) return FTUN_E_INVALID;
  if (!runtime->reload_prepared) return FTUN_OK;
  for (index = runtime->entry_count; index != 0u; index--) {
    ftun_core_module_entry_t *entry = &runtime->entries[index - 1u];
    ftun_status_t status;
    if (entry->descriptor->service == NULL) continue;
    status = ftun_core_service_reload_abort(&entry->service);
    if (status != FTUN_OK && result == FTUN_OK) result = status;
  }
  if (result == FTUN_OK) {
    runtime->pending_required_modules = 0u;
    runtime->pending_selected_modules = 0u;
    runtime->pending_skipped_optional = 0u;
    runtime->reload_prepared = false;
  }
  return result;
}

static void ftun_core_module_usage_add(ftun_core_service_run_usage_t *target,
                                       const ftun_core_service_run_usage_t *add)
{
  target->work = add->work > SIZE_MAX - target->work
    ? SIZE_MAX : target->work + add->work;
  target->busy_ms = add->busy_ms > UINT64_MAX - target->busy_ms
    ? UINT64_MAX : target->busy_ms + add->busy_ms;
  if (add->deadline_lateness_ms > target->deadline_lateness_ms) {
    target->deadline_lateness_ms = add->deadline_lateness_ms;
  }
  target->quota_exhausted = target->quota_exhausted || add->quota_exhausted;
}

ftun_status_t ftun_core_module_runtime_run_once(
  ftun_core_module_runtime_t *runtime, bool may_block,
  ftun_core_service_run_usage_t *out_usage)
{
  size_t active_services = 0u;
  size_t index;
  ftun_status_t status = FTUN_OK;
  if (out_usage != NULL) memset(out_usage, 0, sizeof(*out_usage));
  if (runtime == NULL || out_usage == NULL || !runtime->activated ||
      runtime->rolled_back) return FTUN_E_INVALID;
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
        return ftun_core_service_run_once(&entry->service,
                                          may_block, out_usage);
      }
    }
  }
  for (index = 0u; status == FTUN_OK && index < runtime->service_count; index++) {
    ftun_core_service_run_usage_t usage;
    ftun_core_module_entry_t *entry =
      &runtime->entries[runtime->service_entries[index]];
    if (entry->phase != FTUN_MODULE_ACTIVE) continue;
    status = ftun_core_service_run_once(&entry->service, false, &usage);
    if (status == FTUN_OK) ftun_core_module_usage_add(out_usage, &usage);
  }
  if (status == FTUN_OK && may_block && out_usage->work == 0u) {
    size_t target = runtime->block_cursor++ % active_services;
    size_t ordinal = 0u;
    for (index = 0u; index < runtime->service_count; index++) {
      ftun_core_service_run_usage_t usage;
      ftun_core_module_entry_t *entry =
        &runtime->entries[runtime->service_entries[index]];
      if (entry->phase != FTUN_MODULE_ACTIVE) continue;
      if (ordinal++ != target) continue;
      status = ftun_core_service_run_once(&entry->service, true, &usage);
      if (status == FTUN_OK) ftun_core_module_usage_add(out_usage, &usage);
      break;
    }
  }
  return status;
}

ftun_status_t ftun_core_module_runtime_wakeup(
  ftun_core_module_runtime_t *runtime)
{
  ftun_status_t result = FTUN_OK;
  size_t index;
  if (runtime == NULL) return FTUN_E_INVALID;
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

ftun_status_t ftun_core_module_runtime_quiesce(
  ftun_core_module_runtime_t *runtime)
{
  ftun_status_t result = FTUN_OK;
  size_t index;
  if (runtime == NULL) return FTUN_E_INVALID;
  if (runtime->rolled_back) return FTUN_OK;
  for (index = runtime->entry_count; index != 0u; index--) {
    ftun_core_module_entry_t *entry = &runtime->entries[index - 1u];
    ftun_status_t status;
    if (entry->phase == FTUN_MODULE_ACTIVE &&
        entry->descriptor->service == NULL) {
      entry->phase = FTUN_MODULE_QUIESCED;
      continue;
    }
    if (entry->phase != FTUN_MODULE_ACTIVE ||
        entry->descriptor->service == NULL) continue;
    status = ftun_core_service_quiesce(&entry->service);
    if (status == FTUN_OK) entry->phase = FTUN_MODULE_QUIESCED;
    else if (result == FTUN_OK) result = status;
  }
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
        entry->phase == FTUN_MODULE_DESTROYED) continue;
    if (entry->descriptor->service == NULL) {
      entry->phase = FTUN_MODULE_DRAINED;
      continue;
    }
    status = ftun_core_service_drain_until(&entry->service, deadline_ms);
    if (status != FTUN_OK) return status;
    entry->phase = FTUN_MODULE_DRAINED;
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
  ftun_status_t status;
  size_t index;
  if (runtime == NULL || deadline_ms == 0u) return FTUN_E_INVALID;
  owned = *runtime;
  if (owned == NULL) return FTUN_OK;
  if (!owned->rolled_back) {
    status = ftun_core_module_runtime_drain_until(owned, deadline_ms);
    if (status != FTUN_OK) return status;
  }
  if (owned->reload_prepared) {
    status = ftun_core_module_runtime_reload_abort(owned);
    if (status != FTUN_OK) return status;
  }
  for (index = owned->entry_count; index != 0u; index--) {
    ftun_core_module_entry_t *entry = &owned->entries[index - 1u];
    if (entry->descriptor->service == NULL) {
      entry->phase = FTUN_MODULE_DESTROYED;
      continue;
    }
    if (entry->service.implementation == NULL) {
      entry->phase = FTUN_MODULE_DESTROYED;
      continue;
    }
    status = ftun_core_service_destroy_until(&entry->service, deadline_ms);
    if (status != FTUN_OK) return status;
    entry->phase = FTUN_MODULE_DESTROYED;
  }
  free(owned);
  *runtime = NULL;
  return FTUN_OK;
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
