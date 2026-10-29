#include "proxy/snapshot.h"
#include "proxy/config/plan.h"
#include "proxy/config/transport.h"
#include "proxy/config/plan.h"
#include "proxy/config/model.h"
#include "libs/resolver/config.h"
#include "core/config/document.h"
#include "proxy/route/router.h"
#include "proxy/route/rule.h"
#include "proxy/outbound/group/url_test.h"
#if defined(FTUN_HAVE_MODULE_FRS)
#include "proxy/frs/frs.h"
#endif
#include <stdlib.h>
#include <string.h>

#include "proxy/runtime_internal.h"

ftun_status_t ftun_runtime_resolve_outbound(ftun_string_t name,
                                             uint32_t *out, void *user);

static int ftun_size_add(size_t *total, size_t value)
{
  if (total == NULL || *total > SIZE_MAX - value) return 0;
  *total += value;
  return 1;
}

static int ftun_size_array(size_t *total, size_t count, size_t item_size)
{
  if (item_size != 0u && count > SIZE_MAX / item_size) return 0;
  return ftun_size_add(total, count * item_size);
}

/* 保留限额包含配置和计划；实际预算预留另行扣除已有独立拥有额度。 */
static int ftun_config_accounted_bytes(const ftun_config_t *config, size_t *out)
{
  size_t bytes;
  if (config == NULL || out == NULL || ftun_config_document_header(config)->owned_bytes < sizeof(ftun_config_document_t)) return 0;
  bytes = ftun_config_document_header(config)->owned_bytes;
  if (ftun_proxy_config_plan(config).present &&
      !ftun_size_add(&bytes, ftun_proxy_config_plan(config).owned_bytes)) return 0;
  *out = bytes;
  return 1;
}

static size_t ftun_runtime_reservation_bytes(const ftun_config_t *config,
  size_t accounted_bytes)
{
  if ((ftun_config_document_header(config)->reservation).budget != NULL) accounted_bytes -= ftun_config_document_header(config)->owned_bytes;
  if (ftun_proxy_config_plan(config).present && ftun_proxy_config_plan(config).accounted) {
    accounted_bytes -= ftun_proxy_config_plan(config).owned_bytes;
  }
  return accounted_bytes;
}

static ftun_status_t ftun_runtime_config_budget(ftun_core_t *core,
  const ftun_config_t *config)
{
  bool same = false;
  ftun_status_t status;
  if (ftun_config_document_header(config)->budget == NULL) return FTUN_OK;
  status = ftun_budget_same_root(ftun_runtime_core_budget(core), ftun_config_document_header(config)->budget, &same);
  return status != FTUN_OK ? status : same ? FTUN_OK : FTUN_E_INVALID;
}

static size_t ftun_feature_count(uint64_t features)
{
  size_t count = 0u;
  while (features != 0u) {
    count += (size_t)(features & UINT64_C(1));
    features >>= 1u;
  }
  return count;
}

static int ftun_runtime_layout(const ftun_config_t *config,
                               size_t *item_count, size_t *accounted_bytes)
{
  ftun_proxy_config_plan_t plan;
  size_t count;
  size_t bytes;
  size_t route_bytes;
  if (config == NULL || !ftun_proxy_config_plan(config).present || item_count == NULL ||
      accounted_bytes == NULL || !ftun_config_accounted_bytes(config, &bytes)) {
    return 0;
  }
  plan = ftun_proxy_config_plan(config);
  count = ftun_feature_count(plan.prepare);
  if (ftun_route_table_accounted_bytes(
        (const char *const *)ftun_config_rules(config)->items, ftun_config_rules(config)->count,
        &route_bytes) != FTUN_OK || !ftun_size_add(&bytes, route_bytes)) {
    return 0;
  }
  if (!ftun_size_add(&count, plan.prepare_listener_count) ||
      !ftun_size_add(&count, plan.prepare_tun_count) ||
      !ftun_size_add(&count, plan.prepare_frs_count) ||
      !ftun_size_add(&bytes, sizeof(ftun_runtime_t)) ||
      !ftun_size_array(&bytes, ftun_config_outbound_count(config),
                       sizeof(ftun_runtime_group_choice_state_t)) ||
      !ftun_size_array(&bytes, count, sizeof(ftun_runtime_prepared_item_t))) {
    return 0;
  }
  *item_count = count;
  *accounted_bytes = bytes;
  return 1;
}

ftun_status_t ftun_runtime_accounted_bytes(const ftun_config_t *config,
                                            size_t *out)
{
  size_t item_count;
  size_t accounted_bytes;
  if (out != NULL) *out = 0u;
  if (out == NULL ||
      !ftun_runtime_layout(config, &item_count, &accounted_bytes)) {
    return FTUN_E_INVALID;
  }
  (void)item_count;
  *out = accounted_bytes;
  return FTUN_OK;
}

static void ftun_runtime_fill_items(ftun_runtime_t *runtime,
                                    ftun_proxy_config_plan_t plan)
{
  size_t cursor = 0u;
  size_t bit;
  size_t index;
  for (bit = 0u; bit < 64u; bit++) {
    uint64_t feature = UINT64_C(1) << bit;
    if ((plan.prepare & feature) != 0u) {
      runtime->snapshot.prepared_items[cursor].feature = feature;
      runtime->snapshot.prepared_items[cursor].ordinal = 0u;
      cursor++;
    }
  }
  for (index = 0u; index < plan.prepare_listener_count; index++, cursor++) {
    runtime->snapshot.prepared_items[cursor].feature = FTUN_PROXY_PLAN_INBOUND;
    runtime->snapshot.prepared_items[cursor].ordinal = index;
  }
  for (index = 0u; index < plan.prepare_tun_count; index++, cursor++) {
    runtime->snapshot.prepared_items[cursor].feature = FTUN_PROXY_PLAN_TUN;
    runtime->snapshot.prepared_items[cursor].ordinal = index;
  }
  for (index = 0u; index < plan.prepare_frs_count; index++, cursor++) {
    runtime->snapshot.prepared_items[cursor].feature = FTUN_PROXY_PLAN_FRS;
    runtime->snapshot.prepared_items[cursor].ordinal = index;
  }
}

static ftun_status_t ftun_runtime_fill_group_defaults(
  ftun_runtime_t *runtime, const ftun_config_t *config)
{
  size_t index;
  for (index = 0u; index < ftun_config_outbound_count(config); index++) {
    const ftun_config_outbound_t *outbound = &ftun_config_outbounds(config)[index];
    size_t member_index;
    if (outbound->kind == FTUN_CONFIG_OUTBOUND_SOCKS5) continue;
    for (member_index = 0u; member_index < outbound->members.count;
         member_index++) {
      const char *member = outbound->members.items[member_index];
      if (member != NULL && outbound->default_member != NULL &&
          strcmp(member, outbound->default_member) == 0) {
        ftun_string_t name;
        ftun_status_t status;
        name.data = member;
        name.length = strlen(member);
        status = ftun_runtime_resolve_outbound(
          name, &runtime->owner_state.group_choices[index].selected_member_id,
          (void *)config);
        if (status != FTUN_OK) return status;
        runtime->owner_state.group_choices[index].selected = true;
        break;
      }
    }
  }
  return FTUN_OK;
}

static ftun_status_t ftun_runtime_finalize(ftun_runtime_t *runtime)
{
  ftun_config_t *config;
  ftun_status_t status;
  if (runtime == NULL || runtime->reference_count != 1u) return FTUN_E_STATE_CORRUPT;
  runtime->cleanup_pending = true;
  status = ftun_route_table_destroy(&runtime->snapshot.routes);
  if (status != FTUN_OK) return status;
#if defined(FTUN_HAVE_MODULE_FRS)
  status = ftun_frs_view_release(&runtime->snapshot.frs_view);
  if (status != FTUN_OK) return status;
#endif
  config = (ftun_config_t *)runtime->snapshot.config;
  status = ftun_config_destroy(&config);
  runtime->snapshot.config = config;
  if (status != FTUN_OK) return status;
  free(runtime->snapshot.prepared_items);
  runtime->snapshot.prepared_items = NULL;
  free(runtime->owner_state.group_choices);
  runtime->owner_state.group_choices = NULL;
  status = ftun_reservation_release(&runtime->reservation);
  if (status != FTUN_OK) return status;
  runtime->owner = NULL;
  runtime->snapshot.config = NULL;
  runtime->reference_count = 0u;
  free(runtime);
  return FTUN_OK;
}

/* 对外句柄已消费，失败对象仍挂在 manager；不分配额外回收节点。 */
static ftun_status_t ftun_runtime_retire(ftun_core_t *core,
  ftun_runtime_t *runtime)
{
  ftun_status_t status = ftun_runtime_finalize(runtime);
  if (status != FTUN_OK) {
    runtime->next_retained = FTUN_MANAGER(core)->cleanup;
    FTUN_MANAGER(core)->cleanup = runtime;
  }
  return status;
}

static ftun_status_t ftun_runtime_collect(ftun_core_t *core)
{
  ftun_runtime_t *runtime = FTUN_MANAGER(core)->cleanup;
  ftun_runtime_t *next;
  ftun_status_t status;
  if (runtime == NULL) return FTUN_OK;
  next = runtime->next_retained;
  status = ftun_runtime_finalize(runtime);
  if (status != FTUN_OK) return status;
  FTUN_MANAGER(core)->cleanup = next;
  return next == NULL ? FTUN_OK : FTUN_E_AGAIN;
}

ftun_status_t ftun_runtime_resolve_outbound(ftun_string_t name,
                                             uint32_t *out, void *user)
{
  const ftun_config_t *config = (const ftun_config_t *)user;
  size_t index;
  if (config == NULL || out == NULL || name.data == NULL ||
      name.length == 0u) return FTUN_E_INVALID;
  if (name.length == 6u && memcmp(name.data, "DIRECT", 6u) == 0) {
    *out = FTUN_OUTBOUND_ID_DIRECT;
    return FTUN_OK;
  }
  if (name.length == 6u && memcmp(name.data, "REJECT", 6u) == 0) {
    *out = FTUN_OUTBOUND_ID_REJECT;
    return FTUN_OK;
  }
  for (index = 0u; index < ftun_config_outbound_count(config); index++) {
    const char *candidate = ftun_config_outbounds(config)[index].name;
    if (candidate != NULL && strlen(candidate) == name.length &&
        memcmp(candidate, name.data, name.length) == 0) {
      if (index > UINT32_MAX - FTUN_OUTBOUND_ID_NAMED_BASE) {
        return FTUN_E_LIMIT;
      }
      *out = (uint32_t)index + FTUN_OUTBOUND_ID_NAMED_BASE;
      return FTUN_OK;
    }
  }
  return FTUN_E_INVALID;
}

static int ftun_runtime_unlink_retained(ftun_core_t *core,
                                        ftun_runtime_t *runtime)
{
  ftun_runtime_t **link = &FTUN_MANAGER(core)->retained;
  while (*link != NULL) {
    if (*link == runtime) {
      *link = runtime->next_retained;
      runtime->next_retained = NULL;
      return 1;
    }
    link = &(*link)->next_retained;
  }
  return 0;
}

static int ftun_runtime_retention_available(const ftun_core_t *core)
{
  const ftun_runtime_t *active;
  size_t bytes;
  if (core == NULL) return 0;
  active = FTUN_MANAGER(core)->active;
  if (active == NULL) return 1;
  bytes = active->snapshot.accounted_bytes;
  return FTUN_MANAGER(core)->retained_count < FTUN_MANAGER(core)->retained_limit &&
    bytes <= FTUN_MANAGER(core)->retained_bytes_limit &&
    FTUN_MANAGER(core)->retained_bytes <= FTUN_MANAGER(core)->retained_bytes_limit - bytes;
}

static int ftun_runtime_can_retain_active(const ftun_core_t *core)
{
  return core != NULL && (FTUN_MANAGER(core)->active == NULL ||
    FTUN_MANAGER(core)->active->reference_count == 1u ||
    ftun_runtime_retention_available(core));
}

ftun_status_t ftun_runtime_manager_create(ftun_budget_t *budget,
                                          size_t retained_limit,
                                          ftun_core_t **out)
{
  return ftun_runtime_manager_create_limits(budget, retained_limit,
                                             SIZE_MAX, out);
}

ftun_status_t ftun_runtime_manager_create_limits(
  ftun_budget_t *budget, size_t retained_limit, size_t retained_bytes_limit,
  ftun_core_t **out)
{
  ftun_core_t *core = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (budget == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_core_context_create(budget, &core);
  if (status != FTUN_OK) return status;
  status = ftun_runtime_manager_attach(core, retained_limit,
                                       retained_bytes_limit);
  if (status != FTUN_OK) {
    (void)ftun_core_context_destroy(&core);
    return status;
  }
  *out = core;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_manager_attach(ftun_core_t *core,
  size_t retained_limit, size_t retained_bytes_limit)
{
  ftun_snapshot_manager_t *manager;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_status_t status;
  void *existing = NULL;
  if (!ftun_core_context_is_valid(core)) return FTUN_E_INVALID;
  if (ftun_core_context_extension(core, &existing) == FTUN_OK) return FTUN_E_STALE;
  status = ftun_budget_reserve(ftun_runtime_core_budget(core), sizeof(*manager),
                               &reservation);
  if (status != FTUN_OK) return status;
  manager = (ftun_snapshot_manager_t *)calloc(1u, sizeof(*manager));
  if (manager == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  manager->reservation = reservation;
  manager->runtime_magic = FTUN_RUNTIME_MANAGER_MAGIC;
  manager->retained_limit = retained_limit;
  manager->retained_bytes_limit = retained_bytes_limit;
  status = ftun_core_context_bind(core, manager);
  if (status != FTUN_OK) {
    free(manager);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  return FTUN_OK;
}

ftun_status_t ftun_runtime_manager_get_info(const ftun_core_t *core,
                                            ftun_runtime_manager_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (!ftun_runtime_core_valid(core) || out == NULL) return FTUN_E_INVALID;
  out->generation = ftun_runtime_core_generation(core);
  out->has_active = FTUN_MANAGER(core)->active != NULL;
  out->has_candidate = FTUN_MANAGER(core)->candidate != NULL;
  out->has_cleanup = FTUN_MANAGER(core)->cleanup != NULL;
  out->retained_count = FTUN_MANAGER(core)->retained_count;
  out->retained_limit = FTUN_MANAGER(core)->retained_limit;
  out->retained_bytes = FTUN_MANAGER(core)->retained_bytes;
  out->retained_bytes_limit = FTUN_MANAGER(core)->retained_bytes_limit;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_manager_clear(ftun_core_t *owned)
{
  ftun_snapshot_manager_t *manager;
  ftun_reservation_t reservation;
  ftun_status_t status;
  if (!ftun_core_context_is_valid(owned)) return FTUN_E_INVALID;
  if (FTUN_MANAGER(owned) == NULL) return FTUN_OK;
  if (!ftun_runtime_core_valid(owned)) return FTUN_E_INVALID;
  manager = FTUN_MANAGER(owned);
  status = ftun_runtime_collect(owned);
  if (status != FTUN_OK) return status;
  if (manager->candidate != NULL || manager->retained != NULL ||
      (manager->active != NULL && manager->active->reference_count != 1u)) {
    return FTUN_E_AGAIN;
  }
  if (manager->active != NULL) {
    ftun_runtime_t *active = manager->active;
    manager->active = NULL;
    status = ftun_runtime_retire(owned, active);
    if (status != FTUN_OK) return status;
  }
  status = ftun_core_context_bind(owned, NULL);
  if (status != FTUN_OK) return status;
  reservation = manager->reservation;
  manager->runtime_magic = 0u;
  free(manager);
  return ftun_reservation_release(&reservation);
}

ftun_status_t ftun_runtime_manager_destroy(ftun_core_t **core)
{
  ftun_status_t status;
  if (core == NULL) return FTUN_E_INVALID;
  if (*core == NULL) return FTUN_OK;
  status = ftun_runtime_manager_clear(*core);
  return status == FTUN_OK ? ftun_core_context_destroy(core) : status;
}

static ftun_status_t ftun_runtime_frs_bind(uint16_t kind, ftun_string_t label,
                                           ftun_frs_set_t **out, void *user)
{
#if defined(FTUN_HAVE_MODULE_FRS)
  /* 没有视图表示 FRS 尚未就绪：规则保留并在匹配时拒绝新连接。 */
  if (user == NULL) {
    *out = NULL;
    return FTUN_E_AGAIN;
  }
  return ftun_frs_bind((ftun_frs_view_t *)user, (ftun_frs_set_kind_t)kind,
                       label, out);
#else
  (void)kind;
  (void)label;
  (void)out;
  (void)user;
  return FTUN_E_UNSUPPORTED;
#endif
}

static ftun_status_t ftun_runtime_prepare_internal(
  ftun_core_t *core, const ftun_config_t *config, ftun_frs_view_t *provided_frs,
  bool frs_pending, ftun_runtime_t **out)
{
  ftun_runtime_t *runtime;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  size_t item_count;
  size_t accounted_bytes;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (!ftun_runtime_core_valid(core) || config == NULL || out == NULL ||
      !ftun_proxy_config_plan(config).present) return FTUN_E_INVALID;
  status = ftun_runtime_config_budget(core, config);
  if (status != FTUN_OK) return status;
  if (FTUN_MANAGER(core)->candidate != NULL) return FTUN_E_AGAIN;
  status = ftun_runtime_collect(core);
  if (status != FTUN_OK) return status;
  if (ftun_runtime_core_generation(core) == UINT64_MAX ||
      !ftun_runtime_can_retain_active(core)) return FTUN_E_LIMIT;
  if (!ftun_runtime_layout(config, &item_count, &accounted_bytes)) return FTUN_E_LIMIT;
  status = ftun_budget_reserve(ftun_runtime_core_budget(core),
    ftun_runtime_reservation_bytes(config, accounted_bytes), &reservation);
  if (status != FTUN_OK) return status;
  runtime = (ftun_runtime_t *)calloc(1u, sizeof(*runtime));
  if (runtime == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  /* 先建立回收所需的拥有链，构造错误也可由 manager 保留并重试。 */
  runtime->owner = core;
  runtime->reservation = reservation;
  runtime->reference_count = 1u;
  runtime->state = FTUN_RUNTIME_CANDIDATE;
  status = ftun_config_retain((ftun_config_t *)config);
  if (status != FTUN_OK) goto fail;
  runtime->snapshot.config = config;
  if (item_count != 0u) {
    runtime->snapshot.prepared_items = (ftun_runtime_prepared_item_t *)calloc(
      item_count, sizeof(*runtime->snapshot.prepared_items));
    if (runtime->snapshot.prepared_items == NULL) {
      status = FTUN_E_LIMIT;
      goto fail;
    }
  }
  if (ftun_config_outbound_count(config) != 0u) {
    runtime->owner_state.group_choices = (ftun_runtime_group_choice_state_t *)calloc(
      ftun_config_outbound_count(config), sizeof(*runtime->owner_state.group_choices));
    if (runtime->owner_state.group_choices == NULL) {
      status = FTUN_E_LIMIT;
      goto fail;
    }
  }
#if defined(FTUN_HAVE_MODULE_FRS)
  if ((ftun_proxy_config_plan(config).prepare & FTUN_PROXY_PLAN_FRS) != 0u) {
    if (frs_pending) {
      status = provided_frs == NULL ? FTUN_OK : FTUN_E_INVALID;
    } else if (provided_frs != NULL) {
      status = ftun_frs_view_retain(provided_frs);
      if (status == FTUN_OK) runtime->snapshot.frs_view = provided_frs;
    } else if (ftun_config_frs(config)->path == NULL || ftun_config_frs(config)->path[0] == '\0') {
      status = FTUN_E_INVALID;
    } else {
      status = ftun_frs_open(core, ftun_config_frs(config)->path, &runtime->snapshot.frs_view);
    }
    if (status != FTUN_OK) goto fail;
  } else if (provided_frs != NULL) {
    status = FTUN_E_INVALID;
    goto fail;
  }
#else
  if (provided_frs != NULL || (ftun_proxy_config_plan(config).prepare & FTUN_PROXY_PLAN_FRS) != 0u) {
    status = FTUN_E_UNSUPPORTED;
    goto fail;
  }
#endif
  status = ftun_route_table_create_with_frs(
    0u, (const char *const *)ftun_config_rules(config)->items, ftun_config_rules(config)->count,
    ftun_runtime_resolve_outbound, (void *)config,
    (ftun_proxy_config_plan(config).prepare & FTUN_PROXY_PLAN_FRS) != 0u ? ftun_runtime_frs_bind : NULL,
    runtime->snapshot.frs_view, &runtime->snapshot.routes);
  if (status != FTUN_OK) goto fail;
  runtime->snapshot.prepared_item_count = item_count;
  runtime->snapshot.accounted_bytes = accounted_bytes;
  runtime->owner_state.group_choice_count = ftun_config_outbound_count(config);
  status = ftun_runtime_fill_group_defaults(runtime, config);
  if (status != FTUN_OK) goto fail;
  ftun_runtime_fill_items(runtime, ftun_proxy_config_plan(config));
  FTUN_MANAGER(core)->candidate = runtime;
  *out = runtime;
  return FTUN_OK;

fail:
  /* 首次返回构造错误；清理错误由后续 collect/clear 暴露，不能丢掉资源。 */
  (void)ftun_runtime_retire(core, runtime);
  return status;
}

/* 候选准备和快照生命周期。 */
ftun_status_t ftun_runtime_prepare(ftun_core_t *core,
                                   const ftun_config_t *config,
                                   ftun_runtime_t **out)
{
  return ftun_runtime_prepare_internal(core, config, NULL, false, out);
}

ftun_status_t ftun_runtime_prepare_frs_pending(ftun_core_t *core,
                                               const ftun_config_t *config,
                                               ftun_runtime_t **out)
{
  if (config == NULL || !ftun_proxy_config_plan(config).present ||
      (ftun_proxy_config_plan(config).prepare & FTUN_PROXY_PLAN_FRS) == 0u) {
    if (out != NULL) *out = NULL;
    return FTUN_E_INVALID;
  }
  return ftun_runtime_prepare_internal(core, config, NULL, true, out);
}

ftun_status_t ftun_runtime_prepare_with_frs(ftun_core_t *core,
                                            const ftun_config_t *config,
                                            ftun_frs_view_t *view,
                                            ftun_runtime_t **out)
{
  if (view == NULL) {
    if (out != NULL) *out = NULL;
    return FTUN_E_INVALID;
  }
  return ftun_runtime_prepare_internal(core, config, view, false, out);
}

#if defined(FTUN_HAVE_MODULE_FRS)
ftun_status_t ftun_runtime_prepare_detached(
  const ftun_config_t *config, ftun_frs_view_t *view, ftun_runtime_t **out)
{
  ftun_runtime_t *runtime;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  size_t item_count;
  size_t accounted_bytes;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (config == NULL || out == NULL || !ftun_proxy_config_plan(config).present ||
      (((ftun_proxy_config_plan(config).prepare & FTUN_PROXY_PLAN_FRS) != 0u) != (view != NULL)) ||
      !ftun_runtime_layout(config, &item_count, &accounted_bytes)) {
    return FTUN_E_INVALID;
  }
  /* 配置绑定的预算由宿主持有，Worker 只借用；构造期即可准入，
   * 不再等待 owner attach。独立未绑定调用仍在 attach 时准入。 */
  if (ftun_config_document_header(config)->budget != NULL) {
    status = ftun_budget_reserve(ftun_config_document_header(config)->budget,
      ftun_runtime_reservation_bytes(config, accounted_bytes), &reservation);
    if (status != FTUN_OK) return status;
  }
  runtime = (ftun_runtime_t *)calloc(1u, sizeof(*runtime));
  if (runtime == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  if (item_count != 0u) {
    runtime->snapshot.prepared_items = (ftun_runtime_prepared_item_t *)calloc(
      item_count, sizeof(*runtime->snapshot.prepared_items));
    if (runtime->snapshot.prepared_items == NULL) goto allocation_error;
  }
  if (ftun_config_outbound_count(config) != 0u) {
    runtime->owner_state.group_choices = (ftun_runtime_group_choice_state_t *)calloc(
      ftun_config_outbound_count(config), sizeof(*runtime->owner_state.group_choices));
    if (runtime->owner_state.group_choices == NULL) goto allocation_error;
  }
  status = ftun_route_table_create_with_frs(
    0u, (const char *const *)ftun_config_rules(config)->items, ftun_config_rules(config)->count,
    ftun_runtime_resolve_outbound, (void *)config,
    view == NULL ? NULL : ftun_runtime_frs_bind, view, &runtime->snapshot.routes);
  if (status != FTUN_OK) goto status_error;
  runtime->snapshot.config = config;
  runtime->reservation = reservation;
  runtime->snapshot.frs_view = view;
  runtime->snapshot.prepared_item_count = item_count;
  runtime->snapshot.accounted_bytes = accounted_bytes;
  runtime->owner_state.group_choice_count = ftun_config_outbound_count(config);
  runtime->reference_count = 1u;
  runtime->state = FTUN_RUNTIME_CANDIDATE;
  status = ftun_runtime_fill_group_defaults(runtime, config);
  if (status != FTUN_OK) goto route_error;
  ftun_runtime_fill_items(runtime, ftun_proxy_config_plan(config));
  *out = runtime;
  return FTUN_OK;

route_error:
  (void)ftun_route_table_destroy(&runtime->snapshot.routes);
status_error:
  free(runtime->owner_state.group_choices);
  free(runtime->snapshot.prepared_items);
  free(runtime);
  (void)ftun_reservation_release(&reservation);
  return status;

allocation_error:
  free(runtime->owner_state.group_choices);
  free(runtime->snapshot.prepared_items);
  free(runtime);
  (void)ftun_reservation_release(&reservation);
  return FTUN_E_LIMIT;
}

ftun_status_t ftun_runtime_prepare_detached_frs(
  const ftun_config_t *config, ftun_frs_view_t *view, ftun_runtime_t **out)
{
  if (view == NULL) {
    if (out != NULL) *out = NULL;
    return FTUN_E_INVALID;
  }
  return ftun_runtime_prepare_detached(config, view, out);
}

ftun_status_t ftun_runtime_prepared_release(ftun_runtime_t **prepared)
{
  ftun_runtime_t *runtime;
  ftun_status_t status;
  if (prepared == NULL) return FTUN_E_INVALID;
  runtime = *prepared;
  if (runtime == NULL) return FTUN_OK;
  if (runtime->owner != NULL ||
      runtime->state != FTUN_RUNTIME_CANDIDATE ||
      runtime->reference_count != 1u) return FTUN_E_STATE_CORRUPT;
  runtime->cleanup_pending = true;
  status = ftun_route_table_destroy(&runtime->snapshot.routes);
  if (status != FTUN_OK) return status;
  status = ftun_frs_view_release(&runtime->snapshot.frs_view);
  if (status != FTUN_OK) return status;
  status = ftun_reservation_release(&runtime->reservation);
  if (status != FTUN_OK) return status;
  free(runtime->owner_state.group_choices);
  free(runtime->snapshot.prepared_items);
  memset(runtime, 0, sizeof(*runtime));
  free(runtime);
  *prepared = NULL;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_attach_prepared(ftun_core_t *core,
                                           ftun_runtime_t **prepared,
                                           ftun_runtime_t **out)
{
  ftun_runtime_t *runtime;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (!ftun_runtime_core_valid(core) || prepared == NULL || out == NULL) {
    return FTUN_E_INVALID;
  }
  runtime = *prepared;
  if (runtime == NULL || runtime->cleanup_pending || runtime->owner != NULL ||
      runtime->snapshot.config == NULL ||
      runtime->snapshot.routes == NULL ||
      ((((ftun_proxy_config_plan(runtime->snapshot.config).prepare & FTUN_PROXY_PLAN_FRS) != 0u) !=
        (runtime->snapshot.frs_view != NULL))) ||
      runtime->state != FTUN_RUNTIME_CANDIDATE ||
      runtime->reference_count != 1u) return FTUN_E_INVALID;
  status = ftun_runtime_config_budget(core, runtime->snapshot.config);
  if (status != FTUN_OK) return status;
  if (FTUN_MANAGER(core)->candidate != NULL) return FTUN_E_AGAIN;
  status = ftun_runtime_collect(core);
  if (status != FTUN_OK) return status;
  if (ftun_runtime_core_generation(core) == UINT64_MAX ||
      !ftun_runtime_can_retain_active(core)) return FTUN_E_LIMIT;
  status = ftun_config_retain((ftun_config_t *)runtime->snapshot.config);
  if (status != FTUN_OK) return status;
  /* 已绑定配置的候选持有同根额度，附着只转移拥有者，不重复准入。
   * 未绑定的独立候选在此获得额度；失败只归还本次新增 reservation。 */
  if ((runtime->reservation).budget == NULL) {
    status = ftun_budget_reserve(ftun_runtime_core_budget(core),
      ftun_runtime_reservation_bytes(runtime->snapshot.config, runtime->snapshot.accounted_bytes),
      &reservation);
  }
  if (status == FTUN_OK && runtime->snapshot.frs_view != NULL) {
    status = ftun_frs_view_bind_budget(runtime->snapshot.frs_view, ftun_runtime_core_budget(core));
  }
  if (status != FTUN_OK) {
    ftun_config_t *retained_config = (ftun_config_t *)runtime->snapshot.config;
    (void)ftun_reservation_release(&reservation);
    (void)ftun_config_destroy(&retained_config);
    return status;
  }
  runtime->owner = core;
  if ((runtime->reservation).budget == NULL) runtime->reservation = reservation;
  FTUN_MANAGER(core)->candidate = runtime;
  *prepared = NULL;
  *out = runtime;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_prepared_frs_bytes(
  const ftun_runtime_t *prepared, ftun_bytes_t *out)
{
  if (out != NULL) {
    out->data = NULL;
    out->length = 0u;
  }
  if (prepared == NULL || prepared->cleanup_pending || out == NULL || prepared->snapshot.frs_view == NULL ||
      prepared->state != FTUN_RUNTIME_CANDIDATE) return FTUN_E_INVALID;
  return ftun_frs_view_bytes(prepared->snapshot.frs_view, out);
}
#endif

ftun_status_t ftun_runtime_can_commit(const ftun_core_t *core,
                                      const ftun_runtime_t *candidate)
{
  const ftun_runtime_t *previous;
  if (!ftun_runtime_core_valid(core) || candidate == NULL) {
    return FTUN_E_INVALID;
  }
  if (FTUN_MANAGER(core)->cleanup != NULL) return FTUN_E_AGAIN;
  if (candidate != FTUN_MANAGER(core)->candidate || candidate->owner != core ||
      candidate->state != FTUN_RUNTIME_CANDIDATE ||
      candidate->reference_count != 1u) return FTUN_E_STALE;
  previous = FTUN_MANAGER(core)->active;
  if (ftun_runtime_core_generation(core) == UINT64_MAX) return FTUN_E_LIMIT;
  if (candidate->generation != 0u) {
    if (previous != NULL && previous->reference_count > 1u &&
        !candidate->retention_reserved) return FTUN_E_LIMIT;
    return FTUN_OK;
  }
  if (previous != NULL && previous->reference_count > 1u &&
      !ftun_runtime_can_retain_active(core)) return FTUN_E_LIMIT;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_stage_commit(ftun_core_t *core,
                                        ftun_runtime_t *candidate,
                                        uint64_t generation)
{
  ftun_runtime_t *previous;
  bool retention_reserved = false;
  bool blocks_active_acquire = false;
  ftun_status_t status = ftun_runtime_can_commit(core, candidate);
  if (status != FTUN_OK) return status;
  if (generation == 0u || generation != ftun_runtime_core_generation(core) + 1u) {
    return FTUN_E_STALE;
  }
  if (candidate->generation == generation) return FTUN_OK;
  if (candidate->generation != 0u) return FTUN_E_STALE;
  previous = FTUN_MANAGER(core)->active;
  if (previous != NULL) {
    if (ftun_runtime_retention_available(core)) retention_reserved = true;
    else if (previous->reference_count == 1u) blocks_active_acquire = true;
    else return FTUN_E_LIMIT;
  }
  status = ftun_route_table_set_generation(candidate->snapshot.routes,
                                            generation);
  if (status == FTUN_OK) {
    candidate->generation = generation;
    candidate->retention_reserved = retention_reserved;
    candidate->blocks_active_acquire = blocks_active_acquire;
  }
  return status;
}

static ftun_status_t ftun_runtime_commit_owned(ftun_core_t *core,
  ftun_runtime_t **candidate, const void *owner)
{
  ftun_runtime_t *next;
  ftun_runtime_t *previous;
  uint64_t reserved = 0u;
  uint64_t target = 0u;
  bool self_reserved = false;
  ftun_status_t status;
  if (!ftun_runtime_core_valid(core) || candidate == NULL || *candidate == NULL) {
    return FTUN_E_INVALID;
  }
  next = *candidate;
  status = ftun_runtime_can_commit(core, next);
  if (status != FTUN_OK) return status;
  previous = FTUN_MANAGER(core)->active;
  /* 代次唯一由 Core 上下文发布：owner 非空时只消费它自己持有
   * 的预留；为空时要求没有任何预留，并以候选为持有者自行预留。 */
  if (owner != NULL) {
    status = ftun_core_context_generation_held(core, owner, &target);
    if (status != FTUN_OK) return status;
  } else {
    status = ftun_core_context_generation_reserved(core, &reserved);
    if (status != FTUN_OK) return status;
    if (reserved != 0u) return FTUN_E_AGAIN;
    owner = next;
    status = ftun_core_context_generation_reserve(core, owner, &target);
    if (status != FTUN_OK) return status;
    self_reserved = true;
  }
  status = ftun_runtime_stage_commit(core, next, target);
  if (status == FTUN_OK) {
    status = ftun_core_context_generation_publish(core, owner, target);
  }
  if (status != FTUN_OK) {
    if (self_reserved) (void)ftun_core_context_generation_release(core, owner, target);
    return status;
  }
  next->state = FTUN_RUNTIME_ACTIVE;
  FTUN_MANAGER(core)->candidate = NULL;
  FTUN_MANAGER(core)->active = next;
  *candidate = NULL;
  if (previous != NULL) {
    if (previous->reference_count == 1u) {
      (void)ftun_runtime_retire(core, previous);
    } else {
      previous->state = FTUN_RUNTIME_RETAINED;
      previous->next_retained = FTUN_MANAGER(core)->retained;
      FTUN_MANAGER(core)->retained = previous;
      FTUN_MANAGER(core)->retained_count++;
      FTUN_MANAGER(core)->retained_bytes += previous->snapshot.accounted_bytes;
    }
  }
  return FTUN_OK;
}

ftun_status_t ftun_runtime_commit(ftun_core_t *core, ftun_runtime_t **candidate)
{
  return ftun_runtime_commit_owned(core, candidate, NULL);
}

ftun_status_t ftun_runtime_commit_reserved(ftun_core_t *core,
  ftun_runtime_t **candidate, const void *owner)
{
  if (owner == NULL) return FTUN_E_INVALID;
  return ftun_runtime_commit_owned(core, candidate, owner);
}

ftun_status_t ftun_runtime_abort(ftun_core_t *core,
                                 ftun_runtime_t **candidate)
{
  ftun_runtime_t *runtime;
  if (!ftun_runtime_core_valid(core) || candidate == NULL) return FTUN_E_INVALID;
  runtime = *candidate;
  if (runtime == NULL) return FTUN_OK;
  if (runtime != FTUN_MANAGER(core)->candidate || runtime->owner != core ||
      runtime->state != FTUN_RUNTIME_CANDIDATE) return FTUN_E_STALE;
  FTUN_MANAGER(core)->candidate = NULL;
  *candidate = NULL;
  return ftun_runtime_retire(core, runtime);
}

ftun_status_t ftun_runtime_active_acquire(ftun_core_t *core,
                                          ftun_runtime_t **out)
{
  ftun_runtime_t *runtime;
  if (out != NULL) *out = NULL;
  if (!ftun_runtime_core_valid(core) || out == NULL) return FTUN_E_INVALID;
  runtime = FTUN_MANAGER(core)->active;
  if (runtime == NULL) return FTUN_E_AGAIN;
  /* stage 后必须保证最终 commit 不会因新旧代重叠额度变化而失败。显式
   * 零 retained 额度仍允许无旧引用替换，但持久化窗口拒绝新增引用。 */
  if (FTUN_MANAGER(core)->candidate != NULL && FTUN_MANAGER(core)->candidate->generation != 0u &&
      FTUN_MANAGER(core)->candidate->blocks_active_acquire) return FTUN_E_LIMIT;
  if (runtime->reference_count == SIZE_MAX) return FTUN_E_LIMIT;
  runtime->reference_count++;
  *out = runtime;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_retain(ftun_runtime_t *runtime)
{
  ftun_core_t *core;
  if (runtime == NULL || !ftun_runtime_core_valid(runtime->owner) ||
      runtime->state == FTUN_RUNTIME_CANDIDATE ||
      runtime->reference_count == SIZE_MAX) return FTUN_E_INVALID;
  core = runtime->owner;
  if (runtime == FTUN_MANAGER(core)->active && FTUN_MANAGER(core)->candidate != NULL &&
      FTUN_MANAGER(core)->candidate->generation != 0u &&
      FTUN_MANAGER(core)->candidate->blocks_active_acquire) return FTUN_E_LIMIT;
  runtime->reference_count++;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_release(ftun_runtime_t **runtime)
{
  ftun_runtime_t *owned;
  ftun_core_t *core;
  if (runtime == NULL) return FTUN_E_INVALID;
  owned = *runtime;
  if (owned == NULL) return FTUN_OK;
  core = owned->owner;
  if (!ftun_runtime_core_valid(core) || owned->reference_count <= 1u ||
      owned->state == FTUN_RUNTIME_CANDIDATE) return FTUN_E_STATE_CORRUPT;
  if (owned->state == FTUN_RUNTIME_RETAINED && owned->reference_count == 2u) {
    if (FTUN_MANAGER(core)->retained_count == 0u ||
        owned->snapshot.accounted_bytes > FTUN_MANAGER(core)->retained_bytes ||
        !ftun_runtime_unlink_retained(core, owned)) {
      return FTUN_E_STATE_CORRUPT;
    }
    FTUN_MANAGER(core)->retained_count--;
    FTUN_MANAGER(core)->retained_bytes -= owned->snapshot.accounted_bytes;
    owned->reference_count--;
    *runtime = NULL;
    return ftun_runtime_retire(core, owned);
  }
  owned->reference_count--;
  *runtime = NULL;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_get_info(const ftun_runtime_t *runtime,
                                    ftun_runtime_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (runtime == NULL || out == NULL ||
      !ftun_runtime_core_valid(runtime->owner)) return FTUN_E_INVALID;
  out->state = runtime->state;
  out->generation = runtime->generation;
  out->reference_count = runtime->reference_count;
  out->accounted_bytes = runtime->snapshot.accounted_bytes;
  out->prepared_item_count = runtime->snapshot.prepared_item_count;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_route_table(const ftun_runtime_t *runtime,
                                       const ftun_route_table_t **out)
{
  if (out != NULL) *out = NULL;
  if (runtime == NULL || out == NULL || runtime->snapshot.routes == NULL ||
      runtime->state == FTUN_RUNTIME_CANDIDATE || runtime->generation == 0u ||
      !ftun_runtime_core_valid(runtime->owner)) return FTUN_E_INVALID;
  *out = runtime->snapshot.routes;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_config(const ftun_runtime_t *runtime,
                                  const ftun_config_t **out)
{
  if (out != NULL) *out = NULL;
  if (runtime == NULL || out == NULL || runtime->snapshot.config == NULL ||
      runtime->state == FTUN_RUNTIME_CANDIDATE || runtime->generation == 0u ||
      !ftun_runtime_core_valid(runtime->owner)) return FTUN_E_INVALID;
  *out = runtime->snapshot.config;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_resolve_outbound_name(
  const ftun_runtime_t *runtime, ftun_string_t name, uint32_t *out)
{
  if (out != NULL) *out = 0u;
  if (runtime == NULL || out == NULL || runtime->snapshot.config == NULL ||
      runtime->state == FTUN_RUNTIME_CANDIDATE || runtime->generation == 0u ||
      !ftun_runtime_core_valid(runtime->owner)) return FTUN_E_INVALID;
  return ftun_runtime_resolve_outbound(name, out, (void *)runtime->snapshot.config);
}

ftun_status_t ftun_runtime_frs_view(const ftun_runtime_t *runtime,
                                    ftun_frs_view_t **out)
{
  if (out != NULL) *out = NULL;
  if (runtime == NULL || out == NULL ||
      runtime->state == FTUN_RUNTIME_CANDIDATE || runtime->generation == 0u ||
      !ftun_runtime_core_valid(runtime->owner)) return FTUN_E_INVALID;
  if (runtime->snapshot.frs_view == NULL) return FTUN_E_AGAIN;
  *out = runtime->snapshot.frs_view;
  return FTUN_OK;
}
