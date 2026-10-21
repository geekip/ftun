#include "proxy/snapshot.h"
#include "config/compile.h"
#include "config/model.h"
#include "config/parser.h"
#include "core/context_internal.h"
#include "proxy/route/router.h"
#include "proxy/route/rule.h"
#include "proxy/group/url_test.h"
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

static int ftun_size_string(size_t *total, const char *value)
{
  return value == NULL || ftun_size_add(total, strlen(value) + 1u);
}

static int ftun_size_string_list(size_t *total,
                                 const ftun_config_string_list_t *list)
{
  size_t index;
  if (!ftun_size_array(total, list->count, sizeof(*list->items))) return 0;
  for (index = 0u; index < list->count; index++) {
    if (!ftun_size_string(total, list->items[index])) return 0;
  }
  return 1;
}

static int ftun_config_accounted_bytes(const ftun_config_t *config, size_t *out)
{
  size_t total = sizeof(*config);
  size_t index;
  if (config == NULL || out == NULL) return 0;
  if (!ftun_size_string(&total, config->source_path) ||
      !ftun_size_string(&total, config->base_directory) ||
      !ftun_size_string(&total, config->base.cache_file) ||
      !ftun_size_string(&total, config->log.level) ||
      !ftun_size_string(&total, config->log.file) ||
      !ftun_size_string_list(&total, &config->dns.bootstrap) ||
      !ftun_size_string(&total, config->dns.default_server) ||
      !ftun_size_string(&total, config->dns.fake_ip.range) ||
      !ftun_size_array(&total, config->dns.listener_count,
                       sizeof(*config->dns.listeners))) return 0;
  for (index = 0u; index < config->dns.listener_count; index++) {
    if (!ftun_size_string(&total, config->dns.listeners[index].listen) ||
        !ftun_size_string(&total, config->dns.listeners[index].server)) return 0;
  }
  if (!ftun_size_array(&total, config->dns.server_count,
                       sizeof(*config->dns.servers))) return 0;
  for (index = 0u; index < config->dns.server_count; index++) {
    const ftun_config_dns_server_t *server = &config->dns.servers[index];
    if (!ftun_size_string(&total, server->name) ||
        !ftun_size_string(&total, server->type) ||
        !ftun_size_string_list(&total, &server->addresses) ||
        !ftun_size_string(&total, server->outbound)) return 0;
  }
  if (!ftun_size_string(&total, config->frs.path) ||
      !ftun_size_string(&total, config->frs.url) ||
      !ftun_size_string(&total, config->frs.update_interval) ||
      !ftun_size_string(&total, config->frs.update_outbound) ||
      !ftun_size_string(&total, config->frs.dns_server) ||
      !ftun_size_array(&total, config->inbound_count,
                       sizeof(*config->inbounds))) return 0;
  for (index = 0u; index < config->inbound_count; index++) {
    const ftun_config_inbound_t *inbound = &config->inbounds[index];
    size_t user_index;
    if (!ftun_size_string(&total, inbound->name) ||
        !ftun_size_string(&total, inbound->outbound) ||
        !ftun_size_string(&total, inbound->listen) ||
        !ftun_size_string(&total, inbound->interface_name) ||
        !ftun_size_string(&total, inbound->stack) ||
        !ftun_size_string(&total, inbound->ipv4_address) ||
        !ftun_size_array(&total, inbound->user_count,
                         sizeof(*inbound->users))) return 0;
    for (user_index = 0u; user_index < inbound->user_count; user_index++) {
      if (!ftun_size_string(&total, inbound->users[user_index].name) ||
          !ftun_size_string(&total, inbound->users[user_index].password)) return 0;
    }
  }
  if (!ftun_size_array(&total, config->outbound_count,
                       sizeof(*config->outbounds))) return 0;
  for (index = 0u; index < config->outbound_count; index++) {
    const ftun_config_outbound_t *outbound = &config->outbounds[index];
    if (!ftun_size_string(&total, outbound->name) ||
        !ftun_size_string(&total, outbound->dns_server) ||
        !ftun_size_string(&total, outbound->server) ||
        !ftun_size_string(&total, outbound->username) ||
        !ftun_size_string(&total, outbound->password) ||
        !ftun_size_string_list(&total, &outbound->members) ||
        !ftun_size_string(&total, outbound->default_member) ||
        !ftun_size_string(&total, outbound->url) ||
        !ftun_size_string(&total, outbound->interval) ||
        !ftun_size_string(&total, outbound->timeout)) return 0;
  }
  if (!ftun_size_string_list(&total, &config->rules)) return 0;
  if (config->plan != NULL) {
    if (!ftun_size_add(&total, sizeof(*config->plan)) ||
        !ftun_size_array(&total, config->plan->outbound_count,
                         sizeof(*config->plan->outbound_states)) ||
        !ftun_size_array(&total, config->plan->dns_server_count,
                         sizeof(*config->plan->dns_server_states)) ||
        !ftun_size_array(&total, config->plan->rule_count,
                         sizeof(*config->plan->rule_order))) return 0;
  }
  *out = total;
  return 1;
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
  const ftun_feature_plan_t *plan;
  size_t count;
  size_t bytes;
  size_t route_bytes;
  if (config == NULL || config->plan == NULL || item_count == NULL ||
      accounted_bytes == NULL || !ftun_config_accounted_bytes(config, &bytes)) {
    return 0;
  }
  plan = config->plan;
  count = ftun_feature_count(plan->prepare);
  if (ftun_route_table_accounted_bytes(
        (const char *const *)config->rules.items, config->rules.count,
        &route_bytes) != FTUN_OK || !ftun_size_add(&bytes, route_bytes)) {
    return 0;
  }
  if (!ftun_size_add(&count, plan->prepare_listener_count) ||
      !ftun_size_add(&count, plan->prepare_tun_count) ||
      !ftun_size_add(&count, plan->prepare_frs_count) ||
      !ftun_size_add(&bytes, sizeof(ftun_runtime_t)) ||
      !ftun_size_array(&bytes, config->outbound_count,
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
                                    const ftun_feature_plan_t *plan)
{
  size_t cursor = 0u;
  size_t bit;
  size_t index;
  for (bit = 0u; bit < 64u; bit++) {
    uint64_t feature = UINT64_C(1) << bit;
    if ((plan->prepare & feature) != 0u) {
      runtime->snapshot.prepared_items[cursor].feature = feature;
      runtime->snapshot.prepared_items[cursor].ordinal = 0u;
      cursor++;
    }
  }
  for (index = 0u; index < plan->prepare_listener_count; index++, cursor++) {
    runtime->snapshot.prepared_items[cursor].feature = FTUN_PLAN_INBOUND;
    runtime->snapshot.prepared_items[cursor].ordinal = index;
  }
  for (index = 0u; index < plan->prepare_tun_count; index++, cursor++) {
    runtime->snapshot.prepared_items[cursor].feature = FTUN_PLAN_TUN;
    runtime->snapshot.prepared_items[cursor].ordinal = index;
  }
  for (index = 0u; index < plan->prepare_frs_count; index++, cursor++) {
    runtime->snapshot.prepared_items[cursor].feature = FTUN_PLAN_FRS;
    runtime->snapshot.prepared_items[cursor].ordinal = index;
  }
}

static ftun_status_t ftun_runtime_fill_group_defaults(
  ftun_runtime_t *runtime, const ftun_config_t *config)
{
  size_t index;
  for (index = 0u; index < config->outbound_count; index++) {
    const ftun_config_outbound_t *outbound = &config->outbounds[index];
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
  config = (ftun_config_t *)runtime->snapshot.config;
  status = ftun_config_destroy(&config);
  if (status != FTUN_OK) return status;
  status = ftun_route_table_destroy(&runtime->snapshot.routes);
  if (status != FTUN_OK) return status;
#if defined(FTUN_HAVE_MODULE_FRS)
  status = ftun_frs_view_release(&runtime->snapshot.frs_view);
  if (status != FTUN_OK) return status;
#endif
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
  for (index = 0u; index < config->outbound_count; index++) {
    const char *candidate = config->outbounds[index].name;
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
  ftun_core_t *core;
  ftun_snapshot_manager_t *manager;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (budget == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_core_context_create(budget, &core);
  if (status != FTUN_OK) return status;
  manager = (ftun_snapshot_manager_t *)calloc(1u, sizeof(*manager));
  if (manager == NULL) {
    (void)ftun_core_context_destroy(&core);
    return FTUN_E_LIMIT;
  }
  manager->runtime_magic = FTUN_RUNTIME_MANAGER_MAGIC;
  manager->retained_limit = retained_limit;
  manager->retained_bytes_limit = retained_bytes_limit;
  status = ftun_core_context_bind(core, manager);
  if (status != FTUN_OK) {
    free(manager);
    (void)ftun_core_context_destroy(&core);
    return status;
  }
  *out = core;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_manager_get_info(const ftun_core_t *core,
                                            ftun_runtime_manager_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (!ftun_runtime_core_valid(core) || out == NULL) return FTUN_E_INVALID;
  out->generation = core->generation;
  out->has_active = FTUN_MANAGER(core)->active != NULL;
  out->has_candidate = FTUN_MANAGER(core)->candidate != NULL;
  out->retained_count = FTUN_MANAGER(core)->retained_count;
  out->retained_limit = FTUN_MANAGER(core)->retained_limit;
  out->retained_bytes = FTUN_MANAGER(core)->retained_bytes;
  out->retained_bytes_limit = FTUN_MANAGER(core)->retained_bytes_limit;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_manager_destroy(ftun_core_t **core)
{
  ftun_core_t *owned;
  ftun_snapshot_manager_t *manager;
  ftun_status_t status;
  if (core == NULL) return FTUN_E_INVALID;
  owned = *core;
  if (owned == NULL) return FTUN_OK;
  if (!ftun_runtime_core_valid(owned)) return FTUN_E_INVALID;
  manager = FTUN_MANAGER(owned);
  if (manager->candidate != NULL || manager->retained != NULL ||
      (manager->active != NULL && manager->active->reference_count != 1u)) {
    return FTUN_E_AGAIN;
  }
  if (manager->active != NULL) {
    status = ftun_runtime_finalize(manager->active);
    if (status != FTUN_OK) return status;
    manager->active = NULL;
  }
  manager->runtime_magic = 0u;
  free(manager);
  status = ftun_core_context_bind(owned, NULL);
  if (status != FTUN_OK) return status;
  return ftun_core_context_destroy(core);
}

static ftun_status_t ftun_runtime_frs_bind(uint16_t kind, ftun_string_t label,
                                           ftun_frs_set_t **out, void *user)
{
#if defined(FTUN_HAVE_MODULE_FRS)
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
  ftun_runtime_t **out)
{
  ftun_runtime_t *runtime;
  ftun_frs_view_t *frs_view = NULL;
  ftun_reservation_t *reservation = NULL;
  size_t item_count;
  size_t accounted_bytes;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (!ftun_runtime_core_valid(core) || config == NULL || out == NULL ||
      config->plan == NULL) return FTUN_E_INVALID;
  if (FTUN_MANAGER(core)->candidate != NULL) return FTUN_E_AGAIN;
  if (core->generation == UINT64_MAX ||
      !ftun_runtime_can_retain_active(core)) return FTUN_E_LIMIT;
  if (!ftun_runtime_layout(config, &item_count, &accounted_bytes)) return FTUN_E_LIMIT;
  status = ftun_budget_reserve(core->budget, accounted_bytes, &reservation);
  if (status != FTUN_OK) return status;
  runtime = (ftun_runtime_t *)calloc(1u, sizeof(*runtime));
  if (runtime == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  if (item_count != 0u) {
    runtime->snapshot.prepared_items = (ftun_runtime_prepared_item_t *)calloc(
      item_count, sizeof(*runtime->snapshot.prepared_items));
    if (runtime->snapshot.prepared_items == NULL) {
      free(runtime);
      (void)ftun_reservation_release(&reservation);
      return FTUN_E_LIMIT;
    }
  }
  if (config->outbound_count != 0u) {
    runtime->owner_state.group_choices = (ftun_runtime_group_choice_state_t *)calloc(
      config->outbound_count, sizeof(*runtime->owner_state.group_choices));
    if (runtime->owner_state.group_choices == NULL) {
      free(runtime->snapshot.prepared_items);
      free(runtime);
      (void)ftun_reservation_release(&reservation);
      return FTUN_E_LIMIT;
    }
  }
#if defined(FTUN_HAVE_MODULE_FRS)
  if ((config->plan->prepare & FTUN_PLAN_FRS) != 0u) {
    if (provided_frs != NULL) {
      status = ftun_frs_view_retain(provided_frs);
      if (status == FTUN_OK) frs_view = provided_frs;
    } else if (config->frs.path == NULL || config->frs.path[0] == '\0') {
      status = FTUN_E_INVALID;
    } else {
      status = ftun_frs_open(core, config->frs.path, &frs_view);
    }
    if (status != FTUN_OK) {
      free(runtime->owner_state.group_choices);
      free(runtime->snapshot.prepared_items);
      free(runtime);
      (void)ftun_reservation_release(&reservation);
      return status;
    }
  } else if (provided_frs != NULL) {
    free(runtime->owner_state.group_choices);
    free(runtime->snapshot.prepared_items);
    free(runtime);
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_INVALID;
  }
#else
  if (provided_frs != NULL || (config->plan->prepare & FTUN_PLAN_FRS) != 0u) {
    free(runtime->owner_state.group_choices);
    free(runtime->snapshot.prepared_items);
    free(runtime);
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_UNSUPPORTED;
  }
#endif
  status = ftun_route_table_create_with_frs(
    0u, (const char *const *)config->rules.items, config->rules.count,
    ftun_runtime_resolve_outbound, (void *)config,
    frs_view == NULL ? NULL : ftun_runtime_frs_bind, frs_view,
    &runtime->snapshot.routes);
  if (status != FTUN_OK) {
#if defined(FTUN_HAVE_MODULE_FRS)
    (void)ftun_frs_view_release(&frs_view);
#endif
    free(runtime->owner_state.group_choices);
    free(runtime->snapshot.prepared_items);
    free(runtime);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  status = ftun_config_retain((ftun_config_t *)config);
  if (status != FTUN_OK) {
    (void)ftun_route_table_destroy(&runtime->snapshot.routes);
#if defined(FTUN_HAVE_MODULE_FRS)
    (void)ftun_frs_view_release(&frs_view);
#endif
    free(runtime->owner_state.group_choices);
    free(runtime->snapshot.prepared_items);
    free(runtime);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  runtime->owner = core;
  runtime->snapshot.config = config;
  runtime->reservation = reservation;
  runtime->snapshot.frs_view = frs_view;
  runtime->snapshot.prepared_item_count = item_count;
  runtime->snapshot.accounted_bytes = accounted_bytes;
  runtime->owner_state.group_choice_count = config->outbound_count;
  runtime->reference_count = 1u;
  runtime->state = FTUN_RUNTIME_CANDIDATE;
  status = ftun_runtime_fill_group_defaults(runtime, config);
  if (status != FTUN_OK) {
    (void)ftun_config_destroy((ftun_config_t **)&runtime->snapshot.config);
    (void)ftun_route_table_destroy(&runtime->snapshot.routes);
#if defined(FTUN_HAVE_MODULE_FRS)
    (void)ftun_frs_view_release(&runtime->snapshot.frs_view);
#endif
    free(runtime->owner_state.group_choices);
    free(runtime->snapshot.prepared_items);
    free(runtime);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  ftun_runtime_fill_items(runtime, config->plan);
  FTUN_MANAGER(core)->candidate = runtime;
  *out = runtime;
  return FTUN_OK;
}

/* TASK-CORE-001 / TEST-CORE-001，目标 0.2.0：候选准备和快照生命周期。 */
ftun_status_t ftun_runtime_prepare(ftun_core_t *core,
                                   const ftun_config_t *config,
                                   ftun_runtime_t **out)
{
  return ftun_runtime_prepare_internal(core, config, NULL, out);
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
  return ftun_runtime_prepare_internal(core, config, view, out);
}

#if defined(FTUN_HAVE_MODULE_FRS)
ftun_status_t ftun_runtime_prepare_detached(
  const ftun_config_t *config, ftun_frs_view_t *view, ftun_runtime_t **out)
{
  ftun_runtime_t *runtime;
  size_t item_count;
  size_t accounted_bytes;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (config == NULL || out == NULL || config->plan == NULL ||
      (((config->plan->prepare & FTUN_PLAN_FRS) != 0u) != (view != NULL)) ||
      !ftun_runtime_layout(config, &item_count, &accounted_bytes)) {
    return FTUN_E_INVALID;
  }
  runtime = (ftun_runtime_t *)calloc(1u, sizeof(*runtime));
  if (runtime == NULL) return FTUN_E_LIMIT;
  if (item_count != 0u) {
    runtime->snapshot.prepared_items = (ftun_runtime_prepared_item_t *)calloc(
      item_count, sizeof(*runtime->snapshot.prepared_items));
    if (runtime->snapshot.prepared_items == NULL) goto allocation_error;
  }
  if (config->outbound_count != 0u) {
    runtime->owner_state.group_choices = (ftun_runtime_group_choice_state_t *)calloc(
      config->outbound_count, sizeof(*runtime->owner_state.group_choices));
    if (runtime->owner_state.group_choices == NULL) goto allocation_error;
  }
  status = ftun_route_table_create_with_frs(
    0u, (const char *const *)config->rules.items, config->rules.count,
    ftun_runtime_resolve_outbound, (void *)config,
    view == NULL ? NULL : ftun_runtime_frs_bind, view, &runtime->snapshot.routes);
  if (status != FTUN_OK) goto status_error;
  runtime->snapshot.config = config;
  runtime->snapshot.frs_view = view;
  runtime->snapshot.prepared_item_count = item_count;
  runtime->snapshot.accounted_bytes = accounted_bytes;
  runtime->owner_state.group_choice_count = config->outbound_count;
  runtime->reference_count = 1u;
  runtime->state = FTUN_RUNTIME_CANDIDATE;
  status = ftun_runtime_fill_group_defaults(runtime, config);
  if (status != FTUN_OK) goto route_error;
  ftun_runtime_fill_items(runtime, config->plan);
  *out = runtime;
  return FTUN_OK;

route_error:
  (void)ftun_route_table_destroy(&runtime->snapshot.routes);
status_error:
  free(runtime->owner_state.group_choices);
  free(runtime->snapshot.prepared_items);
  free(runtime);
  return status;

allocation_error:
  free(runtime->owner_state.group_choices);
  free(runtime->snapshot.prepared_items);
  free(runtime);
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
  ftun_status_t status = FTUN_OK;
  ftun_status_t step;
  if (prepared == NULL) return FTUN_E_INVALID;
  runtime = *prepared;
  if (runtime == NULL) return FTUN_OK;
  if (runtime->owner != NULL || runtime->reservation != NULL ||
      runtime->state != FTUN_RUNTIME_CANDIDATE ||
      runtime->reference_count != 1u) return FTUN_E_STATE_CORRUPT;
  step = ftun_route_table_destroy(&runtime->snapshot.routes);
  if (step != FTUN_OK) status = step;
  step = ftun_frs_view_release(&runtime->snapshot.frs_view);
  if (status == FTUN_OK) status = step;
  free(runtime->owner_state.group_choices);
  free(runtime->snapshot.prepared_items);
  memset(runtime, 0, sizeof(*runtime));
  free(runtime);
  *prepared = NULL;
  return status;
}

ftun_status_t ftun_runtime_attach_prepared(ftun_core_t *core,
                                           ftun_runtime_t **prepared,
                                           ftun_runtime_t **out)
{
  ftun_runtime_t *runtime;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (!ftun_runtime_core_valid(core) || prepared == NULL || out == NULL) {
    return FTUN_E_INVALID;
  }
  runtime = *prepared;
  if (runtime == NULL || runtime->owner != NULL ||
      runtime->reservation != NULL || runtime->snapshot.config == NULL ||
      runtime->snapshot.routes == NULL ||
      ((((runtime->snapshot.config->plan->prepare & FTUN_PLAN_FRS) != 0u) !=
        (runtime->snapshot.frs_view != NULL))) ||
      runtime->state != FTUN_RUNTIME_CANDIDATE ||
      runtime->reference_count != 1u) return FTUN_E_INVALID;
  if (FTUN_MANAGER(core)->candidate != NULL) return FTUN_E_AGAIN;
  if (core->generation == UINT64_MAX ||
      !ftun_runtime_can_retain_active(core)) return FTUN_E_LIMIT;
  status = ftun_config_retain((ftun_config_t *)runtime->snapshot.config);
  if (status != FTUN_OK) return status;
  status = ftun_budget_reserve(core->budget, runtime->snapshot.accounted_bytes,
                               &reservation);
  if (status == FTUN_OK && runtime->snapshot.frs_view != NULL) {
    status = ftun_frs_view_bind_budget(runtime->snapshot.frs_view, core->budget);
  }
  if (status != FTUN_OK) {
    ftun_config_t *retained_config = (ftun_config_t *)runtime->snapshot.config;
    (void)ftun_reservation_release(&reservation);
    (void)ftun_config_destroy(&retained_config);
    return status;
  }
  runtime->owner = core;
  runtime->reservation = reservation;
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
  if (prepared == NULL || out == NULL || prepared->snapshot.frs_view == NULL ||
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
  if (candidate != FTUN_MANAGER(core)->candidate || candidate->owner != core ||
      candidate->state != FTUN_RUNTIME_CANDIDATE ||
      candidate->reference_count != 1u) return FTUN_E_STALE;
  previous = FTUN_MANAGER(core)->active;
  if (core->generation == UINT64_MAX) return FTUN_E_LIMIT;
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
  if (generation == 0u || generation != core->generation + 1u) {
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

ftun_status_t ftun_runtime_commit(ftun_core_t *core,
                                  ftun_runtime_t **candidate)
{
  ftun_runtime_t *next;
  ftun_runtime_t *previous;
  ftun_status_t status;
  if (!ftun_runtime_core_valid(core) || candidate == NULL || *candidate == NULL) {
    return FTUN_E_INVALID;
  }
  next = *candidate;
  status = ftun_runtime_can_commit(core, next);
  if (status != FTUN_OK) return status;
  previous = FTUN_MANAGER(core)->active;
  status = ftun_runtime_stage_commit(core, next, core->generation + 1u);
  if (status != FTUN_OK) return status;
  core->generation++;
  next->state = FTUN_RUNTIME_ACTIVE;
  FTUN_MANAGER(core)->candidate = NULL;
  FTUN_MANAGER(core)->active = next;
  *candidate = NULL;
  if (previous != NULL) {
    if (previous->reference_count == 1u) {
      (void)ftun_runtime_finalize(previous);
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
  return ftun_runtime_finalize(runtime);
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
  owned->reference_count--;
  *runtime = NULL;
  if (owned->state == FTUN_RUNTIME_RETAINED && owned->reference_count == 1u) {
    if (FTUN_MANAGER(core)->retained_count == 0u ||
        owned->snapshot.accounted_bytes > FTUN_MANAGER(core)->retained_bytes ||
        !ftun_runtime_unlink_retained(core, owned)) {
      return FTUN_E_STATE_CORRUPT;
    }
    FTUN_MANAGER(core)->retained_count--;
    FTUN_MANAGER(core)->retained_bytes -= owned->snapshot.accounted_bytes;
    return ftun_runtime_finalize(owned);
  }
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
