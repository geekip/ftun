#include "runtime.h"
#include "config/compile.h"
#include "config/model.h"
#include "config/parser.h"
#include "route/router.h"
#include "route/rule.h"
#if defined(FTUN_HAVE_MODULE_FRS)
#include "frs/frs.h"
#endif
#include <stdlib.h>
#include <string.h>

#define FTUN_RUNTIME_MANAGER_MAGIC UINT32_C(0x4654524d)

typedef struct {
  uint64_t feature;
  size_t ordinal;
} ftun_runtime_prepared_item_t;

typedef struct {
  uint32_t selected_member_id;
  bool selected;
  bool degraded;
} ftun_runtime_group_choice_state_t;

struct ftun_runtime {
  ftun_core_t *owner;
  const ftun_config_t *config;
  ftun_reservation_t *reservation;
  ftun_runtime_prepared_item_t *prepared_items;
  ftun_runtime_group_choice_state_t *group_choices;
  ftun_route_table_t *routes;
  ftun_frs_view_t *frs_view;
  size_t prepared_item_count;
  size_t accounted_bytes;
  size_t reference_count;
  uint64_t generation;
  ftun_runtime_state_t state;
  ftun_runtime_t *next_retained;
};

struct ftun_core {
  uint32_t runtime_magic;
  ftun_budget_t *budget;
  ftun_fakeip_service_t *fakeip;
  ftun_dns_dispatcher_t *dns;
  ftun_runtime_t *active;
  ftun_runtime_t *candidate;
  ftun_runtime_t *retained;
  uint64_t generation;
  size_t retained_count;
  size_t retained_limit;
};

static int ftun_runtime_core_valid(const ftun_core_t *core)
{
  return core != NULL && core->runtime_magic == FTUN_RUNTIME_MANAGER_MAGIC &&
         core->budget != NULL;
}

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

static void ftun_runtime_fill_items(ftun_runtime_t *runtime,
                                    const ftun_feature_plan_t *plan)
{
  size_t cursor = 0u;
  size_t bit;
  size_t index;
  for (bit = 0u; bit < 64u; bit++) {
    uint64_t feature = UINT64_C(1) << bit;
    if ((plan->prepare & feature) != 0u) {
      runtime->prepared_items[cursor].feature = feature;
      runtime->prepared_items[cursor].ordinal = 0u;
      cursor++;
    }
  }
  for (index = 0u; index < plan->prepare_listener_count; index++, cursor++) {
    runtime->prepared_items[cursor].feature = FTUN_PLAN_INBOUND;
    runtime->prepared_items[cursor].ordinal = index;
  }
  for (index = 0u; index < plan->prepare_tun_count; index++, cursor++) {
    runtime->prepared_items[cursor].feature = FTUN_PLAN_TUN;
    runtime->prepared_items[cursor].ordinal = index;
  }
  for (index = 0u; index < plan->prepare_frs_count; index++, cursor++) {
    runtime->prepared_items[cursor].feature = FTUN_PLAN_FRS;
    runtime->prepared_items[cursor].ordinal = index;
  }
}

static ftun_status_t ftun_runtime_finalize(ftun_runtime_t *runtime)
{
  ftun_config_t *config;
  ftun_status_t status;
  if (runtime == NULL || runtime->reference_count != 1u) return FTUN_E_STATE_CORRUPT;
  config = (ftun_config_t *)runtime->config;
  status = ftun_config_destroy(&config);
  if (status != FTUN_OK) return status;
  status = ftun_route_table_destroy(&runtime->routes);
  if (status != FTUN_OK) return status;
#if defined(FTUN_HAVE_MODULE_FRS)
  status = ftun_frs_view_release(&runtime->frs_view);
  if (status != FTUN_OK) return status;
#endif
  free(runtime->prepared_items);
  runtime->prepared_items = NULL;
  free(runtime->group_choices);
  runtime->group_choices = NULL;
  status = ftun_reservation_release(&runtime->reservation);
  if (status != FTUN_OK) return status;
  runtime->owner = NULL;
  runtime->config = NULL;
  runtime->reference_count = 0u;
  free(runtime);
  return FTUN_OK;
}

static ftun_status_t ftun_runtime_resolve_outbound(ftun_string_t name,
                                                    uint32_t *out,
                                                    void *user)
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
  ftun_runtime_t **link = &core->retained;
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

ftun_status_t ftun_runtime_manager_create(ftun_budget_t *budget,
                                          size_t retained_limit,
                                          ftun_core_t **out)
{
  ftun_core_t *core;
  if (out != NULL) *out = NULL;
  if (budget == NULL || out == NULL) return FTUN_E_INVALID;
  core = (ftun_core_t *)calloc(1u, sizeof(*core));
  if (core == NULL) return FTUN_E_LIMIT;
  core->runtime_magic = FTUN_RUNTIME_MANAGER_MAGIC;
  core->budget = budget;
  core->retained_limit = retained_limit;
  *out = core;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_manager_get_info(const ftun_core_t *core,
                                            ftun_runtime_manager_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (!ftun_runtime_core_valid(core) || out == NULL) return FTUN_E_INVALID;
  out->generation = core->generation;
  out->has_active = core->active != NULL;
  out->has_candidate = core->candidate != NULL;
  out->retained_count = core->retained_count;
  out->retained_limit = core->retained_limit;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_manager_budget(ftun_core_t *core,
                                          ftun_budget_t **out)
{
  if (out != NULL) *out = NULL;
  if (!ftun_runtime_core_valid(core) || out == NULL) return FTUN_E_INVALID;
  *out = core->budget;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_manager_set_fakeip(ftun_core_t *core,
                                              ftun_fakeip_service_t *service)
{
  if (!ftun_runtime_core_valid(core)) return FTUN_E_INVALID;
  core->fakeip = service;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_manager_fakeip(ftun_core_t *core,
                                          ftun_fakeip_service_t **out)
{
  if (out != NULL) *out = NULL;
  if (!ftun_runtime_core_valid(core) || out == NULL) return FTUN_E_INVALID;
  if (core->fakeip == NULL) return FTUN_E_AGAIN;
  *out = core->fakeip;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_manager_set_dns(ftun_core_t *core,
                                           ftun_dns_dispatcher_t *dispatcher)
{
  if (!ftun_runtime_core_valid(core)) return FTUN_E_INVALID;
  core->dns = dispatcher;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_manager_dns(ftun_core_t *core,
                                       ftun_dns_dispatcher_t **out)
{
  if (out != NULL) *out = NULL;
  if (!ftun_runtime_core_valid(core) || out == NULL) return FTUN_E_INVALID;
  if (core->dns == NULL) return FTUN_E_AGAIN;
  *out = core->dns;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_manager_destroy(ftun_core_t **core)
{
  ftun_core_t *owned;
  ftun_status_t status;
  if (core == NULL) return FTUN_E_INVALID;
  owned = *core;
  if (owned == NULL) return FTUN_OK;
  if (!ftun_runtime_core_valid(owned)) return FTUN_E_INVALID;
  if (owned->candidate != NULL || owned->retained != NULL ||
      (owned->active != NULL && owned->active->reference_count != 1u)) {
    return FTUN_E_AGAIN;
  }
  if (owned->active != NULL) {
    status = ftun_runtime_finalize(owned->active);
    if (status != FTUN_OK) return status;
    owned->active = NULL;
  }
  owned->runtime_magic = 0u;
  owned->budget = NULL;
  owned->fakeip = NULL;
  owned->dns = NULL;
  free(owned);
  *core = NULL;
  return FTUN_OK;
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
  if (core->candidate != NULL) return FTUN_E_AGAIN;
  if (core->generation == UINT64_MAX ||
      (core->active != NULL && core->active->reference_count > 1u &&
       core->retained_count >= core->retained_limit)) return FTUN_E_LIMIT;
  if (!ftun_runtime_layout(config, &item_count, &accounted_bytes)) return FTUN_E_LIMIT;
  status = ftun_budget_reserve(core->budget, accounted_bytes, &reservation);
  if (status != FTUN_OK) return status;
  runtime = (ftun_runtime_t *)calloc(1u, sizeof(*runtime));
  if (runtime == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  if (item_count != 0u) {
    runtime->prepared_items = (ftun_runtime_prepared_item_t *)calloc(
      item_count, sizeof(*runtime->prepared_items));
    if (runtime->prepared_items == NULL) {
      free(runtime);
      (void)ftun_reservation_release(&reservation);
      return FTUN_E_LIMIT;
    }
  }
  if (config->outbound_count != 0u) {
    runtime->group_choices = (ftun_runtime_group_choice_state_t *)calloc(
      config->outbound_count, sizeof(*runtime->group_choices));
    if (runtime->group_choices == NULL) {
      free(runtime->prepared_items);
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
      free(runtime->group_choices);
      free(runtime->prepared_items);
      free(runtime);
      (void)ftun_reservation_release(&reservation);
      return status;
    }
  } else if (provided_frs != NULL) {
    free(runtime->group_choices);
    free(runtime->prepared_items);
    free(runtime);
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_INVALID;
  }
#else
  if (provided_frs != NULL || (config->plan->prepare & FTUN_PLAN_FRS) != 0u) {
    free(runtime->group_choices);
    free(runtime->prepared_items);
    free(runtime);
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_UNSUPPORTED;
  }
#endif
  status = ftun_route_table_create_with_frs(
    0u, (const char *const *)config->rules.items, config->rules.count,
    ftun_runtime_resolve_outbound, (void *)config,
    frs_view == NULL ? NULL : ftun_runtime_frs_bind, frs_view,
    &runtime->routes);
  if (status != FTUN_OK) {
#if defined(FTUN_HAVE_MODULE_FRS)
    (void)ftun_frs_view_release(&frs_view);
#endif
    free(runtime->group_choices);
    free(runtime->prepared_items);
    free(runtime);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  status = ftun_config_retain((ftun_config_t *)config);
  if (status != FTUN_OK) {
    (void)ftun_route_table_destroy(&runtime->routes);
#if defined(FTUN_HAVE_MODULE_FRS)
    (void)ftun_frs_view_release(&frs_view);
#endif
    free(runtime->group_choices);
    free(runtime->prepared_items);
    free(runtime);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  runtime->owner = core;
  runtime->config = config;
  runtime->reservation = reservation;
  runtime->frs_view = frs_view;
  runtime->prepared_item_count = item_count;
  runtime->accounted_bytes = accounted_bytes;
  runtime->reference_count = 1u;
  runtime->state = FTUN_RUNTIME_CANDIDATE;
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
          name.data = member;
          name.length = strlen(member);
          status = ftun_runtime_resolve_outbound(
            name, &runtime->group_choices[index].selected_member_id,
            (void *)config);
          if (status != FTUN_OK) {
            (void)ftun_config_destroy((ftun_config_t **)&runtime->config);
            (void)ftun_route_table_destroy(&runtime->routes);
#if defined(FTUN_HAVE_MODULE_FRS)
            (void)ftun_frs_view_release(&runtime->frs_view);
#endif
            free(runtime->group_choices);
            free(runtime->prepared_items);
            free(runtime);
            (void)ftun_reservation_release(&reservation);
            return status;
          }
          runtime->group_choices[index].selected = true;
          break;
        }
      }
    }
  }
  ftun_runtime_fill_items(runtime, config->plan);
  core->candidate = runtime;
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

ftun_status_t ftun_runtime_commit(ftun_core_t *core,
                                  ftun_runtime_t **candidate)
{
  ftun_runtime_t *next;
  ftun_runtime_t *previous;
  if (!ftun_runtime_core_valid(core) || candidate == NULL || *candidate == NULL) {
    return FTUN_E_INVALID;
  }
  next = *candidate;
  if (next != core->candidate || next->owner != core ||
      next->state != FTUN_RUNTIME_CANDIDATE || next->reference_count != 1u) {
    return FTUN_E_STALE;
  }
  previous = core->active;
  if (core->generation == UINT64_MAX) return FTUN_E_LIMIT;
  if (previous != NULL && previous->reference_count > 1u &&
      core->retained_count >= core->retained_limit) return FTUN_E_LIMIT;
  if (ftun_route_table_set_generation(next->routes,
                                      core->generation + 1u) != FTUN_OK) {
    return FTUN_E_STATE_CORRUPT;
  }
  core->generation++;
  next->generation = core->generation;
  next->state = FTUN_RUNTIME_ACTIVE;
  core->candidate = NULL;
  core->active = next;
  *candidate = NULL;
  if (previous != NULL) {
    if (previous->reference_count == 1u) {
      (void)ftun_runtime_finalize(previous);
    } else {
      previous->state = FTUN_RUNTIME_RETAINED;
      previous->next_retained = core->retained;
      core->retained = previous;
      core->retained_count++;
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
  if (runtime != core->candidate || runtime->owner != core ||
      runtime->state != FTUN_RUNTIME_CANDIDATE) return FTUN_E_STALE;
  core->candidate = NULL;
  *candidate = NULL;
  return ftun_runtime_finalize(runtime);
}

ftun_status_t ftun_runtime_active_acquire(ftun_core_t *core,
                                          ftun_runtime_t **out)
{
  ftun_runtime_t *runtime;
  if (out != NULL) *out = NULL;
  if (!ftun_runtime_core_valid(core) || out == NULL) return FTUN_E_INVALID;
  runtime = core->active;
  if (runtime == NULL) return FTUN_E_AGAIN;
  if (runtime->reference_count == SIZE_MAX) return FTUN_E_LIMIT;
  runtime->reference_count++;
  *out = runtime;
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
    if (!ftun_runtime_unlink_retained(core, owned) || core->retained_count == 0u) {
      return FTUN_E_STATE_CORRUPT;
    }
    core->retained_count--;
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
  out->accounted_bytes = runtime->accounted_bytes;
  out->prepared_item_count = runtime->prepared_item_count;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_route_table(const ftun_runtime_t *runtime,
                                       const ftun_route_table_t **out)
{
  if (out != NULL) *out = NULL;
  if (runtime == NULL || out == NULL || runtime->routes == NULL ||
      runtime->state == FTUN_RUNTIME_CANDIDATE || runtime->generation == 0u ||
      !ftun_runtime_core_valid(runtime->owner)) return FTUN_E_INVALID;
  *out = runtime->routes;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_frs_view(const ftun_runtime_t *runtime,
                                    ftun_frs_view_t **out)
{
  if (out != NULL) *out = NULL;
  if (runtime == NULL || out == NULL ||
      runtime->state == FTUN_RUNTIME_CANDIDATE || runtime->generation == 0u ||
      !ftun_runtime_core_valid(runtime->owner)) return FTUN_E_INVALID;
  if (runtime->frs_view == NULL) return FTUN_E_AGAIN;
  *out = runtime->frs_view;
  return FTUN_OK;
}

static ftun_status_t ftun_runtime_outbound_index(
  const ftun_runtime_t *runtime, uint32_t outbound_id, size_t *out)
{
  size_t index;
  if (runtime == NULL || out == NULL ||
      outbound_id < FTUN_OUTBOUND_ID_NAMED_BASE) return FTUN_E_INVALID;
  index = (size_t)(outbound_id - FTUN_OUTBOUND_ID_NAMED_BASE);
  if (runtime->config == NULL || index >= runtime->config->outbound_count) {
    return FTUN_E_INVALID;
  }
  *out = index;
  return FTUN_OK;
}

static ftun_status_t ftun_runtime_member_id(const ftun_runtime_t *runtime,
                                            const char *name,
                                            uint32_t *out)
{
  ftun_string_t view;
  if (runtime == NULL || name == NULL || out == NULL) return FTUN_E_INVALID;
  view.data = name;
  view.length = strlen(name);
  return ftun_runtime_resolve_outbound(view, out, (void *)runtime->config);
}

static int ftun_runtime_group_has_member(const ftun_runtime_t *runtime,
                                         size_t group_index,
                                         uint32_t member_id)
{
  const ftun_config_outbound_t *group =
    &runtime->config->outbounds[group_index];
  size_t index;
  for (index = 0u; index < group->members.count; index++) {
    uint32_t candidate = 0u;
    if (ftun_runtime_member_id(runtime, group->members.items[index],
                               &candidate) == FTUN_OK &&
        candidate == member_id) return 1;
  }
  return 0;
}

ftun_status_t ftun_runtime_select_set(ftun_core_t *core,
                                      uint32_t group_id,
                                      uint32_t member_id)
{
  ftun_runtime_t *runtime;
  size_t index;
  ftun_status_t status;
  if (!ftun_runtime_core_valid(core)) return FTUN_E_INVALID;
  runtime = core->active;
  if (runtime == NULL) return FTUN_E_AGAIN;
  status = ftun_runtime_outbound_index(runtime, group_id, &index);
  if (status != FTUN_OK) return status;
  if (runtime->config->outbounds[index].kind != FTUN_CONFIG_OUTBOUND_SELECT) {
    return FTUN_E_UNSUPPORTED;
  }
  if (!ftun_runtime_group_has_member(runtime, index, member_id)) {
    return FTUN_E_REJECTED;
  }
  runtime->group_choices[index].selected_member_id = member_id;
  runtime->group_choices[index].selected = true;
  runtime->group_choices[index].degraded = false;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_group_selected(const ftun_runtime_t *runtime,
                                          uint32_t group_id,
                                          uint32_t *member_id,
                                          bool *is_group,
                                          bool *degraded,
                                          ftun_string_t *dns_server)
{
  const ftun_config_outbound_t *outbound;
  size_t index;
  ftun_status_t status;
  if (member_id != NULL) *member_id = 0u;
  if (is_group != NULL) *is_group = false;
  if (degraded != NULL) *degraded = false;
  if (dns_server != NULL) memset(dns_server, 0, sizeof(*dns_server));
  if (runtime == NULL || member_id == NULL || is_group == NULL ||
      degraded == NULL || dns_server == NULL ||
      runtime->state == FTUN_RUNTIME_CANDIDATE || runtime->generation == 0u ||
      !ftun_runtime_core_valid(runtime->owner)) return FTUN_E_INVALID;
  if (group_id < FTUN_OUTBOUND_ID_NAMED_BASE) return FTUN_OK;
  status = ftun_runtime_outbound_index(runtime, group_id, &index);
  if (status != FTUN_OK) return status;
  outbound = &runtime->config->outbounds[index];
  if (outbound->dns_server != NULL && outbound->dns_server[0] != '\0') {
    dns_server->data = outbound->dns_server;
    dns_server->length = strlen(outbound->dns_server);
  }
  if (outbound->kind == FTUN_CONFIG_OUTBOUND_SOCKS5) return FTUN_OK;
  *is_group = true;
  *member_id = runtime->group_choices[index].selected_member_id;
  *degraded = runtime->group_choices[index].degraded;
  if (!runtime->group_choices[index].selected ||
      !ftun_runtime_group_has_member(runtime, index, *member_id)) {
    *member_id = 0u;
    *is_group = false;
    return FTUN_E_STATE_CORRUPT;
  }
  return FTUN_OK;
}

ftun_status_t ftun_runtime_group_publish(ftun_core_t *core,
                                         uint32_t group_id,
                                         const ftun_group_choice_t *choice)
{
  ftun_runtime_t *runtime;
  size_t index;
  ftun_status_t status;
  if (!ftun_runtime_core_valid(core) || choice == NULL ||
      choice->generation == 0u) return FTUN_E_INVALID;
  runtime = core->active;
  if (runtime == NULL) return FTUN_E_AGAIN;
  if (runtime->generation != choice->generation) return FTUN_E_STALE;
  status = ftun_runtime_outbound_index(runtime, group_id, &index);
  if (status != FTUN_OK) return status;
  if (runtime->config->outbounds[index].kind != FTUN_CONFIG_OUTBOUND_URL_TEST) {
    return FTUN_E_UNSUPPORTED;
  }
  if (!ftun_runtime_group_has_member(runtime, index, choice->leaf_id)) {
    return FTUN_E_REJECTED;
  }
  runtime->group_choices[index].selected_member_id = choice->leaf_id;
  runtime->group_choices[index].selected = true;
  runtime->group_choices[index].degraded = choice->degraded;
  return FTUN_OK;
}
