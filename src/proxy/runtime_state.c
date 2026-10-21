#include "proxy/runtime_internal.h"
#include "proxy/snapshot.h"

#include <string.h>

static ftun_status_t ftun_runtime_outbound_index(
  const ftun_runtime_t *runtime, uint32_t outbound_id, size_t *out)
{
  size_t index;
  if (runtime == NULL || out == NULL ||
      outbound_id < FTUN_OUTBOUND_ID_NAMED_BASE) return FTUN_E_INVALID;
  index = (size_t)(outbound_id - FTUN_OUTBOUND_ID_NAMED_BASE);
  if (runtime->snapshot.config == NULL ||
      runtime->owner_state.group_choice_count !=
        runtime->snapshot.config->outbound_count ||
      index >= runtime->owner_state.group_choice_count) {
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
  return ftun_runtime_resolve_outbound(view, out, (void *)runtime->snapshot.config);
}

static int ftun_runtime_group_has_member(const ftun_runtime_t *runtime,
                                         size_t group_index,
                                         uint32_t member_id)
{
  const ftun_config_outbound_t *group =
    &runtime->snapshot.config->outbounds[group_index];
  size_t index;
  for (index = 0u; index < group->members.count; index++) {
    uint32_t candidate = 0u;
    if (ftun_runtime_member_id(runtime, group->members.items[index],
                               &candidate) == FTUN_OK &&
        candidate == member_id) return 1;
  }
  return 0;
}

static int ftun_runtime_string_equal(ftun_string_t value, const char *text);

ftun_status_t ftun_runtime_select_set(ftun_core_t *core,
                                      uint32_t group_id,
                                      uint32_t member_id)
{
  ftun_runtime_t *runtime;
  size_t index;
  ftun_status_t status;
  if (!ftun_runtime_core_valid(core)) return FTUN_E_INVALID;
  runtime = FTUN_MANAGER(core)->active;
  if (runtime == NULL) return FTUN_E_AGAIN;
  status = ftun_runtime_outbound_index(runtime, group_id, &index);
  if (status != FTUN_OK) return status;
  if (runtime->snapshot.config->outbounds[index].kind != FTUN_CONFIG_OUTBOUND_SELECT) {
    return FTUN_E_UNSUPPORTED;
  }
  if (!ftun_runtime_group_has_member(runtime, index, member_id)) {
    return FTUN_E_REJECTED;
  }
  runtime->owner_state.group_choices[index].selected_member_id = member_id;
  runtime->owner_state.group_choices[index].selected = true;
  runtime->owner_state.group_choices[index].degraded = false;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_select_names(ftun_core_t *core,
                                        ftun_string_t group,
                                        ftun_string_t member)
{
  ftun_runtime_t *runtime;
  size_t index;
  uint32_t member_id;
  if (!ftun_runtime_core_valid(core) || group.data == NULL ||
      group.length == 0u || member.data == NULL || member.length == 0u) {
    return FTUN_E_INVALID;
  }
  runtime = FTUN_MANAGER(core)->active;
  if (runtime == NULL) return FTUN_E_AGAIN;
  for (index = 0u; index < runtime->snapshot.config->outbound_count; index++) {
    const ftun_config_outbound_t *outbound = &runtime->snapshot.config->outbounds[index];
    if (!ftun_runtime_string_equal(group, outbound->name)) continue;
    if (outbound->kind != FTUN_CONFIG_OUTBOUND_SELECT) {
      return FTUN_E_UNSUPPORTED;
    }
    if (ftun_runtime_resolve_outbound(member, &member_id,
                                      (void *)runtime->snapshot.config) != FTUN_OK) {
      return FTUN_E_REJECTED;
    }
    if (index > UINT32_MAX - FTUN_OUTBOUND_ID_NAMED_BASE) return FTUN_E_LIMIT;
    return ftun_runtime_select_set(
      core, (uint32_t)index + FTUN_OUTBOUND_ID_NAMED_BASE, member_id);
  }
  return FTUN_E_REJECTED;
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
  outbound = &runtime->snapshot.config->outbounds[index];
  if (outbound->dns_server != NULL && outbound->dns_server[0] != '\0') {
    dns_server->data = outbound->dns_server;
    dns_server->length = strlen(outbound->dns_server);
  }
  if (outbound->kind == FTUN_CONFIG_OUTBOUND_SOCKS5) return FTUN_OK;
  *is_group = true;
  *member_id = runtime->owner_state.group_choices[index].selected_member_id;
  *degraded = runtime->owner_state.group_choices[index].degraded;
  if (!runtime->owner_state.group_choices[index].selected ||
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
  runtime = FTUN_MANAGER(core)->active;
  if (runtime == NULL) return FTUN_E_AGAIN;
  if (runtime->generation != choice->generation) return FTUN_E_STALE;
  status = ftun_runtime_outbound_index(runtime, group_id, &index);
  if (status != FTUN_OK) return status;
  if (runtime->snapshot.config->outbounds[index].kind != FTUN_CONFIG_OUTBOUND_URL_TEST) {
    return FTUN_E_UNSUPPORTED;
  }
  if (!ftun_runtime_group_has_member(runtime, index, choice->leaf_id)) {
    return FTUN_E_REJECTED;
  }
  runtime->owner_state.group_choices[index].selected_member_id = choice->leaf_id;
  runtime->owner_state.group_choices[index].selected = true;
  runtime->owner_state.group_choices[index].degraded = choice->degraded;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_active_config(const ftun_core_t *core,
                                         const ftun_config_t **out)
{
  if (out != NULL) *out = NULL;
  if (!ftun_runtime_core_valid(core) || out == NULL) return FTUN_E_INVALID;
  if (FTUN_MANAGER(core)->active == NULL || FTUN_MANAGER(core)->active->snapshot.config == NULL) return FTUN_E_AGAIN;
  *out = FTUN_MANAGER(core)->active->snapshot.config;
  return FTUN_OK;
}

ftun_status_t ftun_runtime_group_records(const ftun_core_t *core,
                                         ftun_runtime_group_record_t *records,
                                         size_t capacity, size_t *out_count)
{
  const ftun_runtime_t *runtime;
  size_t index;
  size_t count = 0u;
  if (out_count != NULL) *out_count = 0u;
  if (!ftun_runtime_core_valid(core) || out_count == NULL ||
      (capacity != 0u && records == NULL)) return FTUN_E_INVALID;
  runtime = FTUN_MANAGER(core)->active;
  if (runtime == NULL || runtime->snapshot.config == NULL) return FTUN_E_AGAIN;
  for (index = 0u; index < runtime->snapshot.config->outbound_count; index++) {
    const ftun_config_outbound_t *group = &runtime->snapshot.config->outbounds[index];
    const ftun_runtime_group_choice_state_t *state =
      &runtime->owner_state.group_choices[index];
    size_t member_index;
    const char *member_name = NULL;
    if (group->kind == FTUN_CONFIG_OUTBOUND_SOCKS5) continue;
    if (!state->selected) return FTUN_E_STATE_CORRUPT;
    for (member_index = 0u; member_index < group->members.count;
         member_index++) {
      uint32_t member_id = 0u;
      if (ftun_runtime_member_id(runtime, group->members.items[member_index],
                                 &member_id) == FTUN_OK &&
          member_id == state->selected_member_id) {
        member_name = group->members.items[member_index];
        break;
      }
    }
    if (member_name == NULL) return FTUN_E_STATE_CORRUPT;
    if (count < capacity) {
      ftun_runtime_group_record_t *record = &records[count];
      memset(record, 0, sizeof(*record));
      record->group.data = group->name;
      record->group.length = strlen(group->name);
      record->member.data = member_name;
      record->member.length = strlen(member_name);
      record->kind = group->kind == FTUN_CONFIG_OUTBOUND_SELECT
        ? FTUN_RUNTIME_GROUP_SELECT : FTUN_RUNTIME_GROUP_URL_TEST;
      record->degraded = state->degraded;
      record->health_valid = state->health_valid;
      record->health_success = state->health_success;
      record->latency_ms = state->latency_ms;
      record->observed_ms = state->observed_ms;
    }
    count++;
  }
  *out_count = count;
  return count > capacity ? FTUN_E_LIMIT : FTUN_OK;
}

static int ftun_runtime_string_equal(ftun_string_t value, const char *text)
{
  return text != NULL && strlen(text) == value.length &&
    memcmp(text, value.data, value.length) == 0;
}

static ftun_status_t ftun_runtime_group_restore_into(
  ftun_runtime_t *runtime, const ftun_runtime_group_record_t *record,
  bool restore_health)
{
  size_t index;
  uint32_t member_id = 0u;
  if (runtime == NULL || record == NULL ||
      record->group.data == NULL || record->group.length == 0u ||
      record->member.data == NULL || record->member.length == 0u) {
    return FTUN_E_INVALID;
  }
  for (index = 0u; index < runtime->snapshot.config->outbound_count; index++) {
    const ftun_config_outbound_t *group = &runtime->snapshot.config->outbounds[index];
    ftun_runtime_group_kind_t kind;
    size_t member_index;
    if (!ftun_runtime_string_equal(record->group, group->name)) continue;
    if (group->kind == FTUN_CONFIG_OUTBOUND_SOCKS5) return FTUN_E_REJECTED;
    kind = group->kind == FTUN_CONFIG_OUTBOUND_SELECT
      ? FTUN_RUNTIME_GROUP_SELECT : FTUN_RUNTIME_GROUP_URL_TEST;
    if (kind != record->kind) return FTUN_E_REJECTED;
    for (member_index = 0u; member_index < group->members.count;
         member_index++) {
      if (!ftun_runtime_string_equal(record->member,
                                     group->members.items[member_index])) {
        continue;
      }
      if (ftun_runtime_member_id(runtime, group->members.items[member_index],
                                 &member_id) != FTUN_OK) {
        return FTUN_E_STATE_CORRUPT;
      }
      runtime->owner_state.group_choices[index].selected_member_id = member_id;
      runtime->owner_state.group_choices[index].selected = true;
      runtime->owner_state.group_choices[index].degraded = record->degraded;
      if (restore_health && kind == FTUN_RUNTIME_GROUP_URL_TEST &&
          record->health_valid) {
        runtime->owner_state.group_choices[index].health_valid = true;
        runtime->owner_state.group_choices[index].health_success = record->health_success;
        runtime->owner_state.group_choices[index].latency_ms = record->latency_ms;
        runtime->owner_state.group_choices[index].observed_ms = record->observed_ms;
      }
      return FTUN_OK;
    }
    return FTUN_E_REJECTED;
  }
  return FTUN_E_REJECTED;
}

ftun_status_t ftun_runtime_group_restore(ftun_core_t *core,
                                         const ftun_runtime_group_record_t *record,
                                         bool restore_health)
{
  if (!ftun_runtime_core_valid(core)) return FTUN_E_INVALID;
  if (FTUN_MANAGER(core)->active == NULL) return FTUN_E_AGAIN;
  return ftun_runtime_group_restore_into(FTUN_MANAGER(core)->active, record, restore_health);
}

ftun_status_t ftun_runtime_candidate_group_restore(
  ftun_core_t *core, const ftun_runtime_group_record_t *record,
  bool restore_health)
{
  if (!ftun_runtime_core_valid(core)) return FTUN_E_INVALID;
  if (FTUN_MANAGER(core)->candidate == NULL) return FTUN_E_AGAIN;
  return ftun_runtime_group_restore_into(FTUN_MANAGER(core)->candidate, record,
                                         restore_health);
}

ftun_status_t ftun_runtime_group_publish_health(
  ftun_core_t *core, uint32_t group_id, const ftun_group_choice_t *choice,
  const ftun_health_sample_t *sample)
{
  ftun_runtime_t *runtime;
  size_t index;
  ftun_status_t status;
  if (sample == NULL || sample->member_id != choice->leaf_id) {
    return FTUN_E_INVALID;
  }
  status = ftun_runtime_group_publish(core, group_id, choice);
  if (status != FTUN_OK) return status;
  runtime = FTUN_MANAGER(core)->active;
  status = ftun_runtime_outbound_index(runtime, group_id, &index);
  if (status != FTUN_OK) return status;
  runtime->owner_state.group_choices[index].health_valid = true;
  runtime->owner_state.group_choices[index].health_success = sample->success;
  runtime->owner_state.group_choices[index].latency_ms = sample->latency_ms;
  runtime->owner_state.group_choices[index].observed_ms = sample->observed_ms;
  return FTUN_OK;
}
