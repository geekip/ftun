/* TASK-GROUP-001 / TEST-GROUP-001：ftun_select_set，目标 0.4.0。 */
#include "select.h"
#include "core/runtime.h"
#include <string.h>

static int ftun_select_has_member(const ftun_select_state_t *state,
                                  uint32_t member_id)
{
  size_t index;
  for (index = 0u; index < state->member_count; index++) {
    if (state->members[index] == member_id) return 1;
  }
  return 0;
}

ftun_status_t ftun_select_state_init(ftun_select_state_t *state,
                                     uint64_t generation,
                                     uint32_t group_id,
                                     const uint32_t *members,
                                     size_t member_count,
                                     uint32_t default_member_id)
{
  if (state == NULL || generation == 0u || group_id == 0u ||
      members == NULL || member_count == 0u) return FTUN_E_INVALID;
  memset(state, 0, sizeof(*state));
  state->generation = generation;
  state->group_id = group_id;
  state->members = members;
  state->member_count = member_count;
  state->default_member_id = default_member_id;
  if (!ftun_select_has_member(state, default_member_id)) {
    memset(state, 0, sizeof(*state));
    return FTUN_E_INVALID;
  }
  state->selected_member_id = default_member_id;
  return FTUN_OK;
}

ftun_status_t ftun_select_state_set(ftun_select_state_t *state,
                                    uint64_t generation,
                                    uint32_t member_id)
{
  if (state == NULL || generation == 0u) {
    return FTUN_E_INVALID;
  }
  if (state->generation != generation) return FTUN_E_STALE;
  if (!ftun_select_has_member(state, member_id)) return FTUN_E_REJECTED;
  state->selected_member_id = member_id;
  return FTUN_OK;
}

ftun_status_t ftun_select_state_choice(const ftun_select_state_t *state,
                                       ftun_group_choice_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (state == NULL || out == NULL || state->generation == 0u ||
      !ftun_select_has_member(state, state->selected_member_id)) {
    return FTUN_E_INVALID;
  }
  out->generation = state->generation;
  out->leaf_id = state->selected_member_id;
  return FTUN_OK;
}

ftun_status_t ftun_select_set(ftun_core_t *core, uint32_t group_id, uint32_t member_id)
{
  return ftun_runtime_select_set(core, group_id, member_id);
}
