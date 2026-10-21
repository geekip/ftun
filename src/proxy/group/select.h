#ifndef FTUN_PROXY_GROUP_SELECT_H
#define FTUN_PROXY_GROUP_SELECT_H
/* TASK-GROUP-001 / TEST-GROUP-001：ftun_select_set，目标 0.4.0。 */
#include "internal/contracts.h"

typedef struct {
  uint64_t generation;
  uint32_t group_id;
  const uint32_t *members; /* 同步借用，生命周期由不可变 Runtime 保证。 */
  size_t member_count;
  uint32_t default_member_id;
  uint32_t selected_member_id;
} ftun_select_state_t;

/* TASK-GROUP-001 / TEST-GROUP-001：人工选择只影响后续路径展开。 */
ftun_status_t ftun_select_state_init(ftun_select_state_t *state,
                                     uint64_t generation,
                                     uint32_t group_id,
                                     const uint32_t *members,
                                     size_t member_count,
                                     uint32_t default_member_id);
ftun_status_t ftun_select_state_set(ftun_select_state_t *state,
                                    uint64_t generation,
                                    uint32_t member_id);
ftun_status_t ftun_select_state_choice(const ftun_select_state_t *state,
                                       ftun_group_choice_t *out);

/* owner-loop Runtime 入口；校验 active generation、组类型与成员身份。 */
ftun_status_t ftun_select_set(ftun_core_t *core, uint32_t group_id, uint32_t member_id);
#endif
