#ifndef FTUN_ROUTE_TARGET_H
#define FTUN_ROUTE_TARGET_H

#include "internal/contracts.h"

/* 目标与候选约束。
 * 需求 REQ-ROUTE-001；任务 TASK-ROUTE-003；目标 0.2.0；验收 TEST-ROUTE-003。
 * 返回值只借用 metadata 中的域名和候选；original 始终保持入口真实/FakeIP
 * 目标，identity 单独保存恢复或嗅探域名，dial 只能从 allowed 中选择。
 */
ftun_status_t ftun_target_from_metadata(const ftun_metadata_t *metadata,
                                        ftun_target_t *out);
/* READY route 必须同代；route.allowed 必须是当前 allowed 的真子集或同集合。
 * 成功后借用 route.allowed，失败不修改 target。 */
ftun_status_t ftun_target_apply_route(ftun_target_t *target,
                                      const ftun_route_result_t *route);
/* 重试可再次选择 allowed 内地址；不得选择 candidates 中已被路由排除的地址。 */
ftun_status_t ftun_target_select_dial(ftun_target_t *target,
                                      const ftun_endpoint_t *endpoint);
/* 仅完全没有本地真实候选时允许把 identity 作为远端解析 DOMAIN 目标。 */
ftun_status_t ftun_target_select_remote_domain(ftun_target_t *target);

#endif
