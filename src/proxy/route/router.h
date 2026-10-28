#ifndef FTUN_ROUTE_ROUTER_H
#define FTUN_ROUTE_ROUTER_H

#include "internal/contracts.h"
#include "proxy/route/rule.h"

/* 表拥有全部编译规则；文本和 resolver 输入只在 create 调用期间借用。 */
ftun_status_t ftun_route_table_create(
  uint64_t generation, const char *const *rules, size_t rule_count,
  ftun_rule_outbound_resolver_fn resolver, void *resolver_user,
  ftun_route_table_t **out);
ftun_status_t ftun_route_table_create_with_frs(
  uint64_t generation, const char *const *rules, size_t rule_count,
  ftun_rule_outbound_resolver_fn resolver, void *resolver_user,
  ftun_rule_frs_bind_fn frs_bind, void *frs_user,
  ftun_route_table_t **out);
ftun_status_t ftun_route_table_set_generation(ftun_route_table_t *table,
                                              uint64_t generation);
ftun_status_t ftun_route_table_destroy(ftun_route_table_t **table);
ftun_status_t ftun_route_table_accounted_bytes(const char *const *rules,
                                               size_t rule_count,
                                               size_t *out);

/* 保序路由解释器。
 * 从 resume_rule（含）继续按原序求值。缺真实地址只在当前 IP/FRS-IP 规则
 * 返回 NEED_RESOLVE，成功解析后必须用同一索引恢复；解析失败由调用者终结。
 */
ftun_status_t ftun_route_table_evaluate(const ftun_route_table_t *table,
                                        const ftun_metadata_t *metadata,
                                        size_t resume_rule,
                                        ftun_route_result_t *out);

/* DNS 策略阶段只使用现有元数据；需要未来真实 IP 的规则视为当前不匹配，
 * 不触发解析，也不伪造业务端口或 network。 */
ftun_status_t ftun_route_table_evaluate_known(const ftun_route_table_t *table,
                                              const ftun_metadata_t *metadata,
                                              ftun_route_result_t *out);

/* Runtime 包装；Runtime 在 prepare 时编译规则并在 commit 时固定 generation。 */
ftun_status_t ftun_route_evaluate(const ftun_runtime_t *runtime,
                                  const ftun_metadata_t *metadata,
                                  size_t resume_rule,
                                  ftun_route_result_t *out);

#endif
