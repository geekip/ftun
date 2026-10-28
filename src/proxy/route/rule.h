#ifndef FTUN_ROUTE_RULE_H
#define FTUN_ROUTE_RULE_H

#include "internal/contracts.h"
#include "proxy/outbound_id.h"

typedef enum {
  FTUN_RULE_SRC_IP_CIDR = 1,
  FTUN_RULE_IP_CIDR,
  FTUN_RULE_DOMAIN,
  FTUN_RULE_DOMAIN_SUFFIX,
  FTUN_RULE_DOMAIN_KEYWORD,
  FTUN_RULE_FRS_IP,
  FTUN_RULE_FRS_DOMAIN,
  FTUN_RULE_DST_PORT,
  FTUN_RULE_NETWORK,
  FTUN_RULE_MATCH
} ftun_rule_kind_t;

struct ftun_rule {
  ftun_rule_kind_t kind;
  uint32_t outbound_id;
  uint32_t network_address;
  uint32_t network_mask;
  uint16_t port;
  uint8_t network;
  ftun_string_t operand;
  ftun_frs_set_t *frs_set;
  /* FRS 集合尚未就绪：规则无条件命中并拒绝新连接，直到换成就绪的快照。 */
  bool frs_pending;
  char *owned_operand;
};

typedef ftun_status_t (*ftun_rule_outbound_resolver_fn)(
  ftun_string_t name, uint32_t *out, void *user);
typedef ftun_status_t (*ftun_rule_frs_bind_fn)(
  uint16_t kind, ftun_string_t label, ftun_frs_set_t **out, void *user);

/* 配置阶段编译一个已由 config validator 接纳的文本规则。返回的 rule 拥有
 * operand；destroy 幂等消费。resolver 只处理非内置出口名称。 */
ftun_status_t ftun_rule_compile(const char *text,
                                ftun_rule_outbound_resolver_fn resolver,
                                void *resolver_user,
                                ftun_rule_t **out);
ftun_status_t ftun_rule_compile_with_frs(
  const char *text, ftun_rule_outbound_resolver_fn resolver,
  void *resolver_user, ftun_rule_frs_bind_fn frs_bind, void *frs_user,
  ftun_rule_t **out);
ftun_status_t ftun_rule_destroy(ftun_rule_t **rule);
/* 已由配置接纳的规则：自身、真正拥有的operand或FRS绑定句柄。
 * 不重复累计共享FRS视图；准入由调用方所属的Runtime承担。 */
ftun_status_t ftun_rule_accounted_bytes(const char *text, size_t *out);

/* 共享 matcher。
 * 函数只读取已知元数据，不做解析或 I/O。IP/FRS-IP 在只有域名且没有真实
 * 候选时返回 needs_resolve；FakeIP 原地址永不作为真实地址参与匹配。
 */
ftun_status_t ftun_rule_match(const ftun_rule_t *rule,
                              const ftun_metadata_t *metadata,
                              ftun_match_result_t *out);

/* Router 用于构造 IP/FRS-IP 命中的允许候选子集。 */
ftun_status_t ftun_rule_address_match(const ftun_rule_t *rule,
                                      const ftun_endpoint_t *address,
                                      bool *out);

#endif
