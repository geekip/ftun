#ifndef FTUN_ROUTE_RULE_H
#define FTUN_ROUTE_RULE_H

#include "internal/contracts.h"

#define FTUN_OUTBOUND_ID_DIRECT UINT32_C(0)
#define FTUN_OUTBOUND_ID_REJECT UINT32_C(1)
#define FTUN_OUTBOUND_ID_NAMED_BASE UINT32_C(2)

typedef enum {
  FTUN_RULE_SRC_IP_CIDR = 1,
  FTUN_RULE_IP_CIDR,
  FTUN_RULE_DOMAIN,
  FTUN_RULE_DOMAIN_SUFFIX,
  FTUN_RULE_DOMAIN_KEYWORD,
  FTUN_RULE_GEOIP,
  FTUN_RULE_GEOSITE,
  FTUN_RULE_DST_PORT,
  FTUN_RULE_NETWORK,
  FTUN_RULE_MATCH
} ftun_rule_kind_t;

typedef bool (*ftun_rule_geoip_fn)(ftun_string_t label,
                                   const ftun_endpoint_t *address,
                                   void *user);
typedef bool (*ftun_rule_geosite_fn)(ftun_string_t label,
                                     ftun_string_t domain,
                                     void *user);

struct ftun_rule {
  ftun_rule_kind_t kind;
  uint32_t outbound_id;
  uint32_t network_address;
  uint32_t network_mask;
  uint16_t port;
  uint8_t network;
  ftun_string_t operand;
  ftun_rule_geoip_fn geoip;
  ftun_rule_geosite_fn geosite;
  void *geo_user;
  char *owned_operand;
};

typedef ftun_status_t (*ftun_rule_outbound_resolver_fn)(
  ftun_string_t name, uint32_t *out, void *user);

/* 配置阶段编译一个已由 config validator 接纳的文本规则。返回的 rule 拥有
 * operand；destroy 幂等消费。resolver 只处理非内置出口名称。 */
ftun_status_t ftun_rule_compile(const char *text,
                                ftun_rule_outbound_resolver_fn resolver,
                                void *resolver_user,
                                ftun_rule_t **out);
ftun_status_t ftun_rule_destroy(ftun_rule_t **rule);

/* 共享 matcher。
 * 需求 REQ-ROUTE-001；任务 TASK-ROUTE-002；目标 0.3.0；验收 TEST-ROUTE-002。
 * 函数只读取已知元数据，不做解析或 I/O。IP/GEOIP 在只有域名且没有真实
 * 候选时返回 needs_resolve；FakeIP 原地址永不作为真实地址参与匹配。
 */
ftun_status_t ftun_rule_match(const ftun_rule_t *rule,
                              const ftun_metadata_t *metadata,
                              ftun_match_result_t *out);

/* Router 用于构造 IP/GEOIP 命中的允许候选子集。 */
ftun_status_t ftun_rule_address_match(const ftun_rule_t *rule,
                                      const ftun_endpoint_t *address,
                                      bool *out);

#endif
