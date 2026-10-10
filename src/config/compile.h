#ifndef FTUN_CONFIG_COMPILE_H
#define FTUN_CONFIG_COMPILE_H
#include "internal/contracts.h"
/* 返回进程编译时静态能力。指针在进程生命期内有效，调用者不得修改或释放。
 * BUILTIN 仅表示源码已编入，不表示对应运行功能已实现。 */
const ftun_build_capabilities_t *ftun_build_capabilities(void);
/* required 只能包含 FTUN_BUILD_MODULE_ALL 中的位。能力缺失返回 UNSUPPORTED；
 * 未知位返回 INVALID。out 可为 NULL，其中 message 为静态借用视图。 */
ftun_status_t ftun_build_require_modules(uint32_t required, ftun_diagnostic_t *out);

typedef enum {
  FTUN_PLAN_RUNTIME = UINT64_C(1) << 0,
  FTUN_PLAN_RULES = UINT64_C(1) << 1,
  FTUN_PLAN_INBOUND = UINT64_C(1) << 2,
  FTUN_PLAN_TUN = UINT64_C(1) << 3,
  FTUN_PLAN_OUTBOUND = UINT64_C(1) << 4,
  FTUN_PLAN_GROUP = UINT64_C(1) << 5,
  FTUN_PLAN_DNS = UINT64_C(1) << 6,
  FTUN_PLAN_DNS_LISTENER = UINT64_C(1) << 7,
  FTUN_PLAN_DNS_CACHE = UINT64_C(1) << 8,
  FTUN_PLAN_BOOTSTRAP = UINT64_C(1) << 9,
  FTUN_PLAN_SYSTEM_RESOLVER = UINT64_C(1) << 10,
  FTUN_PLAN_FAKE_IP = UINT64_C(1) << 11,
  FTUN_PLAN_GEOIP = UINT64_C(1) << 12,
  FTUN_PLAN_GEOSITE = UINT64_C(1) << 13,
  FTUN_PLAN_GEO_UPDATE = UINT64_C(1) << 14,
  FTUN_PLAN_HEALTH = UINT64_C(1) << 15,
  FTUN_PLAN_STATE_CACHE = UINT64_C(1) << 16,
  FTUN_PLAN_SNIFF = UINT64_C(1) << 17
} ftun_plan_feature_t;

typedef enum {
  FTUN_PLAN_ITEM_COMPILED = 1u << 0,
  FTUN_PLAN_ITEM_REACHABLE = 1u << 1,
  FTUN_PLAN_ITEM_PREPARE = 1u << 2,
  FTUN_PLAN_ITEM_LAZY = 1u << 3,
  FTUN_PLAN_ITEM_ACTIVE = 1u << 4,
  FTUN_PLAN_ITEM_RETAINED = 1u << 5
} ftun_plan_item_state_t;

/* 配置索引数组与原模型同序；计划拥有所有数组，不拥有 config。 */
struct ftun_feature_plan {
  uint32_t built_modules;
  uint32_t required_modules;
  uint64_t compiled;
  uint64_t prepare;
  uint64_t lazy;
  uint64_t active;
  uint64_t retained;
  uint8_t *outbound_states;
  size_t outbound_count;
  size_t reachable_outbound_count;
  uint8_t *dns_server_states;
  size_t dns_server_count;
  size_t reachable_dns_server_count;
  size_t *rule_order;
  size_t rule_count;
  size_t prepare_listener_count;
  size_t prepare_tun_count;
  size_t prepare_geo_count;
  size_t lazy_outbound_count;
  size_t active_health_count;
  size_t lazy_health_count;
};
/* 依赖闭包与资源计划。
 * 需求 REQ-CONF-001；任务 TASK-CONFIG-004；目标 0.2.0；验收 TEST-CONFIG-004。
 * 实现路径：从监听、路由、DNS、探测及历史引用求闭包；区分 compiled/prepare/lazy/active/retained；不重排 rules。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；返回计划独立拥有索引数组，不转移配置所有权。
 */
ftun_status_t ftun_config_compile(const ftun_config_t *config, ftun_feature_plan_t **out);
/* 空计划销毁幂等；成功后清空调用者句柄。 */
ftun_status_t ftun_feature_plan_destroy(ftun_feature_plan_t **plan);
#endif
