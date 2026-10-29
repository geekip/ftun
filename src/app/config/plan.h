#ifndef FTUN_APP_CONFIG_PLAN_H
#define FTUN_APP_CONFIG_PLAN_H
#include "core/limits.h"
#include "core/config/document.h"
enum {
  FTUN_CONFIG_SECTION_PLAN = 13u
};

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
  FTUN_PLAN_FRS = UINT64_C(1) << 12,
  FTUN_PLAN_FRS_UPDATE = UINT64_C(1) << 14,
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
typedef struct ftun_feature_plan ftun_feature_plan_t;
struct ftun_feature_plan {
  ftun_config_modules_t modules;
  size_t owned_bytes;
  ftun_reservation_t reservation;
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
  size_t prepare_frs_count;
  size_t lazy_outbound_count;
  size_t active_health_count;
  size_t lazy_health_count;
};
static inline const ftun_feature_plan_t *ftun_config_plan(const ftun_config_t *config)
{
  return ftun_config_document_section(config, FTUN_CONFIG_SECTION_PLAN);
}

#endif
