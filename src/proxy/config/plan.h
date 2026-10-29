#ifndef FTUN_PROXY_CONFIG_PLAN_H
#define FTUN_PROXY_CONFIG_PLAN_H
#include "core/config/document.h"
#define FTUN_CONFIG_SECTION_PROXY_PLAN 17u
#define FTUN_PROXY_PLAN_INBOUND (UINT64_C(1) << 2)
#define FTUN_PROXY_PLAN_TUN (UINT64_C(1) << 3)
#define FTUN_PROXY_PLAN_FAKE_IP (UINT64_C(1) << 11)
#define FTUN_PROXY_PLAN_FRS (UINT64_C(1) << 12)
#define FTUN_PROXY_PLAN_ITEM_REACHABLE (1u << 1)
typedef struct {
  bool present;
  bool accounted;
  size_t owned_bytes;
  /* 其余位只用于原有诊断项投影，Proxy 不解释其他模块的需求。 */
  uint64_t prepare;
  const uint8_t *outbound_states;
  size_t prepare_listener_count;
  size_t prepare_tun_count;
  size_t prepare_frs_count;
} ftun_proxy_config_plan_t;
typedef struct {
  ftun_proxy_config_plan_t (*get)(const ftun_config_t *config);
} ftun_proxy_config_plan_ops_t;
static inline ftun_proxy_config_plan_t ftun_proxy_config_plan(const ftun_config_t *config)
{
  const ftun_proxy_config_plan_ops_t *ops = ftun_config_document_section(config, FTUN_CONFIG_SECTION_PROXY_PLAN);
  return ops->get(config);
}
#endif
