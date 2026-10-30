#ifndef FTUN_TEST_EGRESS_FIXTURE_H
#define FTUN_TEST_EGRESS_FIXTURE_H
#include "app/config/model.h"
#if defined(FTUN_TEST_PROXY)
#include "proxy/egress.h"
#include "proxy/egress_internal.h"
#endif
#include "dns/service.h"
#include <string.h>

#if defined(FTUN_TEST_PROXY)
static inline size_t ftun_test_egress_bytes(const ftun_config_t *config)
{
  size_t bytes = sizeof(ftun_proxy_egress_t), i;
  for (i = 0u; i < config->outbound_count; i++) {
    const ftun_config_outbound_t *node = &config->outbounds[i];
    bytes += sizeof(ftun_proxy_egress_node_t) + strlen(node->name) + 1u +
      node->members.count * sizeof(uint32_t);
    if (node->dns_server != NULL) bytes += strlen(node->dns_server) + 1u;
  }
  return bytes;
}

/* 配置构造与出口装配在测试宿主完成；DNS只收到通用提供者。 */
static inline ftun_status_t ftun_test_egress(ftun_budget_t *budget,
  const ftun_config_t *config, uint64_t generation,
  ftun_proxy_egress_select_fn select, void *context,
  const ftun_egress_provider_t **out)
{
  ftun_status_t status = ftun_proxy_egress_prepare(budget, config, 0u, out);
  if (status == FTUN_OK) ftun_proxy_egress_bind(*out, generation, select, context);
  return status;
}

#endif
static inline ftun_status_t ftun_test_dns_prepare(
  ftun_core_t *core, ftun_budget_t *budget, ftun_operation_queue_t *operations,
  ftun_event_loop_t *loop, const ftun_config_t *config,
  const ftun_dns_runtime_adapter_t *adapter, const ftun_dns_runtime_network_t *input,
  ftun_dns_runtime_t **out)
{
#if defined(FTUN_TEST_PROXY)
  const ftun_egress_provider_t *egress = NULL;
  ftun_dns_runtime_network_t network = *input;
  ftun_status_t status = ftun_test_egress(budget, config, input->generation, NULL, NULL, &egress);
  if (status == FTUN_OK) {
    ftun_proxy_egress_set_path(egress, input->path, input->context);
    network.egress = egress;
    status = ftun_dns_runtime_prepare(core, budget, operations, loop, config, adapter, &network, out);
  }
  ftun_egress_release(&egress);
  return status;
#else
  return ftun_dns_runtime_prepare(core, budget, operations, loop, config, adapter, input, out);
#endif
}

static inline ftun_status_t ftun_test_dns_reload(
  const ftun_dns_runtime_t *active, ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations, ftun_event_loop_t *loop,
  const ftun_config_t *config, const ftun_dns_runtime_adapter_t *adapter,
  const ftun_dns_runtime_network_t *input, const ftun_dns_runtime_plan_t *plan,
  ftun_dns_runtime_t **out)
{
#if defined(FTUN_TEST_PROXY)
  const ftun_egress_provider_t *egress = NULL;
  ftun_dns_runtime_network_t network = *input;
  ftun_status_t status = ftun_test_egress(budget, config, input->generation, NULL, NULL, &egress);
  if (status == FTUN_OK) {
    ftun_proxy_egress_set_path(egress, input->path, input->context);
    network.egress = egress;
    status = ftun_dns_runtime_prepare_reload_planned(active, core, budget, operations,
      loop, config, adapter, &network, plan, out);
  }
  ftun_egress_release(&egress);
  return status;
#else
  return ftun_dns_runtime_prepare_reload_planned(active, core, budget, operations, loop, config, adapter, input, plan, out);
#endif
}

#if defined(FTUN_TEST_PROXY)
static inline ftun_status_t ftun_test_egress_node(ftun_budget_t *budget,
  const char *server, const char *username, const char *password,
  const char *bootstrap, uint64_t generation, const ftun_egress_provider_t **out)
{
  ftun_config_t config = {0};
  ftun_config_outbound_t node = {0};
  char *bootstrap_item = (char *)bootstrap;
  ftun_status_t status;
  node.kind = FTUN_CONFIG_OUTBOUND_SOCKS5;
  node.name = "test";
  node.server = (char *)server;
  node.username = (char *)username;
  node.password = (char *)password;
  node.udp = true;
  config.outbounds = &node;
  config.outbound_count = 1u;
  if (bootstrap != NULL && bootstrap[0] != '\0') {
    config.dns.bootstrap = (ftun_config_string_list_t){&bootstrap_item, 1u};
  }
  ftun_config_bind_sections(&config);
  status = ftun_test_egress(budget, &config, generation, NULL, NULL, out);
  if (status == FTUN_OK) *out = ftun_proxy_egress_worker(*out);
  return status;
}
#endif
#endif
