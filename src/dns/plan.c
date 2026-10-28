#define _GNU_SOURCE 1

#include "dns/service_internal.h"

#if defined(FTUN_HAVE_MODULE_DNS)

ftun_status_t ftun_dns_runtime_plan_prepare(ftun_budget_t *budget, const ftun_config_t *config,
                                           uint32_t socket_mark,
                                           ftun_dns_runtime_plan_t **out)
{
  ftun_dns_runtime_plan_t *plan;
  ftun_reservation_t *reservation = NULL;
  size_t charge = sizeof(*plan);
  size_t index;
  ftun_status_t status = FTUN_OK;
  if (out != NULL && *out != NULL) return FTUN_E_AGAIN;
  if (budget == NULL || config == NULL || out == NULL) return FTUN_E_INVALID;
  if (config->dns.enable) {
    size_t per_outbound = sizeof(*plan->proxies) + sizeof(*plan->proxy_valid);
    if (config->dns.server_count > FTUN_DNS_RUNTIME_MAX_SERVERS ||
        config->outbound_count > UINT32_MAX - FTUN_DNS_OUTBOUND_NAMED_BASE ||
        config->outbound_count > (SIZE_MAX - charge) / per_outbound) return FTUN_E_LIMIT;
    charge += config->outbound_count * per_outbound;
  }
  status = ftun_budget_reserve(budget, charge, &reservation);
  if (status != FTUN_OK) return status;
  plan = (ftun_dns_runtime_plan_t *)calloc(1u, sizeof(*plan));
  if (plan == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  status = ftun_config_retain((ftun_config_t *)config);
  if (status != FTUN_OK) {
    free(plan);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  plan->reservation = reservation;
  plan->config = (ftun_config_t *)config;
  if (!config->dns.enable) {
    *out = plan;
    return FTUN_OK;
  }
  plan->server_count = config->dns.server_count == 0u && config->dns.enable
    ? 1u : config->dns.server_count;
  plan->outbound_count = config->outbound_count;
  if (plan->server_count > FTUN_DNS_RUNTIME_MAX_SERVERS ||
      plan->outbound_count > UINT32_MAX - FTUN_DNS_OUTBOUND_NAMED_BASE) {
    status = FTUN_E_LIMIT;
  }
  if (status == FTUN_OK && plan->outbound_count != 0u) {
    plan->proxies = (ftun_endpoint_t *)calloc(plan->outbound_count,
                                               sizeof(*plan->proxies));
    plan->proxy_valid = (uint8_t *)calloc(plan->outbound_count,
                                           sizeof(*plan->proxy_valid));
    if (plan->proxies == NULL || plan->proxy_valid == NULL) {
      status = FTUN_E_LIMIT;
    }
  }
  if (status == FTUN_OK) {
    status = ftun_dns_runtime_proxy_dependencies(config, plan->proxy_valid);
  }
  for (index = 0u; status == FTUN_OK && index < config->dns.server_count;
       index++) {
    const ftun_config_dns_server_t *item = &config->dns.servers[index];
    size_t address;
    if (item->addresses.count == 0u ||
        item->addresses.count > FTUN_UPSTREAM_SET_MAX) {
      status = FTUN_E_INVALID;
      break;
    }
    for (address = 0u; status == FTUN_OK && address < item->addresses.count;
         address++) {
      status = ftun_dns_runtime_resolve_upstream(budget, config,
        item->addresses.items[address], socket_mark,
        &plan->addresses[index][address]);
    }
    if (status == FTUN_OK) {
      plan->address_count[index] = (uint8_t)item->addresses.count;
      plan->servers[index] = plan->addresses[index][0];
    }
  }
  if (status == FTUN_OK && config->dns.enable &&
      config->dns.server_count == 0u) {
    status = ftun_dns_runtime_bootstrap_endpoint(budget, config, &plan->servers[0]);
  }
  for (index = 0u; status == FTUN_OK && index < config->outbound_count;
       index++) {
    const ftun_config_outbound_t *item = &config->outbounds[index];
    if (plan->proxy_valid[index] == 0u) continue;
    status = ftun_dns_runtime_resolve_upstream(budget, config, item->server,
      socket_mark, &plan->proxies[index]);
    if (status == FTUN_OK) plan->proxy_valid[index] = 1u;
  }
  if (status != FTUN_OK) {
    (void)ftun_dns_runtime_plan_destroy(&plan);
    *out = plan;
    return status;
  }
  *out = plan;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_plan_destroy(ftun_dns_runtime_plan_t **plan_ptr)
{
  ftun_dns_runtime_plan_t *plan;
  ftun_status_t status;
  if (plan_ptr == NULL) return FTUN_E_INVALID;
  plan = *plan_ptr;
  if (plan == NULL) return FTUN_OK;
  status = ftun_config_destroy(&plan->config);
  if (status != FTUN_OK) return status;
  status = ftun_reservation_release(&plan->reservation);
  if (status != FTUN_OK) return status;
  free(plan->proxies);
  free(plan->proxy_valid);
  memset(plan, 0, sizeof(*plan));
  free(plan);
  *plan_ptr = NULL;
  return FTUN_OK;
}


#endif
