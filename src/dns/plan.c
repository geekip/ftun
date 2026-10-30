#define _GNU_SOURCE 1

#include "dns/service_internal.h"

#if defined(FTUN_HAVE_MODULE_DNS)

ftun_status_t ftun_dns_runtime_plan_prepare(ftun_budget_t *budget, const ftun_config_t *config,
                                           uint32_t socket_mark,
                                           ftun_dns_runtime_plan_t **out)
{
  ftun_dns_runtime_plan_t *plan;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  size_t charge = sizeof(*plan);
  size_t index;
  ftun_status_t status = FTUN_OK;
  if (out != NULL && *out != NULL) return FTUN_E_AGAIN;
  if (budget == NULL || config == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_budget_reserve(budget, charge, &reservation);
  if (status != FTUN_OK) return status;
  plan = (ftun_dns_runtime_plan_t *)calloc(1u, sizeof(*plan));
  if (plan == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  status = ftun_config_retain((ftun_config_t *)config);
  if (status != FTUN_OK) {
    free(plan);
    ftun_reservation_release(&reservation);
    return status;
  }
  plan->reservation = reservation;
  plan->config = (ftun_config_t *)config;
  if (!ftun_config_dns(config)->enable) {
    *out = plan;
    return FTUN_OK;
  }
  plan->server_count = ftun_config_dns(config)->server_count == 0u && ftun_config_dns(config)->enable
    ? 1u : ftun_config_dns(config)->server_count;
  if (plan->server_count > FTUN_DNS_RUNTIME_MAX_SERVERS) status = FTUN_E_LIMIT;
  for (index = 0u; status == FTUN_OK && index < ftun_config_dns(config)->server_count;
       index++) {
    const ftun_config_dns_server_t *item = &ftun_config_dns(config)->servers[index];
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
  if (status == FTUN_OK && ftun_config_dns(config)->enable &&
      ftun_config_dns(config)->server_count == 0u) {
    status = ftun_dns_runtime_bootstrap_endpoint(budget, config, &plan->servers[0]);
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
  ftun_reservation_release(&plan->reservation);
  memset(plan, 0, sizeof(*plan));
  free(plan);
  *plan_ptr = NULL;
  return FTUN_OK;
}


#endif
