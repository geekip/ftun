#define _GNU_SOURCE 1

#include "util/endpoint.h"
#include "dns/service_internal.h"
#include "util/ip.h"
#include "platform/sysresolve.h"
#include "libs/resolver/control.h"

#if defined(FTUN_HAVE_MODULE_DNS)

ftun_status_t ftun_dns_runtime_parse_endpoint(const char *text, ftun_endpoint_t *out)
{
  ftun_host_port_t value;
  ftun_ip_t ip;
  memset(out, 0, sizeof(*out));
  if (text == NULL || !ftun_host_port_split(text, strlen(text), &value)) return FTUN_E_INVALID;
  if (!ftun_ip_parse(value.host, value.host_length, &ip)) return FTUN_E_UNSUPPORTED;
  ftun_endpoint_set_ip(out, &ip, value.has_port ? value.port : 53u);
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_bootstrap_endpoint(
  ftun_budget_t *budget, const ftun_config_t *config, ftun_endpoint_t *out)
{
  ftun_reservation_t reservation = {0};
  ftun_status_t status;
  if (config == NULL || out == NULL) return FTUN_E_INVALID;
  if (ftun_config_dns(config)->bootstrap.count != 0u) {
    return ftun_dns_runtime_parse_endpoint(ftun_config_dns(config)->bootstrap.items[0], out);
  }
  status = ftun_budget_reserve_resources(budget,
    (ftun_budget_resources_t){0u, 1u, 0u}, &reservation);
  if (status != FTUN_OK) return status;
  status = ftun_system_nameserver(out);
  ftun_reservation_release(&reservation);
  return status;
}

ftun_status_t ftun_dns_runtime_resolve_upstream(
  ftun_budget_t *budget, const ftun_config_t *config, const char *text, uint32_t socket_mark,
  ftun_endpoint_t *out)
{
  ftun_control_execution_t execution = {0};
  ftun_control_resolver_plan_t plan = {0};
  ftun_endpoint_t endpoint;
  char domain[FTUN_CONTROL_ENDPOINT_TEXT_BYTES];
  ftun_status_t status;
  if (config == NULL || text == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_control_parse_endpoint(text, 53u, &endpoint, domain);
  if (status != FTUN_OK) return status;
  if (ftun_endpoint_is_ip(&endpoint)) { *out = endpoint; return FTUN_OK; }
  status = ftun_dns_runtime_bootstrap_endpoint(budget, config, plan.bootstrap);
  if (status != FTUN_OK) return status;
  plan.bootstrap_count = 1u;
  plan.socket_mark = socket_mark;
  execution.budget = budget;
  /* 准备线程自有的控制通道，不与数据面代际共享对象。 */
  execution.generation = 1u;
  execution.purpose = FTUN_DIAL_PURPOSE_BOOTSTRAP;
  status = ftun_monotonic_now(&execution.deadline_ms);
  if (status != FTUN_OK) return status;
  execution.deadline_ms += FTUN_DNS_RUNTIME_TIMEOUT_MS;
  status = ftun_control_resolve_bootstrap(&execution, &plan, endpoint.domain,
    endpoint.port, out);
  if (status == FTUN_E_RESOLVE && ftun_config_resolver(config).ipv6) {
    plan.query_type = 28u;
    status = ftun_control_resolve_bootstrap(&execution, &plan, endpoint.domain,
      endpoint.port, out);
  }
  return status;
}

#endif
