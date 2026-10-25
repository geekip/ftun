#include "compile.h"
#include "model.h"
#include "core/budget.h"
#include "validate.h"
#include <stdlib.h>
#include <string.h>

static const char *const ftun_builtin_module_names[] = {
  "core",
#if defined(FTUN_HAVE_MODULE_PROXY)
  "proxy",
#endif
#if defined(FTUN_HAVE_MODULE_DNS)
  "dns",
#endif
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  "fakeip",
#endif
#if defined(FTUN_HAVE_MODULE_TUN)
  "tun",
#endif
#if defined(FTUN_HAVE_MODULE_FRS)
  "frs",
#endif
};

static const ftun_build_capabilities_t ftun_capabilities = {
  FTUN_BUILD_MODULE_CORE
#if defined(FTUN_HAVE_MODULE_PROXY)
    | FTUN_BUILD_MODULE_PROXY
#endif
#if defined(FTUN_HAVE_MODULE_DNS)
    | FTUN_BUILD_MODULE_DNS
#endif
#if defined(FTUN_HAVE_MODULE_FAKEIP)
    | FTUN_BUILD_MODULE_FAKEIP
#endif
#if defined(FTUN_HAVE_MODULE_TUN)
    | FTUN_BUILD_MODULE_TUN
#endif
#if defined(FTUN_HAVE_MODULE_FRS)
    | FTUN_BUILD_MODULE_FRS
#endif
  ,
  ftun_builtin_module_names,
  sizeof(ftun_builtin_module_names) / sizeof(ftun_builtin_module_names[0])
};

static void ftun_build_diagnostic(ftun_diagnostic_t *out, ftun_status_t status,
                                  const char *message)
{
  if (out == NULL) return;
  memset(out, 0, sizeof(*out));
  out->error.status = status;
  out->message.data = message;
  out->message.length = strlen(message);
}

const ftun_build_capabilities_t *ftun_build_capabilities(void)
{
  return &ftun_capabilities;
}

uint32_t ftun_config_required_modules(const ftun_config_t *config)
{
  uint32_t required = FTUN_BUILD_MODULE_CORE;
  size_t index;
  if (config == NULL) return 0u;
  if (config->dns.enable) required |= FTUN_BUILD_MODULE_DNS;
  if (config->inbound_count != 0u) {
    required |= FTUN_BUILD_MODULE_PROXY;
  }
  if (config->rules.count != 0u) {
    required |= FTUN_BUILD_MODULE_PROXY;
  }
  if (config->dns.enable) {
    for (index = 0u; index < config->dns.server_count; index++) {
      const ftun_config_dns_server_t *server = &config->dns.servers[index];
      if (server->fake_ip) {
        required |= FTUN_BUILD_MODULE_FAKEIP | FTUN_BUILD_MODULE_PROXY;
      }
      if (server->outbound != NULL &&
          strcmp(server->outbound, "DIRECT") != 0) {
        required |= FTUN_BUILD_MODULE_PROXY;
      }
    }
  }
  if (config->frs.active) {
    required |= FTUN_BUILD_MODULE_FRS | FTUN_BUILD_MODULE_PROXY;
  }
  for (index = 0u; index < config->inbound_count; index++) {
    if (config->inbounds[index].kind == FTUN_CONFIG_INBOUND_TUN) {
      required |= FTUN_BUILD_MODULE_TUN | FTUN_BUILD_MODULE_PROXY;
    }
  }
  return required;
}

ftun_status_t ftun_build_require_modules(uint32_t required, ftun_diagnostic_t *out)
{
  uint32_t missing;
  if ((required & ~(uint32_t)FTUN_BUILD_MODULE_ALL) != 0u) {
    ftun_build_diagnostic(out, FTUN_E_INVALID, "unknown build module");
    return FTUN_E_INVALID;
  }
  missing = required & ~ftun_capabilities.builtins;
  if (missing != 0u) {
    ftun_build_diagnostic(out, FTUN_E_UNSUPPORTED, "required build module is not built in");
    return FTUN_E_UNSUPPORTED;
  }
  if (out != NULL) memset(out, 0, sizeof(*out));
  return FTUN_OK;
}

static void ftun_plan_add(ftun_feature_plan_t *plan, uint64_t feature,
                          uint8_t phases)
{
  if ((phases & FTUN_PLAN_ITEM_COMPILED) != 0u) plan->compiled |= feature;
  if ((phases & FTUN_PLAN_ITEM_PREPARE) != 0u) plan->prepare |= feature;
  if ((phases & FTUN_PLAN_ITEM_LAZY) != 0u) plan->lazy |= feature;
  if ((phases & FTUN_PLAN_ITEM_ACTIVE) != 0u) plan->active |= feature;
  if ((phases & FTUN_PLAN_ITEM_RETAINED) != 0u) plan->retained |= feature;
}

static int ftun_plan_outbound_index(const ftun_config_t *config,
                                    const char *name, size_t *out)
{
  size_t index;
  if (name == NULL) return 0;
  for (index = 0u; index < config->outbound_count; index++) {
    if (strcmp(config->outbounds[index].name, name) == 0) {
      if (out != NULL) *out = index;
      return 1;
    }
  }
  return 0;
}

static int ftun_plan_dns_index(const ftun_config_t *config,
                               const char *name, size_t *out)
{
  size_t index;
  if (name == NULL) return 0;
  for (index = 0u; index < config->dns.server_count; index++) {
    if (strcmp(config->dns.servers[index].name, name) == 0) {
      if (out != NULL) *out = index;
      return 1;
    }
  }
  return 0;
}

static int ftun_plan_host_is_domain(const char *value, int url)
{
  const char *host = value;
  const char *end;
  size_t length;
  size_t index;
  size_t dots = 0u;
  int digits = 1;
  if (value == NULL) return 0;
  if (url) {
    const char *scheme = strstr(value, "://");
    if (scheme == NULL) return 0;
    host = scheme + 3;
    end = host;
    while (*end != '\0' && *end != ':' && *end != '/' && *end != '?' && *end != '#') end++;
  } else {
    end = strchr(host, ':');
    if (end == NULL) end = host + strlen(host);
  }
  length = (size_t)(end - host);
  for (index = 0u; index < length; index++) {
    if (host[index] == '.') dots++;
    else if (host[index] < '0' || host[index] > '9') digits = 0;
  }
  return !(digits && dots == 3u);
}

static void ftun_plan_need_resolver(const ftun_config_t *config,
                                    ftun_feature_plan_t *plan)
{
  if (config->dns.enable) {
    ftun_plan_add(plan, FTUN_PLAN_DNS,
                  FTUN_PLAN_ITEM_COMPILED | FTUN_PLAN_ITEM_PREPARE |
                  FTUN_PLAN_ITEM_ACTIVE);
    ftun_plan_add(plan, FTUN_PLAN_BOOTSTRAP,
                  FTUN_PLAN_ITEM_COMPILED | FTUN_PLAN_ITEM_LAZY);
  } else {
    ftun_plan_add(plan, FTUN_PLAN_SYSTEM_RESOLVER,
                  FTUN_PLAN_ITEM_COMPILED | FTUN_PLAN_ITEM_LAZY);
  }
}

static ftun_status_t ftun_plan_mark_outbound(const ftun_config_t *config,
                                             ftun_feature_plan_t *plan,
                                             size_t index);
static ftun_status_t ftun_plan_mark_dns_name(const ftun_config_t *config,
                                             ftun_feature_plan_t *plan,
                                             const char *name);

static ftun_status_t ftun_plan_need_business_resolver(const ftun_config_t *config,
                                                      ftun_feature_plan_t *plan)
{
  if (config->dns.enable) {
    return ftun_plan_mark_dns_name(config, plan, config->dns.default_server);
  }
  ftun_plan_add(plan, FTUN_PLAN_SYSTEM_RESOLVER,
                FTUN_PLAN_ITEM_COMPILED | FTUN_PLAN_ITEM_LAZY);
  return FTUN_OK;
}

static ftun_status_t ftun_plan_mark_dns(const ftun_config_t *config,
                                        ftun_feature_plan_t *plan,
                                        size_t index)
{
  const ftun_config_dns_server_t *server = &config->dns.servers[index];
  size_t address_index;
  size_t outbound_index;
  if ((plan->dns_server_states[index] & FTUN_PLAN_ITEM_REACHABLE) != 0u) {
    return FTUN_OK;
  }
  plan->dns_server_states[index] |= FTUN_PLAN_ITEM_REACHABLE |
                                    FTUN_PLAN_ITEM_LAZY |
                                    FTUN_PLAN_ITEM_RETAINED;
  plan->reachable_dns_server_count++;
  ftun_plan_add(plan, FTUN_PLAN_DNS,
                FTUN_PLAN_ITEM_COMPILED | FTUN_PLAN_ITEM_PREPARE |
                FTUN_PLAN_ITEM_ACTIVE | FTUN_PLAN_ITEM_RETAINED);
  for (address_index = 0u; address_index < server->addresses.count; address_index++) {
    if (ftun_plan_host_is_domain(server->addresses.items[address_index], 0)) {
      ftun_plan_need_resolver(config, plan);
    }
  }
  if (server->fake_ip) {
    ftun_plan_add(plan, FTUN_PLAN_FAKE_IP,
                  FTUN_PLAN_ITEM_COMPILED | FTUN_PLAN_ITEM_PREPARE |
                  FTUN_PLAN_ITEM_ACTIVE | FTUN_PLAN_ITEM_RETAINED);
  }
  if (ftun_plan_outbound_index(config, server->outbound, &outbound_index)) {
    return ftun_plan_mark_outbound(config, plan, outbound_index);
  }
  return FTUN_OK;
}

static ftun_status_t ftun_plan_mark_dns_name(const ftun_config_t *config,
                                             ftun_feature_plan_t *plan,
                                             const char *name)
{
  size_t index;
  if (name == NULL || name[0] == '\0') {
    ftun_plan_need_resolver(config, plan);
    return FTUN_OK;
  }
  if (!ftun_plan_dns_index(config, name, &index)) return FTUN_E_INVALID;
  return ftun_plan_mark_dns(config, plan, index);
}

static ftun_status_t ftun_plan_mark_outbound(const ftun_config_t *config,
                                             ftun_feature_plan_t *plan,
                                             size_t index)
{
  const ftun_config_outbound_t *outbound = &config->outbounds[index];
  size_t member_index;
  if ((plan->outbound_states[index] & FTUN_PLAN_ITEM_REACHABLE) != 0u) {
    return FTUN_OK;
  }
  plan->outbound_states[index] |= FTUN_PLAN_ITEM_REACHABLE |
                                  FTUN_PLAN_ITEM_RETAINED;
  plan->reachable_outbound_count++;
  ftun_plan_add(plan, FTUN_PLAN_OUTBOUND,
                FTUN_PLAN_ITEM_COMPILED | FTUN_PLAN_ITEM_RETAINED);
  if (outbound->kind == FTUN_CONFIG_OUTBOUND_SOCKS5) {
    plan->outbound_states[index] |= FTUN_PLAN_ITEM_LAZY;
    plan->lazy_outbound_count++;
    ftun_plan_add(plan, FTUN_PLAN_OUTBOUND, FTUN_PLAN_ITEM_LAZY);
    if (ftun_plan_host_is_domain(outbound->server, 0)) {
      ftun_plan_need_resolver(config, plan);
    }
  } else {
    plan->outbound_states[index] |= FTUN_PLAN_ITEM_ACTIVE;
    ftun_plan_add(plan, FTUN_PLAN_GROUP,
                  FTUN_PLAN_ITEM_COMPILED | FTUN_PLAN_ITEM_ACTIVE |
                  FTUN_PLAN_ITEM_RETAINED);
    if (outbound->kind == FTUN_CONFIG_OUTBOUND_URL_TEST) {
      if (outbound->lazy) {
        plan->lazy_health_count++;
        ftun_plan_add(plan, FTUN_PLAN_HEALTH,
                      FTUN_PLAN_ITEM_COMPILED | FTUN_PLAN_ITEM_LAZY |
                      FTUN_PLAN_ITEM_RETAINED);
      } else {
        plan->active_health_count++;
        ftun_plan_add(plan, FTUN_PLAN_HEALTH,
                      FTUN_PLAN_ITEM_COMPILED | FTUN_PLAN_ITEM_ACTIVE |
                      FTUN_PLAN_ITEM_RETAINED);
      }
      if (ftun_plan_host_is_domain(outbound->url, 1)) {
        ftun_plan_need_resolver(config, plan);
      }
    }
    for (member_index = 0u; member_index < outbound->members.count; member_index++) {
      size_t child;
      if (ftun_plan_outbound_index(config, outbound->members.items[member_index], &child)) {
        ftun_status_t status = ftun_plan_mark_outbound(config, plan, child);
        if (status != FTUN_OK) return status;
      } else if (strcmp(outbound->members.items[member_index], "DIRECT") == 0) {
        ftun_status_t status = ftun_plan_need_business_resolver(config, plan);
        if (status != FTUN_OK) return status;
      }
    }
  }
  if (config->dns.enable && outbound->dns_server[0] != '\0') {
    return ftun_plan_mark_dns_name(config, plan, outbound->dns_server);
  }
  return FTUN_OK;
}

static ftun_status_t ftun_plan_mark_outbound_name(const ftun_config_t *config,
                                                  ftun_feature_plan_t *plan,
                                                  const char *name,
                                                  int direct_needs_resolver)
{
  size_t index;
  if (strcmp(name, "DIRECT") == 0) {
    return direct_needs_resolver ? ftun_plan_need_business_resolver(config, plan) :
                                  FTUN_OK;
  }
  if (strcmp(name, "REJECT") == 0) return FTUN_OK;
  if (!ftun_plan_outbound_index(config, name, &index)) return FTUN_E_INVALID;
  return ftun_plan_mark_outbound(config, plan, index);
}

static const char *ftun_plan_rule_outbound(const char *rule)
{
  const char *comma = strrchr(rule, ',');
  return comma == NULL ? NULL : comma + 1;
}

static int ftun_plan_rule_has_type(const char *rule, const char *type)
{
  size_t length = strlen(type);
  size_t index;
  if (rule == NULL || strlen(rule) <= length || rule[length] != ',') return 0;
  for (index = 0u; index < length; index++) {
    unsigned char left = (unsigned char)rule[index];
    unsigned char right = (unsigned char)type[index];
    if (left >= 'A' && left <= 'Z') left = (unsigned char)(left + ('a' - 'A'));
    if (right >= 'A' && right <= 'Z') right = (unsigned char)(right + ('a' - 'A'));
    if (left != right) return 0;
  }
  return 1;
}

static ftun_status_t ftun_plan_rules(const ftun_config_t *config,
                                     ftun_feature_plan_t *plan,
                                     int *needs_default_dns)
{
  size_t index;
  if (config->rules.count != 0u) {
    ftun_plan_add(plan, FTUN_PLAN_RULES,
                  FTUN_PLAN_ITEM_COMPILED | FTUN_PLAN_ITEM_ACTIVE |
                  FTUN_PLAN_ITEM_RETAINED);
  }
  for (index = 0u; index < config->rules.count; index++) {
    const char *rule = config->rules.items[index];
    const char *outbound = ftun_plan_rule_outbound(rule);
    ftun_status_t status;
    plan->rule_order[index] = index;
    if (outbound == NULL) return FTUN_E_INVALID;
    status = ftun_plan_mark_outbound_name(config, plan, outbound, 1);
    if (status != FTUN_OK) return status;
    if (ftun_plan_rule_has_type(rule, "IP-CIDR") ||
        ftun_plan_rule_has_type(rule, "FRS-IP")) {
      *needs_default_dns = 1;
    }
    if (ftun_plan_rule_has_type(rule, "FRS-IP") ||
        ftun_plan_rule_has_type(rule, "FRS-DOMAIN")) {
      ftun_plan_add(plan, FTUN_PLAN_FRS,
                    FTUN_PLAN_ITEM_COMPILED | FTUN_PLAN_ITEM_PREPARE |
                    FTUN_PLAN_ITEM_ACTIVE | FTUN_PLAN_ITEM_RETAINED);
    }
  }
  return FTUN_OK;
}

static ftun_status_t ftun_plan_inbounds(const ftun_config_t *config,
                                        ftun_feature_plan_t *plan,
                                        int *needs_default_dns)
{
  size_t index;
  if (config->inbound_count != 0u) {
    ftun_plan_add(plan, FTUN_PLAN_INBOUND,
                  FTUN_PLAN_ITEM_COMPILED | FTUN_PLAN_ITEM_PREPARE |
                  FTUN_PLAN_ITEM_ACTIVE);
  }
  for (index = 0u; index < config->inbound_count; index++) {
    const ftun_config_inbound_t *inbound = &config->inbounds[index];
    ftun_status_t status;
    if (inbound->kind == FTUN_CONFIG_INBOUND_TUN) {
      plan->prepare_tun_count++;
      ftun_plan_add(plan, FTUN_PLAN_TUN,
                    FTUN_PLAN_ITEM_COMPILED | FTUN_PLAN_ITEM_PREPARE |
                    FTUN_PLAN_ITEM_ACTIVE);
      if (config->dns.enable && inbound->dns_hijack) *needs_default_dns = 1;
    } else {
      plan->prepare_listener_count++;
    }
    if (inbound->outbound[0] == '\0') {
      *needs_default_dns = 1;
      continue;
    }
    status = ftun_plan_mark_outbound_name(config, plan, inbound->outbound, 1);
    if (status != FTUN_OK) return status;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_plan_dns(const ftun_config_t *config,
                                   ftun_feature_plan_t *plan,
                                   int needs_default_dns)
{
  size_t index;
  if (!config->dns.enable) return FTUN_OK;
  ftun_plan_add(plan, FTUN_PLAN_DNS, FTUN_PLAN_ITEM_COMPILED);
  if (config->dns.listener_count != 0u) {
    plan->prepare_listener_count += config->dns.listener_count;
    ftun_plan_add(plan, FTUN_PLAN_DNS_LISTENER,
                  FTUN_PLAN_ITEM_COMPILED | FTUN_PLAN_ITEM_PREPARE |
                  FTUN_PLAN_ITEM_ACTIVE);
  }
  for (index = 0u; index < config->dns.listener_count; index++) {
    const char *server = config->dns.listeners[index].server;
    ftun_status_t status;
    if (server[0] == '\0') {
      needs_default_dns = 1;
      continue;
    }
    status = ftun_plan_mark_dns_name(config, plan, server);
    if (status != FTUN_OK) return status;
  }
  if (needs_default_dns) {
    ftun_status_t status = ftun_plan_mark_dns_name(config, plan,
                                                   config->dns.default_server);
    if (status != FTUN_OK) return status;
  }
  if ((plan->prepare & FTUN_PLAN_DNS) != 0u && config->dns.cache) {
    ftun_plan_add(plan, FTUN_PLAN_DNS_CACHE,
                  FTUN_PLAN_ITEM_COMPILED | FTUN_PLAN_ITEM_PREPARE |
                  FTUN_PLAN_ITEM_ACTIVE);
  }
  return FTUN_OK;
}

static ftun_status_t ftun_plan_frs(const ftun_config_t *config,
                                   ftun_feature_plan_t *plan)
{
  int needs_frs_resolver;
  if ((plan->prepare & FTUN_PLAN_FRS) == 0u) return FTUN_OK;
  plan->prepare_frs_count = 1u;
  if (!config->frs.auto_update || config->frs.url == NULL ||
      config->frs.url[0] == '\0') return FTUN_OK;
  needs_frs_resolver = ftun_plan_host_is_domain(config->frs.url, 1);
  {
    ftun_status_t status;
    ftun_plan_add(plan, FTUN_PLAN_FRS_UPDATE,
                  FTUN_PLAN_ITEM_COMPILED | FTUN_PLAN_ITEM_ACTIVE |
                  FTUN_PLAN_ITEM_RETAINED);
    status = ftun_plan_mark_outbound_name(config, plan,
                                          config->frs.update_outbound, 0);
    if (status != FTUN_OK) return status;
    if (config->dns.enable && config->frs.dns_server[0] != '\0' &&
        needs_frs_resolver) {
      status = ftun_plan_mark_dns_name(config, plan, config->frs.dns_server);
      if (status != FTUN_OK) return status;
    } else if (needs_frs_resolver) {
      ftun_plan_need_resolver(config, plan);
    }
  }
  return FTUN_OK;
}

static void ftun_plan_compile_definitions(const ftun_config_t *config,
                                          ftun_feature_plan_t *plan)
{
  size_t index;
  ftun_plan_add(plan, FTUN_PLAN_RUNTIME,
                FTUN_PLAN_ITEM_COMPILED | FTUN_PLAN_ITEM_PREPARE |
                FTUN_PLAN_ITEM_ACTIVE | FTUN_PLAN_ITEM_RETAINED);
  if (config->sniff.enable) {
    ftun_plan_add(plan, FTUN_PLAN_SNIFF,
                  FTUN_PLAN_ITEM_COMPILED | FTUN_PLAN_ITEM_LAZY |
                  FTUN_PLAN_ITEM_RETAINED);
  }
  if (config->outbound_count != 0u) {
    ftun_plan_add(plan, FTUN_PLAN_OUTBOUND, FTUN_PLAN_ITEM_COMPILED);
  }
  for (index = 0u; index < config->outbound_count; index++) {
    plan->outbound_states[index] = FTUN_PLAN_ITEM_COMPILED;
    if (config->outbounds[index].kind != FTUN_CONFIG_OUTBOUND_SOCKS5) {
      ftun_plan_add(plan, FTUN_PLAN_GROUP, FTUN_PLAN_ITEM_COMPILED);
    }
    if (config->outbounds[index].kind == FTUN_CONFIG_OUTBOUND_URL_TEST) {
      ftun_plan_add(plan, FTUN_PLAN_HEALTH, FTUN_PLAN_ITEM_COMPILED);
    }
  }
  if (config->dns.enable || config->dns.server_count != 0u ||
      config->dns.listener_count != 0u) {
    ftun_plan_add(plan, FTUN_PLAN_DNS, FTUN_PLAN_ITEM_COMPILED);
  }
  if (config->dns.bootstrap.count != 0u) {
    ftun_plan_add(plan, FTUN_PLAN_BOOTSTRAP, FTUN_PLAN_ITEM_COMPILED);
  }
  if (config->dns.listener_count != 0u) {
    ftun_plan_add(plan, FTUN_PLAN_DNS_LISTENER, FTUN_PLAN_ITEM_COMPILED);
  }
  for (index = 0u; index < config->dns.server_count; index++) {
    plan->dns_server_states[index] = FTUN_PLAN_ITEM_COMPILED;
    if (config->dns.servers[index].fake_ip) {
      ftun_plan_add(plan, FTUN_PLAN_FAKE_IP, FTUN_PLAN_ITEM_COMPILED);
    }
  }
  if (config->frs.active) {
    ftun_plan_add(plan, FTUN_PLAN_FRS, FTUN_PLAN_ITEM_COMPILED);
  }
  if (config->frs.active && config->frs.auto_update &&
      config->frs.url != NULL && config->frs.url[0] != '\0') {
    ftun_plan_add(plan, FTUN_PLAN_FRS_UPDATE, FTUN_PLAN_ITEM_COMPILED);
  }
}

ftun_status_t ftun_feature_plan_destroy(ftun_feature_plan_t **plan)
{
  ftun_feature_plan_t *owned;
  ftun_status_t status;
  if (plan == NULL) return FTUN_E_INVALID;
  owned = *plan;
  if (owned == NULL) return FTUN_OK;
  status = ftun_reservation_release(&owned->reservation);
  if (status != FTUN_OK) return status;
  free(owned->outbound_states);
  free(owned->dns_server_states);
  free(owned->rule_order);
  free(owned);
  *plan = NULL;
  return FTUN_OK;
}

/* TASK-CONFIG-004 / TEST-CONFIG-004，目标 0.2.0：依赖闭包与资源计划。 */
ftun_status_t ftun_config_compile(const ftun_config_t *config, ftun_feature_plan_t **out)
{
  ftun_feature_plan_t *plan;
  ftun_reservation_t *reservation = NULL;
  size_t bytes = sizeof(*plan);
  ftun_status_t status;
  int needs_default_dns = 0;
  if (out != NULL) *out = NULL;
  if (config == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_config_validate(config, NULL);
  if (status != FTUN_OK) return status;
  if (config->outbound_count > SIZE_MAX - bytes) return FTUN_E_LIMIT;
  bytes += config->outbound_count;
  if (config->dns.server_count > SIZE_MAX - bytes) return FTUN_E_LIMIT;
  bytes += config->dns.server_count;
  if (config->rules.count > (SIZE_MAX - bytes) / sizeof(size_t)) return FTUN_E_LIMIT;
  bytes += config->rules.count * sizeof(size_t);
  if (config->budget != NULL) {
    status = ftun_budget_reserve(config->budget, bytes, &reservation);
    if (status != FTUN_OK) return status;
  }
  plan = (ftun_feature_plan_t *)calloc(1u, sizeof(*plan));
  if (plan == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  plan->owned_bytes = bytes;
  plan->reservation = reservation;
  plan->outbound_count = config->outbound_count;
  plan->dns_server_count = config->dns.server_count;
  plan->rule_count = config->rules.count;
  if (plan->outbound_count != 0u) {
    plan->outbound_states = (uint8_t *)calloc(plan->outbound_count,
                                              sizeof(*plan->outbound_states));
  }
  if (plan->dns_server_count != 0u) {
    plan->dns_server_states = (uint8_t *)calloc(plan->dns_server_count,
                                                sizeof(*plan->dns_server_states));
  }
  if (plan->rule_count != 0u) {
    plan->rule_order = (size_t *)calloc(plan->rule_count, sizeof(*plan->rule_order));
  }
  if ((plan->outbound_count != 0u && plan->outbound_states == NULL) ||
      (plan->dns_server_count != 0u && plan->dns_server_states == NULL) ||
      (plan->rule_count != 0u && plan->rule_order == NULL)) {
    (void)ftun_feature_plan_destroy(&plan);
    return FTUN_E_LIMIT;
  }
  plan->built_modules = ftun_build_capabilities()->builtins;
  plan->required_modules = ftun_config_required_modules(config);
  ftun_plan_compile_definitions(config, plan);
  status = ftun_plan_rules(config, plan, &needs_default_dns);
  if (status == FTUN_OK) status = ftun_plan_inbounds(config, plan,
                                                     &needs_default_dns);
  if (status == FTUN_OK) status = ftun_plan_dns(config, plan,
                                                needs_default_dns);
  if (status == FTUN_OK) status = ftun_plan_frs(config, plan);
  if (status == FTUN_OK && config->dns.cache &&
      (plan->prepare & FTUN_PLAN_DNS) != 0u) {
    ftun_plan_add(plan, FTUN_PLAN_DNS_CACHE,
                  FTUN_PLAN_ITEM_COMPILED | FTUN_PLAN_ITEM_PREPARE |
                  FTUN_PLAN_ITEM_ACTIVE);
  }
  if (status == FTUN_OK && config->base.state_cache &&
      (plan->active & FTUN_PLAN_GROUP) != 0u) {
    ftun_plan_add(plan, FTUN_PLAN_STATE_CACHE,
                  FTUN_PLAN_ITEM_COMPILED | FTUN_PLAN_ITEM_PREPARE |
                  FTUN_PLAN_ITEM_ACTIVE | FTUN_PLAN_ITEM_RETAINED);
  }
  if (status != FTUN_OK) {
    (void)ftun_feature_plan_destroy(&plan);
    return status;
  }
  *out = plan;
  return FTUN_OK;
}
