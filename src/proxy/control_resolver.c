#include "proxy/control_resolver.h"
#include "proxy/outbound_id.h"
#include <string.h>

static ftun_status_t ftun_control_copy(char *out, size_t capacity,
                                       const char *value)
{
  size_t length;
  if (out == NULL || capacity == 0u || value == NULL) return FTUN_E_INVALID;
  length = strlen(value);
  if (length >= capacity) return FTUN_E_LIMIT;
  memcpy(out, value, length + 1u);
  return FTUN_OK;
}

static ftun_status_t ftun_control_outbound_id(const ftun_config_t *config,
                                               const char *name,
                                               uint32_t *out)
{
  size_t index;
  if (strcmp(name, "DIRECT") == 0) {
    *out = FTUN_OUTBOUND_ID_DIRECT;
    return FTUN_OK;
  }
  if (strcmp(name, "REJECT") == 0) {
    *out = FTUN_OUTBOUND_ID_REJECT;
    return FTUN_OK;
  }
  for (index = 0u; index < ftun_config_outbound_count(config); index++) {
    if (strcmp(ftun_config_outbounds(config)[index].name, name) == 0) {
      if (index > UINT32_MAX - FTUN_OUTBOUND_ID_NAMED_BASE) {
        return FTUN_E_LIMIT;
      }
      *out = (uint32_t)index + FTUN_OUTBOUND_ID_NAMED_BASE;
      return FTUN_OK;
    }
  }
  return FTUN_E_REJECTED;
}

static ftun_status_t ftun_control_proxy_plan(
  const ftun_config_t *config, const ftun_runtime_t *runtime,
  const char *outbound, ftun_control_resolver_plan_t *plan)
{
  uint32_t current;
  size_t depth;
  ftun_status_t status = ftun_control_outbound_id(config, outbound, &current);
  for (depth = 0u; status == FTUN_OK && depth <= ftun_config_outbound_count(config);
       depth++) {
    const ftun_config_outbound_t *item;
    size_t index;
    if (current == FTUN_OUTBOUND_ID_DIRECT) return FTUN_OK;
    if (current == FTUN_OUTBOUND_ID_REJECT ||
        current < FTUN_OUTBOUND_ID_NAMED_BASE) return FTUN_E_REJECTED;
    index = current - FTUN_OUTBOUND_ID_NAMED_BASE;
    if (index >= ftun_config_outbound_count(config)) return FTUN_E_STATE_CORRUPT;
    item = &ftun_config_outbounds(config)[index];
    if (item->kind == FTUN_CONFIG_OUTBOUND_SOCKS5) {
      status = ftun_control_copy(plan->proxy, sizeof(plan->proxy),
                                 item->server);
      if (status == FTUN_OK && item->username != NULL) {
        status = ftun_control_copy(plan->proxy_username,
          sizeof(plan->proxy_username), item->username);
        if (status == FTUN_OK) status = ftun_control_copy(
          plan->proxy_password, sizeof(plan->proxy_password), item->password);
      }
      if (status == FTUN_OK) plan->use_proxy = true;
      return status;
    }
    if (runtime != NULL) {
      uint32_t selected = 0u;
      bool is_group = false;
      bool degraded = false;
      ftun_string_t dns_server;
      status = ftun_runtime_group_selected(runtime, current, &selected,
        &is_group, &degraded, &dns_server);
      (void)degraded;
      (void)dns_server;
      if (status == FTUN_OK && !is_group) status = FTUN_E_STATE_CORRUPT;
      if (status == FTUN_OK) current = selected;
    } else {
      status = ftun_control_outbound_id(config, item->default_member,
                                        &current);
    }
  }
  return status == FTUN_OK ? FTUN_E_STATE_CORRUPT : status;
}

ftun_status_t ftun_control_resolver_plan(
  const ftun_config_t *config, const ftun_runtime_t *runtime,
  ftun_string_t server, uint32_t socket_mark,
  ftun_control_resolver_plan_t *out)
{
  size_t index;
  ftun_status_t status = FTUN_OK;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (config == NULL || out == NULL ||
      (server.length != 0u && server.data == NULL)) return FTUN_E_INVALID;
  out->socket_mark = socket_mark;
  if (!ftun_config_resolver(config).enable) return FTUN_OK;
  if (ftun_config_resolver(config).bootstrap.count > FTUN_BOOTSTRAP_MAX_SERVERS) {
    return FTUN_E_LIMIT;
  }
  for (index = 0u; index < ftun_config_resolver(config).bootstrap.count; index++) {
    char domain[FTUN_CONTROL_ENDPOINT_TEXT_BYTES];
    status = ftun_control_parse_endpoint(ftun_config_resolver(config).bootstrap.items[index],
      53u, &out->bootstrap[index], domain);
    if (status != FTUN_OK || out->bootstrap[index].kind != FTUN_ADDRESS_IPV4) {
      return status == FTUN_OK ? FTUN_E_INVALID : status;
    }
    out->bootstrap_count++;
  }
  if (server.length == 0u) return FTUN_OK;
  for (index = 0u; index < ftun_config_resolver(config).server_count; index++) {
    const ftun_config_dns_server_t *item = &ftun_config_resolver(config).servers[index];
    if (strlen(item->name) != server.length ||
        memcmp(item->name, server.data, server.length) != 0) continue;
    if (item->addresses.count == 0u) return FTUN_E_STATE_CORRUPT;
    status = ftun_control_copy(out->upstream, sizeof(out->upstream),
                               item->addresses.items[0]);
    if (status == FTUN_OK) status = ftun_control_copy(out->name, sizeof(out->name), item->name);
    if (status == FTUN_OK) {
      out->named = true;
      out->tcp = strcmp(item->type, "tcp") == 0;
      status = ftun_control_proxy_plan(config, runtime, item->outbound, out);
    }
    return status;
  }
  return FTUN_E_REJECTED;
}

