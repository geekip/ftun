#include "proxy/http_route.h"
#include "proxy/outbound_id.h"
#include <string.h>

static ftun_status_t ftun_http_outbound_id(const ftun_config_t *config,
                                            const char *name,
                                            uint32_t *out)
{
  size_t index;
  if (config == NULL || name == NULL || out == NULL) return FTUN_E_INVALID;
  if (strcmp(name, "DIRECT") == 0) {
    *out = FTUN_OUTBOUND_ID_DIRECT;
    return FTUN_OK;
  }
  if (strcmp(name, "REJECT") == 0) {
    *out = FTUN_OUTBOUND_ID_REJECT;
    return FTUN_OK;
  }
  for (index = 0u; index < ftun_config_outbound_count(config); index++) {
    if (strcmp(name, ftun_config_outbounds(config)[index].name) == 0) {
      if (index > UINT32_MAX - FTUN_OUTBOUND_ID_NAMED_BASE) {
        return FTUN_E_LIMIT;
      }
      *out = (uint32_t)index + FTUN_OUTBOUND_ID_NAMED_BASE;
      return FTUN_OK;
    }
  }
  return FTUN_E_REJECTED;
}

ftun_status_t ftun_http_fetch_route(const ftun_config_t *config,
                                    const ftun_runtime_t *runtime,
                                    const char *outbound_name,
                                    ftun_http_fetch_spec_t *spec)
{
  uint32_t current;
  size_t depth;
  ftun_status_t status;
  if (config == NULL || outbound_name == NULL || spec == NULL) {
    return FTUN_E_INVALID;
  }
  if (runtime != NULL) {
    ftun_runtime_info_t info;
    status = ftun_runtime_get_info(runtime, &info);
    if (status != FTUN_OK) return status;
    spec->generation = info.generation;
  }
  spec->use_proxy = false;
  memset(&spec->proxy, 0, sizeof(spec->proxy));
  memset(spec->proxy_domain, 0, sizeof(spec->proxy_domain));
  memset(&spec->proxy_username, 0, sizeof(spec->proxy_username));
  memset(&spec->proxy_password, 0, sizeof(spec->proxy_password));
  status = ftun_http_outbound_id(config, outbound_name, &current);
  for (depth = 0u; status == FTUN_OK && depth <= ftun_config_outbound_count(config);
       depth++) {
    const ftun_config_outbound_t *item;
    size_t index;
    if (current == FTUN_OUTBOUND_ID_DIRECT) return FTUN_OK;
    if (current == FTUN_OUTBOUND_ID_REJECT ||
        current < FTUN_OUTBOUND_ID_NAMED_BASE) return FTUN_E_REJECTED;
    index = (size_t)(current - FTUN_OUTBOUND_ID_NAMED_BASE);
    if (index >= ftun_config_outbound_count(config)) return FTUN_E_STATE_CORRUPT;
    item = &ftun_config_outbounds(config)[index];
    if (item->kind == FTUN_CONFIG_OUTBOUND_SOCKS5) {
      ftun_endpoint_t parsed;
      char domain[FTUN_CONTROL_ENDPOINT_TEXT_BYTES];
      status = ftun_control_parse_endpoint(
        item->server, 1u, &parsed, domain);
      if (status == FTUN_OK && parsed.kind == FTUN_ADDRESS_DOMAIN) {
        spec->proxy.kind = FTUN_ADDRESS_DOMAIN;
        spec->proxy.port = parsed.port;
        memcpy(spec->proxy_domain, domain, parsed.domain.length + 1u);
        spec->proxy.domain.data = spec->proxy_domain;
        spec->proxy.domain.length = parsed.domain.length;
      } else if (status == FTUN_OK) {
        spec->proxy = parsed;
      }
      if (status != FTUN_OK) return status;
      spec->use_proxy = true;
      if (item->username != NULL) {
        spec->proxy_username.data = item->username;
        spec->proxy_username.length = strlen(item->username);
        spec->proxy_password.data = item->password;
        spec->proxy_password.length = strlen(item->password);
      }
      return FTUN_OK;
    }
    if (runtime != NULL) {
      bool is_group = false;
      bool degraded = false;
      ftun_string_t dns_server;
      uint32_t selected = 0u;
      status = ftun_runtime_group_selected(runtime, current, &selected,
                                            &is_group, &degraded,
                                            &dns_server);
      (void)degraded;
      (void)dns_server;
      if (status == FTUN_OK && !is_group) status = FTUN_E_STATE_CORRUPT;
      if (status == FTUN_OK) current = selected;
    } else {
      status = ftun_http_outbound_id(config, item->default_member, &current);
    }
  }
  return status == FTUN_OK ? FTUN_E_STATE_CORRUPT : status;
}

ftun_status_t ftun_http_fetch_resolver(const ftun_config_t *config,
                                       const ftun_runtime_t *runtime,
                                       ftun_string_t server,
                                       ftun_http_fetch_spec_t *spec)
{
  if (spec == NULL) return FTUN_E_INVALID;
  return ftun_control_resolver_plan(config, runtime, server,
                                    spec->socket_mark, &spec->resolver);
}

