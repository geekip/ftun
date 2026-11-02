#include "dns/config/parse.h"
#include "core/config/fields.h"
#include <stdlib.h>
#include <string.h>

static ftun_status_t ftun_parse_fake_ip(const cJSON *item, ftun_config_t *config, ftun_config_dns_t *dns)
{
  static const char *const fields[] = {"enable", "range", "persist"};
  ftun_status_t status = ftun_config_check_fields(config, item, fields, 3u);
  if (status != FTUN_OK) return status;
  status = ftun_config_optional_bool(config, item, "enable", &dns->fake_ip.enable);
  if (status == FTUN_OK) status = ftun_config_replace_string(config, &dns->fake_ip.range,
    item, "range", 0);
  if (status == FTUN_OK) status = ftun_config_optional_bool(config, item, "persist",
    &dns->fake_ip.persist);
  return status;
}


static ftun_status_t ftun_parse_dns_listeners(const cJSON *array,
                                               ftun_config_t *config, ftun_config_dns_t *dns)
{
  static const char *const fields[] = {"listen", "server"};
  const cJSON *item;
  size_t count = 0u;
  size_t index = 0u;
  if (!cJSON_IsArray(array)) return ftun_config_parse_failure(config, array, NULL,
    FTUN_E_INVALID, "expected an array");
  for (item = array->child; item != NULL; item = item->next) count++;
  if (count == 0u) return FTUN_OK;
  dns->listeners = (ftun_config_dns_listener_t *)ftun_config_allocate(config,
    count, sizeof(*dns->listeners));
  if (dns->listeners == NULL) return FTUN_E_LIMIT;
  dns->listener_count = count;
  for (item = array->child; item != NULL; item = item->next, index++) {
    ftun_status_t status = ftun_config_check_fields(config, item, fields, 2u);
    if (status != FTUN_OK) return status;
    status = ftun_config_replace_string(config, &dns->listeners[index].listen,
      item, "listen", 1);
    if (status != FTUN_OK) return status;
    dns->listeners[index].server = ftun_config_string_copy(config, "");
    if (dns->listeners[index].server == NULL) return FTUN_E_LIMIT;
    status = ftun_config_replace_string(config, &dns->listeners[index].server,
      item, "server", 0);
    if (status != FTUN_OK) return status;
  }
  return FTUN_OK;
}


static ftun_status_t ftun_parse_dns_servers(const cJSON *array,
                                             ftun_config_t *config, ftun_config_dns_t *dns)
{
  static const char *const fields[] = {
    "name", "type", "address", "outbound", "fake-ip"
  };
  const cJSON *item;
  size_t count = 0u;
  size_t index = 0u;
  if (!cJSON_IsArray(array)) return ftun_config_parse_failure(config, array, NULL,
    FTUN_E_INVALID, "expected an array");
  for (item = array->child; item != NULL; item = item->next) count++;
  if (count == 0u) return FTUN_OK;
  dns->servers = (ftun_config_dns_server_t *)ftun_config_allocate(config,
    count, sizeof(*dns->servers));
  if (dns->servers == NULL) return FTUN_E_LIMIT;
  dns->server_count = count;
  for (item = array->child; item != NULL; item = item->next, index++) {
    ftun_config_dns_server_t *server = &dns->servers[index];
      ftun_status_t status = ftun_config_check_fields(config, item, fields, 5u);
    if (status != FTUN_OK) return status;
    status = ftun_config_replace_string(config, &server->name,
      item, "name", 1);
    if (status == FTUN_OK) status = ftun_config_replace_string(config, &server->type,
      item, "type", 1);
    if (status != FTUN_OK) return status;
    if (strcmp(server->type, "udp") != 0 && strcmp(server->type, "tcp") != 0) {
      return ftun_config_parse_failure(config, item, "type", FTUN_E_UNSUPPORTED,
        "DNS server type is unsupported");
    }
    status = ftun_config_parse_string_list(config, item, "address", &server->addresses, 1);
    if (status != FTUN_OK) return status;
    server->outbound = ftun_config_string_copy(config, "DIRECT");
    if (server->outbound == NULL) return FTUN_E_LIMIT;
    status = ftun_config_replace_string(config, &server->outbound,
      item, "outbound", 0);
    if (status == FTUN_OK) status = ftun_config_optional_bool(config, item, "fake-ip", &server->fake_ip);
    if (status != FTUN_OK) return status;
  }
  return FTUN_OK;
}


ftun_status_t ftun_config_parse_dns(const cJSON *item, ftun_config_t *config, ftun_config_dns_t *dns)
{
  static const char *const fields[] = {
    "enable", "cache", "bootstrap", "default-server", "fake-ip",
    "listeners", "servers"
  };
  const cJSON *child;
  ftun_status_t status = ftun_config_check_fields(config, item, fields, 7u);
  if (status != FTUN_OK) return status;
  status = ftun_config_optional_bool(config, item, "enable", &dns->enable);
  if (status == FTUN_OK) status = ftun_config_optional_bool(config, item, "cache", &dns->cache);
  child = cJSON_GetObjectItemCaseSensitive(item, "bootstrap");
  if (status == FTUN_OK && child != NULL) {
    status = ftun_config_parse_string_list(config, item, "bootstrap", &dns->bootstrap, 0);
  }
  if (status == FTUN_OK) status = ftun_config_replace_string(config, &dns->default_server,
    item, "default-server", 0);
  child = cJSON_GetObjectItemCaseSensitive(item, "fake-ip");
  if (status == FTUN_OK && child != NULL) status = ftun_parse_fake_ip(child, config, dns);
  child = cJSON_GetObjectItemCaseSensitive(item, "listeners");
  if (status == FTUN_OK && child != NULL) status = ftun_parse_dns_listeners(child, config, dns);
  child = cJSON_GetObjectItemCaseSensitive(item, "servers");
  if (status == FTUN_OK && child != NULL) status = ftun_parse_dns_servers(child, config, dns);
  return status;
}


ftun_status_t ftun_config_defaults_dns(ftun_config_t *config, ftun_config_dns_t *dns)
{
#define SET_DEFAULT(field, value) do { \
  (field) = ftun_config_string_copy(config, value); \
  if ((field) == NULL) return FTUN_E_LIMIT; \
} while (0)
  dns->enable = true;
  dns->cache = true;
  SET_DEFAULT(dns->default_server, "");
  dns->fake_ip.enable = true;
  dns->fake_ip.persist = true;
  SET_DEFAULT(dns->fake_ip.range, "198.18.0.0/15");
#undef SET_DEFAULT
  return FTUN_OK;
}

void ftun_config_clear_dns(ftun_config_dns_t *dns)
{
  size_t index;
  ftun_config_string_list_clear(&dns->bootstrap);
  free(dns->default_server);
  free(dns->fake_ip.range);
  for (index = 0u; index < dns->listener_count; index++) {
    free(dns->listeners[index].listen);
    free(dns->listeners[index].server);
  }
  free(dns->listeners);
  for (index = 0u; index < dns->server_count; index++) {
    free(dns->servers[index].name);
    free(dns->servers[index].type);
    ftun_config_string_list_clear(&dns->servers[index].addresses);
    free(dns->servers[index].outbound);
  }
  free(dns->servers);
}
