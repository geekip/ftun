#include "proxy/config/parse.h"
#include "core/config/fields.h"
#include <stdlib.h>
#include <string.h>

ftun_status_t ftun_config_parse_frs(const cJSON *item, ftun_config_t *config, ftun_config_frs_t *frs)
{
  static const char *const fields[] = {
    "path", "url", "auto-update", "update-interval", "update-outbound",
    "dns-server"
  };
  ftun_status_t status = ftun_config_check_fields(item, fields, 6u);
  if (status != FTUN_OK) return status;
  frs->present = true;
  status = ftun_config_replace_string(config, &frs->path,
    cJSON_GetObjectItemCaseSensitive(item, "path"), 0);
  if (status == FTUN_OK) status = ftun_config_replace_string(config, &frs->url,
    cJSON_GetObjectItemCaseSensitive(item, "url"), 0);
  if (status == FTUN_OK) status = ftun_config_optional_bool(item, "auto-update",
    &frs->auto_update);
  if (status == FTUN_OK) status = ftun_config_replace_string(config, &frs->update_interval,
    cJSON_GetObjectItemCaseSensitive(item, "update-interval"), 0);
  if (status == FTUN_OK) status = ftun_config_replace_string(config, &frs->update_outbound,
    cJSON_GetObjectItemCaseSensitive(item, "update-outbound"), 0);
  if (status == FTUN_OK) status = ftun_config_replace_string(config, &frs->dns_server,
    cJSON_GetObjectItemCaseSensitive(item, "dns-server"), 0);
  return status;
}


ftun_status_t ftun_config_parse_sniff(const cJSON *item, ftun_config_sniff_t *sniff)
{
  static const char *const fields[] = {"enable", "tls-sni", "http-host"};
  ftun_status_t status = ftun_config_check_fields(item, fields, 3u);
  if (status != FTUN_OK) return status;
  status = ftun_config_optional_bool(item, "enable", &sniff->enable);
  if (status == FTUN_OK) status = ftun_config_optional_bool(item, "tls-sni", &sniff->tls_sni);
  if (status == FTUN_OK) status = ftun_config_optional_bool(item, "http-host", &sniff->http_host);
  return status;
}


static ftun_status_t ftun_parse_users(ftun_config_t *config, const cJSON *item,
                                      ftun_config_inbound_t *inbound)
{
  const cJSON *user;
  size_t count = 0u;
  size_t index = 0u;
  if (!cJSON_IsObject(item)) return FTUN_E_INVALID;
  for (user = item->child; user != NULL; user = user->next) count++;
  if (count == 0u) return FTUN_OK;
  inbound->users = (ftun_config_user_t *)ftun_config_allocate(config, count, sizeof(*inbound->users));
  if (inbound->users == NULL) return FTUN_E_LIMIT;
  inbound->user_count = count;
  for (user = item->child; user != NULL; user = user->next, index++) {
    if (user->string == NULL || !cJSON_IsString(user) || user->valuestring == NULL ||
        strlen(user->string) == 0u || strlen(user->string) > 255u ||
        strlen(user->valuestring) == 0u || strlen(user->valuestring) > 255u) {
      return FTUN_E_INVALID;
    }
    inbound->users[index].name = ftun_config_string_copy(config, user->string);
    inbound->users[index].password = ftun_config_string_copy(config, user->valuestring);
    if (inbound->users[index].name == NULL || inbound->users[index].password == NULL) {
      return FTUN_E_LIMIT;
    }
  }
  return FTUN_OK;
}


static ftun_status_t ftun_parse_tun_inbound(ftun_config_t *config,
  const cJSON *item, ftun_config_inbound_t *inbound)
{
  static const char *const fields[] = {
    "name", "type", "outbound", "stack", "tcp", "udp", "dns-hijack", "tcp-idle"
  };
  ftun_status_t status = ftun_config_check_fields(item, fields, 8u);
  if (status != FTUN_OK) return status;
  inbound->kind = FTUN_CONFIG_INBOUND_TUN;
  inbound->tcp = true;
  inbound->udp = true;
  inbound->dns_hijack = true;
  inbound->stack = ftun_config_string_copy(config, "lwip");
  if (inbound->stack == NULL) return FTUN_E_LIMIT;
  status = ftun_config_replace_string(config, &inbound->name,
    cJSON_GetObjectItemCaseSensitive(item, "name"), 1);
  if (status == FTUN_OK) status = ftun_config_replace_string(config, &inbound->outbound,
    cJSON_GetObjectItemCaseSensitive(item, "outbound"), 0);
  if (status == FTUN_OK) status = ftun_config_replace_string(config, &inbound->stack,
    cJSON_GetObjectItemCaseSensitive(item, "stack"), 0);
  if (status != FTUN_OK) return status;
  if (strcmp(inbound->stack, "lwip") != 0) return FTUN_E_UNSUPPORTED;
  status = ftun_config_optional_bool(item, "tcp", &inbound->tcp);
  if (status == FTUN_OK) status = ftun_config_optional_duration(item, "tcp-idle", false,
                                                         &inbound->tcp_idle_ms);
  if (status == FTUN_OK) status = ftun_config_optional_bool(item, "udp", &inbound->udp);
  if (status == FTUN_OK) status = ftun_config_optional_bool(item, "dns-hijack", &inbound->dns_hijack);
  return status;
}


static ftun_status_t ftun_parse_proxy_inbound(ftun_config_t *config, const cJSON *item,
                                               ftun_config_inbound_t *inbound,
                                               ftun_config_inbound_kind_t kind)
{
  static const char *const fields[] = {
    "name", "type", "outbound", "listen", "users", "udp", "tcp-idle"
  };
  const cJSON *users;
  ftun_status_t status = ftun_config_check_fields(item, fields, 7u);
  if (status != FTUN_OK) return status;
  inbound->kind = kind;
  inbound->udp = true;
  status = ftun_config_replace_string(config, &inbound->name,
    cJSON_GetObjectItemCaseSensitive(item, "name"), 1);
  if (status == FTUN_OK) status = ftun_config_replace_string(config, &inbound->outbound,
    cJSON_GetObjectItemCaseSensitive(item, "outbound"), 0);
  if (status == FTUN_OK) status = ftun_config_replace_string(config, &inbound->listen,
    cJSON_GetObjectItemCaseSensitive(item, "listen"), 1);
  users = cJSON_GetObjectItemCaseSensitive(item, "users");
  if (status == FTUN_OK && users != NULL) status = ftun_parse_users(config, users, inbound);
  if (status == FTUN_OK) status = ftun_config_optional_bool(item, "udp", &inbound->udp);
  if (status == FTUN_OK) status = ftun_config_optional_duration(item, "tcp-idle", false,
                                                         &inbound->tcp_idle_ms);
  return status;
}


ftun_status_t ftun_config_parse_inbounds(const cJSON *array, ftun_config_t *config,
  ftun_config_inbound_t **items, size_t *item_count)
{
  const cJSON *item;
  size_t count = 0u;
  size_t index = 0u;
  if (!cJSON_IsArray(array)) return FTUN_E_INVALID;
  for (item = array->child; item != NULL; item = item->next) count++;
  if (count == 0u) return FTUN_OK;
  (*items) = (ftun_config_inbound_t *)ftun_config_allocate(config, count, sizeof(*(*items)));
  if ((*items) == NULL) return FTUN_E_LIMIT;
  (*item_count) = count;
  for (item = array->child; item != NULL; item = item->next, index++) {
    const cJSON *type = cJSON_GetObjectItemCaseSensitive(item, "type");
    ftun_status_t status;
    if (!cJSON_IsObject(item) || !cJSON_IsString(type) || type->valuestring == NULL) {
      return FTUN_E_INVALID;
    }
    (*items)[index].outbound = ftun_config_string_copy(config, "");
    if ((*items)[index].outbound == NULL) return FTUN_E_LIMIT;
    if (strcmp(type->valuestring, "mixed") == 0) {
      status = ftun_parse_proxy_inbound(config, item, &(*items)[index],
                                        FTUN_CONFIG_INBOUND_MIXED);
    } else if (strcmp(type->valuestring, "socks5") == 0) {
      status = ftun_parse_proxy_inbound(config, item, &(*items)[index],
                                        FTUN_CONFIG_INBOUND_SOCKS5);
    } else if (strcmp(type->valuestring, "tun") == 0) {
      status = ftun_parse_tun_inbound(config, item, &(*items)[index]);
    } else {
      return FTUN_E_UNSUPPORTED;
    }
    if (status != FTUN_OK) return status;
  }
  return FTUN_OK;
}


static ftun_status_t ftun_parse_socks_outbound(ftun_config_t *config, const cJSON *item,
                                                ftun_config_outbound_t *outbound)
{
  static const char *const fields[] = {
    "name", "type", "dns-server", "server", "username", "password", "udp"
  };
  const cJSON *username;
  const cJSON *password;
  ftun_status_t status = ftun_config_check_fields(item, fields, 7u);
  if (status != FTUN_OK) return status;
  outbound->kind = FTUN_CONFIG_OUTBOUND_SOCKS5;
  outbound->udp = true;
  status = ftun_config_replace_string(config, &outbound->name,
    cJSON_GetObjectItemCaseSensitive(item, "name"), 1);
  if (status == FTUN_OK) status = ftun_config_replace_string(config, &outbound->dns_server,
    cJSON_GetObjectItemCaseSensitive(item, "dns-server"), 0);
  if (status == FTUN_OK) status = ftun_config_replace_string(config, &outbound->server,
    cJSON_GetObjectItemCaseSensitive(item, "server"), 1);
  username = cJSON_GetObjectItemCaseSensitive(item, "username");
  password = cJSON_GetObjectItemCaseSensitive(item, "password");
  if (status == FTUN_OK && ((username == NULL) != (password == NULL))) return FTUN_E_INVALID;
  if (status == FTUN_OK) status = ftun_config_replace_string(config, &outbound->username, username, 0);
  if (status == FTUN_OK) status = ftun_config_replace_string(config, &outbound->password, password, 0);
  if (status == FTUN_OK) status = ftun_config_optional_bool(item, "udp", &outbound->udp);
  return status;
}


static ftun_status_t ftun_parse_group_outbound(ftun_config_t *config, const cJSON *item,
                                                ftun_config_outbound_t *outbound,
                                                int url_test)
{
  static const char *const select_fields[] = {
    "name", "type", "dns-server", "outbounds", "default"
  };
  static const char *const url_fields[] = {
    "name", "type", "dns-server", "outbounds", "default", "url", "interval",
    "timeout", "tolerance", "lazy", "expected-status"
  };
  const cJSON *members;
  uint32_t expected_status = 204u;
  ftun_status_t status = ftun_config_check_fields(item, url_test ? url_fields : select_fields,
                                           url_test ? 11u : 5u);
  if (status != FTUN_OK) return status;
  outbound->kind = url_test ? FTUN_CONFIG_OUTBOUND_URL_TEST : FTUN_CONFIG_OUTBOUND_SELECT;
  status = ftun_config_replace_string(config, &outbound->name,
    cJSON_GetObjectItemCaseSensitive(item, "name"), 1);
  if (status == FTUN_OK) status = ftun_config_replace_string(config, &outbound->dns_server,
    cJSON_GetObjectItemCaseSensitive(item, "dns-server"), 0);
  members = cJSON_GetObjectItemCaseSensitive(item, "outbounds");
  if (status == FTUN_OK && members == NULL) status = FTUN_E_INVALID;
  if (status == FTUN_OK) status = ftun_config_parse_string_list(config, members, &outbound->members, 1);
  if (status == FTUN_OK) status = ftun_config_replace_string(config, &outbound->default_member,
    cJSON_GetObjectItemCaseSensitive(item, "default"), 1);
  if (status != FTUN_OK || !url_test) return status;
  outbound->interval = ftun_config_string_copy(config, "5m");
  outbound->timeout = ftun_config_string_copy(config, "5s");
  outbound->tolerance_ms = 50u;
  outbound->lazy = true;
  outbound->expected_status = 204u;
  if (outbound->interval == NULL || outbound->timeout == NULL) return FTUN_E_LIMIT;
  status = ftun_config_replace_string(config, &outbound->url,
    cJSON_GetObjectItemCaseSensitive(item, "url"), 1);
  if (status == FTUN_OK) status = ftun_config_replace_string(config, &outbound->interval,
    cJSON_GetObjectItemCaseSensitive(item, "interval"), 0);
  if (status == FTUN_OK) status = ftun_config_replace_string(config, &outbound->timeout,
    cJSON_GetObjectItemCaseSensitive(item, "timeout"), 0);
  if (status == FTUN_OK) status = ftun_config_optional_uint(item, "tolerance", 0u,
    UINT32_MAX, &outbound->tolerance_ms);
  if (status == FTUN_OK) status = ftun_config_optional_bool(item, "lazy", &outbound->lazy);
  if (status == FTUN_OK) status = ftun_config_optional_uint(item, "expected-status", 100u,
    599u, &expected_status);
  outbound->expected_status = (uint16_t)expected_status;
  return status;
}


ftun_status_t ftun_config_parse_outbounds(const cJSON *array, ftun_config_t *config,
  ftun_config_outbound_t **items, size_t *item_count)
{
  const cJSON *item;
  size_t count = 0u;
  size_t index = 0u;
  if (!cJSON_IsArray(array)) return FTUN_E_INVALID;
  for (item = array->child; item != NULL; item = item->next) count++;
  if (count == 0u) return FTUN_OK;
  (*items) = (ftun_config_outbound_t *)ftun_config_allocate(config, count, sizeof(*(*items)));
  if ((*items) == NULL) return FTUN_E_LIMIT;
  (*item_count) = count;
  for (item = array->child; item != NULL; item = item->next, index++) {
    const cJSON *type = cJSON_GetObjectItemCaseSensitive(item, "type");
    ftun_status_t status;
    if (!cJSON_IsObject(item) || !cJSON_IsString(type) || type->valuestring == NULL) {
      return FTUN_E_INVALID;
    }
    (*items)[index].dns_server = ftun_config_string_copy(config, "");
    if ((*items)[index].dns_server == NULL) return FTUN_E_LIMIT;
    if (strcmp(type->valuestring, "socks5") == 0) {
      status = ftun_parse_socks_outbound(config, item, &(*items)[index]);
    } else if (strcmp(type->valuestring, "select") == 0) {
      status = ftun_parse_group_outbound(config, item, &(*items)[index], 0);
    } else if (strcmp(type->valuestring, "url-test") == 0) {
      status = ftun_parse_group_outbound(config, item, &(*items)[index], 1);
    } else {
      return FTUN_E_UNSUPPORTED;
    }
    if (status != FTUN_OK) return status;
  }
  return FTUN_OK;
}


ftun_status_t ftun_config_defaults_frs(ftun_config_t *config, ftun_config_frs_t *frs)
{
#define SET_DEFAULT(field, value) do { \
  (field) = ftun_config_string_copy(config, value); \
  if ((field) == NULL) return FTUN_E_LIMIT; \
} while (0)
  SET_DEFAULT(frs->update_interval, "24h");
  SET_DEFAULT(frs->update_outbound, "DIRECT");
  SET_DEFAULT(frs->dns_server, "");
#undef SET_DEFAULT
  return FTUN_OK;
}

void ftun_config_clear_frs(ftun_config_frs_t *frs)
{
  free(frs->path);
  free(frs->url);
  free(frs->update_interval);
  free(frs->update_outbound);
  free(frs->dns_server);
}

void ftun_config_clear_inbounds(ftun_config_inbound_t *items, size_t count)
{
  size_t index;
  for (index = 0u; index < count; index++) {
    ftun_config_inbound_t *inbound = &items[index];
    size_t user_index;
    free(inbound->name);
    free(inbound->outbound);
    free(inbound->listen);
    for (user_index = 0u; user_index < inbound->user_count; user_index++) {
      free(inbound->users[user_index].name);
      free(inbound->users[user_index].password);
    }
    free(inbound->users);
    free(inbound->interface_name);
    free(inbound->stack);
    free(inbound->ipv4_address);
  }
  free(items);
}

void ftun_config_clear_outbounds(ftun_config_outbound_t *items, size_t count)
{
  size_t index;
  for (index = 0u; index < count; index++) {
    ftun_config_outbound_t *outbound = &items[index];
    free(outbound->name);
    free(outbound->dns_server);
    free(outbound->server);
    free(outbound->username);
    free(outbound->password);
    ftun_config_string_list_clear(&outbound->members);
    free(outbound->default_member);
    free(outbound->url);
    free(outbound->interval);
    free(outbound->timeout);
  }
  free(items);
}
