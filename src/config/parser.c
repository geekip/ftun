#include "parser.h"
#include "compile.h"
#include "model.h"
#include <cJSON.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

static char *ftun_config_string_copy(const char *value)
{
  size_t length;
  char *copy;
  if (value == NULL) return NULL;
  length = strlen(value);
  if (length > FTUN_CONFIG_MAX_STRING_BYTES) return NULL;
  copy = (char *)malloc(length + 1u);
  if (copy == NULL) return NULL;
  memcpy(copy, value, length + 1u);
  return copy;
}

static int ftun_utf8_valid(const unsigned char *text)
{
  size_t index = 0u;
  while (text[index] != 0u) {
    unsigned int codepoint;
    size_t remaining;
    unsigned char first = text[index];
    if (first < 0x80u) {
      index++;
      continue;
    }
    if (first >= 0xc2u && first <= 0xdfu) {
      codepoint = first & 0x1fu;
      remaining = 1u;
    } else if (first >= 0xe0u && first <= 0xefu) {
      codepoint = first & 0x0fu;
      remaining = 2u;
    } else if (first >= 0xf0u && first <= 0xf4u) {
      codepoint = first & 0x07u;
      remaining = 3u;
    } else {
      return 0;
    }
    while (remaining != 0u) {
      unsigned char next = text[index + 1u];
      if ((next & 0xc0u) != 0x80u) return 0;
      codepoint = (codepoint << 6u) | (next & 0x3fu);
      index++;
      remaining--;
    }
    if ((first == 0xe0u && codepoint < 0x800u) ||
        (first == 0xedu && codepoint >= 0xd800u) ||
        (first == 0xf0u && codepoint < 0x10000u) ||
        codepoint > 0x10ffffu ||
        (codepoint >= 0xd800u && codepoint <= 0xdfffu)) return 0;
    index++;
  }
  return 1;
}

static ftun_status_t ftun_json_preflight(ftun_bytes_t json)
{
  size_t index;
  size_t depth = 0u;
  int in_string = 0;
  int escaped = 0;
  if (json.data == NULL || json.length == 0u) return FTUN_E_INVALID;
  if (json.length > FTUN_CONFIG_MAX_JSON_BYTES) return FTUN_E_LIMIT;
  for (index = 0u; index < json.length; index++) {
    unsigned char byte = json.data[index];
    if (byte == 0u) return FTUN_E_INVALID;
    if (in_string) {
      if (escaped) {
        if (byte == 'u' && index + 4u < json.length &&
            json.data[index + 1u] == '0' && json.data[index + 2u] == '0' &&
            json.data[index + 3u] == '0' && json.data[index + 4u] == '0') {
          return FTUN_E_INVALID;
        }
        escaped = 0;
      } else if (byte == '\\') {
        escaped = 1;
      } else if (byte == '"') {
        in_string = 0;
      }
      continue;
    }
    if (byte == '"') {
      in_string = 1;
    } else if (byte == '{' || byte == '[') {
      depth++;
      if (depth > FTUN_CONFIG_MAX_DEPTH) return FTUN_E_LIMIT;
    } else if (byte == '}' || byte == ']') {
      if (depth == 0u) return FTUN_E_INVALID;
      depth--;
    }
  }
  return in_string || escaped || depth != 0u ? FTUN_E_INVALID : FTUN_OK;
}

static ftun_status_t ftun_json_tree_check(const cJSON *item, size_t depth,
                                          size_t *nodes)
{
  const cJSON *child;
  size_t children = 0u;
  if (item == NULL || nodes == NULL) return FTUN_E_INVALID;
  if (depth > FTUN_CONFIG_MAX_DEPTH || *nodes >= FTUN_CONFIG_MAX_NODES) {
    return FTUN_E_LIMIT;
  }
  (*nodes)++;
  if (item->string != NULL &&
      strlen(item->string) > FTUN_CONFIG_MAX_STRING_BYTES) return FTUN_E_LIMIT;
  if (item->string != NULL &&
      !ftun_utf8_valid((const unsigned char *)item->string)) return FTUN_E_INVALID;
  if (cJSON_IsString(item) && item->valuestring == NULL) return FTUN_E_INVALID;
  if (cJSON_IsString(item) &&
      strlen(item->valuestring) > FTUN_CONFIG_MAX_STRING_BYTES) return FTUN_E_LIMIT;
  if (cJSON_IsString(item) &&
      !ftun_utf8_valid((const unsigned char *)item->valuestring)) return FTUN_E_INVALID;
  if (cJSON_IsNumber(item) && !isfinite(item->valuedouble)) return FTUN_E_INVALID;
  if (cJSON_IsObject(item)) {
    const cJSON *other;
    for (child = item->child; child != NULL; child = child->next) {
      children++;
      for (other = child->next; other != NULL; other = other->next) {
        if (child->string != NULL && other->string != NULL &&
            strcmp(child->string, other->string) == 0) return FTUN_E_INVALID;
      }
    }
  } else if (cJSON_IsArray(item)) {
    for (child = item->child; child != NULL; child = child->next) children++;
  }
  if (children > FTUN_CONFIG_MAX_ARRAY_ITEMS) return FTUN_E_LIMIT;
  for (child = item->child; child != NULL; child = child->next) {
    ftun_status_t status = ftun_json_tree_check(child, depth + 1u, nodes);
    if (status != FTUN_OK) return status;
  }
  return FTUN_OK;
}

static int ftun_field_allowed(const char *field, const char *const *allowed,
                              size_t allowed_count)
{
  size_t index;
  for (index = 0u; index < allowed_count; index++) {
    if (strcmp(field, allowed[index]) == 0) return 1;
  }
  return 0;
}

static ftun_status_t ftun_check_fields(const cJSON *object,
                                       const char *const *allowed,
                                       size_t allowed_count)
{
  const cJSON *item;
  if (!cJSON_IsObject(object)) return FTUN_E_INVALID;
  for (item = object->child; item != NULL; item = item->next) {
    if (item->string == NULL ||
        !ftun_field_allowed(item->string, allowed, allowed_count)) {
      return FTUN_E_INVALID;
    }
  }
  return FTUN_OK;
}

static ftun_status_t ftun_replace_string(char **destination, const cJSON *item,
                                         int required)
{
  char *copy;
  if (item == NULL) return required ? FTUN_E_INVALID : FTUN_OK;
  if (!cJSON_IsString(item) || item->valuestring == NULL) return FTUN_E_INVALID;
  copy = ftun_config_string_copy(item->valuestring);
  if (copy == NULL) return FTUN_E_LIMIT;
  free(*destination);
  *destination = copy;
  return FTUN_OK;
}

static ftun_status_t ftun_optional_bool(const cJSON *object, const char *name,
                                        bool *value)
{
  const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
  if (item == NULL) return FTUN_OK;
  if (!cJSON_IsBool(item)) return FTUN_E_INVALID;
  *value = cJSON_IsTrue(item) != 0;
  return FTUN_OK;
}

static ftun_status_t ftun_optional_uint(const cJSON *object, const char *name,
                                        uint32_t minimum, uint32_t maximum,
                                        uint32_t *value)
{
  const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
  double number;
  if (item == NULL) return FTUN_OK;
  if (!cJSON_IsNumber(item)) return FTUN_E_INVALID;
  number = item->valuedouble;
  if (!isfinite(number) || number < (double)minimum || number > (double)maximum ||
      (double)(uint32_t)number != number) return FTUN_E_INVALID;
  *value = (uint32_t)number;
  return FTUN_OK;
}

static ftun_status_t ftun_parse_string_list(const cJSON *item,
                                            ftun_config_string_list_t *list,
                                            int require_nonempty)
{
  const cJSON *child;
  size_t count = 0u;
  size_t index = 0u;
  if (!cJSON_IsArray(item)) return FTUN_E_INVALID;
  for (child = item->child; child != NULL; child = child->next) count++;
  if ((require_nonempty && count == 0u) || count > FTUN_CONFIG_MAX_ARRAY_ITEMS) {
    return count == 0u ? FTUN_E_INVALID : FTUN_E_LIMIT;
  }
  if (count == 0u) return FTUN_OK;
  list->items = (char **)calloc(count, sizeof(*list->items));
  if (list->items == NULL) return FTUN_E_LIMIT;
  list->count = count;
  for (child = item->child; child != NULL; child = child->next, index++) {
    if (!cJSON_IsString(child) || child->valuestring == NULL) return FTUN_E_INVALID;
    list->items[index] = ftun_config_string_copy(child->valuestring);
    if (list->items[index] == NULL) return FTUN_E_LIMIT;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_config_defaults(ftun_config_t *config)
{
#define FTUN_DEFAULT(field, value) do { \
  (field) = ftun_config_string_copy(value); \
  if ((field) == NULL) return FTUN_E_LIMIT; \
} while (0)
  config->base.state_cache = true;
  FTUN_DEFAULT(config->base.cache_file, "~/.ftun/ftun.cache");
  FTUN_DEFAULT(config->log.level, "warn");
  FTUN_DEFAULT(config->log.file, "~/.ftun/ftun.log");
  config->dns.enable = true;
  config->dns.cache = true;
  FTUN_DEFAULT(config->dns.default_server, "");
  config->dns.fake_ip.enable = true;
  config->dns.fake_ip.persist = true;
  FTUN_DEFAULT(config->dns.fake_ip.range, "198.18.0.0/15");
  FTUN_DEFAULT(config->geo.update_interval, "24h");
  FTUN_DEFAULT(config->geo.update_outbound, "DIRECT");
  FTUN_DEFAULT(config->geo.dns_server, "");
  config->sniff.tls_sni = true;
  config->sniff.http_host = true;
#undef FTUN_DEFAULT
  return FTUN_OK;
}

static ftun_status_t ftun_parse_base(const cJSON *item, ftun_config_t *config)
{
  static const char *const fields[] = {
    "ipv6", "allow-lan", "cache-file", "state-cache"
  };
  ftun_status_t status = ftun_check_fields(item, fields, 4u);
  if (status != FTUN_OK) return status;
  status = ftun_optional_bool(item, "ipv6", &config->base.ipv6);
  if (status == FTUN_OK) status = ftun_optional_bool(item, "allow-lan", &config->base.allow_lan);
  if (status == FTUN_OK) status = ftun_replace_string(&config->base.cache_file,
    cJSON_GetObjectItemCaseSensitive(item, "cache-file"), 0);
  if (status == FTUN_OK) status = ftun_optional_bool(item, "state-cache", &config->base.state_cache);
  return status;
}

static ftun_status_t ftun_parse_log(const cJSON *item, ftun_config_t *config)
{
  static const char *const fields[] = {"level", "file"};
  ftun_status_t status = ftun_check_fields(item, fields, 2u);
  if (status != FTUN_OK) return status;
  status = ftun_replace_string(&config->log.level,
    cJSON_GetObjectItemCaseSensitive(item, "level"), 0);
  if (status == FTUN_OK) status = ftun_replace_string(&config->log.file,
    cJSON_GetObjectItemCaseSensitive(item, "file"), 0);
  return status;
}

static ftun_status_t ftun_parse_fake_ip(const cJSON *item, ftun_config_t *config)
{
  static const char *const fields[] = {"enable", "range", "persist"};
  ftun_status_t status = ftun_check_fields(item, fields, 3u);
  if (status != FTUN_OK) return status;
  status = ftun_optional_bool(item, "enable", &config->dns.fake_ip.enable);
  if (status == FTUN_OK) status = ftun_replace_string(&config->dns.fake_ip.range,
    cJSON_GetObjectItemCaseSensitive(item, "range"), 0);
  if (status == FTUN_OK) status = ftun_optional_bool(item, "persist",
    &config->dns.fake_ip.persist);
  return status;
}

static ftun_status_t ftun_parse_dns_listeners(const cJSON *array,
                                               ftun_config_t *config)
{
  static const char *const fields[] = {"listen", "server"};
  const cJSON *item;
  size_t count = 0u;
  size_t index = 0u;
  if (!cJSON_IsArray(array)) return FTUN_E_INVALID;
  for (item = array->child; item != NULL; item = item->next) count++;
  if (count == 0u) return FTUN_OK;
  config->dns.listeners = (ftun_config_dns_listener_t *)calloc(
    count, sizeof(*config->dns.listeners));
  if (config->dns.listeners == NULL) return FTUN_E_LIMIT;
  config->dns.listener_count = count;
  for (item = array->child; item != NULL; item = item->next, index++) {
    ftun_status_t status = ftun_check_fields(item, fields, 2u);
    if (status != FTUN_OK) return status;
    status = ftun_replace_string(&config->dns.listeners[index].listen,
      cJSON_GetObjectItemCaseSensitive(item, "listen"), 1);
    if (status != FTUN_OK) return status;
    config->dns.listeners[index].server = ftun_config_string_copy("");
    if (config->dns.listeners[index].server == NULL) return FTUN_E_LIMIT;
    status = ftun_replace_string(&config->dns.listeners[index].server,
      cJSON_GetObjectItemCaseSensitive(item, "server"), 0);
    if (status != FTUN_OK) return status;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_parse_dns_servers(const cJSON *array,
                                             ftun_config_t *config)
{
  static const char *const fields[] = {
    "name", "type", "address", "outbound", "fake-ip"
  };
  const cJSON *item;
  size_t count = 0u;
  size_t index = 0u;
  if (!cJSON_IsArray(array)) return FTUN_E_INVALID;
  for (item = array->child; item != NULL; item = item->next) count++;
  if (count == 0u) return FTUN_OK;
  config->dns.servers = (ftun_config_dns_server_t *)calloc(
    count, sizeof(*config->dns.servers));
  if (config->dns.servers == NULL) return FTUN_E_LIMIT;
  config->dns.server_count = count;
  for (item = array->child; item != NULL; item = item->next, index++) {
    ftun_config_dns_server_t *server = &config->dns.servers[index];
    const cJSON *addresses;
    ftun_status_t status = ftun_check_fields(item, fields, 5u);
    if (status != FTUN_OK) return status;
    status = ftun_replace_string(&server->name,
      cJSON_GetObjectItemCaseSensitive(item, "name"), 1);
    if (status == FTUN_OK) status = ftun_replace_string(&server->type,
      cJSON_GetObjectItemCaseSensitive(item, "type"), 1);
    if (status != FTUN_OK) return status;
    if (strcmp(server->type, "udp") != 0 && strcmp(server->type, "tcp") != 0) {
      return FTUN_E_UNSUPPORTED;
    }
    addresses = cJSON_GetObjectItemCaseSensitive(item, "address");
    if (addresses == NULL) return FTUN_E_INVALID;
    status = ftun_parse_string_list(addresses, &server->addresses, 1);
    if (status != FTUN_OK) return status;
    server->outbound = ftun_config_string_copy("DIRECT");
    if (server->outbound == NULL) return FTUN_E_LIMIT;
    status = ftun_replace_string(&server->outbound,
      cJSON_GetObjectItemCaseSensitive(item, "outbound"), 0);
    if (status == FTUN_OK) status = ftun_optional_bool(item, "fake-ip", &server->fake_ip);
    if (status != FTUN_OK) return status;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_parse_dns(const cJSON *item, ftun_config_t *config)
{
  static const char *const fields[] = {
    "enable", "cache", "bootstrap", "default-server", "fake-ip",
    "listeners", "servers"
  };
  const cJSON *child;
  ftun_status_t status = ftun_check_fields(item, fields, 7u);
  if (status != FTUN_OK) return status;
  status = ftun_optional_bool(item, "enable", &config->dns.enable);
  if (status == FTUN_OK) status = ftun_optional_bool(item, "cache", &config->dns.cache);
  child = cJSON_GetObjectItemCaseSensitive(item, "bootstrap");
  if (status == FTUN_OK && child != NULL) {
    status = ftun_parse_string_list(child, &config->dns.bootstrap, 0);
  }
  if (status == FTUN_OK) status = ftun_replace_string(&config->dns.default_server,
    cJSON_GetObjectItemCaseSensitive(item, "default-server"), 0);
  child = cJSON_GetObjectItemCaseSensitive(item, "fake-ip");
  if (status == FTUN_OK && child != NULL) status = ftun_parse_fake_ip(child, config);
  child = cJSON_GetObjectItemCaseSensitive(item, "listeners");
  if (status == FTUN_OK && child != NULL) status = ftun_parse_dns_listeners(child, config);
  child = cJSON_GetObjectItemCaseSensitive(item, "servers");
  if (status == FTUN_OK && child != NULL) status = ftun_parse_dns_servers(child, config);
  return status;
}

static ftun_status_t ftun_parse_geo_data(const cJSON *item,
                                         ftun_config_geo_data_t *data)
{
  static const char *const fields[] = {"path", "url"};
  ftun_status_t status = ftun_check_fields(item, fields, 2u);
  if (status != FTUN_OK) return status;
  data->present = true;
  status = ftun_replace_string(&data->path,
    cJSON_GetObjectItemCaseSensitive(item, "path"), 0);
  if (status == FTUN_OK) status = ftun_replace_string(&data->url,
    cJSON_GetObjectItemCaseSensitive(item, "url"), 0);
  return status;
}

static ftun_status_t ftun_parse_geo(const cJSON *item, ftun_config_t *config)
{
  static const char *const fields[] = {
    "auto-update", "update-interval", "update-outbound", "dns-server",
    "geoip", "geosite"
  };
  const cJSON *child;
  ftun_status_t status = ftun_check_fields(item, fields, 6u);
  if (status != FTUN_OK) return status;
  config->geo.present = true;
  status = ftun_optional_bool(item, "auto-update", &config->geo.auto_update);
  if (status == FTUN_OK) status = ftun_replace_string(&config->geo.update_interval,
    cJSON_GetObjectItemCaseSensitive(item, "update-interval"), 0);
  if (status == FTUN_OK) status = ftun_replace_string(&config->geo.update_outbound,
    cJSON_GetObjectItemCaseSensitive(item, "update-outbound"), 0);
  if (status == FTUN_OK) status = ftun_replace_string(&config->geo.dns_server,
    cJSON_GetObjectItemCaseSensitive(item, "dns-server"), 0);
  child = cJSON_GetObjectItemCaseSensitive(item, "geoip");
  if (status == FTUN_OK && child != NULL) status = ftun_parse_geo_data(child, &config->geo.geoip);
  child = cJSON_GetObjectItemCaseSensitive(item, "geosite");
  if (status == FTUN_OK && child != NULL) status = ftun_parse_geo_data(child, &config->geo.geosite);
  return status;
}

static ftun_status_t ftun_parse_sniff(const cJSON *item, ftun_config_t *config)
{
  static const char *const fields[] = {"enable", "tls-sni", "http-host"};
  ftun_status_t status = ftun_check_fields(item, fields, 3u);
  if (status != FTUN_OK) return status;
  status = ftun_optional_bool(item, "enable", &config->sniff.enable);
  if (status == FTUN_OK) status = ftun_optional_bool(item, "tls-sni", &config->sniff.tls_sni);
  if (status == FTUN_OK) status = ftun_optional_bool(item, "http-host", &config->sniff.http_host);
  return status;
}

static ftun_status_t ftun_parse_users(const cJSON *item,
                                      ftun_config_inbound_t *inbound)
{
  const cJSON *user;
  size_t count = 0u;
  size_t index = 0u;
  if (!cJSON_IsObject(item)) return FTUN_E_INVALID;
  for (user = item->child; user != NULL; user = user->next) count++;
  if (count == 0u) return FTUN_OK;
  inbound->users = (ftun_config_user_t *)calloc(count, sizeof(*inbound->users));
  if (inbound->users == NULL) return FTUN_E_LIMIT;
  inbound->user_count = count;
  for (user = item->child; user != NULL; user = user->next, index++) {
    if (user->string == NULL || !cJSON_IsString(user) || user->valuestring == NULL ||
        strlen(user->string) == 0u || strlen(user->string) > 255u ||
        strlen(user->valuestring) == 0u || strlen(user->valuestring) > 255u) {
      return FTUN_E_INVALID;
    }
    inbound->users[index].name = ftun_config_string_copy(user->string);
    inbound->users[index].password = ftun_config_string_copy(user->valuestring);
    if (inbound->users[index].name == NULL || inbound->users[index].password == NULL) {
      return FTUN_E_LIMIT;
    }
  }
  return FTUN_OK;
}

static ftun_status_t ftun_parse_tun(const cJSON *item,
                                    ftun_config_inbound_t *inbound)
{
  static const char *const fields[] = {
    "name", "type", "outbound", "interface", "stack", "ipv4", "tcp", "udp",
    "auto-route", "strict-route", "dns-hijack"
  };
  static const char *const interface_fields[] = {"name", "mtu"};
  static const char *const ipv4_fields[] = {"address"};
  const cJSON *interface_object;
  const cJSON *ipv4_object;
  uint32_t mtu = 1500u;
  ftun_status_t status = ftun_check_fields(item, fields, 11u);
  if (status != FTUN_OK) return status;
  inbound->kind = FTUN_CONFIG_INBOUND_TUN;
  inbound->tcp = true;
  inbound->udp = true;
  inbound->dns_hijack = true;
  inbound->mtu = 1500u;
  inbound->stack = ftun_config_string_copy("lwip");
  if (inbound->stack == NULL) return FTUN_E_LIMIT;
  status = ftun_replace_string(&inbound->name,
    cJSON_GetObjectItemCaseSensitive(item, "name"), 1);
  if (status == FTUN_OK) status = ftun_replace_string(&inbound->outbound,
    cJSON_GetObjectItemCaseSensitive(item, "outbound"), 0);
  if (status == FTUN_OK) status = ftun_replace_string(&inbound->stack,
    cJSON_GetObjectItemCaseSensitive(item, "stack"), 0);
  if (status != FTUN_OK) return status;
  if (strcmp(inbound->stack, "lwip") != 0) return FTUN_E_UNSUPPORTED;
  interface_object = cJSON_GetObjectItemCaseSensitive(item, "interface");
  ipv4_object = cJSON_GetObjectItemCaseSensitive(item, "ipv4");
  if (interface_object == NULL || ipv4_object == NULL) return FTUN_E_INVALID;
  status = ftun_check_fields(interface_object, interface_fields, 2u);
  if (status == FTUN_OK) status = ftun_replace_string(&inbound->interface_name,
    cJSON_GetObjectItemCaseSensitive(interface_object, "name"), 1);
  if (status == FTUN_OK) status = ftun_optional_uint(interface_object, "mtu", 1u,
    UINT32_MAX, &mtu);
  inbound->mtu = mtu;
  if (status == FTUN_OK) status = ftun_check_fields(ipv4_object, ipv4_fields, 1u);
  if (status == FTUN_OK) status = ftun_replace_string(&inbound->ipv4_address,
    cJSON_GetObjectItemCaseSensitive(ipv4_object, "address"), 1);
  if (status == FTUN_OK) status = ftun_optional_bool(item, "tcp", &inbound->tcp);
  if (status == FTUN_OK) status = ftun_optional_bool(item, "udp", &inbound->udp);
  if (status == FTUN_OK) status = ftun_optional_bool(item, "auto-route", &inbound->auto_route);
  if (status == FTUN_OK) status = ftun_optional_bool(item, "strict-route", &inbound->strict_route);
  if (status == FTUN_OK) status = ftun_optional_bool(item, "dns-hijack", &inbound->dns_hijack);
  return status;
}

static ftun_status_t ftun_parse_proxy_inbound(const cJSON *item,
                                               ftun_config_inbound_t *inbound,
                                               ftun_config_inbound_kind_t kind)
{
  static const char *const fields[] = {
    "name", "type", "outbound", "listen", "users", "udp"
  };
  const cJSON *users;
  ftun_status_t status = ftun_check_fields(item, fields, 6u);
  if (status != FTUN_OK) return status;
  inbound->kind = kind;
  inbound->udp = true;
  status = ftun_replace_string(&inbound->name,
    cJSON_GetObjectItemCaseSensitive(item, "name"), 1);
  if (status == FTUN_OK) status = ftun_replace_string(&inbound->outbound,
    cJSON_GetObjectItemCaseSensitive(item, "outbound"), 0);
  if (status == FTUN_OK) status = ftun_replace_string(&inbound->listen,
    cJSON_GetObjectItemCaseSensitive(item, "listen"), 1);
  users = cJSON_GetObjectItemCaseSensitive(item, "users");
  if (status == FTUN_OK && users != NULL) status = ftun_parse_users(users, inbound);
  if (status == FTUN_OK) status = ftun_optional_bool(item, "udp", &inbound->udp);
  return status;
}

static ftun_status_t ftun_parse_inbounds(const cJSON *array, ftun_config_t *config)
{
  const cJSON *item;
  size_t count = 0u;
  size_t index = 0u;
  if (!cJSON_IsArray(array)) return FTUN_E_INVALID;
  for (item = array->child; item != NULL; item = item->next) count++;
  if (count == 0u) return FTUN_OK;
  config->inbounds = (ftun_config_inbound_t *)calloc(count, sizeof(*config->inbounds));
  if (config->inbounds == NULL) return FTUN_E_LIMIT;
  config->inbound_count = count;
  for (item = array->child; item != NULL; item = item->next, index++) {
    const cJSON *type = cJSON_GetObjectItemCaseSensitive(item, "type");
    ftun_status_t status;
    if (!cJSON_IsObject(item) || !cJSON_IsString(type) || type->valuestring == NULL) {
      return FTUN_E_INVALID;
    }
    config->inbounds[index].outbound = ftun_config_string_copy("");
    if (config->inbounds[index].outbound == NULL) return FTUN_E_LIMIT;
    if (strcmp(type->valuestring, "mixed") == 0) {
      status = ftun_parse_proxy_inbound(item, &config->inbounds[index],
                                        FTUN_CONFIG_INBOUND_MIXED);
    } else if (strcmp(type->valuestring, "socks5") == 0) {
      status = ftun_parse_proxy_inbound(item, &config->inbounds[index],
                                        FTUN_CONFIG_INBOUND_SOCKS5);
    } else if (strcmp(type->valuestring, "tun") == 0) {
      status = ftun_parse_tun(item, &config->inbounds[index]);
    } else {
      return FTUN_E_UNSUPPORTED;
    }
    if (status != FTUN_OK) return status;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_parse_socks_outbound(const cJSON *item,
                                                ftun_config_outbound_t *outbound)
{
  static const char *const fields[] = {
    "name", "type", "dns-server", "server", "username", "password", "udp"
  };
  const cJSON *username;
  const cJSON *password;
  ftun_status_t status = ftun_check_fields(item, fields, 7u);
  if (status != FTUN_OK) return status;
  outbound->kind = FTUN_CONFIG_OUTBOUND_SOCKS5;
  outbound->udp = true;
  status = ftun_replace_string(&outbound->name,
    cJSON_GetObjectItemCaseSensitive(item, "name"), 1);
  if (status == FTUN_OK) status = ftun_replace_string(&outbound->dns_server,
    cJSON_GetObjectItemCaseSensitive(item, "dns-server"), 0);
  if (status == FTUN_OK) status = ftun_replace_string(&outbound->server,
    cJSON_GetObjectItemCaseSensitive(item, "server"), 1);
  username = cJSON_GetObjectItemCaseSensitive(item, "username");
  password = cJSON_GetObjectItemCaseSensitive(item, "password");
  if (status == FTUN_OK && ((username == NULL) != (password == NULL))) return FTUN_E_INVALID;
  if (status == FTUN_OK) status = ftun_replace_string(&outbound->username, username, 0);
  if (status == FTUN_OK) status = ftun_replace_string(&outbound->password, password, 0);
  if (status == FTUN_OK) status = ftun_optional_bool(item, "udp", &outbound->udp);
  return status;
}

static ftun_status_t ftun_parse_group_outbound(const cJSON *item,
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
  ftun_status_t status = ftun_check_fields(item, url_test ? url_fields : select_fields,
                                           url_test ? 11u : 5u);
  if (status != FTUN_OK) return status;
  outbound->kind = url_test ? FTUN_CONFIG_OUTBOUND_URL_TEST : FTUN_CONFIG_OUTBOUND_SELECT;
  status = ftun_replace_string(&outbound->name,
    cJSON_GetObjectItemCaseSensitive(item, "name"), 1);
  if (status == FTUN_OK) status = ftun_replace_string(&outbound->dns_server,
    cJSON_GetObjectItemCaseSensitive(item, "dns-server"), 0);
  members = cJSON_GetObjectItemCaseSensitive(item, "outbounds");
  if (status == FTUN_OK && members == NULL) status = FTUN_E_INVALID;
  if (status == FTUN_OK) status = ftun_parse_string_list(members, &outbound->members, 1);
  if (status == FTUN_OK) status = ftun_replace_string(&outbound->default_member,
    cJSON_GetObjectItemCaseSensitive(item, "default"), 1);
  if (status != FTUN_OK || !url_test) return status;
  outbound->interval = ftun_config_string_copy("5m");
  outbound->timeout = ftun_config_string_copy("5s");
  outbound->tolerance_ms = 50u;
  outbound->lazy = true;
  outbound->expected_status = 204u;
  if (outbound->interval == NULL || outbound->timeout == NULL) return FTUN_E_LIMIT;
  status = ftun_replace_string(&outbound->url,
    cJSON_GetObjectItemCaseSensitive(item, "url"), 1);
  if (status == FTUN_OK) status = ftun_replace_string(&outbound->interval,
    cJSON_GetObjectItemCaseSensitive(item, "interval"), 0);
  if (status == FTUN_OK) status = ftun_replace_string(&outbound->timeout,
    cJSON_GetObjectItemCaseSensitive(item, "timeout"), 0);
  if (status == FTUN_OK) status = ftun_optional_uint(item, "tolerance", 0u,
    UINT32_MAX, &outbound->tolerance_ms);
  if (status == FTUN_OK) status = ftun_optional_bool(item, "lazy", &outbound->lazy);
  if (status == FTUN_OK) status = ftun_optional_uint(item, "expected-status", 100u,
    599u, &expected_status);
  outbound->expected_status = (uint16_t)expected_status;
  return status;
}

static ftun_status_t ftun_parse_outbounds(const cJSON *array, ftun_config_t *config)
{
  const cJSON *item;
  size_t count = 0u;
  size_t index = 0u;
  if (!cJSON_IsArray(array)) return FTUN_E_INVALID;
  for (item = array->child; item != NULL; item = item->next) count++;
  if (count == 0u) return FTUN_OK;
  config->outbounds = (ftun_config_outbound_t *)calloc(count, sizeof(*config->outbounds));
  if (config->outbounds == NULL) return FTUN_E_LIMIT;
  config->outbound_count = count;
  for (item = array->child; item != NULL; item = item->next, index++) {
    const cJSON *type = cJSON_GetObjectItemCaseSensitive(item, "type");
    ftun_status_t status;
    if (!cJSON_IsObject(item) || !cJSON_IsString(type) || type->valuestring == NULL) {
      return FTUN_E_INVALID;
    }
    config->outbounds[index].dns_server = ftun_config_string_copy("");
    if (config->outbounds[index].dns_server == NULL) return FTUN_E_LIMIT;
    if (strcmp(type->valuestring, "socks5") == 0) {
      status = ftun_parse_socks_outbound(item, &config->outbounds[index]);
    } else if (strcmp(type->valuestring, "select") == 0) {
      status = ftun_parse_group_outbound(item, &config->outbounds[index], 0);
    } else if (strcmp(type->valuestring, "url-test") == 0) {
      status = ftun_parse_group_outbound(item, &config->outbounds[index], 1);
    } else {
      return FTUN_E_UNSUPPORTED;
    }
    if (status != FTUN_OK) return status;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_parse_root(const cJSON *root, ftun_config_t *config)
{
  static const char *const fields[] = {
    "$schema", "base", "log", "dns", "geo", "sniff", "inbounds", "outbounds",
    "rules"
  };
  const cJSON *item;
  ftun_status_t status = FTUN_OK;
  if (cJSON_GetObjectItemCaseSensitive(root, "api") != NULL ||
      cJSON_GetObjectItemCaseSensitive(root, "plugins") != NULL) {
    return FTUN_E_UNSUPPORTED;
  }
  status = ftun_check_fields(root, fields, 9u);
  if (status != FTUN_OK) return status;
  item = cJSON_GetObjectItemCaseSensitive(root, "$schema");
  if (item != NULL && (!cJSON_IsString(item) || item->valuestring == NULL ||
                       item->valuestring[0] == '\0')) return FTUN_E_INVALID;
  item = cJSON_GetObjectItemCaseSensitive(root, "base");
  if (item != NULL) status = ftun_parse_base(item, config);
  item = cJSON_GetObjectItemCaseSensitive(root, "log");
  if (status == FTUN_OK && item != NULL) status = ftun_parse_log(item, config);
  item = cJSON_GetObjectItemCaseSensitive(root, "dns");
  if (status == FTUN_OK && item != NULL) status = ftun_parse_dns(item, config);
  item = cJSON_GetObjectItemCaseSensitive(root, "geo");
  if (status == FTUN_OK && item != NULL) status = ftun_parse_geo(item, config);
  item = cJSON_GetObjectItemCaseSensitive(root, "sniff");
  if (status == FTUN_OK && item != NULL) status = ftun_parse_sniff(item, config);
  item = cJSON_GetObjectItemCaseSensitive(root, "inbounds");
  if (status == FTUN_OK && item != NULL) status = ftun_parse_inbounds(item, config);
  item = cJSON_GetObjectItemCaseSensitive(root, "outbounds");
  if (status == FTUN_OK && item != NULL) status = ftun_parse_outbounds(item, config);
  item = cJSON_GetObjectItemCaseSensitive(root, "rules");
  if (status == FTUN_OK && item != NULL) status = ftun_parse_string_list(item, &config->rules, 0);
  return status;
}

static void ftun_string_list_clear(ftun_config_string_list_t *list)
{
  size_t index;
  if (list == NULL) return;
  for (index = 0u; index < list->count; index++) free(list->items[index]);
  free(list->items);
  list->items = NULL;
  list->count = 0u;
}

ftun_status_t ftun_config_destroy(ftun_config_t **config)
{
  ftun_config_t *owned;
  size_t index;
  if (config == NULL) return FTUN_E_INVALID;
  owned = *config;
  if (owned == NULL) return FTUN_OK;
  if (owned->reference_count == 0u) return FTUN_E_STATE_CORRUPT;
  owned->reference_count--;
  *config = NULL;
  if (owned->reference_count != 0u) return FTUN_OK;
  free(owned->source_path);
  free(owned->base_directory);
  (void)ftun_feature_plan_destroy(&owned->plan);
  free(owned->base.cache_file);
  free(owned->log.level);
  free(owned->log.file);
  ftun_string_list_clear(&owned->dns.bootstrap);
  free(owned->dns.default_server);
  free(owned->dns.fake_ip.range);
  for (index = 0u; index < owned->dns.listener_count; index++) {
    free(owned->dns.listeners[index].listen);
    free(owned->dns.listeners[index].server);
  }
  free(owned->dns.listeners);
  for (index = 0u; index < owned->dns.server_count; index++) {
    free(owned->dns.servers[index].name);
    free(owned->dns.servers[index].type);
    ftun_string_list_clear(&owned->dns.servers[index].addresses);
    free(owned->dns.servers[index].outbound);
  }
  free(owned->dns.servers);
  free(owned->geo.update_interval);
  free(owned->geo.update_outbound);
  free(owned->geo.dns_server);
  free(owned->geo.geoip.path);
  free(owned->geo.geoip.url);
  free(owned->geo.geosite.path);
  free(owned->geo.geosite.url);
  for (index = 0u; index < owned->inbound_count; index++) {
    ftun_config_inbound_t *inbound = &owned->inbounds[index];
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
  free(owned->inbounds);
  for (index = 0u; index < owned->outbound_count; index++) {
    ftun_config_outbound_t *outbound = &owned->outbounds[index];
    free(outbound->name);
    free(outbound->dns_server);
    free(outbound->server);
    free(outbound->username);
    free(outbound->password);
    ftun_string_list_clear(&outbound->members);
    free(outbound->default_member);
    free(outbound->url);
    free(outbound->interval);
    free(outbound->timeout);
  }
  free(owned->outbounds);
  ftun_string_list_clear(&owned->rules);
  free(owned);
  return FTUN_OK;
}

ftun_status_t ftun_config_retain(ftun_config_t *config)
{
  if (config == NULL) return FTUN_E_INVALID;
  if (config->reference_count == 0u) return FTUN_E_STATE_CORRUPT;
  if (config->reference_count == SIZE_MAX) return FTUN_E_LIMIT;
  config->reference_count++;
  return FTUN_OK;
}

/* TASK-CONFIG-002 / TEST-CONFIG-002，目标 0.2.0：有界 JSON 到拥有型配置。 */
ftun_status_t ftun_config_parse(ftun_bytes_t json, ftun_config_t **out)
{
  char *input;
  cJSON *root;
  ftun_config_t *config;
  size_t nodes = 0u;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (out == NULL) return FTUN_E_INVALID;
  status = ftun_json_preflight(json);
  if (status != FTUN_OK) return status;
  input = (char *)malloc(json.length + 1u);
  if (input == NULL) return FTUN_E_LIMIT;
  memcpy(input, json.data, json.length);
  input[json.length] = '\0';
  root = cJSON_ParseWithLengthOpts(input, json.length + 1u, NULL, 1);
  free(input);
  if (root == NULL || !cJSON_IsObject(root)) {
    cJSON_Delete(root);
    return FTUN_E_INVALID;
  }
  status = ftun_json_tree_check(root, 1u, &nodes);
  if (status != FTUN_OK) {
    cJSON_Delete(root);
    return status;
  }
  config = (ftun_config_t *)calloc(1u, sizeof(*config));
  if (config == NULL) {
    cJSON_Delete(root);
    return FTUN_E_LIMIT;
  }
  config->reference_count = 1u;
  status = ftun_config_defaults(config);
  if (status == FTUN_OK) status = ftun_parse_root(root, config);
  cJSON_Delete(root);
  if (status != FTUN_OK) {
    (void)ftun_config_destroy(&config);
    return status;
  }
  *out = config;
  return FTUN_OK;
}
