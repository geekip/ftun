#include "app/config/parser.h"
#include "core/config/fields.h"
#include "dns/config/parse.h"
#include "proxy/config/parse.h"
#include "libs/tun/config/parse.h"
#include "app/config/compile.h"
#include "app/config/model.h"
#include "app/config/config.h"
#include <cJSON.h>
#include <stdlib.h>
#include <string.h>

static int ftun_rule_type_equal(const char *rule, size_t length,
                                const char *type);

static size_t ftun_name_space_bytes(const unsigned char *text, size_t length)
{
  if (text == NULL || length == 0u) return 0u;
  if (text[0] == 0x20u) return 1u;
  if (length >= 2u && text[0] == 0xc2u && text[1] == 0xa0u) return 2u;
  if (length >= 3u && text[0] == 0xe1u && text[1] == 0x9au &&
      text[2] == 0x80u) return 3u;
  if (length >= 3u && text[0] == 0xe2u && text[1] == 0x80u &&
      ((text[2] >= 0x80u && text[2] <= 0x8au) || text[2] == 0xa8u ||
       text[2] == 0xa9u || text[2] == 0xafu)) return 3u;
  if (length >= 3u && text[0] == 0xe2u && text[1] == 0x81u &&
      text[2] == 0x9fu) return 3u;
  if (length >= 3u && text[0] == 0xe3u && text[1] == 0x80u &&
      text[2] == 0x80u) return 3u;
  return 0u;
}

static void ftun_trim_name(char *value)
{
  unsigned char *bytes = (unsigned char *)value;
  size_t length;
  size_t start = 0u;
  size_t end;
  if (value == NULL) return;
  length = strlen(value);
  while (start < length) {
    size_t space = ftun_name_space_bytes(bytes + start, length - start);
    if (space == 0u) break;
    start += space;
  }
  end = length;
  while (end > start) {
    size_t cursor = end - 1u;
    size_t space;
    while (cursor > start && (bytes[cursor] & 0xc0u) == 0x80u) cursor--;
    space = ftun_name_space_bytes(bytes + cursor, end - cursor);
    if (space == 0u || cursor + space != end) break;
    end = cursor;
  }
  if (start != 0u && end != start) memmove(value, value + start, end - start);
  value[end - start] = '\0';
}

static void ftun_trim_rule_names(char *rule)
{
  char *first;
  char *second;
  if (rule == NULL || (first = strchr(rule, ',')) == NULL) return;
  second = strchr(first + 1u, ',');
  if (second == NULL) {
    ftun_trim_name(first + 1u);
    return;
  }
  ftun_trim_name(second + 1u);
  if (ftun_rule_type_equal(rule, (size_t)(first - rule), "FRS-IP") ||
      ftun_rule_type_equal(rule, (size_t)(first - rule), "FRS-DOMAIN")) {
    unsigned char *operand = (unsigned char *)(first + 1u);
    size_t length = (size_t)(second - first - 1u);
    size_t start = 0u;
    size_t end = length;
    while (start < length) {
      size_t space = ftun_name_space_bytes(operand + start, length - start);
      if (space == 0u) break;
      start += space;
    }
    while (end > start) {
      size_t cursor = end - 1u;
      size_t space;
      while (cursor > start && (operand[cursor] & 0xc0u) == 0x80u) cursor--;
      space = ftun_name_space_bytes(operand + cursor, end - cursor);
      if (space == 0u || cursor + space != end) break;
      end = cursor;
    }
    if (start != 0u && end != start) {
      memmove(first + 1u, operand + start, end - start);
    }
    memmove(first + 1u + (end - start), second, strlen(second) + 1u);
  }
}

void ftun_config_timeouts_default(ftun_config_t *config)
{
  config->base.proxy.timeouts.handshake_ms = 10000u;
  config->base.proxy.timeouts.connect_ms = 10000u;
  config->base.proxy.timeouts.reply_ms = 5000u;
  config->base.proxy.timeouts.write_progress_ms = 120000u;
  config->base.proxy.timeouts.tcp_idle_ms = 0u;
  config->base.proxy.timeouts.udp_idle_ms = 120000u;
  config->base.proxy.timeouts.keepalive.enabled = true;
  config->base.proxy.timeouts.keepalive.idle_s = 30u;
  config->base.proxy.timeouts.keepalive.interval_s = 15u;
  config->base.proxy.timeouts.keepalive.count = 4u;
}

static ftun_status_t ftun_config_defaults(ftun_config_t *config)
{
  ftun_status_t status;
#define FTUN_DEFAULT(field, value) do { \
  (field) = ftun_config_string_copy(config, value); \
  if ((field) == NULL) return FTUN_E_LIMIT; \
} while (0)
  config->base.proxy.state_cache = true;
  config->base.proxy.capacity.tcp_flows = FTUN_CONFIG_CAPACITY_DEFAULT;
  config->base.proxy.capacity.udp_flows = FTUN_CONFIG_CAPACITY_DEFAULT;
  config->base.proxy.capacity.udp_associations = FTUN_CONFIG_CAPACITY_DEFAULT;
  ftun_config_timeouts_default(config);
  config->base.proxy.routing_mark = FTUN_CONFIG_ROUTING_MARK_DEFAULT;
  config->base.watchdog_ms = FTUN_CONFIG_WATCHDOG_DEFAULT_MS;
  config->base.reload_retain_count = FTUN_CONFIG_RELOAD_RETAIN_DEFAULT;
  FTUN_DEFAULT(config->base.proxy.cache_file, "~/.ftun/ftun.cache");
  FTUN_DEFAULT(config->log.level, "warn");
  FTUN_DEFAULT(config->log.file, "~/.ftun/ftun.log");
  config->log.max_size = FTUN_CONFIG_LOG_MAX_SIZE_DEFAULT;
  config->log.max_files = FTUN_CONFIG_LOG_MAX_FILES_DEFAULT;
  status = ftun_config_defaults_dns(config, &config->dns);
  if (status != FTUN_OK) return status;
  status = ftun_config_defaults_frs(config, &config->frs);
  if (status != FTUN_OK) return status;
  config->sniff.tls_sni = true;
  config->sniff.http_host = true;
  ftun_config_defaults_tun(&config->tun);
#undef FTUN_DEFAULT
  return FTUN_OK;
}

static ftun_status_t ftun_parse_timeouts(const cJSON *item, ftun_config_t *config)
{
  static const char *const fields[] = {
    "handshake", "connect", "reply", "tcp-keepalive", "write-progress",
    "tcp-idle", "udp-idle"
  };
  static const char *const keepalive_fields[] = {"idle", "interval", "count"};
  const cJSON *keepalive;
  uint32_t milliseconds;
  ftun_status_t status = ftun_config_check_fields(item, fields, 7u);
  if (status != FTUN_OK) return status;
  if (status == FTUN_OK) status = ftun_config_optional_duration(item, "handshake", false,
    &config->base.proxy.timeouts.handshake_ms);
  if (status == FTUN_OK) status = ftun_config_optional_duration(item, "connect", false,
    &config->base.proxy.timeouts.connect_ms);
  if (status == FTUN_OK) status = ftun_config_optional_duration(item, "reply", false,
    &config->base.proxy.timeouts.reply_ms);
  if (status == FTUN_OK) status = ftun_config_optional_duration(item, "write-progress", false,
    &config->base.proxy.timeouts.write_progress_ms);
  if (status == FTUN_OK) status = ftun_config_optional_duration(item, "tcp-idle", true,
    &config->base.proxy.timeouts.tcp_idle_ms);
  if (status == FTUN_OK) status = ftun_config_optional_duration(item, "udp-idle", false,
    &config->base.proxy.timeouts.udp_idle_ms);
  keepalive = cJSON_GetObjectItemCaseSensitive(item, "tcp-keepalive");
  if (status != FTUN_OK || keepalive == NULL) return status;
  if (cJSON_IsFalse(keepalive)) {
    config->base.proxy.timeouts.keepalive.enabled = false;
    return FTUN_OK;
  }
  status = ftun_config_check_fields(keepalive, keepalive_fields, 3u);
  if (status != FTUN_OK) return status;
  config->base.proxy.timeouts.keepalive.enabled = true;
  milliseconds = config->base.proxy.timeouts.keepalive.idle_s * 1000u;
  status = ftun_config_optional_duration(keepalive, "idle", false, &milliseconds);
  if (status == FTUN_OK) {
    if (milliseconds % 1000u != 0u) return FTUN_E_INVALID;
    config->base.proxy.timeouts.keepalive.idle_s = milliseconds / 1000u;
    milliseconds = config->base.proxy.timeouts.keepalive.interval_s * 1000u;
    status = ftun_config_optional_duration(keepalive, "interval", false, &milliseconds);
  }
  if (status == FTUN_OK) {
    if (milliseconds % 1000u != 0u) return FTUN_E_INVALID;
    config->base.proxy.timeouts.keepalive.interval_s = milliseconds / 1000u;
    status = ftun_config_optional_uint(keepalive, "count", 1u, 1000u,
                                &config->base.proxy.timeouts.keepalive.count);
  }
  return status;
}

static ftun_status_t ftun_parse_base(const cJSON *item, ftun_config_t *config)
{
  static const char *const fields[] = {
    "ipv6", "allow-lan", "cache-file", "state-cache", "capacity", "timeouts",
    "routing-mark", "watchdog", "reload-retain"
  };
  const cJSON *capacity;
  const cJSON *timeouts;
  ftun_status_t status = ftun_config_check_fields(item, fields, 9u);
  if (status != FTUN_OK) return status;
  status = ftun_config_optional_bool(item, "ipv6", &config->base.proxy.ipv6);
  if (status == FTUN_OK) status = ftun_config_optional_bool(item, "allow-lan", &config->base.proxy.allow_lan);
  if (status == FTUN_OK) status = ftun_config_replace_string(config, &config->base.proxy.cache_file,
    cJSON_GetObjectItemCaseSensitive(item, "cache-file"), 0);
  if (status == FTUN_OK) status = ftun_config_optional_bool(item, "state-cache", &config->base.proxy.state_cache);
  capacity = cJSON_GetObjectItemCaseSensitive(item, "capacity");
  if (status == FTUN_OK && capacity != NULL) {
    static const char *const capacity_fields[] = {
      "tcp-flows", "udp-flows", "udp-associations"
    };
    status = ftun_config_check_fields(capacity, capacity_fields, 3u);
    if (status == FTUN_OK) status = ftun_config_optional_uint(
      capacity, "tcp-flows", FTUN_CONFIG_CAPACITY_MINIMUM,
      FTUN_CONFIG_CAPACITY_MAXIMUM, &config->base.proxy.capacity.tcp_flows);
    if (status == FTUN_OK) status = ftun_config_optional_uint(
      capacity, "udp-flows", FTUN_CONFIG_CAPACITY_MINIMUM,
      FTUN_CONFIG_CAPACITY_MAXIMUM, &config->base.proxy.capacity.udp_flows);
    if (status == FTUN_OK) status = ftun_config_optional_uint(
      capacity, "udp-associations", FTUN_CONFIG_CAPACITY_MINIMUM,
      FTUN_CONFIG_CAPACITY_MAXIMUM,
      &config->base.proxy.capacity.udp_associations);
  }
  if (status == FTUN_OK) status = ftun_config_optional_uint(
    item, "routing-mark", 1u, UINT32_MAX, &config->base.proxy.routing_mark);
  if (status == FTUN_OK) status = ftun_config_optional_duration(
    item, "watchdog", true, &config->base.watchdog_ms);
  {
    const cJSON *retain = cJSON_GetObjectItemCaseSensitive(item, "reload-retain");
    static const char *const retain_fields[] = {"count"};
    if (status == FTUN_OK && retain != NULL) {
      status = ftun_config_check_fields(retain, retain_fields, 1u);
      if (status == FTUN_OK) status = ftun_config_optional_uint(
        retain, "count", 1u, FTUN_CONFIG_RELOAD_RETAIN_MAXIMUM,
        &config->base.reload_retain_count);
    }
  }
  timeouts = cJSON_GetObjectItemCaseSensitive(item, "timeouts");
  if (status == FTUN_OK && timeouts != NULL) status = ftun_parse_timeouts(timeouts, config);
  return status;
}

static ftun_status_t ftun_parse_log(const cJSON *item, ftun_config_t *config)
{
  static const char *const fields[] = {"level", "file", "max-size", "max-files"};
  ftun_status_t status = ftun_config_check_fields(item, fields, 4u);
  if (status != FTUN_OK) return status;
  status = ftun_config_replace_string(config, &config->log.level,
    cJSON_GetObjectItemCaseSensitive(item, "level"), 0);
  if (status == FTUN_OK) status = ftun_config_replace_string(config, &config->log.file,
    cJSON_GetObjectItemCaseSensitive(item, "file"), 0);
  if (status == FTUN_OK) status = ftun_config_optional_uint(item, "max-size", 0u, UINT32_MAX,
                                                    &config->log.max_size);
  if (status == FTUN_OK) status = ftun_config_optional_uint(item, "max-files", 1u,
    FTUN_CONFIG_LOG_MAX_FILES_MAXIMUM, &config->log.max_files);
  return status;
}

static int ftun_rule_type_equal(const char *rule, size_t length,
                                const char *type)
{
  size_t index;
  size_t type_length = strlen(type);
  if (length != type_length) return 0;
  for (index = 0u; index < length; index++) {
    unsigned char left = (unsigned char)rule[index];
    unsigned char right = (unsigned char)type[index];
    if (left >= 'A' && left <= 'Z') left = (unsigned char)(left + ('a' - 'A'));
    if (right >= 'A' && right <= 'Z') right = (unsigned char)(right + ('a' - 'A'));
    if (left != right) return 0;
  }
  return 1;
}

static int ftun_root_has_frs_rule(const cJSON *root)
{
  const cJSON *rules = cJSON_GetObjectItemCaseSensitive(root, "rules");
  const cJSON *item;
  if (!cJSON_IsArray(rules)) return 0;
  for (item = rules->child; item != NULL; item = item->next) {
    const char *comma;
    if (!cJSON_IsString(item) || item->valuestring == NULL) continue;
    comma = strchr(item->valuestring, ',');
    if (comma != NULL &&
        (ftun_rule_type_equal(item->valuestring,
                              (size_t)(comma - item->valuestring), "FRS-IP") ||
         ftun_rule_type_equal(item->valuestring,
                              (size_t)(comma - item->valuestring), "FRS-DOMAIN"))) {
      return 1;
    }
  }
  return 0;
}

static void ftun_normalize_config_names(ftun_config_t *config)
{
  size_t index;
  if (config == NULL) return;
  ftun_trim_name(config->dns.default_server);
  for (index = 0u; index < config->dns.listener_count; index++) {
    ftun_trim_name(config->dns.listeners[index].server);
  }
  for (index = 0u; index < config->dns.server_count; index++) {
    ftun_trim_name(config->dns.servers[index].name);
    ftun_trim_name(config->dns.servers[index].outbound);
  }
  ftun_trim_name(config->frs.update_outbound);
  ftun_trim_name(config->frs.dns_server);
  for (index = 0u; index < config->inbound_count; index++) {
    ftun_trim_name(config->inbounds[index].name);
    ftun_trim_name(config->inbounds[index].outbound);
  }
  for (index = 0u; index < config->outbound_count; index++) {
    size_t member;
    ftun_config_outbound_t *outbound = &config->outbounds[index];
    ftun_trim_name(outbound->name);
    ftun_trim_name(outbound->dns_server);
    ftun_trim_name(outbound->default_member);
    for (member = 0u; member < outbound->members.count; member++) {
      ftun_trim_name(outbound->members.items[member]);
    }
  }
  for (index = 0u; index < config->rules.count; index++) {
    ftun_trim_rule_names(config->rules.items[index]);
  }
}

/* 顶层 tun 是物理设备的唯一来源；TUN inbound 只描述 Proxy 消费者，
 * 内部模型把设备参数复制到每个 TUN inbound。 */
static ftun_status_t ftun_normalize_tun_device(ftun_config_t *config)
{
  size_t index;
  if (config == NULL) return FTUN_E_INVALID;
  for (index = 0u; index < config->inbound_count; index++) {
    ftun_config_inbound_t *inbound = &config->inbounds[index];
    if (inbound->kind != FTUN_CONFIG_INBOUND_TUN) continue;
    if (!config->tun.present) return FTUN_E_INVALID;
    inbound->interface_name =
      ftun_config_string_copy(config, config->tun.interface_name);
    inbound->ipv4_address =
      ftun_config_string_copy(config, config->tun.ipv4_address);
    if (inbound->interface_name == NULL || inbound->ipv4_address == NULL) {
      return FTUN_E_LIMIT;
    }
    inbound->mtu = config->tun.mtu;
    inbound->auto_route = config->tun.auto_route;
    inbound->strict_route = config->tun.strict_route;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_parse_root(const cJSON *root, ftun_config_t *config)
{
  static const char *const fields[] = {
    "$schema", "base", "log", "dns", "frs", "sniff", "inbounds", "outbounds",
    "rules", "tun"
  };
  const cJSON *item;
  ftun_status_t status = FTUN_OK;
  if (cJSON_GetObjectItemCaseSensitive(root, "api") != NULL ||
      cJSON_GetObjectItemCaseSensitive(root, "plugins") != NULL) {
    return FTUN_E_UNSUPPORTED;
  }
  status = ftun_config_check_fields(root, fields, 10u);
  if (status != FTUN_OK) return status;
  item = cJSON_GetObjectItemCaseSensitive(root, "$schema");
  if (item != NULL && (!cJSON_IsString(item) || item->valuestring == NULL ||
                       item->valuestring[0] == '\0')) return FTUN_E_INVALID;
  item = cJSON_GetObjectItemCaseSensitive(root, "base");
  if (item != NULL) status = ftun_parse_base(item, config);
  item = cJSON_GetObjectItemCaseSensitive(root, "log");
  if (status == FTUN_OK && item != NULL) status = ftun_parse_log(item, config);
  item = cJSON_GetObjectItemCaseSensitive(root, "dns");
  if (status == FTUN_OK && item != NULL) status = ftun_config_parse_dns(item, config, &config->dns);
  item = cJSON_GetObjectItemCaseSensitive(root, "sniff");
  if (status == FTUN_OK && item != NULL) status = ftun_config_parse_sniff(item, &config->sniff);
  item = cJSON_GetObjectItemCaseSensitive(root, "tun");
  if (status == FTUN_OK && item != NULL) {
    status = ftun_config_parse_tun_device(item, config, &config->tun);
  }
  item = cJSON_GetObjectItemCaseSensitive(root, "inbounds");
  if (status == FTUN_OK && item != NULL) status = ftun_config_parse_inbounds(item, config, &config->inbounds, &config->inbound_count);
  item = cJSON_GetObjectItemCaseSensitive(root, "outbounds");
  if (status == FTUN_OK && item != NULL) status = ftun_config_parse_outbounds(item, config, &config->outbounds, &config->outbound_count);
  item = cJSON_GetObjectItemCaseSensitive(root, "rules");
  if (status == FTUN_OK && item != NULL) status = ftun_config_parse_string_list(config, item, &config->rules, 0);
  config->frs.active = status == FTUN_OK && ftun_root_has_frs_rule(root);
  item = cJSON_GetObjectItemCaseSensitive(root, "frs");
  if (status == FTUN_OK && config->frs.active && item != NULL) {
    status = ftun_config_parse_frs(item, config, &config->frs);
  }
  if (status == FTUN_OK) status = ftun_normalize_tun_device(config);
  if (status == FTUN_OK) ftun_normalize_config_names(config);
  return status;
}

static ftun_status_t prepare_destroy(ftun_config_t *owned)
{
  ftun_status_t status = ftun_feature_plan_destroy(&owned->plan);
  if (status == FTUN_OK) owned->document.modules = NULL;
  return status;
}

static void destroy_fields(ftun_config_t *owned)
{
  free(owned->source_path);
  free(owned->base_directory);
  free(owned->base.proxy.cache_file);
  free(owned->log.level);
  free(owned->log.file);
  ftun_config_clear_dns(&owned->dns);
  ftun_config_clear_frs(&owned->frs);
  ftun_config_clear_tun(&owned->tun);
  ftun_config_clear_inbounds(owned->inbounds, owned->inbound_count);
  ftun_config_clear_outbounds(owned->outbounds, owned->outbound_count);
  ftun_config_string_list_clear(&owned->rules);
}

static size_t channel_count(const ftun_config_t *config)
{
  return config->outbound_count;
}
static ftun_channel_config_t channel_at(const ftun_config_t *config, size_t index)
{
  const ftun_config_outbound_t *item = &config->outbounds[index];
  ftun_channel_config_t view = {0};
  view.kind = item->kind == FTUN_CONFIG_OUTBOUND_SOCKS5 ? FTUN_CHANNEL_CONFIG_SOCKS5 : FTUN_CHANNEL_CONFIG_GROUP;
  view.name = item->name;
  view.dns_server = item->dns_server;
  view.server = item->server;
  view.username = item->username;
  view.password = item->password;
  view.udp = item->udp;
  view.members = item->members;
  return view;
}
static ftun_config_resolver_t resolver_view(const ftun_config_t *config)
{
  ftun_config_resolver_t view = {0};
  view.enable = config->dns.enable;
  view.bootstrap = config->dns.bootstrap;
  view.default_server = config->dns.default_server;
  view.fake_ip = config->dns.fake_ip;
  view.servers = config->dns.servers;
  view.server_count = config->dns.server_count;
  return view;
}
static ftun_dns_config_binding_t dns_binding(const ftun_config_t *config)
{
  size_t index;
  ftun_dns_config_binding_t view = {0};
  view.liveness = ftun_config_socket_liveness(config);
  for (index = 0u; index < config->inbound_count; index++) {
    if (config->inbounds[index].kind == FTUN_CONFIG_INBOUND_TUN && config->inbounds[index].dns_hijack) {
      view.hijack_id = (uint32_t)index + 1u;
      break;
    }
  }
  return view;
}
static ftun_proxy_config_plan_t proxy_plan(const ftun_config_t *config)
{
  const ftun_feature_plan_t *plan = config->plan;
  ftun_proxy_config_plan_t view = {0};
  if (plan == NULL) return view;
  view.present = true;
  view.accounted = plan->reservation.budget != NULL;
  view.owned_bytes = plan->owned_bytes;
  view.prepare = plan->prepare;
  view.outbound_states = plan->outbound_states;
  view.prepare_listener_count = plan->prepare_listener_count;
  view.prepare_tun_count = plan->prepare_tun_count;
  view.prepare_frs_count = plan->prepare_frs_count;
  return view;
}
static const ftun_channel_catalog_t channels = {channel_count, channel_at};
static const ftun_config_resolver_ops_t resolver = {resolver_view};
static const ftun_dns_config_binding_ops_t dns_bindings = {dns_binding};
static const ftun_proxy_config_plan_ops_t proxy_plans = {proxy_plan};

static const void *section(const ftun_config_t *config, uint32_t section_id)
{
  switch (section_id) {
  case FTUN_CONFIG_SECTION_BASE: return &config->base.proxy;
  case FTUN_CONFIG_SECTION_INBOUNDS: return config->inbounds;
  case FTUN_CONFIG_SECTION_INBOUND_COUNT: return &config->inbound_count;
  case FTUN_CONFIG_SECTION_OUTBOUNDS: return config->outbounds;
  case FTUN_CONFIG_SECTION_OUTBOUND_COUNT: return &config->outbound_count;
  case FTUN_CONFIG_SECTION_SOURCE_PATH: return config->source_path;
  case FTUN_CONFIG_SECTION_BASE_DIRECTORY: return config->base_directory;
  case FTUN_CONFIG_SECTION_DNS: return &config->dns;
  case FTUN_CONFIG_SECTION_FRS: return &config->frs;
  case FTUN_CONFIG_SECTION_SNIFF: return &config->sniff;
  case FTUN_CONFIG_SECTION_RULES: return &config->rules;
  case FTUN_CONFIG_SECTION_TUN: return &config->tun;
  case FTUN_CONFIG_SECTION_PLAN: return config->plan;
  case FTUN_CONFIG_SECTION_CHANNELS: return &channels;
  case FTUN_CONFIG_SECTION_RESOLVER: return &resolver;
  case FTUN_CONFIG_SECTION_DNS_BINDING: return &dns_bindings;
  case FTUN_CONFIG_SECTION_PROXY_PLAN: return &proxy_plans;
  default: return NULL;
  }
}

static const ftun_config_document_ops_t document_ops = {prepare_destroy, destroy_fields, section};

void ftun_config_bind_sections(ftun_config_t *config)
{
  config->document.ops = &document_ops;
}

ftun_status_t ftun_config_create_owned(ftun_budget_t *budget, ftun_config_t **out)
{
  return ftun_config_document_create(sizeof(ftun_config_t), budget, &document_ops, out);
}

/* 有界 JSON 到拥有型配置。 */
ftun_status_t ftun_config_parse_budget(ftun_budget_t *budget,
  ftun_bytes_t json, ftun_config_t **out)
{
  ftun_config_json_t document;
  ftun_config_t *config = NULL;
  ftun_status_t status;
  if (out == NULL) return FTUN_E_INVALID;
  *out = NULL;
  status = ftun_config_json_open(budget, json, &document);
  if (status != FTUN_OK) return status;
  status = ftun_config_create_owned(budget, &config);
  if (status == FTUN_OK) status = ftun_config_defaults(config);
  if (status == FTUN_OK) status = ftun_parse_root(document.root, config);
  ftun_config_json_close(&document);
  if (status != FTUN_OK) {
    (void)ftun_config_destroy(&config);
    return status;
  }
  *out = config;
  return FTUN_OK;
}

ftun_status_t ftun_config_parse(ftun_bytes_t json, ftun_config_t **out)
{
  return ftun_config_parse_budget(NULL, json, out);
}
