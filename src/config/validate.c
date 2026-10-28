#include "validate.h"
#include "compile.h"
#include "model.h"
#include "parser.h"
#include "core/budget.h"
#include "network/address.h"
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FTUN_CONFIG_MAX_GROUP_DEPTH 64u

typedef struct {
  uint32_t address;
  uint32_t mask;
} ftun_config_cidr_t;

typedef struct {
  uint32_t address;
  uint16_t port;
} ftun_config_listener_t;

static ftun_status_t ftun_config_diagnostic(ftun_diagnostic_t *out,
                                            ftun_status_t status,
                                            const char *path,
                                            const char *message)
{
  if (out != NULL) {
    memset(out, 0, sizeof(*out));
    out->error.status = status;
    out->path.data = path;
    out->path.length = strlen(path);
    out->message.data = message;
    out->message.length = strlen(message);
  }
  return status;
}

static int ftun_span_equal(const char *data, size_t length, const char *value)
{
  size_t value_length = strlen(value);
  return length == value_length && memcmp(data, value, length) == 0;
}

static int ftun_span_equal_ascii_fold(const char *data, size_t length,
                                      const char *value)
{
  size_t value_length = strlen(value);
  size_t index;
  if (data == NULL || length != value_length) return 0;
  for (index = 0u; index < length; index++) {
    unsigned char left = (unsigned char)data[index];
    unsigned char right = (unsigned char)value[index];
    if (left >= 'A' && left <= 'Z') left = (unsigned char)(left + ('a' - 'A'));
    if (right >= 'A' && right <= 'Z') right = (unsigned char)(right + ('a' - 'A'));
    if (left != right) return 0;
  }
  return 1;
}

static int ftun_name_span_valid(const char *value, size_t length)
{
  size_t index;
  if (value == NULL || length == 0u) return 0;
  for (index = 0u; index < length; index++) {
    unsigned char byte = (unsigned char)value[index];
    if (byte == ',' || byte <= 0x1fu || byte == 0x7fu) return 0;
    if (byte == 0xc2u && index + 1u < length) {
      unsigned char next = (unsigned char)value[index + 1u];
      if (next >= 0x80u && next <= 0x9fu) return 0;
    }
  }
  return 1;
}

static int ftun_name_valid(const char *value)
{
  return value != NULL && ftun_name_span_valid(value, strlen(value));
}

static int ftun_path_valid(const char *value)
{
  size_t index;
  if (value == NULL || value[0] == '\0') return 0;
  for (index = 0u; value[index] != '\0'; index++) {
    unsigned char byte = (unsigned char)value[index];
    if (byte <= 0x1fu || byte == 0x7fu) return 0;
  }
  return 1;
}

static int ftun_ipv4_span(const char *value, size_t length, uint32_t *out)
{
  uint8_t bytes[4];
  if (!ftun_ipv4_parse(value, length, bytes)) return 0;
  if (out != NULL) *out = ftun_ipv4_value(bytes);
  return 1;
}

static int ftun_domain_span(const char *value, size_t length)
{
  size_t effective = length;
  size_t start = 0u;
  size_t index;
  size_t dots = 0u;
  int only_digits_and_dots = 1;
  if (value == NULL || length == 0u) return 0;
  if (value[length - 1u] == '.') effective--;
  if (effective == 0u || effective > 253u) return 0;
  for (index = 0u; index < effective; index++) {
    unsigned char byte = (unsigned char)value[index];
    if (byte == '.') {
      dots++;
    } else if (byte < '0' || byte > '9') {
      only_digits_and_dots = 0;
    }
  }
  if (only_digits_and_dots && dots == 3u) return 0;
  for (index = 0u; index <= effective; index++) {
    if (index == effective || value[index] == '.') {
      size_t label_length = index - start;
      size_t label_index;
      if (label_length == 0u || label_length > 63u ||
          value[start] == '-' || value[index - 1u] == '-') return 0;
      for (label_index = start; label_index < index; label_index++) {
        unsigned char byte = (unsigned char)value[label_index];
        if (!((byte >= 'A' && byte <= 'Z') ||
              (byte >= 'a' && byte <= 'z') ||
              (byte >= '0' && byte <= '9') || byte == '-')) return 0;
      }
      start = index + 1u;
    }
  }
  return 1;
}

static int ftun_host_span(const char *value, size_t length, uint32_t *ipv4,
                          int *is_ipv4)
{
  uint32_t address;
  if (ftun_ipv4_span(value, length, &address)) {
    if (ipv4 != NULL) *ipv4 = address;
    if (is_ipv4 != NULL) *is_ipv4 = 1;
    return 1;
  }
  if (!ftun_domain_span(value, length)) return 0;
  if (is_ipv4 != NULL) *is_ipv4 = 0;
  return 1;
}

static int ftun_listen_address(const char *value, ftun_config_listener_t *out)
{
  const char *colon;
  size_t host_length;
  size_t port_length;
  uint32_t address;
  uint16_t port;
  if (value == NULL) return 0;
  colon = strchr(value, ':');
  if (colon == NULL || strchr(colon + 1, ':') != NULL) return 0;
  host_length = (size_t)(colon - value);
  port_length = strlen(colon + 1);
  if (!ftun_ipv4_span(value, host_length, &address) ||
      !ftun_port_parse(colon + 1, port_length, &port)) return 0;
  if (out != NULL) {
    out->address = address;
    out->port = port;
  }
  return 1;
}

static int ftun_server_address(const char *value, int port_required,
                               uint32_t *ipv4, int *is_ipv4)
{
  const char *colon;
  size_t host_length;
  uint16_t port;
  if (value == NULL || value[0] == '\0') return 0;
  colon = strchr(value, ':');
  if (colon == NULL) {
    if (port_required) return 0;
    return ftun_host_span(value, strlen(value), ipv4, is_ipv4);
  }
  if (strchr(colon + 1, ':') != NULL) return 0;
  host_length = (size_t)(colon - value);
  if (!ftun_host_span(value, host_length, ipv4, is_ipv4)) return 0;
  return ftun_port_parse(colon + 1, strlen(colon + 1), &port);
}

static int ftun_bootstrap_address(const char *value, uint32_t *out)
{
  const char *colon;
  uint32_t address;
  uint16_t port;
  if (value == NULL || value[0] == '\0') return 0;
  colon = strchr(value, ':');
  if (colon == NULL) {
    if (!ftun_ipv4_span(value, strlen(value), &address)) return 0;
    if (out != NULL) *out = address;
    return 1;
  }
  if (strchr(colon + 1, ':') != NULL ||
      !ftun_ipv4_span(value, (size_t)(colon - value), &address)) return 0;
  if (!ftun_port_parse(colon + 1, strlen(colon + 1), &port)) return 0;
  if (out != NULL) *out = address;
  return 1;
}

static int ftun_cidr(const char *value, int require_network,
                     ftun_config_cidr_t *out)
{
  ftun_cidr_t cidr;
  uint32_t network, broadcast;
  if (value == NULL || !ftun_cidr_parse(value, strlen(value), require_network != 0, &cidr) ||
      !ftun_cidr_ipv4_range(&cidr, &network, &broadcast)) return 0;
  if (out != NULL) {
    out->address = network;
    out->mask = ftun_ipv4_mask(cidr.prefix);
  }
  return 1;
}

int ftun_config_duration_ms(const char *value, uint64_t *out)
{
  size_t length;
  size_t digits;
  size_t index;
  uint64_t result = 0u;
  uint64_t multiplier;
  if (value == NULL) return 0;
  length = strlen(value);
  if (length < 2u || value[0] < '1' || value[0] > '9') return 0;
  if (length >= 3u && value[length - 2u] == 'm' && value[length - 1u] == 's') {
    digits = length - 2u;
    multiplier = 1u;
  } else {
    digits = length - 1u;
    if (value[length - 1u] == 's') multiplier = 1000u;
    else if (value[length - 1u] == 'm') multiplier = 60u * 1000u;
    else if (value[length - 1u] == 'h') multiplier = 60u * 60u * 1000u;
    else return 0;
  }
  for (index = 0u; index < digits; index++) {
    uint64_t digit;
    if (value[index] < '0' || value[index] > '9') return 0;
    digit = (uint64_t)(value[index] - '0');
    if (result > (UINT64_MAX - digit) / 10u) return 0;
    result = result * 10u + digit;
  }
  if (result == 0u || result > UINT64_MAX / multiplier) return 0;
  if (out != NULL) *out = result * multiplier;
  return 1;
}

static int ftun_http_url(const char *value, uint32_t *ipv4, int *is_ipv4)
{
  const char *authority;
  const char *end;
  const char *colon;
  size_t host_length;
  int host_is_ipv4;
  uint32_t host_ipv4 = 0u;
  uint16_t ignored_port;
  const unsigned char *cursor;
  if (value == NULL) return 0;
  if (strncmp(value, "http://", 7u) == 0) authority = value + 7u;
  else if (strncmp(value, "https://", 8u) == 0) authority = value + 8u;
  else return 0;
  end = authority;
  while (*end != '\0' && *end != '/' && *end != '?' && *end != '#') end++;
  if (end == authority || memchr(authority, '@', (size_t)(end - authority)) != NULL) return 0;
  colon = memchr(authority, ':', (size_t)(end - authority));
  if (colon != NULL) {
    if (memchr(colon + 1, ':', (size_t)(end - colon - 1)) != NULL) return 0;
    host_length = (size_t)(colon - authority);
    if (!ftun_port_parse(colon + 1, (size_t)(end - colon - 1), &ignored_port)) return 0;
  } else {
    host_length = (size_t)(end - authority);
  }
  if (!ftun_host_span(authority, host_length, &host_ipv4, &host_is_ipv4)) return 0;
  for (cursor = (const unsigned char *)end; *cursor != 0u; cursor++) {
    if (*cursor <= 0x20u || *cursor == 0x7fu) return 0;
  }
  if (ipv4 != NULL) *ipv4 = host_ipv4;
  if (is_ipv4 != NULL) *is_ipv4 = host_is_ipv4;
  return 1;
}

static int ftun_outbound_index_span(const ftun_config_t *config,
                                    const char *name, size_t length,
                                    size_t *out)
{
  size_t index;
  for (index = 0u; index < config->outbound_count; index++) {
    const char *candidate = config->outbounds[index].name;
    if (candidate != NULL && strlen(candidate) == length &&
        memcmp(candidate, name, length) == 0) {
      if (out != NULL) *out = index;
      return 1;
    }
  }
  return 0;
}

static int ftun_outbound_exists_span(const ftun_config_t *config,
                                     const char *name, size_t length)
{
  return ftun_span_equal(name, length, "DIRECT") ||
         ftun_span_equal(name, length, "REJECT") ||
         ftun_outbound_index_span(config, name, length, NULL);
}

static int ftun_outbound_exists(const ftun_config_t *config, const char *name)
{
  return name != NULL && ftun_outbound_exists_span(config, name, strlen(name));
}

static int ftun_dns_server_exists(const ftun_config_t *config, const char *name)
{
  size_t index;
  if (name == NULL) return 0;
  for (index = 0u; index < config->dns.server_count; index++) {
    if (config->dns.servers[index].name != NULL &&
        strcmp(config->dns.servers[index].name, name) == 0) return 1;
  }
  return 0;
}

static int ftun_list_contains(const ftun_config_string_list_t *list,
                              const char *value)
{
  size_t index;
  if (list == NULL || value == NULL) return 0;
  for (index = 0u; index < list->count; index++) {
    if (list->items[index] != NULL && strcmp(list->items[index], value) == 0) return 1;
  }
  return 0;
}

static int ftun_ascii_token(const char *value, size_t length)
{
  size_t index;
  if (value == NULL || length == 0u) return 0;
  for (index = 0u; index < length; index++) {
    unsigned char byte = (unsigned char)value[index];
    if (byte < 0x21u || byte > 0x7eu || byte == ',') return 0;
  }
  return 1;
}

static ftun_status_t ftun_validate_rule(const ftun_config_t *config,
                                        const char *rule,
                                        ftun_diagnostic_t *out)
{
  const char *first;
  const char *second;
  const char *outbound;
  size_t type_length;
  size_t operand_length;
  size_t outbound_length;
  uint32_t ignored;
  ftun_config_cidr_t ignored_cidr;
  if (rule == NULL) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/rules",
                                  "rule is missing");
  }
  first = strchr(rule, ',');
  if (first == NULL) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/rules",
                                  "rule has invalid field count");
  }
  type_length = (size_t)(first - rule);
  if (ftun_span_equal_ascii_fold(rule, type_length, "MATCH")) {
    outbound = first + 1;
    if (outbound[0] == '\0' || strchr(outbound, ',') != NULL) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/rules",
                                    "MATCH rule has invalid field count");
    }
  } else {
    second = strchr(first + 1, ',');
    if (second == NULL || second == first + 1 || second[1] == '\0' ||
        strchr(second + 1, ',') != NULL) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/rules",
                                    "rule has invalid field count");
    }
    operand_length = (size_t)(second - first - 1);
    outbound = second + 1;
    if (ftun_span_equal_ascii_fold(rule, type_length, "SRC-IP-CIDR") ||
        ftun_span_equal_ascii_fold(rule, type_length, "IP-CIDR")) {
      char buffer[32];
      if (operand_length >= sizeof(buffer)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/rules",
                                      "rule CIDR is invalid");
      }
      memcpy(buffer, first + 1, operand_length);
      buffer[operand_length] = '\0';
      if (!ftun_cidr(buffer, 0, &ignored_cidr)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/rules",
                                      "rule CIDR is invalid");
      }
    } else if (ftun_span_equal_ascii_fold(rule, type_length, "DOMAIN") ||
               ftun_span_equal_ascii_fold(rule, type_length, "DOMAIN-SUFFIX")) {
      if (!ftun_domain_span(first + 1, operand_length)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/rules",
                                      "rule domain is invalid");
      }
    } else if (ftun_span_equal_ascii_fold(rule, type_length, "DOMAIN-KEYWORD")) {
      if (!ftun_ascii_token(first + 1, operand_length)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/rules",
                                      "domain keyword is invalid");
      }
    } else if (ftun_span_equal_ascii_fold(rule, type_length, "FRS-IP") ||
               ftun_span_equal_ascii_fold(rule, type_length, "FRS-DOMAIN")) {
      if (!ftun_name_span_valid(first + 1, operand_length)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/rules",
                                      "FRS label is invalid");
      }
    } else if (ftun_span_equal_ascii_fold(rule, type_length, "DST-PORT")) {
      if (!ftun_decimal_parse(first + 1, operand_length, 65535u, &ignored) || ignored == 0u) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/rules",
                                      "rule port is invalid");
      }
    } else if (ftun_span_equal_ascii_fold(rule, type_length, "NETWORK")) {
      if (!ftun_span_equal(first + 1, operand_length, "tcp") &&
          !ftun_span_equal(first + 1, operand_length, "udp")) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/rules",
                                      "rule network is invalid");
      }
    } else {
      return ftun_config_diagnostic(out, FTUN_E_UNSUPPORTED, "/rules",
                                    "rule type is not supported");
    }
  }
  outbound_length = strlen(outbound);
  if (!ftun_name_span_valid(outbound, outbound_length) ||
      !ftun_outbound_exists_span(config, outbound, outbound_length)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/rules",
                                  "rule outbound does not exist");
  }
  return FTUN_OK;
}

static ftun_status_t ftun_validate_group_visit(const ftun_config_t *config,
                                               size_t index, uint8_t *colors,
                                               size_t depth,
                                               ftun_diagnostic_t *out)
{
  const ftun_config_outbound_t *group = &config->outbounds[index];
  size_t member_index;
  if (depth > FTUN_CONFIG_MAX_GROUP_DEPTH) {
    return ftun_config_diagnostic(out, FTUN_E_LIMIT, "/outbounds",
                                  "outbound group depth exceeds limit");
  }
  if (colors[index] == 1u) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/outbounds",
                                  "outbound group contains a cycle");
  }
  if (colors[index] == 2u || group->kind == FTUN_CONFIG_OUTBOUND_SOCKS5) return FTUN_OK;
  colors[index] = 1u;
  for (member_index = 0u; member_index < group->members.count; member_index++) {
    const char *member = group->members.items[member_index];
    size_t child;
    if (member != NULL && ftun_outbound_index_span(config, member, strlen(member), &child)) {
      ftun_status_t status = ftun_validate_group_visit(config, child, colors,
                                                       depth + 1u, out);
      if (status != FTUN_OK) return status;
    }
  }
  colors[index] = 2u;
  return FTUN_OK;
}

static int ftun_config_cidr_has(const ftun_config_cidr_t *cidr, uint32_t address)
{
  return (address & cidr->mask) == cidr->address;
}

static int ftun_cidr_overlap(const ftun_config_cidr_t *left,
                             const ftun_config_cidr_t *right)
{
  uint32_t mask = left->mask < right->mask ? left->mask : right->mask;
  return (left->address & mask) == (right->address & mask);
}

static int ftun_listener_conflict(const ftun_config_listener_t *left,
                                  const ftun_config_listener_t *right)
{
  return left->port == right->port &&
         (left->address == right->address || left->address == 0u || right->address == 0u);
}

/* 各时长的取值范围；write-progress 必须大于 keepalive 判定失联所需的总时长，
 * 否则健康的慢速链路会先被误判为失联。 */
static ftun_status_t ftun_validate_timeouts(const ftun_config_t *config,
                                            ftun_diagnostic_t *out)
{
  const uint32_t minimum_ms = 100u;
  const uint32_t maximum_ms = 600u * 1000u;
  const uint32_t maximum_idle_ms = 7u * 24u * 3600u * 1000u;
  const uint32_t maximum_progress_ms = 3600u * 1000u;
  size_t index;
  if (config->base.timeouts.handshake_ms < minimum_ms ||
      config->base.timeouts.handshake_ms > maximum_ms) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/base/timeouts/handshake",
                                  "handshake timeout is out of range");
  }
  if (config->base.timeouts.connect_ms < minimum_ms ||
      config->base.timeouts.connect_ms > maximum_ms) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/base/timeouts/connect",
                                  "connect timeout is out of range");
  }
  if (config->base.timeouts.reply_ms < minimum_ms ||
      config->base.timeouts.reply_ms > maximum_ms) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/base/timeouts/reply",
                                  "reply timeout is out of range");
  }
  if (config->base.timeouts.write_progress_ms < 1000u ||
      config->base.timeouts.write_progress_ms > maximum_progress_ms) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/base/timeouts/write-progress",
                                  "write progress timeout is out of range");
  }
  if (config->base.timeouts.tcp_idle_ms > maximum_idle_ms ||
      (config->base.timeouts.tcp_idle_ms != 0u && config->base.timeouts.tcp_idle_ms < 1000u)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/base/timeouts/tcp-idle",
                                  "TCP idle timeout is out of range");
  }
  if (config->base.timeouts.udp_idle_ms < 1000u ||
      config->base.timeouts.udp_idle_ms > maximum_idle_ms) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/base/timeouts/udp-idle",
                                  "UDP idle timeout is out of range");
  }
  if (config->base.timeouts.keepalive.enabled) {
    uint64_t detection_ms;
    if (config->base.timeouts.keepalive.idle_s < 1u ||
        config->base.timeouts.keepalive.idle_s > 7200u ||
        config->base.timeouts.keepalive.interval_s < 1u ||
        config->base.timeouts.keepalive.interval_s > 600u ||
        config->base.timeouts.keepalive.count < 1u ||
        config->base.timeouts.keepalive.count > 20u) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/base/timeouts/tcp-keepalive",
                                    "TCP keepalive values are out of range");
    }
    detection_ms = ((uint64_t)config->base.timeouts.keepalive.idle_s +
      (uint64_t)config->base.timeouts.keepalive.interval_s *
      config->base.timeouts.keepalive.count) * 1000u;
    if (config->base.timeouts.write_progress_ms <= detection_ms) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/base/timeouts/write-progress",
        "write progress timeout must exceed the keepalive detection time");
    }
  }
  for (index = 0u; index < config->inbound_count; index++) {
    uint32_t idle = config->inbounds[index].tcp_idle_ms;
    if (idle != 0u && (idle < 1000u || idle > maximum_idle_ms)) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/inbounds",
                                    "inbound TCP idle timeout is out of range");
    }
  }
  return FTUN_OK;
}

static ftun_status_t ftun_validate_basic(const ftun_config_t *config,
                                         ftun_diagnostic_t *out)
{
  static const char *const levels[] = {
    "silent", "error", "warn", "info", "debug", "trace"
  };
  size_t index;
  int level_valid = 0;
  if (config->base.ipv6) {
    return ftun_config_diagnostic(out, FTUN_E_UNSUPPORTED, "/base/ipv6",
                                  "IPv6 mode is not supported");
  }
  if (config->base.watchdog_ms != 0u &&
      (config->base.watchdog_ms < FTUN_CONFIG_WATCHDOG_MINIMUM_MS ||
       config->base.watchdog_ms > FTUN_CONFIG_WATCHDOG_MAXIMUM_MS)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/base/watchdog",
                                  "watchdog must be 1s..10m or null");
  }
  if (config->base.capacity.tcp_flows < FTUN_CONFIG_CAPACITY_MINIMUM ||
      config->base.capacity.tcp_flows > FTUN_CONFIG_CAPACITY_MAXIMUM) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID,
                                  "/base/capacity/tcp-flows",
                                  "TCP flow capacity is out of range");
  }
  if (config->base.capacity.udp_flows < FTUN_CONFIG_CAPACITY_MINIMUM ||
      config->base.capacity.udp_flows > FTUN_CONFIG_CAPACITY_MAXIMUM) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID,
                                  "/base/capacity/udp-flows",
                                  "UDP flow capacity is out of range");
  }
  if (config->base.capacity.udp_associations <
        FTUN_CONFIG_CAPACITY_MINIMUM ||
      config->base.capacity.udp_associations >
        FTUN_CONFIG_CAPACITY_MAXIMUM) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID,
                                  "/base/capacity/udp-associations",
                                  "UDP association capacity is out of range");
  }
  {
    ftun_status_t timeouts = ftun_validate_timeouts(config, out);
    if (timeouts != FTUN_OK) return timeouts;
  }
  if (!ftun_path_valid(config->base.cache_file)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/base/cache-file",
                                  "cache file path is invalid");
  }
  for (index = 0u; index < sizeof(levels) / sizeof(levels[0]); index++) {
    if (config->log.level != NULL && strcmp(config->log.level, levels[index]) == 0) {
      level_valid = 1;
      break;
    }
  }
  if (!level_valid) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/log/level",
                                  "log level is invalid");
  }
  if (!ftun_path_valid(config->log.file)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/log/file",
                                  "log file path is invalid");
  }
  if (config->log.max_size != 0u &&
      config->log.max_size < FTUN_CONFIG_LOG_MAX_SIZE_MINIMUM) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/log/max-size",
                                  "log max-size must be 0 or at least 65536 bytes");
  }
  if (config->log.max_files == 0u ||
      config->log.max_files > FTUN_CONFIG_LOG_MAX_FILES_MAXIMUM) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/log/max-files",
                                  "log max-files must be 1..32");
  }
  return FTUN_OK;
}

static ftun_status_t ftun_validate_dns(const ftun_config_t *config,
                                       ftun_diagnostic_t *out)
{
  ftun_config_cidr_t fake_range;
  size_t index;
  size_t other;
  if (!ftun_cidr(config->dns.fake_ip.range, 0, &fake_range)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/fake-ip/range",
                                  "FakeIP range is invalid");
  }
  for (index = 0u; index < config->dns.bootstrap.count; index++) {
    uint32_t address;
    if (!ftun_bootstrap_address(config->dns.bootstrap.items[index], &address)) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/bootstrap",
                                    "bootstrap address is invalid");
    }
    if (config->dns.enable && config->dns.fake_ip.enable &&
        ftun_config_cidr_has(&fake_range, address)) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/bootstrap",
                                    "bootstrap address overlaps FakeIP range");
    }
  }
  for (index = 0u; index < config->dns.server_count; index++) {
    const ftun_config_dns_server_t *server = &config->dns.servers[index];
    if (!ftun_name_valid(server->name)) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/servers",
                                    "DNS server name is invalid");
    }
    for (other = 0u; other < index; other++) {
      if (strcmp(server->name, config->dns.servers[other].name) == 0) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/servers",
                                      "DNS server name is duplicated");
      }
    }
    if (server->addresses.count == 0u || server->addresses.items == NULL) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/servers",
                                    "DNS server address list is empty");
    }
    if (server->addresses.count > 4u) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/servers",
                                    "DNS server has more than 4 addresses");
    }
    for (other = 0u; other < server->addresses.count; other++) {
      uint32_t address = 0u;
      int is_ipv4 = 0;
      if (!ftun_server_address(server->addresses.items[other], 0, &address, &is_ipv4)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/servers",
                                      "DNS server address is invalid");
      }
      if (config->dns.enable && config->dns.fake_ip.enable && is_ipv4 &&
          ftun_config_cidr_has(&fake_range, address)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/servers",
                                      "DNS server address overlaps FakeIP range");
      }
    }
    if (config->dns.enable && !ftun_outbound_exists(config, server->outbound)) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/servers",
                                    "DNS server outbound does not exist");
    }
  }
  if (config->dns.enable && config->dns.default_server[0] != '\0' &&
      !ftun_dns_server_exists(config, config->dns.default_server)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/default-server",
                                  "default DNS server does not exist");
  }
  for (index = 0u; index < config->dns.listener_count; index++) {
    ftun_config_listener_t ignored;
    const ftun_config_dns_listener_t *listener = &config->dns.listeners[index];
    if (!ftun_listen_address(listener->listen, &ignored)) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/listeners",
                                    "DNS listen address is invalid");
    }
    if (config->dns.enable && listener->server[0] != '\0' &&
        !ftun_dns_server_exists(config, listener->server)) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/listeners",
                                    "DNS listener server does not exist");
    }
  }
  return FTUN_OK;
}

static ftun_status_t ftun_validate_outbounds(const ftun_config_t *config,
                                             const ftun_config_cidr_t *fake_range,
                                             ftun_diagnostic_t *out)
{
  uint8_t *colors;
  ftun_reservation_t *workspace = NULL;
  size_t index;
  size_t other;
  for (index = 0u; index < config->outbound_count; index++) {
    const ftun_config_outbound_t *outbound = &config->outbounds[index];
    if (!ftun_name_valid(outbound->name) || strcmp(outbound->name, "DIRECT") == 0 ||
        strcmp(outbound->name, "REJECT") == 0) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/outbounds",
                                    "outbound name is invalid or reserved");
    }
    for (other = 0u; other < index; other++) {
      if (strcmp(outbound->name, config->outbounds[other].name) == 0) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/outbounds",
                                      "outbound name is duplicated");
      }
    }
    if (config->dns.enable && outbound->dns_server[0] != '\0' &&
        !ftun_dns_server_exists(config, outbound->dns_server)) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/outbounds",
                                    "outbound DNS server does not exist");
    }
    if (outbound->kind == FTUN_CONFIG_OUTBOUND_SOCKS5) {
      size_t user_length = outbound->username == NULL ? 0u : strlen(outbound->username);
      size_t password_length = outbound->password == NULL ? 0u : strlen(outbound->password);
      uint32_t address = 0u;
      int is_ipv4 = 0;
      if (!ftun_server_address(outbound->server, 1, &address, &is_ipv4)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/outbounds",
                                      "SOCKS5 server address is invalid");
      }
      if (config->dns.enable && config->dns.fake_ip.enable && is_ipv4 &&
          ftun_config_cidr_has(fake_range, address)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/outbounds",
                                      "SOCKS5 server overlaps FakeIP range");
      }
      if ((outbound->username == NULL) != (outbound->password == NULL) ||
          (outbound->username != NULL &&
           (user_length == 0u || user_length > 255u ||
            password_length == 0u || password_length > 255u))) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/outbounds",
                                      "SOCKS5 credentials are invalid");
      }
      continue;
    }
    if (outbound->members.items == NULL || outbound->members.count == 0u ||
        !ftun_name_valid(outbound->default_member)) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/outbounds",
                                    "outbound group members are invalid");
    }
    for (other = 0u; other < outbound->members.count; other++) {
      size_t previous;
      const char *member = outbound->members.items[other];
      if (!ftun_name_valid(member) || !ftun_outbound_exists(config, member)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/outbounds",
                                      "outbound group member does not exist");
      }
      for (previous = 0u; previous < other; previous++) {
        if (strcmp(member, outbound->members.items[previous]) == 0) {
          return ftun_config_diagnostic(out, FTUN_E_INVALID, "/outbounds",
                                        "outbound group member is duplicated");
        }
      }
    }
    if (!ftun_list_contains(&outbound->members, outbound->default_member)) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/outbounds",
                                    "outbound group default is not a member");
    }
    if (outbound->kind == FTUN_CONFIG_OUTBOUND_URL_TEST) {
      uint64_t interval;
      uint64_t timeout;
      uint32_t address = 0u;
      int is_ipv4 = 0;
      if (!ftun_http_url(outbound->url, &address, &is_ipv4)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/outbounds",
                                      "health check URL is invalid");
      }
      if (config->dns.enable && config->dns.fake_ip.enable && is_ipv4 &&
          ftun_config_cidr_has(fake_range, address)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/outbounds",
                                      "health check URL overlaps FakeIP range");
      }
      if (!ftun_config_duration_ms(outbound->interval, &interval) ||
          !ftun_config_duration_ms(outbound->timeout, &timeout) || timeout > interval) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/outbounds",
                                      "health check durations are invalid");
      }
    }
  }
  if (config->budget != NULL && ftun_budget_reserve(config->budget,
      config->outbound_count == 0u ? 1u : config->outbound_count, &workspace) != FTUN_OK) {
    return ftun_config_diagnostic(out, FTUN_E_LIMIT, "/outbounds",
                                  "cannot reserve outbound graph workspace");
  }
  colors = (uint8_t *)calloc(config->outbound_count == 0u ? 1u : config->outbound_count,
                             sizeof(*colors));
  if (colors == NULL) {
    (void)ftun_reservation_release(&workspace);
    return ftun_config_diagnostic(out, FTUN_E_LIMIT, "/outbounds",
                                  "cannot allocate outbound graph workspace");
  }
  for (index = 0u; index < config->outbound_count; index++) {
    ftun_status_t status = ftun_validate_group_visit(config, index, colors, 1u, out);
    if (status != FTUN_OK) {
      free(colors);
      (void)ftun_reservation_release(&workspace);
      return status;
    }
  }
  free(colors);
  (void)ftun_reservation_release(&workspace);
  return FTUN_OK;
}

static ftun_status_t ftun_validate_inbounds(const ftun_config_t *config,
                                            const ftun_config_cidr_t *fake_range,
                                            ftun_diagnostic_t *out)
{
  size_t index;
  size_t other;
  size_t tun_count = 0u;
  for (index = 0u; index < config->inbound_count; index++) {
    const ftun_config_inbound_t *inbound = &config->inbounds[index];
    if (!ftun_name_valid(inbound->name)) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/inbounds",
                                    "inbound name is invalid");
    }
    for (other = 0u; other < index; other++) {
      if (strcmp(inbound->name, config->inbounds[other].name) == 0) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/inbounds",
                                      "inbound name is duplicated");
      }
    }
    if (inbound->outbound == NULL ||
        (inbound->outbound[0] != '\0' && !ftun_outbound_exists(config, inbound->outbound))) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/inbounds",
                                    "inbound outbound does not exist");
    }
    if (inbound->kind == FTUN_CONFIG_INBOUND_TUN) {
      ftun_config_cidr_t tun_range;
      tun_count++;
      if (tun_count > 1u) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/inbounds",
                                      "only one TUN inbound is allowed");
      }
      if (!ftun_path_valid(inbound->interface_name) ||
          strlen(inbound->interface_name) > 15u) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/inbounds",
                                      "TUN interface name is invalid");
      }
      if (inbound->mtu == 0u || strcmp(inbound->stack, "lwip") != 0 ||
          (!inbound->tcp && !inbound->udp) ||
          (inbound->strict_route && !inbound->auto_route)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/inbounds",
                                      "TUN options are invalid");
      }
      if (!ftun_cidr(inbound->ipv4_address, 0, &tun_range)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/inbounds",
                                      "TUN IPv4 address is invalid");
      }
      if (config->dns.enable && config->dns.fake_ip.enable &&
          ftun_cidr_overlap(fake_range, &tun_range)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/fake-ip/range",
                                      "FakeIP range overlaps TUN network");
      }
    } else {
      ftun_config_listener_t ignored;
      if (!ftun_listen_address(inbound->listen, &ignored)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/inbounds",
                                      "inbound listen address is invalid");
      }
      for (other = 0u; other < inbound->user_count; other++) {
        size_t user_length;
        size_t password_length;
        if (inbound->users == NULL || inbound->users[other].name == NULL ||
            inbound->users[other].password == NULL) {
          return ftun_config_diagnostic(out, FTUN_E_INVALID, "/inbounds",
                                        "inbound credentials are invalid");
        }
        user_length = strlen(inbound->users[other].name);
        password_length = strlen(inbound->users[other].password);
        if (user_length == 0u || user_length > 255u ||
            password_length == 0u || password_length > 255u) {
          return ftun_config_diagnostic(out, FTUN_E_INVALID, "/inbounds",
                                        "inbound credentials are invalid");
        }
      }
    }
  }
  return FTUN_OK;
}

static ftun_status_t ftun_validate_tun_device(
  const ftun_config_t *config, const ftun_config_cidr_t *fake_range,
  ftun_diagnostic_t *out)
{
  ftun_config_cidr_t tun_range;
  const char *base = "/tun";
  if (config == NULL || !config->tun.present) return FTUN_OK;
  if (!ftun_path_valid(config->tun.interface_name) ||
      strlen(config->tun.interface_name) > 15u) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, base,
                                  "TUN interface name is invalid");
  }
  if (config->tun.route_table < 256u ||
      config->tun.route_table > FTUN_CONFIG_ROUTE_TABLE_MAXIMUM ||
      config->tun.rule_priority == 0u ||
      config->tun.rule_priority > FTUN_CONFIG_RULE_PRIORITY_MAXIMUM) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, base,
      "TUN route-table must be 256..4294967280 and rule-priority 1..32000");
  }
  if (config->tun.mtu == 0u ||
      (config->tun.strict_route && !config->tun.auto_route)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, base,
                                  "TUN options are invalid");
  }
  if (!ftun_cidr(config->tun.ipv4_address, 0, &tun_range)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, base,
                                  "TUN IPv4 address is invalid");
  }
  if (config->dns.enable && config->dns.fake_ip.enable &&
      ftun_cidr_overlap(fake_range, &tun_range)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID,
                                  "/dns/fake-ip/range",
                                  "FakeIP range overlaps TUN network");
  }
  return FTUN_OK;
}

static ftun_status_t ftun_validate_listener_conflicts(const ftun_config_t *config,
                                                      ftun_diagnostic_t *out)
{
  size_t left;
  size_t right;
  for (left = 0u; left < config->inbound_count; left++) {
    ftun_config_listener_t left_listener;
    if (config->inbounds[left].kind == FTUN_CONFIG_INBOUND_TUN) continue;
    (void)ftun_listen_address(config->inbounds[left].listen, &left_listener);
    for (right = left + 1u; right < config->inbound_count; right++) {
      ftun_config_listener_t right_listener;
      if (config->inbounds[right].kind == FTUN_CONFIG_INBOUND_TUN) continue;
      (void)ftun_listen_address(config->inbounds[right].listen, &right_listener);
      if (ftun_listener_conflict(&left_listener, &right_listener)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/inbounds",
                                      "inbound listeners conflict");
      }
    }
    if (!config->dns.enable) continue;
    for (right = 0u; right < config->dns.listener_count; right++) {
      ftun_config_listener_t dns_listener;
      (void)ftun_listen_address(config->dns.listeners[right].listen, &dns_listener);
      if (ftun_listener_conflict(&left_listener, &dns_listener)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/listeners",
                                      "DNS and inbound listeners conflict");
      }
    }
  }
  if (config->dns.enable) {
    for (left = 0u; left < config->dns.listener_count; left++) {
      ftun_config_listener_t left_listener;
      (void)ftun_listen_address(config->dns.listeners[left].listen, &left_listener);
      for (right = left + 1u; right < config->dns.listener_count; right++) {
        ftun_config_listener_t right_listener;
        (void)ftun_listen_address(config->dns.listeners[right].listen, &right_listener);
        if (ftun_listener_conflict(&left_listener, &right_listener)) {
          return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/listeners",
                                        "DNS listeners conflict");
        }
      }
    }
  }
  return FTUN_OK;
}

static ftun_status_t ftun_validate_frs(const ftun_config_t *config,
                                       const ftun_config_cidr_t *fake_range,
                                       ftun_diagnostic_t *out)
{
  uint64_t ignored;
  uint32_t address = 0u;
  int is_ipv4 = 0;
  if (!config->frs.active) return FTUN_OK;
  if (config->frs.path != NULL && !ftun_path_valid(config->frs.path)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/frs/path",
                                  "FRS path is invalid");
  }
  if (!config->frs.auto_update || config->frs.url == NULL ||
      config->frs.url[0] == '\0') return FTUN_OK;
  if (!ftun_http_url(config->frs.url, &address, &is_ipv4)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/frs/url",
                                  "FRS update URL is invalid");
  }
  if (!ftun_config_duration_ms(config->frs.update_interval, &ignored)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/frs/update-interval",
                                  "FRS update interval is invalid");
  }
  if (!ftun_outbound_exists(config, config->frs.update_outbound)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/frs/update-outbound",
                                  "FRS update outbound does not exist");
  }
  if (config->dns.enable && config->frs.dns_server[0] != '\0' &&
      !ftun_dns_server_exists(config, config->frs.dns_server)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/frs/dns-server",
                                  "FRS DNS server does not exist");
  }
  if (config->dns.enable && config->dns.fake_ip.enable && is_ipv4 &&
      ftun_config_cidr_has(fake_range, address)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/frs/url",
                                  "FRS update URL overlaps FakeIP range");
  }
  return FTUN_OK;
}

/* 无副作用语义校验。 */
ftun_status_t ftun_config_validate(const ftun_config_t *config, ftun_diagnostic_t *out)
{
  ftun_config_cidr_t fake_range;
  uint32_t required;
  size_t index;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (config == NULL) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "",
                                  "configuration is missing");
  }
  required = ftun_config_required_modules(config);
  status = ftun_build_require_modules(required, out);
  if (status != FTUN_OK) {
    if (out != NULL) {
      const ftun_build_capabilities_t *capabilities = ftun_build_capabilities();
      static const char proxy_path[] = "/";
      static const char dns_path[] = "/dns/enable";
      static const char fakeip_path[] = "/dns/servers";
      static const char tun_path[] = "/inbounds";
      static const char frs_path[] = "/rules";
      if ((required & FTUN_BUILD_MODULE_PROXY) != 0u &&
          (capabilities->builtins & FTUN_BUILD_MODULE_PROXY) == 0u) {
        out->path.data = proxy_path;
        out->path.length = sizeof(proxy_path) - 1u;
      } else if ((required & FTUN_BUILD_MODULE_DNS) != 0u &&
          (capabilities->builtins & FTUN_BUILD_MODULE_DNS) == 0u) {
        out->path.data = dns_path;
        out->path.length = sizeof(dns_path) - 1u;
      } else if ((required & FTUN_BUILD_MODULE_FAKEIP) != 0u &&
                 (capabilities->builtins & FTUN_BUILD_MODULE_FAKEIP) == 0u) {
        out->path.data = fakeip_path;
        out->path.length = sizeof(fakeip_path) - 1u;
      } else if ((required & FTUN_BUILD_MODULE_TUN) != 0u &&
                 (capabilities->builtins & FTUN_BUILD_MODULE_TUN) == 0u) {
        out->path.data = tun_path;
        out->path.length = sizeof(tun_path) - 1u;
      } else {
        out->path.data = frs_path;
        out->path.length = sizeof(frs_path) - 1u;
      }
    }
    return status;
  }
  status = ftun_validate_basic(config, out);
  if (status != FTUN_OK) return status;
  status = ftun_validate_dns(config, out);
  if (status != FTUN_OK) return status;
  (void)ftun_cidr(config->dns.fake_ip.range, 0, &fake_range);
  status = ftun_validate_outbounds(config, &fake_range, out);
  if (status != FTUN_OK) return status;
  status = ftun_validate_tun_device(config, &fake_range, out);
  if (status != FTUN_OK) return status;
  status = ftun_validate_inbounds(config, &fake_range, out);
  if (status != FTUN_OK) return status;
  status = ftun_validate_listener_conflicts(config, out);
  if (status != FTUN_OK) return status;
  status = ftun_validate_frs(config, &fake_range, out);
  if (status != FTUN_OK) return status;
  for (index = 0u; index < config->rules.count; index++) {
    status = ftun_validate_rule(config, config->rules.items[index], out);
    if (status != FTUN_OK) return status;
  }
  if (out != NULL) memset(out, 0, sizeof(*out));
  return FTUN_OK;
}
