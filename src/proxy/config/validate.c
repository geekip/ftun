#include "proxy/config/validate.h"
#include "core/config/syntax.h"
#include "core/limits.h"
#include "util/ip.h"
#include "util/time_math.h"
#include <stdlib.h>
#include <string.h>
#define FTUN_CONFIG_MAX_GROUP_DEPTH 64u

static int ftun_outbound_index_span(const ftun_config_outbound_t *outbounds, size_t outbound_count,
                                    const char *name, size_t length,
                                    size_t *out)
{
  size_t index;
  for (index = 0u; index < outbound_count; index++) {
    const char *candidate = outbounds[index].name;
    if (candidate != NULL && strlen(candidate) == length &&
        memcmp(candidate, name, length) == 0) {
      if (out != NULL) *out = index;
      return 1;
    }
  }
  return 0;
}

static int ftun_outbound_exists_span(const ftun_config_outbound_t *outbounds, size_t outbound_count,
                                     const char *name, size_t length)
{
  return ftun_span_equal(name, length, "DIRECT") ||
         ftun_span_equal(name, length, "REJECT") ||
         ftun_outbound_index_span(outbounds, outbound_count, name, length, NULL);
}

static int ftun_outbound_exists(const ftun_config_outbound_t *outbounds, size_t outbound_count, const char *name)
{
  return name != NULL && ftun_outbound_exists_span(outbounds, outbound_count, name, strlen(name));
}

static ftun_status_t ftun_validate_group_visit(const ftun_config_outbound_t *outbounds, size_t outbound_count,
                                               size_t index, uint8_t *colors,
                                               size_t depth,
                                               ftun_diagnostic_t *out)
{
  const ftun_config_outbound_t *group = &outbounds[index];
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
    if (member != NULL && ftun_outbound_index_span(outbounds, outbound_count, member, strlen(member), &child)) {
      ftun_status_t status = ftun_validate_group_visit(outbounds, outbound_count, child, colors,
                                                       depth + 1u, out);
      if (status != FTUN_OK) return status;
    }
  }
  colors[index] = 2u;
  return FTUN_OK;
}

ftun_status_t ftun_config_validate_rule(const ftun_config_outbound_t *outbounds, size_t outbound_count,
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
      !ftun_outbound_exists_span(outbounds, outbound_count, outbound, outbound_length)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/rules",
                                  "rule outbound does not exist");
  }
  return FTUN_OK;
}

static ftun_status_t ftun_validate_timeouts(const ftun_config_proxy_base_t *base,
  const ftun_config_inbound_t *inbounds, size_t inbound_count,
                                            ftun_diagnostic_t *out)
{
  const uint32_t minimum_ms = 100u;
  const uint32_t maximum_ms = 600u * 1000u;
  const uint32_t maximum_idle_ms = 7u * 24u * 3600u * 1000u;
  const uint32_t maximum_progress_ms = 3600u * 1000u;
  size_t index;
  if (base->timeouts.handshake_ms < minimum_ms ||
      base->timeouts.handshake_ms > maximum_ms) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/base/timeouts/handshake",
                                  "handshake timeout is out of range");
  }
  if (base->timeouts.connect_ms < minimum_ms ||
      base->timeouts.connect_ms > maximum_ms) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/base/timeouts/connect",
                                  "connect timeout is out of range");
  }
  if (base->timeouts.reply_ms < minimum_ms ||
      base->timeouts.reply_ms > maximum_ms) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/base/timeouts/reply",
                                  "reply timeout is out of range");
  }
  if (base->timeouts.write_progress_ms < 1000u ||
      base->timeouts.write_progress_ms > maximum_progress_ms) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/base/timeouts/write-progress",
                                  "write progress timeout is out of range");
  }
  if (base->timeouts.tcp_idle_ms > maximum_idle_ms ||
      (base->timeouts.tcp_idle_ms != 0u && base->timeouts.tcp_idle_ms < 1000u)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/base/timeouts/tcp-idle",
                                  "TCP idle timeout is out of range");
  }
  if (base->timeouts.udp_idle_ms < 1000u ||
      base->timeouts.udp_idle_ms > maximum_idle_ms) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/base/timeouts/udp-idle",
                                  "UDP idle timeout is out of range");
  }
  if (base->timeouts.keepalive.enabled) {
    uint64_t detection_ms;
    if (base->timeouts.keepalive.idle_s < 1u ||
        base->timeouts.keepalive.idle_s > 7200u ||
        base->timeouts.keepalive.interval_s < 1u ||
        base->timeouts.keepalive.interval_s > 600u ||
        base->timeouts.keepalive.count < 1u ||
        base->timeouts.keepalive.count > 20u) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/base/timeouts/tcp-keepalive",
                                    "TCP keepalive values are out of range");
    }
    detection_ms = ((uint64_t)base->timeouts.keepalive.idle_s +
      (uint64_t)base->timeouts.keepalive.interval_s *
      base->timeouts.keepalive.count) * 1000u;
    if (base->timeouts.write_progress_ms <= detection_ms) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/base/timeouts/write-progress",
        "write progress timeout must exceed the keepalive detection time");
    }
  }
  for (index = 0u; index < inbound_count; index++) {
    uint32_t idle = inbounds[index].tcp_idle_ms;
    if (idle != 0u && (idle < 1000u || idle > maximum_idle_ms)) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/inbounds",
                                    "inbound TCP idle timeout is out of range");
    }
  }
  return FTUN_OK;
}

ftun_status_t ftun_config_validate_proxy_base(const ftun_config_proxy_base_t *base,
  const ftun_config_inbound_t *inbounds, size_t inbound_count, ftun_diagnostic_t *out)
{
  if (base->capacity.tcp_flows < FTUN_CONFIG_CAPACITY_MINIMUM ||
      base->capacity.tcp_flows > FTUN_CONFIG_CAPACITY_MAXIMUM) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID,
                                  "/base/capacity/tcp-flows",
                                  "TCP flow capacity is out of range");
  }
  if (base->capacity.udp_flows < FTUN_CONFIG_CAPACITY_MINIMUM ||
      base->capacity.udp_flows > FTUN_CONFIG_CAPACITY_MAXIMUM) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID,
                                  "/base/capacity/udp-flows",
                                  "UDP flow capacity is out of range");
  }
  if (base->capacity.udp_associations <
        FTUN_CONFIG_CAPACITY_MINIMUM ||
      base->capacity.udp_associations >
        FTUN_CONFIG_CAPACITY_MAXIMUM) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID,
                                  "/base/capacity/udp-associations",
                                  "UDP association capacity is out of range");
  }
  {
    ftun_status_t timeouts = ftun_validate_timeouts(base, inbounds, inbound_count, out);
    if (timeouts != FTUN_OK) return timeouts;
  }
  if (!ftun_path_valid(base->cache_file)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/base/cache-file",
                                  "cache file path is invalid");
  }
  return FTUN_OK;
}

ftun_status_t ftun_config_validate_outbounds(ftun_budget_t *budget,
  const ftun_config_outbound_t *outbounds, size_t outbound_count,
                                             ftun_diagnostic_t *out)
{
  uint8_t *colors;
  ftun_reservation_t workspace = (ftun_reservation_t){0};
  size_t index;
  size_t other;
  for (index = 0u; index < outbound_count; index++) {
    const ftun_config_outbound_t *outbound = &outbounds[index];
    if (!ftun_name_valid(outbound->name) || strcmp(outbound->name, "DIRECT") == 0 ||
        strcmp(outbound->name, "REJECT") == 0) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/outbounds",
                                    "outbound name is invalid or reserved");
    }
    for (other = 0u; other < index; other++) {
      if (strcmp(outbound->name, outbounds[other].name) == 0) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/outbounds",
                                      "outbound name is duplicated");
      }
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
      if (!ftun_name_valid(member) || !ftun_outbound_exists(outbounds, outbound_count, member)) {
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

      if (!ftun_duration_parse_ms(outbound->interval, &interval) ||
          !ftun_duration_parse_ms(outbound->timeout, &timeout) || timeout > interval) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/outbounds",
                                      "health check durations are invalid");
      }
    }
  }
  if (budget != NULL && ftun_budget_reserve(budget,
      outbound_count == 0u ? 1u : outbound_count, &workspace) != FTUN_OK) {
    return ftun_config_diagnostic(out, FTUN_E_LIMIT, "/outbounds",
                                  "cannot reserve outbound graph workspace");
  }
  colors = (uint8_t *)calloc(outbound_count == 0u ? 1u : outbound_count,
                             sizeof(*colors));
  if (colors == NULL) {
    (void)ftun_reservation_release(&workspace);
    return ftun_config_diagnostic(out, FTUN_E_LIMIT, "/outbounds",
                                  "cannot allocate outbound graph workspace");
  }
  for (index = 0u; index < outbound_count; index++) {
    ftun_status_t status = ftun_validate_group_visit(outbounds, outbound_count, index, colors, 1u, out);
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

ftun_status_t ftun_config_validate_inbounds(const ftun_config_inbound_t *inbounds, size_t inbound_count,
  const ftun_config_outbound_t *outbounds, size_t outbound_count,
                                            ftun_diagnostic_t *out)
{
  size_t index;
  size_t other;
  size_t tun_count = 0u;
  for (index = 0u; index < inbound_count; index++) {
    const ftun_config_inbound_t *inbound = &inbounds[index];
    if (!ftun_name_valid(inbound->name)) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/inbounds",
                                    "inbound name is invalid");
    }
    for (other = 0u; other < index; other++) {
      if (strcmp(inbound->name, inbounds[other].name) == 0) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/inbounds",
                                      "inbound name is duplicated");
      }
    }
    if (inbound->outbound == NULL ||
        (inbound->outbound[0] != '\0' && !ftun_outbound_exists(outbounds, outbound_count, inbound->outbound))) {
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
  for (index = 0u; index < inbound_count; index++) {
    ftun_config_listener_t left;
    if (inbounds[index].kind == FTUN_CONFIG_INBOUND_TUN) continue;
    (void)ftun_listen_address(inbounds[index].listen, &left);
    for (other = index + 1u; other < inbound_count; other++) {
      ftun_config_listener_t right;
      if (inbounds[other].kind == FTUN_CONFIG_INBOUND_TUN) continue;
      (void)ftun_listen_address(inbounds[other].listen, &right);
      if (ftun_listener_conflict(&left, &right)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/inbounds",
          "inbound listeners conflict");
      }
    }
  }
  return FTUN_OK;
}

ftun_status_t ftun_config_validate_frs(const ftun_config_frs_t *frs,
  const ftun_config_outbound_t *outbounds, size_t outbound_count,
                                       ftun_diagnostic_t *out)
{
  uint64_t ignored;
  uint32_t address = 0u;
  int is_ipv4 = 0;
  if (!frs->active) return FTUN_OK;
  if (frs->path != NULL && !ftun_path_valid(frs->path)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/frs/path",
                                  "FRS path is invalid");
  }
  if (!frs->auto_update || frs->url == NULL ||
      frs->url[0] == '\0') return FTUN_OK;
  if (!ftun_http_url(frs->url, &address, &is_ipv4)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/frs/url",
                                  "FRS update URL is invalid");
  }
  if (!ftun_duration_parse_ms(frs->update_interval, &ignored)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/frs/update-interval",
                                  "FRS update interval is invalid");
  }
  if (!ftun_outbound_exists(outbounds, outbound_count, frs->update_outbound)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/frs/update-outbound",
                                  "FRS update outbound does not exist");
  }


  return FTUN_OK;
}
