#include "rule.h"

#if defined(FTUN_HAVE_MODULE_FRS)
#include "frs/domain.h"
#include "frs/frs.h"
#include "frs/ip.h"
#endif

#include <stdlib.h>
#include <string.h>

/* 需求 REQ-ROUTE-001；任务 TASK-ROUTE-002；目标 0.3.0；验收 TEST-ROUTE-002。 */

static unsigned char ftun_rule_ascii_lower(unsigned char byte)
{
  if (byte >= (unsigned char)'A' && byte <= (unsigned char)'Z') {
    return (unsigned char)(byte + ((unsigned char)'a' - (unsigned char)'A'));
  }
  return byte;
}

static int ftun_rule_string_equal_fold(ftun_string_t left,
                                       ftun_string_t right)
{
  size_t index;
  while (left.length != 0u && left.data[left.length - 1u] == '.') left.length--;
  while (right.length != 0u && right.data[right.length - 1u] == '.') right.length--;
  if (left.length != right.length || left.data == NULL || right.data == NULL) {
    return 0;
  }
  for (index = 0u; index < left.length; index++) {
    if (ftun_rule_ascii_lower((unsigned char)left.data[index]) !=
        ftun_rule_ascii_lower((unsigned char)right.data[index])) return 0;
  }
  return 1;
}

static int ftun_rule_type_equal(ftun_string_t type, const char *value)
{
  size_t length = strlen(value);
  size_t index;
  if (type.data == NULL || type.length != length) return 0;
  for (index = 0u; index < length; index++) {
    if (ftun_rule_ascii_lower((unsigned char)type.data[index]) !=
        ftun_rule_ascii_lower((unsigned char)value[index])) return 0;
  }
  return 1;
}

static int ftun_rule_string_contains_fold(ftun_string_t value,
                                          ftun_string_t needle)
{
  size_t offset;
  size_t index;
  if (value.data == NULL || needle.data == NULL || needle.length == 0u ||
      needle.length > value.length) return 0;
  for (offset = 0u; offset <= value.length - needle.length; offset++) {
    for (index = 0u; index < needle.length; index++) {
      if (ftun_rule_ascii_lower((unsigned char)value.data[offset + index]) !=
          ftun_rule_ascii_lower((unsigned char)needle.data[index])) break;
    }
    if (index == needle.length) return 1;
  }
  return 0;
}

static int ftun_rule_domain_valid(ftun_string_t domain)
{
  size_t effective;
  size_t start = 0u;
  size_t index;
  if (domain.data == NULL || domain.length == 0u || domain.length > 254u ||
      memchr(domain.data, '\0', domain.length) != NULL) return 0;
  effective = domain.length;
  if (domain.data[effective - 1u] == '.') effective--;
  if (effective == 0u || effective > 253u) return 0;
  for (index = 0u; index <= effective; index++) {
    if (index == effective || domain.data[index] == '.') {
      size_t length = index - start;
      size_t cursor;
      if (length == 0u || length > 63u || domain.data[start] == '-' ||
          domain.data[index - 1u] == '-') return 0;
      for (cursor = start; cursor < index; cursor++) {
        unsigned char byte = (unsigned char)domain.data[cursor];
        if (!((byte >= (unsigned char)'A' && byte <= (unsigned char)'Z') ||
              (byte >= (unsigned char)'a' && byte <= (unsigned char)'z') ||
              (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
              byte == (unsigned char)'-')) return 0;
      }
      start = index + 1u;
    }
  }
  return 1;
}

static int ftun_rule_domain(const ftun_metadata_t *metadata,
                            ftun_string_t *out)
{
  memset(out, 0, sizeof(*out));
  if ((metadata->known_fields & FTUN_META_DOMAIN) != 0u) {
    *out = metadata->domain;
  } else if (metadata->original_target.kind == FTUN_ADDRESS_DOMAIN) {
    *out = metadata->original_target.domain;
  } else {
    return 0;
  }
  return ftun_rule_domain_valid(*out);
}

static uint32_t ftun_rule_ipv4_value(const uint8_t address[4])
{
  return ((uint32_t)address[0] << 24u) |
         ((uint32_t)address[1] << 16u) |
         ((uint32_t)address[2] << 8u) |
         (uint32_t)address[3];
}

ftun_status_t ftun_rule_address_match(const ftun_rule_t *rule,
                                      const ftun_endpoint_t *address,
                                      bool *out)
{
  if (out != NULL) *out = false;
  if (rule == NULL || address == NULL || out == NULL ||
      address->kind != FTUN_ADDRESS_IPV4 || address->domain.length != 0u) {
    return FTUN_E_INVALID;
  }
  if (rule->kind == FTUN_RULE_IP_CIDR ||
      rule->kind == FTUN_RULE_SRC_IP_CIDR) {
    uint32_t value = ftun_rule_ipv4_value(address->address);
    *out = (value & rule->network_mask) == rule->network_address;
    return FTUN_OK;
  }
  if (rule->kind == FTUN_RULE_FRS_IP) {
#if defined(FTUN_HAVE_MODULE_FRS)
    if (rule->frs_set == NULL) return FTUN_E_STATE_CORRUPT;
    return ftun_frs_ip_contains(rule->frs_set, address->address, out);
#else
    return FTUN_E_UNSUPPORTED;
#endif
  }
  return FTUN_E_INVALID;
}

static ftun_status_t ftun_rule_match_ip(const ftun_rule_t *rule,
                                        const ftun_metadata_t *metadata,
                                        ftun_match_result_t *out)
{
  ftun_string_t domain;
  size_t index;
  bool matched;
  ftun_status_t status;
  if (metadata->original_target.kind == FTUN_ADDRESS_IPV4 &&
      !metadata->original_is_fake) {
    status = ftun_rule_address_match(rule, &metadata->original_target,
                                     &matched);
    if (status != FTUN_OK) return status;
    out->matched = matched;
    return FTUN_OK;
  }
  if (metadata->resolved_count != 0u) {
    if (metadata->resolved == NULL) return FTUN_E_INVALID;
    for (index = 0u; index < metadata->resolved_count; index++) {
      status = ftun_rule_address_match(rule, &metadata->resolved[index],
                                       &matched);
      if (status != FTUN_OK) return status;
      if (matched) out->matched = true;
    }
    return FTUN_OK;
  }
  if (ftun_rule_domain(metadata, &domain)) out->needs_resolve = true;
  return FTUN_OK;
}

ftun_status_t ftun_rule_match(const ftun_rule_t *rule,
                              const ftun_metadata_t *metadata,
                              ftun_match_result_t *out)
{
  const uint32_t known = FTUN_META_SOURCE | FTUN_META_PORT |
                         FTUN_META_NETWORK | FTUN_META_DOMAIN;
  ftun_string_t domain;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (rule == NULL || metadata == NULL || out == NULL ||
      metadata->generation == 0u ||
      (metadata->known_fields & ~known) != 0u ||
      (metadata->resolved_count != 0u && metadata->resolved == NULL)) {
    return FTUN_E_INVALID;
  }
  switch (rule->kind) {
    case FTUN_RULE_SRC_IP_CIDR:
      if ((metadata->known_fields & FTUN_META_SOURCE) == 0u ||
          metadata->source.kind != FTUN_ADDRESS_IPV4) return FTUN_OK;
      return ftun_rule_address_match(rule, &metadata->source, &out->matched);
    case FTUN_RULE_IP_CIDR:
    case FTUN_RULE_FRS_IP:
      return ftun_rule_match_ip(rule, metadata, out);
    case FTUN_RULE_DOMAIN:
    case FTUN_RULE_DOMAIN_SUFFIX:
    case FTUN_RULE_DOMAIN_KEYWORD:
    case FTUN_RULE_FRS_DOMAIN:
      if (!ftun_rule_domain(metadata, &domain)) return FTUN_OK;
      if (rule->kind == FTUN_RULE_DOMAIN) {
        out->matched = ftun_rule_string_equal_fold(domain, rule->operand) != 0;
      } else if (rule->kind == FTUN_RULE_DOMAIN_SUFFIX) {
        size_t domain_length = domain.length;
        size_t suffix_length = rule->operand.length;
        while (domain_length != 0u && domain.data[domain_length - 1u] == '.') {
          domain_length--;
        }
        out->matched = ftun_rule_string_equal_fold(domain, rule->operand) != 0 ||
          (domain_length > suffix_length &&
           domain.data[domain_length - suffix_length - 1u] == '.' &&
           ftun_rule_string_equal_fold(
             (ftun_string_t){domain.data + domain_length - suffix_length,
                             suffix_length}, rule->operand));
      } else if (rule->kind == FTUN_RULE_DOMAIN_KEYWORD) {
        out->matched = ftun_rule_string_contains_fold(domain, rule->operand) != 0;
      } else {
#if defined(FTUN_HAVE_MODULE_FRS)
        char normalized[254];
        size_t length = domain.length;
        size_t index;
        ftun_string_t normalized_domain;
        if (rule->frs_set == NULL) return FTUN_E_STATE_CORRUPT;
        if (length != 0u && domain.data[length - 1u] == '.') length--;
        if (length == 0u || length > 253u) return FTUN_E_INVALID;
        for (index = 0u; index < length; index++) {
          normalized[index] = (char)ftun_rule_ascii_lower(
            (unsigned char)domain.data[index]);
        }
        normalized_domain.data = normalized;
        normalized_domain.length = length;
        return ftun_frs_domain_contains(rule->frs_set, normalized_domain,
                                        &out->matched);
#else
        return FTUN_E_UNSUPPORTED;
#endif
      }
      return FTUN_OK;
    case FTUN_RULE_DST_PORT:
      if ((metadata->known_fields & FTUN_META_PORT) != 0u) {
        out->matched = metadata->original_target.port == rule->port;
      }
      return FTUN_OK;
    case FTUN_RULE_NETWORK:
      if ((metadata->known_fields & FTUN_META_NETWORK) != 0u) {
        out->matched = metadata->network == rule->network;
      }
      return FTUN_OK;
    case FTUN_RULE_MATCH:
      out->matched = true;
      return FTUN_OK;
    default:
      return FTUN_E_INVALID;
  }
}

static int ftun_rule_decimal(ftun_string_t value, uint32_t maximum,
                             uint32_t *out)
{
  uint32_t result = 0u;
  size_t index;
  if (value.data == NULL || value.length == 0u ||
      (value.length > 1u && value.data[0] == '0')) return 0;
  for (index = 0u; index < value.length; index++) {
    uint32_t digit;
    if (value.data[index] < '0' || value.data[index] > '9') return 0;
    digit = (uint32_t)(value.data[index] - '0');
    if (result > (maximum - digit) / 10u) return 0;
    result = result * 10u + digit;
  }
  *out = result;
  return 1;
}

static int ftun_rule_cidr(ftun_string_t value, uint32_t *address,
                          uint32_t *mask)
{
  const char *slash;
  size_t cursor = 0u;
  uint32_t result = 0u;
  uint32_t prefix;
  size_t part;
  if (value.data == NULL || value.length == 0u) return 0;
  slash = (const char *)memchr(value.data, '/', value.length);
  if (slash == NULL) return 0;
  for (part = 0u; part < 4u; part++) {
    size_t end = cursor;
    uint32_t octet;
    size_t address_length = (size_t)(slash - value.data);
    while (end < address_length && value.data[end] != '.') end++;
    if (!ftun_rule_decimal((ftun_string_t){value.data + cursor, end - cursor},
                           255u, &octet)) return 0;
    result = (result << 8u) | octet;
    if (part == 3u) {
      if (end != address_length) return 0;
    } else {
      if (end == address_length) return 0;
      cursor = end + 1u;
    }
  }
  if (!ftun_rule_decimal(
        (ftun_string_t){slash + 1u,
                        value.length - (size_t)(slash + 1u - value.data)},
        32u, &prefix)) return 0;
  *mask = prefix == 0u ? 0u : UINT32_MAX << (32u - prefix);
  *address = result & *mask;
  return result == *address;
}

static ftun_status_t ftun_rule_resolve_outbound(
  ftun_string_t name, ftun_rule_outbound_resolver_fn resolver,
  void *resolver_user, uint32_t *out)
{
  static const char direct[] = "DIRECT";
  static const char reject[] = "REJECT";
  if (name.length == sizeof(direct) - 1u &&
      memcmp(name.data, direct, sizeof(direct) - 1u) == 0) {
    *out = FTUN_OUTBOUND_ID_DIRECT;
    return FTUN_OK;
  }
  if (name.length == sizeof(reject) - 1u &&
      memcmp(name.data, reject, sizeof(reject) - 1u) == 0) {
    *out = FTUN_OUTBOUND_ID_REJECT;
    return FTUN_OK;
  }
  if (resolver == NULL) return FTUN_E_INVALID;
  return resolver(name, out, resolver_user);
}

ftun_status_t ftun_rule_compile_with_frs(
  const char *text, ftun_rule_outbound_resolver_fn resolver,
  void *resolver_user, ftun_rule_frs_bind_fn frs_bind, void *frs_user,
  ftun_rule_t **out)
{
  ftun_rule_t *rule;
  const char *first;
  const char *second;
  ftun_string_t type;
  ftun_string_t operand = {NULL, 0u};
  ftun_string_t outbound;
  uint32_t number;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (text == NULL || text[0] == '\0' || out == NULL) return FTUN_E_INVALID;
  first = strchr(text, ',');
  if (first == NULL) return FTUN_E_INVALID;
  type = (ftun_string_t){text, (size_t)(first - text)};
  second = strchr(first + 1u, ',');
  if (ftun_rule_type_equal(type, "MATCH")) {
    if (second != NULL) return FTUN_E_INVALID;
    outbound = (ftun_string_t){first + 1u, strlen(first + 1u)};
  } else {
    if (second == NULL || strchr(second + 1u, ',') != NULL) {
      return FTUN_E_INVALID;
    }
    operand = (ftun_string_t){first + 1u, (size_t)(second - first - 1u)};
    outbound = (ftun_string_t){second + 1u, strlen(second + 1u)};
  }
  if (outbound.length == 0u) return FTUN_E_INVALID;
  rule = (ftun_rule_t *)calloc(1u, sizeof(*rule));
  if (rule == NULL) return FTUN_E_LIMIT;
  if (ftun_rule_type_equal(type, "SRC-IP-CIDR")) {
    rule->kind = FTUN_RULE_SRC_IP_CIDR;
  } else if (ftun_rule_type_equal(type, "IP-CIDR")) {
    rule->kind = FTUN_RULE_IP_CIDR;
  } else if (ftun_rule_type_equal(type, "DOMAIN")) {
    rule->kind = FTUN_RULE_DOMAIN;
  } else if (ftun_rule_type_equal(type, "DOMAIN-SUFFIX")) {
    rule->kind = FTUN_RULE_DOMAIN_SUFFIX;
  } else if (ftun_rule_type_equal(type, "DOMAIN-KEYWORD")) {
    rule->kind = FTUN_RULE_DOMAIN_KEYWORD;
  } else if (ftun_rule_type_equal(type, "FRS-IP")) {
    rule->kind = FTUN_RULE_FRS_IP;
  } else if (ftun_rule_type_equal(type, "FRS-DOMAIN")) {
    rule->kind = FTUN_RULE_FRS_DOMAIN;
  } else if (ftun_rule_type_equal(type, "DST-PORT")) {
    rule->kind = FTUN_RULE_DST_PORT;
  } else if (ftun_rule_type_equal(type, "NETWORK")) {
    rule->kind = FTUN_RULE_NETWORK;
  } else if (ftun_rule_type_equal(type, "MATCH")) {
    rule->kind = FTUN_RULE_MATCH;
  } else {
    status = FTUN_E_UNSUPPORTED;
    goto fail;
  }
  status = ftun_rule_resolve_outbound(outbound, resolver, resolver_user,
                                      &rule->outbound_id);
  if (status != FTUN_OK) goto fail;
  if (rule->kind == FTUN_RULE_FRS_IP || rule->kind == FTUN_RULE_FRS_DOMAIN) {
    uint16_t kind = rule->kind == FTUN_RULE_FRS_IP ? 1u : 2u;
    if (operand.length == 0u || frs_bind == NULL) {
      status = frs_bind == NULL ? FTUN_E_UNSUPPORTED : FTUN_E_INVALID;
      goto fail;
    }
    status = frs_bind(kind, operand, &rule->frs_set, frs_user);
    if (status != FTUN_OK) goto fail;
  } else if (rule->kind == FTUN_RULE_SRC_IP_CIDR ||
      rule->kind == FTUN_RULE_IP_CIDR) {
    if (!ftun_rule_cidr(operand, &rule->network_address,
                        &rule->network_mask)) {
      status = FTUN_E_INVALID;
      goto fail;
    }
  } else if (rule->kind == FTUN_RULE_DST_PORT) {
    if (!ftun_rule_decimal(operand, 65535u, &number) || number == 0u) {
      status = FTUN_E_INVALID;
      goto fail;
    }
    rule->port = (uint16_t)number;
  } else if (rule->kind == FTUN_RULE_NETWORK) {
    if (operand.length == 3u && memcmp(operand.data, "tcp", 3u) == 0) {
      rule->network = 1u;
    } else if (operand.length == 3u &&
               memcmp(operand.data, "udp", 3u) == 0) {
      rule->network = 2u;
    } else {
      status = FTUN_E_INVALID;
      goto fail;
    }
  } else if (rule->kind != FTUN_RULE_MATCH) {
    size_t index;
    if (operand.length == 0u) {
      status = FTUN_E_INVALID;
      goto fail;
    }
    rule->owned_operand = (char *)malloc(operand.length + 1u);
    if (rule->owned_operand == NULL) {
      status = FTUN_E_LIMIT;
      goto fail;
    }
    for (index = 0u; index < operand.length; index++) {
      rule->owned_operand[index] = (char)ftun_rule_ascii_lower(
        (unsigned char)operand.data[index]);
    }
    rule->owned_operand[operand.length] = '\0';
    rule->operand = (ftun_string_t){rule->owned_operand, operand.length};
  }
  *out = rule;
  return FTUN_OK;

fail:
#if defined(FTUN_HAVE_MODULE_FRS)
  (void)ftun_frs_set_release(&rule->frs_set);
#endif
  free(rule->owned_operand);
  free(rule);
  return status;
}

ftun_status_t ftun_rule_compile(const char *text,
                                ftun_rule_outbound_resolver_fn resolver,
                                void *resolver_user,
                                ftun_rule_t **out)
{
  return ftun_rule_compile_with_frs(text, resolver, resolver_user, NULL, NULL,
                                    out);
}

ftun_status_t ftun_rule_destroy(ftun_rule_t **rule)
{
  ftun_rule_t *owned;
  if (rule == NULL) return FTUN_E_INVALID;
  owned = *rule;
  if (owned == NULL) return FTUN_OK;
#if defined(FTUN_HAVE_MODULE_FRS)
  if (ftun_frs_set_release(&owned->frs_set) != FTUN_OK) {
    return FTUN_E_STATE_CORRUPT;
  }
#endif
  free(owned->owned_operand);
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *rule = NULL;
  return FTUN_OK;
}
