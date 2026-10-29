#include "core/config/syntax.h"
#include "util/ip.h"
#include <string.h>

ftun_status_t ftun_config_diagnostic(ftun_diagnostic_t *out,
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

int ftun_span_equal(const char *data, size_t length, const char *value)
{
  size_t value_length = strlen(value);
  return length == value_length && memcmp(data, value, length) == 0;
}

int ftun_span_equal_ascii_fold(const char *data, size_t length,
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

int ftun_name_span_valid(const char *value, size_t length)
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

int ftun_name_valid(const char *value)
{
  return value != NULL && ftun_name_span_valid(value, strlen(value));
}

int ftun_path_valid(const char *value)
{
  size_t index;
  if (value == NULL || value[0] == '\0') return 0;
  for (index = 0u; value[index] != '\0'; index++) {
    unsigned char byte = (unsigned char)value[index];
    if (byte <= 0x1fu || byte == 0x7fu) return 0;
  }
  return 1;
}

int ftun_ipv4_span(const char *value, size_t length, uint32_t *out)
{
  uint8_t bytes[4];
  if (!ftun_ipv4_parse(value, length, bytes)) return 0;
  if (out != NULL) *out = ftun_ipv4_value(bytes);
  return 1;
}

int ftun_domain_span(const char *value, size_t length)
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

int ftun_host_span(const char *value, size_t length, uint32_t *ipv4,
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

int ftun_listen_address(const char *value, ftun_config_listener_t *out)
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

int ftun_server_address(const char *value, int port_required,
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

int ftun_bootstrap_address(const char *value, uint32_t *out)
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

int ftun_cidr(const char *value, int require_network,
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

int ftun_http_url(const char *value, uint32_t *ipv4, int *is_ipv4)
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

int ftun_list_contains(const ftun_config_string_list_t *list,
                              const char *value)
{
  size_t index;
  if (list == NULL || value == NULL) return 0;
  for (index = 0u; index < list->count; index++) {
    if (list->items[index] != NULL && strcmp(list->items[index], value) == 0) return 1;
  }
  return 0;
}

int ftun_ascii_token(const char *value, size_t length)
{
  size_t index;
  if (value == NULL || length == 0u) return 0;
  for (index = 0u; index < length; index++) {
    unsigned char byte = (unsigned char)value[index];
    if (byte < 0x21u || byte > 0x7eu || byte == ',') return 0;
  }
  return 1;
}

int ftun_config_cidr_has(const ftun_config_cidr_t *cidr, uint32_t address)
{
  return (address & cidr->mask) == cidr->address;
}

int ftun_cidr_overlap(const ftun_config_cidr_t *left,
                             const ftun_config_cidr_t *right)
{
  uint32_t mask = left->mask < right->mask ? left->mask : right->mask;
  return (left->address & mask) == (right->address & mask);
}

int ftun_listener_conflict(const ftun_config_listener_t *left,
                                  const ftun_config_listener_t *right)
{
  return left->port == right->port &&
         (left->address == right->address || left->address == 0u || right->address == 0u);
}
