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

int ftun_host_span(const char *value, size_t length, ftun_ip_t *ip, int *is_ip)
{
  ftun_ip_t address;
  bool numeric = ftun_ip_parse(value, length, &address);
  if (!numeric && !ftun_domain_span(value, length)) return 0;
  if (is_ip != NULL) *is_ip = numeric;
  if (ip != NULL) *ip = numeric ? address : (ftun_ip_t){0};
  return 1;
}
int ftun_listen_address(const char *value, ftun_config_listener_t *out)
{
  ftun_host_port_t parsed;
  ftun_ip_t address;
  if (value == NULL || !ftun_host_port_split(value, strlen(value), &parsed) ||
      !parsed.has_port || !ftun_ip_parse(parsed.host, parsed.host_length, &address)) return 0;
  if (out != NULL) *out = (ftun_config_listener_t){address, parsed.port};
  return 1;
}
int ftun_server_address(const char *value, int port_required, ftun_ip_t *ip, int *is_ip)
{
  ftun_host_port_t parsed;
  if (value == NULL || !ftun_host_port_split(value, strlen(value), &parsed) ||
      (port_required && !parsed.has_port)) return 0;
  return ftun_host_span(parsed.host, parsed.host_length, ip, is_ip);
}
int ftun_bootstrap_address(const char *value, ftun_ip_t *out)
{
  ftun_host_port_t parsed;
  ftun_ip_t address;
  if (value == NULL || !ftun_host_port_split(value, strlen(value), &parsed) ||
      !ftun_ip_parse(parsed.host, parsed.host_length, &address)) return 0;
  if (out != NULL) *out = address;
  return 1;
}
int ftun_cidr(const char *value, int require_network, ftun_config_cidr_t *out)
{
  ftun_cidr_t cidr;
  if (value == NULL || !ftun_cidr_parse(value, strlen(value), require_network != 0, &cidr)) return 0;
  if (out != NULL) *out = cidr;
  return 1;
}
int ftun_http_url(const char *value, ftun_ip_t *ip, int *is_ip)
{
  const char *authority, *end;
  char host[260];
  size_t length;
  if (value == NULL) return 0;
  if (strncmp(value, "http://", 7u) == 0) authority = value + 7u;
  else if (strncmp(value, "https://", 8u) == 0) authority = value + 8u;
  else return 0;
  end = authority;
  while (*end != '\0' && *end != '/' && *end != '?' && *end != '#') end++;
  length = (size_t)(end - authority);
  if (length == 0u || length >= sizeof(host) || memchr(authority, '@', length) != NULL) return 0;
  memcpy(host, authority, length);
  host[length] = '\0';
  if (!ftun_server_address(host, 0, ip, is_ip)) return 0;
  while (*end != '\0') {
    if ((unsigned char)*end <= 0x20u || (unsigned char)*end == 0x7fu) return 0;
    end++;
  }
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

int ftun_config_cidr_has(const ftun_config_cidr_t *cidr, const ftun_ip_t *address)
{
  return ftun_cidr_contains(cidr, address);
}
int ftun_cidr_overlap(const ftun_config_cidr_t *left, const ftun_config_cidr_t *right)
{
  return ftun_cidr_contains(left, &right->address) || ftun_cidr_contains(right, &left->address);
}
static bool unspecified(const ftun_ip_t *ip)
{
  static const uint8_t zero[16] = {0};
  return memcmp(ip->bytes, zero, ip->family == FTUN_IP_V6 ? 16u : 4u) == 0;
}
int ftun_listener_conflict(const ftun_config_listener_t *left, const ftun_config_listener_t *right)
{
  if (left->port != right->port) return 0;
  if (left->address.family != right->address.family) {
    return (left->address.family == FTUN_IP_V6 && unspecified(&left->address)) ||
      (right->address.family == FTUN_IP_V6 && unspecified(&right->address));
  }
  return ftun_ip_equal(&left->address, &right->address) ||
    unspecified(&left->address) || unspecified(&right->address);
}
