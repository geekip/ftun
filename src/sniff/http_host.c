#include "http_host.h"
#include <string.h>

/* REQ-SNIFF-001 / TASK-SNIFF-003 / TEST-SNIFF-003，目标 0.5.0：
 * ftun_sniff_http_host 有界解析 HTTP/1 Host 且输入只读。 */

#define FTUN_SNIFF_HTTP_MAX_BYTES 16384u

static int ftun_http_equal(const uint8_t *data, size_t length,
                           const char *literal)
{
  size_t index;
  for (index = 0u; literal[index] != '\0'; index++) {
    unsigned char value;
    if (index >= length) return 0;
    value = data[index];
    if (value >= 'A' && value <= 'Z') value += (unsigned char)('a' - 'A');
    if (value != (unsigned char)literal[index]) return 0;
  }
  return index == length;
}

static int ftun_http_token(uint8_t value)
{
  if ((value >= '0' && value <= '9') ||
      (value >= 'A' && value <= 'Z') ||
      (value >= 'a' && value <= 'z')) return 1;
  switch (value) {
    case '!': case '#': case '$': case '%': case '&': case '\'':
    case '*': case '+': case '-': case '.': case '^': case '_':
    case '`': case '|': case '~': return 1;
    default: return 0;
  }
}

static int ftun_http_request_line(const uint8_t *data, size_t length)
{
  size_t first = 0u;
  size_t second;
  size_t index;
  while (first < length && data[first] != ' ') first++;
  if (first == 0u || first == length) return 0;
  for (index = 0u; index < first; index++) {
    if (!ftun_http_token(data[index])) return 0;
  }
  second = first + 1u;
  while (second < length && data[second] != ' ') {
    if (data[second] < 0x21u || data[second] > 0x7eu) return 0;
    second++;
  }
  if (second == first + 1u || second == length) return 0;
  return (length - second - 1u == 8u) &&
    (memcmp(data + second + 1u, "HTTP/1.0", 8u) == 0 ||
     memcmp(data + second + 1u, "HTTP/1.1", 8u) == 0);
}

static int ftun_http_domain(ftun_sniff_result_t *out, const uint8_t *value,
                            size_t length)
{
  size_t index;
  size_t domain_length = length;
  size_t label = 0u;
  while (domain_length != 0u && value[domain_length - 1u] >= '0' &&
         value[domain_length - 1u] <= '9') domain_length--;
  if (domain_length != length) {
    size_t port_start = domain_length;
    unsigned long port = 0u;
    if (domain_length == 0u || value[domain_length - 1u] != ':') return 0;
    domain_length--;
    if (port_start == length) return 0;
    while (port_start < length) {
      port = port * 10u + (unsigned long)(value[port_start++] - '0');
      if (port > 65535u) return 0;
    }
    if (port == 0u) return 0;
  }
  if (domain_length == 0u || domain_length >= FTUN_SNIFF_DOMAIN_BYTES ||
      value[0] == '.' || value[domain_length - 1u] == '.') return 0;
  for (index = 0u; index < domain_length; index++) {
    unsigned char byte = value[index];
    if (byte == '.') {
      if (label == 0u || label > 63u) return 0;
      label = 0u;
      out->domain_storage[index] = '.';
      continue;
    }
    if (!((byte >= 'a' && byte <= 'z') ||
          (byte >= 'A' && byte <= 'Z') ||
          (byte >= '0' && byte <= '9') || byte == '-')) return 0;
    if ((label == 0u && byte == '-') ||
        (index + 1u < domain_length && value[index + 1u] == '.' &&
         byte == '-')) return 0;
    out->domain_storage[index] = byte >= 'A' && byte <= 'Z'
      ? (char)(byte + ('a' - 'A')) : (char)byte;
    label++;
  }
  if (label == 0u || label > 63u) return 0;
  out->domain_storage[domain_length] = '\0';
  out->domain.data = out->domain_storage;
  out->domain.length = domain_length;
  out->found = true;
  return 1;
}

ftun_status_t ftun_sniff_http_host(ftun_bytes_t preread, ftun_sniff_result_t *out)
{
  size_t header_end = SIZE_MAX;
  size_t line = 0u;
  int found = 0;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (out == NULL || (preread.length != 0u && preread.data == NULL)) {
    return FTUN_E_INVALID;
  }
  if (preread.length > FTUN_SNIFF_HTTP_MAX_BYTES) return FTUN_E_PROTOCOL;
  if (preread.length == 0u) {
    out->need_more = true;
    return FTUN_OK;
  }
  for (line = 0u; line + 3u < preread.length; line++) {
    if (memcmp(preread.data + line, "\r\n\r\n", 4u) == 0) {
      header_end = line + 4u;
      break;
    }
  }
  if (header_end == SIZE_MAX) {
    out->need_more = true;
    return FTUN_OK;
  }
  line = 0u;
  while (line + 1u < header_end &&
         !(preread.data[line] == '\r' && preread.data[line + 1u] == '\n')) {
    unsigned char byte = preread.data[line++];
    if (byte < 0x20u || byte > 0x7eu) return FTUN_E_PROTOCOL;
  }
  if (line == 0u || line + 1u >= header_end) return FTUN_E_PROTOCOL;
  if (!ftun_http_request_line(preread.data, line)) return FTUN_E_PROTOCOL;
  line += 2u;
  while (line + 1u < header_end) {
    size_t end = line;
    size_t colon;
    size_t value_start;
    size_t value_end;
    while (end + 1u < header_end &&
           !(preread.data[end] == '\r' && preread.data[end + 1u] == '\n')) {
      end++;
    }
    if (end + 1u >= header_end) return FTUN_E_PROTOCOL;
    if (end == line) break;
    if (preread.data[line] == ' ' || preread.data[line] == '\t') {
      return FTUN_E_PROTOCOL;
    }
    colon = line;
    while (colon < end && preread.data[colon] != ':') colon++;
    if (colon == line || colon == end) return FTUN_E_PROTOCOL;
    {
      size_t index;
      for (index = line; index < colon; index++) {
        if (!ftun_http_token(preread.data[index])) return FTUN_E_PROTOCOL;
      }
      for (index = colon + 1u; index < end; index++) {
        uint8_t byte = preread.data[index];
        if ((byte < 0x20u && byte != '\t') || byte == 0x7fu) {
          return FTUN_E_PROTOCOL;
        }
      }
    }
    value_start = colon + 1u;
    while (value_start < end &&
           (preread.data[value_start] == ' ' || preread.data[value_start] == '\t')) {
      value_start++;
    }
    value_end = end;
    while (value_end > value_start &&
           (preread.data[value_end - 1u] == ' ' ||
            preread.data[value_end - 1u] == '\t')) value_end--;
    if (ftun_http_equal(preread.data + line, colon - line, "host")) {
      ftun_sniff_result_t candidate;
      memset(&candidate, 0, sizeof(candidate));
      if (!ftun_http_domain(&candidate, preread.data + value_start,
                            value_end - value_start)) return FTUN_E_PROTOCOL;
      if (found && (candidate.domain.length != out->domain.length ||
          memcmp(candidate.domain.data, out->domain.data,
                 candidate.domain.length) != 0)) return FTUN_E_PROTOCOL;
      *out = candidate;
      out->domain.data = out->domain_storage;
      found = 1;
    }
    line = end + 2u;
  }
  return FTUN_OK;
}
