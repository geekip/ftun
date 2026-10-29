/* ftun_http_decode。 */
#include "proxy/inbound/http_codec.h"

#include <string.h>

static int ftun_http_token_byte(uint8_t value)
{
  static const char separators[] = "()<>@,;:\\\"/[]?={} \t";
  return value > 0x20u && value < 0x7fu &&
         strchr(separators, (int)value) == NULL;
}

static int ftun_http_equal_ci(const uint8_t *left, size_t left_length,
                              const char *right)
{
  size_t index;
  size_t right_length = strlen(right);
  if (left_length != right_length) return 0;
  for (index = 0u; index < left_length; index++) {
    uint8_t value = left[index];
    uint8_t expected = (uint8_t)right[index];
    if (value >= (uint8_t)'A' && value <= (uint8_t)'Z') value += 32u;
    if (expected >= (uint8_t)'A' && expected <= (uint8_t)'Z') expected += 32u;
    if (value != expected) return 0;
  }
  return 1;
}

static size_t ftun_http_find_crlf(const uint8_t *data, size_t begin,
                                  size_t length)
{
  size_t index;
  for (index = begin; index + 1u < length; index++) {
    if (data[index] == '\r' && data[index + 1u] == '\n') return index;
  }
  return SIZE_MAX;
}

static ftun_status_t ftun_http_parse_port(const uint8_t *data, size_t length,
                                          uint16_t default_port,
                                          ftun_string_t *host,
                                          uint16_t *port)
{
  size_t colon = SIZE_MAX;
  size_t index;
  uint32_t value = 0u;
  if (host == NULL || port == NULL || data == NULL || length == 0u) {
    return FTUN_E_INVALID;
  }
  for (index = 0u; index < length; index++) {
    uint8_t byte = data[index];
    if (byte == (uint8_t)'@' || byte == (uint8_t)'[' ||
        byte == (uint8_t)']' || byte <= 0x20u || byte >= 0x7fu) {
      return FTUN_E_PROTOCOL;
    }
    if (byte == (uint8_t)':') {
      if (colon != SIZE_MAX) return FTUN_E_UNSUPPORTED;
      colon = index;
    }
  }
  host->data = (const char *)data;
  host->length = colon == SIZE_MAX ? length : colon;
  if (host->length == 0u || host->length > 253u) return FTUN_E_PROTOCOL;
  if (colon == SIZE_MAX) {
    if (default_port == 0u) return FTUN_E_PROTOCOL;
    *port = default_port;
    return FTUN_OK;
  }
  if (colon + 1u == length) return FTUN_E_PROTOCOL;
  for (index = colon + 1u; index < length; index++) {
    if (data[index] < (uint8_t)'0' || data[index] > (uint8_t)'9') {
      return FTUN_E_PROTOCOL;
    }
    value = value * 10u + (uint32_t)(data[index] - (uint8_t)'0');
    if (value > UINT16_MAX) return FTUN_E_PROTOCOL;
  }
  if (value == 0u) return FTUN_E_PROTOCOL;
  *port = (uint16_t)value;
  return FTUN_OK;
}

static int ftun_http_ipv4(ftun_string_t host, uint8_t address[4])
{
  size_t part = 0u;
  size_t index = 0u;
  while (part < 4u) {
    unsigned int value = 0u;
    size_t digits = 0u;
    while (index < host.length && host.data[index] >= '0' &&
           host.data[index] <= '9') {
      value = value * 10u + (unsigned int)(host.data[index] - '0');
      if (value > 255u || ++digits > 3u) return 0;
      index++;
    }
    if (digits == 0u) return 0;
    address[part++] = (uint8_t)value;
    if (part == 4u) return index == host.length;
    if (index >= host.length || host.data[index++] != '.') return 0;
  }
  return 0;
}

static int ftun_http_domain_valid(ftun_string_t host)
{
  size_t effective = host.length;
  size_t start = 0u;
  size_t index;
  if (host.data == NULL || effective == 0u || effective > 253u) return 0;
  if (host.data[effective - 1u] == '.') effective--;
  if (effective == 0u) return 0;
  for (index = 0u; index <= effective; index++) {
    if (index == effective || host.data[index] == '.') {
      size_t length = index - start;
      size_t cursor;
      if (length == 0u || length > 63u || host.data[start] == '-' ||
          host.data[index - 1u] == '-') return 0;
      for (cursor = start; cursor < index; cursor++) {
        uint8_t byte = (uint8_t)host.data[cursor];
        if (!((byte >= (uint8_t)'A' && byte <= (uint8_t)'Z') ||
              (byte >= (uint8_t)'a' && byte <= (uint8_t)'z') ||
              (byte >= (uint8_t)'0' && byte <= (uint8_t)'9') ||
              byte == (uint8_t)'-')) return 0;
      }
      start = index + 1u;
    }
  }
  return 1;
}

static ftun_status_t ftun_http_endpoint(const uint8_t *authority,
                                        size_t authority_length,
                                        uint16_t default_port,
                                        ftun_endpoint_t *out)
{
  ftun_string_t host;
  uint16_t port = 0u;
  ftun_status_t status;
  memset(out, 0, sizeof(*out));
  status = ftun_http_parse_port(authority, authority_length, default_port,
                                &host, &port);
  if (status != FTUN_OK) return status;
  out->port = port;
  if (ftun_http_ipv4(host, out->address)) {
    out->kind = FTUN_ADDRESS_IPV4;
  } else {
    if (!ftun_http_domain_valid(host)) return FTUN_E_PROTOCOL;
    out->kind = FTUN_ADDRESS_DOMAIN;
    out->domain = host;
  }
  return FTUN_OK;
}

static int ftun_http_authority_equal(const ftun_endpoint_t *left,
                                     const ftun_endpoint_t *right)
{
  size_t index;
  if (left->kind != right->kind || left->port != right->port) return 0;
  if (left->kind == FTUN_ADDRESS_IPV4) {
    return memcmp(left->address, right->address, 4u) == 0;
  }
  if (left->domain.length != right->domain.length) return 0;
  for (index = 0u; index < left->domain.length; index++) {
    uint8_t a = (uint8_t)left->domain.data[index];
    uint8_t b = (uint8_t)right->domain.data[index];
    if (a >= (uint8_t)'A' && a <= (uint8_t)'Z') a += 32u;
    if (b >= (uint8_t)'A' && b <= (uint8_t)'Z') b += 32u;
    if (a != b) return 0;
  }
  return 1;
}

static ftun_status_t ftun_http_decimal(const uint8_t *data, size_t length,
                                       uint64_t *out)
{
  size_t index;
  uint64_t value = 0u;
  if (length == 0u) return FTUN_E_PROTOCOL;
  for (index = 0u; index < length; index++) {
    uint64_t digit;
    if (data[index] < (uint8_t)'0' || data[index] > (uint8_t)'9') {
      return FTUN_E_PROTOCOL;
    }
    digit = (uint64_t)(data[index] - (uint8_t)'0');
    if (value > (UINT64_MAX - digit) / 10u) return FTUN_E_LIMIT;
    value = value * 10u + digit;
  }
  *out = value;
  return FTUN_OK;
}

static ftun_status_t ftun_http_decode_request_impl(ftun_bytes_t input,
                                                   ftun_http_request_t *out,
                                                   size_t *consumed)
{
  size_t line_end;
  size_t first_space = SIZE_MAX;
  size_t second_space = SIZE_MAX;
  size_t cursor;
  ftun_endpoint_t request_target;
  ftun_endpoint_t host_target;
  int host_seen = 0;
  int transfer_encoding = 0;
  int proxy_authorization_seen = 0;
  uint64_t content_length = 0u;
  int content_length_seen = 0;
  ftun_status_t status;
  if (out == NULL || consumed == NULL) return FTUN_E_INVALID;
  memset(out, 0, sizeof(*out));
  *consumed = 0u;
  if (input.length != 0u && input.data == NULL) return FTUN_E_INVALID;
  line_end = ftun_http_find_crlf(input.data, 0u, input.length);
  if (line_end == SIZE_MAX) {
    return input.length >= FTUN_HTTP_MAX_HEADER_BYTES ? FTUN_E_LIMIT : FTUN_E_AGAIN;
  }
  for (cursor = 0u; cursor < line_end; cursor++) {
    if (input.data[cursor] == (uint8_t)' ') {
      if (first_space == SIZE_MAX) first_space = cursor;
      else if (second_space == SIZE_MAX) second_space = cursor;
      else return FTUN_E_PROTOCOL;
    }
  }
  if (first_space == SIZE_MAX || second_space == SIZE_MAX || first_space == 0u ||
      first_space > FTUN_HTTP_MAX_METHOD_BYTES ||
      second_space <= first_space + 1u ||
      second_space - first_space - 1u > FTUN_HTTP_MAX_TARGET_BYTES) {
    return FTUN_E_PROTOCOL;
  }
  for (cursor = 0u; cursor < first_space; cursor++) {
    if (!ftun_http_token_byte(input.data[cursor])) return FTUN_E_PROTOCOL;
  }
  if (!(line_end - second_space == 9u &&
        (memcmp(input.data + second_space + 1u, "HTTP/1.0", 8u) == 0 ||
         memcmp(input.data + second_space + 1u, "HTTP/1.1", 8u) == 0))) {
    return FTUN_E_PROTOCOL;
  }
  out->method.data = (const char *)input.data;
  out->method.length = first_space;
  out->request_target.data = (const char *)input.data + first_space + 1u;
  out->request_target.length = second_space - first_space - 1u;
  memset(&request_target, 0, sizeof(request_target));
  if (ftun_http_equal_ci(input.data, first_space, "CONNECT")) {
    out->kind = FTUN_HTTP_PROXY_CONNECT;
    status = ftun_http_endpoint(input.data + first_space + 1u,
                                out->request_target.length, 0u,
                                &request_target);
  } else {
    const uint8_t *target = input.data + first_space + 1u;
    size_t target_length = out->request_target.length;
    size_t authority_length = 0u;
    if (target_length < 8u ||
        !ftun_http_equal_ci(target, 7u, "http://")) return FTUN_E_PROTOCOL;
    if (memchr(target + 7u, '#', target_length - 7u) != NULL) {
      return FTUN_E_PROTOCOL;
    }
    while (7u + authority_length < target_length &&
           target[7u + authority_length] != (uint8_t)'/' &&
           target[7u + authority_length] != (uint8_t)'?' &&
           target[7u + authority_length] != (uint8_t)'#') {
      authority_length++;
    }
    if (authority_length == 0u) return FTUN_E_PROTOCOL;
    out->kind = FTUN_HTTP_PROXY_FORWARD;
    status = ftun_http_endpoint(target + 7u, authority_length, 80u,
                                &request_target);
  }
  if (status != FTUN_OK) return status;

  cursor = line_end + 2u;
  while (1) {
    size_t end;
    size_t colon = SIZE_MAX;
    size_t value_begin;
    size_t value_end;
    size_t index;
    if (cursor > FTUN_HTTP_MAX_HEADER_BYTES) return FTUN_E_LIMIT;
    end = ftun_http_find_crlf(input.data, cursor, input.length);
    if (end == SIZE_MAX) {
      return input.length >= FTUN_HTTP_MAX_HEADER_BYTES ? FTUN_E_LIMIT : FTUN_E_AGAIN;
    }
    if (end == cursor) {
      cursor += 2u;
      break;
    }
    if (input.data[cursor] == (uint8_t)' ' ||
        input.data[cursor] == (uint8_t)'\t') return FTUN_E_PROTOCOL;
    for (value_begin = cursor; value_begin < end; value_begin++) {
      if (input.data[value_begin] == (uint8_t)':') {
        colon = value_begin;
        break;
      }
      if (!ftun_http_token_byte(input.data[value_begin])) return FTUN_E_PROTOCOL;
    }
    if (colon == SIZE_MAX || colon == cursor) return FTUN_E_PROTOCOL;
    value_begin = colon + 1u;
    while (value_begin < end && (input.data[value_begin] == (uint8_t)' ' ||
           input.data[value_begin] == (uint8_t)'\t')) value_begin++;
    value_end = end;
    while (value_end > value_begin && (input.data[value_end - 1u] == (uint8_t)' ' ||
           input.data[value_end - 1u] == (uint8_t)'\t')) value_end--;
    for (index = value_begin; index < value_end; index++) {
      uint8_t byte = input.data[index];
      if (byte < 0x20u || byte == 0x7fu) return FTUN_E_PROTOCOL;
    }
    if (ftun_http_equal_ci(input.data + cursor, colon - cursor, "Host")) {
      if (host_seen) return FTUN_E_PROTOCOL;
      status = ftun_http_endpoint(input.data + value_begin,
                                  value_end - value_begin,
                                  out->kind == FTUN_HTTP_PROXY_FORWARD ? 80u : 0u,
                                  &host_target);
      if (status != FTUN_OK) return status;
      host_seen = 1;
    } else if (ftun_http_equal_ci(input.data + cursor, colon - cursor,
                                  "Content-Length")) {
      uint64_t value = 0u;
      status = ftun_http_decimal(input.data + value_begin,
                                 value_end - value_begin, &value);
      if (status != FTUN_OK) return status;
      if (content_length_seen && value != content_length) return FTUN_E_PROTOCOL;
      content_length = value;
      content_length_seen = 1;
    } else if (ftun_http_equal_ci(input.data + cursor, colon - cursor,
                                  "Transfer-Encoding")) {
      if (value_end == value_begin) return FTUN_E_PROTOCOL;
      transfer_encoding = 1;
    } else if (ftun_http_equal_ci(input.data + cursor, colon - cursor,
                                  "Proxy-Authorization")) {
      if (proxy_authorization_seen || value_end == value_begin) {
        return FTUN_E_PROTOCOL;
      }
      out->proxy_authorization.data =
        (const char *)input.data + value_begin;
      out->proxy_authorization.length = value_end - value_begin;
      out->has_proxy_authorization = true;
      proxy_authorization_seen = 1;
    } else if (ftun_http_equal_ci(input.data + cursor, colon - cursor,
                                  "Connection") &&
               ftun_http_equal_ci(input.data + value_begin,
                                  value_end - value_begin, "close")) {
      out->connection_close = true;
    }
    cursor = end + 2u;
  }
  if (!host_seen || !ftun_http_authority_equal(&request_target, &host_target) ||
      (transfer_encoding && content_length_seen) || transfer_encoding) {
    return transfer_encoding ? FTUN_E_UNSUPPORTED : FTUN_E_PROTOCOL;
  }
  if (out->kind == FTUN_HTTP_PROXY_CONNECT && content_length_seen &&
      content_length != 0u) return FTUN_E_PROTOCOL;
  out->target = request_target;
  out->header_bytes = cursor;
  out->content_length = content_length;
  out->has_content_length = content_length_seen != 0;
  *consumed = cursor;
  return FTUN_OK;
}

ftun_status_t ftun_http_decode_request(ftun_bytes_t input,
                                       ftun_http_request_t *out,
                                       size_t *consumed)
{
  ftun_http_request_t parsed;
  size_t parsed_consumed = 0u;
  ftun_status_t status;
  if (out == NULL || consumed == NULL) return FTUN_E_INVALID;
  memset(out, 0, sizeof(*out));
  *consumed = 0u;
  status = ftun_http_decode_request_impl(input, &parsed, &parsed_consumed);
  if (status != FTUN_OK) return status;
  *out = parsed;
  *consumed = parsed_consumed;
  return FTUN_OK;
}

static ftun_status_t ftun_http_append(uint8_t *output, size_t capacity,
                                      size_t *written, const uint8_t *data,
                                      size_t length)
{
  if (length > capacity - *written) return FTUN_E_LIMIT;
  if (length != 0u) memcpy(output + *written, data, length);
  *written += length;
  return FTUN_OK;
}

ftun_status_t ftun_http_rewrite_forward(
  ftun_bytes_t input, const ftun_http_request_t *request,
  uint8_t *output, size_t capacity, size_t *written)
{
  const uint8_t *target;
  size_t authority_length = 0u;
  size_t origin_offset;
  size_t origin_length;
  size_t request_line_end;
  size_t cursor;
  size_t output_length = 0u;
  ftun_status_t status;
  if (written != NULL) *written = 0u;
  if (request == NULL || output == NULL || written == NULL ||
      input.data == NULL || request->kind != FTUN_HTTP_PROXY_FORWARD ||
      request->header_bytes > input.length || request->header_bytes < 4u ||
      request->method.data == NULL || request->request_target.data == NULL ||
      request->request_target.length < 8u || capacity == 0u) {
    return FTUN_E_INVALID;
  }
  target = (const uint8_t *)request->request_target.data;
  if (!ftun_http_equal_ci(target, 7u, "http://")) return FTUN_E_INVALID;
  while (7u + authority_length < request->request_target.length &&
         target[7u + authority_length] != (uint8_t)'/' &&
         target[7u + authority_length] != (uint8_t)'?') {
    authority_length++;
  }
  if (authority_length == 0u) return FTUN_E_INVALID;
  origin_offset = 7u + authority_length;
  origin_length = request->request_target.length - origin_offset;
  request_line_end = ftun_http_find_crlf(input.data, 0u,
                                          request->header_bytes);
  if (request_line_end == SIZE_MAX) return FTUN_E_INVALID;
  status = ftun_http_append(output, capacity, &output_length,
    (const uint8_t *)request->method.data, request->method.length);
  if (status == FTUN_OK) status = ftun_http_append(output, capacity,
    &output_length, (const uint8_t *)" ", 1u);
  if (status == FTUN_OK && origin_length == 0u) {
    status = ftun_http_append(output, capacity, &output_length,
      (const uint8_t *)"/", 1u);
  } else if (status == FTUN_OK && target[origin_offset] == (uint8_t)'?') {
    status = ftun_http_append(output, capacity, &output_length,
      (const uint8_t *)"/", 1u);
    if (status == FTUN_OK) status = ftun_http_append(output, capacity,
      &output_length, target + origin_offset, origin_length);
  } else if (status == FTUN_OK) {
    status = ftun_http_append(output, capacity, &output_length,
      target + origin_offset, origin_length);
  }
  if (status == FTUN_OK) {
    const uint8_t *version = target + request->request_target.length;
    size_t version_length;
    if (version < input.data || version > input.data + request_line_end) {
      return FTUN_E_INVALID;
    }
    version_length = request_line_end - (size_t)(version - input.data);
    status = ftun_http_append(output, capacity, &output_length,
      version, version_length + 2u);
  }
  cursor = request_line_end + 2u;
  while (status == FTUN_OK && cursor + 1u < request->header_bytes) {
    size_t end = ftun_http_find_crlf(input.data, cursor,
                                     request->header_bytes);
    size_t colon = cursor;
    bool drop;
    if (end == SIZE_MAX) return FTUN_E_INVALID;
    if (end == cursor) {
      status = ftun_http_append(output, capacity, &output_length,
        input.data + cursor, 2u);
      cursor += 2u;
      break;
    }
    while (colon < end && input.data[colon] != (uint8_t)':') colon++;
    if (colon == end) return FTUN_E_INVALID;
    drop = ftun_http_equal_ci(input.data + cursor, colon - cursor,
                              "Proxy-Authorization") ||
           ftun_http_equal_ci(input.data + cursor, colon - cursor,
                              "Proxy-Connection");
    if (!drop) status = ftun_http_append(output, capacity, &output_length,
      input.data + cursor, end + 2u - cursor);
    cursor = end + 2u;
  }
  if (status != FTUN_OK || cursor != request->header_bytes) return status;
  *written = output_length;
  return FTUN_OK;
}

ftun_status_t ftun_http_decode(ftun_bytes_t input, ftun_protocol_result_t *out)
{
  ftun_http_request_t request;
  size_t consumed = 0u;
  ftun_status_t status;
  if (out == NULL) return FTUN_E_INVALID;
  memset(out, 0, sizeof(*out));
  status = ftun_http_decode_request(input, &request, &consumed);
  if (status != FTUN_OK) return status;
  out->complete = true;
  out->consumed = consumed;
  out->target = request.target;
  return FTUN_OK;
}
