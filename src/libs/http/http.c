#define _POSIX_C_SOURCE 200809L

#include "libs/http/http.h"
#include "libs/resolver/control_channel.h"

#include "libs/transport/socks5_client.h"
#include "libs/tls/tls.h"
#include "platform/clock.h"

#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "platform/file.h"

#define FTUN_HTTP_FETCH_HEADER_LIMIT (64u * 1024u)
#define FTUN_HTTP_FETCH_REDIRECTS 5u

typedef struct {
  char host[254];
  char path[2049];
  uint16_t port;
  bool https;
} ftun_http_url_t;

static ftun_status_t ftun_http_string_allocate(ftun_budget_t *budget,
  size_t length, char **out, ftun_reservation_t *out_reservation)
{
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_status_t status;
  char *value;
  *out = NULL;
  *out_reservation = (ftun_reservation_t){0};
  if (length == SIZE_MAX) return FTUN_E_LIMIT;
  status = ftun_budget_reserve(budget, length + 1u, &reservation);
  if (status != FTUN_OK) return status;
  value = (char *)malloc(length + 1u);
  if (value == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  value[length] = '\0';
  *out = value;
  *out_reservation = reservation;
  return FTUN_OK;
}

static int ftun_http_send_all(ftun_control_channel_t *channel, const uint8_t *data,
  size_t length, uint64_t deadline_ms)
{
  size_t offset = 0u;
  (void)deadline_ms;
  while (offset < length) {
    size_t amount = 0u;
    if (ftun_control_channel_write(channel, data + offset,
          length - offset, &amount) != FTUN_OK || amount == 0u) return 0;
    offset += amount;
  }
  return 1;
}

static int ftun_http_recv_all(ftun_control_channel_t *channel, uint8_t *data,
  size_t length, uint64_t deadline_ms)
{
  size_t offset = 0u;
  (void)deadline_ms;
  while (offset < length) {
    size_t amount = 0u;
    ftun_status_t status = ftun_control_channel_read(channel, data + offset,
      length - offset, &amount);
    if (status == FTUN_OK && amount != 0u) offset += amount;
    else if (status == FTUN_E_AGAIN &&
             ftun_control_channel_wait(channel) == FTUN_OK) continue;
    else return 0;
  }
  return 1;
}

static ftun_status_t ftun_http_parse_url(ftun_string_t input,
                                         ftun_http_url_t *out)
{
  const char *prefix;
  size_t prefix_length;
  size_t authority_end;
  size_t host_length;
  size_t index;
  const char *colon = NULL;
  char *tail = NULL;
  unsigned long port;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (input.data == NULL || input.length == 0u || input.length > 2048u ||
      out == NULL) return FTUN_E_INVALID;
  if (input.length >= 8u && memcmp(input.data, "https://", 8u) == 0) {
    prefix = "https://";
    prefix_length = 8u;
    out->https = true;
    out->port = 443u;
  } else if (input.length >= 7u &&
             memcmp(input.data, "http://", 7u) == 0) {
    prefix = "http://";
    prefix_length = 7u;
    out->port = 80u;
  } else {
    return FTUN_E_UNSUPPORTED;
  }
  (void)prefix;
  authority_end = prefix_length;
  while (authority_end < input.length && input.data[authority_end] != '/') {
    authority_end++;
  }
  if (authority_end == prefix_length) return FTUN_E_INVALID;
  for (index = prefix_length; index < authority_end; index++) {
    unsigned char byte = (unsigned char)input.data[index];
    if (byte == ':' && colon == NULL) colon = input.data + index;
    else if (byte <= 0x20u || byte >= 0x7fu || byte == '@' || byte == '[' ||
             byte == ']') return FTUN_E_INVALID;
  }
  host_length = colon == NULL ? authority_end - prefix_length
    : (size_t)(colon - (input.data + prefix_length));
  if (host_length == 0u || host_length >= sizeof(out->host)) {
    return FTUN_E_INVALID;
  }
  memcpy(out->host, input.data + prefix_length, host_length);
  out->host[host_length] = '\0';
  for (index = 0u; index < host_length; index++) {
    unsigned char byte = (unsigned char)out->host[index];
    if (byte >= 'A' && byte <= 'Z') out->host[index] = (char)(byte + 32u);
  }
  if (colon != NULL) {
    char service[6];
    size_t service_length = authority_end -
      (size_t)(colon - input.data) - 1u;
    if (service_length == 0u || service_length >= sizeof(service)) {
      return FTUN_E_INVALID;
    }
    memcpy(service, colon + 1u, service_length);
    service[service_length] = '\0';
    errno = 0;
    port = strtoul(service, &tail, 10);
    if (errno != 0 || tail == service || *tail != '\0' ||
        port == 0u || port > UINT16_MAX) return FTUN_E_INVALID;
    out->port = (uint16_t)port;
  }
  if (authority_end == input.length) {
    memcpy(out->path, "/", 2u);
  } else {
    size_t path_length = input.length - authority_end;
    if (path_length >= sizeof(out->path)) return FTUN_E_LIMIT;
    memcpy(out->path, input.data + authority_end, path_length);
    out->path[path_length] = '\0';
  }
  return FTUN_OK;
}

static ftun_status_t ftun_http_redirect_url(ftun_budget_t *budget, ftun_string_t base,
                                             const char *location,
                                             char **out,
                                             ftun_reservation_t *out_reservation)
{
  ftun_http_url_t parsed;
  const char *scheme;
  const char *path;
  char port[8] = {0};
  char *joined;
  size_t prefix_length;
  size_t path_length;
  size_t location_length;
  size_t total;
  size_t index;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (out_reservation != NULL) *out_reservation = (ftun_reservation_t){0};
  if (budget == NULL || location == NULL || location[0] == '\0' ||
      out == NULL || out_reservation == NULL) {
    return FTUN_E_INVALID;
  }
  location_length = strlen(location);
  if (location_length > 2048u || strpbrk(location, "\r\n") != NULL) {
    return FTUN_E_PROTOCOL;
  }
  if (strncmp(location, "http://", 7u) == 0 ||
      strncmp(location, "https://", 8u) == 0) {
    status = ftun_http_string_allocate(budget, location_length, &joined, out_reservation);
    if (status != FTUN_OK) return status;
    memcpy(joined, location, location_length);
    *out = joined;
    return FTUN_OK;
  }
  if (ftun_http_parse_url(base, &parsed) != FTUN_OK) return FTUN_E_PROTOCOL;
  scheme = parsed.https ? "https://" : "http://";
  if (location[0] == '/' && location[1] == '/') {
    if (strlen(scheme) > SIZE_MAX - location_length) return FTUN_E_LIMIT;
    total = strlen(scheme) + location_length - 2u;
    status = ftun_http_string_allocate(budget, total, &joined, out_reservation);
    if (status != FTUN_OK) return status;
    (void)snprintf(joined, total + 1u, "%s%s", scheme, location + 2u);
    *out = joined;
    return FTUN_OK;
  }
  if (parsed.port != (parsed.https ? 443u : 80u)) {
    (void)snprintf(port, sizeof(port), ":%u", (unsigned int)parsed.port);
  }
  prefix_length = strlen(scheme) + strlen(parsed.host) + strlen(port);
  if (location[0] == '/') {
    path = location;
    path_length = location_length;
  } else {
    path = parsed.path;
    path_length = strlen(parsed.path);
    for (index = path_length; index != 0u; index--) {
      if (path[index - 1u] == '/') {
        path_length = index;
        break;
      }
    }
    if (path_length > SIZE_MAX - location_length) return FTUN_E_LIMIT;
    total = prefix_length + path_length + location_length;
    if (total > 2048u) return FTUN_E_LIMIT;
    status = ftun_http_string_allocate(budget, total, &joined, out_reservation);
    if (status != FTUN_OK) return status;
    (void)snprintf(joined, total + 1u, "%s%s%s%.*s%s", scheme,
                   parsed.host, port, (int)path_length, path, location);
    *out = joined;
    return FTUN_OK;
  }
  if (prefix_length > SIZE_MAX - path_length) return FTUN_E_LIMIT;
  total = prefix_length + path_length;
  if (total > 2048u) return FTUN_E_LIMIT;
  status = ftun_http_string_allocate(budget, total, &joined, out_reservation);
  if (status != FTUN_OK) return status;
  (void)snprintf(joined, total + 1u, "%s%s%s%s", scheme, parsed.host, port,
                 path);
  *out = joined;
  return FTUN_OK;
}

typedef struct {
  ftun_control_channel_t *channel;
  uint64_t deadline_ms;
} ftun_http_socks_io_t;

static ftun_status_t ftun_http_socks_write(void *context, const uint8_t *data,
                                           size_t length)
{
  ftun_http_socks_io_t *io = (ftun_http_socks_io_t *)context;
  return ftun_http_send_all(io->channel, data, length, io->deadline_ms)
    ? FTUN_OK : FTUN_E_TIMEOUT;
}

static ftun_status_t ftun_http_socks_read(void *context, uint8_t *data,
                                          size_t length)
{
  ftun_http_socks_io_t *io = (ftun_http_socks_io_t *)context;
  return ftun_http_recv_all(io->channel, data, length, io->deadline_ms)
    ? FTUN_OK : FTUN_E_TIMEOUT;
}

static ftun_status_t ftun_http_socks_connect(
  ftun_control_channel_t *channel, const ftun_http_fetch_spec_t *spec,
  const ftun_endpoint_t *target)
{
  ftun_http_socks_io_t transport = {channel, spec->deadline_ms};
  ftun_socks5_client_io_t io = {ftun_http_socks_write, ftun_http_socks_read, &transport};
  ftun_socks5_client_options_t options = {0};
  ftun_socks5_client_result_t result;
  ftun_socks5_client_t client;
  ftun_status_t status;
  options.username = (ftun_bytes_t){(const uint8_t *)spec->proxy_username.data,
                                    spec->proxy_username.length};
  options.password = (ftun_bytes_t){(const uint8_t *)spec->proxy_password.data,
                                    spec->proxy_password.length};
  options.command = FTUN_SOCKS5_COMMAND_CONNECT;
  options.target = *target;
  status = ftun_socks5_client_init(&client, &options);
  if (status == FTUN_OK) status = ftun_socks5_client_run(&client, &io, &result);
  return status;
}

static const char *ftun_http_ca_file(void)
{
  static const char *const candidates[] = {
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem"
  };
  ftun_file_info_t info;
  size_t index;
  for (index = 0u; index < sizeof(candidates) / sizeof(candidates[0]); index++) {
    if (ftun_file_inspect_path(candidates[index], &info) == FTUN_OK && info.regular) {
      return candidates[index];
    }
  }
  return NULL;
}

static ftun_status_t ftun_http_tls_flush(ftun_tls_client_t *tls,
  ftun_control_channel_t *channel)
{
  ftun_bytes_t ciphertext;
  while (ftun_tls_client_ciphertext(tls, &ciphertext) == FTUN_OK) {
    size_t written = 0u;
    ftun_status_t status = ftun_control_channel_write(channel,
      ciphertext.data, ciphertext.length, &written);
    if (status != FTUN_OK) return status;
    status = ftun_tls_client_consume(tls, written);
    if (status != FTUN_OK) return status;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_http_tls_drain(ftun_tls_client_t *tls,
  ftun_control_channel_t *channel)
{
  ftun_status_t status;
  while ((status = ftun_http_tls_flush(tls, channel)) == FTUN_E_AGAIN) {
    status = ftun_control_channel_wait(channel);
    if (status != FTUN_OK) return status;
  }
  return status;
}

static ftun_status_t ftun_http_tls_wait(ftun_tls_client_t *tls,
  ftun_control_channel_t *channel, uint64_t deadline_ms)
{
  ftun_tls_info_t info;
  uint8_t ciphertext[4096];
  size_t capacity, length = 0u, consumed = 0u;
  ftun_status_t status = ftun_http_tls_drain(tls, channel);
  if (status != FTUN_OK) return status;
  status = ftun_tls_client_get_info(tls, &info);
  if (status != FTUN_OK || !info.wants_read) return status;
  capacity = ftun_tls_client_input_space(tls);
  assert(capacity != 0u);
  if (capacity > sizeof(ciphertext)) capacity = sizeof(ciphertext);
  status = ftun_control_channel_read(channel, ciphertext, capacity, &length);
  if (status == FTUN_E_AGAIN) return ftun_control_channel_wait(channel);
  if (status == FTUN_E_EOF) {
    ftun_tls_client_close_input(tls);
    return FTUN_OK;
  }
  if (status != FTUN_OK) return status;
  status = ftun_tls_client_feed(tls, (ftun_bytes_t){ciphertext, length}, &consumed);
  assert(status != FTUN_OK || consumed == length);
  (void)deadline_ms; /* 传输每次读写/等待都检查原绝对期限。 */
  return status;
}

static ftun_status_t ftun_http_stream_write(
  ftun_control_channel_t *channel, ftun_tls_client_t *tls, const uint8_t *data, size_t length,
  uint64_t deadline_ms)
{
  size_t offset = 0u;
  while (offset < length) {
    size_t amount = 0u;
    ftun_status_t status = tls == NULL
      ? ftun_control_channel_write(channel,
                           data + offset, length - offset, &amount)
      : ftun_tls_client_write(tls, data + offset, length - offset, &amount);
    if (status == FTUN_OK) offset += amount;
    else if (status == FTUN_E_AGAIN) {
      status = tls == NULL
        ? ftun_control_channel_wait(channel)
        : ftun_http_tls_wait(tls, channel, deadline_ms);
      if (status != FTUN_OK) return status;
    } else return status;
  }
  return tls == NULL ? FTUN_OK : ftun_http_tls_drain(tls, channel);
}

static ftun_status_t ftun_http_stream_read(
  ftun_control_channel_t *channel, ftun_tls_client_t *tls, uint8_t *data, size_t capacity,
  size_t *length, uint64_t deadline_ms)
{
  ftun_status_t status;
  for (;;) {
    status = tls == NULL
      ? ftun_control_channel_read(channel,
                          data, capacity, length)
      : ftun_tls_client_read(tls, data, capacity, length);
    if (status != FTUN_E_AGAIN) {
      if (status == FTUN_OK && tls != NULL) {
        ftun_status_t drained = ftun_http_tls_drain(tls, channel);
        if (drained != FTUN_OK) return drained;
      }
      return status;
    }
    status = tls == NULL
      ? ftun_control_channel_wait(channel)
      : ftun_http_tls_wait(tls, channel, deadline_ms);
    if (status != FTUN_OK) return status;
  }
}

static int ftun_http_ascii_equal(const uint8_t *left, size_t length,
                                 const char *right)
{
  size_t index;
  if (strlen(right) != length) return 0;
  for (index = 0u; index < length; index++) {
    if (tolower((unsigned char)left[index]) !=
        tolower((unsigned char)right[index])) return 0;
  }
  return 1;
}

static int ftun_http_redirect_status(unsigned int status)
{
  return status == 301u || status == 302u || status == 303u ||
         status == 307u || status == 308u;
}

static ftun_status_t ftun_http_decode_chunked(uint8_t *data, size_t length,
                                               size_t maximum,
                                               size_t *out_length)
{
  size_t input = 0u;
  size_t output = 0u;
  while (input < length) {
    size_t line = input;
    size_t chunk = 0u;
    size_t digits = 0u;
    while (line + 1u < length &&
           !(data[line] == '\r' && data[line + 1u] == '\n')) line++;
    if (line + 1u >= length) return FTUN_E_PROTOCOL;
    while (input < line && data[input] != ';') {
      unsigned int value;
      if (data[input] >= '0' && data[input] <= '9') value = data[input] - '0';
      else if (data[input] >= 'a' && data[input] <= 'f') value = data[input] - 'a' + 10u;
      else if (data[input] >= 'A' && data[input] <= 'F') value = data[input] - 'A' + 10u;
      else return FTUN_E_PROTOCOL;
      if (chunk > (SIZE_MAX - value) / 16u) return FTUN_E_LIMIT;
      chunk = chunk * 16u + value;
      digits++;
      input++;
    }
    if (digits == 0u) return FTUN_E_PROTOCOL;
    input = line + 2u;
    if (chunk == 0u) {
      *out_length = output;
      return FTUN_OK;
    }
    if (chunk > maximum - output || chunk > length - input ||
        length - input - chunk < 2u || data[input + chunk] != '\r' ||
        data[input + chunk + 1u] != '\n') return FTUN_E_PROTOCOL;
    memmove(data + output, data + input, chunk);
    output += chunk;
    input += chunk + 2u;
  }
  return FTUN_E_PROTOCOL;
}

ftun_status_t ftun_http_fetch_parse_response(
  ftun_budget_t *budget, uint8_t *wire, size_t wire_length, size_t maximum,
  ftun_http_fetch_result_t *out, char **location,
  ftun_reservation_t *location_reservation)
{
  size_t header_end = 0u;
  size_t cursor;
  size_t body_offset;
  size_t content_length = SIZE_MAX;
  bool chunked = false;
  if (location != NULL) *location = NULL;
  while (header_end + 3u < wire_length &&
         memcmp(wire + header_end, "\r\n\r\n", 4u) != 0) header_end++;
  if (header_end + 3u >= wire_length || header_end > FTUN_HTTP_FETCH_HEADER_LIMIT ||
      header_end < 12u || memcmp(wire, "HTTP/1.", 7u) != 0 ||
      wire[8] != ' ' || wire[9] < '0' || wire[9] > '9' ||
      wire[10] < '0' || wire[10] > '9' ||
      wire[11] < '0' || wire[11] > '9') return FTUN_E_PROTOCOL;
  out->status = (unsigned int)(wire[9] - '0') * 100u +
                (unsigned int)(wire[10] - '0') * 10u +
                (unsigned int)(wire[11] - '0');
  if (out->status < 100u || out->status > 599u) return FTUN_E_PROTOCOL;
  cursor = 0u;
  while (cursor < header_end &&
         !(wire[cursor] == '\r' && wire[cursor + 1u] == '\n')) cursor++;
  cursor += 2u;
  while (cursor < header_end) {
    size_t line_end = cursor;
    size_t colon;
    while (line_end < header_end &&
           !(wire[line_end] == '\r' && wire[line_end + 1u] == '\n')) line_end++;
    colon = cursor;
    while (colon < line_end && wire[colon] != ':') colon++;
    if (colon == line_end) return FTUN_E_PROTOCOL;
    {
      size_t value = colon + 1u;
      while (value < line_end && (wire[value] == ' ' || wire[value] == '\t')) value++;
      if (ftun_http_ascii_equal(wire + cursor, colon - cursor,
                                "content-length")) {
        size_t parsed = 0u;
        if (value == line_end) return FTUN_E_PROTOCOL;
        while (value < line_end) {
          if (wire[value] < '0' || wire[value] > '9' ||
              parsed > (SIZE_MAX - (wire[value] - '0')) / 10u) {
            return FTUN_E_PROTOCOL;
          }
          parsed = parsed * 10u + (wire[value++] - '0');
        }
        content_length = parsed;
      } else if (ftun_http_ascii_equal(wire + cursor, colon - cursor,
                                       "transfer-encoding")) {
        if (line_end - value == 7u &&
            ftun_http_ascii_equal(wire + value, 7u, "chunked")) chunked = true;
        else return FTUN_E_UNSUPPORTED;
      } else if (ftun_http_ascii_equal(wire + cursor, colon - cursor,
                                       "etag")) {
        size_t value_length = line_end - value;
        char *etag = NULL;
        ftun_reservation_t reservation = (ftun_reservation_t){0};
        ftun_status_t status = ftun_http_string_allocate(budget, value_length,
          &etag, &reservation);
        if (status != FTUN_OK) return status;
        memcpy(etag, wire + value, value_length);
        etag[value_length] = '\0';
        free(out->etag);
        (void)ftun_reservation_release(&out->etag_reservation);
        out->etag = etag;
        out->etag_reservation = reservation;
      } else if (location != NULL && ftun_http_ascii_equal(
                   wire + cursor, colon - cursor, "location")) {
        size_t value_length = line_end - value;
        char *copy = NULL;
        ftun_reservation_t reservation = (ftun_reservation_t){0};
        ftun_status_t status = ftun_http_string_allocate(budget, value_length,
          &copy, &reservation);
        if (status != FTUN_OK) return status;
        memcpy(copy, wire + value, value_length);
        copy[value_length] = '\0';
        free(*location);
        (void)ftun_reservation_release(location_reservation);
        *location = copy;
        *location_reservation = reservation;
      }
    }
    cursor = line_end + 2u;
  }
  body_offset = header_end + 4u;
  if (chunked) {
    ftun_status_t status = ftun_http_decode_chunked(wire + body_offset,
      wire_length - body_offset, maximum, &out->length);
    if (status == FTUN_OK) memmove(wire, wire + body_offset, out->length);
    return status;
  }
  out->length = wire_length - body_offset;
  if (content_length != SIZE_MAX && out->length != content_length) {
    return FTUN_E_PROTOCOL;
  }
  if (out->length > maximum) return FTUN_E_LIMIT;
  memmove(wire, wire + body_offset, out->length);
  return FTUN_OK;
}

static ftun_status_t ftun_http_fetch_once(
  const ftun_http_fetch_spec_t *spec, ftun_string_t url_text,
  ftun_tls_context_t **tls_context, ftun_http_fetch_result_t *out, char **location,
  ftun_reservation_t *location_reservation)
{
  ftun_http_url_t url;
  ftun_control_execution_t execution = {spec->budget,
    spec->generation == 0u ? 1u : spec->generation, spec->deadline_ms,
    spec->purpose == 0 ? FTUN_DIAL_PURPOSE_FRS_UPDATE : spec->purpose,
    spec->allow_system_resolver, spec->path};
  ftun_endpoint_t endpoint;
  ftun_endpoint_t proxy_endpoint;
  ftun_tls_options_t tls_options;
  ftun_tls_client_t *tls = NULL;
  uint8_t *wire = NULL;
  char *request = NULL;
  ftun_reservation_t request_reservation = (ftun_reservation_t){0};
  ftun_reservation_t wire_reservation = (ftun_reservation_t){0};
  size_t wire_capacity;
  size_t wire_length = 0u;
  size_t request_capacity;
  ftun_control_channel_t *channel = NULL;
  ftun_status_t status;
  status = ftun_http_parse_url(url_text, &url);
  if (status != FTUN_OK) return status;
  status = ftun_control_resolve(&execution, &spec->resolver,
    (ftun_string_t){url.host, strlen(url.host)}, url.port, &endpoint);
  if (status != FTUN_OK) return status;
  proxy_endpoint = spec->proxy;
  if (spec->use_proxy && proxy_endpoint.kind == FTUN_ADDRESS_DOMAIN) {
    status = ftun_control_resolve_bootstrap(&execution, &spec->resolver,
      (ftun_string_t){spec->proxy_domain,
                      strlen(spec->proxy_domain)},
      proxy_endpoint.port, &proxy_endpoint);
  }
  if (status == FTUN_OK) status = ftun_control_channel_create_execution(&execution, &channel);
  if (status == FTUN_OK) status = ftun_control_channel_connect(channel,
    spec->use_proxy ? &proxy_endpoint : &endpoint, spec->socket_mark,
    spec->purpose == 0 ? FTUN_DIAL_PURPOSE_FRS_UPDATE : spec->purpose);
  if (status == FTUN_OK && spec->use_proxy) {
    status = ftun_http_socks_connect(channel, spec, &endpoint);
  }
  if (status == FTUN_OK && url.https) {
    const char *ca_file = ftun_http_ca_file();
    if (ca_file == NULL) status = FTUN_E_REJECTED;
    memset(&tls_options, 0, sizeof(tls_options));
    tls_options.budget = spec->budget;
    tls_options.server_name.data = url.host;
    tls_options.server_name.length = strlen(url.host);
    tls_options.ca_file = ca_file;
    /* maximum_plaintext is the size of one TLS I/O operation, not a total
     * response limit.  Keep it bounded independently from the download. */
    tls_options.maximum_plaintext = 64u * 1024u;
    if (status == FTUN_OK && *tls_context == NULL) {
      status = ftun_tls_context_open(&tls_options, tls_context);
    }
    if (status == FTUN_OK) status = ftun_tls_client_create(*tls_context, &tls_options, &tls);
    while (status == FTUN_OK) {
      status = ftun_tls_client_handshake(tls);
      if (status == FTUN_E_AGAIN) {
        status = ftun_http_tls_wait(tls, channel, spec->deadline_ms);
        if (status == FTUN_OK) continue;
      }
      break;
    }
    if (status == FTUN_OK) status = ftun_http_tls_drain(tls, channel);
    if (status == FTUN_OK) out->tls_verified = true;
  }
  request_capacity = strlen(url.path) + strlen(url.host) + 256u;
  if (spec->if_none_match.length > SIZE_MAX - request_capacity ||
      spec->if_none_match.length > INT_MAX) status = FTUN_E_LIMIT;
  if (status == FTUN_OK) {
    request_capacity += spec->if_none_match.length;
    status = ftun_http_string_allocate(spec->budget, request_capacity - 1u,
      &request, &request_reservation);
  }
  if (status == FTUN_OK) {
    const bool default_port = url.port == (url.https ? 443u : 80u);
    char port_text[6] = {0};
    if (!default_port) {
      (void)snprintf(port_text, sizeof(port_text), "%u",
                     (unsigned int)url.port);
    }
    int length = snprintf(request, request_capacity,
      "GET %s HTTP/1.1\r\nHost: %s%s%s\r\nUser-Agent: FTUN/1\r\n"
      "Accept: application/octet-stream\r\nConnection: close\r\n%s%.*s%s\r\n",
      url.path, url.host,
      default_port ? "" : ":",
      port_text,
      spec->if_none_match.length == 0u ? "" : "If-None-Match: ",
      (int)spec->if_none_match.length,
      spec->if_none_match.data == NULL ? "" : spec->if_none_match.data,
      spec->if_none_match.length == 0u ? "" : "\r\n");
    if (length <= 0 || (size_t)length >= request_capacity) status = FTUN_E_LIMIT;
    else status = ftun_http_stream_write(channel, tls,
      (const uint8_t *)request, (size_t)length, spec->deadline_ms);
  }
  if (spec->maximum_bytes > SIZE_MAX - FTUN_HTTP_FETCH_HEADER_LIMIT) {
    status = FTUN_E_LIMIT;
  }
  wire_capacity = spec->maximum_bytes + FTUN_HTTP_FETCH_HEADER_LIMIT;
  if (status == FTUN_OK) status = ftun_budget_reserve(spec->budget,
    wire_capacity, &wire_reservation);
  wire = status == FTUN_OK ? (uint8_t *)malloc(wire_capacity) : NULL;
  if (status == FTUN_OK && wire == NULL) status = FTUN_E_LIMIT;
  while (status == FTUN_OK && wire_length < wire_capacity) {
    size_t amount = 0u;
    status = ftun_http_stream_read(channel, tls, wire + wire_length,
      wire_capacity - wire_length, &amount, spec->deadline_ms);
    if (status == FTUN_OK) wire_length += amount;
    else if (status == FTUN_E_EOF) status = FTUN_OK;
    if (amount == 0u) break;
  }
  if (status == FTUN_OK && wire_length == wire_capacity) status = FTUN_E_LIMIT;
  if (status == FTUN_OK) {
    status = ftun_http_fetch_parse_response(spec->budget, wire, wire_length,
      spec->maximum_bytes, out, location, location_reservation);
  }
  if (status == FTUN_OK && out->length != 0u) {
    status = ftun_budget_reserve(spec->budget, out->length, &out->reservation);
    if (status == FTUN_OK) {
      out->data = (uint8_t *)malloc(out->length);
      if (out->data == NULL) status = FTUN_E_LIMIT;
      else memcpy(out->data, wire, out->length);
    }
  }
  free(wire);
  free(request);
  (void)ftun_reservation_release(&wire_reservation);
  (void)ftun_reservation_release(&request_reservation);
  (void)ftun_tls_client_destroy(&tls);
  ftun_control_channel_drain(&channel);
  return status;
}

ftun_status_t ftun_http_fetch(const ftun_http_fetch_spec_t *spec,
                              ftun_http_fetch_result_t *out)
{
  ftun_string_t current;
  ftun_tls_context_t *tls_context = NULL;
  char *owned_url = NULL;
  ftun_reservation_t url_reservation = (ftun_reservation_t){0};
  size_t redirects;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (spec == NULL || out == NULL || spec->budget == NULL ||
      spec->url.data == NULL || spec->url.length == 0u ||
      spec->maximum_bytes == 0u || spec->deadline_ms == 0u ||
      (spec->use_proxy && spec->proxy.kind != FTUN_ADDRESS_IPV4 &&
       (spec->proxy.kind != FTUN_ADDRESS_DOMAIN ||
        spec->proxy_domain[0] == '\0'))) {
    return FTUN_E_INVALID;
  }
  current = spec->url;
  for (redirects = 0u; redirects <= FTUN_HTTP_FETCH_REDIRECTS; redirects++) {
    char *location = NULL;
    ftun_reservation_t location_reservation = (ftun_reservation_t){0};
    ftun_http_fetch_release(out);
    status = ftun_http_fetch_once(spec, current, &tls_context, out, &location,
      &location_reservation);
    if (status != FTUN_OK) {
      free(location);
      (void)ftun_reservation_release(&location_reservation);
      break;
    }
    if (!ftun_http_redirect_status(out->status)) {
      free(location);
      (void)ftun_reservation_release(&location_reservation);
      break;
    }
    if (location == NULL || redirects == FTUN_HTTP_FETCH_REDIRECTS) {
      free(location);
      (void)ftun_reservation_release(&location_reservation);
      status = FTUN_E_PROTOCOL;
      break;
    }
    {
      char *redirect = NULL;
      ftun_reservation_t redirect_reservation = (ftun_reservation_t){0};
      status = ftun_http_redirect_url(spec->budget, current, location, &redirect,
        &redirect_reservation);
      free(location);
      (void)ftun_reservation_release(&location_reservation);
      if (status != FTUN_OK) break;
      free(owned_url);
      (void)ftun_reservation_release(&url_reservation);
      owned_url = redirect;
      url_reservation = redirect_reservation;
    }
    current.data = owned_url;
    current.length = strlen(owned_url);
  }
  free(owned_url);
  (void)ftun_reservation_release(&url_reservation);
  (void)ftun_tls_context_destroy(&tls_context);
  if (status != FTUN_OK) ftun_http_fetch_release(out);
  return status;
}

void ftun_http_fetch_release(ftun_http_fetch_result_t *result)
{
  if (result == NULL) return;
  free(result->data);
  free(result->etag);
  (void)ftun_reservation_release(&result->reservation);
  (void)ftun_reservation_release(&result->etag_reservation);
  memset(result, 0, sizeof(*result));
}
