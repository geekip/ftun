#define _POSIX_C_SOURCE 200809L

#include "core/http_fetch.h"

#include "config/model.h"
#include "core/runtime.h"
#include "protocol/socks5.h"
#include "route/rule.h"
#include "tls/tls.h"
#include "util/time.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define FTUN_HTTP_FETCH_HEADER_LIMIT (64u * 1024u)
#define FTUN_HTTP_FETCH_REDIRECTS 5u

typedef struct {
  char host[254];
  char path[2049];
  uint16_t port;
  bool https;
} ftun_http_url_t;

typedef struct {
  int descriptor;
  uint64_t deadline_ms;
} ftun_http_socket_io_t;

static ftun_status_t ftun_http_errno(int error_code)
{
  if (error_code == EAGAIN || error_code == EWOULDBLOCK ||
      error_code == EINTR) return FTUN_E_AGAIN;
  if (error_code == ENOMEM || error_code == ENOBUFS ||
      error_code == EMFILE || error_code == ENFILE) return FTUN_E_LIMIT;
  if (error_code == ETIMEDOUT) return FTUN_E_TIMEOUT;
  if (error_code == ECONNREFUSED || error_code == ECONNRESET ||
      error_code == EHOSTUNREACH || error_code == ENETUNREACH) {
    return FTUN_E_REJECTED;
  }
  return FTUN_E_IO;
}

static int ftun_http_wait(int descriptor, short events, uint64_t deadline_ms)
{
  struct pollfd item;
  uint64_t now;
  int timeout;
  int result;
  if (ftun_monotonic_now(&now) != FTUN_OK || now >= deadline_ms) return 0;
  timeout = deadline_ms - now > (uint64_t)INT_MAX
    ? INT_MAX : (int)(deadline_ms - now);
  memset(&item, 0, sizeof(item));
  item.fd = descriptor;
  item.events = events;
  do {
    result = poll(&item, 1u, timeout);
  } while (result < 0 && errno == EINTR);
  /* HUP/ERR are readiness notifications too: recv/send/getsockopt must run
   * once to drain buffered bytes or report the concrete socket error. */
  return result == 1 &&
    (item.revents & (events | POLLERR | POLLHUP | POLLNVAL)) != 0;
}

static int ftun_http_send_all(int descriptor, const uint8_t *data,
                              size_t length, uint64_t deadline_ms)
{
  size_t offset = 0u;
  while (offset < length) {
    ssize_t amount = send(descriptor, data + offset, length - offset,
                          MSG_NOSIGNAL);
    if (amount > 0) offset += (size_t)amount;
    else if (amount < 0 && errno == EINTR) continue;
    else if (amount < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) &&
             ftun_http_wait(descriptor, POLLOUT, deadline_ms)) continue;
    else return 0;
  }
  return 1;
}

static int ftun_http_recv_all(int descriptor, uint8_t *data, size_t length,
                              uint64_t deadline_ms)
{
  size_t offset = 0u;
  while (offset < length) {
    ssize_t amount = recv(descriptor, data + offset, length - offset, 0);
    if (amount > 0) offset += (size_t)amount;
    else if (amount < 0 && errno == EINTR) continue;
    else if (amount < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) &&
             ftun_http_wait(descriptor, POLLIN, deadline_ms)) continue;
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

static ftun_status_t ftun_http_redirect_url(ftun_string_t base,
                                             const char *location,
                                             char **out)
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
  if (out != NULL) *out = NULL;
  if (location == NULL || location[0] == '\0' || out == NULL) {
    return FTUN_E_INVALID;
  }
  location_length = strlen(location);
  if (location_length > 2048u || strpbrk(location, "\r\n") != NULL) {
    return FTUN_E_PROTOCOL;
  }
  if (strncmp(location, "http://", 7u) == 0 ||
      strncmp(location, "https://", 8u) == 0) {
    joined = strdup(location);
    if (joined == NULL) return FTUN_E_LIMIT;
    *out = joined;
    return FTUN_OK;
  }
  if (ftun_http_parse_url(base, &parsed) != FTUN_OK) return FTUN_E_PROTOCOL;
  scheme = parsed.https ? "https://" : "http://";
  if (location[0] == '/' && location[1] == '/') {
    if (strlen(scheme) > SIZE_MAX - location_length) return FTUN_E_LIMIT;
    total = strlen(scheme) + location_length - 2u;
    joined = (char *)malloc(total + 1u);
    if (joined == NULL) return FTUN_E_LIMIT;
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
    joined = (char *)malloc(total + 1u);
    if (joined == NULL) return FTUN_E_LIMIT;
    (void)snprintf(joined, total + 1u, "%s%s%s%.*s%s", scheme,
                   parsed.host, port, (int)path_length, path, location);
    *out = joined;
    return FTUN_OK;
  }
  if (prefix_length > SIZE_MAX - path_length) return FTUN_E_LIMIT;
  total = prefix_length + path_length;
  if (total > 2048u) return FTUN_E_LIMIT;
  joined = (char *)malloc(total + 1u);
  if (joined == NULL) return FTUN_E_LIMIT;
  (void)snprintf(joined, total + 1u, "%s%s%s%s", scheme, parsed.host, port,
                 path);
  *out = joined;
  return FTUN_OK;
}

static ftun_status_t ftun_http_outbound_id(const ftun_config_t *config,
                                            const char *name,
                                            uint32_t *out)
{
  size_t index;
  if (config == NULL || name == NULL || out == NULL) return FTUN_E_INVALID;
  if (strcmp(name, "DIRECT") == 0) {
    *out = FTUN_OUTBOUND_ID_DIRECT;
    return FTUN_OK;
  }
  if (strcmp(name, "REJECT") == 0) {
    *out = FTUN_OUTBOUND_ID_REJECT;
    return FTUN_OK;
  }
  for (index = 0u; index < config->outbound_count; index++) {
    if (strcmp(name, config->outbounds[index].name) == 0) {
      if (index > UINT32_MAX - FTUN_OUTBOUND_ID_NAMED_BASE) {
        return FTUN_E_LIMIT;
      }
      *out = (uint32_t)index + FTUN_OUTBOUND_ID_NAMED_BASE;
      return FTUN_OK;
    }
  }
  return FTUN_E_REJECTED;
}

ftun_status_t ftun_http_fetch_route(const ftun_config_t *config,
                                    const ftun_runtime_t *runtime,
                                    const char *outbound_name,
                                    ftun_http_fetch_spec_t *spec)
{
  uint32_t current;
  size_t depth;
  ftun_status_t status;
  if (config == NULL || outbound_name == NULL || spec == NULL) {
    return FTUN_E_INVALID;
  }
  spec->use_proxy = false;
  memset(&spec->proxy, 0, sizeof(spec->proxy));
  memset(spec->proxy_domain, 0, sizeof(spec->proxy_domain));
  memset(&spec->proxy_username, 0, sizeof(spec->proxy_username));
  memset(&spec->proxy_password, 0, sizeof(spec->proxy_password));
  status = ftun_http_outbound_id(config, outbound_name, &current);
  for (depth = 0u; status == FTUN_OK && depth <= config->outbound_count;
       depth++) {
    const ftun_config_outbound_t *item;
    size_t index;
    if (current == FTUN_OUTBOUND_ID_DIRECT) return FTUN_OK;
    if (current == FTUN_OUTBOUND_ID_REJECT ||
        current < FTUN_OUTBOUND_ID_NAMED_BASE) return FTUN_E_REJECTED;
    index = (size_t)(current - FTUN_OUTBOUND_ID_NAMED_BASE);
    if (index >= config->outbound_count) return FTUN_E_STATE_CORRUPT;
    item = &config->outbounds[index];
    if (item->kind == FTUN_CONFIG_OUTBOUND_SOCKS5) {
      ftun_endpoint_t parsed;
      char domain[FTUN_CONTROL_ENDPOINT_TEXT_BYTES];
      status = ftun_control_parse_endpoint(
        item->server, 1u, &parsed, domain);
      if (status == FTUN_OK && parsed.kind == FTUN_ADDRESS_DOMAIN) {
        spec->proxy.kind = FTUN_ADDRESS_DOMAIN;
        spec->proxy.port = parsed.port;
        memcpy(spec->proxy_domain, domain, parsed.domain.length + 1u);
        spec->proxy.domain.data = spec->proxy_domain;
        spec->proxy.domain.length = parsed.domain.length;
      } else if (status == FTUN_OK) {
        spec->proxy = parsed;
      }
      if (status != FTUN_OK) return status;
      spec->use_proxy = true;
      if (item->username != NULL) {
        spec->proxy_username.data = item->username;
        spec->proxy_username.length = strlen(item->username);
        spec->proxy_password.data = item->password;
        spec->proxy_password.length = strlen(item->password);
      }
      return FTUN_OK;
    }
    if (runtime != NULL) {
      bool is_group = false;
      bool degraded = false;
      ftun_string_t dns_server;
      uint32_t selected = 0u;
      status = ftun_runtime_group_selected(runtime, current, &selected,
                                            &is_group, &degraded,
                                            &dns_server);
      (void)degraded;
      (void)dns_server;
      if (status == FTUN_OK && !is_group) status = FTUN_E_STATE_CORRUPT;
      if (status == FTUN_OK) current = selected;
    } else {
      status = ftun_http_outbound_id(config, item->default_member, &current);
    }
  }
  return status == FTUN_OK ? FTUN_E_STATE_CORRUPT : status;
}

ftun_status_t ftun_http_fetch_resolver(const ftun_config_t *config,
                                       const ftun_runtime_t *runtime,
                                       ftun_string_t server,
                                       ftun_http_fetch_spec_t *spec)
{
  if (spec == NULL) return FTUN_E_INVALID;
  return ftun_control_resolver_plan(config, runtime, server,
                                    spec->socket_mark, &spec->resolver);
}

static ftun_status_t ftun_http_connect(const ftun_endpoint_t *target,
                                       uint32_t mark,
                                       uint64_t deadline_ms, int *out)
{
  struct sockaddr_in address;
  int descriptor;
  int flags;
  int error_code = 0;
  socklen_t error_length = (socklen_t)sizeof(error_code);
  if (out != NULL) *out = -1;
  if (target == NULL || target->kind != FTUN_ADDRESS_IPV4 ||
      target->port == 0u || out == NULL) return FTUN_E_INVALID;
  descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
  if (descriptor < 0) return ftun_http_errno(errno);
#if defined(SO_MARK)
  if (mark != 0u && setsockopt(descriptor, SOL_SOCKET, SO_MARK, &mark,
                 (socklen_t)sizeof(mark)) != 0) {
    error_code = errno;
    (void)close(descriptor);
    return ftun_http_errno(error_code);
  }
#else
  (void)mark;
#endif
  flags = fcntl(descriptor, F_GETFL, 0);
  if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0) {
    (void)close(descriptor);
    return FTUN_E_IO;
  }
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_port = htons(target->port);
  memcpy(&address.sin_addr.s_addr, target->address, 4u);
  if (connect(descriptor, (const struct sockaddr *)&address,
              (socklen_t)sizeof(address)) != 0 && errno != EINPROGRESS) {
    error_code = errno;
    (void)close(descriptor);
    return ftun_http_errno(error_code);
  }
  if (!ftun_http_wait(descriptor, POLLOUT, deadline_ms) ||
      getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error_code,
                 &error_length) != 0 || error_code != 0) {
    (void)close(descriptor);
    return error_code == 0 ? FTUN_E_TIMEOUT : ftun_http_errno(error_code);
  }
  *out = descriptor;
  return FTUN_OK;
}

static ftun_status_t ftun_http_socks_reply(int descriptor,
                                            uint64_t deadline_ms,
                                            ftun_socks5_reply_t *reply)
{
  uint8_t frame[262];
  size_t length = 4u;
  size_t consumed = 0u;
  if (!ftun_http_recv_all(descriptor, frame, 4u, deadline_ms)) {
    return FTUN_E_TIMEOUT;
  }
  if (frame[3] == 1u) length = 10u;
  else if (frame[3] == 4u) length = 22u;
  else if (frame[3] == 3u) {
    if (!ftun_http_recv_all(descriptor, frame + 4u, 1u, deadline_ms)) {
      return FTUN_E_TIMEOUT;
    }
    length = 7u + frame[4];
    if (length > sizeof(frame) || !ftun_http_recv_all(
          descriptor, frame + 5u, length - 5u, deadline_ms)) {
      return FTUN_E_TIMEOUT;
    }
    return ftun_socks5_decode_reply((ftun_bytes_t){frame, length}, reply,
                                    &consumed);
  } else return FTUN_E_PROTOCOL;
  if (!ftun_http_recv_all(descriptor, frame + 4u, length - 4u,
                          deadline_ms)) return FTUN_E_TIMEOUT;
  return ftun_socks5_decode_reply((ftun_bytes_t){frame, length}, reply,
                                  &consumed);
}

static ftun_status_t ftun_http_socks_connect(
  int descriptor, const ftun_http_fetch_spec_t *spec,
  const ftun_endpoint_t *target)
{
  uint8_t frame[513];
  uint8_t response[2];
  ftun_socks5_reply_t reply;
  size_t written = 0u;
  ftun_status_t status;
  frame[0] = FTUN_SOCKS5_VERSION;
  frame[1] = 1u;
  frame[2] = spec->proxy_username.length == 0u
    ? FTUN_SOCKS5_METHOD_NO_AUTH : FTUN_SOCKS5_METHOD_USERNAME_PASSWORD;
  if (!ftun_http_send_all(descriptor, frame, 3u, spec->deadline_ms) ||
      !ftun_http_recv_all(descriptor, response, 2u, spec->deadline_ms) ||
      response[0] != FTUN_SOCKS5_VERSION || response[1] != frame[2]) {
    return FTUN_E_REJECTED;
  }
  if (spec->proxy_username.length != 0u) {
    status = ftun_socks5_encode_credentials(
      (ftun_bytes_t){(const uint8_t *)spec->proxy_username.data,
                     spec->proxy_username.length},
      (ftun_bytes_t){(const uint8_t *)spec->proxy_password.data,
                     spec->proxy_password.length},
      frame, sizeof(frame), &written);
    if (status != FTUN_OK || !ftun_http_send_all(descriptor, frame, written,
          spec->deadline_ms) || !ftun_http_recv_all(descriptor, response, 2u,
          spec->deadline_ms) || response[0] != FTUN_SOCKS5_AUTH_VERSION ||
        response[1] != 0u) return status == FTUN_OK ? FTUN_E_REJECTED : status;
  }
  status = ftun_socks5_encode_request(FTUN_SOCKS5_COMMAND_CONNECT, target,
                                      frame, sizeof(frame), &written);
  if (status == FTUN_OK && !ftun_http_send_all(descriptor, frame, written,
                                                spec->deadline_ms)) {
    status = FTUN_E_TIMEOUT;
  }
  if (status == FTUN_OK) {
    status = ftun_http_socks_reply(descriptor, spec->deadline_ms, &reply);
  }
  if (status == FTUN_OK && reply.reply != FTUN_SOCKS5_REPLY_SUCCEEDED) {
    status = FTUN_E_REJECTED;
  }
  return status;
}

static ftun_status_t ftun_http_io_read(void *user, uint8_t *buffer,
                                       size_t capacity, size_t *length)
{
  ftun_http_socket_io_t *io = (ftun_http_socket_io_t *)user;
  ssize_t amount;
  *length = 0u;
  do {
    amount = recv(io->descriptor, buffer, capacity, 0);
  } while (amount < 0 && errno == EINTR);
  if (amount > 0) {
    *length = (size_t)amount;
    return FTUN_OK;
  }
  if (amount == 0) return FTUN_E_EOF;
  return ftun_http_errno(errno);
}

static ftun_status_t ftun_http_io_write(void *user, const uint8_t *buffer,
                                        size_t length, size_t *written)
{
  ftun_http_socket_io_t *io = (ftun_http_socket_io_t *)user;
  ssize_t amount;
  *written = 0u;
  do {
    amount = send(io->descriptor, buffer, length, MSG_NOSIGNAL);
  } while (amount < 0 && errno == EINTR);
  if (amount > 0) {
    *written = (size_t)amount;
    return FTUN_OK;
  }
  return amount == 0 ? FTUN_E_IO : ftun_http_errno(errno);
}

static const char *ftun_http_ca_file(void)
{
  static const char *const candidates[] = {
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem"
  };
  struct stat info;
  size_t index;
  for (index = 0u; index < sizeof(candidates) / sizeof(candidates[0]); index++) {
    if (stat(candidates[index], &info) == 0 && S_ISREG(info.st_mode)) {
      return candidates[index];
    }
  }
  return NULL;
}

static ftun_status_t ftun_http_tls_wait(ftun_tls_client_t *client,
                                        int descriptor,
                                        uint64_t deadline_ms)
{
  ftun_tls_info_t info;
  ftun_status_t status = ftun_tls_client_get_info(client, &info);
  if (status != FTUN_OK) return status;
  return ftun_http_wait(descriptor,
    info.wants_write ? POLLOUT : POLLIN, deadline_ms)
    ? FTUN_OK : FTUN_E_TIMEOUT;
}

static ftun_status_t ftun_http_stream_write(
  int descriptor, ftun_tls_client_t *tls, const uint8_t *data, size_t length,
  uint64_t deadline_ms)
{
  size_t offset = 0u;
  while (offset < length) {
    size_t amount = 0u;
    ftun_status_t status = tls == NULL
      ? ftun_http_io_write(&(ftun_http_socket_io_t){descriptor, deadline_ms},
                           data + offset, length - offset, &amount)
      : ftun_tls_client_write(tls, data + offset, length - offset, &amount);
    if (status == FTUN_OK) offset += amount;
    else if (status == FTUN_E_AGAIN) {
      status = tls == NULL
        ? (ftun_http_wait(descriptor, POLLOUT, deadline_ms)
           ? FTUN_OK : FTUN_E_TIMEOUT)
        : ftun_http_tls_wait(tls, descriptor, deadline_ms);
      if (status != FTUN_OK) return status;
    } else return status;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_http_stream_read(
  int descriptor, ftun_tls_client_t *tls, uint8_t *data, size_t capacity,
  size_t *length, uint64_t deadline_ms)
{
  ftun_status_t status;
  for (;;) {
    status = tls == NULL
      ? ftun_http_io_read(&(ftun_http_socket_io_t){descriptor, deadline_ms},
                          data, capacity, length)
      : ftun_tls_client_read(tls, data, capacity, length);
    if (status != FTUN_E_AGAIN) return status;
    status = tls == NULL
      ? (ftun_http_wait(descriptor, POLLIN, deadline_ms)
         ? FTUN_OK : FTUN_E_TIMEOUT)
      : ftun_http_tls_wait(tls, descriptor, deadline_ms);
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

static ftun_status_t ftun_http_parse_response(
  uint8_t *wire, size_t wire_length, size_t maximum,
  ftun_http_fetch_result_t *out, char **location)
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
  while (cursor + 1u < header_end &&
         !(wire[cursor] == '\r' && wire[cursor + 1u] == '\n')) cursor++;
  cursor += 2u;
  while (cursor < header_end) {
    size_t line_end = cursor;
    size_t colon;
    while (line_end + 1u < header_end &&
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
        char *etag = (char *)malloc(value_length + 1u);
        if (etag == NULL) return FTUN_E_LIMIT;
        memcpy(etag, wire + value, value_length);
        etag[value_length] = '\0';
        free(out->etag);
        out->etag = etag;
      } else if (location != NULL && ftun_http_ascii_equal(
                   wire + cursor, colon - cursor, "location")) {
        size_t value_length = line_end - value;
        char *copy = (char *)malloc(value_length + 1u);
        if (copy == NULL) return FTUN_E_LIMIT;
        memcpy(copy, wire + value, value_length);
        copy[value_length] = '\0';
        free(*location);
        *location = copy;
      }
    }
    cursor = line_end + 2u;
  }
  body_offset = header_end + 4u;
  if (chunked) {
    return ftun_http_decode_chunked(wire + body_offset,
      wire_length - body_offset, maximum, &out->length);
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
  ftun_http_fetch_result_t *out, char **location)
{
  ftun_http_url_t url;
  ftun_endpoint_t endpoint;
  ftun_endpoint_t proxy_endpoint;
  ftun_tls_options_t tls_options;
  ftun_tls_io_t tls_io;
  ftun_tls_client_t *tls = NULL;
  ftun_http_socket_io_t socket_io;
  uint8_t *wire = NULL;
  char *request = NULL;
  size_t wire_capacity;
  size_t wire_length = 0u;
  size_t request_capacity;
  int descriptor = -1;
  ftun_status_t status;
  status = ftun_http_parse_url(url_text, &url);
  if (status != FTUN_OK) return status;
  status = ftun_control_resolve(&spec->resolver,
    (ftun_string_t){url.host, strlen(url.host)}, url.port, &endpoint);
  if (status != FTUN_OK) return status;
  proxy_endpoint = spec->proxy;
  if (spec->use_proxy && proxy_endpoint.kind == FTUN_ADDRESS_DOMAIN) {
    status = ftun_control_resolve_bootstrap(&spec->resolver,
      (ftun_string_t){spec->proxy_domain,
                      strlen(spec->proxy_domain)},
      proxy_endpoint.port, &proxy_endpoint);
  }
  if (status == FTUN_OK) status = ftun_http_connect(
    spec->use_proxy ? &proxy_endpoint : &endpoint,
    spec->socket_mark, spec->deadline_ms, &descriptor);
  if (status == FTUN_OK && spec->use_proxy) {
    status = ftun_http_socks_connect(descriptor, spec, &endpoint);
  }
  memset(&socket_io, 0, sizeof(socket_io));
  socket_io.descriptor = descriptor;
  socket_io.deadline_ms = spec->deadline_ms;
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
    memset(&tls_io, 0, sizeof(tls_io));
    tls_io.read = ftun_http_io_read;
    tls_io.write = ftun_http_io_write;
    tls_io.user = &socket_io;
    if (status == FTUN_OK) status = ftun_tls_client_open(&tls_options,
                                                         &tls_io, &tls);
    while (status == FTUN_OK) {
      status = ftun_tls_client_handshake(tls);
      if (status == FTUN_E_AGAIN) {
        status = ftun_http_tls_wait(tls, descriptor, spec->deadline_ms);
        if (status == FTUN_OK) continue;
      }
      break;
    }
    if (status == FTUN_OK) out->tls_verified = true;
  }
  request_capacity = strlen(url.path) + strlen(url.host) +
    spec->if_none_match.length + 256u;
  request = status == FTUN_OK ? (char *)malloc(request_capacity) : NULL;
  if (status == FTUN_OK && request == NULL) status = FTUN_E_LIMIT;
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
    else status = ftun_http_stream_write(descriptor, tls,
      (const uint8_t *)request, (size_t)length, spec->deadline_ms);
  }
  if (spec->maximum_bytes > SIZE_MAX - FTUN_HTTP_FETCH_HEADER_LIMIT) {
    status = FTUN_E_LIMIT;
  }
  wire_capacity = spec->maximum_bytes + FTUN_HTTP_FETCH_HEADER_LIMIT;
  wire = status == FTUN_OK ? (uint8_t *)malloc(wire_capacity) : NULL;
  if (status == FTUN_OK && wire == NULL) status = FTUN_E_LIMIT;
  while (status == FTUN_OK && wire_length < wire_capacity) {
    size_t amount = 0u;
    status = ftun_http_stream_read(descriptor, tls, wire + wire_length,
      wire_capacity - wire_length, &amount, spec->deadline_ms);
    if (status == FTUN_OK) wire_length += amount;
    else if (status == FTUN_E_EOF) status = FTUN_OK;
    if (amount == 0u) break;
  }
  if (status == FTUN_OK && wire_length == wire_capacity) status = FTUN_E_LIMIT;
  if (status == FTUN_OK) {
    status = ftun_http_parse_response(wire, wire_length,
                                      spec->maximum_bytes, out, location);
  }
  if (status == FTUN_OK && out->length != 0u) {
    out->data = (uint8_t *)malloc(out->length);
    if (out->data == NULL) status = FTUN_E_LIMIT;
    else memcpy(out->data, wire, out->length);
  }
  free(wire);
  free(request);
  (void)ftun_tls_client_destroy(&tls);
  if (descriptor >= 0) (void)close(descriptor);
  return status;
}

ftun_status_t ftun_http_fetch(const ftun_http_fetch_spec_t *spec,
                              ftun_http_fetch_result_t *out)
{
  ftun_string_t current;
  char *owned_url = NULL;
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
  status = ftun_budget_reserve(spec->budget, spec->maximum_bytes,
                               &out->reservation);
  if (status != FTUN_OK) return status;
  current = spec->url;
  for (redirects = 0u; redirects <= FTUN_HTTP_FETCH_REDIRECTS; redirects++) {
    char *location = NULL;
    free(out->data);
    out->data = NULL;
    out->length = 0u;
    free(out->etag);
    out->etag = NULL;
    out->status = 0u;
    out->tls_verified = false;
    status = ftun_http_fetch_once(spec, current, out, &location);
    if (status != FTUN_OK) {
      free(location);
      break;
    }
    if (!ftun_http_redirect_status(out->status)) {
      free(location);
      break;
    }
    if (location == NULL || redirects == FTUN_HTTP_FETCH_REDIRECTS) {
      free(location);
      status = FTUN_E_PROTOCOL;
      break;
    }
    {
      char *redirect = NULL;
      status = ftun_http_redirect_url(current, location, &redirect);
      free(location);
      if (status != FTUN_OK) break;
      free(owned_url);
      owned_url = redirect;
    }
    current.data = owned_url;
    current.length = strlen(owned_url);
  }
  free(owned_url);
  if (status == FTUN_OK) {
    /* Keep only the accepted body charged after the bounded wire buffer has
     * been consumed.  Calls are owner-serialized for a shared budget. */
    (void)ftun_reservation_release(&out->reservation);
    if (out->length != 0u) {
      status = ftun_budget_reserve(spec->budget, out->length,
                                   &out->reservation);
    }
  }
  if (status != FTUN_OK) ftun_http_fetch_release(out);
  return status;
}

void ftun_http_fetch_release(ftun_http_fetch_result_t *result)
{
  if (result == NULL) return;
  free(result->data);
  free(result->etag);
  (void)ftun_reservation_release(&result->reservation);
  memset(result, 0, sizeof(*result));
}
