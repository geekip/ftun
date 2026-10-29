/* ftun_mixed_connection_create。 */
#include "proxy/inbound/mixed.h"
#include "proxy/inbound/socks5.h"
#include "proxy/inbound/http_codec.h"

#include <string.h>
#include <stdlib.h>

typedef enum {
  FTUN_MIXED_DETECT = 1,
  FTUN_MIXED_HTTP_HEADERS,
  FTUN_MIXED_HTTP_WAIT,
  FTUN_MIXED_HTTP_BODY_STATE,
  FTUN_MIXED_SOCKS_STATE,
  FTUN_MIXED_TUNNEL,
  FTUN_MIXED_FAILED
} ftun_mixed_state_t;

struct ftun_mixed_connection {
  ftun_reservation_t reservation;
  ftun_mixed_state_t state;
  ftun_socks5_server_t *socks5;
  uint8_t http_buffer[FTUN_HTTP_MAX_HEADER_BYTES];
  uint8_t http_wire[FTUN_HTTP_MAX_HEADER_BYTES];
  size_t http_length;
  size_t http_header_bytes;
  size_t http_preread_body;
  uint64_t body_remaining;
  ftun_http_request_t request;
  uint8_t reply[128];
};

static int ftun_mixed_equal_ci(const char *left, size_t length,
                               const char *right)
{
  size_t index;
  if (strlen(right) != length) return 0;
  for (index = 0u; index < length; index++) {
    uint8_t a = (uint8_t)left[index];
    uint8_t b = (uint8_t)right[index];
    if (a >= (uint8_t)'A' && a <= (uint8_t)'Z') a += 32u;
    if (b >= (uint8_t)'A' && b <= (uint8_t)'Z') b += 32u;
    if (a != b) return 0;
  }
  return 1;
}

static int ftun_mixed_base64_value(uint8_t byte)
{
  if (byte >= (uint8_t)'A' && byte <= (uint8_t)'Z') {
    return (int)(byte - (uint8_t)'A');
  }
  if (byte >= (uint8_t)'a' && byte <= (uint8_t)'z') {
    return (int)(byte - (uint8_t)'a') + 26;
  }
  if (byte >= (uint8_t)'0' && byte <= (uint8_t)'9') {
    return (int)(byte - (uint8_t)'0') + 52;
  }
  if (byte == (uint8_t)'+') return 62;
  if (byte == (uint8_t)'/') return 63;
  return -1;
}

static ftun_status_t ftun_mixed_basic_credentials(
  ftun_string_t authorization, uint8_t *decoded, size_t capacity,
  ftun_bytes_t *username, ftun_bytes_t *password)
{
  size_t cursor = 0u;
  size_t written = 0u;
  size_t colon;
  if (username != NULL) memset(username, 0, sizeof(*username));
  if (password != NULL) memset(password, 0, sizeof(*password));
  if (authorization.data == NULL || decoded == NULL || username == NULL ||
      password == NULL || authorization.length <= 6u ||
      !ftun_mixed_equal_ci(authorization.data, 5u, "Basic") ||
      authorization.data[5] != ' ') return FTUN_E_REJECTED;
  cursor = 6u;
  if ((authorization.length - cursor) % 4u != 0u) return FTUN_E_REJECTED;
  while (cursor < authorization.length) {
    int a = ftun_mixed_base64_value((uint8_t)authorization.data[cursor]);
    int b = ftun_mixed_base64_value((uint8_t)authorization.data[cursor + 1u]);
    int c = authorization.data[cursor + 2u] == '=' ? -2 :
      ftun_mixed_base64_value((uint8_t)authorization.data[cursor + 2u]);
    int d = authorization.data[cursor + 3u] == '=' ? -2 :
      ftun_mixed_base64_value((uint8_t)authorization.data[cursor + 3u]);
    bool final = cursor + 4u == authorization.length;
    if (a < 0 || b < 0 || c == -1 || d == -1 ||
        (c == -2 && d != -2) || ((c == -2 || d == -2) && !final) ||
        written >= capacity) return FTUN_E_REJECTED;
    decoded[written++] = (uint8_t)(((uint32_t)a << 2u) |
      ((uint32_t)b >> 4u));
    if (c >= 0) {
      if (written >= capacity) return FTUN_E_REJECTED;
      decoded[written++] = (uint8_t)((((uint32_t)b & 15u) << 4u) |
        ((uint32_t)c >> 2u));
      if (d >= 0) {
        if (written >= capacity) return FTUN_E_REJECTED;
        decoded[written++] = (uint8_t)((((uint32_t)c & 3u) << 6u) |
          (uint32_t)d);
      } else if (((uint32_t)c & 3u) != 0u) {
        return FTUN_E_REJECTED;
      }
    } else if (((uint32_t)b & 15u) != 0u) {
      return FTUN_E_REJECTED;
    }
    cursor += 4u;
  }
  for (colon = 0u; colon < written && decoded[colon] != (uint8_t)':';
       colon++) {}
  if (colon == 0u || colon == written || colon > 255u ||
      written - colon - 1u > 255u) return FTUN_E_REJECTED;
  username->data = decoded;
  username->length = colon;
  password->data = decoded + colon + 1u;
  password->length = written - colon - 1u;
  return FTUN_OK;
}

static ftun_status_t ftun_mixed_http_authorize(
  ftun_mixed_connection_t *connection, const ftun_http_request_t *request)
{
  uint8_t decoded[511];
  ftun_bytes_t username;
  ftun_bytes_t password;
  bool authorized = false;
  ftun_status_t status;
  status = ftun_mixed_basic_credentials(request->proxy_authorization,
                                         decoded, sizeof(decoded),
                                         &username, &password);
  if (status != FTUN_OK) return status;
  status = ftun_socks5_server_authorize(connection->socks5, username,
                                         password, &authorized);
  if (status != FTUN_OK) return status;
  return authorized ? FTUN_OK : FTUN_E_REJECTED;
}

ftun_status_t ftun_mixed_classify(ftun_bytes_t input,
                                  ftun_mixed_protocol_t *out)
{
  uint8_t first;
  if (out != NULL) *out = 0;
  if (out == NULL || (input.length != 0u && input.data == NULL)) {
    return FTUN_E_INVALID;
  }
  if (input.length == 0u) return FTUN_E_AGAIN;
  first = input.data[0];
  if (first == FTUN_SOCKS5_VERSION) {
    *out = FTUN_MIXED_PROTOCOL_SOCKS5;
    return FTUN_OK;
  }
  if (first >= (uint8_t)'A' && first <= (uint8_t)'Z') {
    *out = FTUN_MIXED_PROTOCOL_HTTP;
    return FTUN_OK;
  }
  return FTUN_E_PROTOCOL;
}

ftun_status_t ftun_mixed_connection_create(const ftun_inbound_spec_t *spec,
                                            ftun_mixed_connection_t **out)
{
  ftun_mixed_connection_t *connection;
  ftun_status_t status;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  if (out != NULL) *out = NULL;
  if (spec == NULL || out == NULL || spec->kind != FTUN_INBOUND_MIXED) {
    return FTUN_E_INVALID;
  }
  if (spec->budget != NULL) {
    status = ftun_budget_reserve(spec->budget, sizeof(*connection), &reservation);
    if (status != FTUN_OK) return status;
  }
  connection = (ftun_mixed_connection_t *)calloc(1u, sizeof(*connection));
  if (connection == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  connection->reservation = reservation;
  status = ftun_socks5_server_create(spec, &connection->socks5);
  if (status != FTUN_OK) {
    free(connection);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  connection->state = FTUN_MIXED_DETECT;
  *out = connection;
  return FTUN_OK;
}

ftun_status_t ftun_mixed_connection_feed(ftun_mixed_connection_t *connection,
                                         ftun_bytes_t input,
                                         size_t *consumed,
                                         ftun_mixed_event_t *event)
{
  ftun_status_t status;
  if (consumed != NULL) *consumed = 0u;
  if (event != NULL) memset(event, 0, sizeof(*event));
  if (connection == NULL || consumed == NULL || event == NULL ||
      (input.length != 0u && input.data == NULL)) return FTUN_E_INVALID;
  if (connection->state == FTUN_MIXED_TUNNEL ||
      connection->state == FTUN_MIXED_FAILED ||
      connection->state == FTUN_MIXED_HTTP_WAIT) return FTUN_E_AGAIN;
  if (connection->state == FTUN_MIXED_HTTP_BODY_STATE) {
    size_t amount;
    if (input.length == 0u) return FTUN_E_AGAIN;
    amount = input.length;
    if ((uint64_t)amount > connection->body_remaining) {
      amount = (size_t)connection->body_remaining;
    }
    event->kind = FTUN_MIXED_EVENT_HTTP_BODY;
    event->wire.data = input.data;
    event->wire.length = amount;
    connection->body_remaining -= amount;
    event->body_remaining = connection->body_remaining;
    *consumed = amount;
    if (connection->body_remaining == 0u) {
      connection->state = FTUN_MIXED_HTTP_HEADERS;
    }
    return FTUN_OK;
  }
  if (connection->state == FTUN_MIXED_DETECT) {
    ftun_mixed_protocol_t protocol;
    status = ftun_mixed_classify(input, &protocol);
    if (status != FTUN_OK) return status;
    connection->state = protocol == FTUN_MIXED_PROTOCOL_SOCKS5
      ? FTUN_MIXED_SOCKS_STATE : FTUN_MIXED_HTTP_HEADERS;
  }
  if (connection->state == FTUN_MIXED_SOCKS_STATE) {
    event->kind = FTUN_MIXED_EVENT_SOCKS5;
    return ftun_socks5_server_feed(connection->socks5, input, consumed,
                                   &event->socks5);
  }
  if (connection->state == FTUN_MIXED_HTTP_HEADERS) {
    static const char authentication_required[] =
      "HTTP/1.1 407 Proxy Authentication Required\r\n"
      "Proxy-Authenticate: Basic realm=\"ftun\"\r\n"
      "Connection: close\r\nContent-Length: 0\r\n\r\n";
    ftun_bytes_t buffered;
    size_t header = 0u;
    size_t body_available;
    size_t body_preread;
    size_t wire_header = 0u;
    bool requires_auth = false;
    if (input.length > sizeof(connection->http_buffer) -
                       connection->http_length) return FTUN_E_LIMIT;
    if (input.length != 0u) {
      memcpy(connection->http_buffer + connection->http_length,
             input.data, input.length);
    }
    connection->http_length += input.length;
    *consumed = input.length;
    buffered.data = connection->http_buffer;
    buffered.length = connection->http_length;
    status = ftun_http_decode_request(buffered, &connection->request, &header);
    if (status != FTUN_OK) return status;
    status = ftun_socks5_server_requires_auth(connection->socks5,
                                               &requires_auth);
    if (status != FTUN_OK) return status;
    if (requires_auth && (!connection->request.has_proxy_authorization ||
        ftun_mixed_http_authorize(connection, &connection->request) !=
          FTUN_OK)) {
      size_t reply_length = sizeof(authentication_required) - 1u;
      memcpy(connection->reply, authentication_required, reply_length);
      connection->state = FTUN_MIXED_FAILED;
      event->kind = FTUN_MIXED_EVENT_HTTP_REPLY;
      event->wire.data = connection->reply;
      event->wire.length = reply_length;
      return FTUN_OK;
    }
    body_available = connection->http_length - header;
    body_preread = body_available;
    if (!connection->request.has_content_length) body_preread = 0u;
    else if ((uint64_t)body_preread > connection->request.content_length) {
      body_preread = (size_t)connection->request.content_length;
    }
    /* 不允许把流水线下一请求误当成当前无 body 请求的预读 body。 */
    if (!connection->request.has_content_length && body_available != 0u) {
      body_preread = 0u;
    }
    connection->http_header_bytes = header;
    connection->http_preread_body = body_preread;
    if (connection->request.kind == FTUN_HTTP_PROXY_FORWARD) {
      status = ftun_http_rewrite_forward(buffered, &connection->request,
        connection->http_wire, sizeof(connection->http_wire), &wire_header);
      if (status != FTUN_OK || body_preread >
          sizeof(connection->http_wire) - wire_header) {
        return status != FTUN_OK ? status : FTUN_E_LIMIT;
      }
      if (body_preread != 0u) {
        memcpy(connection->http_wire + wire_header,
               connection->http_buffer + header, body_preread);
      }
    }
    connection->state = FTUN_MIXED_HTTP_WAIT;
    event->kind = FTUN_MIXED_EVENT_HTTP_REQUEST;
    event->http = connection->request;
    event->wire.data = connection->request.kind == FTUN_HTTP_PROXY_FORWARD
      ? connection->http_wire : connection->http_buffer;
    event->wire.length = connection->request.kind == FTUN_HTTP_PROXY_FORWARD
      ? wire_header + body_preread : header + body_preread;
    {
      size_t offset = header + (connection->request.kind == FTUN_HTTP_PROXY_FORWARD
        ? body_preread : 0u);
      event->preread.data = connection->http_buffer + offset;
      event->preread.length = connection->http_length - offset;
    }
    event->body_remaining = connection->request.has_content_length
      ? connection->request.content_length - body_preread : 0u;
    return FTUN_OK;
  }
  return FTUN_E_STATE_CORRUPT;
}

ftun_status_t ftun_mixed_http_finish(ftun_mixed_connection_t *connection,
                                     ftun_status_t downstream_status,
                                     ftun_mixed_event_t *event)
{
  static const char established[] =
    "HTTP/1.1 200 Connection Established\r\n\r\n";
  static const char forbidden[] =
    "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
  static const char bad_gateway[] =
    "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
  const char *reply = NULL;
  size_t reply_length = 0u;
  if (event != NULL) memset(event, 0, sizeof(*event));
  if (connection == NULL || event == NULL ||
      connection->state != FTUN_MIXED_HTTP_WAIT) return FTUN_E_INVALID;
  if (downstream_status != FTUN_OK) {
    reply = downstream_status == FTUN_E_REJECTED ? forbidden : bad_gateway;
    reply_length = downstream_status == FTUN_E_REJECTED
      ? sizeof(forbidden) - 1u : sizeof(bad_gateway) - 1u;
    memcpy(connection->reply, reply, reply_length);
    connection->state = FTUN_MIXED_FAILED;
  } else if (connection->request.kind == FTUN_HTTP_PROXY_CONNECT) {
    reply = established;
    reply_length = sizeof(established) - 1u;
    memcpy(connection->reply, reply, reply_length);
    connection->state = FTUN_MIXED_TUNNEL;
  } else {
    size_t frame = connection->http_header_bytes +
                   connection->http_preread_body;
    size_t extra = connection->http_length - frame;
    connection->body_remaining = connection->request.has_content_length
      ? connection->request.content_length - connection->http_preread_body : 0u;
    if (extra != 0u) memmove(connection->http_buffer,
                             connection->http_buffer + frame, extra);
    connection->http_length = extra;
    connection->state = connection->body_remaining == 0u
      ? FTUN_MIXED_HTTP_HEADERS : FTUN_MIXED_HTTP_BODY_STATE;
  }
  event->kind = FTUN_MIXED_EVENT_HTTP_REPLY;
  event->wire.data = reply_length == 0u ? NULL : connection->reply;
  event->wire.length = reply_length;
  event->body_remaining = connection->body_remaining;
  return FTUN_OK;
}

ftun_status_t ftun_mixed_socks5_finish_request(
  ftun_mixed_connection_t *connection, ftun_status_t downstream_status,
  const ftun_endpoint_t *bound, ftun_mixed_event_t *event)
{
  ftun_status_t status;
  if (event != NULL) memset(event, 0, sizeof(*event));
  if (connection == NULL || event == NULL ||
      connection->state != FTUN_MIXED_SOCKS_STATE) return FTUN_E_INVALID;
  status = ftun_socks5_server_finish_request(connection->socks5,
                                              downstream_status, bound,
                                              &event->socks5);
  if (status == FTUN_OK) event->kind = FTUN_MIXED_EVENT_SOCKS5;
  return status;
}

ftun_status_t ftun_mixed_socks5_udp(ftun_mixed_connection_t *connection,
                                    ftun_bytes_t packet,
                                    ftun_socks5_udp_datagram_t *out)
{
  if (connection == NULL || connection->state != FTUN_MIXED_SOCKS_STATE) {
    if (out != NULL) memset(out, 0, sizeof(*out));
    return FTUN_E_INVALID;
  }
  return ftun_socks5_server_udp(connection->socks5, packet, out);
}

ftun_status_t ftun_mixed_connection_destroy(
  ftun_mixed_connection_t **connection)
{
  ftun_mixed_connection_t *owned;
  ftun_status_t status;
  if (connection == NULL) return FTUN_E_INVALID;
  owned = *connection;
  if (owned == NULL) return FTUN_OK;
  status = ftun_socks5_server_destroy(&owned->socks5);
  if (status != FTUN_OK) return status;
  status = ftun_reservation_release(&owned->reservation);
  if (status != FTUN_OK) return status;
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *connection = NULL;
  return status;
}
