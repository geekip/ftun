/* ftun_socks5_server_create。 */
#include "socks5.h"

#include <stdlib.h>
#include <string.h>

#define FTUN_SOCKS5_SERVER_BUFFER_BYTES 1024u

typedef enum {
  FTUN_SOCKS5_SERVER_METHOD = 1,
  FTUN_SOCKS5_SERVER_AUTH,
  FTUN_SOCKS5_SERVER_COMMAND,
  FTUN_SOCKS5_SERVER_WAIT_DOWNSTREAM,
  FTUN_SOCKS5_SERVER_TCP_RELAY,
  FTUN_SOCKS5_SERVER_UDP_RELAY,
  FTUN_SOCKS5_SERVER_FAILED
} ftun_socks5_server_state_t;

struct ftun_socks5_server {
  ftun_reservation_t *reservation;
  ftun_inbound_user_t *users;
  uint8_t *credential_bytes;
  size_t user_count;
  size_t buffered;
  ftun_socks5_server_state_t state;
  ftun_socks5_command_t command;
  ftun_endpoint_t target;
  char target_domain[256];
  uint8_t buffer[FTUN_SOCKS5_SERVER_BUFFER_BYTES];
  uint8_t reply[512];
  size_t reply_length;
  bool udp_enabled;
};

static void ftun_socks5_server_shift(ftun_socks5_server_t *server,
                                     size_t consumed)
{
  server->buffered -= consumed;
  if (server->buffered != 0u) {
    memmove(server->buffer, server->buffer + consumed, server->buffered);
  }
}

static int ftun_socks5_credentials_equal(ftun_bytes_t left,
                                         ftun_bytes_t right)
{
  size_t index;
  uint8_t difference = (uint8_t)(left.length ^ right.length);
  size_t maximum = left.length > right.length ? left.length : right.length;
  for (index = 0u; index < maximum; index++) {
    uint8_t a = index < left.length ? left.data[index] : 0u;
    uint8_t b = index < right.length ? right.data[index] : 0u;
    difference |= (uint8_t)(a ^ b);
  }
  return difference == 0u;
}

static int ftun_socks5_authorized(const ftun_socks5_server_t *server,
                                  const ftun_socks5_credentials_t *credentials)
{
  size_t index;
  int matched = 0;
  for (index = 0u; index < server->user_count; index++) {
    int same_user = ftun_socks5_credentials_equal(
      server->users[index].username, credentials->username);
    int same_password = ftun_socks5_credentials_equal(
      server->users[index].password, credentials->password);
    matched |= same_user & same_password;
  }
  return matched;
}

static ftun_status_t ftun_socks5_normalize_domain(
  ftun_string_t domain, char output[256], size_t *length)
{
  size_t effective;
  size_t label_start = 0u;
  size_t index;
  if (domain.data == NULL || domain.length == 0u ||
      domain.length > 254u || output == NULL || length == NULL) {
    return FTUN_E_PROTOCOL;
  }
  effective = domain.length;
  if (domain.data[effective - 1u] == '.') effective--;
  if (effective == 0u || effective > 253u) return FTUN_E_PROTOCOL;
  for (index = 0u; index <= effective; index++) {
    if (index == effective || domain.data[index] == '.') {
      size_t label_length = index - label_start;
      if (label_length == 0u || label_length > 63u ||
          domain.data[label_start] == '-' || domain.data[index - 1u] == '-') {
        return FTUN_E_PROTOCOL;
      }
      label_start = index + 1u;
    } else {
      uint8_t byte = (uint8_t)domain.data[index];
      if (byte >= (uint8_t)'A' && byte <= (uint8_t)'Z') byte += 32u;
      if (!((byte >= (uint8_t)'a' && byte <= (uint8_t)'z') ||
            (byte >= (uint8_t)'0' && byte <= (uint8_t)'9') ||
            byte == (uint8_t)'-')) return FTUN_E_PROTOCOL;
      output[index] = (char)byte;
    }
    if (index < effective && domain.data[index] == '.') output[index] = '.';
  }
  output[effective] = '\0';
  *length = effective;
  return FTUN_OK;
}

ftun_status_t ftun_socks5_server_authorize(
  const ftun_socks5_server_t *server, ftun_bytes_t username,
  ftun_bytes_t password, bool *out)
{
  ftun_socks5_credentials_t credentials;
  if (out != NULL) *out = false;
  if (server == NULL || out == NULL || username.data == NULL ||
      password.data == NULL || username.length == 0u ||
      password.length == 0u || username.length > 255u ||
      password.length > 255u) return FTUN_E_INVALID;
  credentials.username = username;
  credentials.password = password;
  *out = ftun_socks5_authorized(server, &credentials) != 0;
  return FTUN_OK;
}

ftun_status_t ftun_socks5_server_requires_auth(
  const ftun_socks5_server_t *server, bool *out)
{
  if (out != NULL) *out = false;
  if (server == NULL || out == NULL) return FTUN_E_INVALID;
  *out = server->user_count != 0u;
  return FTUN_OK;
}

static ftun_status_t ftun_socks5_event_wire(ftun_socks5_server_t *server,
                                            ftun_socks5_server_event_kind_t kind,
                                            size_t written,
                                            ftun_socks5_server_event_t *event)
{
  memset(event, 0, sizeof(*event));
  server->reply_length = written;
  event->kind = kind;
  event->wire.data = server->reply;
  event->wire.length = written;
  return FTUN_OK;
}

ftun_status_t ftun_socks5_server_create(const ftun_inbound_spec_t *spec,
                                        ftun_socks5_server_t **out)
{
  ftun_socks5_server_t *server;
  size_t bytes = 0u;
  size_t index;
  uint8_t *cursor;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (spec == NULL || out == NULL ||
      (spec->kind != FTUN_INBOUND_SOCKS5 &&
       spec->kind != FTUN_INBOUND_MIXED) || !spec->tcp ||
      (spec->user_count == 0u) != (spec->users == NULL) ||
      spec->user_count > 64u) return FTUN_E_INVALID;
  for (index = 0u; index < spec->user_count; index++) {
    if (spec->users[index].username.data == NULL ||
        spec->users[index].password.data == NULL ||
        spec->users[index].username.length == 0u ||
        spec->users[index].username.length > 255u ||
        spec->users[index].password.length == 0u ||
        spec->users[index].password.length > 255u ||
        bytes > SIZE_MAX - spec->users[index].username.length ||
        bytes + spec->users[index].username.length >
          SIZE_MAX - spec->users[index].password.length) return FTUN_E_INVALID;
    bytes += spec->users[index].username.length +
             spec->users[index].password.length;
  }
  if (spec->budget != NULL) {
    status = ftun_budget_reserve(spec->budget,
      sizeof(*server) + spec->user_count * sizeof(*server->users) + bytes,
      &reservation);
    if (status != FTUN_OK) return status;
  }
  server = (ftun_socks5_server_t *)calloc(1u, sizeof(*server));
  if (server == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  server->reservation = reservation;
  if (spec->user_count != 0u) {
    server->users = (ftun_inbound_user_t *)calloc(
      spec->user_count, sizeof(*server->users));
    server->credential_bytes = (uint8_t *)malloc(bytes);
    if (server->users == NULL || server->credential_bytes == NULL) {
      free(server->credential_bytes);
      free(server->users);
      free(server);
      (void)ftun_reservation_release(&reservation);
      return FTUN_E_LIMIT;
    }
  }
  cursor = server->credential_bytes;
  for (index = 0u; index < spec->user_count; index++) {
    server->users[index].username.data = cursor;
    server->users[index].username.length = spec->users[index].username.length;
    memcpy(cursor, spec->users[index].username.data,
           spec->users[index].username.length);
    cursor += spec->users[index].username.length;
    server->users[index].password.data = cursor;
    server->users[index].password.length = spec->users[index].password.length;
    memcpy(cursor, spec->users[index].password.data,
           spec->users[index].password.length);
    cursor += spec->users[index].password.length;
  }
  server->user_count = spec->user_count;
  server->udp_enabled = spec->udp;
  server->state = FTUN_SOCKS5_SERVER_METHOD;
  *out = server;
  return FTUN_OK;
}

ftun_status_t ftun_socks5_server_feed(ftun_socks5_server_t *server,
                                      ftun_bytes_t input,
                                      size_t *consumed,
                                      ftun_socks5_server_event_t *event)
{
  ftun_bytes_t buffered;
  size_t frame = 0u;
  ftun_status_t status;
  if (consumed != NULL) *consumed = 0u;
  if (event != NULL) memset(event, 0, sizeof(*event));
  if (server == NULL || consumed == NULL || event == NULL ||
      (input.length != 0u && input.data == NULL)) return FTUN_E_INVALID;
  if (server->state == FTUN_SOCKS5_SERVER_WAIT_DOWNSTREAM ||
      server->state == FTUN_SOCKS5_SERVER_TCP_RELAY ||
      server->state == FTUN_SOCKS5_SERVER_UDP_RELAY) return FTUN_E_AGAIN;
  if (server->state == FTUN_SOCKS5_SERVER_FAILED) return FTUN_E_REJECTED;
  if (input.length > sizeof(server->buffer) - server->buffered) {
    return FTUN_E_LIMIT;
  }
  if (input.length != 0u) {
    memcpy(server->buffer + server->buffered, input.data, input.length);
    server->buffered += input.length;
    *consumed = input.length;
  }
  buffered.data = server->buffer;
  buffered.length = server->buffered;
  if (server->state == FTUN_SOCKS5_SERVER_METHOD) {
    ftun_socks5_method_offer_t offer;
    uint8_t method = server->user_count == 0u
      ? FTUN_SOCKS5_METHOD_NO_AUTH : FTUN_SOCKS5_METHOD_USERNAME_PASSWORD;
    status = ftun_socks5_decode_method_offer(buffered, &offer, &frame);
    if (status != FTUN_OK) return status;
    if (!ftun_socks5_method_offer_contains(&offer, method)) {
      method = FTUN_SOCKS5_METHOD_NONE_ACCEPTABLE;
      server->state = FTUN_SOCKS5_SERVER_FAILED;
    } else {
      server->state = server->user_count == 0u
        ? FTUN_SOCKS5_SERVER_COMMAND : FTUN_SOCKS5_SERVER_AUTH;
    }
    ftun_socks5_server_shift(server, frame);
    status = ftun_socks5_encode_method_selection(
      method, server->reply, sizeof(server->reply), &frame);
    if (status != FTUN_OK) return status;
    return ftun_socks5_event_wire(server, FTUN_SOCKS5_SERVER_METHOD_REPLY,
                                  frame, event);
  }
  if (server->state == FTUN_SOCKS5_SERVER_AUTH) {
    ftun_socks5_credentials_t credentials;
    uint8_t result;
    status = ftun_socks5_decode_credentials(buffered, &credentials, &frame);
    if (status != FTUN_OK) return status;
    result = (uint8_t)(ftun_socks5_authorized(server, &credentials)
      ? 0u : 1u);
    server->state = result == 0u
      ? FTUN_SOCKS5_SERVER_COMMAND : FTUN_SOCKS5_SERVER_FAILED;
    ftun_socks5_server_shift(server, frame);
    status = ftun_socks5_encode_auth_result(
      result, server->reply, sizeof(server->reply), &frame);
    if (status != FTUN_OK) return status;
    return ftun_socks5_event_wire(server, FTUN_SOCKS5_SERVER_AUTH_REPLY,
                                  frame, event);
  }
  if (server->state == FTUN_SOCKS5_SERVER_COMMAND) {
    ftun_socks5_request_t request;
    if (buffered.length >= 2u && buffered.data[0] == FTUN_SOCKS5_VERSION &&
        (buffered.data[1] != FTUN_SOCKS5_COMMAND_CONNECT &&
         buffered.data[1] != FTUN_SOCKS5_COMMAND_UDP_ASSOCIATE)) {
      ftun_endpoint_t none;
      memset(&none, 0, sizeof(none));
      none.kind = FTUN_ADDRESS_IPV4;
      server->state = FTUN_SOCKS5_SERVER_FAILED;
      status = ftun_socks5_encode_reply(FTUN_SOCKS5_REPLY_COMMAND_UNSUPPORTED,
        &none, server->reply, sizeof(server->reply), &frame);
      if (status != FTUN_OK) return status;
      return ftun_socks5_event_wire(server,
        FTUN_SOCKS5_SERVER_COMMAND_REPLY, frame, event);
    }
    status = ftun_socks5_decode_request(buffered, &request, &frame);
    if (status == FTUN_E_UNSUPPORTED && buffered.length >= 4u &&
        buffered.data[3] == 4u) {
      ftun_endpoint_t none;
      memset(&none, 0, sizeof(none));
      none.kind = FTUN_ADDRESS_IPV4;
      server->state = FTUN_SOCKS5_SERVER_FAILED;
      status = ftun_socks5_encode_reply(FTUN_SOCKS5_REPLY_ADDRESS_UNSUPPORTED,
        &none, server->reply, sizeof(server->reply), &frame);
      if (status != FTUN_OK) return status;
      return ftun_socks5_event_wire(server,
        FTUN_SOCKS5_SERVER_COMMAND_REPLY, frame, event);
    }
    if (status != FTUN_OK) return status;
    if (request.command == FTUN_SOCKS5_COMMAND_UDP_ASSOCIATE &&
        !server->udp_enabled) {
      ftun_endpoint_t none;
      memset(&none, 0, sizeof(none));
      none.kind = FTUN_ADDRESS_IPV4;
      server->state = FTUN_SOCKS5_SERVER_FAILED;
      status = ftun_socks5_encode_reply(FTUN_SOCKS5_REPLY_COMMAND_UNSUPPORTED,
        &none, server->reply, sizeof(server->reply), &frame);
      if (status != FTUN_OK) return status;
      return ftun_socks5_event_wire(server,
        FTUN_SOCKS5_SERVER_COMMAND_REPLY, frame, event);
    }
    server->command = request.command;
    server->target = request.endpoint;
    if (request.endpoint.kind == FTUN_ADDRESS_DOMAIN) {
      size_t normalized_length = 0u;
      status = ftun_socks5_normalize_domain(request.endpoint.domain,
                                             server->target_domain,
                                             &normalized_length);
      if (status != FTUN_OK) {
        server->state = FTUN_SOCKS5_SERVER_FAILED;
        return status;
      }
      server->target.domain.data = server->target_domain;
      server->target.domain.length = normalized_length;
    }
    ftun_socks5_server_shift(server, frame);
    server->state = FTUN_SOCKS5_SERVER_WAIT_DOWNSTREAM;
    event->kind = FTUN_SOCKS5_SERVER_REQUEST;
    event->command = server->command;
    event->target = server->target;
    event->preread.data = server->buffered == 0u ? NULL : server->buffer;
    event->preread.length = server->buffered;
    return FTUN_OK;
  }
  return FTUN_E_STATE_CORRUPT;
}

static uint8_t ftun_socks5_reply_for_status(ftun_status_t status)
{
  switch (status) {
    case FTUN_OK: return FTUN_SOCKS5_REPLY_SUCCEEDED;
    case FTUN_E_REJECTED: return FTUN_SOCKS5_REPLY_NOT_ALLOWED;
    case FTUN_E_RESOLVE: return FTUN_SOCKS5_REPLY_HOST_UNREACHABLE;
    case FTUN_E_TIMEOUT: return FTUN_SOCKS5_REPLY_TTL_EXPIRED;
    case FTUN_E_UNSUPPORTED: return FTUN_SOCKS5_REPLY_COMMAND_UNSUPPORTED;
    default: return FTUN_SOCKS5_REPLY_GENERAL_FAILURE;
  }
}

ftun_status_t ftun_socks5_server_finish_request(
  ftun_socks5_server_t *server, ftun_status_t downstream_status,
  const ftun_endpoint_t *bound, ftun_socks5_server_event_t *event)
{
  ftun_endpoint_t empty;
  uint8_t reply;
  size_t written = 0u;
  ftun_status_t status;
  if (event != NULL) memset(event, 0, sizeof(*event));
  if (server == NULL || event == NULL ||
      server->state != FTUN_SOCKS5_SERVER_WAIT_DOWNSTREAM) {
    return FTUN_E_INVALID;
  }
  memset(&empty, 0, sizeof(empty));
  empty.kind = FTUN_ADDRESS_IPV4;
  reply = ftun_socks5_reply_for_status(downstream_status);
  if (reply == FTUN_SOCKS5_REPLY_SUCCEEDED && bound == NULL) {
    return FTUN_E_INVALID;
  }
  status = ftun_socks5_encode_reply(reply, bound == NULL ? &empty : bound,
                                    server->reply, sizeof(server->reply),
                                    &written);
  if (status != FTUN_OK) return status;
  server->state = reply != FTUN_SOCKS5_REPLY_SUCCEEDED
    ? FTUN_SOCKS5_SERVER_FAILED
    : (server->command == FTUN_SOCKS5_COMMAND_CONNECT
       ? FTUN_SOCKS5_SERVER_TCP_RELAY : FTUN_SOCKS5_SERVER_UDP_RELAY);
  return ftun_socks5_event_wire(server, FTUN_SOCKS5_SERVER_COMMAND_REPLY,
                                written, event);
}

ftun_status_t ftun_socks5_server_udp(ftun_socks5_server_t *server,
                                     ftun_bytes_t packet,
                                     ftun_socks5_udp_datagram_t *out)
{
  size_t consumed = 0u;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (server == NULL || out == NULL ||
      server->state != FTUN_SOCKS5_SERVER_UDP_RELAY) return FTUN_E_INVALID;
  return ftun_socks5_decode_udp_datagram(packet, out, &consumed);
}

ftun_status_t ftun_socks5_server_destroy(ftun_socks5_server_t **server)
{
  ftun_socks5_server_t *owned;
  ftun_status_t status = FTUN_OK;
  if (server == NULL) return FTUN_E_INVALID;
  owned = *server;
  if (owned == NULL) return FTUN_OK;
  status = ftun_reservation_release(&owned->reservation);
  if (status != FTUN_OK) return status;
  free(owned->credential_bytes);
  free(owned->users);
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *server = NULL;
  return status;
}
