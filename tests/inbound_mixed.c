#include "inbound/mixed.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "mixed inbound failed: %s\n", #x); return 1; \
} } while (0)

static ftun_bytes_t raw(const void *data, size_t length)
{
  ftun_bytes_t result;
  result.data = (const uint8_t *)data;
  result.length = length;
  return result;
}

static ftun_bytes_t text(const char *value)
{
  return raw(value, strlen(value));
}

static ftun_inbound_spec_t mixed_spec(const ftun_inbound_user_t *users,
                                      size_t user_count)
{
  ftun_inbound_spec_t spec;
  memset(&spec, 0, sizeof(spec));
  spec.kind = FTUN_INBOUND_MIXED;
  spec.tcp = true;
  spec.udp = true;
  spec.users = users;
  spec.user_count = user_count;
  return spec;
}

int main(void)
{
  static const uint8_t username[] = {'u'};
  static const uint8_t password[] = {'p'};
  static const uint8_t socks_offer[] = {5u, 1u, 2u};
  static const uint8_t socks_auth[] = {1u, 1u, 'u', 1u, 'p'};
  static const uint8_t socks_udp_request[] = {
    5u, 3u, 0u, 1u, 0u, 0u, 0u, 0u, 0u, 0u
  };
  static const uint8_t socks_udp_packet[] = {
    0u, 0u, 0u, 1u, 1u, 2u, 3u, 4u, 0u, 53u, 'x'
  };
  static const char unauthorized[] =
    "GET http://one.example/ HTTP/1.1\r\nHost: one.example\r\n\r\n";
  static const char first[] =
    "POST http://one.example/a HTTP/1.1\r\n"
    "Host: one.example\r\nProxy-Authorization: Basic dTpw\r\n"
    "Content-Length: 3\r\n\r\nx";
  static const char second[] =
    "GET http://two.example/b HTTP/1.1\r\n"
    "Host: two.example\r\nProxy-Authorization: Basic dTpw\r\n\r\n";
  static const char first_get[] =
    "GET http://one.example/a HTTP/1.1\r\n"
    "Host: one.example\r\nProxy-Authorization: Basic dTpw\r\n\r\n";
  static const char connect[] =
    "CONNECT tunnel.example:443 HTTP/1.1\r\n"
    "Host: tunnel.example:443\r\n\r\n";
  ftun_inbound_user_t user;
  ftun_inbound_spec_t spec;
  ftun_mixed_connection_t *connection = NULL;
  ftun_mixed_event_t event;
  ftun_mixed_protocol_t protocol = 0;
  ftun_socks5_udp_datagram_t datagram;
  ftun_endpoint_t bound;
  size_t consumed = 0u;
  char pipeline[sizeof(first_get) + sizeof(second)];

  user.username = raw(username, sizeof(username));
  user.password = raw(password, sizeof(password));
  spec = mixed_spec(&user, 1u);

  CHECK(ftun_mixed_classify(raw(NULL, 0u), &protocol) == FTUN_E_AGAIN);
  CHECK(ftun_mixed_classify(raw("\x16", 1u), &protocol) == FTUN_E_PROTOCOL);
  CHECK(ftun_mixed_classify(raw(socks_offer, sizeof(socks_offer)),
                            &protocol) == FTUN_OK &&
        protocol == FTUN_MIXED_PROTOCOL_SOCKS5);
  CHECK(ftun_mixed_classify(text("GET "), &protocol) == FTUN_OK &&
        protocol == FTUN_MIXED_PROTOCOL_HTTP);

  CHECK(ftun_mixed_connection_create(&spec, &connection) == FTUN_OK);
  CHECK(ftun_mixed_connection_feed(connection, text(unauthorized), &consumed,
                                   &event) == FTUN_OK);
  CHECK(consumed == strlen(unauthorized) &&
        event.kind == FTUN_MIXED_EVENT_HTTP_REPLY &&
        event.wire.length > 12u && event.wire.data[9] == (uint8_t)'4' &&
        event.wire.data[10] == (uint8_t)'0' &&
        event.wire.data[11] == (uint8_t)'7');
  CHECK(ftun_mixed_connection_destroy(&connection) == FTUN_OK);

  CHECK(ftun_mixed_connection_create(&spec, &connection) == FTUN_OK);
  CHECK(ftun_mixed_connection_feed(connection, raw(first, 7u), &consumed,
                                   &event) == FTUN_E_AGAIN && consumed == 7u);
  CHECK(ftun_mixed_connection_feed(connection,
          raw(first + 7u, strlen(first) - 7u), &consumed, &event) == FTUN_OK);
  CHECK(event.kind == FTUN_MIXED_EVENT_HTTP_REQUEST &&
        event.http.kind == FTUN_HTTP_PROXY_FORWARD &&
        event.http.target.kind == FTUN_ADDRESS_DOMAIN &&
        event.http.target.domain.length == strlen("one.example") &&
        event.body_remaining == 2u && event.wire.length == strlen(first));
  CHECK(ftun_mixed_http_finish(connection, FTUN_OK, &event) == FTUN_OK &&
        event.kind == FTUN_MIXED_EVENT_HTTP_REPLY && event.wire.length == 0u &&
        event.body_remaining == 2u);
  CHECK(ftun_mixed_connection_feed(connection, text("yz"), &consumed,
                                   &event) == FTUN_OK && consumed == 2u &&
        event.kind == FTUN_MIXED_EVENT_HTTP_BODY &&
        event.body_remaining == 0u);
  CHECK(ftun_mixed_connection_destroy(&connection) == FTUN_OK);

  memcpy(pipeline, first_get, strlen(first_get));
  memcpy(pipeline + strlen(first_get), second, strlen(second));
  CHECK(ftun_mixed_connection_create(&spec, &connection) == FTUN_OK);
  CHECK(ftun_mixed_connection_feed(connection,
          raw(pipeline, strlen(first_get) + strlen(second)), &consumed,
          &event) == FTUN_OK);
  CHECK(event.kind == FTUN_MIXED_EVENT_HTTP_REQUEST &&
        event.body_remaining == 0u);
  CHECK(ftun_mixed_http_finish(connection, FTUN_OK, &event) == FTUN_OK);
  CHECK(ftun_mixed_connection_feed(connection, raw(NULL, 0u), &consumed,
                                   &event) == FTUN_OK);
  CHECK(event.kind == FTUN_MIXED_EVENT_HTTP_REQUEST &&
        event.http.target.domain.length == strlen("two.example") &&
        memcmp(event.http.target.domain.data, "two.example",
               strlen("two.example")) == 0);
  CHECK(ftun_mixed_http_finish(connection, FTUN_E_REJECTED, &event) ==
        FTUN_OK);
  CHECK(event.wire.length > 12u && event.wire.data[9] == (uint8_t)'4' &&
        event.wire.data[10] == (uint8_t)'0' &&
        event.wire.data[11] == (uint8_t)'3');
  CHECK(ftun_mixed_connection_destroy(&connection) == FTUN_OK);

  spec = mixed_spec(NULL, 0u);
  CHECK(ftun_mixed_connection_create(&spec, &connection) == FTUN_OK);
  CHECK(ftun_mixed_connection_feed(connection, text(connect), &consumed,
                                   &event) == FTUN_OK);
  CHECK(event.kind == FTUN_MIXED_EVENT_HTTP_REQUEST &&
        event.http.kind == FTUN_HTTP_PROXY_CONNECT);
  CHECK(ftun_mixed_http_finish(connection, FTUN_OK, &event) == FTUN_OK);
  CHECK(event.kind == FTUN_MIXED_EVENT_HTTP_REPLY &&
        event.wire.length > 12u && event.wire.data[9] == (uint8_t)'2');
  CHECK(ftun_mixed_connection_destroy(&connection) == FTUN_OK);

  spec = mixed_spec(&user, 1u);
  CHECK(ftun_mixed_connection_create(&spec, &connection) == FTUN_OK);
  CHECK(ftun_mixed_connection_feed(connection,
          raw(socks_offer, sizeof(socks_offer)), &consumed, &event) == FTUN_OK);
  CHECK(event.kind == FTUN_MIXED_EVENT_SOCKS5 &&
        event.socks5.kind == FTUN_SOCKS5_SERVER_METHOD_REPLY &&
        event.socks5.wire.length == 2u && event.socks5.wire.data[1] == 2u);
  CHECK(ftun_mixed_connection_feed(connection,
          raw(socks_auth, sizeof(socks_auth)), &consumed, &event) == FTUN_OK &&
        event.socks5.kind == FTUN_SOCKS5_SERVER_AUTH_REPLY &&
        event.socks5.wire.data[1] == 0u);
  CHECK(ftun_mixed_connection_feed(connection,
          raw(socks_udp_request, sizeof(socks_udp_request)), &consumed,
          &event) == FTUN_OK &&
        event.socks5.kind == FTUN_SOCKS5_SERVER_REQUEST &&
        event.socks5.command == FTUN_SOCKS5_COMMAND_UDP_ASSOCIATE);
  memset(&bound, 0, sizeof(bound));
  bound.kind = FTUN_ADDRESS_IPV4;
  bound.address[0] = 127u;
  bound.port = 1081u;
  CHECK(ftun_mixed_socks5_finish_request(connection, FTUN_OK, &bound,
                                         &event) == FTUN_OK &&
        event.socks5.wire.data[1] == FTUN_SOCKS5_REPLY_SUCCEEDED);
  CHECK(ftun_mixed_socks5_udp(connection,
          raw(socks_udp_packet, sizeof(socks_udp_packet)), &datagram) ==
        FTUN_OK && datagram.endpoint.port == 53u &&
        datagram.payload.length == 1u);
  CHECK(ftun_mixed_connection_destroy(&connection) == FTUN_OK);
  return 0;
}
