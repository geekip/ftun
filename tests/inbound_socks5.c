#include "inbound/socks5.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "inbound socks5 failed: %s\n", #x); return 1; \
} } while (0)

static ftun_bytes_t raw(const uint8_t *data, size_t length)
{
  ftun_bytes_t result;
  result.data = data;
  result.length = length;
  return result;
}

int main(void)
{
  static const uint8_t username[] = {'u'};
  static const uint8_t password[] = {'p'};
  static const uint8_t offer[] = {5u, 1u, 2u};
  static const uint8_t auth[] = {1u, 1u, 'u', 1u, 'p'};
  static const uint8_t request[] = {
    5u, 1u, 0u, 3u, 11u, 'e','x','a','m','p','l','e','.','c','o','m', 0u, 80u
  };
  static const uint8_t bind[] = {5u, 2u, 0u, 1u, 0u,0u,0u,0u, 0u,0u};
  static const uint8_t udp_fragment[] = {
    0u,0u,1u,1u,1u,2u,3u,4u,0u,53u,'x'
  };
  ftun_inbound_user_t user;
  ftun_inbound_spec_t spec;
  ftun_socks5_server_t *server = NULL;
  ftun_socks5_server_event_t event;
  ftun_socks5_udp_datagram_t datagram;
  ftun_endpoint_t bound;
  size_t consumed = 0u;
  memset(&spec, 0, sizeof(spec));
  user.username = raw(username, sizeof(username));
  user.password = raw(password, sizeof(password));
  spec.kind = FTUN_INBOUND_SOCKS5;
  spec.tcp = true;
  spec.udp = true;
  spec.users = &user;
  spec.user_count = 1u;
  CHECK(ftun_socks5_server_create(&spec, &server) == FTUN_OK);
  CHECK(ftun_socks5_server_feed(server, raw(offer, 1u), &consumed,
                                &event) == FTUN_E_AGAIN);
  CHECK(consumed == 1u);
  CHECK(ftun_socks5_server_feed(server, raw(offer + 1u, 2u), &consumed,
                                &event) == FTUN_OK);
  CHECK(event.kind == FTUN_SOCKS5_SERVER_METHOD_REPLY &&
        event.wire.length == 2u && event.wire.data[1] == 2u);
  CHECK(ftun_socks5_server_feed(server, raw(auth, sizeof(auth)), &consumed,
                                &event) == FTUN_OK);
  CHECK(event.kind == FTUN_SOCKS5_SERVER_AUTH_REPLY && event.wire.data[1] == 0u);
  CHECK(ftun_socks5_server_feed(server, raw(request, sizeof(request)), &consumed,
                                &event) == FTUN_OK);
  CHECK(event.kind == FTUN_SOCKS5_SERVER_REQUEST);
  CHECK(event.command == FTUN_SOCKS5_COMMAND_CONNECT && event.target.port == 80u);
  memset(&bound, 0, sizeof(bound));
  bound.kind = FTUN_ADDRESS_IPV4;
  bound.address[0] = 127u;
  bound.port = 40000u;
  CHECK(ftun_socks5_server_finish_request(server, FTUN_OK, &bound,
                                          &event) == FTUN_OK);
  CHECK(event.wire.data[1] == FTUN_SOCKS5_REPLY_SUCCEEDED);
  CHECK(ftun_socks5_server_destroy(&server) == FTUN_OK && server == NULL);

  spec.user_count = 0u;
  spec.users = NULL;
  CHECK(ftun_socks5_server_create(&spec, &server) == FTUN_OK);
  {
    static const uint8_t no_auth[] = {5u,1u,0u};
    CHECK(ftun_socks5_server_feed(server, raw(no_auth, sizeof(no_auth)),
                                  &consumed, &event) == FTUN_OK);
    CHECK(event.wire.data[1] == 0u);
  }
  CHECK(ftun_socks5_server_feed(server, raw(bind, sizeof(bind)), &consumed,
                                &event) == FTUN_OK);
  CHECK(event.kind == FTUN_SOCKS5_SERVER_COMMAND_REPLY &&
        event.wire.data[1] == FTUN_SOCKS5_REPLY_COMMAND_UNSUPPORTED);
  CHECK(ftun_socks5_server_destroy(&server) == FTUN_OK);

  CHECK(ftun_socks5_server_create(&spec, &server) == FTUN_OK);
  {
    static const uint8_t no_auth[] = {5u,1u,0u};
    static const uint8_t udp[] = {5u,3u,0u,1u,0u,0u,0u,0u,0u,0u};
    CHECK(ftun_socks5_server_feed(server, raw(no_auth, sizeof(no_auth)),
                                  &consumed, &event) == FTUN_OK);
    CHECK(ftun_socks5_server_feed(server, raw(udp, sizeof(udp)),
                                  &consumed, &event) == FTUN_OK);
    CHECK(event.command == FTUN_SOCKS5_COMMAND_UDP_ASSOCIATE);
    CHECK(ftun_socks5_server_finish_request(server, FTUN_OK, &bound,
                                            &event) == FTUN_OK);
  }
  CHECK(ftun_socks5_server_udp(server, raw(udp_fragment, sizeof(udp_fragment)),
                               &datagram) == FTUN_E_UNSUPPORTED);
  CHECK(ftun_socks5_server_destroy(&server) == FTUN_OK);

  spec.udp = false;
  CHECK(ftun_socks5_server_create(&spec, &server) == FTUN_OK);
  {
    static const uint8_t combined[] = {
      5u,1u,0u,
      5u,1u,0u,1u,1u,2u,3u,4u,0u,80u,
      'a','b','c'
    };
    CHECK(ftun_socks5_server_feed(server, raw(combined, sizeof(combined)),
                                  &consumed, &event) == FTUN_OK &&
          consumed == sizeof(combined) && event.wire.data[1] == 0u);
    CHECK(ftun_socks5_server_feed(server, raw(NULL, 0u), &consumed,
                                  &event) == FTUN_OK &&
          event.kind == FTUN_SOCKS5_SERVER_REQUEST &&
          event.command == FTUN_SOCKS5_COMMAND_CONNECT &&
          event.preread.length == 3u &&
          memcmp(event.preread.data, "abc", 3u) == 0);
  }
  CHECK(ftun_socks5_server_destroy(&server) == FTUN_OK);

  CHECK(ftun_socks5_server_create(&spec, &server) == FTUN_OK);
  {
    static const uint8_t no_auth[] = {5u,1u,0u};
    static const uint8_t udp[] = {5u,3u,0u,1u,0u,0u,0u,0u,0u,0u};
    CHECK(ftun_socks5_server_feed(server, raw(no_auth, sizeof(no_auth)),
                                  &consumed, &event) == FTUN_OK);
    CHECK(ftun_socks5_server_feed(server, raw(udp, sizeof(udp)),
                                  &consumed, &event) == FTUN_OK &&
          event.kind == FTUN_SOCKS5_SERVER_COMMAND_REPLY &&
          event.wire.data[1] == FTUN_SOCKS5_REPLY_COMMAND_UNSUPPORTED);
  }
  CHECK(ftun_socks5_server_destroy(&server) == FTUN_OK);
  return 0;
}
