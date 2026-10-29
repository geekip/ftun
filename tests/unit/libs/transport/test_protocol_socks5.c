#include "proxy/protocol/socks5_codec.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "SOCKS5 contract failed at line %d: %s\n", __LINE__, #x); \
    return 1; \
  } \
} while (0)

static ftun_bytes_t bytes(const uint8_t *data, size_t length)
{
  ftun_bytes_t value;
  value.data = data;
  value.length = length;
  return value;
}

static int all_value(const uint8_t *data, size_t length, uint8_t value)
{
  size_t index;
  for (index = 0u; index < length; index++) {
    if (data[index] != value) return 0;
  }
  return 1;
}

static ftun_endpoint_t ipv4_endpoint(uint16_t port)
{
  ftun_endpoint_t endpoint;
  memset(&endpoint, 0, sizeof(endpoint));
  endpoint.kind = FTUN_ADDRESS_IPV4;
  endpoint.address[0] = 192u;
  endpoint.address[1] = 0u;
  endpoint.address[2] = 2u;
  endpoint.address[3] = 7u;
  endpoint.port = port;
  return endpoint;
}

static ftun_endpoint_t domain_endpoint(const char *domain, size_t length,
                                       uint16_t port)
{
  ftun_endpoint_t endpoint;
  memset(&endpoint, 0, sizeof(endpoint));
  endpoint.kind = FTUN_ADDRESS_DOMAIN;
  endpoint.domain.data = domain;
  endpoint.domain.length = length;
  endpoint.port = port;
  return endpoint;
}

static int test_method_negotiation(void)
{
  static const uint8_t methods[] = {
    FTUN_SOCKS5_METHOD_NO_AUTH, FTUN_SOCKS5_METHOD_USERNAME_PASSWORD
  };
  static const uint8_t expected[] = {0x05u, 0x02u, 0x00u, 0x02u};
  static const uint8_t inbound_only[] = {0x05u, 0x01u, 0x00u};
  static const uint8_t outbound_only[] = {0x05u, 0x01u, 0x02u};
  uint8_t output[260];
  uint8_t selection[3] = {0u};
  uint8_t method = 0xa5u;
  size_t written = 99u;
  size_t consumed = 99u;
  size_t length;
  ftun_socks5_method_offer_t offer;
  ftun_socks5_method_offer_t inbound;
  ftun_socks5_method_offer_t outbound;

  memset(output, 0xa5, sizeof(output));
  CHECK(ftun_socks5_encode_method_offer(bytes(methods, sizeof(methods)),
        output, sizeof(output), &written) == FTUN_OK);
  CHECK(written == sizeof(expected));
  CHECK(memcmp(output, expected, sizeof(expected)) == 0);
  output[written] = 0xeeu;
  for (length = 0u; length < sizeof(expected); length++) {
    memset(&offer, 0xa5, sizeof(offer));
    consumed = 99u;
    CHECK(ftun_socks5_decode_method_offer(bytes(output, length), &offer,
          &consumed) == FTUN_E_AGAIN);
    CHECK(consumed == 0u && offer.methods.data == NULL &&
          offer.methods.length == 0u);
  }
  CHECK(ftun_socks5_decode_method_offer(bytes(output, written + 1u), &offer,
        &consumed) == FTUN_OK);
  CHECK(consumed == written && offer.methods.length == 2u);
  CHECK(ftun_socks5_method_offer_contains(&offer,
        FTUN_SOCKS5_METHOD_NO_AUTH));
  CHECK(ftun_socks5_method_offer_contains(&offer,
        FTUN_SOCKS5_METHOD_USERNAME_PASSWORD));
  CHECK(!ftun_socks5_method_offer_contains(&offer, 0x80u));

  /* 两个方向只共享纯解析代码，各自结果互不修改。 */
  CHECK(ftun_socks5_decode_method_offer(bytes(inbound_only,
        sizeof(inbound_only)), &inbound, &consumed) == FTUN_OK);
  CHECK(ftun_socks5_decode_method_offer(bytes(outbound_only,
        sizeof(outbound_only)), &outbound, &consumed) == FTUN_OK);
  CHECK(inbound.methods.data[0] == FTUN_SOCKS5_METHOD_NO_AUTH);
  CHECK(outbound.methods.data[0] == FTUN_SOCKS5_METHOD_USERNAME_PASSWORD);

  written = 99u;
  CHECK(ftun_socks5_encode_method_selection(
        FTUN_SOCKS5_METHOD_USERNAME_PASSWORD, selection, 2u,
        &written) == FTUN_OK);
  CHECK(written == 2u && selection[0] == 0x05u && selection[1] == 0x02u);
  selection[2] = 0x7au;
  CHECK(ftun_socks5_decode_method_selection(bytes(selection, 1u), &method,
        &consumed) == FTUN_E_AGAIN);
  CHECK(method == 0u && consumed == 0u);
  CHECK(ftun_socks5_decode_method_selection(bytes(selection, 3u), &method,
        &consumed) == FTUN_OK);
  CHECK(method == FTUN_SOCKS5_METHOD_USERNAME_PASSWORD && consumed == 2u);

  output[0] = 0x04u;
  memset(&offer, 0xa5, sizeof(offer));
  consumed = 99u;
  CHECK(ftun_socks5_decode_method_offer(bytes(output, written), &offer,
        &consumed) == FTUN_E_PROTOCOL);
  CHECK(consumed == 0u && offer.methods.data == NULL);
  output[0] = 0x05u;
  output[1] = 0u;
  CHECK(ftun_socks5_decode_method_offer(bytes(output, 2u), &offer,
        &consumed) == FTUN_E_PROTOCOL);

  memset(output, 0xa5, sizeof(output));
  written = 99u;
  CHECK(ftun_socks5_encode_method_offer(bytes(methods, sizeof(methods)),
        output, 3u, &written) == FTUN_E_LIMIT);
  CHECK(written == 0u && all_value(output, sizeof(output), 0xa5u));
  CHECK(ftun_socks5_encode_method_offer(bytes(NULL, 0u), output,
        sizeof(output), &written) == FTUN_E_INVALID && written == 0u);
  CHECK(!ftun_socks5_method_offer_contains(NULL, 0u));
  return 0;
}

static int test_method_boundaries(void)
{
  uint8_t methods[FTUN_SOCKS5_MAX_METHODS];
  uint8_t output[FTUN_SOCKS5_MAX_METHODS + 2u];
  uint8_t too_many[FTUN_SOCKS5_MAX_METHODS + 1u];
  ftun_socks5_method_offer_t offer;
  size_t written = 0u;
  size_t consumed = 0u;
  size_t index;
  for (index = 0u; index < sizeof(methods); index++) {
    methods[index] = (uint8_t)index;
  }
  CHECK(ftun_socks5_encode_method_offer(bytes(methods, sizeof(methods)),
        output, sizeof(output), &written) == FTUN_OK);
  CHECK(written == sizeof(output) && output[1] == 0xffu);
  CHECK(ftun_socks5_decode_method_offer(bytes(output, sizeof(output)), &offer,
        &consumed) == FTUN_OK);
  CHECK(consumed == sizeof(output) && offer.methods.length == sizeof(methods));
  CHECK(ftun_socks5_encode_method_offer(bytes(too_many, sizeof(too_many)),
        output, sizeof(output), &written) == FTUN_E_INVALID);
  return 0;
}

static int test_credentials(void)
{
  static const uint8_t username[] = {'a', 'l', 'i', 'c', 'e'};
  static const uint8_t password[] = {'s', 'e', 'c', 'r', 'e', 't'};
  static const uint8_t expected[] = {
    0x01u, 0x05u, 'a', 'l', 'i', 'c', 'e',
    0x06u, 's', 'e', 'c', 'r', 'e', 't'
  };
  uint8_t output[520];
  uint8_t maximum[255];
  uint8_t oversized[256];
  uint8_t status = 0xa5u;
  ftun_socks5_credentials_t credentials;
  size_t written = 0u;
  size_t consumed = 0u;
  size_t length;
  memset(maximum, 0x61, sizeof(maximum));
  memset(oversized, 0x62, sizeof(oversized));

  CHECK(ftun_socks5_encode_credentials(bytes(username, sizeof(username)),
        bytes(password, sizeof(password)), output, sizeof(output),
        &written) == FTUN_OK);
  CHECK(written == sizeof(expected));
  CHECK(memcmp(output, expected, sizeof(expected)) == 0);
  output[written] = 0xeeu;
  for (length = 0u; length < sizeof(expected); length++) {
    memset(&credentials, 0xa5, sizeof(credentials));
    CHECK(ftun_socks5_decode_credentials(bytes(output, length), &credentials,
          &consumed) == FTUN_E_AGAIN);
    CHECK(consumed == 0u && credentials.username.data == NULL &&
          credentials.password.data == NULL);
  }
  CHECK(ftun_socks5_decode_credentials(bytes(output, written + 1u),
        &credentials, &consumed) == FTUN_OK);
  CHECK(consumed == written && credentials.username.length == sizeof(username));
  CHECK(credentials.password.length == sizeof(password));
  CHECK(memcmp(credentials.username.data, username, sizeof(username)) == 0);
  CHECK(memcmp(credentials.password.data, password, sizeof(password)) == 0);

  CHECK(ftun_socks5_encode_credentials(bytes(maximum, sizeof(maximum)),
        bytes(maximum, sizeof(maximum)), output, sizeof(output),
        &written) == FTUN_OK);
  CHECK(written == 513u);
  CHECK(ftun_socks5_decode_credentials(bytes(output, written), &credentials,
        &consumed) == FTUN_OK);
  CHECK(credentials.username.length == 255u &&
        credentials.password.length == 255u);
  CHECK(ftun_socks5_encode_credentials(bytes(oversized, sizeof(oversized)),
        bytes(maximum, sizeof(maximum)), output, sizeof(output),
        &written) == FTUN_E_INVALID);

  output[0] = 0x02u;
  CHECK(ftun_socks5_decode_credentials(bytes(output, 1u), &credentials,
        &consumed) == FTUN_E_PROTOCOL);
  output[0] = 0x01u;
  output[1] = 0u;
  CHECK(ftun_socks5_decode_credentials(bytes(output, 2u), &credentials,
        &consumed) == FTUN_E_PROTOCOL);
  output[1] = 1u;
  output[2] = 'x';
  output[3] = 0u;
  CHECK(ftun_socks5_decode_credentials(bytes(output, 4u), &credentials,
        &consumed) == FTUN_E_PROTOCOL);

  CHECK(ftun_socks5_encode_auth_result(1u, output, sizeof(output),
        &written) == FTUN_OK);
  CHECK(written == 2u && output[0] == 0x01u && output[1] == 1u);
  CHECK(ftun_socks5_decode_auth_result(bytes(output, 1u), &status,
        &consumed) == FTUN_E_AGAIN);
  CHECK(status == 0u && consumed == 0u);
  CHECK(ftun_socks5_decode_auth_result(bytes(output, 2u), &status,
        &consumed) == FTUN_OK);
  CHECK(status == 1u && consumed == 2u);
  output[0] = 0x05u;
  CHECK(ftun_socks5_decode_auth_result(bytes(output, 2u), &status,
        &consumed) == FTUN_E_PROTOCOL);
  return 0;
}

static int test_request_reply_ipv4(void)
{
  static const uint8_t expected_request[] = {
    0x05u, 0x01u, 0x00u, 0x01u, 192u, 0u, 2u, 7u, 0x12u, 0x34u
  };
  static const uint8_t expected_reply[] = {
    0x05u, 0x05u, 0x00u, 0x01u, 192u, 0u, 2u, 7u, 0x12u, 0x34u
  };
  uint8_t output[32];
  ftun_endpoint_t endpoint = ipv4_endpoint(0x1234u);
  ftun_socks5_request_t request;
  ftun_socks5_reply_t reply;
  ftun_protocol_result_t generic;
  size_t written = 0u;
  size_t consumed = 0u;
  size_t length;

  CHECK(ftun_socks5_encode_request(FTUN_SOCKS5_COMMAND_CONNECT, &endpoint,
        output, sizeof(output), &written) == FTUN_OK);
  CHECK(written == sizeof(expected_request));
  CHECK(memcmp(output, expected_request, sizeof(expected_request)) == 0);
  output[written] = 0xeeu;
  for (length = 0u; length < sizeof(expected_request); length++) {
    memset(&request, 0xa5, sizeof(request));
    CHECK(ftun_socks5_decode_request(bytes(output, length), &request,
          &consumed) == FTUN_E_AGAIN);
    CHECK(consumed == 0u && request.command == 0 &&
          request.endpoint.kind == FTUN_ADDRESS_NONE);
  }
  CHECK(ftun_socks5_decode_request(bytes(output, written + 1u), &request,
        &consumed) == FTUN_OK);
  CHECK(consumed == written && request.command == FTUN_SOCKS5_COMMAND_CONNECT);
  CHECK(request.endpoint.kind == FTUN_ADDRESS_IPV4 &&
        request.endpoint.port == 0x1234u);
  CHECK(memcmp(request.endpoint.address, endpoint.address, 4u) == 0);
  CHECK(ftun_socks5_decode(bytes(output, written + 1u), &generic) == FTUN_OK);
  CHECK(generic.complete && generic.consumed == written &&
        generic.target.port == 0x1234u);

  CHECK(ftun_socks5_encode_reply(FTUN_SOCKS5_REPLY_CONNECTION_REFUSED,
        &endpoint, output, sizeof(output), &written) == FTUN_OK);
  CHECK(written == sizeof(expected_reply));
  CHECK(memcmp(output, expected_reply, sizeof(expected_reply)) == 0);
  output[written] = 0xeeu;
  CHECK(ftun_socks5_decode_reply(bytes(output, written + 1u), &reply,
        &consumed) == FTUN_OK);
  CHECK(consumed == written &&
        reply.reply == FTUN_SOCKS5_REPLY_CONNECTION_REFUSED &&
        reply.endpoint.port == 0x1234u);
  return 0;
}

static int test_request_reply_domain(void)
{
  static const char name[] = "example.com";
  static const uint8_t expected[] = {
    0x05u, 0x03u, 0x00u, 0x03u, 0x0bu,
    'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01u, 0xbbu
  };
  char maximum[255];
  uint8_t output[300];
  ftun_endpoint_t endpoint = domain_endpoint(name, sizeof(name) - 1u, 443u);
  ftun_endpoint_t maximum_endpoint;
  ftun_socks5_request_t request;
  ftun_socks5_reply_t reply;
  size_t written = 0u;
  size_t consumed = 0u;
  size_t length;
  memset(maximum, 'd', sizeof(maximum));

  CHECK(ftun_socks5_encode_request(FTUN_SOCKS5_COMMAND_UDP_ASSOCIATE,
        &endpoint, output, sizeof(output), &written) == FTUN_OK);
  CHECK(written == sizeof(expected));
  CHECK(memcmp(output, expected, sizeof(expected)) == 0);
  for (length = 0u; length < sizeof(expected); length++) {
    CHECK(ftun_socks5_decode_request(bytes(output, length), &request,
          &consumed) == FTUN_E_AGAIN);
    CHECK(consumed == 0u && request.endpoint.domain.data == NULL);
  }
  CHECK(ftun_socks5_decode_request(bytes(output, written), &request,
        &consumed) == FTUN_OK);
  CHECK(request.command == FTUN_SOCKS5_COMMAND_UDP_ASSOCIATE);
  CHECK(request.endpoint.kind == FTUN_ADDRESS_DOMAIN &&
        request.endpoint.port == 443u &&
        request.endpoint.domain.length == sizeof(name) - 1u);
  CHECK(memcmp(request.endpoint.domain.data, name, sizeof(name) - 1u) == 0);

  maximum_endpoint = domain_endpoint(maximum, sizeof(maximum), 65535u);
  CHECK(ftun_socks5_encode_reply(FTUN_SOCKS5_REPLY_SUCCEEDED,
        &maximum_endpoint, output, sizeof(output), &written) == FTUN_OK);
  CHECK(written == 262u && output[3] == 0x03u && output[4] == 0xffu &&
        output[260] == 0xffu && output[261] == 0xffu);
  CHECK(ftun_socks5_decode_reply(bytes(output, written), &reply,
        &consumed) == FTUN_OK);
  CHECK(consumed == written && reply.endpoint.domain.length == 255u &&
        reply.endpoint.port == 65535u);
  return 0;
}

static int test_request_failures(void)
{
  uint8_t frame[32] = {
    0x05u, 0x01u, 0x00u, 0x01u, 127u, 0u, 0u, 1u, 0u, 80u
  };
  uint8_t output[32];
  char too_long[256] = {0};
  ftun_socks5_request_t request;
  ftun_socks5_reply_t reply;
  ftun_endpoint_t endpoint = ipv4_endpoint(80u);
  ftun_endpoint_t bad_domain = domain_endpoint(too_long, sizeof(too_long), 1u);
  ftun_endpoint_t ipv6;
  size_t consumed = 99u;
  size_t written = 99u;
  memset(&ipv6, 0, sizeof(ipv6));
  ipv6.kind = FTUN_ADDRESS_IPV6_RESERVED;

  frame[0] = 0x04u;
  CHECK(ftun_socks5_decode_request(bytes(frame, 10u), &request,
        &consumed) == FTUN_E_PROTOCOL && consumed == 0u);
  frame[0] = 0x05u;
  frame[1] = 0x02u;
  CHECK(ftun_socks5_decode_request(bytes(frame, 2u), &request,
        &consumed) == FTUN_E_UNSUPPORTED && consumed == 0u);
  CHECK(ftun_socks5_encode_request(FTUN_SOCKS5_COMMAND_BIND, &endpoint,
        output, sizeof(output), &written) == FTUN_E_UNSUPPORTED &&
        written == 0u);
  frame[1] = 0x7fu;
  CHECK(ftun_socks5_decode_request(bytes(frame, 2u), &request,
        &consumed) == FTUN_E_PROTOCOL);
  frame[1] = 0x01u;
  frame[2] = 1u;
  CHECK(ftun_socks5_decode_request(bytes(frame, 10u), &request,
        &consumed) == FTUN_E_PROTOCOL);
  frame[2] = 0u;
  frame[3] = 0x7fu;
  CHECK(ftun_socks5_decode_request(bytes(frame, 4u), &request,
        &consumed) == FTUN_E_PROTOCOL);
  frame[3] = 0x03u;
  frame[4] = 0u;
  CHECK(ftun_socks5_decode_request(bytes(frame, 5u), &request,
        &consumed) == FTUN_E_PROTOCOL);
  frame[3] = 0x04u;
  CHECK(ftun_socks5_decode_request(bytes(frame, 4u), &request,
        &consumed) == FTUN_E_UNSUPPORTED);
  CHECK(ftun_socks5_encode_request(FTUN_SOCKS5_COMMAND_CONNECT, &ipv6,
        output, sizeof(output), &written) == FTUN_E_UNSUPPORTED);
  CHECK(ftun_socks5_encode_request(FTUN_SOCKS5_COMMAND_CONNECT, &bad_domain,
        output, sizeof(output), &written) == FTUN_E_INVALID);

  frame[0] = 0x05u;
  frame[1] = 0xffu;
  frame[2] = 1u;
  CHECK(ftun_socks5_decode_reply(bytes(frame, 10u), &reply,
        &consumed) == FTUN_E_PROTOCOL);
  frame[2] = 0u;
  frame[3] = 0x04u;
  /* 回复的 BND 字段允许 IPv6：不足 22 字节等待更多输入，完整时解析成功。 */
  CHECK(ftun_socks5_decode_reply(bytes(frame, 4u), &reply,
        &consumed) == FTUN_E_AGAIN && consumed == 0u);
  {
    uint8_t ipv6_reply[23];
    memset(ipv6_reply, 0, sizeof(ipv6_reply));
    ipv6_reply[0] = 0x05u;
    ipv6_reply[3] = 0x04u;
    ipv6_reply[4] = 0x20u;
    ipv6_reply[19] = 0x01u;
    ipv6_reply[20] = 0x1fu;
    ipv6_reply[21] = 0x90u;
    ipv6_reply[22] = 0x77u;
    CHECK(ftun_socks5_decode_reply(bytes(ipv6_reply, 21u), &reply,
          &consumed) == FTUN_E_AGAIN && consumed == 0u);
    CHECK(ftun_socks5_decode_reply(bytes(ipv6_reply, sizeof(ipv6_reply)),
          &reply, &consumed) == FTUN_OK);
    CHECK(consumed == 22u && reply.reply == 0u &&
          reply.endpoint.kind == FTUN_ADDRESS_IPV6_RESERVED &&
          reply.endpoint.address[0] == 0x20u &&
          reply.endpoint.address[15] == 0x01u &&
          reply.endpoint.port == 8080u);
    ipv6_reply[1] = 0x05u;
    CHECK(ftun_socks5_decode_reply(bytes(ipv6_reply, 22u), &reply,
          &consumed) == FTUN_OK && reply.reply == 0x05u);
  }
  /* 请求目标中的 IPv6 仍未开放，入站据此回复 ADDRESS_UNSUPPORTED。 */
  frame[1] = 0x01u;
  CHECK(ftun_socks5_decode_request(bytes(frame, 4u), &request,
        &consumed) == FTUN_E_UNSUPPORTED);

  memset(output, 0xa5, sizeof(output));
  written = 99u;
  CHECK(ftun_socks5_encode_reply(0u, &endpoint, output, 9u,
        &written) == FTUN_E_LIMIT);
  CHECK(written == 0u && all_value(output, sizeof(output), 0xa5u));
  CHECK(ftun_socks5_decode_request(bytes(NULL, 1u), &request,
        &consumed) == FTUN_E_INVALID);
  CHECK(ftun_socks5_decode_request(bytes(frame, sizeof(frame)), NULL,
        &consumed) == FTUN_E_INVALID);
  return 0;
}

static int test_udp_datagrams(void)
{
  static const char name[] = "dns.example";
  static const uint8_t payload[] = {0xdeu, 0xadu, 0xbeu, 0xefu};
  static const uint8_t expected[] = {
    0x00u, 0x00u, 0x00u, 0x03u, 0x0bu,
    'd', 'n', 's', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x00u, 0x35u, 0xdeu, 0xadu, 0xbeu, 0xefu
  };
  uint8_t output[64];
  ftun_endpoint_t endpoint = domain_endpoint(name, sizeof(name) - 1u, 53u);
  ftun_socks5_udp_datagram_t datagram;
  size_t written = 0u;
  size_t consumed = 0u;
  size_t length;

  CHECK(ftun_socks5_encode_udp_datagram(&endpoint,
        bytes(payload, sizeof(payload)), output, sizeof(output),
        &written) == FTUN_OK);
  CHECK(written == sizeof(expected));
  CHECK(memcmp(output, expected, sizeof(expected)) == 0);
  for (length = 0u; length < sizeof(expected) - sizeof(payload); length++) {
    CHECK(ftun_socks5_decode_udp_datagram(bytes(output, length), &datagram,
          &consumed) == FTUN_E_AGAIN);
    CHECK(consumed == 0u && datagram.payload.data == NULL);
  }
  CHECK(ftun_socks5_decode_udp_datagram(bytes(output,
        sizeof(expected) - sizeof(payload)), &datagram, &consumed) == FTUN_OK);
  CHECK(datagram.payload.length == 0u &&
        consumed == sizeof(expected) - sizeof(payload));
  CHECK(ftun_socks5_decode_udp_datagram(bytes(output, written), &datagram,
        &consumed) == FTUN_OK);
  CHECK(consumed == written && datagram.endpoint.port == 53u &&
        datagram.payload.length == sizeof(payload));
  CHECK(memcmp(datagram.payload.data, payload, sizeof(payload)) == 0);

  output[0] = 1u;
  CHECK(ftun_socks5_decode_udp_datagram(bytes(output, written), &datagram,
        &consumed) == FTUN_E_PROTOCOL);
  output[0] = 0u;
  output[2] = 1u;
  CHECK(ftun_socks5_decode_udp_datagram(bytes(output, written), &datagram,
        &consumed) == FTUN_E_UNSUPPORTED);
  CHECK(consumed == 0u && datagram.payload.data == NULL);
  output[2] = 0u;
  output[3] = 0x04u;
  CHECK(ftun_socks5_decode_udp_datagram(bytes(output, written), &datagram,
        &consumed) == FTUN_E_UNSUPPORTED);

  memset(output, 0xa5, sizeof(output));
  written = 99u;
  CHECK(ftun_socks5_encode_udp_datagram(&endpoint,
        bytes(payload, sizeof(payload)), output, sizeof(expected) - 1u,
        &written) == FTUN_E_LIMIT);
  CHECK(written == 0u && all_value(output, sizeof(output), 0xa5u));
  CHECK(ftun_socks5_encode_udp_datagram(&endpoint, bytes(NULL, 1u), output,
        sizeof(output), &written) == FTUN_E_INVALID);
  return 0;
}

int main(void)
{
  CHECK(test_method_negotiation() == 0);
  CHECK(test_method_boundaries() == 0);
  CHECK(test_credentials() == 0);
  CHECK(test_request_reply_ipv4() == 0);
  CHECK(test_request_reply_domain() == 0);
  CHECK(test_request_failures() == 0);
  CHECK(test_udp_datagrams() == 0);
  return 0;
}
