#include "proxy/protocol/socks5_client.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "socks5 client contract failed at line %d: %s\n", __LINE__, #x); \
    return 1; \
  } \
} while (0)

static ftun_endpoint_t ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port)
{
  ftun_endpoint_t endpoint;
  memset(&endpoint, 0, sizeof(endpoint));
  endpoint.kind = FTUN_ADDRESS_IPV4;
  endpoint.address[0] = a; endpoint.address[1] = b;
  endpoint.address[2] = c; endpoint.address[3] = d;
  endpoint.port = port;
  return endpoint;
}

/* 向状态机逐字节喂入服务端回复，直到它不再需要输入。 */
static ftun_status_t feed(ftun_socks5_client_t *client, const uint8_t *bytes,
                          size_t length, size_t chunk,
                          ftun_socks5_client_result_t *result, size_t *used)
{
  size_t offset = 0u;
  ftun_status_t status = FTUN_E_AGAIN;
  while (offset < length) {
    size_t take = length - offset < chunk ? length - offset : chunk;
    size_t consumed = 0u;
    if (ftun_socks5_client_wants_output(client)) return status;
    status = ftun_socks5_client_input(client, (ftun_bytes_t){bytes + offset, take},
                                      &consumed, result);
    offset += consumed;
    if (status != FTUN_E_AGAIN) break;
    if (consumed == 0u) break;
  }
  *used = offset;
  return status;
}

static int send_frame(ftun_socks5_client_t *client, const uint8_t *expected, size_t length)
{
  uint8_t frame[FTUN_SOCKS5_CLIENT_FRAME_BYTES];
  size_t written = 0u;
  CHECK(ftun_socks5_client_wants_output(client));
  CHECK(ftun_socks5_client_output(client, frame, sizeof(frame), &written) == FTUN_OK);
  CHECK(written == length && memcmp(frame, expected, length) == 0);
  /* 同一帧发完之前重复取得到相同内容。 */
  CHECK(ftun_socks5_client_output(client, frame, sizeof(frame), &written) == FTUN_OK &&
        written == length);
  CHECK(ftun_socks5_client_output_done(client) == FTUN_OK);
  CHECK(!ftun_socks5_client_wants_output(client));
  return 0;
}

static int test_connect_no_auth(size_t chunk)
{
  ftun_socks5_client_t client;
  ftun_socks5_client_options_t options;
  ftun_socks5_client_result_t result;
  size_t used = 0u;
  static const uint8_t offer[] = {5, 1, 0};
  static const uint8_t request[] = {5, 1, 0, 1, 203, 0, 113, 9, 0x01, 0xbb};
  static const uint8_t selection[] = {5, 0};
  static const uint8_t reply[] = {5, 0, 0, 1, 10, 0, 0, 1, 0x1f, 0x90, 'T', 'U', 'N'};
  memset(&options, 0, sizeof(options));
  options.command = FTUN_SOCKS5_COMMAND_CONNECT;
  options.target = ipv4(203, 0, 113, 9, 443u);
  CHECK(ftun_socks5_client_init(&client, &options) == FTUN_OK);
  CHECK(send_frame(&client, offer, sizeof(offer)) == 0);
  CHECK(ftun_socks5_client_needed(&client) == 2u);
  CHECK(feed(&client, selection, sizeof(selection), chunk, &result, &used) == FTUN_E_AGAIN);
  CHECK(used == 2u && ftun_socks5_client_wants_output(&client));
  CHECK(send_frame(&client, request, sizeof(request)) == 0);
  /* 只取走回复本身；后面的隧道数据原样归还调用方。 */
  CHECK(feed(&client, reply, sizeof(reply), chunk, &result, &used) == FTUN_OK);
  CHECK(used == 10u && result.reply == 0u && result.bound.kind == FTUN_ADDRESS_IPV4 &&
        result.bound.port == 8080u && result.bound.address[0] == 10u);
  return 0;
}

static int test_auth(void)
{
  ftun_socks5_client_t client;
  ftun_socks5_client_options_t options;
  ftun_socks5_client_result_t result;
  size_t used = 0u;
  static const uint8_t offer[] = {5, 1, 2};
  static const uint8_t credentials[] = {1, 3, 'b', 'o', 'b', 2, 'p', 'w'};
  static const uint8_t request[] = {5, 1, 0, 3, 7, 'a', '.', 'e', 'x', 'a', 'm', 'p', 0, 80};
  memset(&options, 0, sizeof(options));
  options.command = FTUN_SOCKS5_COMMAND_CONNECT;
  options.username = (ftun_bytes_t){(const uint8_t *)"bob", 3u};
  options.password = (ftun_bytes_t){(const uint8_t *)"pw", 2u};
  options.target.kind = FTUN_ADDRESS_DOMAIN;
  options.target.domain = (ftun_string_t){"a.examp", 7u};
  options.target.port = 80u;
  CHECK(ftun_socks5_client_init(&client, &options) == FTUN_OK);
  CHECK(send_frame(&client, offer, sizeof(offer)) == 0);
  CHECK(feed(&client, (const uint8_t[]){5, 2}, 2u, 1u, &result, &used) == FTUN_E_AGAIN);
  CHECK(send_frame(&client, credentials, sizeof(credentials)) == 0);
  CHECK(ftun_socks5_client_needed(&client) == 2u);
  CHECK(feed(&client, (const uint8_t[]){1, 0}, 2u, 1u, &result, &used) == FTUN_E_AGAIN);
  CHECK(send_frame(&client, request, sizeof(request)) == 0);
  /* 域名形式的 BND：需要的字节数随长度字节变化。 */
  CHECK(feed(&client, (const uint8_t[]){5, 0, 0, 3, 2, 'h', 'i', 0, 53}, 9u, 1u,
             &result, &used) == FTUN_OK);
  CHECK(used == 9u && result.bound.kind == FTUN_ADDRESS_DOMAIN &&
        result.bound.domain.length == 2u && result.bound.port == 53u);
  return 0;
}

static int test_udp_associate_and_ipv6_bnd(void)
{
  ftun_socks5_client_t client;
  ftun_socks5_client_options_t options;
  ftun_socks5_client_result_t result;
  size_t used = 0u;
  uint8_t reply[22] = {5, 0, 0, 4};
  static const uint8_t request[] = {5, 3, 0, 1, 0, 0, 0, 0, 0, 0};
  memset(&options, 0, sizeof(options));
  options.command = FTUN_SOCKS5_COMMAND_UDP_ASSOCIATE;
  options.target = ipv4(1, 2, 3, 4, 53u); /* UDP ASSOCIATE 忽略目标 */
  CHECK(ftun_socks5_client_init(&client, &options) == FTUN_OK);
  CHECK(send_frame(&client, (const uint8_t[]){5, 1, 0}, 3u) == 0);
  CHECK(feed(&client, (const uint8_t[]){5, 0}, 2u, 2u, &result, &used) == FTUN_E_AGAIN);
  CHECK(send_frame(&client, request, sizeof(request)) == 0);
  reply[20] = 0x04u; reply[21] = 0xd2u;
  CHECK(feed(&client, reply, sizeof(reply), 7u, &result, &used) == FTUN_OK);
  CHECK(used == 22u && result.bound.kind == FTUN_ADDRESS_IPV6 &&
        result.bound.port == 1234u);
  return 0;
}

static int test_failures(void)
{
  ftun_socks5_client_t client;
  ftun_socks5_client_options_t options;
  ftun_socks5_client_result_t result;
  size_t used = 0u;
  size_t index;
  static const struct { uint8_t code; ftun_status_t status; } replies[] = {
    {1, FTUN_E_IO}, {2, FTUN_E_REJECTED}, {3, FTUN_E_REJECTED}, {4, FTUN_E_REJECTED},
    {5, FTUN_E_REJECTED}, {6, FTUN_E_TIMEOUT}, {7, FTUN_E_UNSUPPORTED},
    {8, FTUN_E_UNSUPPORTED}, {9, FTUN_E_PROTOCOL}
  };
  memset(&options, 0, sizeof(options));
  options.command = FTUN_SOCKS5_COMMAND_CONNECT;
  options.target = ipv4(203, 0, 113, 9, 443u);
  /* 服务端无可接受方法 / 选了没提供的方法 / 版本不对。 */
  CHECK(ftun_socks5_client_init(&client, &options) == FTUN_OK);
  CHECK(send_frame(&client, (const uint8_t[]){5, 1, 0}, 3u) == 0);
  CHECK(feed(&client, (const uint8_t[]){5, 0xff}, 2u, 2u, &result, &used) == FTUN_E_REJECTED);
  CHECK(ftun_socks5_client_init(&client, &options) == FTUN_OK);
  CHECK(send_frame(&client, (const uint8_t[]){5, 1, 0}, 3u) == 0);
  CHECK(feed(&client, (const uint8_t[]){5, 2}, 2u, 2u, &result, &used) == FTUN_E_PROTOCOL);
  CHECK(ftun_socks5_client_init(&client, &options) == FTUN_OK);
  CHECK(send_frame(&client, (const uint8_t[]){5, 1, 0}, 3u) == 0);
  CHECK(feed(&client, (const uint8_t[]){4, 0}, 2u, 2u, &result, &used) == FTUN_E_PROTOCOL);
  /* 认证失败。 */
  options.username = (ftun_bytes_t){(const uint8_t *)"u", 1u};
  options.password = (ftun_bytes_t){(const uint8_t *)"p", 1u};
  CHECK(ftun_socks5_client_init(&client, &options) == FTUN_OK);
  CHECK(send_frame(&client, (const uint8_t[]){5, 1, 2}, 3u) == 0);
  CHECK(feed(&client, (const uint8_t[]){5, 2}, 2u, 2u, &result, &used) == FTUN_E_AGAIN);
  CHECK(send_frame(&client, (const uint8_t[]){1, 1, 'u', 1, 'p'}, 5u) == 0);
  CHECK(feed(&client, (const uint8_t[]){1, 1}, 2u, 2u, &result, &used) == FTUN_E_REJECTED);
  memset(&options.username, 0, sizeof(options.username));
  memset(&options.password, 0, sizeof(options.password));
  /* 每个回复码的状态映射，result.reply 保留服务端回复码。 */
  for (index = 0u; index < sizeof(replies) / sizeof(replies[0]); index++) {
    uint8_t reply[10] = {5, 0, 0, 1, 0, 0, 0, 0, 0, 0};
    reply[1] = replies[index].code;
    CHECK(ftun_socks5_client_init(&client, &options) == FTUN_OK);
    CHECK(send_frame(&client, (const uint8_t[]){5, 1, 0}, 3u) == 0);
    CHECK(feed(&client, (const uint8_t[]){5, 0}, 2u, 2u, &result, &used) == FTUN_E_AGAIN);
    CHECK(send_frame(&client, (const uint8_t[]){5, 1, 0, 1, 203, 0, 113, 9, 1, 0xbb}, 10u) == 0);
    CHECK(feed(&client, reply, sizeof(reply), 10u, &result, &used) == replies[index].status);
    CHECK(result.reply == replies[index].code);
  }
  /* 非法 ATYP：协议错误。 */
  CHECK(ftun_socks5_client_init(&client, &options) == FTUN_OK);
  CHECK(send_frame(&client, (const uint8_t[]){5, 1, 0}, 3u) == 0);
  CHECK(feed(&client, (const uint8_t[]){5, 0}, 2u, 2u, &result, &used) == FTUN_E_AGAIN);
  CHECK(send_frame(&client, (const uint8_t[]){5, 1, 0, 1, 203, 0, 113, 9, 1, 0xbb}, 10u) == 0);
  CHECK(feed(&client, (const uint8_t[]){5, 0, 0, 9, 0, 0}, 6u, 6u, &result, &used) ==
        FTUN_E_PROTOCOL);
  /* 参数校验。 */
  options.command = FTUN_SOCKS5_COMMAND_BIND;
  CHECK(ftun_socks5_client_init(&client, &options) == FTUN_E_INVALID);
  return 0;
}

int main(void)
{
  size_t chunk;
  for (chunk = 1u; chunk <= 13u; chunk += 3u) {
    CHECK(test_connect_no_auth(chunk) == 0);
  }
  CHECK(test_auth() == 0);
  CHECK(test_udp_associate_and_ipv6_bnd() == 0);
  CHECK(test_failures() == 0);
  puts("SOCKS5 client: handshake phases, incremental input, BND forms, failures and exact reply consumption passed");
  return 0;
}
