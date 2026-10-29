#include "fuzz_common.h"

#include "libs/transport/socks5_codec.h"
#include "libs/transport/socks5_client.h"

#include <string.h>

static void decoders(ftun_bytes_t input)
{
  ftun_socks5_method_offer_t methods;
  ftun_socks5_credentials_t credentials;
  ftun_socks5_request_t request;
  ftun_socks5_reply_t reply;
  ftun_socks5_udp_datagram_t datagram;
  size_t consumed;
  uint8_t byte;
  ftun_status_t status;
  consumed = SIZE_MAX;
  status = ftun_socks5_decode_method_offer(input, &methods, &consumed);
  FUZZ_NOT_CORRUPT(status);
  FUZZ_REQUIRE(status == FTUN_OK ? consumed <= input.length : consumed == 0u);
  consumed = SIZE_MAX;
  status = ftun_socks5_decode_method_selection(input, &byte, &consumed);
  FUZZ_NOT_CORRUPT(status);
  FUZZ_REQUIRE(status == FTUN_OK ? consumed <= input.length : consumed == 0u);
  consumed = SIZE_MAX;
  status = ftun_socks5_decode_credentials(input, &credentials, &consumed);
  FUZZ_NOT_CORRUPT(status);
  FUZZ_REQUIRE(status == FTUN_OK ? consumed <= input.length : consumed == 0u);
  consumed = SIZE_MAX;
  status = ftun_socks5_decode_auth_result(input, &byte, &consumed);
  FUZZ_NOT_CORRUPT(status);
  FUZZ_REQUIRE(status == FTUN_OK ? consumed <= input.length : consumed == 0u);
  consumed = SIZE_MAX;
  status = ftun_socks5_decode_request(input, &request, &consumed);
  FUZZ_NOT_CORRUPT(status);
  FUZZ_REQUIRE(status == FTUN_OK ? consumed <= input.length : consumed == 0u);
  consumed = SIZE_MAX;
  status = ftun_socks5_decode_reply(input, &reply, &consumed);
  FUZZ_NOT_CORRUPT(status);
  FUZZ_REQUIRE(status == FTUN_OK ? consumed <= input.length : consumed == 0u);
  consumed = SIZE_MAX;
  status = ftun_socks5_decode_udp_datagram(input, &datagram, &consumed);
  FUZZ_NOT_CORRUPT(status);
  FUZZ_REQUIRE(status == FTUN_OK ? consumed <= input.length : consumed == 0u);
}

/* 客户端握手状态机：服务端回复由输入决定，第一个字节决定每次喂入的块大小
 * （覆盖分段到达）。状态机必须在有限步内结束，且 consumed 不超过喂入量与 needed。 */
static void client(ftun_bytes_t input, bool authenticate, ftun_socks5_command_t command)
{
  static const uint8_t user[] = "user";
  static const uint8_t pass[] = "pass";
  ftun_socks5_client_options_t options;
  ftun_socks5_client_t machine;
  ftun_socks5_client_result_t result;
  uint8_t frame[FTUN_SOCKS5_CLIENT_FRAME_BYTES];
  size_t offset = 0u;
  size_t step;
  size_t chunk = input.length == 0u ? 1u : 1u + (size_t)(input.data[0] % 16u);
  memset(&options, 0, sizeof(options));
  if (authenticate) {
    options.username = (ftun_bytes_t){user, sizeof(user) - 1u};
    options.password = (ftun_bytes_t){pass, sizeof(pass) - 1u};
  }
  options.command = command;
  options.target.kind = FTUN_ADDRESS_DOMAIN;
  options.target.domain = (ftun_string_t){"example.com", 11u};
  options.target.port = 443u;
  if (ftun_socks5_client_init(&machine, &options) != FTUN_OK) return;
  for (step = 0u; step < 256u; step++) {
    size_t consumed = 0u;
    size_t length = 0u;
    size_t needed;
    ftun_status_t status;
    if (ftun_socks5_client_wants_output(&machine)) {
      status = ftun_socks5_client_output(&machine, frame, sizeof(frame), &length);
      FUZZ_NOT_CORRUPT(status);
      if (status != FTUN_OK) return;
      FUZZ_REQUIRE(length != 0u && length <= sizeof(frame));
      if (ftun_socks5_client_output_done(&machine) != FTUN_OK) return;
      continue;
    }
    needed = ftun_socks5_client_needed(&machine);
    if (needed == 0u || offset >= input.length) return;
    length = input.length - offset < chunk ? input.length - offset : chunk;
    status = ftun_socks5_client_input(&machine,
      (ftun_bytes_t){input.data + offset, length}, &consumed, &result);
    FUZZ_NOT_CORRUPT(status);
    FUZZ_REQUIRE(consumed <= length && consumed <= needed);
    offset += consumed;
    if (status != FTUN_E_AGAIN) return;
    if (consumed == 0u) return;
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  ftun_bytes_t input = {data, size};
  decoders(input);
  client(input, false, FTUN_SOCKS5_COMMAND_CONNECT);
  client(input, true, FTUN_SOCKS5_COMMAND_CONNECT);
  client(input, false, FTUN_SOCKS5_COMMAND_UDP_ASSOCIATE);
  return 0;
}

void ftun_fuzz_seeds(ftun_fuzz_seed_fn add)
{
  static const uint8_t offer[] = {0x05, 0x02, 0x00, 0x02};
  static const uint8_t selection_and_reply[] = {
    0x05, 0x00,
    0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90
  };
  static const uint8_t auth_and_domain_reply[] = {
    0x05, 0x02, 0x01, 0x00,
    0x05, 0x00, 0x00, 0x03, 0x0b, 'e','x','a','m','p','l','e','.','c','o','m', 0x00, 0x50
  };
  static const uint8_t request[] = {
    0x05, 0x01, 0x00, 0x03, 0x0b, 'e','x','a','m','p','l','e','.','c','o','m', 0x00, 0x50
  };
  static const uint8_t ipv6_reply[] = {
    0x05, 0x00, 0x05, 0x00, 0x00, 0x04,
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x00, 0x50
  };
  static const uint8_t udp[] = {
    0x00, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35, 'p', 'a', 'y'
  };
  add(offer, sizeof(offer));
  add(selection_and_reply, sizeof(selection_and_reply));
  add(auth_and_domain_reply, sizeof(auth_and_domain_reply));
  add(request, sizeof(request));
  add(ipv6_reply, sizeof(ipv6_reply));
  add(udp, sizeof(udp));
}
