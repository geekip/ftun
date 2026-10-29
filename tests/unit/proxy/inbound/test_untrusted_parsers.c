#include "proxy/inbound/http_codec.h"
#include "libs/transport/socks5_codec.h"
#include "proxy/sniff/sniff.h"

#if defined(FTUN_TEST_DNS)
#include "libs/resolver/dnswire.h"
#endif
#if defined(FTUN_TEST_FRS)
#include "proxy/frs/format.h"
#include "frs_fixture.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "untrusted parser regression failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

static uint32_t next_random(uint32_t *state)
{
  uint32_t value = *state;
  value ^= value << 13u;
  value ^= value >> 17u;
  value ^= value << 5u;
  *state = value;
  return value;
}

static int status_is_parser_result(ftun_status_t status)
{
  return status == FTUN_OK || status == FTUN_E_AGAIN ||
         status == FTUN_E_PROTOCOL || status == FTUN_E_UNSUPPORTED ||
         status == FTUN_E_LIMIT || status == FTUN_E_INVALID;
}

static int exercise_base_parsers(const uint8_t *data, size_t length)
{
  ftun_bytes_t input = {data, length};
  ftun_socks5_method_offer_t methods;
  ftun_socks5_credentials_t credentials;
  ftun_socks5_request_t request;
  ftun_socks5_reply_t reply;
  ftun_socks5_udp_datagram_t datagram;
  ftun_http_request_t http;
  ftun_metadata_t metadata;
  ftun_sniff_result_t sniff;
  size_t consumed;
  uint8_t byte;
  ftun_status_t status;

  memset(&methods, 0xa5, sizeof(methods));
  consumed = SIZE_MAX;
  status = ftun_socks5_decode_method_offer(input, &methods, &consumed);
  if (!status_is_parser_result(status) ||
      (status != FTUN_OK && (consumed != 0u || methods.methods.data != NULL))) {
    return 0;
  }
  consumed = SIZE_MAX;
  byte = 0xa5u;
  status = ftun_socks5_decode_method_selection(input, &byte, &consumed);
  if (!status_is_parser_result(status) ||
      (status != FTUN_OK && consumed != 0u)) return 0;
  memset(&credentials, 0xa5, sizeof(credentials));
  consumed = SIZE_MAX;
  status = ftun_socks5_decode_credentials(input, &credentials, &consumed);
  if (!status_is_parser_result(status) ||
      (status != FTUN_OK && consumed != 0u)) return 0;
  consumed = SIZE_MAX;
  byte = 0xa5u;
  status = ftun_socks5_decode_auth_result(input, &byte, &consumed);
  if (!status_is_parser_result(status) ||
      (status != FTUN_OK && consumed != 0u)) return 0;
  memset(&request, 0xa5, sizeof(request));
  consumed = SIZE_MAX;
  status = ftun_socks5_decode_request(input, &request, &consumed);
  if (!status_is_parser_result(status) ||
      (status != FTUN_OK && consumed != 0u)) return 0;
  memset(&reply, 0xa5, sizeof(reply));
  consumed = SIZE_MAX;
  status = ftun_socks5_decode_reply(input, &reply, &consumed);
  if (!status_is_parser_result(status) ||
      (status != FTUN_OK && consumed != 0u)) return 0;
  memset(&datagram, 0xa5, sizeof(datagram));
  consumed = SIZE_MAX;
  status = ftun_socks5_decode_udp_datagram(input, &datagram, &consumed);
  if (!status_is_parser_result(status) ||
      (status != FTUN_OK && consumed != 0u)) return 0;

  memset(&http, 0xa5, sizeof(http));
  consumed = SIZE_MAX;
  status = ftun_http_decode_request(input, &http, &consumed);
  if (!status_is_parser_result(status) ||
      (status != FTUN_OK && consumed != 0u)) return 0;

  memset(&metadata, 0, sizeof(metadata));
  metadata.original_target.kind = FTUN_ADDRESS_IPV4;
  metadata.original_target.port = 443u;
  status = ftun_sniff_domain(&metadata, input, &sniff);
  return status_is_parser_result(status);
}

static int exercise_wire_parsers(const uint8_t *data, size_t length)
{
#if defined(FTUN_TEST_DNS)
  ftun_dns_message_t *message = (ftun_dns_message_t *)(uintptr_t)1;
  ftun_status_t status = ftun_dns_message_parse(
    (ftun_bytes_t){data, length}, &message);
  if (!status_is_parser_result(status)) return 0;
  if (status == FTUN_OK) {
    if (message == NULL || ftun_dns_message_release(&message) != FTUN_OK ||
        message != NULL) return 0;
  } else if (message != NULL) {
    return 0;
  }
#else
  (void)data;
  (void)length;
#endif
  return 1;
}

#if defined(FTUN_TEST_FRS)
static int exercise_frs(void)
{
  uint8_t *fixture = NULL;
  uint8_t *copy = NULL;
  size_t length = 0u;
  size_t index;
  CHECK(ftun_test_frs_fixture(&fixture, &length));
  copy = (uint8_t *)malloc(length);
  CHECK(copy != NULL);
  for (index = 0u; index <= length; index++) {
    ftun_frs_layout_t layout;
    ftun_status_t status;
    memset(&layout, 0, sizeof(layout));
    status = ftun_frs_format_validate((ftun_bytes_t){fixture, index}, &layout);
    CHECK(status == FTUN_OK || status == FTUN_E_PROTOCOL ||
          status == FTUN_E_UNSUPPORTED || status == FTUN_E_LIMIT ||
          status == FTUN_E_INVALID);
    ftun_frs_layout_clear(&layout);
  }
  for (index = FTUN_FRS_HEADER_BYTES; index < length; index++) {
    ftun_frs_layout_t layout;
    ftun_status_t status;
    memcpy(copy, fixture, length);
    copy[index] ^= (uint8_t)(1u << (index & 7u));
    memset(copy + 48u, 0, sizeof(uint64_t));
    ftun_frs_write_u64(copy + 48u,
      ftun_frs_file_checksum((ftun_bytes_t){copy, length}));
    memset(&layout, 0, sizeof(layout));
    status = ftun_frs_format_validate((ftun_bytes_t){copy, length}, &layout);
    CHECK(status == FTUN_OK || status == FTUN_E_PROTOCOL ||
          status == FTUN_E_UNSUPPORTED || status == FTUN_E_LIMIT ||
          status == FTUN_E_INVALID);
    ftun_frs_layout_clear(&layout);
  }
  free(copy);
  free(fixture);
  return 0;
}
#endif

int main(void)
{
  static const uint8_t socks_request[] = {
    0x05u, 0x01u, 0x00u, 0x03u, 0x0bu,
    'e','x','a','m','p','l','e','.','c','o','m', 0x00u, 0x50u
  };
  static const uint8_t http_request[] =
    "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
  uint8_t corpus[4096];
  uint32_t random_state = UINT32_C(0x5eed1234);
  size_t iteration;
  size_t index;

  for (index = 0u; index <= sizeof(socks_request); index++) {
    CHECK(exercise_base_parsers(socks_request, index));
    CHECK(exercise_wire_parsers(socks_request, index));
  }
  for (index = 0u; index < sizeof(http_request); index++) {
    CHECK(exercise_base_parsers(http_request, index));
    CHECK(exercise_wire_parsers(http_request, index));
  }
  for (iteration = 0u; iteration < 1024u; iteration++) {
    size_t length = (size_t)(next_random(&random_state) % sizeof(corpus));
    for (index = 0u; index < length; index++) {
      corpus[index] = (uint8_t)next_random(&random_state);
    }
    CHECK(exercise_base_parsers(corpus, length));
    CHECK(exercise_wire_parsers(corpus, length));
  }
#if defined(FTUN_TEST_FRS)
  CHECK(exercise_frs() == 0);
#endif
  return 0;
}
