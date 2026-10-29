#include "fuzz_common.h"

#include "core/limits.h"
#include "proxy/inbound/http_codec.h"
#include "proxy/http_route.h"

#include <stdlib.h>
#include <string.h>

static ftun_budget_t *budget;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc;
  (void)argv;
  FUZZ_REQUIRE(ftun_budget_create(NULL, 8u * 1024u * 1024u, 0u, &budget) == FTUN_OK);
  return 0;
}

/* 代理请求解析（含改写）与 HTTP 响应解析（FRS 更新用）。 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  ftun_bytes_t input = {data, size};
  ftun_http_request_t request;
  ftun_protocol_result_t protocol;
  size_t consumed = SIZE_MAX;
  ftun_status_t status = ftun_http_decode_request(input, &request, &consumed);
  FUZZ_NOT_CORRUPT(status);
  FUZZ_REQUIRE(status == FTUN_OK ? consumed <= size : consumed == 0u);
  if (status == FTUN_OK && request.kind == FTUN_HTTP_PROXY_FORWARD) {
    uint8_t output[FTUN_HTTP_MAX_HEADER_BYTES + 64u];
    size_t written = 0u;
    status = ftun_http_rewrite_forward(input, &request, output, sizeof(output), &written);
    FUZZ_NOT_CORRUPT(status);
    FUZZ_REQUIRE(written <= sizeof(output));
  }
  status = ftun_http_decode(input, &protocol);
  FUZZ_NOT_CORRUPT(status);
  {
    /* 响应解析会在原缓冲里去掉分块编码，所以给它恰好 size 字节的可写副本。 */
    uint8_t *wire = (uint8_t *)malloc(size == 0u ? 1u : size);
    ftun_http_fetch_result_t result;
    char *location = NULL;
    ftun_reservation_t location_reservation = (ftun_reservation_t){0};
    FUZZ_REQUIRE(wire != NULL);
    if (size != 0u) memcpy(wire, data, size);
    memset(&result, 0, sizeof(result));
    status = ftun_http_fetch_parse_response(budget, wire, size, 1024u * 1024u,
      &result, &location, &location_reservation);
    FUZZ_NOT_CORRUPT(status);
    if (status == FTUN_OK) FUZZ_REQUIRE(result.length <= size);
    free(location);
    (void)ftun_reservation_release(&location_reservation);
    ftun_http_fetch_release(&result);
    free(wire);
  }
  return 0;
}

void ftun_fuzz_seeds(ftun_fuzz_seed_fn add)
{
  static const char forward[] =
    "GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\n"
    "Proxy-Authorization: Basic dXNlcjpwYXNz\r\nConnection: close\r\n\r\n";
  static const char connect_request[] =
    "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
  static const char plain[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nETag: \"abc\"\r\n\r\nhello";
  static const char chunked[] =
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
  static const char redirect[] =
    "HTTP/1.1 302 Found\r\nLocation: https://example.com/next\r\nContent-Length: 0\r\n\r\n";
  add((const uint8_t *)forward, sizeof(forward) - 1u);
  add((const uint8_t *)connect_request, sizeof(connect_request) - 1u);
  add((const uint8_t *)plain, sizeof(plain) - 1u);
  add((const uint8_t *)chunked, sizeof(chunked) - 1u);
  add((const uint8_t *)redirect, sizeof(redirect) - 1u);
}
