#include "protocol/http.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "http contract failed: %s\n", #x); return 1; \
} } while (0)

static ftun_bytes_t bytes(const char *text)
{
  ftun_bytes_t result;
  result.data = (const uint8_t *)text;
  result.length = strlen(text);
  return result;
}

int main(void)
{
  ftun_http_request_t request;
  ftun_protocol_result_t generic;
  uint8_t rewritten[512];
  size_t rewritten_length = 0u;
  size_t consumed = 99u;
  const char *forward =
    "GET http://Example.com:80/a?q=1 HTTP/1.1\r\n"
    "Host: example.com\r\nContent-Length: 3\r\n\r\nabc";
  const char *connect =
    "CONNECT example.com:443 HTTP/1.1\r\nHost: EXAMPLE.com:443\r\n\r\nxyz";
  CHECK(ftun_http_decode_request(bytes("GET http://a/ HTTP/1.1\r\n"),
                                 &request, &consumed) == FTUN_E_AGAIN);
  CHECK(consumed == 0u && request.kind == 0);
  CHECK(ftun_http_decode_request(bytes(forward), &request, &consumed) == FTUN_OK);
  CHECK(request.kind == FTUN_HTTP_PROXY_FORWARD);
  CHECK(request.target.kind == FTUN_ADDRESS_DOMAIN && request.target.port == 80u);
  CHECK(request.content_length == 3u && request.has_content_length);
  CHECK(consumed + 3u == strlen(forward));
  CHECK(ftun_http_decode(bytes(forward), &generic) == FTUN_OK);
  CHECK(generic.complete && generic.consumed == consumed);
  CHECK(ftun_http_rewrite_forward(bytes(forward), &request, rewritten,
        sizeof(rewritten), &rewritten_length) == FTUN_OK);
  CHECK(rewritten_length == strlen(
    "GET /a?q=1 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\n"));
  CHECK(memcmp(rewritten,
    "GET /a?q=1 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\n",
    rewritten_length) == 0);
  CHECK(ftun_http_decode_request(bytes(
    "GET http://a?x=1 HTTP/1.1\r\nHost: a\r\n"
    "Proxy-Authorization: Basic dTpw\r\nProxy-Connection: keep-alive\r\n\r\n"),
    &request, &consumed) == FTUN_OK);
  CHECK(ftun_http_rewrite_forward(bytes(
    "GET http://a?x=1 HTTP/1.1\r\nHost: a\r\n"
    "Proxy-Authorization: Basic dTpw\r\nProxy-Connection: keep-alive\r\n\r\n"),
    &request, rewritten, sizeof(rewritten), &rewritten_length) == FTUN_OK);
  CHECK(rewritten_length == strlen("GET /?x=1 HTTP/1.1\r\nHost: a\r\n\r\n"));
  CHECK(memcmp(rewritten, "GET /?x=1 HTTP/1.1\r\nHost: a\r\n\r\n",
               rewritten_length) == 0);
  CHECK(ftun_http_decode_request(bytes(connect), &request, &consumed) == FTUN_OK);
  CHECK(request.kind == FTUN_HTTP_PROXY_CONNECT && request.target.port == 443u);
  CHECK(consumed + 3u == strlen(connect));
  CHECK(ftun_http_decode_request(bytes(
    "GET http://a/ HTTP/1.1\r\nHost: b\r\n\r\n"),
    &request, &consumed) == FTUN_E_PROTOCOL);
  CHECK(ftun_http_decode_request(bytes(
    "GET http://a/ HTTP/1.1\r\nHost: a\r\nHost: a\r\n\r\n"),
    &request, &consumed) == FTUN_E_PROTOCOL);
  CHECK(ftun_http_decode_request(bytes(
    "POST http://a/ HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n"
    "Transfer-Encoding: chunked\r\n\r\n"),
    &request, &consumed) == FTUN_E_UNSUPPORTED);
  CHECK(ftun_http_decode_request(bytes(
    "GET /relative HTTP/1.1\r\nHost: a\r\n\r\n"),
    &request, &consumed) == FTUN_E_PROTOCOL);
  CHECK(ftun_http_decode_request(bytes(
    "GET http://user@a/ HTTP/1.1\r\nHost: a\r\n\r\n"),
    &request, &consumed) == FTUN_E_PROTOCOL);
  CHECK(ftun_http_decode_request(bytes(
    "GET http://bad_name/ HTTP/1.1\r\nHost: bad_name\r\n\r\n"),
    &request, &consumed) == FTUN_E_PROTOCOL);
  CHECK(ftun_http_decode_request(bytes(
    "GET http://a/path#fragment HTTP/1.1\r\nHost: a\r\n\r\n"),
    &request, &consumed) == FTUN_E_PROTOCOL);
  CHECK(ftun_http_decode_request(bytes(
    "GET http://a/ HTTP/1.1\r\nHost: a\r\n"
    "Proxy-Authorization: Basic dTpw\r\n\r\n"),
    &request, &consumed) == FTUN_OK &&
    request.has_proxy_authorization &&
    request.proxy_authorization.length == strlen("Basic dTpw"));
  CHECK(ftun_http_decode_request(bytes(
    "GET http://a/ HTTP/1.1\r\nHost: a\r\n"
    "Proxy-Authorization: Basic dTpw\r\n"
    "Proxy-Authorization: Basic dTpw\r\n\r\n"),
    &request, &consumed) == FTUN_E_PROTOCOL);
  return 0;
}
