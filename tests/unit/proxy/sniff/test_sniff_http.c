#include "proxy/sniff/http_host.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "HTTP sniff contract failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

static ftun_bytes_t text(const char *value)
{
  return (ftun_bytes_t){(const uint8_t *)value, strlen(value)};
}

int main(void)
{
  ftun_sniff_result_t result;
  CHECK(ftun_sniff_http_host(text("GET / HTTP/1.1\r\nHoSt: Example.COM:8080\r\n\r\n"),
                             &result) == FTUN_OK);
  CHECK(result.found && !result.need_more);
  CHECK(result.domain.length == strlen("example.com"));
  CHECK(memcmp(result.domain.data, "example.com", result.domain.length) == 0);
  CHECK(result.domain.data == result.domain_storage);

  CHECK(ftun_sniff_http_host(text("GET / HTTP/1.1\r\nHost: example.com\r\n"),
                             &result) == FTUN_OK);
  CHECK(!result.found && result.need_more);
  CHECK(ftun_sniff_http_host(text("GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\n"),
                             &result) == FTUN_OK);
  CHECK(!result.found && !result.need_more);
  CHECK(ftun_sniff_http_host(text("GET / HTTP/1.1\r\nHost: a.test\r\nHost: b.test\r\n\r\n"),
                             &result) == FTUN_E_PROTOCOL);
  CHECK(ftun_sniff_http_host(text("GET / HTTP/1.1\r\nHost: -bad.test\r\n\r\n"),
                             &result) == FTUN_E_PROTOCOL);
  CHECK(ftun_sniff_http_host(text("not http\r\nHost: false.test\r\n\r\n"),
                             &result) == FTUN_E_PROTOCOL);
  CHECK(ftun_sniff_http_host(text("GET / HTTP/1.1\r\n bad: folded\r\n\r\n"),
                             &result) == FTUN_E_PROTOCOL);
  CHECK(ftun_sniff_http_host((ftun_bytes_t){NULL, 1u}, &result) ==
        FTUN_E_INVALID);
  return 0;
}
