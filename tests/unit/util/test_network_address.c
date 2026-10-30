#include "util/ip.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "network address contract failed at %d: %s\n", __LINE__, #x); \
    return 1; \
  } \
} while (0)

#define TEXT(s) (s), strlen(s)

static int test_decimal_and_port(void)
{
  uint32_t value = 0u;
  uint16_t port = 0u;
  CHECK(ftun_decimal_parse(TEXT("0"), 10u, &value) && value == 0u);
  CHECK(ftun_decimal_parse(TEXT("255"), 255u, &value) && value == 255u);
  CHECK(!ftun_decimal_parse(TEXT("256"), 255u, &value));
  CHECK(!ftun_decimal_parse(TEXT("01"), 255u, &value));
  CHECK(!ftun_decimal_parse(TEXT(""), 255u, &value));
  CHECK(!ftun_decimal_parse(TEXT("+1"), 255u, &value));
  CHECK(!ftun_decimal_parse(TEXT(" 1"), 255u, &value));
  CHECK(!ftun_decimal_parse(TEXT("4294967296"), UINT32_MAX, &value));
  CHECK(ftun_decimal_parse(TEXT("4294967295"), UINT32_MAX, &value) && value == UINT32_MAX);
  CHECK(ftun_port_parse(TEXT("1"), &port) && port == 1u);
  CHECK(ftun_port_parse(TEXT("65535"), &port) && port == 65535u);
  CHECK(!ftun_port_parse(TEXT("0"), &port));
  CHECK(!ftun_port_parse(TEXT("65536"), &port));
  CHECK(!ftun_port_parse(TEXT("80x"), &port));
  return 0;
}

static int test_ip(void)
{
  ftun_ip_t ip;
  uint8_t v4[4];
  char text[FTUN_IP_TEXT_BYTES];
  CHECK(ftun_ipv4_parse(TEXT("192.0.2.1"), v4) && v4[0] == 192u && v4[3] == 1u);
  CHECK(!ftun_ipv4_parse(TEXT("192.0.2"), v4));
  CHECK(!ftun_ipv4_parse(TEXT("192.0.2.1.5"), v4));
  CHECK(!ftun_ipv4_parse(TEXT("192.0.2.256"), v4));
  CHECK(!ftun_ipv4_parse(TEXT("192.0.02.1"), v4));
  CHECK(!ftun_ipv4_parse(TEXT("192..2.1"), v4));
  CHECK(!ftun_ipv4_parse(TEXT("192.0.2.1."), v4));
  CHECK(ftun_ip_parse(TEXT("10.0.0.1"), &ip) && ip.family == FTUN_IP_V4);
  CHECK(ftun_ip_format(&ip, text, sizeof(text)) == 8u && strcmp(text, "10.0.0.1") == 0);
  CHECK(ftun_ip_parse(TEXT("2001:db8::1"), &ip) && ip.family == FTUN_IP_V6 &&
        ip.bytes[0] == 0x20u && ip.bytes[15] == 1u);
  CHECK(ftun_ip_format(&ip, text, sizeof(text)) == 11u && strcmp(text, "2001:db8::1") == 0);
  CHECK(ftun_ip_format(&ip, text, 5u) == 0u);
  CHECK(!ftun_ip_parse(TEXT("2001:db8::g"), &ip));
  CHECK(!ftun_ip_parse(TEXT("example.com"), &ip));
  CHECK(!ftun_ip_parse(TEXT(""), &ip));
  /* 长度只取前缀，不能越界读后面的文本。 */
  CHECK(ftun_ip_parse("10.0.0.1:53", 8u, &ip) && ip.bytes[3] == 1u);
  return 0;
}

static int test_host_port(void)
{
  ftun_host_port_t value;
  CHECK(ftun_host_port_split(TEXT("example.com"), &value) &&
        value.host_length == 11u && !value.has_port && !value.bracketed);
  CHECK(ftun_host_port_split(TEXT("example.com:853"), &value) &&
        value.host_length == 11u && value.has_port && value.port == 853u);
  CHECK(ftun_host_port_split(TEXT("1.2.3.4:53"), &value) &&
        value.host_length == 7u && value.port == 53u);
  CHECK(ftun_host_port_split(TEXT("[2001:db8::1]"), &value) &&
        value.bracketed && value.host_length == 11u && !value.has_port &&
        value.host[0] == '2');
  CHECK(ftun_host_port_split(TEXT("[2001:db8::1]:53"), &value) &&
        value.has_port && value.port == 53u);
  CHECK(!ftun_host_port_split(TEXT("2001:db8::1"), &value));
  CHECK(!ftun_host_port_split(TEXT("::1"), &value));
  CHECK(!ftun_host_port_split(TEXT("host:1:2"), &value));
  CHECK(!ftun_host_port_split(TEXT("host:"), &value));
  CHECK(!ftun_host_port_split(TEXT("host:0"), &value));
  CHECK(!ftun_host_port_split(TEXT("host:70000"), &value));
  CHECK(!ftun_host_port_split(TEXT(":53"), &value));
  CHECK(!ftun_host_port_split(TEXT("[]:53"), &value));
  CHECK(!ftun_host_port_split(TEXT("[::1"), &value));
  CHECK(!ftun_host_port_split(TEXT("[::1]53"), &value));
  CHECK(!ftun_host_port_split(TEXT("[::1]:"), &value));
  CHECK(!ftun_host_port_split(TEXT(""), &value));
  return 0;
}

static int test_cidr(void)
{
  ftun_cidr_t cidr;
  ftun_ip_t inside, outside, v6;
  uint32_t network = 0u, broadcast = 0u;
  CHECK(ftun_cidr_parse(TEXT("198.18.0.0/15"), true, &cidr) &&
        cidr.address.family == FTUN_IP_V4 && cidr.prefix == 15u);
  CHECK(ftun_cidr_ipv4_range(&cidr, &network, &broadcast) &&
        network == UINT32_C(0xc6120000) && broadcast == UINT32_C(0xc613ffff));
  CHECK(ftun_ip_parse(TEXT("198.19.255.255"), &inside) && ftun_cidr_contains(&cidr, &inside));
  CHECK(ftun_ip_parse(TEXT("198.20.0.0"), &outside) && !ftun_cidr_contains(&cidr, &outside));
  CHECK(ftun_ip_parse(TEXT("2001:db8::1"), &v6) && !ftun_cidr_contains(&cidr, &v6));
  CHECK(!ftun_cidr_parse(TEXT("198.19.0.0/15"), true, &cidr));
  CHECK(ftun_cidr_parse(TEXT("198.19.0.0/15"), false, &cidr) && cidr.prefix == 15u);
  CHECK(ftun_cidr_parse(TEXT("10.1.2.3/32"), true, &cidr));
  CHECK(ftun_cidr_parse(TEXT("0.0.0.0/0"), true, &cidr));
  CHECK(!ftun_cidr_parse(TEXT("10.0.0.0/33"), false, &cidr));
  CHECK(!ftun_cidr_parse(TEXT("10.0.0.0/"), false, &cidr));
  CHECK(!ftun_cidr_parse(TEXT("10.0.0.0"), false, &cidr));
  CHECK(!ftun_cidr_parse(TEXT("10.0.0.0/8/8"), false, &cidr));
  CHECK(!ftun_cidr_parse(TEXT("10.0.0.0/08"), false, &cidr));
  CHECK(ftun_cidr_parse(TEXT("2001:db8::/32"), true, &cidr) &&
        cidr.address.family == FTUN_IP_V6 && cidr.prefix == 32u);
  CHECK(!ftun_cidr_ipv4_range(&cidr, &network, &broadcast));
  CHECK(!ftun_cidr_parse(TEXT("2001:db8::1/32"), true, &cidr));
  CHECK(ftun_cidr_parse(TEXT("2001:db8::1/128"), true, &cidr));
  CHECK(!ftun_cidr_parse(TEXT("2001:db8::/129"), false, &cidr));
  CHECK(ftun_cidr_parse(TEXT("2001:db8::/33"), false, &cidr));
  CHECK(ftun_ip_parse(TEXT("2001:db8:7fff::1"), &inside) && ftun_cidr_contains(&cidr, &inside));
  CHECK(ftun_ip_parse(TEXT("2001:db8:8000::1"), &outside) && !ftun_cidr_contains(&cidr, &outside));
  return 0;
}

static int test_ipv4_helpers(void)
{
  uint8_t bytes[4];
  CHECK(ftun_ipv4_mask(0u) == 0u && ftun_ipv4_mask(8u) == UINT32_C(0xff000000) &&
        ftun_ipv4_mask(32u) == UINT32_MAX && ftun_ipv4_mask(31u) == UINT32_C(0xfffffffe));
  ftun_ipv4_store(UINT32_C(0xc0000201), bytes);
  CHECK(bytes[0] == 192u && bytes[1] == 0u && bytes[2] == 2u && bytes[3] == 1u);
  CHECK(ftun_ipv4_value(bytes) == UINT32_C(0xc0000201));
  return 0;
}

/* 文本规则下沉后，各解析入口共用同一标签/长度语义。 */
static int test_domain(void)
{
  char name[255];
  CHECK(ftun_domain_span(TEXT("api.example")));
  CHECK(ftun_domain_span(TEXT("API.example.")));
  CHECK(!ftun_domain_span(TEXT("")) && !ftun_domain_span(NULL, 1u));
  CHECK(!ftun_domain_span(TEXT(".example")) && !ftun_domain_span(TEXT("a..b")));
  CHECK(!ftun_domain_span(TEXT("-a.test")) && !ftun_domain_span(TEXT("a-.test")));
  CHECK(!ftun_domain_span(TEXT("127.0.0.1")));
  CHECK(!ftun_domain_span("a\0b", 3u));
  memset(name, 'a', sizeof(name));
  name[63] = name[127] = name[191] = '.';
  CHECK(ftun_domain_span(name, 253u));
  name[253] = '.';
  CHECK(ftun_domain_span(name, 254u));
  CHECK(!ftun_domain_span(name, 255u));
  name[63] = 'a';
  CHECK(!ftun_domain_span(name, 253u));
  return 0;
}

int main(void)
{
  CHECK(test_decimal_and_port() == 0);
  CHECK(test_ip() == 0);
  CHECK(test_domain() == 0);
  CHECK(test_host_port() == 0);
  CHECK(test_cidr() == 0);
  CHECK(test_ipv4_helpers() == 0);
  return 0;
}
