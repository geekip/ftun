#include "util/ip.h"

#include <stdio.h>
#include <string.h>

/* IPv6 文本算法改编自 musl inet_pton/inet_ntop（MIT）。
 * Copyright © 2005-2020 Rich Felker, et al.
 * 许可原文及原始源码见 third_party/musl。 */
static int hexval(unsigned c)
{
  if (c-'0'<10) return (int)(c-'0');
  c |= 32;
  if (c-'a'<6) return (int)(c-'a'+10);
  return -1;
}

static int parse_ipv6(const char *s, uint8_t *a)
{
  uint16_t ip[8];
  int i, j, v, d, brk=-1, need_v4=0;

  if (*s==':' && *++s!=':') return 0;

  for (i=0; ; i++) {
    if (s[0]==':' && brk<0) {
      brk=i;
      ip[i&7]=0;
      if (!*++s) break;
      if (i==7) return 0;
      continue;
    }
    for (v=j=0; j<4 && (d=hexval((unsigned char)s[j]))>=0; j++)
      v=16*v+d;
    if (j==0) return 0;
    ip[i&7] = (uint16_t)v;
    if (!s[j] && (brk>=0 || i==7)) break;
    if (i==7) return 0;
    if (s[j]!=':') {
      if (s[j]!='.' || (i<6 && brk<0)) return 0;
      need_v4=1;
      i++;
      ip[i&7]=0;
      break;
    }
    s += j+1;
  }
  if (brk>=0) {
    memmove(ip+brk+7-i, ip+brk, (size_t)(2*(i+1-brk)));
    for (j=0; j<7-i; j++) ip[brk+j] = 0;
  }
  for (j=0; j<8; j++) {
    *a++ = (uint8_t)(ip[j]>>8);
    *a++ = (uint8_t)ip[j];
  }
  if (need_v4 && !ftun_ipv4_parse(s, strlen(s), a-4)) return 0;
  return 1;
}
static const char *format_ipv6(const uint8_t *a, char *s, size_t l)
{
  int i, j, max, best;
  char buf[100];
    if (memcmp(a, "\0\0\0\0\0\0\0\0\0\0\377\377", 12))
      snprintf(buf, sizeof buf,
        "%x:%x:%x:%x:%x:%x:%x:%x",
        256*a[0]+a[1],256*a[2]+a[3],
        256*a[4]+a[5],256*a[6]+a[7],
        256*a[8]+a[9],256*a[10]+a[11],
        256*a[12]+a[13],256*a[14]+a[15]);
    else
      snprintf(buf, sizeof buf,
        "%x:%x:%x:%x:%x:%x:%d.%d.%d.%d",
        256*a[0]+a[1],256*a[2]+a[3],
        256*a[4]+a[5],256*a[6]+a[7],
        256*a[8]+a[9],256*a[10]+a[11],
        a[12],a[13],a[14],a[15]);
    /* 压缩最长的连续零块，长度相同则保留最先出现者。 */
    for (i=best=0, max=2; buf[i]; i++) {
      if (i && buf[i] != ':') continue;
      j = (int)strspn(buf+i, ":0");

      if (j>max+(best==0)) best=i, max=j;
    }
    if (max>3) {
      buf[best] = buf[best+1] = ':';
      memmove(buf+best+2, buf+best+max, (size_t)(i-best-max+1));
    }
    if (strlen(buf) < l) {
      strcpy(s, buf);
      return s;
    }
  return NULL;
}

bool ftun_decimal_parse(const char *text, size_t length, uint32_t maximum,
                        uint32_t *out)
{
  uint32_t result = 0u;
  size_t index;
  if (text == NULL || length == 0u || (length > 1u && text[0] == '0')) return false;
  for (index = 0u; index < length; index++) {
    uint32_t digit;
    if (text[index] < '0' || text[index] > '9') return false;
    digit = (uint32_t)(text[index] - '0');
    if (result > (maximum - digit) / 10u) return false;
    result = result * 10u + digit;
  }
  if (out != NULL) *out = result;
  return true;
}

bool ftun_port_parse(const char *text, size_t length, uint16_t *out)
{
  uint32_t port;
  if (!ftun_decimal_parse(text, length, 65535u, &port) || port == 0u) return false;
  if (out != NULL) *out = (uint16_t)port;
  return true;
}

bool ftun_ipv4_parse(const char *text, size_t length, uint8_t out[4])
{
  uint8_t result[4];
  size_t start = 0u;
  size_t part;
  if (text == NULL || length == 0u) return false;
  for (part = 0u; part < 4u; part++) {
    size_t end = start;
    uint32_t octet;
    while (end < length && text[end] != '.') end++;
    if (!ftun_decimal_parse(text + start, end - start, 255u, &octet)) return false;
    result[part] = (uint8_t)octet;
    if (part == 3u) {
      if (end != length) return false;
    } else {
      if (end == length) return false;
      start = end + 1u;
    }
  }
  if (out != NULL) memcpy(out, result, sizeof(result));
  return true;
}

bool ftun_ip_parse(const char *text, size_t length, ftun_ip_t *out)
{
  ftun_ip_t result;
  char buffer[FTUN_IP_TEXT_BYTES];
  memset(&result, 0, sizeof(result));
  if (text == NULL || length == 0u) return false;
  if (ftun_ipv4_parse(text, length, result.bytes)) {
    result.family = FTUN_IP_V4;
  } else {
    /* 文本解析不依赖平台网络库。 */
    if (length >= sizeof(buffer) || memchr(text, ':', length) == NULL) return false;
    memcpy(buffer, text, length);
    buffer[length] = '\0';
    if (parse_ipv6(buffer, result.bytes) != 1) return false;
    result.family = FTUN_IP_V6;
  }
  if (out != NULL) *out = result;
  return true;
}

bool ftun_host_port_split(const char *text, size_t length,
                          ftun_host_port_t *out)
{
  ftun_host_port_t result;
  const char *colon;
  memset(&result, 0, sizeof(result));
  if (text == NULL || length == 0u) return false;
  if (text[0] == '[') {
    const char *close = memchr(text, ']', length);
    size_t rest;
    if (close == NULL || close == text + 1) return false;
    result.host = text + 1;
    result.host_length = (size_t)(close - text) - 1u;
    result.bracketed = true;
    rest = length - (size_t)(close - text) - 1u;
    if (rest != 0u) {
      if (close[1] != ':' || !ftun_port_parse(close + 2, rest - 1u, &result.port)) {
        return false;
      }
      result.has_port = true;
    }
  } else {
    colon = memchr(text, ':', length);
    if (colon == NULL) {
      result.host = text;
      result.host_length = length;
    } else {
      result.host = text;
      result.host_length = (size_t)(colon - text);
      if (!ftun_port_parse(colon + 1, length - (size_t)(colon - text) - 1u,
                           &result.port)) return false;
      result.has_port = true;
    }
  }
  if (result.host_length == 0u) return false;
  if (out != NULL) *out = result;
  return true;
}

uint32_t ftun_ipv4_mask(uint8_t prefix)
{
  return prefix == 0u ? 0u : prefix >= 32u ? UINT32_MAX : UINT32_MAX << (32u - prefix);
}

uint32_t ftun_ipv4_value(const uint8_t bytes[4])
{
  return ((uint32_t)bytes[0] << 24u) | ((uint32_t)bytes[1] << 16u) |
         ((uint32_t)bytes[2] << 8u) | (uint32_t)bytes[3];
}

void ftun_ipv4_store(uint32_t value, uint8_t bytes[4])
{
  bytes[0] = (uint8_t)(value >> 24u);
  bytes[1] = (uint8_t)(value >> 16u);
  bytes[2] = (uint8_t)(value >> 8u);
  bytes[3] = (uint8_t)value;
}

/* 前 prefix 位相同；主机位是否为 0 由调用方决定。 */
static bool ftun_bits_match(const uint8_t *left, const uint8_t *right,
                            unsigned int prefix)
{
  unsigned int whole = prefix / 8u;
  unsigned int rest = prefix % 8u;
  if (whole != 0u && memcmp(left, right, whole) != 0) return false;
  if (rest != 0u) {
    uint8_t mask = (uint8_t)(0xffu << (8u - rest));
    if (((left[whole] ^ right[whole]) & mask) != 0u) return false;
  }
  return true;
}

bool ftun_cidr_parse(const char *text, size_t length, bool require_network,
                     ftun_cidr_t *out)
{
  ftun_cidr_t result;
  const char *slash;
  uint32_t prefix;
  unsigned int maximum;
  memset(&result, 0, sizeof(result));
  if (text == NULL || length == 0u) return false;
  slash = memchr(text, '/', length);
  if (slash == NULL ||
      memchr(slash + 1, '/', length - (size_t)(slash - text) - 1u) != NULL) return false;
  if (!ftun_ip_parse(text, (size_t)(slash - text), &result.address)) return false;
  maximum = result.address.family == FTUN_IP_V4 ? 32u : 128u;
  if (!ftun_decimal_parse(slash + 1, length - (size_t)(slash - text) - 1u,
                          maximum, &prefix)) return false;
  result.prefix = (uint8_t)prefix;
  if (require_network) {
    /* 主机位全 0：与全零地址在后 (maximum - prefix) 位上比较。 */
    uint8_t masked[16];
    unsigned int index;
    memcpy(masked, result.address.bytes, sizeof(masked));
    for (index = 0u; index < maximum / 8u; index++) {
      unsigned int bit = index * 8u;
      if (bit >= prefix) masked[index] = 0u;
      else if (bit + 8u > prefix) masked[index] &= (uint8_t)(0xffu << (8u - (prefix - bit)));
    }
    if (memcmp(masked, result.address.bytes, sizeof(masked)) != 0) return false;
  }
  if (out != NULL) *out = result;
  return true;
}

bool ftun_ip_equal(const ftun_ip_t *left, const ftun_ip_t *right)
{
  size_t size;
  if (left->family != right->family) return false;
  size = left->family == FTUN_IP_V4 ? 4u : left->family == FTUN_IP_V6 ? 16u : 0u;
  return memcmp(left->bytes, right->bytes, size) == 0;
}

bool ftun_cidr_contains(const ftun_cidr_t *cidr, const ftun_ip_t *address)
{
  if (cidr->address.family == FTUN_IP_NONE || cidr->address.family != address->family) {
    return false;
  }
  return ftun_bits_match(cidr->address.bytes, address->bytes, cidr->prefix);
}

size_t ftun_ip_format(const ftun_ip_t *address, char *out, size_t capacity)
{
  int length;
  if (out == NULL || capacity == 0u) return 0;
  out[0] = '\0';
  if (address->family == FTUN_IP_V6) {
    if (format_ipv6(address->bytes, out, capacity) == NULL) return 0;
    return strlen(out);
  }
  if (address->family != FTUN_IP_V4) return 0;
  length = snprintf(out, capacity, "%u.%u.%u.%u", address->bytes[0],
    address->bytes[1], address->bytes[2], address->bytes[3]);
  if (length < 0 || (size_t)length >= capacity) { out[0] = '\0'; return 0; }
  return (size_t)length;
}

bool ftun_cidr_ipv4_range(const ftun_cidr_t *cidr, uint32_t *network,
                          uint32_t *broadcast)
{
  uint32_t mask, value;
  if (cidr->address.family != FTUN_IP_V4 || cidr->prefix > 32u) return false;
  mask = ftun_ipv4_mask(cidr->prefix);
  value = ftun_ipv4_value(cidr->address.bytes) & mask;
  if (network != NULL) *network = value;
  if (broadcast != NULL) *broadcast = value | ~mask;
  return true;
}

bool ftun_cidr_ipv4_hosts(const ftun_cidr_t *cidr, uint32_t *first,
                          uint32_t *end)
{
  uint32_t network, broadcast;
  if (!ftun_cidr_ipv4_range(cidr, &network, &broadcast) ||
      network == UINT32_MAX || network + 1u >= broadcast) return false;
  if (first != NULL) *first = network + 1u;
  if (end != NULL) *end = broadcast;
  return true;
}
