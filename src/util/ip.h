#ifndef FTUN_UTIL_IP_H
#define FTUN_UTIL_IP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* 地址文本的解析与地址运算，纯函数：不分配、不做 I/O、不依赖配置或运行时。
 * 地址可以表示 IPv6（解析、比较、格式化、前缀包含），但 IPv6 数据路径尚未打开，
 * 需要 IPv4 的调用方必须自己检查 family。所有解析都要求完全匹配，不接受
 * 前导零、空白或多余字符。 */

#define FTUN_IP_NONE 0u
#define FTUN_IP_V4 4u
#define FTUN_IP_V6 6u
#define FTUN_IP_TEXT_BYTES 46u

typedef struct {
  uint8_t family;      /* FTUN_IP_NONE / FTUN_IP_V4 / FTUN_IP_V6 */
  uint8_t bytes[16];   /* 网络字节序；IPv4 只用前 4 字节 */
} ftun_ip_t;

typedef struct {
  ftun_ip_t address;
  uint8_t prefix;      /* IPv4 0..32，IPv6 0..128 */
} ftun_cidr_t;

/* "host"、"host:port"、"[ipv6]"、"[ipv6]:port"。host 指向输入，不含方括号。
 * 未加方括号时第一个冒号之后必须是端口，因此裸 IPv6 字面量会被拒绝（有歧义）。 */
typedef struct {
  const char *host;
  size_t host_length;
  uint16_t port;
  bool has_port;
  bool bracketed;
} ftun_host_port_t;

/* 十进制整数：无符号、无前导零（单个 0 除外）、不超过 maximum。 */
bool ftun_decimal_parse(const char *text, size_t length, uint32_t maximum,
                        uint32_t *out);
/* 端口 1..65535。 */
bool ftun_port_parse(const char *text, size_t length, uint16_t *out);
/* 严格点分十进制 IPv4。 */
bool ftun_ipv4_parse(const char *text, size_t length, uint8_t out[4]);
/* IPv4 或 IPv6 字面量。 */
bool ftun_ip_parse(const char *text, size_t length, ftun_ip_t *out);
bool ftun_host_port_split(const char *text, size_t length,
                          ftun_host_port_t *out);
/* "address/prefix"。require_network 为真时主机位必须全 0。 */
bool ftun_cidr_parse(const char *text, size_t length, bool require_network,
                     ftun_cidr_t *out);

bool ftun_ip_equal(const ftun_ip_t *left, const ftun_ip_t *right);
/* address 是否落在 cidr 内；家族不同返回 false。 */
bool ftun_cidr_contains(const ftun_cidr_t *cidr, const ftun_ip_t *address);
/* 文本形式，返回写入长度（不含结尾 0）；容量不足返回 0。 */
size_t ftun_ip_format(const ftun_ip_t *address, char *out, size_t capacity);

/* IPv4 运算，数值均为主机字节序。 */
uint32_t ftun_ipv4_mask(uint8_t prefix);
uint32_t ftun_ipv4_value(const uint8_t bytes[4]);
void ftun_ipv4_store(uint32_t value, uint8_t bytes[4]);
/* IPv4 CIDR 的网络地址与广播地址；非 IPv4 返回 false。 */
bool ftun_cidr_ipv4_range(const ftun_cidr_t *cidr, uint32_t *network,
                          uint32_t *broadcast);
/* 可分配的主机地址区间 [first, end)：网络地址之后到广播地址之前；
 * 至少要有一个主机地址，否则返回 false。 */
bool ftun_cidr_ipv4_hosts(const ftun_cidr_t *cidr, uint32_t *first,
                          uint32_t *end);

#endif
