#ifndef FTUN_PROTOCOL_SOCKS5_H
#define FTUN_PROTOCOL_SOCKS5_H

#include "internal/contracts.h"

#define FTUN_SOCKS5_VERSION 0x05u
#define FTUN_SOCKS5_AUTH_VERSION 0x01u
#define FTUN_SOCKS5_METHOD_NO_AUTH 0x00u
#define FTUN_SOCKS5_METHOD_USERNAME_PASSWORD 0x02u
#define FTUN_SOCKS5_METHOD_NONE_ACCEPTABLE 0xffu
#define FTUN_SOCKS5_MAX_METHODS 255u
#define FTUN_SOCKS5_MAX_CREDENTIAL_BYTES 255u
#define FTUN_SOCKS5_MAX_DOMAIN_BYTES 255u

typedef enum {
  FTUN_SOCKS5_COMMAND_CONNECT = 0x01u,
  FTUN_SOCKS5_COMMAND_BIND = 0x02u,
  FTUN_SOCKS5_COMMAND_UDP_ASSOCIATE = 0x03u
} ftun_socks5_command_t;

typedef enum {
  FTUN_SOCKS5_REPLY_SUCCEEDED = 0x00u,
  FTUN_SOCKS5_REPLY_GENERAL_FAILURE = 0x01u,
  FTUN_SOCKS5_REPLY_NOT_ALLOWED = 0x02u,
  FTUN_SOCKS5_REPLY_NETWORK_UNREACHABLE = 0x03u,
  FTUN_SOCKS5_REPLY_HOST_UNREACHABLE = 0x04u,
  FTUN_SOCKS5_REPLY_CONNECTION_REFUSED = 0x05u,
  FTUN_SOCKS5_REPLY_TTL_EXPIRED = 0x06u,
  FTUN_SOCKS5_REPLY_COMMAND_UNSUPPORTED = 0x07u,
  FTUN_SOCKS5_REPLY_ADDRESS_UNSUPPORTED = 0x08u
} ftun_socks5_reply_code_t;

typedef struct {
  ftun_bytes_t methods; /* 借用输入，仅在输入仍有效时使用。 */
} ftun_socks5_method_offer_t;

typedef struct {
  ftun_bytes_t username; /* 借用输入。 */
  ftun_bytes_t password; /* 借用输入。 */
} ftun_socks5_credentials_t;

typedef struct {
  ftun_socks5_command_t command;
  ftun_endpoint_t endpoint; /* DOMAIN 字符串借用输入。 */
} ftun_socks5_request_t;

typedef struct {
  uint8_t reply;
  ftun_endpoint_t endpoint; /* DOMAIN 字符串借用输入。 */
} ftun_socks5_reply_t;

typedef struct {
  ftun_endpoint_t endpoint; /* DOMAIN 字符串借用输入。 */
  ftun_bytes_t payload;     /* 借用整个 UDP 报文。 */
} ftun_socks5_udp_datagram_t;

/* 共享 SOCKS5 编解码。
 * 所有 decode 都是无状态纯增量解析：OK 表示一帧完整且 consumed 精确指向
 * 下一帧，AGAIN 表示还需字节，PROTOCOL 表示非法线格式，UNSUPPORTED 表示
 * 已识别但首版不支持的 BIND、IPv6 或 UDP 分片。非 OK 时输出和 consumed 清零。
 * 返回视图同步借用 input；调用者分别持有入站/出站认证阶段，不存在共享认证状态。
 * 所有 encode 都是整帧写入；容量不足返回 LIMIT、written=0 且不修改输出。
 */
ftun_status_t ftun_socks5_decode_method_offer(
  ftun_bytes_t input, ftun_socks5_method_offer_t *out, size_t *consumed);
ftun_status_t ftun_socks5_encode_method_offer(
  ftun_bytes_t methods, uint8_t *output, size_t capacity, size_t *written);
bool ftun_socks5_method_offer_contains(
  const ftun_socks5_method_offer_t *offer, uint8_t method);

ftun_status_t ftun_socks5_decode_method_selection(
  ftun_bytes_t input, uint8_t *method, size_t *consumed);
ftun_status_t ftun_socks5_encode_method_selection(
  uint8_t method, uint8_t *output, size_t capacity, size_t *written);

ftun_status_t ftun_socks5_decode_credentials(
  ftun_bytes_t input, ftun_socks5_credentials_t *out, size_t *consumed);
ftun_status_t ftun_socks5_encode_credentials(
  ftun_bytes_t username, ftun_bytes_t password,
  uint8_t *output, size_t capacity, size_t *written);
ftun_status_t ftun_socks5_decode_auth_result(
  ftun_bytes_t input, uint8_t *status, size_t *consumed);
ftun_status_t ftun_socks5_encode_auth_result(
  uint8_t status, uint8_t *output, size_t capacity, size_t *written);

ftun_status_t ftun_socks5_decode_request(
  ftun_bytes_t input, ftun_socks5_request_t *out, size_t *consumed);
ftun_status_t ftun_socks5_encode_request(
  ftun_socks5_command_t command, const ftun_endpoint_t *endpoint,
  uint8_t *output, size_t capacity, size_t *written);
/* 回复的 BND 字段允许 ATYP=IPv6，解析为 FTUN_ADDRESS_IPV6_RESERVED；
 * 是否可用该地址（如 UDP relay）由调用方按自身能力判断。请求和 UDP 封装
 * 中的 IPv6 目标仍返回 UNSUPPORTED。 */
ftun_status_t ftun_socks5_decode_reply(
  ftun_bytes_t input, ftun_socks5_reply_t *out, size_t *consumed);
ftun_status_t ftun_socks5_encode_reply(
  uint8_t reply, const ftun_endpoint_t *endpoint,
  uint8_t *output, size_t capacity, size_t *written);

/* 当前不实现 SOCKS UDP 分片；FRAG!=0 的报文返回 UNSUPPORTED。UDP 输入本身
 * 已有报文边界，因此成功时 consumed 等于整个 input.length，payload 可为空。 */
ftun_status_t ftun_socks5_decode_udp_datagram(
  ftun_bytes_t input, ftun_socks5_udp_datagram_t *out, size_t *consumed);
ftun_status_t ftun_socks5_encode_udp_datagram(
  const ftun_endpoint_t *endpoint, ftun_bytes_t payload,
  uint8_t *output, size_t capacity, size_t *written);

/* 保留模块清单中的通用入口；它按 SOCKS 请求帧解码目标。 */
ftun_status_t ftun_socks5_decode(ftun_bytes_t input,
                                 ftun_protocol_result_t *out);

#endif
