#ifndef FTUN_LIBS_TRANSPORT_SOCKS5_CLIENT_H
#define FTUN_LIBS_TRANSPORT_SOCKS5_CLIENT_H
#include "libs/transport/socks5_codec.h"

/* SOCKS5 客户端握手状态机（无 I/O）。
 * 握手顺序：方法协商 -> （用户名密码认证）-> CONNECT/UDP ASSOCIATE 请求 -> 回复。
 * 状态机只管字节：驱动方（异步事件循环或阻塞调用）自己负责收发，所有驱动共用
 * 这一份实现，因此 BND 地址解析（含 IPv6）、方法协商和回复码映射只存在一处。
 *
 * 用法：
 *   init；然后循环：
 *     wants_output  -> output 取出待发送的整帧，发完（可分多次写）后调用 output_done；
 *     否则          -> needed 给出至少还需读取的字节数，把读到的字节交给 input；
 *   input 返回 OK 表示握手完成（回复码为成功），result 含 BND；
 *   返回 AGAIN 表示还要继续（可能轮到发送，用 wants_output 判断）；
 *   其他状态是握手失败。needed 是“精确读取”的上界：按它读取不会多读到隧道数据。
 * options 里的用户名、密码、目标是借用的，必须在握手期间保持有效。 */
#define FTUN_SOCKS5_CLIENT_FRAME_BYTES 513u
#define FTUN_SOCKS5_CLIENT_REPLY_BYTES 262u

typedef struct {
  ftun_bytes_t username; /* 空表示不认证 */
  ftun_bytes_t password;
  ftun_socks5_command_t command; /* CONNECT 或 UDP_ASSOCIATE */
  ftun_endpoint_t target;        /* UDP_ASSOCIATE 时忽略（发送全零 IPv4） */
} ftun_socks5_client_options_t;

typedef struct {
  uint8_t reply;            /* 服务端回复码 */
  ftun_endpoint_t bound;    /* BND；域名借用状态机内部缓冲，下次 init 前有效 */
} ftun_socks5_client_result_t;

typedef enum {
  FTUN_SOCKS5_CLIENT_METHOD_OUT = 1,
  FTUN_SOCKS5_CLIENT_METHOD_IN,
  FTUN_SOCKS5_CLIENT_AUTH_OUT,
  FTUN_SOCKS5_CLIENT_AUTH_IN,
  FTUN_SOCKS5_CLIENT_REQUEST_OUT,
  FTUN_SOCKS5_CLIENT_REPLY_IN,
  FTUN_SOCKS5_CLIENT_DONE,
  FTUN_SOCKS5_CLIENT_FAILED
} ftun_socks5_client_phase_t;

typedef struct {
  ftun_socks5_client_options_t options;
  ftun_socks5_client_phase_t phase;
  uint8_t input[FTUN_SOCKS5_CLIENT_REPLY_BYTES];
  size_t input_length;
} ftun_socks5_client_t;

ftun_status_t ftun_socks5_client_init(ftun_socks5_client_t *client,
  const ftun_socks5_client_options_t *options);
bool ftun_socks5_client_wants_output(const ftun_socks5_client_t *client);
/* 把当前待发送的整帧编码进调用方的缓冲（至少 FTUN_SOCKS5_CLIENT_FRAME_BYTES）。
 * 同一帧发完之前重复调用得到相同内容；没有待发送内容返回 AGAIN。 */
ftun_status_t ftun_socks5_client_output(const ftun_socks5_client_t *client,
  uint8_t *buffer, size_t capacity, size_t *length);
/* 当前帧已全部发送，转入等待回复。 */
ftun_status_t ftun_socks5_client_output_done(ftun_socks5_client_t *client);
/* 完成当前输入帧还需要读取的字节数（至少 1）；不在等待输入时返回 0。 */
size_t ftun_socks5_client_needed(const ftun_socks5_client_t *client);
/* 喂入收到的字节。consumed 是实际取走的字节数（不会超过完成当前帧所需），其余
 * 字节归还调用方。 */
ftun_status_t ftun_socks5_client_input(ftun_socks5_client_t *client,
  ftun_bytes_t in, size_t *consumed, ftun_socks5_client_result_t *result);

/* 阻塞驱动：用 write_all/read_exact 跑完整个握手。 */
typedef struct {
  ftun_status_t (*write_all)(void *context, const uint8_t *data, size_t length);
  ftun_status_t (*read_exact)(void *context, uint8_t *data, size_t length);
  void *context;
} ftun_socks5_client_io_t;
ftun_status_t ftun_socks5_client_run(ftun_socks5_client_t *client,
  const ftun_socks5_client_io_t *io, ftun_socks5_client_result_t *result);

/* 回复码到状态的统一映射。 */
ftun_status_t ftun_socks5_client_reply_status(uint8_t reply);

#endif
