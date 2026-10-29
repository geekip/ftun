#ifndef FTUN_LIBS_TRANSPORT_PROTOCOL_H
#define FTUN_LIBS_TRANSPORT_PROTOCOL_H
#include "util/types.h"

/* 协议实现由装配层注入。state_bytes 由受信实现给出，调用方先准入再分配，
 * 状态和借用输入只属于一个 owner；帧必须整帧写完后才推进 output_done。
 * input 的 bound 借用状态或输入，datagram 的 endpoint/payload 借用输入。 */
typedef struct {
  ftun_bytes_t username, password;
  ftun_endpoint_t target, peer;
  bool datagram;
} ftun_transport_protocol_options_t;
typedef struct {
  ftun_endpoint_t endpoint;
  ftun_bytes_t payload;
} ftun_transport_datagram_t;
typedef struct {
  ftun_status_t (*write_all)(void *context, const uint8_t *data, size_t length);
  ftun_status_t (*read_exact)(void *context, uint8_t *data, size_t length);
  void *context;
} ftun_transport_protocol_io_t;
typedef struct {
  size_t state_bytes;
  ftun_status_t (*init)(void *state, const ftun_transport_protocol_options_t *options);
  bool (*wants_output)(const void *state);
  ftun_status_t (*output)(const void *state, uint8_t *buffer, size_t capacity, size_t *length);
  ftun_status_t (*output_done)(void *state);
  size_t (*needed)(const void *state);
  ftun_status_t (*input)(void *state, ftun_bytes_t input, size_t *consumed, ftun_endpoint_t *bound);
  ftun_status_t (*encode_datagram)(const ftun_endpoint_t *target, ftun_bytes_t payload,
    uint8_t *output, size_t capacity, size_t *written);
  ftun_status_t (*decode_datagram)(ftun_bytes_t input, ftun_transport_datagram_t *out, size_t *consumed);
  ftun_status_t (*run)(const ftun_transport_protocol_options_t *options,
    const ftun_transport_protocol_io_t *io);
} ftun_transport_protocol_t;
#endif
