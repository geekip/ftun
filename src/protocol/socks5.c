#include "socks5.h"

#include <stdint.h>
#include <string.h>

#define FTUN_SOCKS5_ATYP_IPV4 0x01u
#define FTUN_SOCKS5_ATYP_DOMAIN 0x03u
#define FTUN_SOCKS5_ATYP_IPV6 0x04u

/* ftun_socks5_decode 及同文件细分入口实现 TASK-PROTOCOL-001（0.2.0）。
 * 纯函数只解释 RFC 1928/1929 字节，不持有调用方认证状态。 */

static ftun_status_t validate_input(ftun_bytes_t input)
{
  if (input.length != 0u && input.data == NULL) return FTUN_E_INVALID;
  return FTUN_OK;
}

static ftun_status_t validate_bytes(ftun_bytes_t bytes, size_t minimum,
                                    size_t maximum)
{
  if (bytes.length < minimum || bytes.length > maximum) return FTUN_E_INVALID;
  if (bytes.length != 0u && bytes.data == NULL) return FTUN_E_INVALID;
  return FTUN_OK;
}

static ftun_status_t prepare_encode(uint8_t *output, size_t capacity,
                                    size_t required, size_t *written)
{
  if (written == NULL) return FTUN_E_INVALID;
  *written = 0u;
  if (output == NULL) return FTUN_E_INVALID;
  if (capacity < required) return FTUN_E_LIMIT;
  return FTUN_OK;
}

static ftun_status_t endpoint_wire_size(const ftun_endpoint_t *endpoint,
                                        size_t *out)
{
  if (endpoint == NULL || out == NULL) return FTUN_E_INVALID;
  *out = 0u;
  switch (endpoint->kind) {
    case FTUN_ADDRESS_IPV4:
      *out = 7u;
      return FTUN_OK;
    case FTUN_ADDRESS_DOMAIN:
      if (endpoint->domain.data == NULL || endpoint->domain.length == 0u ||
          endpoint->domain.length > FTUN_SOCKS5_MAX_DOMAIN_BYTES) {
        return FTUN_E_INVALID;
      }
      *out = 4u + endpoint->domain.length;
      return FTUN_OK;
    case FTUN_ADDRESS_IPV6_RESERVED:
      return FTUN_E_UNSUPPORTED;
    case FTUN_ADDRESS_NONE:
    default:
      return FTUN_E_INVALID;
  }
}

static void encode_port(uint16_t port, uint8_t *output)
{
  output[0] = (uint8_t)(port >> 8u);
  output[1] = (uint8_t)(port & 0xffu);
}

static ftun_status_t encode_endpoint(const ftun_endpoint_t *endpoint,
                                     uint8_t *output, size_t capacity,
                                     size_t *written)
{
  size_t required = 0u;
  ftun_status_t status = endpoint_wire_size(endpoint, &required);
  if (status != FTUN_OK) {
    if (written != NULL) *written = 0u;
    return status;
  }
  status = prepare_encode(output, capacity, required, written);
  if (status != FTUN_OK) return status;
  if (endpoint->kind == FTUN_ADDRESS_IPV4) {
    output[0] = FTUN_SOCKS5_ATYP_IPV4;
    memcpy(output + 1u, endpoint->address, 4u);
    encode_port(endpoint->port, output + 5u);
  } else {
    memmove(output + 2u, endpoint->domain.data, endpoint->domain.length);
    output[0] = FTUN_SOCKS5_ATYP_DOMAIN;
    output[1] = (uint8_t)endpoint->domain.length;
    encode_port(endpoint->port, output + 2u + endpoint->domain.length);
  }
  *written = required;
  return FTUN_OK;
}

static ftun_status_t decode_endpoint(ftun_bytes_t input, size_t offset,
                                     ftun_endpoint_t *out, size_t *consumed)
{
  uint8_t atyp;
  size_t required;
  size_t domain_length;
  memset(out, 0, sizeof(*out));
  *consumed = 0u;
  if (input.length <= offset) return FTUN_E_AGAIN;
  atyp = input.data[offset];
  if (atyp == FTUN_SOCKS5_ATYP_IPV6) return FTUN_E_UNSUPPORTED;
  if (atyp == FTUN_SOCKS5_ATYP_IPV4) {
    required = offset + 7u;
    if (input.length < required) return FTUN_E_AGAIN;
    out->kind = FTUN_ADDRESS_IPV4;
    memcpy(out->address, input.data + offset + 1u, 4u);
    out->port = (uint16_t)(((uint16_t)input.data[offset + 5u] << 8u) |
                           (uint16_t)input.data[offset + 6u]);
    *consumed = required;
    return FTUN_OK;
  }
  if (atyp != FTUN_SOCKS5_ATYP_DOMAIN) return FTUN_E_PROTOCOL;
  if (input.length <= offset + 1u) return FTUN_E_AGAIN;
  domain_length = input.data[offset + 1u];
  if (domain_length == 0u) return FTUN_E_PROTOCOL;
  required = offset + 4u + domain_length;
  if (input.length < required) return FTUN_E_AGAIN;
  out->kind = FTUN_ADDRESS_DOMAIN;
  out->domain.data = (const char *)(input.data + offset + 2u);
  out->domain.length = domain_length;
  out->port = (uint16_t)(((uint16_t)input.data[required - 2u] << 8u) |
                         (uint16_t)input.data[required - 1u]);
  *consumed = required;
  return FTUN_OK;
}

ftun_status_t ftun_socks5_decode_method_offer(
  ftun_bytes_t input, ftun_socks5_method_offer_t *out, size_t *consumed)
{
  size_t required;
  if (out == NULL || consumed == NULL) return FTUN_E_INVALID;
  memset(out, 0, sizeof(*out));
  *consumed = 0u;
  if (validate_input(input) != FTUN_OK) return FTUN_E_INVALID;
  if (input.length == 0u) return FTUN_E_AGAIN;
  if (input.data[0] != FTUN_SOCKS5_VERSION) return FTUN_E_PROTOCOL;
  if (input.length < 2u) return FTUN_E_AGAIN;
  if (input.data[1] == 0u) return FTUN_E_PROTOCOL;
  required = 2u + input.data[1];
  if (input.length < required) return FTUN_E_AGAIN;
  out->methods.data = input.data + 2u;
  out->methods.length = input.data[1];
  *consumed = required;
  return FTUN_OK;
}

ftun_status_t ftun_socks5_encode_method_offer(
  ftun_bytes_t methods, uint8_t *output, size_t capacity, size_t *written)
{
  size_t required;
  ftun_status_t status;
  if (written != NULL) *written = 0u;
  status = validate_bytes(methods, 1u, FTUN_SOCKS5_MAX_METHODS);
  if (status != FTUN_OK) return status;
  required = 2u + methods.length;
  status = prepare_encode(output, capacity, required, written);
  if (status != FTUN_OK) return status;
  memmove(output + 2u, methods.data, methods.length);
  output[0] = FTUN_SOCKS5_VERSION;
  output[1] = (uint8_t)methods.length;
  *written = required;
  return FTUN_OK;
}

bool ftun_socks5_method_offer_contains(
  const ftun_socks5_method_offer_t *offer, uint8_t method)
{
  size_t index;
  if (offer == NULL || offer->methods.data == NULL ||
      offer->methods.length == 0u) return false;
  for (index = 0u; index < offer->methods.length; index++) {
    if (offer->methods.data[index] == method) return true;
  }
  return false;
}

ftun_status_t ftun_socks5_decode_method_selection(
  ftun_bytes_t input, uint8_t *method, size_t *consumed)
{
  if (method == NULL || consumed == NULL) return FTUN_E_INVALID;
  *method = 0u;
  *consumed = 0u;
  if (validate_input(input) != FTUN_OK) return FTUN_E_INVALID;
  if (input.length == 0u) return FTUN_E_AGAIN;
  if (input.data[0] != FTUN_SOCKS5_VERSION) return FTUN_E_PROTOCOL;
  if (input.length < 2u) return FTUN_E_AGAIN;
  *method = input.data[1];
  *consumed = 2u;
  return FTUN_OK;
}

ftun_status_t ftun_socks5_encode_method_selection(
  uint8_t method, uint8_t *output, size_t capacity, size_t *written)
{
  ftun_status_t status = prepare_encode(output, capacity, 2u, written);
  if (status != FTUN_OK) return status;
  output[0] = FTUN_SOCKS5_VERSION;
  output[1] = method;
  *written = 2u;
  return FTUN_OK;
}

ftun_status_t ftun_socks5_decode_credentials(
  ftun_bytes_t input, ftun_socks5_credentials_t *out, size_t *consumed)
{
  size_t username_length;
  size_t password_offset;
  size_t password_length;
  size_t required;
  if (out == NULL || consumed == NULL) return FTUN_E_INVALID;
  memset(out, 0, sizeof(*out));
  *consumed = 0u;
  if (validate_input(input) != FTUN_OK) return FTUN_E_INVALID;
  if (input.length == 0u) return FTUN_E_AGAIN;
  if (input.data[0] != FTUN_SOCKS5_AUTH_VERSION) return FTUN_E_PROTOCOL;
  if (input.length < 2u) return FTUN_E_AGAIN;
  username_length = input.data[1];
  if (username_length == 0u) return FTUN_E_PROTOCOL;
  password_offset = 2u + username_length;
  if (input.length <= password_offset) return FTUN_E_AGAIN;
  password_length = input.data[password_offset];
  if (password_length == 0u) return FTUN_E_PROTOCOL;
  required = password_offset + 1u + password_length;
  if (input.length < required) return FTUN_E_AGAIN;
  out->username.data = input.data + 2u;
  out->username.length = username_length;
  out->password.data = input.data + password_offset + 1u;
  out->password.length = password_length;
  *consumed = required;
  return FTUN_OK;
}

ftun_status_t ftun_socks5_encode_credentials(
  ftun_bytes_t username, ftun_bytes_t password,
  uint8_t *output, size_t capacity, size_t *written)
{
  size_t required;
  size_t password_offset;
  ftun_status_t status;
  if (written != NULL) *written = 0u;
  status = validate_bytes(username, 1u, FTUN_SOCKS5_MAX_CREDENTIAL_BYTES);
  if (status != FTUN_OK) return status;
  status = validate_bytes(password, 1u, FTUN_SOCKS5_MAX_CREDENTIAL_BYTES);
  if (status != FTUN_OK) return status;
  required = 3u + username.length + password.length;
  status = prepare_encode(output, capacity, required, written);
  if (status != FTUN_OK) return status;
  password_offset = 3u + username.length;
  memmove(output + password_offset, password.data, password.length);
  memmove(output + 2u, username.data, username.length);
  output[0] = FTUN_SOCKS5_AUTH_VERSION;
  output[1] = (uint8_t)username.length;
  output[2u + username.length] = (uint8_t)password.length;
  *written = required;
  return FTUN_OK;
}

ftun_status_t ftun_socks5_decode_auth_result(
  ftun_bytes_t input, uint8_t *status, size_t *consumed)
{
  if (status == NULL || consumed == NULL) return FTUN_E_INVALID;
  *status = 0u;
  *consumed = 0u;
  if (validate_input(input) != FTUN_OK) return FTUN_E_INVALID;
  if (input.length == 0u) return FTUN_E_AGAIN;
  if (input.data[0] != FTUN_SOCKS5_AUTH_VERSION) return FTUN_E_PROTOCOL;
  if (input.length < 2u) return FTUN_E_AGAIN;
  *status = input.data[1];
  *consumed = 2u;
  return FTUN_OK;
}

ftun_status_t ftun_socks5_encode_auth_result(
  uint8_t status_value, uint8_t *output, size_t capacity, size_t *written)
{
  ftun_status_t status = prepare_encode(output, capacity, 2u, written);
  if (status != FTUN_OK) return status;
  output[0] = FTUN_SOCKS5_AUTH_VERSION;
  output[1] = status_value;
  *written = 2u;
  return FTUN_OK;
}

static ftun_status_t validate_command(uint8_t command)
{
  if (command == FTUN_SOCKS5_COMMAND_BIND) return FTUN_E_UNSUPPORTED;
  if (command != FTUN_SOCKS5_COMMAND_CONNECT &&
      command != FTUN_SOCKS5_COMMAND_UDP_ASSOCIATE) return FTUN_E_PROTOCOL;
  return FTUN_OK;
}

ftun_status_t ftun_socks5_decode_request(
  ftun_bytes_t input, ftun_socks5_request_t *out, size_t *consumed)
{
  ftun_status_t status;
  ftun_endpoint_t endpoint;
  size_t frame_length = 0u;
  if (out == NULL || consumed == NULL) return FTUN_E_INVALID;
  memset(out, 0, sizeof(*out));
  *consumed = 0u;
  if (validate_input(input) != FTUN_OK) return FTUN_E_INVALID;
  if (input.length == 0u) return FTUN_E_AGAIN;
  if (input.data[0] != FTUN_SOCKS5_VERSION) return FTUN_E_PROTOCOL;
  if (input.length < 2u) return FTUN_E_AGAIN;
  status = validate_command(input.data[1]);
  if (status != FTUN_OK) return status;
  if (input.length < 3u) return FTUN_E_AGAIN;
  if (input.data[2] != 0u) return FTUN_E_PROTOCOL;
  status = decode_endpoint(input, 3u, &endpoint, &frame_length);
  if (status != FTUN_OK) return status;
  out->command = (ftun_socks5_command_t)input.data[1];
  out->endpoint = endpoint;
  *consumed = frame_length;
  return FTUN_OK;
}

ftun_status_t ftun_socks5_encode_request(
  ftun_socks5_command_t command, const ftun_endpoint_t *endpoint,
  uint8_t *output, size_t capacity, size_t *written)
{
  size_t endpoint_size = 0u;
  size_t endpoint_written = 0u;
  size_t required;
  ftun_status_t status;
  if (written != NULL) *written = 0u;
  status = validate_command((uint8_t)command);
  if (status != FTUN_OK) return status;
  status = endpoint_wire_size(endpoint, &endpoint_size);
  if (status != FTUN_OK) return status;
  required = 3u + endpoint_size;
  status = prepare_encode(output, capacity, required, written);
  if (status != FTUN_OK) return status;
  status = encode_endpoint(endpoint, output + 3u, capacity - 3u,
                           &endpoint_written);
  if (status != FTUN_OK || endpoint_written != endpoint_size) {
    return status == FTUN_OK ? FTUN_E_STATE_CORRUPT : status;
  }
  output[0] = FTUN_SOCKS5_VERSION;
  output[1] = (uint8_t)command;
  output[2] = 0u;
  *written = required;
  return FTUN_OK;
}

ftun_status_t ftun_socks5_decode_reply(
  ftun_bytes_t input, ftun_socks5_reply_t *out, size_t *consumed)
{
  ftun_status_t status;
  ftun_endpoint_t endpoint;
  size_t frame_length = 0u;
  if (out == NULL || consumed == NULL) return FTUN_E_INVALID;
  memset(out, 0, sizeof(*out));
  *consumed = 0u;
  if (validate_input(input) != FTUN_OK) return FTUN_E_INVALID;
  if (input.length == 0u) return FTUN_E_AGAIN;
  if (input.data[0] != FTUN_SOCKS5_VERSION) return FTUN_E_PROTOCOL;
  if (input.length < 3u) return FTUN_E_AGAIN;
  if (input.data[2] != 0u) return FTUN_E_PROTOCOL;
  status = decode_endpoint(input, 3u, &endpoint, &frame_length);
  if (status != FTUN_OK) return status;
  out->reply = input.data[1];
  out->endpoint = endpoint;
  *consumed = frame_length;
  return FTUN_OK;
}

ftun_status_t ftun_socks5_encode_reply(
  uint8_t reply, const ftun_endpoint_t *endpoint,
  uint8_t *output, size_t capacity, size_t *written)
{
  size_t endpoint_size = 0u;
  size_t endpoint_written = 0u;
  size_t required;
  ftun_status_t status;
  if (written != NULL) *written = 0u;
  status = endpoint_wire_size(endpoint, &endpoint_size);
  if (status != FTUN_OK) return status;
  required = 3u + endpoint_size;
  status = prepare_encode(output, capacity, required, written);
  if (status != FTUN_OK) return status;
  status = encode_endpoint(endpoint, output + 3u, capacity - 3u,
                           &endpoint_written);
  if (status != FTUN_OK || endpoint_written != endpoint_size) {
    return status == FTUN_OK ? FTUN_E_STATE_CORRUPT : status;
  }
  output[0] = FTUN_SOCKS5_VERSION;
  output[1] = reply;
  output[2] = 0u;
  *written = required;
  return FTUN_OK;
}

ftun_status_t ftun_socks5_decode_udp_datagram(
  ftun_bytes_t input, ftun_socks5_udp_datagram_t *out, size_t *consumed)
{
  ftun_status_t status;
  ftun_endpoint_t endpoint;
  size_t payload_offset = 0u;
  if (out == NULL || consumed == NULL) return FTUN_E_INVALID;
  memset(out, 0, sizeof(*out));
  *consumed = 0u;
  if (validate_input(input) != FTUN_OK) return FTUN_E_INVALID;
  if (input.length < 2u) return FTUN_E_AGAIN;
  if (input.data[0] != 0u || input.data[1] != 0u) return FTUN_E_PROTOCOL;
  if (input.length < 3u) return FTUN_E_AGAIN;
  if (input.data[2] != 0u) return FTUN_E_UNSUPPORTED;
  status = decode_endpoint(input, 3u, &endpoint, &payload_offset);
  if (status != FTUN_OK) return status;
  out->endpoint = endpoint;
  out->payload.data = input.data + payload_offset;
  out->payload.length = input.length - payload_offset;
  *consumed = input.length;
  return FTUN_OK;
}

ftun_status_t ftun_socks5_encode_udp_datagram(
  const ftun_endpoint_t *endpoint, ftun_bytes_t payload,
  uint8_t *output, size_t capacity, size_t *written)
{
  size_t endpoint_size = 0u;
  size_t endpoint_written = 0u;
  size_t payload_offset;
  size_t required;
  ftun_status_t status;
  if (written != NULL) *written = 0u;
  if (payload.length != 0u && payload.data == NULL) return FTUN_E_INVALID;
  status = endpoint_wire_size(endpoint, &endpoint_size);
  if (status != FTUN_OK) return status;
  payload_offset = 3u + endpoint_size;
  if (payload.length > SIZE_MAX - payload_offset) return FTUN_E_LIMIT;
  required = payload_offset + payload.length;
  status = prepare_encode(output, capacity, required, written);
  if (status != FTUN_OK) return status;
  if (payload.length != 0u) {
    memmove(output + payload_offset, payload.data, payload.length);
  }
  status = encode_endpoint(endpoint, output + 3u, capacity - 3u,
                           &endpoint_written);
  if (status != FTUN_OK || endpoint_written != endpoint_size) {
    return status == FTUN_OK ? FTUN_E_STATE_CORRUPT : status;
  }
  output[0] = 0u;
  output[1] = 0u;
  output[2] = 0u;
  *written = required;
  return FTUN_OK;
}

ftun_status_t ftun_socks5_decode(ftun_bytes_t input,
                                 ftun_protocol_result_t *out)
{
  ftun_socks5_request_t request;
  size_t consumed = 0u;
  ftun_status_t status;
  if (out == NULL) return FTUN_E_INVALID;
  memset(out, 0, sizeof(*out));
  status = ftun_socks5_decode_request(input, &request, &consumed);
  if (status != FTUN_OK) return status;
  out->complete = true;
  out->consumed = consumed;
  out->target = request.endpoint;
  return FTUN_OK;
}
