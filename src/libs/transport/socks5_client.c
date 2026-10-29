#include "libs/transport/socks5_client.h"
#include <string.h>

static ftun_status_t ftun_socks5_client_expected_method(
  const ftun_socks5_client_t *client, uint8_t *method)
{
  *method = client->options.username.length == 0u
    ? FTUN_SOCKS5_METHOD_NO_AUTH : FTUN_SOCKS5_METHOD_USERNAME_PASSWORD;
  return FTUN_OK;
}

ftun_status_t ftun_socks5_client_reply_status(uint8_t reply)
{
  switch (reply) {
    case FTUN_SOCKS5_REPLY_SUCCEEDED:
      return FTUN_OK;
    case FTUN_SOCKS5_REPLY_TTL_EXPIRED:
      return FTUN_E_TIMEOUT;
    case FTUN_SOCKS5_REPLY_COMMAND_UNSUPPORTED:
    case FTUN_SOCKS5_REPLY_ADDRESS_UNSUPPORTED:
      return FTUN_E_UNSUPPORTED;
    case FTUN_SOCKS5_REPLY_NOT_ALLOWED:
    case FTUN_SOCKS5_REPLY_NETWORK_UNREACHABLE:
    case FTUN_SOCKS5_REPLY_HOST_UNREACHABLE:
    case FTUN_SOCKS5_REPLY_CONNECTION_REFUSED:
      return FTUN_E_REJECTED;
    case FTUN_SOCKS5_REPLY_GENERAL_FAILURE:
      return FTUN_E_IO;
    default:
      return FTUN_E_PROTOCOL;
  }
}

ftun_status_t ftun_socks5_client_init(ftun_socks5_client_t *client,
  const ftun_socks5_client_options_t *options)
{
  if (client == NULL || options == NULL) return FTUN_E_INVALID;
  if ((options->username.length != 0u && options->username.data == NULL) ||
      (options->password.length != 0u && options->password.data == NULL) ||
      options->username.length > FTUN_SOCKS5_MAX_CREDENTIAL_BYTES ||
      options->password.length > FTUN_SOCKS5_MAX_CREDENTIAL_BYTES ||
      (options->command != FTUN_SOCKS5_COMMAND_CONNECT &&
       options->command != FTUN_SOCKS5_COMMAND_UDP_ASSOCIATE)) {
    return FTUN_E_INVALID;
  }
  memset(client, 0, sizeof(*client));
  client->options = *options;
  client->phase = FTUN_SOCKS5_CLIENT_METHOD_OUT;
  return FTUN_OK;
}

bool ftun_socks5_client_wants_output(const ftun_socks5_client_t *client)
{
  return client != NULL &&
    (client->phase == FTUN_SOCKS5_CLIENT_METHOD_OUT ||
     client->phase == FTUN_SOCKS5_CLIENT_AUTH_OUT ||
     client->phase == FTUN_SOCKS5_CLIENT_REQUEST_OUT);
}

ftun_status_t ftun_socks5_client_output(const ftun_socks5_client_t *client,
  uint8_t *buffer, size_t capacity, size_t *length)
{
  if (length != NULL) *length = 0u;
  if (client == NULL || buffer == NULL || length == NULL) return FTUN_E_INVALID;
  if (!ftun_socks5_client_wants_output(client)) return FTUN_E_AGAIN;
  if (client->phase == FTUN_SOCKS5_CLIENT_METHOD_OUT) {
    uint8_t method;
    (void)ftun_socks5_client_expected_method(client, &method);
    return ftun_socks5_encode_method_offer((ftun_bytes_t){&method, 1u}, buffer,
                                           capacity, length);
  }
  if (client->phase == FTUN_SOCKS5_CLIENT_AUTH_OUT) {
    return ftun_socks5_encode_credentials(client->options.username,
      client->options.password, buffer, capacity, length);
  }
  if (client->options.command == FTUN_SOCKS5_COMMAND_CONNECT) {
    return ftun_socks5_encode_request(FTUN_SOCKS5_COMMAND_CONNECT,
      &client->options.target, buffer, capacity, length);
  } else {
    ftun_endpoint_t any;
    memset(&any, 0, sizeof(any));
    any.kind = FTUN_ADDRESS_IPV4;
    return ftun_socks5_encode_request(FTUN_SOCKS5_COMMAND_UDP_ASSOCIATE, &any,
                                      buffer, capacity, length);
  }
}

ftun_status_t ftun_socks5_client_output_done(ftun_socks5_client_t *client)
{
  if (client == NULL || !ftun_socks5_client_wants_output(client)) {
    return FTUN_E_INVALID;
  }
  client->input_length = 0u;
  if (client->phase == FTUN_SOCKS5_CLIENT_METHOD_OUT) {
    client->phase = FTUN_SOCKS5_CLIENT_METHOD_IN;
  } else if (client->phase == FTUN_SOCKS5_CLIENT_AUTH_OUT) {
    client->phase = FTUN_SOCKS5_CLIENT_AUTH_IN;
  } else {
    client->phase = FTUN_SOCKS5_CLIENT_REPLY_IN;
  }
  return FTUN_OK;
}

size_t ftun_socks5_client_needed(const ftun_socks5_client_t *client)
{
  if (client == NULL) return 0u;
  switch (client->phase) {
    case FTUN_SOCKS5_CLIENT_METHOD_IN:
    case FTUN_SOCKS5_CLIENT_AUTH_IN:
      return 2u - client->input_length;
    case FTUN_SOCKS5_CLIENT_REPLY_IN: {
      size_t total;
      if (client->input_length < 4u) return 4u - client->input_length;
      switch (client->input[3]) {
        case 0x01u: total = 10u; break;
        case 0x04u: total = 22u; break;
        case 0x03u:
          if (client->input_length < 5u) return 1u;
          total = 7u + client->input[4];
          break;
        default: return 1u; /* 非法 ATYP：多读一字节让解码报告协议错误 */
      }
      return total > client->input_length ? total - client->input_length : 1u;
    }
    default:
      return 0u;
  }
}

ftun_status_t ftun_socks5_client_input(ftun_socks5_client_t *client,
  ftun_bytes_t in, size_t *consumed, ftun_socks5_client_result_t *result)
{
  size_t take;
  size_t used = 0u;
  ftun_status_t status;
  if (consumed != NULL) *consumed = 0u;
  if (result != NULL) memset(result, 0, sizeof(*result));
  if (client == NULL || consumed == NULL || result == NULL ||
      (in.length != 0u && in.data == NULL)) return FTUN_E_INVALID;
  if (client->phase != FTUN_SOCKS5_CLIENT_METHOD_IN &&
      client->phase != FTUN_SOCKS5_CLIENT_AUTH_IN &&
      client->phase != FTUN_SOCKS5_CLIENT_REPLY_IN) return FTUN_E_STATE_CORRUPT;
  /* 一次最多取走完成当前帧所需的字节，绝不多读到隧道数据。 */
  take = ftun_socks5_client_needed(client);
  if (take > in.length) take = in.length;
  if (client->input_length + take > sizeof(client->input)) {
    client->phase = FTUN_SOCKS5_CLIENT_FAILED;
    return FTUN_E_LIMIT;
  }
  memcpy(client->input + client->input_length, in.data, take);
  client->input_length += take;
  *consumed = take;
  switch (client->phase) {
    case FTUN_SOCKS5_CLIENT_METHOD_IN: {
      uint8_t method = 0u, expected;
      status = ftun_socks5_decode_method_selection(
        (ftun_bytes_t){client->input, client->input_length}, &method, &used);
      if (status == FTUN_E_AGAIN) return FTUN_E_AGAIN;
      if (status != FTUN_OK) break;
      (void)ftun_socks5_client_expected_method(client, &expected);
      if (method == FTUN_SOCKS5_METHOD_NONE_ACCEPTABLE) {
        status = FTUN_E_REJECTED;
        break;
      }
      if (method != expected) {
        status = FTUN_E_PROTOCOL;
        break;
      }
      client->input_length = 0u;
      client->phase = method == FTUN_SOCKS5_METHOD_USERNAME_PASSWORD
        ? FTUN_SOCKS5_CLIENT_AUTH_OUT : FTUN_SOCKS5_CLIENT_REQUEST_OUT;
      return FTUN_E_AGAIN;
    }
    case FTUN_SOCKS5_CLIENT_AUTH_IN: {
      uint8_t auth = 0u;
      status = ftun_socks5_decode_auth_result(
        (ftun_bytes_t){client->input, client->input_length}, &auth, &used);
      if (status == FTUN_E_AGAIN) return FTUN_E_AGAIN;
      if (status != FTUN_OK) break;
      if (auth != 0u) {
        status = FTUN_E_REJECTED;
        break;
      }
      client->input_length = 0u;
      client->phase = FTUN_SOCKS5_CLIENT_REQUEST_OUT;
      return FTUN_E_AGAIN;
    }
    default: {
      ftun_socks5_reply_t reply;
      status = ftun_socks5_decode_reply(
        (ftun_bytes_t){client->input, client->input_length}, &reply, &used);
      if (status == FTUN_E_AGAIN) return FTUN_E_AGAIN;
      if (status != FTUN_OK) break;
      result->reply = reply.reply;
      result->bound = reply.endpoint;
      status = ftun_socks5_client_reply_status(reply.reply);
      if (status == FTUN_OK) {
        client->phase = FTUN_SOCKS5_CLIENT_DONE;
        return FTUN_OK;
      }
      break;
    }
  }
  client->phase = FTUN_SOCKS5_CLIENT_FAILED;
  return status;
}

ftun_status_t ftun_socks5_client_run(ftun_socks5_client_t *client,
  const ftun_socks5_client_io_t *io, ftun_socks5_client_result_t *result)
{
  uint8_t frame[FTUN_SOCKS5_CLIENT_FRAME_BYTES];
  if (client == NULL || io == NULL || io->write_all == NULL ||
      io->read_exact == NULL || result == NULL) return FTUN_E_INVALID;
  for (;;) {
    ftun_status_t status;
    size_t length = 0u;
    if (ftun_socks5_client_wants_output(client)) {
      status = ftun_socks5_client_output(client, frame, sizeof(frame), &length);
      if (status == FTUN_OK) status = io->write_all(io->context, frame, length);
      if (status == FTUN_OK) status = ftun_socks5_client_output_done(client);
      if (status != FTUN_OK) return status;
    } else {
      size_t needed = ftun_socks5_client_needed(client);
      size_t consumed = 0u;
      if (needed == 0u || needed > sizeof(frame)) return FTUN_E_STATE_CORRUPT;
      status = io->read_exact(io->context, frame, needed);
      if (status != FTUN_OK) return status;
      status = ftun_socks5_client_input(client, (ftun_bytes_t){frame, needed},
                                        &consumed, result);
      if (status == FTUN_OK) return FTUN_OK;
      if (status != FTUN_E_AGAIN) return status;
    }
  }
}
