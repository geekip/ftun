#include "proxy/protocol/socks5_transport.h"

#if defined(FTUN_HAVE_MODULE_DNS)

#include "libs/resolver/dnswire.h"
#include "proxy/protocol/socks5_client.h"
#include <string.h>

#define FTUN_RESOLVER_SOCKS5_TIMEOUT_MS UINT64_C(5000)

static ftun_status_t ftun_resolver_socks5_write(void *context, const uint8_t *data,
                                                size_t length)
{
  return ftun_control_channel_write_all((ftun_control_channel_t *)context, data, length);
}

static ftun_status_t ftun_resolver_socks5_read(void *context, uint8_t *data,
                                               size_t length)
{
  return ftun_control_channel_read_exact((ftun_control_channel_t *)context, data, length);
}

static ftun_status_t ftun_resolver_socks5_open(
  const ftun_control_execution_t *execution,
  const ftun_resolver_transport_query_t *query,
  ftun_control_channel_t **control, ftun_control_channel_t **data,
  ftun_endpoint_t *relay)
{
  ftun_socks5_client_result_t result;
  ftun_status_t status;
  *control = NULL;
  *data = NULL;
  memset(relay, 0, sizeof(*relay));
  status = ftun_control_channel_create_execution(execution, control);
  if (status == FTUN_OK) status = ftun_control_channel_connect(*control,
    &query->proxy, query->direct.socket_mark, execution->purpose);
  if (status != FTUN_OK) return status;
  {
    ftun_socks5_client_t client;
    ftun_socks5_client_options_t options = {0};
    ftun_socks5_client_io_t io = {ftun_resolver_socks5_write, ftun_resolver_socks5_read, *control};
    options.username = (ftun_bytes_t){(const uint8_t *)query->proxy_username.data,
                                      query->proxy_username.length};
    options.password = (ftun_bytes_t){(const uint8_t *)query->proxy_password.data,
                                      query->proxy_password.length};
    options.command = query->direct.tcp ? FTUN_SOCKS5_COMMAND_CONNECT
                                        : FTUN_SOCKS5_COMMAND_UDP_ASSOCIATE;
    options.target = query->direct.upstream;
    status = ftun_socks5_client_init(&client, &options);
    if (status == FTUN_OK) status = ftun_socks5_client_run(&client, &io, &result);
    if (status != FTUN_OK) return status;
  }
  if (query->direct.tcp) {
    *data = *control;
    return FTUN_OK;
  }
  if (result.bound.kind != FTUN_ADDRESS_IPV4 || result.bound.port == 0u) return FTUN_E_PROTOCOL;
  *relay = result.bound;
  if (relay->address[0] == 0u && relay->address[1] == 0u &&
      relay->address[2] == 0u && relay->address[3] == 0u) {
    memcpy(relay->address, query->proxy.address, 4u);
  }
  status = ftun_control_channel_create_execution(execution, data);
  if (status == FTUN_OK) status = ftun_control_channel_connect_datagram(*data,
    relay, query->direct.socket_mark, execution->purpose);
  return status;
}

ftun_status_t ftun_resolver_socks5_query_blocking(
  const ftun_control_execution_t *execution,
  const ftun_resolver_transport_query_t *query, ftun_bytes_t wire,
  uint8_t *response, size_t response_capacity, size_t *out_response_size)
{
  ftun_endpoint_t relay, source;
  ftun_control_execution_t limited;
  size_t username_length, password_length;
  ftun_control_channel_t *control = NULL, *data = NULL;
  ftun_status_t status;
  if (out_response_size != NULL) *out_response_size = 0u;
  if (query == NULL) return FTUN_E_INVALID;
  if (!query->use_proxy) return ftun_dns_query_blocking(execution,
    &query->direct, wire, response, response_capacity, out_response_size);
  username_length = query->proxy_username.length;
  password_length = query->proxy_password.length;
  if (query->direct.upstream.kind != FTUN_ADDRESS_IPV4 || query->direct.upstream.port == 0u ||
      query->proxy.kind != FTUN_ADDRESS_IPV4 || query->proxy.port == 0u ||
      wire.data == NULL || wire.length < FTUN_DNS_HEADER_BYTES || wire.length > UINT16_MAX ||
      response == NULL || response_capacity == 0u || out_response_size == NULL ||
      (username_length == 0u) != (password_length == 0u) ||
      username_length > UINT8_MAX || password_length > UINT8_MAX ||
      (username_length != 0u && query->proxy_username.data == NULL) ||
      (password_length != 0u && query->proxy_password.data == NULL)) return FTUN_E_INVALID;
  status = ftun_control_execution_limit(execution, FTUN_RESOLVER_SOCKS5_TIMEOUT_MS, &limited);
  if (status == FTUN_OK) status = ftun_resolver_socks5_open(&limited, query, &control, &data, &relay);
  if (status != FTUN_OK) goto done;
  if (query->direct.tcp) {
    status = ftun_dns_query_stream(data, wire, response, response_capacity, out_response_size);
  } else {
    uint8_t packet[FTUN_DNS_MAX_MESSAGE_BYTES + 263u];
    ftun_socks5_udp_datagram_t datagram;
    size_t packet_length = 0u, consumed = 0u;
    status = ftun_socks5_encode_udp_datagram(&query->direct.upstream,
      wire, packet, sizeof(packet), &packet_length);
    if (status == FTUN_OK) status = ftun_control_channel_send(data, &relay, packet, packet_length);
    while (status == FTUN_OK) {
      status = ftun_control_channel_receive(data, &source, packet, sizeof(packet), &packet_length);
      if (status != FTUN_E_AGAIN) break;
      status = ftun_control_channel_wait(data);
    }
    if (status == FTUN_OK && (source.kind != FTUN_ADDRESS_IPV4 ||
        source.port != relay.port || memcmp(source.address, relay.address, 4u) != 0)) status = FTUN_E_REJECTED;
    if (status == FTUN_OK) status = packet_length == 0u ? FTUN_E_EOF :
      ftun_socks5_decode_udp_datagram((ftun_bytes_t){packet, packet_length}, &datagram, &consumed);
    if (status == FTUN_OK && (consumed != packet_length ||
        datagram.endpoint.kind != FTUN_ADDRESS_IPV4 ||
        datagram.endpoint.port != query->direct.upstream.port ||
        memcmp(datagram.endpoint.address, query->direct.upstream.address, 4u) != 0)) status = FTUN_E_REJECTED;
    if (status == FTUN_OK && datagram.payload.length > response_capacity) status = FTUN_E_LIMIT;
    if (status == FTUN_OK) {
      memcpy(response, datagram.payload.data, datagram.payload.length);
      *out_response_size = datagram.payload.length;
    }
  }
done:
  if (status != FTUN_OK) *out_response_size = 0u;
  if (data == control) data = NULL;
  ftun_control_channel_drain(&data);
  ftun_control_channel_drain(&control);
  return status;
}

#else

ftun_status_t ftun_resolver_socks5_query_blocking(
  const ftun_control_execution_t *execution,
  const ftun_resolver_transport_query_t *query, ftun_bytes_t wire,
  uint8_t *response, size_t response_capacity, size_t *out_response_size)
{
  (void)execution;
  (void)query;
  (void)wire;
  (void)response;
  (void)response_capacity;
  if (out_response_size != NULL) *out_response_size = 0u;
  return FTUN_E_UNSUPPORTED;
}

#endif
