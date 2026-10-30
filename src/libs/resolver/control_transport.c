#include "util/endpoint.h"
#include "libs/resolver/control_transport.h"

#if defined(FTUN_HAVE_MODULE_DNS)

#include "libs/resolver/dnswire.h"
#include <string.h>

#define FTUN_DNS_CONTROL_TIMEOUT_MS UINT64_C(5000)

ftun_status_t ftun_dns_query_stream(ftun_control_channel_t *channel,
  ftun_bytes_t wire, uint8_t *response, size_t response_capacity,
  size_t *out_response_size)
{
  uint8_t prefix[2];
  size_t response_length;
  ftun_status_t status;
  if (out_response_size != NULL) *out_response_size = 0u;
  if (channel == NULL || wire.data == NULL ||
      wire.length < FTUN_DNS_HEADER_BYTES || wire.length > UINT16_MAX ||
      response == NULL || response_capacity == 0u ||
      out_response_size == NULL) return FTUN_E_INVALID;
  prefix[0] = (uint8_t)(wire.length >> 8u);
  prefix[1] = (uint8_t)wire.length;
  status = ftun_control_channel_write_all(channel, prefix, sizeof(prefix));
  if (status == FTUN_OK) status = ftun_control_channel_write_all(channel, wire.data, wire.length);
  if (status == FTUN_OK) status = ftun_control_channel_read_exact(channel, prefix, sizeof(prefix));
  if (status != FTUN_OK) return status;
  response_length = ((size_t)prefix[0] << 8u) | prefix[1];
  if (response_length == 0u || response_length > response_capacity) return FTUN_E_LIMIT;
  status = ftun_control_channel_read_exact(channel, response, response_length);
  if (status == FTUN_OK) *out_response_size = response_length;
  return status;
}

ftun_status_t ftun_dns_query_blocking(
  const ftun_control_execution_t *execution,
  const ftun_dns_blocking_query_t *query, ftun_bytes_t wire,
  uint8_t *response, size_t response_capacity, size_t *out_response_size)
{
  ftun_control_channel_t *channel = NULL;
  ftun_control_execution_t limited;
  ftun_endpoint_t source;
  ftun_status_t status;
  if (out_response_size != NULL) *out_response_size = 0u;
  if (query == NULL || !ftun_endpoint_is_ip(&query->upstream) ||
      query->upstream.port == 0u || wire.data == NULL ||
      wire.length < FTUN_DNS_HEADER_BYTES || wire.length > UINT16_MAX ||
      response == NULL || response_capacity == 0u ||
      out_response_size == NULL) return FTUN_E_INVALID;
  status = ftun_control_execution_limit(execution, FTUN_DNS_CONTROL_TIMEOUT_MS, &limited);
  if (status == FTUN_OK) {
    limited.egress_id = query->egress_id;
    status = ftun_control_channel_create_execution(&limited, &channel);
  }
  if (status == FTUN_OK) {
    status = query->tcp
      ? ftun_control_channel_connect(channel, &query->upstream, query->socket_mark, limited.purpose)
      : ftun_control_channel_connect_datagram(channel, &query->upstream, query->socket_mark, limited.purpose);
  }
  if (status == FTUN_OK && query->tcp) {
    status = ftun_dns_query_stream(channel, wire, response, response_capacity, out_response_size);
  } else if (status == FTUN_OK) {
    status = ftun_control_channel_send(channel, &query->upstream, wire.data, wire.length);
    while (status == FTUN_OK) {
      status = ftun_control_channel_receive(channel, &source, response,
        response_capacity, out_response_size);
      if (status != FTUN_E_AGAIN) break;
      status = ftun_control_channel_wait(channel);
    }
    if (status == FTUN_OK && (!ftun_endpoint_equal(&source, &query->upstream))) status = FTUN_E_REJECTED;
    if (status == FTUN_OK && *out_response_size == 0u) status = FTUN_E_EOF;
  }
  if (status != FTUN_OK) *out_response_size = 0u;
  ftun_control_channel_drain(&channel);
  return status;
}

#else

ftun_status_t ftun_dns_query_stream(ftun_control_channel_t *channel,
  ftun_bytes_t wire, uint8_t *response, size_t response_capacity,
  size_t *out_response_size)
{
  (void)channel;
  (void)wire;
  (void)response;
  (void)response_capacity;
  if (out_response_size != NULL) *out_response_size = 0u;
  return FTUN_E_UNSUPPORTED;
}

ftun_status_t ftun_dns_query_blocking(
  const ftun_control_execution_t *execution,
  const ftun_dns_blocking_query_t *query, ftun_bytes_t wire,
  uint8_t *response, size_t response_capacity, size_t *out_response_size)
{
  (void)execution;
  (void)query;
  return ftun_dns_query_stream(NULL, wire, response, response_capacity, out_response_size);
}

#endif
