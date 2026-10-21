#define _GNU_SOURCE 1

#include "dns/control_transport.h"

#if defined(FTUN_HAVE_MODULE_DNS)

#include "dns/wire.h"
#include "transport/blocking.h"
#include "util/time.h"

#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#define FTUN_DNS_CONTROL_TIMEOUT_MS UINT64_C(5000)

ftun_status_t ftun_dns_query_blocking(
  const ftun_dns_blocking_query_t *query, ftun_bytes_t wire,
  uint8_t *response, size_t response_capacity, size_t *out_response_size)
{
  uint64_t deadline;
  int descriptor = -1;
  ftun_status_t status;
  if (out_response_size != NULL) *out_response_size = 0u;
  if (query == NULL || query->upstream.kind != FTUN_ADDRESS_IPV4 ||
      query->upstream.port == 0u || wire.data == NULL ||
      wire.length < FTUN_DNS_HEADER_BYTES || wire.length > UINT16_MAX ||
      response == NULL || response_capacity == 0u ||
      out_response_size == NULL) return FTUN_E_INVALID;
  if (ftun_monotonic_now(&deadline) != FTUN_OK ||
      deadline > UINT64_MAX - FTUN_DNS_CONTROL_TIMEOUT_MS) return FTUN_E_IO;
  deadline += FTUN_DNS_CONTROL_TIMEOUT_MS;
  status = ftun_blocking_socket_connect_ipv4(
    query->tcp ? SOCK_STREAM : SOCK_DGRAM, query->upstream.address,
    query->upstream.port, query->socket_mark, deadline, &descriptor);
  if (status != FTUN_OK) return status;
  if (!query->tcp) {
    ssize_t received;
    if (!ftun_blocking_socket_send_all(
          descriptor, wire.data, wire.length, deadline) ||
        !ftun_blocking_socket_wait(descriptor, POLLIN, deadline)) {
      status = FTUN_E_TIMEOUT;
      goto done;
    }
    do {
      received = recv(descriptor, response, response_capacity, MSG_TRUNC);
    } while (received < 0 && errno == EINTR);
    if (received < 0) status = ftun_blocking_socket_status(errno);
    else if (received == 0) status = FTUN_E_EOF;
    else if ((size_t)received > response_capacity) status = FTUN_E_LIMIT;
    else *out_response_size = (size_t)received;
  } else {
    uint8_t prefix[2];
    size_t response_length;
    prefix[0] = (uint8_t)(wire.length >> 8u);
    prefix[1] = (uint8_t)wire.length;
    if (!ftun_blocking_socket_send_all(
          descriptor, prefix, sizeof(prefix), deadline) ||
        !ftun_blocking_socket_send_all(
          descriptor, wire.data, wire.length, deadline) ||
        !ftun_blocking_socket_recv_all(
          descriptor, prefix, sizeof(prefix), deadline)) {
      status = FTUN_E_TIMEOUT;
      goto done;
    }
    response_length = ((size_t)prefix[0] << 8u) | prefix[1];
    if (response_length == 0u || response_length > response_capacity) {
      status = FTUN_E_LIMIT;
      goto done;
    }
    if (!ftun_blocking_socket_recv_all(
          descriptor, response, response_length, deadline)) {
      status = FTUN_E_TIMEOUT;
      goto done;
    }
    *out_response_size = response_length;
  }

done:
  (void)close(descriptor);
  return status;
}

#else

ftun_status_t ftun_dns_query_blocking(
  const ftun_dns_blocking_query_t *query, ftun_bytes_t wire,
  uint8_t *response, size_t response_capacity, size_t *out_response_size)
{
  (void)query;
  (void)wire;
  (void)response;
  (void)response_capacity;
  if (out_response_size != NULL) *out_response_size = 0u;
  return FTUN_E_UNSUPPORTED;
}

#endif
