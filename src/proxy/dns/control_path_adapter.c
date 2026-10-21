#define _GNU_SOURCE 1

#include "proxy/dns/control_path_adapter.h"

#if defined(FTUN_HAVE_MODULE_DNS)

#include "dns/wire.h"
#include "protocol/socks5.h"
#include "transport/blocking.h"
#include "util/time.h"

#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define FTUN_PROXY_DNS_CONTROL_TIMEOUT_MS UINT64_C(5000)

static ftun_status_t ftun_proxy_dns_socks_reply(
  int descriptor, uint64_t deadline, ftun_socks5_reply_t *reply)
{
  uint8_t frame[262];
  size_t length = 4u;
  size_t consumed = 0u;
  if (!ftun_blocking_socket_recv_all(descriptor, frame, length, deadline)) {
    return FTUN_E_TIMEOUT;
  }
  if (frame[3] == 1u) length = 10u;
  else if (frame[3] == 4u) length = 22u;
  else if (frame[3] == 3u) {
    if (!ftun_blocking_socket_recv_all(
          descriptor, frame + 4u, 1u, deadline)) return FTUN_E_TIMEOUT;
    length = 7u + frame[4];
    if (length > sizeof(frame)) return FTUN_E_LIMIT;
    if (!ftun_blocking_socket_recv_all(
          descriptor, frame + 5u, length - 5u, deadline)) {
      return FTUN_E_TIMEOUT;
    }
    return ftun_socks5_decode_reply(
      (ftun_bytes_t){frame, length}, reply, &consumed);
  } else {
    return FTUN_E_PROTOCOL;
  }
  if (!ftun_blocking_socket_recv_all(
        descriptor, frame + 4u, length - 4u, deadline)) {
    return FTUN_E_TIMEOUT;
  }
  return ftun_socks5_decode_reply(
    (ftun_bytes_t){frame, length}, reply, &consumed);
}

static ftun_status_t ftun_proxy_dns_socks_open(
  const ftun_proxy_dns_blocking_query_t *query, uint64_t deadline,
  int *control, int *data, ftun_endpoint_t *relay)
{
  uint8_t frame[513];
  uint8_t response[2];
  ftun_socks5_reply_t reply;
  size_t written = 0u;
  ftun_status_t status;
  *control = -1;
  *data = -1;
  memset(relay, 0, sizeof(*relay));
  status = ftun_blocking_socket_connect_ipv4(
    SOCK_STREAM, query->proxy.address, query->proxy.port,
    query->direct.socket_mark, deadline, control);
  if (status != FTUN_OK) return status;
  frame[0] = FTUN_SOCKS5_VERSION;
  frame[1] = 1u;
  frame[2] = query->proxy_username.length == 0u
    ? FTUN_SOCKS5_METHOD_NO_AUTH : FTUN_SOCKS5_METHOD_USERNAME_PASSWORD;
  if (!ftun_blocking_socket_send_all(*control, frame, 3u, deadline) ||
      !ftun_blocking_socket_recv_all(
        *control, response, sizeof(response), deadline)) return FTUN_E_TIMEOUT;
  if (response[0] != FTUN_SOCKS5_VERSION || response[1] != frame[2]) {
    return FTUN_E_REJECTED;
  }
  if (response[1] == FTUN_SOCKS5_METHOD_USERNAME_PASSWORD) {
    status = ftun_socks5_encode_credentials(
      (ftun_bytes_t){(const uint8_t *)query->proxy_username.data,
                     query->proxy_username.length},
      (ftun_bytes_t){(const uint8_t *)query->proxy_password.data,
                     query->proxy_password.length},
      frame, sizeof(frame), &written);
    if (status != FTUN_OK ||
        !ftun_blocking_socket_send_all(*control, frame, written, deadline) ||
        !ftun_blocking_socket_recv_all(
          *control, response, sizeof(response), deadline)) {
      return status == FTUN_OK ? FTUN_E_TIMEOUT : status;
    }
    if (response[0] != 1u || response[1] != 0u) return FTUN_E_REJECTED;
  }
  status = ftun_socks5_encode_request(
    query->direct.tcp ? FTUN_SOCKS5_COMMAND_CONNECT
                      : FTUN_SOCKS5_COMMAND_UDP_ASSOCIATE,
    &query->direct.upstream, frame, sizeof(frame), &written);
  if (status != FTUN_OK ||
      !ftun_blocking_socket_send_all(*control, frame, written, deadline)) {
    return status == FTUN_OK ? FTUN_E_TIMEOUT : status;
  }
  status = ftun_proxy_dns_socks_reply(*control, deadline, &reply);
  if (status != FTUN_OK || reply.reply != FTUN_SOCKS5_REPLY_SUCCEEDED) {
    return status == FTUN_OK ? FTUN_E_REJECTED : status;
  }
  if (query->direct.tcp) {
    *data = *control;
    return FTUN_OK;
  }
  if (reply.endpoint.kind != FTUN_ADDRESS_IPV4 || reply.endpoint.port == 0u) {
    return FTUN_E_PROTOCOL;
  }
  *relay = reply.endpoint;
  if (relay->address[0] == 0u && relay->address[1] == 0u &&
      relay->address[2] == 0u && relay->address[3] == 0u) {
    memcpy(relay->address, query->proxy.address, 4u);
  }
  return ftun_blocking_socket_connect_ipv4(
    SOCK_DGRAM, relay->address, relay->port, query->direct.socket_mark,
    deadline, data);
}

ftun_status_t ftun_proxy_dns_query_blocking(
  const ftun_proxy_dns_blocking_query_t *query, ftun_bytes_t wire,
  uint8_t *response, size_t response_capacity, size_t *out_response_size)
{
  ftun_endpoint_t relay;
  uint64_t deadline;
  size_t username_length;
  size_t password_length;
  int control = -1;
  int descriptor = -1;
  ftun_status_t status;
  if (out_response_size != NULL) *out_response_size = 0u;
  if (query == NULL) return FTUN_E_INVALID;
  if (!query->use_proxy) {
    return ftun_dns_query_blocking(
      &query->direct, wire, response, response_capacity, out_response_size);
  }
  username_length = query->proxy_username.length;
  password_length = query->proxy_password.length;
  if (query->direct.upstream.kind != FTUN_ADDRESS_IPV4 ||
      query->direct.upstream.port == 0u ||
      query->proxy.kind != FTUN_ADDRESS_IPV4 || query->proxy.port == 0u ||
      wire.data == NULL || wire.length < FTUN_DNS_HEADER_BYTES ||
      wire.length > UINT16_MAX || response == NULL || response_capacity == 0u ||
      out_response_size == NULL ||
      (username_length == 0u) != (password_length == 0u) ||
      username_length > UINT8_MAX || password_length > UINT8_MAX ||
      (username_length != 0u && query->proxy_username.data == NULL) ||
      (password_length != 0u && query->proxy_password.data == NULL)) {
    return FTUN_E_INVALID;
  }
  if (ftun_monotonic_now(&deadline) != FTUN_OK ||
      deadline > UINT64_MAX - FTUN_PROXY_DNS_CONTROL_TIMEOUT_MS) {
    return FTUN_E_IO;
  }
  deadline += FTUN_PROXY_DNS_CONTROL_TIMEOUT_MS;
  status = ftun_proxy_dns_socks_open(
    query, deadline, &control, &descriptor, &relay);
  if (status != FTUN_OK) goto done;
  if (!query->direct.tcp) {
    uint8_t packet[FTUN_DNS_MAX_MESSAGE_BYTES + 263u];
    ftun_socks5_udp_datagram_t datagram;
    size_t packet_length = 0u;
    size_t consumed = 0u;
    ssize_t received;
    status = ftun_socks5_encode_udp_datagram(
      &query->direct.upstream, wire, packet, sizeof(packet), &packet_length);
    if (status != FTUN_OK ||
        !ftun_blocking_socket_send_all(
          descriptor, packet, packet_length, deadline) ||
        !ftun_blocking_socket_wait(descriptor, POLLIN, deadline)) {
      if (status == FTUN_OK) status = FTUN_E_TIMEOUT;
      goto done;
    }
    do {
      received = recv(descriptor, packet, sizeof(packet), 0);
    } while (received < 0 && errno == EINTR);
    if (received < 0) status = ftun_blocking_socket_status(errno);
    else if (received == 0) status = FTUN_E_EOF;
    else status = ftun_socks5_decode_udp_datagram(
      (ftun_bytes_t){packet, (size_t)received}, &datagram, &consumed);
    if (status == FTUN_OK && (consumed != (size_t)received ||
        datagram.endpoint.kind != FTUN_ADDRESS_IPV4 ||
        datagram.endpoint.port != query->direct.upstream.port ||
        memcmp(datagram.endpoint.address,
               query->direct.upstream.address, 4u) != 0)) {
      status = FTUN_E_REJECTED;
    }
    if (status == FTUN_OK && datagram.payload.length > response_capacity) {
      status = FTUN_E_LIMIT;
    }
    if (status == FTUN_OK) {
      memcpy(response, datagram.payload.data, datagram.payload.length);
      *out_response_size = datagram.payload.length;
    }
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
  if (descriptor >= 0 && descriptor != control) (void)close(descriptor);
  if (control >= 0) (void)close(control);
  return status;
}

#else

ftun_status_t ftun_proxy_dns_query_blocking(
  const ftun_proxy_dns_blocking_query_t *query, ftun_bytes_t wire,
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
