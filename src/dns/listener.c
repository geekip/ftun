#include "listener.h"

#include "core/context.h"
#include "util/time.h"

#include <stdlib.h>
#include <string.h>

/* 需求 REQ-DNSWIRE-001；任务 TASK-DNS-003；目标 0.3.0；验收 TEST-DNS-003。 */

#define FTUN_DNS_LISTENER_MAX_TC_BYTES \
  (FTUN_DNS_HEADER_BYTES + FTUN_DNS_MAX_NAME_BYTES + 4u)

struct ftun_dns_listener {
  ftun_core_t *core;
  ftun_budget_t *budget;
  ftun_dns_dispatcher_t *dispatcher;
  ftun_dns_dispatch_fn dispatch;
  void *dispatch_user;
  ftun_reservation_t *reservation;
  ftun_dns_entry_t entry;
  size_t fixed_server;
  uint32_t inbound_id;
  uint64_t query_timeout_ms;
  size_t udp_payload_limit;
  size_t max_tcp_connections;
  size_t max_tcp_inflight;
  size_t max_tcp_frame_bytes;
  size_t tcp_connections;
  size_t inflight;
  ftun_dns_listener_reply_fn reply;
  void *reply_user;
  int accepting;
};

struct ftun_dns_connection {
  ftun_dns_listener_t *listener;
  ftun_reservation_t *reservation;
  uint8_t *buffer;
  size_t used;
  size_t expected;
  size_t inflight;
  uint64_t peer_id;
  int failed;
};

typedef struct {
  ftun_dns_listener_t *listener;
  ftun_dns_connection_t *connection;
  ftun_reservation_t *reservation;
  ftun_dns_query_completion_fn completion;
  uint64_t peer_id;
  uint16_t id;
  uint16_t flags;
  uint16_t type;
  uint16_t class_code;
  size_t udp_limit;
  uint8_t name[FTUN_DNS_MAX_NAME_BYTES];
  size_t name_length;
  uint8_t domain[254];
  size_t domain_length;
  uint8_t tc_response[FTUN_DNS_LISTENER_MAX_TC_BYTES];
  uint8_t *tcp_response;
} ftun_dns_listener_request_t;

static ftun_status_t ftun_dns_listener_domain(ftun_dns_name_t name,
                                              uint8_t output[254],
                                              size_t *out_length)
{
  size_t input = 0u;
  size_t cursor = 0u;
  if (out_length != NULL) *out_length = 0u;
  if (name.data == NULL || name.length == 0u || out_length == NULL) {
    return FTUN_E_INVALID;
  }
  while (input < name.length) {
    uint8_t length = name.data[input++];
    if (length == 0u) {
      if (input != name.length || cursor == 0u) return FTUN_E_PROTOCOL;
      output[cursor] = 0u;
      *out_length = cursor;
      return FTUN_OK;
    }
    if (length > 63u || (size_t)length > name.length - input ||
        cursor + (cursor == 0u ? 0u : 1u) + length > 253u) {
      return FTUN_E_PROTOCOL;
    }
    if (cursor != 0u) output[cursor++] = (uint8_t)'.';
    memcpy(output + cursor, name.data + input, length);
    cursor += length;
    input += length;
  }
  return FTUN_E_PROTOCOL;
}

static void ftun_dns_listener_tc(ftun_dns_listener_request_t *request,
                                 ftun_bytes_t response,
                                 ftun_bytes_t *out)
{
  uint16_t flags = (uint16_t)(0x8200u | (request->flags & 0x0110u));
  size_t length = FTUN_DNS_HEADER_BYTES + request->name_length + 4u;
  memset(request->tc_response, 0, length);
  request->tc_response[0] = (uint8_t)(request->id >> 8u);
  request->tc_response[1] = (uint8_t)request->id;
  if (response.data != NULL && response.length >= 4u) {
    flags = (uint16_t)(flags | (response.data[3] & 0x0fu));
  }
  request->tc_response[2] = (uint8_t)(flags >> 8u);
  request->tc_response[3] = (uint8_t)flags;
  request->tc_response[5] = 1u;
  memcpy(request->tc_response + FTUN_DNS_HEADER_BYTES,
         request->name, request->name_length);
  request->tc_response[FTUN_DNS_HEADER_BYTES + request->name_length] =
    (uint8_t)(request->type >> 8u);
  request->tc_response[FTUN_DNS_HEADER_BYTES + request->name_length + 1u] =
    (uint8_t)request->type;
  request->tc_response[FTUN_DNS_HEADER_BYTES + request->name_length + 2u] =
    (uint8_t)(request->class_code >> 8u);
  request->tc_response[FTUN_DNS_HEADER_BYTES + request->name_length + 3u] =
    (uint8_t)request->class_code;
  out->data = request->tc_response;
  out->length = length;
}

static void ftun_dns_listener_completed(ftun_operation_t *operation,
                                        ftun_error_t error,
                                        ftun_bytes_t response, void *user)
{
  ftun_dns_listener_request_t *request =
    (ftun_dns_listener_request_t *)user;
  ftun_dns_listener_t *listener = request->listener;
  ftun_dns_connection_t *connection = request->connection;
  ftun_reservation_t *reservation = request->reservation;
  ftun_dns_transport_t transport = connection == NULL ?
    FTUN_DNS_TRANSPORT_UDP : FTUN_DNS_TRANSPORT_TCP;
  ftun_bytes_t reply = response;
  (void)operation;
  if (error.status == FTUN_OK && connection == NULL &&
      response.length > request->udp_limit) {
    ftun_dns_listener_tc(request, response, &reply);
  } else if (error.status == FTUN_OK && connection != NULL) {
    if (response.length > listener->max_tcp_frame_bytes ||
        response.length > UINT16_MAX) {
      error.status = FTUN_E_LIMIT;
      reply.data = NULL;
      reply.length = 0u;
    } else {
      request->tcp_response[0] = (uint8_t)(response.length >> 8u);
      request->tcp_response[1] = (uint8_t)response.length;
      memcpy(request->tcp_response + 2u, response.data, response.length);
      reply.data = request->tcp_response;
      reply.length = response.length + 2u;
    }
  }
  if (listener->inflight != 0u) listener->inflight--;
  if (connection != NULL && connection->inflight != 0u) {
    connection->inflight--;
  }
  listener->reply(transport, request->peer_id, error, reply,
                  listener->reply_user);
  free(request);
  (void)ftun_reservation_release(&reservation);
}

static ftun_status_t ftun_dns_listener_accept(
  ftun_dns_listener_t *listener, ftun_dns_connection_t *connection,
  uint64_t peer_id, ftun_bytes_t wire, size_t udp_limit,
  ftun_operation_t **out)
{
  ftun_dns_message_t *message = NULL;
  ftun_dns_listener_request_t *request;
  ftun_reservation_t *reservation = NULL;
  uint64_t generation;
  ftun_dns_query_t query;
  ftun_metadata_t metadata;
  size_t bytes = sizeof(*request);
  uint64_t now;
  size_t record_index;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (!listener->accepting) return FTUN_E_CANCELLED;
  status = ftun_dns_message_parse(wire, &message);
  if (status != FTUN_OK) return status;
  if ((message->flags & 0x8000u) != 0u) {
    (void)ftun_dns_message_release(&message);
    return FTUN_E_PROTOCOL;
  }
  if (connection != NULL) {
    if (connection->inflight >= listener->max_tcp_inflight) {
      (void)ftun_dns_message_release(&message);
      return FTUN_E_LIMIT;
    }
    if (bytes > SIZE_MAX - listener->max_tcp_frame_bytes - 2u) {
      (void)ftun_dns_message_release(&message);
      return FTUN_E_LIMIT;
    }
    bytes += listener->max_tcp_frame_bytes + 2u;
  }
  status = ftun_budget_reserve(listener->budget, bytes, &reservation);
  if (status != FTUN_OK) {
    (void)ftun_dns_message_release(&message);
    return status;
  }
  request = (ftun_dns_listener_request_t *)calloc(1u, bytes);
  if (request == NULL) {
    (void)ftun_reservation_release(&reservation);
    (void)ftun_dns_message_release(&message);
    return FTUN_E_LIMIT;
  }
  request->listener = listener;
  request->connection = connection;
  request->reservation = reservation;
  request->peer_id = peer_id;
  request->id = message->id;
  request->flags = message->flags;
  request->type = message->question.type;
  request->class_code = message->question.class_code;
  request->udp_limit = udp_limit;
  request->name_length = message->question.name.length;
  memcpy(request->name, message->question.name.data, request->name_length);
  status = ftun_dns_listener_domain(message->question.name, request->domain,
                                    &request->domain_length);
  if (status != FTUN_OK) goto fail;
  if (connection != NULL) request->tcp_response = (uint8_t *)(request + 1);
  status = ftun_monotonic_now(&now);
  if (status != FTUN_OK || now > UINT64_MAX - listener->query_timeout_ms) {
    status = status == FTUN_OK ? FTUN_E_LIMIT : status;
    goto fail;
  }
  status = ftun_core_context_generation(listener->core, &generation);
  if (status != FTUN_OK) goto fail;
  memset(&metadata, 0, sizeof(metadata));
  metadata.generation = generation;
  metadata.known_fields = FTUN_META_DOMAIN | FTUN_META_SOURCE;
  metadata.inbound_id = listener->inbound_id;
  metadata.domain.data = (const char *)request->domain;
  metadata.domain.length = request->domain_length;
  metadata.domain_source = FTUN_DOMAIN_EXPLICIT;
  metadata.original_target.kind = FTUN_ADDRESS_DOMAIN;
  metadata.original_target.domain = metadata.domain;
  metadata.original_target.port = 53u;
  memset(&query, 0, sizeof(query));
  query.id = message->id;
  query.flags = message->flags;
  query.transport = connection == NULL ? FTUN_DNS_TRANSPORT_UDP :
                                         FTUN_DNS_TRANSPORT_TCP;
  query.question = message->question;
  query.wire.data = message->wire;
  query.wire.length = message->wire_length;
  query.deadline_ms = now + listener->query_timeout_ms;
  query.policy_fingerprint =
    ((uint64_t)listener->inbound_id << 32u) | (uint64_t)listener->entry;
  query.resolution_mode = 1u;
  for (record_index = 0u; record_index < message->record_count;
       record_index++) {
    const ftun_dns_record_t *record = &message->records[record_index];
    if (record->kind == FTUN_DNS_RECORD_OPT &&
        (record->edns_flags & FTUN_DNS_EDNS_FLAG_DO) != 0u) {
      query.dnssec_ok = true;
    }
  }
  query.completion = ftun_dns_listener_completed;
  query.completion_user = request;
  query.entry = listener->entry;
  query.fixed_server = listener->fixed_server;
  query.metadata = listener->entry == FTUN_DNS_ENTRY_POLICY ? &metadata : NULL;
  status = listener->dispatch(listener->dispatch_user, listener->core,
                              listener->dispatcher, &query, out);
  if (status != FTUN_OK) goto fail;
  listener->inflight++;
  if (connection != NULL) connection->inflight++;
  (void)ftun_dns_message_release(&message);
  return FTUN_OK;

fail:
  free(request);
  (void)ftun_reservation_release(&reservation);
  (void)ftun_dns_message_release(&message);
  return status;
}

ftun_status_t ftun_dns_listen(ftun_core_t *core,
                              const ftun_dns_listener_spec_t *spec,
                              ftun_dns_listener_t **out)
{
  ftun_dns_listener_t *listener;
  ftun_reservation_t *reservation = NULL;
  ftun_budget_t *core_budget = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core == NULL || spec == NULL || spec->budget == NULL ||
      spec->dispatcher == NULL || spec->dispatch == NULL || out == NULL ||
      ftun_core_context_budget(core, &core_budget) != FTUN_OK ||
      (spec->entry != FTUN_DNS_ENTRY_FIXED &&
       spec->entry != FTUN_DNS_ENTRY_POLICY) ||
      spec->query_timeout_ms == 0u || spec->udp_payload_limit < 512u ||
      spec->udp_payload_limit > FTUN_DNS_MAX_MESSAGE_BYTES ||
      spec->max_tcp_connections == 0u || spec->max_tcp_inflight == 0u ||
      spec->max_tcp_frame_bytes < FTUN_DNS_HEADER_BYTES ||
      spec->max_tcp_frame_bytes > FTUN_DNS_MAX_MESSAGE_BYTES ||
      spec->reply == NULL) return FTUN_E_INVALID;
  (void)core_budget;
  status = ftun_budget_reserve(spec->budget, sizeof(*listener), &reservation);
  if (status != FTUN_OK) return status;
  listener = (ftun_dns_listener_t *)calloc(1u, sizeof(*listener));
  if (listener == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  listener->core = core;
  listener->budget = spec->budget;
  listener->dispatcher = spec->dispatcher;
  listener->dispatch = spec->dispatch;
  listener->dispatch_user = spec->dispatch_user;
  listener->reservation = reservation;
  listener->entry = spec->entry;
  listener->fixed_server = spec->fixed_server;
  listener->inbound_id = spec->inbound_id;
  listener->query_timeout_ms = spec->query_timeout_ms;
  listener->udp_payload_limit = spec->udp_payload_limit;
  listener->max_tcp_connections = spec->max_tcp_connections;
  listener->max_tcp_inflight = spec->max_tcp_inflight;
  listener->max_tcp_frame_bytes = spec->max_tcp_frame_bytes;
  listener->reply = spec->reply;
  listener->reply_user = spec->reply_user;
  listener->accepting = 1;
  *out = listener;
  return FTUN_OK;
}

ftun_status_t ftun_dns_listener_receive_udp(ftun_dns_listener_t *listener,
                                            uint64_t peer_id,
                                            ftun_bytes_t datagram,
                                            ftun_operation_t **out)
{
  ftun_dns_message_t *message = NULL;
  size_t limit = 512u;
  size_t index;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (listener == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_dns_message_parse(datagram, &message);
  if (status != FTUN_OK) return status;
  for (index = 0u; index < message->record_count; index++) {
    const ftun_dns_record_t *record = &message->records[index];
    if (record->kind == FTUN_DNS_RECORD_OPT) {
      limit = record->udp_payload_size;
      break;
    }
  }
  if (limit > listener->udp_payload_limit) limit = listener->udp_payload_limit;
  (void)ftun_dns_message_release(&message);
  return ftun_dns_listener_accept(listener, NULL, peer_id, datagram, limit, out);
}

ftun_status_t ftun_dns_listener_tcp_open(ftun_dns_listener_t *listener,
                                         uint64_t peer_id,
                                         ftun_dns_connection_t **out)
{
  ftun_dns_connection_t *connection;
  ftun_reservation_t *reservation = NULL;
  size_t bytes;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (listener == NULL || out == NULL) return FTUN_E_INVALID;
  if (!listener->accepting) return FTUN_E_CANCELLED;
  if (listener->tcp_connections >= listener->max_tcp_connections) {
    return FTUN_E_LIMIT;
  }
  if (sizeof(*connection) > SIZE_MAX - listener->max_tcp_frame_bytes - 2u) {
    return FTUN_E_LIMIT;
  }
  bytes = sizeof(*connection) + listener->max_tcp_frame_bytes + 2u;
  status = ftun_budget_reserve(listener->budget, bytes, &reservation);
  if (status != FTUN_OK) return status;
  connection = (ftun_dns_connection_t *)calloc(1u, bytes);
  if (connection == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  connection->listener = listener;
  connection->reservation = reservation;
  connection->buffer = (uint8_t *)(connection + 1);
  connection->peer_id = peer_id;
  listener->tcp_connections++;
  *out = connection;
  return FTUN_OK;
}

ftun_status_t ftun_dns_connection_feed(ftun_dns_connection_t *connection,
                                       ftun_bytes_t bytes,
                                       size_t *out_consumed,
                                       size_t *out_frames)
{
  ftun_dns_listener_t *listener;
  size_t input = 0u;
  size_t frames = 0u;
  ftun_status_t status = FTUN_OK;
  if (out_consumed != NULL) *out_consumed = 0u;
  if (out_frames != NULL) *out_frames = 0u;
  if (connection == NULL || out_consumed == NULL || out_frames == NULL ||
      (bytes.length != 0u && bytes.data == NULL)) return FTUN_E_INVALID;
  listener = connection->listener;
  if (listener == NULL || connection->failed) return FTUN_E_PROTOCOL;
  if (!listener->accepting) return FTUN_E_CANCELLED;
  while (input < bytes.length) {
    size_t target;
    size_t copy;
    if (connection->inflight >= listener->max_tcp_inflight) {
      status = FTUN_E_LIMIT;
      break;
    }
    target = connection->expected == 0u ? 2u : connection->expected + 2u;
    copy = target - connection->used;
    if (copy > bytes.length - input) copy = bytes.length - input;
    memcpy(connection->buffer + connection->used, bytes.data + input, copy);
    connection->used += copy;
    input += copy;
    if (connection->expected == 0u && connection->used == 2u) {
      connection->expected = ((size_t)connection->buffer[0] << 8u) |
                             (size_t)connection->buffer[1];
      if (connection->expected < FTUN_DNS_HEADER_BYTES ||
          connection->expected > listener->max_tcp_frame_bytes) {
        connection->failed = 1;
        status = FTUN_E_PROTOCOL;
        break;
      }
    }
    if (connection->expected != 0u &&
        connection->used == connection->expected + 2u) {
      ftun_operation_t *operation = NULL;
      status = ftun_dns_listener_accept(listener, connection,
        connection->peer_id,
        (ftun_bytes_t){connection->buffer + 2u, connection->expected},
        0u, &operation);
      if (status != FTUN_OK) break;
      connection->used = 0u;
      connection->expected = 0u;
      frames++;
    }
  }
  *out_consumed = input;
  *out_frames = frames;
  return status;
}

ftun_status_t ftun_dns_connection_close(ftun_dns_connection_t **connection)
{
  ftun_dns_connection_t *owned;
  ftun_dns_listener_t *listener;
  ftun_reservation_t *reservation;
  if (connection == NULL) return FTUN_E_INVALID;
  owned = *connection;
  if (owned == NULL) return FTUN_OK;
  if (owned->inflight != 0u) return FTUN_E_AGAIN;
  listener = owned->listener;
  if (listener == NULL || listener->tcp_connections == 0u) {
    return FTUN_E_STATE_CORRUPT;
  }
  listener->tcp_connections--;
  reservation = owned->reservation;
  free(owned);
  *connection = NULL;
  return ftun_reservation_release(&reservation);
}

ftun_status_t ftun_dns_listener_stop(ftun_dns_listener_t *listener)
{
  if (listener == NULL) return FTUN_E_INVALID;
  listener->accepting = 0;
  return FTUN_OK;
}

ftun_status_t ftun_dns_listener_get_info(const ftun_dns_listener_t *listener,
                                         ftun_dns_listener_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (listener == NULL || out == NULL) return FTUN_E_INVALID;
  out->tcp_connections = listener->tcp_connections;
  out->inflight = listener->inflight;
  out->accepting = listener->accepting != 0;
  return FTUN_OK;
}

ftun_status_t ftun_dns_listener_destroy(ftun_dns_listener_t **listener)
{
  ftun_dns_listener_t *owned;
  ftun_reservation_t *reservation;
  if (listener == NULL) return FTUN_E_INVALID;
  owned = *listener;
  if (owned == NULL) return FTUN_OK;
  if (owned->inflight != 0u || owned->tcp_connections != 0u) {
    return FTUN_E_AGAIN;
  }
  reservation = owned->reservation;
  free(owned);
  *listener = NULL;
  return ftun_reservation_release(&reservation);
}
