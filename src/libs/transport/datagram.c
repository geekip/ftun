#include "util/endpoint.h"
#include "libs/transport/datagram.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct ftun_datagram_send {
  ftun_datagram_t *owner;
  ftun_datagram_t *channel;
  ftun_datagram_send_t *previous;
  ftun_datagram_send_t *next;
  ftun_datagram_send_t *free_next;
  ftun_packet_t packet;
  ftun_endpoint_t target;
  char domain[FTUN_DATAGRAM_DOMAIN_BYTES];
  ftun_error_t early_result;
  size_t slot;
  uint64_t generation;
  int starting;
  int cancelling;
  int backend_owned;
  int early_complete;
};

struct ftun_datagram {
  ftun_budget_t *budget;
  ftun_reservation_t reservation;
  ftun_datagram_backend_t backend;
  ftun_datagram_result_fn result;
  ftun_datagram_receive_fn receive;
  void *user;
  ftun_datagram_send_t *head;
  ftun_datagram_send_t *tail;
  ftun_datagram_send_t *storage;
  ftun_datagram_send_t *free_head;
  size_t max_pending_packets;
  size_t max_pending_bytes;
  size_t pending_packets;
  size_t pending_bytes;
  size_t completed_packets;
  size_t failed_packets;
  size_t reference_count;
  size_t callbacks;
  size_t backend_calls;
  uint64_t next_generation;
  int accepting;
  int stopping;
  int destroying;
};

static int ftun_datagram_backend_valid(const ftun_datagram_backend_t *backend)
{
  return backend != NULL && backend->send_start != NULL &&
         backend->send_cancel != NULL && backend->destroy != NULL;
}

static int ftun_datagram_options_valid(const ftun_datagram_options_t *options)
{
  return options != NULL && options->budget != NULL &&
         options->max_pending_packets != 0u;
}

static ftun_datagram_send_token_t ftun_datagram_send_token(
  const ftun_datagram_send_t *send)
{
  ftun_datagram_send_token_t token;
  memset(&token, 0, sizeof(token));
  if (send != NULL) {
    token.channel = send->owner;
    token.slot = send->slot;
    token.generation = send->generation;
  }
  return token;
}

static ftun_datagram_send_t *ftun_datagram_send_resolve(
  ftun_datagram_send_token_t token)
{
  ftun_datagram_send_t *send;
  if (token.channel == NULL || token.generation == 0u ||
      token.slot >= token.channel->max_pending_packets) return NULL;
  send = &token.channel->storage[token.slot];
  if (send->owner != token.channel || send->generation != token.generation) {
    return NULL;
  }
  return send;
}

static ftun_status_t ftun_datagram_endpoint_valid(const ftun_endpoint_t *endpoint)
{
  size_t index;
  if (endpoint == NULL || endpoint->port == 0u) return FTUN_E_INVALID;
  if (ftun_endpoint_is_ip(endpoint)) return FTUN_OK;
  if (endpoint->kind != FTUN_ADDRESS_DOMAIN || endpoint->domain.data == NULL ||
      endpoint->domain.length == 0u ||
      endpoint->domain.length >= FTUN_DATAGRAM_DOMAIN_BYTES) {
    return FTUN_E_INVALID;
  }
  for (index = 0u; index < endpoint->domain.length; index++) {
    if (endpoint->domain.data[index] == '\0') return FTUN_E_INVALID;
  }
  return FTUN_OK;
}

static void ftun_datagram_copy_endpoint(ftun_datagram_send_t *send,
                                        const ftun_endpoint_t *target)
{
  send->target = *target;
  if (target->kind == FTUN_ADDRESS_DOMAIN) {
    memcpy(send->domain, target->domain.data, target->domain.length);
    send->domain[target->domain.length] = '\0';
    send->target.domain.data = send->domain;
  } else {
    send->target.domain.data = NULL;
    send->target.domain.length = 0u;
  }
}

static void ftun_datagram_link(ftun_datagram_t *channel,
                               ftun_datagram_send_t *send)
{
  send->previous = channel->tail;
  if (channel->tail != NULL) channel->tail->next = send;
  else channel->head = send;
  channel->tail = send;
  channel->pending_packets++;
  channel->pending_bytes += send->packet.payload.length;
}

static void ftun_datagram_unlink(ftun_datagram_send_t *send)
{
  ftun_datagram_t *channel = send->channel;
  if (send->previous != NULL) send->previous->next = send->next;
  else channel->head = send->next;
  if (send->next != NULL) send->next->previous = send->previous;
  else channel->tail = send->previous;
  send->previous = NULL;
  send->next = NULL;
  channel->pending_packets--;
  channel->pending_bytes -= send->packet.payload.length;
}

static void ftun_datagram_release_send(ftun_datagram_send_t *send)
{
  ftun_datagram_t *owner = send->owner;
  ftun_packet_release(&send->packet);
  memset(send, 0, sizeof(*send));
  send->owner = owner;
  send->free_next = owner->free_head;
  owner->free_head = send;
}

static void ftun_datagram_finish(ftun_datagram_send_t *send,
                                 ftun_error_t error, int notify)
{
  ftun_datagram_t *channel = send->channel;
  ftun_datagram_unlink(send);
  if (error.status == FTUN_OK) {
    if (channel->completed_packets != SIZE_MAX) channel->completed_packets++;
  } else if (channel->failed_packets != SIZE_MAX) {
    channel->failed_packets++;
  }
  if (notify && channel->result != NULL) {
    channel->callbacks++;
    channel->result(channel, error, &send->target, &send->packet, channel->user);
    channel->callbacks--;
  }
  send->channel = NULL;
  ftun_datagram_release_send(send);
}

static ftun_error_t ftun_datagram_cancelled(void)
{
  ftun_error_t error;
  memset(&error, 0, sizeof(error));
  error.status = FTUN_E_CANCELLED;
  return error;
}

/* 整包所有权。 */
ftun_status_t ftun_packet_init(ftun_packet_t *packet,
                               const ftun_buffer_slice_t *payload,
                               uint32_t source_id)
{
  ftun_status_t status;
  if (packet == NULL || payload == NULL) return FTUN_E_INVALID;
  memset(packet, 0, sizeof(*packet));
  status = ftun_buffer_slice_clone(payload, &packet->payload);
  if (status != FTUN_OK) return status;
  packet->source_id = source_id;
  return FTUN_OK;
}

ftun_status_t ftun_packet_clone(const ftun_packet_t *source,
                                ftun_packet_t *out)
{
  if (out != NULL && source != out) memset(out, 0, sizeof(*out));
  if (source == NULL || out == NULL || source == out) return FTUN_E_INVALID;
  return ftun_packet_init(out, &source->payload, source->source_id);
}

ftun_status_t ftun_packet_view(const ftun_packet_t *packet, ftun_bytes_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (packet == NULL || out == NULL) return FTUN_E_INVALID;
  return ftun_buffer_slice_data(&packet->payload, out);
}

void ftun_packet_release(ftun_packet_t *packet)
{
  assert(packet != NULL);
  ftun_buffer_slice_release(&packet->payload);
  packet->source_id = 0u;
}

ftun_status_t ftun_datagram_create(const ftun_datagram_options_t *options,
                                   const ftun_datagram_backend_t *backend,
                                   ftun_datagram_t **out)
{
  ftun_datagram_t *channel;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_status_t status;
  size_t index;
  size_t charge;
  if (out != NULL) *out = NULL;
  if (out == NULL || !ftun_datagram_options_valid(options) ||
      !ftun_datagram_backend_valid(backend)) return FTUN_E_INVALID;
  if (options->max_pending_packets >
      (SIZE_MAX - sizeof(*channel)) / sizeof(ftun_datagram_send_t)) {
    return FTUN_E_LIMIT;
  }
  charge = sizeof(*channel) + options->max_pending_packets *
    sizeof(ftun_datagram_send_t);
  /* 每个槽可独立持有一个已接纳报文；backend 保存的 token 是同一请求的
   * 引用，不再重复计槽。预留覆盖取消失败、回调及额外引用的整个拥有期。 */
  status = ftun_budget_reserve_resources(options->budget,
    (ftun_budget_resources_t){charge, 0u, options->max_pending_packets},
    &reservation);
  if (status != FTUN_OK) return status;
  channel = (ftun_datagram_t *)calloc(1u, sizeof(*channel));
  if (channel != NULL) {
    channel->storage = (ftun_datagram_send_t *)calloc(
      options->max_pending_packets, sizeof(*channel->storage));
  }
  if (channel == NULL || channel->storage == NULL) {
    if (channel != NULL) free(channel->storage);
    free(channel);
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  channel->budget = options->budget;
  channel->reservation = reservation;
  channel->backend = *backend;
  channel->result = options->result;
  channel->receive = options->receive;
  channel->user = options->user;
  channel->max_pending_packets = options->max_pending_packets;
  channel->max_pending_bytes = options->max_pending_bytes;
  channel->accepting = 1;
  channel->reference_count = 1u;
  for (index = 0u; index < options->max_pending_packets; index++) {
    channel->storage[index].owner = channel;
    channel->storage[index].free_next = channel->free_head;
    channel->free_head = &channel->storage[index];
  }
  *out = channel;
  return FTUN_OK;
}

ftun_status_t ftun_datagram_send(ftun_datagram_t *channel,
                                 const ftun_endpoint_t *target,
                                 ftun_packet_t *packet)
{
  ftun_datagram_send_t *send;
  ftun_bytes_t payload;
  ftun_status_t status;
  if (channel == NULL || packet == NULL) return FTUN_E_INVALID;
  status = ftun_datagram_endpoint_valid(target);
  if (status != FTUN_OK) return status;
  status = ftun_packet_view(packet, &payload);
  if (status != FTUN_OK) return status;
  if (!channel->accepting) return FTUN_E_CANCELLED;
  if (channel->pending_packets >= channel->max_pending_packets ||
      payload.length > channel->max_pending_bytes - channel->pending_bytes) {
    return FTUN_E_LIMIT;
  }
  send = channel->free_head;
  if (send == NULL) return FTUN_E_STATE_CORRUPT;
  channel->free_head = send->free_next;
  memset(send, 0, sizeof(*send));
  send->owner = channel;
  send->channel = channel;
  channel->next_generation++;
  if (channel->next_generation == 0u) channel->next_generation++;
  send->slot = (size_t)(send - channel->storage);
  send->generation = channel->next_generation;
  status = ftun_packet_clone(packet, &send->packet);
  if (status != FTUN_OK) {
    ftun_datagram_release_send(send);
    return status;
  }
  ftun_datagram_copy_endpoint(send, target);
  ftun_datagram_link(channel, send);
  send->starting = 1;
  send->backend_owned = 1;
  channel->backend_calls++;
  status = channel->backend.send_start(channel->backend.context,
                                       ftun_datagram_send_token(send),
                                       &send->target, &send->packet);
  channel->backend_calls--;
  send->starting = 0;
  if (status != FTUN_OK) {
    if (send->early_complete) status = FTUN_E_STATE_CORRUPT;
    send->backend_owned = 0;
    ftun_datagram_unlink(send);
    ftun_datagram_release_send(send);
    return status;
  }
  if (send->early_complete) {
    ftun_error_t result = send->early_result;
    ftun_datagram_finish(send, result, 1);
  }
  return FTUN_OK;
}

ftun_status_t ftun_datagram_send_view(ftun_datagram_send_token_t token,
                                      const ftun_endpoint_t **target,
                                      const ftun_packet_t **packet)
{
  ftun_datagram_send_t *send;
  if (target != NULL) *target = NULL;
  if (packet != NULL) *packet = NULL;
  if (token.channel == NULL || token.generation == 0u ||
      target == NULL || packet == NULL) return FTUN_E_INVALID;
  send = ftun_datagram_send_resolve(token);
  if (send == NULL || send->channel == NULL || !send->backend_owned) {
    return FTUN_E_STALE;
  }
  if (send->cancelling) return FTUN_E_AGAIN;
  *target = &send->target;
  *packet = &send->packet;
  return FTUN_OK;
}

ftun_status_t ftun_datagram_send_complete(ftun_datagram_send_token_t token,
                                          ftun_error_t error)
{
  ftun_datagram_send_t *send;
  if (token.channel == NULL || token.generation == 0u) return FTUN_E_INVALID;
  if (error.status == FTUN_E_AGAIN) return FTUN_E_INVALID;
  send = ftun_datagram_send_resolve(token);
  if (send == NULL || send->channel == NULL || !send->backend_owned) {
    return FTUN_E_STALE;
  }
  if (send->cancelling) return FTUN_E_AGAIN;
  if (send->starting) {
    if (error.status != FTUN_OK || send->early_complete) return FTUN_E_INVALID;
    send->backend_owned = 0;
    send->early_result = error;
    send->early_complete = 1;
    return FTUN_OK;
  }
  send->backend_owned = 0;
  ftun_datagram_finish(send, error, 1);
  return FTUN_OK;
}

ftun_status_t ftun_datagram_deliver(ftun_datagram_t *channel,
                                    const ftun_endpoint_t *source,
                                    const ftun_packet_t *packet)
{
  ftun_bytes_t payload;
  ftun_status_t status;
  if (channel == NULL || packet == NULL) return FTUN_E_INVALID;
  status = ftun_datagram_endpoint_valid(source);
  if (status != FTUN_OK) return status;
  status = ftun_packet_view(packet, &payload);
  if (status != FTUN_OK) return status;
  (void)payload;
  if (!channel->accepting) return FTUN_E_CANCELLED;
  if (channel->receive == NULL) return FTUN_E_UNSUPPORTED;
  channel->callbacks++;
  status = channel->receive(channel, source, packet, channel->user);
  channel->callbacks--;
  return status;
}

ftun_status_t ftun_datagram_budget(ftun_datagram_t *channel,
                                   ftun_budget_t **out)
{
  if (out != NULL) *out = NULL;
  if (channel == NULL || out == NULL) return FTUN_E_INVALID;
  *out = channel->budget;
  return FTUN_OK;
}

ftun_status_t ftun_datagram_retain(ftun_datagram_t *channel)
{
  if (channel == NULL) return FTUN_E_INVALID;
  if (channel->destroying) return FTUN_E_AGAIN;
  if (channel->reference_count == 0u) return FTUN_E_STATE_CORRUPT;
  if (channel->reference_count == SIZE_MAX) return FTUN_E_LIMIT;
  channel->reference_count++;
  return FTUN_OK;
}

void ftun_datagram_release(ftun_datagram_t **channel)
{
  ftun_datagram_t *owned;
  assert(channel != NULL);
  owned = *channel;
  if (owned == NULL) return;
  assert(owned->reference_count > 1u);
  owned->reference_count--;
  *channel = NULL;
}

ftun_status_t ftun_datagram_stop(ftun_datagram_t *channel)
{
  ftun_status_t status;
  if (channel == NULL) return FTUN_E_INVALID;
  channel->accepting = 0;
  if (channel->stopping || channel->callbacks != 0u ||
      channel->backend_calls != 0u) return FTUN_E_AGAIN;
  channel->stopping = 1;
  while (channel->head != NULL) {
    ftun_datagram_send_t *send = channel->head;
    send->cancelling = 1;
    channel->backend_calls++;
    status = channel->backend.send_cancel(channel->backend.context,
                                          ftun_datagram_send_token(send));
    channel->backend_calls--;
    send->cancelling = 0;
    if (status != FTUN_OK) {
      channel->stopping = 0;
      return status;
    }
    send->backend_owned = 0;
    ftun_datagram_finish(send, ftun_datagram_cancelled(), 1);
  }
  channel->stopping = 0;
  return FTUN_OK;
}

ftun_status_t ftun_datagram_get_usage(const ftun_datagram_t *channel,
                                      ftun_datagram_usage_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (channel == NULL || out == NULL) return FTUN_E_INVALID;
  out->max_pending_packets = channel->max_pending_packets;
  out->max_pending_bytes = channel->max_pending_bytes;
  out->pending_packets = channel->pending_packets;
  out->pending_bytes = channel->pending_bytes;
  out->completed_packets = channel->completed_packets;
  out->failed_packets = channel->failed_packets;
  out->reference_count = channel->reference_count;
  out->accepting = channel->accepting != 0;
  out->in_callback = channel->callbacks != 0u;
  out->in_backend = channel->backend_calls != 0u;
  return FTUN_OK;
}

ftun_status_t ftun_datagram_destroy(ftun_datagram_t **channel)
{
  ftun_datagram_t *owned;
  ftun_reservation_t reservation;
  if (channel == NULL) return FTUN_E_INVALID;
  owned = *channel;
  if (owned == NULL) return FTUN_OK;
  if (owned->accepting || owned->stopping || owned->destroying ||
      owned->reference_count != 1u || owned->callbacks != 0u ||
      owned->backend_calls != 0u ||
      owned->pending_packets != 0u || owned->pending_bytes != 0u ||
      owned->head != NULL || owned->tail != NULL) return FTUN_E_AGAIN;
  reservation = owned->reservation;
  ftun_reservation_release(&reservation);
  owned->reservation = (ftun_reservation_t){0};
  owned->destroying = 1;
  owned->backend_calls++;
  owned->backend.destroy(owned->backend.context);
  free(owned->storage);
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *channel = NULL;
  return FTUN_OK;
}
