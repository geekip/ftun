#include "tun.h"

#include <stdlib.h>
#include <string.h>

typedef struct ftun_tun_tcp_bridge ftun_tun_tcp_bridge_t;
typedef struct ftun_tun_udp_bridge ftun_tun_udp_bridge_t;

struct ftun_tun_ingress_context {
  ftun_core_t *core;
  ftun_packet_port_t *port;
  ftun_budget_t *budget;
  ftun_operation_queue_t *operations;
  ftun_reservation_t *reservation;
  ftun_lwip_t *stack;
  ftun_tun_tcp_bridge_t *tcp_streams;
  ftun_tun_udp_bridge_t *udp_channels;
  uint64_t generation;
  uint32_t inbound_id;
  uint32_t mtu;
  size_t max_pending_stream_writes;
  size_t max_pending_stream_bytes;
  size_t max_pending_datagrams;
  size_t max_pending_datagram_bytes;
  size_t tcp_stream_count;
  size_t udp_channel_count;
  ftun_completion_fn stream_write_completion;
  ftun_tun_stream_accept_fn stream_accept;
  ftun_tun_stream_event_fn stream_event;
  ftun_tun_datagram_receive_fn datagram_receive;
  ftun_tun_output_fn output;
  void *user;
  bool tcp;
  bool udp;
  bool accepting;
  bool corrupt;
};

struct ftun_tun_tcp_bridge {
  ftun_tun_ingress_context_t *context;
  ftun_tun_tcp_bridge_t *next;
  ftun_reservation_t *reservation;
  ftun_lwip_tcp_t *flow;
  ftun_stream_t *stream;
  bool linked;
};

struct ftun_tun_udp_bridge {
  ftun_tun_ingress_context_t *context;
  ftun_tun_udp_bridge_t *next;
  ftun_reservation_t *reservation;
  ftun_lwip_udp_t *flow;
  ftun_datagram_t *channel;
  ftun_metadata_t metadata;
  bool linked;
};

static ftun_tun_ingress_context_t *ftun_tun_active;

static int ftun_tun_endpoint_equal(const ftun_endpoint_t *left,
                                   const ftun_endpoint_t *right)
{
  return left != NULL && right != NULL &&
         left->kind == FTUN_ADDRESS_IPV4 &&
         right->kind == FTUN_ADDRESS_IPV4 && left->port == right->port &&
         memcmp(left->address, right->address, 4u) == 0;
}

static void ftun_tun_metadata(ftun_tun_ingress_context_t *context,
                              uint8_t network,
                              const ftun_endpoint_t *source,
                              const ftun_endpoint_t *target,
                              ftun_metadata_t *out)
{
  memset(out, 0, sizeof(*out));
  out->generation = context->generation;
  out->known_fields = FTUN_META_SOURCE | FTUN_META_PORT | FTUN_META_NETWORK;
  out->inbound_id = context->inbound_id;
  out->network = network;
  out->source = *source;
  out->original_target = *target;
}

static void ftun_tun_tcp_unlink(ftun_tun_tcp_bridge_t *bridge)
{
  ftun_tun_tcp_bridge_t **cursor;
  ftun_tun_ingress_context_t *context = bridge->context;
  if (!bridge->linked) return;
  for (cursor = &context->tcp_streams; *cursor != NULL;
       cursor = &(*cursor)->next) {
    if (*cursor == bridge) {
      *cursor = bridge->next;
      bridge->next = NULL;
      bridge->linked = false;
      if (context->tcp_stream_count == 0u) context->corrupt = true;
      else context->tcp_stream_count--;
      return;
    }
  }
  context->corrupt = true;
}

static ftun_status_t ftun_tun_tcp_read(void *user, void *buffer,
                                       size_t capacity, size_t *out_length)
{
  ftun_tun_tcp_bridge_t *bridge = (ftun_tun_tcp_bridge_t *)user;
  ftun_lwip_segment_t segment;
  size_t count = 0u;
  size_t available = 0u;
  size_t copied;
  bool peer_finished = false;
  ftun_status_t status;
  if (out_length != NULL) *out_length = 0u;
  if (bridge == NULL || bridge->flow == NULL || buffer == NULL ||
      capacity == 0u || out_length == NULL) return FTUN_E_INVALID;
  status = ftun_lwip_tcp_peek(bridge->flow, &segment, 1u, &count,
                              &available, &peer_finished);
  if (status != FTUN_OK) return status;
  if (available == 0u) return peer_finished ? FTUN_E_EOF : FTUN_E_AGAIN;
  if (count != 1u || segment.length == 0u || segment.data == NULL) {
    return FTUN_E_STATE_CORRUPT;
  }
  copied = segment.length < capacity ? segment.length : capacity;
  memcpy(buffer, segment.data, copied);
  status = ftun_lwip_tcp_consume(bridge->flow, copied);
  if (status != FTUN_OK) return status;
  *out_length = copied;
  return FTUN_OK;
}

static ftun_status_t ftun_tun_tcp_write_start(
  void *user, ftun_stream_write_t *write, const ftun_buffer_slice_t *slice,
  size_t *accepted)
{
  ftun_tun_tcp_bridge_t *bridge = (ftun_tun_tcp_bridge_t *)user;
  if (bridge == NULL || bridge->flow == NULL) return FTUN_E_INVALID;
  return ftun_lwip_tcp_write_ref_with_token(bridge->flow, slice, write,
                                             accepted);
}

static ftun_status_t ftun_tun_tcp_write_cancel(void *user,
                                                ftun_stream_write_t *write)
{
  ftun_tun_tcp_bridge_t *bridge = (ftun_tun_tcp_bridge_t *)user;
  (void)write;
  if (bridge == NULL || bridge->flow == NULL) return FTUN_E_INVALID;
  /* tcp_write 后不能撤回已排队字节；ACK/终止仍会恰好一次完成 operation。 */
  return FTUN_E_AGAIN;
}

static ftun_status_t ftun_tun_tcp_shutdown(void *user)
{
  ftun_tun_tcp_bridge_t *bridge = (ftun_tun_tcp_bridge_t *)user;
  if (bridge == NULL || bridge->flow == NULL) return FTUN_E_INVALID;
  return ftun_lwip_tcp_shutdown_write(bridge->flow);
}

static void ftun_tun_tcp_destroy(void *user)
{
  ftun_tun_tcp_bridge_t *bridge = (ftun_tun_tcp_bridge_t *)user;
  ftun_reservation_t *reservation;
  ftun_tun_ingress_context_t *context;
  if (bridge == NULL) return;
  context = bridge->context;
  if (bridge->flow != NULL && ftun_lwip_tcp_close(&bridge->flow) != FTUN_OK) {
    context->corrupt = true;
  }
  ftun_tun_tcp_unlink(bridge);
  reservation = bridge->reservation;
  bridge->reservation = NULL;
  bridge->stream = NULL;
  bridge->context = NULL;
  free(bridge);
  if (ftun_reservation_release(&reservation) != FTUN_OK) {
    context->corrupt = true;
  }
}

static ftun_status_t ftun_tun_tcp_accept(
  void *user, ftun_lwip_tcp_t *flow, const ftun_endpoint_t *source,
  const ftun_endpoint_t *target)
{
  ftun_tun_ingress_context_t *context =
    (ftun_tun_ingress_context_t *)user;
  ftun_tun_tcp_bridge_t *bridge;
  ftun_reservation_t *reservation = NULL;
  ftun_stream_options_t options;
  ftun_stream_backend_t backend;
  ftun_metadata_t metadata;
  ftun_status_t status;
  if (context == NULL || flow == NULL || source == NULL || target == NULL ||
      !context->accepting || !context->tcp) return FTUN_E_CANCELLED;
  status = ftun_budget_reserve(context->budget, sizeof(*bridge),
                               &reservation);
  if (status != FTUN_OK) return status;
  bridge = (ftun_tun_tcp_bridge_t *)calloc(1u, sizeof(*bridge));
  if (bridge == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  bridge->context = context;
  bridge->reservation = reservation;
  bridge->flow = flow;
  memset(&options, 0, sizeof(options));
  options.budget = context->budget;
  options.operations = context->operations;
  options.max_pending_writes = context->max_pending_stream_writes;
  options.max_pending_bytes = context->max_pending_stream_bytes;
  options.completion = context->stream_write_completion;
  options.completion_user = context->user;
  memset(&backend, 0, sizeof(backend));
  backend.read = ftun_tun_tcp_read;
  backend.write_start = ftun_tun_tcp_write_start;
  backend.write_cancel = ftun_tun_tcp_write_cancel;
  backend.shutdown_write = ftun_tun_tcp_shutdown;
  backend.destroy = ftun_tun_tcp_destroy;
  backend.context = bridge;
  status = ftun_stream_create(&options, &backend, &bridge->stream);
  if (status != FTUN_OK) {
    free(bridge);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  bridge->next = context->tcp_streams;
  bridge->linked = true;
  context->tcp_streams = bridge;
  context->tcp_stream_count++;
  ftun_tun_metadata(context, 1u, source, target, &metadata);
  status = context->stream_accept(context->user, &metadata, bridge->stream);
  if (status != FTUN_OK) {
    ftun_stream_t *rejected = bridge->stream;
    bridge->flow = NULL; /* lwIP accept 返回后负责销毁被拒 flow。 */
    bridge->stream = NULL;
    (void)ftun_stream_stop(rejected);
    if (ftun_stream_destroy(&rejected) != FTUN_OK) {
      context->corrupt = true;
      return FTUN_E_STATE_CORRUPT;
    }
  }
  return status;
}

static void ftun_tun_tcp_event(void *user, ftun_lwip_tcp_t *flow,
                               ftun_lwip_tcp_event_t event,
                               ftun_status_t status)
{
  ftun_tun_ingress_context_t *context =
    (ftun_tun_ingress_context_t *)user;
  ftun_tun_tcp_bridge_t *bridge;
  ftun_tun_stream_event_t mapped;
  if (context == NULL) return;
  for (bridge = context->tcp_streams; bridge != NULL; bridge = bridge->next) {
    if (bridge->flow == flow) break;
  }
  if (bridge == NULL) {
    context->corrupt = true;
    return;
  }
  switch (event) {
    case FTUN_LWIP_TCP_READABLE: mapped = FTUN_TUN_STREAM_READABLE; break;
    case FTUN_LWIP_TCP_PEER_FIN: mapped = FTUN_TUN_STREAM_PEER_FIN; break;
    case FTUN_LWIP_TCP_WRITABLE: mapped = FTUN_TUN_STREAM_WRITABLE; break;
    case FTUN_LWIP_TCP_CLOSED:
      mapped = FTUN_TUN_STREAM_CLOSED;
      (void)ftun_stream_stop(bridge->stream);
      break;
    default:
      context->corrupt = true;
      return;
  }
  if (context->stream_event != NULL) {
    context->stream_event(context->user, bridge->stream, mapped, status);
  }
}

static void ftun_tun_tcp_write_done(void *user, ftun_lwip_tcp_t *flow,
                                    void *token, ftun_status_t status)
{
  ftun_tun_ingress_context_t *context =
    (ftun_tun_ingress_context_t *)user;
  ftun_error_t error;
  (void)flow;
  memset(&error, 0, sizeof(error));
  error.status = status;
  if (token == NULL || ftun_stream_write_complete(
        (ftun_stream_write_t *)token, error) != FTUN_OK) {
    if (context != NULL) context->corrupt = true;
  }
}

static void ftun_tun_udp_unlink(ftun_tun_udp_bridge_t *bridge)
{
  ftun_tun_udp_bridge_t **cursor;
  ftun_tun_ingress_context_t *context = bridge->context;
  if (!bridge->linked) return;
  for (cursor = &context->udp_channels; *cursor != NULL;
       cursor = &(*cursor)->next) {
    if (*cursor == bridge) {
      *cursor = bridge->next;
      bridge->next = NULL;
      bridge->linked = false;
      if (context->udp_channel_count == 0u) context->corrupt = true;
      else context->udp_channel_count--;
      return;
    }
  }
  context->corrupt = true;
}

static ftun_status_t ftun_tun_udp_send_start(
  void *user, ftun_datagram_send_t *send, const ftun_endpoint_t *target,
  const ftun_packet_t *packet)
{
  ftun_tun_udp_bridge_t *bridge = (ftun_tun_udp_bridge_t *)user;
  ftun_error_t result;
  ftun_status_t status;
  if (bridge == NULL || bridge->flow == NULL ||
      !ftun_tun_endpoint_equal(target, &bridge->metadata.source)) {
    return FTUN_E_REJECTED;
  }
  status = ftun_lwip_udp_send(bridge->flow, packet);
  if (status != FTUN_OK) return status;
  memset(&result, 0, sizeof(result));
  result.status = FTUN_OK;
  return ftun_datagram_send_complete(send, result);
}

static ftun_status_t ftun_tun_udp_send_cancel(void *user,
                                               ftun_datagram_send_t *send)
{
  (void)user;
  (void)send;
  return FTUN_OK;
}

static void ftun_tun_udp_destroy(void *user)
{
  ftun_tun_udp_bridge_t *bridge = (ftun_tun_udp_bridge_t *)user;
  ftun_tun_ingress_context_t *context;
  ftun_reservation_t *reservation;
  if (bridge == NULL) return;
  context = bridge->context;
  if (bridge->flow != NULL && ftun_lwip_udp_close(&bridge->flow) != FTUN_OK) {
    context->corrupt = true;
  }
  ftun_tun_udp_unlink(bridge);
  reservation = bridge->reservation;
  bridge->reservation = NULL;
  bridge->channel = NULL;
  bridge->context = NULL;
  free(bridge);
  if (ftun_reservation_release(&reservation) != FTUN_OK) {
    context->corrupt = true;
  }
}

static ftun_status_t ftun_tun_udp_deliver(
  ftun_datagram_t *channel, const ftun_endpoint_t *source,
  const ftun_packet_t *packet, void *user)
{
  ftun_tun_udp_bridge_t *bridge = (ftun_tun_udp_bridge_t *)user;
  if (bridge == NULL || channel != bridge->channel ||
      !ftun_tun_endpoint_equal(source, &bridge->metadata.original_target)) {
    return FTUN_E_STATE_CORRUPT;
  }
  return bridge->context->datagram_receive(
    bridge->context->user, &bridge->metadata, channel, source, packet);
}

static ftun_status_t ftun_tun_udp_accept(
  void *user, ftun_lwip_udp_t *flow, const ftun_endpoint_t *source,
  const ftun_endpoint_t *target)
{
  ftun_tun_ingress_context_t *context =
    (ftun_tun_ingress_context_t *)user;
  ftun_tun_udp_bridge_t *bridge;
  ftun_reservation_t *reservation = NULL;
  ftun_datagram_options_t options;
  ftun_datagram_backend_t backend;
  ftun_status_t status;
  if (context == NULL || flow == NULL || source == NULL || target == NULL ||
      !context->accepting || !context->udp) return FTUN_E_CANCELLED;
  status = ftun_budget_reserve(context->budget, sizeof(*bridge),
                               &reservation);
  if (status != FTUN_OK) return status;
  bridge = (ftun_tun_udp_bridge_t *)calloc(1u, sizeof(*bridge));
  if (bridge == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  bridge->context = context;
  bridge->reservation = reservation;
  bridge->flow = flow;
  ftun_tun_metadata(context, 2u, source, target, &bridge->metadata);
  memset(&options, 0, sizeof(options));
  options.budget = context->budget;
  options.max_pending_packets = context->max_pending_datagrams;
  options.max_pending_bytes = context->max_pending_datagram_bytes;
  options.receive = ftun_tun_udp_deliver;
  options.user = bridge;
  memset(&backend, 0, sizeof(backend));
  backend.send_start = ftun_tun_udp_send_start;
  backend.send_cancel = ftun_tun_udp_send_cancel;
  backend.destroy = ftun_tun_udp_destroy;
  backend.context = bridge;
  status = ftun_datagram_create(&options, &backend, &bridge->channel);
  if (status != FTUN_OK) {
    free(bridge);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  bridge->next = context->udp_channels;
  bridge->linked = true;
  context->udp_channels = bridge;
  context->udp_channel_count++;
  return FTUN_OK;
}

static ftun_status_t ftun_tun_udp_receive(void *user,
                                          ftun_lwip_udp_t *flow,
                                          const ftun_packet_t *packet)
{
  ftun_tun_ingress_context_t *context =
    (ftun_tun_ingress_context_t *)user;
  ftun_tun_udp_bridge_t *bridge;
  if (context == NULL || flow == NULL || packet == NULL) return FTUN_E_INVALID;
  for (bridge = context->udp_channels; bridge != NULL; bridge = bridge->next) {
    if (bridge->flow == flow) break;
  }
  if (bridge == NULL) return FTUN_E_STATE_CORRUPT;
  return ftun_datagram_deliver(bridge->channel,
                               &bridge->metadata.original_target, packet);
}

static ftun_status_t ftun_tun_output(void *user, ftun_bytes_t packet)
{
  ftun_tun_ingress_context_t *context =
    (ftun_tun_ingress_context_t *)user;
  if (context == NULL || packet.data == NULL || packet.length == 0u) {
    return FTUN_E_INVALID;
  }
  if (context->output != NULL) {
    return context->output(context->user, context->port, packet);
  }
  return ftun_packet_port_write(context->port, packet.data, packet.length);
}

static int ftun_tun_spec_valid(const ftun_tun_ingress_spec_t *spec)
{
  if (spec == NULL || spec->core == NULL || spec->port == NULL ||
      spec->budget == NULL || spec->generation == 0u ||
      spec->inbound_id == 0u || (!spec->tcp && !spec->udp) ||
      spec->mtu < FTUN_LWIP_MIN_MTU || spec->mtu > FTUN_LWIP_MAX_MTU) {
    return 0;
  }
  if (spec->tcp && (spec->operations == NULL || spec->stream_accept == NULL ||
      spec->stream_write_completion == NULL ||
      spec->max_pending_stream_writes == 0u ||
      spec->max_pending_stream_bytes == 0u)) return 0;
  if (spec->udp && (spec->datagram_receive == NULL ||
      spec->max_pending_datagrams == 0u ||
      spec->max_pending_datagram_bytes == 0u)) return 0;
  return 1;
}

/* TASK-INBOUND-005 / TEST-INBOUND-005，目标 0.2.0：PacketPort 到统一传输。 */
ftun_status_t ftun_tun_ingress_bind(
  const ftun_tun_ingress_spec_t *spec, ftun_tun_ingress_context_t **out)
{
  ftun_tun_ingress_context_t *context;
  ftun_reservation_t *reservation = NULL;
  ftun_lwip_spec_t lwip;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (out == NULL || !ftun_tun_spec_valid(spec)) return FTUN_E_INVALID;
  if (ftun_tun_active != NULL) return FTUN_E_AGAIN;
  status = ftun_budget_reserve(spec->budget, sizeof(*context), &reservation);
  if (status != FTUN_OK) return status;
  context = (ftun_tun_ingress_context_t *)calloc(1u, sizeof(*context));
  if (context == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  context->core = spec->core;
  context->port = spec->port;
  context->budget = spec->budget;
  context->operations = spec->operations;
  context->reservation = reservation;
  context->generation = spec->generation;
  context->inbound_id = spec->inbound_id;
  context->mtu = spec->mtu;
  context->max_pending_stream_writes = spec->max_pending_stream_writes;
  context->max_pending_stream_bytes = spec->max_pending_stream_bytes;
  context->max_pending_datagrams = spec->max_pending_datagrams;
  context->max_pending_datagram_bytes = spec->max_pending_datagram_bytes;
  context->stream_write_completion = spec->stream_write_completion;
  context->stream_accept = spec->stream_accept;
  context->stream_event = spec->stream_event;
  context->datagram_receive = spec->datagram_receive;
  context->output = spec->output;
  context->user = spec->user;
  context->tcp = spec->tcp;
  context->udp = spec->udp;
  context->accepting = true;
  memset(&lwip, 0, sizeof(lwip));
  lwip.budget = spec->budget;
  lwip.mtu = spec->mtu;
  lwip.now_ms = spec->now_ms;
  lwip.output = ftun_tun_output;
  lwip.accept = spec->tcp ? ftun_tun_tcp_accept : NULL;
  lwip.tcp_event = spec->tcp ? ftun_tun_tcp_event : NULL;
  lwip.tcp_write_done = spec->tcp ? ftun_tun_tcp_write_done : NULL;
  lwip.udp_accept = spec->udp ? ftun_tun_udp_accept : NULL;
  lwip.udp_receive = spec->udp ? ftun_tun_udp_receive : NULL;
  lwip.packet_source_id = spec->inbound_id;
  lwip.user = context;
  status = ftun_lwip_create(&lwip, &context->stack);
  if (status != FTUN_OK) {
    free(context);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  ftun_tun_active = context;
  *out = context;
  return FTUN_OK;
}

ftun_status_t ftun_tun_ingress(ftun_core_t *core, ftun_packet_port_t *port,
                               ftun_packet_t *packet)
{
  ftun_tun_ingress_context_t *context = ftun_tun_active;
  ftun_bytes_t bytes;
  size_t header_length;
  size_t total_length;
  uint8_t protocol;
  ftun_status_t status;
  if (core == NULL || port == NULL || packet == NULL) return FTUN_E_INVALID;
  if (context == NULL || context->core != core || context->port != port) {
    return FTUN_E_STALE;
  }
  if (!context->accepting) return FTUN_E_CANCELLED;
  if (packet->source_id != context->inbound_id) return FTUN_E_REJECTED;
  status = ftun_packet_view(packet, &bytes);
  if (status != FTUN_OK) return status;
  if (bytes.length < 20u || bytes.length > context->mtu ||
      (bytes.data[0] >> 4) != 4u) return FTUN_E_PROTOCOL;
  header_length = (size_t)(bytes.data[0] & 0x0fu) * 4u;
  total_length = ((size_t)bytes.data[2] << 8) | bytes.data[3];
  if (header_length < 20u || header_length > bytes.length ||
      total_length != bytes.length) return FTUN_E_PROTOCOL;
  protocol = bytes.data[9];
  if (protocol == 6u && !context->tcp) return FTUN_E_UNSUPPORTED;
  if (protocol == 17u && !context->udp) return FTUN_E_UNSUPPORTED;
  if (protocol != 6u && protocol != 17u) return FTUN_E_UNSUPPORTED;
  status = ftun_lwip_input(context->stack, packet);
  if (context->corrupt) return FTUN_E_STATE_CORRUPT;
  return status;
}

ftun_status_t ftun_tun_ingress_tick(ftun_tun_ingress_context_t *context,
                                    uint64_t now_ms)
{
  if (context == NULL || context != ftun_tun_active) return FTUN_E_INVALID;
  if (!context->accepting) return FTUN_E_CANCELLED;
  return ftun_lwip_tick(context->stack, now_ms);
}

ftun_status_t ftun_tun_ingress_get_usage(
  const ftun_tun_ingress_context_t *context, ftun_tun_ingress_usage_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (context == NULL || out == NULL || context != ftun_tun_active) {
    return FTUN_E_INVALID;
  }
  out->tcp_streams = context->tcp_stream_count;
  out->udp_channels = context->udp_channel_count;
  out->accepting = context->accepting;
  out->corrupt = context->corrupt;
  return context->corrupt ? FTUN_E_STATE_CORRUPT : FTUN_OK;
}

ftun_status_t ftun_tun_ingress_close(ftun_tun_ingress_context_t **context)
{
  ftun_tun_ingress_context_t *owned;
  ftun_reservation_t *reservation;
  ftun_status_t status;
  if (context == NULL) return FTUN_E_INVALID;
  owned = *context;
  if (owned == NULL) return FTUN_OK;
  if (owned != ftun_tun_active) return FTUN_E_STALE;
  owned->accepting = false;
  {
    ftun_tun_tcp_bridge_t *bridge;
    for (bridge = owned->tcp_streams; bridge != NULL; bridge = bridge->next) {
      status = ftun_stream_stop(bridge->stream);
      if (status != FTUN_OK) return status;
      if (bridge->flow != NULL) {
        ftun_lwip_tcp_t *flow = bridge->flow;
        bridge->flow = NULL;
        status = ftun_lwip_tcp_close(&flow);
        if (status != FTUN_OK) return status;
      }
    }
  }
  if (owned->tcp_streams != NULL) {
    return FTUN_E_AGAIN;
  }
  while (owned->udp_channels != NULL) {
    ftun_datagram_t *channel = owned->udp_channels->channel;
    status = ftun_datagram_stop(channel);
    if (status != FTUN_OK) return status;
    status = ftun_datagram_destroy(&channel);
    if (status != FTUN_OK) return status;
  }
  status = ftun_lwip_destroy(&owned->stack);
  if (status != FTUN_OK) return status;
  reservation = owned->reservation;
  owned->reservation = NULL;
  ftun_tun_active = NULL;
  *context = NULL;
  status = ftun_reservation_release(&reservation);
  if (status != FTUN_OK) {
    free(owned);
    return status;
  }
  status = owned->corrupt ? FTUN_E_STATE_CORRUPT : FTUN_OK;
  memset(owned, 0, sizeof(*owned));
  free(owned);
  return status;
}
