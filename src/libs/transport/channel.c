#include "libs/transport/channel_internal.h"
#include <string.h>

ftun_status_t ftun_channel_adopt_stream(ftun_channel_t *out, ftun_stream_t **stream)
{
  ftun_stream_usage_t usage;
  ftun_status_t status;
  if (out == NULL || stream == NULL || *stream == NULL) return FTUN_E_INVALID;
  status = ftun_stream_get_usage(*stream, &usage);
  if (status != FTUN_OK) return status;
  if (!usage.accepting || usage.write_shutdown || usage.pending_writes != 0u ||
      usage.in_completion || usage.in_backend || usage.reference_count != 1u) return FTUN_E_AGAIN;
  out->transport = FTUN_DIAL_TCP;
  out->data.stream = *stream;
  *stream = NULL;
  return FTUN_OK;
}

ftun_status_t ftun_channel_adopt_datagram(ftun_channel_t *out, ftun_datagram_t **datagram)
{
  ftun_datagram_usage_t usage;
  ftun_status_t status;
  if (out == NULL || datagram == NULL || *datagram == NULL) return FTUN_E_INVALID;
  status = ftun_datagram_get_usage(*datagram, &usage);
  if (status != FTUN_OK) return status;
  if (!usage.accepting || usage.pending_packets != 0u || usage.in_callback || usage.in_backend) return FTUN_E_AGAIN;
  out->transport = FTUN_DIAL_UDP;
  out->data.datagram = *datagram;
  *datagram = NULL;
  return FTUN_OK;
}

ftun_dial_transport_t ftun_channel_transport(const ftun_channel_t *channel)
{
  return channel->transport;
}

ftun_status_t ftun_channel_budget(ftun_channel_t *channel, ftun_budget_t **out)
{
  return channel->transport == FTUN_DIAL_TCP
    ? ftun_stream_budget(channel->data.stream, out)
    : ftun_datagram_budget(channel->data.datagram, out);
}

ftun_status_t ftun_channel_get_usage(const ftun_channel_t *channel, ftun_channel_usage_t *out)
{
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (channel == NULL || out == NULL) return FTUN_E_INVALID;
  out->transport = channel->transport;
  if (channel->transport == FTUN_DIAL_TCP) {
    ftun_stream_usage_t usage;
    status = ftun_stream_get_usage(channel->data.stream, &usage);
    if (status != FTUN_OK) return status;
    out->pending_items = usage.pending_writes;
    out->pending_bytes = usage.pending_bytes;
    out->references = usage.reference_count;
    out->accepting = usage.accepting;
    out->in_callback = usage.in_completion;
    out->in_backend = usage.in_backend;
  } else if (channel->transport == FTUN_DIAL_UDP) {
    ftun_datagram_usage_t usage;
    status = ftun_datagram_get_usage(channel->data.datagram, &usage);
    if (status != FTUN_OK) return status;
    out->pending_items = usage.pending_packets;
    out->pending_bytes = usage.pending_bytes;
    out->references = usage.reference_count;
    out->accepting = usage.accepting;
    out->in_callback = usage.in_callback;
    out->in_backend = usage.in_backend;
  }
  return FTUN_OK;
}

ftun_status_t ftun_channel_read(ftun_channel_t *channel, void *buffer, size_t capacity, size_t *length)
{
  if (length != NULL) *length = 0u;
  if (channel == NULL) return FTUN_E_INVALID;
  if (channel->transport != FTUN_DIAL_TCP) return FTUN_E_UNSUPPORTED;
  return ftun_stream_read(channel->data.stream, buffer, capacity, length);
}

ftun_status_t ftun_channel_write_ref(ftun_channel_t *channel,
  const ftun_buffer_slice_t *slice, size_t *accepted, ftun_operation_t **out)
{
  if (accepted != NULL) *accepted = 0u;
  if (out != NULL) *out = NULL;
  if (channel == NULL) return FTUN_E_INVALID;
  if (channel->transport != FTUN_DIAL_TCP) return FTUN_E_UNSUPPORTED;
  return ftun_stream_write_ref(channel->data.stream, slice, accepted, out);
}

ftun_status_t ftun_channel_write_ref_with_completion(ftun_channel_t *channel,
  const ftun_buffer_slice_t *slice, ftun_completion_fn completion, void *user,
  size_t *accepted, ftun_operation_t **out)
{
  if (accepted != NULL) *accepted = 0u;
  if (out != NULL) *out = NULL;
  if (channel == NULL) return FTUN_E_INVALID;
  if (channel->transport != FTUN_DIAL_TCP) return FTUN_E_UNSUPPORTED;
  return ftun_stream_write_ref_with_completion(channel->data.stream, slice,
    completion, user, accepted, out);
}

ftun_status_t ftun_channel_shutdown_write(ftun_channel_t *channel)
{
  if (channel == NULL) return FTUN_E_INVALID;
  if (channel->transport != FTUN_DIAL_TCP) return FTUN_E_UNSUPPORTED;
  return ftun_stream_shutdown_write(channel->data.stream);
}

ftun_status_t ftun_channel_send(ftun_channel_t *channel,
  const ftun_endpoint_t *target, ftun_packet_t *packet)
{
  if (channel == NULL) return FTUN_E_INVALID;
  if (channel->transport != FTUN_DIAL_UDP) return FTUN_E_UNSUPPORTED;
  return ftun_datagram_send(channel->data.datagram, target, packet);
}

ftun_status_t ftun_channel_deliver(ftun_channel_t *channel,
  const ftun_endpoint_t *source, const ftun_packet_t *packet)
{
  if (channel == NULL) return FTUN_E_INVALID;
  if (channel->transport != FTUN_DIAL_UDP) return FTUN_E_UNSUPPORTED;
  return ftun_datagram_deliver(channel->data.datagram, source, packet);
}

ftun_status_t ftun_channel_stream(ftun_channel_t *channel, ftun_stream_t **out)
{
  if (out != NULL) *out = NULL;
  if (channel == NULL || out == NULL) return FTUN_E_INVALID;
  if (channel->transport != FTUN_DIAL_TCP) return FTUN_E_UNSUPPORTED;
  *out = channel->data.stream;
  return FTUN_OK;
}

ftun_status_t ftun_channel_datagram(ftun_channel_t *channel, ftun_datagram_t **out)
{
  if (out != NULL) *out = NULL;
  if (channel == NULL || out == NULL) return FTUN_E_INVALID;
  if (channel->transport != FTUN_DIAL_UDP) return FTUN_E_UNSUPPORTED;
  *out = channel->data.datagram;
  return FTUN_OK;
}

ftun_status_t ftun_channel_stop(ftun_channel_t *channel)
{
  if (channel == NULL) return FTUN_E_INVALID;
  if (channel->transport == FTUN_DIAL_TCP) return ftun_stream_abort(channel->data.stream);
  if (channel->transport == FTUN_DIAL_UDP) return ftun_datagram_stop(channel->data.datagram);
  return FTUN_OK;
}

ftun_status_t ftun_channel_destroy(ftun_channel_t *channel)
{
  ftun_status_t status = FTUN_OK;
  if (channel->transport == FTUN_DIAL_TCP) status = ftun_stream_destroy(&channel->data.stream);
  else if (channel->transport == FTUN_DIAL_UDP) status = ftun_datagram_destroy(&channel->data.datagram);
  if (status == FTUN_OK) memset(channel, 0, sizeof(*channel));
  return status;
}
