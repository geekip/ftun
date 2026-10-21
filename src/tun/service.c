#include "tun/internal.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static ftun_status_t ftun_tun_device_open(
  void *user, ftun_core_t *core, const ftun_tun_spec_t *spec,
  ftun_packet_port_t **out)
{
  (void)user;
  return ftun_packet_port_open(core, spec, out);
}

static ftun_status_t ftun_tun_device_get_info(
  void *user, const ftun_packet_port_t *port, ftun_packet_port_info_t *out)
{
  (void)user;
  return ftun_packet_port_get_info(port, out);
}

static ftun_status_t ftun_tun_device_read(
  void *user, ftun_packet_port_t *port, void *buffer, size_t capacity,
  size_t *out_length)
{
  (void)user;
  return ftun_packet_port_read(port, buffer, capacity, out_length);
}

static ftun_status_t ftun_tun_device_write(
  void *user, ftun_packet_port_t *port, const void *packet, size_t length)
{
  (void)user;
  return ftun_packet_port_write(port, packet, length);
}

static ftun_status_t ftun_tun_device_close(
  void *user, ftun_packet_port_t **port)
{
  (void)user;
  return ftun_packet_port_close(port);
}

static const ftun_tun_device_ops_t ftun_tun_system_ops = {
  ftun_tun_device_open,
  ftun_tun_device_get_info,
  ftun_tun_device_read,
  ftun_tun_device_write,
  ftun_tun_device_close,
  NULL
};

static int ftun_tun_service_ops_valid(const ftun_tun_device_ops_t *ops)
{
  return ops != NULL && ops->open != NULL && ops->get_info != NULL &&
         ops->read != NULL && ops->write != NULL && ops->close != NULL;
}

static int ftun_tun_service_add_size(size_t *total, size_t count, size_t size)
{
  if (count != 0u && size > SIZE_MAX / count) return 0;
  if (*total > SIZE_MAX - count * size) return 0;
  *total += count * size;
  return 1;
}

ftun_tun_service_consumer_t *ftun_tun_service_lease_consumer(
  const ftun_tun_service_t *service, ftun_tun_lease_t lease)
{
  size_t index;
  if (service == NULL || lease.service != service || lease.generation == 0u) {
    return NULL;
  }
  for (index = 0u; index < service->consumer_capacity; index++) {
    ftun_tun_service_consumer_t *consumer = &service->consumers[index];
    if (consumer->lease.service == service &&
        consumer->lease.generation == lease.generation) return consumer;
  }
  return NULL;
}

static void ftun_tun_service_ready(ftun_event_source_t *source,
                                   uint32_t events, void *user)
{
  ftun_tun_service_t *service = (ftun_tun_service_t *)user;
  if (service != NULL && service->source == source) {
    (void)ftun_tun_service_notify(service, events);
  }
}

ftun_status_t ftun_tun_service_interests(ftun_tun_service_t *service)
{
  uint32_t interests = FTUN_EVENT_ERROR;
  if (service == NULL || service->source == NULL) return FTUN_E_INVALID;
  if (service->accepting && service->active_leases != 0u) {
    interests |= FTUN_EVENT_READ;
  }
  if (service->queued_outputs != 0u) interests |= FTUN_EVENT_WRITE;
  return ftun_event_io_update(service->source, interests);
}

static ftun_status_t ftun_tun_service_packet_clear(
  ftun_tun_service_packet_t *entries, size_t capacity, size_t *head,
  size_t *count, size_t *bytes, size_t *service_count, size_t *service_bytes,
  size_t *dropped)
{
  ftun_status_t result = FTUN_OK;
  if (entries == NULL || capacity == 0u || head == NULL || count == NULL ||
      bytes == NULL || service_count == NULL || service_bytes == NULL ||
      dropped == NULL) return FTUN_E_INVALID;
  while (*count != 0u) {
    ftun_tun_service_packet_t *entry = &entries[*head];
    ftun_status_t status = ftun_buffer_release(&entry->buffer);
    if (status != FTUN_OK && result == FTUN_OK) result = status;
    if (*bytes < entry->length || *service_bytes < entry->length ||
        *service_count == 0u) {
      result = FTUN_E_STATE_CORRUPT;
      *bytes = 0u;
      *service_bytes = 0u;
      *service_count = 0u;
    } else {
      *bytes -= entry->length;
      *service_bytes -= entry->length;
      (*service_count)--;
    }
    entry->length = 0u;
    entry->lease_generation = 0u;
    entry->path_generation = 0u;
    *head = (*head + 1u) % capacity;
    (*count)--;
    if (*dropped != SIZE_MAX) (*dropped)++;
  }
  *head = 0u;
  *bytes = 0u;
  return result;
}

static void ftun_tun_service_add_drops(ftun_tun_service_t *service,
                                       size_t count)
{
  if (SIZE_MAX - service->packets_dropped < count) {
    service->packets_dropped = SIZE_MAX;
  } else {
    service->packets_dropped += count;
  }
}

ftun_status_t ftun_tun_service_consumer_clear(
  ftun_tun_service_t *service, ftun_tun_service_consumer_t *consumer)
{
  size_t input_count = consumer->input_count;
  size_t output_count = consumer->output_count;
  ftun_status_t result;
  ftun_status_t status;
  result = ftun_tun_service_packet_clear(
    consumer->input, service->input_capacity, &consumer->input_head,
    &consumer->input_count, &consumer->input_bytes,
    &service->queued_inputs, &service->queued_input_bytes,
    &consumer->packets_dropped);
  status = ftun_tun_service_packet_clear(
    consumer->output, service->output_capacity, &consumer->output_head,
    &consumer->output_count, &consumer->output_bytes,
    &service->queued_outputs, &service->queued_output_bytes,
    &consumer->packets_dropped);
  if (status != FTUN_OK && result == FTUN_OK) result = status;
  ftun_tun_service_add_drops(service, input_count);
  ftun_tun_service_add_drops(service, output_count);
  consumer->blocked = false;
  consumer->dispatch_ready = false;
  return result;
}

static ftun_status_t ftun_tun_service_all_outputs_clear(
  ftun_tun_service_t *service)
{
  size_t index;
  ftun_status_t result = FTUN_OK;
  for (index = 0u; index < service->consumer_capacity; index++) {
    ftun_tun_service_consumer_t *consumer = &service->consumers[index];
    size_t count = consumer->output_count;
    ftun_status_t status = ftun_tun_service_packet_clear(
      consumer->output, service->output_capacity, &consumer->output_head,
      &consumer->output_count, &consumer->output_bytes,
      &service->queued_outputs, &service->queued_output_bytes,
      &consumer->packets_dropped);
    if (status != FTUN_OK && result == FTUN_OK) result = status;
    ftun_tun_service_add_drops(service, count);
  }
  return result;
}

static ftun_status_t ftun_tun_service_all_inputs_clear(
  ftun_tun_service_t *service)
{
  size_t index;
  ftun_status_t result = FTUN_OK;
  for (index = 0u; index < service->consumer_capacity; index++) {
    ftun_tun_service_consumer_t *consumer = &service->consumers[index];
    size_t count = consumer->input_count;
    ftun_status_t status = ftun_tun_service_packet_clear(
      consumer->input, service->input_capacity, &consumer->input_head,
      &consumer->input_count, &consumer->input_bytes,
      &service->queued_inputs, &service->queued_input_bytes,
      &consumer->packets_dropped);
    consumer->blocked = false;
    consumer->dispatch_ready = false;
    if (status != FTUN_OK && result == FTUN_OK) result = status;
    ftun_tun_service_add_drops(service, count);
  }
  return result;
}

static ftun_status_t ftun_tun_service_device_open(
  ftun_tun_service_t *service)
{
  ftun_tun_spec_t spec;
  uint32_t interests = FTUN_EVENT_ERROR;
  ftun_status_t status;
  memset(&spec, 0, sizeof(spec));
  spec.name.data = service->device_name;
  spec.name.length = strlen(service->device_name);
  spec.mtu = service->mtu;
  status = service->ops.open(service->ops.user, service->core, &spec,
                             &service->port);
  if (status == FTUN_OK) {
    status = service->ops.get_info(service->ops.user, service->port,
                                   &service->info);
  }
  if (status == FTUN_OK &&
      (service->info.mtu != service->mtu ||
       service->info.native_socket > (ftun_native_socket_t)INT32_MAX)) {
    status = FTUN_E_STATE_CORRUPT;
  }
  if (service->accepting && service->active_leases != 0u) {
    interests |= FTUN_EVENT_READ;
  }
  if (status == FTUN_OK) {
    status = ftun_event_io_start(
      service->loop, service->info.native_socket, interests,
      ftun_tun_service_ready, service, &service->source);
  }
  if (status != FTUN_OK) {
    (void)ftun_event_source_cancel(&service->source);
    (void)service->ops.close(service->ops.user, &service->port);
    memset(&service->info, 0, sizeof(service->info));
    return status;
  }
  service->device_generation++;
  if (service->device_generation == 0u) service->device_generation++;
  return FTUN_OK;
}

ftun_status_t ftun_tun_service_create(
  const ftun_tun_service_spec_t *spec, ftun_tun_service_t **out)
{
  return ftun_tun_service_create_with_ops(spec, &ftun_tun_system_ops, out);
}

ftun_status_t ftun_tun_service_create_with_ops(
  const ftun_tun_service_spec_t *spec, const ftun_tun_device_ops_t *ops,
  ftun_tun_service_t **out)
{
  ftun_tun_service_t *service;
  ftun_reservation_t *reservation = NULL;
  size_t consumer_capacity;
  size_t input_capacity;
  size_t consumer_quota;
  size_t input_count;
  size_t output_count;
  size_t bytes = sizeof(*service);
  size_t index;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (spec == NULL || out == NULL || spec->budget == NULL ||
      spec->loop == NULL || spec->buffers == NULL ||
      spec->device.name.data == NULL || spec->device.name.length == 0u ||
      spec->device.name.length >= FTUN_PACKET_PORT_NAME_BYTES ||
      memchr(spec->device.name.data, '\0', spec->device.name.length) != NULL ||
      spec->device.mtu == 0u || spec->output_capacity == 0u ||
      spec->read_quota == 0u || spec->write_quota == 0u ||
      !ftun_tun_service_ops_valid(ops)) return FTUN_E_INVALID;
  consumer_capacity = spec->consumer_capacity == 0u
    ? 1u : spec->consumer_capacity;
  input_capacity = spec->input_capacity == 0u
    ? spec->read_quota : spec->input_capacity;
  consumer_quota = spec->consumer_quota == 0u
    ? spec->read_quota : spec->consumer_quota;
  if (consumer_capacity > SIZE_MAX / input_capacity ||
      consumer_capacity > SIZE_MAX / spec->output_capacity) {
    return FTUN_E_LIMIT;
  }
  input_count = consumer_capacity * input_capacity;
  output_count = consumer_capacity * spec->output_capacity;
  if (!ftun_tun_service_add_size(&bytes, consumer_capacity,
                                  sizeof(*service->consumers)) ||
      !ftun_tun_service_add_size(&bytes, input_count,
                                  sizeof(*service->input_entries)) ||
      !ftun_tun_service_add_size(&bytes, output_count,
                                  sizeof(*service->output_entries)) ||
      !ftun_tun_service_add_size(&bytes, spec->device.mtu, 1u)) {
    return FTUN_E_LIMIT;
  }
  status = ftun_budget_reserve(spec->budget, bytes, &reservation);
  if (status != FTUN_OK) return status;
  service = (ftun_tun_service_t *)calloc(1u, sizeof(*service));
  if (service == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  service->consumers = (ftun_tun_service_consumer_t *)calloc(
    consumer_capacity, sizeof(*service->consumers));
  service->input_entries = (ftun_tun_service_packet_t *)calloc(
    input_count, sizeof(*service->input_entries));
  service->output_entries = (ftun_tun_service_packet_t *)calloc(
    output_count, sizeof(*service->output_entries));
  service->input = (uint8_t *)malloc(spec->device.mtu);
  if (service->consumers == NULL || service->input_entries == NULL ||
      service->output_entries == NULL || service->input == NULL) {
    free(service->input);
    free(service->output_entries);
    free(service->input_entries);
    free(service->consumers);
    free(service);
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  for (index = 0u; index < consumer_capacity; index++) {
    service->consumers[index].input =
      service->input_entries + index * input_capacity;
    service->consumers[index].output =
      service->output_entries + index * spec->output_capacity;
  }
  memcpy(service->device_name, spec->device.name.data,
         spec->device.name.length);
  service->device_name[spec->device.name.length] = '\0';
  service->core = spec->core;
  service->budget = spec->budget;
  service->reservation = reservation;
  service->loop = spec->loop;
  service->buffers = spec->buffers;
  service->ops = *ops;
  service->mtu = spec->device.mtu;
  service->consumer_capacity = consumer_capacity;
  service->input_capacity = input_capacity;
  service->output_capacity = spec->output_capacity;
  service->consumer_quota = consumer_quota;
  service->read_quota = spec->read_quota;
  service->write_quota = spec->write_quota;
  service->accepting = true;
  status = ftun_tun_service_device_open(service);
  if (status != FTUN_OK) {
    free(service->input);
    free(service->output_entries);
    free(service->input_entries);
    free(service->consumers);
    free(service);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  *out = service;
  return FTUN_OK;
}

ftun_status_t ftun_l3_provider_bind(ftun_tun_service_t *service,
                                    uint64_t generation,
                                    ftun_l3_provider_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (service == NULL || generation == 0u || out == NULL) {
    return FTUN_E_INVALID;
  }
  out->service = service;
  out->budget = service->budget;
  out->generation = generation;
  return FTUN_OK;
}

ftun_status_t ftun_l3_provider_acquire(
  const ftun_l3_provider_t *provider, uint64_t generation,
  const ftun_tun_consumer_spec_t *consumer, ftun_tun_lease_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (provider == NULL || provider->service == NULL ||
      provider->budget == NULL || generation == 0u || consumer == NULL ||
      out == NULL) return FTUN_E_INVALID;
  if (provider->generation != generation) return FTUN_E_STALE;
  return ftun_tun_service_acquire_routed(provider->service, consumer, out);
}

ftun_status_t ftun_l3_provider_reload_prepare(
  ftun_l3_provider_t *provider, uint64_t generation)
{
  if (provider == NULL || provider->service == NULL ||
      provider->budget == NULL || provider->generation == 0u ||
      generation <= provider->generation) return FTUN_E_INVALID;
  if (provider->reload_prepared) return FTUN_E_STALE;
  provider->pending_generation = generation;
  provider->reload_prepared = true;
  return FTUN_OK;
}

ftun_status_t ftun_l3_provider_reload_commit(
  ftun_l3_provider_t *provider, uint64_t generation)
{
  if (provider == NULL || !provider->reload_prepared ||
      generation == 0u || generation != provider->pending_generation) {
    return FTUN_E_INVALID;
  }
  provider->generation = generation;
  provider->pending_generation = 0u;
  provider->reload_prepared = false;
  return FTUN_OK;
}

ftun_status_t ftun_l3_provider_reload_abort(ftun_l3_provider_t *provider)
{
  if (provider == NULL || provider->service == NULL ||
      provider->budget == NULL || provider->generation == 0u) {
    return FTUN_E_INVALID;
  }
  provider->pending_generation = 0u;
  provider->reload_prepared = false;
  return FTUN_OK;
}

ftun_status_t ftun_l3_provider_get_info(
  const ftun_l3_provider_t *provider, ftun_l3_provider_info_t *out)
{
  ftun_tun_service_usage_t usage;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (provider == NULL || provider->service == NULL ||
      provider->budget == NULL || provider->generation == 0u || out == NULL) {
    return FTUN_E_INVALID;
  }
  status = ftun_tun_service_get_usage(provider->service, &usage);
  if (status != FTUN_OK) return status;
  out->device = usage.device;
  out->generation = provider->generation;
  out->pending_generation = provider->pending_generation;
  out->device_generation = usage.device_generation;
  out->active_leases = usage.active_leases;
  out->accepting = usage.accepting;
  out->reload_prepared = provider->reload_prepared;
  return FTUN_OK;
}

ftun_status_t ftun_l3_provider_quiesce(ftun_l3_provider_t *provider)
{
  ftun_status_t status;
  if (provider == NULL || provider->service == NULL ||
      provider->budget == NULL || provider->generation == 0u) {
    return FTUN_E_INVALID;
  }
  status = ftun_tun_service_quiesce(provider->service);
  if (status == FTUN_OK) memset(provider, 0, sizeof(*provider));
  return status;
}

ftun_status_t ftun_tun_service_rebuild(ftun_tun_service_t *service)
{
  ftun_status_t status;
  if (service == NULL) return FTUN_E_INVALID;
  if (!service->accepting) return FTUN_E_CANCELLED;
  status = ftun_event_source_cancel(&service->source);
  if (status != FTUN_OK) return status;
  status = ftun_tun_service_all_outputs_clear(service);
  if (status != FTUN_OK) return status;
  status = service->ops.close(service->ops.user, &service->port);
  if (service->port == NULL) {
    memset(&service->info, 0, sizeof(service->info));
    service->events = 0u;
  }
  if (status != FTUN_OK) return status;
  status = ftun_tun_service_device_open(service);
  if (status == FTUN_OK) {
    ftun_tun_service_broadcast(service, FTUN_TUN_SERVICE_REBUILT, FTUN_OK);
  }
  return status;
}

ftun_status_t ftun_tun_service_quiesce(ftun_tun_service_t *service)
{
  ftun_status_t result;
  ftun_status_t status;
  if (service == NULL) return FTUN_E_INVALID;
  if (!service->accepting && service->source == NULL) return FTUN_OK;
  service->accepting = false;
  result = ftun_event_source_cancel(&service->source);
  status = ftun_tun_service_all_outputs_clear(service);
  if (status != FTUN_OK && result == FTUN_OK) result = status;
  status = ftun_tun_service_all_inputs_clear(service);
  if (status != FTUN_OK && result == FTUN_OK) result = status;
  service->events = 0u;
  if (result == FTUN_OK) {
    ftun_tun_service_broadcast(service, FTUN_TUN_SERVICE_QUIESCED, FTUN_OK);
  }
  return result;
}

ftun_status_t ftun_tun_service_get_usage(
  const ftun_tun_service_t *service, ftun_tun_service_usage_t *out)
{
  size_t index;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (service == NULL || out == NULL) return FTUN_E_INVALID;
  out->device = service->info;
  out->device_generation = service->device_generation;
  out->active_leases = service->active_leases;
  out->queued_inputs = service->queued_inputs;
  out->queued_input_bytes = service->queued_input_bytes;
  out->queued_packets = service->queued_outputs;
  out->queued_bytes = service->queued_output_bytes;
  out->packets_read = service->packets_read;
  out->packets_written = service->packets_written;
  out->packets_dropped = service->packets_dropped;
  out->packet_errors = service->packet_errors;
  out->feedback_sent = service->feedback_sent;
  out->feedback_suppressed = service->feedback_suppressed;
  out->accepting = service->accepting;
  out->ready = service->events != 0u;
  for (index = 0u; index < service->consumer_capacity; index++) {
    const ftun_tun_service_consumer_t *consumer = &service->consumers[index];
    if (consumer->lease.service != service) continue;
    if (service->active_leases == 1u) {
      out->lease_generation = consumer->lease.generation;
    }
    if (consumer->blocked) out->blocked_consumers++;
    if (consumer->dispatch_ready) out->ready = true;
  }
  return FTUN_OK;
}

ftun_status_t ftun_tun_service_get_consumer_usage(
  ftun_tun_lease_t lease, ftun_tun_consumer_usage_t *out)
{
  ftun_tun_service_t *service = lease.service;
  ftun_tun_service_consumer_t *consumer;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (out == NULL) return FTUN_E_INVALID;
  consumer = ftun_tun_service_lease_consumer(service, lease);
  if (consumer == NULL) return FTUN_E_STALE;
  out->route = consumer->route;
  out->path = consumer->path;
  out->path_generation = consumer->path_generation;
  out->inner_mtu = consumer->inner_mtu;
  out->queued_inputs = consumer->input_count;
  out->queued_input_bytes = consumer->input_bytes;
  out->queued_outputs = consumer->output_count;
  out->queued_output_bytes = consumer->output_bytes;
  out->packets_received = consumer->packets_received;
  out->packets_written = consumer->packets_written;
  out->packets_dropped = consumer->packets_dropped;
  out->malformed_packets = consumer->malformed_packets;
  out->oversized_packets = consumer->oversized_packets;
  out->fragments_rejected = consumer->fragments_rejected;
  out->sources_rejected = consumer->sources_rejected;
  out->feedback_sent = consumer->feedback_sent;
  out->feedback_suppressed = consumer->feedback_suppressed;
  out->blocked = consumer->blocked;
  return FTUN_OK;
}

ftun_status_t ftun_tun_service_destroy(ftun_tun_service_t **service)
{
  ftun_tun_service_t *owned;
  ftun_reservation_t *reservation;
  ftun_status_t status;
  if (service == NULL) return FTUN_E_INVALID;
  owned = *service;
  if (owned == NULL) return FTUN_OK;
  if (owned->active_leases != 0u) return FTUN_E_AGAIN;
  status = ftun_event_source_cancel(&owned->source);
  if (status != FTUN_OK) return status;
  status = ftun_tun_service_all_outputs_clear(owned);
  if (status != FTUN_OK) return status;
  status = ftun_tun_service_all_inputs_clear(owned);
  if (status != FTUN_OK) return status;
  status = owned->ops.close(owned->ops.user, &owned->port);
  if (status != FTUN_OK) return status;
  reservation = owned->reservation;
  owned->reservation = NULL;
  free(owned->input);
  free(owned->output_entries);
  free(owned->input_entries);
  free(owned->consumers);
  free(owned);
  *service = NULL;
  return ftun_reservation_release(&reservation);
}
