#include "libs/tun/internal.h"

#include <string.h>

static ftun_status_t ftun_tun_service_packet_queue(
  ftun_tun_service_t *service, ftun_tun_service_consumer_t *consumer,
  ftun_tun_service_packet_t *entries, size_t capacity, size_t head,
  size_t count, ftun_bytes_t packet, size_t *consumer_count,
  size_t *consumer_bytes, size_t *service_count, size_t *service_bytes)
{
  ftun_tun_service_packet_t *entry;
  ftun_buffer_t *buffer = NULL;
  uint8_t *data = NULL;
  size_t buffer_capacity = 0u;
  size_t index;
  ftun_status_t status;
  if (count >= capacity || *consumer_bytes > SIZE_MAX - packet.length ||
      *service_bytes > SIZE_MAX - packet.length) return FTUN_E_LIMIT;
  status = ftun_buffer_pool_acquire(service->buffers, packet.length, &buffer);
  if (status == FTUN_OK) {
    status = ftun_buffer_data(buffer, &data, &buffer_capacity);
  }
  if (status != FTUN_OK || buffer_capacity < packet.length) {
    (void)ftun_buffer_release(&buffer);
    return status == FTUN_OK ? FTUN_E_STATE_CORRUPT : status;
  }
  memcpy(data, packet.data, packet.length);
  index = (head + count) % capacity;
  entry = &entries[index];
  if (entry->buffer != NULL) {
    (void)ftun_buffer_release(&buffer);
    return FTUN_E_STATE_CORRUPT;
  }
  entry->buffer = buffer;
  entry->length = packet.length;
  entry->lease_generation = consumer->lease.generation;
  entry->path_generation = consumer->path_generation;
  (*consumer_count)++;
  *consumer_bytes += packet.length;
  (*service_count)++;
  *service_bytes += packet.length;
  return FTUN_OK;
}

void ftun_tun_service_drop(ftun_tun_service_t *service,
                           ftun_tun_service_consumer_t *consumer)
{
  if (consumer != NULL && consumer->packets_dropped != SIZE_MAX) {
    consumer->packets_dropped++;
  }
  if (service->packets_dropped != SIZE_MAX) service->packets_dropped++;
}

void ftun_tun_service_increment(size_t *value)
{
  if (*value != SIZE_MAX) (*value)++;
}

static ftun_status_t ftun_tun_service_output_queue(
  ftun_tun_service_t *service, ftun_tun_service_consumer_t *consumer,
  ftun_bytes_t packet)
{
  ftun_status_t status = ftun_tun_service_packet_queue(
    service, consumer, consumer->output, service->output_capacity,
    consumer->output_head, consumer->output_count, packet,
    &consumer->output_count, &consumer->output_bytes,
    &service->queued_outputs, &service->queued_output_bytes);
  if (status == FTUN_OK) {
    status = ftun_tun_service_interests(service);
    if (status != FTUN_OK) {
      size_t index = (consumer->output_head + consumer->output_count - 1u) %
        service->output_capacity;
      ftun_tun_service_packet_t *entry = &consumer->output[index];
      consumer->output_count--;
      consumer->output_bytes -= entry->length;
      service->queued_outputs--;
      service->queued_output_bytes -= entry->length;
      entry->length = 0u;
      entry->lease_generation = 0u;
      entry->path_generation = 0u;
      (void)ftun_buffer_release(&entry->buffer);
    }
  }
  return status;
}

ftun_status_t ftun_tun_service_write(
  ftun_tun_lease_t lease, ftun_bytes_t packet)
{
  ftun_tun_service_t *service = lease.service;
  ftun_tun_service_consumer_t *consumer =
    ftun_tun_service_lease_consumer(service, lease);
  bool drop;
  ftun_status_t status;
  if (consumer == NULL) return FTUN_E_STALE;
  if (!service->accepting || service->port == NULL || service->source == NULL) {
    return FTUN_E_CANCELLED;
  }
  if (packet.data == NULL || packet.length == 0u) return FTUN_E_INVALID;
  status = ftun_tun_service_check_packet(
    service, consumer, FTUN_TUN_PACKET_TO_DEVICE, packet, &drop);
  if (status != FTUN_OK || drop) return status;
  if (packet.length > service->info.mtu) return FTUN_E_INVALID;
  if (service->queued_outputs == 0u) {
    status = service->ops.write(service->ops.user, service->port,
                                packet.data, packet.length);
    if (status == FTUN_OK) {
      if (service->packets_written != SIZE_MAX) service->packets_written++;
      if (consumer->packets_written != SIZE_MAX) consumer->packets_written++;
      return FTUN_OK;
    }
    if (status != FTUN_E_AGAIN) return status;
  }
  return ftun_tun_service_output_queue(service, consumer, packet);
}

ftun_status_t ftun_tun_service_resume(ftun_tun_lease_t lease)
{
  ftun_tun_service_t *service = lease.service;
  ftun_tun_service_consumer_t *consumer =
    ftun_tun_service_lease_consumer(service, lease);
  if (consumer == NULL) return FTUN_E_STALE;
  if (!service->accepting) return FTUN_E_CANCELLED;
  consumer->blocked = false;
  consumer->dispatch_ready = consumer->input_count != 0u;
  return ftun_event_loop_wakeup(service->loop);
}

ftun_status_t ftun_tun_service_notify(
  ftun_tun_service_t *service, uint32_t events)
{
  uint32_t allowed = FTUN_EVENT_READ | FTUN_EVENT_WRITE | FTUN_EVENT_ERROR;
  if (service == NULL || events == 0u || (events & ~allowed) != 0u) {
    return FTUN_E_INVALID;
  }
  if (service->source == NULL) return FTUN_E_CANCELLED;
  service->events |= events;
  return FTUN_OK;
}

static ftun_status_t ftun_tun_service_flush(
  ftun_tun_service_t *service, size_t *work)
{
  size_t written = 0u;
  size_t empty_scan = 0u;
  while (service->queued_outputs != 0u && written < service->write_quota) {
    ftun_tun_service_consumer_t *consumer =
      &service->consumers[service->output_cursor];
    service->output_cursor =
      (service->output_cursor + 1u) % service->consumer_capacity;
    if (consumer->output_count == 0u) {
      empty_scan++;
      if (empty_scan >= service->consumer_capacity) {
        return FTUN_E_STATE_CORRUPT;
      }
      continue;
    }
    empty_scan = 0u;
    {
      ftun_tun_service_packet_t *entry =
        &consumer->output[consumer->output_head];
      uint8_t *data = NULL;
      size_t capacity = 0u;
      ftun_status_t status;
      if (consumer->lease.service != service ||
          entry->lease_generation != consumer->lease.generation ||
          entry->path_generation != consumer->path_generation) {
        return FTUN_E_STATE_CORRUPT;
      }
      status = ftun_buffer_data(entry->buffer, &data, &capacity);
      if (status != FTUN_OK || entry->length > capacity) {
        return status == FTUN_OK ? FTUN_E_STATE_CORRUPT : status;
      }
      status = service->ops.write(service->ops.user, service->port,
                                  data, entry->length);
      if (status == FTUN_E_AGAIN) return FTUN_OK;
      if (status != FTUN_OK) {
        if (status == FTUN_E_IO) service->device_lost = true;
        return status;
      }
      consumer->output_bytes -= entry->length;
      service->queued_output_bytes -= entry->length;
      status = ftun_buffer_release(&entry->buffer);
      if (status != FTUN_OK) return status;
      entry->length = 0u;
      entry->lease_generation = 0u;
      entry->path_generation = 0u;
      consumer->output_head =
        (consumer->output_head + 1u) % service->output_capacity;
      consumer->output_count--;
      service->queued_outputs--;
      if (service->packets_written != SIZE_MAX) service->packets_written++;
      if (consumer->packets_written != SIZE_MAX) consumer->packets_written++;
      written++;
      (*work)++;
    }
  }
  if (service->queued_outputs != 0u && written == service->write_quota) {
    service->events |= FTUN_EVENT_WRITE;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_tun_service_input_queue(
  ftun_tun_service_t *service, ftun_tun_service_consumer_t *consumer,
  ftun_bytes_t packet)
{
  ftun_status_t status = ftun_tun_service_packet_queue(
    service, consumer, consumer->input, service->input_capacity,
    consumer->input_head, consumer->input_count, packet,
    &consumer->input_count, &consumer->input_bytes,
    &service->queued_inputs, &service->queued_input_bytes);
  if (status == FTUN_OK && !consumer->blocked) consumer->dispatch_ready = true;
  return status;
}

static ftun_status_t ftun_tun_service_deliver(
  ftun_tun_service_t *service, ftun_tun_service_consumer_t *consumer,
  ftun_bytes_t packet)
{
  ftun_tun_lease_t lease = consumer->lease;
  ftun_status_t status;
  if (consumer->blocked || consumer->input_count != 0u) {
    status = ftun_tun_service_input_queue(service, consumer, packet);
    if (status == FTUN_E_AGAIN || status == FTUN_E_LIMIT) {
      ftun_tun_service_drop(service, consumer);
      return FTUN_OK;
    }
    return status;
  }
  service->callback_depth++;
  status = consumer->consumer.packet(consumer->consumer.user, lease, packet);
  service->callback_depth--;
  if (ftun_tun_service_lease_consumer(service, lease) == NULL) return FTUN_OK;
  if (status == FTUN_OK) {
    if (consumer->packets_received != SIZE_MAX) consumer->packets_received++;
    ftun_tun_service_packet_progress(consumer);
    return FTUN_OK;
  }
  if (status == FTUN_E_AGAIN) {
    consumer->blocked = true;
    consumer->dispatch_ready = false;
    status = ftun_tun_service_input_queue(service, consumer, packet);
    if (status == FTUN_E_AGAIN || status == FTUN_E_LIMIT) {
      ftun_tun_service_drop(service, consumer);
      return FTUN_OK;
    }
    return status;
  }
  ftun_tun_service_drop(service, consumer);
  return status;
}

static ftun_status_t ftun_tun_service_dispatch_queued(
  ftun_tun_service_t *service, size_t *work)
{
  size_t visited;
  size_t start = service->dispatch_cursor;
  for (visited = 0u; visited < service->consumer_capacity; visited++) {
    size_t index = (start + visited) % service->consumer_capacity;
    ftun_tun_service_consumer_t *consumer = &service->consumers[index];
    size_t dispatched = 0u;
    if (consumer->lease.service != service || consumer->blocked ||
        !consumer->dispatch_ready) continue;
    while (consumer->input_count != 0u &&
           dispatched < service->consumer_quota) {
      ftun_tun_service_packet_t *entry =
        &consumer->input[consumer->input_head];
      ftun_tun_lease_t lease = consumer->lease;
      ftun_buffer_t *borrowed;
      uint8_t *data = NULL;
      size_t capacity = 0u;
      ftun_status_t status;
      if (entry->lease_generation != lease.generation) {
        return FTUN_E_STATE_CORRUPT;
      }
      if (entry->path_generation != consumer->path_generation) {
        return FTUN_E_STATE_CORRUPT;
      }
      status = ftun_buffer_data(entry->buffer, &data, &capacity);
      if (status != FTUN_OK || entry->length > capacity) {
        return status == FTUN_OK ? FTUN_E_STATE_CORRUPT : status;
      }
      /* release 可清空当前队列，但不能提前结束回调正在使用的借用。 */
      borrowed = entry->buffer;
      status = ftun_buffer_retain(borrowed);
      if (status != FTUN_OK) return status;
      service->callback_depth++;
      status = consumer->consumer.packet(
        consumer->consumer.user, lease,
        (ftun_bytes_t){data, entry->length});
      service->callback_depth--;
      {
        ftun_status_t released = ftun_buffer_release(&borrowed);
        if (released != FTUN_OK) return released;
      }
      (*work)++;
      if (ftun_tun_service_lease_consumer(service, lease) == NULL) break;
      if (status == FTUN_E_AGAIN) {
        consumer->blocked = true;
        consumer->dispatch_ready = false;
        break;
      }
      if (status != FTUN_OK) return status;
      consumer->input_bytes -= entry->length;
      service->queued_input_bytes -= entry->length;
      status = ftun_buffer_release(&entry->buffer);
      if (status != FTUN_OK) return status;
      entry->length = 0u;
      entry->lease_generation = 0u;
      entry->path_generation = 0u;
      consumer->input_head =
        (consumer->input_head + 1u) % service->input_capacity;
      consumer->input_count--;
      service->queued_inputs--;
      if (consumer->packets_received != SIZE_MAX) consumer->packets_received++;
      ftun_tun_service_packet_progress(consumer);
      dispatched++;
    }
    consumer->dispatch_ready =
      consumer->input_count != 0u && !consumer->blocked;
  }
  service->dispatch_cursor =
    (service->dispatch_cursor + 1u) % service->consumer_capacity;
  return FTUN_OK;
}

static ftun_status_t ftun_tun_service_read(
  ftun_tun_service_t *service, size_t *work)
{
  size_t read_count = 0u;
  while (read_count < service->read_quota) {
    ftun_tun_service_consumer_t *consumer;
    ftun_bytes_t packet;
    size_t length = 0u;
    ftun_status_t status = service->ops.read(
      service->ops.user, service->port, service->input, service->mtu,
      &length);
    if (status == FTUN_E_AGAIN) return FTUN_OK;
    if (status != FTUN_OK) {
      if (status == FTUN_E_IO) service->device_lost = true;
      return status;
    }
    if (length == 0u || length > service->mtu) return FTUN_E_PROTOCOL;
    packet.data = service->input;
    packet.length = length;
    if (service->packets_read != SIZE_MAX) service->packets_read++;
    read_count++;
    (*work)++;
    consumer = ftun_tun_service_route(service, packet);
    if (consumer == NULL) {
      ftun_tun_service_drop(service, NULL);
    } else {
      bool drop = false;
      status = ftun_tun_service_check_packet(
        service, consumer, FTUN_TUN_PACKET_FROM_DEVICE, packet, &drop);
      if (status != FTUN_OK) return status;
      if (!drop) {
        status = ftun_tun_service_deliver(service, consumer, packet);
        if (status != FTUN_OK) return status;
      }
    }
    if (!service->accepting || service->active_leases == 0u) break;
  }
  if (read_count == service->read_quota && service->accepting &&
      service->active_leases != 0u) service->events |= FTUN_EVENT_READ;
  return FTUN_OK;
}

void ftun_tun_service_broadcast(ftun_tun_service_t *service,
                                ftun_tun_service_event_t event,
                                ftun_status_t status)
{
  size_t index;
  for (index = 0u; index < service->consumer_capacity; index++) {
    ftun_tun_service_consumer_t *consumer = &service->consumers[index];
    ftun_tun_lease_t lease = consumer->lease;
    ftun_tun_service_event_fn callback = consumer->consumer.event;
    void *user = consumer->consumer.user;
    if (lease.service == service && callback != NULL) {
      service->callback_depth++;
      callback(user, lease, event, status);
      service->callback_depth--;
    }
  }
}

ftun_status_t ftun_tun_service_run(
  ftun_tun_service_t *service, size_t *out_work)
{
  uint32_t events;
  ftun_status_t status;
  if (out_work != NULL) *out_work = 0u;
  if (service == NULL || out_work == NULL) return FTUN_E_INVALID;
  if (service->callback_depth != 0u) return FTUN_E_AGAIN;
  if (!service->accepting) return FTUN_OK;
  status = ftun_tun_service_dispatch_queued(service, out_work);
  if (status != FTUN_OK) {
    ftun_tun_service_broadcast(service, FTUN_TUN_SERVICE_FAILED, status);
    return status;
  }
  if (service->port == NULL || service->source == NULL) {
    return service->accepting ? FTUN_E_AGAIN : FTUN_OK;
  }
  events = service->events;
  service->events = 0u;
  status = FTUN_OK;
  if ((events & FTUN_EVENT_ERROR) != 0u) service->device_lost = true;
  if (!service->device_lost && (events & FTUN_EVENT_WRITE) != 0u &&
      service->queued_outputs != 0u) {
    status = ftun_tun_service_flush(service, out_work);
  }
  if (!service->device_lost && status == FTUN_OK && (events & FTUN_EVENT_READ) != 0u &&
      service->accepting && service->active_leases != 0u) {
    status = ftun_tun_service_read(service, out_work);
  }
  if (service->device_lost && (status == FTUN_OK || status == FTUN_E_IO)) {
    /* 设备被外部删除或失效不是宿主故障：立即发起重建；重建没有生效时撤销
     * watcher（电平触发的就绪会空转），由 owner 退避重试。 */
    (void)ftun_tun_service_rebuild(service);
    status = FTUN_OK;
    if (service->device_lost && !service->rebuilding && service->source != NULL) {
      service->accepting = false;
      status = ftun_event_source_cancel(&service->source);
    }
    if (status != FTUN_OK) {
      ftun_tun_service_broadcast(service, FTUN_TUN_SERVICE_FAILED, status);
    }
    return status;
  }
  if (status == FTUN_OK && service->source != NULL) {
    status = ftun_tun_service_interests(service);
  }
  if (status != FTUN_OK) {
    ftun_tun_service_broadcast(service, FTUN_TUN_SERVICE_FAILED, status);
  }
  return status;
}
