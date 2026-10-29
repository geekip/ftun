#define _GNU_SOURCE 1

#include "proxy/engine_internal.h"

ftun_status_t ftun_proxy_runtime_flow_slot_acquire(
  ftun_proxy_runtime_t *engine, ftun_proxy_runtime_flow_t **out)
{
  ftun_proxy_runtime_flow_t *flow = NULL;
  ftun_proxy_slot_token_t token;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (engine == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_proxy_slot_pool_acquire(engine->flow_pool,
    (void **)&flow, &token);
  if (status != FTUN_OK) return status;
  flow->slot_token = token;
  flow->client_socket.descriptor = -1;
  flow->remote_socket.descriptor = -1;
  *out = flow;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_flow_slot_release(
  ftun_proxy_runtime_flow_t **flow)
{
  ftun_proxy_runtime_t *engine;
  ftun_proxy_slot_token_t token;
  ftun_status_t status;
  bool tun;
  if (flow == NULL || *flow == NULL || (*flow)->engine == NULL) {
    return FTUN_E_INVALID;
  }
  engine = (*flow)->engine;
  tun = (*flow)->tun;
  if (tun && engine->tun_flow_count == 0u) return FTUN_E_STATE_CORRUPT;
  token = (*flow)->slot_token;
  status = ftun_proxy_slot_pool_release(engine->flow_pool, token, (void **)flow);
  if (status == FTUN_OK && tun) engine->tun_flow_count--;
  return status;
}

ftun_proxy_runtime_flow_t *ftun_proxy_runtime_flow_at(
  ftun_proxy_runtime_t *engine, size_t index)
{
  ftun_proxy_runtime_flow_t *flow = NULL;
  ftun_proxy_slot_token_t token;
  if (engine == NULL || index >= engine->flow_capacity ||
      ftun_proxy_slot_pool_at(engine->flow_pool, index, (void **)&flow,
                              &token) != FTUN_OK) return NULL;
  return flow;
}

ftun_status_t ftun_proxy_runtime_flow_classify(
  ftun_proxy_runtime_flow_t *flow, ftun_proxy_runtime_flow_class_t flow_class)
{
  ftun_proxy_runtime_t *engine;
  if (flow == NULL || !flow->active || flow->engine == NULL ||
      flow_class == FTUN_PROXY_RUNTIME_FLOW_PENDING) return FTUN_E_INVALID;
  if (flow->flow_class == flow_class) return FTUN_OK;
  if (flow->flow_class != FTUN_PROXY_RUNTIME_FLOW_PENDING) {
    return FTUN_E_STATE_CORRUPT;
  }
  engine = flow->engine;
  if (flow_class == FTUN_PROXY_RUNTIME_FLOW_TCP) {
    if (engine->active_tcp_flows >= engine->tcp_capacity) return FTUN_E_LIMIT;
    engine->active_tcp_flows++;
  } else {
    if (engine->active_associations >= engine->association_capacity) {
      return FTUN_E_LIMIT;
    }
    engine->active_associations++;
  }
  flow->flow_class = flow_class;
  return FTUN_OK;
}

void ftun_proxy_runtime_flow_unclassify(ftun_proxy_runtime_flow_t *flow)
{
  if (flow == NULL || flow->engine == NULL) return;
  if (flow->flow_class == FTUN_PROXY_RUNTIME_FLOW_TCP &&
      flow->engine->active_tcp_flows != 0u) {
    flow->engine->active_tcp_flows--;
  } else if (flow->flow_class == FTUN_PROXY_RUNTIME_FLOW_ASSOCIATION &&
             flow->engine->active_associations != 0u) {
    flow->engine->active_associations--;
  }
  flow->flow_class = FTUN_PROXY_RUNTIME_FLOW_PENDING;
}

ftun_proxy_runtime_udp_slot_t *ftun_proxy_runtime_udp_at(
  ftun_proxy_runtime_t *engine, size_t index)
{
  ftun_proxy_runtime_udp_slot_t *slot = NULL;
  ftun_proxy_slot_token_t token;
  if (engine == NULL || index >= engine->udp_capacity ||
      ftun_proxy_slot_pool_at(engine->udp_pool, index, (void **)&slot,
                              &token) != FTUN_OK) return NULL;
  return slot;
}

ftun_proxy_runtime_udp_pending_t *ftun_proxy_runtime_udp_pending_at(
  ftun_proxy_runtime_t *engine, size_t index)
{
  ftun_proxy_runtime_udp_pending_t *pending = NULL;
  ftun_proxy_slot_token_t token;
  if (engine == NULL || index >= engine->udp_capacity ||
      ftun_proxy_slot_pool_at(engine->udp_pending_pool, index,
                              (void **)&pending, &token) != FTUN_OK) {
    return NULL;
  }
  return pending;
}

ftun_status_t ftun_proxy_runtime_object_admit(
  ftun_proxy_runtime_t *engine, ftun_budget_resources_t minimum,
  ftun_budget_t **out_budget, ftun_reservation_t *out_admission)
{
  ftun_budget_usage_t parent_usage;
  ftun_budget_options_t options;
  ftun_budget_t *budget = NULL;
  ftun_reservation_t admission = (ftun_reservation_t){0};
  ftun_status_t status;
  if (out_budget != NULL) *out_budget = NULL;
  if (out_admission != NULL) *out_admission = (ftun_reservation_t){0};
  if (engine == NULL || engine->budget == NULL || out_budget == NULL ||
      out_admission == NULL) return FTUN_E_INVALID;
  status = ftun_budget_get_usage(engine->budget, &parent_usage);
  if (status != FTUN_OK) return status;
  memset(&options, 0, sizeof(options));
  options.limit = parent_usage.limits;
  status = ftun_budget_create_resources(engine->budget, &options, &budget);
  if (status == FTUN_OK) {
    /* 对象仅保留自己的 ready 节点及独占 FD；Pool 等待槽、Event ready、
     * Operation 和 Datagram 发送容量由实际拥有者分别准入。 */
    status = ftun_budget_reserve_resources(budget, minimum, &admission);
  }
  if (status != FTUN_OK) {
    (void)ftun_budget_destroy(&budget);
    return status;
  }
  *out_budget = budget;
  *out_admission = admission;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_object_release(
  ftun_budget_t **budget, ftun_reservation_t *admission)
{
  ftun_status_t status;
  if (budget == NULL || admission == NULL) return FTUN_E_INVALID;
  status = ftun_reservation_release(admission);
  if (status != FTUN_OK) return status;
  return ftun_budget_destroy(budget);
}



void ftun_proxy_runtime_listener_ready(ftun_event_source_t *source,
                                       uint32_t events, void *user)
{
  ftun_proxy_runtime_listener_t *listener = (ftun_proxy_runtime_listener_t *)user;
  if (listener != NULL && listener->source == source) {
    listener->events |= events;
  }
}

void ftun_proxy_runtime_worker_wakeup(void *user)
{
  (void)ftun_event_loop_wakeup((ftun_event_loop_t *)user);
}

void ftun_proxy_runtime_listener_udp_ready(ftun_event_source_t *source,
                                           uint32_t events, void *user)
{
  ftun_proxy_runtime_listener_t *listener = (ftun_proxy_runtime_listener_t *)user;
  if (listener != NULL && listener->udp_source == source) {
    listener->udp_events |= events;
  }
}

void ftun_proxy_runtime_flow_schedule(ftun_proxy_runtime_flow_t *flow)
{
  ftun_proxy_runtime_t *engine;
  if (flow == NULL || !flow->active) return;
  if (flow->driving) {
    flow->reschedule = true;
    return;
  }
  if (flow->ready_queued) return;
  engine = flow->engine;
  if (engine == NULL) return;
  flow->ready_next = NULL;
  if (engine->ready_flow_tail != NULL) {
    engine->ready_flow_tail->ready_next = flow;
  } else {
    engine->ready_flow_head = flow;
  }
  engine->ready_flow_tail = flow;
  flow->ready_queued = true;
}

void ftun_proxy_runtime_relay_progress(void *user)
{
  ftun_proxy_runtime_flow_schedule((ftun_proxy_runtime_flow_t *)user);
}

void ftun_proxy_runtime_flow_client_ready(ftun_event_source_t *source,
                                          uint32_t events, void *user)
{
  ftun_proxy_runtime_flow_t *flow = (ftun_proxy_runtime_flow_t *)user;
  if (flow != NULL && flow->active && flow->client_source == source) {
    flow->client_events |= events;
    ftun_proxy_runtime_flow_schedule(flow);
  }
}

void ftun_proxy_runtime_flow_remote_ready(ftun_event_source_t *source,
                                          uint32_t events, void *user)
{
  ftun_proxy_runtime_flow_t *flow = (ftun_proxy_runtime_flow_t *)user;
  if (flow != NULL && flow->active && flow->remote_source == source) {
    flow->remote_events |= events;
    ftun_proxy_runtime_flow_schedule(flow);
  }
}

void ftun_proxy_runtime_udp_unschedule(ftun_proxy_runtime_udp_slot_t *slot)
{
  ftun_proxy_runtime_t *engine;
  if (slot == NULL || !slot->ready_queued || slot->engine == NULL) return;
  engine = slot->engine;
  if (slot->ready_previous != NULL) {
    slot->ready_previous->ready_next = slot->ready_next;
  } else {
    engine->ready_udp_head = slot->ready_next;
  }
  if (slot->ready_next != NULL) {
    slot->ready_next->ready_previous = slot->ready_previous;
  } else {
    engine->ready_udp_tail = slot->ready_previous;
  }
  slot->ready_previous = NULL;
  slot->ready_next = NULL;
  slot->ready_queued = false;
}

void ftun_proxy_runtime_udp_schedule(ftun_proxy_runtime_udp_slot_t *slot)
{
  ftun_proxy_runtime_t *engine;
  if (slot == NULL || !slot->active || slot->ready_queued ||
      slot->engine == NULL) return;
  engine = slot->engine;
  slot->ready_previous = engine->ready_udp_tail;
  slot->ready_next = NULL;
  if (engine->ready_udp_tail != NULL) {
    engine->ready_udp_tail->ready_next = slot;
  } else {
    engine->ready_udp_head = slot;
  }
  engine->ready_udp_tail = slot;
  slot->ready_queued = true;
}

void ftun_proxy_runtime_udp_path_notify(ftun_path_t *path, uint32_t events,
  ftun_error_t error, void *user)
{
  ftun_proxy_runtime_udp_slot_t *slot = user;
  (void)path;
  if ((events & FTUN_PATH_ERROR) != 0u && error.status != FTUN_OK && error.status != FTUN_E_AGAIN) {
    slot->failure = error.status;
  }
  ftun_proxy_runtime_udp_schedule(slot);
}

bool ftun_proxy_runtime_protocol_pending(ftun_proxy_runtime_flow_t *flow)
{
  ftun_inbound_adapter_info_t info;
  return flow->protocol != NULL &&
    ftun_inbound_adapter_get_info(flow->protocol, &info) == FTUN_OK && info.reply_pending;
}

ftun_status_t ftun_proxy_runtime_flow_interests(
  ftun_proxy_runtime_flow_t *flow, uint32_t *client, uint32_t *remote)
{
  ftun_relay_usage_t usage;
  ftun_inbound_adapter_info_t protocol = {0};
  ftun_status_t status;
  if (flow == NULL || client == NULL || remote == NULL) return FTUN_E_INVALID;
  *client = FTUN_EVENT_ERROR;
  *remote = FTUN_EVENT_ERROR;
  if (flow->protocol != NULL) {
    status = ftun_inbound_adapter_get_info(flow->protocol, &protocol);
    if (status != FTUN_OK) return status;
  }
  if (protocol.reply_pending) {
    if (!protocol.write_pending) *client |= FTUN_EVENT_WRITE;
  } else if (flow->state == FTUN_PROXY_RUNTIME_FLOW_HANDSHAKE ||
             flow->state == FTUN_PROXY_RUNTIME_FLOW_UDP_ASSOCIATE) {
    *client |= FTUN_EVENT_READ;
  }
  if (flow->state != FTUN_PROXY_RUNTIME_FLOW_RELAY || flow->relay == NULL ||
      protocol.reply_pending) {
    return FTUN_OK;
  }
  status = ftun_relay_get_usage(flow->relay, &usage);
  if (status != FTUN_OK) return status;
  if (flow->preread_length != 0u) {
    *remote |= FTUN_EVENT_WRITE;
    return FTUN_OK;
  }
  if (!flow->tun) *client |= usage.left_interests;
  *remote |= usage.right_interests;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_flow_update_sources(ftun_proxy_runtime_flow_t *flow)
{
  uint32_t client;
  uint32_t remote;
  ftun_status_t status = ftun_proxy_runtime_flow_interests(flow, &client, &remote);
  if (status != FTUN_OK) return status;
  if (flow->client_source != NULL) {
    status = ftun_event_io_update(flow->client_source, client);
  }
  if (status == FTUN_OK && flow->remote_source != NULL) {
    status = ftun_event_io_update(flow->remote_source, remote);
  }
  return status;
}

ftun_status_t ftun_proxy_runtime_stream_read(void *user, void *buffer,
                                              size_t capacity,
                                              size_t *out_length)
{
  ftun_proxy_runtime_socket_stream_t *socket_stream =
    (ftun_proxy_runtime_socket_stream_t *)user;
  ptrdiff_t length;
  ftun_status_t io_status;
  if (out_length != NULL) *out_length = 0u;
  if (socket_stream == NULL || socket_stream->descriptor < 0 ||
      buffer == NULL || capacity == 0u || out_length == NULL) {
    return FTUN_E_INVALID;
  }
  length = ftun_socket_stream_receive(socket_stream->descriptor, buffer, capacity, &io_status);
  if (length > 0) {
    *out_length = (size_t)length;
    return FTUN_OK;
  }
  if (length == 0) return FTUN_E_EOF;
  return io_status;
}

ftun_status_t ftun_proxy_runtime_stream_write_start(
  void *user, ftun_stream_write_token_t write,
  const ftun_buffer_slice_t *slice,
  size_t *accepted)
{
  ftun_proxy_runtime_socket_stream_t *socket_stream =
    (ftun_proxy_runtime_socket_stream_t *)user;
  ftun_bytes_t bytes;
  ptrdiff_t length;
  ftun_status_t io_status;
  if (accepted != NULL) *accepted = 0u;
  if (socket_stream == NULL || socket_stream->descriptor < 0 ||
      socket_stream->pending.stream != NULL ||
      write.stream == NULL || slice == NULL || accepted == NULL ||
      ftun_buffer_slice_data(slice, &bytes) != FTUN_OK ||
      bytes.length == 0u) return FTUN_E_INVALID;
  length = ftun_socket_stream_send(socket_stream->descriptor, bytes.data, bytes.length, &io_status);
  if (length < 0) return io_status;
  if (length == 0) return FTUN_E_IO;
  socket_stream->pending = write;
  *accepted = (size_t)length;
  ftun_proxy_runtime_flow_schedule(socket_stream->flow);
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_stream_write_cancel(
  void *user, ftun_stream_write_token_t write)
{
  ftun_proxy_runtime_socket_stream_t *socket_stream =
    (ftun_proxy_runtime_socket_stream_t *)user;
  if (socket_stream == NULL ||
      socket_stream->pending.stream != write.stream ||
      socket_stream->pending.slot != write.slot ||
      socket_stream->pending.generation != write.generation) {
    return FTUN_E_STALE;
  }
  memset(&socket_stream->pending, 0, sizeof(socket_stream->pending));
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_stream_shutdown(void *user)
{
  ftun_proxy_runtime_socket_stream_t *socket_stream =
    (ftun_proxy_runtime_socket_stream_t *)user;
  if (socket_stream == NULL || socket_stream->descriptor < 0) {
    return FTUN_E_INVALID;
  }
  if (socket_stream->write_shutdown) return FTUN_OK;
  ftun_status_t status = ftun_socket_shutdown_write(socket_stream->descriptor);
  if (status != FTUN_OK) return status;
  socket_stream->write_shutdown = true;
  return FTUN_OK;
}

void ftun_proxy_runtime_stream_destroy(void *user)
{
  ftun_proxy_runtime_socket_stream_t *socket_stream =
    (ftun_proxy_runtime_socket_stream_t *)user;
  if (socket_stream == NULL) return;
  if (socket_stream->descriptor >= 0) {
    (void)ftun_socket_close((ftun_native_socket_t)(unsigned int)socket_stream->descriptor);
  }
  socket_stream->descriptor = -1;
  memset(&socket_stream->pending, 0, sizeof(socket_stream->pending));
}

ftun_status_t ftun_proxy_runtime_stream_complete_pending(
  ftun_proxy_runtime_socket_stream_t *socket_stream)
{
  ftun_stream_write_token_t pending;
  ftun_error_t result;
  if (socket_stream == NULL || socket_stream->pending.stream == NULL) {
    return FTUN_OK;
  }
  pending = socket_stream->pending;
  memset(&socket_stream->pending, 0, sizeof(socket_stream->pending));
  memset(&result, 0, sizeof(result));
  result.status = FTUN_OK;
  return ftun_stream_write_complete(pending, result);
}

void ftun_proxy_runtime_stream_completed(ftun_operation_t *operation,
                                         ftun_error_t error, void *user)
{
  ftun_proxy_runtime_flow_t *flow = (ftun_proxy_runtime_flow_t *)user;
  (void)operation;
  if (flow != NULL && error.status != FTUN_OK &&
      error.status != FTUN_E_CANCELLED) ftun_proxy_runtime_flow_close(flow,
                                                               error.status);
}

void ftun_proxy_runtime_stream_progress(void *user)
{
  ftun_proxy_runtime_flow_schedule((ftun_proxy_runtime_flow_t *)user);
}

ftun_status_t ftun_proxy_runtime_stream_create(
  ftun_proxy_runtime_flow_t *flow, ftun_proxy_runtime_socket_stream_t *socket_stream,
  int descriptor, ftun_stream_t **out)
{
  ftun_stream_options_t options;
  ftun_stream_backend_t backend;
  socket_stream->flow = flow;
  socket_stream->descriptor = descriptor;
  socket_stream->write_shutdown = false;
  memset(&options, 0, sizeof(options));
  options.budget = flow->budget;
  options.operations = flow->engine->operations;
  options.max_pending_writes = 16u;
  options.max_pending_bytes = 256u * 1024u;
  options.completion = ftun_proxy_runtime_stream_completed;
  options.completion_user = flow;
  options.progress = ftun_proxy_runtime_stream_progress;
  options.progress_user = flow;
  memset(&backend, 0, sizeof(backend));
  backend.read = ftun_proxy_runtime_stream_read;
  backend.write_start = ftun_proxy_runtime_stream_write_start;
  backend.write_cancel = ftun_proxy_runtime_stream_write_cancel;
  backend.shutdown_write = ftun_proxy_runtime_stream_shutdown;
  backend.destroy = ftun_proxy_runtime_stream_destroy;
  backend.context = socket_stream;
  return ftun_stream_create(&options, &backend, out);
}

const ftun_config_inbound_t *ftun_proxy_runtime_inbound_config(
  const ftun_config_t *config, const ftun_proxy_runtime_listener_t *listener)
{
  size_t index;
  for (index = 0u; index < ftun_config_inbound_count(config); index++) {
    if (ftun_config_inbounds(config)[index].name != NULL &&
        strcmp(ftun_config_inbounds(config)[index].name, listener->name) == 0) {
      return &ftun_config_inbounds(config)[index];
    }
  }
  return NULL;
}

const ftun_config_inbound_t *ftun_proxy_runtime_inbound_by_id(
  const ftun_config_t *config, uint32_t inbound_id)
{
  if (config == NULL || inbound_id == 0u ||
      (size_t)inbound_id > ftun_config_inbound_count(config)) return NULL;
  return &ftun_config_inbounds(config)[inbound_id - 1u];
}

ftun_status_t ftun_proxy_runtime_build_inbound_spec(
  ftun_proxy_runtime_flow_t *flow, const ftun_config_inbound_t *config,
  ftun_inbound_spec_t *spec, ftun_inbound_user_t **out_users,
  ftun_reservation_t *out_reservation)
{
  ftun_inbound_user_t *users = NULL;
  ftun_status_t status;
  size_t index;
  if (out_users != NULL) *out_users = NULL;
  if (out_reservation != NULL) *out_reservation = (ftun_reservation_t){0};
  if (flow == NULL || config == NULL || spec == NULL || out_users == NULL ||
      out_reservation == NULL) {
    return FTUN_E_INVALID;
  }
  if (config->user_count != 0u) {
    if (config->user_count > SIZE_MAX / sizeof(*users)) return FTUN_E_LIMIT;
    status = ftun_budget_reserve(flow->budget,
      config->user_count * sizeof(*users), out_reservation);
    if (status != FTUN_OK) return status;
    users = (ftun_inbound_user_t *)calloc(config->user_count, sizeof(*users));
    if (users == NULL) {
      (void)ftun_reservation_release(out_reservation);
      return FTUN_E_LIMIT;
    }
    for (index = 0u; index < config->user_count; index++) {
      users[index].username.data = (const uint8_t *)config->users[index].name;
      users[index].username.length = strlen(config->users[index].name);
      users[index].password.data =
        (const uint8_t *)config->users[index].password;
      users[index].password.length = strlen(config->users[index].password);
    }
  }
  memset(spec, 0, sizeof(*spec));
  spec->budget = flow->budget;
  spec->kind = config->kind == FTUN_CONFIG_INBOUND_MIXED
    ? FTUN_INBOUND_MIXED : FTUN_INBOUND_SOCKS5;
  spec->generation = flow->engine->generation;
  spec->id = flow->listener->inbound_id;
  spec->name.data = config->name;
  spec->name.length = strlen(config->name);
  spec->tcp = true;
  spec->udp = config->udp;
  spec->users = users;
  spec->user_count = config->user_count;
  *out_users = users;
  return FTUN_OK;
}

void ftun_proxy_runtime_flow_deadline_ready(ftun_event_source_t *source,
                                             uint32_t events, void *user)
{
  ftun_proxy_runtime_flow_t *flow = (ftun_proxy_runtime_flow_t *)user;
  if (flow == NULL || !flow->active || flow->deadline_source != source ||
      (events & FTUN_EVENT_TIMER) == 0u) return;
  ftun_proxy_runtime_flow_close(flow, FTUN_E_TIMEOUT);
}

ftun_status_t ftun_proxy_runtime_flow_deadline_arm(
  ftun_proxy_runtime_flow_t *flow, uint64_t deadline_ms)
{
  ftun_status_t status;
  if (flow == NULL || !flow->active || deadline_ms == 0u) {
    return FTUN_E_INVALID;
  }
  status = ftun_event_source_cancel(&flow->deadline_source);
  if (status != FTUN_OK) return status;
  return ftun_event_timer_start(flow->engine->loop, deadline_ms,
    ftun_proxy_runtime_flow_deadline_ready, flow, &flow->deadline_source);
}

ftun_status_t ftun_proxy_runtime_protocol_update(ftun_proxy_runtime_flow_t *flow)
{
  ftun_inbound_adapter_info_t info;
  ftun_status_t status;
  if (flow->protocol == NULL) return FTUN_OK;
  status = ftun_inbound_adapter_get_info(flow->protocol, &info);
  if (status != FTUN_OK) return status;
  if (info.deadline_ms == flow->protocol_deadline_ms) return FTUN_OK;
  status = info.deadline_ms == 0u ? ftun_event_source_cancel(&flow->deadline_source)
    : ftun_proxy_runtime_flow_deadline_arm(flow, info.deadline_ms);
  if (status == FTUN_OK) flow->protocol_deadline_ms = info.deadline_ms;
  return status;
}

ftun_status_t ftun_proxy_runtime_preread_release(ftun_proxy_runtime_flow_t *flow)
{
  if (flow == NULL) return FTUN_E_INVALID;
  free(flow->preread);
  flow->preread = NULL;
  flow->preread_capacity = 0u;
  flow->preread_offset = 0u;
  flow->preread_length = 0u;
  return ftun_reservation_release(&flow->preread_reservation);
}

ftun_status_t ftun_proxy_runtime_preread_ensure(ftun_proxy_runtime_flow_t *flow,
                                                size_t required)
{
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  uint8_t *storage;
  size_t capacity;
  ftun_status_t status;
  if (flow == NULL || required > FTUN_PROXY_RUNTIME_PREREAD_BYTES) {
    return FTUN_E_LIMIT;
  }
  if (required > flow->preread_capacity) {
    capacity = flow->preread_capacity == 0u ? 4096u : flow->preread_capacity;
    while (capacity < required && capacity < FTUN_PROXY_RUNTIME_PREREAD_BYTES) {
      capacity = capacity > FTUN_PROXY_RUNTIME_PREREAD_BYTES / 2u
        ? FTUN_PROXY_RUNTIME_PREREAD_BYTES : capacity * 2u;
    }
    status = ftun_budget_reserve(flow->budget, capacity,
                                 &reservation);
    if (status != FTUN_OK) return status;
    storage = (uint8_t *)malloc(capacity);
    if (storage == NULL) {
      (void)ftun_reservation_release(&reservation);
      return FTUN_E_LIMIT;
    }
    if (flow->preread_length != 0u) {
      memcpy(storage, flow->preread, flow->preread_length);
    }
    free(flow->preread);
    if (ftun_reservation_release(&flow->preread_reservation) != FTUN_OK) {
      free(storage);
      (void)ftun_reservation_release(&reservation);
      return FTUN_E_STATE_CORRUPT;
    }
    flow->preread = storage;
    flow->preread_reservation = reservation;
    flow->preread_capacity = capacity;
  }
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_copy_preread(ftun_proxy_runtime_flow_t *flow,
                                               ftun_bytes_t bytes)
{
  size_t source_offset = 0u;
  bool aliases_preread = false;
  ftun_status_t status;
  if (flow == NULL || (bytes.length != 0u && bytes.data == NULL) ||
      bytes.length > FTUN_PROXY_RUNTIME_PREREAD_BYTES) return FTUN_E_LIMIT;
  if (flow->preread != NULL && bytes.data != NULL) {
    uintptr_t source = (uintptr_t)bytes.data;
    uintptr_t begin = (uintptr_t)flow->preread;
    if (source >= begin && source - begin <= flow->preread_capacity) {
      source_offset = (size_t)(source - begin);
      aliases_preread = bytes.length <=
        flow->preread_capacity - source_offset;
    }
  }
  status = ftun_proxy_runtime_preread_ensure(flow, bytes.length);
  if (status != FTUN_OK) return status;
  if (aliases_preread) bytes.data = flow->preread + source_offset;
  if (bytes.length != 0u) memmove(flow->preread, bytes.data, bytes.length);
  flow->preread_offset = 0u;
  flow->preread_length = bytes.length;
  return FTUN_OK;
}

void ftun_proxy_runtime_preread_written(ftun_operation_t *operation,
  ftun_error_t error, void *user)
{
  ftun_proxy_runtime_flow_t *flow = (ftun_proxy_runtime_flow_t *)user;
  (void)operation;
  flow->preread_operation = NULL;
  flow->preread_status = error.status;
  ftun_proxy_runtime_flow_schedule(flow);
}

ftun_status_t ftun_proxy_runtime_flush_preread(ftun_proxy_runtime_flow_t *flow)
{
  ftun_status_t status;
  ftun_buffer_slice_t remaining;
  size_t accepted = 0u;
  if (flow->preread_operation != NULL) return FTUN_E_AGAIN;
  if (flow->preread_status != FTUN_OK) return flow->preread_status;
  if (flow->preread_offset == flow->preread_length) {
    status = ftun_buffer_slice_release(&flow->preread_slice);
    if (status != FTUN_OK) return status;
    return ftun_proxy_runtime_preread_release(flow);
  }
  if (flow->preread_slice.owner == NULL) {
    ftun_buffer_t *buffer = NULL;
    uint8_t *data;
    size_t capacity;
    status = ftun_buffer_acquire(flow->budget, flow->preread_length, &buffer);
    if (status != FTUN_OK) return status;
    status = ftun_buffer_data(buffer, &data, &capacity);
    if (status == FTUN_OK) {
      memcpy(data, flow->preread, flow->preread_length);
      status = ftun_buffer_slice(buffer, 0u, flow->preread_length, &flow->preread_slice);
    }
    (void)ftun_buffer_release(&buffer);
    if (status != FTUN_OK) return status;
  }
  remaining = flow->preread_slice;
  remaining.offset += flow->preread_offset;
  remaining.length -= flow->preread_offset;
  status = ftun_stream_write_ref_with_completion(flow->remote, &remaining,
    ftun_proxy_runtime_preread_written, flow, &accepted, &flow->preread_operation);
  if (status == FTUN_OK) flow->preread_offset += accepted;
  return status == FTUN_OK ? FTUN_E_AGAIN : status;
}

ftun_status_t ftun_proxy_runtime_runtime_for_flow(
  ftun_proxy_runtime_flow_t *flow, ftun_runtime_t **out_runtime,
  const ftun_config_t **out_config)
{
  ftun_runtime_t *runtime = NULL;
  ftun_runtime_info_t info;
  ftun_status_t status;
  if (out_runtime != NULL) *out_runtime = NULL;
  if (out_config != NULL) *out_config = NULL;
  if (flow == NULL || out_runtime == NULL || out_config == NULL) {
    return FTUN_E_INVALID;
  }
  status = ftun_runtime_active_acquire(flow->engine->core, &runtime);
  if (status == FTUN_OK) status = ftun_runtime_get_info(runtime, &info);
  if (status == FTUN_OK && info.generation != flow->engine->generation) {
    status = FTUN_E_STALE;
  }
  if (status == FTUN_OK) status = ftun_runtime_config(runtime, out_config);
  if (status != FTUN_OK) {
    (void)ftun_runtime_release(&runtime);
    return status;
  }
  *out_runtime = runtime;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_leaf(
  ftun_proxy_runtime_t *engine, const ftun_runtime_t *runtime,
  const ftun_config_t *config,
  uint32_t requested, uint64_t generation, ftun_outbound_leaf_t *leaf,
  const ftun_config_outbound_t **out_config)
{
  ftun_group_choice_t choice;
  uint32_t id = requested;
  size_t index;
  ftun_status_t status;
  if (out_config != NULL) *out_config = NULL;
  memset(leaf, 0, sizeof(*leaf));
  if (requested >= FTUN_OUTBOUND_ID_NAMED_BASE) {
    index = (size_t)(requested - FTUN_OUTBOUND_ID_NAMED_BASE);
    if (index >= ftun_config_outbound_count(config)) return FTUN_E_INVALID;
    if (ftun_config_outbounds(config)[index].kind != FTUN_CONFIG_OUTBOUND_SOCKS5) {
      if (ftun_config_outbounds(config)[index].kind == FTUN_CONFIG_OUTBOUND_URL_TEST) {
        ftun_proxy_runtime_health_consume(engine, requested);
      }
      status = ftun_group_expand(runtime, requested, &choice);
      if (status != FTUN_OK) return status;
      id = choice.leaf_id;
    }
  }
  leaf->generation = generation;
  leaf->id = id;
  leaf->supports_tcp = true;
  leaf->supports_udp = true;
  if (id == FTUN_OUTBOUND_ID_DIRECT) {
    leaf->kind = FTUN_OUTBOUND_LEAF_DIRECT;
  } else if (id == FTUN_OUTBOUND_ID_REJECT) {
    leaf->kind = FTUN_OUTBOUND_LEAF_REJECT;
  } else {
    index = (size_t)(id - FTUN_OUTBOUND_ID_NAMED_BASE);
    if (index >= ftun_config_outbound_count(config) ||
        ftun_config_outbounds(config)[index].kind != FTUN_CONFIG_OUTBOUND_SOCKS5) {
      return FTUN_E_STATE_CORRUPT;
    }
    leaf->kind = FTUN_OUTBOUND_LEAF_SOCKS5;
    leaf->supports_udp = ftun_config_outbounds(config)[index].udp;
    if (out_config != NULL) *out_config = &ftun_config_outbounds(config)[index];
  }
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_session_start_metadata(
  ftun_proxy_runtime_flow_t *flow, const ftun_metadata_t *input);
ftun_status_t ftun_proxy_runtime_route_open(ftun_proxy_runtime_flow_t *flow);
ftun_status_t ftun_proxy_runtime_start_real_resolution(
  ftun_proxy_runtime_flow_t *flow, ftun_resolve_request_t *request);
ftun_status_t ftun_proxy_runtime_resolve_async(
  ftun_proxy_runtime_t *engine, ftun_budget_t *budget,
  const ftun_config_t *config, ftun_resolver_scope_t *scope,
  ftun_string_t domain, bool bootstrap_only,
  ftun_system_resolve_completion_fn completion, void *user,
  ftun_operation_t **out);

#if defined(FTUN_HAVE_MODULE_FAKEIP)
ftun_status_t ftun_proxy_runtime_restore_fakeip_to(
  ftun_proxy_runtime_t *engine, ftun_metadata_t *metadata,
  char *domain_storage, size_t domain_capacity)
{
  ftun_fakeip_handle_t *handle = NULL;
  ftun_fakeip_service_info_t info;
  ftun_string_t domain;
  uint32_t address;
  uint32_t value;
  ftun_status_t status;
  if (engine == NULL || metadata == NULL || domain_storage == NULL ||
      domain_capacity == 0u || engine->fakeip == NULL ||
      metadata->original_target.kind != FTUN_ADDRESS_IPV4) return FTUN_OK;
  value = ((uint32_t)metadata->original_target.address[0] << 24u) |
          ((uint32_t)metadata->original_target.address[1] << 16u) |
          ((uint32_t)metadata->original_target.address[2] << 8u) |
          (uint32_t)metadata->original_target.address[3];
  status = ftun_fakeip_service_get_info(engine->fakeip, &info);
  if (status != FTUN_OK) return status;
  if (value < info.first_address || value >= info.end_address_exclusive) {
    return FTUN_OK;
  }
  status = ftun_fakeip_reverse(engine->fakeip, value, &handle);
  if (status == FTUN_E_EOF) return FTUN_E_REJECTED;
  if (status != FTUN_OK) return status;
  status = ftun_fakeip_handle_get(handle, &address, &domain);
  if (status == FTUN_OK && (address != value ||
      domain.length >= domain_capacity)) {
    status = FTUN_E_STATE_CORRUPT;
  }
  if (status == FTUN_OK) {
    memcpy(domain_storage, domain.data, domain.length);
    domain_storage[domain.length] = '\0';
    metadata->known_fields |= FTUN_META_DOMAIN;
    metadata->domain.data = domain_storage;
    metadata->domain.length = domain.length;
    metadata->domain_source = FTUN_DOMAIN_FAKEIP;
    metadata->original_is_fake = true;
  }
  if (ftun_fakeip_handle_release(&handle) != FTUN_OK && status == FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
  }
  return status;
}

#else
ftun_status_t ftun_proxy_runtime_restore_fakeip_to(
  ftun_proxy_runtime_t *engine, ftun_metadata_t *metadata,
  char *domain_storage, size_t domain_capacity)
{
  (void)engine;
  (void)metadata;
  (void)domain_storage;
  (void)domain_capacity;
  return FTUN_OK;
}

#endif

#if defined(FTUN_HAVE_MODULE_TUN)
ftun_status_t ftun_proxy_runtime_restore_fakeip(ftun_proxy_runtime_flow_t *flow,
                                                ftun_metadata_t *metadata)
{
  if (flow == NULL) return FTUN_E_INVALID;
  return ftun_proxy_runtime_restore_fakeip_to(flow->engine, metadata,
    flow->sniff_domain, sizeof(flow->sniff_domain));
}
#endif

ftun_status_t ftun_proxy_runtime_session_start(
  ftun_proxy_runtime_flow_t *flow, const ftun_endpoint_t *requested_target)
{
  ftun_metadata_t metadata;
  ftun_status_t status;
  if (flow == NULL || requested_target == NULL) return FTUN_E_INVALID;
  status = ftun_proxy_runtime_flow_classify(
    flow, FTUN_PROXY_RUNTIME_FLOW_TCP);
  if (status != FTUN_OK) return status;
  memset(&metadata, 0, sizeof(metadata));
  metadata.known_fields = FTUN_META_PORT | FTUN_META_NETWORK;
  metadata.network = 1u;
  metadata.original_target = *requested_target;
  if (requested_target->kind == FTUN_ADDRESS_DOMAIN) {
    metadata.known_fields |= FTUN_META_DOMAIN;
    metadata.domain = requested_target->domain;
    metadata.domain_source = FTUN_DOMAIN_EXPLICIT;
  }
  return ftun_proxy_runtime_session_start_metadata(flow, &metadata);
}

void ftun_proxy_runtime_flow_close(ftun_proxy_runtime_flow_t *flow,
                                   ftun_status_t reason)
{
  ftun_error_t error;
  if (flow == NULL || !flow->active ||
      flow->state == FTUN_PROXY_RUNTIME_FLOW_QUARANTINED) return;
  /* A protocol-level failure reply owns the close sequence.  Keep the flow
   * alive until that bounded reply is drained; hard transport failures and
   * timeouts still tear it down immediately. */
  ftun_inbound_adapter_info_t protocol = {0};
  if (flow->protocol != NULL) (void)ftun_inbound_adapter_get_info(flow->protocol, &protocol);
  if (protocol.close_after_reply && protocol.reply_pending &&
      reason != FTUN_E_IO && reason != FTUN_E_EOF &&
      reason != FTUN_E_TIMEOUT && reason != FTUN_E_CANCELLED) {
    ftun_proxy_runtime_flow_schedule(flow);
    return;
  }
  flow->state = FTUN_PROXY_RUNTIME_FLOW_CLOSING;
#if defined(FTUN_HAVE_MODULE_TUN)
  if (flow->tun && flow->client != NULL && flow->engine->tun_ingress != NULL) {
    (void)ftun_tun_ingress_abort_stream(flow->engine->tun_ingress,
                                        flow->client);
  }
#endif
  if (flow->relay != NULL) (void)ftun_relay_stop(flow->relay);
  if (flow->session != NULL) {
    memset(&error, 0, sizeof(error));
    error.status = reason == FTUN_OK ? FTUN_E_CANCELLED : reason;
    (void)ftun_session_finish(flow->session, error);
  } else if (flow->open_operation != NULL) {
    (void)ftun_operation_cancel(flow->open_operation);
  }
  ftun_proxy_runtime_flow_schedule(flow);
}

ftun_status_t ftun_proxy_runtime_protocol_finish(
  ftun_proxy_runtime_flow_t *flow, ftun_status_t downstream,
  const ftun_endpoint_t *bound)
{
  ftun_status_t status;
  if (flow->tun) return FTUN_OK;
  status = ftun_inbound_adapter_finish(flow->protocol, downstream, bound);
  if (status == FTUN_OK) status = ftun_proxy_runtime_protocol_update(flow);
  return status;
}

/* 下游失败不等于客户端传输失败：先排空有界协议错误回复。 */
void ftun_proxy_runtime_downstream_failed(ftun_proxy_runtime_flow_t *flow,
  ftun_status_t failure)
{
  if (flow->state != FTUN_PROXY_RUNTIME_FLOW_CLOSING &&
      ftun_proxy_runtime_protocol_finish(flow, failure, NULL) == FTUN_OK &&
      ftun_proxy_runtime_protocol_pending(flow)) {
    ftun_proxy_runtime_flow_schedule(flow);
    return;
  }
  ftun_proxy_runtime_flow_close(flow, failure);
}

ftun_status_t ftun_proxy_runtime_relay_ready(ftun_proxy_runtime_flow_t *flow,
                                              int descriptor)
{
  const ftun_relay_options_t relay_options = {
    FTUN_RELAY_DEFAULT_HIGH_WATER,
    FTUN_RELAY_DEFAULT_LOW_WATER,
    FTUN_RELAY_DEFAULT_MAX_WORK
  };
  ftun_endpoint_t bound;
  ftun_status_t status;
  memset(&bound, 0, sizeof(bound));
  bound.kind = FTUN_ADDRESS_IPV4;
  (void)ftun_socket_name(descriptor, &bound);
  status = ftun_proxy_runtime_stream_create(flow, &flow->remote_socket, descriptor,
                                     &flow->remote);
  if (status != FTUN_OK) {
    (void)ftun_socket_close((ftun_native_socket_t)(unsigned int)descriptor);
    flow->remote_socket.descriptor = -1;
    return status;
  }
  status = ftun_relay_start_with_pool_options(
    flow->engine->core, flow->client, flow->remote, flow->engine->relay_pool,
    &relay_options, ftun_proxy_runtime_relay_progress, flow, &flow->relay);
  if (status == FTUN_OK && flow->session != NULL) {
    status = ftun_session_transition(flow->session,
                                     FTUN_SESSION_RELAYING, NULL);
  }
  if (status == FTUN_OK) status = ftun_proxy_runtime_protocol_finish(flow, FTUN_OK,
                                                               &bound);
  if (status != FTUN_OK) return status;
  flow->state = FTUN_PROXY_RUNTIME_FLOW_RELAY;
  flow->last_activity_ms = flow->engine->round_ms;
  {
    uint32_t client_interests;
    uint32_t remote_interests;
    status = ftun_proxy_runtime_flow_interests(flow, &client_interests,
                                        &remote_interests);
    if (status == FTUN_OK) {
      status = ftun_event_io_start(flow->engine->loop,
        (ftun_native_socket_t)(unsigned int)descriptor, remote_interests,
        ftun_proxy_runtime_flow_remote_ready, flow, &flow->remote_source);
    }
    if (status == FTUN_OK && flow->client_source != NULL) {
      status = ftun_event_io_update(flow->client_source, client_interests);
    }
  }
  if (status == FTUN_OK) ftun_proxy_runtime_flow_schedule(flow);
  return status;
}

ftun_status_t ftun_proxy_runtime_operation_complete(ftun_proxy_runtime_flow_t *flow,
  ftun_operation_t *operation, ftun_error_t error)
{
  ftun_inbound_adapter_info_t info;
  if (flow->protocol != NULL && flow->state != FTUN_PROXY_RUNTIME_FLOW_CLOSING &&
      ftun_inbound_adapter_get_info(flow->protocol, &info) == FTUN_OK && info.waiting_downstream) {
    return ftun_session_operation_complete_for_reply(flow->session, operation, error);
  }
  return ftun_session_operation_complete(flow->session, operation, error);
}

void ftun_proxy_runtime_path_notify(ftun_path_t *path, uint32_t events,
  ftun_error_t error, void *user)
{
  ftun_proxy_runtime_flow_t *flow = (ftun_proxy_runtime_flow_t *)user;
  (void)path;
  if ((events & FTUN_PATH_READABLE) != 0u) flow->path_events |= FTUN_EVENT_READ;
  if ((events & FTUN_PATH_WRITABLE) != 0u) flow->path_events |= FTUN_EVENT_WRITE;
  if ((events & FTUN_PATH_ERROR) != 0u && error.status != FTUN_OK) {
    ftun_proxy_runtime_flow_close(flow, error.status);
  }
  ftun_proxy_runtime_flow_schedule(flow);
}

ftun_status_t ftun_proxy_runtime_relay_path_ready(ftun_proxy_runtime_flow_t *flow)
{
  const ftun_relay_options_t options = { FTUN_RELAY_DEFAULT_HIGH_WATER,
    FTUN_RELAY_DEFAULT_LOW_WATER, FTUN_RELAY_DEFAULT_MAX_WORK };
  ftun_endpoint_t bound = {0};
  ftun_status_t status = ftun_path_stream(flow->remote_path, &flow->remote);
  if (status == FTUN_OK) {
    status = ftun_path_local_endpoint(flow->remote_path, &bound);
    if (status == FTUN_E_UNSUPPORTED) { bound.kind = FTUN_ADDRESS_IPV4; status = FTUN_OK; }
  }
  if (status == FTUN_OK) status = ftun_relay_start_with_pool_options(flow->engine->core,
    flow->client, flow->remote, flow->engine->relay_pool, &options,
    ftun_proxy_runtime_relay_progress, flow, &flow->relay);
  if (status == FTUN_OK) status = ftun_session_transition(flow->session, FTUN_SESSION_RELAYING, NULL);
  if (status == FTUN_OK) status = ftun_proxy_runtime_protocol_finish(flow, FTUN_OK, &bound);
  if (status != FTUN_OK) return status;
  flow->state = FTUN_PROXY_RUNTIME_FLOW_RELAY;
  flow->last_activity_ms = flow->engine->round_ms;
  /* 早到 READ 已保存在 path_events；普通 Path 等真实提示，避免空探测。 */
  flow->path_events |= FTUN_EVENT_WRITE;
  ftun_proxy_runtime_flow_schedule(flow);
  return FTUN_OK;
}

void ftun_proxy_runtime_direct_path_completed(ftun_operation_t *operation,
  ftun_error_t error, ftun_path_t *path, void *user)
{
  ftun_proxy_runtime_flow_t *flow = (ftun_proxy_runtime_flow_t *)user;
  ftun_status_t status;
  flow->open_operation = NULL;
  flow->remote_path = path;
  status = ftun_proxy_runtime_operation_complete(flow, operation, error);
  if (status == FTUN_OK) status = error.status;
  if (status == FTUN_OK && flow->state == FTUN_PROXY_RUNTIME_FLOW_CLOSING) status = FTUN_E_CANCELLED;
  if (status == FTUN_OK) status = ftun_proxy_runtime_relay_path_ready(flow);
  if (status != FTUN_OK) ftun_proxy_runtime_downstream_failed(flow, status);
}

void ftun_proxy_runtime_socks_completed(
  ftun_operation_t *operation, ftun_error_t error,
  ftun_socks5_connection_t *connection, void *user)
{
  ftun_proxy_runtime_flow_t *flow = (ftun_proxy_runtime_flow_t *)user;
  ftun_status_t status;
  flow->open_operation = NULL;
  flow->proxy_connection = connection;
  status = ftun_proxy_runtime_operation_complete(flow, operation, error);
  if (status == FTUN_OK) status = error.status;
  if (status == FTUN_OK && flow->state == FTUN_PROXY_RUNTIME_FLOW_CLOSING) status = FTUN_E_CANCELLED;
  /* SOCKS5 对象保持通道及通知上下文，直到 Relay 和 Session 释放引用。 */
  if (status == FTUN_OK) status = ftun_socks5_connection_path(connection, &flow->remote_path);
  /* SOCKS5 握手可能只消费回复头，余下应用数据沿用同一次 READ 提示。 */
  if (status == FTUN_OK) flow->path_events |= FTUN_EVENT_READ;
  if (status == FTUN_OK) status = ftun_proxy_runtime_relay_path_ready(flow);
  if (status != FTUN_OK) ftun_proxy_runtime_downstream_failed(flow, status);
}

ftun_status_t ftun_proxy_runtime_system_resolver_path(
  void *user, const ftun_socket_policy_t *protection)
{
  ftun_proxy_runtime_t *engine = (ftun_proxy_runtime_t *)user;
  if (engine == NULL || protection == NULL ||
      (protection->mark == 0u &&
       protection->interface_name.length != 0u)) {
    return FTUN_E_INVALID;
  }
#if defined(FTUN_HAVE_MODULE_TUN)
  /* libc/NSS 隐藏 socket 无法继承 SO_MARK；本机捕获启用时拒绝可能回环的
   * SystemResolver。显式 Bootstrap 和命名 DNS 均使用受保护 socket。 */
  if (engine->tun_auto_route) return FTUN_E_REJECTED;
#endif
  return FTUN_OK;
}

void ftun_proxy_runtime_resolve_completed(
  ftun_operation_t *operation, ftun_error_t error,
  const ftun_system_resolve_result_t *result, void *user)
{
  ftun_proxy_runtime_flow_t *flow = (ftun_proxy_runtime_flow_t *)user;
  ftun_status_t status = FTUN_OK;
  if (flow == NULL || !flow->active || flow->session == NULL) return;
  flow->open_operation = NULL;
  if (error.status == FTUN_OK) {
    if (result == NULL) {
      error.status = FTUN_E_STATE_CORRUPT;
    } else {
      status = ftun_session_store_resolved(flow->session, operation,
        result->addresses, result->address_count);
      if (status != FTUN_OK) error.status = status;
    }
  }
  status = ftun_proxy_runtime_operation_complete(flow, operation, error);
  if (status == FTUN_OK && error.status == FTUN_OK &&
      flow->state != FTUN_PROXY_RUNTIME_FLOW_CLOSING) {
    status = ftun_session_transition(flow->session, FTUN_SESSION_ROUTING,
                                     NULL);
    if (status == FTUN_OK) status = ftun_proxy_runtime_route_open(flow);
  }
  if (status != FTUN_OK || error.status != FTUN_OK) {
    ftun_status_t failure = status != FTUN_OK ? status : error.status;
    ftun_proxy_runtime_downstream_failed(flow, failure);
  }
}

void ftun_proxy_runtime_proxy_resolved(
  ftun_operation_t *operation, ftun_error_t error,
  const ftun_system_resolve_result_t *result, void *user)
{
  ftun_proxy_runtime_flow_t *flow = (ftun_proxy_runtime_flow_t *)user;
  ftun_status_t status = FTUN_OK;
  size_t index;
  if (flow == NULL || !flow->active || flow->session == NULL ||
      flow->open_operation != operation) return;
  flow->open_operation = NULL;
  if (error.status == FTUN_OK && (result == NULL ||
      result->address_count == 0u ||
      result->address_count > FTUN_SESSION_MAX_RESOLVED_IPV4)) {
    error.status = FTUN_E_STATE_CORRUPT;
  }
  for (index = 0u; error.status == FTUN_OK &&
       index < result->address_count; index++) {
    if (result->addresses[index].kind != FTUN_ADDRESS_IPV4) {
      error.status = FTUN_E_UNSUPPORTED;
      break;
    }
    flow->proxy_resolved[index] = result->addresses[index];
    flow->proxy_resolved[index].port = flow->proxy_port;
    flow->proxy_resolved[index].domain.data = NULL;
    flow->proxy_resolved[index].domain.length = 0u;
  }
  if (error.status == FTUN_OK) {
    flow->proxy_resolved_count = result->address_count;
  }
  status = ftun_proxy_runtime_operation_complete(flow, operation, error);
  if (status == FTUN_OK && error.status == FTUN_OK &&
      flow->state != FTUN_PROXY_RUNTIME_FLOW_CLOSING) {
    status = ftun_session_transition(flow->session, FTUN_SESSION_ROUTING,
                                     NULL);
    if (status == FTUN_OK) status = ftun_proxy_runtime_route_open(flow);
  }
  if (status != FTUN_OK || error.status != FTUN_OK) {
    ftun_status_t failure = status != FTUN_OK ? status : error.status;
    ftun_proxy_runtime_downstream_failed(flow, failure);
  }
}

ftun_status_t ftun_proxy_runtime_start_real_resolution(
  ftun_proxy_runtime_flow_t *flow, ftun_resolve_request_t *request)
{
  ftun_operation_t *operation = NULL;
  ftun_status_t status;
  if (flow == NULL || request == NULL || flow->session == NULL) {
    return FTUN_E_INVALID;
  }
  request->query.check_system_path = ftun_proxy_runtime_system_resolver_path;
  request->query.system_path_user = flow->engine;
  request->query.completion = ftun_proxy_runtime_resolve_completed;
  request->query.user = flow;
  status = ftun_resolve_real_with_provider(flow->engine->core, request,
    flow->resolver_scope, &operation);
  if (status != FTUN_OK) return status;
  flow->open_operation = operation;
  status = ftun_session_transition(flow->session, FTUN_SESSION_RESOLVING,
                                   operation);
  if (status != FTUN_OK) {
    (void)ftun_operation_cancel(operation);
    return status;
  }
  flow->open_operation = operation;
  flow->state = FTUN_PROXY_RUNTIME_FLOW_CONNECTING;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_resolve_session(
  ftun_proxy_runtime_flow_t *flow, ftun_string_t server)
{
  ftun_resolve_request_t request;
  ftun_bootstrap_request_t *query = &request.query;
  ftun_endpoint_t bootstrap[FTUN_BOOTSTRAP_MAX_SERVERS];
  const ftun_runtime_t *session_runtime = NULL;
  const ftun_config_t *config = NULL;
  const ftun_metadata_t *stored = NULL;
  size_t index;
  ftun_status_t status;
  if (flow == NULL || flow->session == NULL ||
      (server.length != 0u && server.data == NULL)) return FTUN_E_INVALID;
  memset(&request, 0, sizeof(request));
  status = ftun_session_get_runtime(flow->session, &session_runtime);
  if (status == FTUN_OK) status = ftun_runtime_config(session_runtime,
                                                      &config);
  if (status == FTUN_OK) status = ftun_session_get_metadata(flow->session,
                                                            &stored);
  if (status != FTUN_OK) return status;
  request.session = flow->session;
  request.dns_enabled = ftun_config_resolver(config).enable;
  request.default_server = server;
  query->loop = flow->engine->loop;
  query->operations = flow->engine->operations;
  query->worker = flow->engine->worker;
  query->budget = flow->budget;
  query->domain = stored->domain;
  query->protection.mark = flow->engine->socket_mark;
  query->protection.liveness = flow->engine->liveness;
  status = ftun_monotonic_now(&query->deadline_ms);
  if (status == FTUN_OK && query->deadline_ms <=
      UINT64_MAX - flow->engine->connect_ms) {
    query->deadline_ms += flow->engine->connect_ms;
  } else if (status == FTUN_OK) {
    status = FTUN_E_LIMIT;
  }
  flow->engine->next_dns_query_id++;
  if (flow->engine->next_dns_query_id == 0u) {
    flow->engine->next_dns_query_id++;
  }
  query->query_id = flow->engine->next_dns_query_id;
  for (index = 0u; status == FTUN_OK &&
       index < ftun_config_resolver(config).bootstrap.count; index++) {
    status = ftun_proxy_runtime_parse_bootstrap_endpoint(
      ftun_config_resolver(config).bootstrap.items[index], &bootstrap[index]);
  }
  if (status == FTUN_OK) {
    query->servers = bootstrap;
    query->server_count = ftun_config_resolver(config).bootstrap.count;
  }
  return status == FTUN_OK
    ? ftun_proxy_runtime_start_real_resolution(flow, &request) : status;
}

ftun_status_t ftun_proxy_runtime_session_start_metadata(
  ftun_proxy_runtime_flow_t *flow, const ftun_metadata_t *input)
{
  ftun_runtime_t *runtime = NULL;
  const ftun_config_t *config = NULL;
  const ftun_config_inbound_t *inbound;
  ftun_runtime_info_t runtime_info;
  ftun_metadata_t metadata;
  ftun_status_t status;
  if (flow == NULL || input == NULL) return FTUN_E_INVALID;
  metadata = *input;
  status = ftun_proxy_runtime_runtime_for_flow(flow, &runtime, &config);
  if (status == FTUN_OK) status = ftun_runtime_get_info(runtime,
                                                        &runtime_info);
  inbound = status == FTUN_OK
    ? ftun_proxy_runtime_inbound_config(config, flow->listener) : NULL;
  if (status == FTUN_OK && inbound == NULL) status = FTUN_E_STALE;
  if (status == FTUN_OK) {
    metadata.generation = runtime_info.generation;
    metadata.inbound_id = flow->listener->inbound_id;
    status = ftun_path_provider_scope(flow->engine->path_provider, runtime_info.generation,
      &flow->path_scope);
    if (status == FTUN_OK) status = ftun_resolver_provider_scope(
      flow->engine->resolver_provider, runtime_info.generation, &flow->resolver_scope);
    if (status == FTUN_OK) status = ftun_session_submit(flow->engine->core, &metadata, flow->client,
                                 &flow->session);
  }
  (void)ftun_runtime_release(&runtime);
  if (status != FTUN_OK) return status;
  status = ftun_session_transition(flow->session, FTUN_SESSION_ROUTING, NULL);
  if (status != FTUN_OK) return status;
  return ftun_proxy_runtime_route_open(flow);
}

ftun_status_t ftun_proxy_runtime_route_open(ftun_proxy_runtime_flow_t *flow)
{
  const ftun_runtime_t *session_runtime = NULL;
  const ftun_metadata_t *metadata = NULL;
  const ftun_config_t *config = NULL;
  const ftun_config_inbound_t *inbound;
  const ftun_config_outbound_t *proxy_config = NULL;
  ftun_runtime_info_t runtime_info;
  ftun_route_result_t route;
  ftun_target_t target;
  ftun_outbound_leaf_t leaf;
  ftun_outbound_request_t request;
  ftun_direct_request_t direct;
  ftun_socks5_proxy_t proxy;
  ftun_socks5_connect_request_t socks;
  ftun_endpoint_t proxy_server;
  ftun_reject_result_t reject;
  uint32_t forced = 0u;
  bool has_forced = false;
  bool resume_proxy;
  ftun_status_t status;
  if (flow == NULL || flow->session == NULL) return FTUN_E_INVALID;
  status = ftun_session_get_runtime(flow->session, &session_runtime);
  if (status == FTUN_OK) status = ftun_runtime_get_info(session_runtime,
                                                        &runtime_info);
  if (status == FTUN_OK) status = ftun_runtime_config(session_runtime,
                                                      &config);
  if (status == FTUN_OK) status = ftun_session_get_metadata(flow->session,
                                                            &metadata);
  inbound = status == FTUN_OK
    ? ftun_proxy_runtime_inbound_config(config, flow->listener) : NULL;
  if (status == FTUN_OK && inbound == NULL) status = FTUN_E_STALE;
  resume_proxy = flow->proxy_leaf_id != 0u &&
                 flow->proxy_resolved_count != 0u;
  if (status == FTUN_OK && !resume_proxy && inbound->outbound != NULL &&
      inbound->outbound[0] != '\0') {
    has_forced = true;
    status = ftun_runtime_resolve_outbound_name(session_runtime,
      (ftun_string_t){inbound->outbound, strlen(inbound->outbound)}, &forced);
  }
  memset(&route, 0, sizeof(route));
  if (status == FTUN_OK && resume_proxy) {
    const ftun_route_result_t *stored_route = NULL;
    status = ftun_session_get_route(flow->session, &stored_route);
    if (status == FTUN_OK) {
      route = *stored_route;
      if (stored_route->allowed_count != 0u) {
        memcpy(route.allowed_storage, stored_route->allowed,
          stored_route->allowed_count * sizeof(route.allowed_storage[0]));
        route.allowed = route.allowed_storage;
      }
    }
  } else if (status == FTUN_OK && has_forced) {
    route.kind = forced == FTUN_OUTBOUND_ID_REJECT
      ? FTUN_ROUTE_DENY : FTUN_ROUTE_READY;
    route.generation = runtime_info.generation;
    route.outbound_id = forced;
    if (metadata->original_target.kind == FTUN_ADDRESS_IPV4 &&
        !metadata->original_is_fake) {
      route.allowed = &metadata->original_target;
      route.allowed_count = 1u;
    } else {
      route.allowed = metadata->resolved;
      route.allowed_count = metadata->resolved_count;
    }
  } else if (status == FTUN_OK) {
    status = ftun_route_evaluate(session_runtime, metadata, 0u, &route);
  }
  if (status == FTUN_OK && route.kind == FTUN_ROUTE_NEED_RESOLVE) {
    ftun_string_t server = {NULL, 0u};
    if (ftun_config_resolver(config).default_server != NULL &&
        ftun_config_resolver(config).default_server[0] != '\0') {
      server.data = ftun_config_resolver(config).default_server;
      server.length = strlen(ftun_config_resolver(config).default_server);
    }
    return ftun_proxy_runtime_resolve_session(flow, server);
  }
  if (status == FTUN_OK && route.kind == FTUN_ROUTE_DENY) {
    ftun_proxy_runtime_note_denied(flow->engine, &route);
    status = FTUN_E_REJECTED;
  }
  if (status == FTUN_OK) {
    status = ftun_proxy_runtime_leaf(flow->engine, session_runtime, config,
                              flow->proxy_leaf_id != 0u
                                ? flow->proxy_leaf_id : route.outbound_id,
                              route.generation, &leaf, &proxy_config);
  }
  if (status == FTUN_OK && !resume_proxy &&
      leaf.kind == FTUN_OUTBOUND_LEAF_DIRECT &&
      route.allowed_count == 0u &&
      (metadata->known_fields & FTUN_META_DOMAIN) != 0u) {
    /* DIRECT cannot delegate a domain to a remote peer.  Resolve it through
     * Bootstrap (or SystemResolver when DNS is disabled) before pinning the
     * route; a selected proxy may keep an unresolved SOCKS domain. */
    return ftun_proxy_runtime_resolve_session(flow, (ftun_string_t){NULL, 0u});
  }
  if (status == FTUN_OK && !resume_proxy) {
    route.outbound_id = leaf.id;
    status = ftun_session_pin_route(flow->session, &route);
  }
  if (status == FTUN_OK) {
    status = ftun_target_from_metadata(metadata, &target);
  }
  if (status == FTUN_OK) {
    const ftun_route_result_t *stored_route = NULL;
    status = ftun_session_get_route(flow->session, &stored_route);
    if (status == FTUN_OK) status = ftun_target_apply_route(&target,
                                                            stored_route);
  }
  if (status != FTUN_OK) return status;
  {
    const ftun_route_result_t *stored_route = NULL;
    (void)ftun_session_get_route(flow->session, &stored_route);
    memset(&request, 0, sizeof(request));
    request.route = stored_route;
    request.target = &target;
    request.leaf = &leaf;
    request.transport = FTUN_DIAL_TCP;
  }
  if (leaf.kind == FTUN_OUTBOUND_LEAF_DIRECT) {
    memset(&direct, 0, sizeof(direct));
    direct.loop = flow->engine->loop;
    direct.operations = flow->engine->operations;
    direct.budget = flow->budget;
    direct.protection.mark = flow->engine->socket_mark;
    direct.protection.liveness = flow->engine->liveness;
    direct.deadline_ms = 0u;
    status = ftun_monotonic_now(&direct.deadline_ms);
    if (status == FTUN_OK && direct.deadline_ms <=
        UINT64_MAX - flow->engine->connect_ms) {
      direct.deadline_ms += flow->engine->connect_ms;
    } else if (status == FTUN_OK) {
      status = FTUN_E_LIMIT;
    }
    direct.transport = FTUN_DIAL_TCP;
    direct.scope = flow->path_scope;
    direct.path_completion = ftun_proxy_runtime_direct_path_completed;
    direct.user = flow;
    direct.notify = ftun_proxy_runtime_path_notify;
    direct.notify_user = flow;
    direct.stream.budget = flow->budget;
    direct.stream.operations = flow->engine->operations;
    direct.stream.max_pending_writes = 1u;
    direct.stream.max_pending_bytes = FTUN_PROXY_RUNTIME_PREREAD_BYTES;
    direct.stream.completion = ftun_proxy_runtime_stream_completed;
    direct.stream.completion_user = flow;
    direct.stream.progress = ftun_proxy_runtime_stream_progress;
    direct.stream.progress_user = flow;
    request.direct = &direct;
  } else if (leaf.kind == FTUN_OUTBOUND_LEAF_SOCKS5) {
    status = ftun_proxy_runtime_parse_server_endpoint(proxy_config->server,
                                                      &proxy_server);
    if (status == FTUN_OK && proxy_server.kind == FTUN_ADDRESS_DOMAIN &&
        flow->proxy_resolved_count == 0u) {
      ftun_operation_t *operation = NULL;
      flow->proxy_leaf_id = leaf.id;
      flow->proxy_port = proxy_server.port;
      status = ftun_proxy_runtime_resolve_async(flow->engine, flow->budget, config,
        flow->resolver_scope,
        proxy_server.domain, true, ftun_proxy_runtime_proxy_resolved, flow,
        &operation);
      if (status == FTUN_OK) {
        flow->open_operation = operation;
        status = ftun_session_transition(flow->session,
          FTUN_SESSION_RESOLVING, operation);
      }
      if (status != FTUN_OK && operation != NULL) {
        (void)ftun_operation_cancel(operation);
      }
      if (status == FTUN_OK) {
        flow->open_operation = operation;
        flow->state = FTUN_PROXY_RUNTIME_FLOW_CONNECTING;
      }
      return status;
    }
    if (status == FTUN_OK) {
      memset(&proxy, 0, sizeof(proxy));
      proxy.server = proxy_server;
      if (proxy_server.kind == FTUN_ADDRESS_DOMAIN) {
        proxy.resolved = flow->proxy_resolved;
        proxy.resolved_count = flow->proxy_resolved_count;
      }
      if (proxy_config->username != NULL) {
        proxy.username.data = (const uint8_t *)proxy_config->username;
        proxy.username.length = strlen(proxy_config->username);
      }
      if (proxy_config->password != NULL) {
        proxy.password.data = (const uint8_t *)proxy_config->password;
        proxy.password.length = strlen(proxy_config->password);
      }
      proxy.udp_enabled = proxy_config->udp;
      memset(&socks, 0, sizeof(socks));
      socks.loop = flow->engine->loop;
      socks.operations = flow->engine->operations;
      socks.budget = flow->budget;
      socks.proxy = &proxy;
      socks.target = &target;
      socks.protection.mark = flow->engine->socket_mark;
      socks.protection.liveness = flow->engine->liveness;
      status = ftun_monotonic_now(&socks.deadline_ms);
      if (status == FTUN_OK && socks.deadline_ms <=
          UINT64_MAX - flow->engine->connect_ms) {
        socks.deadline_ms += flow->engine->connect_ms;
      } else if (status == FTUN_OK) {
        status = FTUN_E_LIMIT;
      }
      socks.transport = FTUN_DIAL_TCP;
      socks.completion = ftun_proxy_runtime_socks_completed;
      socks.user = flow;
      socks.scope = flow->path_scope;
      socks.notify = ftun_proxy_runtime_path_notify;
      socks.notify_user = flow;
      socks.stream.budget = flow->budget;
      socks.stream.operations = flow->engine->operations;
      socks.stream.max_pending_writes = 1u;
      socks.stream.max_pending_bytes = FTUN_PROXY_RUNTIME_PREREAD_BYTES;
      socks.stream.completion = ftun_proxy_runtime_stream_completed;
      socks.stream.completion_user = flow;
      socks.stream.progress = ftun_proxy_runtime_stream_progress;
      socks.stream.progress_user = flow;
      request.socks5 = &socks;
    }
  } else {
    status = FTUN_E_REJECTED;
  }
  if (status == FTUN_OK) {
    status = ftun_outbound_open(flow->engine->core, &request, &reject,
                                &flow->open_operation);
  }
  if (status == FTUN_OK) {
    flow->proxy_leaf_id = 0u;
    flow->proxy_port = 0u;
    flow->proxy_resolved_count = 0u;
  }
  if (status == FTUN_OK) {
    status = ftun_session_transition(flow->session,
      FTUN_SESSION_CONNECTING, flow->open_operation);
  }
  if (status == FTUN_OK) flow->state = FTUN_PROXY_RUNTIME_FLOW_CONNECTING;
  return status;
}

ftun_status_t ftun_proxy_runtime_protocol_drive(ftun_proxy_runtime_flow_t *flow,
  bool readable)
{
  ftun_inbound_event_t event;
  ftun_status_t status;
  if (flow->protocol == NULL) return FTUN_OK;
  status = ftun_inbound_adapter_drive(flow->protocol, readable, &event);
  if (status == FTUN_OK && event.kind == FTUN_INBOUND_EVENT_CONNECT) {
    ftun_bytes_t bytes = {NULL, 0u};
    if (event.preread.owner != NULL) status = ftun_buffer_slice_data(&event.preread, &bytes);
    if (status == FTUN_OK) status = ftun_proxy_runtime_copy_preread(flow, bytes);
    if (status == FTUN_OK) status = ftun_proxy_runtime_session_start(flow, &event.target);
  } else if (status == FTUN_OK && event.kind == FTUN_INBOUND_EVENT_ASSOCIATE) {
    status = ftun_proxy_runtime_association_start(flow, &event.target);
  }
  if (event.kind != FTUN_INBOUND_EVENT_NONE && status != FTUN_OK && status != FTUN_E_AGAIN) {
    ftun_proxy_runtime_downstream_failed(flow, status);
    status = FTUN_OK;
  }
  (void)ftun_buffer_slice_release(&event.preread);
  if (status == FTUN_OK || status == FTUN_E_AGAIN) {
    ftun_status_t current = ftun_proxy_runtime_protocol_update(flow);
    if (current != FTUN_OK) status = current;
  }
  return status;
}

ftun_status_t ftun_proxy_runtime_flow_create(ftun_proxy_runtime_t *engine,
                                              ftun_proxy_runtime_listener_t *listener,
                                              int descriptor,
                                              const ftun_endpoint_t *peer)
{
  ftun_proxy_runtime_flow_t *flow = NULL;
  ftun_runtime_t *runtime = NULL;
  const ftun_config_t *config = NULL;
  const ftun_config_inbound_t *inbound;
  ftun_inbound_spec_t spec;
  ftun_inbound_user_t *users = NULL;
  ftun_reservation_t users_reservation = (ftun_reservation_t){0};
  ftun_status_t status;
  uint64_t now;
  status = ftun_proxy_runtime_flow_slot_acquire(engine, &flow);
  if (status != FTUN_OK) {
    (void)ftun_socket_close((ftun_native_socket_t)(unsigned int)descriptor);
    return status;
  }
  flow->engine = engine;
  flow->listener = listener;
  flow->client_socket.descriptor = -1;
  flow->remote_socket.descriptor = -1;
  status = ftun_proxy_runtime_object_admit(engine,
    (ftun_budget_resources_t){0u, 1u, 1u},
    &flow->budget, &flow->admission);
  if (status != FTUN_OK) {
    (void)ftun_socket_close((ftun_native_socket_t)(unsigned int)descriptor);
    (void)ftun_proxy_runtime_flow_slot_release(&flow);
    return status;
  }
  flow->active = true;
  flow->state = FTUN_PROXY_RUNTIME_FLOW_HANDSHAKE;
  status = ftun_monotonic_now(&now);
  if (status != FTUN_OK ||
      now > UINT64_MAX - engine->handshake_ms) {
    status = status == FTUN_OK ? FTUN_E_LIMIT : status;
    goto fail;
  }
  flow->handshake_deadline_ms = now + engine->handshake_ms;
  if (peer != NULL && peer->kind == FTUN_ADDRESS_IPV4) flow->tcp_peer = *peer;
  status = ftun_proxy_runtime_stream_create(flow, &flow->client_socket, descriptor,
                                     &flow->client);
  if (status != FTUN_OK) goto fail;
  status = ftun_proxy_runtime_runtime_for_flow(flow, &runtime, &config);
  if (status != FTUN_OK) goto fail;
  inbound = ftun_proxy_runtime_inbound_config(config, listener);
  if (inbound == NULL) {
    status = FTUN_E_STALE;
    goto fail;
  }
  status = ftun_proxy_runtime_build_inbound_spec(flow, inbound, &spec, &users,
    &users_reservation);
  if (status == FTUN_OK) {
    status = ftun_inbound_adapter_create_with_pool(flow->client, &spec, engine->relay_pool,
      flow->handshake_deadline_ms, engine->reply_ms,
      ftun_proxy_runtime_stream_progress, flow, &flow->protocol);
  }
  free(users);
  users = NULL;
  (void)ftun_reservation_release(&users_reservation);
  (void)ftun_runtime_release(&runtime);
  if (status == FTUN_OK) {
    status = ftun_event_io_start(engine->loop,
      (ftun_native_socket_t)(unsigned int)descriptor,
      FTUN_EVENT_READ | FTUN_EVENT_ERROR,
      ftun_proxy_runtime_flow_client_ready, flow, &flow->client_source);
  }
  if (status == FTUN_OK) {
    status = ftun_proxy_runtime_protocol_update(flow);
  }
  if (status != FTUN_OK) goto fail;
  return FTUN_OK;

fail:
  free(users);
  (void)ftun_reservation_release(&users_reservation);
  (void)ftun_runtime_release(&runtime);
  (void)ftun_event_source_cancel(&flow->client_source);
  (void)ftun_event_source_cancel(&flow->remote_source);
  (void)ftun_event_source_cancel(&flow->deadline_source);
  if (flow->protocol != NULL) {
    (void)ftun_inbound_adapter_stop(flow->protocol);
    (void)ftun_inbound_adapter_destroy(&flow->protocol);
  }
  if (flow->client != NULL) {
    (void)ftun_stream_stop(flow->client);
    (void)ftun_stream_destroy(&flow->client);
  } else if (descriptor >= 0) {
    (void)ftun_socket_close((ftun_native_socket_t)(unsigned int)descriptor);
  }
  if (ftun_proxy_runtime_preread_release(flow) != FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
  }

  if (ftun_proxy_runtime_object_release(&flow->budget, &flow->admission) !=
      FTUN_OK) status = FTUN_E_STATE_CORRUPT;
  ftun_proxy_runtime_flow_unclassify(flow);
  if (ftun_proxy_runtime_flow_slot_release(&flow) != FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
  }
  return status;
}

/* 为已绑定的 socket 注册事件源。 */
ftun_status_t ftun_proxy_runtime_flow_finalize(ftun_proxy_runtime_flow_t *flow)
{
  ftun_session_info_t info;
  ftun_error_t result;
  ftun_status_t status = FTUN_OK;
  if (flow->open_operation != NULL) return FTUN_E_AGAIN;
  if (flow->preread_operation != NULL) {
    status = ftun_operation_cancel(flow->preread_operation);
    return status == FTUN_OK || status == FTUN_E_STALE ? FTUN_E_AGAIN : status;
  }
  if (flow->protocol != NULL) {
    status = ftun_inbound_adapter_stop(flow->protocol);
    if (status != FTUN_OK) return status;
    status = ftun_inbound_adapter_destroy(&flow->protocol);
    if (status != FTUN_OK) return status;
  }
  status = ftun_event_source_cancel(&flow->deadline_source);
  if (status == FTUN_OK) {
    status = ftun_event_source_cancel(&flow->client_source);
  }
  if (status == FTUN_OK) {
    status = ftun_event_source_cancel(&flow->remote_source);
  }
  if (status != FTUN_OK) return status;
  if (flow->relay != NULL) {
    ftun_status_t current = ftun_relay_destroy(&flow->relay);
    if (current != FTUN_OK && current != FTUN_E_AGAIN) return current;
    if (current == FTUN_E_AGAIN) return current;
  }
  if (flow->session != NULL) {
    status = ftun_session_get_info(flow->session, &info);
    if (status != FTUN_OK) return status;
    if (info.state == FTUN_SESSION_RELAYING) {
      status = ftun_session_transition(flow->session,
                                       FTUN_SESSION_DRAINING, NULL);
      if (status == FTUN_OK) {
        memset(&result, 0, sizeof(result));
        result.status = FTUN_OK;
        status = ftun_session_finish(flow->session, result);
      }
    } else if (info.state != FTUN_SESSION_CLOSED) {
      status = ftun_session_cancel(flow->session);
    }
    if (status != FTUN_OK && status != FTUN_E_STALE) return status;
    status = ftun_session_get_info(flow->session, &info);
    if (status != FTUN_OK || info.state != FTUN_SESSION_CLOSED) {
      return status == FTUN_OK ? FTUN_E_AGAIN : status;
    }
    status = ftun_session_destroy(&flow->session);
    if (status != FTUN_OK) return status;
  }
  if (flow->udp_channel != NULL) {
    ftun_proxy_runtime_association_unlink(flow);
    ftun_proxy_runtime_udp_pending_cancel_inbound(flow->engine, flow->udp_channel);
    if (flow->engine->udp_flows != NULL) {
      status = ftun_udp_flow_close_inbound(flow->engine->udp_flows,
                                           flow->udp_channel);
      if (status != FTUN_OK) return status;
    }
    status = ftun_datagram_stop(flow->udp_channel);
    if (status != FTUN_OK) return status;
    status = ftun_datagram_destroy(&flow->udp_channel);
    if (status != FTUN_OK) return status;
  }
  if (flow->udp_runtime != NULL) {
    status = ftun_runtime_release(&flow->udp_runtime);
    if (status != FTUN_OK) return status;
    flow->udp_generation = 0u;
    flow->udp_inbound_id = 0u;
  }

  if (flow->client != NULL) {
    (void)ftun_stream_stop(flow->client);
    status = ftun_stream_destroy(&flow->client);
    if (status != FTUN_OK) return status;
  }
  if (flow->proxy_connection != NULL) {
    status = ftun_socks5_connection_close(&flow->proxy_connection);
    if (status != FTUN_OK) return status;
    flow->remote_path = NULL;
    flow->remote = NULL;
  }
  if (flow->remote_path != NULL) {
    status = ftun_path_revoke(flow->remote_path);
    if (status != FTUN_OK) return status;
    status = ftun_path_destroy(&flow->remote_path);
    if (status != FTUN_OK) return status;
    flow->remote = NULL;
  }
  if (flow->remote != NULL) {
    (void)ftun_stream_stop(flow->remote);
    status = ftun_stream_destroy(&flow->remote);
    if (status != FTUN_OK) return status;
  }
  status = ftun_buffer_slice_release(&flow->preread_slice);
  if (status != FTUN_OK) return status;
  status = ftun_path_scope_release(&flow->path_scope);
  if (status == FTUN_OK) status = ftun_resolver_scope_release(&flow->resolver_scope);
  if (status != FTUN_OK) return status;
  status = ftun_proxy_runtime_preread_release(flow);
  if (status != FTUN_OK) return status;
  status = ftun_proxy_runtime_object_release(&flow->budget, &flow->admission);
  if (status != FTUN_OK) return status;
  ftun_proxy_runtime_flow_unclassify(flow);
  return ftun_proxy_runtime_flow_slot_release(&flow);
}

/* 收尾一条正在关闭的流。AGAIN 表示稍后继续；STATE_CORRUPT 是共享状态损坏，
 * 照常升级；其他失败只影响这一条流：转入隔离，继续占用它自己的槽位。 */
ftun_status_t ftun_proxy_runtime_flow_settle(ftun_proxy_runtime_flow_t *flow)
{
  ftun_proxy_runtime_t *engine = flow->engine;
  ftun_status_t status = ftun_proxy_runtime_flow_finalize(flow);
  if (status == FTUN_OK || status == FTUN_E_AGAIN) return FTUN_OK;
  if (status == FTUN_E_STATE_CORRUPT) return status;
  flow->state = FTUN_PROXY_RUNTIME_FLOW_QUARANTINED;
  engine->quarantined_flows++;
  engine->object_faults++;
  engine->quarantine_due_ms = 0u;
  return FTUN_OK;
}

/* 重试隔离流的收尾。成功即释放槽位；仍失败的继续留在隔离区。 */
ftun_status_t ftun_proxy_runtime_quarantine_run(
  ftun_proxy_runtime_t *engine, uint64_t now_ms, size_t *out_work)
{
  size_t scanned;
  size_t attempts = 0u;
  *out_work = 0u;
  if (engine->quarantined_flows == 0u || now_ms < engine->quarantine_due_ms) {
    return FTUN_OK;
  }
  for (scanned = 0u; scanned < engine->flow_capacity &&
       attempts < FTUN_PROXY_RUNTIME_QUARANTINE_QUOTA &&
       engine->quarantined_flows != 0u; scanned++) {
    ftun_proxy_runtime_flow_t *flow =
      ftun_proxy_runtime_flow_at(engine, engine->quarantine_cursor);
    ftun_status_t status;
    engine->quarantine_cursor =
      (engine->quarantine_cursor + 1u) % engine->flow_capacity;
    if (flow == NULL || !flow->active ||
        flow->state != FTUN_PROXY_RUNTIME_FLOW_QUARANTINED) continue;
    attempts++;
    status = ftun_proxy_runtime_flow_finalize(flow);
    if (status == FTUN_OK) {
      engine->quarantined_flows--;
    } else if (status == FTUN_E_STATE_CORRUPT) {
      return status;
    }
  }
  *out_work = attempts;
  engine->quarantine_due_ms = now_ms > UINT64_MAX - FTUN_PROXY_RUNTIME_QUARANTINE_RETRY_MS
    ? UINT64_MAX : now_ms + FTUN_PROXY_RUNTIME_QUARANTINE_RETRY_MS;
  return FTUN_OK;
}

/* 空闲回收：每秒最多扫描一轮，每轮至多检查 FTUN_PROXY_RUNTIME_IDLE_QUOTA 条流，
 * 不给每条流单独建计时器。只回收已进入转发、且两个方向都没有活动的流。 */
uint32_t ftun_proxy_runtime_flow_idle_ms(const ftun_proxy_runtime_t *engine,
                                                const ftun_proxy_runtime_flow_t *flow)
{
  return flow->listener != NULL && flow->listener->tcp_idle_ms != 0u
    ? flow->listener->tcp_idle_ms : engine->tcp_idle_ms;
}

bool ftun_proxy_runtime_idle_possible(const ftun_proxy_runtime_t *engine)
{
  size_t index;
  if (engine->tcp_idle_ms != 0u || engine->write_progress_ms != 0u) return true;
  for (index = 0u; index < engine->listener_count; index++) {
    if (engine->listeners[index].tcp_idle_ms != 0u) return true;
  }
#if defined(FTUN_HAVE_MODULE_TUN)
  return engine->tun_listener.tcp_idle_ms != 0u;
#else
  return false;
#endif
}

/* 写进展：连接有未被确认的积压，且累计确认字节数在 limit_ms 内没有增长，
 * 则对端已失联或完全停滞（零窗口且不再读取）。慢速但仍在读的对端会持续
 * 确认，不受影响。取不到进展（例如不是 TCP）时不判定。 */
bool ftun_proxy_runtime_write_stalled(
  ftun_proxy_runtime_progress_t *progress, ftun_status_t status,
  uint64_t acked, uint32_t queued, uint64_t now_ms, uint32_t limit_ms)
{
  if (status != FTUN_OK) return false;
  if (queued == 0u || acked != progress->acked) {
    progress->acked = acked;
    progress->stalled_since_ms = queued == 0u ? 0u : now_ms;
    return false;
  }
  if (progress->stalled_since_ms == 0u) progress->stalled_since_ms = now_ms;
  return now_ms - progress->stalled_since_ms >= limit_ms;
}

static bool ftun_proxy_runtime_flow_stalled(
  ftun_proxy_runtime_flow_t *flow, uint64_t now_ms, uint32_t limit_ms)
{
  uint64_t acked = 0u;
  uint32_t queued = 0u;
  ftun_status_t status;
  if (flow->client_socket.descriptor >= 0) {
    status = ftun_socket_send_progress(flow->client_socket.descriptor, &acked, &queued);
    if (ftun_proxy_runtime_write_stalled(&flow->client_progress, status, acked,
                                         queued, now_ms, limit_ms)) return true;
  }
  if (flow->remote_path != NULL) {
    status = ftun_path_send_progress(flow->remote_path, &acked, &queued);
  } else if (flow->remote_socket.descriptor >= 0) {
    status = ftun_socket_send_progress(flow->remote_socket.descriptor, &acked, &queued);
  } else {
    return false;
  }
  return ftun_proxy_runtime_write_stalled(&flow->remote_progress, status, acked,
                                          queued, now_ms, limit_ms);
}

size_t ftun_proxy_runtime_idle_scan(ftun_proxy_runtime_t *engine, uint64_t now_ms)
{
  size_t scanned;
  size_t reclaimed = 0u;
  if (now_ms < engine->idle_next_ms || !ftun_proxy_runtime_idle_possible(engine)) {
    return 0u;
  }
  engine->idle_next_ms = now_ms > UINT64_MAX - FTUN_PROXY_RUNTIME_IDLE_SCAN_MS
    ? UINT64_MAX : now_ms + FTUN_PROXY_RUNTIME_IDLE_SCAN_MS;
  for (scanned = 0u; scanned < engine->flow_capacity &&
       scanned < FTUN_PROXY_RUNTIME_IDLE_QUOTA; scanned++) {
    ftun_proxy_runtime_flow_t *flow =
      ftun_proxy_runtime_flow_at(engine, engine->idle_cursor);
    uint32_t idle;
    engine->idle_cursor = (engine->idle_cursor + 1u) % engine->flow_capacity;
    if (flow == NULL || !flow->active || flow->state != FTUN_PROXY_RUNTIME_FLOW_RELAY) continue;
    idle = ftun_proxy_runtime_flow_idle_ms(engine, flow);
    if ((idle != 0u && now_ms >= flow->last_activity_ms &&
         now_ms - flow->last_activity_ms >= idle) ||
        (engine->write_progress_ms != 0u &&
         ftun_proxy_runtime_flow_stalled(flow, now_ms, engine->write_progress_ms))) {
      ftun_proxy_runtime_flow_close(flow, FTUN_E_TIMEOUT);
      ftun_proxy_runtime_flow_schedule(flow);
      reclaimed++;
    }
  }
  return reclaimed;
}

ftun_status_t ftun_proxy_runtime_flow_drive(ftun_proxy_runtime_flow_t *flow,
                                             uint32_t client_events,
                                             uint32_t remote_events)
{
  ftun_status_t status = FTUN_OK;
  if (!flow->active || flow->state == FTUN_PROXY_RUNTIME_FLOW_QUARANTINED) return FTUN_OK;
  if (flow->state == FTUN_PROXY_RUNTIME_FLOW_RELAY &&
      (client_events != 0u || remote_events != 0u || flow->path_events != 0u ||
       flow->left_events != 0u)) {
    flow->last_activity_ms = flow->engine->round_ms;
  }
#if defined(FTUN_HAVE_MODULE_TUN)
  if (flow->tun && flow->engine->tun_resetting) {
    ftun_proxy_runtime_flow_close(flow, FTUN_E_CANCELLED);
  }
#endif
  if (flow->accept_failure != FTUN_OK) {
    ftun_status_t failure = flow->accept_failure;
    flow->accept_failure = FTUN_OK;
    ftun_proxy_runtime_flow_close(flow, failure);
  }
  status = ftun_proxy_runtime_stream_complete_pending(&flow->client_socket);
  if (status == FTUN_OK) {
    status = ftun_proxy_runtime_stream_complete_pending(&flow->remote_socket);
  }
  if (status != FTUN_OK) ftun_proxy_runtime_flow_close(flow, status);
#if defined(FTUN_HAVE_MODULE_TUN)
  if (flow->tun && flow->state == FTUN_PROXY_RUNTIME_FLOW_HANDSHAKE) {
    bool readable = (flow->left_events & FTUN_EVENT_READ) != 0u;
    flow->left_events = 0u;
    status = ftun_proxy_runtime_tun_sniff(flow, readable);
    if (status != FTUN_OK && status != FTUN_E_AGAIN) {
      ftun_proxy_runtime_flow_close(flow, status);
    }
  }
#endif
  if (!flow->tun && flow->state != FTUN_PROXY_RUNTIME_FLOW_CLOSING) {
    status = ftun_proxy_runtime_protocol_drive(flow,
      flow->state == FTUN_PROXY_RUNTIME_FLOW_HANDSHAKE && (client_events & FTUN_EVENT_READ) != 0u);
    if (status != FTUN_OK && status != FTUN_E_AGAIN) ftun_proxy_runtime_flow_close(flow, status);
  }
  if (flow->state == FTUN_PROXY_RUNTIME_FLOW_UDP_ASSOCIATE) {
    if ((client_events & FTUN_EVENT_READ) != 0u) {
      uint8_t discard[256];
      ptrdiff_t length;
  ftun_status_t io_status;
      length = ftun_socket_stream_receive(flow->client_socket.descriptor,
        discard, sizeof(discard), &io_status);
      if (length == 0 || (length < 0 && io_status != FTUN_E_AGAIN)) {
        ftun_proxy_runtime_flow_close(flow, length == 0 ? FTUN_E_EOF
                                                 : io_status);
      }
    }
  }
  if (flow->state == FTUN_PROXY_RUNTIME_FLOW_RELAY && flow->relay != NULL &&
      !ftun_proxy_runtime_protocol_pending(flow)) {
    ftun_relay_usage_t usage;
    uint32_t left = 0u;
    uint32_t right = 0u;
    size_t work = 0u;
    left = client_events;
#if defined(FTUN_HAVE_MODULE_TUN)
    if (flow->tun) {
      bool readable = false;
      bool writable = false;
      left |= flow->left_events;
      flow->left_events = 0u;
      status = ftun_relay_get_usage(flow->relay, &usage);
      if (status == FTUN_OK) {
        status = ftun_tun_ingress_stream_ready(flow->engine->tun_ingress,
          flow->client, &readable, &writable);
      }
      if (status != FTUN_OK && status != FTUN_E_STALE) {
        ftun_proxy_runtime_flow_close(flow, status);
      } else if (status == FTUN_OK) {
        if (readable && (usage.left_interests & FTUN_EVENT_READ) != 0u) {
          left |= FTUN_EVENT_READ;
        }
        if (writable && (usage.left_interests & FTUN_EVENT_WRITE) != 0u) {
          left |= FTUN_EVENT_WRITE;
        }
      }
    }
#endif
    if (flow->preread_length != 0u) {
      status = ftun_proxy_runtime_flush_preread(flow);
      if (status != FTUN_OK && status != FTUN_E_AGAIN) {
        ftun_proxy_runtime_flow_close(flow, status);
      }
    }
    if (flow->preread_length == 0u && flow->state == FTUN_PROXY_RUNTIME_FLOW_RELAY) {
      /* 早到的提示保留到真正移交 Relay；调用中同步通知属于下一轮。 */
      right = flow->remote_path != NULL ? flow->path_events : remote_events;
      flow->path_events = 0u;
      status = ftun_relay_process(flow->relay, left, right, &work);
      if (status == FTUN_OK && work == FTUN_RELAY_DEFAULT_MAX_WORK) {
        ftun_proxy_runtime_flow_schedule(flow);
      }
      if (status != FTUN_OK) ftun_proxy_runtime_flow_close(flow, status);
    }
    if (flow->relay != NULL &&
        ftun_relay_get_usage(flow->relay, &usage) == FTUN_OK &&
        usage.complete) flow->state = FTUN_PROXY_RUNTIME_FLOW_CLOSING;
  }
  /* 本轮 Native 写已消费的字节，在 write_start 返回后即可排入完成队列。 */
  status = ftun_proxy_runtime_stream_complete_pending(&flow->client_socket);
  if (status == FTUN_OK) {
    status = ftun_proxy_runtime_stream_complete_pending(&flow->remote_socket);
  }
  if (status != FTUN_OK) ftun_proxy_runtime_flow_close(flow, status);
  if ((client_events & FTUN_EVENT_ERROR) != 0u ||
      (remote_events & FTUN_EVENT_ERROR) != 0u) {
    ftun_proxy_runtime_flow_close(flow, FTUN_E_IO);
  }
  if (flow->state == FTUN_PROXY_RUNTIME_FLOW_CLOSING) {
    return ftun_proxy_runtime_flow_settle(flow);
  }
  status = ftun_proxy_runtime_flow_update_sources(flow);
  if (status != FTUN_OK) {
    ftun_proxy_runtime_flow_close(flow, status);
    return ftun_proxy_runtime_flow_settle(flow);
  }
  return status;
}

ftun_status_t ftun_proxy_runtime_flow_drain(ftun_proxy_runtime_t *engine,
                                             size_t quota,
                                             size_t *out_work)
{
  ftun_proxy_runtime_flow_t *last;
  size_t work = 0u;
  if (out_work != NULL) *out_work = 0u;
  if (engine == NULL || quota == 0u || out_work == NULL) {
    return FTUN_E_INVALID;
  }
  /* Preserve the old owner-loop lifecycle boundary: a flow which becomes
   * runnable while this batch is being driven is deferred to the next
   * batch.  Without this boundary a synchronously rescheduled TUN flow can
   * be driven repeatedly and finalized before the packet/ACK cycle which
   * caused the reschedule has returned through the event loop. */
  last = engine->ready_flow_tail;
  while (engine->ready_flow_head != NULL && work < quota) {
    ftun_proxy_runtime_flow_t *flow = engine->ready_flow_head;
    bool batch_complete = flow == last;
    uint32_t client_events;
    uint32_t remote_events;
    ftun_status_t status;
    engine->ready_flow_head = flow->ready_next;
    if (engine->ready_flow_head == NULL) engine->ready_flow_tail = NULL;
    flow->ready_next = NULL;
    flow->ready_queued = false;
    if (!flow->active) continue;
    client_events = flow->client_events;
    remote_events = flow->remote_events;
    flow->client_events = 0u;
    flow->remote_events = 0u;
    flow->driving = true;
    flow->reschedule = false;
    status = ftun_proxy_runtime_flow_drive(flow, client_events, remote_events);
    work++;
    if (flow->active) {
      bool reschedule = flow->reschedule;
      flow->driving = false;
      flow->reschedule = false;
      if (reschedule) ftun_proxy_runtime_flow_schedule(flow);
    }
    if (status != FTUN_OK) return status;
    if (batch_complete) break;
  }
  if (ftun_proxy_slot_pool_trim(engine->flow_pool) != FTUN_OK) {
    return FTUN_E_STATE_CORRUPT;
  }
  *out_work = work;
  return FTUN_OK;
}

