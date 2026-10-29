#define _GNU_SOURCE 1

#include "proxy/engine_internal.h"

void ftun_proxy_runtime_udp_sent(ftun_datagram_t *channel, ftun_error_t error,
  const ftun_endpoint_t *target, const ftun_packet_t *packet, void *user)
{
  ftun_proxy_runtime_udp_slot_t *slot = user;
  ftun_datagram_send_token_t send = slot->sending;
  (void)channel;
  (void)target;
  (void)packet;
  if (slot->cancelling_send) return;
  if (send.channel != NULL && ftun_datagram_send_complete(send, error) == FTUN_OK) {
    memset(&slot->sending, 0, sizeof(slot->sending));
  }
  ftun_proxy_runtime_udp_schedule(slot);
}

ftun_status_t ftun_proxy_runtime_udp_received(ftun_datagram_t *channel,
  const ftun_endpoint_t *source, const ftun_packet_t *packet, void *user);

ftun_status_t ftun_proxy_runtime_udp_send_packet(ftun_proxy_runtime_udp_slot_t *slot,
  ftun_datagram_send_token_t send, const ftun_endpoint_t *target, const ftun_packet_t *packet)
{
  ftun_status_t status;
  if (slot->remote_channel == NULL || slot->sending.channel != NULL) return FTUN_E_AGAIN;
  slot->sending = send;
  status = ftun_channel_send(slot->remote_channel, target, (ftun_packet_t *)packet);
  if (status != FTUN_OK) memset(&slot->sending, 0, sizeof(slot->sending));
  return status;
}

ftun_status_t ftun_proxy_runtime_udp_queue_send(
  ftun_proxy_runtime_udp_slot_t *slot, ftun_datagram_send_token_t send)
{
  if (slot->pending_count >= sizeof(slot->pending) / sizeof(slot->pending[0])) return FTUN_E_LIMIT;
  slot->pending[slot->pending_count++] = send;
  if (slot->ready) ftun_proxy_runtime_udp_schedule(slot);
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_udp_send_start(void *user,
  ftun_datagram_send_token_t send, const ftun_endpoint_t *target, const ftun_packet_t *packet)
{
  ftun_proxy_runtime_udp_slot_t *slot = user;
  ftun_status_t status;
  if (slot == NULL || !slot->active || slot->destroying || send.channel == NULL ||
      !ftun_proxy_runtime_endpoint_equal(target, &slot->remote)) return FTUN_E_INVALID;
  if (slot->failure != FTUN_OK) return slot->failure;
  if (!slot->ready) {
    if (slot->open_operation == NULL) return slot->open_status == FTUN_OK ? FTUN_E_STATE_CORRUPT : slot->open_status;
    return ftun_proxy_runtime_udp_queue_send(slot, send);
  }
  if (slot->pending_count != 0u || slot->sending.channel != NULL) return ftun_proxy_runtime_udp_queue_send(slot, send);
  status = ftun_proxy_runtime_udp_send_packet(slot, send, target, packet);
  return status == FTUN_E_AGAIN ? ftun_proxy_runtime_udp_queue_send(slot, send) : status;
}

ftun_status_t ftun_proxy_runtime_udp_send_cancel(void *user,
  ftun_datagram_send_token_t send)
{
  ftun_proxy_runtime_udp_slot_t *slot = user;
  size_t index;
  if (slot == NULL || send.channel == NULL) return FTUN_E_INVALID;
  if (slot->sending.channel == send.channel && slot->sending.slot == send.slot &&
      slot->sending.generation == send.generation) {
    ftun_status_t status;
    slot->cancelling_send = true;
    status = ftun_channel_stop(slot->remote_channel);
    slot->cancelling_send = false;
    if (status == FTUN_OK) memset(&slot->sending, 0, sizeof(slot->sending));
    return status;
  }
  for (index = 0u; index < slot->pending_count; index++) {
    if (slot->pending[index].channel == send.channel && slot->pending[index].slot == send.slot &&
        slot->pending[index].generation == send.generation) {
      size_t remaining = slot->pending_count - index - 1u;
      if (remaining != 0u) memmove(&slot->pending[index], &slot->pending[index + 1u],
        remaining * sizeof(slot->pending[0]));
      memset(&slot->pending[--slot->pending_count], 0, sizeof(slot->pending[0]));
      return FTUN_OK;
    }
  }
  return FTUN_E_STALE;
}

ftun_status_t ftun_proxy_runtime_udp_slot_reset(ftun_proxy_runtime_udp_slot_t *slot)
{
  ftun_proxy_runtime_t *engine;
  ftun_proxy_slot_token_t token;
  void *owned;
  ftun_status_t status;
  if (slot == NULL || slot->engine == NULL) return FTUN_E_INVALID;
  engine = slot->engine;
  token = slot->slot_token;
  ftun_proxy_runtime_udp_unschedule(slot);
  status = ftun_path_scope_release(&slot->path_scope);
  if (status == FTUN_OK) status = ftun_resolver_scope_release(&slot->resolver_scope);
  if (status != FTUN_OK) return status;
  status = ftun_proxy_runtime_object_release(&slot->budget, &slot->admission);
  if (status != FTUN_OK) return status;
  owned = slot;
  return ftun_proxy_slot_pool_release(engine->udp_pool, token, &owned);
}

ftun_status_t ftun_proxy_runtime_udp_backoff_attempt(void *user,
                                                           ftun_recovery_id_t id)
{
  ftun_proxy_runtime_udp_backoff_t *entry = (ftun_proxy_runtime_udp_backoff_t *)user;
  uint64_t now_ms = 0u;
  (void)ftun_monotonic_now(&now_ms);
  (void)ftun_recovery_attempt_finish(entry->engine->recovery, id, now_ms, FTUN_OK,
                                     FTUN_RECOVERY_FAULT_NETWORK);
  return FTUN_OK;
}

ftun_proxy_runtime_udp_backoff_t *ftun_proxy_runtime_udp_backoff_entry(
  ftun_proxy_runtime_t *engine, uint32_t outbound_id, bool create)
{
  ftun_proxy_runtime_udp_backoff_t *free_entry = NULL;
  size_t index;
  for (index = 0u; index < engine->udp_backoff_capacity; index++) {
    ftun_proxy_runtime_udp_backoff_t *entry = &engine->udp_backoff[index];
    if (entry->active && entry->outbound_id == outbound_id) return entry;
    if (!entry->active && free_entry == NULL) free_entry = entry;
  }
  if (!create || free_entry == NULL || engine->recovery == NULL) return NULL;
  {
    ftun_recovery_spec_t spec;
    uint64_t now_ms = 0u;
    memset(&spec, 0, sizeof(spec));
    spec.kind = FTUN_PROXY_RUNTIME_UDP_RECOVERY_KIND;
    spec.attempt = ftun_proxy_runtime_udp_backoff_attempt;
    spec.user = free_entry;
    (void)ftun_monotonic_now(&now_ms);
    memset(free_entry, 0, sizeof(*free_entry));
    free_entry->engine = engine;
    free_entry->outbound_id = outbound_id;
    if (ftun_recovery_entity_register(engine->recovery, &spec, now_ms,
                                      &free_entry->id) != FTUN_OK) {
      memset(free_entry, 0, sizeof(*free_entry));
      return NULL;
    }
  }
  free_entry->active = true;
  return free_entry;
}

/* 该出口当前是否可以建立 association：退避中（WAITING）不可以。 */
bool ftun_proxy_runtime_udp_backoff_allowed(ftun_proxy_runtime_t *engine,
                                            uint32_t outbound_id)
{
  ftun_proxy_runtime_udp_backoff_t *entry =
    ftun_proxy_runtime_udp_backoff_entry(engine, outbound_id, false);
  ftun_recovery_info_t info;
  if (entry == NULL) return true;
  if (ftun_recovery_query(engine->recovery, entry->id.slot, &info) != FTUN_OK) return true;
  return info.state == FTUN_RECOVERY_AVAILABLE;
}

void ftun_proxy_runtime_udp_backoff_failed(ftun_proxy_runtime_t *engine,
                                           uint32_t outbound_id)
{
  ftun_proxy_runtime_udp_backoff_t *entry =
    ftun_proxy_runtime_udp_backoff_entry(engine, outbound_id, true);
  uint64_t now_ms = 0u;
  if (entry == NULL || ftun_monotonic_now(&now_ms) != FTUN_OK) return;
  (void)ftun_recovery_report_failure(engine->recovery, entry->id, now_ms,
                                     FTUN_RECOVERY_FAULT_NETWORK);
}

/* 成功不需要手工重置：A0 在实体持续可用满一个稳定窗口后才清零退避，
 * 偶发成功不会让反复失败的出口立刻回到最短退避。 */
void ftun_proxy_runtime_udp_backoff_succeeded(ftun_proxy_runtime_t *engine,
                                              uint32_t outbound_id)
{
  (void)engine;
  (void)outbound_id;
}

ftun_status_t ftun_proxy_runtime_udp_cleanup(ftun_proxy_runtime_udp_slot_t *slot)
{
  ftun_status_t status;
  if (!slot->destroying || slot->channel != NULL) return FTUN_E_AGAIN;
  if (slot->open_operation != NULL) {
    status = ftun_operation_cancel(slot->open_operation);
    return status == FTUN_OK || status == FTUN_E_STALE ? FTUN_E_AGAIN : status;
  }
  if (slot->sending.channel != NULL || slot->pending_count != 0u) return FTUN_E_AGAIN;
  if (slot->proxy_connection != NULL) {
    status = ftun_socks5_connection_close(&slot->proxy_connection);
    if (status != FTUN_OK) return status;
    slot->remote_channel = NULL;
  }
  if (slot->path != NULL) {
    status = ftun_path_revoke(slot->path);
    if (status == FTUN_OK) status = ftun_path_destroy(&slot->path);
    if (status != FTUN_OK) return status;
    slot->remote_channel = NULL;
  }
  return ftun_proxy_runtime_udp_slot_reset(slot);
}

void ftun_proxy_runtime_udp_destroy(void *user)
{
  ftun_proxy_runtime_udp_slot_t *slot = user;
  /* 后端 destroy 无返回值；槽继续拥有 Path/子操作，owner 后续重试回收。 */
  slot->channel = NULL;
  slot->destroying = true;
  ftun_proxy_runtime_udp_schedule(slot);
}

void ftun_proxy_runtime_udp_finish_pending(ftun_proxy_runtime_udp_slot_t *slot,
  ftun_status_t status)
{
  while (slot->pending_count != 0u && slot->sending.channel == NULL) {
    ftun_datagram_send_token_t send = slot->pending[0];
    const ftun_endpoint_t *target = NULL;
    const ftun_packet_t *packet = NULL;
    if (status == FTUN_OK) {
      status = ftun_datagram_send_view(send, &target, &packet);
      if (status == FTUN_OK) status = ftun_proxy_runtime_udp_send_packet(slot, send, target, packet);
      if (status == FTUN_E_AGAIN) return;
    }
    if (--slot->pending_count != 0u) memmove(&slot->pending[0], &slot->pending[1],
      slot->pending_count * sizeof(slot->pending[0]));
    memset(&slot->pending[slot->pending_count], 0, sizeof(slot->pending[0]));
    if (status != FTUN_OK) (void)ftun_datagram_send_complete(send, (ftun_error_t){status, 0u, 0});
  }
}

void ftun_proxy_runtime_udp_socks_completed(ftun_operation_t *operation,
  ftun_error_t error, ftun_socks5_connection_t *connection, void *user);

void ftun_proxy_runtime_udp_direct_completed(ftun_operation_t *operation,
  ftun_error_t error, ftun_path_t *path, void *user)
{
  ftun_proxy_runtime_udp_slot_t *slot = user;
  ftun_status_t status = error.status;
  (void)operation;
  slot->open_operation = NULL;
  slot->path = path;
  if (status == FTUN_OK && !slot->destroying) status = ftun_path_channel(path, &slot->remote_channel);
  slot->ready = status == FTUN_OK && !slot->destroying;
  slot->resume_pending = slot->ready;
  slot->open_status = status;
  ftun_proxy_runtime_udp_schedule(slot);
}

void ftun_proxy_runtime_udp_handshake_written(ftun_operation_t *operation,
  ftun_error_t error, void *user)
{
  (void)operation;
  (void)error;
  (void)user;
}

ftun_status_t ftun_proxy_runtime_udp_socks_start(
  ftun_proxy_runtime_udp_slot_t *slot)
{
  ftun_socks5_proxy_t proxy;
  ftun_socks5_connect_request_t socks;
  ftun_status_t status;
  if (slot == NULL || slot->engine == NULL || !slot->active ||
      slot->open_operation != NULL) return FTUN_E_INVALID;
  memset(&proxy, 0, sizeof(proxy));
  proxy.server = slot->proxy_server;
  if (proxy.server.kind == FTUN_ADDRESS_DOMAIN) {
    proxy.resolved = slot->proxy_resolved;
    proxy.resolved_count = slot->proxy_resolved_count;
  }
  proxy.username.data = slot->proxy_username_length == 0u
    ? NULL : slot->proxy_username;
  proxy.username.length = slot->proxy_username_length;
  proxy.password.data = slot->proxy_password_length == 0u
    ? NULL : slot->proxy_password;
  proxy.password.length = slot->proxy_password_length;
  proxy.udp_enabled = true;
  memset(&socks, 0, sizeof(socks));
  socks.loop = slot->engine->loop;
  socks.operations = slot->engine->operations;
  socks.budget = slot->budget;
  socks.proxy = &proxy;
  socks.target = &slot->socks_target;
  socks.protection.mark = slot->engine->socket_mark;
  socks.protection.liveness = slot->engine->liveness;
  status = ftun_monotonic_now(&socks.deadline_ms);
  if (status == FTUN_OK && socks.deadline_ms <=
      UINT64_MAX - slot->engine->connect_ms) {
    socks.deadline_ms += slot->engine->connect_ms;
  } else if (status == FTUN_OK) {
    status = FTUN_E_LIMIT;
  }
  socks.transport = FTUN_DIAL_UDP;
  socks.completion = ftun_proxy_runtime_udp_socks_completed;
  socks.user = slot;
  socks.scope = slot->path_scope;
  socks.notify = ftun_proxy_runtime_udp_path_notify;
  socks.notify_user = slot;
  socks.stream.max_pending_writes = 1u;
  socks.stream.max_pending_bytes = 8192u;
  socks.stream.completion = ftun_proxy_runtime_udp_handshake_written;
  socks.datagram.max_pending_packets = 1u;
  socks.datagram.max_pending_bytes = UINT16_MAX + 263u;
  socks.datagram.result = ftun_proxy_runtime_udp_sent;
  socks.datagram.receive = ftun_proxy_runtime_udp_received;
  socks.datagram.user = slot;
  if (status == FTUN_OK) {
    status = ftun_socks5_connect(slot->engine->core, &socks,
                                 &slot->open_operation);
  }
  return status;
}

void ftun_proxy_runtime_udp_proxy_resolved(
  ftun_operation_t *operation, ftun_error_t error,
  const ftun_system_resolve_result_t *result, void *user)
{
  ftun_proxy_runtime_udp_slot_t *slot = (ftun_proxy_runtime_udp_slot_t *)user;
  ftun_status_t status = error.status;
  size_t index;
  if (slot == NULL || !slot->active || slot->open_operation != operation) {
    return;
  }
  slot->open_operation = NULL;
  if (slot->destroying) {
    ftun_proxy_runtime_udp_schedule(slot);
    return;
  }
  if (status == FTUN_OK && (result == NULL || result->address_count == 0u ||
      result->address_count > FTUN_SESSION_MAX_RESOLVED_IPV4)) {
    status = FTUN_E_STATE_CORRUPT;
  }
  for (index = 0u; status == FTUN_OK && index < result->address_count;
       index++) {
    if (result->addresses[index].kind != FTUN_ADDRESS_IPV4) {
      status = FTUN_E_UNSUPPORTED;
      break;
    }
    slot->proxy_resolved[index] = result->addresses[index];
    slot->proxy_resolved[index].port = slot->proxy_server.port;
    slot->proxy_resolved[index].domain.data = NULL;
    slot->proxy_resolved[index].domain.length = 0u;
  }
  if (status == FTUN_OK) {
    slot->proxy_resolved_count = result->address_count;
    status = ftun_proxy_runtime_udp_socks_start(slot);
  }
  if (status != FTUN_OK) {
    ftun_proxy_runtime_udp_backoff_failed(slot->engine, slot->outbound_id);
    slot->open_status = status;
    ftun_proxy_runtime_udp_finish_pending(slot, status);
  }
}

void ftun_proxy_runtime_udp_socks_completed(ftun_operation_t *operation,
  ftun_error_t error, ftun_socks5_connection_t *connection, void *user)
{
  ftun_proxy_runtime_udp_slot_t *slot = user;
  ftun_status_t status = error.status;
  (void)operation;
  slot->open_operation = NULL;
  slot->proxy_connection = connection;
  if (status == FTUN_OK && !slot->destroying) status = ftun_socks5_connection_channel(connection, &slot->remote_channel);
  slot->ready = status == FTUN_OK && !slot->destroying;
  slot->resume_pending = slot->ready;
  slot->open_status = status;
  if (status != FTUN_OK && !slot->destroying) ftun_proxy_runtime_udp_backoff_failed(slot->engine, slot->outbound_id);
  ftun_proxy_runtime_udp_schedule(slot);
}

ftun_status_t ftun_proxy_runtime_udp_socks_prepare(
  ftun_proxy_runtime_udp_slot_t *slot, const ftun_target_t *target,
  const ftun_config_outbound_t *config, const ftun_endpoint_t *server)
{
  size_t length;
  if (slot == NULL || target == NULL || config == NULL || server == NULL ||
      target->candidate_count > FTUN_SESSION_MAX_RESOLVED_IPV4 ||
      target->allowed_count > FTUN_SESSION_MAX_RESOLVED_IPV4 ||
      (target->candidate_count != 0u && target->candidates == NULL) ||
      (target->allowed_count != 0u && target->allowed == NULL)) {
    return FTUN_E_INVALID;
  }
  slot->socks_target = *target;
  if (target->candidate_count != 0u) {
    memcpy(slot->target_candidates, target->candidates,
      target->candidate_count * sizeof(slot->target_candidates[0]));
    slot->socks_target.candidates = slot->target_candidates;
  }
  if (target->allowed_count != 0u) {
    memcpy(slot->target_allowed, target->allowed,
      target->allowed_count * sizeof(slot->target_allowed[0]));
    slot->socks_target.allowed = slot->target_allowed;
  }
  if (target->identity.length != 0u) {
    if (target->identity.data == NULL ||
        target->identity.length >= sizeof(slot->target_domain)) {
      return FTUN_E_LIMIT;
    }
    memcpy(slot->target_domain, target->identity.data,
           target->identity.length);
    slot->target_domain[target->identity.length] = '\0';
    slot->socks_target.identity.data = slot->target_domain;
    if (slot->socks_target.original.kind == FTUN_ADDRESS_DOMAIN) {
      slot->socks_target.original.domain.data = slot->target_domain;
    }
  }
  slot->proxy_server = *server;
  if (server->kind == FTUN_ADDRESS_DOMAIN) {
    if (server->domain.data == NULL || server->domain.length == 0u ||
        server->domain.length >= sizeof(slot->proxy_domain)) {
      return FTUN_E_INVALID;
    }
    memcpy(slot->proxy_domain, server->domain.data, server->domain.length);
    slot->proxy_domain[server->domain.length] = '\0';
    slot->proxy_server.domain.data = slot->proxy_domain;
  }
  if (config->username != NULL) {
    size_t password_length;
    length = strlen(config->username);
    password_length = config->password == NULL
      ? 0u : strlen(config->password);
    if (length > sizeof(slot->proxy_username) || password_length == 0u ||
        password_length > sizeof(slot->proxy_password)) return FTUN_E_INVALID;
    memcpy(slot->proxy_username, config->username, length);
    memcpy(slot->proxy_password, config->password, password_length);
    slot->proxy_username_length = length;
    slot->proxy_password_length = password_length;
  }
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_udp_open(
  void *user, ftun_core_t *core, const ftun_runtime_t *runtime,
  const ftun_metadata_t *metadata, const ftun_route_result_t *prepared_route,
  const ftun_udp_flow_admission_t *admission,
  ftun_datagram_result_fn result,
  ftun_datagram_receive_fn receive, void *callback_user,
  uint32_t *outbound_id, ftun_endpoint_t *remote, ftun_datagram_t **out)
{
  ftun_proxy_runtime_t *engine = (ftun_proxy_runtime_t *)user;
  const ftun_config_t *config = NULL;
  const ftun_config_inbound_t *inbound;
  const ftun_config_outbound_t *proxy_config = NULL;
  ftun_route_result_t route;
  ftun_target_t target;
  ftun_outbound_leaf_t leaf;
  ftun_outbound_request_t request;
  ftun_direct_request_t direct;
  ftun_endpoint_t proxy_server;
  ftun_reject_result_t reject;
  ftun_proxy_runtime_udp_slot_t *slot = NULL;
  ftun_datagram_options_t options;
  ftun_datagram_backend_t backend;
  ftun_status_t status;
  uint32_t forced = 0u;
  bool has_forced = false;
  if (out != NULL) *out = NULL;
  if (engine == NULL || core != engine->core || runtime == NULL ||
      metadata == NULL || result == NULL || receive == NULL ||
      outbound_id == NULL || remote == NULL || out == NULL) {
    return FTUN_E_INVALID;
  }
  status = ftun_runtime_config(runtime, &config);
  inbound = status == FTUN_OK
    ? ftun_proxy_runtime_inbound_by_id(config, metadata->inbound_id) : NULL;
  if (status == FTUN_OK && inbound == NULL) status = FTUN_E_STALE;
  if (status == FTUN_OK && inbound->outbound != NULL &&
      inbound->outbound[0] != '\0') {
    has_forced = true;
    status = ftun_runtime_resolve_outbound_name(runtime,
      (ftun_string_t){inbound->outbound, strlen(inbound->outbound)}, &forced);
  }
  memset(&route, 0, sizeof(route));
  if (status == FTUN_OK && prepared_route != NULL) {
    route = *prepared_route;
    if (prepared_route->allowed_count != 0u) {
      if (prepared_route->allowed_count > FTUN_ROUTE_MAX_CANDIDATES) {
        status = FTUN_E_LIMIT;
      } else {
        memcpy(route.allowed_storage, prepared_route->allowed,
          prepared_route->allowed_count * sizeof(route.allowed_storage[0]));
        route.allowed = route.allowed_storage;
      }
    }
  } else if (status == FTUN_OK && has_forced) {
    route.kind = forced == FTUN_OUTBOUND_ID_REJECT
      ? FTUN_ROUTE_DENY : FTUN_ROUTE_READY;
    route.generation = metadata->generation;
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
    status = ftun_route_evaluate(runtime, metadata, 0u, &route);
  }
  if (status == FTUN_OK && route.kind == FTUN_ROUTE_DENY) {
    status = FTUN_E_REJECTED;
  } else if (status == FTUN_OK && route.kind != FTUN_ROUTE_READY) {
    status = FTUN_E_RESOLVE;
  }
  if (status == FTUN_OK) {
    status = ftun_proxy_runtime_leaf(engine, runtime, config, route.outbound_id,
                              route.generation, &leaf, &proxy_config);
  }
  if (status == FTUN_OK && (leaf.kind == FTUN_OUTBOUND_LEAF_REJECT ||
      (leaf.kind == FTUN_OUTBOUND_LEAF_SOCKS5 && !leaf.supports_udp))) {
    status = FTUN_E_REJECTED;
  } else if (status == FTUN_OK && leaf.kind != FTUN_OUTBOUND_LEAF_DIRECT &&
             leaf.kind != FTUN_OUTBOUND_LEAF_SOCKS5) {
    status = FTUN_E_UNSUPPORTED;
  }
  if (status == FTUN_OK && leaf.kind == FTUN_OUTBOUND_LEAF_SOCKS5 &&
      !ftun_proxy_runtime_udp_backoff_allowed(engine, leaf.id)) {
    status = FTUN_E_AGAIN;
  }
  if (status == FTUN_OK) {
    route.outbound_id = leaf.id;
    status = ftun_target_from_metadata(metadata, &target);
  }
  if (status == FTUN_OK) status = ftun_target_apply_route(&target, &route);
  if (status == FTUN_OK && target.allowed_count == 0u &&
      leaf.kind == FTUN_OUTBOUND_LEAF_DIRECT) {
    status = FTUN_E_REJECTED;
  }
  if (status != FTUN_OK) return status;

  {
    ftun_proxy_slot_token_t token;
    status = ftun_proxy_slot_pool_acquire(engine->udp_pool,
      (void **)&slot, &token);
    if (status == FTUN_OK) {
      slot->slot_token = token;
      slot->engine = engine;
    }
  }
  if (status != FTUN_OK) return status;
  status = ftun_proxy_runtime_object_admit(engine,
    (ftun_budget_resources_t){0u, 0u, 1u},
    &slot->budget, &slot->admission);
  if (status != FTUN_OK) {
    (void)ftun_proxy_runtime_udp_slot_reset(slot);
    return status;
  }
  if (target.allowed_count != 0u) {
    slot->remote = target.allowed[0];
  } else {
    slot->remote.kind = FTUN_ADDRESS_DOMAIN;
    slot->remote.domain = target.identity;
    slot->remote.port = target.original.port;
  }
  slot->socks5 = leaf.kind == FTUN_OUTBOUND_LEAF_SOCKS5;
  slot->outbound_id = leaf.id;
  slot->open_status = FTUN_E_AGAIN;
  slot->active = true;
  if (admission != NULL) {
    status = ftun_path_scope_retain(admission->path);
    if (status == FTUN_OK) slot->path_scope = admission->path;
    if (status == FTUN_OK) status = ftun_resolver_scope_retain(admission->resolver);
    if (status == FTUN_OK) slot->resolver_scope = admission->resolver;
  } else {
    status = ftun_path_provider_scope(engine->path_provider, metadata->generation, &slot->path_scope);
    if (status == FTUN_OK) status = ftun_resolver_provider_scope(
      engine->resolver_provider, metadata->generation, &slot->resolver_scope);
  }
  if (status != FTUN_OK) { (void)ftun_proxy_runtime_udp_slot_reset(slot); return status; }
  memset(&options, 0, sizeof(options));
  options.budget = slot->budget;
  options.max_pending_packets = FTUN_PROXY_RUNTIME_DATAGRAM_CAPACITY;
  options.max_pending_bytes = 256u * 1024u;
  options.result = result;
  options.receive = receive;
  options.user = callback_user;
  memset(&backend, 0, sizeof(backend));
  backend.send_start = ftun_proxy_runtime_udp_send_start;
  backend.send_cancel = ftun_proxy_runtime_udp_send_cancel;
  backend.destroy = ftun_proxy_runtime_udp_destroy;
  backend.context = slot;
  status = ftun_datagram_create(&options, &backend, &slot->channel);
  if (status != FTUN_OK) {
    (void)ftun_proxy_runtime_udp_slot_reset(slot);
    return status;
  }

  memset(&direct, 0, sizeof(direct));
  memset(&request, 0, sizeof(request));
  request.route = &route;
  request.target = &target;
  request.leaf = &leaf;
  request.transport = FTUN_DIAL_UDP;
  if (leaf.kind == FTUN_OUTBOUND_LEAF_DIRECT) {
    direct.loop = engine->loop;
    direct.operations = engine->operations;
    direct.budget = slot->budget;
    direct.protection.mark = engine->socket_mark;
    direct.protection.liveness = engine->liveness;
    status = ftun_monotonic_now(&direct.deadline_ms);
    if (status == FTUN_OK && direct.deadline_ms <=
        UINT64_MAX - engine->connect_ms) {
      direct.deadline_ms += engine->connect_ms;
    } else if (status == FTUN_OK) {
      status = FTUN_E_LIMIT;
    }
    direct.transport = FTUN_DIAL_UDP;
    direct.scope = slot->path_scope;
    direct.path_completion = ftun_proxy_runtime_udp_direct_completed;
    direct.user = slot;
    direct.notify = ftun_proxy_runtime_udp_path_notify;
    direct.notify_user = slot;
    direct.datagram.max_pending_packets = 1u;
    direct.datagram.max_pending_bytes = UINT16_MAX;
    direct.datagram.result = ftun_proxy_runtime_udp_sent;
    direct.datagram.receive = ftun_proxy_runtime_udp_received;
    direct.datagram.user = slot;
    request.direct = &direct;
    if (status == FTUN_OK) {
      status = ftun_outbound_open(core, &request, &reject,
                                  &slot->open_operation);
    }
  } else {
    status = ftun_proxy_runtime_parse_server_endpoint(proxy_config->server,
                                                      &proxy_server);
    if (status == FTUN_OK) {
      status = ftun_proxy_runtime_udp_socks_prepare(slot, &target, proxy_config,
                                             &proxy_server);
    }
    if (status == FTUN_OK && proxy_server.kind == FTUN_ADDRESS_DOMAIN) {
      status = ftun_proxy_runtime_resolve_async(engine, slot->budget, config,
        slot->resolver_scope,
        slot->proxy_server.domain, true, ftun_proxy_runtime_udp_proxy_resolved, slot,
        &slot->open_operation);
    } else if (status == FTUN_OK) {
      status = ftun_proxy_runtime_udp_socks_start(slot);
    }
  }
  if (status != FTUN_OK) {
    (void)ftun_datagram_stop(slot->channel);
    (void)ftun_datagram_destroy(&slot->channel);
    return status;
  }
  *outbound_id = leaf.id;
  *remote = slot->remote;
  *out = slot->channel;
  return FTUN_OK;
}

void ftun_proxy_runtime_udp_pending_release(
  ftun_proxy_runtime_udp_pending_t *pending)
{
  ftun_proxy_runtime_t *engine;
  ftun_proxy_slot_token_t token;
  void *owned;
  if (pending == NULL || pending->engine == NULL) return;
  engine = pending->engine;
  token = pending->slot_token;
  if (pending->tun) engine->tun_pending_count--;
  (void)ftun_datagram_release(&pending->inbound);
  (void)ftun_resolver_scope_release(&pending->resolver_scope);
  (void)ftun_path_scope_release(&pending->path_scope);
  (void)ftun_packet_release(&pending->packet);
  (void)ftun_runtime_release(&pending->runtime);
  owned = pending;
  if (ftun_proxy_slot_pool_release(engine->udp_pending_pool, token,
                                    &owned) != FTUN_OK) {
    ftun_proxy_runtime_background_log(engine, FTUN_E_STATE_CORRUPT,
                                      FTUN_DIAGNOSTIC_UDP_RELEASE, "UDP pending slot release failed");
  }
}

void ftun_proxy_runtime_udp_pending_cancel_inbound(
  ftun_proxy_runtime_t *engine, ftun_datagram_t *inbound)
{
  size_t index;
  if (engine == NULL || inbound == NULL) return;
  for (index = 0u; index < engine->udp_capacity; index++) {
    ftun_proxy_runtime_udp_pending_t *pending =
      ftun_proxy_runtime_udp_pending_at(engine, index);
    if (pending == NULL) continue;
    if (pending->active && pending->inbound == inbound) {
      pending->cancelled = true;
      if (pending->operation != NULL) (void)ftun_operation_cancel(pending->operation);
    }
  }
}

void ftun_proxy_runtime_udp_pending_cancel_all(ftun_proxy_runtime_t *engine)
{
  size_t index;
  if (engine == NULL) return;
  for (index = 0u; index < engine->udp_capacity; index++) {
    ftun_proxy_runtime_udp_pending_t *pending =
      ftun_proxy_runtime_udp_pending_at(engine, index);
    if (pending == NULL) continue;
    if (pending->active) {
      pending->cancelled = true;
      if (pending->operation != NULL) (void)ftun_operation_cancel(pending->operation);
    }
  }
}

ftun_status_t ftun_proxy_runtime_udp_route_own(
  ftun_route_result_t *route)
{
  if (route == NULL || route->allowed_count > FTUN_ROUTE_MAX_CANDIDATES ||
      (route->allowed_count != 0u && route->allowed == NULL)) {
    return FTUN_E_INVALID;
  }
  if (route->allowed_count != 0u && route->allowed != route->allowed_storage) {
    memcpy(route->allowed_storage, route->allowed,
      route->allowed_count * sizeof(route->allowed_storage[0]));
    route->allowed = route->allowed_storage;
  }
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_resolve_async(
  ftun_proxy_runtime_t *engine, ftun_budget_t *budget,
  const ftun_config_t *config, ftun_resolver_scope_t *scope,
  ftun_string_t domain, bool bootstrap_only,
  ftun_system_resolve_completion_fn completion, void *user,
  ftun_operation_t **out)
{
  ftun_bootstrap_request_t query;
  ftun_string_t server = {NULL, 0u};
  ftun_endpoint_t bootstrap[FTUN_BOOTSTRAP_MAX_SERVERS];
  size_t index;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (engine == NULL || budget == NULL || config == NULL || domain.data == NULL ||
      domain.length == 0u || completion == NULL || out == NULL) {
    return FTUN_E_INVALID;
  }
  memset(&query, 0, sizeof(query));
  query.loop = engine->loop;
  query.operations = engine->operations;
  query.worker = engine->worker;
  query.budget = budget;
  query.domain = domain;
  query.protection.mark = engine->socket_mark;
  query.protection.liveness = engine->liveness;
  query.check_system_path = ftun_proxy_runtime_system_resolver_path;
  query.system_path_user = engine;
  query.completion = completion;
  query.user = user;
  status = ftun_monotonic_now(&query.deadline_ms);
  if (status == FTUN_OK && query.deadline_ms <=
      UINT64_MAX - engine->connect_ms) {
    query.deadline_ms += engine->connect_ms;
  } else if (status == FTUN_OK) {
    status = FTUN_E_LIMIT;
  }
  engine->next_dns_query_id++;
  if (engine->next_dns_query_id == 0u) engine->next_dns_query_id++;
  query.query_id = engine->next_dns_query_id;
  for (index = 0u; status == FTUN_OK &&
       index < ftun_config_resolver(config).bootstrap.count; index++) {
    status = ftun_proxy_runtime_parse_bootstrap_endpoint(
      ftun_config_resolver(config).bootstrap.items[index], &bootstrap[index]);
  }
  if (status != FTUN_OK) return status;
  query.servers = bootstrap;
  query.server_count = ftun_config_resolver(config).bootstrap.count;
  if (!bootstrap_only && ftun_config_resolver(config).default_server != NULL &&
      ftun_config_resolver(config).default_server[0] != '\0') {
    server.data = ftun_config_resolver(config).default_server;
    server.length = strlen(ftun_config_resolver(config).default_server);
  }
  return ftun_proxy_dns_resolve_with_provider(engine->core, scope,
    ftun_config_resolver(config).enable, server, &query,
    bootstrap_only ? FTUN_DIAL_PURPOSE_PROXY : FTUN_DIAL_PURPOSE_BUSINESS, out);
}

ftun_status_t ftun_proxy_runtime_udp_finish_route(
  ftun_proxy_runtime_udp_pending_t *pending, bool after_resolution)
{
  const ftun_config_t *config = NULL;
  const ftun_config_inbound_t *inbound;
  const ftun_config_outbound_t *proxy_config = NULL;
  ftun_outbound_leaf_t leaf;
  ftun_status_t status;
  uint32_t forced = 0u;
  bool has_forced = false;
  status = ftun_runtime_config(pending->runtime, &config);
  inbound = status == FTUN_OK
    ? ftun_proxy_runtime_inbound_by_id(config, pending->metadata.inbound_id) : NULL;
  if (status == FTUN_OK && inbound == NULL) status = FTUN_E_STALE;
  if (status == FTUN_OK && !after_resolution &&
      inbound->outbound != NULL && inbound->outbound[0] != '\0') {
    has_forced = true;
    status = ftun_runtime_resolve_outbound_name(pending->runtime,
      (ftun_string_t){inbound->outbound, strlen(inbound->outbound)}, &forced);
  }
  if (status == FTUN_OK && after_resolution && pending->preserve_route) {
    size_t index;
    pending->route.allowed_count = pending->metadata.resolved_count;
    for (index = 0u; index < pending->route.allowed_count; index++) {
      pending->route.allowed_storage[index] = pending->resolved[index];
    }
    pending->route.allowed = pending->route.allowed_count == 0u
      ? NULL : pending->route.allowed_storage;
  } else if (status == FTUN_OK && has_forced) {
    memset(&pending->route, 0, sizeof(pending->route));
    pending->route.kind = forced == FTUN_OUTBOUND_ID_REJECT
      ? FTUN_ROUTE_DENY : FTUN_ROUTE_READY;
    pending->route.generation = pending->metadata.generation;
    pending->route.outbound_id = forced;
    if (pending->metadata.original_target.kind == FTUN_ADDRESS_IPV4 &&
        !pending->metadata.original_is_fake) {
      pending->route.allowed = &pending->metadata.original_target;
      pending->route.allowed_count = 1u;
    } else {
      pending->route.allowed = pending->metadata.resolved;
      pending->route.allowed_count = pending->metadata.resolved_count;
    }
  } else if (status == FTUN_OK) {
    status = ftun_route_evaluate(pending->runtime, &pending->metadata,
      after_resolution ? pending->resume_rule : 0u, &pending->route);
  }
  if (status == FTUN_OK && pending->route.kind == FTUN_ROUTE_NEED_RESOLVE) {
    pending->resume_rule = pending->route.resume_rule;
    return FTUN_E_RESOLVE;
  }
  if (status == FTUN_OK && pending->route.kind == FTUN_ROUTE_DENY) {
    status = FTUN_E_REJECTED;
  } else if (status == FTUN_OK && pending->route.kind != FTUN_ROUTE_READY) {
    status = FTUN_E_STATE_CORRUPT;
  }
  if (status == FTUN_OK) status = ftun_proxy_runtime_udp_route_own(&pending->route);
  if (status == FTUN_OK) {
    status = ftun_proxy_runtime_leaf(pending->engine, pending->runtime, config,
      pending->route.outbound_id, pending->route.generation, &leaf,
      &proxy_config);
  }
  (void)proxy_config;
  if (status == FTUN_OK && (leaf.kind == FTUN_OUTBOUND_LEAF_REJECT ||
      (leaf.kind == FTUN_OUTBOUND_LEAF_SOCKS5 && !leaf.supports_udp))) {
    status = FTUN_E_REJECTED;
  }
  if (status == FTUN_OK) pending->route.outbound_id = leaf.id;
  if (status == FTUN_OK && leaf.kind == FTUN_OUTBOUND_LEAF_DIRECT &&
      pending->route.allowed_count == 0u) {
    if (after_resolution) return FTUN_E_RESOLVE;
    pending->preserve_route = true;
    return FTUN_E_RESOLVE;
  }
  if (status == FTUN_OK) {
    ftun_udp_flow_admission_t admission;
    admission.runtime = pending->runtime;
    admission.path = pending->path_scope;
    admission.resolver = pending->resolver_scope;
    status = ftun_udp_flow_input_routed(pending->engine->udp_flows,
      pending->inbound, &pending->metadata, &pending->route,
      &admission, &pending->packet);
  }
  return status;
}

void ftun_proxy_runtime_udp_resolved(
  ftun_operation_t *operation, ftun_error_t error,
  const ftun_system_resolve_result_t *result, void *user)
{
  ftun_proxy_runtime_udp_pending_t *pending =
    (ftun_proxy_runtime_udp_pending_t *)user;
  ftun_status_t status = error.status;
  size_t index;
  if (pending == NULL || !pending->active ||
      pending->operation != operation) return;
  pending->operation = NULL;
  if (pending->cancelled || !pending->engine->accepting) status = FTUN_E_CANCELLED;
#if defined(FTUN_HAVE_MODULE_TUN)
  if (pending->tun && pending->engine->tun_resetting) status = FTUN_E_CANCELLED;
#endif
  if (status == FTUN_OK) {
    ftun_datagram_usage_t usage;
    status = ftun_datagram_get_usage(pending->inbound, &usage);
    if (status == FTUN_OK && !usage.accepting) status = FTUN_E_CANCELLED;
  }
  if (status == FTUN_OK && (result == NULL || result->address_count == 0u ||
      result->address_count > FTUN_UDP_FLOW_MAX_RESOLVED_IPV4)) {
    status = FTUN_E_STATE_CORRUPT;
  }
  for (index = 0u; status == FTUN_OK && index < result->address_count;
       index++) {
    if (result->addresses[index].kind != FTUN_ADDRESS_IPV4) {
      status = FTUN_E_UNSUPPORTED;
      break;
    }
    pending->resolved[index] = result->addresses[index];
    pending->resolved[index].port = pending->metadata.original_target.port;
    pending->resolved[index].domain.data = NULL;
    pending->resolved[index].domain.length = 0u;
  }
  if (status == FTUN_OK) {
    pending->metadata.resolved = pending->resolved;
    pending->metadata.resolved_count = result->address_count;
    status = ftun_proxy_runtime_udp_finish_route(pending, true);
  }
  ftun_proxy_runtime_udp_pending_release(pending);
}

ftun_status_t ftun_proxy_runtime_udp_route_datagram(
  ftun_proxy_runtime_t *engine, ftun_datagram_t *inbound,
  const ftun_metadata_t *metadata, const ftun_packet_t *packet,
  ftun_runtime_t *runtime, bool tun)
{
  ftun_proxy_runtime_udp_pending_t *pending = NULL;
  ftun_metadata_t restored;
  ftun_runtime_info_t info;
  const ftun_config_t *config = NULL;
  char restored_domain[254];
  bool found = false;
  ftun_status_t status;
  if (engine == NULL || inbound == NULL || metadata == NULL || packet == NULL) {
    return FTUN_E_INVALID;
  }
  restored = *metadata;
  if ((metadata->known_fields & FTUN_META_DOMAIN) != 0u) {
    if (metadata->domain.data == NULL || metadata->domain.length == 0u ||
        metadata->domain.length >= sizeof(restored_domain)) {
      return FTUN_E_INVALID;
    }
    memcpy(restored_domain, metadata->domain.data, metadata->domain.length);
    restored_domain[metadata->domain.length] = '\0';
    restored.domain.data = restored_domain;
    if (metadata->original_target.kind == FTUN_ADDRESS_DOMAIN) {
      restored.original_target.domain.data = restored_domain;
    }
  }
  status = ftun_proxy_runtime_restore_fakeip_to(engine, &restored,
    restored_domain, sizeof(restored_domain));
  if (status != FTUN_OK) return status;
  status = ftun_udp_flow_input_existing(engine->udp_flows, inbound, &restored,
    (ftun_packet_t *)packet, &found);
  if (status != FTUN_OK || found) return status;

  {
    ftun_proxy_slot_token_t token;
    status = ftun_proxy_slot_pool_acquire(engine->udp_pending_pool,
      (void **)&pending, &token);
    if (status != FTUN_OK) return status;
    pending->slot_token = token;
  }
  pending->engine = engine;
  pending->tun = tun;
  if (tun) engine->tun_pending_count++;
  status = ftun_datagram_retain(inbound);
  if (status != FTUN_OK) goto pending_fail;
  pending->inbound = inbound;
  pending->metadata = restored;
  if ((restored.known_fields & FTUN_META_DOMAIN) != 0u) {
    if (restored.domain.data == NULL || restored.domain.length == 0u ||
        restored.domain.length >= sizeof(pending->domain)) {
      status = FTUN_E_INVALID;
      goto pending_fail;
    }
    memcpy(pending->domain, restored.domain.data, restored.domain.length);
    pending->domain[restored.domain.length] = '\0';
    pending->metadata.domain.data = pending->domain;
    if (restored.original_target.kind == FTUN_ADDRESS_DOMAIN) {
      pending->metadata.original_target.domain.data = pending->domain;
    }
  }
  if (metadata->resolved_count != 0u) {
    if (metadata->resolved == NULL ||
        metadata->resolved_count > FTUN_UDP_FLOW_MAX_RESOLVED_IPV4) {
      status = FTUN_E_INVALID;
      goto pending_fail;
    }
    memcpy(pending->resolved, metadata->resolved,
      metadata->resolved_count * sizeof(pending->resolved[0]));
    pending->metadata.resolved = pending->resolved;
  }
  pending->active = true;
  if (runtime != NULL) {
    status = ftun_runtime_retain(runtime);
    if (status == FTUN_OK) pending->runtime = runtime;
  } else {
    status = ftun_runtime_active_acquire(engine->core, &pending->runtime);
  }
  if (status == FTUN_OK) status = ftun_runtime_get_info(pending->runtime,
                                                        &info);
  if (status == FTUN_OK && info.generation != pending->metadata.generation) {
    status = FTUN_E_STALE;
  }
  if (status == FTUN_OK) status = ftun_runtime_config(pending->runtime,
                                                       &config);
  if (status == FTUN_OK) status = ftun_packet_clone(packet, &pending->packet);
  if (status == FTUN_OK) status = ftun_path_provider_scope(engine->path_provider,
    pending->metadata.generation, &pending->path_scope);
  if (status == FTUN_OK) status = ftun_resolver_provider_scope(engine->resolver_provider,
    pending->metadata.generation, &pending->resolver_scope);
  if (status == FTUN_OK) status = ftun_proxy_runtime_udp_finish_route(pending, false);
  if (status == FTUN_E_RESOLVE) {
    ftun_string_t domain = pending->metadata.domain;
    if (domain.length == 0u &&
        pending->metadata.original_target.kind == FTUN_ADDRESS_DOMAIN) {
      domain = pending->metadata.original_target.domain;
    }
    status = ftun_proxy_runtime_resolve_async(engine, engine->budget, config,
      pending->resolver_scope,
      domain, false,
      ftun_proxy_runtime_udp_resolved, pending, &pending->operation);
    if (status == FTUN_OK) return FTUN_OK;
  }
pending_fail:
  ftun_proxy_runtime_udp_pending_release(pending);
  return status;
}

ftun_status_t ftun_proxy_runtime_udp_received(ftun_datagram_t *channel,
  const ftun_endpoint_t *source, const ftun_packet_t *packet, void *user)
{
  ftun_proxy_runtime_udp_slot_t *slot = user;
  ftun_status_t status;
  (void)channel;
  if (slot->destroying || slot->channel == NULL) return FTUN_E_CANCELLED;
  if (!slot->ready) return FTUN_E_AGAIN;
  if (!ftun_proxy_runtime_endpoint_equal(source, &slot->remote)) return FTUN_OK;
  status = ftun_datagram_deliver(slot->channel, &slot->remote, packet);
  if (status == FTUN_OK && slot->socks5) ftun_proxy_runtime_udp_backoff_succeeded(slot->engine, slot->outbound_id);
  return status;
}

ftun_status_t ftun_proxy_runtime_association_send_start(
  void *user, ftun_datagram_send_token_t send,
  const ftun_endpoint_t *target,
  const ftun_packet_t *packet)
{
  (void)user;
  (void)send;
  (void)target;
  (void)packet;
  return FTUN_E_STATE_CORRUPT;
}

ftun_status_t ftun_proxy_runtime_association_send_cancel(
  void *user, ftun_datagram_send_token_t send)
{
  (void)user;
  (void)send;
  return FTUN_E_STALE;
}

void ftun_proxy_runtime_association_destroy(void *user)
{
  (void)user;
}

void ftun_proxy_runtime_association_result(
  ftun_datagram_t *channel, ftun_error_t error,
  const ftun_endpoint_t *target, const ftun_packet_t *packet, void *user)
{
  (void)channel;
  (void)error;
  (void)target;
  (void)packet;
  (void)user;
}

ftun_status_t ftun_proxy_runtime_association_receive(
  ftun_datagram_t *channel, const ftun_endpoint_t *source,
  const ftun_packet_t *packet, void *user)
{
  (void)channel;
  (void)source;
  (void)packet;
  (void)user;
  return FTUN_E_STATE_CORRUPT;
}

size_t ftun_proxy_runtime_association_client_bucket(
  const ftun_proxy_runtime_t *engine,
  const ftun_proxy_runtime_listener_t *listener, const ftun_endpoint_t *client)
{
  uint32_t hash = UINT32_C(2166136261);
  uintptr_t identity = (uintptr_t)listener;
  size_t index;
  for (index = 0u; index < sizeof(identity); index++) {
    hash = (hash ^ (uint8_t)(identity >> (index * 8u))) *
      UINT32_C(16777619);
  }
  for (index = 0u; index < 4u; index++) {
    hash = (hash ^ client->address[index]) * UINT32_C(16777619);
  }
  hash = (hash ^ client->port) * UINT32_C(16777619);
  return (size_t)(hash % engine->association_bucket_count);
}

size_t ftun_proxy_runtime_association_channel_bucket(
  const ftun_proxy_runtime_t *engine, const ftun_datagram_t *channel)
{
  uintptr_t value = (uintptr_t)channel;
  value ^= value >> 17u;
  value *= (uintptr_t)UINT32_C(0xed5ad4bb);
  value ^= value >> 11u;
  return (size_t)(value % engine->association_bucket_count);
}

void ftun_proxy_runtime_association_index_client(ftun_proxy_runtime_flow_t *flow)
{
  size_t bucket;
  if (flow == NULL || flow->association_client_indexed ||
      !flow->udp_client_pinned || flow->listener == NULL) return;
  bucket = ftun_proxy_runtime_association_client_bucket(flow->engine,
                                                  flow->listener,
                                                  &flow->udp_client);
  flow->association_client_next = flow->engine->association_clients[bucket];
  flow->engine->association_clients[bucket] = flow;
  flow->association_client_indexed = true;
}

void ftun_proxy_runtime_association_index_channel(ftun_proxy_runtime_flow_t *flow)
{
  size_t bucket;
  if (flow == NULL || flow->association_channel_indexed ||
      flow->udp_channel == NULL) return;
  bucket = ftun_proxy_runtime_association_channel_bucket(flow->engine,
                                                   flow->udp_channel);
  flow->association_channel_next = flow->engine->association_channels[bucket];
  flow->engine->association_channels[bucket] = flow;
  flow->association_channel_indexed = true;
}

void ftun_proxy_runtime_association_unlink(ftun_proxy_runtime_flow_t *flow)
{
  ftun_proxy_runtime_flow_t **cursor;
  size_t bucket;
  if (flow == NULL || flow->engine == NULL) return;
  if (flow->association_client_indexed && flow->listener != NULL) {
    bucket = ftun_proxy_runtime_association_client_bucket(flow->engine,
                                                    flow->listener,
                                                    &flow->udp_client);
    for (cursor = &flow->engine->association_clients[bucket];
         *cursor != NULL; cursor = &(*cursor)->association_client_next) {
      if (*cursor == flow) {
        *cursor = flow->association_client_next;
        break;
      }
    }
  }
  if (flow->association_channel_indexed && flow->udp_channel != NULL) {
    bucket = ftun_proxy_runtime_association_channel_bucket(flow->engine,
                                                     flow->udp_channel);
    for (cursor = &flow->engine->association_channels[bucket];
         *cursor != NULL; cursor = &(*cursor)->association_channel_next) {
      if (*cursor == flow) {
        *cursor = flow->association_channel_next;
        break;
      }
    }
  }
  flow->association_client_next = NULL;
  flow->association_channel_next = NULL;
  flow->association_client_indexed = false;
  flow->association_channel_indexed = false;
}

ftun_proxy_runtime_flow_t *ftun_proxy_runtime_association_find_channel(
  ftun_proxy_runtime_t *engine, ftun_datagram_t *channel)
{
  ftun_proxy_runtime_flow_t *flow;
  size_t bucket = ftun_proxy_runtime_association_channel_bucket(engine,
                                                          channel);
  for (flow = engine->association_channels[bucket]; flow != NULL;
       flow = flow->association_channel_next) {
    if (flow->active && flow->udp_channel == channel) return flow;
  }
  return NULL;
}

ftun_status_t ftun_proxy_runtime_udp_reply(
  void *user, ftun_datagram_t *inbound, const ftun_metadata_t *metadata,
  const ftun_endpoint_t *source, const ftun_packet_t *packet)
{
  ftun_proxy_runtime_t *engine = (ftun_proxy_runtime_t *)user;
  ftun_proxy_runtime_flow_t *association = NULL;
  ftun_bytes_t payload;
  uint8_t wire[UINT16_MAX + 263u];
  size_t written = 0u;
  ptrdiff_t sent;
  ftun_status_t status;
  if (engine == NULL || inbound == NULL || metadata == NULL ||
      source == NULL || packet == NULL) return FTUN_E_INVALID;
  association = ftun_proxy_runtime_association_find_channel(engine, inbound);
  if (association == NULL) {
    return ftun_datagram_send(inbound, &metadata->source,
                              (ftun_packet_t *)packet);
  }
  if (!association->udp_client_pinned ||
      association->listener == NULL ||
      association->listener->udp_descriptor < 0) return FTUN_E_STALE;
  status = ftun_packet_view(packet, &payload);
  if (status == FTUN_OK) {
    status = ftun_socks5_encode_udp_datagram(source, payload, wire,
                                             sizeof(wire), &written);
  }
  if (status != FTUN_OK) return status;
  sent = ftun_socket_send_to(association->listener->udp_descriptor, wire, written,
    &association->udp_client, &status);
  if (sent < 0 && status == FTUN_E_AGAIN) return FTUN_OK;
  if (sent < 0) return status;
  return (size_t)sent == written ? FTUN_OK : FTUN_E_IO;
}

ftun_status_t ftun_proxy_runtime_association_start(
  ftun_proxy_runtime_flow_t *flow, const ftun_endpoint_t *requested)
{
  ftun_datagram_options_t options;
  ftun_datagram_backend_t backend;
  ftun_runtime_info_t runtime_info;
  ftun_endpoint_t bound;
  ftun_status_t status;
  if (flow == NULL || requested == NULL || flow->listener == NULL ||
      flow->listener->udp_descriptor < 0 ||
      requested->kind != FTUN_ADDRESS_IPV4) return FTUN_E_UNSUPPORTED;
  status = ftun_proxy_runtime_flow_classify(
    flow, FTUN_PROXY_RUNTIME_FLOW_ASSOCIATION);
  if (status != FTUN_OK) return status;
  status = ftun_runtime_active_acquire(flow->engine->core,
                                       &flow->udp_runtime);
  if (status == FTUN_OK) {
    status = ftun_runtime_get_info(flow->udp_runtime, &runtime_info);
  }
  if (status == FTUN_OK) {
    flow->udp_generation = runtime_info.generation;
    flow->udp_inbound_id = flow->listener->inbound_id;
  }
  if (status != FTUN_OK) goto fail;
  memset(&options, 0, sizeof(options));
  options.budget = flow->budget;
  options.max_pending_packets = 1u;
  options.max_pending_bytes = 1u;
  options.result = ftun_proxy_runtime_association_result;
  options.receive = ftun_proxy_runtime_association_receive;
  options.user = flow;
  memset(&backend, 0, sizeof(backend));
  backend.send_start = ftun_proxy_runtime_association_send_start;
  backend.send_cancel = ftun_proxy_runtime_association_send_cancel;
  backend.destroy = ftun_proxy_runtime_association_destroy;
  backend.context = flow;
  status = ftun_datagram_create(&options, &backend, &flow->udp_channel);
  if (status != FTUN_OK) goto fail;
  memset(&bound, 0, sizeof(bound));
  status = ftun_socket_name(flow->listener->udp_descriptor, &bound);
  if (status == FTUN_OK && bound.address[0] == 0u && bound.address[1] == 0u &&
      bound.address[2] == 0u && bound.address[3] == 0u) {
    status = ftun_socket_name(flow->client_socket.descriptor, &bound);
  }
  if (status == FTUN_OK) {
    flow->udp_request = *requested;
    flow->state = FTUN_PROXY_RUNTIME_FLOW_UDP_ASSOCIATE;
    status = ftun_proxy_runtime_protocol_finish(flow, FTUN_OK, &bound);
  }
  if (status == FTUN_OK) {
    ftun_proxy_runtime_association_index_channel(flow);
    return FTUN_OK;
  }

fail:
  if (flow->udp_channel != NULL) {
    (void)ftun_datagram_stop(flow->udp_channel);
    (void)ftun_datagram_destroy(&flow->udp_channel);
  }
  (void)ftun_runtime_release(&flow->udp_runtime);
  flow->udp_generation = 0u;
  flow->udp_inbound_id = 0u;
  ftun_proxy_runtime_flow_unclassify(flow);
  return status;
}

bool ftun_proxy_runtime_zero_ipv4(const ftun_endpoint_t *endpoint)
{
  static const uint8_t zero[4] = {0u, 0u, 0u, 0u};
  return endpoint != NULL && endpoint->kind == FTUN_ADDRESS_IPV4 &&
         memcmp(endpoint->address, zero, sizeof(zero)) == 0;
}

ftun_proxy_runtime_flow_t *ftun_proxy_runtime_association_find(
  ftun_proxy_runtime_t *engine, ftun_proxy_runtime_listener_t *listener,
  const ftun_endpoint_t *client)
{
  ftun_proxy_runtime_flow_t *flow;
  size_t bucket = ftun_proxy_runtime_association_client_bucket(engine,
                                                         listener, client);
  size_t index;
  for (flow = engine->association_clients[bucket]; flow != NULL;
       flow = flow->association_client_next) {
    if (flow->active && flow->listener == listener &&
        flow->state == FTUN_PROXY_RUNTIME_FLOW_UDP_ASSOCIATE &&
        ftun_proxy_runtime_endpoint_equal(&flow->udp_client, client)) return flow;
  }
  for (index = 0u; index < engine->flow_capacity; index++) {
    flow = ftun_proxy_runtime_flow_at(engine, index);
    if (flow == NULL) continue;
    if (!flow->active || flow->listener != listener ||
        flow->state != FTUN_PROXY_RUNTIME_FLOW_UDP_ASSOCIATE ||
        flow->udp_client_pinned ||
        flow->tcp_peer.kind != FTUN_ADDRESS_IPV4 ||
        memcmp(flow->tcp_peer.address, client->address, 4u) != 0) {
      continue;
    }
    if (!ftun_proxy_runtime_zero_ipv4(&flow->udp_request) &&
        memcmp(flow->udp_request.address, client->address, 4u) != 0) continue;
    if (flow->udp_request.port != 0u &&
        flow->udp_request.port != client->port) continue;
    flow->udp_client = *client;
    flow->udp_client_pinned = true;
    ftun_proxy_runtime_association_index_client(flow);
    return flow;
  }
  return NULL;
}

ftun_status_t ftun_proxy_runtime_listener_udp(ftun_proxy_runtime_t *engine,
                                               ftun_proxy_runtime_listener_t *listener)
{
  uint8_t wire[65535];
  size_t received;
  for (received = 0u; received < FTUN_PROXY_RUNTIME_DATAGRAM_QUOTA; received++) {
    ftun_proxy_runtime_flow_t *flow;
    ftun_socks5_udp_datagram_t datagram;
    ftun_endpoint_t client;
    ftun_metadata_t metadata;
    ftun_buffer_t *buffer = NULL;
    ftun_buffer_slice_t slice;
    ftun_packet_t packet;
    uint8_t *storage = NULL;
    size_t capacity = 0u;
    ptrdiff_t length;
    ftun_status_t status;
    length = ftun_socket_receive_from(listener->udp_descriptor, wire, sizeof(wire),
      &client, &status);
    if (length < 0) return status == FTUN_E_AGAIN ? FTUN_OK : status;
    if (client.port == 0u) continue;
    flow = ftun_proxy_runtime_association_find(engine, listener, &client);
    if (flow == NULL) continue;
    memset(&datagram, 0, sizeof(datagram));
    status = ftun_inbound_adapter_udp(flow->protocol,
      (ftun_bytes_t){wire, (size_t)length}, &datagram);
    if (status != FTUN_OK) continue;
    memset(&metadata, 0, sizeof(metadata));
    metadata.generation = flow->udp_generation;
    metadata.known_fields = FTUN_META_SOURCE | FTUN_META_PORT |
                            FTUN_META_NETWORK;
    metadata.inbound_id = flow->udp_inbound_id;
    metadata.network = 2u;
    metadata.source = client;
    metadata.original_target = datagram.endpoint;
    if (datagram.endpoint.kind == FTUN_ADDRESS_DOMAIN) {
      metadata.known_fields |= FTUN_META_DOMAIN;
      metadata.domain = datagram.endpoint.domain;
      metadata.domain_source = FTUN_DOMAIN_EXPLICIT;
    }
    memset(&slice, 0, sizeof(slice));
    memset(&packet, 0, sizeof(packet));
    if (status == FTUN_OK) {
      status = ftun_buffer_pool_acquire(engine->relay_pool,
        datagram.payload.length == 0u ? 1u : datagram.payload.length, &buffer);
    }
    if (status == FTUN_OK) {
      status = ftun_buffer_data(buffer, &storage, &capacity);
    }
    if (status == FTUN_OK && capacity < datagram.payload.length) {
      status = FTUN_E_STATE_CORRUPT;
    }
    if (status == FTUN_OK && datagram.payload.length != 0u) {
      memcpy(storage, datagram.payload.data, datagram.payload.length);
    }
    if (status == FTUN_OK) {
      status = ftun_buffer_slice(buffer, 0u, datagram.payload.length, &slice);
    }
    if (status == FTUN_OK) {
      status = ftun_packet_init(&packet, &slice, flow->udp_inbound_id);
    }
    (void)ftun_buffer_slice_release(&slice);
    (void)ftun_buffer_release(&buffer);
    if (status == FTUN_OK) {
      status = ftun_proxy_runtime_udp_route_datagram(engine, flow->udp_channel,
        &metadata, &packet, flow->udp_runtime, false);
    }
    (void)ftun_packet_release(&packet);
    /* Client/protocol/routing failures drop this datagram, not the daemon. */
    (void)status;
  }
  return FTUN_OK;
}

