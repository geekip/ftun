#define _GNU_SOURCE 1

#include "dns/service_internal.h"

#if defined(FTUN_HAVE_MODULE_DNS)

ftun_status_t ftun_dns_runtime_outbound_id(
  const ftun_config_t *config, const char *name, uint32_t *out)
{
  size_t index;
  if (config == NULL || name == NULL || out == NULL) return FTUN_E_INVALID;
  if (strcmp(name, "DIRECT") == 0) {
    *out = FTUN_DNS_OUTBOUND_DIRECT;
    return FTUN_OK;
  }
  if (strcmp(name, "REJECT") == 0) {
    *out = FTUN_DNS_OUTBOUND_REJECT;
    return FTUN_OK;
  }
  for (index = 0u; index < ftun_config_channel_count(config); index++) {
    if (strcmp(ftun_config_channel(config, index).name, name) == 0) {
      *out = (uint32_t)index + FTUN_DNS_OUTBOUND_NAMED_BASE;
      return FTUN_OK;
    }
  }
  return FTUN_E_INVALID;
}

ftun_status_t ftun_dns_runtime_named_index(ftun_string_t name,
                                                  size_t *out, void *user)
{
  ftun_dns_runtime_t *dns = (ftun_dns_runtime_t *)user;
  size_t index;
  for (index = 0u; index < ftun_config_dns(dns->config)->server_count; index++) {
    const char *candidate = ftun_config_dns(dns->config)->servers[index].name;
    if (strlen(candidate) == name.length &&
        memcmp(candidate, name.data, name.length) == 0) {
      *out = index;
      return FTUN_OK;
    }
  }
  return FTUN_E_INVALID;
}

ftun_status_t ftun_dns_runtime_select(uint32_t outbound_id,
                                             size_t *out, void *user)
{
  ftun_dns_runtime_t *dns = (ftun_dns_runtime_t *)user;
  if (outbound_id >= FTUN_DNS_OUTBOUND_NAMED_BASE) {
    size_t index = outbound_id - FTUN_DNS_OUTBOUND_NAMED_BASE;
    if (index < ftun_config_channel_count(dns->config)) {
      const char *name = ftun_config_channel(dns->config, index).dns_server;
      if (name != NULL && name[0] != '\0') {
        return ftun_dns_runtime_named_index(
          (ftun_string_t){name, strlen(name)}, out, user);
      }
    }
  }
  *out = dns->default_server;
  return FTUN_OK;
}

ftun_dns_runtime_pending_t *ftun_dns_runtime_pending(
  ftun_dns_runtime_t *dns, uint64_t id)
{
  size_t index;
  for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_PENDING; index++) {
    if (dns->pending[index].active && dns->pending[index].id == id) {
      return &dns->pending[index];
    }
  }
  return NULL;
}

void ftun_dns_runtime_pending_clear(ftun_dns_runtime_t *dns,
                                          ftun_dns_runtime_pending_t *pending)
{
  if (pending == NULL || !pending->active) return;
  if (pending->listener_index < dns->listener_count &&
      dns->listeners[pending->listener_index].pending_count != 0u) {
    dns->listeners[pending->listener_index].pending_count--;
  }
  ftun_datagram_release(&pending->inbound);
  if (dns->pending_count != 0u) dns->pending_count--;
  memset(pending, 0, sizeof(*pending));
  pending->descriptor = -1;
  pending->listener_index = SIZE_MAX;
}

ftun_dns_runtime_tcp_t *ftun_dns_runtime_tcp_find(
  ftun_dns_runtime_t *dns, uint64_t peer_id)
{
  size_t index;
  for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS; index++) {
    if (dns->tcp[index].active && dns->tcp[index].peer_id == peer_id) {
      return &dns->tcp[index];
    }
  }
  return NULL;
}

void ftun_dns_runtime_reply(ftun_dns_transport_t transport,
                                  uint64_t peer_id, ftun_error_t error,
                                  ftun_bytes_t response, void *user)
{
  ftun_dns_runtime_t *dns = (ftun_dns_runtime_t *)user;
  ftun_dns_runtime_pending_t *pending = ftun_dns_runtime_pending(dns, peer_id);
  if (transport == FTUN_DNS_TRANSPORT_TCP) {
    ftun_dns_runtime_tcp_t *connection = ftun_dns_runtime_tcp_find(dns, peer_id);
    ftun_dns_runtime_response_t *queued;
    ftun_reservation_t reservation = (ftun_reservation_t){0};
    size_t bytes;
    if (connection == NULL) return;
    /* 迟到完成仍归原连接；只触发回收，不再分配响应或恢复网络监听。 */
    if (connection->transport_failed) {
      ftun_dns_runtime_tcp_set_ready(connection, true);
      return;
    }
    if (error.status != FTUN_OK || response.data == NULL ||
        response.length < 2u || response.length > FTUN_DNS_MAX_MESSAGE_BYTES + 2u ||
        connection->response_count >= 4u ||
        response.length > SIZE_MAX - offsetof(ftun_dns_runtime_response_t,
                                               data)) {
      connection->peer_eof = true;
      ftun_dns_runtime_tcp_set_ready(connection, true);
      return;
    }
    bytes = offsetof(ftun_dns_runtime_response_t, data) + response.length;
    if (ftun_budget_reserve(dns->budget, bytes, &reservation) != FTUN_OK) {
      connection->peer_eof = true;
      ftun_dns_runtime_tcp_set_ready(connection, true);
      return;
    }
    queued = (ftun_dns_runtime_response_t *)malloc(bytes);
    if (queued == NULL) {
      ftun_reservation_release(&reservation);
      connection->peer_eof = true;
      ftun_dns_runtime_tcp_set_ready(connection, true);
      return;
    }
    memset(queued, 0, offsetof(ftun_dns_runtime_response_t, data));
    queued->reservation = reservation;
    queued->length = response.length;
    memcpy(queued->data, response.data, response.length);
    if (connection->response_tail != NULL) {
      connection->response_tail->next = queued;
    } else {
      connection->response_head = queued;
    }
    connection->response_tail = queued;
    connection->response_count++;
    ftun_dns_runtime_tcp_set_ready(connection, true);
    return;
  }
  if (pending == NULL) return;
  if (error.status == FTUN_OK && transport == FTUN_DNS_TRANSPORT_UDP) {
    if (pending->kind == FTUN_DNS_RUNTIME_PENDING_SOCKET) {
      ftun_status_t status;
      (void)ftun_socket_send_to(pending->descriptor, response.data, response.length,
        &pending->peer, &status);
    } else {
      ftun_buffer_t *buffer = NULL;
      ftun_buffer_slice_t slice;
      ftun_packet_t packet;
      uint8_t *storage = NULL;
      size_t capacity = 0u;
      memset(&slice, 0, sizeof(slice));
      memset(&packet, 0, sizeof(packet));
      if (ftun_buffer_acquire(dns->budget, response.length, &buffer) == FTUN_OK &&
          ftun_buffer_data(buffer, &storage, &capacity) == FTUN_OK &&
          capacity >= response.length) {
        memcpy(storage, response.data, response.length);
        if (ftun_buffer_slice(buffer, 0u, response.length, &slice) == FTUN_OK &&
            ftun_packet_init(&packet, &slice, 0u) == FTUN_OK) {
          (void)ftun_datagram_send(pending->inbound, &pending->client, &packet);
          ftun_packet_release(&packet);
        }
      }
      ftun_buffer_slice_release(&slice);
      ftun_buffer_release(&buffer);
    }
  }
  ftun_dns_runtime_pending_clear(dns, pending);
}

ftun_dns_runtime_pending_t *ftun_dns_runtime_pending_new(
  ftun_dns_runtime_t *dns, size_t listener_index)
{
  size_t scanned;
  if (dns->pending_count >= FTUN_DNS_RUNTIME_MAX_PENDING ||
      (listener_index < dns->listener_count &&
       dns->listeners[listener_index].pending_count >=
         FTUN_DNS_RUNTIME_MAX_PENDING_PER_LISTENER)) return NULL;
  for (scanned = 0u; scanned < FTUN_DNS_RUNTIME_MAX_PENDING; scanned++) {
    size_t index = (dns->pending_cursor + scanned) %
                   FTUN_DNS_RUNTIME_MAX_PENDING;
    ftun_dns_runtime_pending_t *pending = &dns->pending[index];
    if (pending->active) continue;
    memset(pending, 0, sizeof(*pending));
    pending->descriptor = -1;
    pending->listener_index = listener_index;
    pending->active = true;
    dns->pending_cursor = (index + 1u) % FTUN_DNS_RUNTIME_MAX_PENDING;
    dns->pending_count++;
    if (listener_index < dns->listener_count) {
      dns->listeners[listener_index].pending_count++;
    }
    dns->next_peer_id++;
    if (dns->next_peer_id == 0u) dns->next_peer_id++;
    pending->id = dns->next_peer_id;
    return pending;
  }
  return NULL;
}

ftun_status_t ftun_dns_runtime_protocol_create(
  ftun_dns_runtime_t *dns, bool policy, size_t fixed_server,
  uint32_t inbound_id, ftun_dns_listener_t **out)
{
  ftun_dns_listener_spec_t spec;
  memset(&spec, 0, sizeof(spec));
  spec.budget = dns->budget;
  spec.dispatcher = dns->dispatcher;
  spec.dispatch = dns->adapter.dispatch != NULL
    ? dns->adapter.dispatch : (policy ? NULL : ftun_dns_dispatch_fixed);
  spec.dispatch_user = dns->adapter.user;
  if (spec.dispatch == NULL) return FTUN_E_UNSUPPORTED;
  spec.entry = policy ? FTUN_DNS_ENTRY_POLICY : FTUN_DNS_ENTRY_FIXED;
  spec.fixed_server = fixed_server;
  spec.inbound_id = inbound_id;
  spec.query_timeout_ms = FTUN_DNS_RUNTIME_TIMEOUT_MS;
  spec.udp_payload_limit = 4096u;
  spec.max_tcp_connections = 64u;
  spec.max_tcp_inflight = 4u;
  spec.max_tcp_frame_bytes = FTUN_DNS_MAX_MESSAGE_BYTES;
  spec.reply = ftun_dns_runtime_reply;
  spec.reply_user = dns;
  return ftun_dns_listen(dns->core, &spec, out);
}

ftun_status_t ftun_dns_runtime_socket_open(const char *text,
  ftun_dial_transport_t type, ftun_handle_t *out, ftun_socket_bind_issue_t *issue)
{
  ftun_endpoint_t endpoint;
  ftun_status_t status = ftun_dns_runtime_parse_endpoint(text, &endpoint);
  if (status != FTUN_OK) return status;
  return ftun_socket_listen(&endpoint, type, 64, out, issue);
}

/* 打开一个监听槽的 UDP 与 TCP socket。地址暂不可用（EADDRNOTAVAIL）不算失败：
 * 槽进入等待恢复；其他错误（含地址被占用）照常失败。 */
ftun_status_t ftun_dns_runtime_listener_bind(
  ftun_dns_runtime_listener_slot_t *slot, const char *listen)
{
  ftun_socket_bind_issue_t error_code = FTUN_SOCKET_BIND_OTHER;
  ftun_status_t status = ftun_dns_runtime_socket_open(listen, FTUN_DIAL_UDP,
    &slot->descriptor, &error_code);
  if (status == FTUN_OK) {
    status = ftun_dns_runtime_socket_open(listen, FTUN_DIAL_TCP,
      &slot->tcp_descriptor, &error_code);
    if (status != FTUN_OK) {
      (void)ftun_socket_close((ftun_native_socket_t)slot->descriptor);
      slot->descriptor = -1;
    }
  }
  if (status != FTUN_OK && error_code == FTUN_SOCKET_BIND_ADDRESS_UNAVAILABLE) {
    slot->waiting = true;
    return FTUN_OK;
  }
  return status;
}

ftun_status_t ftun_dns_runtime_slot_recover(void *user,
                                                   ftun_recovery_id_t id);

/* 恢复调度器的实体来自两处：监听槽，以及多地址服务器的各个上游地址。
 * 容量按配置一次性确定；没有任何实体时不创建。 */
ftun_status_t ftun_dns_runtime_recovery_create(ftun_dns_runtime_t *dns,
  const ftun_config_t *config)
{
  ftun_recovery_policy_t policy;
  uint64_t now_ms = ftun_dns_runtime_now(NULL);
  size_t capacity = ftun_config_dns(config)->listener_count;
  size_t index;
  for (index = 0u; index < ftun_config_dns(config)->server_count; index++) {
    size_t count = ftun_config_dns(config)->servers[index].addresses.count;
    if (count > 1u) capacity += count > FTUN_UPSTREAM_SET_MAX ? FTUN_UPSTREAM_SET_MAX : count;
  }
  if (capacity == 0u) return FTUN_OK;
  memset(&policy, 0, sizeof(policy));
  policy.initial_ms = FTUN_DNS_RUNTIME_LISTENER_RETRY_INITIAL_MS;
  policy.maximum_ms = FTUN_DNS_RUNTIME_LISTENER_RETRY_MAXIMUM_MS;
  policy.stable_ms = FTUN_DNS_RUNTIME_LISTENER_RETRY_STABLE_MS;
  policy.jitter_permille = 200u;
  policy.auth_retry_ms = FTUN_DNS_RUNTIME_LISTENER_RETRY_MAXIMUM_MS;
  policy.seed = now_ms == 0u ? 1u : now_ms;
  return ftun_recovery_scheduler_create(dns->budget, capacity, &policy,
                                        &dns->recovery);
}

/* 每个监听槽注册为恢复实体；启动时地址未就绪的槽立即进入等待。 */
ftun_status_t ftun_dns_runtime_recovery_open(ftun_dns_runtime_t *dns)
{
  uint64_t now_ms = ftun_dns_runtime_now(NULL);
  size_t index;
  ftun_status_t status = FTUN_OK;
  if (dns->listener_count == 0u) return FTUN_OK;
  for (index = 0u; status == FTUN_OK && index < dns->listener_count; index++) {
    ftun_dns_runtime_listener_slot_t *slot = &dns->listeners[index];
    ftun_recovery_spec_t spec;
    memset(&spec, 0, sizeof(spec));
    spec.kind = 1u;
    spec.attempt = ftun_dns_runtime_slot_recover;
    spec.user = slot;
    slot->dns = dns;
    status = ftun_recovery_entity_register(dns->recovery, &spec, now_ms,
                                           &slot->recovery);
    if (status == FTUN_OK && slot->waiting) {
      status = ftun_recovery_report_failure(dns->recovery, slot->recovery, now_ms,
                                            FTUN_RECOVERY_FAULT_NETWORK);
    }
  }
  return status;
}

ftun_status_t ftun_dns_runtime_prepare_internal(
  ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations, ftun_event_loop_t *loop,
  const ftun_config_t *config, const ftun_dns_runtime_adapter_t *adapter,
  const ftun_dns_runtime_network_t *network, bool bind_sockets,
  const ftun_dns_runtime_plan_t *plan, ftun_dns_runtime_t **out)
{
  ftun_dns_runtime_t *dns;
  ftun_path_provider_spec_t path_spec = {0};
  uint32_t socket_mark;
  ftun_reservation_t listener_reservation = (ftun_reservation_t){0};
  ftun_budget_resources_t listener_resources = {0u, 0u, 0u};
  ftun_dns_dispatcher_options_t dispatcher;
  ftun_dns_cache_options_t cache;
  ftun_dns_server_options_t server;
  ftun_dns_query_transport_t transport;
  size_t index;
  ftun_status_t status = FTUN_OK;
  if (out != NULL && *out != NULL) return FTUN_E_AGAIN;
  if (core == NULL || budget == NULL || operations == NULL || loop == NULL ||
      config == NULL || out == NULL) return FTUN_E_INVALID;
  if (!ftun_config_dns(config)->enable) return FTUN_OK;
  if (network == NULL || network->generation == 0u ||
      network->path.open == NULL) return FTUN_E_INVALID;
  socket_mark = network->socket_mark;
  if (plan != NULL && (plan->config != config || plan->server_count !=
      (ftun_config_dns(config)->server_count == 0u ? 1u : ftun_config_dns(config)->server_count) ||
      plan->outbound_count != ftun_config_channel_count(config))) return FTUN_E_STALE;
  if (ftun_config_dns(config)->server_count > FTUN_DNS_RUNTIME_MAX_SERVERS ||
      ftun_config_dns(config)->listener_count > FTUN_DNS_RUNTIME_MAX_LISTENERS ||
      ftun_config_channel_count(config) > UINT32_MAX - FTUN_DNS_OUTBOUND_NAMED_BASE) {
    return FTUN_E_LIMIT;
  }
  /* UDP/TCP socket 与对应事件源在重载 prepare 期间和旧代并存。每个 DNS
   * 实例独立持有这份额度，因而只有完整的新代额度获批后才会打开 fd。 */
  listener_resources.descriptors = ftun_config_dns(config)->listener_count * 2u;
  listener_resources.queue_slots = ftun_config_dns(config)->listener_count * 2u;
  if (ftun_config_dns(config)->listener_count != 0u) {
    status = ftun_budget_reserve_resources(budget, listener_resources,
                                            &listener_reservation);
  }
  if (status != FTUN_OK) return status;
  dns = (ftun_dns_runtime_t *)calloc(1u, sizeof(*dns));
  if (dns == NULL) {
    ftun_reservation_release(&listener_reservation);
    return FTUN_E_LIMIT;
  }
  for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_LISTENERS; index++) {
    dns->listeners[index].dns = dns;
    dns->listeners[index].descriptor = -1;
    dns->listeners[index].tcp_descriptor = -1;
  }
  for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_PENDING; index++) {
    dns->pending[index].descriptor = -1;
    dns->pending[index].listener_index = SIZE_MAX;
  }
  for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS; index++) {
    dns->tcp[index].dns = dns;
    dns->tcp[index].descriptor = -1;
  }
  dns->core = core;
  dns->budget = budget;
  dns->listener_reservation = listener_reservation;
  dns->operations = operations;
  dns->loop = loop;
  if (adapter != NULL) dns->adapter = *adapter;
  dns->socket_mark = socket_mark;
  dns->liveness = ftun_dns_config_binding(config).liveness;
  dns->generation = network->generation;
  dns->protocol = network->protocol;
  path_spec.budget = budget;
  path_spec.generation = network->generation;
  path_spec.ops = network->path;
  path_spec.context = network->context;
  path_spec.max_pending = FTUN_DNS_RUNTIME_MAX_PENDING;
  path_spec.max_paths = FTUN_DNS_RUNTIME_MAX_PENDING * 2u;
  status = ftun_path_provider_create(&path_spec, &dns->paths);
  if (status != FTUN_OK) goto fail;
  status = ftun_config_retain((ftun_config_t *)config);
  if (status != FTUN_OK) goto fail;
  dns->config = (ftun_config_t *)config;
  if (ftun_config_channel_count(config) != 0u) {
    dns->proxy_endpoints = (ftun_endpoint_t *)calloc(ftun_config_channel_count(config),
      sizeof(*dns->proxy_endpoints));
    dns->proxy_endpoint_valid = (uint8_t *)calloc(ftun_config_channel_count(config),
      sizeof(*dns->proxy_endpoint_valid));
    if (dns->proxy_endpoints == NULL || dns->proxy_endpoint_valid == NULL) {
      status = FTUN_E_LIMIT;
    }
  }
  if (status == FTUN_OK) {
    status = ftun_dns_runtime_proxy_dependencies(config,
      dns->proxy_endpoint_valid);
  }
  for (index = 0u; status == FTUN_OK && index < ftun_config_channel_count(config);
       index++) {
    ftun_channel_config_t item_view = ftun_config_channel(config, index);
    const ftun_channel_config_t *item = &item_view;
    if (dns->proxy_endpoint_valid[index] == 0u) continue;
    if (plan != NULL) {
      if (plan->proxy_valid[index] == 0u) status = FTUN_E_RESOLVE;
      else {
        dns->proxy_endpoints[index] = plan->proxies[index];
        dns->proxy_endpoint_valid[index] = 1u;
      }
    } else {
      status = ftun_dns_runtime_resolve_upstream(budget, config, item->server,
        socket_mark, &dns->proxy_endpoints[index]);
      if (status == FTUN_OK) dns->proxy_endpoint_valid[index] = 1u;
    }
  }
  memset(&transport, 0, sizeof(transport));
  transport.select = ftun_dns_runtime_transport_select;
  transport.submit = ftun_dns_runtime_transport_submit;
  transport.cancel = ftun_dns_runtime_transport_cancel;
  transport.context = dns;
  transport.response_now = ftun_dns_runtime_response_now;
  if (status == FTUN_OK && ftun_config_dns(config)->cache) {
    memset(&cache, 0, sizeof(cache));
    cache.budget = budget;
    cache.max_entries = 1024u;
    cache.now = ftun_dns_runtime_now;
    status = ftun_dns_cache_create(&cache, &dns->cache);
  }
  if (status == FTUN_OK) status = ftun_dns_runtime_recovery_create(dns, config);
  for (index = 0u; status == FTUN_OK &&
       index < ftun_config_dns(config)->server_count; index++) {
    const ftun_config_dns_server_t *item = &ftun_config_dns(config)->servers[index];
    uint32_t outbound_id;
    if (item->addresses.count == 0u) {
      status = FTUN_E_INVALID;
      break;
    }
    ftun_endpoint_t addresses[FTUN_UPSTREAM_SET_MAX];
    size_t address_count = item->addresses.count;
    size_t address;
    if (address_count > FTUN_UPSTREAM_SET_MAX) {
      status = FTUN_E_INVALID;
      break;
    }
    memset(&server, 0, sizeof(server));
    server.budget = budget;
    server.operations = operations;
    for (address = 0u; status == FTUN_OK && address < address_count; address++) {
      if (plan != NULL) addresses[address] = plan->addresses[index][address];
      else status = ftun_dns_runtime_resolve_upstream(budget, config,
        item->addresses.items[address], socket_mark, &addresses[address]);
    }
    if (status != FTUN_OK) break;
    server.upstream = addresses[0];
    if (address_count > 1u) {
      status = ftun_upstream_set_create(budget, dns->recovery, addresses,
        address_count, ftun_dns_runtime_now, NULL, &dns->upstream_sets[index]);
      if (status != FTUN_OK) break;
      server.upstream_set = dns->upstream_sets[index];
    }
    status = ftun_dns_runtime_outbound_id(config, item->outbound,
                                         &outbound_id);
    if (status != FTUN_OK) break;
    server.outbound_id = outbound_id;
    server.fingerprint = (uint64_t)index + 1u;
    server.transport = strcmp(item->type, "tcp") == 0
      ? FTUN_DNS_TRANSPORT_TCP : FTUN_DNS_TRANSPORT_UDP;
    server.tcp_fallback = true;
    server.fakeip = item->fake_ip;
    server.max_response_bytes = FTUN_DNS_MAX_MESSAGE_BYTES;
    server.query_transport = transport;
    server.cache = dns->cache;
    server.now = ftun_dns_runtime_now;
    status = ftun_dns_server_create(&server, &dns->servers[index]);
    if (status != FTUN_OK) break;
    dns->server_count++;
  }
  if (status == FTUN_OK && ftun_config_dns(config)->server_count == 0u) {
    uint32_t outbound_id = FTUN_DNS_OUTBOUND_DIRECT;
    memset(&server, 0, sizeof(server));
    server.budget = budget;
    server.operations = operations;
    if (plan != NULL) server.upstream = plan->servers[0];
    else status = ftun_dns_runtime_bootstrap_endpoint(budget, config, &server.upstream);
    server.outbound_id = outbound_id;
    server.fingerprint = UINT64_C(0x42535450);
    server.transport = FTUN_DNS_TRANSPORT_UDP;
    server.tcp_fallback = true;
    server.max_response_bytes = FTUN_DNS_MAX_MESSAGE_BYTES;
    server.query_transport = transport;
    server.cache = dns->cache;
    server.now = ftun_dns_runtime_now;
    if (status == FTUN_OK) {
      status = ftun_dns_server_create(&server, &dns->servers[0]);
    }
    if (status == FTUN_OK) dns->server_count = 1u;
  }
  if (status == FTUN_OK && ftun_config_dns(config)->default_server[0] != '\0') {
    status = ftun_dns_runtime_named_index(
      (ftun_string_t){ftun_config_dns(config)->default_server,
                      strlen(ftun_config_dns(config)->default_server)},
      &dns->default_server, dns);
  }
  memset(&dispatcher, 0, sizeof(dispatcher));
  if (status == FTUN_OK) {
    dispatcher.budget = budget;
    dispatcher.config_scope = config;
    dispatcher.operations = operations;
    dispatcher.servers = dns->servers;
    dispatcher.server_count = dns->server_count;
    dispatcher.select_server = ftun_dns_runtime_select;
    dispatcher.select_named_server = ftun_dns_runtime_named_index;
    dispatcher.select_user = dns;
    status = ftun_dns_dispatcher_create(&dispatcher, &dns->dispatcher);
  }
  for (index = 0u; status == FTUN_OK &&
       index < ftun_config_dns(config)->listener_count; index++) {
    const ftun_config_dns_listener_t *item = &ftun_config_dns(config)->listeners[index];
    ftun_dns_runtime_listener_slot_t *slot = &dns->listeners[index];
    size_t fixed = dns->default_server;
    /* 先记录本槽所有权，UDP 成功而 TCP/协议失败也必须回收。 */
    dns->listener_count = index + 1u;
    bool policy = item->server == NULL || item->server[0] == '\0';
    if (!policy) {
      status = ftun_dns_runtime_named_index(
        (ftun_string_t){item->server, strlen(item->server)}, &fixed, dns);
    }
    if (status == FTUN_OK && bind_sockets) {
      status = ftun_dns_runtime_listener_bind(slot, item->listen);
    }
    if (status == FTUN_OK) {
      status = ftun_dns_runtime_protocol_create(dns, policy, fixed,
        (uint32_t)index + UINT32_C(0x10000), &slot->protocol);
    }
    slot->fixed_server = fixed;
    slot->policy = policy;
  }
  if (status == FTUN_OK) {
    uint32_t hijack_id = ftun_dns_config_binding(config).hijack_id;
    if (hijack_id != 0u) {
      status = ftun_dns_runtime_protocol_create(dns, true, dns->default_server,
        hijack_id, &dns->hijack);
    }
  }
  if (status == FTUN_OK) status = ftun_dns_runtime_recovery_open(dns);
  if (status != FTUN_OK) goto fail;
  *out = dns;
  return FTUN_OK;

fail:
  dns->cleanup_only = true;
  (void)ftun_dns_runtime_destroy(&dns);
  *out = dns;
  return status;
}

ftun_status_t ftun_dns_runtime_prepare(
  ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations, ftun_event_loop_t *loop,
  const ftun_config_t *config, const ftun_dns_runtime_adapter_t *adapter,
  const ftun_dns_runtime_network_t *network,
  ftun_dns_runtime_t **out)
{
  return ftun_dns_runtime_prepare_internal(core, budget, operations, loop,
                                           config, adapter, network,
                                           true, NULL, out);
}

ftun_status_t ftun_dns_runtime_idle(const ftun_dns_runtime_t *dns)
{
  ftun_dns_dispatcher_info_t dispatcher;
  size_t index;
  if (dns == NULL) return FTUN_OK;
  if (dns->dispatcher != NULL) {
    if (ftun_dns_dispatcher_get_info(dns->dispatcher, &dispatcher) != FTUN_OK) {
      return FTUN_E_STATE_CORRUPT;
    }
    if (dispatcher.inflight_local != 0u) return FTUN_E_AGAIN;
  }
  for (index = 0u; index < dns->server_count; index++) {
    ftun_dns_server_info_t server;
    if (ftun_dns_server_get_info(dns->servers[index], &server) != FTUN_OK) {
      return FTUN_E_STATE_CORRUPT;
    }
    if (server.inflight != 0u) return FTUN_E_AGAIN;
  }
  for (index = 0u; index < dns->listener_count; index++) {
    ftun_dns_listener_info_t listener;
    if (ftun_dns_listener_get_info(dns->listeners[index].protocol,
                                   &listener) != FTUN_OK) {
      return FTUN_E_STATE_CORRUPT;
    }
    if (listener.inflight != 0u || listener.tcp_connections != 0u) {
      return FTUN_E_AGAIN;
    }
  }
  if (dns->hijack != NULL) {
    ftun_dns_listener_info_t listener;
    if (ftun_dns_listener_get_info(dns->hijack, &listener) != FTUN_OK) {
      return FTUN_E_STATE_CORRUPT;
    }
    if (listener.inflight != 0u || listener.tcp_connections != 0u) {
      return FTUN_E_AGAIN;
    }
  }
  if (dns->pending_count != 0u || dns->request_count != 0u) return FTUN_E_AGAIN;
  return FTUN_OK;
}

int ftun_dns_runtime_listener_reusable(
  const ftun_dns_runtime_t *dns, const char *listen, size_t *out_index)
{
  size_t index;
  if (dns == NULL || listen == NULL) return 0;
  for (index = 0u; index < dns->listener_count; index++) {
    const char *candidate = ftun_config_dns(dns->config)->listeners[index].listen;
    if (candidate != NULL && strcmp(candidate, listen) == 0) {
      if (out_index != NULL) *out_index = index;
      return 1;
    }
  }
  return 0;
}

ftun_status_t ftun_dns_runtime_socket_duplicate(ftun_handle_t descriptor, ftun_handle_t *out)
{
  if (descriptor < 0 || out == NULL) return FTUN_E_INVALID;
  return ftun_socket_duplicate(descriptor, out);
}

ftun_status_t ftun_dns_runtime_prepare_reload_planned(
  const ftun_dns_runtime_t *active, ftun_core_t *core,
  ftun_budget_t *budget, ftun_operation_queue_t *operations,
  ftun_event_loop_t *loop,
  const ftun_config_t *config, const ftun_dns_runtime_adapter_t *adapter,
  const ftun_dns_runtime_network_t *network,
  const ftun_dns_runtime_plan_t *plan,
  ftun_dns_runtime_t **out)
{
  ftun_dns_runtime_t *prepared = NULL;
  size_t index;
  ftun_status_t status;
  if (out != NULL && *out != NULL) return FTUN_E_AGAIN;
  if (core == NULL || budget == NULL || operations == NULL || loop == NULL ||
      config == NULL || out == NULL) return FTUN_E_INVALID;
  if (!ftun_config_dns(config)->enable) return FTUN_OK;
  if (network == NULL || network->generation == 0u ||
      network->path.open == NULL) return FTUN_E_INVALID;
  if (active != NULL && network->generation <= active->generation) return FTUN_E_STALE;
  if (active == NULL) {
    status = ftun_dns_runtime_prepare_internal(core, budget, operations, loop,
                                              config, adapter, network,
                                              true, plan,
                                              &prepared);
    if (status != FTUN_OK) {
      *out = prepared;
      return status;
    }
    if (status == FTUN_OK) {
      status = ftun_dns_runtime_listener_sources_start(prepared);
      if (status == FTUN_OK) prepared->sources_prepared = true;
    }
    if (status != FTUN_OK) {
      if (prepared != NULL) prepared->cleanup_only = true;
      (void)ftun_dns_runtime_destroy(&prepared);
      *out = prepared;
      return status;
    }
    *out = prepared;
    return FTUN_OK;
  }
  status = ftun_dns_runtime_prepare_internal(core, budget, operations, loop,
                                             config, adapter, network,
                                             false, plan, &prepared);
  if (status != FTUN_OK) {
    *out = prepared;
    return status;
  }
  for (index = 0u; status == FTUN_OK &&
       index < prepared->listener_count; index++) {
    const char *listen = ftun_config_dns(config)->listeners[index].listen;
    ftun_dns_runtime_listener_slot_t *slot = &prepared->listeners[index];
    size_t old_index;
    if (ftun_dns_runtime_listener_reusable(active, listen, &old_index) &&
        !active->listeners[old_index].waiting) {
      status = ftun_dns_runtime_socket_duplicate(
        active->listeners[old_index].descriptor, &slot->descriptor);
      if (status == FTUN_OK) {
        status = ftun_dns_runtime_socket_duplicate(
          active->listeners[old_index].tcp_descriptor,
          &slot->tcp_descriptor);
      }
    } else {
      status = ftun_dns_runtime_listener_bind(slot, listen);
    }
  }
  if (status == FTUN_OK) {
    status = ftun_dns_runtime_listener_sources_start(prepared);
    if (status == FTUN_OK) prepared->sources_prepared = true;
  }
  if (status != FTUN_OK) {
    if (prepared != NULL) prepared->cleanup_only = true;
    (void)ftun_dns_runtime_destroy(&prepared);
    *out = prepared;
    return status;
  }
  *out = prepared;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_prepare_reload(
  const ftun_dns_runtime_t *active, ftun_core_t *core,
  ftun_budget_t *budget, ftun_operation_queue_t *operations,
  ftun_event_loop_t *loop,
  const ftun_config_t *config, const ftun_dns_runtime_adapter_t *adapter,
  const ftun_dns_runtime_network_t *network,
  ftun_dns_runtime_t **out)
{
  return ftun_dns_runtime_prepare_reload_planned(active, core, budget,
    operations, loop, config, adapter, network, NULL, out);
}

ftun_status_t ftun_dns_runtime_quiesce(ftun_dns_runtime_t *dns)
{
  size_t index;
  ftun_status_t result = FTUN_OK;
  if (dns == NULL) return FTUN_OK;
  dns->accepting = false;
  dns->active = false;
  for (index = 0u; index < dns->listener_count; index++) {
    ftun_status_t status = ftun_event_source_cancel(
      &dns->listeners[index].source);
    if (status != FTUN_OK && result == FTUN_OK) result = status;
    status = ftun_event_source_cancel(&dns->listeners[index].tcp_source);
    if (status != FTUN_OK && result == FTUN_OK) result = status;
    dns->listeners[index].events = 0u;
    dns->listeners[index].tcp_events = 0u;
    /* UDP fd 还是已接收请求的回复通道；等旧代 inflight 清零再关闭。 */
    if (dns->listeners[index].tcp_source == NULL &&
        dns->listeners[index].tcp_descriptor >= 0) {
      (void)ftun_socket_close((ftun_native_socket_t)dns->listeners[index].tcp_descriptor);
      dns->listeners[index].tcp_descriptor = -1;
    }
    (void)ftun_dns_listener_stop(dns->listeners[index].protocol);
  }
  (void)ftun_dns_listener_stop(dns->hijack);
  for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS; index++) {
    if (dns->tcp[index].active) {
      /* 已接收的请求继续完成并发送回复，但不再读取下一帧。 */
      dns->tcp[index].peer_eof = true;
      ftun_dns_runtime_tcp_set_ready(&dns->tcp[index], true);
    }
  }
  dns->sources_prepared = false;
  ftun_recovery_scheduler_stop(dns->recovery);
  return result;
}

ftun_status_t ftun_dns_runtime_commit_reload(ftun_dns_runtime_t **active_ptr,
                                             ftun_dns_runtime_t **prepared_ptr,
                                             ftun_dns_runtime_t **retired_ptr)
{
  ftun_dns_runtime_t *active;
  ftun_dns_runtime_t *prepared;
  ftun_status_t status;
  if (active_ptr == NULL || prepared_ptr == NULL || retired_ptr == NULL ||
      *retired_ptr != NULL) return FTUN_E_INVALID;
  active = *active_ptr;
  prepared = *prepared_ptr;
  if (prepared != NULL && !prepared->sources_prepared) {
    return FTUN_E_STATE_CORRUPT;
  }
  if (active != NULL) {
    status = ftun_dns_runtime_quiesce(active);
    if (status != FTUN_OK) return status;
  }
  if (prepared != NULL) {
    status = ftun_dns_runtime_activate(prepared);
    if (status != FTUN_OK) return status;
  }
  *retired_ptr = active;
  *active_ptr = prepared;
  *prepared_ptr = NULL;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_reap(ftun_dns_runtime_t **retired)
{
  ftun_status_t status;
  if (retired == NULL) return FTUN_E_INVALID;
  if (*retired == NULL) return FTUN_OK;
  status = ftun_dns_runtime_idle(*retired);
  if (status != FTUN_OK) return status;
  return ftun_dns_runtime_destroy(retired);
}

ftun_status_t ftun_dns_runtime_slot_sources_start(
  ftun_dns_runtime_t *dns, ftun_dns_runtime_listener_slot_t *slot)
{
  ftun_status_t status = FTUN_OK;
  if (slot->descriptor >= 0) {
    status = ftun_event_io_start(dns->loop,
      (ftun_native_socket_t)slot->descriptor,
      FTUN_EVENT_READ | FTUN_EVENT_ERROR, ftun_dns_runtime_listener_ready,
      slot, &slot->source);
  }
  if (status == FTUN_OK && slot->tcp_descriptor >= 0) {
    status = ftun_event_io_start(dns->loop,
      (ftun_native_socket_t)slot->tcp_descriptor,
      FTUN_EVENT_READ | FTUN_EVENT_ERROR,
      ftun_dns_runtime_listener_tcp_ready, slot, &slot->tcp_source);
  }
  return status;
}

ftun_status_t ftun_dns_runtime_listener_sources_start(
  ftun_dns_runtime_t *dns)
{
  size_t index;
  ftun_status_t status = FTUN_OK;
  for (index = 0u; status == FTUN_OK && index < dns->listener_count; index++) {
    status = ftun_dns_runtime_slot_sources_start(dns, &dns->listeners[index]);
  }
  if (status != FTUN_OK) {
    for (index = 0u; index < dns->listener_count; index++) {
      (void)ftun_event_source_cancel(&dns->listeners[index].source);
      (void)ftun_event_source_cancel(&dns->listeners[index].tcp_source);
    }
  }
  return status;
}

ftun_status_t ftun_dns_runtime_activate(ftun_dns_runtime_t *dns)
{
  ftun_status_t status;
  if (dns == NULL) return FTUN_OK;
  if (dns->cleanup_only) return FTUN_E_INVALID;
  status = dns->sources_prepared
    ? FTUN_OK : ftun_dns_runtime_listener_sources_start(dns);
  if (status == FTUN_OK) {
    dns->accepting = true;
    dns->active = true;
    dns->sources_prepared = true;
  } else {
    size_t index;
    for (index = 0u; index < dns->listener_count; index++) {
      (void)ftun_event_source_cancel(&dns->listeners[index].source);
      (void)ftun_event_source_cancel(&dns->listeners[index].tcp_source);
    }
  }
  return status;
}

ftun_status_t ftun_dns_runtime_tcp_disconnect(
  ftun_dns_runtime_tcp_t *connection)
{
  ftun_status_t status = ftun_event_source_cancel(&connection->source);
  if (status != FTUN_OK) return status;
  while (connection->response_head != NULL) {
    ftun_dns_runtime_response_t *response = connection->response_head;
    ftun_reservation_t reservation = response->reservation;
    connection->response_head = response->next;
    free(response);
    ftun_reservation_release(&reservation);
  }
  connection->response_tail = NULL;
  connection->response_count = 0u;
  free(connection->input);
  connection->input = NULL;
  ftun_reservation_release(&connection->input_reservation);
  connection->input_offset = 0u;
  connection->input_length = 0u;
  connection->prefix_length = 0u;
  if (connection->descriptor >= 0) (void)ftun_socket_close((ftun_native_socket_t)connection->descriptor);
  connection->descriptor = -1;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_tcp_close(
  ftun_dns_runtime_tcp_t *connection)
{
  ftun_status_t status = ftun_dns_runtime_tcp_disconnect(connection);
  if (status != FTUN_OK) return status;
  status = ftun_dns_connection_close(&connection->protocol);
  /* listener 的在途请求仍借用 protocol，完成前禁止复用槽位。 */
  if (status != FTUN_OK) return status;
  connection->active = false;
  ftun_dns_runtime_tcp_set_ready(connection, false);
  connection->events = 0u;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_tcp_accept(
  ftun_dns_runtime_t *dns, ftun_dns_runtime_listener_slot_t *listener,
  size_t quota, size_t *out_accepted)
{
  uint64_t now_ms;
  size_t accepted = 0u;
  ftun_status_t status = ftun_monotonic_now(&now_ms);
  if (out_accepted != NULL) *out_accepted = 0u;
  if (dns == NULL || listener == NULL || quota == 0u ||
      out_accepted == NULL) return FTUN_E_INVALID;
  if (status != FTUN_OK) return status;
  if (now_ms < listener->accept_after_ms) return FTUN_OK;
  while (accepted < quota) {
    ftun_dns_runtime_tcp_t *connection = NULL;
    ftun_handle_t descriptor;
    size_t index;
    ftun_socket_accept_disposition_t disposition;
    status = ftun_socket_accept(listener->tcp_descriptor, &descriptor, NULL, &disposition);
    if (status != FTUN_OK) {
      if (disposition == FTUN_SOCKET_ACCEPT_RETRY) continue;
      if (disposition == FTUN_SOCKET_ACCEPT_DRAINED ||
          disposition == FTUN_SOCKET_ACCEPT_SKIP) {
        return FTUN_OK;
      }
      if (disposition == FTUN_SOCKET_ACCEPT_BACKOFF) {
        uint64_t delay = listener->accept_backoff_ms == 0u
          ? FTUN_DNS_RUNTIME_ACCEPT_BACKOFF_MIN_MS
          : listener->accept_backoff_ms;
        if (delay > FTUN_DNS_RUNTIME_ACCEPT_BACKOFF_MAX_MS) {
          delay = FTUN_DNS_RUNTIME_ACCEPT_BACKOFF_MAX_MS;
        }
        listener->accept_after_ms = now_ms > UINT64_MAX - delay
          ? UINT64_MAX : now_ms + delay;
        listener->accept_backoff_ms =
          delay >= FTUN_DNS_RUNTIME_ACCEPT_BACKOFF_MAX_MS / 2u
          ? FTUN_DNS_RUNTIME_ACCEPT_BACKOFF_MAX_MS : delay * 2u;
        status = listener->tcp_source == NULL ? FTUN_OK
          : ftun_event_io_update(listener->tcp_source, FTUN_EVENT_ERROR);
        return status;
      }
      return status;
    }
    listener->accept_after_ms = 0u;
    listener->accept_backoff_ms = 0u;
    accepted++;
    *out_accepted = accepted;
    /* 接入的 TCP 连接设置存活探测与确认期限；设置失败只丢弃这一条连接。 */
    {
      ftun_socket_liveness_t liveness = dns->liveness;
      if (ftun_socket_apply_liveness(descriptor, &liveness) != FTUN_OK) {
        (void)ftun_socket_close((ftun_native_socket_t)descriptor);
        continue;
      }
    }
    for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS; index++) {
      if (!dns->tcp[index].active) {
        connection = &dns->tcp[index];
        break;
      }
    }
    if (connection == NULL) {
      (void)ftun_socket_close((ftun_native_socket_t)descriptor);
      return FTUN_OK;
    }
    memset(connection, 0, sizeof(*connection));
    connection->dns = dns;
    connection->descriptor = descriptor;
    connection->active = true;
    dns->next_peer_id++;
    if (dns->next_peer_id == 0u) dns->next_peer_id++;
    connection->peer_id = dns->next_peer_id;
    if (ftun_dns_listener_tcp_open(listener->protocol, connection->peer_id,
                                   &connection->protocol) != FTUN_OK) {
      status = ftun_dns_runtime_tcp_close(connection);
      if (status != FTUN_OK) return status;
    } else {
      status = ftun_event_io_start(dns->loop,
        (ftun_native_socket_t)descriptor,
        FTUN_EVENT_READ | FTUN_EVENT_ERROR, ftun_dns_runtime_tcp_ready,
        connection, &connection->source);
      if (status != FTUN_OK) {
        ftun_dns_runtime_record(dns, ftun_dns_runtime_tcp_close(connection));
        return status;
      }
      ftun_dns_runtime_tcp_set_ready(connection, true);
    }
  }
  *out_accepted = accepted;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_hijack_tcp(ftun_dns_runtime_t *dns,
                                         ftun_handle_t descriptor)
{
  ftun_dns_runtime_tcp_t *connection = NULL;
  size_t index;
  ftun_status_t status;
  if (dns == NULL || descriptor < 0 || !dns->accepting ||
      dns->hijack == NULL) return FTUN_E_INVALID;
  for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS; index++) {
    if (!dns->tcp[index].active) {
      connection = &dns->tcp[index];
      break;
    }
  }
  if (connection == NULL) return FTUN_E_LIMIT;
  memset(connection, 0, sizeof(*connection));
  connection->dns = dns;
  connection->descriptor = descriptor;
  connection->active = true;
  dns->next_peer_id++;
  if (dns->next_peer_id == 0u) dns->next_peer_id++;
  connection->peer_id = dns->next_peer_id;
  status = ftun_dns_listener_tcp_open(dns->hijack, connection->peer_id,
                                      &connection->protocol);
  if (status != FTUN_OK) {
    connection->descriptor = -1;
    connection->active = false;
  } else {
    status = ftun_event_io_start(dns->loop,
      (ftun_native_socket_t)descriptor,
      FTUN_EVENT_READ | FTUN_EVENT_ERROR, ftun_dns_runtime_tcp_ready,
      connection, &connection->source);
    if (status != FTUN_OK) {
      /* 接纳失败不消费调用方的 descriptor。io_start 失败输出为空。 */
      connection->descriptor = -1;
      ftun_dns_runtime_record(dns, ftun_dns_runtime_tcp_close(connection));
    } else {
      ftun_dns_runtime_tcp_set_ready(connection, true);
    }
  }
  return status;
}

ftun_status_t ftun_dns_runtime_tcp_drive(
  ftun_dns_runtime_t *dns, ftun_dns_runtime_tcp_t *connection)
{
  if (!connection->transport_failed && connection->response_head != NULL) {
    ftun_dns_runtime_response_t *response = connection->response_head;
    ptrdiff_t sent;
    ftun_status_t io_status;
    sent = ftun_socket_stream_send(connection->descriptor,
      response->data + response->offset, response->length - response->offset, &io_status);
    if (sent > 0) {
      response->offset += (size_t)sent;
      if (response->offset == response->length) {
        ftun_reservation_t reservation = response->reservation;
        connection->response_head = response->next;
        if (connection->response_head == NULL) {
          connection->response_tail = NULL;
        }
        if (connection->response_count != 0u) connection->response_count--;
        free(response);
        ftun_reservation_release(&reservation);
      }
    } else if (sent == 0 || (io_status != FTUN_E_AGAIN)) {
      connection->peer_eof = true;
      connection->transport_failed = true;
    }
  }
  if (!connection->peer_eof) {
    ptrdiff_t received;
    ftun_status_t io_status;
    if (connection->input == NULL && connection->prefix_length < 2u) {
      received = ftun_socket_stream_receive(connection->descriptor,
        connection->prefix + connection->prefix_length,
        2u - connection->prefix_length, &io_status);
      if (received > 0) connection->prefix_length += (size_t)received;
      else if (received == 0) connection->peer_eof = true;
      else if (io_status != FTUN_E_AGAIN) {
        connection->peer_eof = true;
        connection->transport_failed = true;
      }
      if (connection->prefix_length == 2u) {
        size_t payload = ((size_t)connection->prefix[0] << 8u) |
                         connection->prefix[1];
        if (payload == 0u || payload > FTUN_DNS_MAX_MESSAGE_BYTES ||
            ftun_budget_reserve(dns->budget, payload + 2u,
              &connection->input_reservation) != FTUN_OK) {
          connection->peer_eof = true;
        } else {
          connection->input = (uint8_t *)malloc(payload + 2u);
          if (connection->input == NULL) {
            ftun_reservation_release(&connection->input_reservation);
            connection->peer_eof = true;
          } else {
            memcpy(connection->input, connection->prefix, 2u);
            connection->input_offset = 2u;
            connection->input_length = payload + 2u;
          }
        }
      }
    }
    if (!connection->peer_eof && connection->input != NULL &&
        connection->input_offset < connection->input_length) {
      received = ftun_socket_stream_receive(connection->descriptor,
        connection->input + connection->input_offset,
        connection->input_length - connection->input_offset, &io_status);
      if (received > 0) connection->input_offset += (size_t)received;
      else if (received == 0) connection->peer_eof = true;
      else if (io_status != FTUN_E_AGAIN) {
        connection->peer_eof = true;
        connection->transport_failed = true;
      }
    }
    if (!connection->peer_eof && connection->input != NULL &&
        connection->input_offset == connection->input_length) {
      size_t consumed = 0u;
      size_t frames = 0u;
      ftun_status_t status = ftun_dns_connection_feed(connection->protocol,
        (ftun_bytes_t){connection->input, connection->input_length},
        &consumed, &frames);
      if (status == FTUN_OK && consumed == connection->input_length &&
          frames == 1u) {
        free(connection->input);
        connection->input = NULL;
        ftun_reservation_release(&connection->input_reservation);
        connection->input_offset = 0u;
        connection->input_length = 0u;
        connection->prefix_length = 0u;
      } else if (status != FTUN_E_LIMIT) {
        connection->peer_eof = true;
      }
    }
  }
  if (connection->transport_failed) {
    ftun_status_t status = ftun_dns_runtime_tcp_disconnect(connection);
    if (status != FTUN_OK) return status;
  }
  if (connection->peer_eof && connection->response_head == NULL) {
    ftun_status_t status = ftun_dns_connection_close(&connection->protocol);
    if (status == FTUN_OK) return ftun_dns_runtime_tcp_close(connection);
    else if (status != FTUN_E_AGAIN) return status;
  }
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_step_request(ftun_dns_runtime_t *dns,
                                                  bool *out_work)
{
  ftun_dns_runtime_transport_request_t *request = dns->ready_request_head;
  ftun_status_t status;
  *out_work = false;
  if (request == NULL) return FTUN_OK;
  ftun_dns_runtime_request_ready_remove(request);
  if (request->closing) {
    ftun_dns_runtime_request_complete_one(request);
    *out_work = true;
    return FTUN_OK;
  }
  status = ftun_dns_runtime_request_drive(request);
  *out_work = true;
  if (status != FTUN_E_AGAIN) {
    ftun_dns_runtime_request_finish(request, status);
    ftun_dns_runtime_request_complete_one(request);
    return FTUN_OK;
  }
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_step_deadline(ftun_dns_runtime_t *dns,
                                                   uint64_t now_ms,
                                                   bool *out_work)
{
  ftun_dns_runtime_transport_waiter_t *waiter;
  ftun_dns_runtime_transport_request_t *request;
  *out_work = false;
  if (dns->waiter_count == 0u ||
      dns->waiter_heap[0]->deadline_ms > now_ms) return FTUN_OK;
  waiter = dns->waiter_heap[0];
  request = waiter->request;
  /* 已提交的响应不能因分批交付跨过期限而退化为 TIMEOUT。 */
  if (request->closing) {
    ftun_dns_runtime_request_complete_one(request);
    *out_work = true;
    return FTUN_OK;
  }
  ftun_dns_runtime_waiter_finish(waiter, FTUN_E_TIMEOUT,
                                (ftun_bytes_t){NULL, 0u});
  if (request->waiter_head == NULL) {
    ftun_dns_runtime_request_release(request);
  }
  *out_work = true;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_listener_udp_one(
  ftun_dns_runtime_t *dns, ftun_dns_runtime_listener_slot_t *slot,
  size_t listener_index, bool *out_work)
{
  uint8_t wire[FTUN_DNS_MAX_MESSAGE_BYTES];
  ftun_endpoint_t peer;
  ftun_dns_runtime_pending_t *pending;
  ftun_operation_t *operation = NULL;
  ptrdiff_t length;
  ftun_status_t status;
  *out_work = false;
  length = ftun_socket_receive_from(slot->descriptor, wire, sizeof(wire), &peer, &status);
  if (length < 0 && status == FTUN_E_AGAIN) {
    slot->events &= ~FTUN_EVENT_READ;
    return FTUN_OK;
  }
  if (length < 0) return status;
  *out_work = true;
  pending = ftun_dns_runtime_pending_new(dns, listener_index);
  if (pending == NULL) return FTUN_OK;
  pending->kind = FTUN_DNS_RUNTIME_PENDING_SOCKET;
  pending->descriptor = slot->descriptor;
  pending->peer = peer;
  status = ftun_dns_listener_receive_udp(slot->protocol, pending->id,
    (ftun_bytes_t){wire, (size_t)length}, &operation);
  if (status != FTUN_OK) {
    ftun_dns_runtime_pending_clear(dns, pending);
  }
  return FTUN_OK;
}

/* 取消事件源并关闭监听 socket；取消失败则保持原状，稍后重试。 */
ftun_status_t ftun_dns_runtime_slot_close(
  ftun_dns_runtime_listener_slot_t *slot)
{
  ftun_status_t status = ftun_event_source_cancel(&slot->source);
  if (status == FTUN_OK) status = ftun_event_source_cancel(&slot->tcp_source);
  if (status != FTUN_OK) return status;
  slot->events = 0u;
  slot->tcp_events = 0u;
  slot->accept_after_ms = 0u;
  if (slot->descriptor >= 0) (void)ftun_socket_close((ftun_native_socket_t)slot->descriptor);
  if (slot->tcp_descriptor >= 0) (void)ftun_socket_close((ftun_native_socket_t)slot->tcp_descriptor);
  slot->descriptor = -1;
  slot->tcp_descriptor = -1;
  return FTUN_OK;
}

/* 监听出错：关闭 socket，转入等待恢复；只影响这个监听。 */
ftun_status_t ftun_dns_runtime_slot_fail(
  ftun_dns_runtime_t *dns, ftun_dns_runtime_listener_slot_t *slot)
{
  ftun_status_t status = ftun_dns_runtime_slot_close(slot);
  if (status != FTUN_OK) return status;
  slot->waiting = true;
  dns->object_faults++;
  return ftun_recovery_report_failure(dns->recovery, slot->recovery,
    ftun_dns_runtime_now(NULL), FTUN_RECOVERY_FAULT_NETWORK);
}

/* A0 的尝试：按原地址重新 bind 并注册事件源。同步结束。 */
ftun_status_t ftun_dns_runtime_slot_recover(void *user,
                                                   ftun_recovery_id_t id)
{
  ftun_dns_runtime_listener_slot_t *slot = (ftun_dns_runtime_listener_slot_t *)user;
  ftun_dns_runtime_t *dns = slot->dns;
  size_t index = (size_t)(slot - dns->listeners);
  ftun_socket_bind_issue_t error_code = FTUN_SOCKET_BIND_OTHER;
  ftun_status_t status = ftun_dns_runtime_socket_open(
    ftun_config_dns(dns->config)->listeners[index].listen, FTUN_DIAL_UDP, &slot->descriptor,
    &error_code);
  if (status == FTUN_OK) {
    status = ftun_dns_runtime_socket_open(
      ftun_config_dns(dns->config)->listeners[index].listen, FTUN_DIAL_TCP,
      &slot->tcp_descriptor, &error_code);
  }
  if (status == FTUN_OK) status = ftun_dns_runtime_slot_sources_start(dns, slot);
  if (status != FTUN_OK) {
    (void)ftun_dns_runtime_slot_close(slot);
    if (slot->descriptor >= 0) { (void)ftun_socket_close((ftun_native_socket_t)slot->descriptor); slot->descriptor = -1; }
  } else {
    slot->waiting = false;
  }
  (void)ftun_recovery_attempt_finish(dns->recovery, id,
    ftun_dns_runtime_now(NULL), status,
    error_code == FTUN_SOCKET_BIND_PERMISSION
      ? FTUN_RECOVERY_FAULT_CONFIG : FTUN_RECOVERY_FAULT_NETWORK);
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_step_listener(ftun_dns_runtime_t *dns,
                                                   uint64_t now_ms,
                                                   bool *out_work)
{
  size_t scanned;
  *out_work = false;
  if (!dns->accepting || dns->listener_count == 0u) return FTUN_OK;
  for (scanned = 0u; scanned < dns->listener_count; scanned++) {
    size_t index = (dns->listener_cursor + scanned) % dns->listener_count;
    ftun_dns_runtime_listener_slot_t *slot = &dns->listeners[index];
    size_t attempt;
    if (slot->accept_after_ms != 0u && now_ms >= slot->accept_after_ms) {
      ftun_status_t status;
      slot->accept_after_ms = 0u;
      status = ftun_event_io_update(slot->tcp_source,
                                    FTUN_EVENT_READ | FTUN_EVENT_ERROR);
      if (status != FTUN_OK) return status;
      slot->tcp_events |= FTUN_EVENT_READ;
    }
    if (slot->waiting) continue;
    if ((slot->events & FTUN_EVENT_ERROR) != 0u ||
        (slot->tcp_events & FTUN_EVENT_ERROR) != 0u) {
      ftun_status_t failed = ftun_dns_runtime_slot_fail(dns, slot);
      if (failed != FTUN_OK) return failed;
      *out_work = true;
      return FTUN_OK;
    }
    for (attempt = 0u; attempt < 2u; attempt++) {
      bool choose_tcp = attempt == 0u ? dns->listener_tcp_turn :
                                       !dns->listener_tcp_turn;
      if (choose_tcp && (slot->tcp_events & FTUN_EVENT_READ) != 0u) {
        size_t accepted = 0u;
        ftun_status_t status = ftun_dns_runtime_tcp_accept(dns, slot, 1u,
                                                          &accepted);
        if (status == FTUN_E_STATE_CORRUPT) return status;
        if (status != FTUN_OK) {
          /* accept 的致命 errno 只影响这个监听：关闭并等待恢复。 */
          status = ftun_dns_runtime_slot_fail(dns, slot);
          if (status != FTUN_OK) return status;
          *out_work = true;
          return FTUN_OK;
        }
        if (accepted == 0u) slot->tcp_events &= ~FTUN_EVENT_READ;
        else {
          dns->listener_cursor = (index + 1u) % dns->listener_count;
          dns->listener_tcp_turn = false;
          *out_work = true;
          return FTUN_OK;
        }
      } else if (!choose_tcp && (slot->events & FTUN_EVENT_READ) != 0u) {
        ftun_status_t status = ftun_dns_runtime_listener_udp_one(
          dns, slot, index, out_work);
        if (status == FTUN_E_STATE_CORRUPT) return status;
        if (status != FTUN_OK) {
          status = ftun_dns_runtime_slot_fail(dns, slot);
          if (status != FTUN_OK) return status;
          *out_work = true;
          return FTUN_OK;
        }
        if (*out_work) {
          dns->listener_cursor = (index + 1u) % dns->listener_count;
          dns->listener_tcp_turn = true;
          return FTUN_OK;
        }
      }
    }
  }
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_step_tcp(ftun_dns_runtime_t *dns,
                                              bool *out_work)
{
  size_t index = ftun_dns_runtime_tcp_next_ready(dns);
  ftun_status_t status;
  *out_work = false;
  if (index == SIZE_MAX) return FTUN_OK;
  if (!dns->tcp[index].active) return FTUN_E_STATE_CORRUPT;
  dns->tcp_cursor = (index + 1u) % FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS;
  ftun_dns_runtime_tcp_set_ready(&dns->tcp[index], false);
  dns->tcp[index].events = 0u;
  status = ftun_dns_runtime_tcp_drive(dns, &dns->tcp[index]);
  *out_work = true;
  if (status == FTUN_OK && dns->tcp[index].active) {
    status = ftun_dns_runtime_tcp_source_update(&dns->tcp[index]);
  }
  /* 单条连接的收尾/更新失败只影响这一条：转入隔离，到点再试，其余通道不受牵连；
   * STATE_CORRUPT 是共享状态损坏，照常升级。 */
  if (status != FTUN_OK && status != FTUN_E_STATE_CORRUPT) {
    ftun_dns_runtime_tcp_t *connection = &dns->tcp[index];
    uint64_t now_ms = ftun_dns_runtime_now(NULL);
    if (connection->quarantine_retry_ms == 0u) dns->quarantined_tcp++;
    connection->quarantine_retry_ms = now_ms > UINT64_MAX - FTUN_DNS_RUNTIME_QUARANTINE_RETRY_MS
      ? UINT64_MAX : now_ms + FTUN_DNS_RUNTIME_QUARANTINE_RETRY_MS;
    dns->object_faults++;
    return FTUN_OK;
  }
  return status;
}

ftun_status_t ftun_dns_runtime_run_slice(ftun_dns_runtime_t *dns,
                                                size_t quota, size_t *out_work)
{
  size_t work = 0u;
  if (dns->cleanup_only) return FTUN_E_INVALID;
  if (dns->pending_status != FTUN_OK) {
    ftun_status_t status = dns->pending_status;
    dns->pending_status = FTUN_OK;
    return status;
  }
  if (dns->recovery != NULL) {
    size_t recovery_work = 0u;
    ftun_status_t status = ftun_recovery_run(dns->recovery,
      ftun_dns_runtime_now(NULL), 4u, &recovery_work);
    if (status != FTUN_OK) return status;
  }
  if (dns->quarantined_tcp != 0u) {
    uint64_t now_ms = ftun_dns_runtime_now(NULL);
    size_t index;
    for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS; index++) {
      ftun_dns_runtime_tcp_t *connection = &dns->tcp[index];
      if (connection->quarantine_retry_ms == 0u ||
          now_ms < connection->quarantine_retry_ms) continue;
      connection->quarantine_retry_ms = 0u;
      dns->quarantined_tcp--;
      ftun_dns_runtime_tcp_set_ready(connection, true);
    }
  }
  while (work < quota) {
    uint64_t now_ms = ftun_dns_runtime_now(NULL);
    bool did_work = false;
    size_t attempt;
    ftun_status_t status;
    if (!dns->deadline_served && dns->waiter_count != 0u &&
        dns->waiter_heap[0]->deadline_ms <= now_ms) {
      status = ftun_dns_runtime_step_deadline(dns, now_ms, &did_work);
      if (status != FTUN_OK) return status;
      if (did_work) {
        work++;
        dns->deadline_served = true;
        continue;
      }
    }
    for (attempt = 0u; attempt < FTUN_DNS_RUNTIME_LANE_COUNT; attempt++) {
      size_t lane = (dns->lane_cursor + attempt) %
                    FTUN_DNS_RUNTIME_LANE_COUNT;
      if (lane == 0u) {
        status = ftun_dns_runtime_step_request(dns, &did_work);
      } else if (lane == 1u) {
        status = ftun_dns_runtime_step_deadline(dns, now_ms, &did_work);
      } else if (lane == 2u) {
        status = ftun_dns_runtime_step_listener(dns, now_ms, &did_work);
      } else {
        status = ftun_dns_runtime_step_tcp(dns, &did_work);
      }
      if (status != FTUN_OK) return status;
      if (did_work) {
        dns->lane_cursor = (lane + 1u) % FTUN_DNS_RUNTIME_LANE_COUNT;
        dns->deadline_served = lane == 1u;
        work++;
        break;
      }
    }
    if (!did_work) break;
  }
  *out_work = work;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_run_once(ftun_dns_runtime_t *dns, size_t quota,
                                       size_t *out_work)
{
  ftun_status_t status;
  if (out_work != NULL) *out_work = 0u;
  if (quota == 0u || out_work == NULL) return FTUN_E_INVALID;
  if (dns == NULL) return FTUN_OK;
  if (dns->dispatching) return FTUN_E_AGAIN;
  dns->dispatching = true;
  status = ftun_dns_runtime_run_slice(dns, quota, out_work);
  dns->dispatching = false;
  return status;
}

void ftun_dns_runtime_network_changed(ftun_dns_runtime_t *dns, uint64_t now_ms)
{
  if (dns == NULL || dns->recovery == NULL) return;
  ftun_recovery_trigger_kind(dns->recovery,
    UINT32_C(1) | FTUN_UPSTREAM_SET_RECOVERY_KIND, now_ms);
}

ftun_status_t ftun_dns_runtime_next_deadline(
  const ftun_dns_runtime_t *dns, uint64_t *out_deadline_ms, bool *out_present)
{
  uint64_t deadline = UINT64_MAX;
  size_t index;
  if (out_deadline_ms != NULL) *out_deadline_ms = 0u;
  if (out_present != NULL) *out_present = false;
  if (out_deadline_ms == NULL || out_present == NULL) return FTUN_E_INVALID;
  if (dns == NULL) return FTUN_OK;
  if (dns->waiter_count != 0u) deadline = dns->waiter_heap[0]->deadline_ms;
  for (index = 0u; index < dns->listener_count; index++) {
    if (dns->listeners[index].accept_after_ms != 0u &&
        dns->listeners[index].accept_after_ms < deadline) {
      deadline = dns->listeners[index].accept_after_ms;
    }
  }
  if (dns->recovery != NULL) {
    uint64_t candidate = 0u;
    bool candidate_present = false;
    if (ftun_recovery_next_deadline(dns->recovery, &candidate,
                                    &candidate_present) == FTUN_OK &&
        candidate_present && candidate < deadline) deadline = candidate;
  }
  if (dns->quarantined_tcp != 0u) {
    for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS; index++) {
      uint64_t retry = dns->tcp[index].quarantine_retry_ms;
      if (retry != 0u && retry < deadline) deadline = retry;
    }
  }
  if (deadline != UINT64_MAX) {
    *out_deadline_ms = deadline;
    *out_present = true;
  }
  return FTUN_OK;
}

size_t ftun_dns_runtime_quarantined(const ftun_dns_runtime_t *dns)
{
  return dns == NULL ? 0u : dns->quarantined_tcp;
}

size_t ftun_dns_runtime_listeners_waiting(const ftun_dns_runtime_t *dns)
{
  size_t index;
  size_t waiting = 0u;
  if (dns == NULL) return 0u;
  for (index = 0u; index < dns->listener_count; index++) {
    if (dns->listeners[index].waiting) waiting++;
  }
  return waiting;
}

size_t ftun_dns_runtime_take_object_faults(ftun_dns_runtime_t *dns)
{
  size_t faults = dns == NULL ? 0u : dns->object_faults;
  if (dns != NULL) dns->object_faults = 0u;
  return faults;
}

bool ftun_dns_runtime_has_ready(const ftun_dns_runtime_t *dns)
{
  uint64_t deadline = 0u;
  bool present = false;
  size_t index;
  if (dns == NULL) return false;
  if (dns->pending_status != FTUN_OK) return true;
  if (dns->ready_request_head != NULL) return true;
  for (index = 0u; index < dns->listener_count; index++) {
    if (dns->listeners[index].events != 0u ||
        dns->listeners[index].tcp_events != 0u) return true;
  }
  if (dns->tcp_ready_mask != 0u) return true;
  if (ftun_dns_runtime_next_deadline(dns, &deadline, &present) == FTUN_OK &&
      present && ftun_dns_runtime_now(NULL) >= deadline) return true;
  return false;
}

bool ftun_dns_runtime_has_hijack(const ftun_dns_runtime_t *dns)
{
  return dns != NULL && dns->hijack != NULL && dns->accepting;
}

ftun_status_t ftun_dns_runtime_dispatcher(ftun_dns_runtime_t *dns,
                                        ftun_dns_dispatcher_t **out)
{
  if (out != NULL) *out = NULL;
  if (dns == NULL || out == NULL) return FTUN_E_INVALID;
  if (dns->dispatcher == NULL) return FTUN_E_AGAIN;
  *out = dns->dispatcher;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_hijack_udp(
  ftun_dns_runtime_t *dns, ftun_datagram_t *inbound,
  const ftun_endpoint_t *client, const ftun_packet_t *packet)
{
  ftun_dns_runtime_pending_t *pending;
  ftun_operation_t *operation = NULL;
  ftun_bytes_t wire;
  ftun_status_t status;
  if (!ftun_dns_runtime_has_hijack(dns) || inbound == NULL || client == NULL ||
      packet == NULL || ftun_packet_view(packet, &wire) != FTUN_OK) {
    return FTUN_E_INVALID;
  }
  pending = ftun_dns_runtime_pending_new(dns, SIZE_MAX);
  if (pending == NULL) return FTUN_E_LIMIT;
  status = ftun_datagram_retain(inbound);
  if (status != FTUN_OK) {
    ftun_dns_runtime_pending_clear(dns, pending);
    return status;
  }
  pending->kind = FTUN_DNS_RUNTIME_PENDING_TUN;
  pending->inbound = inbound;
  pending->client = *client;
  status = ftun_dns_listener_receive_udp(dns->hijack, pending->id, wire,
                                         &operation);
  if (status != FTUN_OK) {
    ftun_dns_runtime_pending_clear(dns, pending);
  }
  return status;
}

ftun_status_t ftun_dns_runtime_stop_slice(ftun_dns_runtime_t *dns,
                                                 uint64_t deadline_ms)
{
  size_t index, work = 0u;
  ftun_status_t result;
  ftun_dns_runtime_transport_request_t *request;
  if (deadline_ms == 0u) return FTUN_E_INVALID;
  if (dns == NULL) return FTUN_OK;
  result = ftun_dns_runtime_quiesce(dns);
  /* 全停关闭通道接纳；热重载 quiesce 仍允许旧查询的 TC fallback。 */
  if (dns->paths != NULL) {
    ftun_status_t status = ftun_path_provider_quiesce(dns->paths);
    if (status != FTUN_OK && result == FTUN_OK) result = status;
  }
  for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS; index++) {
    ftun_status_t status = ftun_event_source_cancel(&dns->tcp[index].source);
    if (status != FTUN_OK && result == FTUN_OK) result = status;
  }
  if (result != FTUN_OK) return result;
  /* 先轮转拥有链，再交付回调；回调可取消其他请求，不能保留其 next 指针。 */
  while (dns->request_head != NULL && work < FTUN_DNS_RUNTIME_STOP_QUOTA) {
    if (ftun_dns_runtime_now(NULL) >= deadline_ms) return FTUN_E_TIMEOUT;
    request = dns->request_head;
    if (request->next != NULL) {
      dns->request_head = request->next;
      dns->request_head->previous = NULL;
      request->previous = dns->request_tail;
      request->next = NULL;
      dns->request_tail->next = request;
      dns->request_tail = request;
    }
    ftun_dns_runtime_request_finish(request, FTUN_E_CANCELLED);
    ftun_dns_runtime_request_complete_one(request);
    work++;
  }
  if (dns->request_head != NULL) return FTUN_E_AGAIN;
  for (index = 0u; index < dns->listener_count; index++) {
    if (dns->listeners[index].descriptor >= 0) {
      (void)ftun_socket_close((ftun_native_socket_t)dns->listeners[index].descriptor);
      dns->listeners[index].descriptor = -1;
    }
    if (dns->listeners[index].tcp_descriptor >= 0) {
      (void)ftun_socket_close((ftun_native_socket_t)dns->listeners[index].tcp_descriptor);
      dns->listeners[index].tcp_descriptor = -1;
    }
  }
  for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS; index++) {
    if (dns->tcp[index].active) {
      dns->tcp[index].peer_eof = true;
      dns->tcp[index].transport_failed = true;
      result = ftun_dns_runtime_tcp_disconnect(&dns->tcp[index]);
      if (result != FTUN_OK) return result;
    }
  }
  return dns->paths == NULL ? FTUN_OK :
    ftun_path_provider_stop_until(dns->paths, deadline_ms);
}

ftun_status_t ftun_dns_runtime_stop_until(ftun_dns_runtime_t *dns,
                                        uint64_t deadline_ms)
{
  ftun_status_t status;
  if (deadline_ms == 0u) return FTUN_E_INVALID;
  if (dns == NULL) return FTUN_OK;
  if (dns->dispatching) return FTUN_E_AGAIN;
  dns->dispatching = true;
  status = ftun_dns_runtime_stop_slice(dns, deadline_ms);
  dns->dispatching = false;
  return status;
}

ftun_status_t ftun_dns_runtime_stop(ftun_dns_runtime_t *dns)
{
  return ftun_dns_runtime_stop_until(dns, UINT64_MAX);
}

ftun_status_t ftun_dns_runtime_destroy(ftun_dns_runtime_t **dns_ptr)
{
  ftun_dns_runtime_t *dns;
  ftun_status_t status;
  size_t index;
  if (dns_ptr == NULL) return FTUN_E_INVALID;
  dns = *dns_ptr;
  if (dns == NULL) return FTUN_OK;
  status = ftun_dns_runtime_stop(dns);
  if (status != FTUN_OK) return status;
  for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_TCP_CONNECTIONS; index++) {
    status = ftun_dns_runtime_tcp_close(&dns->tcp[index]);
    if (status != FTUN_OK) return status;
  }
  /* 上游集合借用调度器，必须先于它销毁。 */
  for (index = 0u; index < FTUN_DNS_RUNTIME_MAX_SERVERS; index++) {
    (void)ftun_upstream_set_destroy(&dns->upstream_sets[index]);
  }
  ftun_recovery_scheduler_stop(dns->recovery);
  if (ftun_recovery_scheduler_destroy(&dns->recovery) != FTUN_OK) return FTUN_E_AGAIN;
  for (index = 0u; index < dns->listener_count; index++) {
    if (ftun_dns_listener_destroy(&dns->listeners[index].protocol) != FTUN_OK) {
      return FTUN_E_AGAIN;
    }
  }
  if (ftun_dns_listener_destroy(&dns->hijack) != FTUN_OK) return FTUN_E_AGAIN;
  if (ftun_dns_dispatcher_destroy(&dns->dispatcher) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
  for (index = dns->server_count; index != 0u; index--) {
    if (ftun_dns_server_destroy(&dns->servers[index - 1u]) != FTUN_OK) {
      return FTUN_E_AGAIN;
    }
  }
  if (ftun_dns_cache_destroy(&dns->cache) != FTUN_OK) return FTUN_E_AGAIN;
  status = ftun_path_provider_destroy(&dns->paths);
  if (status != FTUN_OK) return status;
  if (ftun_config_destroy(&dns->config) != FTUN_OK) return FTUN_E_AGAIN;
  ftun_reservation_release(&dns->listener_reservation);
  free(dns->proxy_endpoints);
  free(dns->proxy_endpoint_valid);
  memset(dns, 0, sizeof(*dns));
  free(dns);
  *dns_ptr = NULL;
  return FTUN_OK;
}

#endif
