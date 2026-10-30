#define _GNU_SOURCE 1

#include "util/endpoint.h"
#include "proxy/engine_internal.h"

int ftun_proxy_runtime_endpoint_equal(const ftun_endpoint_t *left, const ftun_endpoint_t *right)
{
  return left != NULL && right != NULL && ftun_endpoint_equal(left, right);
}

#if defined(FTUN_HAVE_MODULE_TUN)
void ftun_proxy_runtime_tun_stream_completed(ftun_operation_t *operation,
                                              ftun_error_t error, void *user)
{
  (void)operation;
  (void)error;
  (void)user;
}

ftun_status_t ftun_proxy_runtime_tun_begin(ftun_proxy_runtime_flow_t *flow,
                                           const ftun_metadata_t *metadata)
{
  ftun_runtime_t *runtime = NULL;
  const ftun_config_t *config = NULL;
  const ftun_config_inbound_t *inbound;
  uint64_t now;
  ftun_status_t status;
  flow->pending_metadata = *metadata;
  status = ftun_proxy_runtime_restore_fakeip(flow, &flow->pending_metadata);
  if (status != FTUN_OK) return status;
  status = ftun_proxy_runtime_runtime_for_flow(flow, &runtime, &config);
  inbound = status == FTUN_OK
    ? ftun_proxy_runtime_inbound_config(config, flow->listener) : NULL;
  if (status == FTUN_OK && inbound == NULL) status = FTUN_E_STALE;
  if (status == FTUN_OK && ftun_config_sniff(config)->enable &&
      (flow->pending_metadata.known_fields & FTUN_META_DOMAIN) == 0u) {
    status = ftun_monotonic_now(&now);
    if (status == FTUN_OK) {
      flow->sniff_deadline_ms = now > UINT64_MAX - 200u
        ? UINT64_MAX : now + 200u;
      flow->state = FTUN_PROXY_RUNTIME_FLOW_HANDSHAKE;
    }
  } else if (status == FTUN_OK) {
    status = ftun_proxy_runtime_session_start_metadata(flow,
                                                &flow->pending_metadata);
  }
  (void)ftun_runtime_release(&runtime);
  return status;
}

ftun_status_t ftun_proxy_runtime_tun_sniff(ftun_proxy_runtime_flow_t *flow,
                                            bool readable)
{
  ftun_runtime_t *runtime = NULL;
  const ftun_config_t *config = NULL;
  ftun_sniff_result_t result;
  ftun_bytes_t bytes;
  uint64_t now;
  bool enabled;
  ftun_status_t status;
  if (readable && flow->preread_length < FTUN_PROXY_RUNTIME_PREREAD_BYTES) {
    size_t received = 0u;
    if (flow->preread_length == flow->preread_capacity) {
      size_t wanted = flow->preread_capacity == 0u
        ? 4096u : flow->preread_capacity * 2u;
      if (wanted > FTUN_PROXY_RUNTIME_PREREAD_BYTES) {
        wanted = FTUN_PROXY_RUNTIME_PREREAD_BYTES;
      }
      status = ftun_proxy_runtime_preread_ensure(flow, wanted);
      if (status != FTUN_OK) return status;
    }
    status = ftun_stream_read(flow->client,
      flow->preread + flow->preread_length,
      flow->preread_capacity - flow->preread_length, &received);
    if (status == FTUN_OK) flow->preread_length += received;
    else if (status != FTUN_E_AGAIN && status != FTUN_E_EOF) return status;
  }
  status = ftun_monotonic_now(&now);
  if (status != FTUN_OK) return status;
  status = ftun_proxy_runtime_runtime_for_flow(flow, &runtime, &config);
  if (status != FTUN_OK) return status;
  enabled = flow->preread_length != 0u &&
    ((flow->preread[0] == 22u && ftun_config_sniff(config)->tls_sni) ||
     (flow->preread[0] != 22u && ftun_config_sniff(config)->http_host));
  memset(&result, 0, sizeof(result));
  bytes.data = flow->preread;
  bytes.length = flow->preread_length;
  status = enabled ? ftun_sniff_domain_with_budget(flow->budget, &flow->pending_metadata, bytes, &result)
                   : FTUN_OK;
  (void)ftun_runtime_release(&runtime);
  if (status != FTUN_OK) return status;
  if (enabled && result.need_more &&
      flow->preread_length < FTUN_PROXY_RUNTIME_PREREAD_BYTES &&
      now < flow->sniff_deadline_ms) return FTUN_E_AGAIN;
  if (result.found) {
    if (result.domain.length >= sizeof(flow->sniff_domain)) return FTUN_E_LIMIT;
    memcpy(flow->sniff_domain, result.domain.data, result.domain.length);
    flow->sniff_domain[result.domain.length] = '\0';
    flow->pending_metadata.known_fields |= FTUN_META_DOMAIN;
    flow->pending_metadata.domain.data = flow->sniff_domain;
    flow->pending_metadata.domain.length = result.domain.length;
    flow->pending_metadata.domain_source = FTUN_DOMAIN_SNIFF;
  }
  flow->preread_offset = 0u;
  return ftun_proxy_runtime_session_start_metadata(flow, &flow->pending_metadata);
}

ftun_status_t ftun_proxy_runtime_tun_accept(
  void *user, const ftun_metadata_t *metadata, ftun_stream_t *stream)
{
  ftun_proxy_runtime_t *engine = (ftun_proxy_runtime_t *)user;
  ftun_proxy_runtime_flow_t *flow = NULL;
  ftun_handle_t dns_pair[2] = {-1, -1};
  bool dns_hijack = false;
  ftun_status_t status;
  if (engine == NULL || metadata == NULL || stream == NULL) {
    return FTUN_E_INVALID;
  }
  if (!engine->accepting || engine->tun_resetting) return FTUN_E_CANCELLED;
  status = ftun_proxy_runtime_flow_slot_acquire(engine, &flow);
  if (status != FTUN_OK) return status;
  flow->engine = engine;
  flow->listener = &engine->tun_listener;
  flow->client_socket.descriptor = -1;
  flow->remote_socket.descriptor = -1;
#if defined(FTUN_HAVE_MODULE_DNS)
  dns_hijack = metadata->original_target.port == 53u &&
    ftun_proxy_dns_has_hijack(engine->dns_adapter);
#endif
  /* 普通 TUN Stream 没有独占 FD；DNS 桥接的 socketpair 才预留两个。 */
  status = ftun_proxy_runtime_object_admit(engine,
    (ftun_budget_resources_t){0u,
      dns_hijack ? 2u : 0u, 1u},
    &flow->budget, &flow->admission);
  if (status != FTUN_OK) {
    (void)ftun_proxy_runtime_flow_slot_release(&flow);
    return status;
  }
  flow->client = stream;
  flow->tun = true;
  engine->tun_flow_count++;
  flow->active = true;
  flow->state = FTUN_PROXY_RUNTIME_FLOW_CONNECTING;
  status = ftun_proxy_runtime_flow_classify(
    flow, FTUN_PROXY_RUNTIME_FLOW_TCP);
#if defined(FTUN_HAVE_MODULE_DNS)
  if (status == FTUN_OK && dns_hijack) {
    status = ftun_socket_pair(dns_pair);
    if (status == FTUN_OK) {
      status = ftun_proxy_dns_hijack_tcp(engine->dns_adapter, dns_pair[1]);
      if (status == FTUN_OK) {
        ftun_handle_t remote = dns_pair[0];
        dns_pair[1] = -1;
        /* relay_ready 在成功和失败时均消费 FD；不得由局部清理再次关闭。 */
        dns_pair[0] = -1;
        status = ftun_proxy_runtime_relay_ready(flow, remote);
      }
    }
  } else
#else
  (void)dns_hijack;
#endif
  if (status == FTUN_OK) {
    status = ftun_proxy_runtime_tun_begin(flow, metadata);
  }
  if (status != FTUN_OK) {
    /* 已接纳初始 Stream 引用，Session/Relay 可能仍持有异步引用。
     * 返回成功移交拥有权；退出 lwIP accept 栈后再走统一关闭/重试，
     * 避免在回调内销毁 PCB，或拒绝路径与 Runtime 同时回收 Stream。 */
    flow->accept_failure = status;
    ftun_proxy_runtime_flow_schedule(flow);
  }
  if (dns_pair[0] >= 0) (void)ftun_socket_close((ftun_native_socket_t)dns_pair[0]);
  if (dns_pair[1] >= 0) (void)ftun_socket_close((ftun_native_socket_t)dns_pair[1]);
  return FTUN_OK;
}

void ftun_proxy_runtime_tun_stream_event(
  void *user, ftun_stream_t *stream, ftun_tun_stream_event_t event,
  ftun_status_t status)
{
  ftun_proxy_runtime_t *engine = (ftun_proxy_runtime_t *)user;
  size_t index;
  if (engine == NULL || stream == NULL) return;
  for (index = 0u; index < engine->flow_capacity; index++) {
    ftun_proxy_runtime_flow_t *flow = ftun_proxy_runtime_flow_at(engine, index);
    if (flow == NULL) continue;
    if (!flow->active || !flow->tun || flow->client != stream) continue;
    if (event == FTUN_TUN_STREAM_READABLE ||
        event == FTUN_TUN_STREAM_PEER_FIN) {
      flow->left_events |= FTUN_EVENT_READ;
    } else if (event == FTUN_TUN_STREAM_WRITABLE) {
      flow->left_events |= FTUN_EVENT_WRITE;
    } else if (event == FTUN_TUN_STREAM_CLOSED && status != FTUN_OK &&
               status != FTUN_E_EOF) {
      ftun_proxy_runtime_flow_close(flow, status);
    }
    ftun_proxy_runtime_flow_schedule(flow);
    return;
  }
}

ftun_status_t ftun_proxy_runtime_tun_output(
  void *user, ftun_bytes_t packet)
{
  ftun_proxy_runtime_t *engine = (ftun_proxy_runtime_t *)user;
  if (engine == NULL || engine->tun_lease.service == NULL) {
    return FTUN_E_INVALID;
  }
  if (!engine->accepting || engine->tun_resetting) return FTUN_E_CANCELLED;
  if (packet.data == NULL || packet.length == 0u ||
      packet.length > engine->tun_info.mtu) return FTUN_E_INVALID;
  return ftun_tun_service_write(engine->tun_lease, packet);
}
#endif

#if defined(FTUN_HAVE_MODULE_TUN)
ftun_status_t ftun_proxy_runtime_tun_datagram(
  void *user, const ftun_metadata_t *metadata, ftun_datagram_t *channel,
  const ftun_endpoint_t *source, const ftun_packet_t *packet)
{
  ftun_proxy_runtime_t *engine = (ftun_proxy_runtime_t *)user;
  ftun_status_t status;
  if (engine == NULL || metadata == NULL || source == NULL ||
      !ftun_proxy_runtime_endpoint_equal(source, &metadata->original_target)) {
    return FTUN_E_STATE_CORRUPT;
  }
  if (!engine->accepting || engine->tun_resetting) return FTUN_E_CANCELLED;
#if defined(FTUN_HAVE_MODULE_DNS)
  if (metadata->original_target.port == 53u &&
      ftun_proxy_dns_has_hijack(engine->dns_adapter)) {
    return ftun_proxy_dns_hijack_udp(
      engine->dns_adapter, channel, &metadata->source, packet);
  }
#endif
  status = ftun_proxy_runtime_udp_route_datagram(engine, channel, metadata,
                                                  packet, NULL, true);
  if (status == FTUN_E_PROTOCOL || status == FTUN_E_REJECTED ||
      status == FTUN_E_RESOLVE || status == FTUN_E_LIMIT ||
      status == FTUN_E_AGAIN || status == FTUN_E_STALE) return FTUN_OK;
  return status;
}

ftun_status_t ftun_proxy_runtime_tun_packet(
  void *user, ftun_tun_lease_t lease, ftun_bytes_t packet)
{
  ftun_proxy_runtime_t *engine = (ftun_proxy_runtime_t *)user;
  ftun_status_t status;
  if (engine == NULL || lease.service != engine->tun_lease.service ||
      lease.generation != engine->tun_lease.generation) return FTUN_E_STALE;
  /* 恢复期间丢弃输入，不把新网络的数据排队送入旧协议栈。 */
  if (!engine->accepting || engine->tun_resetting) return FTUN_OK;
  status = ftun_tun_ingress_bytes(
    engine->tun_ingress, engine->relay_pool, packet);
  /* TUN 可能收到内核生成的 ICMP 等非 TCP/UDP 包。当前数据面不处理这些
   * 协议，但单个不支持的包不能终止整个共享物理接口。 */
  return status == FTUN_E_PROTOCOL || status == FTUN_E_UNSUPPORTED
    ? FTUN_OK : status;
}
#endif

#if defined(FTUN_HAVE_MODULE_TUN)
ftun_status_t ftun_proxy_runtime_tun_prepare(
  ftun_proxy_runtime_t *engine, const ftun_config_inbound_t *inbound,
  uint32_t inbound_id)
{
  ftun_tun_ingress_spec_t ingress;
  ftun_status_t status;
  if (engine->l3_provider == NULL) return FTUN_E_UNSUPPORTED;
  engine->tun_listener.descriptor = -1;
  engine->tun_listener.name = strdup(inbound->name);
  if (engine->tun_listener.name == NULL) return FTUN_E_LIMIT;
  engine->tun_listener.kind = FTUN_CONFIG_INBOUND_TUN;
  engine->tun_listener.tcp_idle_ms = inbound->tcp_idle_ms;
  engine->tun_listener.inbound_id = inbound_id;
  engine->tun_info.mtu = inbound->mtu;
  engine->tun_auto_route = inbound->auto_route;
  status = ftun_monotonic_now(&engine->now_ms);
  if (status != FTUN_OK) return status;
  memset(&ingress, 0, sizeof(ingress));
  ingress.budget = engine->budget;
  ingress.operations = engine->operations;
  ingress.generation = engine->generation;
  ingress.now_ms = engine->now_ms;
  ingress.inbound_id = inbound_id;
  ingress.liveness = engine->liveness;
  ingress.mtu = inbound->mtu;
  ingress.max_pending_stream_writes = 32u;
  ingress.max_pending_stream_bytes = 256u * 1024u;
  ingress.max_pending_datagrams = FTUN_PROXY_RUNTIME_DATAGRAM_CAPACITY;
  ingress.max_pending_datagram_bytes = 256u * 1024u;
  ingress.tcp = inbound->tcp;
  ingress.udp = inbound->udp;
  ingress.stream_write_completion = ftun_proxy_runtime_tun_stream_completed;
  ingress.stream_accept = ftun_proxy_runtime_tun_accept;
  ingress.stream_event = ftun_proxy_runtime_tun_stream_event;
  ingress.datagram_receive = ftun_proxy_runtime_tun_datagram;
  ingress.output = ftun_proxy_runtime_tun_output;
  ingress.user = engine;
  engine->tun_spec = ingress;
  status = ftun_tun_ingress_bind(&ingress, &engine->tun_ingress);
  if (status == FTUN_OK) engine->has_tun = true;
  return status;
}

void ftun_proxy_runtime_tun_event(void *user, ftun_tun_lease_t lease,
  ftun_tun_service_event_t event, ftun_status_t status)
{
  ftun_proxy_runtime_t *engine = user;
  if (engine == NULL || lease.service != engine->tun_lease.service ||
      lease.generation != engine->tun_lease.generation || !engine->accepting) return;
  engine->tun_provider_ready = status == FTUN_OK &&
    (event == FTUN_TUN_SERVICE_REBUILT || event == FTUN_TUN_SERVICE_PATH_UPDATED ||
     event == FTUN_TUN_SERVICE_NETWORK_UPDATED);
  engine->tun_resetting = true;
  engine->tun_reset_due_ms = 0u;
  if (engine->tun_ingress != NULL) (void)ftun_tun_ingress_quiesce(engine->tun_ingress);
}

/* 事件仅关接纳；owner 轮次按固定额度清理，所有旧引用静默后才重新绑定。 */
ftun_status_t ftun_proxy_runtime_tun_reset(ftun_proxy_runtime_t *engine,
  uint64_t now_ms, size_t *out_work)
{
  const size_t quota = 32u;
  size_t scanned, work = 0u;
  ftun_status_t status;
  ftun_l3_provider_info_t provider;
  ftun_tun_consumer_usage_t consumer;
  *out_work = 0u;
  if (!engine->tun_resetting || !engine->accepting ||
      engine->tun_reset_due_ms > now_ms) return FTUN_OK;
  engine->tun_reset_due_ms = now_ms > UINT64_MAX - 10u ? UINT64_MAX : now_ms + 10u;
  for (scanned = 0u; engine->tun_flow_count != 0u &&
       scanned < quota && scanned < engine->flow_capacity; scanned++) {
    ftun_proxy_runtime_flow_t *flow = ftun_proxy_runtime_flow_at(engine, engine->tun_flow_cursor);
    engine->tun_flow_cursor = (engine->tun_flow_cursor + 1u) % engine->flow_capacity;
    (*out_work)++;
    if (flow != NULL && flow->tun) ftun_proxy_runtime_flow_close(flow, FTUN_E_CANCELLED);
  }
  for (scanned = 0u; engine->tun_pending_count != 0u &&
       scanned < quota && scanned < engine->udp_capacity; scanned++) {
    ftun_proxy_runtime_udp_pending_t *pending = ftun_proxy_runtime_udp_pending_at(
      engine, engine->tun_pending_cursor);
    engine->tun_pending_cursor = (engine->tun_pending_cursor + 1u) % engine->udp_capacity;
    (*out_work)++;
    if (pending != NULL && pending->tun) {
      pending->cancelled = true;
      if (pending->operation != NULL) (void)ftun_operation_cancel(pending->operation);
    }
  }
  status = ftun_tun_ingress_close_step(&engine->tun_ingress, quota, &work);
  *out_work += work;
  if (status != FTUN_OK && status != FTUN_E_AGAIN) return status;
  if (engine->udp_flows != NULL) {
    status = ftun_udp_flow_reap_stopped(engine->udp_flows, quota, &work);
    *out_work += work;
    if (status != FTUN_OK && status != FTUN_E_AGAIN) return status;
  }
  if (engine->tun_flow_count != 0u || engine->tun_pending_count != 0u ||
      engine->tun_ingress != NULL) return FTUN_OK;
  if (!engine->tun_provider_ready) {
    engine->tun_reset_due_ms = UINT64_MAX;
    return FTUN_OK;
  }
  status = ftun_l3_provider_get_info(engine->l3_provider, &provider);
  if (status != FTUN_OK) return status;
  if (!provider.accepting || engine->reload_prepared || engine->reload_pending) return FTUN_OK;
  status = ftun_tun_service_get_consumer_usage(engine->tun_lease, &consumer);
  if (status != FTUN_OK) return status;
  if (consumer.inner_mtu < FTUN_LWIP_MIN_MTU) return FTUN_E_UNSUPPORTED;
  engine->tun_spec.generation = engine->generation;
  engine->tun_spec.inbound_id = engine->tun_listener.inbound_id;
  engine->tun_spec.now_ms = now_ms;
  engine->tun_spec.mtu = consumer.inner_mtu;
  status = ftun_tun_ingress_bind(&engine->tun_spec, &engine->tun_ingress);
  if (status != FTUN_OK) return status;
  engine->tun_info = provider.device;
  engine->tun_resetting = false;
  engine->tun_reset_due_ms = 0u;
  (*out_work)++;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_tun_activate(
  ftun_proxy_runtime_t *engine)
{
  ftun_l3_provider_info_t provider;
  ftun_tun_consumer_spec_t consumer;
  ftun_status_t status;
  if (engine == NULL || !engine->has_tun || engine->l3_provider == NULL ||
      engine->tun_ingress == NULL || engine->tun_lease.service != NULL) {
    return FTUN_E_INVALID;
  }
  status = ftun_l3_provider_get_info(engine->l3_provider, &provider);
  if (status != FTUN_OK) return status;
  if (provider.generation != engine->generation || !provider.accepting ||
      provider.device.mtu != engine->tun_info.mtu) {
    return FTUN_E_STATE_CORRUPT;
  }
  engine->tun_info = provider.device;
  memset(&consumer, 0, sizeof(consumer));
  consumer.consumer.packet = ftun_proxy_runtime_tun_packet;
  consumer.consumer.event = ftun_proxy_runtime_tun_event;
  consumer.consumer.user = engine;
  consumer.route.kind = FTUN_TUN_ROUTE_DEFAULT;
  consumer.route.priority = UINT16_MAX;
  return ftun_l3_provider_acquire(engine->l3_provider,
    engine->generation, &consumer, &engine->tun_lease);
}
#endif

