#define _GNU_SOURCE 1

#include "proxy/engine_internal.h"
#include "libs/tls/tls.h"

ftun_status_t ftun_proxy_runtime_datagram_capacity(
  const ftun_config_t *config, size_t *out)
{
  size_t per_flow = FTUN_PROXY_RUNTIME_DATAGRAM_CAPACITY + 2u;
  size_t associations;
  if (out != NULL) *out = 0u;
  if (config == NULL || out == NULL ||
      ftun_config_base(config)->capacity.udp_flows > FTUN_CONFIG_CAPACITY_MAXIMUM ||
      ftun_config_base(config)->capacity.udp_associations > FTUN_CONFIG_CAPACITY_MAXIMUM) {
    return FTUN_E_INVALID;
  }
#if defined(FTUN_HAVE_MODULE_TUN)
  /* TUN 入站通道独立于出站通道，容量覆盖同一配置额度内的入站选择。 */
  per_flow += FTUN_PROXY_RUNTIME_DATAGRAM_CAPACITY;
#endif
  associations = ftun_config_base(config)->capacity.udp_associations;
  if ((size_t)ftun_config_base(config)->capacity.udp_flows >
      (SIZE_MAX - associations) / per_flow) return FTUN_E_LIMIT;
  /* 每流包括外层请求槽，以及 SOCKS5 的协议与 wire 各一槽；DIRECT 只用
   * 后者之一。每个 SOCKS5 入站 association 另有一个回包通道槽。 */
  *out = associations + (size_t)ftun_config_base(config)->capacity.udp_flows * per_flow;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_event_source_capacity(
  const ftun_config_t *config, size_t *out)
{
  size_t flow_capacity;
  size_t capacity;
  if (out != NULL) *out = 0u;
  if (config == NULL || out == NULL ||
      ftun_config_base(config)->capacity.tcp_flows > FTUN_CONFIG_CAPACITY_MAXIMUM ||
      ftun_config_base(config)->capacity.udp_flows > FTUN_CONFIG_CAPACITY_MAXIMUM ||
      ftun_config_base(config)->capacity.udp_associations >
        FTUN_CONFIG_CAPACITY_MAXIMUM) return FTUN_E_INVALID;
  flow_capacity = (size_t)ftun_config_base(config)->capacity.tcp_flows +
    (size_t)ftun_config_base(config)->capacity.udp_associations;
  if (flow_capacity > (SIZE_MAX - 64u) / 3u) return FTUN_E_LIMIT;
  capacity = 64u + flow_capacity * 3u;
  /* TCP SOCKS5 握手的 task/期限及物理通道发送任务均计入峰值。 */
  if ((size_t)ftun_config_base(config)->capacity.tcp_flows > (SIZE_MAX - capacity) / 3u) return FTUN_E_LIMIT;
  capacity += (size_t)ftun_config_base(config)->capacity.tcp_flows * 3u;
  /* UDP SOCKS5 的控制流与报文通道各有一个有界发送任务。 */
  if ((size_t)ftun_config_base(config)->capacity.udp_flows >
      (SIZE_MAX - capacity) / 6u) return FTUN_E_LIMIT;
  *out = capacity + (size_t)ftun_config_base(config)->capacity.udp_flows * 6u;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_prepare(ftun_core_t *core, ftun_budget_t *budget,
                                  ftun_operation_queue_t *operations,
                                  const ftun_proxy_bindings_t *bindings,
                                  const ftun_config_t *config,
                                  uint64_t generation,
                                  ftun_proxy_runtime_t **out)
{
  ftun_proxy_runtime_t *engine;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_resolver_provider_spec_t resolver_provider;
  ftun_path_provider_spec_t path_provider;
  /* Event 后端、source 和 Worker 队列分别由实际拥有者计量。 */
  ftun_budget_resources_t engine_resources = {sizeof(*engine), 0u, 0u};
  ftun_udp_flow_table_spec_t flow_spec;
  bool udp_required = false;
  bool tun_required = false;
  size_t flow_capacity;
  size_t association_bucket_count = 1u;
  size_t association_bucket_bytes;
  size_t udp_backoff_capacity;
  size_t udp_backoff_bytes;
  size_t relay_waiters;
  size_t index;
  ftun_status_t status;
  if (out != NULL && *out != NULL) return FTUN_E_AGAIN;
  if (core == NULL || budget == NULL || operations == NULL ||
      !ftun_proxy_bindings_valid(bindings) || config == NULL ||
      generation == 0u || out == NULL) return FTUN_E_INVALID;
#if defined(FTUN_HAVE_MODULE_TUN)
  if (bindings->l3 != NULL && bindings->l3->service != NULL &&
      bindings->l3->generation != generation) {
    return FTUN_E_STALE;
  }
#endif
  if (ftun_config_inbound_count(config) > FTUN_PROXY_RUNTIME_MAX_LISTENERS) return FTUN_E_LIMIT;
  if (ftun_config_base(config)->capacity.tcp_flows < FTUN_CONFIG_CAPACITY_MINIMUM ||
      ftun_config_base(config)->capacity.tcp_flows > FTUN_CONFIG_CAPACITY_MAXIMUM ||
      ftun_config_base(config)->capacity.udp_flows < FTUN_CONFIG_CAPACITY_MINIMUM ||
      ftun_config_base(config)->capacity.udp_flows > FTUN_CONFIG_CAPACITY_MAXIMUM ||
      ftun_config_base(config)->capacity.udp_associations < FTUN_CONFIG_CAPACITY_MINIMUM ||
      ftun_config_base(config)->capacity.udp_associations > FTUN_CONFIG_CAPACITY_MAXIMUM) {
    return FTUN_E_INVALID;
  }
  flow_capacity = (size_t)ftun_config_base(config)->capacity.tcp_flows +
                  (size_t)ftun_config_base(config)->capacity.udp_associations;
  while (association_bucket_count <
         (size_t)ftun_config_base(config)->capacity.udp_associations * 2u) {
    if (association_bucket_count > SIZE_MAX / 2u) return FTUN_E_LIMIT;
    association_bucket_count *= 2u;
  }
  association_bucket_bytes = association_bucket_count *
    2u * sizeof(ftun_proxy_runtime_flow_t *);
  engine_resources.memory_bytes += association_bucket_bytes;
  udp_backoff_capacity = ftun_config_outbound_count(config) + 2u;
  udp_backoff_bytes = udp_backoff_capacity *
    sizeof(ftun_proxy_runtime_udp_backoff_t);
  engine_resources.memory_bytes += udp_backoff_bytes;
  relay_waiters = (size_t)ftun_config_base(config)->capacity.tcp_flows * 2u;
  for (index = 0u; index < ftun_config_inbound_count(config); index++) {
    size_t name_bytes;
    size_t descriptors = ftun_config_inbounds(config)[index].kind ==
      FTUN_CONFIG_INBOUND_TUN ? 0u :
      1u + (ftun_config_inbounds(config)[index].udp ? 1u : 0u);
    if (ftun_config_inbounds(config)[index].name == NULL) return FTUN_E_INVALID;
    name_bytes = strlen(ftun_config_inbounds(config)[index].name) + 1u;
    if (engine_resources.descriptors > SIZE_MAX - descriptors ||
        engine_resources.memory_bytes > SIZE_MAX - name_bytes) {
      return FTUN_E_LIMIT;
    }
    /* listener 的名字副本和物理 socket 归 Engine；watcher 不在此重复预留。 */
    engine_resources.memory_bytes += name_bytes;
    engine_resources.descriptors += descriptors;
  }
  status = ftun_budget_reserve_resources(budget, engine_resources,
                                         &reservation);
  if (status != FTUN_OK) return status;
  engine = (ftun_proxy_runtime_t *)calloc(1u, sizeof(*engine));
  if (engine == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  for (index = 0u; index < FTUN_PROXY_RUNTIME_MAX_LISTENERS; index++) {
    engine->listeners[index].descriptor = -1;
    engine->listeners[index].udp_descriptor = -1;
  }
  engine->core = core;
  engine->budget = budget;
  engine->reservation = reservation;
  engine->operations = operations;
  engine->generation = generation;
  engine->l3_provider = bindings->l3;
  engine->loop = bindings->loop;
  engine->control_path = bindings->control_path;
  engine->dns_adapter = bindings->dns;
  engine->fakeip_slot = bindings->fakeip_slot;
  engine->flow_capacity = flow_capacity;
  engine->tcp_capacity = ftun_config_base(config)->capacity.tcp_flows;
  engine->association_capacity = ftun_config_base(config)->capacity.udp_associations;
  engine->udp_capacity = ftun_config_base(config)->capacity.udp_flows;
  engine->association_bucket_count = association_bucket_count;
  engine->association_clients = (ftun_proxy_runtime_flow_t **)calloc(
    association_bucket_count, sizeof(*engine->association_clients));
  engine->association_channels = (ftun_proxy_runtime_flow_t **)calloc(
    association_bucket_count, sizeof(*engine->association_channels));
  engine->udp_backoff_capacity = udp_backoff_capacity;
  engine->udp_backoff = (ftun_proxy_runtime_udp_backoff_t *)calloc(
    udp_backoff_capacity, sizeof(*engine->udp_backoff));
  if (engine->association_clients == NULL ||
      engine->association_channels == NULL || engine->udp_backoff == NULL) {
    status = FTUN_E_LIMIT;
    goto fail;
  }
  memset(&resolver_provider, 0, sizeof(resolver_provider));
  resolver_provider.budget = budget;
  resolver_provider.generation = generation;
  resolver_provider.ops = bindings->resolver;
  resolver_provider.context = bindings->resolver_context;
  status = ftun_resolver_provider_create(&resolver_provider,
                                          &engine->resolver_provider);
  if (status != FTUN_OK) goto fail;
  status = ftun_proxy_slot_pool_create(budget,
    sizeof(ftun_proxy_runtime_flow_t), flow_capacity, 64u, 1u,
    &engine->flow_pool);
  if (status != FTUN_OK) goto fail;
  status = ftun_proxy_slot_pool_create(budget,
    sizeof(ftun_proxy_runtime_udp_slot_t), engine->udp_capacity, 32u, 1u,
    &engine->udp_pool);
  if (status != FTUN_OK) goto fail;
  status = ftun_proxy_slot_pool_create(budget,
    sizeof(ftun_proxy_runtime_udp_pending_t), engine->udp_capacity, 64u, 1u,
    &engine->udp_pending_pool);
  if (status != FTUN_OK) goto fail;
#if defined(FTUN_HAVE_MODULE_FRS)
  if (ftun_config_frs(config)->active && ftun_config_frs(config)->auto_update &&
      ftun_config_frs(config)->url != NULL && ftun_config_frs(config)->url[0] != '\0') {
    if (!ftun_proxy_runtime_duration_ms(ftun_config_frs(config)->update_interval,
                                 &engine->frs_interval_ms) ||
        ftun_monotonic_now(&engine->now_ms) != FTUN_OK ||
        engine->frs_interval_ms > UINT64_MAX - engine->now_ms) {
      status = FTUN_E_INVALID;
      goto fail;
    }
    engine->frs_due_ms = engine->now_ms + engine->frs_interval_ms;
    engine->frs_enabled = true;
    {
      ftun_file_info_t info;
      /* 本地规则文件缺失：应用层已让 FRS 以 NOT_READY 启动，立即开始下载。 */
      if (ftun_config_frs(config)->path != NULL && ftun_file_inspect_path(ftun_config_frs(config)->path, &info) == FTUN_E_EOF) {
        engine->frs_not_ready = true;
        engine->frs_due_ms = engine->now_ms;
      }
    }
  }
#endif
  for (index = 0u; index < ftun_config_inbound_count(config); index++) {
    if (ftun_config_inbounds(config)[index].udp) udp_required = true;
    if (ftun_config_inbounds(config)[index].kind == FTUN_CONFIG_INBOUND_TUN) {
      tun_required = true;
    }
  }
  engine->socket_mark = tun_required ? ftun_config_base(config)->routing_mark : 0u;
  {
    ftun_proxy_runtime_timeouts_t timeouts;
    ftun_proxy_runtime_timeouts_from(config, &timeouts);
    engine->liveness = timeouts.liveness;
    engine->handshake_ms = timeouts.handshake_ms;
    engine->connect_ms = timeouts.connect_ms;
    engine->reply_ms = timeouts.reply_ms;
    engine->tcp_idle_ms = timeouts.tcp_idle_ms;
    engine->write_progress_ms = timeouts.write_progress_ms;
  }
  status = ftun_proxy_runtime_health_prepare(engine, config, generation,
    &engine->health_groups, &engine->health_group_count,
    &engine->health_slots, &engine->health_slot_count,
    &engine->health_reservation);
  if (status == FTUN_OK) {
    status = ftun_worker_create(budget, 64u, &engine->worker);
  }
  if (status == FTUN_OK) {
    status = ftun_worker_create(budget, 16u, &engine->maintenance_worker);
  }
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  if (status == FTUN_OK &&
      (ftun_proxy_config_plan(config).prepare & FTUN_PROXY_PLAN_FAKE_IP) != 0u &&
      ftun_config_resolver(config).fake_ip.persist) {
    status = ftun_worker_create(budget, 2u, &engine->fakeip_worker);
  }
#endif
  if (status == FTUN_OK) {
    status = ftun_buffer_pool_create_waitable(
      budget, FTUN_PROXY_RUNTIME_RELAY_POOL_BYTES, FTUN_PROXY_RUNTIME_RELAY_POOL_BUFFERS,
      relay_waiters, relay_waiters < FTUN_PROXY_RUNTIME_RELAY_WAKE_QUOTA
        ? relay_waiters : FTUN_PROXY_RUNTIME_RELAY_WAKE_QUOTA,
      &engine->relay_pool);
  }
  if (status == FTUN_OK) {
    status = ftun_buffer_pool_set_wakeup(engine->relay_pool,
      ftun_proxy_runtime_worker_wakeup, engine->loop);
  }
  if (status == FTUN_OK) {
    memset(&path_provider, 0, sizeof(path_provider));
    path_provider.budget = budget;
    path_provider.generation = generation;
    path_provider.ops = bindings->path;
    path_provider.context = bindings->path_context;
    path_provider.max_pending = engine->flow_capacity + engine->udp_capacity;
    path_provider.max_paths = 2u * path_provider.max_pending;
    path_provider.receive_pool = engine->relay_pool;
    status = ftun_path_provider_create(&path_provider, &engine->path_provider);
  }
  if (status == FTUN_OK) {
    status = ftun_worker_set_wakeup(engine->worker,
      ftun_proxy_runtime_worker_wakeup, engine->loop);
  }
  if (status == FTUN_OK) {
    status = ftun_worker_set_wakeup(engine->maintenance_worker,
      ftun_proxy_runtime_worker_wakeup, engine->loop);
  }
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  if (status == FTUN_OK && engine->fakeip_worker != NULL) {
    status = ftun_worker_set_wakeup(engine->fakeip_worker,
      ftun_proxy_runtime_worker_wakeup, engine->loop);
  }
#endif
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  if (status == FTUN_OK) status = ftun_proxy_runtime_fakeip_prepare(engine, config);
#endif
  if (status == FTUN_OK) *engine->fakeip_slot =
#if defined(FTUN_HAVE_MODULE_FAKEIP)
    engine->fakeip;
#else
    NULL;
#endif
  if (status == FTUN_OK && udp_required) {
    status = ftun_monotonic_now(&engine->now_ms);
    memset(&flow_spec, 0, sizeof(flow_spec));
    flow_spec.core = core;
    flow_spec.budget = budget;
    flow_spec.capacity = ftun_config_base(config)->capacity.udp_flows;
    flow_spec.idle_timeout_ms = ftun_config_base(config)->timeouts.udp_idle_ms;
    flow_spec.now_ms = engine->now_ms;
    flow_spec.backend.open = ftun_proxy_runtime_udp_open;
    flow_spec.backend.reply = ftun_proxy_runtime_udp_reply;
    flow_spec.backend.user = engine;
    if (status == FTUN_OK) {
      status = ftun_udp_flow_table_create(&flow_spec, &engine->udp_flows);
    }
  }
  if (status != FTUN_OK) goto fail;
  {
    ftun_recovery_policy_t policy;
    memset(&policy, 0, sizeof(policy));
    policy.initial_ms = FTUN_PROXY_RUNTIME_LISTENER_RETRY_INITIAL_MS;
    policy.maximum_ms = FTUN_PROXY_RUNTIME_LISTENER_RETRY_MAXIMUM_MS;
    policy.stable_ms = FTUN_PROXY_RUNTIME_LISTENER_RETRY_STABLE_MS;
    policy.jitter_permille = 200u;
    policy.auth_retry_ms = FTUN_PROXY_RUNTIME_LISTENER_RETRY_MAXIMUM_MS;
    policy.seed = engine->now_ms == 0u ? 1u : engine->now_ms;
    /* 监听实体加上每个出口一个 UDP 退避实体。 */
    status = ftun_recovery_scheduler_create(budget,
      FTUN_PROXY_RUNTIME_MAX_LISTENERS + engine->udp_backoff_capacity,
      &policy, &engine->recovery);
    if (status != FTUN_OK) goto fail;
  }
  for (index = 0u; index < ftun_config_inbound_count(config); index++) {
    const ftun_config_inbound_t *inbound = &ftun_config_inbounds(config)[index];
    ftun_proxy_runtime_listener_t *listener;
    if (inbound->kind == FTUN_CONFIG_INBOUND_TUN) {
      #if defined(FTUN_HAVE_MODULE_TUN)
      status = ftun_proxy_runtime_tun_prepare(engine, inbound,
                                        (uint32_t)index + 1u);
      if (status != FTUN_OK) goto fail;
      continue;
      #else
      status = FTUN_E_UNSUPPORTED;
      goto fail;
      #endif
    }
    listener = &engine->listeners[engine->listener_count];
    listener->engine = engine;
    status = ftun_proxy_runtime_listener_endpoint(listener, inbound,
                                            (uint32_t)index + 1u);
    if (status != FTUN_OK) goto fail;
    engine->listener_count++;
    {
      ftun_recovery_spec_t spec;
      uint64_t now_ms = 0u;
      memset(&spec, 0, sizeof(spec));
      spec.kind = 1u;
      spec.attempt = ftun_proxy_runtime_listener_recover;
      spec.user = listener;
      (void)ftun_monotonic_now(&now_ms);
      status = ftun_recovery_entity_register(engine->recovery, &spec, now_ms,
                                             &listener->recovery);
      if (status != FTUN_OK) goto fail;
      status = ftun_proxy_runtime_listener_bind(listener);
      /* 启动时地址尚未就绪（例如开机时网卡还没配好）：不失败，进入等待恢复；
       * 地址被占用和其他错误仍然让启动失败。 */
      if (status != FTUN_OK && listener->bind_issue == FTUN_SOCKET_BIND_ADDRESS_UNAVAILABLE) {
        listener->waiting = true;
        status = ftun_recovery_report_failure(engine->recovery, listener->recovery,
          now_ms, FTUN_RECOVERY_FAULT_NETWORK);
      } else if (status == FTUN_OK) {
        status = ftun_proxy_runtime_listener_start(engine, listener);
      }
    }
    if (status != FTUN_OK) goto fail;
  }
  *out = engine;
  return FTUN_OK;

fail:
  {
    uint64_t deadline_ms = 1u;
    engine->cleanup_only = true;
    (void)ftun_monotonic_now(&deadline_ms);
    /* prepare 的原始错误不被清理覆盖；未静默的实例由上层继续拥有。 */
    (void)ftun_proxy_runtime_destroy_until(&engine, deadline_ms);
    *out = engine;
  }
  return status;
}

ftun_status_t ftun_proxy_runtime_activate(ftun_proxy_runtime_t *engine)
{
  if (engine == NULL || engine->stopped || engine->cleanup_only) {
    return FTUN_E_INVALID;
  }
#if defined(FTUN_HAVE_MODULE_TUN)
  if (engine->has_tun) {
    ftun_status_t status = ftun_proxy_runtime_tun_activate(engine);
    if (status != FTUN_OK) return status;
  }
#endif
  engine->accepting = true;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_reload_prepare_owned(
  ftun_proxy_runtime_t *engine, const ftun_config_t *config, uint64_t generation,
  const void *plan, ftun_proxy_reload_owner_t owner)
{
  ftun_runtime_t *active_runtime = NULL;
  const ftun_config_t *active_config = NULL;
  ftun_status_t status;
  if (engine == NULL || config == NULL || generation == 0u ||
      engine->stopped || engine->cleanup_only) {
    return FTUN_E_INVALID;
  }
  if (engine->reload_pending) {
    /* 另一方的事务正在持有准备状态：稍后重试，不触碰它。 */
    return engine->reload_owner != owner &&
           engine->reload_owner != FTUN_PROXY_RELOAD_OWNER_NONE
      ? FTUN_E_AGAIN : FTUN_E_INVALID;
  }
  (void)plan;
  if (generation <= engine->generation) return FTUN_E_STALE;
#if defined(FTUN_HAVE_MODULE_TUN)
  if (engine->tun_resetting) return FTUN_E_AGAIN;
#endif
  status = ftun_runtime_active_acquire(engine->core, &active_runtime);
  if (status == FTUN_OK) {
    status = ftun_runtime_config(active_runtime, &active_config);
  }
  if (status == FTUN_OK &&
      (ftun_config_base(active_config)->capacity.tcp_flows !=
         ftun_config_base(config)->capacity.tcp_flows ||
       ftun_config_base(active_config)->capacity.udp_flows !=
         ftun_config_base(config)->capacity.udp_flows ||
       ftun_config_base(active_config)->capacity.udp_associations !=
         ftun_config_base(config)->capacity.udp_associations)) {
    status = FTUN_E_UNSUPPORTED;
  }
  (void)ftun_runtime_release(&active_runtime);
  active_config = NULL;
  if (status != FTUN_OK) return status;
  status = ftun_proxy_runtime_prepare_inbound_ids(engine, config);
  if (status != FTUN_OK) return status;
#if defined(FTUN_HAVE_MODULE_TUN)
  if (engine->tun_ingress != NULL) {
    status = ftun_tun_ingress_can_set_identity(engine->tun_ingress,
      generation, engine->pending_tun_inbound_id);
    if (status != FTUN_OK) return status;
  }
#endif
  status = ftun_runtime_active_acquire(engine->core, &active_runtime);
  if (status == FTUN_OK) {
    status = ftun_runtime_config(active_runtime, &active_config);
  }
  if (status == FTUN_OK) {
    engine->pending_health_reuse =
      ftun_proxy_runtime_health_config_equal(active_config, config) != 0;
  }
  (void)ftun_runtime_release(&active_runtime);
  if (status != FTUN_OK) return status;
  engine->reload_pending = true;
  engine->reload_owner = owner;
  if (!engine->pending_health_reuse) {
    size_t index;
    for (index = 0u; index < engine->health_slot_count; index++) {
      if (engine->health_slots[index].operation != NULL) return FTUN_E_AGAIN;
    }
    status = ftun_proxy_runtime_health_prepare(engine, config, generation,
      &engine->pending_health_groups, &engine->pending_health_group_count,
      &engine->pending_health_slots, &engine->pending_health_slot_count,
      &engine->pending_health_reservation);
    if (status != FTUN_OK) return status;
  }
  ftun_proxy_runtime_timeouts_from(config, &engine->pending_timeouts);
#if defined(FTUN_HAVE_MODULE_FRS)
  engine->pending_frs_enabled = ftun_config_frs(config)->active &&
    ftun_config_frs(config)->auto_update && ftun_config_frs(config)->url != NULL &&
    ftun_config_frs(config)->url[0] != '\0';
  engine->pending_frs_interval_ms = 0u;
  if (engine->pending_frs_enabled && !ftun_proxy_runtime_duration_ms(
        ftun_config_frs(config)->update_interval, &engine->pending_frs_interval_ms)) {
    engine->pending_frs_enabled = false;
    (void)ftun_proxy_runtime_reload_abort(engine);
    return FTUN_E_INVALID;
  }
#endif
  status = ftun_resolver_provider_reload_prepare(engine->resolver_provider,
                                                  generation);
  if (status == FTUN_OK) {
    status = ftun_path_provider_reload_prepare(engine->path_provider,
                                                generation);
  }
  if (status != FTUN_OK) {
    (void)ftun_proxy_runtime_reload_abort_owned(engine, owner);
    return status;
  }
  engine->reload_prepared = true;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_reload_prepare_planned(
  ftun_proxy_runtime_t *engine, const ftun_config_t *config, uint64_t generation,
  const void *plan)
{
  return ftun_proxy_runtime_reload_prepare_owned(engine, config, generation,
    plan, FTUN_PROXY_RELOAD_OWNER_HOST);
}

ftun_status_t ftun_proxy_runtime_reload_prepare(ftun_proxy_runtime_t *engine,
                                         const ftun_config_t *config,
                                         uint64_t generation)
{
  return ftun_proxy_runtime_reload_prepare_planned(engine, config, generation, NULL);
}

ftun_status_t ftun_proxy_runtime_reload_commit_owned(
  ftun_proxy_runtime_t *engine, uint64_t generation,
  ftun_proxy_reload_owner_t owner)
{
  ftun_resolver_provider_info_t resolver_info;
  ftun_path_provider_info_t path_info;
  ftun_status_t status;
  if (engine == NULL || generation == 0u || engine->stopped ||
      !engine->reload_prepared || engine->reload_owner != owner ||
      generation <= engine->generation) {
    return FTUN_E_INVALID;
  }
  status = ftun_resolver_provider_get_info(engine->resolver_provider,
                                            &resolver_info);
  if (status == FTUN_OK) {
    status = ftun_path_provider_get_info(engine->path_provider, &path_info);
  }
  if (status != FTUN_OK) return status;
  if (!resolver_info.reload_prepared || !path_info.reload_prepared ||
      resolver_info.pending_generation != generation ||
      path_info.pending_generation != generation) {
    return FTUN_E_STATE_CORRUPT;
  }
  status = ftun_resolver_provider_reload_commit(engine->resolver_provider,
                                                 generation);
  if (status == FTUN_OK) {
    status = ftun_path_provider_reload_commit(engine->path_provider,
                                               generation);
  }
  if (status != FTUN_OK) return status;
  if (engine->pending_health_reuse) {
    size_t index;
    for (index = 0u; index < engine->health_slot_count; index++) {
      engine->health_slots[index].generation = generation;
    }
  } else {
    status = ftun_proxy_runtime_health_release(&engine->health_groups,
      &engine->health_slots, engine->health_slot_count,
      &engine->health_reservation);
    if (status != FTUN_OK) return status;
    engine->health_deadline_valid = false;
    engine->health_groups = engine->pending_health_groups;
    engine->health_group_count = engine->pending_health_group_count;
    engine->health_slots = engine->pending_health_slots;
    engine->health_slot_count = engine->pending_health_slot_count;
    engine->health_cursor = 0u;
    engine->health_reservation = engine->pending_health_reservation;
    engine->pending_health_groups = NULL;
    engine->pending_health_group_count = 0u;
    engine->pending_health_slots = NULL;
    engine->pending_health_slot_count = 0u;
    engine->pending_health_reservation = (ftun_reservation_t){0};
  }
  {
    size_t index;
    for (index = 0u; index < engine->listener_count; index++) {
      engine->listeners[index].inbound_id =
        engine->pending_listener_ids[index];
      engine->pending_listener_ids[index] = 0u;
    }
  }
#if defined(FTUN_HAVE_MODULE_TUN)
  if (engine->has_tun) {
    if (engine->tun_ingress != NULL && !engine->tun_resetting) {
      status = ftun_tun_ingress_set_identity(engine->tun_ingress, generation,
        engine->pending_tun_inbound_id);
      if (status != FTUN_OK) return status;
    }
    engine->tun_listener.inbound_id = engine->pending_tun_inbound_id;
    engine->pending_tun_inbound_id = 0u;
  }
#endif
  engine->liveness = engine->pending_timeouts.liveness;
  engine->handshake_ms = engine->pending_timeouts.handshake_ms;
  engine->connect_ms = engine->pending_timeouts.connect_ms;
  engine->reply_ms = engine->pending_timeouts.reply_ms;
  engine->tcp_idle_ms = engine->pending_timeouts.tcp_idle_ms;
  engine->write_progress_ms = engine->pending_timeouts.write_progress_ms;
  engine->generation = generation;
  engine->reload_prepared = false;
  engine->reload_pending = false;
  engine->reload_owner = FTUN_PROXY_RELOAD_OWNER_NONE;
  engine->pending_health_reuse = false;
#if defined(FTUN_HAVE_MODULE_FRS)
  engine->frs_enabled = engine->pending_frs_enabled;
  engine->frs_interval_ms = engine->pending_frs_interval_ms;
  engine->pending_frs_enabled = false;
  engine->pending_frs_interval_ms = 0u;
  free(engine->frs_etag);
  engine->frs_etag = NULL;
  ftun_reservation_release(&engine->frs_etag_reservation);
  if (engine->frs_enabled &&
      ftun_monotonic_now(&engine->now_ms) == FTUN_OK &&
      engine->frs_interval_ms <= UINT64_MAX - engine->now_ms) {
    engine->frs_due_ms = engine->now_ms + engine->frs_interval_ms;
  } else {
    engine->frs_due_ms = UINT64_MAX;
  }
#endif
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_reload_commit(ftun_proxy_runtime_t *engine,
                                        uint64_t generation)
{
  return ftun_proxy_runtime_reload_commit_owned(engine, generation,
    FTUN_PROXY_RELOAD_OWNER_HOST);
}

ftun_status_t ftun_proxy_runtime_reload_abort_owned(
  ftun_proxy_runtime_t *engine, ftun_proxy_reload_owner_t owner)
{
  ftun_status_t status;
  if (engine == NULL) return FTUN_E_INVALID;
  /* 准备状态属于另一方时不撤销；无持有者时仍可清理半成品。 */
  if (engine->reload_owner != FTUN_PROXY_RELOAD_OWNER_NONE &&
      engine->reload_owner != owner) return FTUN_OK;
  status = ftun_path_provider_reload_abort(engine->path_provider);
  if (status == FTUN_OK) {
    status = ftun_resolver_provider_reload_abort(engine->resolver_provider);
  }
  if (status == FTUN_OK && !engine->pending_health_reuse) {
    status = ftun_proxy_runtime_health_release(&engine->pending_health_groups,
      &engine->pending_health_slots, engine->pending_health_slot_count,
      &engine->pending_health_reservation);
    if (status == FTUN_OK) {
      engine->pending_health_group_count = 0u;
      engine->pending_health_slot_count = 0u;
    }
  }
  if (status == FTUN_OK) {
    engine->reload_prepared = false;
    engine->reload_pending = false;
    engine->reload_owner = FTUN_PROXY_RELOAD_OWNER_NONE;
    engine->pending_health_reuse = false;
    memset(engine->pending_listener_ids, 0,
           sizeof(engine->pending_listener_ids));
#if defined(FTUN_HAVE_MODULE_TUN)
    engine->pending_tun_inbound_id = 0u;
#endif
#if defined(FTUN_HAVE_MODULE_FRS)
    engine->pending_frs_enabled = false;
    engine->pending_frs_interval_ms = 0u;
#endif
  }
  return status;
}

ftun_status_t ftun_proxy_runtime_reload_abort(ftun_proxy_runtime_t *engine)
{
  return ftun_proxy_runtime_reload_abort_owned(engine,
    FTUN_PROXY_RELOAD_OWNER_HOST);
}

ftun_status_t ftun_proxy_runtime_get_capacity_info(
  ftun_proxy_runtime_t *engine, ftun_proxy_runtime_capacity_info_t *out)
{
  ftun_proxy_slot_pool_info_t flows;
  ftun_proxy_slot_pool_info_t udp;
  ftun_proxy_slot_pool_info_t pending;
  ftun_udp_flow_usage_t udp_flows;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (engine == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_proxy_slot_pool_get_info(engine->flow_pool, &flows);
  if (status == FTUN_OK) {
    status = ftun_proxy_slot_pool_get_info(engine->udp_pool, &udp);
  }
  if (status == FTUN_OK) {
    status = ftun_proxy_slot_pool_get_info(engine->udp_pending_pool, &pending);
  }
  memset(&udp_flows, 0, sizeof(udp_flows));
  if (status == FTUN_OK && engine->udp_flows != NULL) {
    status = ftun_udp_flow_get_usage(engine->udp_flows, &udp_flows);
  }
  if (status != FTUN_OK) return status;
  out->tcp_capacity = engine->tcp_capacity;
  out->tcp_active = engine->active_tcp_flows;
  out->udp_flow_capacity = engine->udp_capacity;
  out->udp_flow_active = udp_flows.active;
  out->udp_association_capacity = engine->association_capacity;
  out->udp_association_active = engine->active_associations;
  out->flow_resident_slabs = flows.resident_slabs;
  out->udp_resident_slabs = udp.resident_slabs;
  out->pending_resident_slabs = pending.resident_slabs;
  out->stale_slot_rejections = flows.stale_rejections +
    udp.stale_rejections + pending.stale_rejections;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_udp_drain(ftun_proxy_runtime_t *engine,
  size_t quota, size_t *out_work)
{
  size_t work = 0u;
  if (out_work != NULL) *out_work = 0u;
  if (engine == NULL || quota == 0u || out_work == NULL) return FTUN_E_INVALID;
  while (engine->ready_udp_head != NULL && work < quota) {
    ftun_proxy_runtime_udp_slot_t *slot = engine->ready_udp_head;
    ftun_status_t status;
    ftun_proxy_runtime_udp_unschedule(slot);
    work++;
    if (!slot->active) continue;
    if (slot->destroying) {
      status = ftun_proxy_runtime_udp_cleanup(slot);
      if (status != FTUN_OK) ftun_proxy_runtime_udp_schedule(slot);
      continue;
    }
    if (slot->failure != FTUN_OK) {
      if (slot->socks5) ftun_proxy_runtime_udp_backoff_failed(engine, slot->outbound_id);
      status = ftun_udp_flow_fail_outbound(engine->udp_flows, slot->channel, slot->failure);
      if (status != FTUN_OK && status != FTUN_E_STALE) ftun_proxy_runtime_udp_schedule(slot);
      continue;
    }
    if (slot->resume_pending) {
      status = slot->socks5 ? ftun_socks5_connection_resume(slot->proxy_connection) : ftun_path_resume(slot->path);
      if (status == FTUN_E_AGAIN) { ftun_proxy_runtime_udp_schedule(slot); continue; }
      slot->resume_pending = false;
      if (status != FTUN_OK && status != FTUN_E_UNSUPPORTED) {
        slot->failure = status;
        ftun_proxy_runtime_udp_schedule(slot);
        continue;
      }
    }
    if (slot->open_operation == NULL) ftun_proxy_runtime_udp_finish_pending(slot, slot->open_status);
  }
  if (ftun_proxy_slot_pool_trim(engine->udp_pool) != FTUN_OK ||
      ftun_proxy_slot_pool_trim(engine->udp_pending_pool) != FTUN_OK) return FTUN_E_STATE_CORRUPT;
  *out_work = work;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_run_once(ftun_proxy_runtime_t *engine, bool may_block,
                                   ftun_proxy_runtime_run_usage_t *out_usage)
{
  ftun_event_loop_usage_t event_usage;
  ftun_buffer_pool_usage_t pool_usage;
  size_t pool_before[4];
  uint64_t started_ms = 0u;
  uint64_t before_event_ms = 0u;
  uint64_t after_event_ms = 0u;
  uint64_t finished_ms = 0u;
  uint64_t deadline_lateness = 0u;
  size_t index;
  size_t callbacks = 0u;
  size_t flow_work = 0u;
  size_t pool_callbacks = 0u;
  size_t udp_work = 0u;
  size_t deadline_work = 0u;
  size_t total_work = 0u;
  bool immediate_work = false;
  bool quota_exhausted = false;
  bool deadline_quota_exhausted = false;
  bool blocked = false;
  ftun_status_t status;
  if (out_usage != NULL) memset(out_usage, 0, sizeof(*out_usage));
  if (engine == NULL || engine->stopped || engine->cleanup_only ||
      out_usage == NULL) {
    return FTUN_E_INVALID;
  }
  engine->health_scan_work = 0u;
  status = ftun_buffer_pool_get_usage(engine->relay_pool, &pool_usage);
  if (status != FTUN_OK) return status;
  pool_before[0] = pool_usage.selection_steps;
  pool_before[1] = pool_usage.availability_probes;
  pool_before[2] = pool_usage.idle_scan_steps;
  pool_before[3] = pool_usage.pressure_trimmed_buffers;
  status = ftun_monotonic_now(&started_ms);
  if (status != FTUN_OK) return status;
  engine->round_ms = started_ms;
  if (engine->udp_flows != NULL) {
    status = ftun_udp_flow_set_now(engine->udp_flows, started_ms);
    if (status != FTUN_OK) return status;
  }
#if defined(FTUN_HAVE_MODULE_TUN)
  {
    size_t tun_work = 0u;
    status = ftun_proxy_runtime_tun_reset(engine, started_ms, &tun_work);
    if (status != FTUN_OK) return status;
    total_work += tun_work;
    if (tun_work >= 32u) quota_exhausted = true;
  }
#endif
  status = ftun_proxy_runtime_deadline_schedule(engine);
  if (status != FTUN_OK) return status;
  status = ftun_proxy_runtime_deadline_run(engine, started_ms, &deadline_work,
    &deadline_lateness, &deadline_quota_exhausted);
  if (status != FTUN_OK) return status;
  total_work += deadline_work;
  quota_exhausted = quota_exhausted || deadline_quota_exhausted;
  if (engine->recovery != NULL) {
    size_t recovery_work = 0u;
    status = ftun_recovery_run(engine->recovery, started_ms, 4u, &recovery_work);
    if (status != FTUN_OK) return status;
    total_work += recovery_work;
  }
  status = ftun_buffer_pool_dispatch(engine->relay_pool,
    FTUN_PROXY_RUNTIME_RELAY_WAKE_QUOTA, &pool_callbacks);
  if (status != FTUN_OK) return status;
  total_work += pool_callbacks;
  if (pool_callbacks == FTUN_PROXY_RUNTIME_RELAY_WAKE_QUOTA) quota_exhausted = true;
  if (engine->worker != NULL) {
    status = ftun_worker_poll(engine->worker, FTUN_PROXY_RUNTIME_WORKER_QUOTA,
                              &callbacks);
    if (status != FTUN_OK) return status;
    total_work += callbacks;
    if (callbacks == FTUN_PROXY_RUNTIME_WORKER_QUOTA) quota_exhausted = true;
  }
  if (engine->maintenance_worker != NULL) {
    status = ftun_worker_poll(engine->maintenance_worker,
      FTUN_PROXY_RUNTIME_MAINTENANCE_QUOTA, &callbacks);
    if (status != FTUN_OK) return status;
    total_work += callbacks;
    if (callbacks == FTUN_PROXY_RUNTIME_MAINTENANCE_QUOTA) quota_exhausted = true;
  }
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  if (engine->fakeip_worker != NULL) {
    status = ftun_worker_poll(engine->fakeip_worker,
      FTUN_PROXY_RUNTIME_FAKEIP_QUOTA, &callbacks);
    if (status != FTUN_OK) return status;
    total_work += callbacks;
    if (callbacks == FTUN_PROXY_RUNTIME_FAKEIP_QUOTA) quota_exhausted = true;
  }
  status = ftun_proxy_runtime_fakeip_reserve_runtime(engine);
  if (status != FTUN_OK) return status;
#endif
  status = ftun_proxy_runtime_flow_drain(engine, FTUN_PROXY_RUNTIME_FLOW_QUOTA, &flow_work);
  if (status != FTUN_OK) return status;
  total_work += flow_work;
  {
    size_t quarantine_work = 0u;
    status = ftun_proxy_runtime_quarantine_run(engine, started_ms, &quarantine_work);
    if (status != FTUN_OK) return status;
    total_work += quarantine_work;
    total_work += ftun_proxy_runtime_idle_scan(engine, started_ms);
  }
  if (flow_work == FTUN_PROXY_RUNTIME_FLOW_QUOTA) quota_exhausted = true;
  status = ftun_proxy_runtime_udp_drain(engine, FTUN_PROXY_RUNTIME_UDP_QUOTA, &udp_work);
  if (status != FTUN_OK) return status;
  total_work += udp_work;
  if (udp_work == FTUN_PROXY_RUNTIME_UDP_QUOTA) quota_exhausted = true;
  status = ftun_proxy_runtime_deadline_schedule(engine);
  if (status != FTUN_OK) return status;
  immediate_work = total_work != 0u || engine->ready_flow_head != NULL ||
    engine->ready_udp_head != NULL || engine->deadline_ready;
  for (index = 0u; !immediate_work && index < engine->listener_count; index++) {
    if (engine->listeners[index].events != 0u ||
        engine->listeners[index].udp_events != 0u) immediate_work = true;
  }
  if (engine->worker != NULL) {
    if (ftun_worker_has_ready(engine->worker)) immediate_work = true;
  }
  if (engine->maintenance_worker != NULL) {
    if (ftun_worker_has_ready(engine->maintenance_worker)) {
      immediate_work = true;
    }
  }
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  if (engine->fakeip_worker != NULL) {
    if (ftun_worker_has_ready(engine->fakeip_worker)) immediate_work = true;
  }
#endif
  blocked = may_block && !immediate_work;
  (void)ftun_monotonic_now(&before_event_ms);
  status = ftun_event_loop_run_once(engine->loop, blocked,
                                    FTUN_PROXY_RUNTIME_EVENT_QUOTA, &callbacks);
  if (status != FTUN_OK) return status;
  status = ftun_monotonic_now(&after_event_ms);
  if (status != FTUN_OK) return status;
  /* The event wait may have blocked close to an idle deadline.  Advance the
   * session clock before delivering the readiness collected by that wait, so
   * activity refreshes from receipt time rather than the pre-wait sample. */
  if (engine->udp_flows != NULL) {
    status = ftun_udp_flow_set_now(engine->udp_flows, after_event_ms);
    if (status != FTUN_OK) return status;
  }
  total_work += callbacks;
  if (callbacks == FTUN_PROXY_RUNTIME_EVENT_QUOTA) quota_exhausted = true;
  {
    size_t inspected = 0u;
    size_t io_sources = 0u;
    while (inspected < engine->listener_count &&
           io_sources < FTUN_PROXY_RUNTIME_IO_SOURCE_QUOTA) {
      ftun_proxy_runtime_listener_t *listener =
        &engine->listeners[engine->listener_cursor];
      uint32_t events = listener->events;
      uint32_t udp_events = listener->udp_events;
      engine->listener_cursor = (engine->listener_cursor + 1u) %
        engine->listener_count;
      inspected++;
      if ((events & FTUN_EVENT_ERROR) != 0u ||
          (udp_events & FTUN_EVENT_ERROR) != 0u) {
        status = ftun_proxy_runtime_listener_fail(engine, listener,
                                                  FTUN_RECOVERY_FAULT_NETWORK);
        if (status != FTUN_OK) return status;
        total_work++;
        continue;
      }
      if (engine->accepting && (events & FTUN_EVENT_READ) != 0u) {
        listener->events = 0u;
        status = ftun_proxy_runtime_accept(engine, listener);
        if (status == FTUN_E_STATE_CORRUPT) return status;
        if (status != FTUN_OK) {
          /* accept 的致命 errno 只影响这个监听：关闭并等待恢复。 */
          status = ftun_proxy_runtime_listener_fail(engine, listener,
                                                    FTUN_RECOVERY_FAULT_NETWORK);
          if (status != FTUN_OK) return status;
        }
        total_work++;
        io_sources++;
      }
      if (io_sources < FTUN_PROXY_RUNTIME_IO_SOURCE_QUOTA && engine->accepting &&
          (udp_events & FTUN_EVENT_READ) != 0u) {
        listener->udp_events = 0u;
        status = ftun_proxy_runtime_listener_udp(engine, listener);
        if (status != FTUN_OK) return status;
        total_work++;
        io_sources++;
      }
    }
    if (io_sources == FTUN_PROXY_RUNTIME_IO_SOURCE_QUOTA) quota_exhausted = true;
  }
  /* I/O callbacks may change a deadline.  The next owner round recomputes it
   * before running or blocking; keeping deadline_ready here also avoids
   * cancelling and re-arming an already fired timer at the end of this round. */
  status = ftun_event_loop_get_usage(engine->loop, &event_usage);
  if (status != FTUN_OK) return status;
  total_work += event_usage.last_work >= callbacks ? event_usage.last_work - callbacks : 0u;
  if (event_usage.backend_quota_exhausted) quota_exhausted = true;
  if (event_usage.ready_count != 0u || event_usage.deferred_count != 0u ||
      engine->ready_flow_head != NULL || engine->ready_udp_head != NULL ||
      engine->deadline_ready) quota_exhausted = true;
  for (index = 0u; !quota_exhausted && index < engine->listener_count;
       index++) {
    if (engine->listeners[index].events != 0u ||
        engine->listeners[index].udp_events != 0u) quota_exhausted = true;
  }
  status = ftun_buffer_pool_get_usage(engine->relay_pool, &pool_usage);
  if (status != FTUN_OK) return status;
  {
    const size_t after[4] = {pool_usage.selection_steps, pool_usage.availability_probes,
      pool_usage.idle_scan_steps, pool_usage.pressure_trimmed_buffers};
    /* 同一 owner 回合内的实际选择、预算探测、idle 访问和回收也计工作，
     * 不只统计成功通知的 waiter；各累计计数饱和时保持保守饱和。 */
    for (index = 0u; index < 4u; index++) {
      size_t delta = after[index] == SIZE_MAX || after[index] < pool_before[index]
        ? SIZE_MAX : after[index] - pool_before[index];
      total_work = delta > SIZE_MAX - total_work ? SIZE_MAX : total_work + delta;
    }
  }
  /* 扫描成本计入本轮统计，但不当作下一轮立即可运行的工作。 */
  total_work = engine->health_scan_work > SIZE_MAX - total_work
    ? SIZE_MAX : total_work + engine->health_scan_work;
  (void)ftun_monotonic_now(&finished_ms);
  out_usage->work = total_work;
  out_usage->object_faults = engine->object_faults;
  engine->object_faults = 0u;
  out_usage->deadline_lateness_ms = deadline_lateness;
  if (event_usage.max_timer_lateness_ms > out_usage->deadline_lateness_ms) {
    out_usage->deadline_lateness_ms = event_usage.max_timer_lateness_ms;
  }
  out_usage->quota_exhausted = quota_exhausted;
  if (before_event_ms >= started_ms) {
    out_usage->busy_ms = before_event_ms - started_ms;
  }
  if (finished_ms >= after_event_ms) {
    out_usage->busy_ms += finished_ms - after_event_ms;
  }
  if (blocked) out_usage->busy_ms += event_usage.last_dispatch_ms;
  else if (after_event_ms >= before_event_ms) {
    out_usage->busy_ms += after_event_ms - before_event_ms;
  }
  return FTUN_OK;
}

void ftun_proxy_runtime_network_changed(ftun_proxy_runtime_t *engine, uint64_t now_ms)
{
  if (engine == NULL || engine->stopped) return;
  if (engine->recovery != NULL) {
    ftun_recovery_trigger_kind(engine->recovery,
      UINT32_C(1) | FTUN_PROXY_RUNTIME_UDP_RECOVERY_KIND, now_ms);
  }
  /* url-test：网络回来了就不再等探测间隔，下一轮立即探测一次（合并，不并发）。 */
  {
    size_t index;
    for (index = 0u; index < engine->health_slot_count; index++) {
      ftun_proxy_runtime_health_slot_t *slot = &engine->health_slots[index];
      if (slot->operation == NULL && slot->schedule.next_due_ms > now_ms) {
        slot->schedule.next_due_ms = now_ms;
      }
    }
    engine->health_deadline_valid = false;
  }
#if defined(FTUN_HAVE_MODULE_FRS)
  /* 规则文件还没下载到：网络回来了就不再等退避，立即重试。 */
  if (engine->frs_enabled && engine->frs_not_ready && engine->frs_operation == NULL) {
    engine->frs_retry_ms = 0u;
    engine->frs_due_ms = now_ms;
  }
#endif
}

ftun_status_t ftun_proxy_runtime_wakeup(ftun_proxy_runtime_t *engine)
{
  if (engine == NULL || engine->loop == NULL || engine->stopped) {
    return FTUN_E_INVALID;
  }
  return ftun_event_loop_wakeup(engine->loop);
}

ftun_status_t ftun_proxy_runtime_quiesce(ftun_proxy_runtime_t *engine)
{
  size_t index;
  ftun_status_t result = FTUN_OK;
  if (engine == NULL) return FTUN_E_INVALID;
  if (engine->stopped) return FTUN_OK;
  engine->accepting = false;
  if (engine->resolver_provider != NULL) {
    ftun_status_t status = ftun_resolver_provider_quiesce(
      engine->resolver_provider);
    if (status != FTUN_OK && result == FTUN_OK) result = status;
  }
  if (engine->path_provider != NULL) {
    ftun_status_t status = ftun_path_provider_quiesce(engine->path_provider);
    if (status != FTUN_OK && result == FTUN_OK) result = status;
  }
  ftun_recovery_scheduler_stop(engine->recovery);
  for (index = 0u; index < engine->listener_count; index++) {
    ftun_status_t status = ftun_event_source_cancel(
      &engine->listeners[index].source);
    if (status != FTUN_OK && result == FTUN_OK) result = status;
    status = ftun_event_source_cancel(&engine->listeners[index].udp_source);
    if (status != FTUN_OK && result == FTUN_OK) result = status;
    engine->listeners[index].events = 0u;
    engine->listeners[index].udp_events = 0u;
    if (engine->listeners[index].source == NULL &&
        engine->listeners[index].descriptor >= 0) {
      (void)ftun_socket_close((ftun_native_socket_t)engine->listeners[index].descriptor);
      engine->listeners[index].descriptor = -1;
    }
    if (engine->listeners[index].udp_source == NULL &&
        engine->listeners[index].udp_descriptor >= 0) {
      (void)ftun_socket_close((ftun_native_socket_t)engine->listeners[index].udp_descriptor);
      engine->listeners[index].udp_descriptor = -1;
    }
  }
  return result;
}

ftun_status_t ftun_proxy_runtime_stop_until(ftun_proxy_runtime_t *engine,
                                     uint64_t deadline_ms)
{
  size_t index;
  ftun_status_t result = FTUN_OK;
  if (engine == NULL) return FTUN_E_INVALID;
  if (engine->stopped) {
    if (engine->resolver_provider != NULL) {
      result = ftun_resolver_provider_stop_until(engine->resolver_provider,
                                                  deadline_ms);
    }
    if (engine->path_provider != NULL) {
      ftun_status_t status = ftun_path_provider_stop_until(
        engine->path_provider, deadline_ms);
      if (status != FTUN_OK && result == FTUN_OK) result = status;
    }
    return result;
  }
  result = ftun_proxy_runtime_quiesce(engine);
  /* 先移除所有会借用 Flow/UDP/engine 的 watcher。取消失败时保留对象，
   * 下次 stop 重试，不让 flow_close 释放仍有后端引用的槽。 */
  for (index = 0u; index < engine->flow_capacity; index++) {
    ftun_proxy_runtime_flow_t *flow = ftun_proxy_runtime_flow_at(engine, index);
    ftun_status_t status;
    if (flow == NULL) continue;
    status = ftun_event_source_cancel(&flow->client_source);
    if (status != FTUN_OK && result == FTUN_OK) result = status;
    status = ftun_event_source_cancel(&flow->remote_source);
    if (status != FTUN_OK && result == FTUN_OK) result = status;
    status = ftun_event_source_cancel(&flow->deadline_source);
    if (status != FTUN_OK && result == FTUN_OK) result = status;
  }
  {
    ftun_status_t status = ftun_event_source_cancel(&engine->deadline_source);
    if (status != FTUN_OK && result == FTUN_OK) result = status;
  }
  if (result != FTUN_OK) return result;
  ftun_proxy_runtime_udp_pending_cancel_all(engine);
  for (index = 0u; index < engine->health_slot_count; index++) {
    if (engine->health_slots[index].operation != NULL) {
      (void)ftun_operation_cancel(engine->health_slots[index].operation);
    }
  }
#if defined(FTUN_HAVE_MODULE_FRS)
  engine->frs_enabled = false;
  if (engine->frs_operation != NULL) {
    (void)ftun_operation_cancel(engine->frs_operation);
  }
#endif
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  if (engine->fakeip_store != NULL && engine->fakeip != NULL) {
    ftun_fakeip_snapshot_t *snapshot = NULL;
    ftun_operation_t *operation = NULL;
    size_t expected;
    ftun_status_t status = FTUN_OK;
    if (engine->fakeip_reserve_operation != NULL) {
      expected = engine->fakeip_store_completions + 1u;
      status = ftun_proxy_runtime_wait_worker_until(engine, engine->fakeip_worker,
                                              expected, deadline_ms);
      if (status == FTUN_E_TIMEOUT &&
          engine->fakeip_reserve_operation != NULL) {
        (void)ftun_operation_cancel(engine->fakeip_reserve_operation);
      }
    }
    expected = engine->fakeip_store_completions + 1u;
    if (status == FTUN_OK) {
      status = ftun_fakeip_service_snapshot(engine->fakeip, &snapshot);
    }
    if (status == FTUN_OK) {
      engine->fakeip_store_status = FTUN_E_AGAIN;
      status = ftun_fakeip_snapshot_save(engine->fakeip_store, snapshot,
                                         &operation);
    }
    (void)ftun_fakeip_snapshot_destroy(&snapshot);
    if (status == FTUN_OK) status = ftun_proxy_runtime_wait_worker_until(
      engine, engine->fakeip_worker, expected, deadline_ms);
    if (status == FTUN_E_TIMEOUT &&
        engine->fakeip_store_completions < expected && operation != NULL) {
      (void)ftun_operation_cancel(operation);
    }
    if (status != FTUN_OK) result = status;
  }
#endif
  for (index = 0u; index < engine->flow_capacity; index++) {
    ftun_proxy_runtime_flow_t *flow = ftun_proxy_runtime_flow_at(engine, index);
    if (flow == NULL) continue;
    (void)ftun_event_source_cancel(&flow->client_source);
    (void)ftun_event_source_cancel(&flow->remote_source);
    (void)ftun_event_source_cancel(&flow->deadline_source);
    ftun_proxy_runtime_flow_close(flow, FTUN_E_CANCELLED);
    flow->ready_queued = false;
    flow->ready_next = NULL;
  }
  engine->ready_flow_head = NULL;
  engine->ready_flow_tail = NULL;
#if defined(FTUN_HAVE_MODULE_TUN)
  if (engine->tun_ingress != NULL) {
    ftun_status_t status = ftun_tun_ingress_close(&engine->tun_ingress);
    /* 活跃 lwIP 流的最终引用会在随后的 worker/Flow drain 中释放。
     * close 的 AGAIN 是可重试销毁状态，不能把正常 SIGTERM 变成运行失败。 */
    if (status != FTUN_OK && status != FTUN_E_AGAIN && result == FTUN_OK) {
      result = status;
    }
  }
  if (engine->tun_lease.service != NULL) {
    ftun_status_t status = ftun_tun_service_release(&engine->tun_lease);
    if (status != FTUN_OK && result == FTUN_OK) result = status;
  }
#endif
  (void)ftun_event_source_cancel(&engine->deadline_source);
  engine->deadline_ready = false;
  engine->deadline_ms = 0u;
  if (engine->resolver_provider != NULL) {
    ftun_status_t status = ftun_resolver_provider_stop_until(
      engine->resolver_provider, deadline_ms);
    if (status != FTUN_OK && result == FTUN_OK) result = status;
  }
  if (engine->path_provider != NULL) {
    ftun_status_t status = ftun_path_provider_stop_until(
      engine->path_provider, deadline_ms);
    if (status != FTUN_OK && result == FTUN_OK) result = status;
  }
  /* 本地源已全部取消；重复调用仍重试 Provider，但不重复提交落盘任务。 */
  engine->stopped = true;
  return result;
}

ftun_status_t ftun_proxy_runtime_drain_until(ftun_proxy_runtime_t *engine,
                                             uint64_t deadline_ms)
{
  return ftun_proxy_runtime_stop_until(engine, deadline_ms);
}

ftun_status_t ftun_proxy_runtime_worker_stop_until(ftun_worker_t *worker,
                                                    uint64_t deadline_ms)
{
  size_t callbacks = 0u;
  ftun_status_t status;
  if (worker == NULL) return FTUN_OK;
  status = ftun_worker_stop(worker);
  if (status != FTUN_OK) return status;
  status = ftun_worker_poll(worker, SIZE_MAX, &callbacks);
  if (status != FTUN_OK) return status;
  status = ftun_worker_join_until(worker, deadline_ms);
  if (status != FTUN_OK) return status;
  callbacks = 0u;
  return ftun_worker_poll(worker, SIZE_MAX, &callbacks);
}

ftun_status_t ftun_proxy_runtime_destroy_until(ftun_proxy_runtime_t **engine,
                                        uint64_t deadline_ms)
{
  ftun_proxy_runtime_t *owned;
  size_t index;
  ftun_status_t stop_status;
  ftun_status_t result = FTUN_OK;
  if (engine == NULL) return FTUN_E_INVALID;
  owned = *engine;
  if (owned == NULL) return FTUN_OK;
  stop_status = ftun_proxy_runtime_stop_until(owned, deadline_ms);
  if (stop_status != FTUN_OK) return stop_status;
  /* Drain every worker callback while the DNS/flow/health owners they refer
   * to are still alive.  Destroying those owners first can turn a clean stop
   * with an in-flight probe or resolver into a retry-only partial teardown. */
  if (owned->worker != NULL) {
    ftun_status_t status = ftun_proxy_runtime_worker_stop_until(owned->worker,
                                                         deadline_ms);
    if (status != FTUN_OK) return status;
  }
  if (owned->maintenance_worker != NULL) {
    ftun_status_t status = ftun_proxy_runtime_worker_stop_until(
      owned->maintenance_worker, deadline_ms);
    if (status != FTUN_OK) return status;
  }
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  if (owned->fakeip_worker != NULL) {
    ftun_status_t status = ftun_proxy_runtime_worker_stop_until(
      owned->fakeip_worker, deadline_ms);
    if (status != FTUN_OK) return status;
  }
#endif
  if (owned->reload_pending && ftun_proxy_runtime_reload_abort_owned(owned,
        owned->reload_owner) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
#if defined(FTUN_HAVE_MODULE_FRS)
  ftun_proxy_runtime_frs_release_generation(owned);
  if (owned->frs_candidate != NULL &&
      ftun_runtime_abort(owned->core, &owned->frs_candidate) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
#endif
  for (index = 0u; index < owned->flow_capacity; index++) {
    ftun_proxy_runtime_flow_t *flow = ftun_proxy_runtime_flow_at(owned, index);
    if (flow == NULL) continue;
    if (flow->open_operation != NULL) {
      (void)ftun_operation_cancel(flow->open_operation);
      result = FTUN_E_AGAIN;
      continue;
    }
    if (ftun_proxy_runtime_flow_finalize(flow) != FTUN_OK) result = FTUN_E_AGAIN;
  }
  if (result != FTUN_OK) return result;
  if (owned->flow_pool != NULL) {
    if (ftun_proxy_slot_pool_trim(owned->flow_pool) != FTUN_OK ||
        ftun_proxy_slot_pool_destroy(&owned->flow_pool) != FTUN_OK) {
      return FTUN_E_AGAIN;
    }
  }
  if (owned->udp_flows != NULL &&
      ftun_udp_flow_table_destroy(&owned->udp_flows) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
  for (index = 0u; index < owned->udp_capacity; index++) {
    ftun_proxy_runtime_udp_slot_t *slot = ftun_proxy_runtime_udp_at(owned, index);
    if (slot != NULL && ftun_proxy_runtime_udp_cleanup(slot) != FTUN_OK) result = FTUN_E_AGAIN;
  }
  if (result != FTUN_OK) return result;
  if (owned->udp_pool != NULL &&
      (ftun_proxy_slot_pool_trim(owned->udp_pool) != FTUN_OK ||
       ftun_proxy_slot_pool_destroy(&owned->udp_pool) != FTUN_OK)) {
    return FTUN_E_AGAIN;
  }
  if (owned->udp_pending_pool != NULL &&
      (ftun_proxy_slot_pool_trim(owned->udp_pending_pool) != FTUN_OK ||
       ftun_proxy_slot_pool_destroy(&owned->udp_pending_pool) != FTUN_OK)) {
    return FTUN_E_AGAIN;
  }
#if defined(FTUN_HAVE_MODULE_TUN)
  if (owned->tun_ingress != NULL &&
      ftun_tun_ingress_close(&owned->tun_ingress) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
  if (owned->tun_lease.service != NULL &&
      ftun_tun_service_release(&owned->tun_lease) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
  free(owned->tun_listener.name);
  owned->tun_listener.name = NULL;
#endif
  if (owned->resolver_provider != NULL &&
      ftun_resolver_provider_destroy(&owned->resolver_provider) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
  if (owned->path_provider != NULL &&
      ftun_path_provider_destroy(&owned->path_provider) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
  if (owned->fakeip_slot != NULL) {
#if defined(FTUN_HAVE_MODULE_FAKEIP)
    if (*owned->fakeip_slot == owned->fakeip) *owned->fakeip_slot = NULL;
#else
    *owned->fakeip_slot = NULL;
#endif
  }
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  if (owned->fakeip != NULL &&
      ftun_fakeip_service_destroy(&owned->fakeip) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
  if (owned->fakeip_store != NULL &&
      ftun_fakeip_store_destroy(&owned->fakeip_store) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
  free(owned->fakeip_directory);
  owned->fakeip_directory = NULL;
  ftun_reservation_release(&owned->fakeip_directory_reservation);
#endif
  for (index = 0u; index < owned->listener_count; index++) {
    free(owned->listeners[index].name);
    owned->listeners[index].name = NULL;
  }
  if (ftun_recovery_scheduler_destroy(&owned->recovery) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
  if (owned->relay_pool != NULL) {
    if (ftun_buffer_pool_set_wakeup(owned->relay_pool, NULL, NULL) != FTUN_OK) {
      return FTUN_E_AGAIN;
    }
  }
  if (owned->worker != NULL) {
    if (ftun_worker_destroy(&owned->worker) != FTUN_OK) return FTUN_E_AGAIN;
  }
  if (owned->maintenance_worker != NULL) {
    if (ftun_worker_destroy(&owned->maintenance_worker) != FTUN_OK) {
      return FTUN_E_AGAIN;
    }
  }
  if (ftun_tls_context_destroy(&owned->http_tls_context) != FTUN_OK) return FTUN_E_AGAIN;
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  if (owned->fakeip_worker != NULL &&
      ftun_worker_destroy(&owned->fakeip_worker) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
#endif
  if (owned->relay_pool != NULL &&
      ftun_buffer_pool_destroy(&owned->relay_pool) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
  if (ftun_proxy_runtime_health_release(&owned->health_groups,
      &owned->health_slots, owned->health_slot_count,
      &owned->health_reservation) != FTUN_OK) return FTUN_E_AGAIN;
  if (ftun_proxy_runtime_health_release(&owned->pending_health_groups,
      &owned->pending_health_slots, owned->pending_health_slot_count,
      &owned->pending_health_reservation) != FTUN_OK) return FTUN_E_AGAIN;
#if defined(FTUN_HAVE_MODULE_FRS)
  free(owned->frs_etag);
  owned->frs_etag = NULL;
  ftun_reservation_release(&owned->frs_etag_reservation);
  free(owned->frs_candidate_etag);
  owned->frs_candidate_etag = NULL;
  ftun_reservation_release(&owned->frs_candidate_etag_reservation);
  free(owned->frs_group_records);
  owned->frs_group_records = NULL;
  ftun_reservation_release(&owned->frs_group_records_reservation);
#endif
  free(owned->association_channels);
  owned->association_channels = NULL;
  free(owned->association_clients);
  owned->association_clients = NULL;
  free(owned->udp_backoff);
  owned->udp_backoff = NULL;
  ftun_reservation_release(&owned->reservation);
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *engine = NULL;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_destroy(ftun_proxy_runtime_t **engine)
{
  return ftun_proxy_runtime_destroy_until(engine, UINT64_MAX);
}

size_t ftun_proxy_runtime_quarantined(const ftun_proxy_runtime_t *engine)
{
  return engine == NULL ? 0u : engine->quarantined_flows;
}

size_t ftun_proxy_runtime_listeners_waiting(const ftun_proxy_runtime_t *engine)
{
  size_t index;
  size_t waiting = 0u;
  if (engine == NULL) return 0u;
  for (index = 0u; index < engine->listener_count; index++) {
    if (engine->listeners[index].waiting) waiting++;
  }
  return waiting;
}
