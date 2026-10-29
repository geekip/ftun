#define _GNU_SOURCE 1

#include "proxy/engine_internal.h"

ftun_status_t ftun_proxy_runtime_listener_endpoint(
  ftun_proxy_runtime_listener_t *listener, const ftun_config_inbound_t *config,
  uint32_t inbound_id)
{
  ftun_endpoint_t endpoint;
  ftun_status_t status = ftun_proxy_runtime_parse_ipv4_endpoint(config->listen,
                                                          &endpoint);
  if (status != FTUN_OK) return status;
  listener->name = strdup(config->name);
  if (listener->name == NULL) return FTUN_E_LIMIT;
  listener->address = endpoint;
  listener->udp = config->udp;
  listener->tcp_idle_ms = config->tcp_idle_ms;
  listener->kind = config->kind;
  listener->inbound_id = inbound_id;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_listener_bind(
  ftun_proxy_runtime_listener_t *listener)
{
  ftun_handle_t descriptor;
  ftun_handle_t udp_descriptor = -1;
  ftun_status_t status = ftun_socket_listen(&listener->address, FTUN_DIAL_TCP,
    128, &descriptor, &listener->bind_issue);
  if (status != FTUN_OK) return status;
  if (listener->udp) {
    status = ftun_socket_listen(&listener->address, FTUN_DIAL_UDP,
      0, &udp_descriptor, &listener->bind_issue);
    if (status != FTUN_OK) {
      (void)ftun_socket_close((ftun_native_socket_t)descriptor);
      return status;
    }
  }
  listener->descriptor = descriptor;
  listener->udp_descriptor = udp_descriptor;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_listener_start(
  ftun_proxy_runtime_t *engine, ftun_proxy_runtime_listener_t *listener)
{
  ftun_status_t status = ftun_event_io_start(engine->loop,
    (ftun_native_socket_t)listener->descriptor,
    FTUN_EVENT_READ | FTUN_EVENT_ERROR, ftun_proxy_runtime_listener_ready,
    listener, &listener->source);
  if (status == FTUN_OK && listener->udp_descriptor >= 0) {
    status = ftun_event_io_start(engine->loop,
      (ftun_native_socket_t)listener->udp_descriptor,
      FTUN_EVENT_READ | FTUN_EVENT_ERROR,
      ftun_proxy_runtime_listener_udp_ready, listener, &listener->udp_source);
  }
  return status;
}

/* 取消事件源并关闭 socket；取消失败则保持原状，由调用方稍后重试。 */
ftun_status_t ftun_proxy_runtime_listener_close(
  ftun_proxy_runtime_listener_t *listener)
{
  ftun_status_t status = ftun_event_source_cancel(&listener->source);
  if (status == FTUN_OK) status = ftun_event_source_cancel(&listener->udp_source);
  if (status != FTUN_OK) return status;
  listener->events = 0u;
  listener->udp_events = 0u;
  if (listener->descriptor >= 0) (void)ftun_socket_close((ftun_native_socket_t)listener->descriptor);
  if (listener->udp_descriptor >= 0) (void)ftun_socket_close((ftun_native_socket_t)listener->udp_descriptor);
  listener->descriptor = -1;
  listener->udp_descriptor = -1;
  return FTUN_OK;
}

/* 监听出错：关闭 socket，转入等待恢复。只影响这个监听，不上报服务错误。 */
ftun_status_t ftun_proxy_runtime_listener_fail(
  ftun_proxy_runtime_t *engine, ftun_proxy_runtime_listener_t *listener,
  ftun_recovery_fault_t fault)
{
  uint64_t now_ms = 0u;
  ftun_status_t status = ftun_proxy_runtime_listener_close(listener);
  if (status != FTUN_OK) return status;
  (void)ftun_monotonic_now(&now_ms);
  listener->waiting = true;
  listener->paused = false;
  engine->object_faults++;
  return ftun_recovery_report_failure(engine->recovery, listener->recovery,
                                      now_ms, fault);
}

/* A0 的尝试：暂停中的监听恢复读取；已关闭的监听按原地址重新 bind。同步结束。 */
ftun_status_t ftun_proxy_runtime_listener_recover(
  void *user, ftun_recovery_id_t id)
{
  ftun_proxy_runtime_listener_t *listener = (ftun_proxy_runtime_listener_t *)user;
  ftun_proxy_runtime_t *engine = listener->engine;
  ftun_recovery_fault_t fault = FTUN_RECOVERY_FAULT_NETWORK;
  uint64_t now_ms = 0u;
  ftun_status_t status;
  (void)ftun_monotonic_now(&now_ms);
  if (listener->descriptor >= 0) {
    status = ftun_event_io_update(listener->source,
                                  FTUN_EVENT_READ | FTUN_EVENT_ERROR);
    if (status == FTUN_OK) listener->paused = false;
  } else {
    status = ftun_proxy_runtime_listener_bind(listener);
    if (status == FTUN_OK) {
      status = ftun_proxy_runtime_listener_start(engine, listener);
      if (status != FTUN_OK) (void)ftun_proxy_runtime_listener_close(listener);
    } else if (listener->bind_issue == FTUN_SOCKET_BIND_PERMISSION) {
      fault = FTUN_RECOVERY_FAULT_CONFIG;
    }
    if (status == FTUN_OK) listener->waiting = false;
  }
  (void)ftun_recovery_attempt_finish(engine->recovery, id, now_ms, status, fault);
  return FTUN_OK;
}

/* accept 资源不足：停止读取，交给恢复调度器按退避恢复，不另建计时器。 */
ftun_status_t ftun_proxy_runtime_accept_pause(
  ftun_proxy_runtime_t *engine, ftun_proxy_runtime_listener_t *listener)
{
  uint64_t now_ms = 0u;
  ftun_status_t status;
  if (engine == NULL || listener == NULL || listener->source == NULL) {
    return FTUN_E_INVALID;
  }
  if (listener->paused) return FTUN_OK;
  status = ftun_event_io_update(listener->source, FTUN_EVENT_ERROR);
  if (status != FTUN_OK) return status;
  listener->paused = true;
  (void)ftun_monotonic_now(&now_ms);
  return ftun_recovery_report_failure(engine->recovery, listener->recovery,
                                      now_ms, FTUN_RECOVERY_FAULT_RESOURCE);
}

ftun_status_t ftun_proxy_runtime_accept(ftun_proxy_runtime_t *engine,
                                         ftun_proxy_runtime_listener_t *listener)
{
  size_t accepted;
  for (accepted = 0u; accepted < FTUN_PROXY_RUNTIME_ACCEPT_QUOTA; accepted++) {
    ftun_endpoint_t peer;
    ftun_handle_t descriptor;
    ftun_socket_accept_disposition_t disposition;
    ftun_status_t status = ftun_socket_accept(listener->descriptor, &descriptor,
      &peer, &disposition);
    if (status != FTUN_OK) {
      switch (disposition) {
        case FTUN_SOCKET_ACCEPT_RETRY:
          continue;
        case FTUN_SOCKET_ACCEPT_DRAINED:
        case FTUN_SOCKET_ACCEPT_SKIP:
          return FTUN_OK;
        case FTUN_SOCKET_ACCEPT_BACKOFF:
          return ftun_proxy_runtime_accept_pause(engine, listener);
        case FTUN_SOCKET_ACCEPT_FATAL:
        default:
          return status;
      }
    }
    /* 接入的 TCP 连接设置存活探测与确认期限；设置失败只丢弃这一条连接。 */
    if (ftun_socket_apply_liveness(descriptor, &engine->liveness) != FTUN_OK) {
      (void)ftun_socket_close((ftun_native_socket_t)descriptor);
      continue;
    }
    {
      ftun_runtime_t *runtime = NULL;
      const ftun_config_t *config = NULL;
      bool permitted = false;
      status = ftun_runtime_active_acquire(engine->core, &runtime);
      if (status == FTUN_OK) status = ftun_runtime_config(runtime, &config);
      if (status == FTUN_OK && peer.kind == FTUN_ADDRESS_IPV4) {
        const uint8_t *address = peer.address;
        permitted = ftun_config_base(config)->allow_lan || address[0] == 127u;
      }
      (void)ftun_runtime_release(&runtime);
      if (status != FTUN_OK || !permitted) {
        (void)ftun_socket_close((ftun_native_socket_t)descriptor);
        if (status != FTUN_OK) return status;
        continue;
      }
    }
    status = ftun_proxy_runtime_flow_create(engine, listener, descriptor, &peer);
    if (status != FTUN_OK) {
      if (status == FTUN_E_LIMIT) return FTUN_OK;
      return status;
    }
  }
  return FTUN_OK;
}

