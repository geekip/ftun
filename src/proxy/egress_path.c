#include "proxy/egress_internal.h"
#include "libs/transport/socket_path.h"
#include "platform/clock.h"
#include "proxy/outbound_id.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  ftun_reservation_t reservation;
  const ftun_egress_provider_t *provider;
  ftun_proxy_egress_node_t *node;
  ftun_core_t *core;
  ftun_dial_request_t dial;
  ftun_stream_options_t stream;
  ftun_datagram_options_t datagram;
  ftun_endpoint_t endpoint;
  char interface_name[FTUN_SOCKET_INTERFACE_BYTES];
  ftun_event_source_t *pump, *deadline;
  ftun_proxy_resolution_waiter_t resolver;
  ftun_operation_t *operation, *child;
  ftun_operation_token_t token;
  ftun_error_t error;
  bool cancelling, delivered, cleaned;
  ftun_path_provider_t *physical;
  ftun_path_scope_t *scope;
  ftun_socks5_connection_t *connection;
  ftun_path_t *path;
  const ftun_path_spec_t *result;
  ftun_path_completion_fn completion;
  void *user;
  ftun_path_notify_fn notify;
  void *notify_user;
} session_t;

static ftun_status_t stop(void *context)
{
  session_t *session = context;
  return ftun_socks5_connection_quiesce(session->connection);
}

static ftun_status_t resume(void *context)
{
  session_t *session = context;
  ftun_path_t *path = NULL;
  ftun_status_t status = ftun_socks5_connection_path(session->connection, &path);
  return status == FTUN_OK ? ftun_path_resume(path) :
    ftun_socks5_connection_resume(session->connection);
}

static ftun_status_t cleanup(session_t *session)
{
  ftun_status_t status;
  if (session->cleaned) return FTUN_OK;
  status = session->connection == NULL ? FTUN_OK : stop(session);
  if (status == FTUN_OK) status = ftun_socks5_connection_close(&session->connection);
  if (status != FTUN_OK) return status;
  ftun_path_scope_release(&session->scope);
  status = ftun_path_provider_stop_until(session->physical, UINT64_MAX);
  if (status == FTUN_OK) status = ftun_path_provider_destroy(&session->physical);
  if (status == FTUN_OK) session->cleaned = true;
  return status;
}

static void free_session(session_t *session)
{
  ftun_reservation_t reservation = session->reservation;
  ftun_egress_release(&session->provider);
  free(session);
  ftun_reservation_release(&reservation);
}

static ftun_status_t destroy(void *context)
{
  session_t *session = context;
  ftun_status_t status = cleanup(session);
  if (status == FTUN_OK) {
    session->path = NULL;
    if (session->delivered) free_session(session);
  }
  return status;
}

static void completed(ftun_operation_t *operation, ftun_error_t error, void *context)
{
  session_t *session = context;
  ftun_path_completion_fn completion = session->completion;
  void *user = session->user;
  ftun_path_t *path = session->path;
  session->operation = NULL;
  session->delivered = true;
  if (error.status != FTUN_OK && path == NULL) { assert(session->cleaned); free_session(session); }
  completion(operation, error, path, user);
}

static void pump(ftun_event_source_t *source, uint32_t events, void *context)
{
  session_t *session = context;
  ftun_status_t status = FTUN_OK;
  (void)source; (void)events;
  if (session->child != NULL || session->resolver.job != NULL) return;
  if (session->cancelling) session->error.status = FTUN_E_CANCELLED;
  status = ftun_event_source_cancel(&session->deadline);
  if (status == FTUN_OK && session->error.status != FTUN_OK) {
    if (session->path != NULL) {
      status = ftun_path_revoke(session->path);
      if (status == FTUN_OK) status = ftun_path_destroy(&session->path);
    } else status = cleanup(session);
  }
  if (status == FTUN_OK) status = ftun_event_source_cancel(&session->pump);
  if (status == FTUN_OK) status = ftun_operation_complete(session->token, session->error);
  if (status != FTUN_OK && session->pump != NULL) {
    ftun_status_t scheduled = ftun_event_task_ready(session->pump);
    assert(scheduled == FTUN_OK);
    (void)scheduled;
  }
}

static ftun_status_t cancel(void *context)
{
  session_t *session = context;
  ftun_status_t status;
  /* 已建立的结果即使被取消也交给Provider回收，不在取消hook中释放payload。 */
  if (session->path != NULL) {
    status = ftun_path_revoke(session->path);
    if (status == FTUN_OK && session->pump != NULL) status = ftun_event_source_cancel(&session->pump);
    return status;
  }
  session->cancelling = true;
  status = ftun_proxy_resolution_cancel(&session->resolver, FTUN_E_CANCELLED);
  if (status != FTUN_OK) {
    ftun_status_t scheduled = ftun_event_task_ready(session->pump);
    assert(scheduled == FTUN_OK);
    (void)scheduled;
    return status;
  }
  if (session->child != NULL) {
    status = ftun_operation_cancel(session->child);
    if (status != FTUN_OK && status != FTUN_E_STALE) return status;
  }
  status = ftun_event_task_ready(session->pump);
  return status == FTUN_OK ? FTUN_E_AGAIN : status;
}

static void notified(ftun_path_t *path, uint32_t events, ftun_error_t error, void *context)
{
  session_t *session = context;
  ftun_path_t *held = session->path;
  (void)path;
  if (held == NULL || session->notify == NULL) return;
  if (ftun_path_retain(held) != FTUN_OK) return;
  session->notify(held, events, error, session->notify_user);
  ftun_path_release(&held);
}

static void connected(ftun_operation_t *operation, ftun_error_t error,
  ftun_socks5_connection_t *connection, void *context)
{
  session_t *session = context;
  ftun_path_t *physical = NULL;
  ftun_channel_t *channel = NULL;
  ftun_path_spec_t spec = *session->result;
  ftun_path_t *result = NULL;
  (void)operation;
  session->child = NULL;
  session->connection = connection;
  if (error.status == FTUN_OK) {
    error.status = ftun_socks5_connection_path(connection, &physical);
    if (error.status == FTUN_OK) error.status = ftun_path_channel(physical, &channel);
    else error.status = ftun_socks5_connection_channel(connection, &channel);
    if (error.status == FTUN_OK) {
      spec.driver = (ftun_path_driver_t){0};
      spec.driver.stop = stop;
      spec.driver.resume = resume;
      spec.driver.destroy = destroy;
      spec.driver.context = session;
      error.status = ftun_path_wrap_channel(&spec, channel, &result);
      session->path = result;
    }
  }
  session->error = error;
  {
    ftun_status_t scheduled = ftun_event_task_ready(session->pump);
    assert(scheduled == FTUN_OK);
    (void)scheduled;
  }
}

static ftun_status_t connect_proxy(session_t *session)
{
  ftun_socks5_proxy_t proxy = session->node->proxy;
  ftun_socks5_connect_request_t connect = {0};
  ftun_target_t target = {0};
  if (proxy.server.kind == FTUN_ADDRESS_DOMAIN) {
    proxy.resolved = &session->endpoint;
    proxy.resolved_count = 1u;
  }
  target.generation = session->result->configuration_generation;
  target.original = session->dial.endpoint;
  target.identity = target.original.domain;
  target.candidates = target.allowed = session->dial.allowed;
  target.candidate_count = target.allowed_count = session->dial.allowed_count;
  connect.loop = session->dial.loop;
  connect.operations = session->dial.operations;
  connect.budget = session->dial.budget;
  connect.proxy = &proxy;
  connect.target = &target;
  connect.network_view = session->result->network_view;
  connect.network_generation = session->dial.network_generation;
  connect.requested_domain = session->dial.requested_domain;
  connect.protection = session->dial.protection;
  connect.deadline_ms = session->dial.deadline_ms;
  connect.transport = session->dial.transport;
  connect.completion = connected;
  connect.user = session;
  connect.scope = session->scope;
  connect.stream = session->stream;
  connect.datagram = session->datagram;
  connect.report_datagram_errors = true;
  connect.notify = notified;
  connect.notify_user = session;
  return ftun_socks5_connect(session->core, &connect, &session->child);
}

static void resolved(void *context, ftun_error_t error,
  const ftun_endpoint_t *endpoint)
{
  session_t *session = context;
  ftun_status_t status = ftun_event_source_cancel(&session->deadline);
  if (status != FTUN_OK) error.status = status;
  if (!session->cancelling && error.status == FTUN_OK) {
    session->endpoint = *endpoint;
    error.status = connect_proxy(session);
    if (error.status == FTUN_OK) return;
  }
  session->error = error;
  status = ftun_event_task_ready(session->pump);
  assert(status == FTUN_OK);
  (void)status;
}

static void expired(ftun_event_source_t *source, uint32_t events, void *context)
{
  session_t *session = context;
  (void)source; (void)events;
  ftun_status_t status = ftun_proxy_resolution_cancel(&session->resolver, FTUN_E_TIMEOUT);
  session->error.status = status == FTUN_OK ? FTUN_E_TIMEOUT : status;
  status = ftun_event_task_ready(session->pump);
  assert(status == FTUN_OK);
  (void)status;
}

static ftun_status_t open_path(void *context, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *spec,
  ftun_operation_t **out, bool blocking)
{
  ftun_proxy_egress_t *plan = context;
  ftun_proxy_egress_node_t *node;
  ftun_egress_info_t selection;
  ftun_path_open_request_t selected = *request;
  ftun_path_provider_spec_t physical = {0};
  ftun_endpoint_t endpoint;
  session_t *session;
  size_t bytes;
  uint64_t now = 0u;
  ftun_reservation_t reservation = {0};
  ftun_status_t status;
  *out = NULL;
  if (spec->configuration_generation != plan->generation) return FTUN_E_STALE;
  status = (blocking ? plan->worker.query : plan->provider.query)(plan,
    request->egress, spec->configuration_generation, &selection);
  if (status != FTUN_OK) return status;
  selected.egress = selection.id;
  request = &selected;
  if (request->egress == FTUN_EGRESS_DIRECT) return plan->physical.open(plan->physical_context, core, request, spec, out);
  if (request->egress < FTUN_OUTBOUND_ID_NAMED_BASE ||
      request->egress - FTUN_OUTBOUND_ID_NAMED_BASE >= plan->count) return FTUN_E_REJECTED;
  node = &plan->nodes[request->egress - FTUN_OUTBOUND_ID_NAMED_BASE];
  if (node->kind != FTUN_CONFIG_OUTBOUND_SOCKS5) return FTUN_E_REJECTED;
  /* worker只访问不可变配置；它的同步解析在有界维护线程执行。 */
  endpoint = node->proxy.server;
  if (blocking && endpoint.kind == FTUN_ADDRESS_DOMAIN) {
    ftun_control_execution_t execution = {0};
    execution.budget = request->dial.budget;
    execution.generation = spec->configuration_generation;
    execution.deadline_ms = request->dial.deadline_ms;
    execution.purpose = spec->purpose;
    execution.allow_system_resolver = request->dial.protection.mark == 0u;
    status = ftun_control_resolve_bootstrap(&execution, &plan->bootstrap,
      node->proxy.server.domain, node->proxy.server.port, &endpoint);
    if (status != FTUN_OK) return status;
  } else if (!blocking && endpoint.kind == FTUN_ADDRESS_DOMAIN) {
    status = ftun_monotonic_now(&now);
    if (status != FTUN_OK) return status;
    (void)ftun_proxy_resolution_cached(node, &request->dial, now, &endpoint);
  }
  if (request->dial.allowed_count > (SIZE_MAX - sizeof(*session)) / sizeof(ftun_endpoint_t)) return FTUN_E_LIMIT;
  bytes = sizeof(*session) + request->dial.allowed_count * sizeof(ftun_endpoint_t);
  status = ftun_budget_reserve(request->dial.budget, bytes, &reservation);
  if (status != FTUN_OK) return status;
  session = calloc(1u, bytes);
  if (session == NULL) { ftun_reservation_release(&reservation); return FTUN_E_LIMIT; }
  session->reservation = reservation;
  session->provider = &plan->provider;
  ftun_egress_retain(session->provider);
  session->node = node;
  session->core = core;
  session->endpoint = endpoint;
  session->dial = request->dial;
  session->stream = request->stream;
  session->datagram = request->datagram;
  session->dial.allowed = (ftun_endpoint_t *)(session + 1);
  if (request->dial.allowed_count != 0u) memcpy((void *)session->dial.allowed,
    request->dial.allowed, request->dial.allowed_count * sizeof(ftun_endpoint_t));
  if (request->dial.protection.interface_name.length != 0u) {
    memcpy(session->interface_name, request->dial.protection.interface_name.data,
      request->dial.protection.interface_name.length);
    session->dial.protection.interface_name.data = session->interface_name;
  }
  session->result = spec;
  session->completion = request->completion;
  session->user = request->user;
  session->notify = request->notify;
  session->notify_user = request->notify_user;
  physical.budget = request->dial.budget;
  physical.generation = spec->configuration_generation;
  physical.ops = plan->physical;
  physical.context = plan->physical_context;
  physical.max_pending = 2u;
  physical.max_paths = 2u;
  physical.receive_pool = spec->receive_pool;
  status = ftun_path_provider_create(&physical, &session->physical);
  if (status == FTUN_OK) status = ftun_path_provider_scope(session->physical,
    spec->configuration_generation, &session->scope);
  if (status == FTUN_OK) status = ftun_event_task_start(request->dial.loop,
    pump, session, &session->pump);
  if (status == FTUN_OK) status = ftun_operation_accept(request->dial.operations,
    completed, session, &session->operation, &session->token);
  if (status == FTUN_OK) status = ftun_operation_set_cancel_hook(session->operation, cancel, session);
  if (status == FTUN_OK && endpoint.kind == FTUN_ADDRESS_DOMAIN) {
    session->resolver.completion = resolved;
    session->resolver.user = session;
    status = ftun_event_timer_start(request->dial.loop, request->dial.deadline_ms,
      expired, session, &session->deadline);
    if (status == FTUN_OK) status = ftun_proxy_resolution_start(plan, node,
      core, &session->dial, now, &session->resolver);
  } else if (status == FTUN_OK) status = connect_proxy(session);
  if (status != FTUN_OK) {
    ftun_status_t cancelled = ftun_event_source_cancel(&session->deadline);
    if (cancelled != FTUN_OK) {
      session->error.status = status;
      ftun_status_t scheduled = ftun_event_task_ready(session->pump);
      assert(scheduled == FTUN_OK);
      (void)scheduled;
      *out = session->operation;
      return FTUN_OK;
    }
    if (session->operation != NULL) {
      ftun_status_t rejected = ftun_operation_set_cancel_hook(session->operation, NULL, NULL);
      if (rejected == FTUN_OK) rejected = ftun_operation_reject(&session->operation);
      assert(rejected == FTUN_OK);
      (void)rejected;
    }
    if (session->pump != NULL) {
      ftun_status_t cancelled = ftun_event_source_cancel(&session->pump);
      assert(cancelled == FTUN_OK);
      (void)cancelled;
    }
    ftun_path_scope_release(&session->scope);
    if (session->physical != NULL) {
      ftun_status_t cleanup = ftun_path_provider_stop_until(session->physical, UINT64_MAX);
      if (cleanup == FTUN_OK) cleanup = ftun_path_provider_destroy(&session->physical);
      assert(cleanup == FTUN_OK);
      (void)cleanup;
    }
    free_session(session);
  }
  if (status == FTUN_OK) *out = session->operation;
  return status;
}

ftun_status_t ftun_proxy_egress_open(void *context, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *spec,
  ftun_operation_t **out)
{ return open_path(context, core, request, spec, out, false); }

ftun_status_t ftun_proxy_egress_worker_open(void *context, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *spec,
  ftun_operation_t **out)
{ return open_path(context, core, request, spec, out, true); }
