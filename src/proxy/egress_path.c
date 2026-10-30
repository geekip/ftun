#include "proxy/egress_internal.h"
#include "libs/transport/socket_path.h"
#include "platform/clock.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  ftun_reservation_t reservation;
  ftun_event_source_t *pump;
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
  if (session->child != NULL) return;
  if (session->cancelling) session->error.status = FTUN_E_CANCELLED;
  if (session->error.status != FTUN_OK) {
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

static ftun_status_t open_path(void *context, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *spec,
  ftun_operation_t **out, bool blocking)
{
  const ftun_proxy_egress_t *plan = context;
  const ftun_proxy_egress_node_t *node;
  ftun_socks5_proxy_t proxy;
  ftun_socks5_connect_request_t connect = {0};
  ftun_path_provider_spec_t physical = {0};
  ftun_target_t target = {0};
  ftun_endpoint_t endpoint;
  session_t *session;
  ftun_reservation_t reservation = {0};
  ftun_status_t status;
  *out = NULL;
  if (spec->configuration_generation != plan->generation) return FTUN_E_STALE;
  if (request->egress == FTUN_EGRESS_DIRECT) return plan->physical.open(plan->physical_context, core, request, spec, out);
  if (request->egress < 2u || request->egress - 2u >= plan->count) return FTUN_E_REJECTED;
  node = &plan->nodes[request->egress - 2u];
  if (node->kind != FTUN_CONFIG_OUTBOUND_SOCKS5) return FTUN_E_REJECTED;
  proxy = node->proxy;
  endpoint = node->endpoint;
  if (!node->resolved) {
    ftun_control_execution_t execution = {0};
    if (!blocking) return FTUN_E_RESOLVE;
    execution.budget = request->dial.budget;
    execution.generation = spec->configuration_generation;
    execution.deadline_ms = request->dial.deadline_ms;
    execution.purpose = spec->purpose;
    execution.allow_system_resolver = request->dial.protection.mark == 0u;
    status = ftun_control_resolve_bootstrap(&execution, &plan->bootstrap,
      proxy.server.domain, proxy.server.port, &endpoint);
    if (status != FTUN_OK) return status;
  }
  if (proxy.server.kind == FTUN_ADDRESS_DOMAIN) {
    proxy.resolved = &endpoint;
    proxy.resolved_count = 1u;
  }
  target.generation = spec->configuration_generation;
  target.original = request->dial.endpoint;
  target.identity = request->dial.endpoint.domain;
  target.candidates = request->dial.allowed;
  target.candidate_count = request->dial.allowed_count;
  target.allowed = request->dial.allowed;
  target.allowed_count = request->dial.allowed_count;
  status = ftun_budget_reserve(request->dial.budget, sizeof(*session), &reservation);
  if (status != FTUN_OK) return status;
  session = calloc(1u, sizeof(*session));
  if (session == NULL) { ftun_reservation_release(&reservation); return FTUN_E_LIMIT; }
  session->reservation = reservation;
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
  connect.loop = request->dial.loop;
  connect.operations = request->dial.operations;
  connect.budget = request->dial.budget;
  connect.proxy = &proxy;
  connect.target = &target;
  connect.network_view = request->dial.network_view;
  connect.network_generation = request->dial.network_generation;
  connect.requested_domain = request->dial.requested_domain;
  connect.protection = request->dial.protection;
  connect.deadline_ms = request->dial.deadline_ms;
  connect.transport = request->dial.transport;
  connect.completion = connected;
  connect.user = session;
  connect.scope = session->scope;
  connect.stream = request->stream;
  connect.datagram = request->datagram;
  connect.report_datagram_errors = true;
  connect.notify = notified;
  connect.notify_user = session;
  if (status == FTUN_OK) status = ftun_event_task_start(request->dial.loop,
    pump, session, &session->pump);
  if (status == FTUN_OK) status = ftun_operation_accept(request->dial.operations,
    completed, session, &session->operation, &session->token);
  if (status == FTUN_OK) status = ftun_operation_set_cancel_hook(session->operation, cancel, session);
  if (status == FTUN_OK) status = ftun_socks5_connect(core, &connect, &session->child);
  if (status != FTUN_OK) {
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
    free(session);
    ftun_reservation_release(&reservation);
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
